//! First-class backwards slice over semantic and syntax-derived flow facts.
//!
//! This command answers "what facts influence `<symbol>` at `<line>`?"
//! It prefers the shared value-flow/IDG graph when semantic sidecars have
//! already been hydrated, then merges adapter-emitted
//! [`FlowEvent`](bonsai_lang_api::FlowEvent) evidence for local syntax
//! detail. When it reaches a parameter boundary, an unavailable semantic
//! graph, or a caller-supplied cap, the result says so through
//! `analysis_incomplete_reasons`.

use crate::common::{file_path_matches_filter, format_span};
use ahash::AHashSet;
use bonsai_common::{FuncId, SymbolId};
use bonsai_hash::fnv1a_names_low32;
use bonsai_lang_api::{Decl, DeclKind, FlowEvent};
use bonsai_workspace::{
    value_flow::{ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind},
    Workspace,
};
use serde::Serialize;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Filter bundle for [`slices`].
#[derive(Copy, Clone, Debug)]
pub struct SliceFilters<'a> {
    /// Variable / place / normalized symbol to slice backwards from.
    pub symbol: &'a str,
    /// One-based source line where the symbol is inspected.
    pub line: u32,
    /// Optional workspace-relative file path filter used to disambiguate
    /// same-line callables across a workspace. Explicit absolute paths
    /// are also accepted.
    pub file: Option<&'a str>,
    /// Maximum slice steps to emit. `0` means uncapped.
    pub max_steps: usize,
}

impl Default for SliceFilters<'_> {
    fn default() -> Self {
        Self {
            symbol: "",
            line: 0,
            file: None,
            max_steps: 64,
        }
    }
}

/// Full slice query result.
#[derive(Serialize, Clone, Debug, Default)]
pub struct SliceOutcome {
    pub symbol: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub candidate_count: usize,
    pub slice_count: usize,
    pub max_steps: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<String>,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
    pub slices: Vec<SliceRow>,
}

/// One candidate callable's backwards slice.
#[derive(Serialize, Clone, Debug)]
pub struct SliceRow {
    pub slice_id: String,
    pub file: String,
    pub function: String,
    pub function_line: u32,
    pub target_line: u32,
    pub target_symbol: String,
    pub step_count: usize,
    pub backends: Vec<String>,
    pub influencing_symbols: Vec<String>,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
    pub steps: Vec<SliceStep>,
}

/// One syntax fact in a backwards slice.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SliceStep {
    pub kind: String,
    pub symbol: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub in_function: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defines: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_call: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nesting: Vec<String>,
}

#[derive(Clone, Debug)]
struct SliceFact {
    kind: &'static str,
    symbol: String,
    file: String,
    line: u32,
    column: u32,
    in_function: String,
    detail: String,
    defines: Option<String>,
    sources: Vec<String>,
    via_call: Option<String>,
    nesting: Vec<String>,
    span_start: u64,
}

#[derive(Clone, Debug, Default)]
struct SliceComputation {
    steps: Vec<SliceStep>,
    influencing_symbols: Vec<String>,
    analysis_incomplete_reasons: Vec<String>,
    backends: Vec<String>,
}

#[derive(Clone, Debug)]
enum SemanticSliceResult {
    Computed(SliceComputation),
    Unavailable,
    NoTargetNode,
}

/// Query local backwards slices for `symbol` at `line`.
pub fn slices(ws: &Workspace, filters: &SliceFilters<'_>) -> SliceOutcome {
    let mut outcome = SliceOutcome {
        symbol: filters.symbol.to_string(),
        line: filters.line,
        file: filters.file.map(str::to_string),
        max_steps: filters.max_steps,
        ..SliceOutcome::default()
    };
    if filters.symbol.trim().is_empty() {
        outcome
            .analysis_incomplete_reasons
            .push("empty slice symbol".to_string());
        finalize_outcome(&mut outcome);
        return outcome;
    }
    if filters.line == 0 {
        outcome
            .analysis_incomplete_reasons
            .push("slice line must be one-based".to_string());
        finalize_outcome(&mut outcome);
        return outcome;
    }

    let global = ws.db().global_index();
    let mut rows = Vec::new();
    for file in global.all_files() {
        let Ok(path) = ws.vfs().path(file) else {
            continue;
        };
        let file_path = path.to_string_lossy().to_string();
        if filters
            .file
            .is_some_and(|needle| !file_path_matches_filter(ws, &file_path, needle))
        {
            continue;
        }
        for decl in global.decls_in(file) {
            if !is_callable_decl(decl.kind) || !decl_contains_line(ws, decl, filters.line) {
                continue;
            }
            rows.push(slice_decl(ws, decl, &file_path, filters));
        }
    }
    let matched_candidate_count = rows.len();
    retain_non_empty_slices_if_any(&mut rows);
    rows.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.function_line.cmp(&b.function_line))
            .then_with(|| a.function.cmp(&b.function))
    });
    outcome.candidate_count = matched_candidate_count;
    outcome.slices = rows;
    outcome.slice_count = outcome.slices.len();
    if outcome.candidate_count == 0 {
        outcome.analysis_incomplete_reasons.push(format!(
            "no callable contains line {}{}",
            filters.line,
            filters
                .file
                .map(|file| format!(" in files matching `{file}`"))
                .unwrap_or_default()
        ));
    } else if outcome.candidate_count > 1 && filters.file.is_none() {
        outcome.analysis_incomplete_reasons.push(format!(
            "line {} matched {} callables; pass --file to narrow",
            filters.line, outcome.candidate_count
        ));
    }
    finalize_outcome(&mut outcome);
    outcome
}

fn retain_non_empty_slices_if_any(rows: &mut Vec<SliceRow>) {
    if rows.iter().any(|row| row.step_count > 0) {
        rows.retain(|row| row.step_count > 0);
    }
}

fn slice_decl(ws: &Workspace, decl: &Decl, file_path: &str, filters: &SliceFilters<'_>) -> SliceRow {
    let (_, function_line, _) = format_span(&decl.name_span, ws);
    let mut facts = Vec::new();
    flatten_events(&decl.flow_events, &decl.name, ws, &mut Vec::new(), &mut facts);
    facts.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then_with(|| a.span_start.cmp(&b.span_start))
            .then_with(|| a.kind.cmp(b.kind))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });
    let local_computation = backward_slice_from_facts(
        filters.symbol,
        filters.line,
        filters.max_steps,
        &facts,
        &decl.params,
        &decl.name,
        file_path,
    );
    let computation = match semantic_slice_from_value_flow(
        ws,
        decl,
        filters.symbol,
        filters.line,
        filters.max_steps,
    ) {
        SemanticSliceResult::Computed(semantic) => {
            let mut computation = semantic;
            merge_slice_computations(&mut computation, local_computation, filters.max_steps, &decl.name);
            computation
        }
        SemanticSliceResult::Unavailable => {
            let mut computation = local_computation;
            push_unique_string(
                &mut computation.analysis_incomplete_reasons,
                "semantic value-flow graph was not available; run `bonsai-ninja index --semantic` to hydrate reusable semantic sidecars",
            );
            computation
        }
        SemanticSliceResult::NoTargetNode => {
            let mut computation = local_computation;
            push_unique_string(
                &mut computation.analysis_incomplete_reasons,
                &format!(
                    "semantic value-flow graph has no target node for `{}` at or before line {}",
                    filters.symbol, filters.line
                ),
            );
            computation
        }
    };
    let slice_id = compute_slice_id(
        file_path,
        &decl.name,
        filters.symbol,
        filters.line,
        &computation.steps,
    );
    let analysis_complete = computation.analysis_incomplete_reasons.is_empty();
    SliceRow {
        slice_id,
        file: file_path.to_string(),
        function: decl.name.clone(),
        function_line,
        target_line: filters.line,
        target_symbol: filters.symbol.to_string(),
        step_count: computation.steps.len(),
        backends: computation.backends,
        influencing_symbols: computation.influencing_symbols,
        analysis_complete,
        analysis_incomplete_reasons: computation.analysis_incomplete_reasons,
        steps: computation.steps,
    }
}

fn flatten_events(
    events: &[FlowEvent],
    in_function: &str,
    ws: &Workspace,
    nesting: &mut Vec<String>,
    out: &mut Vec<SliceFact>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                args,
                ..
            } => {
                let mut sources = Vec::new();
                if let Some(receiver) = receiver {
                    push_unique_symbol(&mut sources, receiver);
                }
                for arg in args {
                    if let Some(place) = arg.place.as_deref() {
                        push_unique_symbol(&mut sources, place);
                    }
                    for source in &arg.source_names {
                        push_unique_symbol(&mut sources, source);
                    }
                    if let Some(simple) = simple_symbol_from_value(&arg.value_text) {
                        push_unique_symbol(&mut sources, &simple);
                    }
                }
                let (file, line, column) = format_span(span, ws);
                out.push(SliceFact {
                    kind: "call",
                    symbol: name.clone(),
                    file,
                    line,
                    column,
                    in_function: in_function.to_string(),
                    detail: format!("call {name}(...)"),
                    defines: None,
                    sources,
                    via_call: Some(name.clone()),
                    nesting: nesting.clone(),
                    span_start: span.start,
                });
            }
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                let mut sources = Vec::new();
                if let Some(source_name) = source_name {
                    push_unique_symbol(&mut sources, source_name);
                }
                for source in source_names {
                    push_unique_symbol(&mut sources, source);
                }
                for arg in source_call_args {
                    if let Some(simple) = simple_symbol_from_value(arg) {
                        push_unique_symbol(&mut sources, &simple);
                    }
                }
                let (file, line, column) = format_span(span, ws);
                let detail = source_call.as_ref().map_or_else(
                    || format!("assign {target}"),
                    |call| format!("assign {target} = {call}(...)"),
                );
                out.push(SliceFact {
                    kind: "assign",
                    symbol: target.clone(),
                    file,
                    line,
                    column,
                    in_function: in_function.to_string(),
                    detail,
                    defines: Some(target.clone()),
                    sources,
                    via_call: source_call.clone(),
                    nesting: nesting.clone(),
                    span_start: span.start,
                });
            }
            FlowEvent::Return {
                span,
                value_text,
                value_name,
            } => {
                let mut sources = Vec::new();
                if let Some(value_name) = value_name {
                    push_unique_symbol(&mut sources, value_name);
                }
                if let Some(value_text) = value_text {
                    if let Some(simple) = simple_symbol_from_value(value_text) {
                        push_unique_symbol(&mut sources, &simple);
                    }
                }
                push_value_fact(
                    ws,
                    out,
                    span,
                    ValueFactParts::borrowed("return", "return", sources),
                    in_function,
                    nesting,
                );
            }
            FlowEvent::Throw { span, value_name, .. } => {
                let mut sources = Vec::new();
                if let Some(value_name) = value_name {
                    push_unique_symbol(&mut sources, value_name);
                }
                push_value_fact(
                    ws,
                    out,
                    span,
                    ValueFactParts::borrowed("throw", "throw", sources),
                    in_function,
                    nesting,
                );
            }
            FlowEvent::Await { span, value_name } => {
                let mut sources = Vec::new();
                if let Some(value_name) = value_name {
                    push_unique_symbol(&mut sources, value_name);
                }
                push_value_fact(
                    ws,
                    out,
                    span,
                    ValueFactParts::borrowed("await", "await", sources),
                    in_function,
                    nesting,
                );
            }
            FlowEvent::Yield { span, value_text } => {
                let mut sources = Vec::new();
                if let Some(value_text) = value_text {
                    if let Some(simple) = simple_symbol_from_value(value_text) {
                        push_unique_symbol(&mut sources, &simple);
                    }
                }
                push_value_fact(
                    ws,
                    out,
                    span,
                    ValueFactParts::borrowed("yield", "yield", sources),
                    in_function,
                    nesting,
                );
            }
            FlowEvent::Lifecycle {
                span,
                name,
                transition,
            } => {
                let (file, line, column) = format_span(span, ws);
                out.push(SliceFact {
                    kind: "lifecycle",
                    symbol: name.clone(),
                    file,
                    line,
                    column,
                    in_function: in_function.to_string(),
                    detail: format!("{name} -> {transition}"),
                    defines: None,
                    sources: vec![name.clone()],
                    via_call: None,
                    nesting: nesting.clone(),
                    span_start: span.start,
                });
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                if let Some(condition) = condition {
                    let mut sources = Vec::new();
                    if let Some(simple) = simple_symbol_from_value(condition) {
                        push_unique_symbol(&mut sources, &simple);
                    }
                    push_value_fact(
                        ws,
                        out,
                        span,
                        ValueFactParts::owned("branch", format!("branch on {condition}"), sources),
                        in_function,
                        nesting,
                    );
                }
                nesting.push("then".to_string());
                flatten_events(then_events, in_function, ws, nesting, out);
                nesting.pop();
                if !else_events.is_empty() {
                    nesting.push("else".to_string());
                    flatten_events(else_events, in_function, ws, nesting, out);
                    nesting.pop();
                }
            }
            FlowEvent::Loop { body, .. } => {
                nesting.push("loop".to_string());
                flatten_events(body, in_function, ws, nesting, out);
                nesting.pop();
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                nesting.push("try".to_string());
                flatten_events(body, in_function, ws, nesting, out);
                nesting.pop();
                if let Some(catch_param) = catch_param {
                    let span = event.span();
                    let (file, line, column) = format_span(&span, ws);
                    out.push(SliceFact {
                        kind: "catch",
                        symbol: catch_param.clone(),
                        file,
                        line,
                        column,
                        in_function: in_function.to_string(),
                        detail: format!("catch parameter {catch_param}"),
                        defines: Some(catch_param.clone()),
                        sources: Vec::new(),
                        via_call: None,
                        nesting: nesting.clone(),
                        span_start: span.start,
                    });
                }
                if !catch_events.is_empty() {
                    nesting.push("catch".to_string());
                    flatten_events(catch_events, in_function, ws, nesting, out);
                    nesting.pop();
                }
                if !finally_events.is_empty() {
                    nesting.push("finally".to_string());
                    flatten_events(finally_events, in_function, ws, nesting, out);
                    nesting.pop();
                }
            }
            FlowEvent::Defer { body, .. } => {
                nesting.push("defer".to_string());
                flatten_events(body, in_function, ws, nesting, out);
                nesting.pop();
            }
            FlowEvent::Using { body, .. } => {
                nesting.push("using".to_string());
                flatten_events(body, in_function, ws, nesting, out);
                nesting.pop();
            }
            FlowEvent::Break { .. } | FlowEvent::Continue { .. } => {}
        }
    }
}

struct ValueFactParts<'a> {
    kind: &'static str,
    detail: Cow<'a, str>,
    sources: Vec<String>,
}

impl<'a> ValueFactParts<'a> {
    fn borrowed(kind: &'static str, detail: &'static str, sources: Vec<String>) -> Self {
        Self {
            kind,
            detail: Cow::Borrowed(detail),
            sources,
        }
    }

    fn owned(kind: &'static str, detail: String, sources: Vec<String>) -> Self {
        Self {
            kind,
            detail: Cow::Owned(detail),
            sources,
        }
    }
}

fn push_value_fact(
    ws: &Workspace,
    out: &mut Vec<SliceFact>,
    span: &bonsai_common::Span,
    fact: ValueFactParts<'_>,
    in_function: &str,
    nesting: &[String],
) {
    let (file, line, column) = format_span(span, ws);
    let symbol = fact
        .sources
        .first()
        .cloned()
        .unwrap_or_else(|| fact.kind.to_string());
    out.push(SliceFact {
        kind: fact.kind,
        symbol,
        file,
        line,
        column,
        in_function: in_function.to_string(),
        detail: fact.detail.into_owned(),
        defines: None,
        sources: fact.sources,
        via_call: None,
        nesting: nesting.to_vec(),
        span_start: span.start,
    });
}

fn backward_slice_from_facts(
    symbol: &str,
    target_line: u32,
    max_steps: usize,
    facts: &[SliceFact],
    params: &[String],
    in_function: &str,
    file: &str,
) -> SliceComputation {
    let cap = if max_steps == 0 { usize::MAX } else { max_steps };
    let mut wanted = BTreeSet::new();
    wanted.insert(symbol.trim().to_string());
    let mut influencing = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    let mut steps = Vec::new();
    let mut seen = AHashSet::default();
    let mut capped = false;

    for fact in facts.iter().rev() {
        if fact.line == 0 || fact.line > target_line {
            continue;
        }
        let relation = fact_relation_to_wanted(fact, &wanted);
        let Some(relation) = relation else {
            continue;
        };
        if !relation.defines_wanted && fact.line != target_line {
            continue;
        }
        if steps.len() >= cap {
            capped = true;
            break;
        }
        let step_key = format!(
            "{}:{}:{}:{}:{}",
            fact.kind, fact.file, fact.line, fact.column, fact.detail
        );
        if !seen.insert(step_key) {
            continue;
        }
        steps.push(SliceStep {
            kind: fact.kind.to_string(),
            symbol: relation.matched_symbol.clone(),
            file: fact.file.clone(),
            line: fact.line,
            column: fact.column,
            in_function: fact.in_function.clone(),
            detail: fact.detail.clone(),
            defines: fact.defines.clone(),
            sources: fact.sources.clone(),
            via_call: fact.via_call.clone(),
            nesting: fact.nesting.clone(),
        });

        if relation.defines_wanted {
            if let Some(call) = fact.via_call.as_deref() {
                if fact.defines.is_some() {
                    reasons.insert(format!(
                        "call return from `{call}` is local-only; interprocedural summaries were not expanded"
                    ));
                }
            }
        }
        if relation.defines_wanted {
            if let Some(defined) = fact.defines.as_deref() {
                wanted.retain(|name| !symbol_matches(name, defined));
            }
            if fact.sources.is_empty() && fact.via_call.is_none() {
                reasons.insert(format!(
                    "assignment to `{}` had no surfaced source operands",
                    fact.defines.as_deref().unwrap_or(&fact.symbol)
                ));
            }
            for source in &fact.sources {
                if !source.trim().is_empty() {
                    influencing.insert(source.clone());
                    wanted.insert(source.clone());
                }
            }
        } else {
            for source in &fact.sources {
                if wanted.iter().any(|name| symbol_matches(name, source)) {
                    influencing.insert(source.clone());
                }
            }
        }
    }

    if capped {
        reasons.insert(format!("slice truncated by --max-steps {max_steps}"));
    }

    for param in params {
        if wanted.iter().any(|name| symbol_matches(name, param)) {
            if steps.len() < cap {
                steps.push(SliceStep {
                    kind: "param".to_string(),
                    symbol: param.clone(),
                    file: file.to_string(),
                    line: 0,
                    column: 0,
                    in_function: in_function.to_string(),
                    detail: format!("parameter {param}"),
                    defines: Some(param.clone()),
                    sources: Vec::new(),
                    via_call: None,
                    nesting: Vec::new(),
                });
            } else {
                capped = true;
            }
            influencing.insert(param.clone());
            reasons.insert(format!("slice reached parameter boundary `{param}`"));
        }
    }
    if capped {
        reasons.insert(format!("slice truncated by --max-steps {max_steps}"));
    }
    if steps.is_empty() {
        reasons.insert(format!(
            "no syntax-flow facts for `{}` at or before line {target_line}",
            symbol.trim()
        ));
    }

    SliceComputation {
        steps,
        influencing_symbols: influencing.into_iter().collect(),
        analysis_incomplete_reasons: reasons.into_iter().collect(),
        backends: vec!["flow-events".to_string()],
    }
}

fn semantic_slice_from_value_flow(
    ws: &Workspace,
    decl: &Decl,
    symbol: &str,
    target_line: u32,
    max_steps: usize,
) -> SemanticSliceResult {
    let has_semantic_cache = !ws.value_flow().is_empty() || ws.db().idg_service().is_some();
    if !has_semantic_cache {
        return SemanticSliceResult::Unavailable;
    }
    let func = FuncId::new(decl.symbol.raw());
    let graph = ws
        .value_flow()
        .graph_for_with_caches(func, ws.db(), ws.inter_taint_caches());
    if graph.nodes.is_empty() {
        return SemanticSliceResult::Unavailable;
    }
    let targets = semantic_target_nodes(ws, decl, &graph, func, symbol, target_line);
    if targets.is_empty() {
        return SemanticSliceResult::NoTargetNode;
    }

    let cap = slice_step_cap(max_steps);
    let mut node_set = AHashSet::default();
    for target in &targets {
        node_set.insert(target.clone());
        node_set.extend(graph.backward_closure(target));
    }
    let mut nodes: Vec<_> = node_set.into_iter().collect();
    nodes.sort_by(|a, b| compare_semantic_nodes(ws, &targets, target_line, a, b));

    let mut reasons = BTreeSet::new();
    if graph.saturated {
        reasons.insert("semantic value-flow graph saturated before completion".to_string());
    }
    if nodes.len() > cap {
        reasons.insert(format!("slice truncated by --max-steps {max_steps}"));
        nodes.truncate(cap);
    }

    let target_set: AHashSet<ValueFlowNode> = targets.into_iter().collect();
    let closure_set: AHashSet<ValueFlowNode> = nodes.iter().cloned().collect();
    let mut influencing = BTreeSet::new();
    let mut steps = Vec::with_capacity(nodes.len());
    for node in nodes {
        if !target_set.contains(&node) {
            influencing.insert(node.value_text.clone());
        }
        let (file, line, column) = format_span(&node.span, ws);
        let sources = semantic_immediate_sources(&graph, &node, &closure_set);
        let function = semantic_function_name(ws, node.func);
        steps.push(SliceStep {
            kind: semantic_step_kind(node.kind).to_string(),
            symbol: node.value_text.clone(),
            file,
            line,
            column,
            in_function: function,
            detail: semantic_step_detail(node.kind, &node.value_text),
            defines: semantic_defines(node.kind, &node.value_text),
            sources,
            via_call: None,
            nesting: Vec::new(),
        });
    }

    SemanticSliceResult::Computed(SliceComputation {
        steps,
        influencing_symbols: influencing.into_iter().collect(),
        analysis_incomplete_reasons: reasons.into_iter().collect(),
        backends: vec!["value-flow".to_string()],
    })
}

fn semantic_target_nodes(
    ws: &Workspace,
    decl: &Decl,
    graph: &ValueFlowGraph,
    func: FuncId,
    symbol: &str,
    target_line: u32,
) -> Vec<ValueFlowNode> {
    let mut candidates: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| {
            node.func == func
                && node.span.file == decl.span.file
                && symbol_matches(symbol, &node.value_text)
                && semantic_node_line(ws, node).is_some_and(|line| line <= target_line)
        })
        .cloned()
        .collect();
    if candidates.is_empty() {
        return candidates;
    }
    candidates.sort_by(|a, b| {
        semantic_node_line(ws, b)
            .cmp(&semantic_node_line(ws, a))
            .then_with(|| a.value_text.cmp(&b.value_text))
            .then_with(|| semantic_step_kind(a.kind).cmp(semantic_step_kind(b.kind)))
    });
    if candidates
        .iter()
        .any(|node| semantic_node_line(ws, node) == Some(target_line))
    {
        candidates.retain(|node| semantic_node_line(ws, node) == Some(target_line));
    } else if let Some(best_line) = candidates.first().and_then(|node| semantic_node_line(ws, node)) {
        candidates.retain(|node| semantic_node_line(ws, node) == Some(best_line));
    }
    candidates
}

fn merge_slice_computations(
    base: &mut SliceComputation,
    semantic: SliceComputation,
    max_steps: usize,
    current_function: &str,
) {
    for backend in semantic.backends {
        push_unique_string(&mut base.backends, &backend);
    }
    let semantic_crosses_function = semantic
        .steps
        .iter()
        .any(|step| step.in_function != current_function);
    let cap = slice_step_cap(max_steps);
    let mut seen: AHashSet<String> = base.steps.iter().map(slice_step_key).collect();
    let mut truncated = false;
    for step in semantic.steps {
        if base.steps.len() >= cap {
            truncated = true;
            break;
        }
        if seen.insert(slice_step_key(&step)) {
            base.steps.push(step);
        }
    }
    let crosses_function_after_merge =
        semantic_crosses_function || base.steps.iter().any(|step| step.in_function != current_function);
    if crosses_function_after_merge {
        base.analysis_incomplete_reasons
            .retain(|reason| !reason.contains("interprocedural summaries were not expanded"));
    }
    for reason in semantic.analysis_incomplete_reasons {
        if !base.steps.is_empty() && reason.starts_with("no syntax-flow facts for `") {
            continue;
        }
        if crosses_function_after_merge && reason.contains("interprocedural summaries were not expanded") {
            continue;
        }
        push_unique_string(&mut base.analysis_incomplete_reasons, &reason);
    }
    if truncated {
        push_unique_string(
            &mut base.analysis_incomplete_reasons,
            &format!("slice truncated by --max-steps {max_steps}"),
        );
    }
    for symbol in semantic.influencing_symbols {
        push_unique_string(&mut base.influencing_symbols, &symbol);
    }
    base.influencing_symbols.sort();
    base.influencing_symbols.dedup();
    base.analysis_incomplete_reasons.sort();
    base.analysis_incomplete_reasons.dedup();
}

fn compare_semantic_nodes(
    ws: &Workspace,
    targets: &[ValueFlowNode],
    target_line: u32,
    a: &ValueFlowNode,
    b: &ValueFlowNode,
) -> Ordering {
    let a_target = targets.iter().any(|target| target == a);
    let b_target = targets.iter().any(|target| target == b);
    b_target
        .cmp(&a_target)
        .then_with(|| {
            semantic_node_distance(ws, a, target_line).cmp(&semantic_node_distance(ws, b, target_line))
        })
        .then_with(|| semantic_function_name(ws, a.func).cmp(&semantic_function_name(ws, b.func)))
        .then_with(|| semantic_node_line(ws, b).cmp(&semantic_node_line(ws, a)))
        .then_with(|| a.value_text.cmp(&b.value_text))
        .then_with(|| semantic_step_kind(a.kind).cmp(semantic_step_kind(b.kind)))
}

fn semantic_node_distance(ws: &Workspace, node: &ValueFlowNode, target_line: u32) -> u32 {
    semantic_node_line(ws, node)
        .map(|line| line.abs_diff(target_line))
        .unwrap_or(u32::MAX)
}

fn semantic_node_line(ws: &Workspace, node: &ValueFlowNode) -> Option<u32> {
    let (_, line, _) = format_span(&node.span, ws);
    (line > 0).then_some(line)
}

fn semantic_immediate_sources(
    graph: &ValueFlowGraph,
    node: &ValueFlowNode,
    closure: &AHashSet<ValueFlowNode>,
) -> Vec<String> {
    let mut sources = BTreeSet::new();
    if let Some(edges) = graph.backward.get(node) {
        for edge in edges {
            if closure.contains(&edge.from) && edge.from != *node {
                sources.insert(edge.from.value_text.clone());
            }
        }
    }
    sources.into_iter().collect()
}

fn semantic_function_name(ws: &Workspace, func: FuncId) -> String {
    ws.db()
        .global_index()
        .decl_of(SymbolId::new(func.raw()))
        .map(|decl| decl.name.clone())
        .unwrap_or_else(|| format!("F:{}", func.raw()))
}

fn semantic_step_kind(kind: ValueFlowNodeKind) -> &'static str {
    match kind {
        ValueFlowNodeKind::Param => "semantic_param",
        ValueFlowNodeKind::AssignTarget => "semantic_assign",
        ValueFlowNodeKind::CallArg => "semantic_call_arg",
        ValueFlowNodeKind::Return => "semantic_return",
        ValueFlowNodeKind::Catch => "semantic_catch",
        ValueFlowNodeKind::Read => "semantic_read",
    }
}

fn semantic_step_detail(kind: ValueFlowNodeKind, value_text: &str) -> String {
    match kind {
        ValueFlowNodeKind::Param => format!("semantic parameter {value_text}"),
        ValueFlowNodeKind::AssignTarget => format!("semantic assignment target {value_text}"),
        ValueFlowNodeKind::CallArg => format!("semantic call argument {value_text}"),
        ValueFlowNodeKind::Return => format!("semantic return value {value_text}"),
        ValueFlowNodeKind::Catch => format!("semantic catch value {value_text}"),
        ValueFlowNodeKind::Read => format!("semantic read {value_text}"),
    }
}

fn semantic_defines(kind: ValueFlowNodeKind, value_text: &str) -> Option<String> {
    matches!(
        kind,
        ValueFlowNodeKind::Param
            | ValueFlowNodeKind::AssignTarget
            | ValueFlowNodeKind::Catch
            | ValueFlowNodeKind::Read
    )
    .then(|| value_text.to_string())
}

#[derive(Clone, Debug)]
struct FactRelation {
    matched_symbol: String,
    defines_wanted: bool,
}

fn fact_relation_to_wanted(fact: &SliceFact, wanted: &BTreeSet<String>) -> Option<FactRelation> {
    if let Some(defined) = fact.defines.as_deref() {
        if let Some(matched) = wanted.iter().find(|name| symbol_matches(name, defined)) {
            return Some(FactRelation {
                matched_symbol: matched.clone(),
                defines_wanted: true,
            });
        }
    }
    for wanted_symbol in wanted {
        if symbol_matches(wanted_symbol, &fact.symbol)
            || fact
                .sources
                .iter()
                .any(|source| symbol_matches(wanted_symbol, source))
        {
            return Some(FactRelation {
                matched_symbol: wanted_symbol.clone(),
                defines_wanted: false,
            });
        }
    }
    None
}

fn finalize_outcome(outcome: &mut SliceOutcome) {
    for row in &outcome.slices {
        for backend in &row.backends {
            push_unique_string(&mut outcome.backends, backend);
        }
        outcome
            .analysis_incomplete_reasons
            .extend(row.analysis_incomplete_reasons.clone());
    }
    outcome.analysis_incomplete_reasons.sort();
    outcome.analysis_incomplete_reasons.dedup();
    outcome.analysis_complete = outcome.analysis_incomplete_reasons.is_empty();
}

fn decl_contains_line(ws: &Workspace, decl: &Decl, line: u32) -> bool {
    let span = decl.body_span.unwrap_or(decl.span);
    if span.file != decl.span.file {
        return false;
    }
    let (_, start_line, _) = format_span(&span, ws);
    let end_span = if span.end > span.start {
        bonsai_common::Span::new(span.file, span.end.saturating_sub(1), span.end)
    } else {
        span
    };
    let (_, end_line, _) = format_span(&end_span, ws);
    start_line <= line && line <= end_line.max(start_line)
}

fn is_callable_decl(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    )
}

fn push_unique_symbol(out: &mut Vec<String>, raw: &str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() || out.iter().any(|existing| existing == trimmed) {
        return;
    }
    out.push(trimmed.to_string());
}

fn push_unique_string(out: &mut Vec<String>, raw: &str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() || out.iter().any(|existing| existing == trimmed) {
        return;
    }
    out.push(trimmed.to_string());
}

fn slice_step_cap(max_steps: usize) -> usize {
    if max_steps == 0 {
        usize::MAX
    } else {
        max_steps
    }
}

fn slice_step_key(step: &SliceStep) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        step.kind, step.symbol, step.file, step.line, step.column, step.detail
    )
}

fn simple_symbol_from_value(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    let mut has_name_char = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '@') {
            has_name_char = true;
            continue;
        }
        if matches!(ch, '.' | ':' | '-' | '>' | '[' | ']') {
            continue;
        }
        return None;
    }
    has_name_char.then(|| value.to_string())
}

fn symbol_matches(query: &str, candidate: &str) -> bool {
    let query = query.trim();
    let candidate = candidate.trim();
    if query.is_empty() || candidate.is_empty() {
        return false;
    }
    if query == candidate {
        return true;
    }
    if candidate.ends_with(&format!(".{query}"))
        || candidate.ends_with(&format!("::{query}"))
        || candidate.ends_with(&format!("->{query}"))
    {
        return true;
    }
    let query_segments = symbol_segments(query);
    let candidate_segments = symbol_segments(candidate);
    if query_segments.len() == 1 {
        return candidate_segments
            .iter()
            .any(|segment| segment == &query_segments[0]);
    }
    candidate_segments
        .windows(query_segments.len())
        .any(|window| window == query_segments.as_slice())
}

fn symbol_segments(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '@')))
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect()
}

fn compute_slice_id(file: &str, function: &str, symbol: &str, line: u32, steps: &[SliceStep]) -> String {
    let mut tokens = vec![
        file.to_string(),
        function.to_string(),
        symbol.to_string(),
        line.to_string(),
    ];
    tokens.extend(
        steps
            .iter()
            .map(|step| format!("{}:{}:{}:{}", step.kind, step.symbol, step.line, step.column)),
    );
    format!("SL:{:08x}", fnv1a_names_low32(&tokens))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(
        kind: &'static str,
        symbol: &str,
        line: u32,
        defines: Option<&str>,
        sources: &[&str],
        via_call: Option<&str>,
    ) -> SliceFact {
        SliceFact {
            kind,
            symbol: symbol.to_string(),
            file: "app.py".to_string(),
            line,
            column: 1,
            in_function: "handler".to_string(),
            detail: format!("{kind} {symbol}"),
            defines: defines.map(str::to_string),
            sources: sources.iter().map(|s| (*s).to_string()).collect(),
            via_call: via_call.map(str::to_string),
            nesting: Vec::new(),
            span_start: u64::from(line),
        }
    }

    fn step(kind: &str, symbol: &str, in_function: &str) -> SliceStep {
        SliceStep {
            kind: kind.to_string(),
            symbol: symbol.to_string(),
            file: "app.py".to_string(),
            line: 4,
            column: 1,
            in_function: in_function.to_string(),
            detail: format!("{kind} {symbol}"),
            defines: Some(symbol.to_string()),
            sources: Vec::new(),
            via_call: None,
            nesting: Vec::new(),
        }
    }

    #[test]
    fn backwards_slice_follows_assignment_sources_to_params() {
        let facts = vec![
            fact("assign", "token", 2, Some("token"), &["request"], Some("get")),
            fact(
                "assign",
                "result",
                4,
                Some("result"),
                &["token", "action"],
                Some("update_user"),
            ),
        ];
        let slice = backward_slice_from_facts(
            "result",
            4,
            16,
            &facts,
            &["request".to_string(), "action".to_string()],
            "handler",
            "app.py",
        );
        let symbols: Vec<_> = slice.steps.iter().map(|step| step.symbol.as_str()).collect();
        assert_eq!(symbols[0], "result");
        assert!(symbols.contains(&"token"));
        assert!(symbols.contains(&"request"));
        assert!(symbols.contains(&"action"));
        assert!(slice
            .analysis_incomplete_reasons
            .iter()
            .any(|reason| reason.contains("parameter boundary `request`")));
        assert!(slice
            .analysis_incomplete_reasons
            .iter()
            .any(|reason| reason.contains("call return from `update_user`")));
    }

    #[test]
    fn backwards_slice_respects_step_cap() {
        let facts = vec![
            fact("assign", "c", 1, Some("c"), &["d"], None),
            fact("assign", "b", 2, Some("b"), &["c"], None),
            fact("assign", "a", 3, Some("a"), &["b"], None),
        ];
        let slice = backward_slice_from_facts("a", 3, 1, &facts, &[], "handler", "app.py");
        assert_eq!(slice.steps.len(), 1);
        assert!(slice
            .analysis_incomplete_reasons
            .iter()
            .any(|reason| reason.contains("--max-steps 1")));
    }

    #[test]
    fn semantic_slice_steps_are_preferred_under_step_cap() {
        let mut semantic = SliceComputation {
            steps: vec![step("semantic_assign", "result", "callee")],
            influencing_symbols: vec!["payload".to_string()],
            analysis_incomplete_reasons: Vec::new(),
            backends: vec!["value-flow".to_string()],
        };
        let local = SliceComputation {
            steps: vec![step("assign", "result", "handler")],
            influencing_symbols: vec!["request".to_string()],
            analysis_incomplete_reasons: vec![
                "call return from `callee` is local-only; interprocedural summaries were not expanded"
                    .to_string(),
                "no syntax-flow facts for `result` at or before line 4".to_string(),
            ],
            backends: vec!["flow-events".to_string()],
        };

        merge_slice_computations(&mut semantic, local, 1, "handler");

        assert_eq!(semantic.steps.len(), 1);
        assert_eq!(semantic.steps[0].kind, "semantic_assign");
        assert_eq!(semantic.backends, vec!["value-flow", "flow-events"]);
        assert!(
            semantic.analysis_incomplete_reasons.iter().all(|reason| !reason
                .contains("interprocedural summaries were not expanded")
                && !reason.starts_with("no syntax-flow facts")),
            "semantic evidence should suppress lower-priority local-only warnings: {semantic:#?}"
        );
        assert!(
            semantic
                .analysis_incomplete_reasons
                .iter()
                .any(|reason| reason.contains("--max-steps 1")),
            "dropping local syntax rows due to the cap must still be reported: {semantic:#?}"
        );
    }

    #[test]
    fn symbol_matching_uses_normalized_segments_not_substrings() {
        assert!(symbol_matches("cmd", "request.cmd"));
        assert!(symbol_matches("request.cmd", "ctx.request.cmd"));
        assert!(!symbol_matches("cmd", "cmdline"));
        assert!(!symbol_matches("id", "user_id"));
    }

    fn row_for_test(function: &str, step_count: usize) -> SliceRow {
        SliceRow {
            slice_id: format!("SL:{function}"),
            file: "app.py".to_string(),
            function: function.to_string(),
            function_line: 1,
            target_line: 2,
            target_symbol: "cmd".to_string(),
            step_count,
            backends: Vec::new(),
            influencing_symbols: Vec::new(),
            analysis_complete: step_count > 0,
            analysis_incomplete_reasons: Vec::new(),
            steps: Vec::new(),
        }
    }

    #[test]
    fn retain_non_empty_slices_preserves_external_candidate_count() {
        let mut rows = vec![
            row_for_test("empty_candidate", 0),
            row_for_test("real_candidate", 2),
        ];
        let matched_candidate_count = rows.len();

        retain_non_empty_slices_if_any(&mut rows);

        assert_eq!(matched_candidate_count, 2);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].function, "real_candidate");
    }
}
