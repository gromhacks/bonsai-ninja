//! First-class source-to-target path query.
//!
//! This is a renderer/data layer over the canonical resolved callgraph:
//! it consumes FuncId-keyed semantic edges and never resolves by raw
//! text or invents missing call edges.

use crate::common::format_span;
use crate::edges::{compute_edge_id, edge_record_from_resolved_edge, EdgeRecord};
use crate::resolution::{resolution_coverage, ResolutionCoverageFilters};
use bonsai_callgraph::{
    enumerate_paths_resolved, CallEdge, EdgeProvenance, PathTruncation, ResolvedCallGraph, ResolvedPath,
};
use bonsai_common::{FuncId, Span, SymbolId};
use bonsai_hash::fnv1a_names_low32;
use bonsai_idg::CrossCallEdge;
use bonsai_inspect::{matching_func_ids, Matcher};
use bonsai_lang_api::{DeclKind, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`paths`].
#[derive(Copy, Clone, Debug)]
pub struct PathFilters<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub regex: bool,
    pub max_paths: usize,
    pub max_depth: usize,
    pub max_probes: usize,
}

impl Default for PathFilters<'_> {
    fn default() -> Self {
        Self {
            from: "",
            to: "",
            regex: false,
            max_paths: 10,
            max_depth: 12,
            max_probes: 4096,
        }
    }
}

/// Full path query result.
#[derive(Serialize, Clone, Debug, Default)]
pub struct PathOutcome {
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<String>,
    pub idg_available: bool,
    pub idg_semantic_edges: usize,
    pub from_matches: usize,
    pub to_matches: usize,
    pub max_paths: usize,
    pub max_depth: usize,
    pub max_probes: usize,
    pub path_count: usize,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
    pub paths: Vec<PathRow>,
}

/// One ranked path row.
#[derive(Serialize, Clone, Debug)]
pub struct PathRow {
    pub path_id: String,
    pub hops: usize,
    pub precision: String,
    pub functions: Vec<PathFunctionRow>,
    pub edges: Vec<EdgeRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_call: Option<PathTerminalCallRow>,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
}

/// Function hop in a path row.
#[derive(Serialize, Clone, Debug)]
pub struct PathFunctionRow {
    pub name: String,
    pub file: String,
    pub line: u32,
}

/// Syntax-backed call site that matched `--to` when no callable
/// declaration did. The semantic path ends at this call site's
/// enclosing function; this row is evidence for the terminal call
/// inside that function, not an invented edge to an external API.
#[derive(Serialize, Clone, Debug)]
pub struct PathTerminalCallRow {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub enclosing_function: String,
}

#[derive(Clone, Debug)]
struct TerminalCallTarget {
    func: FuncId,
    row: PathTerminalCallRow,
}

/// Query source-to-target paths over resolved semantic callgraph edges.
pub fn paths(ws: &Workspace, filters: &PathFilters<'_>) -> Result<PathOutcome, regex::Error> {
    let from_matcher = Matcher::build(Some(filters.from), filters.regex)?;
    let to_matcher = Matcher::build(Some(filters.to), filters.regex)?;
    let from_funcs = matching_func_ids(ws, &from_matcher);
    let to_funcs = matching_func_ids(ws, &to_matcher);
    let terminal_targets = if to_funcs.is_empty() {
        matching_terminal_call_targets(ws, &to_matcher)
    } else {
        Vec::new()
    };
    let path_graph = semantic_path_graph(ws);
    let mut outcome = PathOutcome {
        from: filters.from.to_string(),
        to: filters.to.to_string(),
        backends: path_graph.backends.clone(),
        idg_available: path_graph.idg_available,
        idg_semantic_edges: path_graph.idg_semantic_edges,
        from_matches: from_funcs.len(),
        to_matches: if to_funcs.is_empty() {
            terminal_targets.len()
        } else {
            to_funcs.len()
        },
        max_paths: filters.max_paths,
        max_depth: filters.max_depth,
        max_probes: filters.max_probes,
        ..PathOutcome::default()
    };
    if from_funcs.is_empty() {
        outcome
            .analysis_incomplete_reasons
            .push(format!("no callable source matched `{}`", filters.from));
    }
    if to_funcs.is_empty() {
        if terminal_targets.is_empty() {
            outcome.analysis_incomplete_reasons.push(format!(
                "no callable or call-site target matched `{}`",
                filters.to
            ));
        } else {
            outcome.analysis_incomplete_reasons.push(format!(
                "target `{}` matched call site(s), not callable declaration(s); paths end at enclosing callable and show terminal call evidence",
                filters.to
            ));
        }
    }
    if from_funcs.is_empty() || (to_funcs.is_empty() && terminal_targets.is_empty()) {
        finalize_outcome(ws, &mut outcome, PathTruncation::None);
        return Ok(outcome);
    }

    let global = ws.db().global_index();
    let mut rows = Vec::new();
    let mut hydration_reasons = Vec::new();
    let mut truncation = PathTruncation::None;
    let callable_targets: Vec<(FuncId, Option<PathTerminalCallRow>)> = if to_funcs.is_empty() {
        terminal_targets
            .iter()
            .map(|target| (target.func, Some(target.row.clone())))
            .collect()
    } else {
        to_funcs.iter().copied().map(|func| (func, None)).collect()
    };
    'outer: for from in &from_funcs {
        for (to, terminal_call) in &callable_targets {
            let remaining = filters.max_paths.saturating_sub(rows.len());
            if remaining == 0 {
                truncation = PathTruncation::MaxPaths;
                break 'outer;
            }
            let (paths, pair_truncation) = enumerate_paths_resolved(
                &path_graph.graph,
                *from,
                *to,
                remaining,
                filters.max_depth,
                filters.max_probes,
            );
            truncation = merge_truncation(truncation, pair_truncation);
            for path in paths {
                match hydrate_path_row(ws, global.as_ref(), &path) {
                    Ok(mut row) => {
                        row.terminal_call.clone_from(terminal_call);
                        row.path_id = compute_path_id(&row.functions, &row.edges, row.terminal_call.as_ref());
                        rows.push(row);
                    }
                    Err(reason) => hydration_reasons.push(reason),
                }
                if rows.len() >= filters.max_paths {
                    truncation = PathTruncation::MaxPaths;
                    break 'outer;
                }
            }
        }
    }
    rows.sort_by(|a, b| {
        a.hops
            .cmp(&b.hops)
            .then_with(|| precision_rank(&a.precision).cmp(&precision_rank(&b.precision)))
            .then_with(|| a.path_id.cmp(&b.path_id))
    });
    rows.truncate(filters.max_paths);
    outcome.paths = rows;
    outcome.path_count = outcome.paths.len();
    outcome.analysis_incomplete_reasons.extend(hydration_reasons);
    finalize_outcome(ws, &mut outcome, truncation);
    Ok(outcome)
}

fn matching_terminal_call_targets(ws: &Workspace, matcher: &Matcher) -> Vec<TerminalCallTarget> {
    let global = ws.db().global_index();
    let mut targets = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let format = |span: &Span| format_span(span, ws);
            collect_terminal_call_targets_for_events(
                FuncId::new(decl.symbol.raw()),
                &decl.name,
                &decl.flow_events,
                matcher,
                &format,
                &mut targets,
            );
        }
    }
    targets.sort_by(|a, b| {
        a.row
            .file
            .cmp(&b.row.file)
            .then_with(|| a.row.line.cmp(&b.row.line))
            .then_with(|| a.row.column.cmp(&b.row.column))
            .then_with(|| a.row.name.cmp(&b.row.name))
    });
    targets
}

fn collect_terminal_call_targets_for_events(
    func: FuncId,
    enclosing_function: &str,
    events: &[FlowEvent],
    matcher: &Matcher,
    format: &dyn Fn(&Span) -> (String, u32, u32),
    out: &mut Vec<TerminalCallTarget>,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } => {
                if matcher.is_match(name) {
                    let (file, line, column) = format(span);
                    out.push(TerminalCallTarget {
                        func,
                        row: PathTerminalCallRow {
                            name: name.clone(),
                            file,
                            line,
                            column,
                            enclosing_function: enclosing_function.to_string(),
                        },
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    then_events,
                    matcher,
                    format,
                    out,
                );
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    else_events,
                    matcher,
                    format,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    body,
                    matcher,
                    format,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    body,
                    matcher,
                    format,
                    out,
                );
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    catch_events,
                    matcher,
                    format,
                    out,
                );
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    finally_events,
                    matcher,
                    format,
                    out,
                );
            }
            FlowEvent::Assign { .. }
            | FlowEvent::AggregateAssign { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

struct SemanticPathGraph {
    graph: ResolvedCallGraph,
    backends: Vec<String>,
    idg_available: bool,
    idg_semantic_edges: usize,
}

fn semantic_path_graph(ws: &Workspace) -> SemanticPathGraph {
    let mut graph = ws.cached_resolved_call_graph().inner().clone();
    let mut backends = vec!["resolved-callgraph".to_string()];
    let mut idg_available = false;
    let mut idg_semantic_edges = 0usize;
    if let Some(idg) = ws.db().idg_service() {
        idg_available = true;
        for edge in idg.semantic_cross_call_edges_with_max_precision(Some(bonsai_common::Precision::Narrowed))
        {
            if !idg_cross_call_is_structural_path_edge(edge) {
                continue;
            }
            graph.add_edge(call_edge_from_idg_cross_call(edge));
            idg_semantic_edges = idg_semantic_edges.saturating_add(1);
        }
        backends.push("warmed-idg-cross-call".to_string());
    }
    SemanticPathGraph {
        graph: ResolvedCallGraph::from_call_graph(graph),
        backends,
        idg_available,
        idg_semantic_edges,
    }
}

fn idg_cross_call_is_structural_path_edge(edge: CrossCallEdge) -> bool {
    edge.relation.is_renderable_call()
        && edge.precision.is_semantic()
        && (edge.arg_idx != u32::MAX || edge.param_idx != u32::MAX)
}

fn call_edge_from_idg_cross_call(edge: CrossCallEdge) -> CallEdge {
    let evidence = if edge.arg_idx == u32::MAX {
        format!(
            "IDG callback/output edge into parameter {} at call site",
            edge.param_idx
        )
    } else if edge.param_idx == u32::MAX {
        format!("IDG call argument {} propagated through call site", edge.arg_idx)
    } else {
        format!(
            "IDG call argument {} propagated to parameter {}",
            edge.arg_idx, edge.param_idx
        )
    };
    CallEdge {
        from: edge.caller,
        to: edge.callee,
        span: edge.call_span,
        kind: edge.call_kind,
        precision: edge.precision,
        provenance: EdgeProvenance::new("idg_cross_call", evidence, 88),
    }
}

fn function_row(ws: &Workspace, func: FuncId) -> Option<PathFunctionRow> {
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(func.raw()))?;
    let (file, line, _) = format_span(&decl.name_span, ws);
    Some(PathFunctionRow {
        name: decl.name.clone(),
        file,
        line,
    })
}

fn hydrate_path_row(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    path: &ResolvedPath,
) -> Result<PathRow, String> {
    if path.funcs.len() != path.edges.len().saturating_add(1) {
        return Err(format!(
            "path candidate skipped because it had {} function node(s) and {} edge(s)",
            path.funcs.len(),
            path.edges.len()
        ));
    }

    let mut functions = Vec::with_capacity(path.funcs.len());
    for func in &path.funcs {
        let Some(row) = function_row(ws, *func) else {
            return Err(format!(
                "path candidate skipped because function F:{} was not present in the current index",
                func.raw()
            ));
        };
        functions.push(row);
    }

    let mut edges = Vec::with_capacity(path.edges.len());
    for edge in &path.edges {
        let Some(row) = edge_record_from_resolved_edge(ws, global, edge) else {
            return Err(format!(
                "path candidate skipped because edge F:{} -> F:{} at file {}:{}-{} was not present in the current index",
                edge.from.raw(),
                edge.to.raw(),
                edge.span.file.raw(),
                edge.span.start,
                edge.span.end
            ));
        };
        edges.push(row);
    }

    let precision = precision_display(path.precision).to_string();
    let path_id = compute_path_id(&functions, &edges, None);
    Ok(PathRow {
        path_id,
        hops: path.edges.len(),
        precision,
        functions,
        edges,
        terminal_call: None,
        analysis_complete: false,
        analysis_incomplete_reasons: Vec::new(),
    })
}

fn finalize_outcome(ws: &Workspace, outcome: &mut PathOutcome, truncation: PathTruncation) {
    if let Some(label) = truncation.label() {
        outcome
            .analysis_incomplete_reasons
            .push(format!("path enumeration truncated by {label}"));
    }
    let unresolved: usize = resolution_coverage(ws, &ResolutionCoverageFilters::default())
        .iter()
        .map(|row| row.unresolved_call_sites)
        .sum();
    if unresolved > 0 {
        outcome.analysis_incomplete_reasons.push(format!(
            "workspace has {unresolved} unresolved call site(s); missing paths cannot be ruled out"
        ));
    }
    if !outcome.idg_available {
        outcome
            .analysis_incomplete_reasons
            .push("warmed IDG sidecar unavailable; path used resolved callgraph only".to_string());
    }
    outcome.analysis_incomplete_reasons.sort();
    outcome.analysis_incomplete_reasons.dedup();
    outcome.analysis_complete = outcome.analysis_incomplete_reasons.is_empty();
    for path in &mut outcome.paths {
        path.analysis_complete = outcome.analysis_complete;
        path.analysis_incomplete_reasons
            .clone_from(&outcome.analysis_incomplete_reasons);
    }
}

fn merge_truncation(left: PathTruncation, right: PathTruncation) -> PathTruncation {
    if truncation_rank(right) > truncation_rank(left) {
        right
    } else {
        left
    }
}

fn truncation_rank(value: PathTruncation) -> u8 {
    match value {
        PathTruncation::None => 0,
        PathTruncation::MaxDepth => 1,
        PathTruncation::MaxPaths => 2,
        PathTruncation::ProbeBudget => 3,
    }
}

fn compute_path_id(
    functions: &[PathFunctionRow],
    edges: &[EdgeRecord],
    terminal_call: Option<&PathTerminalCallRow>,
) -> String {
    let mut tokens = Vec::with_capacity(functions.len() + edges.len());
    tokens.extend(functions.iter().map(|func| func.name.clone()));
    tokens.extend(edges.iter().map(|edge| {
        if edge.edge_id.is_empty() {
            compute_edge_id(
                &edge.caller_name,
                &edge.callee_name,
                &edge.call_file,
                edge.call_line,
                edge.call_column,
            )
        } else {
            edge.edge_id.clone()
        }
    }));
    if let Some(call) = terminal_call {
        tokens.push(call.name.clone());
        tokens.push(format!("{}:{}:{}", call.file, call.line, call.column));
    }
    format!("PTH:{:08x}", fnv1a_names_low32(&tokens))
}

fn precision_display(precision: bonsai_common::Precision) -> &'static str {
    match precision {
        bonsai_common::Precision::Exact => "exact",
        bonsai_common::Precision::Narrowed => "narrowed",
        bonsai_common::Precision::OverApproximate => "over-approximate",
        bonsai_common::Precision::Unknown => "unknown",
    }
}

fn precision_rank(precision: &str) -> u8 {
    match precision {
        "exact" => 0,
        "narrowed" => 1,
        "over-approximate" => 2,
        _ => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_callgraph::EdgeKind;
    use bonsai_common::{FileId, Precision, Span};

    fn cross_call(arg_idx: u32, param_idx: u32) -> CrossCallEdge {
        CrossCallEdge {
            caller: FuncId::new(1),
            callee: FuncId::new(2),
            call_span: Span::new(FileId::new(1), 10, 20),
            arg_idx,
            param_idx,
            precision: Precision::Narrowed,
            call_kind: EdgeKind::Direct,
            relation: bonsai_idg::CrossCallRelation::Argument,
        }
    }

    #[test]
    fn path_rows_hydrate_complete_function_and_edge_facts() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def sink():\n    return 1\n\ndef entry():\n    return sink()\n",
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let outcome = paths(
            &ws,
            &PathFilters {
                from: "entry",
                to: "sink",
                ..PathFilters::default()
            },
        )
        .expect("path query");
        let row = outcome.paths.first().unwrap_or_else(|| {
            panic!("expected entry -> sink path, got outcome: {outcome:#?}");
        });

        assert_eq!(
            row.functions.len(),
            row.edges.len() + 1,
            "path rows must render only fully hydrated function/edge chains"
        );
        assert_eq!(row.hops, row.edges.len());
        assert!(row.functions.iter().any(|func| func.name == "entry"));
        assert!(row.functions.iter().any(|func| func.name == "sink"));
        assert!(row.terminal_call.is_none());
    }

    #[test]
    fn terminal_call_targets_collect_nested_syntax_call_facts() {
        let matcher = Matcher::build(Some("external_sink"), false).expect("matcher");
        let call_span = Span::new(FileId::new(7), 40, 44);
        let events = vec![FlowEvent::Branch {
            span: Span::new(FileId::new(7), 10, 12),
            condition: Some("ok".to_string()),
            then_events: vec![FlowEvent::Call {
                span: call_span,
                name: "external_sink".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: Vec::new(),
            }],
            else_events: vec![FlowEvent::Call {
                span: Span::new(FileId::new(7), 60, 64),
                name: "other_call".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: Vec::new(),
            }],
        }];
        let format = |span: &Span| {
            assert_eq!(*span, call_span);
            ("app.py".to_string(), 4, 5)
        };
        let mut out = Vec::new();

        collect_terminal_call_targets_for_events(
            FuncId::new(9),
            "run_admin_command",
            &events,
            &matcher,
            &format,
            &mut out,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].func, FuncId::new(9));
        assert_eq!(out[0].row.name, "external_sink");
        assert_eq!(out[0].row.file, "app.py");
        assert_eq!(out[0].row.line, 4);
        assert_eq!(out[0].row.column, 5);
        assert_eq!(out[0].row.enclosing_function, "run_admin_command");
    }

    #[test]
    fn path_id_includes_terminal_call_site_evidence() {
        let functions = vec![PathFunctionRow {
            name: "run_admin_command".to_string(),
            file: "app.py".to_string(),
            line: 3,
        }];
        let first = PathTerminalCallRow {
            name: "external_sink".to_string(),
            file: "app.py".to_string(),
            line: 4,
            column: 5,
            enclosing_function: "run_admin_command".to_string(),
        };
        let second = PathTerminalCallRow {
            column: 12,
            ..first.clone()
        };

        let without_terminal = compute_path_id(&functions, &[], None);
        let with_first = compute_path_id(&functions, &[], Some(&first));
        let with_second = compute_path_id(&functions, &[], Some(&second));

        assert_ne!(without_terminal, with_first);
        assert_ne!(with_first, with_second);
    }

    #[test]
    fn path_row_hydration_rejects_missing_function_fact() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.py"), "def entry():\n    return 1\n").expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        let global = ws.db().global_index();
        let stale_path = ResolvedPath {
            funcs: vec![FuncId::new(u32::MAX)],
            edges: Vec::new(),
            precision: Precision::Exact,
        };

        let err = hydrate_path_row(&ws, global.as_ref(), &stale_path)
            .expect_err("stale function ids must not render as partial paths");

        assert!(
            err.contains("was not present in the current index"),
            "unexpected hydration error: {err}"
        );
    }

    #[test]
    fn idg_path_edges_keep_only_structural_call_shapes() {
        assert!(idg_cross_call_is_structural_path_edge(cross_call(0, 0)));
        assert!(idg_cross_call_is_structural_path_edge(cross_call(u32::MAX, 1)));
        assert!(!idg_cross_call_is_structural_path_edge(cross_call(
            u32::MAX,
            u32::MAX
        )));

        let mut over = cross_call(0, 0);
        over.precision = Precision::OverApproximate;
        assert!(!idg_cross_call_is_structural_path_edge(over));
    }
}
