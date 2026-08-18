//! Bounded compiler evidence for one callable symbol.
//!
//! A symbol summary is deliberately not a recursively expanded call path.
//! It combines one exact Tree-sitter-lowered declaration with the direct
//! incoming/outgoing edges selected by the shared resolver, unresolved
//! workspace call sites, and file-local imports. Its work is therefore
//! linear in the selected symbol's body and graph degree; diamonds and cycles
//! cannot multiply into an exponential set of paths.

use crate::common::format_span;
use crate::edges::edge_record_from_graph_nodes;
use crate::refs::read_snippet;
use bonsai_callgraph::{CallEdge, ResolvedCallGraph};
use bonsai_common::{FuncId, Span, SymbolId};
use bonsai_lang_api::{for_each_flow_event, DeclKind, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Whether a row is exact source evidence or a semantic resolver proof.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolEvidenceKind {
    Source,
    Resolved,
    Unresolved,
}

/// One direct compiler-resolved call edge adjacent to the selected symbol.
#[derive(Clone, Debug, Serialize)]
pub struct SymbolCallEdge {
    pub evidence_kind: SymbolEvidenceKind,
    pub edge_id: String,
    pub caller_symbol_id: u32,
    pub caller: String,
    pub callee_symbol_id: u32,
    pub callee: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub call_text: String,
    pub dispatch: String,
    pub precision: String,
    pub resolver_stage: String,
    pub resolver_evidence: String,
}

/// One import declared in the selected symbol's source file.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SymbolImport {
    pub evidence_kind: SymbolEvidenceKind,
    pub module: String,
    pub alias: Option<String>,
    pub original_name: Option<String>,
    pub wildcard: bool,
    pub line: u32,
}

/// A call expression for which the resolver could not prove a runtime target.
/// This includes ambiguous workspace candidates and callable-parameter
/// invocations without a compiler-proven binding.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UnresolvedCallEvidence {
    pub evidence_kind: SymbolEvidenceKind,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub call_text: String,
    pub reason: String,
}

/// Self-contained, non-recursive evidence packet for one callable.
#[derive(Clone, Debug, Serialize)]
pub struct SymbolSummary {
    /// Stable content-addressed id for reopening this summary.
    pub summary_id: String,
    /// Snapshot-local compiler ordinal. Useful for correlating raw graph
    /// records, but not a persistent identifier.
    pub compiler_symbol_id: u32,
    pub name: String,
    pub qualified_name: Option<String>,
    pub kind: String,
    pub language: String,
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub params: Vec<String>,
    pub signature: String,
    pub source: String,
    pub direct_callers: Vec<SymbolCallEdge>,
    pub direct_callees: Vec<SymbolCallEdge>,
    pub unresolved_calls: Vec<UnresolvedCallEvidence>,
    pub imports: Vec<SymbolImport>,
    pub graph_scope: &'static str,
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
}

/// Return bounded compiler summaries for every callable matching `pattern`.
///
/// Matching selects candidates only. Every emitted declaration and edge is
/// hydrated from canonical compiler/resolver identities.
pub fn symbol_summaries(
    ws: &Workspace,
    pattern: Option<&str>,
    regex: bool,
) -> Result<Vec<SymbolSummary>, regex::Error> {
    let matcher = bonsai_inspect::Matcher::build(pattern, regex)?;
    let targets = bonsai_inspect::matching_func_ids(ws, &matcher);
    let graph = ws.cached_resolved_call_graph();
    let headers = ws.compiler_header_index();
    let mut summaries = targets
        .into_iter()
        .filter_map(|func| symbol_summary(ws, headers.as_ref(), graph.as_ref(), func))
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(summaries)
}

fn symbol_summary(
    ws: &Workspace,
    headers: &bonsai_index::GlobalIndex,
    graph: &ResolvedCallGraph,
    func: FuncId,
) -> Option<SymbolSummary> {
    let decl = ws.exact_decl(SymbolId::new(func.raw()))?;
    if !matches!(
        decl.kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    ) {
        return None;
    }
    let (file, start_line, _) = format_span(&decl.span, ws);
    let (_, end_line, _) = format_span(
        &bonsai_common::Span::new(decl.span.file, decl.span.end.saturating_sub(1), decl.span.end),
        ws,
    );
    let source = source_for_span(ws, decl.span);
    let signature = signature_for_decl(&decl.name, &decl.params, &source);

    let mut direct_callers = graph
        .callers_of(func)
        .filter(|edge| edge.precision.is_semantic())
        .filter_map(|edge| summary_edge(ws, graph, edge))
        .collect::<Vec<_>>();
    let mut direct_callees = graph
        .callees_of(func)
        .filter(|edge| edge.precision.is_semantic())
        .filter_map(|edge| summary_edge(ws, graph, edge))
        .collect::<Vec<_>>();
    sort_edges(&mut direct_callers);
    sort_edges(&mut direct_callees);

    let unresolved_workspace_spans = graph
        .unresolved_workspace_call_sites()
        .filter(|(caller, _)| *caller == func)
        .map(|(_, span)| span)
        .collect::<Vec<_>>();
    let semantic_outgoing_spans = graph
        .callees_of(func)
        .filter(|edge| edge.precision.is_semantic())
        .map(|edge| edge.span)
        .collect::<Vec<_>>();
    let unresolved_parameter_spans = unresolved_callable_parameter_spans(
        &decl.flow_events,
        &decl.params,
        &semantic_outgoing_spans,
        &unresolved_workspace_spans,
    );

    let mut unresolved_calls = unresolved_workspace_spans
        .iter()
        .copied()
        .map(|span| {
            let (file, line, column) = format_span(&span, ws);
            UnresolvedCallEvidence {
                evidence_kind: SymbolEvidenceKind::Unresolved,
                file,
                line,
                column,
                call_text: read_snippet(ws, &span),
                reason: "workspace candidates existed, but compiler evidence did not justify a target"
                    .to_string(),
            }
        })
        .collect::<Vec<_>>();
    unresolved_calls.extend(unresolved_parameter_spans.iter().map(|span| {
        let (file, line, column) = format_span(span, ws);
        UnresolvedCallEvidence {
            evidence_kind: SymbolEvidenceKind::Unresolved,
            file,
            line,
            column,
            call_text: read_snippet(ws, span),
            reason: "callable parameter invocation has no compiler-proven binding".to_string(),
        }
    }));
    unresolved_calls.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.column.cmp(&right.column))
            .then_with(|| left.call_text.cmp(&right.call_text))
            .then_with(|| left.reason.cmp(&right.reason))
    });

    let mut imports = ws
        .db()
        .import_index_uncached(decl.span.file)
        .into_iter()
        .flat_map(|index| index.imports)
        .map(|import| {
            let (_, line, _) = format_span(&import.span, ws);
            SymbolImport {
                evidence_kind: SymbolEvidenceKind::Source,
                module: import.module,
                alias: import.alias,
                original_name: import.original_name,
                wildcard: import.is_wildcard,
                line,
            }
        })
        .collect::<Vec<_>>();
    imports.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.module.cmp(&right.module))
    });

    let mut analysis_incomplete_reasons = Vec::new();
    if !unresolved_workspace_spans.is_empty() {
        analysis_incomplete_reasons.push(format!(
            "{} workspace call site(s) have candidates but no compiler-proven target",
            unresolved_workspace_spans.len()
        ));
    }
    if !unresolved_parameter_spans.is_empty() {
        analysis_incomplete_reasons.push(format!(
            "{} callable parameter invocation(s) have no compiler-proven binding",
            unresolved_parameter_spans.len()
        ));
    }
    Some(SymbolSummary {
        summary_id: bonsai_workspace::flow_ids::compute_structural_flow_id(
            headers,
            ws.db(),
            ws.vfs(),
            &[func],
        ),
        compiler_symbol_id: func.raw(),
        name: decl.name.clone(),
        qualified_name: decl.qualified_name.clone(),
        kind: format!("{:?}", decl.kind).to_lowercase(),
        language: ws
            .db()
            .adapter_for(decl.span.file)
            .map_or("unknown", |adapter| adapter.language_id().as_str())
            .to_string(),
        file,
        start_line,
        end_line,
        params: decl.params.clone(),
        signature,
        source,
        direct_callers,
        direct_callees,
        unresolved_calls,
        imports,
        graph_scope: "direct_resolved_neighbors",
        analysis_complete: analysis_incomplete_reasons.is_empty(),
        analysis_incomplete_reasons,
    })
}

/// Collect direct calls through parameters that the context-free callgraph
/// cannot prove. This stays declaration-local: callers may bind a parameter
/// at runtime, but that does not justify a resolved summary edge here.
fn unresolved_callable_parameter_spans(
    events: &[FlowEvent],
    params: &[String],
    semantic_outgoing_spans: &[Span],
    unresolved_workspace_spans: &[Span],
) -> Vec<Span> {
    let mut spans = Vec::new();
    for_each_flow_event(events, &mut |event| {
        if let FlowEvent::Call { span, name, .. } = event {
            if params.iter().any(|param| param == name.trim())
                && !semantic_outgoing_spans.contains(span)
                && !unresolved_workspace_spans.contains(span)
            {
                spans.push(*span);
            }
        }
    });
    spans.sort_unstable_by_key(|span| (span.file.raw(), span.start, span.end));
    spans.dedup();
    spans
}

fn summary_edge(ws: &Workspace, graph: &ResolvedCallGraph, edge: &CallEdge) -> Option<SymbolCallEdge> {
    let row = edge_record_from_graph_nodes(ws, graph, edge)?;
    Some(SymbolCallEdge {
        evidence_kind: SymbolEvidenceKind::Resolved,
        edge_id: row.edge_id,
        caller_symbol_id: edge.from.raw(),
        caller: row.caller_name,
        callee_symbol_id: edge.to.raw(),
        callee: row.callee_name,
        file: row.call_file,
        line: row.call_line,
        column: row.call_column,
        call_text: row.call_text,
        dispatch: row.kind,
        precision: row.precision,
        resolver_stage: row.resolver_stage,
        resolver_evidence: row.evidence,
    })
}

fn sort_edges(edges: &mut Vec<SymbolCallEdge>) {
    edges.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.column.cmp(&right.column))
            .then_with(|| left.edge_id.cmp(&right.edge_id))
    });
    edges.dedup_by(|left, right| left.edge_id == right.edge_id);
}

fn source_for_span(ws: &Workspace, span: bonsai_common::Span) -> String {
    let Ok(snapshot) = ws.vfs().snapshot(span.file) else {
        return String::new();
    };
    let bytes = snapshot.text.as_bytes();
    let start = (span.start as usize).min(bytes.len());
    let end = (span.end as usize).min(bytes.len()).max(start);
    String::from_utf8_lossy(&bytes[start..end]).into_owned()
}

fn signature_for_decl(name: &str, params: &[String], source: &str) -> String {
    let first_line = source.lines().next().unwrap_or_default().trim();
    if !first_line.is_empty() && first_line.contains(name) {
        first_line.to_string()
    } else {
        format!("{name}({})", params.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::LanguageRegistry;
    use std::sync::Arc;

    fn workspace(source: &str) -> Workspace {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let ws = Workspace::new(registry);
        ws.vfs().write("main.py".to_string(), Arc::<str>::from(source));
        for file in ws.vfs().all_files() {
            let _ = ws.db().decl_index(file);
        }
        ws
    }

    #[test]
    fn summary_is_direct_and_reports_resolved_neighbors() {
        let ws = workspace(
            "def leaf(x):\n    return x\n\ndef middle(x):\n    return leaf(x)\n\ndef root(x):\n    return middle(x)\n",
        );
        let rows = symbol_summaries(&ws, Some("middle"), false).expect("summary");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.language, "python");
        assert!(row.direct_callers.iter().any(|edge| edge.caller == "root"));
        assert!(row.direct_callees.iter().any(|edge| edge.callee == "leaf"));
        assert_eq!(row.graph_scope, "direct_resolved_neighbors");
        assert!(!row.source.contains("def root"));
    }

    #[test]
    fn diamond_graph_does_not_materialize_paths() {
        let ws = workspace(
            "def sink(x):\n    return x\n\ndef left(x):\n    return sink(x)\n\ndef right(x):\n    return sink(x)\n\ndef root(x):\n    return left(x) + right(x)\n",
        );
        let rows = symbol_summaries(&ws, Some("sink"), false).expect("summary");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].direct_callers.len(), 2);
        assert!(rows[0].direct_callees.is_empty());
    }

    #[test]
    fn stable_summary_id_uses_compiler_identity_not_graph_degree() {
        let without_caller = workspace("def target(x):\n    return x\n");
        let with_caller = workspace("def target(x):\n    return x\n\ndef caller(x):\n    return target(x)\n");

        let first = symbol_summaries(&without_caller, Some("target"), false).expect("first summary");
        let second = symbol_summaries(&with_caller, Some("target"), false).expect("second summary");
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].summary_id, second[0].summary_id);
        assert!(first[0].direct_callers.is_empty());
        assert_eq!(second[0].direct_callers.len(), 1);
    }
}
