//! `bonsai-ninja dump-edges` data layer.
//!
//! One [`EdgeRecord`] per resolved call edge in the workspace.
//! This is a renderer over [`bonsai_callgraph::ResolvedCallGraph`],
//! not a second resolver. Keeping one semantic source of truth prevents
//! debug output from over-fanning or drifting from inspect/export/taint.

use crate::common::format_span;
use bonsai_callgraph::{CallEdge, EdgeKind, ResolvedCallGraph};
use bonsai_common::{FuncId, Span, SymbolId};
use bonsai_hash::edge_id_low32;
use bonsai_lang_api::{CallArg, Decl, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`dump_edges`]. Match-anywhere semantics on
/// `from`/`to`; an `edge_id` filter narrows to a single edge.
#[derive(Copy, Clone, Default, Debug)]
pub struct EdgesFilters<'a> {
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub edge_id: Option<&'a str>,
}

/// One resolved call edge. `call_*` fields point at the resolved
/// call-site span; `caller_*` / `callee_*` point at the
/// decl name spans. `kind` is `direct` / `virtual` / `indirect`.
/// `resolver_stage` / `evidence` / `confidence` are forwarded from the
/// shared resolver provenance on the call edge; the dump layer does not
/// infer or rewrite them.
#[derive(Serialize, Clone, Debug)]
pub struct EdgeRecord {
    pub edge_id: String,
    pub caller_name: String,
    pub caller_file: String,
    pub caller_line: u32,
    pub callee_name: String,
    pub callee_file: String,
    pub callee_line: u32,
    pub call_file: String,
    pub call_line: u32,
    pub call_column: u32,
    pub call_text: String,
    pub kind: String,
    pub resolver_stage: String,
    pub evidence: String,
    pub confidence: u8,
}

/// Stable content-hash id for one resolved call edge: `E:` + 8 hex
/// chars (low 32 bits of FNV-1a-64) over `(caller, callee,
/// call_site)`. Same hash family as the inspect flow / group ids.
#[must_use]
pub fn compute_edge_id(
    caller_name: &str,
    callee_name: &str,
    call_file: &str,
    call_line: u32,
    call_column: u32,
) -> String {
    format!(
        "E:{:08x}",
        edge_id_low32(caller_name, callee_name, call_file, call_line, call_column)
    )
}

/// Collect matching resolved call edges in the workspace. Cheap filters over
/// compiler symbols are applied before an [`EdgeRecord`] allocates rendered
/// paths, snippets, provenance strings, and ids. This matters on multi-million
/// edge workspaces: a selective query remains proportional in allocations to
/// its result set even though exact coverage still examines every candidate
/// edge.
pub fn dump_edges(ws: &Workspace, f: &EdgesFilters<'_>) -> Vec<EdgeRecord> {
    if let Some((edge_id, digest)) = f.edge_id.and_then(parse_edge_id_digest) {
        if let Some(records) = dump_persisted_edge_id(ws, f, edge_id, digest) {
            return records;
        }
    }
    // The partition visitor is exact for filtered and unfiltered reports and
    // keeps broad diagnostic dumps bounded by one compiler file relation.
    // Falling back to the resident graph is required only when the validated
    // sidecar is unavailable or corrupt.
    if let Some(records) = dump_persisted_filtered_edges(ws, f) {
        return records;
    }
    let global = ws.compiler_header_index();
    let resolved = ws.cached_resolved_call_graph();
    let mut records: Vec<EdgeRecord> = resolved
        .inner()
        .edges
        .iter()
        .filter_map(|edge| {
            let caller_decl = global.decl_of(SymbolId::new(edge.from.raw()))?;
            let callee_decl = global.decl_of(SymbolId::new(edge.to.raw()))?;
            if !edge_names_match_filters(&caller_decl.name, &callee_decl.name, f) {
                return None;
            }
            if f.edge_id.is_some_and(|id| {
                edge_id_from_names_and_span(ws, &caller_decl.name, &callee_decl.name, edge.span) != id
            }) {
                return None;
            }
            let record = edge_record_from_decls(ws, caller_decl, callee_decl, edge);
            Some(record)
        })
        .collect();
    records.sort_by(|a, b| {
        a.caller_name
            .cmp(&b.caller_name)
            .then_with(|| a.callee_name.cmp(&b.callee_name))
            .then_with(|| a.call_line.cmp(&b.call_line))
    });
    records
}

fn parse_edge_id_digest(edge_id: &str) -> Option<(&str, u32)> {
    let hex = edge_id.strip_prefix("E:")?;
    (hex.len() == 8)
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
        .map(|digest| (edge_id, digest))
}

fn dump_persisted_edge_id(
    ws: &Workspace,
    filters: &EdgesFilters<'_>,
    expected_id: &str,
    digest: u32,
) -> Option<Vec<EdgeRecord>> {
    let matches = ws.persisted_callgraph_edges_by_stable_digest(digest)?;
    let matches = matches.ok()?;
    let mut records = Vec::with_capacity(matches.len());
    for (caller, callee, edge) in matches {
        if !edge_names_match_filters(caller.name.as_ref(), callee.name.as_ref(), filters) {
            continue;
        }
        let record = edge_record_from_nodes(ws, &caller, &callee, &edge);
        if record.edge_id == expected_id {
            records.push(record);
        }
    }
    sort_edge_records(&mut records);
    Some(records)
}

fn dump_persisted_filtered_edges(ws: &Workspace, filters: &EdgesFilters<'_>) -> Option<Vec<EdgeRecord>> {
    let scan_outgoing = filters.from.is_some();
    let mut records = Vec::new();
    let mut failure = None;
    let visited = ws.visit_persisted_callgraph_partitions(|_, nodes, outgoing, incoming, _| {
        if failure.is_some() {
            return;
        }
        let edges = if scan_outgoing { outgoing } else { incoming };
        for edge in edges {
            let local_function = if scan_outgoing { edge.from } else { edge.to };
            let Some(local_node) = nodes
                .binary_search_by_key(&local_function.raw(), |node| node.func.raw())
                .ok()
                .map(|index| &nodes[index])
            else {
                failure = Some(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "callgraph partition is missing local edge endpoint {}",
                        local_function.raw()
                    ),
                ));
                return;
            };
            let local_matches = if scan_outgoing {
                filters.from.is_none_or(|needle| local_node.name.contains(needle))
            } else {
                filters.to.is_none_or(|needle| local_node.name.contains(needle))
            };
            if !local_matches {
                continue;
            }
            let remote_function = if scan_outgoing { edge.to } else { edge.from };
            let Some(remote) = ws.persisted_callgraph_node(remote_function) else {
                failure = Some(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "partitioned callgraph became unavailable during edge rendering",
                ));
                return;
            };
            let remote = match remote {
                Ok(node) => node,
                Err(error) => {
                    failure = Some(error);
                    return;
                }
            };
            let (caller, callee) = if scan_outgoing {
                (local_node, &remote)
            } else {
                (&remote, local_node)
            };
            if !edge_names_match_filters(caller.name.as_ref(), callee.name.as_ref(), filters) {
                continue;
            }
            if filters.edge_id.is_some_and(|edge_id| {
                edge_id_from_names_and_span(ws, caller.name.as_ref(), callee.name.as_ref(), edge.span)
                    != edge_id
            }) {
                continue;
            }
            let record = edge_record_from_nodes(ws, caller, callee, edge);
            records.push(record);
        }
    })?;
    if visited.is_err() || failure.is_some() {
        return None;
    }
    sort_edge_records(&mut records);
    Some(records)
}

pub(crate) fn edge_record_from_graph_nodes(
    ws: &Workspace,
    graph: &ResolvedCallGraph,
    edge: &CallEdge,
) -> Option<EdgeRecord> {
    let node = |func: FuncId| {
        graph
            .nodes()
            .binary_search_by_key(&func.raw(), |node| node.func.raw())
            .ok()
            .map(|index| &graph.nodes()[index])
    };
    let caller = node(edge.from)?;
    let callee = node(edge.to)?;
    Some(edge_record_from_nodes(ws, caller, callee, edge))
}

fn edge_record_from_nodes(
    ws: &Workspace,
    caller: &bonsai_callgraph::CallGraphNode,
    callee: &bonsai_callgraph::CallGraphNode,
    edge: &CallEdge,
) -> EdgeRecord {
    let (caller_file, caller_line, _) = format_span(&caller.name_span, ws);
    let (callee_file, callee_line, _) = format_span(&callee.name_span, ws);
    let (call_file, call_line, call_column) = format_span(&edge.span, ws);
    let call_text = call_text_for_span(ws, edge.span).unwrap_or_else(|| callee.name.as_ref().to_string());
    EdgeRecord {
        edge_id: compute_edge_id(
            caller.name.as_ref(),
            callee.name.as_ref(),
            &call_file,
            call_line,
            call_column,
        ),
        caller_name: caller.name.as_ref().to_string(),
        caller_file,
        caller_line,
        callee_name: callee.name.as_ref().to_string(),
        callee_file,
        callee_line,
        call_file,
        call_line,
        call_column,
        call_text,
        kind: edge_kind_display(edge.kind).to_string(),
        resolver_stage: edge.provenance.resolver_stage().to_string(),
        evidence: edge.provenance.evidence().to_string(),
        confidence: edge.provenance.confidence(),
    }
}

/// Compute the stable id from compact callgraph metadata before hydrating the
/// source-backed edge preview. Stable-id drilldown otherwise reads the source
/// span for every edge merely to reject all but one candidate, which turns
/// `show E:<id>` into a multi-million-source-read operation on large graphs.
fn edge_id_from_names_and_span(ws: &Workspace, caller_name: &str, callee_name: &str, span: Span) -> String {
    let (call_file, call_line, call_column) = format_span(&span, ws);
    compute_edge_id(caller_name, callee_name, &call_file, call_line, call_column)
}

fn edge_names_match_filters(caller_name: &str, callee_name: &str, filters: &EdgesFilters<'_>) -> bool {
    filters.from.is_none_or(|needle| caller_name.contains(needle))
        && filters.to.is_none_or(|needle| callee_name.contains(needle))
}

fn sort_edge_records(records: &mut [EdgeRecord]) {
    records.sort_by(|a, b| {
        a.caller_name
            .cmp(&b.caller_name)
            .then_with(|| a.callee_name.cmp(&b.callee_name))
            .then_with(|| a.call_line.cmp(&b.call_line))
    });
}

fn edge_record_from_decls(
    ws: &Workspace,
    caller_decl: &Decl,
    callee_decl: &Decl,
    edge: &CallEdge,
) -> EdgeRecord {
    let (caller_file, caller_line, _) = format_span(&caller_decl.name_span, ws);
    let (callee_file, callee_line, _) = format_span(&callee_decl.name_span, ws);
    let (call_file, call_line, call_column) = format_span(&edge.span, ws);
    EdgeRecord {
        edge_id: compute_edge_id(
            &caller_decl.name,
            &callee_decl.name,
            &call_file,
            call_line,
            call_column,
        ),
        caller_name: caller_decl.name.clone(),
        caller_file,
        caller_line,
        callee_name: callee_decl.name.clone(),
        callee_file,
        callee_line,
        call_file,
        call_line,
        call_column,
        call_text: call_text_for_edge(ws, caller_decl, edge).unwrap_or_else(|| callee_decl.name.clone()),
        kind: edge_kind_display(edge.kind).to_string(),
        resolver_stage: edge.provenance.resolver_stage().to_string(),
        evidence: edge.provenance.evidence().to_string(),
        confidence: edge.provenance.confidence(),
    }
}

fn edge_kind_display(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Direct => "direct",
        EdgeKind::Virtual => "virtual",
        EdgeKind::Indirect => "indirect",
        EdgeKind::Unknown => "unknown",
    }
}

fn call_text_for_edge(ws: &Workspace, caller_decl: &Decl, edge: &CallEdge) -> Option<String> {
    call_text_for_flow_event(&caller_decl.flow_events, edge.span)
        .or_else(|| call_text_for_span(ws, edge.span))
}

fn call_text_for_flow_event(events: &[FlowEvent], target: Span) -> Option<String> {
    for event in events {
        match event {
            FlowEvent::Call { span, name, args, .. } if spans_overlap(*span, target) => {
                return Some(render_call_preview(name, args))
            }
            FlowEvent::Assign {
                span,
                source_call: Some(name),
                source_call_args,
                ..
            } if spans_overlap(*span, target) => {
                return Some(render_assign_call_preview(name, source_call_args))
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(found) = call_text_for_flow_event(then_events, target)
                    .or_else(|| call_text_for_flow_event(else_events, target))
                {
                    return Some(found);
                }
            }
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                if let Some(found) = call_text_for_flow_event(condition_events, target)
                    .or_else(|| call_text_for_flow_event(body, target))
                    .or_else(|| call_text_for_flow_event(update_events, target))
                {
                    return Some(found);
                }
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(found) = call_text_for_flow_event(body, target) {
                    return Some(found);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(found) = call_text_for_flow_event(body, target)
                    .or_else(|| call_text_for_flow_event(catch_events, target))
                    .or_else(|| call_text_for_flow_event(finally_events, target))
                {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

fn spans_overlap(left: Span, right: Span) -> bool {
    left.file == right.file && left.start < right.end && right.start < left.end
}

fn render_call_preview(name: &str, args: &[CallArg]) -> String {
    let arg_display: Vec<String> = args
        .iter()
        .map(|arg| match arg.name.as_deref() {
            Some(keyword) => format!("{keyword}={}", arg.value_text),
            None => arg.value_text.clone(),
        })
        .collect();
    truncate_call_text(&format!("{name}({})", arg_display.join(", ")))
}

fn render_assign_call_preview(name: &str, args: &[String]) -> String {
    truncate_call_text(&format!("{name}({})", args.join(", ")))
}

fn truncate_call_text(rendered: &str) -> String {
    crate::common::truncate_at_char_boundary(rendered, 80, "...")
}

fn call_text_for_span(ws: &Workspace, span: Span) -> Option<String> {
    let snapshot = ws.db().vfs().snapshot(span.file).ok()?;
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    let text = snapshot.text.as_ref();
    if start >= end || end > text.len() || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return None;
    }
    let rendered = text[start..end].trim();
    if rendered.is_empty() {
        return None;
    }
    Some(truncate_call_text(rendered))
}

#[cfg(test)]
#[path = "edges_tests.rs"]
mod tests;
