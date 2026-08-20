//! `bonsai-ninja dump-edges` data layer.
//!
//! One [`EdgeRecord`] per resolved call edge in the workspace.
//! This is a renderer over [`bonsai_callgraph::ResolvedCallGraph`],
//! not a second resolver. Keeping one semantic source of truth prevents
//! debug output from over-fanning or drifting from inspect/export/taint.

use crate::common::format_span;
use bonsai_callgraph::{CallEdge, EdgeKind, ResolvedCallGraph};
use bonsai_common::{FuncId, Span, SymbolId};
use bonsai_hash::fnv1a_names_low32;
use bonsai_lang_api::{CallArg, Decl, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Stable, library-level mirror of `bonsai_common::Precision`.
/// Filtering across the FFI boundary uses this enum so frontends
/// don't need to depend on `bonsai_common` directly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrecisionClass {
    Exact,
    Narrowed,
    OverApproximate,
    Unknown,
}

impl PrecisionClass {
    /// Parse the public string form (`"exact"` / `"narrowed"` /
    /// `"over-approximate"` / `"unknown"`) back to the enum.
    /// Unknown spellings map to [`Self::Unknown`] so a caller can
    /// stay open-ended without unwrapping.
    #[must_use]
    pub fn from_label(s: &str) -> Self {
        match s {
            "exact" => Self::Exact,
            "narrowed" => Self::Narrowed,
            "over-approximate" => Self::OverApproximate,
            _ => Self::Unknown,
        }
    }
    /// Compare an external [`PrecisionClass`] filter against the
    /// internal [`bonsai_common::Precision`] tag carried on every
    /// resolved edge. Public analysis surfaces are semantic-only, so
    /// diagnostic broad classes never match.
    pub fn matches(self, precision: bonsai_common::Precision) -> bool {
        use bonsai_common::Precision;
        matches!(
            (self, precision),
            (Self::Exact, Precision::Exact) | (Self::Narrowed, Precision::Narrowed)
        )
    }
}

/// Filter bundle for [`dump_edges`]. Match-anywhere semantics on
/// `from`/`to`; an `edge_id` filter narrows to a single edge.
#[derive(Copy, Clone, Default, Debug)]
pub struct EdgesFilters<'a> {
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub precision: Option<PrecisionClass>,
    pub edge_id: Option<&'a str>,
}

/// One resolved call edge. `call_*` fields point at the resolved
/// call-site span; `caller_*` / `callee_*` point at the
/// decl name spans. `kind` is `direct` / `virtual`; `precision` is
/// `exact` / `narrowed` on public surfaces. Diagnostic-only internal
/// classes are not emitted by default analysis/export commands.
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
    pub precision: String,
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
    let call_site_token = format!("{call_file}:{call_line}:{call_column}");
    let tokens = [caller_name.to_string(), callee_name.to_string(), call_site_token];
    format!("E:{:08x}", fnv1a_names_low32(&tokens))
}

/// Collect matching resolved call edges in the workspace. Cheap filters over
/// compiler symbols are applied before an [`EdgeRecord`] allocates rendered
/// paths, snippets, provenance strings, and ids. This matters on multi-million
/// edge workspaces: a selective query remains proportional in allocations to
/// its result set even though exact coverage still examines every candidate
/// edge.
pub fn dump_edges(ws: &Workspace, f: &EdgesFilters<'_>) -> Vec<EdgeRecord> {
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
            if !edge.precision.is_semantic()
                || f.precision
                    .is_some_and(|precision| !precision.matches(edge.precision))
            {
                return None;
            }
            let caller_decl = global.decl_of(SymbolId::new(edge.from.raw()))?;
            let callee_decl = global.decl_of(SymbolId::new(edge.to.raw()))?;
            if !edge_names_match_filters(&caller_decl.name, &callee_decl.name, f) {
                return None;
            }
            let record = edge_record_from_decls(ws, caller_decl, callee_decl, edge);
            f.edge_id.is_none_or(|id| record.edge_id == id).then_some(record)
        })
        .collect();
    records.sort_by(|a, b| {
        precision_sort_key(&a.precision)
            .cmp(&precision_sort_key(&b.precision))
            .then_with(|| a.caller_name.cmp(&b.caller_name))
            .then_with(|| a.callee_name.cmp(&b.callee_name))
            .then_with(|| a.call_line.cmp(&b.call_line))
    });
    records
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
            if !edge.precision.is_semantic()
                || filters
                    .precision
                    .is_some_and(|precision| !precision.matches(edge.precision))
            {
                continue;
            }
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
            let record = edge_record_from_nodes(ws, caller, callee, edge);
            if filters.edge_id.is_none_or(|edge_id| edge_id == record.edge_id) {
                records.push(record);
            }
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
        precision: precision_display(edge.precision).to_string(),
        resolver_stage: edge.provenance.resolver_stage().to_string(),
        evidence: edge.provenance.evidence().to_string(),
        confidence: edge.provenance.confidence(),
    }
}

fn edge_names_match_filters(caller_name: &str, callee_name: &str, filters: &EdgesFilters<'_>) -> bool {
    filters.from.is_none_or(|needle| caller_name.contains(needle))
        && filters.to.is_none_or(|needle| callee_name.contains(needle))
}

fn sort_edge_records(records: &mut [EdgeRecord]) {
    records.sort_by(|a, b| {
        precision_sort_key(&a.precision)
            .cmp(&precision_sort_key(&b.precision))
            .then_with(|| a.caller_name.cmp(&b.caller_name))
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
        precision: precision_display(edge.precision).to_string(),
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

fn precision_display(precision: bonsai_common::Precision) -> &'static str {
    match precision {
        bonsai_common::Precision::Exact => "exact",
        bonsai_common::Precision::Narrowed => "narrowed",
        bonsai_common::Precision::OverApproximate => "over-approximate",
        bonsai_common::Precision::Unknown => "unknown",
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
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
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

/// Lower number = weaker precision; semantic edges still sort
/// deterministically, and broad classes stay listed for stable
/// ordering if older sidecars surface them internally.
fn precision_sort_key(precision: &str) -> u8 {
    match precision {
        "unknown" => 0,
        "over-approximate" => 1,
        "narrowed" => 2,
        "exact" => 3,
        _ => 4,
    }
}

#[cfg(test)]
#[path = "edges_tests.rs"]
mod tests;
