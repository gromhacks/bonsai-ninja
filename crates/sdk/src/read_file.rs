//! `read-file` — single-file connected-content view (SDK aggregator).
//!
//! Reads a workspace file and overlays the analysis facts that
//! touch its lines: which decls cover each line, which calls /
//! cross-file edges live there, which `S:` finding the line
//! participates in, the flow's entry/exit, and the cross-file
//! callers/callees of the file (with body slices when within
//! budget). Lives in `bonsai_sdk` because it aggregates across
//! browse + security + callgraph data.

use bonsai_browse::Locator;
use bonsai_common::{FuncId, SymbolId};
use bonsai_security::rule::Severity;
use bonsai_security::{
    run_taint_analysis, CombinedFindingWithChain, Finding, FindingMatch, FindingStatus, Rulepack,
    TaintAnalysisOptions,
};
use bonsai_workspace::Workspace;
use serde::Serialize;
use std::path::Path;

use crate::tree::{CrossEdge, IndexedStatus};

#[derive(Clone, Debug, Default)]
pub struct ReadFileFilters<'a> {
    pub path: &'a str,
    pub line_range: Option<(u32, u32)>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub max_inlined_bodies: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReadFileOut {
    pub locator: Locator,
    pub lines_total: u32,
    pub indexed: IndexedStatus,
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flows_in_view: Vec<FlowEntryExit>,
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_decl_index: Vec<LineDeclSpan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub marks: Vec<LineMark>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers_in: Vec<InlinedDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees_out: Vec<InlinedDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings_in_view: Vec<FindingDigest>,
    pub truncated: ReadFileTruncation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ReadFileTruncation {
    pub bodies_dropped: usize,
    pub marks_dropped: usize,
    pub callers_dropped: usize,
    pub callees_dropped: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlowEntryExit {
    pub flow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    pub enters_at: Locator,
    pub exits_at: Locator,
    pub extends_beyond_view: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LineDeclSpan {
    pub line_start: u32,
    pub line_end: u32,
    pub locator: Locator,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkKind {
    Source,
    Sink,
    Sanitizer,
    Through,
    CallOut,
    CallIn,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowRole {
    Source,
    Through,
    Sink,
}

#[derive(Clone, Debug, Serialize)]
pub struct LineMark {
    pub line: u32,
    pub kind: MarkKind,
    pub at: Locator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Locator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<FindingStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint_source_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_history: Vec<TaintHop>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitizer_seen_at: Option<Locator>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TaintHop {
    pub locator: Locator,
    pub event: String,
    pub flow_role: FlowRole,
}

#[derive(Clone, Debug, Serialize)]
pub struct InlinedDecl {
    pub locator: Locator,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridges_to: Option<Locator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers_in: Vec<CrossEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees_out: Vec<CrossEdge>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FindingDigest {
    pub finding_id: String,
    pub rule_id: String,
    pub tag: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
    pub source: Locator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_trust: Option<String>,
    pub sink: Locator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    pub drilldown: String,
}

/// Build the read-file view. When a rulepack is configured on the
/// workspace, runs `taint_analysis` to populate finding/flow data
/// for the requested file. Without one, marks/findings are empty.
pub fn read_file(
    ws: &Workspace,
    rulepack: Option<&Rulepack>,
    filters: &ReadFileFilters<'_>,
) -> anyhow::Result<ReadFileOut> {
    read_file_with_taint_options(
        ws,
        rulepack,
        filters,
        semantic_read_file_taint_options(Default::default()),
    )
}

fn read_file_with_taint_options(
    ws: &Workspace,
    rulepack: Option<&Rulepack>,
    filters: &ReadFileFilters<'_>,
    taint_options: TaintAnalysisOptions,
) -> anyhow::Result<ReadFileOut> {
    let path = filters.path;
    let file_id = ws
        .vfs()
        .all_files()
        .into_iter()
        .find(|fid| {
            ws.vfs()
                .path(*fid)
                .ok()
                .is_some_and(|p| file_path_matches_requested(ws, &p.display().to_string(), path))
        })
        .ok_or_else(|| anyhow::anyhow!("file not found in workspace: {path}"))?;

    let snapshot = ws
        .vfs()
        .snapshot(file_id)
        .map_err(|e| anyhow::anyhow!("vfs snapshot for {path}: {e}"))?;
    let raw_path = ws
        .vfs()
        .path(file_id)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.to_string());

    let language = ws
        .db()
        .adapter_for(file_id)
        .map(|a| a.language_id().as_str().to_string());

    let (line_lo, line_hi) = filters.line_range.unwrap_or((1, u32::MAX));
    let total_lines = snapshot.text.lines().count() as u32;
    let actual_hi = line_hi.min(total_lines);

    let source_slice: String = snapshot
        .text
        .lines()
        .enumerate()
        .filter(|(idx, _)| {
            let line_no = (*idx as u32) + 1;
            line_no >= line_lo && line_no <= actual_hi
        })
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");

    let taint_options = semantic_read_file_taint_options(taint_options);
    let report = match rulepack {
        Some(pack) => Some(run_taint_analysis(ws, pack, taint_options)?),
        None => None,
    };

    let mut finding_ids: Vec<String> = Vec::new();
    let mut flow_ids: Vec<String> = Vec::new();
    let mut marks: Vec<LineMark> = Vec::new();
    let mut flows_in_view: Vec<FlowEntryExit> = Vec::new();
    let mut findings_in_view: Vec<FindingDigest> = Vec::new();
    let mut finding_incomplete_reasons: Vec<String> = Vec::new();

    if let Some(rep) = report.as_ref() {
        for cf in &rep.findings {
            if !combined_finding_matches_filters(cf, filters.from, filters.to) {
                continue;
            }
            let f = &cf.finding;
            let in_sink = f.sink.file == raw_path && f.sink.line >= line_lo && f.sink.line <= actual_hi;
            let source_in_view = |source: &FindingMatch| {
                source.file == raw_path && source.line >= line_lo && source.line <= actual_hi
            };
            let visible_routes = f
                .flows()
                .filter(|flow| in_sink || source_in_view(flow.source))
                .collect::<Vec<_>>();
            if visible_routes.is_empty() {
                continue;
            }
            finding_incomplete_reasons.extend(finding_analysis_incomplete_reasons(f));
            finding_ids.push(f.finding_id.clone());
            for route in visible_routes {
                let route_source_in_view = source_in_view(route.source);
                if let Some(flow_id) = route.flow_id {
                    flow_ids.push(flow_id.to_string());
                    flows_in_view.push(FlowEntryExit {
                        flow_id: flow_id.to_string(),
                        finding_id: Some(f.finding_id.clone()),
                        enters_at: match_to_locator(route.source),
                        exits_at: match_to_locator(&f.sink),
                        extends_beyond_view: !(route_source_in_view && in_sink),
                    });
                }
                if route_source_in_view {
                    marks.push(make_mark_for_flow(
                        MarkKind::Source,
                        f,
                        route.source,
                        route.flow_id,
                    ));
                }
                if in_sink {
                    let mut route_sink = f.sink.clone();
                    route_sink.tainted_args = route.sink_tainted_args.to_vec();
                    marks.push(make_mark_for_flow(MarkKind::Sink, f, &route_sink, route.flow_id));
                }
                for sanitizer in route.sanitizers_seen {
                    if source_in_view(sanitizer) {
                        marks.push(make_mark_for_flow(
                            MarkKind::Sanitizer,
                            f,
                            sanitizer,
                            route.flow_id,
                        ));
                    }
                }
            }
            findings_in_view.push(build_finding_digest(f));
        }
    }
    finding_ids.sort();
    finding_ids.dedup();
    flow_ids.sort();
    flow_ids.dedup();
    marks.sort_by_key(|m| m.line);

    // Cross-file callers / callees for this file's decls.
    let resolved = ws.cached_resolved_call_graph();
    let global = ws.compiler_linkage_index();
    let file_funcs: Vec<FuncId> = global
        .decls_in(file_id)
        .iter()
        .map(|d| FuncId::new(d.symbol.raw()))
        .collect();
    drop(global);
    let mut callers_in: Vec<InlinedDecl> = Vec::new();
    let mut callees_out: Vec<InlinedDecl> = Vec::new();
    for func in &file_funcs {
        for caller_edge in resolved
            .callers_of(*func)
            .filter(|edge| edge.precision.is_semantic())
        {
            let caller_loc = func_to_locator(caller_edge.from, ws);
            if caller_loc.file == raw_path {
                continue;
            }
            callers_in.push(InlinedDecl {
                locator: caller_loc,
                source: String::new(),
                flow_id: None,
                edge_id: None,
                bridges_to: None,
                callers_in: Vec::new(),
                callees_out: Vec::new(),
            });
        }
        for callee_edge in resolved
            .callees_of(*func)
            .filter(|edge| edge.precision.is_semantic())
        {
            let callee_loc = func_to_locator(callee_edge.to, ws);
            if callee_loc.file == raw_path {
                continue;
            }
            callees_out.push(InlinedDecl {
                locator: callee_loc,
                source: String::new(),
                flow_id: None,
                edge_id: None,
                bridges_to: None,
                callers_in: Vec::new(),
                callees_out: Vec::new(),
            });
        }
    }
    dedupe_inlined_decls(&mut callers_in);
    dedupe_inlined_decls(&mut callees_out);

    let max_bodies = effective_max_inlined_bodies(filters.max_inlined_bodies);
    let raw_callers = callers_in.len();
    let raw_callees = callees_out.len();
    callers_in.truncate(max_bodies);
    callees_out.truncate(max_bodies);

    // Body inlining: read the snapshot for the cross-file decl and
    // slice its body span. Best-effort; on failure we leave source
    // empty and the renderer falls back to header-only.
    let mut bodies_dropped = 0usize;
    for decl in callers_in.iter_mut().chain(callees_out.iter_mut()) {
        if decl.locator.file == "external" {
            bodies_dropped += 1;
            continue;
        }
        if let Some(text) = read_decl_body(&decl.locator, ws) {
            decl.source = text;
        } else {
            bodies_dropped += 1;
        }
    }

    // Build a line_decl_index from the file's decls.
    let local_decls = ws
        .exact_decl_index_shared(file_id)
        .ok_or_else(|| anyhow::anyhow!("compiler declarations unavailable for {path}"))?;
    let line_decl_index: Vec<LineDeclSpan> = local_decls
        .defs
        .iter()
        .map(|d| {
            let loc = Locator::from_span(d.span, ws);
            let span_map = bonsai_common::cached_span_map_arc(file_id, snapshot.version, &snapshot.text);
            let start = span_map.line_col(d.span.start).line;
            let end = span_map.line_col(d.span.end).line;
            LineDeclSpan {
                line_start: start,
                line_end: end,
                locator: loc,
            }
        })
        .collect();
    drop(local_decls);

    let primary_locator = Locator {
        file: raw_path.clone(),
        line: line_lo,
        column: 1,
        language,
        ..Locator::default()
    };
    let truncated = ReadFileTruncation {
        bodies_dropped,
        marks_dropped: 0,
        callers_dropped: raw_callers.saturating_sub(max_bodies),
        callees_dropped: raw_callees.saturating_sub(max_bodies),
    };
    let mut analysis_incomplete_reasons = read_file_analysis_incomplete_reasons(&truncated);
    analysis_incomplete_reasons.extend(finding_incomplete_reasons);
    analysis_incomplete_reasons.sort();
    analysis_incomplete_reasons.dedup();
    let analysis_complete = analysis_incomplete_reasons.is_empty();

    Ok(ReadFileOut {
        locator: primary_locator,
        lines_total: total_lines,
        indexed: IndexedStatus::Complete,
        analysis_complete,
        analysis_incomplete_reasons,
        finding_ids,
        flow_ids,
        flows_in_view,
        source: source_slice,
        line_decl_index,
        marks,
        callers_in,
        callees_out,
        findings_in_view,
        truncated,
        page_cursor: None,
    })
}

fn semantic_read_file_taint_options(options: TaintAnalysisOptions) -> TaintAnalysisOptions {
    options.semantic_precision_only()
}

fn effective_max_inlined_bodies(max_inlined_bodies: Option<usize>) -> usize {
    match max_inlined_bodies {
        Some(0) => usize::MAX,
        Some(limit) => limit,
        None => 8,
    }
}

fn read_file_analysis_incomplete_reasons(truncated: &ReadFileTruncation) -> Vec<String> {
    let mut reasons = Vec::new();
    if truncated.callers_dropped > 0 || truncated.callees_dropped > 0 {
        reasons.push(format!(
            "inlined-bodies-truncated:callers_dropped={},callees_dropped={}",
            truncated.callers_dropped, truncated.callees_dropped
        ));
    }
    if truncated.bodies_dropped > 0 {
        reasons.push(format!(
            "inlined-bodies-unavailable:bodies_dropped={}",
            truncated.bodies_dropped
        ));
    }
    if truncated.marks_dropped > 0 {
        reasons.push(format!(
            "marks-truncated:marks_dropped={}",
            truncated.marks_dropped
        ));
    }
    reasons
}

fn finding_analysis_incomplete_reasons(finding: &Finding) -> Vec<String> {
    if finding.analysis_complete {
        return Vec::new();
    }
    if finding.analysis_incomplete_reasons.is_empty() {
        return vec![format!("finding:{}:analysis-incomplete", finding.finding_id)];
    }
    finding
        .analysis_incomplete_reasons
        .iter()
        .map(|reason| format!("finding:{}:{reason}", finding.finding_id))
        .collect()
}

fn combined_finding_matches_filters(
    finding: &CombinedFindingWithChain,
    from: Option<&str>,
    to: Option<&str>,
) -> bool {
    from.is_none_or(|needle| finding_source_side_matches(finding, needle))
        && to.is_none_or(|needle| finding_sink_side_matches(finding, needle))
}

fn finding_source_side_matches(finding: &CombinedFindingWithChain, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    finding
        .additional_sources
        .iter()
        .any(|source| match_site_matches_needle(source, needle))
        || finding.finding.flows().any(|flow| {
            match_site_matches_needle(flow.source, needle)
                || flow
                    .chain_display
                    .first()
                    .is_some_and(|name| text_matches_needle(name, needle))
                || flow
                    .taint_path
                    .iter()
                    .any(|step| text_matches_needle(&step.caller, needle))
        })
}

fn finding_sink_side_matches(finding: &CombinedFindingWithChain, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    match_site_matches_needle(&finding.finding.sink, needle)
        || finding
            .additional_sinks
            .iter()
            .any(|sink| match_site_matches_needle(sink, needle))
        || finding.finding.flows().any(|flow| {
            flow.chain_display
                .last()
                .is_some_and(|name| text_matches_needle(name, needle))
                || flow
                    .taint_path
                    .iter()
                    .any(|step| text_matches_needle(&step.callee, needle))
        })
}

fn match_site_matches_needle(site: &FindingMatch, needle: &str) -> bool {
    text_matches_needle(&site.rule_id, needle)
        || text_matches_needle(&site.file, needle)
        || text_matches_needle(&site.text, needle)
        || site
            .enclosing_fn
            .as_deref()
            .is_some_and(|value| text_matches_needle(value, needle))
        || site
            .tag
            .as_deref()
            .is_some_and(|value| text_matches_needle(value, needle))
        || site
            .category
            .as_deref()
            .is_some_and(|value| text_matches_needle(value, needle))
        || site
            .trust
            .as_deref()
            .is_some_and(|value| text_matches_needle(value, needle))
        || site
            .payload_types
            .iter()
            .any(|value| text_matches_needle(value, needle))
        || site
            .tainted_args
            .iter()
            .any(|arg| text_matches_needle(&arg.value_text, needle))
}

fn text_matches_needle(value: &str, needle: &str) -> bool {
    value.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn file_path_matches_requested(ws: &Workspace, file_path: &str, requested: &str) -> bool {
    let requested = normalize_locator_path(requested);
    if requested.is_empty() {
        return false;
    }
    let file_path = normalize_locator_path(file_path);
    if file_path == requested {
        return true;
    }
    let relative = workspace_relative_locator_path(ws, &file_path);
    if relative == requested {
        return true;
    }
    !Path::new(&requested).is_absolute() && file_path.ends_with(&format!("/{requested}"))
}

fn workspace_relative_locator_path(ws: &Workspace, path: &str) -> String {
    let Some(root) = ws.db().workspace_root() else {
        return normalize_locator_path(path);
    };
    if let Ok(relative) = Path::new(path).strip_prefix(&root) {
        return normalize_locator_path(&relative.to_string_lossy());
    }
    let path = normalize_locator_path(path);
    let root = normalize_locator_path(&root.to_string_lossy());
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return path;
    }
    if path == root {
        return String::new();
    }
    path.strip_prefix(&format!("{root}/"))
        .map(ToOwned::to_owned)
        .unwrap_or(path)
}

fn normalize_locator_path(value: &str) -> String {
    value.replace('\\', "/").trim_start_matches("./").to_string()
}

fn dedupe_inlined_decls(decls: &mut Vec<InlinedDecl>) {
    let mut seen = std::collections::HashSet::new();
    decls.retain(|decl| {
        seen.insert((
            decl.locator.file.clone(),
            decl.locator.line,
            decl.locator.column,
            decl.locator.decl.clone(),
        ))
    });
}

fn make_mark_for_flow(kind: MarkKind, f: &Finding, m: &FindingMatch, flow_id: Option<&str>) -> LineMark {
    LineMark {
        line: m.line,
        kind,
        at: Locator {
            file: m.file.clone(),
            line: m.line,
            column: m.column,
            decl: m.enclosing_fn.clone(),
            ..Locator::default()
        },
        target: None,
        finding_id: Some(f.finding_id.clone()),
        flow_id: flow_id.map(str::to_owned),
        edge_id: None,
        taint_id: None,
        rule_id: Some(m.rule_id.clone()),
        tag: m.tag.clone(),
        severity: m.severity,
        status: Some(f.status),
        taint_source_name: m.tainted_args.first().map(|t| t.value_text.clone()),
        taint_history: Vec::new(),
        sanitizer_seen_at: None,
    }
}

fn build_finding_digest(f: &Finding) -> FindingDigest {
    let drill = f.representative_flow_id.as_deref().map_or_else(
        || {
            format!(
                "bonsai-ninja read-file <ws> {} --lines {}:{}",
                f.sink.file,
                f.sink.line.saturating_sub(2).max(1),
                f.sink.line.saturating_add(5),
            )
        },
        |flow_id| format!("bonsai-ninja show <ws> {flow_id}"),
    );
    FindingDigest {
        finding_id: f.finding_id.clone(),
        rule_id: f.sink.rule_id.clone(),
        tag: f.tag.clone().unwrap_or_default(),
        severity: f.severity.unwrap_or(Severity::Info),
        status: f.status,
        analysis_complete: f.analysis_complete,
        analysis_incomplete_reasons: f.analysis_incomplete_reasons.clone(),
        source: match_to_locator(&f.source),
        source_trust: f.source.trust.clone(),
        sink: match_to_locator(&f.sink),
        remediation: None,
        drilldown: drill,
    }
}

fn match_to_locator(m: &FindingMatch) -> Locator {
    Locator {
        file: m.file.clone(),
        line: m.line,
        column: m.column,
        decl: m.enclosing_fn.clone(),
        ..Locator::default()
    }
}

fn func_to_locator(func: FuncId, ws: &Workspace) -> Locator {
    let global = ws.compiler_linkage_index();
    let symbol = SymbolId::new(func.raw());
    let Some(decl) = global.decl_of(symbol) else {
        return Locator::external(format!("FuncId({})", func.raw()));
    };
    Locator::from_span(decl.span, ws)
}

#[cfg(test)]
#[path = "read_file_tests.rs"]
mod tests;

fn read_decl_body(loc: &Locator, ws: &Workspace) -> Option<String> {
    // Find file id by path match.
    let file_id = ws.vfs().all_files().into_iter().find(|fid| {
        ws.vfs()
            .path(*fid)
            .ok()
            .map(|p| p.display().to_string() == loc.file)
            .unwrap_or(false)
    })?;
    let snap = ws.vfs().snapshot(file_id).ok()?;
    let local_decls = ws.exact_decl_index_shared(file_id)?;
    // Find decl by name + line.
    for decl in &local_decls.defs {
        if loc.decl.as_deref() == Some(decl.name.as_str()) {
            let start = decl.span.start as usize;
            let end = (decl.span.end as usize).min(snap.text.len());
            // `start`/`end` are raw byte offsets and `end` is clamped to the
            // (possibly newer) snapshot length, so neither is guaranteed to
            // land on a UTF-8 char boundary. Use `get` rather than slicing to
            // avoid panicking on files with multibyte chars; a boundary miss
            // just falls through to the next decl / `None`.
            if start <= end {
                if let Some(body) = snap.text.get(start..end) {
                    return Some(body.to_string());
                }
            }
        }
    }
    None
}
