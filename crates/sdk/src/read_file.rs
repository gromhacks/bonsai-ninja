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
    run_taint_analysis, Finding, FindingMatch, FindingStatus, Rulepack, TaintAnalysisOptions,
};
use bonsai_workspace::Workspace;
use serde::Serialize;

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
    let path = filters.path;
    let file_id = ws
        .vfs()
        .all_files()
        .into_iter()
        .find(|fid| {
            ws.vfs()
                .path(*fid)
                .ok()
                .map(|p| p.display().to_string())
                .is_some_and(|s| s == path || s.ends_with(path))
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

    let report = match rulepack {
        Some(pack) => run_taint_analysis(ws, pack, TaintAnalysisOptions::default()).ok(),
        None => None,
    };

    let mut finding_ids: Vec<String> = Vec::new();
    let mut flow_ids: Vec<String> = Vec::new();
    let mut marks: Vec<LineMark> = Vec::new();
    let mut flows_in_view: Vec<FlowEntryExit> = Vec::new();
    let mut findings_in_view: Vec<FindingDigest> = Vec::new();

    if let Some(rep) = report.as_ref() {
        for cf in &rep.findings {
            let f = &cf.finding;
            let in_source =
                f.source.file == raw_path && f.source.line >= line_lo && f.source.line <= actual_hi;
            let in_sink = f.sink.file == raw_path && f.sink.line >= line_lo && f.sink.line <= actual_hi;
            if !in_source && !in_sink {
                continue;
            }
            finding_ids.push(f.finding_id.clone());
            if let Some(fid) = &f.representative_flow_id {
                flow_ids.push(fid.clone());
                flows_in_view.push(FlowEntryExit {
                    flow_id: fid.clone(),
                    finding_id: Some(f.finding_id.clone()),
                    enters_at: match_to_locator(&f.source),
                    exits_at: match_to_locator(&f.sink),
                    extends_beyond_view: !(in_source && in_sink),
                });
            }
            if in_source {
                marks.push(make_mark(MarkKind::Source, f, &f.source));
            }
            if in_sink {
                marks.push(make_mark(MarkKind::Sink, f, &f.sink));
            }
            for sm in &f.sanitizers_seen {
                if sm.file == raw_path && sm.line >= line_lo && sm.line <= actual_hi {
                    marks.push(make_mark(MarkKind::Sanitizer, f, sm));
                }
            }
            findings_in_view.push(build_finding_digest(f, &raw_path, line_lo, actual_hi));
        }
    }
    finding_ids.sort();
    finding_ids.dedup();
    flow_ids.sort();
    flow_ids.dedup();
    marks.sort_by_key(|m| m.line);

    // Cross-file callers / callees for this file's decls.
    let resolved = ws.resolved_call_graph();
    let global = ws.db().global_index();
    let file_funcs: Vec<FuncId> = global
        .decls_in(file_id)
        .iter()
        .map(|d| FuncId::new(d.symbol.raw()))
        .collect();
    drop(global);
    let mut callers_in: Vec<InlinedDecl> = Vec::new();
    let mut callees_out: Vec<InlinedDecl> = Vec::new();
    for func in &file_funcs {
        for caller_edge in resolved.callers_of(*func) {
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
        for callee_edge in resolved.callees_of(*func) {
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

    let max_bodies = filters.max_inlined_bodies.unwrap_or(8);
    let raw_callers = callers_in.len();
    let raw_callees = callees_out.len();
    callers_in.truncate(max_bodies);
    callees_out.truncate(max_bodies);

    // Body inlining: read the snapshot for the cross-file decl and
    // slice its body span. Best-effort; on failure we leave source
    // empty and the renderer falls back to header-only.
    for decl in callers_in.iter_mut().chain(callees_out.iter_mut()) {
        if decl.locator.file == "external" {
            continue;
        }
        if let Some(text) = read_decl_body(&decl.locator, ws) {
            decl.source = text;
        }
    }

    // Build a line_decl_index from the file's decls.
    let global = ws.db().global_index();
    let line_decl_index: Vec<LineDeclSpan> = global
        .decls_in(file_id)
        .iter()
        .map(|d| {
            let loc = Locator::from_span(d.span, ws);
            let span_map = bonsai_common::cached_span_map(file_id, snapshot.version, snapshot.text.as_ref());
            let start = span_map.line_col(d.span.start).line;
            let end = span_map.line_col(d.span.end).line;
            LineDeclSpan {
                line_start: start,
                line_end: end,
                locator: loc,
            }
        })
        .collect();
    drop(global);

    let primary_locator = Locator {
        file: raw_path.clone(),
        line: line_lo,
        column: 1,
        language,
        ..Locator::default()
    };

    Ok(ReadFileOut {
        locator: primary_locator,
        lines_total: total_lines,
        indexed: IndexedStatus::Complete,
        finding_ids,
        flow_ids,
        flows_in_view,
        source: source_slice,
        line_decl_index,
        marks,
        callers_in,
        callees_out,
        findings_in_view,
        truncated: ReadFileTruncation {
            bodies_dropped: 0,
            marks_dropped: 0,
            callers_dropped: raw_callers.saturating_sub(max_bodies),
            callees_dropped: raw_callees.saturating_sub(max_bodies),
        },
        page_cursor: None,
    })
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

fn make_mark(kind: MarkKind, f: &Finding, m: &FindingMatch) -> LineMark {
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
        flow_id: f.representative_flow_id.clone(),
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

fn build_finding_digest(f: &Finding, file: &str, line_lo: u32, line_hi: u32) -> FindingDigest {
    let _ = (file, line_lo, line_hi);
    let drill = format!(
        "bonsai-ninja read-file <ws> {} --lines {}:{} --no-compact{}",
        f.sink.file,
        f.sink.line.saturating_sub(2).max(1),
        f.sink.line.saturating_add(5),
        f.representative_flow_id
            .as_deref()
            .map(|fid| format!(" --from {fid}"))
            .unwrap_or_default()
    );
    FindingDigest {
        finding_id: f.finding_id.clone(),
        rule_id: f.sink.rule_id.clone(),
        tag: f.tag.clone().unwrap_or_default(),
        severity: f.severity.unwrap_or(Severity::Info),
        status: f.status,
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
    let global = ws.db().global_index();
    let symbol = SymbolId::new(func.raw());
    let Some(decl) = global.decl_of(symbol) else {
        return Locator::external(format!("FuncId({})", func.raw()));
    };
    Locator::from_span(decl.span, ws)
}

fn read_decl_body(loc: &Locator, ws: &Workspace) -> Option<String> {
    let global = ws.db().global_index();
    // Find file id by path match.
    let file_id = ws.vfs().all_files().into_iter().find(|fid| {
        ws.vfs()
            .path(*fid)
            .ok()
            .map(|p| p.display().to_string() == loc.file)
            .unwrap_or(false)
    })?;
    let snap = ws.vfs().snapshot(file_id).ok()?;
    // Find decl by name + line.
    for decl in global.decls_in(file_id) {
        if loc.decl.as_deref() == Some(decl.name.as_str()) {
            let start = decl.span.start as usize;
            let end = (decl.span.end as usize).min(snap.text.len());
            if start <= end {
                return Some(snap.text[start..end].to_string());
            }
        }
    }
    None
}
