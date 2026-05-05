//! `tree` — workspace navigation surface (SDK aggregator).
//!
//! Composes browse facts (`bonsai_browse::Locator`) with security
//! findings (`bonsai_security::run_taint_analysis`) and the
//! resolved call graph to render a hierarchical view where every
//! file row carries its connections: finding ids, flow ids, the
//! most-severe flow's entry/exit, and cross-file caller/callee
//! edges. Directory rows aggregate severity counts up the tree.
//!
//! Lives in `bonsai_sdk` (not `bonsai_browse`) because it's an
//! aggregator across both browse + security data — the SDK facade
//! is the architectural home for cross-service surfaces per
//! `docs/contributing/architecture.mdx`.

use ahash::AHashMap;
use bonsai_browse::Locator;
use bonsai_callgraph::EdgeKind;
use bonsai_common::{FuncId, Precision, SymbolId};
use bonsai_security::rule::Severity;
use bonsai_security::{run_taint_analysis, Finding, FindingMatch, Rulepack, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use serde::Serialize;

#[derive(Clone, Debug, Default)]
pub struct TreeFilters<'a> {
    pub max_depth: Option<usize>,
    pub file: Option<&'a str>,
    pub exclude_files: &'a [String],
    pub severity: Option<Severity>,
    pub limit: usize,
    pub follow: usize,
    pub max_finding_ids_per_file: Option<usize>,
    pub max_flow_ids_per_file: Option<usize>,
    pub max_cross_file_edges_per_file: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TreeOut {
    pub roots: Vec<TreeNode>,
    pub summary: TreeSummary,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TreeSummary {
    pub total_files: usize,
    /// Total files seen by the underlying scan, regardless of
    /// `--max-depth` truncation. `total_files` only counts files
    /// that survived the depth limit and made it into the rendered
    /// tree, so on a `--max-depth 3` walk of a `crates/X/src/lib.rs`
    /// layout `total_files` is `0`. Renderers should surface this
    /// when it differs from `total_files` so users don't see
    /// "0 files" and assume the workspace is empty.
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub total_files_scanned: usize,
    pub total_dirs: usize,
    pub total_findings: usize,
    pub severity_counts: SeverityHistogram,
    pub indexed_complete: usize,
    pub indexed_stale: usize,
    pub indexed_missing: usize,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde `skip_serializing_if` callback signature
fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Dir,
    File,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SeverityHistogram {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityHistogram {
    fn add(&mut self, sev: Option<Severity>) {
        match sev {
            Some(Severity::Critical) => self.critical += 1,
            Some(Severity::High) => self.high += 1,
            Some(Severity::Medium) => self.medium += 1,
            Some(Severity::Low) => self.low += 1,
            Some(Severity::Info) => self.info += 1,
            None => {}
        }
    }

    fn merge(&mut self, other: &Self) {
        self.critical += other.critical;
        self.high += other.high;
        self.medium += other.medium;
        self.low += other.low;
        self.info += other.info;
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    fn max(&self) -> Option<Severity> {
        if self.critical > 0 {
            Some(Severity::Critical)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else if self.info > 0 {
            Some(Severity::Info)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TreeNode {
    pub kind: NodeKind,
    pub name: String,
    pub locator: Locator,
    pub depth: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "is_zero_histogram")]
    pub finding_severity_counts: SeverityHistogram,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_file_callers_in: Vec<CrossEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_file_callees_out: Vec<CrossEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub most_severe_flow: Option<MostSevereFlowSummary>,
    pub indexed: IndexedStatus,
    pub render_priority: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<TreeNode>,
    pub truncated: TreeTruncation,
}

fn is_zero_histogram(h: &SeverityHistogram) -> bool {
    h.total() == 0
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TreeTruncation {
    pub children_dropped: usize,
    pub finding_ids_dropped: usize,
    pub flow_ids_dropped: usize,
    pub callers_in_dropped: usize,
    pub callees_out_dropped: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CrossEdge {
    pub caller: Locator,
    pub callee: Locator,
    pub call_site: Locator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    pub precision: Precision,
    pub edge_kind: EdgeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<ExternalKind>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalKind {
    Stdlib,
    ThirdParty,
    Ffi,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexedStatus {
    Complete,
    Stale,
    Missing,
}

impl Default for IndexedStatus {
    fn default() -> Self {
        IndexedStatus::Complete
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MostSevereFlowSummary {
    pub flow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    pub severity: Severity,
    pub enters_at: Locator,
    pub exits_at: Locator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_display: Vec<String>,
    pub extends_beyond_workspace: bool,
}

/// Build the tree view. When a rulepack is configured on the
/// workspace, runs `taint_analysis` to populate finding/flow data.
/// Without one, severity counts are zero and `most_severe_flow` is
/// `None` everywhere — same graceful degradation pattern as every
/// other security-touching command.
pub fn tree(
    ws: &Workspace,
    rulepack: Option<&Rulepack>,
    filters: &TreeFilters<'_>,
) -> anyhow::Result<TreeOut> {
    let max_findings_cap = filters.max_finding_ids_per_file.unwrap_or(3);
    let max_flow_cap = filters.max_flow_ids_per_file.unwrap_or(5);
    let max_edge_cap = filters.max_cross_file_edges_per_file.unwrap_or(3);
    let limit = if filters.limit == 0 {
        usize::MAX
    } else {
        filters.limit
    };

    let report = match rulepack {
        Some(pack) => run_taint_analysis(ws, pack, TaintAnalysisOptions::default()).ok(),
        None => None,
    };

    let mut findings_by_file: AHashMap<String, Vec<Finding>> = AHashMap::new();
    if let Some(rep) = report.as_ref() {
        for cf in &rep.findings {
            findings_by_file
                .entry(cf.finding.sink.file.clone())
                .or_default()
                .push(cf.finding.clone());
        }
    }

    let resolved = ws.resolved_call_graph();
    let global = ws.db().global_index();
    let cross_edges = build_cross_edges(&resolved, ws);

    let mut files: Vec<(String, bonsai_common::FileId)> = ws
        .vfs()
        .all_files()
        .into_iter()
        .filter_map(|fid| {
            let abs = ws.vfs().path(fid).ok()?;
            let rel = abs.display().to_string();
            if let Some(needle) = filters.file {
                if !rel.contains(needle) {
                    return None;
                }
            }
            for ex in filters.exclude_files {
                if rel.contains(ex.as_str()) {
                    return None;
                }
            }
            Some((rel, fid))
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));

    drop(global);

    let mut tree_root = DirBuilder::default();
    for (rel, file_id) in &files {
        let segments: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            continue;
        }
        let language = ws
            .db()
            .adapter_for(*file_id)
            .map(|a| a.language_id().as_str().to_string());

        let file_findings = findings_by_file.get(rel.as_str()).cloned().unwrap_or_default();
        let mut finding_ids: Vec<String> = file_findings.iter().map(|f| f.finding_id.clone()).collect();
        finding_ids.sort();
        finding_ids.dedup();

        let mut sev_counts = SeverityHistogram::default();
        for f in &file_findings {
            sev_counts.add(f.severity);
        }
        let max_severity = sev_counts.max();

        if let Some(min_sev) = filters.severity {
            if max_severity.is_none_or(|s| s < min_sev) {
                continue;
            }
        }

        let mut flow_ids: Vec<String> = file_findings
            .iter()
            .filter_map(|f| f.representative_flow_id.clone())
            .collect();
        flow_ids.sort();
        flow_ids.dedup();

        let raw_finding_count = finding_ids.len();
        let raw_flow_count = flow_ids.len();
        finding_ids.truncate(max_findings_cap);
        flow_ids.truncate(max_flow_cap);

        let most_severe_flow = file_findings
            .iter()
            .filter(|f| f.severity.is_some())
            .max_by_key(|f| f.severity)
            .map(build_most_severe_flow);

        let callers_in = cross_edges
            .into_callers
            .get(rel.as_str())
            .cloned()
            .unwrap_or_default();
        let callees_out = cross_edges
            .out_callees
            .get(rel.as_str())
            .cloned()
            .unwrap_or_default();
        let raw_callers_count = callers_in.len();
        let raw_callees_count = callees_out.len();
        let callers_in: Vec<CrossEdge> = callers_in.into_iter().take(max_edge_cap).collect();
        let callees_out: Vec<CrossEdge> = callees_out.into_iter().take(max_edge_cap).collect();

        let render_priority = compute_render_priority(max_severity, sev_counts.total());

        let truncated = TreeTruncation {
            children_dropped: 0,
            finding_ids_dropped: raw_finding_count.saturating_sub(finding_ids.len()),
            flow_ids_dropped: raw_flow_count.saturating_sub(flow_ids.len()),
            callers_in_dropped: raw_callers_count.saturating_sub(callers_in.len()),
            callees_out_dropped: raw_callees_count.saturating_sub(callees_out.len()),
        };

        let basename = segments.last().copied().unwrap_or(rel.as_str()).to_string();
        let depth = segments.len().saturating_sub(1);
        let locator = Locator {
            file: rel.clone(),
            line: 0,
            column: 0,
            language,
            ..Locator::default()
        };

        let node = TreeNode {
            kind: NodeKind::File,
            name: basename,
            locator,
            depth,
            finding_ids,
            flow_ids,
            max_severity,
            finding_severity_counts: sev_counts,
            cross_file_callers_in: callers_in,
            cross_file_callees_out: callees_out,
            most_severe_flow,
            indexed: IndexedStatus::Complete,
            render_priority,
            children: Vec::new(),
            truncated,
        };

        tree_root.insert(&segments, node);
    }

    // Track files scanned before depth truncation. Without this the
    // header on a `--max-depth 3` walk of `crates/X/src/lib.rs`
    // (files at depth 4) reads "tree — 0 files" and looks like the
    // workspace is empty even though hundreds of files were
    // indexed.
    let mut summary = TreeSummary {
        total_files_scanned: files.len(),
        ..TreeSummary::default()
    };
    let max_depth = filters.max_depth.unwrap_or(usize::MAX);
    let roots = tree_root.finalize("", 0, max_depth, limit, &mut summary);

    Ok(TreeOut { roots, summary })
}

#[derive(Default)]
struct CrossEdgeIndex {
    into_callers: AHashMap<String, Vec<CrossEdge>>,
    out_callees: AHashMap<String, Vec<CrossEdge>>,
}

fn build_cross_edges(graph: &bonsai_callgraph::ResolvedCallGraph, ws: &Workspace) -> CrossEdgeIndex {
    let mut index = CrossEdgeIndex::default();
    let global = ws.db().global_index();
    for edge in &graph.inner().edges {
        let caller_file = global
            .declaring_file(SymbolId::new(edge.from.raw()))
            .and_then(|fid| ws.vfs().path(fid).ok().map(|p| p.display().to_string()));
        let callee_file = global
            .declaring_file(SymbolId::new(edge.to.raw()))
            .and_then(|fid| ws.vfs().path(fid).ok().map(|p| p.display().to_string()));
        let (Some(caller_path), Some(callee_path)) = (caller_file, callee_file) else {
            continue;
        };
        if caller_path == callee_path {
            continue;
        }
        let caller_loc = func_to_locator(edge.from, ws);
        let callee_loc = func_to_locator(edge.to, ws);
        let call_site = Locator {
            file: caller_loc.file.clone(),
            line: caller_loc.line,
            column: caller_loc.column,
            ..Locator::default()
        };
        let cross = CrossEdge {
            caller: caller_loc,
            callee: callee_loc,
            call_site,
            edge_id: None,
            flow_id: None,
            finding_id: None,
            precision: edge.precision,
            edge_kind: edge.kind,
            external: None,
        };
        index
            .into_callers
            .entry(callee_path.clone())
            .or_default()
            .push(cross.clone());
        index.out_callees.entry(caller_path).or_default().push(cross);
    }
    for v in index.into_callers.values_mut() {
        let v: &mut Vec<CrossEdge> = v;
        v.sort_by_key(|edge| std::cmp::Reverse(precision_rank(edge.precision)));
    }
    for v in index.out_callees.values_mut() {
        let v: &mut Vec<CrossEdge> = v;
        v.sort_by_key(|edge| std::cmp::Reverse(precision_rank(edge.precision)));
    }
    index
}

fn precision_rank(p: Precision) -> u8 {
    match p {
        Precision::Exact => 4,
        Precision::Narrowed => 3,
        Precision::OverApproximate => 2,
        Precision::Unknown => 1,
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

fn build_most_severe_flow(f: &Finding) -> MostSevereFlowSummary {
    MostSevereFlowSummary {
        flow_id: f
            .representative_flow_id
            .clone()
            .unwrap_or_else(|| "F:0000000000000000".to_string()),
        finding_id: Some(f.finding_id.clone()),
        severity: f.severity.unwrap_or(Severity::Info),
        enters_at: match_to_locator(&f.source),
        exits_at: match_to_locator(&f.sink),
        chain_display: f.chain_display.clone(),
        extends_beyond_workspace: false,
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

fn compute_render_priority(sev: Option<Severity>, total: usize) -> u8 {
    let sev_score: u32 = match sev {
        Some(Severity::Critical) => 200,
        Some(Severity::High) => 150,
        Some(Severity::Medium) => 100,
        Some(Severity::Low) => 50,
        Some(Severity::Info) => 25,
        None => 0,
    };
    let scaled = sev_score.saturating_add(u32::try_from(total.min(50)).unwrap_or(0));
    scaled.min(255) as u8
}

#[derive(Default)]
struct DirBuilder {
    files: Vec<TreeNode>,
    dirs: AHashMap<String, DirBuilder>,
}

impl DirBuilder {
    fn insert(&mut self, segments: &[&str], file_node: TreeNode) {
        if segments.len() <= 1 {
            self.files.push(file_node);
            return;
        }
        let head = segments[0].to_string();
        self.dirs
            .entry(head)
            .or_default()
            .insert(&segments[1..], file_node);
    }

    fn finalize(
        self,
        path_prefix: &str,
        depth: usize,
        max_depth: usize,
        limit: usize,
        summary: &mut TreeSummary,
    ) -> Vec<TreeNode> {
        if depth > max_depth {
            return Vec::new();
        }
        let mut out: Vec<TreeNode> = Vec::new();
        let mut dirs: Vec<(String, DirBuilder)> = self.dirs.into_iter().collect();
        dirs.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, builder) in dirs {
            let next_path = if path_prefix.is_empty() {
                name.clone()
            } else {
                format!("{path_prefix}/{name}")
            };
            let children = builder.finalize(&next_path, depth + 1, max_depth, limit, summary);
            let mut hist = SeverityHistogram::default();
            for c in &children {
                hist.merge(&c.finding_severity_counts);
            }
            summary.total_dirs += 1;
            let dir_locator = Locator {
                file: next_path.clone(),
                ..Locator::default()
            };
            let max_sev = hist.max();
            let dir_priority = compute_render_priority(max_sev, hist.total());
            out.push(TreeNode {
                kind: NodeKind::Dir,
                name,
                locator: dir_locator,
                depth,
                finding_ids: Vec::new(),
                flow_ids: Vec::new(),
                max_severity: max_sev,
                finding_severity_counts: hist,
                cross_file_callers_in: Vec::new(),
                cross_file_callees_out: Vec::new(),
                most_severe_flow: None,
                indexed: IndexedStatus::Complete,
                render_priority: dir_priority,
                children,
                truncated: TreeTruncation::default(),
            });
        }
        let mut files = self.files;
        files.sort_by(|a, b| a.name.cmp(&b.name));
        let raw_files = files.len();
        let dropped = raw_files.saturating_sub(limit);
        files.truncate(limit);
        for f in &files {
            summary.total_files += 1;
            summary.severity_counts.merge(&f.finding_severity_counts);
            summary.total_findings += f.finding_severity_counts.total();
            match f.indexed {
                IndexedStatus::Complete => summary.indexed_complete += 1,
                IndexedStatus::Stale => summary.indexed_stale += 1,
                IndexedStatus::Missing => summary.indexed_missing += 1,
            }
        }
        out.extend(files);
        if dropped > 0 {
            if let Some(last) = out.last_mut() {
                last.truncated.children_dropped = dropped;
            }
        }
        out
    }
}
