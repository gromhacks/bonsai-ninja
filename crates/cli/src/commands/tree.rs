//! `tree` — workspace navigation surface (CLI renderer).
//!
//! Builds the SDK [`bonsai_sdk::TreeOut`] and renders it as text
//! or JSON. Text mode draws a `tree(1)`-style hierarchy with
//! `├──` / `└──` / `│` connectors, themed via the global
//! [`crate::ui::Ui`] palette so it matches every other command.
//! The default view includes inline `←in:` / `→out:` lines for
//! cross-file edges; compact mode drops those extras for a
//! one-line-per-entry tree.

use anyhow::Result;
use bonsai_sdk::{
    CrossEdge, IndexedStatus, Locator, MostSevereFlowSummary, NodeKind, Severity, SeverityHistogram,
    TreeFilters, TreeNode, TreeOut, TreeSummary, TreeTruncation,
};
use std::path::{Path, PathBuf};

use super::{emit_json_value_paged_cached, open_project_index_only_with_rulepack};
use crate::cli_println;
use crate::footer::render_paging_footer;
use crate::paging::{self, FormatClass};
use crate::progress;
use crate::ui;

pub(crate) struct TreeArgs<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) max_depth: Option<usize>,
    pub(crate) file: Option<&'a str>,
    pub(crate) exclude_file: &'a [String],
    pub(crate) severity: Option<&'a str>,
    pub(crate) limit: usize,
    pub(crate) compact: bool,
    pub(crate) context: Option<&'a str>,
    pub(crate) page: Option<&'a str>,
    pub(crate) all: bool,
    pub(crate) format: &'a str,
    pub(crate) rules_dir: Option<&'a Path>,
}

pub(crate) fn cmd_tree(args: TreeArgs<'_>) -> Result<()> {
    let severity = parse_severity(args.severity)?;
    let filters_hash = tree_filters_hash(&args);
    let fast_filesystem_tree = args.rules_dir.is_none() && severity.is_none() && !args.all;
    let out = if fast_filesystem_tree {
        build_fast_filesystem_tree(&args)?
    } else {
        let (project, _footer) = open_project_index_only_with_rulepack(args.workspace, args.rules_dir)?;
        let filters = TreeFilters {
            max_depth: args.max_depth,
            file: args.file,
            exclude_files: args.exclude_file,
            severity,
            limit: if args.all { 0 } else { args.limit },
            follow: 0,
            max_finding_ids_per_file: args.all.then_some(0),
            max_flow_ids_per_file: args.all.then_some(0),
            max_cross_file_edges_per_file: args.all.then_some(0),
        };
        let spin = progress::spinner("building tree");
        let out = project.browse().tree(filters)?;
        spin.finish_and_clear();
        out
    };

    match args.format {
        "json" => {
            let cfg = paging::config_from_raw(args.context, args.page, args.all, FormatClass::Programmatic)
                .map_err(|e| anyhow::anyhow!(e))?;
            emit_json_value_paged_cached(args.workspace, &out, &cfg, "tree", filters_hash)?;
        }
        _ => render_text_paged(
            &out,
            args.compact,
            args.context,
            args.page,
            args.all,
            filters_hash,
        )?,
    }
    Ok(())
}

struct FastTreeBuild {
    max_depth: usize,
    child_limit: usize,
    file_filter: Option<String>,
    exclude_files: Vec<String>,
    files_scanned: usize,
    files_rendered: usize,
    dirs_rendered: usize,
    depth_truncated: usize,
    children_dropped: usize,
}

fn build_fast_filesystem_tree(args: &TreeArgs<'_>) -> Result<TreeOut> {
    let root = args
        .workspace
        .canonicalize()
        .unwrap_or_else(|_| args.workspace.to_path_buf());
    let mut build = FastTreeBuild {
        max_depth: if args.file.is_some() {
            usize::MAX
        } else {
            args.max_depth.unwrap_or(usize::MAX)
        },
        child_limit: if args.limit == 0 { usize::MAX } else { args.limit },
        file_filter: args.file.map(str::to_string),
        exclude_files: args.exclude_file.to_vec(),
        files_scanned: 0,
        files_rendered: 0,
        dirs_rendered: 0,
        depth_truncated: 0,
        children_dropped: 0,
    };
    let root_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_else(|| root.to_str().unwrap_or("."))
        .to_string();
    let root_node = build_fast_dir_node(&root, root_name, 0, &mut build)?;
    let mut reasons = Vec::new();
    if build.depth_truncated > 0 {
        reasons.push(format!(
            "tree-files-truncated:depth_limited_nodes={}",
            build.depth_truncated
        ));
    }
    if build.children_dropped > 0 {
        reasons.push(format!(
            "tree-children-truncated:children_dropped={}",
            build.children_dropped
        ));
    }
    let analysis_complete = reasons.is_empty();
    Ok(TreeOut {
        analysis_complete,
        analysis_incomplete_reasons: reasons,
        roots: vec![root_node],
        summary: TreeSummary {
            total_files: build.files_rendered,
            total_files_scanned: build.files_scanned,
            total_dirs: build.dirs_rendered,
            total_findings: 0,
            severity_counts: SeverityHistogram::default(),
            indexed_complete: build.files_rendered,
            indexed_stale: 0,
            indexed_missing: 0,
        },
    })
}

fn build_fast_dir_node(
    path: &Path,
    name: String,
    depth: usize,
    build: &mut FastTreeBuild,
) -> Result<TreeNode> {
    build.dirs_rendered += 1;
    let mut node = empty_tree_node(NodeKind::Dir, name, path, depth);
    if depth >= build.max_depth {
        let dropped = visible_child_count(path, build)?;
        if dropped > 0 {
            node.truncated.children_dropped = dropped;
            build.depth_truncated += dropped;
        }
        return Ok(node);
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(path)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|entry_path| !fast_tree_should_skip(entry_path, build))
        .collect();
    entries.sort();
    let mut children = Vec::new();
    for entry_path in entries {
        let Some(name) = entry_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if entry_path.is_dir() {
            if children.len() >= build.child_limit {
                node.truncated.children_dropped += 1;
                build.children_dropped += 1;
                continue;
            }
            let child = build_fast_dir_node(&entry_path, name, depth + 1, build)?;
            if build.file_filter.is_none() || !child.children.is_empty() {
                children.push(child);
            }
        } else if entry_path.is_file() {
            build.files_scanned += 1;
            if !fast_tree_file_matches(&entry_path, build) {
                continue;
            }
            if children.len() >= build.child_limit {
                node.truncated.children_dropped += 1;
                build.children_dropped += 1;
                continue;
            }
            build.files_rendered += 1;
            children.push(empty_tree_node(NodeKind::File, name, &entry_path, depth + 1));
        }
    }
    node.children = children;
    Ok(node)
}

fn empty_tree_node(kind: NodeKind, name: String, path: &Path, depth: usize) -> TreeNode {
    TreeNode {
        kind,
        name,
        locator: Locator {
            file: path.display().to_string(),
            line: 1,
            column: 1,
            ..Locator::default()
        },
        depth,
        finding_ids: Vec::new(),
        flow_ids: Vec::new(),
        max_severity: None,
        finding_severity_counts: SeverityHistogram::default(),
        cross_file_callers_in: Vec::new(),
        cross_file_callees_out: Vec::new(),
        most_severe_flow: None,
        indexed: IndexedStatus::Complete,
        render_priority: 0,
        children: Vec::new(),
        truncated: TreeTruncation::default(),
    }
}

fn visible_child_count(path: &Path, build: &FastTreeBuild) -> Result<usize> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(path)?.flatten() {
        let entry_path = entry.path();
        if fast_tree_should_skip(&entry_path, build) {
            continue;
        }
        if entry_path.is_dir() || (entry_path.is_file() && fast_tree_file_matches(&entry_path, build)) {
            count += 1;
        }
    }
    Ok(count)
}

fn fast_tree_should_skip(path: &Path, build: &FastTreeBuild) -> bool {
    let path_text = path.to_string_lossy();
    if build
        .exclude_files
        .iter()
        .any(|needle| path_text.contains(needle))
    {
        return true;
    }
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(".git" | ".bonsai" | "target" | "node_modules" | ".gradle" | "build" | "dist" | "out" | ".idea")
    )
}

fn fast_tree_file_matches(path: &Path, build: &FastTreeBuild) -> bool {
    build
        .file_filter
        .as_deref()
        .is_none_or(|needle| path.to_string_lossy().contains(needle))
}

fn tree_filters_hash(args: &TreeArgs<'_>) -> u64 {
    let max_depth = args.max_depth.map(|n| n.to_string()).unwrap_or_default();
    let exclude_file = args.exclude_file.join("\0");
    let limit = args.limit.to_string();
    let compact = if args.compact { "1" } else { "0" };
    let rules_dir = args
        .rules_dir
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    paging::hash_filters(&[
        ("max_depth", &max_depth),
        ("file", args.file.unwrap_or("")),
        ("exclude_file", &exclude_file),
        ("severity", args.severity.unwrap_or("")),
        ("limit", &limit),
        ("compact", compact),
        ("rules_dir", &rules_dir),
    ])
}

fn parse_severity(s: Option<&str>) -> Result<Option<Severity>> {
    let Some(raw) = s else { return Ok(None) };
    match raw.to_ascii_lowercase().as_str() {
        "info" => Ok(Some(Severity::Info)),
        "low" => Ok(Some(Severity::Low)),
        "medium" => Ok(Some(Severity::Medium)),
        "high" => Ok(Some(Severity::High)),
        "critical" => Ok(Some(Severity::Critical)),
        other => Err(anyhow::anyhow!(
            "invalid --severity value '{other}' (expected one of: info, low, medium, high, critical)"
        )),
    }
}

fn render_text_paged(
    out: &TreeOut,
    compact: bool,
    context: Option<&str>,
    page: Option<&str>,
    all: bool,
    filters_hash: u64,
) -> Result<()> {
    let lines = render_text_lines(out, compact);
    let cfg =
        paging::config_from_raw(context, page, all, FormatClass::Text).map_err(|e| anyhow::anyhow!(e))?;
    let rows: Vec<usize> = (0..lines.len()).collect();
    let (page_rows, info) = paging::paginate(&rows, &cfg, "tree", filters_hash, |idx| {
        lines[*idx].len() as u64 + 128
    });
    for idx in page_rows {
        cli_println!("{}", lines[idx]);
    }
    render_paging_footer(&info, "bonsai-ninja tree <workspace>");
    Ok(())
}

fn render_text_lines(out: &TreeOut, compact: bool) -> Vec<String> {
    let u = ui();
    let mut lines = Vec::new();
    // Heading
    let total = out.summary.total_files;
    let scanned = out.summary.total_files_scanned;
    // When `--max-depth` truncated the rendered tree, the rendered
    // file count is much smaller than what the underlying scan saw.
    // Surface the scanned count so users don't read "0 files" and
    // assume the workspace is empty.
    let file_chip = if scanned > total {
        format!(
            "{} file{} ({} scanned)",
            total,
            if total == 1 { "" } else { "s" },
            scanned
        )
    } else {
        format!("{} file{}", total, if total == 1 { "" } else { "s" })
    };
    let header = format!(
        "tree — {} · {} dir{} · {} finding{}",
        file_chip,
        out.summary.total_dirs,
        if out.summary.total_dirs == 1 { "" } else { "s" },
        out.summary.total_findings,
        if out.summary.total_findings == 1 { "" } else { "s" },
    );
    lines.push(u.heading(&header));
    if !out.analysis_complete {
        let reasons = if out.analysis_incomplete_reasons.is_empty() {
            "analysis-incomplete".to_string()
        } else {
            out.analysis_incomplete_reasons.join("; ")
        };
        lines.push(format!(
            "{} {}",
            u.warn("semantic-only tree incomplete:"),
            u.dim(&reasons)
        ));
        lines.push(
            u.dim("rerun with --all and avoid restrictive --max-depth when you need every node/evidence id"),
        );
    }
    lines.push(String::new());

    let last = out.roots.len().saturating_sub(1);
    for (root_index, root) in out.roots.iter().enumerate() {
        let is_last = root_index == last;
        render_node_lines(root, "", is_last, compact, &mut lines);
    }

    lines.push(String::new());
    let sev = &out.summary.severity_counts;
    let sev_chip = format!(
        "{} crit · {} high · {} med · {} low · {} info",
        sev.critical, sev.high, sev.medium, sev.low, sev.info
    );
    lines.push(format!(
        "{} {}",
        u.label("[ severity ]"),
        if sev.critical + sev.high > 0 {
            u.warn(&sev_chip)
        } else {
            u.dim(&sev_chip)
        }
    ));
    if out.summary.indexed_stale > 0 || out.summary.indexed_missing > 0 {
        lines.push(format!(
            "{} {} complete · {} stale · {} missing",
            u.label("[ taint-index ]"),
            out.summary.indexed_complete,
            out.summary.indexed_stale,
            out.summary.indexed_missing,
        ));
    }
    lines
}

fn render_node_lines(node: &TreeNode, prefix: &str, is_last: bool, compact: bool, lines: &mut Vec<String>) {
    let u = ui();
    let connector = if is_last { "└── " } else { "├── " };
    let next_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });

    // Node line: connector + name + summary chips
    let name_styled = match node.kind {
        NodeKind::Dir => u.kind(&format!("{}/", node.name)),
        NodeKind::File => u.name(&node.name),
    };
    let summary = compose_node_summary(node);
    let line = if summary.is_empty() {
        format!("{prefix}{}{}", u.dim(connector), name_styled)
    } else {
        format!("{prefix}{}{}  {}", u.dim(connector), name_styled, summary)
    };
    lines.push(line);

    // Compact-disabled extras: cross-file edges + most-severe flow
    if !compact && matches!(node.kind, NodeKind::File) {
        if !node.cross_file_callers_in.is_empty() {
            push_edge_line(lines, &next_prefix, "←in: ", &node.cross_file_callers_in);
        }
        if !node.cross_file_callees_out.is_empty() {
            push_edge_line(lines, &next_prefix, "→out:", &node.cross_file_callees_out);
        }
        if let Some(msf) = &node.most_severe_flow {
            push_most_severe_flow(lines, &next_prefix, msf);
        }
    }

    let last = node.children.len().saturating_sub(1);
    for (child_index, child) in node.children.iter().enumerate() {
        let child_is_last = child_index == last;
        render_node_lines(child, &next_prefix, child_is_last, compact, lines);
    }
}

fn compose_node_summary(node: &TreeNode) -> String {
    let u = ui();
    let mut parts: Vec<String> = Vec::new();
    if let Some(sev) = node.max_severity {
        let chip = severity_label(sev).to_string();
        let styled = match sev {
            Severity::Critical | Severity::High => u.warn(&chip),
            _ => u.kind(&chip),
        };
        parts.push(styled);
    }
    if !node.finding_ids.is_empty() {
        let mut ids = node
            .finding_ids
            .iter()
            .map(|s| u.annotation(s))
            .collect::<Vec<_>>()
            .join(" ");
        if node.truncated.finding_ids_dropped > 0 {
            ids = format!(
                "{ids} {}",
                u.dim(&format!("+{}", node.truncated.finding_ids_dropped))
            );
        }
        parts.push(ids);
    }
    if !node.flow_ids.is_empty() {
        let mut ids = node
            .flow_ids
            .iter()
            .map(|s| u.kind(s))
            .collect::<Vec<_>>()
            .join(" ");
        if node.truncated.flow_ids_dropped > 0 {
            ids = format!(
                "{ids} {}",
                u.dim(&format!("+{}", node.truncated.flow_ids_dropped))
            );
        }
        parts.push(ids);
    }
    if matches!(node.kind, NodeKind::Dir) && node.finding_severity_counts.total() > 0 {
        let h = &node.finding_severity_counts;
        let chip = format!("✦ {} ({}c {}h {}m)", h.total(), h.critical, h.high, h.medium);
        parts.push(if h.critical + h.high > 0 {
            u.warn(&chip)
        } else {
            u.dim(&chip)
        });
    }
    if matches!(node.indexed, IndexedStatus::Stale) {
        parts.push(u.warn("taint-index: stale"));
    } else if matches!(node.indexed, IndexedStatus::Missing) {
        parts.push(u.warn("taint-index: missing"));
    }
    parts.join(" · ")
}

fn push_edge_line(lines: &mut Vec<String>, prefix: &str, label: &str, edges: &[CrossEdge]) {
    let u = ui();
    let parts: Vec<String> = edges.iter().map(format_edge_for_text).collect();
    lines.push(format!("{prefix}{} {}", u.dim(label), parts.join(", ")));
}

fn format_edge_for_text(edge: &CrossEdge) -> String {
    let u = ui();
    let other = &edge.callee;
    let module = other.module.as_deref().unwrap_or("");
    let class = other.class.as_deref();
    let decl = other.decl.as_deref().unwrap_or("?");
    let sym = match class {
        Some(c) if !c.is_empty() => format!("{module}.{c}.{decl}"),
        _ if module.is_empty() => decl.to_string(),
        _ => format!("{module}.{decl}"),
    };
    let loc = format!("{}:{}:{}", other.file, other.line, other.column);
    format!("{} {}", u.name(&sym), u.path(&format!("({loc})")))
}

fn push_most_severe_flow(lines: &mut Vec<String>, prefix: &str, msf: &MostSevereFlowSummary) {
    let u = ui();
    let chain = if msf.chain_display.is_empty() {
        format!(
            "{} → {}",
            msf.enters_at.decl.as_deref().unwrap_or("?"),
            msf.exits_at.decl.as_deref().unwrap_or("?")
        )
    } else {
        msf.chain_display.join(" → ")
    };
    lines.push(format!(
        "{prefix}{} {} ({} {})",
        u.dim("most-severe-flow:"),
        u.name(&chain),
        u.annotation(&msf.flow_id),
        match msf.severity {
            Severity::Critical | Severity::High => u.warn(severity_label(msf.severity)),
            _ => u.kind(severity_label(msf.severity)),
        },
    ));
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}
