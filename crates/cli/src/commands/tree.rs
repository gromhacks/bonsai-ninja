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
    CrossEdge, IndexedStatus, MostSevereFlowSummary, NodeKind, Severity, TreeFilters, TreeNode, TreeOut,
};
use std::path::Path;

use super::open_project_index_only_with_rulepack;
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
    let (project, _footer) = open_project_index_only_with_rulepack(args.workspace, args.rules_dir)?;

    let severity = parse_severity(args.severity)?;
    let filters_hash = tree_filters_hash(&args);
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

    match args.format {
        "json" => {
            let s = serde_json::to_string_pretty(&out)?;
            cli_println!("{s}");
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
