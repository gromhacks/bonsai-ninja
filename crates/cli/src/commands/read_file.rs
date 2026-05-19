//! `read-file` — single-file connected-content view (CLI renderer).
//!
//! Builds the SDK [`bonsai_sdk::ReadFileOut`] and renders it with
//! the global [`crate::ui::Ui`] palette so it matches every other
//! command's chrome. Compact mode prints a step list of marks
//! (one line per finding/sink/source); the default view shows the
//! primary file source with marks beside the relevant lines, then
//! inlines cross-file caller / callee bodies when available.

use anyhow::Result;
use bonsai_sdk::{FlowEntryExit, InlinedDecl, LineMark, MarkKind, ReadFileFilters, ReadFileOut, Severity};
use std::path::Path;

use super::open_project_index_only_with_rulepack;
use crate::cli_println;
use crate::footer::render_paging_footer;
use crate::page_cache;
use crate::paging::{self, FormatClass};
use crate::ui;
use crate::ui::extension_for;

pub(crate) struct ReadFileArgs<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) path: &'a str,
    pub(crate) lines: Option<&'a str>,
    pub(crate) from: Option<&'a str>,
    pub(crate) to: Option<&'a str>,
    pub(crate) max_inlined_bodies: Option<usize>,
    pub(crate) compact: bool,
    pub(crate) context: Option<&'a str>,
    pub(crate) page: Option<&'a str>,
    pub(crate) all: bool,
    pub(crate) format: &'a str,
    pub(crate) rules_dir: Option<&'a Path>,
}

pub(crate) fn cmd_read_file(args: ReadFileArgs<'_>) -> Result<()> {
    let (project, _footer) = open_project_index_only_with_rulepack(args.workspace, args.rules_dir)?;
    let line_range = parse_line_range(args.lines)?;
    let filters = ReadFileFilters {
        path: args.path,
        line_range,
        from: args.from,
        to: args.to,
        max_inlined_bodies: if args.all {
            Some(0)
        } else {
            args.max_inlined_bodies
        },
    };
    let out = project.browse().read_file(filters)?;

    match args.format {
        "json" => {
            let s = serde_json::to_string_pretty(&out)?;
            cli_println!("{s}");
        }
        _ => {
            let filters_hash = read_file_filters_hash(&args);
            render_text_paged(
                args.workspace,
                &out,
                args.compact,
                args.context,
                args.page,
                args.all,
                filters_hash,
            )?;
        }
    }
    Ok(())
}

fn render_text_paged(
    workspace: &Path,
    out: &ReadFileOut,
    compact: bool,
    context: Option<&str>,
    page: Option<&str>,
    all: bool,
    filters_hash: u64,
) -> Result<()> {
    let cfg =
        paging::config_from_raw(context, page, all, FormatClass::Text).map_err(|e| anyhow::anyhow!(e))?;
    let rendered = page_cache::capture(|| {
        render_text(out, compact);
        Ok(())
    })?;
    let lines: Vec<String> = rendered.lines().map(str::to_string).collect();
    page_cache::emit_paged_text(
        workspace,
        &lines,
        &cfg,
        "read-file",
        filters_hash,
        |line| line.len() as u64 + 128,
        |paged, info, _cfg| {
            for line in paged {
                cli_println!("{line}");
            }
            render_paging_footer(info, "bonsai-ninja read-file <workspace> <path>");
            Ok(())
        },
    )
}

fn read_file_filters_hash(args: &ReadFileArgs<'_>) -> u64 {
    let max_inlined_bodies = args.max_inlined_bodies.map(|n| n.to_string()).unwrap_or_default();
    let compact = if args.compact { "1" } else { "0" };
    let rules_dir = args
        .rules_dir
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    paging::hash_filters(&[
        ("path", args.path),
        ("lines", args.lines.unwrap_or("")),
        ("from", args.from.unwrap_or("")),
        ("to", args.to.unwrap_or("")),
        ("max_inlined_bodies", &max_inlined_bodies),
        ("compact", compact),
        ("rules_dir", &rules_dir),
    ])
}

fn parse_line_range(s: Option<&str>) -> Result<Option<(u32, u32)>> {
    let Some(raw) = s else { return Ok(None) };
    let (lo, hi) = raw
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("--lines expects A:B (got '{raw}')"))?;
    let lo: u32 = lo
        .parse()
        .map_err(|_| anyhow::anyhow!("--lines start not a number"))?;
    let hi: u32 = hi
        .parse()
        .map_err(|_| anyhow::anyhow!("--lines end not a number"))?;
    if hi < lo {
        return Err(anyhow::anyhow!("--lines end < start"));
    }
    Ok(Some((lo, hi)))
}

fn render_text(out: &ReadFileOut, compact: bool) {
    let u = ui();
    let lang = out.locator.language.as_deref().unwrap_or("?");
    let header = format!(
        "read-file — {} [{} · {} lines]",
        out.locator.file, lang, out.lines_total
    );
    cli_println!("{}", u.heading(&header));
    if let Some(module) = &out.locator.module {
        cli_println!("{} {}", u.label("module:"), u.name(module));
    }
    if !out.analysis_complete {
        let reasons = if out.analysis_incomplete_reasons.is_empty() {
            "analysis-incomplete".to_string()
        } else {
            out.analysis_incomplete_reasons.join("; ")
        };
        cli_println!("{} {}", u.warn("semantic-only view incomplete:"), u.dim(&reasons));
        if out.truncated.callers_dropped > 0 || out.truncated.callees_dropped > 0 {
            cli_println!(
                "{}",
                u.dim("rerun with --all or --max-inlined-bodies 0 to include every cross-file body")
            );
        }
    }

    if !out.findings_in_view.is_empty() {
        cli_println!();
        cli_println!(
            "{}",
            u.label(&format!("findings ({}):", out.findings_in_view.len()))
        );
        for d in &out.findings_in_view {
            let sev_styled = match d.severity {
                Severity::Critical | Severity::High => u.warn(severity_label(d.severity)),
                _ => u.kind(severity_label(d.severity)),
            };
            cli_println!(
                "  {} {} ({}/{}) {}",
                u.annotation(&d.finding_id),
                u.name(&d.rule_id),
                u.kind(&d.tag),
                sev_styled,
                u.path(&format!("{}:{}", d.sink.file, d.sink.line)),
            );
        }
    }

    if !out.flows_in_view.is_empty() {
        cli_println!();
        cli_println!("{}", u.label(&format!("flows ({}):", out.flows_in_view.len())));
        for f in &out.flows_in_view {
            print_flow_entry_exit(f);
        }
    }

    let callers_summary = build_caller_summaries(&out.callers_in);
    if !callers_summary.is_empty() {
        cli_println!();
        cli_println!("{}", u.label("callers in (cross-file):"));
        for c in callers_summary {
            cli_println!("  {c}");
        }
    }
    let callees_summary = build_callee_summaries(&out.callees_out);
    if !callees_summary.is_empty() {
        cli_println!();
        cli_println!("{}", u.label("callees out (cross-file):"));
        for c in callees_summary {
            cli_println!("  {c}");
        }
    }

    cli_println!();
    if compact {
        render_compact_marks(out);
    } else {
        render_no_compact(out);
    }
}

fn render_compact_marks(out: &ReadFileOut) {
    let u = ui();
    if out.marks.is_empty() {
        cli_println!("{}", u.dim("(no marks in view)"));
        return;
    }
    for m in &out.marks {
        cli_println!("{} {}", u.annotation(&format!("L{}", m.line)), format_mark(m));
    }
}

fn render_no_compact(out: &ReadFileOut) {
    let u = ui();
    let ext = extension_for(&out.locator.file);
    let lo = out.line_range_start();

    cli_println!("{}", u.ruler('─', 72));
    cli_println!("  {} {}", u.label("┌─"), u.path(&out.locator.file));
    cli_println!("{}", u.ruler('─', 72));

    let highlighted = u.highlight(&out.source, ext);
    for (idx, line) in highlighted.lines().enumerate() {
        let line_no = lo + idx as u32;
        let mark = out.marks.iter().find(|m| m.line == line_no);
        let gutter = if mark.is_some() {
            u.warn(&format!("> {:>4} │ ", line_no))
        } else {
            u.dim(&format!("  {:>4} │ ", line_no))
        };
        cli_println!("{gutter}{line}");
        if let Some(m) = mark {
            cli_println!("{} {}", u.dim("              ←"), format_mark(m));
        }
    }
    if !out.callers_in.is_empty() {
        cli_println!();
        for caller in &out.callers_in {
            print_inlined_decl(caller, "caller (cross-file)");
        }
    }
    if !out.callees_out.is_empty() {
        cli_println!();
        for callee in &out.callees_out {
            print_inlined_decl(callee, "callee (cross-file)");
        }
    }
    if out.truncated.callers_dropped > 0 || out.truncated.callees_dropped > 0 {
        cli_println!();
        cli_println!(
            "{}",
            u.dim(&format!(
                "(not inlined: {} callers + {} callees · pass --max-inlined-bodies 0 to lift)",
                out.truncated.callers_dropped, out.truncated.callees_dropped
            ))
        );
    }
}

fn print_inlined_decl(decl: &InlinedDecl, label: &str) {
    let u = ui();
    let module = decl.locator.module.as_deref().unwrap_or("");
    let class = decl.locator.class.as_deref();
    let dname = decl.locator.decl.as_deref().unwrap_or("?");
    let sym = match class {
        Some(c) if !c.is_empty() => format!("{module}.{c}.{dname}"),
        _ if module.is_empty() => dname.to_string(),
        _ => format!("{module}.{dname}"),
    };
    let head_left = format!("── {label}");
    let head_right = format!(
        "{} {}",
        u.name(&sym),
        u.path(&format!("({}:{})", decl.locator.file, decl.locator.line)),
    );
    cli_println!("{} {} ──", u.dim(&head_left), head_right);
    if !decl.source.is_empty() {
        let ext = extension_for(&decl.locator.file);
        let highlighted = u.highlight(&decl.source, ext);
        for line in highlighted.lines() {
            cli_println!("    {line}");
        }
    } else {
        cli_println!("    {}", u.dim("(body not inlined)"));
    }
}

fn print_flow_entry_exit(f: &FlowEntryExit) {
    let u = ui();
    let partial = if f.extends_beyond_view {
        u.warn(" (partial)")
    } else {
        String::new()
    };
    cli_println!(
        "  {}  {} {} {}  {} {} {}{}",
        u.annotation(&f.flow_id),
        u.dim("ENTERS"),
        u.path(&format!(
            "{}:{}:{}",
            f.enters_at.file, f.enters_at.line, f.enters_at.column
        )),
        u.kind(&format!("fn={}", f.enters_at.decl.as_deref().unwrap_or("?"))),
        u.dim("EXITS"),
        u.path(&format!(
            "{}:{}:{}",
            f.exits_at.file, f.exits_at.line, f.exits_at.column
        )),
        u.kind(&format!("fn={}", f.exits_at.decl.as_deref().unwrap_or("?"))),
        partial,
    );
}

fn format_mark(m: &LineMark) -> String {
    let u = ui();
    let kind_label = match m.kind {
        MarkKind::Source => "SOURCE",
        MarkKind::Sink => "SINK",
        MarkKind::Sanitizer => "SANITIZER",
        MarkKind::Through => "THROUGH",
        MarkKind::CallOut => "CALL→",
        MarkKind::CallIn => "→CALL",
    };
    let kind_styled = match m.kind {
        MarkKind::Sink => u.warn(kind_label),
        MarkKind::Source => u.annotation(kind_label),
        _ => u.kind(kind_label),
    };
    let mut parts: Vec<String> = vec![kind_styled];
    if let Some(rid) = &m.rule_id {
        parts.push(u.name(rid));
    }
    if let Some(fid) = &m.finding_id {
        parts.push(u.annotation(fid));
    }
    if let Some(flow) = &m.flow_id {
        parts.push(u.kind(flow));
    }
    if let Some(tag) = &m.tag {
        parts.push(u.dim(&format!("({tag})")));
    }
    if let Some(sev) = m.severity {
        let label = severity_label(sev);
        parts.push(match sev {
            Severity::Critical | Severity::High => u.warn(label),
            _ => u.kind(label),
        });
    }
    if let Some(t) = &m.taint_source_name {
        parts.push(u.dim(&format!("taint←{t}")));
    }
    parts.join(" ")
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

fn build_caller_summaries(callers: &[InlinedDecl]) -> Vec<String> {
    let u = ui();
    callers
        .iter()
        .map(|d| {
            let module = d.locator.module.as_deref().unwrap_or("");
            let class = d.locator.class.as_deref();
            let dname = d.locator.decl.as_deref().unwrap_or("?");
            let sym = match class {
                Some(c) if !c.is_empty() => format!("{module}.{c}.{dname}"),
                _ if module.is_empty() => dname.to_string(),
                _ => format!("{module}.{dname}"),
            };
            format!(
                "{} {}",
                u.name(&sym),
                u.path(&format!("({}:{})", d.locator.file, d.locator.line))
            )
        })
        .collect()
}

fn build_callee_summaries(callees: &[InlinedDecl]) -> Vec<String> {
    build_caller_summaries(callees)
}

trait ReadFileOutExt {
    fn line_range_start(&self) -> u32;
}

impl ReadFileOutExt for ReadFileOut {
    fn line_range_start(&self) -> u32 {
        if self.locator.line == 0 {
            1
        } else {
            self.locator.line
        }
    }
}
