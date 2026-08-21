//! `read-file` — single-file connected-content view (CLI renderer).
//!
//! Builds the SDK [`bonsai_sdk::ReadFileOut`] and renders it with
//! the global [`crate::ui::Ui`] palette so it matches every other
//! command's chrome. Compact mode prints a step list of marks
//! (one line per finding/sink/source); the default view shows the
//! primary file source with marks beside relevant lines. Cross-file caller /
//! callee bodies appear only when the caller requests a semantic overlay.

use anyhow::Result;
use bonsai_sdk::{FlowEntryExit, InlinedDecl, LineMark, MarkKind, ReadFileFilters, ReadFileOut, Severity};
use std::path::{Path, PathBuf};

use super::{
    emit_json_value_paged_cached, open_project_index_matching_literal, open_project_index_matching_path,
    open_project_index_only, open_project_index_only_with_rulepack,
};
use crate::args::BrowseFormat;
use crate::cli_println;
use crate::footer::render_paging_footer;
use crate::page_cache;
use crate::paging::{self, FormatClass};
use crate::progress;
use crate::ui;
use crate::ui::extension_for;

pub(crate) struct ReadFileArgs<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) path: Option<&'a str>,
    pub(crate) symbol: Option<&'a str>,
    pub(crate) lines: Option<&'a str>,
    pub(crate) from: Option<&'a str>,
    pub(crate) to: Option<&'a str>,
    pub(crate) max_inlined_bodies: Option<usize>,
    pub(crate) compact: bool,
    pub(crate) context: Option<&'a str>,
    pub(crate) page: Option<&'a str>,
    pub(crate) all: bool,
    pub(crate) format: BrowseFormat,
    pub(crate) rules_dir: Option<&'a Path>,
}

pub(crate) fn cmd_read_file(args: ReadFileArgs<'_>) -> Result<()> {
    let target_stage = progress::ScopedSpinner::new("resolving file target");
    let resolved_path = resolve_read_file_target(args.workspace, args.path, args.symbol)?;
    target_stage.finish();
    let path = resolved_path.as_str();
    let needs_workspace_analysis = args.from.is_some()
        || args.to.is_some()
        || args.rules_dir.is_some()
        || args.max_inlined_bodies.is_some();
    let (project, _footer) = if needs_workspace_analysis {
        open_project_index_only_with_rulepack(args.workspace, args.rules_dir)?
    } else {
        open_project_index_matching_path(args.workspace, Path::new(path))?
    };
    let line_range = parse_line_range(args.lines)?;
    let filters = ReadFileFilters {
        path,
        line_range,
        from: args.from,
        to: args.to,
        max_inlined_bodies: args.max_inlined_bodies,
    };
    let stage = progress::ScopedSpinner::new("building file view");
    let out = project.browse().read_file(filters)?;
    stage.finish();

    match args.format {
        BrowseFormat::Json => {
            let filters_hash = read_file_filters_hash(&args);
            let cfg = paging::config_from_raw(args.context, args.page, args.all, FormatClass::Programmatic)
                .map_err(|e| anyhow::anyhow!(e))?;
            emit_json_value_paged_cached(args.workspace, &out, &cfg, "read-file", filters_hash)?;
        }
        BrowseFormat::Text => {
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

fn resolve_requested_path(workspace: &Path, requested: &str) -> Result<String> {
    let registry = bonsai_adapters::all_languages_registry();
    let root = stable_root(workspace);
    let requested_path = Path::new(requested);

    if requested_path.is_absolute() {
        if requested_path.is_file() {
            ensure_supported_source(&registry, requested_path)?;
            return Ok(display_path_relative_to(&root, requested_path));
        }
    } else {
        let exact = root.join(requested_path);
        if exact.is_file() {
            ensure_supported_source(&registry, &exact)?;
            return Ok(normalize_path(requested_path));
        }
    }

    let candidates = collect_supported_source_paths(&root, &registry)?;
    let query = normalize_query(requested);
    let matches = ranked_path_matches(&candidates, &query);
    if let Some((best_score, _)) = matches.first() {
        let best: Vec<&ReadFilePathCandidate> = matches
            .iter()
            .take_while(|(score, _)| score == best_score)
            .map(|(_, candidate)| *candidate)
            .collect();
        if best.len() == 1 {
            return Ok(best[0].relative.clone());
        }
        anyhow::bail!(
            "read-file path `{requested}` is ambiguous; use a longer workspace-relative path:\n{}",
            format_path_suggestions(best.iter().map(|candidate| candidate.relative.as_str()))
        );
    }

    let suggestions = nearest_path_suggestions(&candidates, &query, 6);
    if suggestions.is_empty() {
        anyhow::bail!(
            "read-file path `{requested}` did not match any supported source file under {}",
            workspace.display()
        );
    }
    anyhow::bail!(
        "read-file path `{requested}` did not match any supported source file under {}\nDid you mean:\n{}",
        workspace.display(),
        format_path_suggestions(suggestions.iter().map(String::as_str))
    );
}

fn resolve_read_file_target(workspace: &Path, path: Option<&str>, symbol: Option<&str>) -> Result<String> {
    if let Some(path) = path {
        return resolve_requested_path(workspace, path);
    }
    if let Some(symbol) = symbol {
        return resolve_symbol_path(workspace, symbol);
    }
    anyhow::bail!("read-file needs a path or --symbol <name>");
}

fn resolve_symbol_path(workspace: &Path, symbol: &str) -> Result<String> {
    let literal = bonsai_callgraph::short_callee(symbol);
    let (project, _footer) = open_project_index_matching_literal(workspace, literal)?;
    let stage = progress::ScopedSpinner::new("resolving symbol path");
    let defs = project.browse().defs(bonsai_sdk::DefsFilters {
        name: Some(symbol),
        ..Default::default()
    })?;
    stage.finish();
    let exact: Vec<&bonsai_sdk::DefOut> = defs
        .iter()
        .filter(|def| def.name == symbol || def.qualified_name.as_deref() == Some(symbol))
        .collect();
    let candidates: Vec<&bonsai_sdk::DefOut> = if exact.is_empty() {
        defs.iter().collect()
    } else {
        exact
    };
    match candidates.as_slice() {
        [one] => Ok(one.file.clone()),
        [] => {
            // A failed exact lookup is the only path that needs a global
            // suggestion inventory. Keep successful `--symbol` reads scoped
            // to files containing the declaration spelling.
            let (suggestion_project, _footer) = open_project_index_only(workspace)?;
            let suggestions = nearest_symbol_suggestions(&suggestion_project, symbol, 6)?;
            if suggestions.is_empty() {
                anyhow::bail!("read-file --symbol `{symbol}` did not match any definition");
            }
            anyhow::bail!(
                "read-file --symbol `{symbol}` did not match any definition\nDid you mean:\n{}",
                format_path_suggestions(suggestions.iter().map(String::as_str))
            );
        }
        many => {
            let preview = many
                .iter()
                .take(8)
                .map(|def| format!("  {}:{}:{} {}", def.file, def.line, def.column, def.name))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!(
                "read-file --symbol `{symbol}` is ambiguous; pass a path or a more specific symbol:\n{preview}"
            );
        }
    }
}

fn nearest_symbol_suggestions(
    project: &bonsai_sdk::Project,
    symbol: &str,
    limit: usize,
) -> Result<Vec<String>> {
    let stage = progress::ScopedSpinner::new("collecting symbol suggestions");
    let defs = project.browse().defs(Default::default())?;
    stage.finish();
    let mut ranked: Vec<(usize, String)> = defs
        .into_iter()
        .map(|def| {
            let qualified = def.qualified_name.unwrap_or_else(|| def.name.clone());
            let score = edit_distance(&def.name.to_ascii_lowercase(), &symbol.to_ascii_lowercase()).min(
                edit_distance(&qualified.to_ascii_lowercase(), &symbol.to_ascii_lowercase()),
            );
            (score, qualified)
        })
        .collect();
    ranked.sort_by(|(score_a, name_a), (score_b, name_b)| {
        score_a.cmp(score_b).then_with(|| name_a.cmp(name_b))
    });
    ranked.dedup_by(|(_, a), (_, b)| a == b);
    Ok(ranked.into_iter().take(limit).map(|(_, name)| name).collect())
}

#[derive(Clone, Debug)]
struct ReadFilePathCandidate {
    relative: String,
}

fn collect_supported_source_paths(
    root: &Path,
    registry: &bonsai_lang_api::LanguageRegistry,
) -> Result<Vec<ReadFilePathCandidate>> {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(true)
        .parents(true)
        .ignore(true)
        .add_custom_ignore_filename(".bonsaiignore");

    let mut candidates = Vec::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if ignore_error_is_missing_or_denied(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() || !is_supported_source_path(registry, entry.path()) {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map(normalize_path)
            .unwrap_or_else(|_| normalize_path(entry.path()));
        candidates.push(ReadFilePathCandidate { relative });
    }
    candidates.sort_by(|a, b| a.relative.cmp(&b.relative));
    candidates.dedup_by(|a, b| a.relative == b.relative);
    Ok(candidates)
}

fn ranked_path_matches<'a>(
    candidates: &'a [ReadFilePathCandidate],
    query: &str,
) -> Vec<(u8, &'a ReadFilePathCandidate)> {
    let query = query.to_ascii_lowercase();
    let query_file = Path::new(&query)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(query.as_str());
    let mut matches = Vec::new();
    for candidate in candidates {
        let rel = candidate.relative.to_ascii_lowercase();
        let file = Path::new(&rel)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(rel.as_str());
        let score = if rel == query {
            Some(0)
        } else if rel.ends_with(&format!("/{query}")) {
            Some(1)
        } else if file == query_file && !query_file.is_empty() {
            Some(2)
        } else {
            None
        };
        if let Some(score) = score {
            matches.push((score, candidate));
        }
    }
    matches
        .sort_by(|(score_a, a), (score_b, b)| score_a.cmp(score_b).then_with(|| a.relative.cmp(&b.relative)));
    matches
}

fn nearest_path_suggestions(candidates: &[ReadFilePathCandidate], query: &str, limit: usize) -> Vec<String> {
    let query = query.to_ascii_lowercase();
    let query_file = Path::new(&query)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(query.as_str())
        .to_string();
    let mut ranked: Vec<(usize, &ReadFilePathCandidate)> = candidates
        .iter()
        .map(|candidate| {
            let rel = candidate.relative.to_ascii_lowercase();
            let file = Path::new(&rel)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(rel.as_str());
            let score = edit_distance(&rel, &query).min(edit_distance(file, &query_file));
            (score, candidate)
        })
        .collect();
    ranked
        .sort_by(|(score_a, a), (score_b, b)| score_a.cmp(score_b).then_with(|| a.relative.cmp(&b.relative)));
    ranked
        .into_iter()
        .take(limit)
        .map(|(_, candidate)| candidate.relative.clone())
        .collect()
}

fn ensure_supported_source(registry: &bonsai_lang_api::LanguageRegistry, path: &Path) -> Result<()> {
    if is_supported_source_path(registry, path) {
        return Ok(());
    }
    if registry.source_file_representation(path) == Some(bonsai_lang_api::SourceFileRepresentation::Minified)
    {
        anyhow::bail!(
            "read-file path `{}` is a minified compiler input; rerun with --minified-js to include it",
            path.display()
        );
    }
    anyhow::bail!(
        "read-file path `{}` is not a supported source file",
        path.display()
    );
}

fn is_supported_source_path(registry: &bonsai_lang_api::LanguageRegistry, path: &Path) -> bool {
    registry
        .source_file_representation(path)
        .is_some_and(|representation| {
            crate::include_minified_sources()
                || representation != bonsai_lang_api::SourceFileRepresentation::Minified
        })
}

fn display_path_relative_to(root: &Path, path: &Path) -> String {
    let stable_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    stable_path
        .strip_prefix(root)
        .map(normalize_path)
        .unwrap_or_else(|_| normalize_path(&stable_path))
}

fn stable_root(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn normalize_query(raw: &str) -> String {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| raw.to_string())
    } else {
        normalize_path(path)
    }
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str().map(str::to_string),
            std::path::Component::CurDir => None,
            std::path::Component::ParentDir => Some("..".to_string()),
            std::path::Component::RootDir => None,
            std::path::Component::Prefix(prefix) => Some(prefix.as_os_str().to_string_lossy().into_owned()),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn format_path_suggestions<'a>(paths: impl IntoIterator<Item = &'a str>) -> String {
    paths
        .into_iter()
        .take(8)
        .map(|path| format!("  {path}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn edit_distance(a: &str, b: &str) -> usize {
    if a.is_empty() {
        return b.chars().count();
    }
    if b.is_empty() {
        return a.chars().count();
    }
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut cur = vec![0; b_chars.len() + 1];
    for (i, ac) in a.chars().enumerate() {
        cur[0] = i + 1;
        for (j, bc) in b_chars.iter().enumerate() {
            let cost = usize::from(ac != *bc);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b_chars.len()]
}

fn ignore_error_is_missing_or_denied(error: &ignore::Error) -> bool {
    error.io_error().is_some_and(|io_error| {
        matches!(
            io_error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        )
    })
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
        ("path", args.path.unwrap_or("")),
        ("symbol", args.symbol.unwrap_or("")),
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
                u.dim("rerun with --max-inlined-bodies 0 to include every cross-file body")
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
