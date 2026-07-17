//! Dump-family commands: `dump-callgraph`, `dump-edges`, `dump-ast`,
//! `dump-resolve`, `dump-taint`. Structural introspection views of
//! the workspace — each picks one plane of the analysis (call graph,
//! AST, symbol resolution, taint flows) and renders it verbatim.
//! Row-shaped JSON and text output honor the token budget by default;
//! `--all` / `--context uncapped` are the explicit exhaustive modes.

use crate::args::{BrowseFormat, PrecisionFilter};
use crate::footer::{render_paging_footer, render_truncation_notice};
use crate::page_cache;
use crate::paging;
use crate::progress;
use crate::ui::Ui;
use crate::{cli_println, ui};
use anyhow::Result;

use super::browse::{effective_limit, truncate};
use super::{
    apply_text_limit, emit_json_paged_cached, emit_json_value_paged_cached, nearest_names,
    open_project_index_only as open_project, open_project_index_only_with_rulepack, page_info_to_json,
    paged_json_incomplete_reasons, short_file,
};

pub(crate) fn cmd_dump_callgraph(
    root: &std::path::Path,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let stage = progress::ScopedSpinner::new("collecting call graph");
    let rows = project.dump().callgraph();
    stage.finish();
    let filters_hash = 0;
    let cost = |r: &bonsai_sdk::CallgraphRow| (r.function.len() + 8) as u64 + paging::TABLE_ROW_CHROME_BYTES;
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &rows, &paging_cfg, "dump-callgraph", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &rows,
                &paging_cfg,
                "dump-callgraph",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (shown, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let mut t = u.table(&["function", "callers", "outgoing"]);
                    for row in &shown {
                        t.add_row(vec![
                            comfy_table::Cell::new(u.name(&row.function)),
                            comfy_table::Cell::new(u.dim(&row.callers.to_string())),
                            comfy_table::Cell::new(u.dim(&row.outgoing.to_string())),
                        ]);
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} functions)", rows.len())));
                    render_truncation_notice(shown.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja dump-callgraph <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

// dump-edges — the renderer. `EdgeRecord` collection lives in `bonsai_sdk::edges`.
#[allow(clippy::too_many_arguments)] // stable parameter list — one field per --flag
pub(crate) fn cmd_dump_edges(
    root: &std::path::Path,
    from_filter: Option<&str>,
    to_filter: Option<&str>,
    precision_filter: Option<PrecisionFilter>,
    compact: bool,
    edge_id_filter: Option<&str>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    if matches!(
        precision_filter,
        Some(PrecisionFilter::OverApproximate | PrecisionFilter::Unknown)
    ) {
        anyhow::bail!("`dump-edges` is semantic-only; use `--precision exact` or `--precision narrowed`");
    }
    let (project, _footer) = open_project(root)?;
    let filters = bonsai_sdk::EdgesFilters {
        from: from_filter,
        to: to_filter,
        precision: precision_filter.map(|p| match p {
            PrecisionFilter::Exact => bonsai_sdk::PrecisionClass::Exact,
            PrecisionFilter::Narrowed => bonsai_sdk::PrecisionClass::Narrowed,
            PrecisionFilter::OverApproximate => bonsai_sdk::PrecisionClass::OverApproximate,
            PrecisionFilter::Unknown => bonsai_sdk::PrecisionClass::Unknown,
        }),
        edge_id: edge_id_filter,
    };
    let stage = progress::ScopedSpinner::new("collecting semantic edges");
    let records = project.dump().edges(filters);
    stage.finish();
    if let Some(id) = edge_id_filter {
        if records.is_empty() {
            anyhow::bail!(
                "no edge matching `{id}` in this workspace + filter combination. \
                 Edge ids are printed in the leftmost column of `dump-edges` text output \
                 and in `edge_id` on each object in `--format json`."
            );
        }
    }
    let filters_hash = paging::hash_filters(&[
        ("from", from_filter.unwrap_or("")),
        ("to", to_filter.unwrap_or("")),
        (
            "precision",
            &precision_filter.map(|p| format!("{p:?}")).unwrap_or_default(),
        ),
        ("compact", if compact { "1" } else { "0" }),
        ("edge_id", edge_id_filter.unwrap_or("")),
    ]);
    let cost = |e: &bonsai_sdk::EdgeRecord| {
        (e.caller_name.len()
            + e.callee_name.len()
            + e.edge_id.len()
            + e.call_text.len().min(120)
            + e.call_file.len()
            + e.resolver_stage.len()
            + e.evidence.len().min(120)
            + 32) as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &records, &paging_cfg, "dump-edges", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &records,
                &paging_cfg,
                "dump-edges",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (shown, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    render_edge_records_text(&shown, compact, records.len());
                    render_truncation_notice(shown.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja dump-edges <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn cmd_dump_resolution(
    root: &std::path::Path,
    file_filter: Option<&str>,
    unresolved_only: bool,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let filters = bonsai_sdk::ResolutionCoverageFilters {
        file: file_filter,
        unresolved_only,
    };
    let stage = progress::ScopedSpinner::new("collecting resolution coverage");
    let rows = project.dump().resolution_coverage(filters);
    stage.finish();
    let filters_hash = paging::hash_filters(&[
        ("file", file_filter.unwrap_or("")),
        ("unresolved_only", if unresolved_only { "1" } else { "0" }),
    ]);
    let cost = |row: &bonsai_sdk::ResolutionCoverageFileRow| {
        (row.file.len() + row.decls.len().saturating_mul(48) + 96) as u64 + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &rows, &paging_cfg, "dump-resolution", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &rows,
                &paging_cfg,
                "dump-resolution",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (shown, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    render_resolution_coverage_text(&shown, rows.len());
                    render_truncation_notice(shown.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja dump-resolution <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

fn render_resolution_coverage_text(rows: &[bonsai_sdk::ResolutionCoverageFileRow], total: usize) {
    let u = ui();
    if rows.is_empty() {
        cli_println!("{}", u.dim("(no resolution coverage rows matched)"));
        return;
    }
    let mut table = u.table(&[
        "file",
        "funcs",
        "calls",
        "resolved",
        "external",
        "unresolved",
        "coverage",
        "gaps",
    ]);
    for row in rows {
        let gaps = if row.analysis_incomplete_reasons.is_empty() {
            String::new()
        } else {
            row.analysis_incomplete_reasons.join("; ")
        };
        table.add_row(vec![
            comfy_table::Cell::new(u.path(&short_file(&row.file))),
            comfy_table::Cell::new(u.dim(&row.functions.to_string())),
            comfy_table::Cell::new(u.dim(&row.call_sites.to_string())),
            comfy_table::Cell::new(u.dim(&row.resolved_call_sites.to_string())),
            comfy_table::Cell::new(u.dim(&row.external_call_sites.to_string())),
            comfy_table::Cell::new(if row.unresolved_call_sites == 0 {
                u.dim("0")
            } else {
                u.warn(&row.unresolved_call_sites.to_string())
            }),
            comfy_table::Cell::new(u.annotation(&format!("{:.1}%", row.coverage_percent))),
            comfy_table::Cell::new(if gaps.is_empty() {
                u.dim("-")
            } else {
                u.warn(&gaps)
            }),
        ]);
    }
    cli_println!("{table}");
    cli_println!("{}", u.dim(&format!("({total} files)")));
}

fn render_edge_records_text(records: &[bonsai_sdk::EdgeRecord], compact: bool, total: usize) {
    let u = ui();
    if records.is_empty() {
        cli_println!("{}", u.dim("(no edges matched)"));
        return;
    }
    if compact {
        // Compact one-line-per-edge render. Columns:
        //   E:id  kind  precision  caller → callee (callee file:line)  call site
        //
        // Callee file:line is included so virtual edges with multiple
        // candidates (same edge_id, different callee decls) stay
        // visually distinct — the column is what tells the reader
        // "this is one of N candidates" at a glance.
        let mut table = u.table(&[
            "edge",
            "kind",
            "precision",
            "stage",
            "conf",
            "caller → callee",
            "callee loc",
            "call site",
        ]);
        for edge in records {
            let arrow_row = format!("{} → {}", edge.caller_name, edge.callee_name);
            let callee_loc = format!("{}:{}", short_file(&edge.callee_file), edge.callee_line);
            let call_site = format!("{}:{}", short_file(&edge.call_file), edge.call_line);
            table.add_row(vec![
                comfy_table::Cell::new(u.dim(&edge.edge_id)),
                comfy_table::Cell::new(u.annotation(&edge.kind)),
                comfy_table::Cell::new(precision_tag(u, &edge.precision)),
                comfy_table::Cell::new(u.annotation(&edge.resolver_stage)),
                comfy_table::Cell::new(u.dim(&edge.confidence.to_string())),
                comfy_table::Cell::new(u.name(&arrow_row)),
                comfy_table::Cell::new(u.path(&callee_loc)),
                comfy_table::Cell::new(u.path(&call_site)),
            ]);
        }
        cli_println!("{table}");
        cli_println!("{}", u.dim(&format!("({total} edges)")));
        return;
    }
    // Full multi-line render: one block per edge with full locations
    // and the call-site source snippet.
    for edge in records {
        cli_println!();
        cli_println!(
            "{} {} {} {}",
            u.annotation(&edge.edge_id),
            u.annotation(&edge.kind),
            precision_tag(u, &edge.precision),
            u.annotation(&format!("{}:{}%", edge.resolver_stage, edge.confidence)),
        );
        cli_println!(
            "  {} {} {}",
            u.dim("caller:"),
            u.name(&edge.caller_name),
            u.path(&format!(
                "({}:{})",
                short_file(&edge.caller_file),
                edge.caller_line
            )),
        );
        cli_println!(
            "  {} {} {}",
            u.dim("callee:"),
            u.name(&edge.callee_name),
            u.path(&format!(
                "({}:{})",
                short_file(&edge.callee_file),
                edge.callee_line
            )),
        );
        cli_println!("  {} {}", u.dim("why:   "), u.dim(&edge.evidence),);
        cli_println!(
            "  {}   {}  {}",
            u.dim("call:  "),
            u.path(&format!(
                "{}:{}:{}",
                short_file(&edge.call_file),
                edge.call_line,
                edge.call_column
            )),
            u.name(&edge.call_text),
        );
    }
    cli_println!();
    cli_println!("{}", u.dim(&format!("({} edges)", records.len())));
}

/// Colorize precision/outcome tags. `exact` / `narrowed` stay dim;
/// diagnostic-only states such as `ambiguous`, `over-approximate`,
/// `unknown`, and `unresolved` get the palette's warning color.
fn precision_tag(u: &Ui, precision: &str) -> String {
    match precision {
        "exact" | "narrowed" => u.dim(precision),
        _ => u.warn(precision),
    }
}

// dump-ast — tree-sitter parse tree renderer. Walker / `AstFileDump`
// live in `bonsai_sdk::ast`; this file owns only the text renderer.
#[allow(clippy::too_many_arguments)] // stable parameter list — one field per --flag
pub(crate) fn cmd_dump_ast(
    root_dir: &std::path::Path,
    file_filter: Option<&str>,
    function_filter: Option<&str>,
    compact: bool,
    max_depth: Option<usize>,
    node_id_filter: Option<&str>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root_dir)?;
    let filters = bonsai_sdk::AstFilters {
        file: file_filter,
        function: function_filter,
        max_depth,
        node_id: node_id_filter,
    };
    let stage = progress::ScopedSpinner::new("building AST dump");
    let file_dumps = match project.dump().ast(filters) {
        bonsai_sdk::AstOutcome::Dumps(d) => d,
        bonsai_sdk::AstOutcome::NodeIdNotFound => anyhow::bail!(
            "no AST node matching `{}` in this workspace + filter \
             combination. Node ids are printed next to every node in text \
             output and in `node_id` on each object in `--format json`.",
            node_id_filter.unwrap_or("")
        ),
    };
    stage.finish();
    let filters_hash = paging::hash_filters(&[
        ("file", file_filter.unwrap_or("")),
        ("function", function_filter.unwrap_or("")),
        ("compact", if compact { "1" } else { "0" }),
        ("max_depth", &max_depth.map(|n| n.to_string()).unwrap_or_default()),
        ("node_id", node_id_filter.unwrap_or("")),
    ]);
    // One AST file-dump is enormously larger than one browse row
    // (tens of thousands of named nodes in a real source file).
    // Byte cost per file-dump. Each rendered node takes ~180 bytes
    // once chrome is counted — depth-indent (4 chars per level,
    // typical depth 6–10), the themed `kind` label, the `N:id`
    // stable hash, the `line:col-line:col` span, the optional
    // source-text snippet (~50 bytes), a trailing newline, and
    // ANSI burst overhead. The original 80-byte estimate
    // underreported by ~2× on realistic files; a 4 K budget would
    // fit 50 nodes but render ~12 K tokens of actual output.
    fn node_count(node: &bonsai_sdk::AstNode) -> usize {
        1 + node.children.iter().map(node_count).sum::<usize>()
    }
    let cost = |d: &bonsai_sdk::AstFileDump| (d.path.len() + node_count(&d.root) * 180) as u64;
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            if paging_cfg.json_wrapped() {
                emit_json_value_paged_cached(root_dir, &file_dumps, &paging_cfg, "dump-ast", filters_hash)?;
            } else {
                emit_json_paged_cached(root_dir, &file_dumps, &paging_cfg, "dump-ast", filters_hash, cost)?;
            }
        }
        BrowseFormat::Text => {
            let (shown, truncated) = apply_text_limit(&file_dumps, effective_limit(limit, &paging_cfg));
            let lines = render_ast_text_lines(&shown, compact, file_dumps.len());
            page_cache::emit_paged_text(
                root_dir,
                &lines,
                &paging_cfg,
                "dump-ast",
                filters_hash,
                |line| line.len() as u64 + 128,
                |paged, info, _cfg| {
                    for line in paged {
                        cli_println!("{line}");
                    }
                    render_truncation_notice(shown.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja dump-ast <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

fn render_ast_text_lines(file_dumps: &[bonsai_sdk::AstFileDump], compact: bool, total: usize) -> Vec<String> {
    let u = ui();
    let mut lines = Vec::new();
    if file_dumps.is_empty() {
        lines.push(u.dim("(no AST matched)"));
        return lines;
    }
    let mut total_nodes = 0usize;
    for file_dump in file_dumps {
        lines.push(String::new());
        lines.push(format!("{} {}", u.heading("═══"), u.path(&file_dump.path)));
        total_nodes += render_ast_node_text(u, &file_dump.root, 0, compact, &mut lines);
    }
    lines.push(String::new());
    lines.push(u.dim(&format!("({total} file(s), {total_nodes} node(s))")));
    lines
}

/// Render one `AstNode` + its subtree. Returns the total number of
/// nodes emitted so the outer render can show a summary line.
/// Indentation is 2 spaces per level. In compact mode the verbatim
/// source text is dropped; in full mode it's shown dim-styled after
/// the kind / range / id header.
fn render_ast_node_text(
    u: &Ui,
    node: &bonsai_sdk::AstNode,
    depth: usize,
    compact: bool,
    lines: &mut Vec<String>,
) -> usize {
    let indent = "  ".repeat(depth);
    let field_prefix = match node.field.as_deref() {
        Some(field) => format!("{}: ", u.kind(field)),
        None => String::new(),
    };
    let range = format!(
        "[{}:{}..{}:{}]",
        node.start_line, node.start_column, node.end_line, node.end_column
    );
    if compact {
        lines.push(format!(
            "{indent}{field_prefix}{} {} {}",
            u.name(&node.kind),
            u.path(&range),
            u.dim(&node.node_id),
        ));
    } else {
        let text_preview = match node.text.as_deref() {
            Some(text) if !text.is_empty() && node.children.is_empty() => {
                let preview_width = 96usize.saturating_sub(indent.len()).max(24);
                let preview = truncate(&text.replace('\n', "\\n"), preview_width);
                format!("  {}", u.dim(&format!("\"{preview}\"")))
            }
            _ => String::new(),
        };
        lines.push(format!(
            "{indent}{field_prefix}{} {} {}{text_preview}",
            u.name(&node.kind),
            u.path(&range),
            u.dim(&node.node_id),
        ));
    }
    let mut total = 1;
    for child in &node.children {
        total += render_ast_node_text(u, child, depth + 1, compact, lines);
    }
    total
}

// dump-resolve — stage-by-stage trace of the name resolver. Trace
// computation lives in `bonsai_sdk::resolve`; this file owns the printer.
pub(crate) fn cmd_dump_resolve(
    root: &std::path::Path,
    query: &str,
    in_file_filter: Option<&str>,
    compact: bool,
    candidate_id_filter: Option<&str>,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let filters = bonsai_sdk::ResolveFilters {
        in_file: in_file_filter,
        candidate_id: candidate_id_filter,
    };
    let stage = progress::ScopedSpinner::new("resolving symbol candidates");
    let trace = match project
        .dump()
        .resolve_with_suggestions(query, filters, |ws, q| nearest_names(ws, q, 5))
    {
        bonsai_sdk::ResolveOutcome::Trace(t) => t,
        bonsai_sdk::ResolveOutcome::FileContextNotFound { needle } => anyhow::bail!(
            "dump-resolve: --in-file `{needle}` did not match any indexed file. \
             File context is required for semantic narrowing; rerun with a path \
             substring from `bonsai-ninja tree` or omit --in-file for a name inventory."
        ),
        bonsai_sdk::ResolveOutcome::CandidateNotFound => anyhow::bail!(
            "no candidate matching `{}` for query `{query}`. \
             Candidate ids are printed next to every row in `dump-resolve` \
             text output and in `candidate_id` on each object in \
             `--format json`.",
            candidate_id_filter.unwrap_or("")
        ),
    };
    stage.finish();

    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => cli_println!("{}", serde_json::to_string_pretty(&trace)?),
        BrowseFormat::Text => render_resolve_trace_text(&trace, compact),
    }

    // Unresolved queries exit non-zero so CI / scripts can detect
    // surprise zero-candidate outcomes. (Non-zero status is the
    // convention `--flow <id>` / `--group <id>` / `--edge <id>`
    // already follow for unknown-id errors.)
    if trace.outcome == "unresolved" && candidate_id_filter.is_none() {
        std::process::exit(2);
    }
    Ok(())
}

fn render_resolve_trace_text(trace: &bonsai_sdk::ResolveTrace, compact: bool) {
    let u = ui();
    if compact {
        render_resolve_compact(u, trace);
        return;
    }
    render_resolve_full(u, trace);
}

fn render_resolve_compact(u: &Ui, trace: &bonsai_sdk::ResolveTrace) {
    // One-line header summarizing the lookup, then one row per
    // candidate. Matches the density `inspect --compact` aims for.
    let file_tag = match trace.in_file.as_deref() {
        Some(path) => format!("in {}", short_file(path)),
        None => "global".to_string(),
    };
    cli_println!(
        "{} {} ({}) → {} {}",
        u.label("resolve"),
        u.name(&trace.query),
        u.dim(&file_tag),
        u.name(&trace.candidates.len().to_string()),
        precision_tag(u, &trace.outcome),
    );
    render_resolve_incomplete_note(u, trace);
    if trace.candidates.is_empty() {
        if !trace.suggestions.is_empty() {
            cli_println!("  {} {}", u.dim("did you mean:"), trace.suggestions.join(", "));
        }
        return;
    }
    let mut table = u.table(&["candidate", "kind", "name", "location"]);
    for candidate in &trace.candidates {
        let location = format!(
            "{}:{}:{}",
            short_file(&candidate.file),
            candidate.line,
            candidate.column
        );
        table.add_row(vec![
            comfy_table::Cell::new(u.dim(&candidate.candidate_id)),
            comfy_table::Cell::new(u.annotation(&candidate.kind)),
            comfy_table::Cell::new(u.name(&candidate.name)),
            comfy_table::Cell::new(u.path(&location)),
        ]);
    }
    cli_println!("{table}");
}

fn render_resolve_full(u: &Ui, trace: &bonsai_sdk::ResolveTrace) {
    cli_println!(
        "{} {} {}",
        u.label("resolve"),
        u.name(&trace.query),
        match trace.in_file.as_deref() {
            Some(path) => format!("({} {})", u.dim("in"), u.path(&short_file(path))),
            None => u.dim("(global — no file context)"),
        }
    );
    render_resolve_incomplete_note(u, trace);

    // Stage 1: short_callee. `u.heading` already prepends a
    // leading `\n` so section separation comes for free — no manual
    // `cli_println!()` between stages.
    cli_println!("{}", u.heading("  stage 1 — short_callee"));
    cli_println!("    {} {}", u.dim("input:"), u.name(&trace.query));
    cli_println!("    {} {}", u.dim("short:"), u.name(&trace.short));
    if trace.short != trace.query {
        cli_println!(
            "    {} {}",
            u.dim("note:"),
            u.dim("trimmed to rightmost path segment"),
        );
    }
    // Stage 2: alias rewrite.
    cli_println!("{}", u.heading("  stage 2 — alias rewrite"));
    if trace.in_file.is_none() {
        cli_println!("    {}", u.dim("skipped — no --in-file; alias table is per-file"),);
    } else {
        cli_println!(
            "    {} {} {}",
            u.dim("alias map:"),
            u.name(&trace.alias_map_size.to_string()),
            u.dim("entries"),
        );
        match trace.alias_rewrite.as_ref() {
            Some((local, original)) => {
                cli_println!(
                    "    {} {} {} {}",
                    u.dim("rewrite:"),
                    u.name(local),
                    u.dim("→"),
                    u.name(original),
                );
            }
            None => {
                let note = format!("no alias matched — lookup stays on `{}`", trace.short);
                cli_println!("    {} {}", u.dim("rewrite:"), u.dim(&note));
            }
        }
    }
    // Stage 3: primary lookup.
    cli_println!("{}", u.heading("  stage 3 — semantic resolver"));
    cli_println!(
        "    {} {}",
        u.dim("lookup name:"),
        u.name(&trace.primary_lookup_name),
    );
    cli_println!(
        "    {} {} {}",
        u.dim("candidates:"),
        u.name(&trace.primary_candidate_count.to_string()),
        u.dim(candidate_count_note(trace.primary_candidate_count)),
    );
    // Stage 4: fallback.
    cli_println!("{}", u.heading("  stage 4 — broad fallback guard"));
    if !trace.fallback_applied {
        cli_println!(
            "    {}",
            u.dim(if trace.primary_candidate_count > 0 {
                "skipped — primary lookup succeeded"
            } else {
                "skipped — semantic mode does not broaden unresolved names"
            }),
        );
    } else {
        cli_println!("    {} {}", u.dim("retried with literal:"), u.name(&trace.query),);
        cli_println!(
            "    {} {} {}",
            u.dim("candidates:"),
            u.name(&trace.fallback_candidate_count.to_string()),
            u.dim(candidate_count_note(trace.fallback_candidate_count)),
        );
    }
    // Outcome banner + candidate table.
    cli_println!(
        "{} {} → {}",
        u.heading("  outcome:"),
        u.name(&format!("{} candidate(s)", trace.candidates.len())),
        precision_tag(u, &trace.outcome),
    );
    cli_println!();

    if trace.candidates.is_empty() {
        cli_println!("    {}", u.dim("unresolved — call would escape the workspace"));
        if !trace.suggestions.is_empty() {
            cli_println!("    {} {}", u.dim("did you mean:"), trace.suggestions.join(", "),);
        }
        return;
    }
    for candidate in &trace.candidates {
        cli_println!(
            "  {} {} {}",
            u.annotation(&candidate.candidate_id),
            u.annotation(&candidate.kind),
            u.name(&candidate.name),
        );
        cli_println!(
            "    {} {} {} {}",
            u.dim("at:   "),
            u.path(&format!(
                "{}:{}:{}",
                short_file(&candidate.file),
                candidate.line,
                candidate.column
            )),
            u.dim("FuncId:"),
            u.dim(&candidate.func_id.to_string()),
        );
    }
}

fn render_resolve_incomplete_note(u: &Ui, trace: &bonsai_sdk::ResolveTrace) {
    if trace.analysis_complete {
        return;
    }
    let reasons = if trace.analysis_incomplete_reasons.is_empty() {
        "analysis-incomplete".to_string()
    } else {
        trace.analysis_incomplete_reasons.join("; ")
    };
    cli_println!(
        "  {} {}",
        u.warn("semantic resolution incomplete:"),
        u.dim(&reasons),
    );
}

/// Human-readable note for the candidate count column. Surfaces the
/// outcome that count implies so users don't have to re-interpret.
fn candidate_count_note(count: usize) -> &'static str {
    match count {
        0 => "(unresolved — no matching decls in workspace)",
        1 => "(single candidate — direct / narrowed edge)",
        _ => "(multi-candidate — ambiguous without call-site context)",
    }
}

// dump-taint — runs the intra+interprocedural pipeline and emits one
// record per cross-function propagation. The data layer
// (`TaintReport`, `TaintRecord`, etc.) lives in `bonsai_sdk::taint`;
// this file owns the renderer.
#[allow(clippy::too_many_arguments)] // stable parameter list — one field per --flag
pub(crate) fn cmd_dump_taint(
    root: &std::path::Path,
    source_name: &str,
    seeds: &[String],
    sink_filter: Option<&str>,
    compact: bool,
    taint_id_filter: Option<&str>,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project_index_only_with_rulepack(root, None)?;
    let filters = bonsai_sdk::TaintFilters {
        source: source_name,
        seeds: seeds.to_vec(),
        sink: sink_filter,
        taint_id: taint_id_filter,
        ..Default::default()
    };
    // The taint pipeline (cross-function propagation + sink reachability)
    // can run for a while on large workspaces; spin so the user knows
    // the CLI didn't hang.
    let spin = progress::ScopedSpinner::new("propagating taint");
    let outcome = project.dump().taint(filters);
    spin.finish();
    let filters_hash = dump_taint_filters_hash(source_name, seeds, sink_filter, compact, taint_id_filter);
    match outcome {
        bonsai_sdk::TaintOutcome::SourceNotFound => anyhow::bail!(
            "dump-taint: no callable decl named `{source_name}` in the workspace. \
             Try `bonsai-ninja defs <ws> --name {source_name}` to list available names."
        ),
        bonsai_sdk::TaintOutcome::SourceAmbiguous { candidates, .. } => {
            let preview = candidates
                .iter()
                .take(8)
                .map(|candidate| {
                    format!(
                        "{}:{}:{} {}",
                        candidate.file, candidate.line, candidate.column, candidate.name
                    )
                })
                .collect::<Vec<_>>()
                .join("\n  ");
            anyhow::bail!(
                "dump-taint: source `{source_name}` is ambiguous ({} callable decls). \
                 Use a more-qualified source name.\n  {}",
                candidates.len(),
                preview
            )
        }
        bonsai_sdk::TaintOutcome::TaintIdNotFound => anyhow::bail!(
            "no propagation matching `{}` in this workspace + seed combination. \
             Taint ids are shown in the leftmost column of `dump-taint` text output and \
             in `taint_id` on each object in `--format json`.",
            taint_id_filter.unwrap_or("")
        ),
        bonsai_sdk::TaintOutcome::Report(report) => match format {
            BrowseFormat::Json | BrowseFormat::Sarif => {
                render_taint_report_json_paged(root, &report, &paging_cfg, filters_hash)?;
            }
            BrowseFormat::Text => {
                render_taint_report_text_paged(root, &report, compact, &paging_cfg, filters_hash)?;
            }
        },
    }
    Ok(())
}

fn render_taint_report_json_paged(
    root: &std::path::Path,
    report: &bonsai_sdk::TaintReport,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<()> {
    if !paging_cfg.json_wrapped() {
        cli_println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    let force_page_metadata = paging_cfg.context.is_some()
        || !matches!(paging_cfg.page, paging::PageArg::First)
        || crate::filter::active().is_active();
    page_cache::emit_paged_text(
        root,
        &report.records,
        paging_cfg,
        "dump-taint",
        filters_hash,
        |record| {
            let arg_bytes: usize = record
                .tainted_args
                .iter()
                .map(|arg| arg.value_text.len() + arg.param_name.len() + 48)
                .sum();
            (record.taint_id.len()
                + record.caller_name.len()
                + record.caller_file.len()
                + record.callee_name.len()
                + record.callee_file.len()
                + record.call_file.len()
                + record.call_code.len()
                + record.edge_kind.len()
                + record.edge_precision.len()
                + arg_bytes
                + 256) as u64
        },
        |records, info, _cfg| {
            let presentation_complete = info.page_number == 1 && info.is_last;
            if !force_page_metadata && presentation_complete {
                cli_println!("{}", serde_json::to_string_pretty(report)?);
                return Ok(());
            }

            let presentation_incomplete_reasons = paged_json_incomplete_reasons("dump-taint", info);
            let mut semantic_incomplete_reasons = report.analysis_incomplete_reasons.clone();
            if !report.analysis_complete && semantic_incomplete_reasons.is_empty() {
                semantic_incomplete_reasons
                    .push("dump-taint incomplete: unknown semantic reason".to_string());
            }
            let mut combined_incomplete_reasons = semantic_incomplete_reasons.clone();
            combined_incomplete_reasons.extend(presentation_incomplete_reasons.iter().cloned());
            combined_incomplete_reasons.sort();
            combined_incomplete_reasons.dedup();

            let payload = serde_json::json!({
                "source": &report.source,
                "seeds": &report.seeds,
                "analysis_complete": report.analysis_complete
                    && presentation_complete
                    && combined_incomplete_reasons.is_empty(),
                "analysis_incomplete_reasons": combined_incomplete_reasons,
                "semantic_analysis_complete": report.analysis_complete,
                "semantic_analysis_incomplete_reasons": semantic_incomplete_reasons,
                "presentation_complete": presentation_complete,
                "presentation_incomplete_reasons": presentation_incomplete_reasons,
                "precision": &report.precision,
                "pairs_analyzed": report.pairs_analyzed,
                "records": records,
                "page": page_info_to_json(info),
            });
            cli_println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn dump_taint_filters_hash(
    source_name: &str,
    seeds: &[String],
    sink_filter: Option<&str>,
    compact: bool,
    taint_id_filter: Option<&str>,
) -> u64 {
    let seeds_joined = seeds.join("\0");
    let compact_text = if compact { "1" } else { "0" };
    paging::hash_filters(&[
        ("source", source_name),
        ("seeds", &seeds_joined),
        ("sink", sink_filter.unwrap_or("")),
        ("compact", compact_text),
        ("taint", taint_id_filter.unwrap_or("")),
    ])
}

fn render_taint_report_text_paged(
    root: &std::path::Path,
    report: &bonsai_sdk::TaintReport,
    compact: bool,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<()> {
    let rendered = page_cache::capture(|| {
        render_taint_report_text(report, compact);
        Ok(())
    })?;
    let lines: Vec<String> = rendered.lines().map(str::to_string).collect();
    page_cache::emit_paged_text(
        root,
        &lines,
        paging_cfg,
        "dump-taint",
        filters_hash,
        |line| line.len() as u64 + 128,
        |paged, info, _cfg| {
            for line in paged {
                cli_println!("{line}");
            }
            render_paging_footer(info, "bonsai-ninja dump-taint <workspace>");
            Ok(())
        },
    )
}

fn render_taint_report_text(report: &bonsai_sdk::TaintReport, compact: bool) {
    let u = ui();
    // Header — source, seed, precision, pair count.
    let mut seed_preview = report.seeds.clone();
    seed_preview.sort();
    cli_println!(
        "{} {} {} {} {} {}",
        u.label("taint"),
        u.name(&report.source),
        u.dim("seed:"),
        u.name(&format!("{{{}}}", seed_preview.join(", "))),
        u.dim("→"),
        precision_tag(u, &report.precision),
    );
    cli_println!(
        "  {} {} {} {}",
        u.dim("pairs analyzed:"),
        u.name(&report.pairs_analyzed.to_string()),
        u.dim("· propagations:"),
        u.name(&report.records.len().to_string()),
    );
    if report.analysis_complete {
        cli_println!("  {}", u.dim("analysis: complete"));
    } else {
        let reasons = if report.analysis_incomplete_reasons.is_empty() {
            "unknown reason".to_string()
        } else {
            report.analysis_incomplete_reasons.join("; ")
        };
        for line in u.wrapped_warn_labeled_lines("analysis incomplete", &reasons) {
            cli_println!("{line}");
        }
    }
    if report.records.is_empty() {
        cli_println!();
        cli_println!(
            "  {}",
            u.dim("(no cross-function propagations — seed may not flow through any call site)")
        );
        return;
    }
    if compact {
        let mut table = u.table(&[
            "taint",
            "kind",
            "precision",
            "caller → callee",
            "args",
            "call site",
        ]);
        for record in &report.records {
            let arrow = format!("{} → {}", record.caller_name, record.callee_name);
            let args: String = record
                .tainted_args
                .iter()
                .map(|a| format!("{}→{}", a.value_text, a.param_name))
                .collect::<Vec<_>>()
                .join(", ");
            let call_site = format!("{}:{}", short_file(&record.call_file), record.call_line);
            table.add_row(vec![
                comfy_table::Cell::new(u.dim(&record.taint_id)),
                comfy_table::Cell::new(u.annotation(&record.edge_kind)),
                comfy_table::Cell::new(precision_tag(u, &record.edge_precision)),
                comfy_table::Cell::new(u.name(&arrow)),
                comfy_table::Cell::new(u.annotation(&args)),
                comfy_table::Cell::new(u.path(&call_site)),
            ]);
        }
        cli_println!("{table}");
        cli_println!("{}", u.dim(&format!("({} propagation(s))", report.records.len())));
        return;
    }
    // Full render — one multi-line block per propagation.
    for record in &report.records {
        cli_println!();
        cli_println!(
            "{} {} {}",
            u.annotation(&record.taint_id),
            u.annotation(&record.edge_kind),
            precision_tag(u, &record.edge_precision),
        );
        cli_println!(
            "  {} {} {}",
            u.dim("caller:"),
            u.name(&record.caller_name),
            u.path(&format!(
                "({}:{})",
                short_file(&record.caller_file),
                record.caller_line
            )),
        );
        cli_println!(
            "  {} {} {}",
            u.dim("callee:"),
            u.name(&record.callee_name),
            u.path(&format!(
                "({}:{})",
                short_file(&record.callee_file),
                record.callee_line
            )),
        );
        cli_println!(
            "  {}   {}",
            u.dim("call:  "),
            u.path(&format!(
                "{}:{}:{}",
                short_file(&record.call_file),
                record.call_line,
                record.call_column
            )),
        );
        if !record.tainted_args.is_empty() {
            cli_println!("  {}", u.dim("tainted args:"));
            for arg in &record.tainted_args {
                let index = if arg.index == usize::MAX {
                    "receiver".to_string()
                } else {
                    format!("[{}]", arg.index)
                };
                cli_println!(
                    "    {} {} {} {}",
                    u.dim(&index),
                    u.name(&arg.value_text),
                    u.dim("→"),
                    u.name(&arg.param_name),
                );
            }
        }
    }
    cli_println!();
    cli_println!("{}", u.dim(&format!("({} propagation(s))", report.records.len())));
}
