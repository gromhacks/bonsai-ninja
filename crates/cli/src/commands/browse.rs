//! Browse commands: `defs`, `calls`, `imports`, `vars`, `strings`,
//! `comments`, `args`, `classes`, `refs`, `search`. Each reads from the shared
//! `GlobalIndex` and emits a uniform `{header row, rows, footer}`
//! shape. JSON output is a bare array by default; `--context` /
//! `--page` opts into `{rows, page}` wrapping.

use anyhow::Result;
use bonsai_lang_api::FlowEvent;
use bonsai_sdk::Workspace;
use comfy_table::Cell;

use crate::args::{BrowseFormat, OutputFormat};
use crate::footer::{render_paging_footer, render_truncation_notice};
use crate::page_cache;
use crate::paging;
use crate::progress;
use crate::ui::{extension_for, Ui};
use crate::{cli_println, ui};

use super::open_project_index_only as open_project;

// Filter + output types are re-exports of the SDK definitions in
// `bonsai_browse`. Keeping them aliased here means existing call
// sites in the dispatcher need no changes — they already build the
// struct field-by-field — and library consumers get the exact same
// types.
pub(crate) use bonsai_sdk::{
    ArgsFilters, CallsFilters, ClassesFilters, CommentsFilters, DefsFilters, ImportsFilters, RefsFilters,
    SearchFilters, StringsFilters, VarsFilters,
};

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_defs(
    root: &std::path::Path,
    f: DefsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .defs(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("kind", f.kind.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("name", f.name.unwrap_or("")),
        ("has_callee", f.has_callee.unwrap_or("")),
        ("has_decorator", f.has_decorator.unwrap_or("")),
        ("has_param", f.has_param.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let cost = |d: &bonsai_sdk::DefOut| {
        (d.name.len() + d.file.len() + 24 + d.params.iter().map(|p| p.len() + 2).sum::<usize>()) as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "defs", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "defs",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers =
                        with_flows_header(&["name", "kind", "location", "signature", "callees"], flows);
                    let mut t = u.table(&headers);
                    let decls_by_name = decls_lookup(ws);
                    for d in &rows {
                        // Perl's adapter emits both sigil'd (`$token`) and
                        // bare (`token`) forms for each parameter so the
                        // taint-state lookup succeeds against either shape.
                        // For human-facing signature display the duplicate
                        // is noise — prefer the sigil'd form (it's what the
                        // Perl reader actually wrote) and drop the bare
                        // companion. For languages without sigils this is a
                        // no-op.
                        let display_params = dedup_sigil_params(&d.params);
                        let signature = if display_params.is_empty() {
                            format!("{}()", d.name)
                        } else {
                            format!("{}({})", d.name, display_params.join(", "))
                        };
                        let loc = format!("{}:{}:{}", short_file(&d.file), d.line, d.column);
                        let callees_cell = match decls_by_name.get(&d.name) {
                            Some(decl) => summarize_callees(decl, 3),
                            None => String::new(),
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&d.name)),
                            Cell::new(u.kind(&d.kind)),
                            Cell::new(u.path(&loc)),
                            Cell::new(u.snippet(&signature, extension_for(&d.file))),
                            Cell::new(u.dim(&callees_cell)),
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            cells.push(flows_cell(u, &ann.labels_for(&d.file, d.line)));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} definitions)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja defs <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

/// Build a name → `&Decl` lookup used by browse commands that want to
/// surface a definition's flow (callees) alongside its location.
pub(crate) fn decls_lookup(ws: &Workspace) -> std::collections::HashMap<String, bonsai_lang_api::Decl> {
    let mut map = std::collections::HashMap::new();
    let global = ws.db().global_index();
    for f in global.all_files() {
        for d in global.decls_in(f) {
            map.entry(d.name.clone()).or_insert_with(|| d.clone());
        }
    }
    map
}

/// Short preview of a function's outgoing calls: the first `limit`
/// callee names, joined with `→`, followed by an ellipsis if there are
/// more. Returns an empty string for call-less bodies (e.g. classes).
pub(crate) fn summarize_callees(decl: &bonsai_lang_api::Decl, limit: usize) -> String {
    let mut names: Vec<String> = Vec::new();
    collect_callees(&decl.flow_events, &mut names);
    // De-duplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));
    if names.is_empty() {
        return String::new();
    }
    let total = names.len();
    let shown: Vec<String> = names.into_iter().take(limit).collect();
    if total > limit {
        format!("{} (+{})", shown.join(" → "), total - limit)
    } else {
        shown.join(" → ")
    }
}

/// UTF-8-safe middle truncation: keeps the first `n` characters and
/// appends an ellipsis when `s` overflows. Counts by chars (not
/// bytes) so slicing never falls inside a multi-byte character.
pub(crate) fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else if n == 0 {
        "…".to_string()
    } else {
        let mut end = 0;
        for (i, _ch) in s.char_indices().take(n) {
            end = i;
        }
        let cutoff = s[end..].chars().next().map(|c| end + c.len_utf8()).unwrap_or(end);
        format!("{}…", &s[..cutoff])
    }
}

pub(crate) fn short_file(p: &str) -> String {
    // Keep last 3 path components for table compactness.
    let parts: Vec<&str> = p.rsplitn(4, '/').collect();
    if parts.len() <= 3 {
        return p.to_string();
    }
    let mut keep: Vec<&str> = parts[..3].to_vec();
    keep.reverse();
    keep.join("/")
}

/// Apply the text-mode row cap to `rows`. When truncation happens,
/// returns `(visible, Some(total))` so the caller can render a
/// "showing N of TOTAL" hint; otherwise `(visible, None)`. A `limit`
/// of `0` means "uncapped" — matches the user-facing `--limit 0`
/// opt-out.
pub(crate) fn apply_text_limit<T: Clone>(rows: &[T], limit: usize) -> (Vec<T>, Option<usize>) {
    if limit == 0 || rows.len() <= limit {
        (rows.to_vec(), None)
    } else {
        (rows[..limit].to_vec(), Some(rows.len()))
    }
}

/// Resolve the effective legacy row limit. When paging is active
/// (budget set via `--context`, `--page` specified, or `--all`
/// passed), the `--limit` cap becomes redundant — pagination is
/// already deciding "show less", and firing the legacy `showing
/// N of TOTAL — pass --limit 0` notice alongside a `page 1 of 2
/// · context U / B tokens` footer gave the reader two conflicting
/// stories. Yielding to paging in those cases keeps the footer
/// clean.
pub(crate) fn effective_limit(legacy_limit: usize, cfg: &paging::PagingConfig) -> usize {
    // Suppress the legacy `--limit` cap only when the user
    // EXPLICITLY opted into paging (`--context`, `--page`, or
    // `--all`). The implicit default-budget case keeps `--limit`
    // in effect so pre-paging scripts + tests that depend on the
    // legacy "showing N of TOTAL" notice keep working.
    let paging_explicit = cfg.all || cfg.context.is_some() || !matches!(cfg.page, paging::PageArg::First);
    if paging_explicit {
        0
    } else {
        legacy_limit
    }
}

/// Parse the four CLI paging flags into a [`paging::PagingConfig`].
/// Inputs are the raw clap strings; errors propagate up as
/// `anyhow::Error` so a bad `--context 12x` lands as a clean
/// error exit rather than a panic.
pub(crate) fn paging_from_cli(
    context: Option<&str>,
    page: Option<&str>,
    all: bool,
    format: BrowseFormat,
) -> Result<paging::PagingConfig> {
    let ctx = match context {
        Some(s) => paging::parse_context(s).map_err(anyhow::Error::msg)?,
        None => None,
    };
    let pg = match page {
        Some(s) => paging::PageArg::parse(s).map_err(anyhow::Error::msg)?,
        None => paging::PageArg::First,
    };
    let format_class = match format {
        BrowseFormat::Text => paging::FormatClass::Text,
        BrowseFormat::Json | BrowseFormat::Sarif => paging::FormatClass::Programmatic,
    };
    Ok(paging::PagingConfig::new(ctx, pg, None, all, format_class))
}

/// Paging config for commands with the three-way `OutputFormat`
/// (text / json / dot) — `trace` is the only caller today.
/// Classifies `dot` as `RenderOnly` since a half-dot file is
/// meaningless; text paginates, JSON opts in.
pub(crate) fn paging_from_cli_output(
    context: Option<&str>,
    page: Option<&str>,
    all: bool,
    format: OutputFormat,
) -> Result<paging::PagingConfig> {
    let ctx = match context {
        Some(s) => paging::parse_context(s).map_err(anyhow::Error::msg)?,
        None => None,
    };
    let pg = match page {
        Some(s) => paging::PageArg::parse(s).map_err(anyhow::Error::msg)?,
        None => paging::PageArg::First,
    };
    let format_class = match format {
        OutputFormat::Text => paging::FormatClass::Text,
        OutputFormat::Json => paging::FormatClass::Programmatic,
        OutputFormat::Dot => paging::FormatClass::RenderOnly,
    };
    Ok(paging::PagingConfig::new(ctx, pg, None, all, format_class))
}

/// Row-level code-cell folder. Browse commands frequently emit
/// adjacent rows that point at the same source line — for
/// example, multiple call events or argument positions on a
/// single `r.URL.Query().Get("k")` expression. Rendering the
/// source line verbatim for every such row wastes tokens
/// (~30–50 chars per repeat × hundreds of rows on real
/// workspaces) without adding information.
///
/// [`fold_repeated_code`] takes a borrowed code-line string and
/// the previous non-empty rendered line, and returns the string
/// to actually render. When the two match, returns the dim `↑
/// same` marker so the reader can tell at a glance "this row
/// shares the previous source line." Never elides the first
/// occurrence.
///
/// The caller threads a `&mut Option<String>` across the row
/// loop — `None` at the start, updated to the most recent
/// rendered line after each call. Rows whose `code` field is
/// empty (e.g. classes, imports with empty snippets) pass through
/// unchanged.
pub(crate) fn fold_repeated_code(code: &str, prev: &mut Option<String>) -> String {
    if code.is_empty() {
        return code.to_string();
    }
    let trimmed = code.trim();
    if let Some(p) = prev.as_deref() {
        if p == trimmed {
            return "↑ same".to_string();
        }
    }
    *prev = Some(trimmed.to_string());
    code.to_string()
}

/// Header helper: extend `base` with a trailing `"flows"` column
/// when the `flows` column is enabled. Keeps the column list in
/// one place per renderer so ordering stays consistent.
pub(crate) fn with_flows_header<'a>(base: &'a [&'a str], flows: bool) -> Vec<&'a str> {
    let mut out: Vec<&str> = base.to_vec();
    if flows {
        out.push("flows");
    }
    out
}

/// Paired `(annotator, progress_bar)` for a browse-command row
/// loop. When `flows` is set, returns an annotator + a
/// row-count-sized progress bar so the user sees ticks during
/// what would otherwise be a multi-second silent pause on big
/// workspaces (Redis-scale chain enumeration for the first hit
/// against each enclosing function). Both are `None` when the
/// flows column is disabled.
pub(crate) fn build_flow_annotator<'a>(
    ws: &'a Workspace,
    flows: bool,
    row_count: u64,
) -> (
    Option<bonsai_sdk::FlowAnnotator<'a>>,
    Option<indicatif::ProgressBar>,
) {
    if !flows {
        return (None, None);
    }
    let bar = progress::progress_bar("annotating flows", row_count);
    (Some(bonsai_sdk::FlowAnnotator::new(ws)), Some(bar))
}

/// Cell helper: wrap a flow-id string for the `flows` column.
/// Empty string becomes a dim `-` so the column never looks blank.
/// Non-empty strings render in the "loc" style (monospace-leaning,
/// same palette as file paths) so the `F:<16-hex>` ids are easy to
/// spot and copy.
///
/// When the row's enclosing function carries many flows (a hub
/// caller can sit on dozens), the cell can grow large enough to
/// dominate the per-row paging budget — `--callee unwrap` on a
/// huge workspace was paginating one row per page because each row
/// pulled in the same long flow list. Cap the displayed list at a
/// fixed sample plus an "(+N more)" tail so the cell stays bounded
/// while users still see enough flow ids to drill into via
/// `inspect --flow F:<16-hex>`. JSON output is unaffected (the SDK
/// `labels_for` keeps emitting the full set).
pub(crate) fn flows_cell(u: &Ui, labels: &str) -> Cell {
    if labels.is_empty() {
        return Cell::new(u.dim("-"));
    }
    const MAX_INLINE_FLOWS: usize = 8;
    let mut parts: Vec<&str> = labels.split_whitespace().collect();
    let truncation_marker = parts.last().copied().map(|p| p.ends_with('…')).unwrap_or(false);
    if parts.len() > MAX_INLINE_FLOWS {
        let extra = parts.len() - MAX_INLINE_FLOWS;
        parts.truncate(MAX_INLINE_FLOWS);
        let mut shown = parts.join(" ");
        shown.push_str(&format!(" (+{extra} more)"));
        if truncation_marker {
            shown.push('…');
        }
        Cell::new(u.loc(&shown))
    } else {
        Cell::new(u.loc(labels))
    }
}

/// Conservative visible-byte estimate for one comfy-table cell.
/// Long source lines and flow-id lists wrap inside the terminal,
/// and every wrap repeats table borders and padding. The paginator
/// needs the post-wrap shape, not just the raw string length.
fn wrapped_table_cell_cost(len: usize) -> u64 {
    let len = len as u64;
    let wraps = len / 60;
    len.saturating_mul(3)
        .saturating_add(wraps.saturating_mul(180))
        .saturating_add(32)
}

fn browse_table_row_cost(cells: &[usize]) -> u64 {
    paging::TABLE_ROW_CHROME_BYTES
        .saturating_add(700)
        .saturating_add(cells.iter().map(|len| wrapped_table_cell_cost(*len)).sum::<u64>())
}

fn source_line_cell_cost(ws: &Workspace, file: &str, line: u32) -> u64 {
    wrapped_table_cell_cost(read_line(ws, file, line).len().min(4_000))
}

fn source_line_estimated_cell_cost() -> u64 {
    wrapped_table_cell_cost(320)
}

fn flow_labels_cell_cost(labels: &str) -> u64 {
    if labels.is_empty() {
        return wrapped_table_cell_cost(1);
    }
    // The render layer caps flows-cell content at MAX_INLINE_FLOWS
    // ids plus an "(+N more)" tail (see `flows_cell`), so the
    // post-render byte cost is bounded by ~8 × `F:<16-hex> ` ≈ 152
    // chars + the suffix. Cost the cell against that ceiling rather
    // than the raw label string — a hub caller with 100+ flows used
    // to inflate the per-row cost by 5x and force one row per
    // page.
    const FLOW_CELL_CAP: usize = 120;
    wrapped_table_cell_cost(labels.len().min(FLOW_CELL_CAP))
}

fn flow_labels_estimated_cell_cost(flows: bool) -> u64 {
    if flows {
        // Location-based rows (`calls`, `vars`, `strings`, `args`)
        // can share a hot enclosing function whose flow labels are
        // expensive to enumerate. Pricing every row exactly would
        // rebuild the label set for the whole result list before
        // rendering page 1. Use a wrap-aware allowance that matches
        // the rendered cap (see `flow_labels_cell_cost`); the
        // renderer still computes exact labels only for the rows it
        // actually prints.
        wrapped_table_cell_cost(120)
    } else {
        0
    }
}

fn location_flow_labels_cell_cost(
    exact_ann: Option<&bonsai_sdk::FlowAnnotator<'_>>,
    flows: bool,
    file: &str,
    line: u32,
) -> u64 {
    if let Some(ann) = exact_ann {
        flow_labels_cell_cost(&ann.labels_for(file, line))
    } else {
        flow_labels_estimated_cell_cost(flows)
    }
}

fn import_flow_labels(ann: &bonsai_sdk::FlowAnnotator<'_>, import: &bonsai_sdk::ImportOut) -> String {
    // Imports live at module scope — `labels_for(file, line)` would
    // always be empty. The useful labels are those terminating in
    // the imported symbols/local bindings. Keep this in one helper
    // so the renderer and paginator price the exact same value.
    let mut names: Vec<&str> = Vec::new();
    if let Some(orig) = import.original_name.as_deref() {
        names.push(orig);
    }
    if let Some(alias) = import.alias.as_deref() {
        if !names.contains(&alias) {
            names.push(alias);
        }
    }
    for binding in &import.local_bindings {
        let s = binding.as_str();
        if !names.contains(&s) {
            names.push(s);
        }
    }
    let mut union: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for name in &names {
        let labels = ann.labels_for_symbol(name);
        if !labels.is_empty() {
            for id in labels.split_whitespace() {
                union.insert(id.to_string());
            }
        }
    }
    union.into_iter().collect::<Vec<_>>().join(" ")
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_calls(
    root: &std::path::Path,
    f: CallsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .calls(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    // Filter-signature hash: same `(cmd, filters_hash, offset)`
    // tuple used to derive the cursor must be stable across runs
    // so a `P:xxxxxxxx` cursor from a bug report reproduces.
    let filters_hash = paging::hash_filters(&[
        ("callee", f.callee.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("caller", f.caller.unwrap_or("")),
        ("call_kind", f.call_kind.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    let exact_flow_cost_ann =
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::FlowAnnotator::new(ws));
    let cost_bytes = |c: &bonsai_sdk::CallOut| {
        if !text_cost {
            return (c.callee.len()
                + c.caller.as_deref().map_or(1, str::len)
                + c.file.len()
                + 16
                + read_line(ws, &c.file, c.line).len()) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let caller = c.caller.as_deref().unwrap_or("-");
        let loc_len = short_file(&c.file).len() + 24;
        browse_table_row_cost(&[c.callee.len(), caller.len(), loc_len])
            .saturating_add(source_line_estimated_cell_cost())
            .saturating_add(location_flow_labels_cell_cost(
                exact_flow_cost_ann.as_ref(),
                flows,
                &c.file,
                c.line,
            ))
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            // JSON honors paging only when explicitly opted in
            // (either `--context` or `--page` passed). Default
            // stays the bare array shape for back-compat with
            // every existing script.
            if paging_cfg.json_wrapped() {
                emit_json_paged_cached(root, &out, &paging_cfg, "calls", filters_hash, cost_bytes)?;
            } else {
                cli_println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        BrowseFormat::Text => {
            // `--context` / `--page` / `--all` drive the slice.
            // Legacy `--limit` applies after paging — a belt-and-
            // suspenders truncation a user can set when their
            // context budget happens to fit more rows than they
            // want visually (rare). Paging is the primary knob.
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "calls",
                filters_hash,
                cost_bytes,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers = with_flows_header(&["callee", "caller", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    let mut last_code: Option<String> = None;
                    for c in &rows {
                        let caller = c.caller.as_deref().unwrap_or("-");
                        let loc = format!("{}:{}:{}", short_file(&c.file), c.line, c.column);
                        let ext = extension_for(&c.file);
                        let line_text = read_line(ws, &c.file, c.line);
                        let code_render = fold_repeated_code(&line_text, &mut last_code);
                        let code_cell = if code_render == "↑ same" {
                            Cell::new(u.dim(&code_render))
                        } else {
                            Cell::new(u.snippet(&code_render, ext))
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&c.callee)),
                            Cell::new(u.kind(caller)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            cells.push(flows_cell(u, &ann.labels_for(&c.file, c.line)));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} call sites)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja calls <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn emit_json_paged_cached<T, F>(
    workspace: &std::path::Path,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: F,
) -> Result<()>
where
    T: serde::Serialize + Clone,
    F: Fn(&T) -> u64,
{
    if cfg.json_wrapped() {
        page_cache::emit_paged_text(
            workspace,
            rows,
            cfg,
            command,
            filters_hash,
            row_cost_bytes,
            |slice, info, _cfg| {
                let wrapped = serde_json::json!({
                    "rows": slice,
                    "page": page_info_to_json(info),
                });
                cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
                Ok(())
            },
        )?;
    } else {
        cli_println!("{}", serde_json::to_string_pretty(&rows)?);
    }
    Ok(())
}

/// Collapse the bare+sigil'd twin entries Perl's adapter emits for
/// each parameter into a single display-friendly list. Perl's
/// adapter needs both forms (`$token` AND `token`) so taint-state
/// lookups succeed against either shape, but for human display the
/// bare form is redundant when the sigil'd form exists. For
/// non-Perl adapters every param is its own distinct entry, so this
/// is a no-op there.
fn dedup_sigil_params(params: &[String]) -> Vec<String> {
    // First collect the set of sigil'd names and their bare
    // companions (without the leading `$`/`@`/`%`). Any bare entry
    // that also appears with a sigil somewhere in the list is
    // dropped — preserve the original order otherwise.
    let mut sigil_bares: ahash::AHashSet<&str> = ahash::AHashSet::default();
    for p in params {
        if let Some(first) = p.chars().next() {
            if matches!(first, '$' | '@' | '%') {
                sigil_bares.insert(&p[first.len_utf8()..]);
            }
        }
    }
    let mut out: Vec<String> = Vec::with_capacity(params.len());
    for p in params {
        // Keep if sigil'd, or if bare but no sigil'd twin exists.
        let first = p.chars().next();
        let is_sigil = matches!(first, Some('$' | '@' | '%'));
        if is_sigil || !sigil_bares.contains(p.as_str()) {
            out.push(p.clone());
        }
    }
    out
}

/// Convert a [`paging::PageInfo`] into the JSON `page` object
/// shape: numeric counters, cursors, and `is_last`. Used only
/// when the caller opted into paged JSON via `--context` or
/// `--page` — the default JSON shape is a bare array for
/// back-compat.
pub(crate) fn page_info_to_json(info: &paging::PageInfo) -> serde_json::Value {
    serde_json::json!({
        "number": info.page_number,
        "total_pages": info.total_pages,
        "page_size": info.page_size,
        "shown_rows": info.shown_rows,
        "total_rows": info.total_rows,
        "budget": info.budget,
        "tokens_used": info.tokens_used,
        "total_tokens_uncapped": info.total_tokens_uncapped,
        "cursor": info.cursor,
        "next_cursor": info.next_cursor,
        "is_last": info.is_last,
    })
}

/// Read a single 1-indexed line from a workspace file path, trimming
/// trailing whitespace. Returns empty on any I/O or lookup failure.
pub(crate) fn read_line(ws: &Workspace, file_path: &str, line: u32) -> String {
    // Find the `FileId` that matches this path.
    let global = ws.db().global_index();
    let Some(file_id) = global.all_files().find(|f| {
        ws.vfs()
            .path(*f)
            .map(|p| p.display().to_string())
            .is_ok_and(|p| p == file_path)
    }) else {
        return String::new();
    };
    let Ok(snapshot) = ws.vfs().snapshot(file_id) else {
        return String::new();
    };
    snapshot
        .text
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .unwrap_or("")
        .trim_end()
        .to_string()
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_imports(
    root: &std::path::Path,
    mut f: ImportsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    f.resolve_workspace_bindings = flows && matches!(format, BrowseFormat::Text);
    let out = project
        .browse()
        .imports(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("file", f.file.unwrap_or("")),
        ("module", f.module.unwrap_or("")),
        ("alias", f.alias.unwrap_or("")),
        ("wildcard", if f.wildcard { "1" } else { "0" }),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    let flow_cost_ann = (flows && text_cost).then(|| bonsai_sdk::FlowAnnotator::new(ws));
    let cost = |import: &bonsai_sdk::ImportOut| {
        if !text_cost {
            return (import.module.len()
                + import.alias.as_deref().map_or(1, str::len)
                + import.original_name.as_deref().map_or(1, str::len)
                + import.file.len()
                + 16
                + read_line(ws, &import.file, import.line).len()) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let alias = import.alias.as_deref().unwrap_or("-");
        let symbol = import.original_name.as_deref().unwrap_or("-");
        let kind = if import.is_wildcard { "wildcard" } else { "named" };
        let loc_len = short_file(&import.file).len() + 16;
        let flow_cost = flow_cost_ann
            .as_ref()
            .map(|ann| flow_labels_cell_cost(&import_flow_labels(ann, import)))
            .unwrap_or(0);
        browse_table_row_cost(&[
            import.module.len(),
            symbol.len(),
            alias.len(),
            kind.len(),
            loc_len,
        ])
        .saturating_add(source_line_cell_cost(ws, &import.file, import.line))
        .saturating_add(flow_cost)
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "imports", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "imports",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers =
                        with_flows_header(&["module", "symbol", "alias", "kind", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    let mut last_code: Option<String> = None;
                    for import in &rows {
                        let alias = import.alias.clone().unwrap_or_else(|| "-".to_string());
                        // `symbol` column surfaces the specific name imported
                        // from the module — `verify_token` in `from
                        // .auth_service import verify_token`. Without it,
                        // multi-symbol `from x import a, b` rendered as two
                        // visually identical rows (same module, same span).
                        let symbol = import.original_name.clone().unwrap_or_else(|| "-".to_string());
                        let kind = if import.is_wildcard { "wildcard" } else { "named" };
                        let loc = format!("{}:{}", short_file(&import.file), import.line);
                        let ext = extension_for(&import.file);
                        let line_text = read_line(ws, &import.file, import.line);
                        let code_render = fold_repeated_code(&line_text, &mut last_code);
                        let code_cell = if code_render == "↑ same" {
                            Cell::new(u.dim(&code_render))
                        } else {
                            Cell::new(u.snippet(&code_render, ext))
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&import.module)),
                            Cell::new(u.dim(&symbol)),
                            Cell::new(u.dim(&alias)),
                            Cell::new(u.kind(kind)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = import_flow_labels(ann, import);
                            cells.push(flows_cell(u, &labels));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} imports)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja imports <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_vars(
    root: &std::path::Path,
    f: VarsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .vars(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("name", f.name.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("source", f.source.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    let exact_flow_cost_ann =
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::FlowAnnotator::new(ws));
    let cost = |v: &bonsai_sdk::VarOut| {
        if !text_cost {
            return (v.name.len()
                + v.in_function.len()
                + v.source_name.as_deref().map_or(1, str::len)
                + v.file.len()
                + 16
                + read_line(ws, &v.file, v.line).len()) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let src = v.source_name.as_deref().unwrap_or("-");
        let loc_len = short_file(&v.file).len() + 24;
        browse_table_row_cost(&[v.name.len(), v.in_function.len(), src.len(), loc_len])
            .saturating_add(source_line_estimated_cell_cost())
            .saturating_add(location_flow_labels_cell_cost(
                exact_flow_cost_ann.as_ref(),
                flows,
                &v.file,
                v.line,
            ))
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "vars", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "vars",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers = with_flows_header(&["var", "in", "source", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    let mut last_code: Option<String> = None;
                    for v in &rows {
                        let loc = format!("{}:{}:{}", short_file(&v.file), v.line, v.column);
                        let src = v.source_name.clone().unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&v.file);
                        let line_text = read_line(ws, &v.file, v.line);
                        let code_render = fold_repeated_code(&line_text, &mut last_code);
                        let code_cell = if code_render == "↑ same" {
                            Cell::new(u.dim(&code_render))
                        } else {
                            Cell::new(u.snippet(&code_render, ext))
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&v.name)),
                            Cell::new(u.kind(&v.in_function)),
                            Cell::new(u.dim(&src)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            cells.push(flows_cell(u, &ann.labels_for(&v.file, v.line)));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} writes)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja vars <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_strings(
    root: &std::path::Path,
    f: StringsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .strings(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("category", f.category.unwrap_or("")),
        ("contains", f.contains.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("min_len", &f.min_len.map(|n| n.to_string()).unwrap_or_default()),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    // Strings table has a syntax-highlighted `code` column (the
    // enclosing source line, up to ~120 bytes) + a `flows` column
    // that accretes F:<16-hex> ids for rows inside hot functions.
    // Account for both — the original estimate only covered the
    // text preview + file path.
    let text_cost = matches!(format, BrowseFormat::Text);
    let exact_flow_cost_ann =
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::FlowAnnotator::new(ws));
    let cost = |s: &bonsai_sdk::StringOut| {
        if !text_cost {
            return (s.category.len() + s.text.len().min(120) + s.file.len() + 16 + 180) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let loc_len = short_file(&s.file).len() + 24;
        let enclosing_len = 24;
        browse_table_row_cost(&[
            s.category.len(),
            truncate(&s.text, 60).len(),
            enclosing_len,
            loc_len,
        ])
        .saturating_add(source_line_estimated_cell_cost())
        .saturating_add(location_flow_labels_cell_cost(
            exact_flow_cost_ann.as_ref(),
            flows,
            &s.file,
            s.line,
        ))
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "strings", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "strings",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers = with_flows_header(&["category", "text", "in", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    let mut last_code: Option<String> = None;
                    for s in &rows {
                        let preview = truncate(&s.text, 60);
                        let loc = format!("{}:{}:{}", short_file(&s.file), s.line, s.column);
                        let enclosing = enclosing_fn_for_file_line(ws, &s.file, s.line)
                            .unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&s.file);
                        let line_text = read_line(ws, &s.file, s.line);
                        let code_render = fold_repeated_code(&line_text, &mut last_code);
                        let code_cell = if code_render == "↑ same" {
                            Cell::new(u.dim(&code_render))
                        } else {
                            Cell::new(u.snippet(&code_render, ext))
                        };
                        let mut cells = vec![
                            Cell::new(u.annotation(&s.category)),
                            Cell::new(u.name(&preview)),
                            Cell::new(u.kind(&enclosing)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            cells.push(flows_cell(u, &ann.labels_for(&s.file, s.line)));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} strings)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja strings <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

// Re-export `enclosing_fn_for_file_line` from `bonsai_sdk::strings` so
// the renderer can keep using the bare name without qualifying.
use bonsai_sdk::strings::enclosing_fn_for_file_line;

/// `bonsai-ninja comments` renderer — same shape as `cmd_strings`.
#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_comments(
    root: &std::path::Path,
    f: CommentsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .comments(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("kind", f.kind.unwrap_or("")),
        ("contains", f.contains.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("min_len", &f.min_len.map(|n| n.to_string()).unwrap_or_default()),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let cost = |c: &bonsai_sdk::CommentOut| {
        (c.kind.len() + c.text.len().min(200) + c.file.len() + 16) as u64 + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "comments", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "comments",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let headers = &["kind", "text", "in", "location"];
                    let mut t = u.table(headers);
                    for c in &rows {
                        let preview = truncate(&c.text.replace('\n', " "), 100);
                        let loc = format!("{}:{}:{}", short_file(&c.file), c.line, c.column);
                        let enclosing = enclosing_fn_for_file_line(ws, &c.file, c.line)
                            .unwrap_or_else(|| "-".to_string());
                        let cells = vec![
                            Cell::new(u.annotation(&c.kind)),
                            Cell::new(u.name(&preview)),
                            Cell::new(u.kind(&enclosing)),
                            Cell::new(u.path(&loc)),
                        ];
                        t.add_row(cells);
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} comments)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja comments <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_args(
    root: &std::path::Path,
    f: ArgsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .args(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("callee", f.callee.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("value", f.value.unwrap_or("")),
        ("position", &f.position.map(|n| n.to_string()).unwrap_or_default()),
        ("keyword", f.keyword.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    let exact_flow_cost_ann =
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::FlowAnnotator::new(ws));
    let cost = |a: &bonsai_sdk::ArgOut| {
        if !text_cost {
            return (a.callee.len()
                + a.value.len().min(80)
                + a.keyword.as_deref().map_or(0, str::len)
                + a.file.len()
                + 16
                + read_line(ws, &a.file, a.line).len()) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let pos_len = a
            .keyword
            .as_deref()
            .map_or_else(|| a.position.to_string().len(), |k| k.len() + 1);
        let loc_len = short_file(&a.file).len() + 24;
        let caller_len = 24;
        browse_table_row_cost(&[
            a.callee.len(),
            pos_len,
            truncate(&a.value, 50).len(),
            caller_len,
            loc_len,
        ])
        .saturating_add(source_line_estimated_cell_cost())
        .saturating_add(location_flow_labels_cell_cost(
            exact_flow_cost_ann.as_ref(),
            flows,
            &a.file,
            a.line,
        ))
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "args", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "args",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers =
                        with_flows_header(&["callee", "pos", "arg", "caller", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    let mut last_code: Option<String> = None;
                    for a in &rows {
                        let pos_label = a
                            .keyword
                            .as_deref()
                            .map(|k| format!("{k}="))
                            .unwrap_or_else(|| a.position.to_string());
                        let value = truncate(&a.value, 50);
                        let loc = format!("{}:{}:{}", short_file(&a.file), a.line, a.column);
                        let caller = enclosing_fn_for_file_line(ws, &a.file, a.line)
                            .unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&a.file);
                        let line_text = read_line(ws, &a.file, a.line);
                        let code_render = fold_repeated_code(&line_text, &mut last_code);
                        let code_cell = if code_render == "↑ same" {
                            Cell::new(u.dim(&code_render))
                        } else {
                            Cell::new(u.snippet(&code_render, ext))
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&a.callee)),
                            Cell::new(u.loc(&pos_label)),
                            Cell::new(u.dim(&value)),
                            Cell::new(u.kind(&caller)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            cells.push(flows_cell(u, &ann.labels_for(&a.file, a.line)));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} arguments)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja args <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_classes(
    root: &std::path::Path,
    f: ClassesFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .classes(f)
        .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("name", f.name.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("kind", f.kind.unwrap_or("")),
        ("has_method", f.has_method.unwrap_or("")),
        (
            "min_methods",
            &f.min_methods.map(|n| n.to_string()).unwrap_or_default(),
        ),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let cost = |c: &bonsai_sdk::ClassOut| {
        (c.name.len()
            + c.kind.len()
            + c.file.len()
            + 16
            + c.methods.iter().take(8).map(|m| m.len() + 2).sum::<usize>()) as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "classes", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "classes",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers = with_flows_header(&["name", "kind", "location", "#", "methods"], flows);
                    let mut t = u.table(&headers);
                    for c in &rows {
                        let loc = format!("{}:{}", short_file(&c.file), c.line);
                        let methods_cell = if c.methods.is_empty() {
                            u.dim("—")
                        } else {
                            let shown: Vec<String> = c.methods.iter().take(8).cloned().collect();
                            let rest = c.method_count.saturating_sub(shown.len());
                            let mut s = shown.join("\n");
                            if rest > 0 {
                                s.push_str(&format!("\n… +{rest} more"));
                            }
                            s
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&c.name)),
                            Cell::new(u.kind(&c.kind)),
                            Cell::new(u.path(&loc)),
                            Cell::new(u.dim(&c.method_count.to_string())),
                            Cell::new(methods_cell),
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            // Classes don't sit inside a function body, so
                            // `labels_for(file, line)` is always empty here.
                            // The flows a reader expects are the ones
                            // terminating in the class's methods — union
                            // labels across every method name declared on
                            // the class. Matches the "imports" logic where
                            // we aggregate Local-scope siblings.
                            let mut union: std::collections::BTreeSet<String> =
                                std::collections::BTreeSet::new();
                            for method in &c.methods {
                                let labels = ann.labels_for_symbol(method);
                                for id in labels.split_whitespace() {
                                    union.insert(id.to_string());
                                }
                            }
                            // Fall back to the class name itself (constructors,
                            // call-site references with that exact name).
                            if union.is_empty() {
                                let labels = ann.labels_for_symbol(&c.name);
                                for id in labels.split_whitespace() {
                                    union.insert(id.to_string());
                                }
                            }
                            let flows_text = union.into_iter().collect::<Vec<_>>().join(" ");
                            cells.push(flows_cell(u, &flows_text));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} types)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja classes <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_refs(
    root: &std::path::Path,
    symbol: &str,
    f: RefsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let out = project
        .browse()
        .refs(symbol, f)
        .map_err(|e| anyhow::anyhow!("invalid regex `{symbol}`: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("symbol", symbol),
        ("kind", f.kind.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let cost = |r: &bonsai_sdk::RefOut| {
        (r.symbol.len() + r.kind.len() + r.file.len() + 16 + r.snippet.len().min(100)) as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &out, &paging_cfg, "refs", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "refs",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    let headers = with_flows_header(&["symbol", "kind", "in", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    let mut last_code: Option<String> = None;
                    for r in &rows {
                        let loc = format!("{}:{}:{}", short_file(&r.file), r.line, r.column);
                        let snip = truncate(r.snippet.trim(), 100);
                        let enclosing = enclosing_fn_for_file_line(ws, &r.file, r.line)
                            .unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&r.file);
                        let code_render = fold_repeated_code(&snip, &mut last_code);
                        let code_cell = if code_render == "↑ same" {
                            Cell::new(u.dim(&code_render))
                        } else {
                            Cell::new(u.snippet(&code_render, ext))
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&r.symbol)),
                            Cell::new(u.kind(&r.kind)),
                            Cell::new(u.kind(&enclosing)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            cells.push(flows_cell(u, &ann.labels_for(&r.file, r.line)));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} references)", out.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja refs <workspace> <symbol>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_search(
    root: &std::path::Path,
    query: &str,
    f: SearchFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let hits = project
        .browse()
        .search(query, f, usize::MAX)
        .map_err(|e| anyhow::anyhow!("invalid regex `{query}`: {e}"))?;
    let filters_hash = paging::hash_filters(&[
        ("query", query),
        ("kind", f.kind.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let cost = |h: &bonsai_sdk::SearchHit| {
        (h.name.len()
            + h.kind.len()
            + h.qualified_name.as_deref().map_or(0, str::len)
            + h.context.as_deref().map_or(0, str::len)
            + h.code.len().min(100)
            + h.file.len()
            + 16) as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_json_paged_cached(root, &hits, &paging_cfg, "search", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &hits,
                &paging_cfg,
                "search",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_flow_annotator(ws, flows, rows.len() as u64);
                    // The "qualified" column is only meaningful for decl-kind
                    // hits; non-decl hits use the context column (signature /
                    // alias / "in <fn>") for the analogous info. The "code"
                    // column shows the actual source line, syntax-highlighted.
                    let headers = with_flows_header(
                        &["name", "kind", "qualified", "context", "code", "location"],
                        flows,
                    );
                    let mut t = u.table(&headers);
                    let mut last_code: Option<String> = None;
                    for h in &rows {
                        let loc = format!("{}:{}:{}", short_file(&h.file), h.line, h.column);
                        let qualified = h.qualified_name.clone().unwrap_or_else(|| "-".to_string());
                        let context = h.context.clone().unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&h.file);
                        let code = h.code.trim();
                        let code_render = fold_repeated_code(code, &mut last_code);
                        let code_cell = if code_render == "↑ same" {
                            Cell::new(u.dim(&code_render))
                        } else {
                            Cell::new(u.snippet(&code_render, ext))
                        };
                        let mut cells = vec![
                            Cell::new(u.name(&h.name)),
                            Cell::new(u.kind(&h.kind)),
                            Cell::new(u.dim(&qualified)),
                            Cell::new(u.dim(&context)),
                            code_cell,
                            Cell::new(u.path(&loc)),
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            cells.push(flows_cell(u, &ann.labels_for(&h.file, h.line)));
                            if let Some(b) = flow_bar.as_ref() {
                                b.inc(1);
                            }
                        }
                        t.add_row(cells);
                    }
                    if let Some(b) = flow_bar {
                        b.finish_and_clear();
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} matches)", hits.len())));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja search <workspace> <query>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn collect_callees(events: &[FlowEvent], out: &mut Vec<String>) {
    for e in events {
        match e {
            FlowEvent::Call { name, .. } => out.push(name.clone()),
            FlowEvent::Assign {
                source_call: Some(name),
                ..
            } => out.push(name.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_callees(then_events, out);
                collect_callees(else_events, out);
            }
            FlowEvent::Loop { body, .. } => collect_callees(body, out),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_callees(body, out);
                collect_callees(catch_events, out);
                collect_callees(finally_events, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_callees(body, out);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{collect_callees, truncate};
    use bonsai_common::{FileId, Span};
    use bonsai_lang_api::{CallKind, FlowEvent};

    fn span() -> Span {
        Span {
            file: FileId(0),
            start: 0,
            end: 1,
        }
    }

    #[test]
    fn truncate_zero_chars_keeps_only_ellipsis() {
        assert_eq!(truncate("abcdef", 0), "…");
        assert_eq!(truncate("éclair", 0), "…");
    }

    #[test]
    fn collect_callees_includes_assignment_source_calls() {
        let events = vec![
            FlowEvent::Assign {
                target: "x".to_string(),
                source_name: None,
                source_names: Vec::new(),
                source_call: Some("read_user".to_string()),
                source_call_args: vec!["request".to_string()],
                span: span(),
                            declares_new_binding: false,
                value_kind: None,
            },
            FlowEvent::Call {
                name: "sink".to_string(),
                receiver: None,
                args: Vec::new(),
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                span: span(),
            },
        ];
        let mut out = Vec::new();
        collect_callees(&events, &mut out);
        assert_eq!(out, vec!["read_user", "sink"]);
    }
}
