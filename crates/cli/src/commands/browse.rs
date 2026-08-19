//! Browse commands: `defs`, `entrypoints`, `calls`, `imports`, `vars`,
//! `strings`, `comments`, `args`, `operations`, `classes`, `refs`, `search`. Each reads
//! from the shared `GlobalIndex` and emits a uniform `{header row, rows, footer}`
//! shape. JSON output keeps a bare array when the full result fits the
//! token budget; larger or explicitly paged renders use `{rows, page}`.

use anyhow::Result;
use bonsai_sdk::Workspace;
use comfy_table::Cell;

use crate::args::{BrowseFormat, OutputFormat};
use crate::footer::{render_paging_footer, render_truncation_notice, WorkspaceFooter};
use crate::page_cache;
use crate::paging;
use crate::progress;
use crate::ui::{extension_for, Ui};
use crate::{cli_println, ui};

use super::{
    open_project_index_filtered_paths, open_project_index_matching_literal, open_project_index_matching_path,
    open_project_index_only as open_project, open_project_index_retrieval_candidates,
    workspace_file_count_exceeds,
};

const BROWSE_LITERAL_PREFILTER_FILE_LIMIT: usize = 5_000;
fn browse_literal_prefilter_enabled(root: &std::path::Path, literal: Option<&str>, regex: bool) -> bool {
    literal
        .and_then(|literal| {
            if regex {
                exact_identifier_regex_literal(literal)
            } else {
                Some(literal)
            }
        })
        .is_some_and(|literal| {
            literal.len() >= 3 && workspace_file_count_exceeds(root, BROWSE_LITERAL_PREFILTER_FILE_LIMIT)
        })
}

fn exact_identifier_regex_literal(pattern: &str) -> Option<&str> {
    let literal = pattern.strip_prefix('^')?.strip_suffix('$')?;
    (!literal.is_empty()
        && literal
            .chars()
            .all(|character| character == '_' || character == '$' || character.is_alphanumeric()))
    .then_some(literal)
}

fn open_browse_project(
    root: &std::path::Path,
    literal: Option<&str>,
    regex: bool,
) -> Result<(bonsai_sdk::Project, WorkspaceFooter, bool)> {
    let prefilter_literal = literal.and_then(|literal| {
        if regex {
            exact_identifier_regex_literal(literal)
        } else {
            Some(literal)
        }
    });
    let use_literal_prefilter = browse_literal_prefilter_enabled(root, literal, regex);
    let (project, footer) = match (use_literal_prefilter, prefilter_literal) {
        (true, Some(literal)) => open_project_index_matching_literal(root, literal)?,
        _ => open_project(root)?,
    };
    Ok((project, footer, use_literal_prefilter))
}

fn open_browse_project_with_retrieval(
    root: &std::path::Path,
    literal: Option<&str>,
    kind: Option<&str>,
    file: Option<&str>,
    regex: bool,
) -> Result<(bonsai_sdk::Project, WorkspaceFooter, bool)> {
    // An explicit file filter defines the complete requested universe. Open
    // that syntax slice directly instead of hydrating the full workspace and
    // discarding nearly every row after allocation. This is both exact and
    // important for compiler-like latency on large repositories: `defs
    // --file X`, `classes --file X`, and the other browse facades should cost
    // roughly one file, not one Elasticsearch checkout.
    if let Some(file) = file.filter(|file| !file.trim().is_empty()) {
        let requested_path = std::path::Path::new(file);
        let direct_path = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            root.join(requested_path)
        };
        if direct_path.is_file() {
            let (project, footer) = open_project_index_matching_path(root, requested_path)?;
            return Ok((project, footer, true));
        }
        let include_filters = [file.to_string()];
        let (project, footer) = open_project_index_filtered_paths(root, &include_filters, &[])?;
        return Ok((project, footer, true));
    }
    if let Some(query) = literal.and_then(|query| {
        if regex {
            exact_identifier_regex_literal(query)
        } else {
            Some(query)
        }
    }) {
        if query.trim().len() >= 3 && workspace_file_count_exceeds(root, BROWSE_LITERAL_PREFILTER_FILE_LIMIT)
        {
            if let Some((project, footer)) = open_project_index_retrieval_candidates(
                root,
                query,
                SearchFilters {
                    kind,
                    file,
                    regex: false,
                },
            )? {
                return Ok((project, footer, true));
            }
        }
    }
    open_browse_project(root, literal, regex)
}

#[cfg(test)]
fn retrieval_prefilter_for_browse_literal_with_limit(
    root: &std::path::Path,
    query: &str,
    kind: Option<&str>,
    file: Option<&str>,
    regex: bool,
    large_workspace_limit: usize,
) -> Result<Option<Vec<String>>> {
    let query = if regex {
        let Some(literal) = exact_identifier_regex_literal(query) else {
            return Ok(None);
        };
        literal
    } else {
        query
    };
    if query.trim().len() < 3 || !workspace_file_count_exceeds(root, large_workspace_limit) {
        return Ok(None);
    }
    let Some(mut include_filters) = super::bonsai_for_cli().retrieval_hydration_include_filters(
        root,
        query,
        SearchFilters {
            kind,
            file,
            regex: false,
        },
    )?
    else {
        return Ok(None);
    };
    include_filters.sort();
    include_filters.dedup();
    Ok(Some(include_filters))
}

#[cfg(test)]
fn retrieval_prefilter_for_search_with_limit(
    root: &std::path::Path,
    query: &str,
    f: SearchFilters<'_>,
    large_workspace_limit: usize,
) -> Result<Option<Vec<String>>> {
    if f.regex || query.trim().len() < 3 || !workspace_file_count_exceeds(root, large_workspace_limit) {
        return Ok(None);
    }
    let Some(mut include_filters) =
        super::bonsai_for_cli().retrieval_hydration_include_filters(root, query, f)?
    else {
        return Ok(None);
    };
    include_filters.sort();
    include_filters.dedup();
    Ok(Some(include_filters))
}

fn with_browse_progress<T>(label: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let stage = progress::ScopedSpinner::new(label);
    let out = f()?;
    stage.finish();
    Ok(out)
}

// Filter + output types are re-exports of the SDK definitions in
// `bonsai_browse`. Keeping them aliased here means existing call
// sites in the dispatcher need no changes — they already build the
// struct field-by-field — and library consumers get the exact same
// types.
pub(crate) use bonsai_sdk::{
    ArgsFilters, CallsFilters, ClassesFilters, CommentsFilters, DefsFilters, EntryPointsFilters,
    ImportsFilters, OperationsFilters, RefsFilters, SearchFilters, StringsFilters, VarsFilters,
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.name.or(f.has_callee).or(f.has_param).or(f.has_decorator);
    let retrieval_kind = if f.name.is_some() {
        f.kind
    } else if f.has_callee.is_some() {
        Some("call")
    } else if f.has_decorator.is_some() {
        Some("ref-decorator")
    } else {
        f.kind
    };
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, retrieval_kind, f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting definitions", || {
        project
            .browse()
            .defs(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "defs",
                    filters_hash,
                    cost,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "defs", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers =
                        with_summaries_header(&["name", "kind", "location", "signature", "callees"], flows);
                    let mut t = u.table(&headers);
                    let callees_by_row = def_callee_summaries(ws, &rows, 3);
                    for (d, callees_cell) in rows.iter().zip(callees_by_row) {
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
                        let mut cells = vec![
                            Cell::new(u.name(&d.name)),
                            Cell::new(u.kind(&d.kind)),
                            Cell::new(u.path(&loc)),
                            Cell::new(u.snippet(&signature, extension_for(&d.file))),
                            Cell::new(u.dim(&callees_cell)),
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&d.file, d.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} definitions)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja defs <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn cmd_entrypoints(
    root: &std::path::Path,
    f: EntryPointsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let (project, _footer) = if let Some(file) = f.file.filter(|file| !file.trim().is_empty()) {
        open_project_index_filtered_paths(root, &[file.to_string()], &[])?
    } else {
        open_project(root)?
    };
    let out = with_browse_progress("collecting entrypoints", || {
        project
            .browse()
            .entrypoints(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
    let filters_hash = paging::hash_filters(&[
        ("kind", f.kind.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("name", f.name.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let cost = |e: &bonsai_sdk::EntryPointOut| {
        let loc_len = short_file(&e.file).len() + 24;
        let params_len = e.params.iter().map(|p| p.len() + 2).sum::<usize>();
        let callees_len = e.callees.iter().map(|c| c.len() + 3).sum::<usize>();
        browse_table_row_cost(&[
            e.name.len(),
            e.kind.len(),
            loc_len,
            params_len,
            callees_len,
            e.reason.len(),
        ])
    };
    match format {
        BrowseFormat::Json => {
            emit_json_paged_cached(root, &out, &paging_cfg, "entrypoints", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "entrypoints",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let mut t = u.table(&["name", "kind", "location", "signature", "callees", "reason"]);
                    for e in &rows {
                        let display_params = dedup_sigil_params(&e.params);
                        let signature = if display_params.is_empty() {
                            format!("{}()", e.name)
                        } else {
                            format!("{}({})", e.name, display_params.join(", "))
                        };
                        let loc = format!("{}:{}:{}", short_file(&e.file), e.line, e.column);
                        let shown: Vec<&str> = e.callees.iter().take(4).map(String::as_str).collect();
                        let callees = if shown.is_empty() {
                            String::new()
                        } else if e.callees.len() > shown.len() {
                            format!("{} (+{})", shown.join(" → "), e.callees.len() - shown.len())
                        } else {
                            shown.join(" → ")
                        };
                        t.add_row(vec![
                            Cell::new(u.name(&e.name)),
                            Cell::new(u.kind(&e.kind)),
                            Cell::new(u.path(&loc)),
                            Cell::new(u.snippet(&signature, extension_for(&e.file))),
                            Cell::new(u.dim(&callees)),
                            Cell::new(u.dim(&e.reason)),
                        ]);
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({} entry points)", info.total_rows)));
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja entrypoints <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

/// Build one compact outgoing-call preview per rendered definition row.
/// Exact file/line/column identity keeps same-named callables separate, while
/// per-function attribution avoids decoding whole-workspace call linkage for
/// a page-sized presentation field.
pub(crate) fn def_callee_summaries(ws: &Workspace, rows: &[bonsai_sdk::DefOut], limit: usize) -> Vec<String> {
    let headers = ws.compiler_header_index();
    rows.iter()
        .map(|row| {
            let Some(file) = bonsai_sdk::workspace_file_id(ws, &row.file) else {
                return String::new();
            };
            let Some(decl) = headers.decls_in(file).iter().find(|decl| {
                if decl.name != row.name || decl.qualified_name != row.qualified_name {
                    return false;
                }
                let (_, line, column) = bonsai_sdk::format_span(&decl.name_span, ws);
                line == row.line && column == row.column
            }) else {
                return String::new();
            };
            let Some(attribution) = ws.db().compiler_function_attribution_uncached(file, decl.span) else {
                return String::new();
            };
            let mut names = attribution
                .calls
                .into_iter()
                .map(|call| call.name)
                .collect::<Vec<_>>();
            let mut seen = std::collections::HashSet::new();
            names.retain(|name| seen.insert(name.clone()));
            let total = names.len();
            let shown = names.into_iter().take(limit).collect::<Vec<_>>();
            if total > limit {
                format!("{} (+{})", shown.join(" → "), total - limit)
            } else {
                shown.join(" → ")
            }
        })
        .collect()
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

/// Treat an explicit nonzero `--limit` as a maximum page size before rows
/// are selected. Applying it after pagination silently discarded the tail of
/// each page and made page/cursor coverage lossy. `--all` remains exhaustive.
pub(crate) fn paging_with_row_limit(mut cfg: paging::PagingConfig, limit: usize) -> paging::PagingConfig {
    if limit != 0 && !cfg.all {
        cfg.page_size = Some(limit as u64);
    }
    cfg
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
        BrowseFormat::Json => paging::FormatClass::Programmatic,
    };
    let explicit_uncapped = context.is_some() && ctx.is_none();
    Ok(paging::PagingConfig::new(
        ctx,
        pg,
        None,
        all || explicit_uncapped,
        format_class,
    ))
}

/// Paging config for commands with the three-way `OutputFormat`
/// (text / json / dot) — `trace` is the only caller today.
/// Classifies `dot` as `RenderOnly` since a half-dot file is
/// meaningless; text paginates, default JSON is budgeted.
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
    let explicit_uncapped = context.is_some() && ctx.is_none();
    Ok(paging::PagingConfig::new(
        ctx,
        pg,
        None,
        all || explicit_uncapped,
        format_class,
    ))
}

/// Header helper: extend `base` with a trailing `"summaries"` column
/// when compiler summary ids are enabled. Keeps the column list in
/// one place per renderer so ordering stays consistent.
pub(crate) fn with_summaries_header<'a>(base: &'a [&'a str], flows: bool) -> Vec<&'a str> {
    let mut out: Vec<&str> = base.to_vec();
    if flows {
        out.push("summaries");
    }
    out
}

/// Paired `(annotator, progress_bar)` for a browse-command row
/// loop. When summaries are requested, returns an annotator + a
/// row-count-sized progress bar so the user sees ticks during
/// what would otherwise be a multi-second silent pause on big
/// workspaces. Both are `None` when the summary column is disabled.
pub(crate) fn build_summary_annotator<'a>(
    ws: &'a Workspace,
    flows: bool,
    row_count: u64,
) -> (
    Option<bonsai_sdk::SummaryAnnotator<'a>>,
    Option<indicatif::ProgressBar>,
) {
    if !flows {
        return (None, None);
    }
    let bar = progress::progress_bar("annotating symbol summaries", row_count);
    (Some(bonsai_sdk::SummaryAnnotator::new(ws)), Some(bar))
}

/// Cell helper: render compact references for the `summaries`
/// column. Full `F:<16-hex>` ids are intentionally not placed
/// inside dense browse tables because comfy-table may split long
/// tokens under width pressure. The cell gets short per-render
/// references (`F1`, `F2`, ...), and `render_summary_column_notice`
/// prints the complete copyable ids below the table.
pub(crate) fn format_summary_labels_for_cell(
    labels: &str,
    status: &mut SummaryColumnStatus,
) -> Option<String> {
    if labels.trim().is_empty() {
        return None;
    }
    const MAX_INLINE_FLOWS: usize = 8;
    let ids: Vec<String> = labels
        .split_whitespace()
        .filter_map(|part| {
            let id = part.trim_end_matches('…');
            (!id.is_empty()).then(|| id.to_string())
        })
        .collect();
    if ids.is_empty() {
        return None;
    }
    let mut refs = Vec::new();
    for id in ids.iter().take(MAX_INLINE_FLOWS) {
        refs.push(status.summary_ref(id));
    }
    if refs.is_empty() {
        return None;
    }
    let extra = ids.len().saturating_sub(MAX_INLINE_FLOWS);
    let mut shown = refs.join("\n");
    if extra > 0 {
        shown.push_str(&format!("\n(+{extra} more)"));
    }
    Some(shown)
}

#[derive(Default)]
pub(crate) struct SummaryColumnStatus {
    pub(crate) flow_ids: Vec<String>,
}

impl SummaryColumnStatus {
    fn summary_ref(&mut self, id: &str) -> String {
        let idx = self
            .flow_ids
            .iter()
            .position(|existing| existing == id)
            .unwrap_or_else(|| {
                self.flow_ids.push(id.to_string());
                self.flow_ids.len() - 1
            });
        format!("F{}", idx + 1)
    }
}

fn summary_cell_with_status(u: &Ui, labels: &str, status: &mut SummaryColumnStatus) -> Cell {
    let Some(shown) = format_summary_labels_for_cell(labels, status) else {
        return Cell::new(u.dim("-"));
    };
    Cell::new(u.loc(&shown))
}

fn render_summary_column_notice(u: &Ui, status: &SummaryColumnStatus) {
    if !status.flow_ids.is_empty() {
        cli_println!("{}", u.label("symbol summary ids:"));
        for (idx, id) in status.flow_ids.iter().enumerate() {
            cli_println!("  {} {}", u.dim(&format!("F{}", idx + 1)), u.loc(id));
        }
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

/// Estimate a row whose complete visible cells are already known.
///
/// Comfy-table renders at roughly 140 bytes per physical line in the
/// canonical CLI width. Folding the combined cell width into 120 visible
/// columns and allowing 160 encoded bytes per output line accounts for
/// borders, padding, and optional ANSI without charging every cell as if it
/// wrapped independently. Use this for inventories such as imports where the
/// source cell is cheap to read exactly.
fn rendered_table_row_cost(cells: &[usize]) -> u64 {
    let visible = cells
        .iter()
        .copied()
        .sum::<usize>()
        .saturating_add(cells.len().saturating_mul(3));
    let physical_lines = visible.max(1).div_ceil(120);
    u64::try_from(physical_lines)
        .unwrap_or(u64::MAX)
        .saturating_mul(160)
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
        // the rendered cap (see `flow_labels_cell_cost`); rendering
        // still resolves labels only for rows it actually prints and
        // emits a notice if those labels are capped prefixes.
        wrapped_table_cell_cost(120)
    } else {
        0
    }
}

fn location_flow_labels_cell_cost(
    exact_ann: Option<&bonsai_sdk::SummaryAnnotator<'_>>,
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

fn import_flow_labels(ann: &bonsai_sdk::SummaryAnnotator<'_>, import: &bonsai_sdk::ImportOut) -> String {
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

fn class_summary_labels(ann: &bonsai_sdk::SummaryAnnotator<'_>, class: &bonsai_sdk::ClassOut) -> String {
    let mut union = std::collections::BTreeSet::new();
    for method in &class.methods {
        union.extend(
            ann.labels_for_symbol(method)
                .split_whitespace()
                .map(str::to_string),
        );
    }
    if union.is_empty() {
        union.extend(
            ann.labels_for_symbol(&class.name)
                .split_whitespace()
                .map(str::to_string),
        );
    }
    union.into_iter().collect::<Vec<_>>().join(" ")
}

#[derive(serde::Serialize)]
struct SummaryJsonRow<'row, T> {
    #[serde(flatten)]
    row: &'row T,
    summary_ids: Vec<String>,
}

impl<T> Clone for SummaryJsonRow<'_, T> {
    fn clone(&self) -> Self {
        Self {
            row: self.row,
            summary_ids: self.summary_ids.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)] // mirrors the existing paged JSON emitter contract
fn emit_summary_json_paged_cached<T, F, L>(
    workspace: &std::path::Path,
    ws: &Workspace,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: F,
    labels_for: L,
) -> Result<()>
where
    T: serde::Serialize,
    F: Fn(&T) -> u64,
    L: Fn(&bonsai_sdk::SummaryAnnotator<'_>, &T) -> String,
{
    let annotator = bonsai_sdk::SummaryAnnotator::new(ws);
    let annotated: Vec<SummaryJsonRow<'_, T>> = rows
        .iter()
        .map(|row| SummaryJsonRow {
            row,
            summary_ids: labels_for(&annotator, row)
                .split_whitespace()
                .map(str::to_string)
                .collect(),
        })
        .collect();
    emit_json_paged_cached(workspace, &annotated, cfg, command, filters_hash, |row| {
        row_cost_bytes(row.row) + row.summary_ids.iter().map(|id| id.len() as u64 + 4).sum::<u64>() + 20
    })
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.callee.or(f.caller);
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, Some("call"), f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting call sites", || {
        project
            .browse()
            .calls(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
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
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::SummaryAnnotator::new(ws));
    let cost_bytes = |c: &bonsai_sdk::CallOut| {
        if !text_cost {
            return (c.callee.len() + c.caller.as_deref().map_or(1, str::len) + c.file.len() + 16) as u64
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "calls",
                    filters_hash,
                    cost_bytes,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "calls", filters_hash, cost_bytes)?;
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers =
                        with_summaries_header(&["callee text", "caller", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    for c in &rows {
                        let caller = c.caller.as_deref().unwrap_or("-");
                        let loc = format!("{}:{}:{}", short_file(&c.file), c.line, c.column);
                        let ext = extension_for(&c.file);
                        let line_text = read_line(ws, &c.file, c.line);
                        let code_cell = Cell::new(u.snippet(&line_text, ext));
                        let mut cells = vec![
                            Cell::new(u.name(&c.callee)),
                            Cell::new(u.kind(caller)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&c.file, c.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} call sites)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
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
        let force_wrapper = cfg.context.is_some() || !matches!(cfg.page, paging::PageArg::First);
        page_cache::emit_paged_text(
            workspace,
            rows,
            cfg,
            command,
            filters_hash,
            row_cost_bytes,
            |slice, info, _cfg| {
                if !force_wrapper && page_covers_entire_result(info) {
                    cli_println!("{}", serde_json::to_string_pretty(slice)?);
                    return Ok(());
                }
                let analysis_incomplete_reasons = paged_json_incomplete_reasons(command, info);
                let wrapped = serde_json::json!({
                    "analysis_complete": page_covers_entire_result(info),
                    "analysis_incomplete_reasons": analysis_incomplete_reasons,
                    "rows": slice,
                    "page": page_info_to_json(info),
                });
                cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
                Ok(())
            },
        )?;
    } else {
        // Bare-array path (no pagination wrapper) renders directly and
        // so doesn't pass through `emit_paged_text`'s shared filter —
        // apply the secondary `--contains` / `--not-contains` filter
        // here so json `--all` matches the text path's filtered set.
        let secondary = crate::filter::active();
        if secondary.is_active() {
            let kept: Vec<&T> = rows.iter().filter(|row| secondary.matches_value(row)).collect();
            cli_println!("{}", serde_json::to_string_pretty(&kept)?);
        } else {
            cli_println!("{}", serde_json::to_string_pretty(&rows)?);
        }
    }
    Ok(())
}

pub(crate) fn emit_json_value_paged_cached<T>(
    workspace: &std::path::Path,
    value: &T,
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
) -> Result<()>
where
    T: serde::Serialize,
{
    let rendered = serde_json::to_string_pretty(value)?;
    if !cfg.json_wrapped() {
        cli_println!("{rendered}");
        return Ok(());
    }

    let force_wrapper = cfg.context.is_some()
        || !matches!(cfg.page, paging::PageArg::First)
        || crate::filter::active().is_active();
    let lines: Vec<String> = rendered.lines().map(str::to_string).collect();
    page_cache::emit_paged_text(
        workspace,
        &lines,
        cfg,
        command,
        filters_hash,
        |line| line.len() as u64 + 8,
        |slice, info, _cfg| {
            // Preserve the command's native JSON schema whenever the whole
            // value fits. With an explicit paging request, add `page` beside
            // the native object fields instead of turning the object into an
            // array of JSON source lines.
            if page_covers_entire_result(info) && !crate::filter::active().is_active() {
                if !force_wrapper {
                    cli_println!("{}", slice.join("\n"));
                    return Ok(());
                }
                let mut native = serde_json::to_value(value)?;
                match &mut native {
                    serde_json::Value::Object(fields) => {
                        fields.insert("page".to_string(), page_info_to_json(info));
                    }
                    _ => {
                        native = serde_json::json!({
                            "value": native,
                            "page": page_info_to_json(info),
                        });
                    }
                }
                cli_println!("{}", serde_json::to_string_pretty(&native)?);
                return Ok(());
            }
            let analysis_incomplete_reasons = paged_json_incomplete_reasons(command, info);
            let wrapped = serde_json::json!({
                "analysis_complete": page_covers_entire_result(info),
                "analysis_incomplete_reasons": analysis_incomplete_reasons,
                "json_lines": slice,
                "page": page_info_to_json(info),
            });
            cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
            Ok(())
        },
    )
}

fn page_covers_entire_result(info: &paging::PageInfo) -> bool {
    info.page_number == 1 && info.is_last
}

pub(crate) fn paged_json_incomplete_reasons(command: &str, info: &paging::PageInfo) -> Vec<String> {
    if page_covers_entire_result(info) {
        return Vec::new();
    }
    if let Some(next_cursor) = info.next_cursor.as_deref() {
        return vec![format!(
            "paged {command} result incomplete: page {} of {}; continue with --page {} or pass --all",
            info.page_number, info.total_pages, next_cursor,
        )];
    }
    vec![format!(
        "paged {command} result incomplete: page {} of {}; this response contains only the requested page, pass --all for the full result set",
        info.page_number, info.total_pages,
    )]
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
    let Some(file_id) = bonsai_sdk::workspace_file_id(ws, file_path) else {
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.module.or(f.alias);
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, Some("import"), f.file, f.regex)?;
    let ws = project.workspace();
    f.resolve_workspace_bindings = flows;
    let out = with_browse_progress("collecting imports", || {
        project
            .browse()
            .imports(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
    let filters_hash = paging::hash_filters(&[
        ("file", f.file.unwrap_or("")),
        ("module", f.module.unwrap_or("")),
        ("alias", f.alias.unwrap_or("")),
        ("wildcard", if f.wildcard { "1" } else { "0" }),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    let flow_cost_ann = (flows && text_cost).then(|| bonsai_sdk::SummaryAnnotator::new(ws));
    let cost = |import: &bonsai_sdk::ImportOut| {
        if !text_cost {
            return (import.module.len()
                + import.alias.as_deref().map_or(1, str::len)
                + import.original_name.as_deref().map_or(1, str::len)
                + import.file.len()
                + 16) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let alias = import.alias.as_deref().unwrap_or("-");
        let symbol = import.original_name.as_deref().unwrap_or("-");
        let kind = import_kind_label(import.is_wildcard, import.original_name.as_deref());
        let loc_len = short_file(&import.file).len() + 16;
        let flow_len = flow_cost_ann
            .as_ref()
            .map(|ann| import_flow_labels(ann, import).len().min(120))
            .unwrap_or(0);
        rendered_table_row_cost(&[
            import.module.len(),
            symbol.len(),
            alias.len(),
            kind.len(),
            loc_len,
            flow_len,
        ])
        .saturating_add(source_line_estimated_cell_cost())
    };
    match format {
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "imports",
                    filters_hash,
                    cost,
                    import_flow_labels,
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "imports", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers = with_summaries_header(
                        &["module", "symbol", "alias", "kind", "location", "code"],
                        flows,
                    );
                    let mut t = u.table(&headers);
                    for import in &rows {
                        let alias = import.alias.clone().unwrap_or_else(|| "-".to_string());
                        // `symbol` column surfaces the specific name imported
                        // from the module — `verify_token` in `from
                        // .auth_service import verify_token`. Without it,
                        // multi-symbol `from x import a, b` rendered as two
                        // visually identical rows (same module, same span).
                        let symbol = import.original_name.clone().unwrap_or_else(|| "-".to_string());
                        let kind = import_kind_label(import.is_wildcard, import.original_name.as_deref());
                        let loc = format!("{}:{}", short_file(&import.file), import.line);
                        let ext = extension_for(&import.file);
                        let line_text = read_line(ws, &import.file, import.line);
                        let code_cell = Cell::new(u.snippet(&line_text, ext));
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
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} imports)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja imports <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

/// Text-table `kind` label for an import row: `wildcard` for
/// `from x import *`, `module` for whole-module imports that bind no
/// specific symbol (`import os`), `named` otherwise.
fn import_kind_label(is_wildcard: bool, original_name: Option<&str>) -> &'static str {
    if is_wildcard {
        "wildcard"
    } else if original_name.is_none() {
        "module"
    } else {
        "named"
    }
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.name.or(f.source).or(f.in_fn);
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, Some("var"), f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting variables", || {
        project
            .browse()
            .vars(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
    let filters_hash = paging::hash_filters(&[
        ("name", f.name.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("source", f.source.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    let exact_flow_cost_ann =
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::SummaryAnnotator::new(ws));
    let cost = |v: &bonsai_sdk::VarOut| {
        if !text_cost {
            return (v.name.len()
                + v.in_function.len()
                + v.source_name.as_deref().map_or(1, str::len)
                + v.file.len()
                + 16) as u64
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "vars",
                    filters_hash,
                    cost,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "vars", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers = with_summaries_header(&["var", "in", "source", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    for v in &rows {
                        let loc = format!("{}:{}:{}", short_file(&v.file), v.line, v.column);
                        let src = v.source_name.clone().unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&v.file);
                        let line_text = read_line(ws, &v.file, v.line);
                        let code_cell = Cell::new(u.snippet(&line_text, ext));
                        let mut cells = vec![
                            Cell::new(u.name(&v.name)),
                            Cell::new(u.kind(&v.in_function)),
                            Cell::new(u.dim(&src)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&v.file, v.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} writes)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.contains.or(f.in_fn);
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, Some("string"), f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting strings", || {
        project
            .browse()
            .strings(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
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
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::SummaryAnnotator::new(ws));
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "strings",
                    filters_hash,
                    cost,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "strings", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let enclosing_ann = bonsai_sdk::SummaryAnnotator::new(ws);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers =
                        with_summaries_header(&["category", "text", "in", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    for s in &rows {
                        let preview = truncate(&s.text, 60);
                        let loc = format!("{}:{}:{}", short_file(&s.file), s.line, s.column);
                        let enclosing = enclosing_ann
                            .enclosing_function_name(&s.file, s.line)
                            .unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&s.file);
                        let line_text = read_line(ws, &s.file, s.line);
                        let code_cell = Cell::new(u.snippet(&line_text, ext));
                        let mut cells = vec![
                            Cell::new(u.annotation(&s.category)),
                            Cell::new(u.name(&preview)),
                            Cell::new(u.kind(&enclosing)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&s.file, s.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} strings)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja strings <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

/// `bonsai-ninja comments` renderer — same shape as `cmd_strings`.
#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_comments(
    root: &std::path::Path,
    f: CommentsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.contains.or(f.in_fn);
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, Some("comment"), f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting comments", || {
        project
            .browse()
            .comments(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
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
        BrowseFormat::Json => {
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
                    let enclosing_ann = bonsai_sdk::SummaryAnnotator::new(ws);
                    let headers = &["kind", "text", "in", "location"];
                    let mut t = u.table(headers);
                    for c in &rows {
                        let preview = truncate(&c.text.replace('\n', " "), 100);
                        let loc = format!("{}:{}:{}", short_file(&c.file), c.line, c.column);
                        let enclosing = enclosing_ann
                            .enclosing_function_name(&c.file, c.line)
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
                    cli_println!("{}", u.dim(&format!("({} comments)", info.total_rows)));
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.callee.or(f.value).or(f.in_fn).or(f.keyword);
    let retrieval_kind = if f.callee.is_some() {
        Some("call")
    } else {
        Some("arg")
    };
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, retrieval_kind, f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting arguments", || {
        project
            .browse()
            .args(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
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
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::SummaryAnnotator::new(ws));
    let cost = |a: &bonsai_sdk::ArgOut| {
        if !text_cost {
            return (a.callee.len()
                + a.value.len().min(80)
                + a.keyword.as_deref().map_or(0, str::len)
                + a.file.len()
                + 16) as u64
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "args",
                    filters_hash,
                    cost,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "args", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let enclosing_ann = bonsai_sdk::SummaryAnnotator::new(ws);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers = with_summaries_header(
                        &["callee text", "pos", "arg", "caller", "location", "code"],
                        flows,
                    );
                    let mut t = u.table(&headers);
                    for a in &rows {
                        let pos_label = a
                            .keyword
                            .as_deref()
                            .map(|k| format!("{k}="))
                            .unwrap_or_else(|| a.position.to_string());
                        let value = truncate(&a.value, 50);
                        let loc = format!("{}:{}:{}", short_file(&a.file), a.line, a.column);
                        let caller = enclosing_ann
                            .enclosing_function_name(&a.file, a.line)
                            .unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&a.file);
                        let line_text = read_line(ws, &a.file, a.line);
                        let code_cell = Cell::new(u.snippet(&line_text, ext));
                        let mut cells = vec![
                            Cell::new(u.name(&a.callee)),
                            Cell::new(u.loc(&pos_label)),
                            Cell::new(u.dim(&value)),
                            Cell::new(u.kind(&caller)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&a.file, a.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} arguments)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
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
pub(crate) fn cmd_operations(
    root: &std::path::Path,
    f: OperationsFilters<'_>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    flows: bool,
    format: BrowseFormat,
) -> Result<()> {
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let prefilter_literal = f.name.or(f.in_fn);
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, Some("operation"), f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting operations", || {
        project
            .browse()
            .operations(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
    let filters_hash = paging::hash_filters(&[
        ("kind", f.kind.unwrap_or("")),
        ("name", f.name.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    let exact_flow_cost_ann =
        (flows && text_cost && out.len() <= 512).then(|| bonsai_sdk::SummaryAnnotator::new(ws));
    let cost = |op: &bonsai_sdk::OperationOut| {
        let operands_len = op
            .operands
            .iter()
            .map(|operand| operand.role.len() + operand.name.len() + 2)
            .sum::<usize>();
        if !text_cost {
            return (op.kind.len()
                + op.name.len()
                + op.in_function.len()
                + op.detail.as_deref().map_or(0, str::len)
                + operands_len
                + op.file.len()
                + 16) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let loc_len = short_file(&op.file).len() + 24;
        browse_table_row_cost(&[
            op.kind.len(),
            op.name.len(),
            op.in_function.len(),
            op.detail.as_deref().unwrap_or("-").len(),
            operands_len.min(80),
            loc_len,
        ])
        .saturating_add(source_line_estimated_cell_cost())
        .saturating_add(location_flow_labels_cell_cost(
            exact_flow_cost_ann.as_ref(),
            flows,
            &op.file,
            op.line,
        ))
    };
    match format {
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "operations",
                    filters_hash,
                    cost,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "operations", filters_hash, cost)?;
            }
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &out,
                &paging_cfg,
                "operations",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers = with_summaries_header(
                        &["kind", "name", "in", "detail", "operands", "location", "code"],
                        flows,
                    );
                    let mut t = u.table(&headers);
                    for op in &rows {
                        let operands = if op.operands.is_empty() {
                            "-".to_string()
                        } else {
                            truncate(
                                &op.operands
                                    .iter()
                                    .map(|operand| format!("{}:{}", operand.role, operand.name))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                80,
                            )
                        };
                        let loc = format!("{}:{}:{}", short_file(&op.file), op.line, op.column);
                        let ext = extension_for(&op.file);
                        let line_text = read_line(ws, &op.file, op.line);
                        let mut cells = vec![
                            Cell::new(u.kind(&op.kind)),
                            Cell::new(u.name(&op.name)),
                            Cell::new(u.kind(&op.in_function)),
                            Cell::new(u.dim(op.detail.as_deref().unwrap_or("-"))),
                            Cell::new(u.dim(&operands)),
                            Cell::new(u.path(&loc)),
                            Cell::new(u.snippet(&line_text, ext)),
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&op.file, op.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} operations)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja operations <workspace>");
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let (prefilter_literal, prefilter_regex) =
        f.name.map_or((f.has_method, false), |name| (Some(name), f.regex));
    let retrieval_kind = if f.has_method.is_some() {
        Some("method")
    } else {
        f.kind
    };
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, prefilter_literal, retrieval_kind, f.file, prefilter_regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting classes", || {
        project
            .browse()
            .classes(f)
            .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
    })?;
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "classes",
                    filters_hash,
                    cost,
                    class_summary_labels,
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "classes", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers = with_summaries_header(&["name", "kind", "location", "#", "methods"], flows);
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
                            let flows_text = class_summary_labels(ann, c);
                            cells.push(summary_cell_with_status(u, &flows_text, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} types)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let (project, _footer, _partial_workspace) =
        open_browse_project_with_retrieval(root, Some(symbol), Some("ref"), f.file, f.regex)?;
    let ws = project.workspace();
    let out = with_browse_progress("collecting references", || {
        project
            .browse()
            .refs(symbol, f)
            .map_err(|e| anyhow::anyhow!("invalid regex `{symbol}`: {e}"))
    })?;
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &out,
                    &paging_cfg,
                    "refs",
                    filters_hash,
                    cost,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &out, &paging_cfg, "refs", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let enclosing_ann = bonsai_sdk::SummaryAnnotator::new(ws);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers = with_summaries_header(&["symbol", "kind", "in", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    for r in &rows {
                        let loc = format!("{}:{}:{}", short_file(&r.file), r.line, r.column);
                        let snip = truncate(r.snippet.trim(), 100);
                        let enclosing = enclosing_ann
                            .enclosing_function_name(&r.file, r.line)
                            .unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&r.file);
                        let code_cell = Cell::new(u.snippet(&snip, ext));
                        let mut cells = vec![
                            Cell::new(u.name(&r.symbol)),
                            Cell::new(u.kind(&r.kind)),
                            Cell::new(u.kind(&enclosing)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&r.file, r.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} references)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
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
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let retrieval_project = if !f.regex
        && query.trim().len() >= 3
        && workspace_file_count_exceeds(root, BROWSE_LITERAL_PREFILTER_FILE_LIMIT)
    {
        open_project_index_retrieval_candidates(root, query, f)?
    } else {
        None
    };
    let (project, _footer, _partial_workspace) = if let Some((project, footer)) = retrieval_project {
        (project, footer, true)
    } else {
        open_browse_project(root, Some(query), f.regex)?
    };
    let ws = project.workspace();
    let hits = with_browse_progress("hydrating verified facts", || {
        project
            .browse()
            .search(query, f, usize::MAX)
            .map_err(|e| anyhow::anyhow!("invalid regex `{query}`: {e}"))
    })?;
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
        BrowseFormat::Json => {
            if flows {
                emit_summary_json_paged_cached(
                    root,
                    ws,
                    &hits,
                    &paging_cfg,
                    "search",
                    filters_hash,
                    cost,
                    |ann, row| ann.labels_for(&row.file, row.line),
                )?;
            } else {
                emit_json_paged_cached(root, &hits, &paging_cfg, "search", filters_hash, cost)?;
            }
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
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    // The "qualified" column is only meaningful for decl-kind
                    // hits; non-decl hits use the context column (signature /
                    // alias / "in <fn>") for the analogous info. The "code"
                    // column shows the actual source line, syntax-highlighted.
                    let headers = with_summaries_header(
                        &["name", "kind", "qualified", "context", "code", "location"],
                        flows,
                    );
                    let mut t = u.table(&headers);
                    for h in &rows {
                        let loc = format!("{}:{}:{}", short_file(&h.file), h.line, h.column);
                        let qualified = h.qualified_name.clone().unwrap_or_else(|| "-".to_string());
                        let context = h.context.clone().unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&h.file);
                        let code = h.code.trim();
                        let code_cell = Cell::new(u.snippet(code, ext));
                        let mut cells = vec![
                            Cell::new(u.name(&h.name)),
                            Cell::new(u.kind(&h.kind)),
                            Cell::new(u.dim(&qualified)),
                            Cell::new(u.dim(&context)),
                            code_cell,
                            Cell::new(u.path(&loc)),
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_for(&h.file, h.line);
                            cells.push(summary_cell_with_status(u, &labels, &mut flow_status));
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
                    cli_println!("{}", u.dim(&format!("({} matches)", info.total_rows)));
                    render_summary_column_notice(u, &flow_status);
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja search <workspace> <query>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn cmd_symbol_summary(
    root: &std::path::Path,
    symbol: &str,
    regex: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    // Summary edges are semantic resolver products. Candidate retrieval is
    // intentionally not used here because a partial workspace cannot prove
    // the complete direct caller/callee set.
    let (project, _footer) = open_project(root)?;
    let rows = with_browse_progress("building compiler symbol summary", || {
        project
            .browse()
            .symbol_summaries(Some(symbol), regex)
            .map_err(|error| anyhow::anyhow!("invalid symbol regex `{symbol}`: {error}"))
    })?;
    let filters_hash = paging::hash_filters(&[("symbol", symbol), ("regex", if regex { "1" } else { "0" })]);
    let cost = |row: &bonsai_sdk::SymbolSummary| {
        serde_json::to_string(row).map_or(512, |encoded| {
            encoded.len() as u64 + paging::TABLE_ROW_CHROME_BYTES
        })
    };
    match format {
        BrowseFormat::Json => {
            emit_json_paged_cached(root, &rows, &paging_cfg, "symbol-summary", filters_hash, cost)?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                root,
                &rows,
                &paging_cfg,
                "symbol-summary",
                filters_hash,
                cost,
                |page, info, _cfg| {
                    let u = ui();
                    for row in page {
                        let qualified = row.qualified_name.as_deref().unwrap_or(&row.name);
                        cli_println!();
                        cli_println!("{}", u.heading(&format!("{}  {}", qualified, row.summary_id)));
                        cli_println!(
                            "{}",
                            u.dim(&format!(
                                "{}:{}-{} · {} · {} · {}",
                                short_file(&row.file),
                                row.start_line,
                                row.end_line,
                                row.language,
                                row.kind,
                                row.graph_scope
                            ))
                        );
                        cli_println!("{}", u.snippet(&row.signature, extension_for(&row.file)));
                        if !row.source.trim().is_empty() {
                            cli_println!();
                            cli_println!("{}", u.label("SOURCE EVIDENCE"));
                            cli_println!("{}", u.snippet(&row.source, extension_for(&row.file)));
                        }
                        render_summary_edges(u, "DIRECT CALLERS", &row.direct_callers);
                        render_summary_edges(u, "DIRECT CALLEES", &row.direct_callees);
                        if !row.unresolved_calls.is_empty() {
                            cli_println!();
                            cli_println!("{}", u.label("UNRESOLVED WORKSPACE CALLS"));
                            for call in &row.unresolved_calls {
                                cli_println!(
                                    "  {}:{}:{}  {}",
                                    short_file(&call.file),
                                    call.line,
                                    call.column,
                                    call.call_text.trim()
                                );
                            }
                        }
                        if !row.imports.is_empty() {
                            cli_println!();
                            cli_println!("{}", u.label("IMPORTS"));
                            for import in &row.imports {
                                cli_println!(
                                    "  {}:{}  {}",
                                    short_file(&row.file),
                                    import.line,
                                    import.module
                                );
                            }
                        }
                    }
                    render_paging_footer(info, "bonsai-ninja symbol-summary <workspace> --symbol <name>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

fn render_summary_edges(u: &Ui, title: &str, edges: &[bonsai_sdk::SymbolCallEdge]) {
    if edges.is_empty() {
        return;
    }
    cli_println!();
    cli_println!("{}", u.label(title));
    for edge in edges {
        cli_println!(
            "  {} {} → {}  {}:{}:{}  {} / {}",
            edge.edge_id,
            edge.caller,
            edge.callee,
            short_file(&edge.file),
            edge.line,
            edge.column,
            edge.precision,
            edge.resolver_stage
        );
        if !edge.call_text.trim().is_empty() {
            cli_println!(
                "    {}",
                u.snippet(edge.call_text.trim(), extension_for(&edge.file))
            );
        }
        if !edge.resolver_evidence.trim().is_empty() {
            cli_println!("    {}", u.dim(&edge.resolver_evidence));
        }
    }
}

#[cfg(test)]
#[path = "browse_tests.rs"]
mod tests;
