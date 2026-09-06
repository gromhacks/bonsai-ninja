//! Browse commands: `defs`, `entrypoints`, `calls`, `imports`, `vars`,
//! `strings`, `comments`, `args`, `operations`, `classes`, `refs`, `search`. Each reads
//! from the shared `GlobalIndex` and emits a uniform `{header row, rows, footer}`
//! shape. JSON output keeps a bare array when the full result fits the
//! token budget; larger or explicitly paged renders use `{rows, page}`.

use anyhow::Result;
use bonsai_sdk::Workspace;
use comfy_table::Cell;

use crate::args::BrowseFormat;
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

/// Canonical presentation fields shared by text and JSON browse views. The
/// compiler fact remains flattened at the row root; these derived fields are
/// kept together so automation can consume every value the table renderer
/// shows without parsing terminal text.
#[derive(Clone, Debug, serde::Serialize)]
struct BrowsePresentation {
    location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enclosing_function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    import_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    summary_ids: Vec<String>,
}

fn canonical_browse_row<T: serde::Serialize>(
    ws: &Workspace,
    annotator: &bonsai_sdk::SummaryAnnotator<'_>,
    row: &T,
    include_summaries: bool,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(row)?;
    let fields = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("browse row did not serialize as an object"))?;
    let file = fields
        .get("file")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let line = fields
        .get("line")
        .and_then(serde_json::Value::as_u64)
        .and_then(|line| u32::try_from(line).ok())
        .unwrap_or(0);
    let column = fields
        .get("column")
        .and_then(serde_json::Value::as_u64)
        .and_then(|column| u32::try_from(column).ok())
        .unwrap_or(0);
    let location = if column == 0 {
        format!("{}:{line}", short_file(file))
    } else {
        format!("{}:{line}:{column}", short_file(file))
    };
    let code = fields
        .get("code")
        .and_then(serde_json::Value::as_str)
        .or_else(|| fields.get("snippet").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .or_else(|| (line != 0).then(|| read_line(ws, file, line)));
    let enclosing_function = (line != 0)
        .then(|| annotator.enclosing_function_name_at(file, line, column))
        .flatten();
    let signature = fields
        .get("name")
        .and_then(serde_json::Value::as_str)
        .zip(fields.get("params").and_then(serde_json::Value::as_array))
        .map(|(name, params)| {
            let params = params
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>();
            let params = dedup_sigil_params(&params);
            format!("{name}({})", params.join(", "))
        });
    let import_kind = fields
        .get("is_wildcard")
        .and_then(serde_json::Value::as_bool)
        .map(|wildcard| {
            import_kind_label(
                wildcard,
                fields.get("original_name").and_then(serde_json::Value::as_str),
            )
            .to_string()
        });
    let summary_ids = if include_summaries && line != 0 {
        annotator
            .labels_at(file, line, column)
            .split_whitespace()
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    fields.insert(
        "presentation".to_string(),
        serde_json::to_value(BrowsePresentation {
            location,
            code,
            enclosing_function,
            signature,
            import_kind,
            summary_ids,
        })?,
    );
    Ok(value)
}

#[derive(Clone, Debug, serde::Serialize)]
struct BrowseUsedIn {
    file: String,
    callers_in: Vec<bonsai_sdk::ModuleEdgeGroup>,
}

#[derive(Default)]
struct BrowseUses {
    connections: Vec<BrowseUsedIn>,
    incomplete_reasons: Vec<String>,
}

const SCOPED_CALL_EVIDENCE_UNAVAILABLE: &str = "cross-module caller evidence is unavailable or incomplete for this scoped view; run index <workspace> --semantic and retry";

/// Exact incoming cross-module call sites for the callable identities
/// represented by a browse page. A source row first resolves through the
/// compiler's enclosing-function ranges; incoming edges are then joined by
/// the target's stable compiler identity. This keeps filtered
/// browse pages from inheriting unrelated callers from the same file.
fn browse_used_in_connections<T: BrowseRowLocation>(ws: &Workspace, rows: &[T]) -> BrowseUses {
    let annotator = bonsai_sdk::SummaryAnnotator::new(ws);
    let mut targets = std::collections::BTreeMap::<
        bonsai_common::FileId,
        std::collections::BTreeSet<bonsai_common::FuncId>,
    >::new();
    for row in rows {
        let Some(file) = bonsai_sdk::workspace_file_id(ws, row.row_file()) else {
            continue;
        };
        let functions = row.row_functions(&annotator);
        if !functions.is_empty() {
            targets.entry(file).or_default().extend(functions);
        }
    }
    if targets.is_empty() {
        return BrowseUses::default();
    }
    let file_ids = targets.keys().copied().collect::<Vec<_>>();
    let facts = bonsai_sdk::file_connections(ws, &file_ids);
    let mut incomplete_reasons = Vec::new();
    if facts.iter().any(|facts| !facts.calls_complete) {
        incomplete_reasons.push(SCOPED_CALL_EVIDENCE_UNAVAILABLE.to_string());
        page_cache::mark_optional_evidence_unavailable();
    }
    let connections = facts
        .into_iter()
        .filter_map(|facts| {
            let wanted = targets.get(&facts.file_id)?;
            let callers_in = facts
                .callers_in
                .into_iter()
                .filter_map(|mut group| {
                    group.edges.retain(|edge| wanted.contains(&edge.callee_func));
                    (!group.edges.is_empty()).then_some(group)
                })
                .collect::<Vec<_>>();
            (!callers_in.is_empty()).then_some(BrowseUsedIn {
                file: facts.file,
                callers_in,
            })
        })
        .collect();
    BrowseUses {
        connections,
        incomplete_reasons,
    }
}

/// Render the incoming compiler-resolved cross-module uses for the current
/// page. This is intentionally a section rather than a table column: it is a
/// callable-level relation shared by all syntax row kinds, and keeping it out
/// of the dense row table preserves the exact source fact without widening
/// every browse schema. Empty sections are still rendered so every browse
/// command has the same discoverable cross-module affordance.
fn render_browse_used_in_section<T: BrowseRowLocation>(u: &Ui, ws: &Workspace, rows: &[T]) {
    let uses = browse_used_in_connections(ws, rows);
    cli_println!("{}", u.heading("used in (cross-module)"));
    for reason in &uses.incomplete_reasons {
        cli_println!("  {}", u.dim(reason));
    }
    let connections = uses.connections;
    if connections.is_empty() {
        if uses.incomplete_reasons.is_empty() {
            cli_println!(
                "  {}",
                u.dim("no compiler-resolved cross-module callers on this page")
            );
        }
        return;
    }
    let mut table = u.table(&["target", "caller", "callee", "call site", "edge"]);
    for facts in connections {
        for group in facts.callers_in {
            for edge in group.edges {
                let caller = format!("{} ({})", edge.caller, group.file);
                let call_site = format!("{}:{}:{}", group.file, edge.line, edge.column);
                table.add_row(vec![
                    Cell::new(u.path(&facts.file)),
                    Cell::new(u.name(&caller)),
                    Cell::new(u.name(&edge.callee)),
                    Cell::new(u.path(&call_site)),
                    Cell::new(u.annotation(&edge.edge_id)),
                ]);
            }
        }
    }
    cli_println!("{table}");
}

/// Apply the global `--contains` / `--not-contains` view to browse rows.
///
/// The filter reads the semantic row — every field the JSON `rows[]` entry
/// carries — plus its rendered `location` (`file:line[:column]`). It never
/// projects rows through the workspace (source lines, enclosing functions,
/// callee summaries), so narrowing a 300k-row result costs one serialization
/// per row and no engine work; the projection runs only for the rows that
/// reach the page. `_project` is kept in the signature so call sites keep
/// naming the projection they render with.
fn filter_browse_rows_by_canonical_value<T, P>(rows: &[T], _project: &P) -> Result<Option<Vec<T>>>
where
    T: Clone + serde::Serialize,
    P: Fn(&T) -> Result<serde_json::Value>,
{
    let secondary = crate::filter::active();
    if !secondary.is_active() {
        return Ok(None);
    }
    let mut scratch = crate::filter::FilterScratch::default();
    let mut location = String::new();
    Ok(Some(
        rows.iter()
            .filter(|row| {
                location.clear();
                row_location_leaf(*row, &mut location);
                let extra = (!location.is_empty()).then_some(location.as_str());
                secondary.matches_row(*row, &mut scratch, extra)
            })
            .cloned()
            .collect(),
    ))
}

/// The presentation strings a row renders that are pure functions of its
/// own fields — `location` (`file:line[:column]`) and `signature`
/// (`name(params)`) — derived without touching the workspace, one per line.
fn row_location_leaf<T: serde::Serialize>(row: &T, out: &mut String) {
    #[derive(serde::Deserialize, Default)]
    struct Derived {
        #[serde(default)]
        file: String,
        #[serde(default)]
        line: u32,
        #[serde(default)]
        column: u32,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        params: Option<Vec<String>>,
    }
    let Ok(json) = serde_json::to_vec(row) else {
        return;
    };
    let Ok(derived) = serde_json::from_slice::<Derived>(&json) else {
        return;
    };
    use std::fmt::Write as _;
    if !derived.file.is_empty() {
        if derived.column == 0 {
            let _ = writeln!(out, "{}:{}", short_file(&derived.file), derived.line);
        } else {
            let _ = writeln!(
                out,
                "{}:{}:{}",
                short_file(&derived.file),
                derived.line,
                derived.column
            );
        }
    }
    if let (Some(name), Some(params)) = (derived.name.as_deref(), derived.params.as_deref()) {
        let params = dedup_sigil_params(params);
        let _ = writeln!(out, "{name}({})", params.join(", "));
    }
}

/// Source location a browse row renders from. Every cached row type carries a
/// file and line, so the compiler can resolve its enclosing callable without
/// reparsing or name-based cross-module lookup.
pub(crate) trait BrowseRowLocation {
    fn row_file(&self) -> &str;
    fn row_line(&self) -> u32;
    fn row_column(&self) -> u32;
    fn row_functions(&self, ann: &bonsai_sdk::SummaryAnnotator<'_>) -> Vec<bonsai_common::FuncId> {
        ann.enclosing_function_id_at(self.row_file(), self.row_line(), self.row_column())
            .into_iter()
            .collect()
    }
}

impl BrowseRowLocation for bonsai_sdk::ClassOut {
    fn row_file(&self) -> &str {
        &self.file
    }
    fn row_line(&self) -> u32 {
        self.line
    }
    fn row_column(&self) -> u32 {
        self.column
    }
    fn row_functions(&self, ann: &bonsai_sdk::SummaryAnnotator<'_>) -> Vec<bonsai_common::FuncId> {
        ann.class_member_ids_at(&self.file, self.line, self.column)
    }
}

macro_rules! browse_row_location {
    ($($ty:ty),* $(,)?) => {
        $(impl BrowseRowLocation for $ty {
            fn row_file(&self) -> &str {
                &self.file
            }

            fn row_line(&self) -> u32 {
                self.line
            }

            fn row_column(&self) -> u32 {
                self.column
            }
        })*
    };
}

browse_row_location!(
    bonsai_sdk::DefOut,
    bonsai_sdk::CallOut,
    bonsai_sdk::RefOut,
    bonsai_sdk::ImportOut,
    bonsai_sdk::EntryPointOut,
    bonsai_sdk::ArgOut,
    bonsai_sdk::StringOut,
    bonsai_sdk::VarOut,
    bonsai_sdk::OperationOut,
    bonsai_sdk::CommentOut,
    bonsai_sdk::SearchHit,
);

/// Above this many distinct files the scoped open stops paying off and the
/// normal index-only open is used instead.
const ROWS_WINDOW_SCOPED_OPEN_FILE_LIMIT: usize = 512;

/// Open the workspace for rendering a cached complete row set: apply the text
/// filter, plan the pages exactly as the renderer will, and open only the
/// files of the rows in the render window. Falls back to the index-only open
/// when the window spans too many files or the whole result (`--all`).
fn open_project_for_rows_window<T>(
    root: &std::path::Path,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    cost: &dyn Fn(&T) -> u64,
) -> Result<(bonsai_sdk::Project, WorkspaceFooter, bool)>
where
    T: Clone + serde::Serialize + BrowseRowLocation,
{
    let filtered = filter_browse_rows_by_canonical_value(rows, &|_: &T| Ok(serde_json::Value::Null))?;
    let rows: &[T] = filtered.as_deref().unwrap_or(rows);
    let mut files: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut scoped = !cfg.all;
    if scoped {
        let (_, info) = paging::paginate(rows, cfg, command, filters_hash, cost)?;
        for page_number in page_cache::query_report_page_window(info.page_number, info.total_pages) {
            let mut page_cfg = cfg.clone();
            page_cfg.page = paging::PageArg::Number(page_number);
            let (slice, _) = paging::paginate(rows, &page_cfg, command, filters_hash, cost)?;
            files.extend(slice.iter().map(|row| row.row_file().to_string()));
            if files.len() > ROWS_WINDOW_SCOPED_OPEN_FILE_LIMIT {
                scoped = false;
                break;
            }
        }
    }
    if !scoped || files.is_empty() {
        let (project, footer) = open_project(root)?;
        return Ok((project, footer, false));
    }
    let include: Vec<String> = files.into_iter().collect();
    let (project, footer) = open_project_index_filtered_paths(root, &include, &[])?;
    // Rendering projects rows through exact compiler facts (attributions,
    // enclosing functions); attach the persisted compiler objects for the
    // window's files so those reads decode instead of re-lowering source.
    let ws = project.workspace();
    let window_files = ws.vfs().all_files();
    if let Err(error) = ws
        .db()
        .attach_reusable_compiler_object_store_for_files(&window_files)
    {
        tracing::debug!("scoped open could not attach compiler objects: {error}");
    }
    Ok((project, footer, true))
}

#[allow(clippy::too_many_arguments)]
fn emit_canonical_browse_json<T, C, P>(
    workspace: &std::path::Path,
    ws: &Workspace,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: C,
    project: P,
    analysis_incomplete_reasons: &[String],
) -> Result<()>
where
    T: Clone + serde::Serialize + BrowseRowLocation,
    C: Fn(&T) -> u64,
    P: Fn(&T) -> Result<serde_json::Value>,
{
    page_cache::emit_paged_text_prefiltered(
        workspace,
        rows,
        cfg,
        command,
        filters_hash,
        row_cost_bytes,
        |slice, info, _cfg| {
            let rendered = slice.iter().map(&project).collect::<Result<Vec<_>>>()?;
            let uses = browse_used_in_connections(ws, slice);
            let result_complete = page_covers_entire_result(info);
            let wrapped = serde_json::json!({
                "analysis_complete": analysis_incomplete_reasons.is_empty(),
                "analysis_incomplete_reasons": analysis_incomplete_reasons,
                "result_complete": result_complete,
                "result_incomplete_reasons": if result_complete {
                    Vec::<String>::new()
                } else {
                    paged_json_incomplete_reasons(command, info)
                },
                "rows": rendered,
                "used_in": uses.connections,
                "used_in_complete": uses.incomplete_reasons.is_empty(),
                "used_in_incomplete_reasons": uses.incomplete_reasons,
                "page": page_info_to_json(info),
            });
            crate::output::emit_json_document(&wrapped)?;
            Ok(())
        },
    )
}
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
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::DefOut>(root, "defs", filters_hash)?;
    // A cached complete row set needs the workspace only for the rows it
    // renders: open exactly their files instead of ingesting the tree.
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) => {
            let scoped =
                open_project_for_rows_window(root, &payload.rows, &paging_cfg, "defs", filters_hash, &cost)?;
            (scoped.0, scoped.1, scoped.2)
        }
        None => open_browse_project_with_retrieval(root, prefilter_literal, retrieval_kind, f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting definitions", || {
                project
                    .browse()
                    .defs(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "defs", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row = |definition: &bonsai_sdk::DefOut| {
        let mut value = canonical_browse_row(ws, &canonical_ann, definition, flows)?;
        let callees = def_callee_summaries(ws, std::slice::from_ref(definition), usize::MAX)
            .into_iter()
            .next()
            .unwrap_or_default();
        if let Some(presentation) = value
            .get_mut("presentation")
            .and_then(serde_json::Value::as_object_mut)
        {
            presentation.insert("callees".to_string(), serde_json::json!(callees));
        }
        Ok(value)
    };
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "defs",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                            let labels = ann.labels_at(&d.file, d.line, d.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
        // Entry-point rows have six independently wrapped columns. The
        // shared table model prices their combined width, while comfy-table
        // repeats borders/padding at each column wrap and the renderer also
        // formats the signature/callee preview. Keep this command's estimate
        // conservative so a normal context page does not render over its
        // advertised budget.
        browse_table_row_cost(&[
            e.name.len(),
            e.kind.len(),
            loc_len,
            params_len,
            callees_len,
            e.reason.len(),
        ])
        .saturating_mul(5)
        .saturating_div(4)
    };
    let cached_rows =
        page_cache::read_rows_payload::<bonsai_sdk::EntryPointOut>(root, "entrypoints", filters_hash)?;
    // A cached complete row set needs the workspace only for the rows it
    // renders: open exactly their files instead of ingesting the tree.
    let (project, _footer) = match cached_rows.as_ref() {
        Some(payload) => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "entrypoints",
                filters_hash,
                &cost,
            )?;
            (scoped.0, scoped.1)
        }
        None => {
            if let Some(file) = f.file.filter(|file| !file.trim().is_empty()) {
                open_project_index_filtered_paths(root, &[file.to_string()], &[])?
            } else {
                open_project(root)?
            }
        }
    };
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting entrypoints", || {
                project
                    .browse()
                    .entrypoints(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "entrypoints", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(project.workspace());
    let project_row = |entrypoint: &bonsai_sdk::EntryPointOut| {
        canonical_browse_row(project.workspace(), &canonical_ann, entrypoint, false)
    };
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons = cached_analysis_reasons
        .unwrap_or_else(|| super::touched_parser_incomplete_reasons(project.workspace()));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                project.workspace(),
                rows,
                &paging_cfg,
                "entrypoints",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, project.workspace(), &rows);
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

/// One-line preview of a fact's text for table cells: whitespace runs
/// (including newlines inside a multi-line argument or string) collapse to a
/// single space before the width cap. The canonical row keeps the full text.
pub(crate) fn one_line_preview(text: &str, max: usize) -> String {
    let mut collapsed = String::with_capacity(text.len().min(max + 4));
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = !collapsed.is_empty();
            continue;
        }
        if pending_space {
            collapsed.push(' ');
            pending_space = false;
        }
        collapsed.push(ch);
        if collapsed.chars().count() > max + 1 {
            break;
        }
    }
    truncate(&collapsed, max)
}

/// Display form of a row's file: the exact workspace-relative path JSON
/// carries. Locations printed by the text view must be the same fact a
/// script reads, and must paste back into `read-file`, `--file`, and
/// `--in-file` unchanged, so no component is ever dropped.
pub(crate) fn short_file(p: &str) -> String {
    p.to_string()
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
/// Cost of one cell on the rendered-line model (see
/// [`rendered_table_row_cost`]): the physical lines the cell folds into,
/// each charged a generous per-line allowance.
fn wrapped_table_cell_cost(len: usize) -> u64 {
    rendered_table_row_cost(&[len])
}

/// Estimate one table row from its cell widths. Comfy-table folds the row
/// into physical lines of at most the canonical CLI width, so the cost is
/// the number of rendered lines times a generous per-line allowance plus a
/// small per-row chrome; charging every character three times over made
/// pages stop at roughly a tenth of their stated budget.
fn browse_table_row_cost(cells: &[usize]) -> u64 {
    rendered_table_row_cost(cells).saturating_add(48)
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
    column: u32,
) -> u64 {
    if let Some(ann) = exact_ann {
        flow_labels_cell_cost(&ann.labels_at(file, line, column))
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
    ann.labels_for_class_at(&class.file, class.line, class.column)
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
    let filters_hash = paging::hash_filters(&[
        ("callee", f.callee.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("caller", f.caller.unwrap_or("")),
        ("call_kind", f.call_kind.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    // Workspace-free page cost: identical to the model below whenever
    // summaries are off, which is when a cached row set may open only the
    // render window's files.
    let window_cost = |c: &bonsai_sdk::CallOut| {
        if !text_cost {
            return (c.callee.len() + c.caller.as_deref().map_or(1, str::len) + c.file.len() + 16) as u64
                + paging::TABLE_ROW_CHROME_BYTES;
        }
        let caller = c.caller.as_deref().unwrap_or("-");
        let loc_len = short_file(&c.file).len() + 24;
        browse_table_row_cost(&[c.callee.len(), caller.len(), loc_len])
            .saturating_add(source_line_estimated_cell_cost())
            .saturating_add(location_flow_labels_cell_cost(
                None::<&bonsai_sdk::SummaryAnnotator<'_>>,
                flows,
                &c.file,
                c.line,
                c.column,
            ))
    };
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::CallOut>(root, "calls", filters_hash)?;
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) if !flows => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "calls",
                filters_hash,
                &window_cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        _ => open_browse_project_with_retrieval(root, prefilter_literal, Some("call"), f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting call sites", || {
                project
                    .browse()
                    .calls(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "calls", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    // Filter-signature hash: same `(cmd, filters_hash, offset)`
    // tuple used to derive the cursor must be stable across runs
    // so a `P:xxxxxxxx` cursor from a bug report reproduces.
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
                c.column,
            ))
    };
    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row = |call: &bonsai_sdk::CallOut| canonical_browse_row(ws, &canonical_ann, call, flows);
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "calls",
                filters_hash,
                cost_bytes,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            // `--context` / `--page` / `--all` drive the slice.
            // Legacy `--limit` applies after paging — a belt-and-
            // suspenders truncation a user can set when their
            // context budget happens to fit more rows than they
            // want visually (rare). Paging is the primary knob.
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                        with_summaries_header(&["callee text", "caller function", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    for c in &rows {
                        let caller = c.caller.as_deref().unwrap_or("-");
                        let loc = format!("{}:{}:{}", short_file(&c.file), c.line, c.column);
                        let ext = extension_for(&c.file);
                        let line_text = read_line(ws, &c.file, c.line);
                        let code_cell = Cell::new(u.snippet(&line_text, ext));
                        let mut cells = vec![
                            Cell::new(u.name(&one_line_preview(&c.callee, 120))),
                            Cell::new(u.kind(caller)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_at(&c.file, c.line, c.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
                    render_paging_footer(info, "bonsai-ninja calls <workspace>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_json_paged_cached<T, F>(
    workspace: &std::path::Path,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: F,
    analysis_incomplete_reasons: &[String],
) -> Result<()>
where
    T: serde::Serialize + Clone,
    F: Fn(&T) -> u64,
{
    // Row-oriented JSON has one stable document shape regardless of paging:
    // command completeness plus the exact canonical rows rendered by text.
    // Returning a bare array for `--all` made consumers branch on flags and
    // discarded the distinction between analysis and result completeness.
    page_cache::emit_paged_text(
        workspace,
        rows,
        cfg,
        command,
        filters_hash,
        row_cost_bytes,
        |slice, info, _cfg| {
            let result_incomplete_reasons = paged_json_incomplete_reasons(command, info);
            let wrapped = serde_json::json!({
                "analysis_complete": analysis_incomplete_reasons.is_empty(),
                "analysis_incomplete_reasons": analysis_incomplete_reasons,
                "result_complete": result_incomplete_reasons.is_empty(),
                "result_incomplete_reasons": result_incomplete_reasons,
                "rows": slice,
                "page": page_info_to_json(info),
            });
            crate::output::emit_json_document(&wrapped)?;
            Ok(())
        },
    )?;
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
    emit_json_value_paged_cached_inner(workspace, value, cfg, command, filters_hash, true)
}

pub(crate) fn emit_json_value_paged_cached_prefiltered<T>(
    workspace: &std::path::Path,
    value: &T,
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
) -> Result<()>
where
    T: serde::Serialize,
{
    emit_json_value_paged_cached_inner(workspace, value, cfg, command, filters_hash, false)
}

fn emit_json_value_paged_cached_inner<T>(
    workspace: &std::path::Path,
    value: &T,
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    apply_secondary_filter: bool,
) -> Result<()>
where
    T: serde::Serialize,
{
    let canonical = serde_json::to_value(value)?;
    let secondary = crate::filter::active();
    if apply_secondary_filter && secondary.is_active() && !secondary.matches_value(&canonical) {
        crate::output::emit_json_document(&serde_json::json!({
            "analysis_complete": true,
            "analysis_incomplete_reasons": [],
            "result_complete": true,
            "result_incomplete_reasons": [],
            "matched": false,
            "value": null,
        }))?;
        return Ok(());
    }

    // A structured object is one semantic result, not a bag of formatted JSON
    // source lines. Keep it atomic even when it exceeds a requested context
    // budget; `page.oversized_rows` makes that explicit without corrupting the
    // command schema or omitting child facts.
    page_cache::emit_paged_text_prefiltered(
        workspace,
        std::slice::from_ref(&canonical),
        cfg,
        command,
        filters_hash,
        |row| {
            serde_json::to_vec(row)
                .map(|bytes| bytes.len() as u64 + paging::TABLE_ROW_CHROME_BYTES)
                .unwrap_or(paging::TABLE_ROW_CHROME_BYTES)
        },
        |slice, info, _cfg| {
            let mut native = slice.first().cloned().unwrap_or(serde_json::Value::Null);
            match &mut native {
                serde_json::Value::Object(fields) => {
                    fields
                        .entry("analysis_complete".to_string())
                        .or_insert(serde_json::Value::Bool(true));
                    fields
                        .entry("analysis_incomplete_reasons".to_string())
                        .or_insert_with(|| serde_json::json!([]));
                    fields.insert("result_complete".to_string(), serde_json::Value::Bool(true));
                    fields.insert("result_incomplete_reasons".to_string(), serde_json::json!([]));
                    fields.insert("page".to_string(), page_info_to_json(info));
                }
                serde_json::Value::Array(rows) => {
                    native = serde_json::json!({
                        "analysis_complete": true,
                        "analysis_incomplete_reasons": [],
                        "result_complete": true,
                        "result_incomplete_reasons": [],
                        "rows": rows,
                        "page": page_info_to_json(info),
                    });
                }
                _ => {
                    native = serde_json::json!({
                        "analysis_complete": true,
                        "analysis_incomplete_reasons": [],
                        "result_complete": true,
                        "result_incomplete_reasons": [],
                        "value": native,
                        "page": page_info_to_json(info),
                    });
                }
            }
            crate::output::emit_json_document(&native)?;
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

/// Convert a [`paging::PageInfo`] into the canonical JSON `page` object.
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
        "budget_exceeded": info.budget.is_some_and(|budget| info.tokens_used > budget),
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
    // Summaries resolve workspace bindings while collecting, which changes
    // the rows: the setting is part of the row set's identity.
    f.resolve_workspace_bindings = flows;
    let filters_hash = paging::hash_filters(&[
        ("file", f.file.unwrap_or("")),
        ("module", f.module.unwrap_or("")),
        ("alias", f.alias.unwrap_or("")),
        ("wildcard", if f.wildcard { "1" } else { "0" }),
        ("regex", if f.regex { "1" } else { "0" }),
        ("resolve_bindings", if flows { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    // Workspace-free page cost: identical to the model below whenever
    // summaries are off, which is when a cached row set may open only the
    // render window's files.
    let window_cost = |import: &bonsai_sdk::ImportOut| {
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
        let flow_len = None::<&bonsai_sdk::SummaryAnnotator<'_>>
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
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::ImportOut>(root, "imports", filters_hash)?;
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) if !flows => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "imports",
                filters_hash,
                &window_cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        _ => open_browse_project_with_retrieval(root, prefilter_literal, Some("import"), f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting imports", || {
                project
                    .browse()
                    .imports(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "imports", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

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
    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row = |import: &bonsai_sdk::ImportOut| {
        let mut value = canonical_browse_row(ws, &canonical_ann, import, flows)?;
        if flows {
            if let Some(presentation) = value
                .get_mut("presentation")
                .and_then(serde_json::Value::as_object_mut)
            {
                presentation.insert(
                    "summary_ids".to_string(),
                    serde_json::json!(import_flow_labels(&canonical_ann, import)
                        .split_whitespace()
                        .collect::<Vec<_>>()),
                );
            }
        }
        Ok(value)
    };
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "imports",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                        let loc = format!("{}:{}:{}", short_file(&import.file), import.line, import.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    let filters_hash = paging::hash_filters(&[
        ("name", f.name.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("source", f.source.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    // Workspace-free page cost: identical to the model below whenever
    // summaries are off, which is when a cached row set may open only the
    // render window's files.
    let window_cost = |v: &bonsai_sdk::VarOut| {
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
                None::<&bonsai_sdk::SummaryAnnotator<'_>>,
                flows,
                &v.file,
                v.line,
                v.column,
            ))
    };
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::VarOut>(root, "vars", filters_hash)?;
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) if !flows => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "vars",
                filters_hash,
                &window_cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        _ => open_browse_project_with_retrieval(root, prefilter_literal, Some("var"), f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting variables", || {
                project
                    .browse()
                    .vars(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "vars", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

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
                v.column,
            ))
    };
    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row =
        |variable: &bonsai_sdk::VarOut| canonical_browse_row(ws, &canonical_ann, variable, flows);
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "vars",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
                &paging_cfg,
                "vars",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers =
                        with_summaries_header(&["var", "in function", "source", "location", "code"], flows);
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
                            let labels = ann.labels_at(&v.file, v.line, v.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    let filters_hash = paging::hash_filters(&[
        ("category", f.category.unwrap_or("")),
        ("contains", f.contains.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("min_len", &f.min_len.map(|n| n.to_string()).unwrap_or_default()),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    // Workspace-free page cost: identical to the model below whenever
    // summaries are off, which is when a cached row set may open only the
    // render window's files.
    let window_cost = |s: &bonsai_sdk::StringOut| {
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
            None::<&bonsai_sdk::SummaryAnnotator<'_>>,
            flows,
            &s.file,
            s.line,
            s.column,
        ))
    };
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::StringOut>(root, "strings", filters_hash)?;
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) if !flows => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "strings",
                filters_hash,
                &window_cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        _ => open_browse_project_with_retrieval(root, prefilter_literal, Some("string"), f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting strings", || {
                project
                    .browse()
                    .strings(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "strings", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    // Strings table has a syntax-highlighted `code` column (the
    // enclosing source line, up to ~120 bytes) + a `flows` column
    // that accretes F:<16-hex> ids for rows inside hot functions.
    // Account for both — the original estimate only covered the
    // text preview + file path.
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
            s.column,
        ))
    };
    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row =
        |string: &bonsai_sdk::StringOut| canonical_browse_row(ws, &canonical_ann, string, flows);
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "strings",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                    let headers = with_summaries_header(
                        &["category", "text", "in function", "location", "code"],
                        flows,
                    );
                    let mut t = u.table(&headers);
                    for s in &rows {
                        let preview = truncate(&s.text, 60);
                        let loc = format!("{}:{}:{}", short_file(&s.file), s.line, s.column);
                        let enclosing = enclosing_ann
                            .enclosing_function_name_at(&s.file, s.line, s.column)
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
                            let labels = ann.labels_at(&s.file, s.line, s.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    let cached_rows =
        page_cache::read_rows_payload::<bonsai_sdk::CommentOut>(root, "comments", filters_hash)?;
    // A cached complete row set needs the workspace only for the rows it
    // renders: open exactly their files instead of ingesting the tree.
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "comments",
                filters_hash,
                &cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        None => {
            open_browse_project_with_retrieval(root, prefilter_literal, Some("comment"), f.file, f.regex)?
        }
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting comments", || {
                project
                    .browse()
                    .comments(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "comments", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row =
        |comment: &bonsai_sdk::CommentOut| canonical_browse_row(ws, &canonical_ann, comment, false);
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "comments",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
                &paging_cfg,
                "comments",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let enclosing_ann = bonsai_sdk::SummaryAnnotator::new(ws);
                    let headers = &["kind", "text", "in function", "location"];
                    let mut t = u.table(headers);
                    for c in &rows {
                        let preview = truncate(&c.text.replace('\n', " "), 100);
                        let loc = format!("{}:{}:{}", short_file(&c.file), c.line, c.column);
                        let enclosing = enclosing_ann
                            .enclosing_function_name_at(&c.file, c.line, c.column)
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    // Workspace-free page cost: identical to the model below whenever
    // summaries are off, which is when a cached row set may open only the
    // render window's files.
    let window_cost = |a: &bonsai_sdk::ArgOut| {
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
            None::<&bonsai_sdk::SummaryAnnotator<'_>>,
            flows,
            &a.file,
            a.line,
            a.column,
        ))
    };
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::ArgOut>(root, "args", filters_hash)?;
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) if !flows => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "args",
                filters_hash,
                &window_cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        _ => open_browse_project_with_retrieval(root, prefilter_literal, retrieval_kind, f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting arguments", || {
                project
                    .browse()
                    .args(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "args", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

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
            a.column,
        ))
    };
    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row =
        |argument: &bonsai_sdk::ArgOut| canonical_browse_row(ws, &canonical_ann, argument, flows);
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "args",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                        &[
                            "callee text",
                            "position",
                            "value",
                            "in function",
                            "location",
                            "code",
                        ],
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
                            .enclosing_function_name_at(&a.file, a.line, a.column)
                            .unwrap_or_else(|| "-".to_string());
                        let ext = extension_for(&a.file);
                        let line_text = read_line(ws, &a.file, a.line);
                        let code_cell = Cell::new(u.snippet(&line_text, ext));
                        let mut cells = vec![
                            Cell::new(u.name(&one_line_preview(&a.callee, 120))),
                            Cell::new(u.loc(&pos_label)),
                            Cell::new(u.dim(&value)),
                            Cell::new(u.kind(&caller)),
                            Cell::new(u.path(&loc)),
                            code_cell,
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_at(&a.file, a.line, a.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    let filters_hash = paging::hash_filters(&[
        ("kind", f.kind.unwrap_or("")),
        ("name", f.name.unwrap_or("")),
        ("file", f.file.unwrap_or("")),
        ("in_fn", f.in_fn.unwrap_or("")),
        ("regex", if f.regex { "1" } else { "0" }),
    ]);
    let text_cost = matches!(format, BrowseFormat::Text);
    // Workspace-free page cost: identical to the model below whenever
    // summaries are off, which is when a cached row set may open only the
    // render window's files.
    let window_cost = |op: &bonsai_sdk::OperationOut| {
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
            None::<&bonsai_sdk::SummaryAnnotator<'_>>,
            flows,
            &op.file,
            op.line,
            op.column,
        ))
    };
    let cached_rows =
        page_cache::read_rows_payload::<bonsai_sdk::OperationOut>(root, "operations", filters_hash)?;
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) if !flows => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "operations",
                filters_hash,
                &window_cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        _ => open_browse_project_with_retrieval(root, prefilter_literal, Some("operation"), f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting operations", || {
                project
                    .browse()
                    .operations(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "operations", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

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
            op.column,
        ))
    };
    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row =
        |operation: &bonsai_sdk::OperationOut| canonical_browse_row(ws, &canonical_ann, operation, flows);
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "operations",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                        &[
                            "kind",
                            "name",
                            "in function",
                            "detail",
                            "operands",
                            "location",
                            "code",
                        ],
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
                            let labels = ann.labels_at(&op.file, op.line, op.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::ClassOut>(root, "classes", filters_hash)?;
    // A cached complete row set needs the workspace only for the rows it
    // renders: open exactly their files instead of ingesting the tree.
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "classes",
                filters_hash,
                &cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        None => open_browse_project_with_retrieval(
            root,
            prefilter_literal,
            retrieval_kind,
            f.file,
            prefilter_regex,
        )?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting classes", || {
                project
                    .browse()
                    .classes(f)
                    .map_err(|e| anyhow::anyhow!("invalid regex: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "classes", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row = |class: &bonsai_sdk::ClassOut| {
        let mut value = canonical_browse_row(ws, &canonical_ann, class, flows)?;
        if flows {
            if let Some(presentation) = value
                .get_mut("presentation")
                .and_then(serde_json::Value::as_object_mut)
            {
                presentation.insert(
                    "summary_ids".to_string(),
                    serde_json::json!(class_summary_labels(&canonical_ann, class)
                        .split_whitespace()
                        .collect::<Vec<_>>()),
                );
            }
        }
        Ok(value)
    };
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "classes",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
                &paging_cfg,
                "classes",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let (rows, truncated) = apply_text_limit(paged, effective_limit(limit, cfg));
                    let u = ui();
                    let (flow_ann, flow_bar) = build_summary_annotator(ws, flows, rows.len() as u64);
                    let mut flow_status = SummaryColumnStatus::default();
                    let headers = with_summaries_header(
                        &["name", "kind", "location", "method count", "methods"],
                        flows,
                    );
                    let mut t = u.table(&headers);
                    for c in &rows {
                        let loc = format!("{}:{}:{}", short_file(&c.file), c.line, c.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::RefOut>(root, "refs", filters_hash)?;
    // A cached complete row set needs the workspace only for the rows it
    // renders: open exactly their files instead of ingesting the tree.
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) => {
            let scoped =
                open_project_for_rows_window(root, &payload.rows, &paging_cfg, "refs", filters_hash, &cost)?;
            (scoped.0, scoped.1, scoped.2)
        }
        None => open_browse_project_with_retrieval(root, Some(symbol), Some("ref"), f.file, f.regex)?,
    };
    let ws = project.workspace();
    let (out, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let out = with_browse_progress("collecting references", || {
                project
                    .browse()
                    .refs(symbol, f)
                    .map_err(|e| anyhow::anyhow!("invalid regex `{symbol}`: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "refs", filters_hash, &out, &reasons);
            (out, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row =
        |reference: &bonsai_sdk::RefOut| canonical_browse_row(ws, &canonical_ann, reference, flows);
    let filtered_rows = filter_browse_rows_by_canonical_value(&out, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&out);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "refs",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                    let headers =
                        with_summaries_header(&["symbol", "kind", "in function", "location", "code"], flows);
                    let mut t = u.table(&headers);
                    for r in &rows {
                        let loc = format!("{}:{}:{}", short_file(&r.file), r.line, r.column);
                        let snip = truncate(r.snippet.trim(), 100);
                        let enclosing = enclosing_ann
                            .enclosing_function_name_at(&r.file, r.line, r.column)
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
                            let labels = ann.labels_at(&r.file, r.line, r.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
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
    let cached_rows = page_cache::read_rows_payload::<bonsai_sdk::SearchHit>(root, "search", filters_hash)?;
    // A cached complete row set needs the workspace only for the rows it
    // renders: open exactly their files instead of ingesting the tree.
    let (project, _footer, _partial_workspace) = match cached_rows.as_ref() {
        Some(payload) => {
            let scoped = open_project_for_rows_window(
                root,
                &payload.rows,
                &paging_cfg,
                "search",
                filters_hash,
                &cost,
            )?;
            (scoped.0, scoped.1, scoped.2)
        }
        None => {
            if let Some((project, footer)) = retrieval_project {
                (project, footer, true)
            } else {
                open_browse_project(root, Some(query), f.regex)?
            }
        }
    };
    let ws = project.workspace();
    let (hits, cached_analysis_reasons) = match cached_rows {
        Some(payload) => (payload.rows, Some(payload.analysis_incomplete_reasons)),
        None => {
            let hits = with_browse_progress("hydrating verified facts", || {
                project
                    .browse()
                    .search(query, f, usize::MAX)
                    .map_err(|e| anyhow::anyhow!("invalid regex `{query}`: {e}"))
            })?;
            let reasons = super::touched_parser_incomplete_reasons(project.workspace());
            page_cache::save_rows_payload(root, "search", filters_hash, &hits, &reasons);
            (hits, None)
        }
    };
    // The complete row set is a cached object keyed by the semantic
    // filters; page turns, formats, and text filters reuse it.

    let canonical_ann = bonsai_sdk::SummaryAnnotator::new(ws);
    let project_row = |hit: &bonsai_sdk::SearchHit| canonical_browse_row(ws, &canonical_ann, hit, flows);
    let filtered_rows = filter_browse_rows_by_canonical_value(&hits, &project_row)?;
    let rows = filtered_rows.as_deref().unwrap_or(&hits);
    let analysis_reasons =
        cached_analysis_reasons.unwrap_or_else(|| super::touched_parser_incomplete_reasons(ws));
    match format {
        BrowseFormat::Json => {
            emit_canonical_browse_json(
                root,
                ws,
                rows,
                &paging_cfg,
                "search",
                filters_hash,
                cost,
                project_row,
                &analysis_reasons,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text_prefiltered(
                root,
                rows,
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
                            Cell::new(u.name(&one_line_preview(&h.name, 80))),
                            Cell::new(u.kind(&h.kind)),
                            Cell::new(u.dim(&qualified)),
                            Cell::new(u.dim(&context)),
                            code_cell,
                            Cell::new(u.path(&loc)),
                        ];
                        if let Some(ann) = flow_ann.as_ref() {
                            let labels = ann.labels_at(&h.file, h.line, h.column);
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
                    super::render_analysis_incomplete_notice(&analysis_reasons);
                    render_browse_used_in_section(u, ws, &rows);
                    render_paging_footer(info, "bonsai-ninja search <workspace> <query>");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "browse_tests.rs"]
mod tests;
