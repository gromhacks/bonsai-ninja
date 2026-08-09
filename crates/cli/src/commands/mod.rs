//! Per-subcommand handlers and renderers.
//!
//! Sub-modules: [`browse`] (browse commands), [`dump`] (structural
//! dumps), [`trace`], [`inspect`], [`export`]. Shared helpers
//! (project open, symbol resolution, paging plumbing) live here.

use anyhow::Result;
use bonsai_sdk::Workspace;
use bonsai_sdk::{Project, WorkspaceCacheStatus, WorkspaceOpenEvent};
use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use crate::footer::WorkspaceFooter;
use crate::progress;

pub(crate) mod browse;
pub(crate) mod cache;
pub(crate) mod diagnostics;
pub(crate) mod dump;
pub(crate) mod export;
pub(crate) mod inspect;
pub(crate) mod path;
pub(crate) mod read_file;
pub(crate) mod security;
pub(crate) mod show;
pub(crate) mod slice;
pub(crate) mod trace;
pub(crate) mod tree;

pub(crate) use bonsai_sdk::{
    ArgsFilters, CallsFilters, ClassesFilters, CommentsFilters, DefsFilters, EntryPointsFilters,
    ImportsFilters, OperationsFilters, RefsFilters, SearchFilters, StringsFilters, VarsFilters,
};
pub(crate) use browse::{
    apply_text_limit, cmd_args, cmd_calls, cmd_classes, cmd_comments, cmd_defs, cmd_entrypoints, cmd_imports,
    cmd_operations, cmd_refs, cmd_search, cmd_strings, cmd_vars, emit_json_paged_cached,
    emit_json_value_paged_cached, page_info_to_json, paged_json_incomplete_reasons, paging_from_cli,
    paging_from_cli_output, paging_with_row_limit, short_file, truncate,
};
pub(crate) use cache::cmd_cache;
pub(crate) use diagnostics::{
    cmd_context, cmd_diagnostics, cmd_dump_cfg, cmd_dump_hir, cmd_index, IndexCommandOptions,
};
pub(crate) use dump::{
    cmd_dump_ast, cmd_dump_callgraph, cmd_dump_edges, cmd_dump_resolution, cmd_dump_resolve, cmd_dump_taint,
};
pub(crate) use export::cmd_export;
pub(crate) use inspect::{
    cmd_inspect, render_flow_block_with_heading, render_flow_with_cached_call_spans, BodySet,
    InspectCommandOptions, InspectFilters, InspectFlowRendered, InspectRenderOptions,
};
pub(crate) use path::{cmd_path, PathCommandOptions};
pub(crate) use slice::cmd_slice;
pub(crate) use trace::{cmd_trace, nearest_names, not_found_with_suggestions};

/// Return as soon as a workspace contains more than `limit` source-tree
/// entries. This cheap probe selects retrieval-backed command plans without
/// building compiler state merely to estimate repository size.
pub(crate) fn workspace_file_count_exceeds(root: &std::path::Path, limit: usize) -> bool {
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if is_internal_workspace_entry_name(name) {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                seen += 1;
                if seen > limit {
                    return true;
                }
            }
        }
    }
    false
}

/// Product metadata and generated build roots omitted from direct filesystem
/// navigation and its cheap repository-size probe. This is CLI lifecycle
/// policy, not source-language or security-pattern knowledge.
pub(crate) fn is_internal_workspace_entry_name(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".bonsai"
            | ".bonsai-agent"
            | "target"
            | "node_modules"
            | ".gradle"
            | "build"
            | "dist"
            | "out"
            | ".idea"
    ) || name.starts_with(".bonsai.pre-")
}

/// Resolve the symbol for commands that accept either a positional
/// argument (`bonsai-ninja trace ./src handle_request`) or a named
/// flag (`--symbol` / `--query` depending on the subcommand). The
/// positional form wins when both are set so scripted pipelines
/// have predictable precedence.
///
/// `flag_name` is the name of the named flag for the calling
/// command (`symbol` for most dumps / refs / trace; `query` for
/// search / inspect) so the error message points the user at the
/// right flag rather than a generic "try --symbol or --query".
pub(crate) fn resolve_symbol_arg(
    positional: Option<String>,
    flag: Option<String>,
    flag_name: &str,
) -> Result<String> {
    positional
        .or(flag)
        .ok_or_else(|| anyhow::anyhow!("expected a symbol as positional arg or --{flag_name}"))
}

/// Open the workspace at `root` through the SDK lifecycle facade and
/// return the live project plus a [`WorkspaceFooter`] guard.
///
/// The guard prints a cloc/LLM-style summary line on drop (when
/// stderr is a TTY and chrome isn't muted), so every CLI command
/// that opens a workspace gets a consistent closing stats line for
/// free — no per-command wiring needed beyond holding the guard
/// alive for the function's body.
///
/// Callers always bind the guard to a name (even `_footer`) —
/// dropping it immediately would print the footer BEFORE the
/// command's actual output renders.
pub(crate) fn open_project_dataflow_prewarm(root: &std::path::Path) -> Result<(Project, WorkspaceFooter)> {
    let mut options = bonsai_sdk::OpenOptions::parse_only();
    options.load_dataflow_sidecar = true;
    options.prewarm_dataflow = true;
    options.save_dataflow_sidecar = true;
    open_project_with_options(root, options)
}

pub(crate) fn open_project_index_only(root: &std::path::Path) -> Result<(Project, WorkspaceFooter)> {
    open_project_with_options(root, bonsai_sdk::OpenOptions::lazy_query())
}

/// Open a semantic path query without hydrating unrelated compatibility
/// caches. A fresh IDG sidecar is loaded when present; a miss remains
/// read-only and the path facade falls back to the exact resolved callgraph.
pub(crate) fn open_project_path_query(root: &std::path::Path) -> Result<(Project, WorkspaceFooter)> {
    let mut options = bonsai_sdk::OpenOptions::lazy_query();
    options.load_idg_sidecar = true;
    open_project_with_options(root, options)
}

pub(crate) fn open_project_index_matching_literal(
    root: &std::path::Path,
    literal: &str,
) -> Result<(Project, WorkspaceFooter)> {
    let progress = workspace_open_progress();
    let project = bonsai_for_cli()
        .open_query_matching_literal_with_progress(root, literal, progress)?
        .with_auto_refresh(false);
    crate::page_cache::remember_workspace_fingerprint(root, project.source_content_fingerprint());
    let footer = WorkspaceFooter::new();
    Ok((project, footer))
}

pub(crate) fn open_project_index_matching_any_literal(
    root: &std::path::Path,
    literals: &[&str],
) -> Result<(Project, WorkspaceFooter)> {
    let progress = workspace_open_progress();
    let project = bonsai_for_cli()
        .open_query_matching_any_literal_with_progress(root, literals, progress)?
        .with_auto_refresh(false);
    crate::page_cache::remember_workspace_fingerprint(root, project.source_content_fingerprint());
    let footer = WorkspaceFooter::new();
    Ok((project, footer))
}

pub(crate) fn open_project_index_filtered_paths(
    root: &std::path::Path,
    include_filters: &[String],
    exclude_filters: &[String],
) -> Result<(Project, WorkspaceFooter)> {
    let progress = workspace_open_progress();
    let project = bonsai_for_cli()
        .open_query_filtered_paths_with_progress(root, include_filters, exclude_filters, progress)?
        .with_auto_refresh(false);
    crate::page_cache::remember_workspace_fingerprint(root, project.source_content_fingerprint());
    let footer = WorkspaceFooter::new();
    Ok((project, footer))
}

pub(crate) fn open_project_index_retrieval_candidates(
    root: &std::path::Path,
    query: &str,
    filters: bonsai_sdk::SearchFilters<'_>,
) -> Result<Option<(Project, WorkspaceFooter)>> {
    let progress = workspace_open_progress();
    let Some(project) =
        bonsai_for_cli().open_query_retrieval_candidates_with_progress(root, query, filters, progress)?
    else {
        return Ok(None);
    };
    crate::page_cache::remember_workspace_fingerprint(root, project.source_content_fingerprint());
    Ok(Some((project, WorkspaceFooter::new())))
}

pub(crate) fn open_project_index_retrieval_candidate_union(
    root: &std::path::Path,
    queries: &[&str],
    filters: bonsai_sdk::SearchFilters<'_>,
) -> Result<Option<(Project, WorkspaceFooter)>> {
    let progress = workspace_open_progress();
    let Some(project) = bonsai_for_cli()
        .open_query_retrieval_candidate_union_with_progress(root, queries, filters, progress)?
    else {
        return Ok(None);
    };
    crate::page_cache::remember_workspace_fingerprint(root, project.source_content_fingerprint());
    Ok(Some((project, WorkspaceFooter::new())))
}

pub(crate) fn open_project_index_matching_path(
    root: &std::path::Path,
    path: &std::path::Path,
) -> Result<(Project, WorkspaceFooter)> {
    let progress = workspace_open_progress();
    let project = bonsai_for_cli()
        .open_query_matching_path_with_progress(root, path, progress)?
        .with_auto_refresh(false);
    crate::page_cache::remember_workspace_fingerprint(root, project.source_content_fingerprint());
    let footer = WorkspaceFooter::new();
    Ok((project, footer))
}

pub(crate) fn open_project_parse_only(root: &std::path::Path) -> Result<(Project, WorkspaceFooter)> {
    open_project_with_options(root, bonsai_sdk::OpenOptions::parse_only())
}

/// Open only the compact workspace snapshot needed to validate or build one
/// persisted semantic compiler phase. Internal semantic workers deliberately
/// avoid a footer because the parent `index --semantic` command owns output.
pub(crate) fn open_project_sidecar_validation_only(root: &std::path::Path) -> Result<Project> {
    build_project_with_bonsai_and_options(
        root,
        bonsai_for_cli(),
        bonsai_sdk::OpenOptions::sidecar_validation_only(),
    )
}

pub(crate) fn open_project_index_only_with_rulepack(
    root: &std::path::Path,
    rules_dir: Option<&std::path::Path>,
) -> Result<(Project, WorkspaceFooter)> {
    let bonsai = bonsai_with_rulepack(root, rules_dir)?;
    open_project_with_bonsai_and_options(root, bonsai, bonsai_sdk::OpenOptions::lazy_query())
}

fn open_project_with_options(
    root: &std::path::Path,
    options: bonsai_sdk::OpenOptions,
) -> Result<(Project, WorkspaceFooter)> {
    open_project_with_bonsai_and_options(root, bonsai_for_cli(), options)
}

fn open_project_with_bonsai_and_options(
    root: &std::path::Path,
    bonsai: bonsai_sdk::Bonsai,
    options: bonsai_sdk::OpenOptions,
) -> Result<(Project, WorkspaceFooter)> {
    let project = build_project_with_bonsai_and_options(root, bonsai, options)?;
    let footer = WorkspaceFooter::new();
    Ok((project, footer))
}

fn build_project_with_bonsai_and_options(
    root: &std::path::Path,
    bonsai: bonsai_sdk::Bonsai,
    options: bonsai_sdk::OpenOptions,
) -> Result<Project> {
    let open_started = std::time::Instant::now();
    let progress = workspace_open_progress();
    let project = bonsai
        .open_with_options_and_progress(root, options, progress)?
        .with_auto_refresh(false);
    bonsai_diagnostics::debug_log!(
        "workspace-open",
        "workspace construction: {:.3}s",
        open_started.elapsed().as_secs_f64()
    );
    let fingerprint_started = std::time::Instant::now();
    crate::page_cache::remember_workspace_fingerprint(root, project.source_content_fingerprint());
    bonsai_diagnostics::debug_log!(
        "workspace-open",
        "workspace fingerprint registration: {:.3}s",
        fingerprint_started.elapsed().as_secs_f64()
    );
    Ok(project)
}

fn bonsai_with_rulepack(
    workspace: &std::path::Path,
    rules_dir: Option<&std::path::Path>,
) -> Result<bonsai_sdk::Bonsai> {
    let bonsai = bonsai_for_cli();
    if let Some(dir) = rules_dir {
        return bonsai.with_rulepack(dir);
    }
    let Some(dir) = bonsai_sdk::Bonsai::discover_rulepack_root(workspace) else {
        return Ok(bonsai);
    };
    match bonsai.clone().with_rulepack(&dir) {
        Ok(with_pack) => Ok(with_pack),
        Err(_) => Ok(bonsai),
    }
}

pub(crate) fn bonsai_for_cli() -> bonsai_sdk::Bonsai {
    let bonsai = bonsai_sdk::Bonsai::new();
    match crate::PARSE_TIMEOUT_MS.get().copied().flatten() {
        Some(ms) => bonsai.with_parse_timeout(Duration::from_millis(ms)),
        None => bonsai,
    }
}

fn workspace_open_progress() -> impl Fn(WorkspaceOpenEvent) + Sync {
    let ingest: Arc<Mutex<Option<indicatif::ProgressBar>>> = Arc::new(Mutex::new(None));
    let parse: Arc<Mutex<Option<indicatif::ProgressBar>>> = Arc::new(Mutex::new(None));
    let dataflow: Arc<Mutex<Option<indicatif::ProgressBar>>> = Arc::new(Mutex::new(None));
    let value_flow: Arc<Mutex<Option<indicatif::ProgressBar>>> = Arc::new(Mutex::new(None));
    let flow_ids: Arc<Mutex<Option<indicatif::ProgressBar>>> = Arc::new(Mutex::new(None));
    let ingest_started = Arc::new(Mutex::new(None::<std::time::Instant>));

    move |event| match event {
        WorkspaceOpenEvent::IngestStarted => {
            *ingest_started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::time::Instant::now());
            replace_progress(&ingest, progress::spinner("ingesting workspace"));
        }
        WorkspaceOpenEvent::IngestFinished { files } => {
            finish_progress(&ingest);
            if let Some(started) = ingest_started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                bonsai_diagnostics::debug_log!(
                    "workspace-open",
                    "workspace ingest: {:.3}s · files {}",
                    started.elapsed().as_secs_f64(),
                    files
                );
            }
        }
        WorkspaceOpenEvent::ParseStarted { files } => {
            finish_progress(&ingest);
            replace_progress(&parse, progress::progress_bar("parsing", files as u64));
        }
        WorkspaceOpenEvent::ParseFileIndexed => {
            if let Some(bar) = lock_progress_slot(&parse).as_ref() {
                bar.inc(1);
            }
        }
        WorkspaceOpenEvent::ParseFinished => {
            finish_progress(&parse);
        }
        WorkspaceOpenEvent::DataflowPrewarmStarted { pending } => {
            finish_progress(&parse);
            if pending > 0 {
                replace_progress(
                    &dataflow,
                    progress::progress_bar("building dataflow graph", pending as u64),
                );
            }
        }
        WorkspaceOpenEvent::DataflowEntryBuilt => {
            if let Some(bar) = lock_progress_slot(&dataflow).as_ref() {
                bar.inc(1);
            }
        }
        WorkspaceOpenEvent::DataflowPrewarmFinished => {
            finish_progress(&dataflow);
        }
        WorkspaceOpenEvent::ValueFlowPrewarmStarted => {
            finish_progress(&dataflow);
            replace_progress(&value_flow, progress::spinner("building value-flow graph"));
        }
        WorkspaceOpenEvent::ValueFlowPrewarmFinished => {
            finish_progress(&value_flow);
        }
        WorkspaceOpenEvent::FlowIdsPrewarmStarted => {
            finish_progress(&value_flow);
            replace_progress(&flow_ids, progress::spinner("building flow ids"));
        }
        WorkspaceOpenEvent::FlowIdsPrewarmFinished => {
            finish_progress(&flow_ids);
        }
        WorkspaceOpenEvent::CacheChecked {
            cache,
            status,
            entries,
        } => {
            if progress::debug_category_enabled("workspace-cache") {
                eprintln!(
                    "  [workspace-cache] {}",
                    render_workspace_cache_note(cache, status, entries)
                );
            }
        }
    }
}

fn replace_progress(slot: &Mutex<Option<indicatif::ProgressBar>>, bar: indicatif::ProgressBar) {
    let mut guard = lock_progress_slot(slot);
    if let Some(previous) = guard.take() {
        previous.finish_and_clear();
    }
    *guard = Some(bar);
}

fn finish_progress(slot: &Mutex<Option<indicatif::ProgressBar>>) {
    if let Some(bar) = lock_progress_slot(slot).take() {
        bar.finish_and_clear();
    }
}

fn lock_progress_slot(
    slot: &Mutex<Option<indicatif::ProgressBar>>,
) -> MutexGuard<'_, Option<indicatif::ProgressBar>> {
    slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn workspace_cache_status_label(status: WorkspaceCacheStatus) -> &'static str {
    match status {
        WorkspaceCacheStatus::Hit => "hit",
        WorkspaceCacheStatus::Miss => "miss",
        WorkspaceCacheStatus::Skipped => "skipped",
        WorkspaceCacheStatus::Error => "error",
    }
}

fn render_workspace_cache_note(cache: &str, status: WorkspaceCacheStatus, entries: usize) -> String {
    format!(
        "{cache}: {} · {}",
        workspace_cache_status_label(status),
        counted_usize(entries, "entry", "entries")
    )
}

fn counted_usize(value: usize, singular: &str, plural: &str) -> String {
    format!("{value} {}", if value == 1 { singular } else { plural })
}

/// Render a span as `(path, line, column)`. Used by every browse /
/// inspect / dump renderer that needs a printable location.
pub(crate) fn format_span(span: &bonsai_common::Span, ws: &Workspace) -> (String, u32, u32) {
    bonsai_sdk::format_span(span, ws)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Mutex as StdMutex;

    static PANIC_HOOK_LOCK: StdMutex<()> = StdMutex::new(());

    fn poison_slot(slot: &Mutex<Option<indicatif::ProgressBar>>) {
        let _hook_guard = PANIC_HOOK_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let old_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = slot.lock().expect("initial progress lock");
            panic!("poison progress lock");
        }));
        std::panic::set_hook(old_hook);
        assert!(result.is_err(), "slot poisoning helper must panic while locked");
    }

    #[test]
    fn finish_progress_recovers_poisoned_slot() {
        let slot = Mutex::new(Some(indicatif::ProgressBar::hidden()));
        poison_slot(&slot);

        finish_progress(&slot);

        assert!(lock_progress_slot(&slot).is_none());
    }

    #[test]
    fn replace_progress_recovers_poisoned_slot() {
        let slot = Mutex::new(Some(indicatif::ProgressBar::hidden()));
        poison_slot(&slot);

        replace_progress(&slot, indicatif::ProgressBar::hidden());

        assert!(lock_progress_slot(&slot).is_some());
    }
}
