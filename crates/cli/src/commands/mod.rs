//! Per-subcommand handlers and renderers.
//!
//! Sub-modules: [`browse`] (browse commands), [`dump`] (structural
//! dumps), `trace` output, [`inspect`], [`export`]. Shared helpers
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
pub(crate) mod read_file;
pub(crate) mod security;
pub(crate) mod show;
pub(crate) mod tree;

pub(crate) use bonsai_sdk::{
    ArgsFilters, CallsFilters, ClassesFilters, CommentsFilters, DefsFilters, EntryPointsFilters,
    ImportsFilters, OperationsFilters, RefsFilters, SearchFilters, StringsFilters, VarsFilters,
};
pub(crate) use browse::{
    apply_text_limit, cmd_args, cmd_calls, cmd_classes, cmd_comments, cmd_defs, cmd_entrypoints, cmd_imports,
    cmd_operations, cmd_refs, cmd_search, cmd_strings, cmd_vars, emit_json_paged_cached,
    emit_json_value_paged_cached, emit_json_value_paged_cached_prefiltered, one_line_preview,
    page_info_to_json, paged_json_incomplete_reasons, paging_from_cli, paging_with_row_limit, short_file,
    truncate,
};
pub(crate) use cache::cmd_cache;
pub(crate) use diagnostics::{cmd_diagnostics, cmd_dump_cfg, cmd_dump_hir, cmd_index, IndexCommandOptions};
pub(crate) use dump::{
    cmd_dump_ast, cmd_dump_callgraph, cmd_dump_edges, cmd_dump_resolution, cmd_dump_resolve, cmd_dump_taint,
};
pub(crate) use export::cmd_export;
pub(crate) use inspect::{
    cmd_inspect, render_flow_block_with_heading, render_flow_with_cached_call_spans, BodySet,
    InspectCommandOptions, InspectFilters, InspectFlowRendered, InspectRenderOptions,
};

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

/// Resolve a selector for commands that accept either a positional argument
/// or a named flag (`--symbol`, `--query`, `--name`, or `--id`). Clap groups
/// guarantee exactly one form before dispatch; this remains a defensive check
/// for direct/internal callers.
///
/// `flag_name` is the name of the named flag for the calling
/// command (`symbol` for most dumps / refs / trace; `query` for
/// search / inspect) so the error message points the user at the
/// right flag rather than a generic "try --symbol or --query".
pub(crate) fn resolve_selector_arg(
    positional: Option<String>,
    flag: Option<String>,
    flag_name: &str,
) -> Result<String> {
    positional
        .or(flag)
        .ok_or_else(|| anyhow::anyhow!("expected a positional value or --{flag_name}"))
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
    let options = options_for_cache_policy(options, *crate::NO_CACHE.get().unwrap_or(&false));
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
    let (lazy_installed, lazy_loaded) = project.workspace().vfs().lazy_source_counts();
    bonsai_diagnostics::debug_log!(
        "workspace-open",
        "lazy sources: interned by identity {} · loaded so far {}",
        lazy_installed,
        lazy_loaded
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

fn options_for_cache_policy(mut options: bonsai_sdk::OpenOptions, no_cache: bool) -> bonsai_sdk::OpenOptions {
    if no_cache {
        options.disable_persistent_semantic_cache();
    }
    options
}

#[cfg(test)]
mod cache_policy_tests {
    use super::options_for_cache_policy;

    #[test]
    fn no_cache_bypasses_every_reusable_semantic_sidecar() {
        let cached = bonsai_sdk::OpenOptions::full_prewarm();
        assert_eq!(options_for_cache_policy(cached, false), cached);

        let uncached = options_for_cache_policy(cached, true);
        assert!(!uncached.persistent_semantic_cache);
        assert!(!uncached.load_compiler_object_sidecar);
        assert!(!uncached.save_compiler_object_sidecar);
        assert!(!uncached.load_callgraph_sidecar);
        assert!(!uncached.load_dataflow_sidecar);
        assert!(!uncached.save_dataflow_sidecar);
        assert!(!uncached.load_value_flow_sidecar);
        assert!(!uncached.save_value_flow_sidecar);
        assert!(!uncached.load_idg_sidecar);
        assert!(
            uncached.prewarm_dataflow,
            "cache policy must change reuse only, never requested semantic work"
        );
        assert!(!uncached.prewarm_flow_ids);
    }
}

fn bonsai_with_rulepack(
    workspace: &std::path::Path,
    rules_dir: Option<&std::path::Path>,
) -> Result<bonsai_sdk::Bonsai> {
    let bonsai = bonsai_for_cli();
    if let Some(dir) = rules_dir {
        return bonsai.with_rulepack(dir);
    }
    let dir = bonsai_sdk::Bonsai::default_rulepack_root(workspace)?;
    bonsai.with_rulepack(&dir)
}

pub(crate) fn bonsai_for_cli() -> bonsai_sdk::Bonsai {
    let bonsai = bonsai_sdk::Bonsai::new()
        .with_minified_sources(crate::include_minified_sources())
        .with_persistent_semantic_cache(!*crate::NO_CACHE.get().unwrap_or(&false));
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
        WorkspaceOpenEvent::IngestFilesStarted { files } => {
            replace_progress(
                &ingest,
                progress::progress_bar("reading source files", files as u64),
            );
        }
        WorkspaceOpenEvent::IngestFileRead => {
            if let Some(bar) = lock_progress_slot(&ingest).as_ref() {
                bar.inc(1);
            }
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

/// One atomic command result with the shared completeness contract.
///
/// The native object keeps its own fields; `analysis_complete` /
/// `analysis_incomplete_reasons` are preserved when the compiler reported
/// them and default to complete otherwise, and `result_complete` is true
/// because atomic documents are never paged. Row commands build the same
/// keys through their paging envelope instead.
pub(crate) fn with_completeness(value: &serde_json::Value) -> serde_json::Value {
    let mut fields = match value {
        serde_json::Value::Object(fields) => fields.clone(),
        other => {
            let mut fields = serde_json::Map::new();
            fields.insert("value".to_string(), other.clone());
            fields
        }
    };
    fields
        .entry("analysis_complete".to_string())
        .or_insert(serde_json::Value::Bool(true));
    fields
        .entry("analysis_incomplete_reasons".to_string())
        .or_insert_with(|| serde_json::json!([]));
    fields.insert("result_complete".to_string(), serde_json::Value::Bool(true));
    fields.insert("result_incomplete_reasons".to_string(), serde_json::json!([]));
    serde_json::Value::Object(fields)
}

/// The same completeness contract when the secondary output filter did not
/// select an atomic result: analysis facts are reported, the selected value
/// is null, and `matched` says why.
pub(crate) fn filtered_out_document(value: &serde_json::Value) -> serde_json::Value {
    let analysis_complete = value
        .get("analysis_complete")
        .cloned()
        .unwrap_or(serde_json::Value::Bool(true));
    let analysis_incomplete_reasons = value
        .get("analysis_incomplete_reasons")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    serde_json::json!({
        "analysis_complete": analysis_complete,
        "analysis_incomplete_reasons": analysis_incomplete_reasons,
        "result_complete": true,
        "result_incomplete_reasons": [],
        "matched": false,
        "value": null,
    })
}

/// Parser-coverage reasons for the compiler objects this command touched.
///
/// Every compiler object publishes its exact parser diagnostics into the
/// in-process sink when it is lowered or loaded from the sidecar, so this
/// is a free lookup — no file is parsed merely to answer it — and it reports
/// the same `syntax-error-files:N` / `parse-failed-files:N` /
/// `parse-timeout-files:N` reasons as the exhaustive workspace audit, scoped
/// to the files the inventory actually examined. A lightweight inventory
/// must never claim a complete analysis over a file it could not parse.
pub(crate) fn touched_parser_incomplete_reasons(ws: &Workspace) -> Vec<String> {
    let mut syntax_error_files = ahash::AHashSet::default();
    let mut parse_failed_files = ahash::AHashSet::default();
    let mut parse_timeout_files = ahash::AHashSet::default();
    for diagnostic in ws.db().diagnostics() {
        match diagnostic.code.as_deref() {
            Some("syntax-error") => {
                syntax_error_files.insert(diagnostic.span.file);
            }
            Some("parse-failed") => {
                parse_failed_files.insert(diagnostic.span.file);
            }
            Some("parse-timeout") => {
                parse_timeout_files.insert(diagnostic.span.file);
            }
            _ => {}
        }
    }
    let mut reasons = Vec::new();
    if !parse_failed_files.is_empty() {
        reasons.push(format!("parse-failed-files:{}", parse_failed_files.len()));
    }
    if !parse_timeout_files.is_empty() {
        reasons.push(format!("parse-timeout-files:{}", parse_timeout_files.len()));
    }
    if !syntax_error_files.is_empty() {
        reasons.push(format!("syntax-error-files:{}", syntax_error_files.len()));
    }
    reasons
}

/// Text counterpart of the JSON `analysis_incomplete_reasons` field for
/// row commands: printed under the table so a human sees the same fact.
pub(crate) fn render_analysis_incomplete_notice(reasons: &[String]) {
    if reasons.is_empty() {
        return;
    }
    let u = crate::ui();
    for line in u.wrapped_warn_labeled_lines("analysis incomplete", &reasons.join("; ")) {
        crate::cli_println!("{line}");
    }
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

// ---- shared "did you mean" suggestions for symbol-taking commands ----

pub(crate) fn not_found_with_suggestions(ws: &Workspace, symbol: &str) -> anyhow::Error {
    let needle = symbol.to_lowercase();
    let global = ws.compiler_header_index();
    // Collect all candidate names with a similarity score. Higher score =
    // more relevant. Combines: substring containment (either direction),
    // shared-prefix length, and normalized Levenshtein.
    let mut scored: Vec<(i32, String)> = Vec::new();
    for f in global.all_files() {
        for d in global.decls_in(f) {
            let n = &d.name;
            let nl = n.to_lowercase();
            let prefix = common_prefix_len(&nl, &needle);
            let contains_ab = nl.contains(&needle);
            let contains_ba = needle.contains(&nl) && nl.len() >= 3;
            let max_len = nl.len().max(needle.len()) as i32;
            let dist = levenshtein(&nl, &needle) as i32;
            let ratio = if max_len == 0 {
                0
            } else {
                (max_len - dist) * 100 / max_len
            };
            let mut score = 0;
            if contains_ab {
                score += 80;
            }
            if contains_ba {
                score += 60;
            }
            score += (prefix as i32) * 10;
            score += ratio;
            if score >= 30 {
                scored.push((score, n.clone()));
            }
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.len().cmp(&b.1.len())));
    scored.dedup_by(|a, b| a.1 == b.1);
    if scored.is_empty() {
        anyhow::anyhow!("symbol not found: {symbol}")
    } else {
        anyhow::anyhow!(
            "symbol not found: {symbol}\n  did you mean: {}",
            scored
                .iter()
                .take(8)
                .map(|(_, n)| n.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Number of leading characters two strings share. Powers the
/// "did you mean" prefix-bias heuristic.
fn common_prefix_len(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

/// Return up to `limit` workspace decl names that look similar to
/// `symbol`, sorted by relevance. Shares the scoring heuristic with
/// [`not_found_with_suggestions`] but returns the names instead of
/// formatting them into an error.
pub(crate) fn nearest_names(ws: &Workspace, symbol: &str, limit: usize) -> Vec<String> {
    let needle = symbol.to_lowercase();
    let global = ws.compiler_header_index();
    let mut scored: Vec<(i32, String)> = Vec::new();
    for f in global.all_files() {
        for d in global.decls_in(f) {
            let nl = d.name.to_lowercase();
            let prefix = common_prefix_len(&nl, &needle);
            let max_len = nl.len().max(needle.len()) as i32;
            let dist = levenshtein(&nl, &needle) as i32;
            let ratio = if max_len == 0 {
                0
            } else {
                (max_len - dist) * 100 / max_len
            };
            let mut score = 0;
            if nl.contains(&needle) {
                score += 80;
            }
            if needle.contains(&nl) && nl.len() >= 3 {
                score += 60;
            }
            score += (prefix as i32) * 10;
            score += ratio;
            if score >= 30 {
                scored.push((score, d.name.clone()));
            }
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.len().cmp(&b.1.len())));
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(limit).map(|(_, n)| n).collect()
}

/// Classic two-row Levenshtein edit distance over byte slices. Used
/// only for ranking suggestion candidates, so byte-level is fine.
fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0; b.len() + 1];
    for left_index in 1..=a.len() {
        curr[0] = left_index;
        for right_index in 1..=b.len() {
            let cost = usize::from(a[left_index - 1] != b[right_index - 1]);
            curr[right_index] = (prev[right_index] + 1)
                .min(curr[right_index - 1] + 1)
                .min(prev[right_index - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}
