//! Per-subcommand handlers and renderers.
//!
//! Sub-modules: [`browse`] (10 browse commands), [`dump`] (structural
//! dumps), [`trace`], [`inspect`], [`export`]. Shared helpers
//! (project open, symbol resolution, paging plumbing) live here.

use anyhow::Result;
use bonsai_sdk::Workspace;
use bonsai_sdk::{Project, WorkspaceOpenEvent};
use std::{
    sync::{Arc, Mutex},
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
pub(crate) mod trace;
pub(crate) mod tree;

pub(crate) use bonsai_sdk::{
    ArgsFilters, CallsFilters, ClassesFilters, CommentsFilters, DefsFilters, ImportsFilters, RefsFilters,
    SearchFilters, StringsFilters, VarsFilters,
};
pub(crate) use browse::{
    apply_text_limit, cmd_args, cmd_calls, cmd_classes, cmd_comments, cmd_defs, cmd_imports, cmd_refs,
    cmd_search, cmd_strings, cmd_vars, collect_callees, emit_json_paged_cached, page_info_to_json,
    paging_from_cli, paging_from_cli_output, short_file, truncate,
};
pub(crate) use cache::cmd_cache;
pub(crate) use diagnostics::{cmd_diagnostics, cmd_dump_cfg, cmd_dump_hir, cmd_index};
pub(crate) use dump::{cmd_dump_ast, cmd_dump_callgraph, cmd_dump_edges, cmd_dump_resolve, cmd_dump_taint};
pub(crate) use export::cmd_export;
pub(crate) use inspect::{
    cmd_inspect, render_flow_block_with_heading, render_flow_with_filters, BodySet, InspectFilters,
    InspectFlowRendered, InspectRenderOptions,
};
pub(crate) use trace::{cmd_trace, nearest_names, not_found_with_suggestions};

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
pub(crate) fn open_project_full(root: &std::path::Path) -> Result<(Project, WorkspaceFooter)> {
    open_project_with_options(root, bonsai_sdk::OpenOptions::default())
}

pub(crate) fn open_project_index_only(root: &std::path::Path) -> Result<(Project, WorkspaceFooter)> {
    open_project_with_options(root, bonsai_sdk::OpenOptions::query_only())
}

pub(crate) fn open_project_index_only_with_rulepack(
    root: &std::path::Path,
    rules_dir: Option<&std::path::Path>,
) -> Result<(Project, WorkspaceFooter)> {
    let bonsai = bonsai_with_rulepack(root, rules_dir)?;
    open_project_with_bonsai_and_options(root, bonsai, bonsai_sdk::OpenOptions::query_only())
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
    let progress = workspace_open_progress();
    let project = bonsai.open_with_options_and_progress(root, options, progress)?;
    let footer = WorkspaceFooter::new();
    Ok((project, footer))
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

fn bonsai_for_cli() -> bonsai_sdk::Bonsai {
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

    move |event| match event {
        WorkspaceOpenEvent::IngestStarted => {
            *ingest.lock().expect("ingest progress lock") = Some(progress::spinner("ingesting workspace"));
        }
        WorkspaceOpenEvent::IngestFinished { .. } => {
            if let Some(bar) = ingest.lock().expect("ingest progress lock").take() {
                bar.finish_and_clear();
            }
        }
        WorkspaceOpenEvent::ParseStarted { files } => {
            *parse.lock().expect("parse progress lock") =
                Some(progress::progress_bar("parsing", files as u64));
        }
        WorkspaceOpenEvent::ParseFileIndexed => {
            if let Some(bar) = parse.lock().expect("parse progress lock").as_ref() {
                bar.inc(1);
            }
        }
        WorkspaceOpenEvent::ParseFinished => {
            if let Some(bar) = parse.lock().expect("parse progress lock").take() {
                bar.finish_and_clear();
            }
        }
        WorkspaceOpenEvent::DataflowPrewarmStarted { pending } => {
            if pending > 0 {
                *dataflow.lock().expect("dataflow progress lock") =
                    Some(progress::progress_bar("building dataflow graph", pending as u64));
            }
        }
        WorkspaceOpenEvent::DataflowEntryBuilt => {
            if let Some(bar) = dataflow.lock().expect("dataflow progress lock").as_ref() {
                bar.inc(1);
            }
        }
        WorkspaceOpenEvent::DataflowPrewarmFinished => {
            if let Some(bar) = dataflow.lock().expect("dataflow progress lock").take() {
                bar.finish_and_clear();
            }
        }
        WorkspaceOpenEvent::ValueFlowPrewarmStarted => {
            *value_flow.lock().expect("value-flow progress lock") =
                Some(progress::spinner("building value-flow graph"));
        }
        WorkspaceOpenEvent::ValueFlowPrewarmFinished => {
            if let Some(bar) = value_flow.lock().expect("value-flow progress lock").take() {
                bar.finish_and_clear();
            }
        }
        WorkspaceOpenEvent::FlowIdsPrewarmStarted => {
            *flow_ids.lock().expect("flow-ids progress lock") = Some(progress::spinner("building flow ids"));
        }
        WorkspaceOpenEvent::FlowIdsPrewarmFinished => {
            if let Some(bar) = flow_ids.lock().expect("flow-ids progress lock").take() {
                bar.finish_and_clear();
            }
        }
    }
}

/// Render a span as `(path, line, column)`. Used by every browse /
/// inspect / dump renderer that needs a printable location.
pub(crate) fn format_span(span: &bonsai_common::Span, ws: &Workspace) -> (String, u32, u32) {
    let path = ws
        .vfs()
        .path(span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    let snapshot = ws.vfs().snapshot(span.file).ok();
    let (line, col) = if let Some(s) = snapshot {
        let map = bonsai_common::cached_span_map(span.file, s.version, s.text.as_ref());
        let lc = map.line_col(span.start);
        (lc.line, lc.column)
    } else {
        (0, 0)
    };
    (path, line, col)
}
