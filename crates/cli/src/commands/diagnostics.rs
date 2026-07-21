//! `bonsai-ninja index` / `diagnostics` / `dump-hir` / `dump-cfg` —
//! low-ceremony inspection commands that open the workspace, run one
//! analysis pass, and print the result as JSON. They don't have
//! per-row rendering or text-mode decoration, so they all fit in a
//! single small module together.

use anyhow::Result;
use serde_json::json;
use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

use crate::args::SemanticWorkerPhase;
use crate::cli_println;
use crate::progress;

use super::{
    not_found_with_suggestions, open_project_dataflow_prewarm, open_project_index_only,
    open_project_parse_only, open_project_sidecar_validation_only, open_project_streaming_parse_only,
    open_workspace_syntax_only,
};

#[derive(Copy, Clone, Debug)]
pub(crate) struct IndexCommandOptions {
    pub(crate) watch: bool,
    pub(crate) interval_ms: u64,
    pub(crate) prewarm_dataflow: bool,
    pub(crate) semantic: bool,
    pub(crate) semantic_worker: Option<SemanticWorkerPhase>,
    pub(crate) structural_only: bool,
}

pub(crate) fn cmd_index(root: &std::path::Path, options: IndexCommandOptions) -> Result<()> {
    let _ = options.structural_only;
    if options.semantic {
        if let Some(phase) = options.semantic_worker {
            return run_semantic_worker(root, phase);
        }
        run_semantic_workers(root)?;
        return Ok(());
    }
    let (project, _footer) = if options.prewarm_dataflow {
        open_project_dataflow_prewarm(root)?
    } else if options.watch {
        open_project_parse_only(root)?
    } else {
        open_project_streaming_parse_only(root)?
    };
    let stage = progress::ScopedSpinner::new("collecting index stats");
    let stats = project.stats();
    stage.finish();
    cli_println!("{}", serde_json::to_string_pretty(&stats)?);
    flush_stdout()?;
    if !options.watch {
        return Ok(());
    }
    cli_println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "event": "watching",
            "workspace": root.display().to_string(),
            "interval_ms": options.interval_ms,
        }))?
    );
    flush_stdout()?;
    let interval = Duration::from_millis(options.interval_ms.max(100));
    loop {
        std::thread::sleep(interval);
        let report = project.refresh_from_disk()?;
        if report.changed() {
            cli_println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "event": "reindexed",
                    "added": report.added,
                    "modified": report.modified,
                    "removed": report.removed,
                    "dataflow_entries_built": report.dataflow_entries_built,
                    "stats": project.stats(),
                }))?
            );
            flush_stdout()?;
        }
    }
}

/// Execute exact semantic compiler phases in separate processes. Dropping a
/// Rust value releases its allocations logically, but Tree-sitter's C
/// allocator and the process allocator may retain those pages indefinitely.
/// A worker exit is the portable hard reclamation boundary: every phase still
/// sees the complete AST-derived compiler input and emits the same sidecars,
/// while their peak resident sets cannot become additive.
fn run_semantic_workers(root: &std::path::Path) -> Result<()> {
    let executable = std::env::current_exe()?;
    for phase in [SemanticWorkerPhase::Frontend, SemanticWorkerPhase::Idg] {
        let phase_name = match phase {
            SemanticWorkerPhase::Frontend => "frontend",
            SemanticWorkerPhase::Idg => "idg",
        };
        let mut command = Command::new(&executable);
        command
            .arg("index")
            .arg("--semantic")
            .arg("--semantic-worker")
            .arg(phase_name)
            .arg(root);
        if let Some(timeout_ms) = crate::PARSE_TIMEOUT_MS.get().copied().flatten() {
            command.arg("--parse-timeout").arg(timeout_ms.to_string());
        }
        let status = command.status()?;
        if !status.success() {
            anyhow::bail!("semantic {phase_name} worker exited with {status}");
        }
    }
    Ok(())
}

fn run_semantic_worker(root: &std::path::Path, phase: SemanticWorkerPhase) -> Result<()> {
    let project = open_project_sidecar_validation_only(root)?;
    match phase {
        SemanticWorkerPhase::Frontend => project.cache().warm_retrieval_and_callgraph_sidecars(),
        SemanticWorkerPhase::Idg => {
            project.cache().warm_idg_sidecar_and_manifest()?;
            let stage = progress::ScopedSpinner::new("collecting index stats");
            let stats = project.stats();
            stage.finish();
            cli_println!("{}", serde_json::to_string_pretty(&stats)?);
            flush_stdout()
        }
    }
}

pub(crate) fn cmd_context(root: &std::path::Path) -> Result<()> {
    // Workspace context is a filesystem/path fact. It does not inspect
    // declarations, so parsing every Tree-sitter input here would be an
    // accidental whole-program compiler pass for a metadata-only command.
    let (workspace, _footer) = open_workspace_syntax_only(root)?;
    let stage = progress::ScopedSpinner::new("collecting workspace context");
    let context = workspace.semantic_context();
    stage.finish();
    cli_println!("{}", serde_json::to_string_pretty(&context)?);
    flush_stdout()?;
    Ok(())
}

fn flush_stdout() -> Result<()> {
    std::io::stdout().flush()?;
    Ok(())
}

pub(crate) fn cmd_diagnostics(root: &std::path::Path) -> Result<()> {
    let (project, _footer) = open_project_index_only(root)?;
    let ws = project.workspace();
    let files = ws.vfs().all_files();
    let bar = progress::progress_bar("collecting diagnostics", files.len() as u64);
    let parse_result = (|| -> Result<()> {
        for f in files {
            let _ = ws.db().parse(f)?;
            bar.inc(1);
        }
        Ok(())
    })();
    bar.finish_and_clear();
    parse_result?;
    cli_println!("{}", serde_json::to_string_pretty(&project.diagnostics_report())?);
    Ok(())
}

pub(crate) fn cmd_dump_hir(root: &std::path::Path, symbol: &str) -> Result<()> {
    let (project, _footer) = open_project_index_only(root)?;
    let ws = project.workspace();
    let stage = progress::ScopedSpinner::new("building HIR dump");
    let dump = project
        .dump()
        .hir(symbol)
        .map_err(|err| anyhow::anyhow!("dump-hir: {err}"))?
        .ok_or_else(|| not_found_with_suggestions(ws, symbol))?;
    stage.finish();
    cli_println!("{}", serde_json::to_string_pretty(&dump)?);
    Ok(())
}

pub(crate) fn cmd_dump_cfg(root: &std::path::Path, symbol: &str) -> Result<()> {
    let (project, _footer) = open_project_index_only(root)?;
    let ws = project.workspace();
    let stage = progress::ScopedSpinner::new("building CFG dump");
    let cfg = project
        .dump()
        .cfg(symbol)
        .map_err(|err| anyhow::anyhow!("dump-cfg: {err}"))?
        .ok_or_else(|| not_found_with_suggestions(ws, symbol))?;
    stage.finish();
    cli_println!("{}", serde_json::to_string_pretty(&cfg)?);
    Ok(())
}
