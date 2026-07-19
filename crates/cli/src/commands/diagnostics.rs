//! `bonsai-ninja index` / `diagnostics` / `dump-hir` / `dump-cfg` —
//! low-ceremony inspection commands that open the workspace, run one
//! analysis pass, and print the result as JSON. They don't have
//! per-row rendering or text-mode decoration, so they all fit in a
//! single small module together.

use anyhow::Result;
use serde_json::json;
use std::io::Write as _;
use std::time::Duration;

use crate::cli_println;
use crate::progress;

use super::{
    not_found_with_suggestions, open_project_dataflow_prewarm, open_project_index_only,
    open_project_parse_only, open_project_semantic_prewarm, open_project_streaming_parse_only,
    open_workspace_syntax_only,
};

#[derive(Copy, Clone, Debug)]
pub(crate) struct IndexCommandOptions {
    pub(crate) watch: bool,
    pub(crate) interval_ms: u64,
    pub(crate) prewarm_dataflow: bool,
    pub(crate) semantic: bool,
    pub(crate) structural_only: bool,
}

pub(crate) fn cmd_index(root: &std::path::Path, options: IndexCommandOptions) -> Result<()> {
    let _ = options.structural_only;
    let (project, _footer) = if options.prewarm_dataflow {
        open_project_dataflow_prewarm(root)?
    } else if options.semantic {
        open_project_semantic_prewarm(root)?
    } else if options.watch {
        open_project_parse_only(root)?
    } else {
        open_project_streaming_parse_only(root)?
    };
    let stage = progress::ScopedSpinner::new("collecting index stats");
    if options.prewarm_dataflow || options.semantic {
        let _manifest = project.cache().write_manifest()?;
    }
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
