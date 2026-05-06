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

use super::{not_found_with_suggestions, open_project_full, open_project_index_only};

pub(crate) fn cmd_index(root: &std::path::Path, watch: bool, interval_ms: u64) -> Result<()> {
    let (project, _footer) = open_project_full(root)?;
    let stats = project.stats();
    cli_println!("{}", serde_json::to_string_pretty(&stats)?);
    flush_stdout()?;
    if !watch {
        return Ok(());
    }
    cli_println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "event": "watching",
            "workspace": root.display().to_string(),
            "interval_ms": interval_ms,
        }))?
    );
    flush_stdout()?;
    let interval = Duration::from_millis(interval_ms.max(100));
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

fn flush_stdout() -> Result<()> {
    std::io::stdout().flush()?;
    Ok(())
}

pub(crate) fn cmd_diagnostics(root: &std::path::Path) -> Result<()> {
    let (project, _footer) = open_project_index_only(root)?;
    let ws = project.workspace();
    let files = ws.vfs().all_files();
    let bar = progress::progress_bar("collecting diagnostics", files.len() as u64);
    for f in files {
        let _ = ws.db().parse(f)?;
        bar.inc(1);
    }
    bar.finish_and_clear();
    cli_println!("{}", serde_json::to_string_pretty(&project.diagnostics())?);
    Ok(())
}

pub(crate) fn cmd_dump_hir(root: &std::path::Path, symbol: &str) -> Result<()> {
    let (project, _footer) = open_project_index_only(root)?;
    let ws = project.workspace();
    let dump = project
        .dump()
        .hir(symbol)
        .ok_or_else(|| not_found_with_suggestions(ws, symbol))?;
    cli_println!("{}", serde_json::to_string_pretty(&dump)?);
    Ok(())
}

pub(crate) fn cmd_dump_cfg(root: &std::path::Path, symbol: &str) -> Result<()> {
    let (project, _footer) = open_project_index_only(root)?;
    let ws = project.workspace();
    let cfg = project
        .dump()
        .cfg(symbol)
        .ok_or_else(|| not_found_with_suggestions(ws, symbol))?;
    cli_println!("{}", serde_json::to_string_pretty(&cfg)?);
    Ok(())
}
