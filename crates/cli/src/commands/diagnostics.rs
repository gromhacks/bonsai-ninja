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
    bonsai_for_cli, not_found_with_suggestions, open_project_dataflow_prewarm, open_project_index_only,
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
pub(super) fn run_semantic_workers(root: &std::path::Path) -> Result<()> {
    let executable = std::env::current_exe()?;
    loop {
        // Cache validation hashes the complete source snapshot and may inspect
        // large factstore metadata. A fresh process is a hard reclamation
        // boundary, so planner allocator pages cannot stack with compiler or
        // graph workers.
        let stats = semantic_cache_stats(&executable, root)?;
        if semantic_generation_is_current(&stats.validation) {
            return Ok(());
        }
        for phase in semantic_phase_plan(&stats.validation) {
            let phase_name = match phase {
                SemanticWorkerPhase::Compiler => "compiler",
                SemanticWorkerPhase::Retrieval => "retrieval",
                SemanticWorkerPhase::Callgraph => "callgraph",
                SemanticWorkerPhase::Linkage => "linkage",
                SemanticWorkerPhase::Idg => "idg",
                SemanticWorkerPhase::Manifest => "manifest",
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
        // Each worker publishes atomically. This final validation proves every
        // artifact describes the same current snapshot. An edit between
        // workers reruns the exact compiler pipeline until it reaches a
        // quiescent generation; there is no semantic retry cap.
        let validation = semantic_cache_stats(&executable, root)?.validation;
        if semantic_generation_is_current(&validation) {
            return Ok(());
        }
        let retry = progress::ScopedSpinner::new(
            "workspace changed between semantic workers; rebuilding one coherent generation",
        );
        retry.finish();
    }
}

fn semantic_generation_is_current(validation: &bonsai_sdk::CacheValidationReport) -> bool {
    validation.semantic_ready && validation.manifest_status == bonsai_sdk::CacheFreshnessStatus::Fresh
}

fn semantic_cache_stats(
    executable: &std::path::Path,
    root: &std::path::Path,
) -> Result<bonsai_sdk::CacheStats> {
    let output = Command::new(executable)
        .arg("cache")
        .arg("stats")
        .arg(root)
        .arg("--format")
        .arg("json")
        .arg("--no-color")
        .arg("--no-progress")
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "semantic cache validation exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        anyhow::anyhow!(
            "semantic cache validation returned invalid JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

/// Compute the minimum exact phase closure needed for one coherent semantic
/// generation. Independently versioned sidecars are the authority; the
/// descriptive manifest never forces an otherwise current compiler phase to
/// rerun.
fn semantic_phase_plan(validation: &bonsai_sdk::CacheValidationReport) -> Vec<SemanticWorkerPhase> {
    let sidecar_is_fresh = |name: &str| {
        validation
            .sidecars
            .iter()
            .find(|sidecar| sidecar.name == name)
            .is_some_and(|sidecar| {
                matches!(
                    sidecar.status,
                    bonsai_sdk::CacheFreshnessStatus::Fresh | bonsai_sdk::CacheFreshnessStatus::NotApplicable
                )
            })
    };
    let compiler_stale = !sidecar_is_fresh("compiler_objects");
    // Compiler-object storage is an independently versioned serialization of
    // adapter facts. Its storage ABI may change without changing callgraph,
    // linkage, retrieval, or IDG semantics; those artifacts carry their own
    // semantic ABIs and exact source fingerprints.
    let callgraph_stale = !sidecar_is_fresh("callgraph");
    let retrieval_stale = callgraph_stale || !sidecar_is_fresh("retrieval");
    let linkage_stale = !sidecar_is_fresh("linkage");
    let idg_stale = callgraph_stale || linkage_stale || !sidecar_is_fresh("idg");

    let mut phases = [
        (SemanticWorkerPhase::Compiler, compiler_stale),
        (SemanticWorkerPhase::Callgraph, callgraph_stale),
        (SemanticWorkerPhase::Retrieval, retrieval_stale),
        (SemanticWorkerPhase::Linkage, linkage_stale),
        (SemanticWorkerPhase::Idg, idg_stale),
    ]
    .into_iter()
    .filter_map(|(phase, stale)| stale.then_some(phase))
    .collect::<Vec<_>>();
    // The IDG phase commits the manifest from its live exact workspace.
    // Otherwise refresh the descriptive manifest after any artifact change,
    // or when only manifest producer metadata drifted.
    if !idg_stale
        && (!phases.is_empty() || validation.manifest_status != bonsai_sdk::CacheFreshnessStatus::Fresh)
    {
        phases.push(SemanticWorkerPhase::Manifest);
    }
    phases
}

fn run_semantic_worker(root: &std::path::Path, phase: SemanticWorkerPhase) -> Result<()> {
    if phase == SemanticWorkerPhase::Manifest {
        let _ = bonsai_for_cli().cache(root).write_manifest()?;
        return Ok(());
    }
    let project = open_project_sidecar_validation_only(root)?;
    match phase {
        SemanticWorkerPhase::Compiler => project.cache().warm_compiler_object_sidecar(),
        SemanticWorkerPhase::Retrieval => project.cache().warm_retrieval_sidecar(),
        SemanticWorkerPhase::Callgraph => project.cache().warm_callgraph_sidecar(),
        SemanticWorkerPhase::Linkage => project.cache().warm_compiler_linkage_sidecar(),
        SemanticWorkerPhase::Idg => {
            project.cache().warm_idg_sidecar_and_manifest()?;
            let stage = progress::ScopedSpinner::new("collecting index stats");
            let stats = project.stats();
            stage.finish();
            cli_println!("{}", serde_json::to_string_pretty(&stats)?);
            flush_stdout()
        }
        SemanticWorkerPhase::Manifest => unreachable!("manifest phase returned before workspace open"),
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

#[cfg(test)]
mod semantic_phase_tests {
    use super::*;
    use bonsai_sdk::{CacheFreshnessStatus, CacheSidecarValidation, CacheValidationReport};
    use std::path::PathBuf;

    fn validation(
        compiler: CacheFreshnessStatus,
        callgraph: CacheFreshnessStatus,
        retrieval: CacheFreshnessStatus,
        linkage: CacheFreshnessStatus,
        idg: CacheFreshnessStatus,
    ) -> CacheValidationReport {
        let sidecars = [
            ("compiler_objects", compiler),
            ("callgraph", callgraph),
            ("retrieval", retrieval),
            ("linkage", linkage),
            ("idg", idg),
        ]
        .into_iter()
        .map(|(name, status)| CacheSidecarValidation {
            name: name.to_string(),
            path: PathBuf::from(name),
            status,
            exists: status != CacheFreshnessStatus::Missing,
            bytes: 1,
            reason: None,
        })
        .collect();
        CacheValidationReport {
            manifest_status: CacheFreshnessStatus::Fresh,
            structural_ready: false,
            semantic_ready: false,
            legacy_dataflow_ready: false,
            taint_graph_ready: false,
            export_ready: false,
            sidecars,
            stale_reasons: Vec::new(),
        }
    }

    #[test]
    fn all_current_sidecars_require_no_worker() {
        let current = CacheFreshnessStatus::Fresh;
        assert!(semantic_phase_plan(&validation(current, current, current, current, current)).is_empty());
    }

    #[test]
    fn semantic_generation_requires_validated_semantic_readiness() {
        let current = CacheFreshnessStatus::Fresh;
        let mut report = validation(current, current, current, current, current);
        report.structural_ready = true;
        assert!(!semantic_generation_is_current(&report));
        report.semantic_ready = true;
        assert!(semantic_generation_is_current(&report));
    }

    #[test]
    fn compiler_object_storage_invalidation_rebuilds_only_that_generation() {
        let current = CacheFreshnessStatus::Fresh;
        assert_eq!(
            semantic_phase_plan(&validation(
                CacheFreshnessStatus::Stale,
                current,
                current,
                current,
                current,
            )),
            vec![SemanticWorkerPhase::Compiler, SemanticWorkerPhase::Manifest,]
        );
    }

    #[test]
    fn leaf_invalidation_rebuilds_only_the_leaf() {
        let current = CacheFreshnessStatus::Fresh;
        assert_eq!(
            semantic_phase_plan(&validation(
                current,
                current,
                CacheFreshnessStatus::Missing,
                current,
                current,
            )),
            vec![SemanticWorkerPhase::Retrieval, SemanticWorkerPhase::Manifest,]
        );
    }

    #[test]
    fn linkage_invalidation_rebuilds_linkage_and_dependent_idg() {
        let current = CacheFreshnessStatus::Fresh;
        assert_eq!(
            semantic_phase_plan(&validation(
                current,
                current,
                current,
                CacheFreshnessStatus::Stale,
                current,
            )),
            vec![SemanticWorkerPhase::Linkage, SemanticWorkerPhase::Idg]
        );
    }

    #[test]
    fn non_applicable_idg_is_current() {
        let current = CacheFreshnessStatus::Fresh;
        assert!(semantic_phase_plan(&validation(
            current,
            current,
            current,
            current,
            CacheFreshnessStatus::NotApplicable,
        ))
        .is_empty());
    }

    #[test]
    fn stale_descriptive_manifest_refreshes_without_rebuilding_semantics() {
        let current = CacheFreshnessStatus::Fresh;
        let mut validation = validation(current, current, current, current, current);
        validation.manifest_status = CacheFreshnessStatus::Stale;
        assert_eq!(
            semantic_phase_plan(&validation),
            vec![SemanticWorkerPhase::Manifest]
        );
    }
}
