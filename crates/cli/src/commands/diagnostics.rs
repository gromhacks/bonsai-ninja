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

use crate::args::{BrowseFormat, SemanticWorkerPhase};
use crate::cli_println;
use crate::{progress, ui};
use comfy_table::Cell;

use super::{
    bonsai_for_cli, not_found_with_suggestions, open_project_dataflow_prewarm,
    open_project_index_matching_literal, open_project_index_matching_path, open_project_index_only,
    open_project_parse_only, open_project_sidecar_validation_only,
};

const SEMANTIC_PHASE_POSITION_ENV: &str = "BONSAI_SEMANTIC_PHASE_POSITION";

#[derive(Copy, Clone, Debug)]
pub(crate) struct IndexCommandOptions {
    pub(crate) watch: bool,
    pub(crate) interval_ms: u64,
    pub(crate) prewarm_dataflow: bool,
    pub(crate) semantic: bool,
    pub(crate) semantic_worker: Option<SemanticWorkerPhase>,
    pub(crate) structural_only: bool,
    pub(crate) format: BrowseFormat,
}

pub(crate) fn cmd_index(root: &std::path::Path, options: IndexCommandOptions) -> Result<()> {
    if options.semantic {
        if let Some(phase) = options.semantic_worker {
            return run_semantic_worker(root, phase);
        }
        let result = run_semantic_workers(root)?;
        let cache = bonsai_for_cli().cache(root);
        let manifest = cache.read_manifest()?.ok_or_else(|| {
            anyhow::anyhow!("semantic prewarm completed without publishing a cache manifest")
        })?;
        let ready_sidecars = result
            .stats
            .validation
            .sidecars
            .iter()
            .filter(|sidecar| {
                matches!(
                    sidecar.status,
                    bonsai_sdk::CacheFreshnessStatus::Fresh | bonsai_sdk::CacheFreshnessStatus::NotApplicable
                )
            })
            .map(|sidecar| (sidecar.name.clone(), sidecar.bytes))
            .collect::<std::collections::BTreeMap<_, _>>();
        emit_index_value(
            &json!({
                "mode": "semantic",
                "files": manifest.workspace_sources.files,
                "include_minified_sources": manifest.include_minified_sources,
                "semantic_cache": if result.rebuilt { "rebuilt" } else { "hit" },
                "semantic_ready": result.stats.validation.semantic_ready,
                "manifest_status": result.stats.validation.manifest_status.as_str(),
                "cache_bytes": result.stats.total_bytes,
                "ready_sidecars": ready_sidecars,
            }),
            options.format,
        )?;
        flush_stdout()?;
        return Ok(());
    }
    // A one-shot structural index must leave reusable compiler artifacts.
    // Merely parsing into a process-local workspace makes the documented
    // warm-up disappear at process exit and forces the next semantic command
    // to parse the repository again. The command itself is already the hard
    // process-lifetime boundary, so build and report from one source snapshot
    // instead of spawning a worker and reopening the whole repository merely
    // to print counters. `--structural-only` is the explicit spelling of this
    // default behavior; it suppresses graph sidecars, not syntax objects.
    let _ = options.structural_only;
    if !options.watch && !options.prewarm_dataflow {
        let maintenance = progress::ScopedSpinner::new("maintaining compiler cache");
        let cache = bonsai_for_cli().cache(root);
        cache.maintain_persisted_sidecars()?;
        maintenance.finish();
        // `--no-cache` / `BONSAI_NO_CACHE` asks for one exact cold pass: skip
        // the persisted compiler-object generation and recompile.
        let cache_disabled = *crate::NO_CACHE.get().unwrap_or(&false);
        if let Some(files) = cache.current_compiler_object_count()?.filter(|_| !cache_disabled) {
            // A warm structural index is a cache-validation operation, not a
            // request to ingest every source body into a fresh process. Keep
            // the exact compiler-generation proof root-only and derive the
            // reported workspace context from filesystem metadata.
            let include_minified_sources = crate::include_minified_sources();
            let mut context_options = bonsai_sdk::OpenOptions::lazy_query();
            context_options.include_minified_sources = include_minified_sources;
            let workspace = bonsai_sdk::Workspace::new_with_open_options(
                bonsai_adapters::all_languages_registry(),
                context_options,
            );
            let context = workspace
                .semantic_context_for_root(root)
                .map_err(|error| anyhow::anyhow!("collecting context for {}: {error}", root.display()))?;
            anyhow::ensure!(
                context.summary.indexed_files == files,
                "compiler cache/source inventory mismatch: generation has {files} files, metadata scan found {}",
                context.summary.indexed_files
            );
            // The manifest records each source's stamp and text identity so
            // later opens intern unchanged files without reading them; a
            // binary upgrade or moved checkout leaves it stale until here.
            if cache.manifest_needs_republish()? {
                let stage = progress::ScopedSpinner::new("publishing cache manifest");
                let _ = cache.write_manifest()?;
                stage.finish();
            }
            emit_index_value(
                &json!({
                    "files": files,
                    "include_minified_sources": include_minified_sources,
                    "compiler_cache": "hit",
                    "compiler_objects": files,
                    "parsed_files": 0,
                    "semantic_context": context.summary,
                    "context": workspace_context_value(&context),
                }),
                options.format,
            )?;
            flush_stdout()?;
            return Ok(());
        }
        let project = open_project_sidecar_validation_only(root)?;
        let stats = project.stats();
        let compiler = progress::progress_bar("compiling Tree-sitter objects", stats.files as u64);
        let compiler_result = project
            .workspace()
            .save_compiler_object_sidecar_with_progress(root, || compiler.inc(1));
        compiler.finish_and_clear();
        compiler_result?;
        {
            // A fresh compiler generation is reusable state: publish the
            // manifest that describes it (coverage, fingerprints, and the
            // per-source identities lazy opens rely on).
            let stage = progress::ScopedSpinner::new("publishing cache manifest");
            let _ = bonsai_for_cli().cache(root).write_manifest()?;
            stage.finish();
        }
        let context = project.semantic_context();
        emit_index_value(
            &json!({
                "files": stats.files,
                "include_minified_sources": stats.include_minified_sources,
                "compiler_cache": "rebuilt",
                "compiler_objects": stats.files,
                "parsed_files": stats.files,
                "semantic_context": stats.semantic_context,
                "context": workspace_context_value(&context),
            }),
            options.format,
        )?;
        flush_stdout()?;
        return Ok(());
    }
    let project = if options.prewarm_dataflow {
        open_project_dataflow_prewarm(root)?.0
    } else {
        open_project_parse_only(root)?.0
    };
    let stage = progress::ScopedSpinner::new("collecting index stats");
    let stats = project.stats();
    let mut stats_value = serde_json::to_value(stats)?;
    if let Some(fields) = stats_value.as_object_mut() {
        fields.insert(
            "context".to_string(),
            workspace_context_value(&project.semantic_context()),
        );
    }
    stage.finish();
    emit_index_value(&stats_value, options.format)?;
    flush_stdout()?;
    if !options.watch {
        return Ok(());
    }
    emit_index_value(
        &json!({
            "event": "watching",
            "workspace": root.display().to_string(),
            "interval_ms": options.interval_ms,
        }),
        options.format,
    )?;
    flush_stdout()?;
    let interval = Duration::from_millis(options.interval_ms.max(100));
    loop {
        std::thread::sleep(interval);
        let report = project.refresh_from_disk()?;
        if report.changed() {
            emit_index_value(
                &json!({
                    "event": "reindexed",
                    "added": report.added,
                    "modified": report.modified,
                    "removed": report.removed,
                    "dataflow_entries_built": report.dataflow_entries_built,
                    "stats": project.stats(),
                }),
                options.format,
            )?;
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
pub(super) struct SemanticWarmResult {
    stats: bonsai_sdk::CacheStats,
    rebuilt: bool,
}

pub(super) fn run_semantic_workers(root: &std::path::Path) -> Result<SemanticWarmResult> {
    let executable = std::env::current_exe()?;
    // Maintenance is intentionally separate from semantic planning. A fully
    // fresh manifest can coexist with crash staging files or sidecars from an
    // older schema; reclaim those under writer locks without opening or
    // decoding any compiler graph.
    let maintenance = progress::ScopedSpinner::new("maintaining semantic cache");
    bonsai_for_cli().cache(root).maintain_persisted_sidecars()?;
    maintenance.finish();
    let mut rebuilt = false;
    loop {
        // Cache validation hashes the complete source snapshot and may inspect
        // large factstore metadata. A fresh process is a hard reclamation
        // boundary, so planner allocator pages cannot stack with compiler or
        // graph workers.
        let stats = semantic_cache_stats(&executable, root)?;
        if semantic_generation_is_current(&stats.validation) {
            return Ok(SemanticWarmResult { stats, rebuilt });
        }
        let phases = semantic_phase_plan(&stats.validation);
        rebuilt |= !phases.is_empty();
        let phase_count = phases.len();
        for (index, phase) in phases.into_iter().enumerate() {
            run_semantic_phase_process(&executable, root, phase, index + 1, phase_count)?;
        }
        // Each worker publishes atomically. This final validation proves every
        // artifact describes the same current snapshot. An edit between
        // workers reruns the exact compiler pipeline until it reaches a
        // quiescent generation; there is no semantic retry cap.
        let stats = semantic_cache_stats(&executable, root)?;
        if semantic_generation_is_current(&stats.validation) {
            return Ok(SemanticWarmResult { stats, rebuilt });
        }
        let retry = progress::ScopedSpinner::new(
            "workspace changed between semantic workers; rebuilding one coherent generation",
        );
        retry.finish();
    }
}

/// Publish the compact semantic generation needed by exact graph-navigation
/// queries, without also building or mapping the workspace IDG.
///
/// Target-oriented `inspect` needs compiler objects, the
/// partitioned call graph, retrieval candidates, and stable linkage headers.
/// Building those phases in isolated processes keeps parser and graph
/// allocator peaks from accumulating in one long-lived CLI process. The
/// resulting query can then hydrate only the target's exact caller/callee cut
/// rather than opening every body in a large workspace.
pub(super) fn run_graph_query_workers(root: &std::path::Path) -> Result<()> {
    let executable = std::env::current_exe()?;
    let maintenance = progress::ScopedSpinner::new("maintaining semantic cache");
    bonsai_for_cli().cache(root).maintain_persisted_sidecars()?;
    maintenance.finish();
    loop {
        let stats = semantic_cache_stats(&executable, root)?;
        if graph_query_generation_is_current(&stats.validation) {
            return Ok(());
        }
        let phases = graph_query_phase_plan(&stats.validation);
        let phase_count = phases.len();
        for (index, phase) in phases.into_iter().enumerate() {
            run_semantic_phase_process(&executable, root, phase, index + 1, phase_count)?;
        }
        let validation = semantic_cache_stats(&executable, root)?.validation;
        if graph_query_generation_is_current(&validation) {
            return Ok(());
        }
        let retry = progress::ScopedSpinner::new(
            "workspace changed between graph-query workers; rebuilding one coherent generation",
        );
        retry.finish();
    }
}

fn run_semantic_phase_process(
    executable: &std::path::Path,
    root: &std::path::Path,
    phase: SemanticWorkerPhase,
    ordinal: usize,
    total: usize,
) -> Result<()> {
    let phase_name = semantic_phase_name(phase);
    let started = std::time::Instant::now();
    let mut command = semantic_phase_command(
        executable,
        root,
        phase,
        progress::is_disabled(),
        progress::is_color_disabled(),
    );
    command.env(SEMANTIC_PHASE_POSITION_ENV, format!("{ordinal}/{total}"));
    let status = command.status()?;
    bonsai_diagnostics::debug_log!(
        "semantic-index",
        "phase={} elapsed_seconds={:.3}",
        phase_name,
        started.elapsed().as_secs_f64()
    );
    if !status.success() {
        anyhow::bail!("semantic {phase_name} worker exited with {status}");
    }
    Ok(())
}

fn semantic_phase_name(phase: SemanticWorkerPhase) -> &'static str {
    match phase {
        SemanticWorkerPhase::Compiler => "compiler",
        SemanticWorkerPhase::Retrieval => "retrieval",
        SemanticWorkerPhase::Callgraph => "callgraph",
        SemanticWorkerPhase::Linkage => "linkage",
        SemanticWorkerPhase::Idg => "idg",
        SemanticWorkerPhase::Manifest => "manifest",
    }
}

fn semantic_phase_progress_action(phase: SemanticWorkerPhase) -> &'static str {
    match phase {
        SemanticWorkerPhase::Compiler => "compiling Tree-sitter objects",
        SemanticWorkerPhase::Linkage => "building declaration linkage",
        SemanticWorkerPhase::Callgraph => "resolving callgraph",
        SemanticWorkerPhase::Retrieval => "building retrieval index",
        SemanticWorkerPhase::Idg => "building dataflow graph",
        SemanticWorkerPhase::Manifest => "publishing cache manifest",
    }
}

fn semantic_phase_command(
    executable: &std::path::Path,
    root: &std::path::Path,
    phase: SemanticWorkerPhase,
    suppress_progress: bool,
    suppress_color: bool,
) -> Command {
    let phase_name = semantic_phase_name(phase);
    let mut command = Command::new(executable);
    // The worker owns its phase UI because it can report real compiler units.
    // Preserve explicit/non-TTY suppression across the process boundary.
    if suppress_progress {
        command.arg("--no-progress");
    }
    if suppress_color {
        command.arg("--no-color");
    }
    // Compiler-input scope is semantic state. Pass the public flag explicitly
    // across the process-reclamation boundary instead of relying only on an
    // inherited environment variable.
    if crate::include_minified_sources() {
        command.arg("--minified-js");
    }
    command
        .arg("index")
        .arg("--semantic")
        .arg("--semantic-worker")
        .arg(phase_name)
        .arg(root);
    if let Some(timeout_ms) = crate::PARSE_TIMEOUT_MS.get().copied().flatten() {
        command.arg("--parse-timeout").arg(timeout_ms.to_string());
    }
    command
}

fn semantic_generation_is_current(validation: &bonsai_sdk::CacheValidationReport) -> bool {
    validation.semantic_ready && validation.manifest_status == bonsai_sdk::CacheFreshnessStatus::Fresh
}

fn sidecar_is_fresh(validation: &bonsai_sdk::CacheValidationReport, name: &str) -> bool {
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
}

fn graph_query_generation_is_current(validation: &bonsai_sdk::CacheValidationReport) -> bool {
    ["compiler_objects", "callgraph", "retrieval", "linkage"]
        .into_iter()
        .all(|name| sidecar_is_fresh(validation, name))
        && validation.manifest_status == bonsai_sdk::CacheFreshnessStatus::Fresh
}

fn semantic_cache_stats(
    executable: &std::path::Path,
    root: &std::path::Path,
) -> Result<bonsai_sdk::CacheStats> {
    let stage = progress::ScopedSpinner::new("validating semantic generation");
    let mut command = Command::new(executable);
    if crate::include_minified_sources() {
        command.arg("--minified-js");
    }
    let output = command
        .arg("cache")
        .arg("stats")
        .arg(root)
        .arg("--format")
        .arg("json")
        .arg("--no-color")
        .arg("--no-progress")
        .output()?;
    stage.finish();
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
    let compiler_stale = !sidecar_is_fresh(validation, "compiler_objects");
    // Compiler-object storage is an independently versioned serialization of
    // adapter facts. Its storage ABI may change without changing callgraph,
    // linkage, retrieval, or IDG semantics; those artifacts carry their own
    // semantic ABIs and exact source fingerprints.
    let callgraph_stale = !sidecar_is_fresh(validation, "callgraph");
    let retrieval_stale = callgraph_stale || !sidecar_is_fresh(validation, "retrieval");
    let linkage_stale = !sidecar_is_fresh(validation, "linkage");
    let idg_stale = callgraph_stale || linkage_stale || !sidecar_is_fresh(validation, "idg");

    let mut phases = [
        (SemanticWorkerPhase::Compiler, compiler_stale),
        // Linkage publishes independently decodable declaration headers.
        // Build it before callgraph so that worker streams only call bodies
        // instead of first reconstructing the same workspace header table.
        (SemanticWorkerPhase::Linkage, linkage_stale),
        (SemanticWorkerPhase::Callgraph, callgraph_stale),
        (SemanticWorkerPhase::Retrieval, retrieval_stale),
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

fn graph_query_phase_plan(validation: &bonsai_sdk::CacheValidationReport) -> Vec<SemanticWorkerPhase> {
    let compiler_stale = !sidecar_is_fresh(validation, "compiler_objects");
    let callgraph_stale = !sidecar_is_fresh(validation, "callgraph");
    let retrieval_stale = callgraph_stale || !sidecar_is_fresh(validation, "retrieval");
    let linkage_stale = !sidecar_is_fresh(validation, "linkage");
    let mut phases = [
        (SemanticWorkerPhase::Compiler, compiler_stale),
        (SemanticWorkerPhase::Linkage, linkage_stale),
        (SemanticWorkerPhase::Callgraph, callgraph_stale),
        (SemanticWorkerPhase::Retrieval, retrieval_stale),
    ]
    .into_iter()
    .filter_map(|(phase, stale)| stale.then_some(phase))
    .collect::<Vec<_>>();
    if !phases.is_empty() || validation.manifest_status != bonsai_sdk::CacheFreshnessStatus::Fresh {
        phases.push(SemanticWorkerPhase::Manifest);
    }
    phases
}

fn retain_worker_owner_until_process_exit<T>(owner: T) -> std::mem::ManuallyDrop<T> {
    std::mem::ManuallyDrop::new(owner)
}

fn run_semantic_worker(root: &std::path::Path, phase: SemanticWorkerPhase) -> Result<()> {
    let label = std::env::var(SEMANTIC_PHASE_POSITION_ENV).map_or_else(
        |_| semantic_phase_progress_action(phase).to_string(),
        |position| format!("semantic {position} · {}", semantic_phase_progress_action(phase)),
    );
    if phase == SemanticWorkerPhase::Manifest {
        let stage = progress::ScopedSpinner::new(&label);
        let _ = bonsai_for_cli().cache(root).write_manifest()?;
        stage.finish();
        return Ok(());
    }
    if phase == SemanticWorkerPhase::Compiler {
        let cache = bonsai_for_cli().cache(root);
        if cache.migrate_legacy_compiler_object_sidecar()?.is_some() {
            let stage = progress::ScopedSpinner::new(&label);
            let _ = cache.write_manifest()?;
            stage.finish();
            return Ok(());
        }
    }
    // Semantic phases run only in dedicated subprocesses. Keep the complete
    // project alive until that subprocess exits and let the OS reclaim it as
    // one unit. Dropping a production-sized workspace here can spend minutes
    // recursively releasing compiler/IDG allocations after the atomically
    // published phase is already complete; on Linux that made the parent wait
    // indefinitely for an otherwise successful worker. `ManuallyDrop` is the
    // intended hard-reclamation boundary, not a semantic shortcut: all phase
    // work and persistence below still finish before the worker returns.
    let project = retain_worker_owner_until_process_exit(open_project_sidecar_validation_only(root)?);
    match phase {
        SemanticWorkerPhase::Compiler => {
            let bar = progress::progress_bar(&label, project.stats().files as u64);
            let result = project
                .workspace()
                .save_compiler_object_sidecar_with_progress(root, || bar.inc(1))
                .map(|_| ())
                .map_err(anyhow::Error::from);
            bar.finish_and_clear();
            result
        }
        SemanticWorkerPhase::Callgraph => {
            let total = project.workspace().compiler_linkage_index().all_files().count() as u64;
            let bar = progress::progress_bar(&label, total);
            let result = project
                .workspace()
                .save_callgraph_sidecar_with_progress(root, || bar.inc(1))
                .map_err(anyhow::Error::from);
            bar.finish_and_clear();
            result
        }
        SemanticWorkerPhase::Retrieval => {
            let stage = progress::PhaseProgress::spinner(&label);
            let result = project
                .cache()
                .warm_retrieval_sidecar_with_progress(|event| match event {
                    bonsai_sdk::RetrievalBuildProgress::FilesStarted { files } => {
                        stage.start_bar(&label, files as u64);
                    }
                    bonsai_sdk::RetrievalBuildProgress::FileCompleted => stage.inc(1),
                    bonsai_sdk::RetrievalBuildProgress::Persisting { docs } => {
                        stage.start_spinner(&format!("{label} · persisting {docs} candidates"));
                    }
                });
            stage.finish();
            result
        }
        SemanticWorkerPhase::Linkage => {
            let stage = progress::PhaseProgress::spinner(&label);
            let result = project
                .cache()
                .warm_compiler_linkage_sidecar_with_progress(|event| match event {
                    bonsai_sdk::CompilerLinkageProgress::FilesStarted { files } => {
                        stage.start_bar(&label, files as u64);
                    }
                    bonsai_sdk::CompilerLinkageProgress::FileCompleted => stage.inc(1),
                    bonsai_sdk::CompilerLinkageProgress::Persisting { declarations } => {
                        stage.start_spinner(&format!("{label} · persisting {declarations} declarations"));
                    }
                });
            stage.finish();
            result
        }
        SemanticWorkerPhase::Idg => {
            let stage = progress::PhaseProgress::spinner(&label);
            let result = project
                .cache()
                .warm_idg_sidecar_and_manifest_with_progress(|event| match event {
                    bonsai_sdk::IdgPersistenceProgress::TransferStarted { segments } => {
                        stage.start_bar(&format!("{label} · lowering IDG segments"), segments as u64);
                    }
                    bonsai_sdk::IdgPersistenceProgress::TransferSegmentCompleted => {
                        stage.inc(1);
                    }
                    bonsai_sdk::IdgPersistenceProgress::AcceleratorStarted => {
                        stage.start_spinner(&format!("{label} · compiling query accelerator"));
                    }
                    bonsai_sdk::IdgPersistenceProgress::Persisting { segments } => {
                        stage.start_spinner(&format!("{label} · persisting {segments} IDG segments"));
                    }
                    bonsai_sdk::IdgPersistenceProgress::ResidentFallbackStarted => {
                        stage.start_spinner(&format!("{label} · building exact resident fallback"));
                    }
                    bonsai_sdk::IdgPersistenceProgress::ManifestStarted => {
                        stage.start_spinner(&format!("{label} · publishing manifest"));
                    }
                });
            stage.finish();
            result
        }
        SemanticWorkerPhase::Manifest => unreachable!("manifest phase returned before workspace open"),
    }
}

fn emit_index_value(value: &serde_json::Value, format: BrowseFormat) -> Result<()> {
    if crate::filter::active().is_active() && !crate::filter::active().matches_value(value) {
        match format {
            BrowseFormat::Json => crate::output::emit_json_document(&super::filtered_out_document(value))?,
            BrowseFormat::Text => cli_println!("no index result matches the active output filter"),
        }
        return Ok(());
    }
    match format {
        BrowseFormat::Json => crate::output::emit_json_document(&super::with_completeness(value))?,
        BrowseFormat::Text => render_flat_json_text("index", value),
    }
    Ok(())
}

/// Readable fact table for one flat compiler/index object: every scalar
/// leaf becomes a `dotted.path → value` row, so the text view exposes the
/// same facts as the JSON object without printing a JSON blob.
fn render_flat_json_text(title: &str, value: &serde_json::Value) {
    let u = ui();
    cli_println!();
    cli_println!("{}", u.heading(title));
    let mut facts = Vec::new();
    flatten_json_value("", value, &mut facts);
    let mut table = u.table(&["fact", "value"]);
    for (name, value) in facts {
        table.add_row(vec![Cell::new(u.kind(&name)), Cell::new(value)]);
    }
    cli_println!("{table}");
}

/// Flatten nested JSON into `(dotted.path, rendered value)` facts. Scalar
/// lists render inline; lists of objects index their members.
fn flatten_json_value(prefix: &str, value: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(fields) => {
            if fields.is_empty() {
                out.push((prefix.to_string(), "(none)".to_string()));
            }
            for (key, child) in fields {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_json_value(&path, child, out);
            }
        }
        serde_json::Value::Array(items) if items.iter().all(|item| !item.is_object() && !item.is_array()) => {
            let rendered = items.iter().map(flat_scalar_text).collect::<Vec<_>>().join(", ");
            out.push((
                prefix.to_string(),
                if rendered.is_empty() {
                    "(none)".to_string()
                } else {
                    rendered
                },
            ));
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                flatten_json_value(&format!("{prefix}[{index}]"), item, out);
            }
        }
        other => out.push((prefix.to_string(), flat_scalar_text(other))),
    }
}

fn flat_scalar_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => "-".to_string(),
        other => compact_json(other),
    }
}

/// The workspace-shape facts every `index` report carries: module,
/// dependency, generated, and excluded roots; toolchain manifests; configured
/// source variants; source-transformation evidence; and the reasons the
/// context is incomplete. Same structure as `Project::semantic_context()`.
fn workspace_context_value(context: &bonsai_sdk::WorkspaceSemanticContext) -> serde_json::Value {
    serde_json::json!({
        "workspace_root": context.workspace_root,
        "module_roots": context.module_roots,
        "dependency_roots": context.dependency_roots,
        "generated_roots": context.generated_roots,
        "excluded_roots": context.excluded_roots,
        "toolchain_manifests": context.toolchain_manifests,
        "configured_source_variants": context.configured_source_variants,
        "source_transformations": context.source_transformations,
        "incomplete_reasons": context.incomplete_reasons,
    })
}

fn flush_stdout() -> Result<()> {
    std::io::stdout().flush()?;
    Ok(())
}

fn emit_complete_value(title: &str, value: &serde_json::Value, format: BrowseFormat) -> Result<()> {
    if crate::filter::active().is_active() && !crate::filter::active().matches_value(value) {
        match format {
            BrowseFormat::Json => crate::output::emit_json_document(&super::filtered_out_document(value))?,
            BrowseFormat::Text => {
                cli_println!("no {title} result matches the active output filter");
            }
        }
        return Ok(());
    }
    match format {
        BrowseFormat::Json => crate::output::emit_json_document(&super::with_completeness(value))?,
        BrowseFormat::Text => match title {
            "compiler diagnostics" => render_diagnostics_text(value),
            "compiler HIR" => render_hir_text(value),
            "compiler CFG" => render_cfg_text(value),
            _ => render_flat_json_text(title, value),
        },
    }
    Ok(())
}

fn render_diagnostics_text(value: &serde_json::Value) {
    let u = ui();
    cli_println!();
    cli_println!("{}", u.heading("compiler diagnostics"));
    let languages = value["workspace_languages"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let diagnostics = value["diagnostics"].as_array().map_or(0, Vec::len);
    let files = value["diagnostic_files"].as_array().map_or(0, Vec::len);
    cli_println!(
        "  {} {}    {} {}    {} {}",
        u.label("languages"),
        u.name(if languages.is_empty() { "-" } else { &languages }),
        u.label("diagnostics"),
        u.name(&diagnostics.to_string()),
        u.label("files"),
        u.name(&files.to_string())
    );
    if let Some(capabilities) = value["adapter_capabilities"].as_array() {
        for capability in capabilities {
            let language = capability["display_name"]
                .as_str()
                .or_else(|| capability["language"].as_str())
                .unwrap_or("-");
            let extensions = capability["file_extensions"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            cli_println!();
            cli_println!(
                "{}  {}",
                u.name(language),
                u.dim(&format!(
                    "extensions: {}",
                    if extensions.is_empty() { "-" } else { &extensions }
                ))
            );
            let mut table = u.table(&["capability", "support / evidence"]);
            if let Some(object) = capability.as_object() {
                for (name, detail) in object {
                    if matches!(name.as_str(), "display_name" | "language" | "file_extensions") {
                        continue;
                    }
                    let rendered = detail
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| compact_json(detail));
                    table.add_row(vec![Cell::new(u.kind(name)), Cell::new(rendered)]);
                }
            }
            cli_println!("{table}");
        }
    }
    if let Some(rows) = value["diagnostics"].as_array().filter(|rows| !rows.is_empty()) {
        let mut table = u.table(&["#", "diagnostic"]);
        for (index, row) in rows.iter().enumerate() {
            table.add_row(vec![
                Cell::new((index + 1).to_string()),
                Cell::new(compact_json(row)),
            ]);
        }
        cli_println!("{table}");
    }
}

fn render_hir_text(value: &serde_json::Value) {
    let u = ui();
    let qualified = value["qualified_name"]
        .as_str()
        .or_else(|| value["name"].as_str())
        .unwrap_or("<unknown>");
    cli_println!();
    cli_println!("{}", u.heading(&format!("HIR {qualified}")));
    cli_println!(
        "  {} {}    {} {}    {} {}",
        u.label("kind"),
        u.kind(value["kind"].as_str().unwrap_or("-")),
        u.label("params"),
        u.name(&compact_json(&value["params"])),
        u.label("status"),
        analysis_status(value)
    );
    cli_println!(
        "  {} {}    {} {}",
        u.label("span"),
        u.path(&span_text(&value["span"])),
        u.label("body"),
        u.path(&span_text(&value["body_span"]))
    );
    render_incomplete_reasons(value);
    if let Some(aliases) = value["type_aliases"].as_array().filter(|rows| !rows.is_empty()) {
        let mut table = u.table(&["typed value", "type"]);
        for alias in aliases {
            table.add_row(vec![
                Cell::new(u.name(alias["name"].as_str().unwrap_or("-"))),
                Cell::new(u.kind(alias["type_name"].as_str().unwrap_or("-"))),
            ]);
        }
        cli_println!("{table}");
    }
    render_event_table(
        "FLOW EVENTS",
        value["flow_events"].as_array().map(Vec::as_slice).unwrap_or(&[]),
    );
}

fn render_cfg_text(value: &serde_json::Value) {
    let u = ui();
    let function = value["function"].as_str().unwrap_or("<unknown>");
    cli_println!();
    cli_println!("{}", u.heading(&format!("CFG {function}")));
    cli_println!(
        "  {} {}    {} {}    {} {}    {} {}",
        u.label("entry"),
        u.name(&value["entry"].to_string()),
        u.label("exit"),
        u.name(&value["exit"].to_string()),
        u.label("blocks"),
        u.name(&value["blocks"].as_array().map_or(0, Vec::len).to_string()),
        u.label("status"),
        analysis_status(value)
    );
    render_incomplete_reasons(value);
    if let Some(blocks) = value["blocks"].as_array() {
        let mut table = u.table(&[
            "block",
            "label / kind",
            "terminator",
            "successors",
            "events",
            "span",
        ]);
        for block in blocks {
            table.add_row(vec![
                Cell::new(u.name(&block["id"].to_string())),
                Cell::new(format!(
                    "{} · {}",
                    block["label"].as_str().unwrap_or("-"),
                    block["synthetic_kind"].as_str().unwrap_or("-")
                )),
                Cell::new(compact_json(&block["terminator"])),
                Cell::new(compact_json(&block["successors"])),
                Cell::new(block["events"].as_array().map_or(0, Vec::len).to_string()),
                Cell::new(u.path(&span_text(&block["span"]))),
            ]);
        }
        cli_println!("{table}");
        for block in blocks {
            let Some(events) = block["events"].as_array().filter(|events| !events.is_empty()) else {
                continue;
            };
            render_event_table(
                &format!(
                    "BLOCK {} · {}",
                    block["id"],
                    block["label"].as_str().unwrap_or("-")
                ),
                events,
            );
        }
    }
}

fn render_event_table(title: &str, events: &[serde_json::Value]) {
    let u = ui();
    cli_println!();
    cli_println!("{}", u.label(title));
    if events.is_empty() {
        cli_println!("{}", u.dim("(none)"));
        return;
    }
    let mut table = u.table(&["#", "event", "span", "compiler facts"]);
    for (index, event) in events.iter().enumerate() {
        let (kind, payload) = event
            .as_object()
            .and_then(|object| object.iter().next())
            .map_or(("unknown", event), |(kind, payload)| (kind.as_str(), payload));
        let span = payload
            .get("span")
            .map(span_text)
            .unwrap_or_else(|| "-".to_string());
        let mut facts = payload.clone();
        if let Some(object) = facts.as_object_mut() {
            object.remove("span");
        }
        // One `path: value` line per compiler fact. The JSON object is the
        // canonical record; the text view flattens it so a reader never has
        // to parse a JSON blob inside a table cell.
        let mut flat = Vec::new();
        flatten_json_value("", &facts, &mut flat);
        let facts_cell = if flat.is_empty() {
            u.dim("-")
        } else {
            flat.iter()
                .map(|(name, value)| format!("{}: {value}", u.dim(name)))
                .collect::<Vec<_>>()
                .join("\n")
        };
        table.add_row(vec![
            Cell::new((index + 1).to_string()),
            Cell::new(u.kind(kind)),
            Cell::new(u.path(&span)),
            Cell::new(facts_cell),
        ]);
    }
    cli_println!("{table}");
}

fn analysis_status(value: &serde_json::Value) -> String {
    let u = ui();
    if value["analysis_complete"].as_bool().unwrap_or(false) {
        u.name("complete")
    } else {
        u.warn("incomplete")
    }
}

fn render_incomplete_reasons(value: &serde_json::Value) {
    let Some(reasons) = value["analysis_incomplete_reasons"]
        .as_array()
        .filter(|rows| !rows.is_empty())
    else {
        return;
    };
    let text = reasons
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    for line in ui().wrapped_warn_labeled_lines("analysis incomplete", &text) {
        cli_println!("{line}");
    }
}

fn span_text(span: &serde_json::Value) -> String {
    if !span.is_object() {
        return compact_json(span);
    }
    format!("file {} bytes {}..{}", span["file"], span["start"], span["end"])
}

fn compact_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_string())
}

pub(crate) fn cmd_diagnostics(root: &std::path::Path, format: BrowseFormat) -> Result<()> {
    let (project, _footer) = open_project_index_only(root)?;
    let file_count = project.workspace().vfs().file_count();
    let bar = progress::progress_bar("collecting diagnostics", file_count as u64);
    // `diagnostics_report_with_progress` owns the one exact compiler pass.
    // Parsing every file first retained a workspace-sized syntax forest and
    // then repeated the frontend work while collecting adapter diagnostics.
    let report = project.diagnostics_report_with_progress(|| bar.inc(1));
    bar.finish_and_clear();
    emit_complete_value("compiler diagnostics", &serde_json::to_value(&report)?, format)?;
    Ok(())
}

pub(crate) fn cmd_dump_hir(root: &std::path::Path, symbol: &str, format: BrowseFormat) -> Result<()> {
    let (project, _footer) = open_project_for_dump_target(root, symbol)?;
    let ws = project.workspace();
    let stage = progress::ScopedSpinner::new("building HIR dump");
    let dump = project
        .dump()
        .hir(symbol)
        .map_err(|err| anyhow::anyhow!("dump-hir: {err}"))?
        .ok_or_else(|| not_found_with_suggestions(ws, symbol))?;
    stage.finish();
    emit_complete_value("compiler HIR", &serde_json::to_value(&dump)?, format)?;
    Ok(())
}

pub(crate) fn cmd_dump_cfg(root: &std::path::Path, symbol: &str, format: BrowseFormat) -> Result<()> {
    let (project, _footer) = open_project_for_dump_target(root, symbol)?;
    let ws = project.workspace();
    let stage = progress::ScopedSpinner::new("building CFG dump");
    let cfg = project
        .dump()
        .cfg(symbol)
        .map_err(|err| anyhow::anyhow!("dump-cfg: {err}"))?
        .ok_or_else(|| not_found_with_suggestions(ws, symbol))?;
    stage.finish();
    emit_complete_value("compiler CFG", &serde_json::to_value(&cfg)?, format)?;
    Ok(())
}

fn open_project_for_dump_target(
    root: &std::path::Path,
    symbol: &str,
) -> Result<(bonsai_sdk::Project, crate::footer::WorkspaceFooter)> {
    if let Some(file) = bonsai_sdk::dump_callable_file_qualifier(symbol) {
        return open_project_index_matching_path(root, std::path::Path::new(file));
    }
    // A compiler-qualified identity (for example the exact `qualified_name`
    // printed by `defs`) need not appear verbatim in source. Use its terminal
    // declaration token only for candidate-file selection; the browse layer
    // then resolves the complete qualified identity against typed headers.
    open_project_index_matching_literal(root, bonsai_callgraph::short_callee(symbol))
}

#[cfg(test)]
mod semantic_phase_tests {
    use super::*;
    use bonsai_sdk::{CacheFreshnessStatus, CacheSidecarValidation, CacheValidationReport};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropProbe(&'static AtomicBool);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn semantic_worker_owners_are_reclaimed_only_by_process_exit() {
        static DROPPED: AtomicBool = AtomicBool::new(false);
        DROPPED.store(false, Ordering::SeqCst);
        {
            let _owner = retain_worker_owner_until_process_exit(DropProbe(&DROPPED));
        }
        assert!(
            !DROPPED.load(Ordering::SeqCst),
            "isolated semantic workers must not recursively tear down a production workspace before exiting"
        );
    }

    #[test]
    fn semantic_workers_have_distinct_user_facing_progress_actions() {
        let phases = [
            SemanticWorkerPhase::Compiler,
            SemanticWorkerPhase::Linkage,
            SemanticWorkerPhase::Callgraph,
            SemanticWorkerPhase::Retrieval,
            SemanticWorkerPhase::Idg,
            SemanticWorkerPhase::Manifest,
        ];
        let actions = phases.map(semantic_phase_progress_action);
        assert!(actions.iter().all(|action| !action.trim().is_empty()));
        let unique = actions.into_iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), phases.len());
    }

    #[test]
    fn semantic_worker_child_owns_progress_unless_parent_suppresses_it() {
        let command = semantic_phase_command(
            std::path::Path::new("bonsai-ninja"),
            std::path::Path::new("workspace"),
            SemanticWorkerPhase::Idg,
            false,
            false,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            ["index", "--semantic", "--semantic-worker", "idg", "workspace",]
        );

        let command = semantic_phase_command(
            std::path::Path::new("bonsai-ninja"),
            std::path::Path::new("workspace"),
            SemanticWorkerPhase::Idg,
            true,
            true,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(args.first().map(String::as_str), Some("--no-progress"));
        assert_eq!(args.get(1).map(String::as_str), Some("--no-color"));
    }

    #[test]
    fn dump_target_file_qualifier_understands_documented_disambiguators() {
        assert_eq!(
            bonsai_sdk::dump_callable_file_qualifier("server/src/App.java:42:dispatchRequest"),
            Some("server/src/App.java")
        );
        assert_eq!(
            bonsai_sdk::dump_callable_file_qualifier("server/src/App.java:dispatchRequest"),
            Some("server/src/App.java")
        );
        assert_eq!(
            bonsai_sdk::dump_callable_file_qualifier("App.java:42:dispatchRequest"),
            Some("App.java")
        );
        assert_eq!(bonsai_sdk::dump_callable_file_qualifier("dispatchRequest"), None);
        assert_eq!(
            bonsai_sdk::dump_callable_file_qualifier("module::dispatchRequest"),
            None
        );
    }

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
    fn graph_query_generation_does_not_require_idg() {
        let current = CacheFreshnessStatus::Fresh;
        let report = validation(current, current, current, current, CacheFreshnessStatus::Missing);
        assert!(graph_query_generation_is_current(&report));
        assert!(graph_query_phase_plan(&report).is_empty());
    }

    #[test]
    fn graph_query_plan_builds_only_compact_navigation_sidecars() {
        let current = CacheFreshnessStatus::Fresh;
        let report = validation(
            current,
            CacheFreshnessStatus::Missing,
            CacheFreshnessStatus::Missing,
            CacheFreshnessStatus::Missing,
            CacheFreshnessStatus::Missing,
        );
        assert_eq!(
            graph_query_phase_plan(&report),
            vec![
                SemanticWorkerPhase::Linkage,
                SemanticWorkerPhase::Callgraph,
                SemanticWorkerPhase::Retrieval,
                SemanticWorkerPhase::Manifest,
            ]
        );
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
