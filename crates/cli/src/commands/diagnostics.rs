//! `bonsai-ninja index` / `diagnostics` / `dump-hir` / `dump-cfg` —
//! low-ceremony inspection commands that open the workspace, run one
//! analysis pass, and print the result as JSON. They don't have
//! per-row rendering or text-mode decoration, so they all fit in a
//! single small module together.

use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

use crate::args::SemanticWorkerPhase;
use crate::cli_println;
use crate::{page_cache, paging, progress};

use super::{
    bonsai_for_cli, not_found_with_suggestions, open_project_dataflow_prewarm,
    open_project_index_matching_literal, open_project_index_matching_path, open_project_index_only,
    open_project_parse_only, open_project_sidecar_validation_only, page_info_to_json,
    paged_json_incomplete_reasons,
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
        cli_println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "mode": "semantic",
                "files": manifest.workspace_sources.files,
                "semantic_cache": if result.rebuilt { "rebuilt" } else { "hit" },
                "semantic_ready": result.stats.validation.semantic_ready,
                "manifest_status": result.stats.validation.manifest_status.as_str(),
                "cache_bytes": result.stats.total_bytes,
                "ready_sidecars": ready_sidecars,
            }))?
        );
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
        bonsai_for_cli().cache(root).maintain_persisted_sidecars()?;
        let project = open_project_sidecar_validation_only(root)?;
        let compiler_cache_hit = project.cache().compiler_object_generation_is_current();
        project.cache().warm_compiler_object_sidecar()?;
        let stats = project.stats();
        cli_println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "files": stats.files,
                "compiler_cache": if compiler_cache_hit { "hit" } else { "rebuilt" },
                "compiler_objects": stats.files,
                "parsed_files": if compiler_cache_hit { 0 } else { stats.files },
                "semantic_context": stats.semantic_context,
            }))?
        );
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
    bonsai_for_cli().cache(root).maintain_persisted_sidecars()?;
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
        for phase in phases {
            run_semantic_phase_process(&executable, root, phase)?;
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
/// Target-oriented `inspect --graph-flow` needs compiler objects, the
/// partitioned call graph, retrieval candidates, and stable linkage headers.
/// Building those phases in isolated processes keeps parser and graph
/// allocator peaks from accumulating in one long-lived CLI process. The
/// resulting query can then hydrate only the target's exact caller/callee cut
/// rather than opening every body in a large workspace.
pub(super) fn run_graph_query_workers(root: &std::path::Path) -> Result<()> {
    let executable = std::env::current_exe()?;
    bonsai_for_cli().cache(root).maintain_persisted_sidecars()?;
    loop {
        let stats = semantic_cache_stats(&executable, root)?;
        if graph_query_generation_is_current(&stats.validation) {
            return Ok(());
        }
        for phase in graph_query_phase_plan(&stats.validation) {
            run_semantic_phase_process(&executable, root, phase)?;
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
) -> Result<()> {
    let phase_name = match phase {
        SemanticWorkerPhase::Compiler => "compiler",
        SemanticWorkerPhase::Retrieval => "retrieval",
        SemanticWorkerPhase::Callgraph => "callgraph",
        SemanticWorkerPhase::Linkage => "linkage",
        SemanticWorkerPhase::Idg => "idg",
        SemanticWorkerPhase::Manifest => "manifest",
    };
    let mut command = Command::new(executable);
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
    Ok(())
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

fn run_semantic_worker(root: &std::path::Path, phase: SemanticWorkerPhase) -> Result<()> {
    if phase == SemanticWorkerPhase::Manifest {
        let _ = bonsai_for_cli().cache(root).write_manifest()?;
        return Ok(());
    }
    if phase == SemanticWorkerPhase::Compiler {
        let cache = bonsai_for_cli().cache(root);
        if cache.migrate_legacy_compiler_object_sidecar()?.is_some() {
            let _ = cache.write_manifest()?;
            return Ok(());
        }
    }
    let project = open_project_sidecar_validation_only(root)?;
    match phase {
        SemanticWorkerPhase::Compiler => project.cache().warm_compiler_object_sidecar(),
        SemanticWorkerPhase::Retrieval => project.cache().warm_retrieval_sidecar(),
        SemanticWorkerPhase::Callgraph => project.cache().warm_callgraph_sidecar(),
        SemanticWorkerPhase::Linkage => project.cache().warm_compiler_linkage_sidecar(),
        SemanticWorkerPhase::Idg => project.cache().warm_idg_sidecar_and_manifest(),
        SemanticWorkerPhase::Manifest => unreachable!("manifest phase returned before workspace open"),
    }
}

#[derive(Clone, Debug, Serialize)]
struct ContextRow {
    category: &'static str,
    #[serde(flatten)]
    value: serde_json::Value,
}

fn context_row<T: Serialize>(category: &'static str, value: T) -> Result<ContextRow> {
    Ok(ContextRow {
        category,
        value: serde_json::to_value(value)?,
    })
}

fn context_row_json_cost(row: &ContextRow) -> u64 {
    let Ok(pretty) = serde_json::to_string_pretty(row) else {
        return 512;
    };
    // The page renderer nests each pretty row under the root object's
    // `rows` array. Account for the four extra indentation bytes on every
    // rendered line plus the separating comma/newline. Pricing compact JSON
    // here used to let `context --context 16k` emit ~20k tokens on
    // Elasticsearch even though the paginator reported 15.5k.
    let lines = pretty.split('\n').count();
    pretty
        .len()
        .saturating_add(lines.saturating_mul(4))
        // Array separators and the transition from an empty `rows: []`
        // wrapper to a populated pretty array add a few more bytes. Keep a
        // small per-row margin so the advertised ceiling remains a ceiling.
        .saturating_add(16) as u64
}

pub(crate) fn cmd_context(root: &std::path::Path, paging_cfg: paging::PagingConfig) -> Result<()> {
    // Workspace context is a filesystem/path fact. It does not inspect
    // declarations, so do not read source contents into a VFS or invoke
    // Tree-sitter for a metadata-only command.
    let workspace = bonsai_sdk::Workspace::new(bonsai_adapters::all_languages_registry());
    let stage = progress::ScopedSpinner::new("collecting workspace context");
    let context = workspace
        .semantic_context_for_root(root)
        .map_err(|error| anyhow::anyhow!("collecting context for {}: {error}", root.display()))?;
    stage.finish();
    if !paging_cfg.json_wrapped() {
        cli_println!("{}", serde_json::to_string_pretty(&context)?);
        flush_stdout()?;
        return Ok(());
    }

    let mut rows = Vec::with_capacity(
        context.module_roots.len()
            + context.dependency_roots.len()
            + context.generated_roots.len()
            + context.excluded_roots.len()
            + context.toolchain_manifests.len()
            + context.configured_source_variants.len()
            + context.source_transformations.len()
            + context.incomplete_reasons.len(),
    );
    for value in &context.module_roots {
        rows.push(context_row("module_root", value)?);
    }
    for value in &context.dependency_roots {
        rows.push(context_row("dependency_root", value)?);
    }
    for value in &context.generated_roots {
        rows.push(context_row("generated_root", value)?);
    }
    for value in &context.excluded_roots {
        rows.push(context_row("excluded_root", value)?);
    }
    for value in &context.toolchain_manifests {
        rows.push(context_row("toolchain_manifest", value)?);
    }
    for value in &context.configured_source_variants {
        rows.push(context_row("configured_source_variant", value)?);
    }
    for value in &context.source_transformations {
        rows.push(context_row("source_transformation", value)?);
    }
    for reason in &context.incomplete_reasons {
        rows.push(context_row(
            "incomplete_reason",
            serde_json::json!({ "reason": reason }),
        )?);
    }

    let workspace_root = context.workspace_root.clone();
    let summary = context.summary;
    let semantic_incomplete_reasons = context.incomplete_reasons.clone();
    let canonical_context = context.clone();
    let force_wrapper = paging_cfg.context.is_some() || !matches!(paging_cfg.page, paging::PageArg::First);
    let filters_hash = paging::hash_filters(&[("command", "context")]);
    page_cache::emit_paged_text(
        root,
        &rows,
        &paging_cfg,
        "context",
        filters_hash,
        context_row_json_cost,
        |slice, info, _cfg| {
            let page_complete = info.page_number == 1 && info.is_last;
            if !force_wrapper && page_complete {
                cli_println!("{}", serde_json::to_string_pretty(&canonical_context)?);
                return Ok(());
            }
            let mut analysis_incomplete_reasons = semantic_incomplete_reasons.clone();
            analysis_incomplete_reasons.extend(paged_json_incomplete_reasons("context", info));
            let wrapped = serde_json::json!({
                "workspace_root": workspace_root,
                "summary": summary,
                "analysis_complete": semantic_incomplete_reasons.is_empty() && page_complete,
                "analysis_incomplete_reasons": analysis_incomplete_reasons,
                "rows": slice,
                "page": page_info_to_json(info),
            });
            cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
            Ok(())
        },
    )?;
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
    let (project, _footer) = open_project_for_dump_target(root, symbol)?;
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
    let (project, _footer) = open_project_for_dump_target(root, symbol)?;
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

fn open_project_for_dump_target(
    root: &std::path::Path,
    symbol: &str,
) -> Result<(bonsai_sdk::Project, crate::footer::WorkspaceFooter)> {
    if let Some(file) = bonsai_sdk::dump_callable_file_qualifier(symbol) {
        return open_project_index_matching_path(root, std::path::Path::new(file));
    }
    open_project_index_matching_literal(root, symbol)
}

#[cfg(test)]
mod semantic_phase_tests {
    use super::*;
    use bonsai_sdk::{CacheFreshnessStatus, CacheSidecarValidation, CacheValidationReport};
    use std::path::PathBuf;

    #[test]
    fn context_row_cost_covers_pretty_nested_json() {
        let row = context_row(
            "toolchain_manifest",
            serde_json::json!({
                "path": "services/search/build.gradle",
                "kind": "gradle",
                "nested": { "targets": ["main", "test"] }
            }),
        )
        .expect("context row");
        let with_row = serde_json::to_string_pretty(&serde_json::json!({ "rows": [&row] }))
            .expect("serialize wrapped row");
        let empty = serde_json::to_string_pretty(&serde_json::json!({ "rows": [] }))
            .expect("serialize empty wrapper");
        let cost = context_row_json_cost(&row) as usize;
        let introduced = with_row.len().saturating_sub(empty.len());
        assert!(
            cost >= introduced,
            "row pricing ({cost}) must cover the bytes introduced by nested pretty JSON ({introduced})"
        );
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
