//! `bonsai-ninja cache <stats|clear|rebuild>` — operate on the
//! on-disk `.bonsai/` directory. The directory stores persisted
//! analysis sidecars such as the dataflow taint graph and the warmed
//! export JSON; `cache stats` reports artifact paths and byte sizes,
//! `cache clear` removes them, and `cache rebuild` refreshes them.
//!
//! In-process chain / downstream / reachable-names caches are
//! per-run and drop at process exit; [`cmd_cache`] prints a closing
//! "note" line so nobody mistakes `cache clear` for an in-memory
//! reset.

use anyhow::{Context, Result};

use crate::args::{BrowseFormat, CacheAction};
use crate::progress;
use crate::{cli_println, ui};

use super::export::warm_export_cache_for_project;
use super::open_project_index_only;

/// Handler for `bonsai-ninja cache <stats|clear|rebuild>`. Operates
/// on the on-disk `.bonsai/` cache under the target workspace.
/// In-process chain caches are per-run and drop at exit; this handler
/// always reminds the user of that in its final "note" line so nobody
/// mistakes `cache clear` for an in-memory reset.
pub(crate) fn cmd_cache(action: CacheAction) -> Result<()> {
    match action {
        CacheAction::Stats {
            workspace,
            format,
            output: _,
        } => cache_stats(workspace, format),
        CacheAction::Clear {
            workspace,
            dataflow_only,
        } => cache_clear(workspace, dataflow_only),
        CacheAction::Rebuild {
            workspace,
            export: warm_export,
        } => cache_rebuild(workspace, warm_export),
    }
}

fn print_kv(key: &str, value: &str) {
    let ui = ui();
    cli_println!("{}  {}", ui.label(&format!("{key:>26}")), value);
}

fn cache_stats(workspace: Option<std::path::PathBuf>, format: BrowseFormat) -> Result<()> {
    let ui = ui();
    let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
    let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root).with_discovered_rulepack_root();
    let stage = progress::ScopedSpinner::new("reading cache metadata");
    let stats = cache.stats()?;
    stage.finish();
    if matches!(format, BrowseFormat::Json | BrowseFormat::Sarif) {
        cli_println!("{}", serde_json::to_string_pretty(&stats)?);
        return Ok(());
    }
    print_kv("scope", "in-process (per command invocation)");
    print_kv(
        "reachable cap",
        &bonsai_sdk::cache::REACHABLE_CACHE_CAP.to_string(),
    );
    print_kv("chains cap", &bonsai_sdk::cache::CHAINS_CACHE_CAP.to_string());
    print_kv(
        "downstream cap",
        &bonsai_sdk::cache::DOWNSTREAM_CACHE_CAP.to_string(),
    );
    print_kv("callees cap", &bonsai_sdk::cache::CALLEES_CACHE_CAP.to_string());
    print_kv(
        "enclosing cap",
        &bonsai_sdk::cache::ENCLOSING_CACHE_CAP.to_string(),
    );
    let no_cache_env_set = std::env::var("BONSAI_NO_CACHE")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"));
    print_kv(
        "BONSAI_NO_CACHE env",
        if no_cache_env_set {
            "set (caches disabled)"
        } else {
            "unset"
        },
    );
    if stats.bonsai_dir_exists {
        print_kv(
            "on-disk cache dir",
            &format!("{} ({} bytes)", stats.bonsai_dir.display(), stats.total_bytes),
        );
    } else {
        print_kv(
            "on-disk cache dir",
            &format!("{} (does not exist)", stats.bonsai_dir.display()),
        );
    }
    print_kv(
        "manifest freshness",
        freshness_summary(stats.validation.manifest_status, None).as_str(),
    );
    print_kv(
        "semantic cache",
        if stats.validation.semantic_ready {
            "fresh"
        } else {
            "not ready"
        },
    );
    print_kv(
        "dataflow cache",
        if stats.validation.legacy_dataflow_ready {
            "fresh"
        } else {
            "not ready"
        },
    );
    print_kv(
        "taint graph cache",
        if stats.validation.taint_graph_ready {
            "fresh"
        } else {
            "not ready"
        },
    );
    print_kv(
        "export cache",
        if stats.validation.export_ready {
            "fresh"
        } else {
            "not ready"
        },
    );
    print_validated_artifact(
        &print_kv,
        "cache manifest",
        &stats.manifest,
        stats.manifest_exists,
        stats.manifest_bytes,
        stats.validation.manifest_status,
        manifest_status_reason(&stats),
    );
    // Itemise the dataflow sidecar specifically — it's the
    // expensive artifact users actually want to reason about.
    print_validated_sidecar(
        &print_kv,
        "dataflow legacy sidecar",
        &stats.dataflow_sidecar,
        stats.dataflow_sidecar_exists,
        stats.dataflow_sidecar_bytes,
        validation_sidecar(&stats, "dataflow_legacy"),
    );
    print_validated_sidecar(
        &print_kv,
        "dataflow factstore",
        &stats.dataflow_factstore_sidecar,
        stats.dataflow_factstore_sidecar_exists,
        stats.dataflow_factstore_sidecar_bytes,
        validation_sidecar(&stats, "dataflow_factstore"),
    );
    print_validated_sidecar(
        &print_kv,
        "value-flow factstore",
        &stats.value_flow_sidecar,
        stats.value_flow_sidecar_exists,
        stats.value_flow_sidecar_bytes,
        validation_sidecar(&stats, "value_flow"),
    );
    print_validated_sidecar(
        &print_kv,
        "flow-id factstore",
        &stats.flow_ids_sidecar,
        stats.flow_ids_sidecar_exists,
        stats.flow_ids_sidecar_bytes,
        validation_sidecar(&stats, "flow_ids"),
    );
    print_validated_sidecar(
        &print_kv,
        "compiler objects",
        &stats.compiler_object_sidecar,
        stats.compiler_object_sidecar_exists,
        stats.compiler_object_sidecar_bytes,
        validation_sidecar(&stats, "compiler_objects"),
    );
    print_validated_sidecar(
        &print_kv,
        "callgraph sidecar",
        &stats.callgraph_sidecar,
        stats.callgraph_sidecar_exists,
        stats.callgraph_sidecar_bytes,
        validation_sidecar(&stats, "callgraph"),
    );
    print_validated_sidecar(
        &print_kv,
        "compiler linkage sidecar",
        &stats.linkage_sidecar,
        stats.linkage_sidecar_exists,
        stats.linkage_sidecar_bytes,
        validation_sidecar(&stats, "linkage"),
    );
    print_validated_sidecar(
        &print_kv,
        "IDG factstore",
        &stats.idg_sidecar,
        stats.idg_sidecar_exists,
        stats.idg_sidecar_bytes,
        validation_sidecar(&stats, "idg"),
    );
    print_validated_sidecar(
        &print_kv,
        "retrieval factstore",
        &stats.retrieval_sidecar,
        stats.retrieval_sidecar_exists,
        stats.retrieval_sidecar_bytes,
        validation_sidecar(&stats, "retrieval"),
    );
    print_validated_sidecar(
        &print_kv,
        "taint-graph factstore",
        &stats.taint_graph_sidecar,
        stats.taint_graph_sidecar_exists,
        stats.taint_graph_sidecar_bytes,
        validation_sidecar(&stats, "taint_graph"),
    );
    print_validated_sidecar(
        &print_kv,
        "export sidecar",
        &stats.export_sidecar,
        stats.export_sidecar_exists,
        stats.export_sidecar_bytes,
        validation_sidecar(&stats, "export_default"),
    );
    cli_println!();
    for line in ui.wrapped_dim_prefixed_lines(
        "note: ",
        &ui.dim("note: "),
        "      ",
        "in-process caches drop at process exit; use --no-cache on any command to \
                 bypass them within a single run. The dataflow sidecar persists workspace \
                 taint facts across runs, and the export sidecar persists the default export \
                 JSON — delete via `cache clear` or rebuild via `cache rebuild`.",
    ) {
        cli_println!("{line}");
    }
    Ok(())
}

fn cache_clear(workspace: Option<std::path::PathBuf>, dataflow_only: bool) -> Result<()> {
    let ui = ui();
    let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
    let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root).with_discovered_rulepack_root();
    let stage = progress::ScopedSpinner::new("reading cache metadata");
    let stats = cache.stats()?;
    stage.finish();
    if dataflow_only {
        // Remove just the dataflow sidecar, leaving the rest
        // of `.bonsai/` intact.
        if stats.dataflow_sidecar_exists || stats.dataflow_factstore_sidecar_exists {
            let freed = stats
                .dataflow_sidecar_bytes
                .saturating_add(stats.dataflow_factstore_sidecar_bytes);
            let clear_stage = progress::ScopedSpinner::new("clearing dataflow cache");
            cache
                .clear_dataflow_only()
                .with_context(|| format!("removing {}", stats.dataflow_sidecar.display()))?;
            clear_stage.finish();
            if stats.dataflow_sidecar_exists {
                print_kv("removed", &stats.dataflow_sidecar.display().to_string());
            }
            if stats.dataflow_factstore_sidecar_exists {
                print_kv("removed", &stats.dataflow_factstore_sidecar.display().to_string());
            }
            print_kv("freed", &format!("{freed} bytes"));
        } else {
            print_kv(
                "dataflow sidecars",
                &format!(
                    "{}, {} (nothing to clear)",
                    stats.dataflow_factstore_sidecar.display(),
                    stats.dataflow_sidecar.display()
                ),
            );
        }
    } else if stats.bonsai_dir_exists {
        let freed_bytes = stats.total_bytes;
        // List individual artifacts so the user can see
        // exactly what got removed.
        if stats.dataflow_sidecar_exists {
            print_kv(
                "  dataflow legacy sidecar",
                &stats.dataflow_sidecar.display().to_string(),
            );
        }
        if stats.dataflow_factstore_sidecar_exists {
            print_kv(
                "  dataflow factstore",
                &stats.dataflow_factstore_sidecar.display().to_string(),
            );
        }
        print_existing_sidecar(
            &print_kv,
            "  value-flow factstore",
            &stats.value_flow_sidecar,
            stats.value_flow_sidecar_exists,
        );
        print_existing_sidecar(
            &print_kv,
            "  flow-id factstore",
            &stats.flow_ids_sidecar,
            stats.flow_ids_sidecar_exists,
        );
        print_existing_sidecar(
            &print_kv,
            "  compiler objects",
            &stats.compiler_object_sidecar,
            stats.compiler_object_sidecar_exists,
        );
        print_existing_sidecar(
            &print_kv,
            "  callgraph sidecar",
            &stats.callgraph_sidecar,
            stats.callgraph_sidecar_exists,
        );
        print_existing_sidecar(
            &print_kv,
            "  compiler linkage sidecar",
            &stats.linkage_sidecar,
            stats.linkage_sidecar_exists,
        );
        print_existing_sidecar(
            &print_kv,
            "  IDG factstore",
            &stats.idg_sidecar,
            stats.idg_sidecar_exists,
        );
        print_existing_sidecar(
            &print_kv,
            "  retrieval factstore",
            &stats.retrieval_sidecar,
            stats.retrieval_sidecar_exists,
        );
        print_existing_sidecar(
            &print_kv,
            "  taint-graph factstore",
            &stats.taint_graph_sidecar,
            stats.taint_graph_sidecar_exists,
        );
        if stats.export_sidecar_exists {
            print_kv("  export sidecar", &stats.export_sidecar.display().to_string());
        }
        if stats.manifest_exists {
            print_kv("  cache manifest", &stats.manifest.display().to_string());
        }
        let clear_stage = progress::ScopedSpinner::new("clearing workspace cache");
        cache
            .clear_all()
            .with_context(|| format!("removing {}", stats.bonsai_dir.display()))?;
        clear_stage.finish();
        print_kv("removed", &stats.bonsai_dir.display().to_string());
        print_kv("freed", &format!("{freed_bytes} bytes"));
    } else {
        print_kv(
            "on-disk cache",
            &format!("{} (nothing to clear)", stats.bonsai_dir.display()),
        );
    }
    cli_println!();
    cli_println!(
        "{}",
        ui.dim(
            "note: in-process caches are per-run and drop at exit — no \
                     action needed there. To bypass them on the next command, \
                     pass --no-cache or set BONSAI_NO_CACHE=1."
        )
    );
    Ok(())
}

fn cache_rebuild(workspace: Option<std::path::PathBuf>, warm_export: bool) -> Result<()> {
    let ui = ui();
    let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
    let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root).with_discovered_rulepack_root();
    let stage = progress::ScopedSpinner::new("reading cache metadata");
    let stats = cache.stats()?;
    stage.finish();
    if stats.bonsai_dir_exists {
        let freed = stats.total_bytes;
        let clear_stage = progress::ScopedSpinner::new("clearing stale cache");
        cache
            .clear_all()
            .with_context(|| format!("removing {}", stats.bonsai_dir.display()))?;
        clear_stage.finish();
        print_kv("removed stale cache", &stats.bonsai_dir.display().to_string());
        print_kv("freed", &format!("{freed} bytes"));
    }

    // Refresh each exact compiler phase in its own worker process. This is the
    // same frontend-artifact -> IDG pipeline used by `index --semantic`; the
    // OS reclaims Tree-sitter and allocator arenas between phases instead of
    // making their peaks additive. No source, edge, or fixed-point cap is
    // involved.
    print_kv("rebuilding", &workspace_root.display().to_string());
    let spin = progress::ScopedSpinner::new("warming structural compiler sidecars");
    super::diagnostics::run_semantic_workers(&workspace_root)?;
    spin.finish();

    if warm_export {
        let (project, _footer) = open_project_index_only(&workspace_root)?;
        let spin = progress::ScopedSpinner::new("warming export cache");
        warm_export_cache_for_project(&project)?;
        spin.finish();
    }

    let spin = progress::ScopedSpinner::new("writing cache manifest");
    let _manifest = cache.write_manifest()?;
    spin.finish();

    let rebuilt = cache.stats()?;
    print_sidecar(
        &print_kv,
        "wrote compiler objects",
        &rebuilt.compiler_object_sidecar,
        rebuilt.compiler_object_sidecar_exists,
        rebuilt.compiler_object_sidecar_bytes,
    );
    print_sidecar(
        &print_kv,
        "wrote callgraph sidecar",
        &rebuilt.callgraph_sidecar,
        rebuilt.callgraph_sidecar_exists,
        rebuilt.callgraph_sidecar_bytes,
    );
    print_sidecar(
        &print_kv,
        "wrote compiler linkage sidecar",
        &rebuilt.linkage_sidecar,
        rebuilt.linkage_sidecar_exists,
        rebuilt.linkage_sidecar_bytes,
    );
    print_sidecar(
        &print_kv,
        "wrote IDG factstore",
        &rebuilt.idg_sidecar,
        rebuilt.idg_sidecar_exists,
        rebuilt.idg_sidecar_bytes,
    );
    print_sidecar(
        &print_kv,
        "wrote retrieval factstore",
        &rebuilt.retrieval_sidecar,
        rebuilt.retrieval_sidecar_exists,
        rebuilt.retrieval_sidecar_bytes,
    );
    if warm_export {
        print_sidecar(
            &print_kv,
            "wrote export sidecar",
            &rebuilt.export_sidecar,
            rebuilt.export_sidecar_exists,
            rebuilt.export_sidecar_bytes,
        );
    } else {
        print_kv("export sidecar", "not warmed (pass --export)");
    }
    print_sidecar(
        &print_kv,
        "wrote cache manifest",
        &rebuilt.manifest,
        rebuilt.manifest_exists,
        rebuilt.manifest_bytes,
    );
    cli_println!();
    for line in ui.wrapped_dim_prefixed_lines(
        "note: ",
        &ui.dim("note: "),
        "      ",
        "cache rebuild refreshes reusable structural sidecars. The export JSON cache is \
                 warmed only with --export. Exact taint/source/security commands still compute \
                 their requested scope before rendering; caches only make that work faster when \
                 fresh.",
    ) {
        cli_println!("{line}");
    }
    Ok(())
}

fn print_existing_sidecar<F>(print_kv: &F, label: &str, path: &std::path::Path, exists: bool)
where
    F: Fn(&str, &str),
{
    if exists {
        print_kv(label, &path.display().to_string());
    }
}

fn print_sidecar<F>(print_kv: &F, label: &str, path: &std::path::Path, exists: bool, bytes: u64)
where
    F: Fn(&str, &str),
{
    if exists {
        print_kv(label, &format!("{} ({} bytes)", path.display(), bytes));
    } else {
        print_kv(label, &format!("{} (not present)", path.display()));
    }
}

fn print_validated_sidecar<F>(
    print_kv: &F,
    label: &str,
    path: &std::path::Path,
    exists: bool,
    bytes: u64,
    validation: Option<&bonsai_sdk::CacheSidecarValidation>,
) where
    F: Fn(&str, &str),
{
    let (status, reason) = validation
        .map(|validation| (validation.status, validation.reason.as_deref()))
        .unwrap_or((bonsai_sdk::CacheFreshnessStatus::Unvalidated, None));
    print_validated_artifact(print_kv, label, path, exists, bytes, status, reason);
}

fn print_validated_artifact<F>(
    print_kv: &F,
    label: &str,
    path: &std::path::Path,
    exists: bool,
    bytes: u64,
    status: bonsai_sdk::CacheFreshnessStatus,
    reason: Option<&str>,
) where
    F: Fn(&str, &str),
{
    let reason = visible_freshness_reason(status, reason);
    let details = if exists {
        format!(
            "{} ({} bytes; {})",
            path.display(),
            bytes,
            freshness_summary(status, reason)
        )
    } else {
        format!(
            "{} (not present; {})",
            path.display(),
            freshness_summary(status, reason)
        )
    };
    print_kv(label, &details);
}

fn validation_sidecar<'a>(
    stats: &'a bonsai_sdk::CacheStats,
    name: &str,
) -> Option<&'a bonsai_sdk::CacheSidecarValidation> {
    stats
        .validation
        .sidecars
        .iter()
        .find(|sidecar| sidecar.name == name)
}

fn freshness_summary(status: bonsai_sdk::CacheFreshnessStatus, reason: Option<&str>) -> String {
    match reason {
        Some(reason) if !reason.is_empty() => format!("{}: {reason}", status.as_str()),
        _ => status.as_str().to_string(),
    }
}

fn visible_freshness_reason(status: bonsai_sdk::CacheFreshnessStatus, reason: Option<&str>) -> Option<&str> {
    match status {
        bonsai_sdk::CacheFreshnessStatus::Stale
        | bonsai_sdk::CacheFreshnessStatus::Unvalidated
        | bonsai_sdk::CacheFreshnessStatus::Error
        | bonsai_sdk::CacheFreshnessStatus::NotApplicable => reason,
        bonsai_sdk::CacheFreshnessStatus::Fresh | bonsai_sdk::CacheFreshnessStatus::Missing => None,
    }
}

fn manifest_status_reason(stats: &bonsai_sdk::CacheStats) -> Option<&str> {
    if matches!(
        stats.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Stale
            | bonsai_sdk::CacheFreshnessStatus::Unvalidated
            | bonsai_sdk::CacheFreshnessStatus::Error
    ) {
        stats.validation.stale_reasons.first().map(String::as_str)
    } else {
        None
    }
}
