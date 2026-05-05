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

use crate::args::CacheAction;
use crate::progress;
use crate::{cli_println, ui};

use super::export::warm_export_cache_for_project;
use super::open_project_full;

/// Handler for `bonsai-ninja cache <stats|clear|rebuild>`. Operates
/// on the on-disk `.bonsai/` cache under the target workspace.
/// In-process chain caches are per-run and drop at exit; this handler
/// always reminds the user of that in its final "note" line so nobody
/// mistakes `cache clear` for an in-memory reset.
pub(crate) fn cmd_cache(action: CacheAction) -> Result<()> {
    let ui = ui();
    let print_kv = |key: &str, value: &str| {
        cli_println!("{}  {}", ui.label(&format!("{key:>26}")), value);
    };
    match action {
        CacheAction::Stats { workspace } => {
            let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
            let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root);
            let stats = cache.stats()?;
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
            // Itemise the dataflow sidecar specifically — it's the
            // expensive artifact users actually want to reason about.
            if stats.dataflow_sidecar_exists {
                print_kv(
                    "dataflow sidecar",
                    &format!(
                        "{} ({} bytes)",
                        stats.dataflow_sidecar.display(),
                        stats.dataflow_sidecar_bytes
                    ),
                );
            } else {
                print_kv(
                    "dataflow sidecar",
                    &format!("{} (not present)", stats.dataflow_sidecar.display()),
                );
            }
            if stats.export_sidecar_exists {
                print_kv(
                    "export sidecar",
                    &format!(
                        "{} ({} bytes)",
                        stats.export_sidecar.display(),
                        stats.export_sidecar_bytes
                    ),
                );
            } else {
                print_kv(
                    "export sidecar",
                    &format!("{} (not present)", stats.export_sidecar.display()),
                );
            }
            cli_println!();
            cli_println!(
                "{}",
                ui.dim(
                    "note: in-process caches drop at process exit; use --no-cache \
                     on any command to bypass them within a single run. The dataflow \
                     sidecar persists workspace taint facts across runs, and the export \
                     sidecar persists the default export JSON — delete via `cache clear` \
                     or rebuild via `cache rebuild`."
                )
            );
            Ok(())
        }
        CacheAction::Clear {
            workspace,
            dataflow_only,
        } => {
            let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
            let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root);
            if dataflow_only {
                // Remove just the dataflow sidecar, leaving the rest
                // of `.bonsai/` intact.
                let stats = cache.stats()?;
                if stats.dataflow_sidecar_exists {
                    let freed = stats.dataflow_sidecar_bytes;
                    cache
                        .clear_dataflow_only()
                        .with_context(|| format!("removing {}", stats.dataflow_sidecar.display()))?;
                    print_kv("removed", &stats.dataflow_sidecar.display().to_string());
                    print_kv("freed", &format!("{freed} bytes"));
                } else {
                    print_kv(
                        "dataflow sidecar",
                        &format!("{} (nothing to clear)", stats.dataflow_sidecar.display()),
                    );
                }
            } else {
                let stats = cache.stats()?;
                if stats.bonsai_dir_exists {
                    let freed_bytes = stats.total_bytes;
                    // List individual artifacts so the user can see
                    // exactly what got removed.
                    if stats.dataflow_sidecar_exists {
                        print_kv(
                            "  dataflow sidecar",
                            &stats.dataflow_sidecar.display().to_string(),
                        );
                    }
                    if stats.export_sidecar_exists {
                        print_kv("  export sidecar", &stats.export_sidecar.display().to_string());
                    }
                    cache
                        .clear_all()
                        .with_context(|| format!("removing {}", stats.bonsai_dir.display()))?;
                    print_kv("removed", &stats.bonsai_dir.display().to_string());
                    print_kv("freed", &format!("{freed_bytes} bytes"));
                } else {
                    print_kv(
                        "on-disk cache",
                        &format!("{} (nothing to clear)", stats.bonsai_dir.display()),
                    );
                }
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
        CacheAction::Rebuild { workspace } => {
            let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
            let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root);
            let stats = cache.stats()?;
            let sidecar = stats.dataflow_sidecar.clone();
            let export_sidecar = stats.export_sidecar.clone();
            // Step 1: drop the persisted sidecar so the SDK open
            // can't rehydrate a stale entry.
            if stats.dataflow_sidecar_exists {
                let freed = stats.dataflow_sidecar_bytes;
                cache
                    .clear_dataflow_only()
                    .with_context(|| format!("removing {}", sidecar.display()))?;
                print_kv("removed stale sidecar", &sidecar.display().to_string());
                print_kv("freed", &format!("{freed} bytes"));
            }
            if stats.export_sidecar_exists {
                let freed = stats.export_sidecar_bytes;
                std::fs::remove_file(&export_sidecar)
                    .with_context(|| format!("removing {}", export_sidecar.display()))?;
                print_kv("removed stale export", &export_sidecar.display().to_string());
                print_kv("freed", &format!("{freed} bytes"));
            }
            // Step 2: open the workspace — this runs full indexing +
            // `prewarm_all` + writes the sidecar back. Open emits its
            // own progress (ingest spinner, parse bar, dataflow bar);
            // the post-open warm phases below are silent so we wrap
            // them in spinners.
            print_kv("rebuilding", &workspace_root.display().to_string());
            let (project, _footer) = open_project_full(&workspace_root)?;
            let entries_now = project.workspace().dataflow().len();
            let spin = progress::spinner("writing dataflow sidecar");
            project
                .save_dataflow_sidecar()
                .with_context(|| format!("writing {}", sidecar.display()))?;
            spin.finish_and_clear();
            let size = std::fs::metadata(&sidecar).map(|m| m.len()).unwrap_or(0);
            print_kv("wrote sidecar", &sidecar.display().to_string());
            print_kv("entries", &entries_now.to_string());
            print_kv("size", &format!("{size} bytes"));
            let spin = progress::spinner("warming export cache");
            warm_export_cache_for_project(&project)?;
            spin.finish_and_clear();
            let export_size = project.cache().stats()?.export_sidecar_bytes;
            print_kv("wrote export sidecar", &export_sidecar.display().to_string());
            print_kv("export size", &format!("{export_size} bytes"));
            cli_println!();
            cli_println!(
                "{}",
                ui.dim(
                    "note: future opens of this workspace will load this sidecar \
                     and default export can stream the warmed export sidecar."
                )
            );
            Ok(())
        }
    }
}
