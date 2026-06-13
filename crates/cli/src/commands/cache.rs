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
    let ui = ui();
    let print_kv = |key: &str, value: &str| {
        cli_println!("{}  {}", ui.label(&format!("{key:>26}")), value);
    };
    match action {
        CacheAction::Stats {
            workspace,
            format,
            output: _,
        } => {
            let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
            let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root);
            let stats = cache.stats()?;
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
            // Itemise the dataflow sidecar specifically — it's the
            // expensive artifact users actually want to reason about.
            if stats.dataflow_sidecar_exists {
                print_kv(
                    "dataflow legacy sidecar",
                    &format!(
                        "{} ({} bytes)",
                        stats.dataflow_sidecar.display(),
                        stats.dataflow_sidecar_bytes
                    ),
                );
            } else {
                print_kv(
                    "dataflow legacy sidecar",
                    &format!("{} (not present)", stats.dataflow_sidecar.display()),
                );
            }
            if stats.dataflow_factstore_sidecar_exists {
                print_kv(
                    "dataflow factstore",
                    &format!(
                        "{} ({} bytes)",
                        stats.dataflow_factstore_sidecar.display(),
                        stats.dataflow_factstore_sidecar_bytes
                    ),
                );
            } else {
                print_kv(
                    "dataflow factstore",
                    &format!("{} (not present)", stats.dataflow_factstore_sidecar.display()),
                );
            }
            print_sidecar(
                &print_kv,
                "value-flow factstore",
                &stats.value_flow_sidecar,
                stats.value_flow_sidecar_exists,
                stats.value_flow_sidecar_bytes,
            );
            print_sidecar(
                &print_kv,
                "flow-id factstore",
                &stats.flow_ids_sidecar,
                stats.flow_ids_sidecar_exists,
                stats.flow_ids_sidecar_bytes,
            );
            print_sidecar(
                &print_kv,
                "callgraph sidecar",
                &stats.callgraph_sidecar,
                stats.callgraph_sidecar_exists,
                stats.callgraph_sidecar_bytes,
            );
            print_sidecar(
                &print_kv,
                "IDG factstore",
                &stats.idg_sidecar,
                stats.idg_sidecar_exists,
                stats.idg_sidecar_bytes,
            );
            print_sidecar(
                &print_kv,
                "taint-graph factstore",
                &stats.taint_graph_sidecar,
                stats.taint_graph_sidecar_exists,
                stats.taint_graph_sidecar_bytes,
            );
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
                if stats.dataflow_sidecar_exists || stats.dataflow_factstore_sidecar_exists {
                    let freed = stats
                        .dataflow_sidecar_bytes
                        .saturating_add(stats.dataflow_factstore_sidecar_bytes);
                    cache
                        .clear_dataflow_only()
                        .with_context(|| format!("removing {}", stats.dataflow_sidecar.display()))?;
                    if stats.dataflow_sidecar_exists {
                        print_kv("removed", &stats.dataflow_sidecar.display().to_string());
                    }
                    if stats.dataflow_factstore_sidecar_exists {
                        print_kv("removed", &stats.dataflow_factstore_sidecar.display().to_string());
                    }
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
                        "  callgraph sidecar",
                        &stats.callgraph_sidecar,
                        stats.callgraph_sidecar_exists,
                    );
                    print_existing_sidecar(
                        &print_kv,
                        "  IDG factstore",
                        &stats.idg_sidecar,
                        stats.idg_sidecar_exists,
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
        CacheAction::Rebuild {
            workspace,
            export: warm_export,
        } => {
            let workspace_root = workspace.unwrap_or(std::env::current_dir()?);
            let cache = bonsai_sdk::WorkspaceCache::new(&workspace_root);
            let stats = cache.stats()?;
            if stats.bonsai_dir_exists {
                let freed = stats.total_bytes;
                cache
                    .clear_all()
                    .with_context(|| format!("removing {}", stats.bonsai_dir.display()))?;
                print_kv("removed stale cache", &stats.bonsai_dir.display().to_string());
                print_kv("freed", &format!("{freed} bytes"));
            }

            // Open structurally, then refresh bounded reusable
            // sidecars explicitly. Do not route through a full
            // workspace prewarm path here: that computes
            // dataflow/value-flow/flow-id caches and can retain
            // gigabytes on broad workspaces. Exact taint and
            // source-analysis commands compute their requested scope
            // when invoked; cache rebuild only prepares structural
            // artifacts those exact commands can reuse.
            print_kv("rebuilding", &workspace_root.display().to_string());
            let (project, _footer) = open_project_index_only(&workspace_root)?;
            let workspace = project.workspace();

            let spin = progress::spinner("warming callgraph sidecar");
            let _ = workspace.cached_resolved_call_graph();
            workspace
                .save_callgraph_sidecar(&workspace_root)
                .with_context(|| format!("writing {}", stats.callgraph_sidecar.display()))?;
            spin.finish_and_clear();

            let spin = progress::spinner("warming IDG sidecar");
            let _ = workspace.build_and_seed_idg_service();
            spin.finish_and_clear();

            if warm_export {
                let spin = progress::spinner("warming export cache");
                warm_export_cache_for_project(&project)?;
                spin.finish_and_clear();
            }

            let rebuilt = project.cache().stats()?;
            print_sidecar(
                &print_kv,
                "wrote callgraph sidecar",
                &rebuilt.callgraph_sidecar,
                rebuilt.callgraph_sidecar_exists,
                rebuilt.callgraph_sidecar_bytes,
            );
            print_sidecar(
                &print_kv,
                "wrote IDG factstore",
                &rebuilt.idg_sidecar,
                rebuilt.idg_sidecar_exists,
                rebuilt.idg_sidecar_bytes,
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
            cli_println!();
            cli_println!(
                "{}",
                ui.dim(
                    "note: cache rebuild refreshes bounded structural sidecars. \
                     The export JSON cache is warmed only with --export. \
                     Exact taint/source/security commands still compute their \
                     requested scope before rendering; caches only make that \
                     work faster when fresh."
                )
            );
            Ok(())
        }
    }
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
