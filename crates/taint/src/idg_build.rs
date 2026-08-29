//! Database-level IDG construction.
//!
//! The IDG query service is normally built and cached at the
//! `Workspace` open path (`Workspace::build_and_seed_idg_service`,
//! which adds on-disk sidecar persistence and content fingerprinting).
//! But the public taint API — `interprocedural_taint`,
//! `call_site_receives_taint`, and the inspect/value-flow fallbacks —
//! takes a bare `&AnalyzerDb`, and unit-test fixtures construct only a
//! db, never a full `Workspace`. Those callers historically fell back
//! to a *second* taint engine (the interprocedural worklist) when
//! `db.idg_service()` was `None`.
//!
//! To collapse the two engines into one, this module builds the IDG
//! directly from a db — the same core construction the workspace path
//! performs, minus the sidecar/fingerprint machinery — and caches it on
//! the db so every taint surface queries a single graph. Every input
//! (`global_index`, resolved call graph, per-file alias maps, language
//! ids, paths) is derivable from the db, and `crates/taint` already
//! depends on every crate involved, so no layering is violated.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use bonsai_db::AnalyzerDb;
use bonsai_idg::IdgQueryService;

struct CompilerIdgFileSemantics<'a> {
    db: &'a AnalyzerDb,
}

impl bonsai_idg::workspace_adapter::IdgFileSemanticsProvider for CompilerIdgFileSemantics<'_> {
    fn aliases(&mut self, file: bonsai_common::FileId) -> ahash::AHashMap<String, String> {
        bonsai_resolve::semantic_import_binding_map_for_file(&self.db.imports_for_uncached(file))
    }

    fn language(&self, file: bonsai_common::FileId) -> Option<&'static str> {
        self.db
            .adapter_for(file)
            .map(|adapter| adapter.language_id().as_str())
    }

    fn capabilities(&self, file: bonsai_common::FileId) -> bonsai_lang_api::LanguageCapabilities {
        self.db
            .adapter_for(file)
            .map(|adapter| adapter.capabilities())
            .unwrap_or_else(bonsai_lang_api::LanguageCapabilities::unsupported)
    }

    fn path(&self, file: bonsai_common::FileId) -> Option<String> {
        self.db
            .vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }

    fn source_bytes(&self, file: bonsai_common::FileId) -> Option<u64> {
        self.db
            .vfs()
            .snapshot(file)
            .ok()
            .map(|snapshot| u64::try_from(snapshot.text.len()).unwrap_or(u64::MAX))
    }

    fn module_resolution_extensions(&self, file: bonsai_common::FileId) -> &'static [&'static str] {
        self.db
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().module_resolution_extensions)
            .unwrap_or(&[])
    }

    fn module_default_export_names(&self, file: bonsai_common::FileId) -> &'static [&'static str] {
        self.db
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().module_default_export_names)
            .unwrap_or(&[])
    }

    fn module_path_syntax(&self, file: bonsai_common::FileId) -> bonsai_lang_api::ModulePathSyntax {
        self.db
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().module_path_syntax)
            .unwrap_or_else(bonsai_lang_api::ModulePathSyntax::none)
    }
}

/// Return the canonical adapter/VFS compiler contract for an IDG build.
pub fn compiler_idg_file_semantics(
    db: &AnalyzerDb,
) -> impl bonsai_idg::workspace_adapter::IdgFileSemanticsProvider + '_ {
    CompilerIdgFileSemantics { db }
}

/// Return the workspace IDG query service, building and caching it on
/// the db if it has not been seeded yet. Idempotent and thread-safe: a
/// peer thread that seeds the slot first wins, and its service is
/// returned instead of a duplicate build.
///
/// This is the single entry point that lets the taint engine query the
/// IDG from any `&AnalyzerDb`, including the bare-db unit-test path,
/// removing the need for a fallback engine when the service is absent.
#[must_use]
pub fn ensure_idg_service(db: &AnalyzerDb) -> Arc<IdgQueryService> {
    if let Some(service) = db.idg_service() {
        return service;
    }
    // Match the canonical workspace/compiler graph. Adapter capability facts
    // select symbolic access paths; no command facade maintains its own
    // language or API inventory.
    let transfer_options =
        bonsai_idg::TransferOptions::compiler_semantics(db.complete_field_place_languages());
    let service = configured_idg_service(db, &transfer_options);
    // Bare-db tests do not have a Workspace to seed the default slot. Publish
    // the same service there so subsequent taint/export facades share it.
    if let Some(established) = db.idg_service() {
        return established;
    }
    db.set_idg_service(Arc::clone(&service));
    service
}

/// Return the canonical compiler IDG without publishing it as the workspace's
/// explicitly warmed service.
///
/// The persisted dataflow facade uses this path on a cache miss: it still
/// executes the one IDG engine, while `syntax_flow_graph` can truthfully keep
/// its lifecycle contract that a cold inspect query does not warm the
/// workspace IDG slot. The semantic-fingerprint cache shares the build across
/// subsequent dataflow misses.
#[must_use]
pub fn compiler_idg_service(db: &AnalyzerDb) -> Arc<IdgQueryService> {
    if let Some(service) = db.idg_service() {
        return service;
    }
    let transfer_options =
        bonsai_idg::TransferOptions::compiler_semantics(db.complete_field_place_languages());
    configured_idg_service(db, &transfer_options)
}

/// Build a configured IDG for a public API call that supplied
/// transfer-time source/overwrite shapes. These shapes change graph edges,
/// so this variant deliberately does not replace the database's shared
/// service: a later caller may use a different configuration.
pub(crate) fn idg_service_for_inter_config(
    db: &AnalyzerDb,
    config: &crate::idg_api::InterTaintConfig,
) -> Arc<IdgQueryService> {
    if config.clean_output_overwrites.is_empty()
        && config.clean_receiver_overwrites.is_empty()
        && config.source_output_args.is_empty()
        && config.source_callback_args.is_empty()
        && config.callback_invocations.is_empty()
        && config.call_result_passthroughs.is_empty()
        && config.output_arg_flows.is_empty()
        && config.receiver_state_propagations.is_empty()
    {
        return ensure_idg_service(db);
    }
    let compiler_options =
        bonsai_idg::TransferOptions::compiler_semantics(db.complete_field_place_languages());
    let transfer_options = bonsai_idg::TransferOptions {
        clean_output_overwrites: config
            .clean_output_overwrites
            .iter()
            .map(|shape| bonsai_idg::CleanOutputOverwriteSpec {
                callee: shape.callee.clone(),
                output_arg_index: shape.output_arg_index,
                value_start_arg_index: shape.value_start_arg_index,
            })
            .collect(),
        clean_receiver_overwrites: config
            .clean_receiver_overwrites
            .iter()
            .map(|shape| bonsai_idg::CleanReceiverOverwriteSpec {
                callee: shape.callee.clone(),
                resolved_call_sites: shape.resolved_call_sites.clone(),
            })
            .collect(),
        source_output_args: config
            .source_output_args
            .iter()
            .map(|shape| bonsai_idg::SourceOutputArgSpec {
                callee: shape.callee.clone(),
                output_arg_indices: shape.output_arg_indices.clone(),
                output_arg_start_index: shape.output_arg_start_index,
                resolved_call_sites: shape.resolved_call_sites.clone(),
            })
            .collect(),
        source_callback_args: config
            .source_callback_args
            .iter()
            .map(|shape| bonsai_idg::SourceCallbackArgSpec {
                callee: shape.callee.clone(),
                callback_arg_index: shape.callback_arg_index,
                source_param_indices: shape.source_param_indices.clone(),
                source_param_indices_from: shape.source_param_indices_from,
                resolved_call_sites: shape.resolved_call_sites.clone(),
            })
            .collect(),
        callback_invocations: config
            .callback_invocations
            .iter()
            .map(|shape| bonsai_idg::CallbackInvocationSpec {
                callee: shape.callee.clone(),
                callback_arg_index: shape.callback_arg_index,
                callback_map_field_path: shape.callback_map_field_path.clone(),
                forwarded_argument_field_path: shape.forwarded_argument_field_path.clone(),
                forwarded_callback_param_index: shape.forwarded_callback_param_index,
                forwarded_args_from: shape.forwarded_args_from,
                receiver_to_callback_param: shape.receiver_to_callback_param,
                callback_return_result_offset: shape.callback_return_result_offset,
                resolved_call_sites: shape.resolved_call_sites.clone(),
                resolved_callback_targets: shape.resolved_callback_targets.clone(),
            })
            .collect(),
        call_result_passthroughs: config
            .call_result_passthroughs
            .iter()
            .map(|shape| bonsai_idg::CallResultPassthroughSpec {
                callee: shape.callee.clone(),
                receiver_type: shape.receiver_type.clone(),
                input_arg_indices: shape.input_arg_indices.clone(),
                input_arg_start_index: shape.input_arg_start_index,
                input_receiver: shape.input_receiver,
                resolved_call_sites: shape.resolved_call_sites.clone(),
            })
            .collect(),
        output_arg_flows: config
            .output_arg_flows
            .iter()
            .map(|shape| bonsai_idg::OutputArgFlowSpec {
                callee: shape.callee.clone(),
                output_arg_index: shape.output_arg_index,
                input_receiver: shape.input_receiver,
                value_arg_indices: shape.value_arg_indices.clone(),
                value_start_arg_index: shape.value_start_arg_index,
                resolved_call_sites: shape.resolved_call_sites.clone(),
            })
            .collect(),
        receiver_state_propagations: config
            .receiver_state_propagations
            .iter()
            .map(|shape| bonsai_idg::ReceiverStatePropagationSpec {
                method: shape.method.clone(),
                receiver_type: shape.receiver_type.clone(),
                resolved_call_sites: shape.resolved_call_sites.clone(),
            })
            .collect(),
        include_diagnostic_field_flows: compiler_options.include_diagnostic_field_flows,
        include_receiver_method_propagation: compiler_options.include_receiver_method_propagation,
        include_field_argument_forwarding: compiler_options.include_field_argument_forwarding,
        symbolic_field_forwarding: compiler_options.symbolic_field_forwarding,
        symbolic_field_languages: compiler_options.symbolic_field_languages,
        include_unresolved_call_result_passthrough: compiler_options
            .include_unresolved_call_result_passthrough,
        include_unresolved_receiver_result_passthrough: compiler_options
            .include_unresolved_receiver_result_passthrough,
    }
    .canonicalized();
    configured_idg_service(db, &transfer_options)
}

fn configured_idg_service(
    db: &AnalyzerDb,
    transfer_options: &bonsai_idg::TransferOptions,
) -> Arc<IdgQueryService> {
    let transfer_options = transfer_options.clone().canonicalized();
    let fingerprint = transfer_options.semantic_fingerprint();
    db.get_or_init_idg_service_for_semantics(fingerprint, || build_idg_service(db, &transfer_options))
}

fn build_idg_service(
    db: &AnalyzerDb,
    transfer_options: &bonsai_idg::TransferOptions,
) -> Arc<IdgQueryService> {
    let global = db.build_global_linkage_index();
    // Resolve calls against the same immutable linkage headers the IDG will
    // retain. Building a fresh header index here duplicates complete
    // workspace lowering and can mix snapshots if a file changes mid-phase.
    let call_graph = build_resolved_call_graph_snapshot_with_headers(db, global.as_ref());
    let semantics = compiler_idg_file_semantics(db);
    let ws = bonsai_idg::workspace_adapter::build_streaming_with_file_semantics_and_options(
        global.as_ref(),
        &call_graph,
        semantics,
        transfer_options,
        |file| db.decl_index_remapped_to_headers(global.as_ref(), file),
    );
    Arc::new(IdgQueryService::new(Arc::new(ws), global))
}

/// Build the canonical resolved call graph from adapter-emitted compiler
/// facts. Workspace and IDG consumers share this facade so their syntax and
/// linkage semantics cannot drift.
pub fn build_resolved_call_graph_snapshot(db: &AnalyzerDb) -> bonsai_callgraph::ResolvedCallGraph {
    build_resolved_call_graph_snapshot_scoped(db, None)
}

/// Build the canonical resolved call graph for a subset of caller files while
/// retaining workspace-wide targets and resolution indexes.
pub fn build_resolved_call_graph_snapshot_for_files(
    db: &AnalyzerDb,
    included_files: &[bonsai_common::FileId],
) -> bonsai_callgraph::ResolvedCallGraph {
    build_resolved_call_graph_snapshot_scoped(db, Some(included_files))
}

fn build_resolved_call_graph_snapshot_scoped(
    db: &AnalyzerDb,
    included_files: Option<&[bonsai_common::FileId]>,
) -> bonsai_callgraph::ResolvedCallGraph {
    let global = db.build_global_header_index();
    build_resolved_call_graph_snapshot_with_headers_scoped(db, global.as_ref(), included_files, || {})
}

/// Build the canonical resolved call graph against an already-validated
/// workspace declaration header table.
///
/// Semantic prewarm persists those headers in the linkage artifact before
/// starting the isolated callgraph worker. Reusing them here avoids decoding
/// every compiler body once to reconstruct declarations and then a second
/// time to resolve calls. Resolver semantics are unchanged: exact file bodies
/// are still streamed from the adapter-lowered compiler objects below.
#[must_use]
pub fn build_resolved_call_graph_snapshot_with_headers(
    db: &AnalyzerDb,
    global: &bonsai_index::GlobalIndex,
) -> bonsai_callgraph::ResolvedCallGraph {
    build_resolved_call_graph_snapshot_with_headers_scoped(db, global, None, || {})
}

/// Build the canonical graph while reporting one tick after each exact caller
/// file has been fully resolved.
#[must_use]
pub fn build_resolved_call_graph_snapshot_with_headers_and_progress<Q>(
    db: &AnalyzerDb,
    global: &bonsai_index::GlobalIndex,
    on_file: Q,
) -> bonsai_callgraph::ResolvedCallGraph
where
    Q: Fn() + Sync,
{
    build_resolved_call_graph_snapshot_with_headers_scoped(db, global, None, on_file)
}

/// Return the two exact alias projections consumed by callgraph resolution
/// while decoding the adapter-owned import header only once per file.
///
/// `CallGraphFileSemantics` materializes a file's simple aliases immediately
/// before its typed alias targets. Keeping the second projection in this
/// one-row handoff avoids a second FactStore lookup/decompression for every
/// source file without retaining a workspace-sized import cache. A future
/// callgraph API that changes that pairing fails loudly here instead of
/// silently reusing another file's compiler facts.
#[allow(clippy::type_complexity)]
pub fn callgraph_alias_projection_callbacks(
    db: &AnalyzerDb,
) -> (
    impl FnMut(bonsai_common::FileId) -> ahash::AHashMap<String, String> + '_,
    impl FnMut(bonsai_common::FileId) -> ahash::AHashMap<String, bonsai_lang_api::AliasTarget> + '_,
) {
    let pending = Rc::new(RefCell::new(None));
    let pending_targets = Rc::clone(&pending);
    let aliases = move |file| {
        let imports = db.imports_for_uncached(file);
        let aliases = bonsai_resolve::alias_map_for_file(&imports);
        let targets = bonsai_lang_api::alias_map_from_import_specs(&imports)
            .into_iter()
            .collect();
        let previous = pending.replace(Some((file, targets)));
        assert!(
            previous.is_none(),
            "callgraph requested aliases for a second file before consuming the first file's typed targets"
        );
        aliases
    };
    let targets = move |file| {
        let (pending_file, targets) = pending_targets
            .take()
            .expect("callgraph requested typed alias targets before exact import aliases");
        assert_eq!(
            pending_file, file,
            "callgraph alias projections crossed compiler file identities"
        );
        targets
    };
    (aliases, targets)
}

fn build_resolved_call_graph_snapshot_with_headers_scoped<Q>(
    db: &AnalyzerDb,
    global: &bonsai_index::GlobalIndex,
    included_files: Option<&[bonsai_common::FileId]>,
    on_file: Q,
) -> bonsai_callgraph::ResolvedCallGraph
where
    Q: Fn() + Sync,
{
    match included_files {
        Some(files) => {
            let context = bonsai_callgraph::ResolvedCallGraph::build_context(
                global,
                |file| {
                    db.vfs()
                        .path(file)
                        .ok()
                        .map(|path| path.to_string_lossy().into_owned())
                },
                |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
                |file| {
                    db.adapter_for(file)
                        .map(|adapter| adapter.capabilities())
                        .unwrap_or_else(bonsai_lang_api::LanguageCapabilities::unsupported)
                },
            );
            let (aliases_for_file, alias_targets_for_file) = callgraph_alias_projection_callbacks(db);
            bonsai_callgraph::ResolvedCallGraph::build_with_file_semantics_for_files_streaming_with_context_and_progress(
                global,
                aliases_for_file,
                alias_targets_for_file,
                files,
                &context,
                |file| db.decl_index_remapped_to_headers(global, file),
                on_file,
            )
        }
        None => {
            let (aliases_for_file, alias_targets_for_file) = callgraph_alias_projection_callbacks(db);
            let semantics = bonsai_callgraph::CallGraphFileSemantics::new(
                aliases_for_file,
                alias_targets_for_file,
                |file| {
                    db.vfs()
                        .path(file)
                        .ok()
                        .map(|path| path.to_string_lossy().into_owned())
                },
                |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
                |file| {
                    db.adapter_for(file)
                        .map(|adapter| adapter.capabilities())
                        .unwrap_or_else(bonsai_lang_api::LanguageCapabilities::unsupported)
                },
            );
            bonsai_callgraph::ResolvedCallGraph::build_with_file_semantics_streaming_with_progress(
                global,
                semantics,
                |file| db.decl_index_remapped_to_headers(global, file),
                on_file,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingImportPythonAdapter {
        import_calls: Arc<AtomicUsize>,
    }

    impl bonsai_lang_api::LanguageAdapter for CountingImportPythonAdapter {
        fn language_id(&self) -> bonsai_lang_api::LanguageId {
            bonsai_lang_api::LanguageId::new("python")
        }

        fn display_name(&self) -> &'static str {
            "Python import-header counter"
        }

        fn file_extensions(&self) -> &'static [&'static str] {
            &["py"]
        }

        fn tree_sitter_language(&self) -> Result<tree_sitter::Language, bonsai_lang_api::AdapterError> {
            bonsai_lang_python::PythonAdapter::new().tree_sitter_language()
        }

        fn capabilities(&self) -> bonsai_lang_api::LanguageCapabilities {
            bonsai_lang_python::PythonAdapter::new().capabilities()
        }

        fn extract_declarations(
            &self,
            file: bonsai_common::FileId,
            ctx: &bonsai_lang_api::AdapterContext<'_>,
        ) -> bonsai_lang_api::DeclIndex {
            bonsai_lang_python::PythonAdapter::new().extract_declarations(file, ctx)
        }

        fn extract_imports(
            &self,
            file: bonsai_common::FileId,
            ctx: &bonsai_lang_api::AdapterContext<'_>,
        ) -> bonsai_lang_api::ImportIndex {
            self.import_calls.fetch_add(1, Ordering::SeqCst);
            bonsai_lang_python::PythonAdapter::new().extract_imports(file, ctx)
        }
    }

    #[test]
    fn callgraph_alias_projections_decode_each_import_header_once() {
        let vfs = Arc::new(bonsai_vfs::Vfs::new());
        vfs.write("first.py", "from package import execute as run\n");
        vfs.write("second.py", "import client as api\n");
        let import_calls = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(bonsai_lang_api::LanguageRegistry::new());
        registry.register(Arc::new(CountingImportPythonAdapter {
            import_calls: Arc::clone(&import_calls),
        }));
        let db = AnalyzerDb::new(vfs, registry);
        let (mut aliases_for_file, mut alias_targets_for_file) = callgraph_alias_projection_callbacks(&db);

        let files = db.vfs().all_files();
        for file in &files {
            let _aliases = aliases_for_file(*file);
            let _targets = alias_targets_for_file(*file);
        }
        drop(aliases_for_file);
        drop(alias_targets_for_file);

        assert_eq!(
            import_calls.load(Ordering::SeqCst),
            files.len(),
            "simple and typed callgraph aliases must share one exact import-header decode per file"
        );
    }

    #[test]
    fn public_taint_reuses_the_canonical_default_service() {
        let db = AnalyzerDb::new(
            Arc::new(bonsai_vfs::Vfs::new()),
            Arc::new(bonsai_lang_api::LanguageRegistry::new()),
        );
        let default_service = Arc::new(IdgQueryService::new(
            Arc::new(bonsai_idg::IdgWorkspace::new()),
            Arc::new(bonsai_index::GlobalIndex::new()),
        ));
        db.set_idg_service(default_service.clone());

        let canonical = ensure_idg_service(&db);
        assert!(Arc::ptr_eq(&canonical, &default_service));
        assert!(Arc::ptr_eq(&ensure_idg_service(&db), &canonical));
    }

    #[test]
    fn cold_compiler_service_is_single_flight_inside_a_rayon_batch() {
        let vfs = Arc::new(bonsai_vfs::Vfs::new());
        vfs.write(
            "fixture.py",
            "def entry(value):\n    return helper(value)\n\n\
             def helper(value):\n    return sink(value)\n\n\
             def sink(value):\n    return value\n",
        );
        let registry = Arc::new(bonsai_lang_api::LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let db = AnalyzerDb::new(vfs, registry);
        for file in db.vfs().all_files() {
            let _ = db.decl_index(file);
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("test pool");
        let services: Vec<Arc<IdgQueryService>> = pool.install(|| {
            (0..16_u8)
                .into_par_iter()
                .map(|_| compiler_idg_service(&db))
                .collect()
        });

        let first = services.first().expect("compiler service");
        assert!(services.iter().all(|service| Arc::ptr_eq(service, first)));
        assert!(
            db.idg_service().is_none(),
            "non-default compiler preparation must preserve lifecycle state"
        );
    }
}
