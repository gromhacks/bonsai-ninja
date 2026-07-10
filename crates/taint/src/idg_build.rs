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

use std::sync::Arc;

use bonsai_db::AnalyzerDb;
use bonsai_idg::IdgQueryService;

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
    // Match the semantic graph used by security: diagnostic peer-method
    // fan-out is intentionally excluded. The one compatibility concession
    // belongs specifically to this token-level API — unresolved syntax-
    // classified calls conservatively preserve argument/receiver taint,
    // matching the retired worklist without changing rulepack-driven
    // security graphs.
    let transfer_options = bonsai_idg::TransferOptions {
        include_diagnostic_field_flows: false,
        include_receiver_method_propagation: false,
        include_unresolved_call_result_passthrough: true,
        include_unresolved_receiver_result_passthrough: true,
        ..bonsai_idg::TransferOptions::default()
    };
    configured_idg_service(db, &transfer_options)
}

/// Build the compatibility IDG for a public API call that supplied
/// transfer-time source/overwrite shapes. These shapes change graph edges,
/// so this variant deliberately does not replace the database's shared
/// service: a later caller may use a different configuration.
pub(crate) fn idg_service_for_inter_config(
    db: &AnalyzerDb,
    config: &crate::inter::InterTaintConfig,
) -> Arc<IdgQueryService> {
    if config.clean_output_overwrites.is_empty()
        && config.source_output_args.is_empty()
        && config.source_callback_args.is_empty()
    {
        return ensure_idg_service(db);
    }
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
        source_output_args: config
            .source_output_args
            .iter()
            .map(|shape| bonsai_idg::SourceOutputArgSpec {
                callee: shape.callee.clone(),
                output_arg_indices: shape.output_arg_indices.clone(),
            })
            .collect(),
        source_callback_args: config
            .source_callback_args
            .iter()
            .map(|shape| bonsai_idg::SourceCallbackArgSpec {
                callee: shape.callee.clone(),
                callback_arg_index: shape.callback_arg_index,
                source_param_indices: shape.source_param_indices.clone(),
            })
            .collect(),
        include_diagnostic_field_flows: false,
        include_receiver_method_propagation: false,
        include_field_argument_forwarding: true,
        include_unresolved_call_result_passthrough: true,
        include_unresolved_receiver_result_passthrough: true,
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
    if let Some(service) = db.idg_service_for_semantics(fingerprint) {
        return service;
    }
    let built = build_idg_service(db, &transfer_options);
    db.set_idg_service_for_semantics(fingerprint, built)
}

fn build_idg_service(
    db: &AnalyzerDb,
    transfer_options: &bonsai_idg::TransferOptions,
) -> Arc<IdgQueryService> {
    let global = db.global_index();
    let call_graph = build_resolved_call_graph_snapshot(db);
    let ws = bonsai_idg::workspace_adapter::build_with_file_info_and_options_with_paths(
        global.as_ref(),
        &call_graph,
        |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
        |file| {
            db.vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        },
        transfer_options,
    );
    Arc::new(IdgQueryService::new(Arc::new(ws), global))
}

/// Build the resolved call graph from a db. Mirrors the workspace
/// snapshot builder (`build_resolved_call_graph_snapshot`) so the
/// db-level IDG resolves calls identically to the workspace path.
fn build_resolved_call_graph_snapshot(db: &AnalyzerDb) -> bonsai_callgraph::ResolvedCallGraph {
    let global = db.global_index();
    bonsai_callgraph::ResolvedCallGraph::build_with_file_info_and_super_tokens(
        global.as_ref(),
        |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
        |file| {
            bonsai_lang_api::alias_map_from_import_specs(&db.imports_for(file))
                .into_iter()
                .collect()
        },
        |file| {
            db.vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        },
        |file| {
            db.adapter_for(file)
                .map(|adapter| adapter.capabilities().module_export_aliases)
                .unwrap_or(&[])
        },
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
        |file| {
            db.adapter_for(file)
                .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
                .unwrap_or(bonsai_common::SUPER_RECEIVER_TOKENS)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn compatibility_idg_does_not_reuse_or_replace_default_service() {
        let db = AnalyzerDb::new(
            Arc::new(bonsai_vfs::Vfs::new()),
            Arc::new(bonsai_lang_api::LanguageRegistry::new()),
        );
        let default_service = Arc::new(IdgQueryService::new(
            Arc::new(bonsai_idg::IdgWorkspace::new()),
            Arc::new(bonsai_index::GlobalIndex::new()),
        ));
        db.set_idg_service(default_service.clone());

        let compatibility = ensure_idg_service(&db);
        assert!(!Arc::ptr_eq(&compatibility, &default_service));
        assert!(Arc::ptr_eq(
            &db.idg_service().expect("default service remains seeded"),
            &default_service
        ));
        assert!(Arc::ptr_eq(&ensure_idg_service(&db), &compatibility));
    }
}
