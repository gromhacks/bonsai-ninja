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
    if let Some(service) = db.idg_service() {
        return service;
    }
    let global = db.global_index();
    let call_graph = build_resolved_call_graph_snapshot(db);
    let ws = bonsai_idg::workspace_adapter::build_with_file_info_and_paths(
        global.as_ref(),
        &call_graph,
        |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
        |file| {
            db.vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        },
    );
    let service = Arc::new(IdgQueryService::new(Arc::new(ws), global));
    db.set_idg_service(service.clone());
    // A peer thread may have seeded the slot between our `None` check
    // and here; prefer the cached service so all callers share one.
    db.idg_service().unwrap_or(service)
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
