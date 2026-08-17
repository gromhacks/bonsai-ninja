//! Symbol evidence + filter engine — the SDK behind `inspect`.
//!
//! Builds (or fetches a cached) `ResolvedCallGraph`, hydrates bounded
//! per-symbol evidence and direct graph neighbors, filters it by
//! `--from`/`--to`/kind needles, and caches exact intermediate facts inside
//! [`ChainCache`].
//! The CLI is a renderer/orchestrator on top; any other consumer
//! (LSP, MCP daemon, library) can call the same surface.

// `cache` exposes the generic bounded memo used by the SDK. Other submodules
// are internal; consumers go through the re-exports.
pub mod cache;
pub(crate) mod call_edges;
pub(crate) mod chain_cache;
pub(crate) mod filter;
pub(crate) mod flow_id;
pub(crate) mod query;

#[cfg(test)]
mod chain_cache_tests;

pub use cache::BoundedCache;
pub use call_edges::{find_call_span_by_name, find_call_span_to_func_uncached, CallEdgeResolver};
pub use chain_cache::{find_enclosing_func, ChainCache};
pub use filter::{
    chain_matches_filters, chain_matches_filters_for_hit, name_token_match, FactKindFilter, FilterHit,
    InspectFilters, PrecisionFilter,
};
pub use flow_id::{
    compute_flow_id, compute_flow_labels_from, compute_group_id, compute_structural_group_id,
    compute_taint_flow_id, fnv1a_names64, fnv1a_names_low32, TaintFlowIdentityStep,
};
pub use query::{matching_decls, matching_func_ids, matching_func_ids_in_headers, Matcher};

/// Display name for a [`bonsai_common::FuncId`]. Returns the decl's
/// short name (the FuncId itself is the disambiguator) or
/// `"<unknown>"` for a missing entry.
#[must_use]
pub fn func_display_name(workspace: &bonsai_workspace::Workspace, func_id: bonsai_common::FuncId) -> String {
    let global = workspace.compiler_header_index();
    let symbol = bonsai_common::SymbolId::new(func_id.raw());
    global
        .decl_of(symbol)
        .map(|decl| decl.name.clone())
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Map a chain of [`bonsai_common::FuncId`]s to display names for
/// rendering. Just a loop wrapping [`func_display_name`].
#[must_use]
pub fn chain_to_names(
    workspace: &bonsai_workspace::Workspace,
    chain: &[bonsai_common::FuncId],
) -> Vec<String> {
    chain
        .iter()
        .map(|&func_id| func_display_name(workspace, func_id))
        .collect()
}
