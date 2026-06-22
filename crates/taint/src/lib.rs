//! Taint reachability analysis over resolved flow chains.
//!
//! This crate is the named home for "what counts as tainted" in the
//! bonsai-ninja engine. Every pass is driven by the resolver's
//! [`bonsai_callgraph::ResolvedCallGraph`] — no workspace-wide BFS /
//! DFS over strings. Security mode's source / sink / sanitizer
//! matching rides on top of these passes.
//!
//! ## Passes
//!
//! Four passes, each building on the previous one:
//!
//! | pass | question it answers | primary input |
//! |---|---|---|
//! | **reachability** (`reachable`) | "is the source name visible anywhere on a chain that reaches the sink?" | `&[FuncId]`, `Workspace` |
//! | **assign-chain** (`assignment`) | "do `FlowEvent::Assign` edges transitively link source to sink?" | reachability + flow events |
//! | **intraprocedural** (`intra`) | "does the tainted value reach a program point following the function's CFG?" | assign-chain + `bonsai_cfg` |
//! | **interprocedural** (`inter`) | "does taint propagate across resolved call edges (callee parameters, return values)?" | intraprocedural + `ResolvedCallGraph` |
//!
//! All four passes are implemented and exercised by per-language
//! construct + language matrix tests. They reuse the same
//! `ResolvedCallGraph` + `bonsai_resolve` spine — never a
//! workspace-wide string search.

// Submodules: kept `pub(crate)` because the public surface is the
// re-exports below. External callers go through the re-exports;
// path-style `bonsai_taint::inter::...` access is intentionally
// unsupported so the inner module structure can refactor without
// affecting consumers.
pub(crate) mod assignment;
pub(crate) mod inter;
pub(crate) mod intra;
pub(crate) mod reachable;
mod text;
mod tokens;
pub mod value_flow;

pub use assignment::{assign_chain_taints, target_is_tainted};
pub use inter::{
    call_site_receives_taint, call_site_receives_taint_with_caches, function_summary, interprocedural_taint,
    interprocedural_taint_to_completion_with_caches, interprocedural_taint_with_caches,
    resume_interprocedural_taint_with_caches, CallPropagation, CallResultPassthrough, CleanOutputOverwrite,
    FunctionSeed, FunctionSummary, InterTaintCaches, InterTaintConfig, InterTaintContinuation,
    InterTaintResult, InterTaintWorkItem, OutputArgFlow, ReceiverStatePropagation, SourceCallbackArgs,
    SourceOutputArgs, TaintedArg, TaintedArgAtCall, TaintedCall, TaintedCallKind,
};
pub use intra::{intraprocedural_taint, IntraTaintResult, TaintConfig};
pub use reachable::{
    apply_configured_transfer_fixpoint, default_entry_graph_seed, default_entry_taint_seed,
    entry_taint_call_records_from_idg, entry_taint_call_records_from_idg_with_max_precision,
    entry_taint_call_records_from_idg_with_target_filters_and_max_precision, entry_taint_graph_from_idg,
    entry_taint_graph_from_idg_with_max_precision,
    entry_taint_graph_from_idg_with_target_filters_and_max_precision,
    entry_taint_graph_from_idg_with_target_funcs_and_max_precision,
    entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision,
    inspect_entry_taint_graph_from_idg_with_target_funcs, merge_into, name_reachable_through_chain_kinded,
    name_reachable_through_file_kinded, name_reachable_through_func_kinded,
    source_seed_reaches_return_from_idg, source_seed_reaches_return_from_idg_with_max_precision,
    taint_facts_and_graph_for_entry, taint_facts_and_graph_for_entry_with_caches, taint_facts_for_entry,
    EntryTaintGraph, FactKind, KindedTokens, TaintedCallEdge, TokenSet,
};
pub use value_flow::{
    value_flow_for_function, value_flow_for_function_with_caches, LatticeMode, ProvenanceMarker,
    ProvenanceSet, ValueFlowEdge, ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind,
};
