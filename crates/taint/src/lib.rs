//! Taint reachability over the workspace interprocedural dataflow graph.
//!
//! The canonical engine is an SSA-narrowed IDG closure built from adapter
//! AST facts plus the resolved call graph. Security, dump-taint, inspect,
//! `interprocedural_taint`, and `call_site_receives_taint` all query that
//! graph; there is no second interprocedural worklist. The older
//! reachability/assignment/intraprocedural modules remain as local
//! compiler-dataflow and code-navigation utilities, not an alternate
//! cross-function taint engine.

// Submodules stay private; external callers use the re-exports below so the
// implementation can evolve without exposing module layout.
pub(crate) mod assignment;
mod idg_api;
pub mod idg_build;
mod idg_query;
pub(crate) mod intra;
pub(crate) mod reachable;
mod text;
mod tokens;
pub mod value_flow;

pub use assignment::{assign_chain_taints, target_is_tainted};
pub use idg_api::{
    call_site_receives_taint, call_site_receives_taint_with_caches, function_summary, interprocedural_taint,
    interprocedural_taint_with_caches, CallPropagation, CallResultPassthrough, CleanOutputOverwrite,
    FunctionSeed, FunctionSummary, InterTaintCaches, InterTaintConfig, InterTaintResult, OutputArgFlow,
    ParamSideEffect, ReceiverStatePropagation, ReturnAccessPath, ReturnElementTaint, ReturnFieldTaint,
    SourceCallbackArgs, SourceOutputArgs, TaintedArg, TaintedArgAtCall, TaintedCall, TaintedCallKind,
};
pub use idg_build::{compiler_idg_service, ensure_idg_service};
pub use idg_query::{
    IdgReturnQuery, IdgTaintQuery, IdgTaintSeed, IdgTaintSource, IdgTaintTargets, IdgTaintTransfers,
};
pub use intra::{intraprocedural_taint, IntraTaintResult, TaintConfig};
pub use reachable::{
    apply_configured_transfer_fixpoint, compose_idg_seed_nodes, default_entry_graph_seed,
    default_entry_taint_seed, entry_taint_call_records_from_idg, entry_taint_call_records_from_idg_query,
    entry_taint_graph_from_idg, entry_taint_graph_from_idg_query,
    inspect_entry_taint_graph_from_idg_with_target_funcs, merge_into, name_reachable_through_chain_kinded,
    name_reachable_through_file_kinded, name_reachable_through_func_kinded,
    source_seed_reaches_return_from_idg, source_seed_reaches_return_from_idg_query,
    taint_facts_and_graph_for_entry, taint_facts_and_graph_for_entry_with_caches, taint_facts_for_entry,
    EntryTaintGraph, FactKind, IdgSeedRequest, KindedTokens, TaintedCallEdge, TokenSet,
};
pub use value_flow::{
    value_flow_for_function, value_flow_for_function_with_caches, ProvenanceMarker, ProvenanceSet,
    ValueFlowEdge, ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind,
};
