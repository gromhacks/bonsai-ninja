//! Chain enumeration over the resolved call graph.
//!
//! The implementation lives in [`bonsai_callgraph::chains`] so both
//! `bonsai_inspect` and `bonsai_workspace::flow_ids` consume the
//! same primitive — earlier the two crates carried byte-equivalent
//! private copies and drifted on cycle / precision-cut edge cases,
//! making browse-row F: ids and `inspect --flow F:…` disagree on
//! the chain set. This module is now a thin re-export so existing
//! `bonsai_inspect::ResolvedChain` / `enumerate_chains_resolved`
//! callers keep compiling unchanged.

pub use bonsai_callgraph::chains::{
    downstream_funcs_set, enumerate_chains_resolved, ChainTruncation, ResolvedChain,
};

// `is_precise_chain` is only consumed by the in-tree enumeration
// helper that lives next to it; downstream consumers don't need it,
// so don't re-export and trip `unreachable-pub`.
