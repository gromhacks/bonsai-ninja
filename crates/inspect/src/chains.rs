//! Chain enumeration over the resolved call graph.
//!
//! `enumerate_chains_resolved` is the workhorse — DFS from a target
//! `FuncId` to its roots over [`bonsai_callgraph::ResolvedCallGraph`].
//! Each emitted chain carries the worst-case [`bonsai_common::Precision`]
//! seen along the way (Direct < Narrowed < OverApproximate < Unknown,
//! folded with `meet`).
//!
//! The legacy string-keyed `enumerate_chains_with` is kept for
//! parity with old tests; everything new is FuncId-keyed.

use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{FuncId, Precision};

/// One enumerated chain plus the worst-case [`Precision`] of any
/// edge it crossed. The precision is the `meet` of every edge along
/// the chain: a chain is only as precise as its weakest hop. Used
/// by the renderer to surface "this flow is over-approximate" so
/// users can tell which evidence is rock-solid (every hop Direct/
/// Narrowed) vs over-broad (some hop Virtual / OverApproximate from
/// name-collision resolution like PHP's `parent::__construct`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedChain {
    pub funcs: Vec<FuncId>,
    pub precision: Precision,
}

/// Why an [`enumerate_chains_resolved`] call returned fewer chains
/// than the underlying call graph might support.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChainTruncation {
    /// Enumeration ran to completion — every chain that exists is
    /// in the result vector. No data was dropped.
    None,
    /// We hit `max_chains`. There is at least one more chain that
    /// was not enumerated. Re-run with a larger `max_chains` to see
    /// them.
    MaxChains,
    /// We hit the probe budget (`max_probes * 16` visits). Some
    /// chains in deeper branches of the DFS were never explored.
    /// Re-run with a larger `max_probes` to push the budget out.
    ProbeBudget,
}

impl ChainTruncation {
    /// Was anything dropped relative to a fully-enumerated chain set?
    #[must_use]
    pub fn is_truncated(self) -> bool {
        !matches!(self, ChainTruncation::None)
    }

    /// Short label suitable for the "(N flows truncated by ...)"
    /// summary line. Returns `None` when nothing was truncated.
    #[must_use]
    pub fn label(self) -> Option<&'static str> {
        match self {
            ChainTruncation::None => None,
            ChainTruncation::MaxChains => Some("max-flows cap"),
            ChainTruncation::ProbeBudget => Some("entry-probe budget"),
        }
    }
}

/// FuncId-keyed DFS chain enumeration. Walks the resolved
/// [`ResolvedCallGraph`] from `target` backward to its roots, emitting
/// every distinct caller-chain it finds.
///
/// Each chain element is a [`FuncId`] so cycles, dedup, and
/// termination are exact: two distinct functions with the same short
/// name are different graph nodes here. Every emitted chain carries
/// its accumulated [`Precision`] (the `meet` of every traversed
/// edge's precision) so the renderer can flag over-approximate flows
/// without re-walking the graph.
#[must_use]
pub fn enumerate_chains_resolved(
    cg: &ResolvedCallGraph,
    target: FuncId,
    max_chains: usize,
    max_probes: usize,
) -> (Vec<ResolvedChain>, ChainTruncation) {
    let mut results: Vec<ResolvedChain> = Vec::new();
    let mut initial_set = ahash::AHashSet::new();
    initial_set.insert(target);
    let mut stack: Vec<(Vec<FuncId>, ahash::AHashSet<FuncId>, Precision)> =
        vec![(vec![target], initial_set, Precision::Exact)];
    let mut visited_budget = 0usize;
    let mut truncation = ChainTruncation::None;
    let mut emitted_chains: ahash::AHashSet<Vec<FuncId>> = ahash::AHashSet::new();
    while let Some((path_rev, path_set, path_prec)) = stack.pop() {
        if results.len() >= max_chains {
            truncation = ChainTruncation::MaxChains;
            break;
        }
        visited_budget += 1;
        if visited_budget > max_probes * 16 {
            truncation = ChainTruncation::ProbeBudget;
            break;
        }
        let head = *path_rev.last().expect("non-empty path");
        let mut pushed_any_parent = false;
        let mut pushed_precise_parent = false;
        for edge in cg.callers_of(head) {
            let parent = edge.from;
            if path_set.contains(&parent) {
                continue; // cycle — skip the edge but treat the path as terminal
            }
            let mut next = path_rev.clone();
            next.push(parent);
            let mut next_set = path_set.clone();
            next_set.insert(parent);
            let next_prec = path_prec.meet(edge.precision);
            if is_precise_chain(next_prec) {
                pushed_precise_parent = true;
            }
            stack.push((next, next_set, next_prec));
            pushed_any_parent = true;
        }
        if !pushed_any_parent || (!pushed_precise_parent && is_precise_chain(path_prec)) {
            // No more callers (entry point reached) OR all callers
            // already on the path (recursion). Also emit the precise
            // suffix when every non-cyclic incoming edge would degrade
            // it to over-approximate/unknown. Without this cut, a
            // virtual framework/dispatcher caller can hide an otherwise
            // exact entry-to-sink path from inspect's default
            // exact/narrowed view.
            let mut chain = path_rev.clone();
            chain.reverse();
            if emitted_chains.insert(chain.clone()) && results.len() < max_chains {
                results.push(ResolvedChain {
                    funcs: chain,
                    precision: path_prec,
                });
            }
        }
    }
    // Sort + dedup so the cache key is deterministic.
    results.sort_by(|a, b| a.funcs.cmp(&b.funcs));
    results.dedup_by(|a, b| a.funcs == b.funcs);
    if results.len() > max_chains {
        truncation = ChainTruncation::MaxChains;
        results.truncate(max_chains);
    }
    (results, truncation)
}

fn is_precise_chain(precision: Precision) -> bool {
    matches!(precision, Precision::Exact | Precision::Narrowed)
}

/// FuncId-keyed transitive callee closure. Walks `cg.callees(...)`
/// transitively from `target`, bounded by `max_depth` (recursion
/// depth) and `max_funcs` (total downstream functions emitted).
#[must_use]
pub fn downstream_funcs_set(
    call_graph: &ResolvedCallGraph,
    target: FuncId,
    max_depth: usize,
    max_funcs: usize,
) -> Vec<FuncId> {
    let mut visited: ahash::AHashSet<FuncId> = ahash::AHashSet::new();
    visited.insert(target);
    let mut downstream: Vec<FuncId> = Vec::new();
    fn recurse(
        call_graph: &ResolvedCallGraph,
        from_func: FuncId,
        depth: usize,
        max_depth: usize,
        max_funcs: usize,
        visited: &mut ahash::AHashSet<FuncId>,
        downstream: &mut Vec<FuncId>,
    ) {
        if depth >= max_depth || downstream.len() >= max_funcs {
            return;
        }
        for edge in call_graph.callees_of(from_func) {
            let callee = edge.to;
            if !visited.insert(callee) {
                continue;
            }
            downstream.push(callee);
            if downstream.len() >= max_funcs {
                return;
            }
            recurse(
                call_graph,
                callee,
                depth + 1,
                max_depth,
                max_funcs,
                visited,
                downstream,
            );
        }
    }
    recurse(
        call_graph,
        target,
        0,
        max_depth,
        max_funcs,
        &mut visited,
        &mut downstream,
    );
    downstream
}
