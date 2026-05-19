//! Chain enumeration over the resolved call graph.
//!
//! `enumerate_chains_resolved` is the workhorse — DFS from a target
//! `FuncId` to its roots over [`super::ResolvedCallGraph`]. Each
//! emitted chain carries the worst-case [`bonsai_common::Precision`]
//! seen along the way. Public chain enumeration is semantic by default:
//! it traverses only `Exact` / `Narrowed` edges. Broader edges may still
//! exist in the resolved graph for explicit diagnostics.
//!
//! This module lives in `bonsai_callgraph` so both `bonsai_inspect`
//! and `bonsai_workspace` can consume the same primitive without a
//! crate-cycle. Earlier it was duplicated in both crates with one
//! `Vec<ResolvedChain>` shape and one `Vec<Vec<FuncId>>` shape;
//! that drift made browse F: ids and inspect's `--flow F:…`
//! disagree on the chain set under cycle / precision-cut edge cases.

use crate::ResolvedCallGraph;
use bonsai_common::{FuncId, Precision};

/// One enumerated chain plus the worst-case [`Precision`] of any
/// edge it crossed. The precision is the `meet` of every edge along
/// the chain: a chain is only as precise as its weakest hop.
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
    /// We hit the probe budget (`max_probes * 16` visits, saturating).
    /// Passing `usize::MAX` disables this budget. Some
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

/// FuncId-keyed DFS chain enumeration. Walks the resolved call
/// graph from `target` backward to its roots, emitting every distinct
/// caller-chain it finds.
///
/// Each chain element is a [`FuncId`] so cycles, dedup, and
/// termination are exact: two distinct functions with the same short
/// name are different graph nodes here. Every emitted chain carries
/// its accumulated [`Precision`] (the `meet` of every traversed
/// semantic edge's precision) without re-walking the graph.
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
    let mut emitted_chains: ahash::AHashMap<Vec<FuncId>, Precision> = ahash::AHashMap::new();
    while let Some((path_rev, path_set, path_prec)) = stack.pop() {
        if results.len() >= max_chains {
            truncation = ChainTruncation::MaxChains;
            break;
        }
        visited_budget = visited_budget.saturating_add(1);
        if visited_budget > max_probes.saturating_mul(16) {
            truncation = ChainTruncation::ProbeBudget;
            break;
        }
        let head = *path_rev.last().expect("non-empty path");
        let mut pushed_any_parent = false;
        let mut pushed_precise_parent = false;
        for edge in cg.callers_of(head).filter(|edge| edge.precision.is_semantic()) {
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
            // already on the path (recursion). The precision suffix
            // guard is retained for callers that pre-filter graph
            // inputs differently, but the default iterator above only
            // traverses semantic exact/narrowed edges.
            let mut chain = path_rev.clone();
            chain.reverse();
            let should_record = emitted_chains
                .get(&chain)
                .is_none_or(|previous| path_prec < *previous);
            if should_record {
                emitted_chains.insert(chain.clone(), path_prec);
                if let Some(existing) = results.iter_mut().find(|existing| existing.funcs == chain) {
                    existing.precision = path_prec;
                } else if results.len() < max_chains {
                    results.push(ResolvedChain {
                        funcs: chain,
                        precision: path_prec,
                    });
                }
            }
        }
    }
    // Sort + dedup so the cache key is deterministic. When two
    // resolution routes produce the same FuncId path, keep the
    // most precise copy.
    results.sort_by(|a, b| a.funcs.cmp(&b.funcs).then_with(|| a.precision.cmp(&b.precision)));
    let mut deduped = Vec::with_capacity(results.len());
    for chain in results {
        if deduped
            .last()
            .is_some_and(|previous: &ResolvedChain| previous.funcs == chain.funcs)
        {
            continue;
        }
        deduped.push(chain);
    }
    results = deduped;
    if results.len() > max_chains {
        truncation = ChainTruncation::MaxChains;
        results.truncate(max_chains);
    }
    (results, truncation)
}

/// Predicate the chain enumeration uses to decide whether to emit a
/// "precise suffix" when later parents would degrade precision.
#[must_use]
pub fn is_precise_chain(precision: Precision) -> bool {
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
        for edge in call_graph
            .callees_of(from_func)
            .filter(|edge| edge.precision.is_semantic())
        {
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
