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

use crate::{CallEdge, ResolvedCallGraph};
use bonsai_common::{FuncId, Precision};
use std::cmp::Ordering;

/// One enumerated chain plus the worst-case [`Precision`] of any
/// edge it crossed. The precision is the `meet` of every edge along
/// the chain: a chain is only as precise as its weakest hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedChain {
    pub funcs: Vec<FuncId>,
    pub precision: Precision,
}

/// One bounded source-to-target path over the resolved call graph.
///
/// `funcs` contains the function nodes in caller-to-callee order.
/// `edges` contains the exact semantic call edges between adjacent
/// functions, also in caller-to-callee order.
#[derive(Clone, Debug)]
pub struct ResolvedPath {
    pub funcs: Vec<FuncId>,
    pub edges: Vec<CallEdge>,
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

/// Why [`enumerate_paths_resolved`] may have returned fewer paths than
/// the semantic graph contains.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PathTruncation {
    /// The bounded walk completed without dropping any candidate path.
    None,
    /// At least one candidate hit the configured edge-depth cap.
    MaxDepth,
    /// The command emitted `max_paths` paths and stopped.
    MaxPaths,
    /// The graph walk hit its probe budget before exhausting candidates.
    ProbeBudget,
}

impl PathTruncation {
    #[must_use]
    pub fn is_truncated(self) -> bool {
        !matches!(self, PathTruncation::None)
    }

    #[must_use]
    pub fn label(self) -> Option<&'static str> {
        match self {
            PathTruncation::None => None,
            PathTruncation::MaxDepth => Some("max-depth cap"),
            PathTruncation::MaxPaths => Some("max-paths cap"),
            PathTruncation::ProbeBudget => Some("path-probe budget"),
        }
    }
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

/// Enumerate ranked source-to-target paths over the resolved semantic
/// call graph.
///
/// This walks only `Exact` / `Narrowed` edges. It never widens an
/// unresolved call into a guessed edge, and every result carries the
/// weakest precision observed on the path. Results are ranked before
/// returning by hop count, precision, and stable FuncId order.
#[must_use]
pub fn enumerate_paths_resolved(
    cg: &ResolvedCallGraph,
    from: FuncId,
    to: FuncId,
    max_paths: usize,
    max_depth: usize,
    max_probes: usize,
) -> (Vec<ResolvedPath>, PathTruncation) {
    if max_paths == 0 {
        return (Vec::new(), PathTruncation::MaxPaths);
    }
    // Compile the exact reverse corridor once before enumerating concrete
    // paths. A forward simple-path walk without this relation explores every
    // unrelated branch reachable from `from` merely to discover that it can
    // never reach `to`; on large callgraphs that is exponential work. The
    // reverse fixed point is O(V+E), syntax-graph exact, and does not impose a
    // repository-shaped search cap.
    let mut can_reach_target = ahash::AHashSet::new();
    let mut reverse_work = vec![to];
    can_reach_target.insert(to);
    while let Some(callee) = reverse_work.pop() {
        let mut callers: Vec<FuncId> = cg
            .callers_of(callee)
            .filter(|edge| edge.precision.is_semantic())
            .map(|edge| edge.from)
            .collect();
        callers.sort_unstable_by_key(|func| func.raw());
        callers.dedup();
        for caller in callers {
            if can_reach_target.insert(caller) {
                reverse_work.push(caller);
            }
        }
    }
    if !can_reach_target.contains(&from) {
        return (Vec::new(), PathTruncation::None);
    }
    let mut queue = std::collections::BinaryHeap::new();
    let mut initial_seen = ahash::AHashSet::new();
    initial_seen.insert(from);
    queue.push(PathState {
        funcs: vec![from],
        edges: Vec::new(),
        seen: initial_seen,
        precision: Precision::Exact,
        order: 0,
    });
    let mut next_order = 1usize;
    let mut probes = 0usize;
    let mut truncation = PathTruncation::None;
    let mut results = Vec::new();
    let mut emitted: ahash::AHashSet<Vec<(FuncId, u64, u64, u32)>> = ahash::AHashSet::default();

    while let Some(state) = queue.pop() {
        probes = probes.saturating_add(1);
        if max_probes != 0 && probes > max_probes {
            truncation = PathTruncation::ProbeBudget;
            break;
        }
        let current = *state.funcs.last().expect("path state has at least one func");
        if current == to {
            let key = path_identity(&state.funcs, &state.edges);
            if emitted.insert(key) {
                if results.len() >= max_paths {
                    truncation = PathTruncation::MaxPaths;
                    break;
                }
                results.push(ResolvedPath {
                    funcs: state.funcs,
                    edges: state.edges,
                    precision: state.precision,
                });
            }
            continue;
        }
        if max_depth != 0 && state.edges.len() >= max_depth {
            if truncation == PathTruncation::None {
                truncation = PathTruncation::MaxDepth;
            }
            continue;
        }

        let mut edges: Vec<&CallEdge> = cg
            .callees_of(current)
            .filter(|edge| edge.precision.is_semantic() && can_reach_target.contains(&edge.to))
            .collect();
        edges.sort_by_key(|edge| {
            (
                edge.to.raw(),
                edge.span.file.raw(),
                edge.span.start,
                edge.span.end,
                edge_kind_rank(edge.kind),
                precision_rank(edge.precision),
            )
        });
        for edge in edges {
            if state.seen.contains(&edge.to) {
                continue;
            }
            let mut next_funcs = state.funcs.clone();
            next_funcs.push(edge.to);
            let mut next_edges = state.edges.clone();
            next_edges.push(edge.clone());
            let mut next_seen = state.seen.clone();
            next_seen.insert(edge.to);
            let next_precision = state.precision.meet(edge.precision);
            queue.push(PathState {
                funcs: next_funcs,
                edges: next_edges,
                seen: next_seen,
                precision: next_precision,
                order: next_order,
            });
            next_order = next_order.saturating_add(1);
        }
    }

    results.sort_by(|a, b| {
        a.edges
            .len()
            .cmp(&b.edges.len())
            .then_with(|| precision_rank(a.precision).cmp(&precision_rank(b.precision)))
            .then_with(|| a.funcs.cmp(&b.funcs))
    });
    (results, truncation)
}

#[derive(Clone)]
struct PathState {
    funcs: Vec<FuncId>,
    edges: Vec<CallEdge>,
    seen: ahash::AHashSet<FuncId>,
    precision: Precision,
    order: usize,
}

impl PathState {
    fn hops(&self) -> usize {
        self.edges.len()
    }
}

impl PartialEq for PathState {
    fn eq(&self, other: &Self) -> bool {
        self.hops() == other.hops()
            && precision_rank(self.precision) == precision_rank(other.precision)
            && self.order == other.order
    }
}

impl Eq for PathState {}

impl PartialOrd for PathState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathState {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .hops()
            .cmp(&self.hops())
            .then_with(|| precision_rank(other.precision).cmp(&precision_rank(self.precision)))
            .then_with(|| other.order.cmp(&self.order))
    }
}

fn path_identity(funcs: &[FuncId], edges: &[CallEdge]) -> Vec<(FuncId, u64, u64, u32)> {
    funcs
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, func)| {
            let edge = edges.get(idx);
            (
                func,
                edge.map_or(0, |edge| edge.span.start),
                edge.map_or(0, |edge| edge.span.end),
                edge.map_or(u32::MAX, |edge| edge.span.file.raw()),
            )
        })
        .collect()
}

fn edge_kind_rank(kind: crate::EdgeKind) -> u8 {
    match kind {
        crate::EdgeKind::Direct => 0,
        crate::EdgeKind::Virtual => 1,
        crate::EdgeKind::Indirect => 2,
        crate::EdgeKind::Unknown => 3,
    }
}

fn precision_rank(precision: Precision) -> u8 {
    match precision {
        Precision::Exact => 0,
        Precision::Narrowed => 1,
        Precision::OverApproximate => 2,
        Precision::Unknown => 3,
    }
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
