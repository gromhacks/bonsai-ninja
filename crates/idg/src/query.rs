//! Reachability queries over the workspace IDG.
//!
//! The hot operations are:
//!
//! - `forward_closure(seed)`: every node reachable forward from any
//!   seed node (one sparse monotone worklist over the forward CSR).
//! - `backward_closure(seed)`: every node that can reach any seed
//!   node (the same fixed-point kernel over the backward CSR).
//! - `reaches(src, sink)`: bit AND of single-source forward and
//!   backward closures.
//! - `reachable_from_any(seeds)`: union forward closure from a bag
//!   of sources — the canonical security-analysis kernel.
//! - `paths_with_truncation(src, sink, max_paths, max_len)`: demand-driven
//!   diagnostic path enumeration inside the cut. Rendering bounds are
//!   reported explicitly; the closure pre-computation makes path enumeration
//!   O(actual paths) instead of O(graph size).
//!
//! Algorithmic shape: classical compiler dataflow over numeric IR. Ordinary
//! value edges are compact CSR relations; access-path transfers stay symbolic
//! and are composed only for demanded facts. No traversal guesses through
//! source text or identifier spellings. Sparse worklists run monotonically to
//! a fixed point without semantic depth or iteration limits.

use crate::bitset::NodeBitSet;
use crate::csr::EdgeCsr;
use crate::edge::IdgEdge;
use crate::node::NodeId;
use bonsai_callgraph::PathTruncation;
use bonsai_common::Precision;

/// Cached bitvector adjacency for one IDG. Built once from the
/// flat edge list; queries reuse it.
#[derive(Clone, Debug)]
pub struct ReachabilityIndex {
    forward: EdgeCsr,
    backward: EdgeCsr,
    n_nodes: usize,
}

impl ReachabilityIndex {
    /// Construct the index from a graph's edge list and node count.
    /// Builds both forward and backward CSRs so neither direction
    /// needs a transpose at query time.
    #[must_use]
    pub fn new(n_nodes: usize, edges: &[IdgEdge]) -> Self {
        Self {
            forward: EdgeCsr::forward(n_nodes, edges),
            backward: EdgeCsr::backward(n_nodes, edges),
            n_nodes,
        }
    }

    /// Construct the index from compact `(from, to)` edge pairs.
    /// Equivalent to [`Self::new`] for reachability, but avoids
    /// retaining full edge metadata during query materialisation.
    #[must_use]
    pub fn from_pairs(n_nodes: usize, edges: &[(u32, u32)]) -> Self {
        Self {
            forward: EdgeCsr::forward_pairs(n_nodes, edges),
            backward: EdgeCsr::backward_pairs(n_nodes, edges),
            n_nodes,
        }
    }

    /// Construct both directional CSRs from a repeatable exact pair visitor.
    /// This accepts heterogeneous borrowed compiler relations without a
    /// workspace-sized staging vector.
    pub(crate) fn from_pair_visitor<F>(n_nodes: usize, visit_pairs: F) -> Self
    where
        F: Fn(&mut dyn FnMut(u32, u32)),
    {
        let (forward, backward) = EdgeCsr::bidirectional_from_pair_visitor(n_nodes, visit_pairs);
        Self {
            forward,
            backward,
            n_nodes,
        }
    }

    /// Construct the exact forward relation without an unused transpose.
    ///
    /// Function-summary compilation performs forward closures exclusively.
    /// Interactive target-relevance queries continue to use
    /// [`Self::from_pair_visitor`] and retain both directions.
    pub(crate) fn from_forward_pair_visitor<F>(n_nodes: usize, visit_pairs: F) -> Self
    where
        F: Fn(&mut dyn FnMut(u32, u32)),
    {
        Self {
            forward: EdgeCsr::forward_from_pair_visitor(n_nodes, visit_pairs),
            backward: EdgeCsr::empty(n_nodes),
            n_nodes,
        }
    }

    /// Construct the index from compact `(from, to, precision)` edge
    /// records. Reachability ignores precision; precision-scoped
    /// traversals keep their own side adjacency.
    #[must_use]
    pub fn from_precision_edges(n_nodes: usize, edges: &[(u32, u32, Precision)]) -> Self {
        Self {
            forward: EdgeCsr::forward_precision(n_nodes, edges),
            backward: EdgeCsr::backward_precision(n_nodes, edges),
            n_nodes,
        }
    }

    /// Total addressable nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.n_nodes
    }

    /// Forward closure: every node reachable from any of `seeds`
    /// by following forward edges. Uses a sparse CSR worklist with a
    /// visited bitset — no path enumeration during the closure.
    #[must_use]
    pub fn forward_closure(&self, seeds: &[NodeId]) -> NodeBitSet {
        bitvector_closure(&self.forward, self.n_nodes, seeds)
    }

    /// Forward closure as a sparse node list in worklist visitation
    /// order. This is the same exact fixpoint as
    /// [`Self::forward_closure`], but avoids converting the final
    /// bitset back into a `Vec` when callers immediately iterate
    /// reached nodes.
    #[must_use]
    pub fn forward_closure_nodes(&self, seeds: &[NodeId]) -> Vec<NodeId> {
        sparse_closure_nodes(&self.forward, self.n_nodes, seeds)
    }

    pub(crate) fn forward_neighbours(&self, node: NodeId) -> &[u32] {
        self.forward.neighbours(node)
    }

    pub(crate) fn backward_neighbours(&self, node: NodeId) -> &[u32] {
        self.backward.neighbours(node)
    }

    /// Forward closure restricted to `allowed` nodes.
    ///
    /// A source-to-target query computes `allowed` as the target's backward
    /// closure. Filtering while traversing keeps work proportional to the
    /// actual source-to-target corridor; computing an unrestricted closure
    /// and intersecting afterward visits unrelated branches needlessly.
    #[must_use]
    pub fn forward_closure_within(&self, seeds: &[NodeId], allowed: &NodeBitSet) -> NodeBitSet {
        debug_assert_eq!(allowed.len(), self.n_nodes);
        bitvector_closure_within(&self.forward, self.n_nodes, seeds, allowed)
    }

    /// Restricted forward closure as a sparse node list in visitation order.
    /// This avoids scanning the entire result bitset when a target corridor is
    /// much smaller than the workspace graph.
    #[must_use]
    pub fn forward_closure_nodes_within(&self, seeds: &[NodeId], allowed: &NodeBitSet) -> Vec<NodeId> {
        debug_assert_eq!(allowed.len(), self.n_nodes);
        sparse_closure_nodes_within(&self.forward, self.n_nodes, seeds, allowed)
    }

    /// Backward closure: every node that can reach any of `seeds`.
    #[must_use]
    pub fn backward_closure(&self, seeds: &[NodeId]) -> NodeBitSet {
        bitvector_closure(&self.backward, self.n_nodes, seeds)
    }

    /// True iff `src` reaches `sink`. O(forward closure + AND test).
    /// For batch reachability ("which sources reach this sink?"),
    /// use [`Self::cut`] which amortises closures.
    #[must_use]
    pub fn reaches(&self, src: NodeId, sink: NodeId) -> bool {
        let forward = self.forward_closure(&[src]);
        forward.contains(sink)
    }

    /// Multi-source forward closure — the security-analysis kernel.
    /// For a security scan with K sources, this is ONE closure
    /// computation, not K. Same for sinks via
    /// [`Self::backward_closure`].
    #[must_use]
    pub fn reachable_from_any(&self, seeds: &[NodeId]) -> NodeBitSet {
        self.forward_closure(seeds)
    }

    /// "Sources reaching sinks" — the bitvector intersection of the
    /// multi-source forward closure and the multi-sink backward
    /// closure. Returns the cut: every node on at least one
    /// source-to-sink path.
    #[must_use]
    pub fn cut(&self, sources: &[NodeId], sinks: &[NodeId]) -> NodeBitSet {
        let forward = self.forward_closure(sources);
        let backward = self.backward_closure(sinks);
        forward.intersect(&backward)
    }

    /// Demand-driven path enumeration. Walks paths from `src` to
    /// `sink` within `cut` (the precomputed reachable intersection).
    /// Bounded by `max_paths` and `max_len`; reports when either rendering
    /// bound omitted diagnostic paths.
    ///
    /// The `cut` argument lets the caller compute one bitvector cut
    /// once and enumerate paths for many `(src, sink)` pairs —
    /// matching how security analysis emits multiple findings on
    /// shared graph slices.
    pub fn paths_in_cut_with_truncation(
        &self,
        src: NodeId,
        sink: NodeId,
        cut: &NodeBitSet,
        max_paths: usize,
        max_len: usize,
    ) -> (Vec<Vec<NodeId>>, PathTruncation) {
        if !cut.contains(src) || !cut.contains(sink) {
            return (Vec::new(), PathTruncation::None);
        }
        if max_paths == 0 {
            return (Vec::new(), PathTruncation::MaxPaths);
        }
        if max_len == 0 {
            return (Vec::new(), PathTruncation::MaxDepth);
        }
        let search_limit = max_paths.saturating_add(1);
        let (mut out, mut truncation) = enumerate_paths(self, cut, src, sink, search_limit, max_len);
        if out.len() > max_paths {
            out.truncate(max_paths);
            truncation = PathTruncation::MaxPaths;
        }
        (out, truncation)
    }

    /// Compatibility wrapper that drops explicit truncation metadata.
    ///
    /// New diagnostic renderers should call
    /// [`Self::paths_in_cut_with_truncation`] or
    /// [`Self::paths_with_truncation`].
    #[deprecated(note = "use paths_in_cut_with_truncation so rendering bounds remain visible")]
    pub fn paths_in_cut(
        &self,
        src: NodeId,
        sink: NodeId,
        cut: &NodeBitSet,
        max_paths: usize,
        max_len: usize,
    ) -> Vec<Vec<NodeId>> {
        self.paths_in_cut_with_truncation(src, sink, cut, max_paths, max_len)
            .0
    }

    /// Convenience wrapper: compute the cut from `(src, sink)` and then
    /// enumerate bounded diagnostic paths with explicit truncation metadata.
    pub fn paths_with_truncation(
        &self,
        src: NodeId,
        sink: NodeId,
        max_paths: usize,
        max_len: usize,
    ) -> (Vec<Vec<NodeId>>, PathTruncation) {
        let cut = self.cut(&[src], &[sink]);
        self.paths_in_cut_with_truncation(src, sink, &cut, max_paths, max_len)
    }

    /// Compatibility wrapper that drops explicit truncation metadata.
    #[deprecated(note = "use paths_with_truncation so rendering bounds remain visible")]
    pub fn paths(&self, src: NodeId, sink: NodeId, max_paths: usize, max_len: usize) -> Vec<Vec<NodeId>> {
        self.paths_with_truncation(src, sink, max_paths, max_len).0
    }

    /// Forward neighborhood: every node reachable in `≤ k` hops
    /// from `node`. For inspect's "show me 1 hop around foo".
    #[must_use]
    pub fn forward_neighbourhood(&self, node: NodeId, k_hops: usize) -> NodeBitSet {
        bitvector_bounded_closure(&self.forward, self.n_nodes, &[node], k_hops)
    }

    /// Backward neighborhood: every node that reaches `node` in
    /// `≤ k` hops.
    #[must_use]
    pub fn backward_neighbourhood(&self, node: NodeId, k_hops: usize) -> NodeBitSet {
        bitvector_bounded_closure(&self.backward, self.n_nodes, &[node], k_hops)
    }
}

/// Generic exact closure: sparse monotone stack expansion until empty.
///
/// The earlier frontier-bitset implementation was exact but paid
/// `O(depth * graph_words)` because every level allocated and scanned
/// whole-graph bitsets for `next \ reached`. Source/security analysis
/// issues many scoped closures over sparse IDG slices, so a stack plus
/// one visited bitset is both exact and substantially cheaper: work is
/// proportional to the reached edges plus one final bitset.
fn bitvector_closure(csr: &EdgeCsr, n_nodes: usize, seeds: &[NodeId]) -> NodeBitSet {
    let mut reached = NodeBitSet::zeros(n_nodes);
    let mut pending: Vec<NodeId> = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        if seed.0 as usize >= n_nodes || reached.contains(seed) {
            continue;
        }
        reached.set(seed);
        pending.push(seed);
    }

    while let Some(src) = pending.pop() {
        for &target in csr.neighbours(src) {
            let target = NodeId(target);
            if reached.contains(target) {
                continue;
            }
            reached.set(target);
            pending.push(target);
        }
    }
    reached
}

fn bitvector_closure_within(
    csr: &EdgeCsr,
    n_nodes: usize,
    seeds: &[NodeId],
    allowed: &NodeBitSet,
) -> NodeBitSet {
    let mut reached = NodeBitSet::zeros(n_nodes);
    let mut pending: Vec<NodeId> = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        if seed.0 as usize >= n_nodes || !allowed.contains(seed) || reached.contains(seed) {
            continue;
        }
        reached.set(seed);
        pending.push(seed);
    }

    while let Some(src) = pending.pop() {
        for &target in csr.neighbours(src) {
            let target = NodeId(target);
            if !allowed.contains(target) || reached.contains(target) {
                continue;
            }
            reached.set(target);
            pending.push(target);
        }
    }
    reached
}

fn sparse_closure_nodes(csr: &EdgeCsr, n_nodes: usize, seeds: &[NodeId]) -> Vec<NodeId> {
    let mut reached = NodeBitSet::zeros(n_nodes);
    let mut reached_nodes: Vec<NodeId> = Vec::with_capacity(seeds.len());
    let mut pending: Vec<NodeId> = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        if seed.0 as usize >= n_nodes || reached.contains(seed) {
            continue;
        }
        reached.set(seed);
        reached_nodes.push(seed);
        pending.push(seed);
    }

    while let Some(src) = pending.pop() {
        for &target in csr.neighbours(src) {
            let target = NodeId(target);
            if reached.contains(target) {
                continue;
            }
            reached.set(target);
            reached_nodes.push(target);
            pending.push(target);
        }
    }
    reached_nodes
}

fn sparse_closure_nodes_within(
    csr: &EdgeCsr,
    n_nodes: usize,
    seeds: &[NodeId],
    allowed: &NodeBitSet,
) -> Vec<NodeId> {
    let mut reached = NodeBitSet::zeros(n_nodes);
    let mut reached_nodes: Vec<NodeId> = Vec::with_capacity(seeds.len());
    let mut pending: Vec<NodeId> = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        if seed.0 as usize >= n_nodes || !allowed.contains(seed) || reached.contains(seed) {
            continue;
        }
        reached.set(seed);
        reached_nodes.push(seed);
        pending.push(seed);
    }

    while let Some(src) = pending.pop() {
        for &target in csr.neighbours(src) {
            let target = NodeId(target);
            if !allowed.contains(target) || reached.contains(target) {
                continue;
            }
            reached.set(target);
            reached_nodes.push(target);
            pending.push(target);
        }
    }
    reached_nodes
}

/// Bitvector bounded closure: same as [`bitvector_closure`] but
/// stops after `k_hops` BFS steps. Used for `inspect --query`'s
/// neighbourhood view.
fn bitvector_bounded_closure(csr: &EdgeCsr, n_nodes: usize, seeds: &[NodeId], k_hops: usize) -> NodeBitSet {
    let mut reached = NodeBitSet::from_seed(n_nodes, seeds);
    if k_hops == 0 {
        return reached;
    }
    let mut frontier = reached.clone();
    for _ in 0..k_hops {
        if frontier.is_zero() {
            break;
        }
        let mut next = NodeBitSet::zeros(n_nodes);
        for src in frontier.iter() {
            for &target in csr.neighbours(src) {
                next.set(NodeId(target));
            }
        }
        let new_frontier = next.difference(&reached);
        reached.union_inplace(&new_frontier);
        frontier = new_frontier;
    }
    reached
}

/// Iterative DFS for [`ReachabilityIndex::paths_in_cut_with_truncation`].
///
/// `path_next_edges` is the explicit call stack: each entry records the next
/// outgoing edge to examine for the node at the same index in `path`. This
/// keeps deep but valid source graphs off the Rust thread stack.
fn enumerate_paths(
    rix: &ReachabilityIndex,
    cut: &NodeBitSet,
    src: NodeId,
    sink: NodeId,
    max_paths: usize,
    max_len: usize,
) -> (Vec<Vec<NodeId>>, PathTruncation) {
    let capacity = max_len.min(rix.n_nodes);
    let mut out = Vec::new();
    let mut path = Vec::with_capacity(capacity);
    let mut path_next_edges = Vec::with_capacity(capacity);
    let mut visited = NodeBitSet::zeros(rix.n_nodes);
    let mut truncation = PathTruncation::None;
    path.push(src);
    path_next_edges.push(0_usize);
    visited.set(src);

    while !path.is_empty() && out.len() < max_paths {
        let path_index = path.len() - 1;
        let cur = path[path_index];
        if cur == sink {
            out.push(path.clone());
            visited.clear(cur);
            path.pop();
            path_next_edges.pop();
            continue;
        }

        let neighbours = rix.forward.neighbours(cur);
        if path.len() >= max_len {
            if truncation == PathTruncation::None
                && neighbours
                    .iter()
                    .copied()
                    .map(NodeId)
                    .any(|target| cut.contains(target) && !visited.contains(target))
            {
                truncation = PathTruncation::MaxDepth;
            }
            visited.clear(cur);
            path.pop();
            path_next_edges.pop();
            continue;
        }

        let next_edge = &mut path_next_edges[path_index];
        let mut selected = None;
        while let Some(&target) = neighbours.get(*next_edge) {
            *next_edge += 1;
            let target = NodeId(target);
            if cut.contains(target) && !visited.contains(target) {
                selected = Some(target);
                break;
            }
        }
        if let Some(target) = selected {
            visited.set(target);
            path.push(target);
            path_next_edges.push(0);
        } else {
            visited.clear(cur);
            path.pop();
            path_next_edges.pop();
        }
    }
    (out, truncation)
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
