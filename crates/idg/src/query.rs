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
//! - `paths(src, sink, max_paths, max_len)`: demand-driven path
//!   enumeration inside the cut. Capped by user budget; the closure
//!   pre-computation makes path enumeration O(actual paths) instead
//!   of O(graph size).
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

    /// Direct forward successors for compiler clients that compose another
    /// monotone relation with the ordinary IDG without restarting closure.
    pub(crate) fn forward_neighbours(&self, node: NodeId) -> &[u32] {
        self.forward.neighbours(node)
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
    /// Bounded by `max_paths` and `max_len`; returns paths as `Vec<NodeId>`.
    ///
    /// The `cut` argument lets the caller compute one bitvector cut
    /// once and enumerate paths for many `(src, sink)` pairs —
    /// matching how security analysis emits multiple findings on
    /// shared graph slices.
    pub fn paths_in_cut(
        &self,
        src: NodeId,
        sink: NodeId,
        cut: &NodeBitSet,
        max_paths: usize,
        max_len: usize,
    ) -> Vec<Vec<NodeId>> {
        if max_paths == 0 || max_len == 0 || !cut.contains(src) || !cut.contains(sink) {
            return Vec::new();
        }
        let mut out: Vec<Vec<NodeId>> = Vec::new();
        let mut path: Vec<NodeId> = Vec::with_capacity(max_len);
        path.push(src);
        let mut visited = NodeBitSet::zeros(self.n_nodes);
        visited.set(src);
        enumerate_paths(
            self,
            cut,
            sink,
            &mut path,
            &mut visited,
            &mut out,
            max_paths,
            max_len,
        );
        out
    }

    /// Convenience wrapper: compute the cut from `(src, sink)` and
    /// then enumerate up to `max_paths` paths inside it.
    pub fn paths(&self, src: NodeId, sink: NodeId, max_paths: usize, max_len: usize) -> Vec<Vec<NodeId>> {
        let cut = self.cut(&[src], &[sink]);
        self.paths_in_cut(src, sink, &cut, max_paths, max_len)
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

/// Recursive helper for [`ReachabilityIndex::paths_in_cut`].
/// Walks forward edges, restricted to the precomputed `cut`.
#[allow(clippy::too_many_arguments)]
fn enumerate_paths(
    rix: &ReachabilityIndex,
    cut: &NodeBitSet,
    sink: NodeId,
    path: &mut Vec<NodeId>,
    visited: &mut NodeBitSet,
    out: &mut Vec<Vec<NodeId>>,
    max_paths: usize,
    max_len: usize,
) {
    if out.len() >= max_paths {
        return;
    }
    let cur = *path.last().expect("non-empty path");
    if cur == sink {
        out.push(path.clone());
        return;
    }
    if path.len() >= max_len {
        return;
    }
    for &target in rix.forward.neighbours(cur) {
        let nid = NodeId(target);
        if !cut.contains(nid) {
            continue;
        }
        if visited.contains(nid) {
            continue;
        }
        visited.set(nid);
        path.push(nid);
        enumerate_paths(rix, cut, sink, path, visited, out, max_paths, max_len);
        path.pop();
        visited.clear(nid);
        if out.len() >= max_paths {
            return;
        }
    }
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
