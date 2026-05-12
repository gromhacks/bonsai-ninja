//! Reachability queries over the workspace IDG.
//!
//! The hot operations are:
//!
//! - `forward_closure(seed)`: every node reachable forward from any
//!   seed node (one BFS over the forward CSR using bitset frontier).
//! - `backward_closure(seed)`: every node that can reach any seed
//!   node (BFS over the backward CSR).
//! - `reaches(src, sink)`: bit AND of single-source forward and
//!   backward closures.
//! - `reachable_from_any(seeds)`: union forward closure from a bag
//!   of sources — the canonical security-analysis kernel.
//! - `paths(src, sink, max_paths, max_len)`: demand-driven path
//!   enumeration inside the cut. Capped by user budget; the closure
//!   pre-computation makes path enumeration O(actual paths) instead
//!   of O(graph size).
//!
//! Algorithmic shape: classical IFDS / dataflow as **bitvector
//! reachability over a precomputed exploded supergraph**. No
//! BFS/DFS over names; no per-query repropagation; the worklist
//! is a frontier bitset that empties when we hit fixpoint.

use crate::bitset::NodeBitSet;
use crate::csr::EdgeCsr;
use crate::edge::IdgEdge;
use crate::node::NodeId;

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

    /// Total addressable nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.n_nodes
    }

    /// Forward closure: every node reachable from any of `seeds`
    /// by following forward edges. Uses the canonical bitvector
    /// frontier algorithm — no DFS / no path enumeration during
    /// the closure.
    #[must_use]
    pub fn forward_closure(&self, seeds: &[NodeId]) -> NodeBitSet {
        bitvector_closure(&self.forward, self.n_nodes, seeds)
    }

    /// Backward closure: every node that can reach any of `seeds`.
    #[must_use]
    pub fn backward_closure(&self, seeds: &[NodeId]) -> NodeBitSet {
        bitvector_closure(&self.backward, self.n_nodes, seeds)
    }

    /// True iff `src` reaches `sink`. O(forward closure + AND test).
    /// For batch reachability ("which sources reach this sink?"),
    /// use [`Self::sources_reaching_sinks`] which amortises closures.
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

/// Generic bitvector closure: BFS frontier expansion until empty.
fn bitvector_closure(csr: &EdgeCsr, n_nodes: usize, seeds: &[NodeId]) -> NodeBitSet {
    let mut reached = NodeBitSet::from_seed(n_nodes, seeds);
    let mut frontier = reached.clone();
    while !frontier.is_zero() {
        let mut next = NodeBitSet::zeros(n_nodes);
        for src in frontier.iter() {
            for &target in csr.neighbours(src) {
                next.set(NodeId(target));
            }
        }
        // New frontier = next \ reached.
        let new_frontier = next.difference(&reached);
        reached.union_inplace(&new_frontier);
        frontier = new_frontier;
    }
    reached
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
mod tests {
    use super::*;
    use crate::edge::{EdgeMeta, IdgEdgeKind};
    use bonsai_callgraph::EdgeKind as CallEdgeKind;
    use bonsai_common::{FileId, Precision, Span};

    fn span() -> Span {
        Span::new(FileId::new(0), 0, 1)
    }

    fn meta() -> EdgeMeta {
        EdgeMeta {
            precision: Precision::Exact,
            kind: IdgEdgeKind::IntraAssign,
            call_kind: CallEdgeKind::Direct,
            via_span: span(),
        }
    }

    fn edge(from: u32, to: u32) -> IdgEdge {
        IdgEdge {
            from: NodeId(from),
            to: NodeId(to),
            meta: meta(),
        }
    }

    #[test]
    fn forward_closure_from_root_reaches_all_descendants() {
        // 0 → 1 → 2 → 3, and 0 → 4
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3), edge(0, 4)];
        let rix = ReachabilityIndex::new(5, &edges);
        let r = rix.forward_closure(&[NodeId(0)]);
        for n in 0..5 {
            assert!(r.contains(NodeId(n)), "node {n} should be reached");
        }
    }

    #[test]
    fn forward_closure_from_leaf_reaches_only_leaf() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let rix = ReachabilityIndex::new(3, &edges);
        let r = rix.forward_closure(&[NodeId(2)]);
        assert!(r.contains(NodeId(2)));
        assert!(!r.contains(NodeId(0)));
        assert!(!r.contains(NodeId(1)));
    }

    #[test]
    fn backward_closure_from_leaf_reaches_all_ancestors() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(0, 2)];
        let rix = ReachabilityIndex::new(3, &edges);
        let r = rix.backward_closure(&[NodeId(2)]);
        assert!(r.contains(NodeId(0)));
        assert!(r.contains(NodeId(1)));
        assert!(r.contains(NodeId(2)));
    }

    #[test]
    fn closure_terminates_on_cycle() {
        // 0 → 1 → 2 → 0  (cycle)
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 0)];
        let rix = ReachabilityIndex::new(3, &edges);
        let r = rix.forward_closure(&[NodeId(0)]);
        // All three nodes in the cycle are reached, no infinite loop.
        assert_eq!(r.popcount(), 3);
    }

    #[test]
    fn reaches_returns_true_iff_path_exists() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let rix = ReachabilityIndex::new(4, &edges);
        assert!(rix.reaches(NodeId(0), NodeId(2)));
        assert!(rix.reaches(NodeId(1), NodeId(2)));
        assert!(!rix.reaches(NodeId(2), NodeId(0)), "no reverse path");
        assert!(!rix.reaches(NodeId(0), NodeId(3)), "isolated sink");
    }

    #[test]
    fn reachable_from_any_unions_seed_reachable_sets() {
        // Two disjoint chains: 0 → 1 → 2 and 10 → 11.
        let edges = vec![edge(0, 1), edge(1, 2), edge(10, 11)];
        let rix = ReachabilityIndex::new(20, &edges);
        let r = rix.reachable_from_any(&[NodeId(0), NodeId(10)]);
        // Both chains' nodes reachable; nothing else.
        for n in [0, 1, 2, 10, 11] {
            assert!(r.contains(NodeId(n)), "node {n} should be reached");
        }
        for n in [3, 4, 5, 12, 19] {
            assert!(!r.contains(NodeId(n)), "node {n} should NOT be reached");
        }
    }

    #[test]
    fn cut_is_intersection_of_forward_and_backward_closures() {
        // Diamond: 0 → 1 → 3, 0 → 2 → 3.
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        let cut = rix.cut(&[NodeId(0)], &[NodeId(3)]);
        assert!(cut.contains(NodeId(0)));
        assert!(cut.contains(NodeId(3)));
        assert!(cut.contains(NodeId(1)));
        assert!(cut.contains(NodeId(2)));
        assert_eq!(cut.popcount(), 4);
    }

    #[test]
    fn cut_excludes_unreachable_intermediate_nodes() {
        // 0 → 1 → 2; 3 unreachable from 0 and doesn't reach 2.
        let edges = vec![edge(0, 1), edge(1, 2), edge(3, 1)];
        let rix = ReachabilityIndex::new(4, &edges);
        let cut = rix.cut(&[NodeId(0)], &[NodeId(2)]);
        // Node 3 reaches 1 but isn't reached from 0; cut excludes it.
        assert!(cut.contains(NodeId(0)));
        assert!(cut.contains(NodeId(1)));
        assert!(cut.contains(NodeId(2)));
        assert!(!cut.contains(NodeId(3)));
    }

    #[test]
    fn paths_enumerates_unique_paths_in_cut() {
        // Diamond.
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        let paths = rix.paths(NodeId(0), NodeId(3), 10, 5);
        assert_eq!(paths.len(), 2);
        for p in &paths {
            assert_eq!(p.first(), Some(&NodeId(0)));
            assert_eq!(p.last(), Some(&NodeId(3)));
        }
    }

    #[test]
    fn paths_respects_max_paths_budget() {
        // Linear chain of length 4.
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        let paths = rix.paths(NodeId(0), NodeId(3), 1, 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn paths_respects_max_len_budget() {
        // Chain 0 → 1 → 2 → 3 (length 4 nodes).
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        let paths = rix.paths(NodeId(0), NodeId(3), 10, 3);
        // Only path is length 4; max_len=3 cuts it.
        assert_eq!(paths.len(), 0);
    }

    #[test]
    fn paths_skips_when_no_reachability() {
        let edges = vec![edge(0, 1), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        let paths = rix.paths(NodeId(0), NodeId(3), 10, 10);
        assert!(paths.is_empty());
    }

    #[test]
    fn paths_handles_self_target() {
        // src == sink edge case: the path is [src].
        let edges = vec![edge(0, 1)];
        let rix = ReachabilityIndex::new(2, &edges);
        let paths = rix.paths(NodeId(0), NodeId(0), 10, 10);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![NodeId(0)]);
    }

    #[test]
    fn paths_avoids_cycle_revisits() {
        // 0 → 1 → 2; cycle 1 → 1 makes the loop possible but visited
        // tracking should prevent re-entering 1.
        let edges = vec![edge(0, 1), edge(1, 1), edge(1, 2)];
        let rix = ReachabilityIndex::new(3, &edges);
        let paths = rix.paths(NodeId(0), NodeId(2), 10, 10);
        // Single non-cyclic path: 0 → 1 → 2.
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![NodeId(0), NodeId(1), NodeId(2)]);
    }

    #[test]
    fn forward_neighbourhood_is_zero_hops_just_self() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let rix = ReachabilityIndex::new(3, &edges);
        let n = rix.forward_neighbourhood(NodeId(0), 0);
        assert_eq!(n.popcount(), 1);
        assert!(n.contains(NodeId(0)));
    }

    #[test]
    fn forward_neighbourhood_one_hop() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        let n = rix.forward_neighbourhood(NodeId(0), 1);
        assert!(n.contains(NodeId(0)));
        assert!(n.contains(NodeId(1)));
        assert!(!n.contains(NodeId(2)));
    }

    #[test]
    fn forward_neighbourhood_unbounded_matches_full_closure() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        // 100 hops is way more than chain length; should match
        // unbounded closure.
        let n = rix.forward_neighbourhood(NodeId(0), 100);
        let r = rix.forward_closure(&[NodeId(0)]);
        assert_eq!(n, r);
    }

    #[test]
    fn backward_neighbourhood_inverts_direction() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let rix = ReachabilityIndex::new(3, &edges);
        let n = rix.backward_neighbourhood(NodeId(2), 1);
        assert!(n.contains(NodeId(2)));
        assert!(n.contains(NodeId(1)));
        assert!(!n.contains(NodeId(0)));
    }

    #[test]
    fn paths_in_cut_uses_precomputed_cut() {
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3)];
        let rix = ReachabilityIndex::new(4, &edges);
        let cut = rix.cut(&[NodeId(0)], &[NodeId(3)]);
        let paths = rix.paths_in_cut(NodeId(0), NodeId(3), &cut, 10, 5);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn empty_seeds_produce_empty_closure() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let rix = ReachabilityIndex::new(3, &edges);
        let r = rix.forward_closure(&[]);
        assert!(r.is_zero());
    }

    #[test]
    fn duplicate_edges_dont_double_count_in_closure() {
        let edges = vec![edge(0, 1), edge(0, 1), edge(0, 1)];
        let rix = ReachabilityIndex::new(2, &edges);
        let r = rix.forward_closure(&[NodeId(0)]);
        assert_eq!(r.popcount(), 2);
    }
}
