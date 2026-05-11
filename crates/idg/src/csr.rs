//! Compressed sparse-row adjacency for the workspace IDG.
//!
//! For an N-node graph with E edges:
//!
//! ```text
//! offsets : [u32; N + 1]    cumulative outgoing-edge count
//! targets : [u32; E]         destination NodeIds, sorted by from-node
//! ```
//!
//! `offsets[from] .. offsets[from+1]` is the slice of `targets` for
//! the edges leaving node `from`. Symmetrical for the backward
//! direction (a separate CSR built on the transposed edge list).
//!
//! ## Why CSR
//!
//! Closure operations walk neighbours of every node currently in
//! the frontier; CSR lets that be a single index lookup + slice
//! iteration with no per-edge branching. Auto-vectorises well on
//! aarch64 + x86 because the inner loop is a tight u32 OR-into-bitset
//! pattern.

use crate::edge::IdgEdge;
use crate::node::NodeId;

/// Compressed-sparse-row adjacency. Built from a list of edges; one
/// CSR for forward (`from → targets`), one for backward (`to →
/// sources`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeCsr {
    offsets: Vec<u32>,
    targets: Vec<u32>,
    n_nodes: usize,
}

impl EdgeCsr {
    /// Build a forward CSR from `edges`. Each edge contributes one
    /// `from → to` entry. The CSR addresses node ids in `[0,
    /// n_nodes)`; edges referencing higher ids are dropped.
    #[must_use]
    pub fn forward(n_nodes: usize, edges: &[IdgEdge]) -> Self {
        Self::build(n_nodes, edges, |e| (e.from.0, e.to.0))
    }

    /// Build a backward CSR (transposed): each edge contributes one
    /// `to → from` entry.
    #[must_use]
    pub fn backward(n_nodes: usize, edges: &[IdgEdge]) -> Self {
        Self::build(n_nodes, edges, |e| (e.to.0, e.from.0))
    }

    /// Build a CSR. `extract` returns `(src, dst)` from each edge —
    /// the same function reused for forward and backward (with
    /// swapped from/to).
    fn build<F>(n_nodes: usize, edges: &[IdgEdge], extract: F) -> Self
    where
        F: Fn(&IdgEdge) -> (u32, u32),
    {
        let mut offsets = vec![0u32; n_nodes + 1];
        let valid_edges = edges.iter().filter(|e| {
            let (s, d) = extract(e);
            (s as usize) < n_nodes && (d as usize) < n_nodes
        });
        // First pass: count outgoing per node.
        for edge in valid_edges.clone() {
            let (s, _) = extract(edge);
            offsets[s as usize + 1] += 1;
        }
        // Cumulative sum: offsets[i] = total edges with src < i.
        for i in 1..offsets.len() {
            offsets[i] += offsets[i - 1];
        }
        let total = *offsets.last().unwrap_or(&0) as usize;
        let mut targets = vec![0u32; total];
        // Second pass: fill targets, advancing per-source cursor.
        let mut cursor = offsets.clone();
        for edge in valid_edges {
            let (s, d) = extract(edge);
            let pos = cursor[s as usize] as usize;
            targets[pos] = d;
            cursor[s as usize] += 1;
        }
        Self {
            offsets,
            targets,
            n_nodes,
        }
    }

    /// Number of nodes in the address space.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.n_nodes
    }

    /// Number of directed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.targets.len()
    }

    /// Iterate the destinations for `from`. Empty if `from` is out
    /// of range or has no outgoing edges.
    pub fn neighbours(&self, from: NodeId) -> &[u32] {
        let i = from.0 as usize;
        if i >= self.n_nodes {
            return &[];
        }
        let lo = self.offsets[i] as usize;
        let hi = self.offsets[i + 1] as usize;
        &self.targets[lo..hi]
    }

    /// Out-degree of `from`. Cheaper than `neighbours().len()`.
    #[must_use]
    pub fn degree(&self, from: NodeId) -> usize {
        let i = from.0 as usize;
        if i >= self.n_nodes {
            return 0;
        }
        (self.offsets[i + 1] - self.offsets[i]) as usize
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
    fn empty_csr_zero_edges() {
        let csr = EdgeCsr::forward(0, &[]);
        assert_eq!(csr.node_count(), 0);
        assert_eq!(csr.edge_count(), 0);
        assert_eq!(csr.degree(NodeId(0)), 0);
    }

    #[test]
    fn forward_csr_neighbours_per_source() {
        // 0 → 1, 0 → 2, 1 → 3
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3)];
        let csr = EdgeCsr::forward(4, &edges);
        let mut n0: Vec<u32> = csr.neighbours(NodeId(0)).to_vec();
        n0.sort_unstable();
        assert_eq!(n0, vec![1, 2]);
        let n1: Vec<u32> = csr.neighbours(NodeId(1)).to_vec();
        assert_eq!(n1, vec![3]);
        assert_eq!(csr.neighbours(NodeId(3)), &[] as &[u32]);
    }

    #[test]
    fn backward_csr_inverts_direction() {
        // forward 0 → 1, 2 → 1 means backward 1 → {0, 2}
        let edges = vec![edge(0, 1), edge(2, 1)];
        let csr = EdgeCsr::backward(3, &edges);
        let mut n1 = csr.neighbours(NodeId(1)).to_vec();
        n1.sort_unstable();
        assert_eq!(n1, vec![0, 2]);
        assert_eq!(csr.neighbours(NodeId(0)), &[] as &[u32]);
        assert_eq!(csr.neighbours(NodeId(2)), &[] as &[u32]);
    }

    #[test]
    fn degree_matches_neighbours_length() {
        let edges = vec![edge(0, 1), edge(0, 2), edge(0, 3), edge(1, 2)];
        let csr = EdgeCsr::forward(4, &edges);
        assert_eq!(csr.degree(NodeId(0)), 3);
        assert_eq!(csr.degree(NodeId(1)), 1);
        assert_eq!(csr.degree(NodeId(2)), 0);
        assert_eq!(csr.degree(NodeId(3)), 0);
    }

    #[test]
    fn out_of_range_source_returns_empty_slice() {
        let csr = EdgeCsr::forward(2, &[edge(0, 1)]);
        assert_eq!(csr.neighbours(NodeId(99)), &[] as &[u32]);
        assert_eq!(csr.degree(NodeId(99)), 0);
    }

    #[test]
    fn edges_referencing_out_of_range_nodes_dropped() {
        let edges = vec![edge(0, 1), edge(0, 99), edge(99, 0)];
        let csr = EdgeCsr::forward(2, &edges);
        // Only edge 0 → 1 survives.
        assert_eq!(csr.edge_count(), 1);
        assert_eq!(csr.neighbours(NodeId(0)), &[1]);
    }

    #[test]
    fn forward_and_backward_csrs_have_matching_total_edges() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3), edge(3, 0)];
        let f = EdgeCsr::forward(4, &edges);
        let b = EdgeCsr::backward(4, &edges);
        assert_eq!(f.edge_count(), b.edge_count());
    }

    #[test]
    fn duplicate_edges_appear_multiple_times_in_csr() {
        // The CSR is faithful — duplicates are kept; consumers can
        // dedupe at query time if needed.
        let edges = vec![edge(0, 1), edge(0, 1), edge(0, 1)];
        let csr = EdgeCsr::forward(2, &edges);
        assert_eq!(csr.degree(NodeId(0)), 3);
        let n: Vec<u32> = csr.neighbours(NodeId(0)).to_vec();
        assert_eq!(n, vec![1, 1, 1]);
    }
}
