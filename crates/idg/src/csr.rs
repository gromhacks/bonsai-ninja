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
use bonsai_common::Precision;

/// Compressed-sparse-row adjacency. Built from a list of edges; one
/// CSR for forward (`from → targets`), one for backward (`to →
/// sources`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

    /// Build a forward CSR from compact `(from, to)` edge pairs.
    #[must_use]
    pub fn forward_pairs(n_nodes: usize, edges: &[(u32, u32)]) -> Self {
        Self::build_pairs(n_nodes, edges, |(from, to)| (*from, *to))
    }

    /// Build a forward CSR from compact `(from, to, precision)` edge records.
    #[must_use]
    pub fn forward_precision(n_nodes: usize, edges: &[(u32, u32, Precision)]) -> Self {
        Self::build_precision(n_nodes, edges, |(from, to, _)| (*from, *to))
    }

    /// Build a backward CSR (transposed): each edge contributes one
    /// `to → from` entry.
    #[must_use]
    pub fn backward(n_nodes: usize, edges: &[IdgEdge]) -> Self {
        Self::build(n_nodes, edges, |e| (e.to.0, e.from.0))
    }

    /// Build a backward CSR from compact `(from, to)` edge pairs.
    #[must_use]
    pub fn backward_pairs(n_nodes: usize, edges: &[(u32, u32)]) -> Self {
        Self::build_pairs(n_nodes, edges, |(from, to)| (*to, *from))
    }

    /// Build both directional CSRs from a repeatable pair visitor.
    ///
    /// This form can stream relations borrowed from several differently
    /// shaped compiler stores without boxing an iterator or staging their
    /// endpoints. The visitor runs exactly twice: once to size both CSRs and
    /// once to fill them.
    pub(crate) fn bidirectional_from_pair_visitor<F>(n_nodes: usize, visit_pairs: F) -> (Self, Self)
    where
        F: Fn(&mut dyn FnMut(u32, u32)),
    {
        // Store cumulative end positions in one word per node. Filling each
        // adjacency backward turns those ends into starts in place, avoiding
        // a second workspace-sized cursor vector for either direction.
        let mut forward_offsets = vec![0_u32; n_nodes];
        let mut backward_offsets = vec![0_u32; n_nodes];
        visit_pairs(&mut |from, to| {
            if (from as usize) >= n_nodes || (to as usize) >= n_nodes {
                return;
            }
            forward_offsets[from as usize] += 1;
            backward_offsets[to as usize] += 1;
        });
        for index in 1..forward_offsets.len() {
            forward_offsets[index] += forward_offsets[index - 1];
            backward_offsets[index] += backward_offsets[index - 1];
        }

        let forward_total = *forward_offsets.last().unwrap_or(&0);
        let backward_total = *backward_offsets.last().unwrap_or(&0);
        let mut forward_targets = vec![0_u32; forward_total as usize];
        let mut backward_targets = vec![0_u32; backward_total as usize];
        visit_pairs(&mut |from, to| {
            if (from as usize) >= n_nodes || (to as usize) >= n_nodes {
                return;
            }
            forward_offsets[from as usize] -= 1;
            let forward_position = forward_offsets[from as usize] as usize;
            forward_targets[forward_position] = to;

            backward_offsets[to as usize] -= 1;
            let backward_position = backward_offsets[to as usize] as usize;
            backward_targets[backward_position] = from;
        });
        forward_offsets.push(forward_total);
        backward_offsets.push(backward_total);
        // Backward filling reverses each source's visitation order. Restore
        // it so persisted accelerators and diagnostic traversal remain byte-
        // deterministic with the canonical pair visitor.
        for range in forward_offsets.windows(2) {
            forward_targets[range[0] as usize..range[1] as usize].reverse();
        }
        for range in backward_offsets.windows(2) {
            backward_targets[range[0] as usize..range[1] as usize].reverse();
        }

        (
            Self {
                offsets: forward_offsets,
                targets: forward_targets,
                n_nodes,
            },
            Self {
                offsets: backward_offsets,
                targets: backward_targets,
                n_nodes,
            },
        )
    }

    /// Build only the forward CSR from a repeatable exact pair visitor.
    ///
    /// Forward-only compiler phases must not allocate a reverse relation they
    /// cannot query. The same pair visitor and canonical numeric endpoints are
    /// used; omitting the unused transpose changes allocation lifetime only.
    pub(crate) fn forward_from_pair_visitor<F>(n_nodes: usize, visit_pairs: F) -> Self
    where
        F: Fn(&mut dyn FnMut(u32, u32)),
    {
        let mut offsets = vec![0_u32; n_nodes];
        visit_pairs(&mut |from, to| {
            if (from as usize) >= n_nodes || (to as usize) >= n_nodes {
                return;
            }
            offsets[from as usize] += 1;
        });
        for index in 1..offsets.len() {
            offsets[index] += offsets[index - 1];
        }

        let total = *offsets.last().unwrap_or(&0);
        let mut targets = vec![0_u32; total as usize];
        visit_pairs(&mut |from, to| {
            if (from as usize) >= n_nodes || (to as usize) >= n_nodes {
                return;
            }
            offsets[from as usize] -= 1;
            let position = offsets[from as usize] as usize;
            targets[position] = to;
        });
        offsets.push(total);
        for range in offsets.windows(2) {
            targets[range[0] as usize..range[1] as usize].reverse();
        }
        Self {
            offsets,
            targets,
            n_nodes,
        }
    }

    /// Empty adjacency over an existing numeric node address space.
    #[must_use]
    pub(crate) fn empty(n_nodes: usize) -> Self {
        Self {
            offsets: vec![0; n_nodes.saturating_add(1)],
            targets: Vec::new(),
            n_nodes,
        }
    }

    /// Build a backward CSR from compact `(from, to, precision)` edge records.
    #[must_use]
    pub fn backward_precision(n_nodes: usize, edges: &[(u32, u32, Precision)]) -> Self {
        Self::build_precision(n_nodes, edges, |(from, to, _)| (*to, *from))
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

    /// Build a CSR from compact `(from, to, precision)` records. The
    /// precision is ignored here; callers keep it in a side adjacency
    /// when precision-scoped traversal needs it.
    fn build_precision<F>(n_nodes: usize, edges: &[(u32, u32, Precision)], extract: F) -> Self
    where
        F: Fn(&(u32, u32, Precision)) -> (u32, u32),
    {
        let mut offsets = vec![0u32; n_nodes + 1];
        let valid_edges = edges.iter().filter(|edge| {
            let (s, d) = extract(edge);
            (s as usize) < n_nodes && (d as usize) < n_nodes
        });
        for edge in valid_edges.clone() {
            let (s, _) = extract(edge);
            offsets[s as usize + 1] += 1;
        }
        for i in 1..offsets.len() {
            offsets[i] += offsets[i - 1];
        }
        let total = *offsets.last().unwrap_or(&0) as usize;
        let mut targets = vec![0u32; total];
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

    /// Build a CSR from compact `(from, to)` pairs. Used by query
    /// materialisation when metadata has already been split into
    /// side indexes and reachability only needs raw endpoints.
    fn build_pairs<F>(n_nodes: usize, edges: &[(u32, u32)], extract: F) -> Self
    where
        F: Fn(&(u32, u32)) -> (u32, u32),
    {
        let mut offsets = vec![0u32; n_nodes + 1];
        let valid_edges = edges.iter().filter(|edge| {
            let (s, d) = extract(edge);
            (s as usize) < n_nodes && (d as usize) < n_nodes
        });
        for edge in valid_edges.clone() {
            let (s, _) = extract(edge);
            offsets[s as usize + 1] += 1;
        }
        for i in 1..offsets.len() {
            offsets[i] += offsets[i - 1];
        }
        let total = *offsets.last().unwrap_or(&0) as usize;
        let mut targets = vec![0u32; total];
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

    /// Validate an independently persisted CSR before installing it into a
    /// query service. Acceleration data may change representation only; bad
    /// offsets or targets must be rejected rather than changing reachability.
    pub(crate) fn is_valid_for(&self, expected_nodes: usize) -> bool {
        self.n_nodes == expected_nodes
            && self.offsets.len() == expected_nodes.saturating_add(1)
            && self.offsets.first().copied() == Some(0)
            && self.offsets.windows(2).all(|pair| pair[0] <= pair[1])
            && self.offsets.last().copied().map(|last| last as usize) == Some(self.targets.len())
            && self
                .targets
                .iter()
                .all(|target| (*target as usize) < expected_nodes)
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

    pub(crate) fn persisted_parts(&self) -> (&[u32], &[u32]) {
        (&self.offsets, &self.targets)
    }
}

#[cfg(test)]
#[path = "csr_tests.rs"]
mod tests;
