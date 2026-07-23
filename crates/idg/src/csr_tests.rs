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
fn bidirectional_factory_matches_independent_csrs() {
    let pairs = vec![(0, 1), (0, 2), (2, 1), (2, 1), (9, 0)];
    let expected_forward = EdgeCsr::forward_pairs(3, &pairs);
    let expected_backward = EdgeCsr::backward_pairs(3, &pairs);
    let (forward, backward) = EdgeCsr::bidirectional_from_pair_visitor(3, |visit| {
        for &(from, to) in &pairs {
            visit(from, to);
        }
    });

    assert_eq!(forward, expected_forward);
    assert_eq!(backward, expected_backward);
}

#[test]
fn bidirectional_visitor_matches_independent_csrs() {
    let pairs = vec![(0, 1), (0, 2), (2, 1), (2, 1), (9, 0)];
    let expected_forward = EdgeCsr::forward_pairs(3, &pairs);
    let expected_backward = EdgeCsr::backward_pairs(3, &pairs);
    let (forward, backward) = EdgeCsr::bidirectional_from_pair_visitor(3, |visit| {
        for &(from, to) in &pairs {
            visit(from, to);
        }
    });

    assert_eq!(forward, expected_forward);
    assert_eq!(backward, expected_backward);
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
