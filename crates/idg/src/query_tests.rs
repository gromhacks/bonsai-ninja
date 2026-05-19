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
