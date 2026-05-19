use super::*;
use bonsai_common::FileId;

fn span() -> Span {
    Span::new(FileId::new(0), 0, 1)
}

#[test]
fn intra_assign_constructor_sets_exact_precision_and_direct() {
    let e = IdgEdge::intra_assign(NodeId(1), NodeId(2), span());
    assert_eq!(e.meta.precision, Precision::Exact);
    assert_eq!(e.meta.kind, IdgEdgeKind::IntraAssign);
    assert_eq!(e.meta.call_kind, CallEdgeKind::Direct);
}

#[test]
fn inter_call_arg_carries_call_kind() {
    let e = IdgEdge::inter_call_arg(
        NodeId(1),
        NodeId(2),
        span(),
        Precision::OverApproximate,
        CallEdgeKind::Virtual,
    );
    assert_eq!(e.meta.precision, Precision::OverApproximate);
    assert_eq!(e.meta.kind, IdgEdgeKind::InterCallArg);
    assert_eq!(e.meta.call_kind, CallEdgeKind::Virtual);
}

#[test]
fn is_inter_only_for_inter_kinds() {
    assert!(IdgEdgeKind::InterCallArg.is_inter());
    assert!(IdgEdgeKind::InterReturn.is_inter());
    assert!(IdgEdgeKind::InterThrow.is_inter());
    assert!(!IdgEdgeKind::IntraAssign.is_inter());
    assert!(!IdgEdgeKind::IntraRead.is_inter());
    assert!(!IdgEdgeKind::IntraReturn.is_inter());
    assert!(!IdgEdgeKind::IntraThrow.is_inter());
}

#[test]
fn is_intra_is_negation_of_is_inter() {
    for tag in 0u8..=10 {
        let kind = IdgEdgeKind::from_tag(tag).expect("known tag");
        assert_ne!(kind.is_intra(), kind.is_inter());
    }
}

#[test]
fn tag_roundtrips_via_from_tag() {
    for tag in 0u8..=10 {
        let kind = IdgEdgeKind::from_tag(tag).expect("known tag");
        assert_eq!(kind.tag(), tag);
    }
}

#[test]
fn from_tag_rejects_unknown_values() {
    assert_eq!(IdgEdgeKind::from_tag(11), None);
    assert_eq!(IdgEdgeKind::from_tag(255), None);
}

#[test]
fn edge_equality_full_componentwise() {
    let a = IdgEdge::intra_assign(NodeId(1), NodeId(2), span());
    let b = IdgEdge::intra_assign(NodeId(1), NodeId(2), span());
    assert_eq!(a, b);
    let c = IdgEdge::intra_assign(NodeId(1), NodeId(3), span());
    assert_ne!(a, c);
}

#[test]
fn edge_kind_tag_values_are_pinned() {
    // The on-disk format depends on these — pin them so a future
    // enum reorder is caught at build time.
    assert_eq!(IdgEdgeKind::IntraAssign.tag(), 0);
    assert_eq!(IdgEdgeKind::IntraRead.tag(), 1);
    assert_eq!(IdgEdgeKind::IntraReturn.tag(), 2);
    assert_eq!(IdgEdgeKind::IntraThrow.tag(), 3);
    assert_eq!(IdgEdgeKind::InterCallArg.tag(), 4);
    assert_eq!(IdgEdgeKind::InterReturn.tag(), 5);
    assert_eq!(IdgEdgeKind::InterThrow.tag(), 6);
    assert_eq!(IdgEdgeKind::IntraFieldRead.tag(), 7);
    assert_eq!(IdgEdgeKind::IntraFieldWrite.tag(), 8);
    assert_eq!(IdgEdgeKind::IntraYield.tag(), 9);
    assert_eq!(IdgEdgeKind::IntraAwait.tag(), 10);
}
