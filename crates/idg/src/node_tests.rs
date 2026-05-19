use super::*;

#[test]
fn place_id_sentinel_recognised() {
    assert!(PlaceId::SENTINEL.is_sentinel());
    assert!(!PlaceId(0).is_sentinel());
    assert!(!PlaceId(123).is_sentinel());
}

#[test]
fn node_id_sentinel_recognised() {
    assert!(NodeId::SENTINEL.is_sentinel());
    assert!(!NodeId(0).is_sentinel());
    assert!(!NodeId(7).is_sentinel());
}

#[test]
fn idg_node_construction_preserves_components() {
    let n = IdgNode::new(FuncId::new(42), PlaceId(7));
    assert_eq!(n.func, FuncId::new(42));
    assert_eq!(n.place, PlaceId(7));
}

#[test]
fn idg_node_equality_componentwise() {
    let a = IdgNode::new(FuncId::new(1), PlaceId(2));
    let b = IdgNode::new(FuncId::new(1), PlaceId(2));
    let c = IdgNode::new(FuncId::new(1), PlaceId(3));
    let d = IdgNode::new(FuncId::new(2), PlaceId(2));
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
}

#[test]
fn place_id_display_marks_sentinel() {
    assert_eq!(format!("{}", PlaceId::SENTINEL), "Place(_)");
    assert_eq!(format!("{}", PlaceId(7)), "Place(7)");
}

#[test]
fn node_id_display_marks_sentinel() {
    assert_eq!(format!("{}", NodeId::SENTINEL), "Node(_)");
    assert_eq!(format!("{}", NodeId(0)), "Node(0)");
}

#[test]
fn idg_node_is_copy_and_compact() {
    // The compactness invariant: 4-byte FuncId raw + 4-byte
    // PlaceId. Total 8 bytes; fits in two u32 slots, vectorisable.
    assert_eq!(std::mem::size_of::<IdgNode>(), 8);
    assert_eq!(std::mem::align_of::<IdgNode>(), 4);
}

#[test]
fn node_id_size_is_four_bytes() {
    assert_eq!(std::mem::size_of::<NodeId>(), 4);
    assert_eq!(std::mem::size_of::<PlaceId>(), 4);
}
