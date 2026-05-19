use super::*;

fn nid(n: u32) -> NodeId {
    NodeId(n)
}

#[test]
fn zeros_starts_empty() {
    let s = NodeBitSet::zeros(64);
    assert_eq!(s.len(), 64);
    assert_eq!(s.popcount(), 0);
    assert!(s.is_zero());
    assert!(!s.contains(nid(0)));
    assert!(!s.contains(nid(63)));
}

#[test]
fn from_seed_sets_seed_nodes_only() {
    let s = NodeBitSet::from_seed(128, &[nid(3), nid(67), nid(120)]);
    assert!(s.contains(nid(3)));
    assert!(s.contains(nid(67)));
    assert!(s.contains(nid(120)));
    assert!(!s.contains(nid(0)));
    assert!(!s.contains(nid(64)));
    assert_eq!(s.popcount(), 3);
}

#[test]
fn set_and_contains_roundtrip() {
    let mut s = NodeBitSet::zeros(200);
    s.set(nid(42));
    s.set(nid(199));
    assert!(s.contains(nid(42)));
    assert!(s.contains(nid(199)));
    assert!(!s.contains(nid(43)));
    assert_eq!(s.popcount(), 2);
}

#[test]
fn clear_removes_bit() {
    let mut s = NodeBitSet::zeros(100);
    s.set(nid(7));
    s.clear(nid(7));
    assert!(!s.contains(nid(7)));
    assert_eq!(s.popcount(), 0);
}

#[test]
fn out_of_range_set_clear_contains_no_op() {
    let mut s = NodeBitSet::zeros(64);
    s.set(nid(64)); // 64 is out of range for len=64
    s.set(nid(1000));
    s.clear(nid(64));
    assert!(!s.contains(nid(64)));
    assert!(!s.contains(nid(1000)));
    assert_eq!(s.popcount(), 0);
}

#[test]
fn union_inplace_combines_bits() {
    let mut a = NodeBitSet::from_seed(128, &[nid(0), nid(5)]);
    let b = NodeBitSet::from_seed(128, &[nid(5), nid(99)]);
    a.union_inplace(&b);
    assert_eq!(a.popcount(), 3);
    assert!(a.contains(nid(0)));
    assert!(a.contains(nid(5)));
    assert!(a.contains(nid(99)));
}

#[test]
fn intersect_keeps_only_common_bits() {
    let a = NodeBitSet::from_seed(128, &[nid(0), nid(5), nid(10)]);
    let b = NodeBitSet::from_seed(128, &[nid(5), nid(10), nid(15)]);
    let c = a.intersect(&b);
    assert_eq!(c.popcount(), 2);
    assert!(c.contains(nid(5)));
    assert!(c.contains(nid(10)));
    assert!(!c.contains(nid(0)));
    assert!(!c.contains(nid(15)));
}

#[test]
fn intersect_inplace_matches_intersect_alloc() {
    let a = NodeBitSet::from_seed(128, &[nid(0), nid(5), nid(10)]);
    let b = NodeBitSet::from_seed(128, &[nid(5), nid(10), nid(15)]);
    let mut a_mut = a.clone();
    a_mut.intersect_inplace(&b);
    assert_eq!(a_mut, a.intersect(&b));
}

#[test]
fn difference_clears_bits_in_other() {
    let a = NodeBitSet::from_seed(128, &[nid(0), nid(5), nid(10)]);
    let b = NodeBitSet::from_seed(128, &[nid(5)]);
    let c = a.difference(&b);
    assert!(c.contains(nid(0)));
    assert!(c.contains(nid(10)));
    assert!(!c.contains(nid(5)));
    assert_eq!(c.popcount(), 2);
}

#[test]
fn difference_inplace_matches_difference_alloc() {
    let a = NodeBitSet::from_seed(128, &[nid(0), nid(5), nid(10)]);
    let b = NodeBitSet::from_seed(128, &[nid(5)]);
    let mut a_mut = a.clone();
    a_mut.difference_inplace(&b);
    assert_eq!(a_mut, a.difference(&b));
}

#[test]
fn iter_yields_set_bits_in_ascending_order() {
    let s = NodeBitSet::from_seed(200, &[nid(199), nid(0), nid(72), nid(63)]);
    let collected: Vec<u32> = s.iter().map(|n| n.0).collect();
    assert_eq!(collected, vec![0, 63, 72, 199]);
}

#[test]
fn iter_on_empty_yields_nothing() {
    let s = NodeBitSet::zeros(128);
    let count = s.iter().count();
    assert_eq!(count, 0);
}

#[test]
fn iter_handles_dense_first_word() {
    let mut s = NodeBitSet::zeros(64);
    for i in 0..32 {
        s.set(nid(i));
    }
    let collected: Vec<u32> = s.iter().map(|n| n.0).collect();
    assert_eq!(collected, (0..32u32).collect::<Vec<_>>());
}

#[test]
fn iter_does_not_emit_bits_past_len() {
    // Underlying word may have spurious bits past `len` if the
    // caller used set on an out-of-range id; our iter should
    // honour `len`. We force the situation by manually poking
    // the underlying buffer (white-box test).
    let mut s = NodeBitSet::zeros(70);
    // Force-set bit 71 in the underlying word — out of logical
    // range, but technically present in the high word.
    s.bits[1] |= 1u64 << (71 - 64);
    let nodes: Vec<u32> = s.iter().map(|n| n.0).collect();
    // Iter must NOT yield 71.
    assert!(!nodes.contains(&71));
}

#[test]
fn zero_length_bitset_is_default_safe() {
    let s = NodeBitSet::default();
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
    assert_eq!(s.popcount(), 0);
    assert_eq!(s.iter().count(), 0);
}

#[test]
fn equal_bitsets_compare_equal() {
    let a = NodeBitSet::from_seed(128, &[nid(0), nid(5), nid(10)]);
    let b = NodeBitSet::from_seed(128, &[nid(5), nid(10), nid(0)]); // reordered seed
    assert_eq!(a, b);
}

#[test]
fn closure_step_pattern_works_via_difference_and_union() {
    // Exercise the canonical closure-step kernel:
    // reached.union_inplace(frontier);
    // frontier = next.difference(reached);
    // (the bits in `next` that aren't already reached become the
    // new frontier).
    let mut reached = NodeBitSet::from_seed(64, &[nid(0)]);
    let next = NodeBitSet::from_seed(64, &[nid(0), nid(1), nid(2)]);
    reached.union_inplace(&next);
    let new_frontier = next.difference(&reached);
    // After union, reached contains 0,1,2.
    assert!(reached.contains(nid(0)));
    assert!(reached.contains(nid(1)));
    assert!(reached.contains(nid(2)));
    // Every bit in `next` is now in `reached`, so the difference
    // is empty.
    assert!(new_frontier.is_zero());
}
