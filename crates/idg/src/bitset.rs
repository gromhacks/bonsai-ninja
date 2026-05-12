//! Compact bitset over `NodeId`. Used for forward / backward
//! reachability sets in [`crate::query`].
//!
//! Implementation: `Box<[u64]>` with `(n_nodes + 63) / 64` words.
//! Set / clear / test are bit ops on `u64`. Union / intersection /
//! difference are word-wise loops; the compiler auto-vectorises
//! for the target architecture (NEON on aarch64, AVX/SSE on x86),
//! so this is fast on every platform we ship without using
//! arch-specific intrinsics.
//!
//! Bitsets are sized at construction; the size is fixed for the
//! lifetime of the workspace IDG (no resizing during queries).

use crate::node::NodeId;

/// Compact bitset addressed by [`NodeId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeBitSet {
    bits: Box<[u64]>,
    /// Logical bit count — the bitset addresses `[0, len)`. The
    /// underlying `bits` slice may have one trailing word with
    /// unused high bits; tests + iteration mask them off.
    len: usize,
}

impl NodeBitSet {
    /// Construct an all-zero bitset addressing `len` node ids
    /// (`NodeId(0)..NodeId(len)`).
    #[must_use]
    pub fn zeros(len: usize) -> Self {
        let words = len.div_ceil(64);
        Self {
            bits: vec![0u64; words].into_boxed_slice(),
            len,
        }
    }

    /// Construct a bitset with only the seed nodes set.
    /// Out-of-range seeds are silently dropped — callers that care
    /// should validate before calling.
    #[must_use]
    pub fn from_seed(len: usize, seed: &[NodeId]) -> Self {
        let mut s = Self::zeros(len);
        for n in seed {
            s.set(*n);
        }
        s
    }

    /// Number of addressable bits (i.e. node id range).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True iff `len() == 0`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Set the bit for `node`. Out-of-range ids are a no-op.
    pub fn set(&mut self, node: NodeId) {
        let i = node.0 as usize;
        if i >= self.len {
            return;
        }
        self.bits[i >> 6] |= 1u64 << (i & 63);
    }

    /// Clear the bit for `node`. Out-of-range ids are a no-op.
    pub fn clear(&mut self, node: NodeId) {
        let i = node.0 as usize;
        if i >= self.len {
            return;
        }
        self.bits[i >> 6] &= !(1u64 << (i & 63));
    }

    /// True iff the bit for `node` is set.
    #[must_use]
    pub fn contains(&self, node: NodeId) -> bool {
        let i = node.0 as usize;
        if i >= self.len {
            return false;
        }
        (self.bits[i >> 6] & (1u64 << (i & 63))) != 0
    }

    /// In-place union: `self ∪= other`. The compiler auto-vectorises
    /// the inner word-OR loop; on hot paths this is the closure
    /// step's per-frontier cost.
    pub fn union_inplace(&mut self, other: &Self) {
        debug_assert_eq!(self.bits.len(), other.bits.len());
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
    }

    /// In-place intersection: `self ∩= other`.
    pub fn intersect_inplace(&mut self, other: &Self) {
        debug_assert_eq!(self.bits.len(), other.bits.len());
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a &= *b;
        }
    }

    /// Returns a new bitset = `self ∩ other`. Used by the
    /// source-to-sink reachability query.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        debug_assert_eq!(self.bits.len(), other.bits.len());
        let bits: Box<[u64]> = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .map(|(a, b)| a & b)
            .collect();
        Self { bits, len: self.len }
    }

    /// In-place difference: `self &= !other` (clears every bit set
    /// in `other`).
    pub fn difference_inplace(&mut self, other: &Self) {
        debug_assert_eq!(self.bits.len(), other.bits.len());
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a &= !*b;
        }
    }

    /// Returns a new bitset = `self & !other`.
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        debug_assert_eq!(self.bits.len(), other.bits.len());
        let bits: Box<[u64]> = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .map(|(a, b)| a & !*b)
            .collect();
        Self { bits, len: self.len }
    }

    /// Number of bits currently set. Useful for progress / size
    /// reporting; not on the hot path.
    #[must_use]
    pub fn popcount(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// True iff no bits are set.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }

    /// Iterate the node ids whose bits are set. Iteration order is
    /// ascending by node id.
    pub fn iter(&self) -> NodeBitSetIter<'_> {
        NodeBitSetIter {
            bits: &self.bits,
            word_idx: 0,
            cur_word: if self.bits.is_empty() { 0 } else { self.bits[0] },
            len: self.len,
        }
    }
}

impl Default for NodeBitSet {
    fn default() -> Self {
        Self::zeros(0)
    }
}

/// Ascending iterator over set bits in a [`NodeBitSet`]. Walks
/// word-by-word using `trailing_zeros` for fast next-bit search;
/// each step is constant work plus the per-bit emit.
pub struct NodeBitSetIter<'a> {
    bits: &'a [u64],
    word_idx: usize,
    cur_word: u64,
    len: usize,
}

impl<'a> Iterator for NodeBitSetIter<'a> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        loop {
            if self.cur_word != 0 {
                let bit = self.cur_word.trailing_zeros() as usize;
                let nid = (self.word_idx * 64) + bit;
                if nid >= self.len {
                    return None;
                }
                // Clear the lowest set bit so the next call advances.
                self.cur_word &= self.cur_word - 1;
                return Some(NodeId(nid as u32));
            }
            // Move to next word; bail if exhausted.
            self.word_idx += 1;
            if self.word_idx >= self.bits.len() {
                return None;
            }
            self.cur_word = self.bits[self.word_idx];
        }
    }
}

#[cfg(test)]
mod tests {
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
}
