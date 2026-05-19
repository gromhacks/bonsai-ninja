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

impl<'a> IntoIterator for &'a NodeBitSet {
    type Item = NodeId;
    type IntoIter = NodeBitSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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
#[path = "bitset_tests.rs"]
mod tests;
