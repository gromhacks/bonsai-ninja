//! IDG nodes: `(FuncId, PlaceId)` pairs interned to `NodeId`.
//!
//! The IDG's hot-path identity for a node is a single `u32`
//! [`NodeId`]. Edge tables, adjacency CSRs, and bitvector closures
//! all key on `NodeId`. The richer `(FuncId, PlaceId)` shape is held
//! in a per-segment dictionary indexed by `NodeId`.
//!
//! ## Why u32 NodeId everywhere
//!
//! The hottest IDG operation is forward / backward closure: a
//! bitvector OR over up to N nodes. Keeping the per-node identity
//! at 4 bytes:
//!
//! - Lets the closure bitvector fit in `(N + 63) / 64` × 8 bytes.
//!   For N = 5M nodes that's ~600 KB; closures touch a fraction of
//!   it per step.
//! - Lets edge records stay at 14 bytes each (2 × NodeId + 6 bytes
//!   of metadata) — tens of millions of edges fit comfortably in
//!   a few hundred MB.
//! - Gives the optimiser room to vectorise the CSR scan.
//!
//! 2³² ≈ 4 B nodes. A workspace would have to host > 4 G distinct
//! `(FuncId, Place)` pairs to hit this — i.e. tens of trillions of
//! lines of code, well past anything bonsai-ninja runs against. The
//! `try_from` boundary panics rather than silently wrapping (same
//! convention as `SymbolId`).

use bonsai_common::FuncId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Compact handle into the IDG's place dictionary. Stable across
/// reads of one segment file.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PlaceId(pub u32);

impl PlaceId {
    /// Sentinel meaning "no place" — used by builder paths that
    /// haven't yet resolved a place but need a placeholder.
    pub const SENTINEL: Self = Self(u32::MAX);

    /// True iff this id is the [`Self::SENTINEL`] value.
    #[must_use]
    pub fn is_sentinel(self) -> bool {
        self.0 == u32::MAX
    }
}

impl fmt::Display for PlaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_sentinel() {
            f.write_str("Place(_)")
        } else {
            write!(f, "Place({})", self.0)
        }
    }
}

/// Compact handle into the IDG's node dictionary. Identifies one
/// `(FuncId, PlaceId)` pair within a segment.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub u32);

impl NodeId {
    /// Sentinel meaning "no node" — used by builder paths that
    /// haven't yet resolved a node but need a placeholder.
    pub const SENTINEL: Self = Self(u32::MAX);

    /// True iff this id is the [`Self::SENTINEL`] value.
    #[must_use]
    pub fn is_sentinel(self) -> bool {
        self.0 == u32::MAX
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_sentinel() {
            f.write_str("Node(_)")
        } else {
            write!(f, "Node({})", self.0)
        }
    }
}

/// Owned IDG node: a `(FuncId, PlaceId)` pair. The dictionary stores
/// one per `NodeId`. Most code passes `NodeId` instead — this type
/// is for builder/render paths that want both halves at once.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdgNode {
    /// Containing function. The same `Place` can appear in multiple
    /// functions (e.g. `Place::Return` exists for every callable).
    pub func: FuncId,
    /// Position within `func`. Indexes the place dictionary.
    pub place: PlaceId,
}

impl IdgNode {
    /// Construct an IDG node from its two halves.
    #[must_use]
    pub const fn new(func: FuncId, place: PlaceId) -> Self {
        Self { func, place }
    }
}

impl fmt::Display for IdgNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.place, self.func)
    }
}

#[cfg(test)]
mod tests {
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
}
