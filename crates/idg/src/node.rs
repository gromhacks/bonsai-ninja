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
#[path = "node_tests.rs"]
mod tests;
