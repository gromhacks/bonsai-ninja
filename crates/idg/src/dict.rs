//! Place + node dictionaries for one IDG segment.
//!
//! A segment file holds:
//! - a `PlaceDict` — `Place` ↔ `PlaceId` mapping
//! - a `NodeDict` — `(FuncId, PlaceId)` ↔ `NodeId` mapping
//!
//! Both deduplicate during construction (interning) and serialise as
//! flat `Vec`s indexed by id. Lookups use `AHashMap` while an interner is
//! active and fall back to the canonical vectors after a compiler phase
//! releases its reverse indexes. Warm readers rebuild the maps once.

use ahash::AHashMap;
use bonsai_common::FuncId;
use serde::{Deserialize, Serialize};

use crate::node::{IdgNode, NodeId, PlaceId};
use crate::place::Place;

/// Build-side place interner. Hands out stable `PlaceId`s and
/// keeps the canonical `Place` value indexed by id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceDict {
    /// Canonical Place per id. `places[id.0 as usize]` is the
    /// `Place` for `PlaceId(id)`.
    pub places: Vec<Place>,
    /// Hash-based reverse lookup. Skipped at serialise time
    /// (`#[serde(skip)]`); warm readers rebuild it after decoding.
    #[serde(skip)]
    by_place: AHashMap<Place, PlaceId>,
    /// Whether `by_place` covers every canonical place. When false it is a
    /// small delta index for values interned after a compiler phase released
    /// the complete reverse map.
    #[serde(skip)]
    lookup_complete: bool,
}

impl Default for PlaceDict {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaceDict {
    /// Construct an empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            places: Vec::new(),
            by_place: AHashMap::new(),
            lookup_complete: true,
        }
    }

    /// Pre-allocate hints. Useful when the caller can predict the
    /// rough number of places in the segment.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            places: Vec::with_capacity(cap),
            by_place: AHashMap::with_capacity(cap),
            lookup_complete: true,
        }
    }

    /// Intern `place`. Returns the existing id if `place` is
    /// already present; otherwise allocates a new id.
    pub fn intern(&mut self, place: Place) -> PlaceId {
        if let Some(id) = self.by_place.get(&place) {
            return *id;
        }
        if !self.lookup_complete {
            if let Some(index) = self.places.iter().position(|candidate| candidate == &place) {
                return PlaceId(index as u32);
            }
        }
        let raw = u32::try_from(self.places.len()).expect("place dict overflow: > 2^32 places");
        let id = PlaceId(raw);
        self.by_place.insert(place.clone(), id);
        self.places.push(place);
        id
    }

    /// Look up a place by id. `None` for ids past the end of the
    /// dictionary.
    #[must_use]
    pub fn get(&self, id: PlaceId) -> Option<&Place> {
        self.places.get(id.0 as usize)
    }

    /// Look up the id of a place, if interned.
    ///
    /// This is O(1) while the build/query reverse index is retained. A
    /// sidecar-only compiler build may deliberately release that transient
    /// index after endpoint resolution; in that state the canonical vector is
    /// searched exactly rather than dropping facts or imposing a result cap.
    #[must_use]
    pub fn lookup(&self, place: &Place) -> Option<PlaceId> {
        if let Some(id) = self.by_place.get(place) {
            return Some(*id);
        }
        if self.lookup_complete {
            return None;
        }
        self.places
            .iter()
            .position(|candidate| candidate == place)
            .map(|index| PlaceId(index as u32))
    }

    /// Number of unique places.
    #[must_use]
    pub fn len(&self) -> usize {
        self.places.len()
    }

    /// True iff the dictionary is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.places.is_empty()
    }

    /// Rebuild the reverse-lookup index from the canonical `places`
    /// vec. Called after deserialisation since `by_place` is skipped.
    pub fn rebuild_lookup(&mut self) {
        self.by_place.clear();
        self.by_place.reserve(self.places.len());
        for (i, place) in self.places.iter().enumerate() {
            let id = PlaceId(i as u32);
            self.by_place.insert(place.clone(), id);
        }
        self.lookup_complete = true;
    }

    pub(crate) fn release_lookup(&mut self) {
        self.by_place = AHashMap::new();
        self.lookup_complete = false;
    }
}

/// Build-side node interner. Hands out stable `NodeId`s for
/// `(FuncId, PlaceId)` pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDict {
    /// Canonical IdgNode per id. `nodes[id.0 as usize]` is the
    /// `IdgNode` for `NodeId(id)`.
    pub nodes: Vec<IdgNode>,
    /// Hash-based reverse lookup. Skipped at serialise time; readers
    /// rebuild on demand.
    #[serde(skip)]
    by_node: AHashMap<IdgNode, NodeId>,
    /// Whether `by_node` covers every canonical node. When false it contains
    /// only nodes interned after the complete reverse map was released.
    #[serde(skip)]
    lookup_complete: bool,
}

impl Default for NodeDict {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeDict {
    /// Construct an empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            by_node: AHashMap::new(),
            lookup_complete: true,
        }
    }

    /// Pre-allocate hints.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(cap),
            by_node: AHashMap::with_capacity(cap),
            lookup_complete: true,
        }
    }

    /// Intern `(func, place)`. Returns the existing id if present.
    pub fn intern(&mut self, func: FuncId, place: PlaceId) -> NodeId {
        let node = IdgNode::new(func, place);
        if let Some(id) = self.by_node.get(&node) {
            return *id;
        }
        if !self.lookup_complete {
            if let Some(index) = self.nodes.iter().position(|candidate| *candidate == node) {
                return NodeId(index as u32);
            }
        }
        let raw = u32::try_from(self.nodes.len()).expect("node dict overflow: > 2^32 nodes");
        let id = NodeId(raw);
        self.by_node.insert(node, id);
        self.nodes.push(node);
        id
    }

    /// Look up an `IdgNode` by id.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<&IdgNode> {
        self.nodes.get(id.0 as usize)
    }

    /// Look up the id of an `IdgNode`, if interned.
    ///
    /// Uses the reverse index when present and an exact canonical-vector scan
    /// after a sidecar-only compiler phase releases that transient index.
    #[must_use]
    pub fn lookup(&self, func: FuncId, place: PlaceId) -> Option<NodeId> {
        let node = IdgNode::new(func, place);
        if let Some(id) = self.by_node.get(&node) {
            return Some(*id);
        }
        if self.lookup_complete {
            return None;
        }
        self.nodes
            .iter()
            .position(|candidate| *candidate == node)
            .map(|index| NodeId(index as u32))
    }

    /// Number of unique nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True iff the dictionary is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Rebuild the reverse-lookup index from the canonical `nodes`
    /// vec. Called after deserialisation.
    pub fn rebuild_lookup(&mut self) {
        self.by_node.clear();
        self.by_node.reserve(self.nodes.len());
        for (i, node) in self.nodes.iter().enumerate() {
            let id = NodeId(i as u32);
            self.by_node.insert(*node, id);
        }
        self.lookup_complete = true;
    }

    pub(crate) fn release_lookup(&mut self) {
        self.by_node = AHashMap::new();
        self.lookup_complete = false;
    }
}

#[cfg(test)]
#[path = "dict_tests.rs"]
mod tests;
