//! Place + node dictionaries for one IDG segment.
//!
//! A segment file holds:
//! - a `PlaceDict` — `Place` ↔ `PlaceId` mapping
//! - a `NodeDict` — `(FuncId, PlaceId)` ↔ `NodeId` mapping
//!
//! Both deduplicate during construction (interning) and serialise as
//! flat `Vec`s indexed by id. Lookups are `AHashMap` at build time;
//! readers reconstitute the lookup from the persisted vecs.

use ahash::AHashMap;
use bonsai_common::FuncId;
use serde::{Deserialize, Serialize};

use crate::node::{IdgNode, NodeId, PlaceId};
use crate::place::Place;

/// Build-side place interner. Hands out stable `PlaceId`s and
/// keeps the canonical `Place` value indexed by id.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PlaceDict {
    /// Canonical Place per id. `places[id.0 as usize]` is the
    /// `Place` for `PlaceId(id)`.
    pub places: Vec<Place>,
    /// Hash-based reverse lookup. Skipped at serialise time
    /// (`#[serde(skip)]`); readers rebuild on first lookup if needed.
    #[serde(skip)]
    by_place: AHashMap<Place, PlaceId>,
}

impl PlaceDict {
    /// Construct an empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            places: Vec::new(),
            by_place: AHashMap::new(),
        }
    }

    /// Pre-allocate hints. Useful when the caller can predict the
    /// rough number of places in the segment.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            places: Vec::with_capacity(cap),
            by_place: AHashMap::with_capacity(cap),
        }
    }

    /// Intern `place`. Returns the existing id if `place` is
    /// already present; otherwise allocates a new id.
    pub fn intern(&mut self, place: Place) -> PlaceId {
        if let Some(id) = self.by_place.get(&place) {
            return *id;
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

    /// Look up the id of a place, if interned. O(1).
    #[must_use]
    pub fn lookup(&self, place: &Place) -> Option<PlaceId> {
        self.by_place.get(place).copied()
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
    }

    pub(crate) fn release_lookup(&mut self) {
        self.by_place = AHashMap::new();
    }
}

/// Build-side node interner. Hands out stable `NodeId`s for
/// `(FuncId, PlaceId)` pairs.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NodeDict {
    /// Canonical IdgNode per id. `nodes[id.0 as usize]` is the
    /// `IdgNode` for `NodeId(id)`.
    pub nodes: Vec<IdgNode>,
    /// Hash-based reverse lookup. Skipped at serialise time; readers
    /// rebuild on demand.
    #[serde(skip)]
    by_node: AHashMap<IdgNode, NodeId>,
}

impl NodeDict {
    /// Construct an empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            by_node: AHashMap::new(),
        }
    }

    /// Pre-allocate hints.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(cap),
            by_node: AHashMap::with_capacity(cap),
        }
    }

    /// Intern `(func, place)`. Returns the existing id if present.
    pub fn intern(&mut self, func: FuncId, place: PlaceId) -> NodeId {
        let node = IdgNode::new(func, place);
        if let Some(id) = self.by_node.get(&node) {
            return *id;
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
    #[must_use]
    pub fn lookup(&self, func: FuncId, place: PlaceId) -> Option<NodeId> {
        let node = IdgNode::new(func, place);
        self.by_node.get(&node).copied()
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
    }

    pub(crate) fn release_lookup(&mut self) {
        self.by_node = AHashMap::new();
    }
}

#[cfg(test)]
#[path = "dict_tests.rs"]
mod tests;
