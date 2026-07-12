//! Per-source-file IDG segment.
//!
//! One on-disk file holds the IDG slice originating from a single
//! source file: the place dictionary, node dictionary, and the
//! list of edges whose `from` node is in this file. Cross-file
//! edges (a call from this file into another file's function) are
//! recorded separately by the workspace-level union — segments stay
//! local so a file edit invalidates only the affected slice.
//!
//! ## Layout
//!
//! Built on top of [`bonsai_factstore`] but uses just the
//! single-payload-per-file shape: one factstore entry holds the
//! whole serialized [`IdgSegment`]. The factstore atomic-rename and
//! pipeline-hash invalidation gate apply unchanged.
//!
//! Why piggyback on factstore rather than `bincode + atomic-rename`:
//! the table id + pipeline hash header validation gives us free
//! version + matcher-policy invalidation, the streaming writer is
//! already cross-arch + cross-platform, and we get consistent
//! tooling between IDG segments and the per-function caches.

use bonsai_common::FuncId;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::dict::{NodeDict, PlaceDict};
use crate::edge::IdgEdge;
use crate::error::{IdgError, IdgResult};
use crate::node::{NodeId, PlaceId};
use crate::place::Place;

/// Caller-defined factstore table id stamped into segment headers.
/// Distinct from the per-function cache table ids in the workspace
/// crate (1=ValueFlow, 2=DataFlow, 3=FlowIds, 4=TaintGraph) so a
/// segment file mistakenly opened as another cache fails on the
/// table-id check rather than silently misinterpreting bytes.
pub const IDG_SEGMENT_TABLE_ID: u32 = 100;

/// On-disk format version for IDG segments. Bump on layout change.
pub const IDG_SEGMENT_VERSION: u32 = 2;

/// One source file's portion of the workspace IDG.
///
/// Built once per source file at index time, persisted as a
/// factstore-backed file. Contains the place + node dictionaries
/// for all places that originate in this file plus the edges whose
/// `from` is in this file.
///
/// **Cross-file edges** (e.g. a call from this file to another
/// file's function) are stitched at the workspace level — the
/// segment only carries the local nodes' interned dictionaries
/// because cross-file edges' `to` node is in a different segment.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct IdgSegment {
    /// Format version recorded in the payload (independent of the
    /// factstore header version) so callers can fail-closed if the
    /// segment layout shifts incompatibly.
    pub version: u32,
    /// Place dictionary local to this segment.
    pub places: PlaceDict,
    /// Node dictionary local to this segment. Each `IdgNode` here
    /// has a `func` declared in this source file; cross-file refs
    /// are stitched at the workspace level.
    pub nodes: NodeDict,
    /// Intra-file edges: every edge whose `from` is in this segment.
    /// Cross-file `from` edges are routed through the workspace
    /// edge index instead.
    pub edges: Vec<IdgEdge>,
    /// FuncIds whose data is encoded in this segment. Persisted so
    /// the workspace IDG can index `FuncId → segment` without
    /// scanning every edge. Sorted ascending.
    pub funcs: Vec<u32>,
    /// Names interned by this segment's `Place::Read` /
    /// `Place::Write` / field-path / type-name fields. Populated by
    /// the segment merge from each function's
    /// [`crate::transfer::TransferOutput::names`] pool. Lets
    /// consumers translate a segment-local `StrId` back into a
    /// source-level identifier and conversely look up the StrId for
    /// a known name (e.g. seed-name → `Place::Read{name}` lookup).
    #[serde(default)]
    pub strings: bonsai_factstore::StringPoolBuilder,
}

impl IdgSegment {
    /// Construct an empty segment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: IDG_SEGMENT_VERSION,
            places: PlaceDict::new(),
            nodes: NodeDict::new(),
            edges: Vec::new(),
            funcs: Vec::new(),
            strings: bonsai_factstore::StringPoolBuilder::new(),
        }
    }

    /// Pre-allocate hints. Useful when the caller can predict
    /// per-segment scale.
    #[must_use]
    pub fn with_capacity(places: usize, nodes: usize, edges: usize) -> Self {
        Self {
            version: IDG_SEGMENT_VERSION,
            places: PlaceDict::with_capacity(places),
            nodes: NodeDict::with_capacity(nodes),
            edges: Vec::with_capacity(edges),
            funcs: Vec::new(),
            strings: bonsai_factstore::StringPoolBuilder::new(),
        }
    }

    /// Intern `place` into this segment's place dictionary.
    pub fn intern_place(&mut self, place: Place) -> PlaceId {
        self.places.intern(place)
    }

    /// Intern `(func, place)` into this segment's node dictionary.
    pub fn intern_node(&mut self, func: FuncId, place: PlaceId) -> NodeId {
        self.nodes.intern(func, place)
    }

    /// Append an edge. Caller is responsible for ensuring `from` and
    /// `to` are interned in this segment's node dictionary.
    pub fn add_edge(&mut self, edge: IdgEdge) {
        self.edges.push(edge);
    }

    /// Mark `func` as encoded in this segment. Idempotent.
    pub fn record_func(&mut self, func: FuncId) {
        let raw = func.raw();
        match self.funcs.binary_search(&raw) {
            Ok(_) => {} // already present
            Err(pos) => self.funcs.insert(pos, raw),
        }
    }

    /// Number of places, nodes, and edges respectively.
    #[must_use]
    pub fn dimensions(&self) -> (usize, usize, usize) {
        (self.places.len(), self.nodes.len(), self.edges.len())
    }

    /// True iff the segment carries no edges (and so contributes
    /// nothing to the workspace IDG even if its dictionaries are
    /// populated).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Persist this segment to `path` as a factstore file. Single
    /// entry, key 0, payload = bincode of self.
    pub fn write_to_path(&self, path: &Path, pipeline_hash: u64) -> IdgResult<()> {
        let writer = FactStoreWriter::create(path, IDG_SEGMENT_TABLE_ID, pipeline_hash)?;
        let payload = bincode::serialize(self)
            .map_err(|e| IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        writer.add_owned(0, 0, payload)?;
        writer.finish()?;
        Ok(())
    }

    /// Load a segment from `path`. Returns `Ok(None)` for missing
    /// files (treat as empty segment); `Err` for corrupt or
    /// version-mismatched files.
    pub fn read_from_path(path: &Path, pipeline_hash: u64) -> IdgResult<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let reader = FactStoreReader::open(path, IDG_SEGMENT_TABLE_ID, pipeline_hash)?;
        if reader.header().table_id != IDG_SEGMENT_TABLE_ID {
            return Err(IdgError::WrongTable {
                got: reader.header().table_id,
                expected: IDG_SEGMENT_TABLE_ID,
            });
        }
        let Some(hit) = reader.get(0)? else {
            return Ok(None);
        };
        let mut segment: Self = bincode::deserialize(&hit.payload)
            .map_err(|e| IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        if segment.version != IDG_SEGMENT_VERSION {
            return Ok(None);
        }
        // Rebuild reverse-lookup maps that bincode skipped.
        segment.places.rebuild_lookup();
        segment.nodes.rebuild_lookup();
        segment.strings.rebuild_lookup();
        Ok(Some(segment))
    }
}

#[cfg(test)]
#[path = "segment_tests.rs"]
mod tests;
