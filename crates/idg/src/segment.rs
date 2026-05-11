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
pub const IDG_SEGMENT_VERSION: u32 = 1;

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
        let payload = bincode::serialize(self).map_err(|e| {
            IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        writer.add(0, 0, &payload)?;
        let _ = writer.finish()?;
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
        let mut segment: Self = bincode::deserialize(&hit.payload).map_err(|e| {
            IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
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
mod tests {
    use super::*;
    use bonsai_common::{FileId, Span};
    use bonsai_factstore::FactStoreError;

    fn span() -> Span {
        Span::new(FileId::new(0), 0, 1)
    }

    #[test]
    fn empty_segment_has_zero_dimensions() {
        let seg = IdgSegment::new();
        assert_eq!(seg.dimensions(), (0, 0, 0));
        assert!(seg.is_empty());
    }

    #[test]
    fn intern_place_then_node_chains_correctly() {
        let mut seg = IdgSegment::new();
        let pid = seg.intern_place(Place::Return);
        let nid = seg.intern_node(FuncId::new(7), pid);
        assert_eq!(seg.dimensions(), (1, 1, 0));
        assert_eq!(seg.places.get(pid), Some(&Place::Return));
        let node = seg.nodes.get(nid).expect("node interned");
        assert_eq!(node.func, FuncId::new(7));
        assert_eq!(node.place, pid);
    }

    #[test]
    fn add_edge_grows_edge_list() {
        let mut seg = IdgSegment::new();
        let p_ret = seg.intern_place(Place::Return);
        let p_param = seg.intern_place(Place::Param { idx: 0 });
        let n1 = seg.intern_node(FuncId::new(1), p_param);
        let n2 = seg.intern_node(FuncId::new(1), p_ret);
        seg.add_edge(IdgEdge::intra_assign(n1, n2, span()));
        seg.add_edge(IdgEdge::intra_assign(n2, n1, span()));
        assert_eq!(seg.edges.len(), 2);
        assert!(!seg.is_empty());
    }

    #[test]
    fn record_func_dedups_and_sorts() {
        let mut seg = IdgSegment::new();
        seg.record_func(FuncId::new(5));
        seg.record_func(FuncId::new(2));
        seg.record_func(FuncId::new(5));
        seg.record_func(FuncId::new(8));
        assert_eq!(seg.funcs, vec![2, 5, 8]);
    }

    #[test]
    fn write_then_read_roundtrips_segment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.factstore");
        let mut seg = IdgSegment::new();
        let pid_ret = seg.intern_place(Place::Return);
        let pid_param = seg.intern_place(Place::Param { idx: 1 });
        let pid_read = seg.intern_place(Place::read(11));
        let n_param = seg.intern_node(FuncId::new(7), pid_param);
        let n_ret = seg.intern_node(FuncId::new(7), pid_ret);
        let n_read = seg.intern_node(FuncId::new(7), pid_read);
        seg.add_edge(IdgEdge::intra_assign(n_param, n_read, span()));
        seg.add_edge(IdgEdge::intra_assign(n_read, n_ret, span()));
        seg.record_func(FuncId::new(7));

        seg.write_to_path(&path, 0xCAFE).expect("write");
        let restored = IdgSegment::read_from_path(&path, 0xCAFE)
            .expect("read")
            .expect("segment present");

        assert_eq!(restored.dimensions(), (3, 3, 2));
        assert_eq!(restored.funcs, vec![7]);
        // Reverse-lookup maps must be rebuilt.
        assert_eq!(restored.places.lookup(&Place::Return), Some(pid_ret));
        assert_eq!(
            restored.nodes.lookup(FuncId::new(7), pid_param),
            Some(n_param),
        );
    }

    #[test]
    fn read_from_nonexistent_path_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.factstore");
        let result = IdgSegment::read_from_path(&path, 0).expect("ok on missing");
        assert!(result.is_none());
    }

    #[test]
    fn pipeline_hash_mismatch_surfaces_factstore_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.factstore");
        let seg = IdgSegment::new();
        seg.write_to_path(&path, 0xCAFE).expect("write");
        let err = IdgSegment::read_from_path(&path, 0xBEEF).expect_err("must mismatch");
        match err {
            IdgError::FactStore(FactStoreError::PipelineMismatch { file, expected }) => {
                assert_eq!(file, 0xCAFE);
                assert_eq!(expected, 0xBEEF);
            }
            other => panic!("expected FactStore::PipelineMismatch, got {other:?}"),
        }
    }

    #[test]
    fn version_mismatch_in_payload_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.factstore");
        // Hand-craft a segment with a wrong version field.
        let mut seg = IdgSegment::new();
        seg.version = IDG_SEGMENT_VERSION + 1;
        seg.write_to_path(&path, 0).expect("write");
        // Reader detects version drift and returns None instead of
        // misinterpreting the bytes.
        let result = IdgSegment::read_from_path(&path, 0).expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn intern_node_reuses_id_for_same_input() {
        let mut seg = IdgSegment::new();
        let pid = seg.intern_place(Place::Return);
        let a = seg.intern_node(FuncId::new(1), pid);
        let b = seg.intern_node(FuncId::new(1), pid);
        assert_eq!(a, b);
        assert_eq!(seg.dimensions(), (1, 1, 0));
    }

    #[test]
    fn segment_with_capacity_starts_empty() {
        let seg = IdgSegment::with_capacity(16, 64, 256);
        assert_eq!(seg.dimensions(), (0, 0, 0));
        assert!(seg.is_empty());
    }
}
