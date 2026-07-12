//! Workspace-level IDG: union of per-file segments + cross-file edges.
//!
//! Each source file produces one [`IdgSegment`] (see [`crate::segment`])
//! holding nodes whose `func` lives in that file plus edges whose
//! `from` is in those nodes. The workspace aggregates them into a
//! single addressable graph by:
//!
//! 1. **Maintaining a `FuncId → SegmentId` index** so lookups know
//!    which segment to consult.
//! 2. **Storing cross-file edges separately** in
//!    [`CrossFileEdges`]. A call from `caller_func` (in segment A)
//!    to `callee_func` (in segment B) appears as a cross-file edge
//!    whose endpoints reference both segments by funcid.
//!
//! Hot-reload story: when a single source file changes, only that
//! file's segment is re-built. Cross-file edges that originated
//! from the changed file are invalidated and re-stitched. Other
//! segments and the rest of the cross-file index stay untouched.

use ahash::AHashMap;
use bonsai_common::FuncId;
use serde::{Deserialize, Serialize};

use crate::edge::IdgEdge;
use crate::segment::{IdgSegment, IDG_SEGMENT_VERSION};
use crate::symbolic::{SymbolicFieldBase, SymbolicFieldGraph, SymbolicFieldTransform};

/// Stable handle to a segment in the workspace's segment list.
/// Distinct from `FuncId`; multiple FuncIds map to one SegmentId.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SegmentId(pub u32);

/// One cross-file edge: an inter-procedural edge whose source and
/// destination live in different segments.
///
/// Held separately from intra-segment edges because:
/// - Hot reload: the edge is invalidated when *either* segment
///   changes.
/// - Queries: cross-file traversal is a small fraction of total
///   edges; keeping them in their own table keeps in-segment
///   traversal cache-friendly.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrossFileEdge {
    /// The from-segment for this edge (resolved from edge.from at
    /// stitch time).
    pub from_segment: SegmentId,
    /// The to-segment for this edge.
    pub to_segment: SegmentId,
    /// The edge itself. Note that `edge.from` and `edge.to` are
    /// `NodeId`s **local to their respective segments**. Resolving
    /// them requires looking up the segment via
    /// [`SegmentId`]→`IdgSegment`.
    pub edge: IdgEdge,
}

/// One cross-method field-flow link: a writer method's
/// receiver-field assignment feeding a reader method's
/// receiver-field load. Built by Phase 3c
/// (`stitch_receiver_field_flow`) and consumed by
/// [`crate::service::IdgQueryService::cross_call_edges_in_closure`] which
/// synthesises a [`crate::service::CrossCallEdge`] when both endpoints land in
/// the same forward closure. The synthetic edge lets the
/// security-analysis lineage walk cross the writer-reader
/// boundary the same way it crosses a real call edge — without
/// it, `chain_funcs_for_lineage` rejects the chain because the
/// terminal call's caller never appears as a callee in
/// `call_records`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldFlowLink {
    /// The method that wrote the field (`@cmd = X` in Ruby's
    /// `initialize`, `self.cmd = X` in Python's `__init__`).
    pub writer: bonsai_common::FuncId,
    /// The method that reads the field (`sink(@cmd)` in Ruby's
    /// `run`).
    pub reader: bonsai_common::FuncId,
    /// Workspace ws_node of the writer-method's `Place::Write`
    /// for the field. The query layer reads it via the unified
    /// address space to lift into a synthetic CrossCallEdge.
    pub writer_ws_node: u32,
    /// Workspace ws_node of the reader-method's `Place::Read`
    /// for the field.
    pub reader_ws_node: u32,
    /// Span of the writer-method's field assignment. Used as the
    /// synthetic call_span so `taint_path_identity_tokens` and
    /// chain `F:` ids stay stable.
    pub via_span: bonsai_common::Span,
    /// Precision of the synthetic field-flow hop. Receiver-call
    /// field propagation is narrowed by a concrete call site;
    /// broad peer-method field bucketing remains diagnostic-only.
    pub precision: bonsai_common::Precision,
}

/// Cross-file edges, indexed for both forward (from-side) and
/// backward (to-side) lookup. Built once during workspace IDG
/// construction.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileEdges {
    /// Every cross-file edge, in stable insertion order. Indexed by
    /// CrossFileEdgeId (a `usize` cast).
    pub edges: Vec<CrossFileEdge>,
    /// `caller_segment → indices into edges` for forward queries.
    /// Skipped in serde; rebuilt from `edges` after deserialise.
    #[serde(skip)]
    by_from_segment: AHashMap<SegmentId, Vec<u32>>,
    /// `callee_segment → indices into edges` for backward queries.
    #[serde(skip)]
    by_to_segment: AHashMap<SegmentId, Vec<u32>>,
}

impl CrossFileEdges {
    /// Construct an empty cross-file edge index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a cross-file edge. Updates both directional indexes.
    pub fn push(&mut self, edge: CrossFileEdge) {
        let idx = u32::try_from(self.edges.len()).expect("cross-file edge index overflow: > 2^32 edges");
        self.by_from_segment
            .entry(edge.from_segment)
            .or_default()
            .push(idx);
        self.by_to_segment.entry(edge.to_segment).or_default().push(idx);
        self.edges.push(edge);
    }

    /// Iterate every cross-file edge whose source is in `seg`.
    pub fn outgoing_from_segment(&self, seg: SegmentId) -> impl Iterator<Item = &CrossFileEdge> + '_ {
        self.by_from_segment
            .get(&seg)
            .into_iter()
            .flatten()
            .filter_map(move |idx| self.edges.get(*idx as usize))
    }

    /// Iterate every cross-file edge whose destination is in `seg`.
    pub fn incoming_to_segment(&self, seg: SegmentId) -> impl Iterator<Item = &CrossFileEdge> + '_ {
        self.by_to_segment
            .get(&seg)
            .into_iter()
            .flatten()
            .filter_map(move |idx| self.edges.get(*idx as usize))
    }

    /// Number of cross-file edges in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// True iff the index has no cross-file edges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Drop every cross-file edge whose source segment is `seg`.
    /// Used by hot-reload when segment `seg` is being recomputed —
    /// callers re-stitch the new edges after this call. Returns the
    /// number of edges dropped.
    pub fn invalidate_from_segment(&mut self, seg: SegmentId) -> usize {
        let to_drop: ahash::AHashSet<u32> = self
            .by_from_segment
            .remove(&seg)
            .map(|ixs| ixs.into_iter().collect())
            .unwrap_or_default();
        if to_drop.is_empty() {
            return 0;
        }
        let dropped = to_drop.len();
        // Remove from `by_to_segment` too. Because invalidation is
        // O(edges-from-seg) per file edit, this scan is bounded by
        // the typical fan-out of a single source file.
        for ixs in self.by_to_segment.values_mut() {
            ixs.retain(|i| !to_drop.contains(i));
        }
        // Compact the edges vec: build a new index for surviving
        // entries, rewrite both reverse maps to the new indices.
        let mut compacted: Vec<CrossFileEdge> = Vec::with_capacity(self.edges.len() - dropped);
        let mut remap: AHashMap<u32, u32> = AHashMap::with_capacity(self.edges.len() - dropped);
        for (old_idx, edge) in self.edges.drain(..).enumerate() {
            let old = old_idx as u32;
            if to_drop.contains(&old) {
                continue;
            }
            let new = u32::try_from(compacted.len()).expect("compacted len fits u32");
            remap.insert(old, new);
            compacted.push(edge);
        }
        self.edges = compacted;
        for ixs in self
            .by_from_segment
            .values_mut()
            .chain(self.by_to_segment.values_mut())
        {
            for ix in ixs.iter_mut() {
                if let Some(new) = remap.get(ix) {
                    *ix = *new;
                }
            }
        }
        dropped
    }

    /// Rebuild reverse-lookup indexes after deserialisation.
    pub fn rebuild_indexes(&mut self) {
        self.by_from_segment.clear();
        self.by_to_segment.clear();
        for (idx, edge) in self.edges.iter().enumerate() {
            let i = idx as u32;
            self.by_from_segment.entry(edge.from_segment).or_default().push(i);
            self.by_to_segment.entry(edge.to_segment).or_default().push(i);
        }
    }
}

/// Workspace-level IDG. Holds per-file segments, the cross-file
/// edge index, and the `FuncId → SegmentId` lookup map.
///
/// Persisted as a single versioned factstore payload under `.bonsai/`
/// via [`Self::save_to_disk`]. The workspace open path tries
/// [`Self::load_from_disk`] before triggering a full rebuild, so an
/// already-indexed workspace skips the heavy
/// `workspace_adapter::build_with_aliases` pass on every CLI invocation.
#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct IdgWorkspace {
    segments: Vec<IdgSegment>,
    /// `FuncId.raw() → SegmentId`. Rebuilt from each segment's `funcs`
    /// list after deserialisation; bincode skips it on the wire.
    #[serde(skip)]
    by_func: AHashMap<u32, SegmentId>,
    /// Cross-file edges. Populated by the workspace builder
    /// (Phase 3).
    cross_file: CrossFileEdges,
    /// Cross-method field-flow links surfaced by Phase 3c. These
    /// aren't true call edges — they record that a writer-method's
    /// receiver-field write feeds a reader-method's receiver-field
    /// read. The query layer
    /// ([`crate::service::IdgQueryService::cross_call_edges_in_closure`]) lifts each
    /// link into a synthetic [`crate::service::CrossCallEdge`] when both endpoints
    /// land in the same forward closure, so source/sink lineage and
    /// `find-group` chain enumeration can traverse cross-method
    /// state propagation the same way they traverse real calls.
    field_flow: Vec<FieldFlowLink>,
    /// Compact AST/resolver-derived access-path transform algebra. Query
    /// services interpret this relation without expanding every concrete
    /// suffix into the ordinary edge table.
    symbolic_field: SymbolicFieldGraph,
}

impl IdgWorkspace {
    /// Construct an empty workspace IDG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `segment` with the workspace and return its
    /// [`SegmentId`]. Updates the `FuncId → SegmentId` index.
    pub fn register_segment(&mut self, segment: IdgSegment) -> SegmentId {
        let raw = u32::try_from(self.segments.len()).expect("segment index overflow: > 2^32 segments");
        let id = SegmentId(raw);
        for func_raw in &segment.funcs {
            self.by_func.insert(*func_raw, id);
        }
        self.segments.push(segment);
        id
    }

    /// Look up the segment that owns `func`.
    #[must_use]
    pub fn segment_for_func(&self, func: FuncId) -> Option<SegmentId> {
        self.by_func.get(&func.raw()).copied()
    }

    /// Borrow segment `id`. `None` for invalid ids.
    #[must_use]
    pub fn segment(&self, id: SegmentId) -> Option<&IdgSegment> {
        self.segments.get(id.0 as usize)
    }

    /// Mutably borrow segment `id`.
    pub fn segment_mut(&mut self, id: SegmentId) -> Option<&mut IdgSegment> {
        self.segments.get_mut(id.0 as usize)
    }

    /// Iterate every segment.
    pub fn segments(&self) -> impl Iterator<Item = (SegmentId, &IdgSegment)> + '_ {
        self.segments
            .iter()
            .enumerate()
            .map(|(i, s)| (SegmentId(i as u32), s))
    }

    /// Number of segments registered.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Total number of functions across all segments.
    #[must_use]
    pub fn func_count(&self) -> usize {
        self.by_func.len()
    }

    /// Total number of intra-segment edges across the workspace.
    #[must_use]
    pub fn intra_edge_count(&self) -> usize {
        self.segments.iter().map(|s| s.edges.len()).sum()
    }

    /// Borrow the cross-file edge index.
    #[must_use]
    pub fn cross_file(&self) -> &CrossFileEdges {
        &self.cross_file
    }

    /// Read-only access to the cross-method field-flow links.
    pub fn field_flow(&self) -> &[FieldFlowLink] {
        &self.field_flow
    }

    /// Mutable access for Phase 3c to push field-flow links during
    /// IDG construction.
    pub fn field_flow_mut(&mut self) -> &mut Vec<FieldFlowLink> {
        &mut self.field_flow
    }

    /// Borrow the symbolic access-path relation.
    #[must_use]
    pub fn symbolic_field(&self) -> &SymbolicFieldGraph {
        &self.symbolic_field
    }

    /// Replace the symbolic access-path relation after Phase 3 stitching.
    pub fn set_symbolic_field(&mut self, graph: SymbolicFieldGraph) {
        self.symbolic_field = graph;
    }

    /// Mutable access for the IDG builder phase 3 to push
    /// cross-file edges as it stitches them.
    pub fn cross_file_mut(&mut self) -> &mut CrossFileEdges {
        &mut self.cross_file
    }

    /// Total edge count: intra-segment + cross-file.
    #[must_use]
    pub fn total_edge_count(&self) -> usize {
        self.intra_edge_count() + self.cross_file.len()
    }

    /// Persist the entire workspace IDG to `path` as a streamed
    /// factstore. Each segment is serialised as its own factstore
    /// entry (key = segment index + 1) so peak RAM during persistence
    /// is bounded by the writer's small, backpressured pipeline of
    /// active/queued bincode buffers, not the whole IDG. Each serialized
    /// `Vec<u8>` moves into the writer without a second payload copy.
    /// A 100K-LOC C codebase's IDG can occupy several GB in memory; the
    /// previous single-buffer `bincode::serialize` path needed that much
    /// RAM again during the write, OOM'ing processes that the in-memory
    /// build had already cleared.
    ///
    /// Entry 0 holds the per-workspace metadata and chunk counts.
    /// Segments, cross-file edges, and field-flow links are written as
    /// separate entries so no individual factstore payload needs to
    /// approach the factstore format's 4GiB per-entry limit.
    ///
    /// `pipeline_hash` is folded into the factstore header so a
    /// matcher-policy bump (or any consumer that wants the IDG
    /// invalidated together) naturally rejects a stale sidecar.
    pub fn save_to_disk(&self, path: &std::path::Path, pipeline_hash: u64) -> crate::IdgResult<()> {
        use bonsai_factstore::FactStoreWriter;
        let cross_file_chunk_count = chunk_count(self.cross_file.edges.len(), IDG_WORKSPACE_EDGE_CHUNK_LEN);
        let field_flow_chunk_count = chunk_count(self.field_flow.len(), IDG_WORKSPACE_FIELD_FLOW_CHUNK_LEN);
        let symbolic_transform_chunk_count = chunk_count(
            self.symbolic_field.transforms().len(),
            IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN,
        );
        let entry_count = 1usize
            .saturating_add(self.segments.len())
            .saturating_add(cross_file_chunk_count)
            .saturating_add(field_flow_chunk_count)
            .saturating_add(1)
            .saturating_add(symbolic_transform_chunk_count);
        let writer = FactStoreWriter::create_with_capacity(
            path,
            IDG_WORKSPACE_TABLE_ID,
            pipeline_hash,
            entry_count,
            entry_count.saturating_mul(64 * 1024),
            entry_count.saturating_mul(64),
        )?;
        let metadata = IdgWorkspaceMetadata {
            version: IDG_WORKSPACE_VERSION,
            segment_count: self.segments.len() as u32,
            cross_file_edge_count: self.cross_file.edges.len() as u64,
            cross_file_chunk_count: cross_file_chunk_count as u32,
            field_flow_count: self.field_flow.len() as u64,
            field_flow_chunk_count: field_flow_chunk_count as u32,
            symbolic_string_count: self.symbolic_field.strings().len() as u64,
            symbolic_base_count: self.symbolic_field.bases().len() as u64,
            symbolic_transform_count: self.symbolic_field.transforms().len() as u64,
            symbolic_transform_chunk_count: symbolic_transform_chunk_count as u32,
        };
        let meta_bytes = bincode::serialize(&metadata)
            .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        writer.add_owned(0, IDG_WORKSPACE_VERSION as u64, meta_bytes)?;
        for (idx, segment) in self.segments.iter().enumerate() {
            let segment_bytes = bincode::serialize(segment)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            writer.add_owned((idx + 1) as u64, IDG_WORKSPACE_VERSION as u64, segment_bytes)?;
        }
        let cross_base = first_cross_file_chunk_key(self.segments.len() as u32);
        for (idx, chunk) in self
            .cross_file
            .edges
            .chunks(IDG_WORKSPACE_EDGE_CHUNK_LEN)
            .enumerate()
        {
            let bytes = bincode::serialize(chunk)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            writer.add_owned(cross_base + idx as u64, IDG_WORKSPACE_VERSION as u64, bytes)?;
        }
        let field_base =
            first_field_flow_chunk_key(self.segments.len() as u32, cross_file_chunk_count as u32);
        for (idx, chunk) in self
            .field_flow
            .chunks(IDG_WORKSPACE_FIELD_FLOW_CHUNK_LEN)
            .enumerate()
        {
            let bytes = bincode::serialize(chunk)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            writer.add_owned(field_base + idx as u64, IDG_WORKSPACE_VERSION as u64, bytes)?;
        }
        let symbolic_header = symbolic_field_header_key(
            self.segments.len() as u32,
            cross_file_chunk_count as u32,
            field_flow_chunk_count as u32,
        );
        let header_bytes = bincode::serialize(&(self.symbolic_field.strings(), self.symbolic_field.bases()))
            .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        writer.add_owned(symbolic_header, IDG_WORKSPACE_VERSION as u64, header_bytes)?;
        let transform_base = symbolic_header + 1;
        for (idx, chunk) in self
            .symbolic_field
            .transforms()
            .chunks(IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN)
            .enumerate()
        {
            let bytes = bincode::serialize(chunk)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            writer.add_owned(transform_base + idx as u64, IDG_WORKSPACE_VERSION as u64, bytes)?;
        }
        writer.finish()?;
        Ok(())
    }

    /// Load a workspace IDG from `path`. Returns `Ok(None)` for missing
    /// files, version drift, or `pipeline_hash` mismatch — the caller
    /// rebuilds in those cases. Returns `Err` for genuine I/O / decode
    /// errors. After load, rebuilds the `FuncId → SegmentId` lookup
    /// and each segment's reverse-lookup dictionaries.
    pub fn load_from_disk(path: &std::path::Path, pipeline_hash: u64) -> crate::IdgResult<Option<Self>> {
        if !path.exists() {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace sidecar miss: path={} reason=missing",
                path.display()
            );
            return Ok(None);
        }
        let reader =
            match bonsai_factstore::FactStoreReader::open(path, IDG_WORKSPACE_TABLE_ID, pipeline_hash) {
                Ok(reader) => reader,
                Err(err) => {
                    bonsai_diagnostics::debug_log!(
                        "idg-build",
                        "workspace sidecar miss: path={} reason=open-error error={} expected_pipeline={:#x}",
                        path.display(),
                        err,
                        pipeline_hash
                    );
                    return Ok(None);
                }
            };
        let Some(metadata_hit) = reader.get(0)? else {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace sidecar miss: path={} reason=missing-metadata",
                path.display()
            );
            return Ok(None);
        };
        if metadata_hit.body_hash != IDG_WORKSPACE_VERSION as u64 {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace sidecar miss: path={} reason=metadata-version body_hash={} expected={}",
                path.display(),
                metadata_hit.body_hash,
                IDG_WORKSPACE_VERSION
            );
            return Ok(None);
        }
        let metadata: IdgWorkspaceMetadataOwned = bincode::deserialize(&metadata_hit.payload)
            .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        if metadata.version != IDG_WORKSPACE_VERSION {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace sidecar miss: path={} reason=metadata-payload-version version={} expected={}",
                path.display(),
                metadata.version,
                IDG_WORKSPACE_VERSION
            );
            return Ok(None);
        }
        let mut ws = Self {
            segments: Vec::with_capacity(metadata.segment_count as usize),
            by_func: AHashMap::new(),
            cross_file: CrossFileEdges::new(),
            field_flow: Vec::with_capacity(metadata.field_flow_count.min(usize::MAX as u64) as usize),
            symbolic_field: SymbolicFieldGraph::new(),
        };
        for idx in 0..metadata.segment_count {
            let Some(hit) = reader.get((idx + 1) as u64)? else {
                // Truncated sidecar — fail-closed so the caller rebuilds.
                bonsai_diagnostics::debug_log!(
                    "idg-build",
                    "workspace sidecar miss: path={} reason=missing-segment segment={}",
                    path.display(),
                    idx
                );
                return Ok(None);
            };
            let mut segment: IdgSegment = bincode::deserialize(&hit.payload)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            if segment.version != IDG_SEGMENT_VERSION {
                bonsai_diagnostics::debug_log!(
                    "idg-build",
                    "workspace sidecar miss: path={} reason=segment-version segment={} version={} expected={}",
                    path.display(),
                    idx,
                    segment.version,
                    IDG_SEGMENT_VERSION
                );
                return Ok(None);
            }
            segment.places.rebuild_lookup();
            segment.nodes.rebuild_lookup();
            segment.strings.rebuild_lookup();
            let seg_id = SegmentId(idx);
            for func_raw in &segment.funcs {
                ws.by_func.insert(*func_raw, seg_id);
            }
            ws.segments.push(segment);
        }
        let cross_base = first_cross_file_chunk_key(metadata.segment_count);
        for chunk_idx in 0..metadata.cross_file_chunk_count {
            let Some(hit) = reader.get(cross_base + u64::from(chunk_idx))? else {
                bonsai_diagnostics::debug_log!(
                    "idg-build",
                    "workspace sidecar miss: path={} reason=missing-cross-file-chunk chunk={}",
                    path.display(),
                    chunk_idx
                );
                return Ok(None);
            };
            let chunk: Vec<CrossFileEdge> = bincode::deserialize(&hit.payload)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            for edge in chunk {
                ws.cross_file.push(edge);
            }
        }
        if ws.cross_file.len() as u64 != metadata.cross_file_edge_count {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace sidecar miss: path={} reason=cross-file-count loaded={} expected={}",
                path.display(),
                ws.cross_file.len(),
                metadata.cross_file_edge_count
            );
            return Ok(None);
        }
        let field_base = first_field_flow_chunk_key(metadata.segment_count, metadata.cross_file_chunk_count);
        for chunk_idx in 0..metadata.field_flow_chunk_count {
            let Some(hit) = reader.get(field_base + u64::from(chunk_idx))? else {
                bonsai_diagnostics::debug_log!(
                    "idg-build",
                    "workspace sidecar miss: path={} reason=missing-field-flow-chunk chunk={}",
                    path.display(),
                    chunk_idx
                );
                return Ok(None);
            };
            let chunk: Vec<FieldFlowLink> = bincode::deserialize(&hit.payload)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            ws.field_flow.extend(chunk);
        }
        if ws.field_flow.len() as u64 != metadata.field_flow_count {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace sidecar miss: path={} reason=field-flow-count loaded={} expected={}",
                path.display(),
                ws.field_flow.len(),
                metadata.field_flow_count
            );
            return Ok(None);
        }
        let symbolic_header = symbolic_field_header_key(
            metadata.segment_count,
            metadata.cross_file_chunk_count,
            metadata.field_flow_chunk_count,
        );
        let Some(header_hit) = reader.get(symbolic_header)? else {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace sidecar miss: path={} reason=missing-symbolic-field-header",
                path.display()
            );
            return Ok(None);
        };
        let (strings, bases): (Vec<String>, Vec<SymbolicFieldBase>) =
            bincode::deserialize(&header_hit.payload)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        if strings.len() as u64 != metadata.symbolic_string_count
            || bases.len() as u64 != metadata.symbolic_base_count
        {
            return Ok(None);
        }
        let mut symbolic = SymbolicFieldGraph::from_parts(strings, bases, Vec::new());
        for chunk_idx in 0..metadata.symbolic_transform_chunk_count {
            let Some(hit) = reader.get(symbolic_header + 1 + u64::from(chunk_idx))? else {
                bonsai_diagnostics::debug_log!(
                    "idg-build",
                    "workspace sidecar miss: path={} reason=missing-symbolic-transform-chunk chunk={}",
                    path.display(),
                    chunk_idx
                );
                return Ok(None);
            };
            let chunk: Vec<SymbolicFieldTransform> = bincode::deserialize(&hit.payload)
                .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            symbolic.extend_transforms(chunk);
        }
        if symbolic.transforms().len() as u64 != metadata.symbolic_transform_count {
            return Ok(None);
        }
        ws.symbolic_field = symbolic;
        ws.cross_file.rebuild_indexes();
        bonsai_diagnostics::debug_log!(
            "idg-build",
            "workspace sidecar loaded: path={} segments={} funcs={} total_edges={} field_links={}",
            path.display(),
            ws.segment_count(),
            ws.by_func.len(),
            ws.total_edge_count(),
            ws.field_flow.len()
        );
        Ok(Some(ws))
    }

    /// Validate that a workspace IDG sidecar is structurally readable and
    /// decodes with the pipeline hash stamped in its factstore header.
    /// This does not prove the sidecar is fresh for a specific workspace;
    /// callers combine it with source/dependency/build freshness checks or
    /// use [`Self::load_from_disk`] when they have an expected pipeline hash.
    pub fn validate_sidecar_file(path: &std::path::Path) -> crate::IdgResult<usize> {
        let reader = bonsai_factstore::FactStoreReader::open_relaxed(path)?;
        if reader.header().table_id != IDG_WORKSPACE_TABLE_ID {
            return Err(crate::IdgError::WrongTable {
                got: reader.header().table_id,
                expected: IDG_WORKSPACE_TABLE_ID,
            });
        }
        let pipeline_hash = reader.header().pipeline_hash;
        drop(reader);
        let Some(workspace) = Self::load_from_disk(path, pipeline_hash)? else {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace IDG sidecar did not decode to a valid workspace",
            )));
        };
        Ok(workspace.segment_count())
    }
}

/// Per-workspace metadata written at entry 0 of the streamed IDG
/// sidecar. Large edge/link payloads are stored in fixed-size chunks
/// after the segment entries.
#[derive(serde::Serialize)]
struct IdgWorkspaceMetadata {
    version: u32,
    segment_count: u32,
    cross_file_edge_count: u64,
    cross_file_chunk_count: u32,
    field_flow_count: u64,
    field_flow_chunk_count: u32,
    symbolic_string_count: u64,
    symbolic_base_count: u64,
    symbolic_transform_count: u64,
    symbolic_transform_chunk_count: u32,
}

/// Owned mirror of [`IdgWorkspaceMetadata`] used by the load path.
#[derive(serde::Deserialize)]
struct IdgWorkspaceMetadataOwned {
    version: u32,
    segment_count: u32,
    cross_file_edge_count: u64,
    cross_file_chunk_count: u32,
    field_flow_count: u64,
    field_flow_chunk_count: u32,
    symbolic_string_count: u64,
    symbolic_base_count: u64,
    symbolic_transform_count: u64,
    symbolic_transform_chunk_count: u32,
}

/// Factstore table id for the workspace-wide IDG sidecar. Distinct
/// from [`crate::segment::IDG_SEGMENT_TABLE_ID`] so a single `.bonsai/`
/// directory can hold both formats without ambiguity.
const IDG_WORKSPACE_TABLE_ID: u32 = 101;

/// Wire-format/semantic version for the workspace IDG sidecar. Bump on
/// any incompatible persisted-shape change (e.g. new field on
/// [`IdgSegment`], renamed enum variant in [`crate::place::Place`]) or
/// source-to-call edge semantic change that can leave old facts
/// structurally decodable but security-significant.
const IDG_WORKSPACE_VERSION: u32 = 10;

#[cfg(not(test))]
const IDG_WORKSPACE_EDGE_CHUNK_LEN: usize = 100_000;
#[cfg(test)]
const IDG_WORKSPACE_EDGE_CHUNK_LEN: usize = 2;
#[cfg(not(test))]
const IDG_WORKSPACE_FIELD_FLOW_CHUNK_LEN: usize = 100_000;
#[cfg(test)]
const IDG_WORKSPACE_FIELD_FLOW_CHUNK_LEN: usize = 2;
#[cfg(not(test))]
const IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN: usize = 100_000;
#[cfg(test)]
const IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN: usize = 2;

fn chunk_count(len: usize, chunk_len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len.div_ceil(chunk_len)
    }
}

fn first_cross_file_chunk_key(segment_count: u32) -> u64 {
    1 + u64::from(segment_count)
}

fn first_field_flow_chunk_key(segment_count: u32, cross_file_chunk_count: u32) -> u64 {
    first_cross_file_chunk_key(segment_count) + u64::from(cross_file_chunk_count)
}

fn symbolic_field_header_key(
    segment_count: u32,
    cross_file_chunk_count: u32,
    field_flow_chunk_count: u32,
) -> u64 {
    first_field_flow_chunk_key(segment_count, cross_file_chunk_count) + u64::from(field_flow_chunk_count)
}

/// Conventional sidecar path under `<workspace>/.bonsai/`.
#[must_use]
pub fn idg_sidecar_path(workspace_root: &std::path::Path) -> std::path::PathBuf {
    bonsai_common::workspace_bonsai_dir(workspace_root)
        .join(format!("idg.v{IDG_WORKSPACE_VERSION}.factstore"))
}

/// Rulepack-transfer-specific sidecar path under `<workspace>/.bonsai/`.
///
/// Transfer options alter IDG edges, so security analysis cannot reuse
/// the default source-structure sidecar. The caller supplies a stable
/// fingerprint of the configured transfer semantics.
#[must_use]
pub fn idg_transfer_sidecar_path(workspace_root: &std::path::Path, transfer_hash: u64) -> std::path::PathBuf {
    bonsai_common::workspace_bonsai_dir(workspace_root).join(format!(
        "idg.v{IDG_WORKSPACE_VERSION}.transfer.{transfer_hash:016x}.factstore"
    ))
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod tests;
