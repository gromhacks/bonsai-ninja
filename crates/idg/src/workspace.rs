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
use bonsai_common::{wire, FuncId};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;

use crate::edge::IdgEdge;
use crate::segment::{IdgSegment, IDG_SEGMENT_VERSION};
use crate::symbolic::{SymbolicFieldBase, SymbolicFieldGraph, SymbolicFieldTransform};

/// Stable handle to a segment in the workspace's segment list.
/// Distinct from `FuncId`; multiple FuncIds map to one SegmentId.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SegmentId(pub u32);

/// Borrowed or page-cached view of one source-file IDG segment.
///
/// Resident compiler workspaces borrow their canonical segment directly.
/// Warm query workspaces retain an `Arc` only for the cache working set; the
/// same API therefore preserves exact segment contents without forcing every
/// persisted compilation unit into memory.
pub(crate) enum SegmentView<'a> {
    Resident(&'a IdgSegment),
    Paged(Arc<IdgSegment>),
}

impl Deref for SegmentView<'_> {
    type Target = IdgSegment;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Resident(segment) => segment,
            Self::Paged(segment) => segment,
        }
    }
}

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

#[derive(Copy, Clone, Debug)]
struct SpoolEntry {
    offset: u64,
    encoded_len: u64,
    node_count: u32,
    edge_count: usize,
}

/// Append-only compiler spill for canonical IDG segments.
///
/// Persistence builds rewrite one source-file segment at a time. Appending a
/// new version and replacing its tiny offset-table entry keeps memory bounded
/// by the largest compilation unit while preserving the exact canonical wire
/// payload. The prepared FactStore payload disappears automatically on every
/// error path and is adopted directly by the final atomic writer on success.
#[derive(Debug)]
pub(crate) struct IdgSegmentSpool {
    file: bonsai_factstore::PreparedFactStorePayload,
    entries: Vec<Option<SpoolEntry>>,
    generation: Option<SpoolGeneration>,
    target: std::path::PathBuf,
}

#[derive(Debug)]
struct SpoolGeneration {
    file: bonsai_factstore::PreparedFactStorePayload,
    entries: Vec<Option<SpoolEntry>>,
}

#[derive(Copy, Clone, Debug)]
struct WireChunkEntry {
    offset: u64,
    encoded_len: u32,
}

#[derive(Debug)]
pub(crate) struct WireChunkSpool<T> {
    file: bonsai_factstore::PreparedFactStorePayload,
    entries: Vec<WireChunkEntry>,
    buffer: Vec<T>,
    item_count: usize,
    chunk_len: usize,
    kind: &'static str,
    error: Option<String>,
}

impl<T> WireChunkSpool<T> {
    pub(crate) fn new(
        target: &std::path::Path,
        chunk_len: usize,
        kind: &'static str,
    ) -> crate::IdgResult<Self> {
        Ok(Self {
            file: bonsai_factstore::PreparedFactStorePayload::create_near(target)?,
            entries: Vec::new(),
            buffer: Vec::with_capacity(chunk_len),
            item_count: 0,
            chunk_len,
            kind,
            error: None,
        })
    }

    pub(crate) fn push(&mut self, item: T)
    where
        T: serde::Serialize,
    {
        if self.error.is_some() {
            return;
        }
        self.buffer.push(item);
        self.item_count = self.item_count.saturating_add(1);
        if self.buffer.len() == self.chunk_len {
            if let Err(error) = self.flush_buffer() {
                self.error = Some(error.to_string());
                self.buffer.clear();
            }
        }
    }

    fn flush_buffer(&mut self) -> crate::IdgResult<()>
    where
        T: serde::Serialize,
    {
        self.check_error()?;
        if self.buffer.is_empty() {
            return Ok(());
        }
        let payload = encode_sidecar_value(self.buffer.as_slice())?;
        let (offset, encoded_len) = self.file.append(&payload)?;
        self.entries.push(WireChunkEntry { offset, encoded_len });
        self.buffer.clear();
        Ok(())
    }

    pub(crate) fn check_error(&self) -> crate::IdgResult<()> {
        if let Some(error) = &self.error {
            return Err(crate::IdgError::Io(std::io::Error::other(format!(
                "{} spool failed: {error}",
                self.kind
            ))));
        }
        Ok(())
    }

    pub(crate) fn visit<F>(&self, mut visit: F) -> crate::IdgResult<()>
    where
        T: serde::de::DeserializeOwned,
        F: FnMut(&[T]) -> crate::IdgResult<()>,
    {
        self.check_error()?;
        let mut file = self.file.try_clone_file()?;
        for entry in &self.entries {
            file.seek(SeekFrom::Start(entry.offset))?;
            let mut payload = vec![0_u8; entry.encoded_len as usize];
            file.read_exact(&mut payload)?;
            let items: Vec<T> = wire::decode(&payload).map_err(|error| {
                crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })?;
            if items.len() != self.chunk_len {
                return Err(crate::IdgError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} spool contains a non-canonical full chunk", self.kind),
                )));
            }
            visit(&items)?;
        }
        visit(&self.buffer)
    }

    /// Consume the spool and visit owned decoded chunks. Compiler replay uses
    /// this form so a record moves directly into the next phase without a
    /// second in-memory clone of its typed IR.
    pub(crate) fn into_visit<F>(mut self, mut visit: F) -> crate::IdgResult<()>
    where
        T: serde::de::DeserializeOwned,
        F: FnMut(Vec<T>) -> crate::IdgResult<()>,
    {
        self.check_error()?;
        let mut file = self.file.try_clone_file()?;
        for entry in &self.entries {
            file.seek(SeekFrom::Start(entry.offset))?;
            let mut payload = vec![0_u8; entry.encoded_len as usize];
            file.read_exact(&mut payload)?;
            let items: Vec<T> = wire::decode(&payload).map_err(|error| {
                crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })?;
            if items.len() != self.chunk_len {
                return Err(crate::IdgError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} spool contains a non-canonical full chunk", self.kind),
                )));
            }
            visit(items)?;
        }
        if !self.buffer.is_empty() {
            visit(std::mem::take(&mut self.buffer))?;
        }
        Ok(())
    }

    fn write_chunks(
        mut self,
        writer: &bonsai_factstore::FactStoreWriter,
        first_key: u64,
    ) -> crate::IdgResult<()>
    where
        T: serde::Serialize,
    {
        self.flush_buffer()?;
        self.check_error()?;
        for (index, entry) in self.entries.into_iter().enumerate() {
            let mut file = self.file.try_clone_file()?;
            writer.add_streamed(
                first_key + index as u64,
                IDG_WORKSPACE_VERSION as u64,
                move |output| {
                    file.seek(SeekFrom::Start(entry.offset))?;
                    let copied = std::io::copy(&mut file.take(u64::from(entry.encoded_len)), output)?;
                    if copied != u64::from(entry.encoded_len) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            format!("{} spool payload was truncated", self.kind),
                        ));
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.item_count
    }

    fn chunk_count(&self) -> usize {
        chunk_count(self.item_count, self.chunk_len)
    }
}

/// Append-only exact wire chunks for sidecar-only cross-file edges.
///
/// A compiler build never queries the finished graph in-process. Retaining
/// millions of cross edges in a growing `Vec` therefore adds no semantic
/// value and can briefly require both the old and new allocation during a
/// capacity increase. The shared wire spool retains one canonical chunk in
/// memory, supports streamed compiler scans, and later copies the already-
/// encoded chunks into the final FactStore.
type CrossFileEdgeSpool = WireChunkSpool<CrossFileEdge>;
type SymbolicTransformSpool = WireChunkSpool<SymbolicFieldTransform>;

/// Compiler-owned symbolic access-path relation.
///
/// Query graphs retain transforms and build their outgoing index. Sidecar-only
/// compilers retain only the numeric string/base dictionaries and stream every
/// transform in canonical insertion order. The two modes therefore have the
/// same wire facts while choosing different memory lifetimes.
pub(crate) struct SymbolicFieldCompilerStorage {
    graph: SymbolicFieldGraph,
    transform_spool: Option<SymbolicTransformSpool>,
}

impl SymbolicFieldCompilerStorage {
    pub(crate) fn resident() -> Self {
        Self {
            graph: SymbolicFieldGraph::new(),
            transform_spool: None,
        }
    }

    pub(crate) fn spooled(target: &std::path::Path) -> crate::IdgResult<Self> {
        Ok(Self {
            graph: SymbolicFieldGraph::new(),
            transform_spool: Some(WireChunkSpool::new(
                target,
                IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN,
                "symbolic field transform",
            )?),
        })
    }

    pub(crate) fn intern_string(&mut self, value: &str) -> u32 {
        self.graph.intern_string(value)
    }

    pub(crate) fn intern_base(&mut self, segment: SegmentId, func: FuncId, storage: &str) -> u32 {
        self.graph.intern_base(segment, func, storage)
    }

    pub(crate) fn push_transform(&mut self, transform: SymbolicFieldTransform) {
        if let Some(spool) = &mut self.transform_spool {
            spool.push(transform);
        } else {
            self.graph.push_transform(transform);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.transform_count() == 0
    }

    pub(crate) fn transform_count(&self) -> usize {
        self.transform_spool
            .as_ref()
            .map_or_else(|| self.graph.transforms().len(), WireChunkSpool::len)
    }

    pub(crate) fn bases(&self) -> &[SymbolicFieldBase] {
        self.graph.bases()
    }

    pub(crate) fn string(&self, id: u32) -> Option<&str> {
        self.graph.string(id)
    }

    pub(crate) fn visit_transforms<F>(&self, mut visit: F) -> crate::IdgResult<()>
    where
        F: FnMut(&[SymbolicFieldTransform]) -> crate::IdgResult<()>,
    {
        if let Some(spool) = &self.transform_spool {
            spool.visit(visit)
        } else {
            visit(self.graph.transforms())
        }
    }

    pub(crate) fn check_spool(&self) -> crate::IdgResult<()> {
        self.transform_spool
            .as_ref()
            .map_or(Ok(()), WireChunkSpool::check_error)
    }
}

impl IdgSegmentSpool {
    fn new(target: &std::path::Path) -> crate::IdgResult<Self> {
        Ok(Self {
            file: bonsai_factstore::PreparedFactStorePayload::create_near(target)?,
            entries: Vec::new(),
            generation: None,
            target: target.to_path_buf(),
        })
    }

    fn write_segment(&mut self, id: SegmentId, segment: &IdgSegment) -> crate::IdgResult<()> {
        let payload = wire::encode(segment)
            .map_err(|err| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err)))?;
        let (file, entries) = self
            .generation
            .as_mut()
            .map_or((&mut self.file, &mut self.entries), |generation| {
                (&mut generation.file, &mut generation.entries)
            });
        let (offset, encoded_len) = file.append(&payload)?;
        let index = id.0 as usize;
        if entries.len() <= index {
            entries.resize(index + 1, None);
        }
        entries[index] = Some(SpoolEntry {
            offset,
            encoded_len: u64::from(encoded_len),
            node_count: u32::try_from(segment.nodes.len()).expect("segment node count exceeds u32"),
            edge_count: segment.edges.len(),
        });
        Ok(())
    }

    fn read_segment(&mut self, id: SegmentId) -> crate::IdgResult<IdgSegment> {
        let index = id.0 as usize;
        let from_generation = self
            .generation
            .as_ref()
            .and_then(|generation| generation.entries.get(index))
            .copied()
            .flatten();
        let entry = from_generation.map_or_else(|| self.entry(id), Ok)?;
        let len = usize::try_from(entry.encoded_len).map_err(|_| {
            crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "spooled IDG segment exceeds addressable memory",
            ))
        })?;
        let mut payload = vec![0_u8; len];
        let mut file = if from_generation.is_some() {
            self.generation
                .as_ref()
                .expect("generation entry checked above")
                .file
                .try_clone_file()?
        } else {
            self.file.try_clone_file()?
        };
        file.seek(SeekFrom::Start(entry.offset))?;
        file.read_exact(&mut payload)?;
        let segment: IdgSegment = wire::decode(&payload)
            .map_err(|err| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err)))?;
        if segment.version != IDG_SEGMENT_VERSION {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "spooled IDG segment version mismatch",
            )));
        }
        Ok(segment)
    }

    fn entry(&self, id: SegmentId) -> crate::IdgResult<SpoolEntry> {
        if let Some(entry) = self
            .generation
            .as_ref()
            .and_then(|generation| generation.entries.get(id.0 as usize))
            .copied()
            .flatten()
        {
            return Ok(entry);
        }
        self.entries.get(id.0 as usize).copied().flatten().ok_or_else(|| {
            crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("missing spooled IDG segment {}", id.0),
            ))
        })
    }

    fn edge_count(&self, id: SegmentId) -> usize {
        self.entry(id).map_or(0, |entry| entry.edge_count)
    }

    fn node_count(&self, id: SegmentId) -> u32 {
        self.entry(id).map_or(0, |entry| entry.node_count)
    }

    fn len(&self) -> usize {
        self.generation.as_ref().map_or(self.entries.len(), |generation| {
            self.entries.len().max(generation.entries.len())
        })
    }

    fn begin_generation(&mut self) -> crate::IdgResult<()> {
        if self.generation.is_some() {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IDG spool generation already active",
            )));
        }
        self.generation = Some(SpoolGeneration {
            file: bonsai_factstore::PreparedFactStorePayload::create_near(&self.target)?,
            entries: vec![None; self.entries.len()],
        });
        Ok(())
    }

    fn finish_generation(&mut self) -> crate::IdgResult<()> {
        let generation = self.generation.take().ok_or_else(|| {
            crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IDG spool generation is not active",
            ))
        })?;
        if generation.entries.len() != self.entries.len() || generation.entries.iter().any(Option::is_none) {
            self.generation = Some(generation);
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IDG spool generation did not rewrite every compiler segment",
            )));
        }
        self.file = generation.file;
        self.entries = generation.entries;
        Ok(())
    }

    fn into_factstore_writer(
        self,
        path: &std::path::Path,
        pipeline_hash: u64,
    ) -> crate::IdgResult<bonsai_factstore::FactStoreWriter> {
        if self.generation.is_some() {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot persist an active IDG spool generation",
            )));
        }
        let entries = self
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| {
                let entry = entry.ok_or_else(|| {
                    crate::IdgError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("missing spooled IDG segment {index}"),
                    ))
                })?;
                let payload_len = u32::try_from(entry.encoded_len).map_err(|_| {
                    crate::IdgError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "spooled IDG segment exceeds the FactStore entry limit",
                    ))
                })?;
                Ok(bonsai_factstore::PreparedFactStoreEntry {
                    key: (index + 1) as u64,
                    body_hash: IDG_WORKSPACE_VERSION as u64,
                    payload_offset: entry.offset,
                    payload_len,
                })
            })
            .collect::<crate::IdgResult<Vec<_>>>()?;
        bonsai_factstore::FactStoreWriter::create_from_prepared(
            path,
            IDG_WORKSPACE_TABLE_ID,
            pipeline_hash,
            self.file,
            entries,
        )
        .map_err(Into::into)
    }
}

/// Canonical cross-file edges with optional forward/backward indexes.
/// Query-built workspaces maintain both indexes as edges are appended;
/// persisted builds and warm loads defer them to avoid duplicating a
/// whole-workspace relation in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileEdges {
    /// Every cross-file edge, in stable insertion order. Indexed by
    /// CrossFileEdgeId (a `usize` cast).
    pub edges: Vec<CrossFileEdge>,
    /// `caller_segment → indices into edges` for forward queries.
    /// Skipped in serde; canonical-vector lookup remains exact when empty.
    #[serde(skip)]
    by_from_segment: AHashMap<SegmentId, Vec<u32>>,
    /// `callee_segment → indices into edges` for backward queries.
    #[serde(skip)]
    by_to_segment: AHashMap<SegmentId, Vec<u32>>,
    /// Sidecar-only compiler builds persist the canonical edge vector and do
    /// not answer queries in-process. Avoid retaining two additional edge-id
    /// vectors while that canonical graph is growing. Warm loads keep the
    /// canonical representation and service-owned compact views.
    #[serde(skip)]
    maintain_indexes: bool,
}

impl Default for CrossFileEdges {
    fn default() -> Self {
        Self {
            edges: Vec::new(),
            by_from_segment: AHashMap::new(),
            by_to_segment: AHashMap::new(),
            maintain_indexes: true,
        }
    }
}

impl CrossFileEdges {
    /// Construct an empty cross-file edge index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a cross-file edge. Updates both directional indexes when this
    /// workspace is live/queryable; sidecar-only builds retain only `edges`.
    pub fn push(&mut self, edge: CrossFileEdge) {
        if self.maintain_indexes {
            let idx = u32::try_from(self.edges.len()).expect("cross-file edge index overflow: > 2^32 edges");
            self.by_from_segment
                .entry(edge.from_segment)
                .or_default()
                .push(idx);
            self.by_to_segment.entry(edge.to_segment).or_default().push(idx);
        }
        self.edges.push(edge);
    }

    /// Iterate every cross-file edge whose source is in `seg`.
    pub fn outgoing_from_segment(&self, seg: SegmentId) -> impl Iterator<Item = &CrossFileEdge> + '_ {
        let indexed = self.maintain_indexes;
        let mut indices = self
            .by_from_segment
            .get(&seg)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter();
        let mut canonical = self.edges.iter();
        std::iter::from_fn(move || {
            if indexed {
                indices.find_map(|idx| self.edges.get(*idx as usize))
            } else {
                canonical.find(|edge| edge.from_segment == seg)
            }
        })
    }

    /// Iterate every cross-file edge whose destination is in `seg`.
    pub fn incoming_to_segment(&self, seg: SegmentId) -> impl Iterator<Item = &CrossFileEdge> + '_ {
        let indexed = self.maintain_indexes;
        let mut indices = self
            .by_to_segment
            .get(&seg)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter();
        let mut canonical = self.edges.iter();
        std::iter::from_fn(move || {
            if indexed {
                indices.find_map(|idx| self.edges.get(*idx as usize))
            } else {
                canonical.find(|edge| edge.to_segment == seg)
            }
        })
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
        if !self.maintain_indexes {
            let before = self.edges.len();
            self.edges.retain(|edge| edge.from_segment != seg);
            let dropped = before.saturating_sub(self.edges.len());
            self.rebuild_indexes();
            return dropped;
        }
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
        self.maintain_indexes = true;
        self.by_from_segment.clear();
        self.by_to_segment.clear();
        for (idx, edge) in self.edges.iter().enumerate() {
            let i = idx as u32;
            self.by_from_segment.entry(edge.from_segment).or_default().push(i);
            self.by_to_segment.entry(edge.to_segment).or_default().push(i);
        }
    }

    fn release_indexes(&mut self) {
        self.by_from_segment = AHashMap::new();
        self.by_to_segment = AHashMap::new();
        self.maintain_indexes = false;
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
    /// Validated positioned-reader backend for warm queries. Segment,
    /// cross-edge, and symbolic-transform payloads stay in the factstore and
    /// page through a resource-sized cache. Compiler-built/test workspaces
    /// leave this unset and use the resident vectors above.
    #[serde(skip)]
    query_sidecar: Option<Arc<IdgQuerySidecar>>,
    /// Sidecar-only builds keep inactive segment payloads in an anonymous
    /// compiler spool. Query workspaces never enable this field.
    #[serde(skip)]
    segment_spool: Option<IdgSegmentSpool>,
    /// Residency bit per segment while `segment_spool` is active. Skipped on
    /// disk; a normal decoded workspace has every segment resident.
    #[serde(skip)]
    resident_segments: Vec<bool>,
    /// Sidecar-only canonical cross-edge chunks. Kept separate from the
    /// resident query vector so cold compilation is bounded by one wire chunk.
    #[serde(skip)]
    cross_file_spool: Option<CrossFileEdgeSpool>,
    /// Sidecar-only symbolic transform chunks. The accompanying string/base
    /// dictionaries remain in `symbolic_field`; query workspaces instead keep
    /// transforms resident and build the outgoing runtime index.
    #[serde(skip)]
    symbolic_transform_spool: Option<SymbolicTransformSpool>,
    /// `FuncId.raw() → SegmentId`. Rebuilt from each segment's `funcs`
    /// list after deserialisation; Serde skips it on the wire.
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
        if self.segment_spool.is_some() {
            self.resident_segments.push(true);
        }
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
        if self.segment_spool.is_some()
            && !self
                .resident_segments
                .get(id.0 as usize)
                .copied()
                .unwrap_or(false)
        {
            return None;
        }
        self.segments.get(id.0 as usize)
    }

    pub(crate) fn segment_view(&self, id: SegmentId) -> Option<SegmentView<'_>> {
        if let Some(sidecar) = &self.query_sidecar {
            return sidecar.segment(id).ok().flatten().map(SegmentView::Paged);
        }
        self.segment(id).map(SegmentView::Resident)
    }

    pub(crate) fn segment_views(&self) -> impl Iterator<Item = (SegmentId, SegmentView<'_>)> + '_ {
        (0..self.segment_count()).filter_map(|index| {
            let id = SegmentId(u32::try_from(index).ok()?);
            self.segment_view(id).map(|segment| (id, segment))
        })
    }

    /// Mutably borrow segment `id`.
    pub fn segment_mut(&mut self, id: SegmentId) -> Option<&mut IdgSegment> {
        if self.segment_spool.is_some()
            && !self
                .resident_segments
                .get(id.0 as usize)
                .copied()
                .unwrap_or(false)
        {
            return None;
        }
        self.segments.get_mut(id.0 as usize)
    }

    /// Iterate every segment.
    pub fn segments(&self) -> impl Iterator<Item = (SegmentId, &IdgSegment)> + '_ {
        self.segments
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                self.segment_spool.is_none() || self.resident_segments.get(*i).copied().unwrap_or(false)
            })
            .map(|(i, s)| (SegmentId(i as u32), s))
    }

    pub(crate) fn enable_segment_spool(&mut self, target: &std::path::Path) -> crate::IdgResult<()> {
        if self.segment_spool.is_none() {
            let segment_spool = IdgSegmentSpool::new(target)?;
            let cross_file_spool =
                WireChunkSpool::new(target, IDG_WORKSPACE_EDGE_CHUNK_LEN, "cross-file edge")?;
            self.segment_spool = Some(segment_spool);
            self.cross_file_spool = Some(cross_file_spool);
            self.resident_segments = vec![true; self.segments.len()];
        }
        Ok(())
    }

    pub(crate) fn has_segment_spool(&self) -> bool {
        self.segment_spool.is_some()
    }

    pub(crate) fn spill_segment(&mut self, id: SegmentId) -> crate::IdgResult<()> {
        let index = id.0 as usize;
        if self.segment_spool.is_none() || !self.resident_segments.get(index).copied().unwrap_or(false) {
            return Ok(());
        }
        let segment = self.segments.get(index).ok_or_else(|| {
            crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IDG segment {}", id.0),
            ))
        })?;
        self.segment_spool
            .as_mut()
            .expect("spool checked above")
            .write_segment(id, segment)?;
        self.segments[index] = IdgSegment::new();
        self.resident_segments[index] = false;
        Ok(())
    }

    pub(crate) fn hydrate_segment(&mut self, id: SegmentId) -> crate::IdgResult<()> {
        let index = id.0 as usize;
        if self.segment_spool.is_none() || self.resident_segments.get(index).copied().unwrap_or(false) {
            return Ok(());
        }
        let segment = self
            .segment_spool
            .as_mut()
            .expect("spool checked above")
            .read_segment(id)?;
        let slot = self.segments.get_mut(index).ok_or_else(|| {
            crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IDG segment {}", id.0),
            ))
        })?;
        *slot = segment;
        self.resident_segments[index] = true;
        Ok(())
    }

    pub(crate) fn hydrate_segments<I>(&mut self, ids: I) -> crate::IdgResult<()>
    where
        I: IntoIterator<Item = SegmentId>,
    {
        for id in ids {
            self.hydrate_segment(id)?;
        }
        Ok(())
    }

    pub(crate) fn visit_segment<F>(&mut self, id: SegmentId, visit: F) -> crate::IdgResult<()>
    where
        F: FnOnce(&IdgSegment),
    {
        let index = id.0 as usize;
        let was_resident =
            self.segment_spool.is_none() || self.resident_segments.get(index).copied().unwrap_or(false);
        self.hydrate_segment(id)?;
        let segment = self.segment(id).ok_or_else(|| {
            crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IDG segment {}", id.0),
            ))
        })?;
        visit(segment);
        if self.segment_spool.is_some() && !was_resident {
            self.segments[index] = IdgSegment::new();
            self.resident_segments[index] = false;
        }
        Ok(())
    }

    pub(crate) fn segment_node_count(&self, id: SegmentId) -> u32 {
        let index = id.0 as usize;
        if self.segment_spool.is_some() && !self.resident_segments.get(index).copied().unwrap_or(false) {
            return self
                .segment_spool
                .as_ref()
                .map_or(0, |spool| spool.node_count(id));
        }
        self.segments.get(index).map_or(0, |segment| {
            u32::try_from(segment.nodes.len()).expect("segment node count exceeds u32")
        })
    }

    pub(crate) fn spill_resident_segments(&mut self) -> crate::IdgResult<()> {
        if self.segment_spool.is_none() {
            return Ok(());
        }
        for index in 0..self.segments.len() {
            if self.resident_segments.get(index).copied().unwrap_or(false) {
                self.spill_segment(SegmentId(index as u32))?;
            }
        }
        Ok(())
    }

    pub(crate) fn begin_spool_generation(&mut self) -> crate::IdgResult<()> {
        if let Some(spool) = &mut self.segment_spool {
            spool.begin_generation()?;
        }
        Ok(())
    }

    pub(crate) fn finish_spool_generation(&mut self) -> crate::IdgResult<()> {
        if let Some(spool) = &mut self.segment_spool {
            spool.finish_generation()?;
        }
        Ok(())
    }

    pub(crate) fn visit_segments_mut<F>(&mut self, mut visit: F) -> crate::IdgResult<()>
    where
        F: FnMut(SegmentId, &mut IdgSegment),
    {
        if self.segment_spool.is_none() {
            for (index, segment) in self.segments.iter_mut().enumerate() {
                visit(SegmentId(index as u32), segment);
            }
            return Ok(());
        }
        self.begin_spool_generation()?;
        for index in 0..self.segments.len() {
            let id = SegmentId(index as u32);
            self.hydrate_segment(id)?;
            visit(id, &mut self.segments[index]);
            self.spill_segment(id)?;
        }
        self.finish_spool_generation()
    }

    /// Number of segments registered.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.query_sidecar
            .as_ref()
            .map_or(self.segments.len(), |sidecar| {
                sidecar.metadata.segment_count as usize
            })
    }

    /// Total number of functions across all segments.
    #[must_use]
    pub fn func_count(&self) -> usize {
        self.by_func.len()
    }

    /// Total number of intra-segment edges across the workspace.
    #[must_use]
    pub fn intra_edge_count(&self) -> usize {
        if let Some(sidecar) = &self.query_sidecar {
            return usize::try_from(sidecar.intra_edge_count).unwrap_or(usize::MAX);
        }
        self.segments
            .iter()
            .enumerate()
            .map(|(index, segment)| {
                if self.segment_spool.is_some()
                    && !self.resident_segments.get(index).copied().unwrap_or(false)
                {
                    self.segment_spool
                        .as_ref()
                        .map_or(0, |spool| spool.edge_count(SegmentId(index as u32)))
                } else {
                    segment.edges.len()
                }
            })
            .sum()
    }

    /// Borrow the cross-file edge index.
    #[must_use]
    pub fn cross_file(&self) -> &CrossFileEdges {
        &self.cross_file
    }

    /// Exact cross-file edge count across resident and sidecar-only storage.
    #[must_use]
    pub fn cross_file_edge_count(&self) -> usize {
        if let Some(sidecar) = &self.query_sidecar {
            return usize::try_from(sidecar.metadata.cross_file_edge_count).unwrap_or(usize::MAX);
        }
        self.cross_file_spool
            .as_ref()
            .map_or_else(|| self.cross_file.len(), CrossFileEdgeSpool::len)
    }

    /// Visit canonical cross-file edges without requiring them to be resident.
    pub(crate) fn visit_cross_file_edges<F>(&self, mut visit: F) -> crate::IdgResult<()>
    where
        F: FnMut(&[CrossFileEdge]),
    {
        if let Some(sidecar) = &self.query_sidecar {
            sidecar.visit_cross_file_edges(visit)
        } else if let Some(spool) = &self.cross_file_spool {
            spool.visit(|edges| {
                visit(edges);
                Ok(())
            })
        } else {
            visit(&self.cross_file.edges);
            Ok(())
        }
    }

    /// Append one canonical cross-file edge to resident query storage or the
    /// bounded sidecar compiler spool selected for this workspace.
    pub(crate) fn push_cross_file_edge(&mut self, edge: CrossFileEdge) {
        if let Some(spool) = &mut self.cross_file_spool {
            spool.push(edge);
        } else {
            self.cross_file.push(edge);
        }
    }

    pub(crate) fn check_cross_file_spool(&self) -> crate::IdgResult<()> {
        self.cross_file_spool
            .as_ref()
            .map_or(Ok(()), CrossFileEdgeSpool::check_error)
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

    pub(crate) fn has_symbolic_transforms(&self) -> bool {
        self.query_sidecar.as_ref().map_or_else(
            || {
                self.symbolic_transform_spool.as_ref().map_or_else(
                    || !self.symbolic_field.transforms().is_empty(),
                    |spool| spool.len() != 0,
                )
            },
            |sidecar| sidecar.metadata.symbolic_transform_count != 0,
        )
    }

    pub(crate) fn visit_symbolic_transforms<F>(&self, mut visit: F) -> crate::IdgResult<()>
    where
        F: FnMut(&[SymbolicFieldTransform]) -> crate::IdgResult<()>,
    {
        if let Some(sidecar) = &self.query_sidecar {
            sidecar.visit_symbolic_transforms(visit)
        } else if let Some(spool) = &self.symbolic_transform_spool {
            spool.visit(visit)
        } else {
            visit(self.symbolic_field.transforms())
        }
    }

    /// Replace the symbolic access-path relation after Phase 3 stitching.
    pub fn set_symbolic_field(&mut self, graph: SymbolicFieldGraph) {
        self.symbolic_field = graph;
    }

    pub(crate) fn install_symbolic_compiler_storage(&mut self, storage: SymbolicFieldCompilerStorage) {
        self.symbolic_field = storage.graph;
        self.symbolic_transform_spool = storage.transform_spool;
    }

    #[cfg(test)]
    pub(crate) fn symbolic_transform_count(&self) -> usize {
        self.symbolic_transform_spool
            .as_ref()
            .map_or_else(|| self.symbolic_field.transforms().len(), WireChunkSpool::len)
    }

    /// Mutable access for the IDG builder phase 3 to push
    /// cross-file edges as it stitches them.
    pub fn cross_file_mut(&mut self) -> &mut CrossFileEdges {
        &mut self.cross_file
    }

    /// Total edge count: intra-segment + cross-file.
    #[must_use]
    pub fn total_edge_count(&self) -> usize {
        self.intra_edge_count() + self.cross_file_edge_count()
    }

    /// Persist the entire workspace IDG to `path` as a streamed
    /// factstore. Each segment is serialised as its own factstore
    /// entry (key = segment index + 1) so peak RAM during persistence
    /// is bounded by the writer's small, backpressured pipeline of
    /// active/queued MessagePack buffers, not the whole IDG. Each serialized
    /// `Vec<u8>` moves into the writer without a second payload copy.
    /// A 100K-LOC C codebase's IDG can occupy several GB in memory; the
    /// previous single-buffer serialization path needed that much
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
        if self.segment_spool.is_some() {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "spooled compiler workspace must be consumed by save_into_disk",
            )));
        }
        save_workspace_parts(
            path,
            pipeline_hash,
            PersistSegments::Borrowed(&self.segments),
            PersistCrossFileEdges::Resident(PersistSlice::Borrowed(&self.cross_file.edges)),
            PersistSlice::Borrowed(&self.field_flow),
            PersistSymbolic::Borrowed(&self.symbolic_field),
        )
    }

    /// Consume a completed compiler graph and persist its canonical wire
    /// representation after releasing indexes that Serde does not encode.
    ///
    /// Explicit prewarming needs the sidecar, not a second live query graph.
    /// Dropping build-side hash tables before encoding prevents persistence
    /// memory from becoming additive with those tables on large workspaces.
    /// Every node and edge remains in the canonical vectors written by
    /// [`Self::save_to_disk`]; warm loads rebuild the reverse indexes.
    pub fn save_into_disk(mut self, path: &std::path::Path, pipeline_hash: u64) -> crate::IdgResult<()> {
        self.spill_resident_segments()?;
        let Self {
            mut segments,
            query_sidecar,
            segment_spool,
            resident_segments,
            cross_file_spool,
            symbolic_transform_spool,
            by_func,
            mut cross_file,
            field_flow,
            mut symbolic_field,
        } = self;
        drop(query_sidecar);
        drop(resident_segments);
        drop(by_func);
        cross_file.release_indexes();
        symbolic_field.release_indexes();
        for segment in &mut segments {
            segment.release_reverse_lookups();
        }
        let cross_file_edges = std::sync::Arc::new(std::mem::take(&mut cross_file.edges));
        drop(cross_file);
        let persist_segments =
            segment_spool.map_or_else(|| PersistSegments::Owned(segments), PersistSegments::Spool);
        let persist_cross_file = cross_file_spool.map_or_else(
            || PersistCrossFileEdges::Resident(PersistSlice::Owned(cross_file_edges)),
            PersistCrossFileEdges::Spool,
        );
        let persist_symbolic = match symbolic_transform_spool {
            Some(spool) => PersistSymbolic::Spool {
                graph: symbolic_field,
                spool,
            },
            None => PersistSymbolic::Owned(symbolic_field),
        };
        let result = save_workspace_parts(
            path,
            pipeline_hash,
            persist_segments,
            persist_cross_file,
            PersistSlice::Owned(std::sync::Arc::new(field_flow)),
            persist_symbolic,
        );
        result
    }

    pub(crate) fn disable_cross_file_indexes(&mut self) {
        self.cross_file.release_indexes();
    }

    /// Load a workspace IDG from `path`. Returns `Ok(None)` for missing
    /// files, version drift, or `pipeline_hash` mismatch — the caller
    /// rebuilds in those cases. Returns `Err` for genuine I/O / decode
    /// errors. After load, rebuilds only the compact `FuncId → SegmentId`
    /// lookup. Segment and cross-edge queries use exact canonical-vector
    /// fallbacks or service-owned compact views instead of eagerly duplicating
    /// every persisted dictionary.
    pub fn load_from_disk(path: &std::path::Path, pipeline_hash: u64) -> crate::IdgResult<Option<Self>> {
        use rayon::prelude::*;

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
        let metadata: IdgWorkspaceMetadataOwned = wire::decode(&metadata_hit.payload)
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
            query_sidecar: None,
            segment_spool: None,
            resident_segments: Vec::new(),
            cross_file_spool: None,
            symbolic_transform_spool: None,
            by_func: AHashMap::new(),
            cross_file: CrossFileEdges::new(),
            field_flow: Vec::with_capacity(metadata.field_flow_count.min(usize::MAX as u64) as usize),
            symbolic_field: SymbolicFieldGraph::new(),
        };
        ws.disable_cross_file_indexes();
        // Segment entries are independent positioned reads. Decode them in
        // parallel, then install them in segment-id order so persisted IDs
        // remain deterministic. The canonical vectors are the query-time
        // representation: deserialization deliberately leaves the skipped
        // reverse hash maps incomplete, and dictionary lookups fall back to an
        // exact per-segment scan. Rebuilding three hash tables for every file
        // can add gigabytes to a large warm graph even though each query only
        // touches a small fraction of those dictionaries.
        let decode_width = idg_serialization_worker_count();
        for batch_start in (0..metadata.segment_count).step_by(decode_width) {
            let batch_end = metadata
                .segment_count
                .min(batch_start.saturating_add(decode_width as u32));
            let decoded_segments = (batch_start..batch_end)
                .into_par_iter()
                .map(|idx| -> crate::IdgResult<Option<IdgSegment>> {
                    let Some(hit) = reader.get((idx + 1) as u64)? else {
                        bonsai_diagnostics::debug_log!(
                            "idg-build",
                            "workspace sidecar miss: path={} reason=missing-segment segment={}",
                            path.display(),
                            idx
                        );
                        return Ok(None);
                    };
                    let segment: IdgSegment = wire::decode(&hit.payload).map_err(|e| {
                        crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    })?;
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
                    Ok(Some(segment))
                })
                .collect::<Vec<_>>();
            for (offset, decoded) in decoded_segments.into_iter().enumerate() {
                let Some(segment) = decoded? else {
                    return Ok(None);
                };
                let idx = batch_start as usize + offset;
                let seg_id = SegmentId(u32::try_from(idx).expect("segment index came from u32 metadata"));
                for func_raw in &segment.funcs {
                    ws.by_func.insert(*func_raw, seg_id);
                }
                ws.segments.push(segment);
            }
        }
        let cross_base = first_cross_file_chunk_key(metadata.segment_count);
        ws.cross_file
            .edges
            .reserve(metadata.cross_file_edge_count.min(usize::MAX as u64) as usize);
        let cross_complete = visit_sidecar_chunks::<CrossFileEdge, _>(
            &reader,
            path,
            cross_base,
            metadata.cross_file_chunk_count,
            "cross-file",
            |chunk| ws.cross_file.edges.extend(chunk),
        )?;
        if !cross_complete {
            return Ok(None);
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
        let field_complete = visit_sidecar_chunks::<FieldFlowLink, _>(
            &reader,
            path,
            field_base,
            metadata.field_flow_chunk_count,
            "field-flow",
            |chunk| ws.field_flow.extend(chunk),
        )?;
        if !field_complete {
            return Ok(None);
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
        let (strings, bases): (Vec<String>, Vec<SymbolicFieldBase>) = wire::decode(&header_hit.payload)
            .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        if strings.len() as u64 != metadata.symbolic_string_count
            || bases.len() as u64 != metadata.symbolic_base_count
        {
            return Ok(None);
        }
        let mut symbolic = SymbolicFieldGraph::from_parts(strings, bases, Vec::new());
        let transforms_complete = visit_sidecar_chunks::<SymbolicFieldTransform, _>(
            &reader,
            path,
            symbolic_header + 1,
            metadata.symbolic_transform_chunk_count,
            "symbolic-transform",
            |chunk| symbolic.extend_transforms(chunk),
        )?;
        if !transforms_complete {
            return Ok(None);
        }
        if symbolic.transforms().len() as u64 != metadata.symbolic_transform_count {
            return Ok(None);
        }
        ws.symbolic_field = symbolic;
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

    /// Open a validated warm-query workspace without hydrating its complete
    /// graph. Source-file segments, cross-file chunks, and symbolic transform
    /// chunks remain in the factstore and are decoded through a memory-sized
    /// working-set cache. The initial segment scan rebuilds only the compact
    /// `FuncId -> SegmentId` directory and exact edge count; decoded segments
    /// are evicted immediately afterward.
    pub(crate) fn load_query_from_disk(
        path: &std::path::Path,
        pipeline_hash: u64,
    ) -> crate::IdgResult<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let reader =
            match bonsai_factstore::FactStoreReader::open(path, IDG_WORKSPACE_TABLE_ID, pipeline_hash) {
                Ok(reader) => reader,
                Err(error) => {
                    bonsai_diagnostics::debug_log!(
                        "idg-build",
                        "workspace query sidecar miss: path={} error={}",
                        path.display(),
                        error
                    );
                    return Ok(None);
                }
            };
        let Some(metadata_hit) = reader.get(0)? else {
            return Ok(None);
        };
        if metadata_hit.body_hash != IDG_WORKSPACE_VERSION as u64 {
            return Ok(None);
        }
        let metadata: IdgWorkspaceMetadataOwned =
            wire::decode(&metadata_hit.payload).map_err(invalid_sidecar_payload)?;
        if metadata.version != IDG_WORKSPACE_VERSION {
            return Ok(None);
        }
        let expected_entries = 1_u64
            .saturating_add(u64::from(metadata.segment_count))
            .saturating_add(u64::from(metadata.cross_file_chunk_count))
            .saturating_add(u64::from(metadata.field_flow_chunk_count))
            .saturating_add(1)
            .saturating_add(u64::from(metadata.symbolic_transform_chunk_count));
        if reader.len() as u64 != expected_entries
            || (0..expected_entries).any(|key| !reader.contains_key(key))
        {
            return Ok(None);
        }

        let symbolic_header = symbolic_field_header_key(
            metadata.segment_count,
            metadata.cross_file_chunk_count,
            metadata.field_flow_chunk_count,
        );
        let Some(symbolic_hit) = reader.get(symbolic_header)? else {
            return Ok(None);
        };
        let (strings, bases): (Vec<String>, Vec<SymbolicFieldBase>) =
            wire::decode(&symbolic_hit.payload).map_err(invalid_sidecar_payload)?;
        if strings.len() as u64 != metadata.symbolic_string_count
            || bases.len() as u64 != metadata.symbolic_base_count
        {
            return Ok(None);
        }
        let symbolic_field = SymbolicFieldGraph::from_header_parts(strings, bases);

        let mut sidecar = IdgQuerySidecar::open(path, pipeline_hash, metadata)?;
        let mut by_func = AHashMap::new();
        let mut intra_edge_count = 0_u64;
        for index in 0..metadata.segment_count {
            let id = SegmentId(index);
            let Some(segment) = sidecar.segment(id)? else {
                return Ok(None);
            };
            intra_edge_count = intra_edge_count.saturating_add(segment.edges.len() as u64);
            for &func in &segment.funcs {
                by_func.insert(func, id);
            }
        }
        sidecar.segment_cache.clear();
        sidecar.intra_edge_count = intra_edge_count;

        let mut field_flow = Vec::with_capacity(metadata.field_flow_count.min(usize::MAX as u64) as usize);
        let field_base = first_field_flow_chunk_key(metadata.segment_count, metadata.cross_file_chunk_count);
        let field_complete = visit_sidecar_chunks::<FieldFlowLink, _>(
            &reader,
            path,
            field_base,
            metadata.field_flow_chunk_count,
            "field-flow",
            |chunk| field_flow.extend(chunk),
        )?;
        if !field_complete || field_flow.len() as u64 != metadata.field_flow_count {
            return Ok(None);
        }

        let mut cross_file = CrossFileEdges::new();
        cross_file.release_indexes();
        let workspace = Self {
            segments: Vec::new(),
            query_sidecar: Some(Arc::new(sidecar)),
            segment_spool: None,
            resident_segments: Vec::new(),
            cross_file_spool: None,
            symbolic_transform_spool: None,
            by_func,
            cross_file,
            field_flow,
            symbolic_field,
        };
        bonsai_diagnostics::debug_log!(
            "idg-build",
            "workspace query sidecar opened: path={} segments={} funcs={} intra_edges={} cross_edges={} symbolic_transforms={}",
            path.display(),
            workspace.segment_count(),
            workspace.func_count(),
            workspace.intra_edge_count(),
            workspace.cross_file_edge_count(),
            metadata.symbolic_transform_count
        );
        Ok(Some(workspace))
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

    /// Validate the cheap-to-read sidecar contract for an exact pipeline
    /// without hydrating the complete graph. This checks the factstore header,
    /// section/index bounds, metadata schema, and the complete expected key
    /// layout. Query consumers open the sidecar through
    /// [`crate::IdgQueryService::load_from_disk`], which scans each segment
    /// once for the compact function directory and pages exact relation
    /// payloads on demand.
    pub fn validate_sidecar_layout_with_pipeline(
        path: &std::path::Path,
        pipeline_hash: u64,
    ) -> crate::IdgResult<usize> {
        let reader = bonsai_factstore::FactStoreReader::open(path, IDG_WORKSPACE_TABLE_ID, pipeline_hash)?;
        let metadata_hit = reader.get(0)?.ok_or_else(|| {
            crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace IDG sidecar is missing metadata",
            ))
        })?;
        if metadata_hit.body_hash != IDG_WORKSPACE_VERSION as u64 {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace IDG metadata version mismatch",
            )));
        }
        let metadata: IdgWorkspaceMetadataOwned = wire::decode(&metadata_hit.payload)
            .map_err(|err| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err)))?;
        if metadata.version != IDG_WORKSPACE_VERSION {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace IDG metadata payload version mismatch",
            )));
        }
        let expected_entries = 1_u64
            .saturating_add(u64::from(metadata.segment_count))
            .saturating_add(u64::from(metadata.cross_file_chunk_count))
            .saturating_add(u64::from(metadata.field_flow_chunk_count))
            .saturating_add(1)
            .saturating_add(u64::from(metadata.symbolic_transform_chunk_count));
        if reader.len() as u64 != expected_entries
            || (0..expected_entries).any(|key| !reader.contains_key(key))
        {
            return Err(crate::IdgError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace IDG sidecar entry layout mismatch",
            )));
        }
        Ok(metadata.segment_count as usize)
    }
}

enum PersistSegments<'a> {
    Borrowed(&'a [IdgSegment]),
    Owned(Vec<IdgSegment>),
    Spool(IdgSegmentSpool),
}

enum PersistSlice<'a, T> {
    Borrowed(&'a [T]),
    Owned(std::sync::Arc<Vec<T>>),
}

enum PersistCrossFileEdges<'a> {
    Resident(PersistSlice<'a, CrossFileEdge>),
    Spool(CrossFileEdgeSpool),
}

impl PersistCrossFileEdges<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Resident(edges) => edges.as_slice().len(),
            Self::Spool(spool) => spool.len(),
        }
    }

    fn chunk_count(&self) -> usize {
        match self {
            Self::Resident(edges) => chunk_count(edges.as_slice().len(), IDG_WORKSPACE_EDGE_CHUNK_LEN),
            Self::Spool(spool) => spool.chunk_count(),
        }
    }
}

impl<T> PersistSlice<'_, T> {
    fn as_slice(&self) -> &[T] {
        match self {
            Self::Borrowed(values) => values,
            Self::Owned(values) => values,
        }
    }
}

enum PersistSymbolic<'a> {
    Borrowed(&'a SymbolicFieldGraph),
    Owned(SymbolicFieldGraph),
    Spool {
        graph: SymbolicFieldGraph,
        spool: SymbolicTransformSpool,
    },
}

impl PersistSymbolic<'_> {
    fn as_graph(&self) -> &SymbolicFieldGraph {
        match self {
            Self::Borrowed(graph) => graph,
            Self::Owned(graph) => graph,
            Self::Spool { graph, .. } => graph,
        }
    }

    fn transform_count(&self) -> usize {
        match self {
            Self::Borrowed(graph) => graph.transforms().len(),
            Self::Owned(graph) => graph.transforms().len(),
            Self::Spool { spool, .. } => spool.len(),
        }
    }

    fn transform_chunk_count(&self) -> usize {
        match self {
            Self::Borrowed(graph) => chunk_count(
                graph.transforms().len(),
                IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN,
            ),
            Self::Owned(graph) => chunk_count(
                graph.transforms().len(),
                IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN,
            ),
            Self::Spool { spool, .. } => spool.chunk_count(),
        }
    }
}

impl PersistSegments<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(segments) => segments.len(),
            Self::Owned(segments) => segments.len(),
            Self::Spool(spool) => spool.len(),
        }
    }
}

fn encode_sidecar_value<T: serde::Serialize + ?Sized>(value: &T) -> crate::IdgResult<Vec<u8>> {
    wire::encode(value)
        .map_err(|err| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err)))
}

fn encode_sidecar_to_writer<T: serde::Serialize + ?Sized>(
    writer: &mut dyn std::io::Write,
    value: &T,
) -> std::io::Result<()> {
    wire::encode_to_writer(writer, value)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn write_slice_chunks<T>(
    writer: &bonsai_factstore::FactStoreWriter,
    values: PersistSlice<'_, T>,
    chunk_len: usize,
    first_key: u64,
) -> crate::IdgResult<()>
where
    T: serde::Serialize + Send + Sync + 'static,
{
    match values {
        PersistSlice::Borrowed(values) => {
            for (idx, chunk) in values.chunks(chunk_len).enumerate() {
                writer.add_owned(
                    first_key + idx as u64,
                    IDG_WORKSPACE_VERSION as u64,
                    encode_sidecar_value(chunk)?,
                )?;
            }
        }
        PersistSlice::Owned(values) => {
            for (idx, start) in (0..values.len()).step_by(chunk_len).enumerate() {
                let values = std::sync::Arc::clone(&values);
                let end = values.len().min(start.saturating_add(chunk_len));
                writer.add_streamed(first_key + idx as u64, IDG_WORKSPACE_VERSION as u64, move |out| {
                    encode_sidecar_to_writer(out, &values[start..end])
                })?;
            }
        }
    }
    Ok(())
}

fn save_workspace_parts(
    path: &std::path::Path,
    pipeline_hash: u64,
    segments: PersistSegments<'_>,
    cross_file_edges: PersistCrossFileEdges<'_>,
    field_flow: PersistSlice<'_, FieldFlowLink>,
    symbolic_field: PersistSymbolic<'_>,
) -> crate::IdgResult<()> {
    use bonsai_factstore::FactStoreWriter;
    use rayon::prelude::*;

    let persistence_started = std::time::Instant::now();
    let segment_count = segments.len();
    let cross_file_edge_count = cross_file_edges.len();
    let cross_file_chunk_count = cross_file_edges.chunk_count();
    let field_flow_chunk_count = chunk_count(field_flow.as_slice().len(), IDG_WORKSPACE_FIELD_FLOW_CHUNK_LEN);
    let symbolic = symbolic_field.as_graph();
    let symbolic_transform_count = symbolic_field.transform_count();
    let symbolic_transform_chunk_count = symbolic_field.transform_chunk_count();
    // Segment payloads carry their own compact string dictionaries; the
    // outer factstore string pool is intentionally empty. A compiler spool is
    // already a prepared FactStore payload file, so adopt its exact bytes and
    // append the remaining tables rather than copying every segment through a
    // second userspace writer pass.
    let (writer, resident_segments) = match segments {
        PersistSegments::Spool(spool) => (spool.into_factstore_writer(path, pipeline_hash)?, None),
        other => (
            FactStoreWriter::create(path, IDG_WORKSPACE_TABLE_ID, pipeline_hash)?,
            Some(other),
        ),
    };
    bonsai_diagnostics::debug_log!(
        "idg-build",
        "persist writer-ready: {:.3}s segments={segment_count}",
        persistence_started.elapsed().as_secs_f64()
    );
    let metadata = IdgWorkspaceMetadata {
        version: IDG_WORKSPACE_VERSION,
        segment_count: segment_count as u32,
        cross_file_edge_count: cross_file_edge_count as u64,
        cross_file_chunk_count: cross_file_chunk_count as u32,
        field_flow_count: field_flow.as_slice().len() as u64,
        field_flow_chunk_count: field_flow_chunk_count as u32,
        symbolic_string_count: symbolic.strings().len() as u64,
        symbolic_base_count: symbolic.bases().len() as u64,
        symbolic_transform_count: symbolic_transform_count as u64,
        symbolic_transform_chunk_count: symbolic_transform_chunk_count as u32,
    };
    writer.add_owned(0, IDG_WORKSPACE_VERSION as u64, encode_sidecar_value(&metadata)?)?;

    // A borrowed query graph remains intact. A sidecar-only compiler prewarm
    // transfers ownership here, so completed segment dictionaries and edge
    // vectors are released batch by batch while the exact wire entries are
    // streamed in deterministic SegmentId order.
    let encoding_width = idg_serialization_worker_count();
    match resident_segments {
        Some(PersistSegments::Borrowed(segments)) => {
            for (batch_idx, batch) in segments.chunks(encoding_width).enumerate() {
                let encoded = batch.par_iter().map(encode_sidecar_value).collect::<Vec<_>>();
                let first_segment_idx = batch_idx * encoding_width;
                for (offset, bytes) in encoded.into_iter().enumerate() {
                    writer.add_owned(
                        (first_segment_idx + offset + 1) as u64,
                        IDG_WORKSPACE_VERSION as u64,
                        bytes?,
                    )?;
                }
            }
        }
        Some(PersistSegments::Owned(segments)) => {
            for (idx, segment) in segments.into_iter().enumerate() {
                writer.add_streamed((idx + 1) as u64, IDG_WORKSPACE_VERSION as u64, move |out| {
                    encode_sidecar_to_writer(out, &segment)
                })?;
            }
        }
        Some(PersistSegments::Spool(_)) => unreachable!("spool was adopted above"),
        None => {}
    }
    bonsai_diagnostics::debug_log!(
        "idg-build",
        "persist segments: {:.3}s segments={segment_count}",
        persistence_started.elapsed().as_secs_f64()
    );

    let cross_base = first_cross_file_chunk_key(segment_count as u32);
    match cross_file_edges {
        PersistCrossFileEdges::Resident(edges) => {
            write_slice_chunks(&writer, edges, IDG_WORKSPACE_EDGE_CHUNK_LEN, cross_base)?;
        }
        PersistCrossFileEdges::Spool(spool) => spool.write_chunks(&writer, cross_base)?,
    }
    bonsai_diagnostics::debug_log!(
        "idg-build",
        "persist cross-file: {:.3}s edges={cross_file_edge_count} chunks={cross_file_chunk_count}",
        persistence_started.elapsed().as_secs_f64()
    );
    let field_base = first_field_flow_chunk_key(segment_count as u32, cross_file_chunk_count as u32);
    write_slice_chunks(
        &writer,
        field_flow,
        IDG_WORKSPACE_FIELD_FLOW_CHUNK_LEN,
        field_base,
    )?;
    bonsai_diagnostics::debug_log!(
        "idg-build",
        "persist field-flow: {:.3}s links={} chunks={field_flow_chunk_count}",
        persistence_started.elapsed().as_secs_f64(),
        metadata.field_flow_count
    );
    let symbolic_header = symbolic_field_header_key(
        segment_count as u32,
        cross_file_chunk_count as u32,
        field_flow_chunk_count as u32,
    );
    enum PersistTransforms<'a> {
        Borrowed(&'a [SymbolicFieldTransform]),
        Owned(std::sync::Arc<Vec<SymbolicFieldTransform>>),
        Spool(SymbolicTransformSpool),
    }
    let transforms = match symbolic_field {
        PersistSymbolic::Borrowed(graph) => {
            writer.add_owned(
                symbolic_header,
                IDG_WORKSPACE_VERSION as u64,
                encode_sidecar_value(&(graph.strings(), graph.bases()))?,
            )?;
            PersistTransforms::Borrowed(graph.transforms())
        }
        PersistSymbolic::Owned(graph) => {
            let (strings, bases, transforms) = graph.into_parts();
            writer.add_streamed(symbolic_header, IDG_WORKSPACE_VERSION as u64, move |out| {
                encode_sidecar_to_writer(out, &(strings.as_slice(), bases.as_slice()))
            })?;
            PersistTransforms::Owned(std::sync::Arc::new(transforms))
        }
        PersistSymbolic::Spool { graph, spool } => {
            let (strings, bases, transforms) = graph.into_parts();
            debug_assert!(
                transforms.is_empty(),
                "spooled symbolic compiler graph must not retain transforms"
            );
            writer.add_streamed(symbolic_header, IDG_WORKSPACE_VERSION as u64, move |out| {
                encode_sidecar_to_writer(out, &(strings.as_slice(), bases.as_slice()))
            })?;
            drop(transforms);
            PersistTransforms::Spool(spool)
        }
    };
    bonsai_diagnostics::debug_log!(
        "idg-build",
        "persist symbolic-header: {:.3}s strings={} bases={}",
        persistence_started.elapsed().as_secs_f64(),
        metadata.symbolic_string_count,
        metadata.symbolic_base_count
    );
    let transform_base = symbolic_header + 1;
    match transforms {
        PersistTransforms::Borrowed(transforms) => {
            for (idx, chunk) in transforms
                .chunks(IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN)
                .enumerate()
            {
                writer.add_owned(
                    transform_base + idx as u64,
                    IDG_WORKSPACE_VERSION as u64,
                    encode_sidecar_value(chunk)?,
                )?;
            }
        }
        PersistTransforms::Owned(transforms) => {
            for (idx, start) in (0..transforms.len())
                .step_by(IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN)
                .enumerate()
            {
                let transforms = std::sync::Arc::clone(&transforms);
                let end = transforms
                    .len()
                    .min(start.saturating_add(IDG_WORKSPACE_SYMBOLIC_TRANSFORM_CHUNK_LEN));
                writer.add_streamed(
                    transform_base + idx as u64,
                    IDG_WORKSPACE_VERSION as u64,
                    move |out| encode_sidecar_to_writer(out, &transforms[start..end]),
                )?;
            }
        }
        PersistTransforms::Spool(spool) => {
            spool.write_chunks(&writer, transform_base)?;
        }
    }
    bonsai_diagnostics::debug_log!(
        "idg-build",
        "persist symbolic-transforms: {:.3}s transforms={symbolic_transform_count} chunks={symbolic_transform_chunk_count}",
        persistence_started.elapsed().as_secs_f64()
    );
    writer.finish()?;
    bonsai_diagnostics::debug_log!(
        "idg-build",
        "persist finished: {:.3}s bytes={}",
        persistence_started.elapsed().as_secs_f64(),
        std::fs::metadata(path).map_or(0, |metadata| metadata.len())
    );
    Ok(())
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
#[derive(Copy, Clone, Debug, serde::Deserialize)]
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

struct IdgQuerySidecar {
    metadata: IdgWorkspaceMetadataOwned,
    segment_cache: bonsai_factstore::FactCache<IdgSegment>,
    relation_reader: bonsai_factstore::FactStoreReader,
    intra_edge_count: u64,
}

impl std::fmt::Debug for IdgQuerySidecar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdgQuerySidecar")
            .field("metadata", &self.metadata)
            .field("resident_segments", &self.segment_cache.resident())
            .field("intra_edge_count", &self.intra_edge_count)
            .finish()
    }
}

impl IdgQuerySidecar {
    fn segment_cache_capacity() -> NonZeroUsize {
        // A cross-segment compiler relation has two canonical endpoints. Two
        // pages keep the source page resident while target segments change;
        // this is an I/O working set, never a semantic edge or file cap.
        let workers = bonsai_common::compiler_worker_count(rayon::current_num_threads()).max(2);
        NonZeroUsize::new(workers).expect("segment cache capacity is non-zero")
    }

    fn open(
        path: &std::path::Path,
        pipeline_hash: u64,
        metadata: IdgWorkspaceMetadataOwned,
    ) -> crate::IdgResult<Self> {
        let segment_reader =
            bonsai_factstore::FactStoreReader::open(path, IDG_WORKSPACE_TABLE_ID, pipeline_hash)?;
        let relation_reader =
            bonsai_factstore::FactStoreReader::open(path, IDG_WORKSPACE_TABLE_ID, pipeline_hash)?;
        Ok(Self {
            metadata,
            segment_cache: bonsai_factstore::FactCache::new(segment_reader, Self::segment_cache_capacity()),
            relation_reader,
            intra_edge_count: 0,
        })
    }

    fn segment(&self, id: SegmentId) -> crate::IdgResult<Option<Arc<IdgSegment>>> {
        let key = u64::from(id.0) + 1;
        match self.segment_cache.get(key)? {
            bonsai_factstore::CacheGet::Hit(segment) => Ok(Some(segment)),
            bonsai_factstore::CacheGet::Absent => Ok(None),
            bonsai_factstore::CacheGet::Miss(hit) => {
                let segment: IdgSegment = wire::decode(&hit.payload).map_err(|error| {
                    crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
                })?;
                if segment.version != IDG_SEGMENT_VERSION {
                    return Err(crate::IdgError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("IDG segment {} version mismatch", id.0),
                    )));
                }
                let segment = Arc::new(segment);
                self.segment_cache.insert_decoded(key, Arc::clone(&segment));
                Ok(Some(segment))
            }
        }
    }

    fn visit_cross_file_edges<F>(&self, mut visit: F) -> crate::IdgResult<()>
    where
        F: FnMut(&[CrossFileEdge]),
    {
        let first = first_cross_file_chunk_key(self.metadata.segment_count);
        for chunk in 0..self.metadata.cross_file_chunk_count {
            let hit = self
                .relation_reader
                .get(first + u64::from(chunk))?
                .ok_or_else(|| missing_sidecar_entry("cross-file", chunk))?;
            let edges: Vec<CrossFileEdge> = wire::decode(&hit.payload).map_err(invalid_sidecar_payload)?;
            visit(&edges);
        }
        Ok(())
    }

    fn visit_symbolic_transforms<F>(&self, mut visit: F) -> crate::IdgResult<()>
    where
        F: FnMut(&[SymbolicFieldTransform]) -> crate::IdgResult<()>,
    {
        let first = symbolic_field_header_key(
            self.metadata.segment_count,
            self.metadata.cross_file_chunk_count,
            self.metadata.field_flow_chunk_count,
        ) + 1;
        for chunk in 0..self.metadata.symbolic_transform_chunk_count {
            let hit = self
                .relation_reader
                .get(first + u64::from(chunk))?
                .ok_or_else(|| missing_sidecar_entry("symbolic-transform", chunk))?;
            let transforms: Vec<SymbolicFieldTransform> =
                wire::decode(&hit.payload).map_err(invalid_sidecar_payload)?;
            visit(&transforms)?;
        }
        Ok(())
    }
}

fn missing_sidecar_entry(kind: &str, index: u32) -> crate::IdgError {
    crate::IdgError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("workspace IDG sidecar is missing {kind} entry {index}"),
    ))
}

fn invalid_sidecar_payload(error: impl std::fmt::Display) -> crate::IdgError {
    crate::IdgError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        error.to_string(),
    ))
}

/// Decode independent factstore chunks in resource-bounded batches and pass
/// each completed chunk directly to its resident destination. Missing entries
/// fail closed so callers rebuild the complete sidecar; decode/I/O failures
/// retain their typed error.
fn visit_sidecar_chunks<T, F>(
    reader: &bonsai_factstore::FactStoreReader,
    path: &std::path::Path,
    first_key: u64,
    chunk_count: u32,
    kind: &'static str,
    mut visit: F,
) -> crate::IdgResult<bool>
where
    T: serde::de::DeserializeOwned + Send,
    F: FnMut(Vec<T>),
{
    use rayon::prelude::*;

    let decode_width = idg_serialization_worker_count();
    for batch_start in (0..chunk_count).step_by(decode_width) {
        let batch_end = chunk_count.min(batch_start.saturating_add(decode_width as u32));
        let decoded = (batch_start..batch_end)
            .into_par_iter()
            .map(|chunk_idx| -> crate::IdgResult<Option<Vec<T>>> {
                let Some(hit) = reader.get(first_key + u64::from(chunk_idx))? else {
                    bonsai_diagnostics::debug_log!(
                        "idg-build",
                        "workspace sidecar miss: path={} reason=missing-chunk kind={} chunk={}",
                        path.display(),
                        kind,
                        chunk_idx
                    );
                    return Ok(None);
                };
                wire::decode(&hit.payload)
                    .map(Some)
                    .map_err(|e| crate::IdgError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
            })
            .collect::<Vec<_>>();
        for chunk in decoded {
            let Some(chunk) = chunk? else {
                return Ok(false);
            };
            visit(chunk);
        }
    }
    Ok(true)
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
const IDG_WORKSPACE_VERSION: u32 = 13;

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

fn idg_serialization_worker_count() -> usize {
    let cpu_workers = rayon::current_num_threads().max(1);
    // Keep most of the process budget available for the resident compiler
    // graph. Only the remaining quarter may be occupied by concurrent wire
    // buffers and decoded chunks. This affects throughput, never sidecar
    // completeness or graph semantics.
    let reserve = bonsai_common::effective_memory_limit_bytes()
        .map(|limit| limit.saturating_sub(limit / 4))
        .unwrap_or(1024 * 1024 * 1024);
    const SERIALIZATION_BYTES_PER_WORKER: u64 = 256 * 1024 * 1024;
    bonsai_common::memory_bounded_worker_count(cpu_workers, SERIALIZATION_BYTES_PER_WORKER, reserve)
}

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
