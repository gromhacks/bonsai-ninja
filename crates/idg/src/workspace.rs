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
use crate::segment::IdgSegment;

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
/// [`IdgQueryService::cross_call_edges_in_closure`] which
/// synthesises a [`CrossCallEdge`] when both endpoints land in
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
        let idx = u32::try_from(self.edges.len())
            .expect("cross-file edge index overflow: > 2^32 edges");
        self.by_from_segment
            .entry(edge.from_segment)
            .or_default()
            .push(idx);
        self.by_to_segment
            .entry(edge.to_segment)
            .or_default()
            .push(idx);
        self.edges.push(edge);
    }

    /// Iterate every cross-file edge whose source is in `seg`.
    pub fn outgoing_from_segment(
        &self,
        seg: SegmentId,
    ) -> impl Iterator<Item = &CrossFileEdge> + '_ {
        self.by_from_segment
            .get(&seg)
            .into_iter()
            .flatten()
            .filter_map(move |idx| self.edges.get(*idx as usize))
    }

    /// Iterate every cross-file edge whose destination is in `seg`.
    pub fn incoming_to_segment(
        &self,
        seg: SegmentId,
    ) -> impl Iterator<Item = &CrossFileEdge> + '_ {
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
            self.by_from_segment
                .entry(edge.from_segment)
                .or_default()
                .push(i);
            self.by_to_segment
                .entry(edge.to_segment)
                .or_default()
                .push(i);
        }
    }
}

/// Workspace-level IDG. Holds per-file segments, the cross-file
/// edge index, and the `FuncId → SegmentId` lookup map.
///
/// This is the in-memory aggregate; persistence is per-segment via
/// [`crate::segment::IdgSegment::write_to_path`] plus the cross-file
/// edge factstore (added in Phase 3 builder).
#[derive(Default, Debug)]
pub struct IdgWorkspace {
    segments: Vec<IdgSegment>,
    /// `FuncId.raw() → SegmentId`. Built by [`Self::register_segment`].
    by_func: AHashMap<u32, SegmentId>,
    /// Cross-file edges. Populated by the workspace builder
    /// (Phase 3).
    cross_file: CrossFileEdges,
    /// Cross-method field-flow links surfaced by Phase 3c. These
    /// aren't true call edges — they record that a writer-method's
    /// receiver-field write feeds a reader-method's receiver-field
    /// read. The query layer
    /// ([`IdgQueryService::cross_call_edges_in_closure`]) lifts each
    /// link into a synthetic [`CrossCallEdge`] when both endpoints
    /// land in the same forward closure, so source/sink lineage and
    /// `find-group` chain enumeration can traverse cross-method
    /// state propagation the same way they traverse real calls.
    field_flow: Vec<FieldFlowLink>,
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
        let raw = u32::try_from(self.segments.len())
            .expect("segment index overflow: > 2^32 segments");
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

    /// Mutably borrow the cross-file edge index. Used by the Phase 3
    /// builder when it stitches inter-segment edges.
    /// Read-only access to the cross-method field-flow links.
    pub fn field_flow(&self) -> &[FieldFlowLink] {
        &self.field_flow
    }

    /// Mutable access for Phase 3c to push field-flow links during
    /// IDG construction.
    pub fn field_flow_mut(&mut self) -> &mut Vec<FieldFlowLink> {
        &mut self.field_flow
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{IdgEdge, IdgEdgeKind};
    use crate::node::NodeId;
    use crate::place::Place;
    use bonsai_callgraph::EdgeKind as CallEdgeKind;
    use bonsai_common::{FileId, Precision, Span};

    fn span() -> Span {
        Span::new(FileId::new(0), 0, 1)
    }

    fn populate_segment(seg: &mut IdgSegment, func: FuncId) -> (NodeId, NodeId) {
        let p_param = seg.intern_place(Place::Param { idx: 0 });
        let p_return = seg.intern_place(Place::Return);
        let n_param = seg.intern_node(func, p_param);
        let n_return = seg.intern_node(func, p_return);
        seg.add_edge(IdgEdge::intra_assign(n_param, n_return, span()));
        seg.record_func(func);
        (n_param, n_return)
    }

    #[test]
    fn empty_workspace_has_zero_segments() {
        let w = IdgWorkspace::new();
        assert_eq!(w.segment_count(), 0);
        assert_eq!(w.func_count(), 0);
        assert_eq!(w.intra_edge_count(), 0);
        assert_eq!(w.total_edge_count(), 0);
        assert!(w.cross_file().is_empty());
    }

    #[test]
    fn register_segment_indexes_funcs() {
        let mut w = IdgWorkspace::new();
        let mut seg = IdgSegment::new();
        let _ = populate_segment(&mut seg, FuncId::new(7));
        seg.record_func(FuncId::new(8)); // separate func with no edges
        let id = w.register_segment(seg);
        assert_eq!(w.segment_count(), 1);
        assert_eq!(w.func_count(), 2);
        assert_eq!(w.segment_for_func(FuncId::new(7)), Some(id));
        assert_eq!(w.segment_for_func(FuncId::new(8)), Some(id));
        assert_eq!(w.segment_for_func(FuncId::new(99)), None);
    }

    #[test]
    fn segment_lookup_returns_registered_segment() {
        let mut w = IdgWorkspace::new();
        let mut seg = IdgSegment::new();
        populate_segment(&mut seg, FuncId::new(7));
        let id = w.register_segment(seg);
        let retrieved = w.segment(id).expect("segment present");
        assert_eq!(retrieved.dimensions(), (2, 2, 1));
    }

    #[test]
    fn cross_file_edge_indexed_both_directions() {
        let mut cfe = CrossFileEdges::new();
        let from_seg = SegmentId(1);
        let to_seg = SegmentId(2);
        let edge = IdgEdge::inter_call_arg(
            NodeId(0),
            NodeId(1),
            span(),
            Precision::Exact,
            CallEdgeKind::Direct,
        );
        cfe.push(CrossFileEdge {
            from_segment: from_seg,
            to_segment: to_seg,
            edge,
        });
        assert_eq!(cfe.outgoing_from_segment(from_seg).count(), 1);
        assert_eq!(cfe.incoming_to_segment(to_seg).count(), 1);
        assert_eq!(cfe.outgoing_from_segment(to_seg).count(), 0);
        assert_eq!(cfe.incoming_to_segment(from_seg).count(), 0);
    }

    #[test]
    fn cross_file_invalidate_from_segment_drops_only_those_edges() {
        let mut cfe = CrossFileEdges::new();
        let edge = IdgEdge::inter_call_arg(
            NodeId(0),
            NodeId(1),
            span(),
            Precision::Exact,
            CallEdgeKind::Direct,
        );
        for from_raw in [1u32, 1, 2, 1, 3] {
            cfe.push(CrossFileEdge {
                from_segment: SegmentId(from_raw),
                to_segment: SegmentId(0),
                edge,
            });
        }
        assert_eq!(cfe.len(), 5);
        let dropped = cfe.invalidate_from_segment(SegmentId(1));
        assert_eq!(dropped, 3);
        assert_eq!(cfe.len(), 2);
        // The two surviving edges are the SegmentId(2) and SegmentId(3) ones.
        assert_eq!(cfe.outgoing_from_segment(SegmentId(1)).count(), 0);
        assert_eq!(cfe.outgoing_from_segment(SegmentId(2)).count(), 1);
        assert_eq!(cfe.outgoing_from_segment(SegmentId(3)).count(), 1);
        // The destination index should also reflect the compaction.
        assert_eq!(cfe.incoming_to_segment(SegmentId(0)).count(), 2);
    }

    #[test]
    fn cross_file_invalidate_returns_zero_for_unknown_segment() {
        let mut cfe = CrossFileEdges::new();
        cfe.push(CrossFileEdge {
            from_segment: SegmentId(1),
            to_segment: SegmentId(0),
            edge: IdgEdge::inter_call_arg(
                NodeId(0),
                NodeId(0),
                span(),
                Precision::Exact,
                CallEdgeKind::Direct,
            ),
        });
        assert_eq!(cfe.invalidate_from_segment(SegmentId(99)), 0);
        assert_eq!(cfe.len(), 1);
    }

    #[test]
    fn cross_file_rebuild_indexes_after_serde() {
        let mut cfe = CrossFileEdges::new();
        cfe.push(CrossFileEdge {
            from_segment: SegmentId(1),
            to_segment: SegmentId(2),
            edge: IdgEdge::inter_call_arg(
                NodeId(0),
                NodeId(1),
                span(),
                Precision::Exact,
                CallEdgeKind::Direct,
            ),
        });
        let bytes = bincode::serialize(&cfe).unwrap();
        let mut restored: CrossFileEdges = bincode::deserialize(&bytes).unwrap();
        // After deserialize, by_from / by_to are empty.
        assert_eq!(restored.outgoing_from_segment(SegmentId(1)).count(), 0);
        restored.rebuild_indexes();
        assert_eq!(restored.outgoing_from_segment(SegmentId(1)).count(), 1);
        assert_eq!(restored.incoming_to_segment(SegmentId(2)).count(), 1);
    }

    #[test]
    fn workspace_total_counts_intra_plus_cross_file() {
        let mut w = IdgWorkspace::new();
        let mut seg_a = IdgSegment::new();
        populate_segment(&mut seg_a, FuncId::new(1));
        let mut seg_b = IdgSegment::new();
        populate_segment(&mut seg_b, FuncId::new(2));
        let id_a = w.register_segment(seg_a);
        let id_b = w.register_segment(seg_b);
        w.cross_file_mut().push(CrossFileEdge {
            from_segment: id_a,
            to_segment: id_b,
            edge: IdgEdge::new(
                NodeId(0),
                NodeId(0),
                crate::edge::EdgeMeta {
                    precision: Precision::Exact,
                    kind: IdgEdgeKind::InterCallArg,
                    call_kind: CallEdgeKind::Direct,
                    via_span: span(),
                },
            ),
        });
        assert_eq!(w.intra_edge_count(), 2);
        assert_eq!(w.cross_file().len(), 1);
        assert_eq!(w.total_edge_count(), 3);
    }

    #[test]
    fn segment_mut_lets_caller_extend_post_registration() {
        let mut w = IdgWorkspace::new();
        let mut seg = IdgSegment::new();
        populate_segment(&mut seg, FuncId::new(1));
        let id = w.register_segment(seg);
        let segment = w.segment_mut(id).expect("present");
        segment.record_func(FuncId::new(99));
        // Note: by_func index is NOT updated by this — the workspace
        // owns its index. Phase 3 builder is expected to either fully
        // populate the segment before registration, or call a
        // re-index helper. This test pins current behaviour so a
        // future change is intentional.
        assert_eq!(w.segment_for_func(FuncId::new(99)), None);
    }
}
