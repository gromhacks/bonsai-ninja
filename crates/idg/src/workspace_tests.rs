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

#[test]
fn save_load_round_trip_preserves_segments_and_indexes() {
    let mut w = IdgWorkspace::new();
    let mut seg_a = IdgSegment::new();
    populate_segment(&mut seg_a, FuncId::new(11));
    let mut seg_b = IdgSegment::new();
    populate_segment(&mut seg_b, FuncId::new(22));
    let id_a = w.register_segment(seg_a);
    let id_b = w.register_segment(seg_b);
    w.cross_file_mut().push(CrossFileEdge {
        from_segment: id_a,
        to_segment: id_b,
        edge: IdgEdge::inter_call_arg(
            NodeId(0),
            NodeId(0),
            span(),
            Precision::Exact,
            CallEdgeKind::Direct,
        ),
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idg.factstore");
    w.save_to_disk(&path, 0xDEAD_BEEF).expect("save succeeds");
    let restored = IdgWorkspace::load_from_disk(&path, 0xDEAD_BEEF)
        .expect("load Ok")
        .expect("Some workspace");
    assert_eq!(restored.segment_count(), 2);
    assert_eq!(restored.segment_for_func(FuncId::new(11)), Some(id_a));
    assert_eq!(restored.segment_for_func(FuncId::new(22)), Some(id_b));
    assert_eq!(restored.cross_file().len(), 1);
    assert_eq!(restored.cross_file().outgoing_from_segment(id_a).count(), 1);
    assert_eq!(restored.intra_edge_count(), 2);
}

#[test]
fn save_load_round_trip_preserves_chunked_cross_file_and_field_flow() {
    let mut w = IdgWorkspace::new();
    let mut seg_a = IdgSegment::new();
    populate_segment(&mut seg_a, FuncId::new(11));
    let mut seg_b = IdgSegment::new();
    populate_segment(&mut seg_b, FuncId::new(22));
    let id_a = w.register_segment(seg_a);
    let id_b = w.register_segment(seg_b);

    for idx in 0..3 {
        w.cross_file_mut().push(CrossFileEdge {
            from_segment: id_a,
            to_segment: id_b,
            edge: IdgEdge::inter_call_arg(
                NodeId(idx),
                NodeId(idx),
                Span::new(FileId::new(0), idx as u64, idx as u64 + 1),
                Precision::Exact,
                CallEdgeKind::Direct,
            ),
        });
        w.field_flow_mut().push(FieldFlowLink {
            writer: FuncId::new(11),
            reader: FuncId::new(22),
            writer_ws_node: idx,
            reader_ws_node: idx + 10,
            via_span: Span::new(FileId::new(0), idx as u64, idx as u64 + 1),
            precision: Precision::Exact,
        });
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idg.factstore");
    w.save_to_disk(&path, 0xCAFE).expect("save succeeds");
    let restored = IdgWorkspace::load_from_disk(&path, 0xCAFE)
        .expect("load Ok")
        .expect("Some workspace");

    assert_eq!(restored.cross_file().len(), 3);
    assert_eq!(restored.cross_file().outgoing_from_segment(id_a).count(), 3);
    assert_eq!(restored.cross_file().incoming_to_segment(id_b).count(), 3);
    assert_eq!(restored.field_flow().len(), 3);
}

#[test]
fn load_rejects_pipeline_hash_mismatch() {
    let mut w = IdgWorkspace::new();
    let mut seg = IdgSegment::new();
    populate_segment(&mut seg, FuncId::new(1));
    w.register_segment(seg);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idg.factstore");
    w.save_to_disk(&path, 1).expect("save");
    // Different pipeline_hash → load returns None so caller rebuilds.
    let loaded = IdgWorkspace::load_from_disk(&path, 2).expect("load Ok");
    assert!(loaded.is_none(), "stale sidecar must be rejected");
}

#[test]
fn workspace_sidecar_round_trips_wide_positional_places() {
    let mut workspace = IdgWorkspace::new();
    let mut segment = IdgSegment::new();
    let func = FuncId::new(1);
    let site = crate::place::CallSiteId(span());
    let param = segment.intern_place(Place::Param { idx: 299 });
    let arg = segment.intern_place(Place::CallArg { site, idx: 299 });
    let param_node = segment.intern_node(func, param);
    let arg_node = segment.intern_node(func, arg);
    segment.add_edge(IdgEdge::intra_assign(param_node, arg_node, span()));
    segment.record_func(func);
    workspace.register_segment(segment);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wide-idg.factstore");
    workspace.save_to_disk(&path, 0xCAFE).expect("save");
    let restored = IdgWorkspace::load_from_disk(&path, 0xCAFE)
        .expect("load")
        .expect("current workspace");
    let segment = restored.segment(SegmentId(0)).expect("segment");
    assert!(segment.places.lookup(&Place::Param { idx: 299 }).is_some());
    assert!(segment
        .places
        .lookup(&Place::CallArg { site, idx: 299 })
        .is_some());
}

#[test]
fn workspace_sidecar_rejects_stale_segment_layout() {
    let mut workspace = IdgWorkspace::new();
    let mut segment = IdgSegment::new();
    populate_segment(&mut segment, FuncId::new(1));
    segment.version = IDG_SEGMENT_VERSION - 1;
    workspace.register_segment(segment);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("stale-idg.factstore");
    workspace.save_to_disk(&path, 0xCAFE).expect("save");
    let restored = IdgWorkspace::load_from_disk(&path, 0xCAFE).expect("load");
    assert!(
        restored.is_none(),
        "stale segment layout must force an IDG rebuild"
    );
}

#[test]
fn sidecar_file_validator_rejects_corrupt_payload() {
    let mut w = IdgWorkspace::new();
    let mut seg = IdgSegment::new();
    populate_segment(&mut seg, FuncId::new(1));
    w.register_segment(seg);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idg.factstore");
    w.save_to_disk(&path, 0xCAFE).expect("save");
    assert_eq!(
        IdgWorkspace::validate_sidecar_file(&path).expect("valid sidecar"),
        1
    );

    let len = std::fs::metadata(&path).expect("metadata").len();
    std::fs::write(&path, vec![0_u8; len as usize]).expect("corrupt same-size sidecar");
    assert!(
        IdgWorkspace::validate_sidecar_file(&path).is_err(),
        "same-size corrupt IDG factstore must not validate"
    );
}

#[test]
fn load_returns_none_for_missing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("does-not-exist.factstore");
    let loaded = IdgWorkspace::load_from_disk(&path, 0).expect("load Ok");
    assert!(loaded.is_none());
}
