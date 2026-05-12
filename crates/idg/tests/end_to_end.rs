//! End-to-end Phase 1 integration: build a tiny workspace IDG by
//! hand, persist each segment to disk, reopen, verify everything
//! round-trips with the same shape.

use bonsai_callgraph::EdgeKind as CallEdgeKind;
use bonsai_common::{FileId, FuncId, Precision, Span};
use bonsai_idg::dict::{NodeDict, PlaceDict};
use bonsai_idg::edge::EdgeMeta;
use bonsai_idg::edge::IdgEdgeKind;
use bonsai_idg::node::{NodeId, PlaceId};
use bonsai_idg::place::Place;
use bonsai_idg::segment::IdgSegment;
use bonsai_idg::{
    workspace::{CrossFileEdge, IdgWorkspace, SegmentId},
    IdgEdge, IdgError,
};

fn span(file: u32, lo: u64, hi: u64) -> Span {
    Span::new(FileId::new(file), lo, hi)
}

#[test]
fn two_file_workspace_roundtrips_through_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pipeline = 0xDEAD_BEEF;

    // ─── Build segment A: file 0 hosts func 100 ────────────────
    let seg_a_path = dir.path().join("a.factstore");
    let mut seg_a = IdgSegment::new();
    let p_param0 = seg_a.intern_place(Place::Param { idx: 0 });
    let p_arg0 = seg_a.intern_place(Place::CallArg {
        site: bonsai_idg::place::CallSiteId(span(0, 100, 110)),
        idx: 0,
    });
    let n_a_param = seg_a.intern_node(FuncId::new(100), p_param0);
    let n_a_arg = seg_a.intern_node(FuncId::new(100), p_arg0);
    seg_a.add_edge(IdgEdge::intra_assign(n_a_param, n_a_arg, span(0, 50, 60)));
    seg_a.record_func(FuncId::new(100));
    seg_a.write_to_path(&seg_a_path, pipeline).expect("write A");

    // ─── Build segment B: file 1 hosts func 200 ────────────────
    let seg_b_path = dir.path().join("b.factstore");
    let mut seg_b = IdgSegment::new();
    let p_param0_b = seg_b.intern_place(Place::Param { idx: 0 });
    let p_return = seg_b.intern_place(Place::Return);
    let p_read = seg_b.intern_place(Place::read(42));
    let n_b_param = seg_b.intern_node(FuncId::new(200), p_param0_b);
    let n_b_return = seg_b.intern_node(FuncId::new(200), p_return);
    let n_b_read = seg_b.intern_node(FuncId::new(200), p_read);
    seg_b.add_edge(IdgEdge::intra_assign(n_b_param, n_b_read, span(1, 10, 20)));
    seg_b.add_edge(IdgEdge::intra_assign(n_b_read, n_b_return, span(1, 30, 40)));
    seg_b.record_func(FuncId::new(200));
    seg_b.write_to_path(&seg_b_path, pipeline).expect("write B");

    // ─── Reopen + register both segments in a fresh workspace ──
    let restored_a = IdgSegment::read_from_path(&seg_a_path, pipeline)
        .expect("read A")
        .expect("A present");
    let restored_b = IdgSegment::read_from_path(&seg_b_path, pipeline)
        .expect("read B")
        .expect("B present");

    let mut ws = IdgWorkspace::new();
    let id_a = ws.register_segment(restored_a);
    let id_b = ws.register_segment(restored_b);

    // ─── Add a cross-file edge: A.func 100 calls B.func 200 ────
    ws.cross_file_mut().push(CrossFileEdge {
        from_segment: id_a,
        to_segment: id_b,
        edge: IdgEdge::inter_call_arg(
            n_a_arg,
            n_b_param,
            span(0, 100, 110),
            Precision::Exact,
            CallEdgeKind::Direct,
        ),
    });

    // ─── Verify integrity ──────────────────────────────────────
    assert_eq!(ws.segment_count(), 2);
    assert_eq!(ws.func_count(), 2);
    assert_eq!(ws.intra_edge_count(), 3);
    assert_eq!(ws.cross_file().len(), 1);
    assert_eq!(ws.total_edge_count(), 4);

    // FuncId → SegmentId resolution must point at the right slice.
    assert_eq!(ws.segment_for_func(FuncId::new(100)), Some(id_a));
    assert_eq!(ws.segment_for_func(FuncId::new(200)), Some(id_b));

    // Cross-file edge is indexed both directions.
    assert_eq!(ws.cross_file().outgoing_from_segment(id_a).count(), 1);
    assert_eq!(ws.cross_file().incoming_to_segment(id_b).count(), 1);

    // Re-built segment dictionaries are usable post-deserialise.
    let seg_a_view = ws.segment(id_a).expect("A present");
    assert_eq!(seg_a_view.places.lookup(&Place::Param { idx: 0 }), Some(p_param0));
    let seg_b_view = ws.segment(id_b).expect("B present");
    assert_eq!(seg_b_view.places.lookup(&Place::Return), Some(p_return));
    assert_eq!(
        seg_b_view.nodes.lookup(FuncId::new(200), p_return),
        Some(n_b_return)
    );
}

#[test]
fn hot_reload_invalidates_only_affected_cross_file_edges() {
    // Build a 3-segment workspace where two segments call into the
    // third, then "edit" one of the callers and confirm only that
    // caller's cross-file edges are invalidated.
    let mut ws = IdgWorkspace::new();

    fn make_segment(func: FuncId) -> IdgSegment {
        let mut seg = IdgSegment::new();
        let p = seg.intern_place(Place::Param { idx: 0 });
        let _ = seg.intern_node(func, p);
        seg.record_func(func);
        seg
    }

    let id_a = ws.register_segment(make_segment(FuncId::new(1)));
    let id_b = ws.register_segment(make_segment(FuncId::new(2)));
    let id_target = ws.register_segment(make_segment(FuncId::new(99)));

    let cfedge = |from, to| CrossFileEdge {
        from_segment: from,
        to_segment: to,
        edge: IdgEdge::new(
            NodeId(0),
            NodeId(0),
            EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::InterCallArg,
                call_kind: CallEdgeKind::Direct,
                via_span: span(0, 0, 1),
            },
        ),
    };

    ws.cross_file_mut().push(cfedge(id_a, id_target));
    ws.cross_file_mut().push(cfedge(id_a, id_target));
    ws.cross_file_mut().push(cfedge(id_b, id_target));
    assert_eq!(ws.cross_file().len(), 3);
    assert_eq!(
        ws.cross_file().outgoing_from_segment(id_a).count(),
        2,
        "A → target before edit"
    );
    assert_eq!(
        ws.cross_file().outgoing_from_segment(id_b).count(),
        1,
        "B → target before edit"
    );
    assert_eq!(
        ws.cross_file().incoming_to_segment(id_target).count(),
        3,
        "target receives 3 edges before edit"
    );

    // Hot-reload of segment A: invalidate its cross-file edges.
    let dropped = ws.cross_file_mut().invalidate_from_segment(id_a);
    assert_eq!(dropped, 2);
    assert_eq!(ws.cross_file().len(), 1);
    assert_eq!(ws.cross_file().outgoing_from_segment(id_a).count(), 0);
    assert_eq!(
        ws.cross_file().outgoing_from_segment(id_b).count(),
        1,
        "B → target survives A's invalidation"
    );
    assert_eq!(
        ws.cross_file().incoming_to_segment(id_target).count(),
        1,
        "target only sees B's edge after A invalidated"
    );
}

#[test]
fn segment_table_id_mismatch_is_typed_error() {
    use bonsai_factstore::FactStoreWriter;
    // Write a factstore file with a wrong table id; segment reader
    // should fail on the table-id gate.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wrong_table.factstore");
    let writer = FactStoreWriter::create(&path, /* table */ 999, 0).expect("create");
    writer.add(0, 0, b"junk").expect("add");
    writer.finish().expect("finish");

    match IdgSegment::read_from_path(&path, 0) {
        Err(IdgError::FactStore(_)) => {
            // The factstore layer rejects the table-id mismatch via
            // its `WrongTable` error variant, which we wrap as
            // `IdgError::FactStore`. Acceptable.
        }
        other => panic!("expected FactStore error, got {other:?}"),
    }
}

#[test]
fn empty_dictionaries_are_consistent() {
    // Defensive check: ensure builders for the dict types stay in
    // sync with the segment defaults.
    let p = PlaceDict::new();
    let n = NodeDict::new();
    assert!(p.is_empty());
    assert!(n.is_empty());
    assert_eq!(p.len(), 0);
    assert_eq!(n.len(), 0);
    assert_eq!(p.get(PlaceId(0)), None);
    assert_eq!(n.get(NodeId(0)), None);
}

#[test]
fn cross_file_id_zero_segment_does_not_alias_uninserted_segment() {
    // A SegmentId(0) appearing in a cross-file edge before any
    // segment is registered must not crash anything (out-of-range
    // lookup returns None).
    let mut ws = IdgWorkspace::new();
    ws.cross_file_mut().push(CrossFileEdge {
        from_segment: SegmentId(0),
        to_segment: SegmentId(1),
        edge: IdgEdge::new(
            NodeId(0),
            NodeId(0),
            EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::InterCallArg,
                call_kind: CallEdgeKind::Direct,
                via_span: span(0, 0, 1),
            },
        ),
    });
    assert_eq!(ws.cross_file().len(), 1);
    assert!(ws.segment(SegmentId(0)).is_none());
    assert!(ws.segment(SegmentId(1)).is_none());
}
