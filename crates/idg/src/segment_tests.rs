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
    assert_eq!(restored.nodes.lookup(FuncId::new(7), pid_param), Some(n_param),);
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
