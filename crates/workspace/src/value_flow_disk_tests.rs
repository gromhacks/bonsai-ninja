use super::*;
use bonsai_factstore::StringPoolBuilder;
use bonsai_taint::ValueFlowGraph;

fn span(file: u32, start: u64, end: u64) -> Span {
    Span::new(FileId::new(file), start, end)
}

fn node(func: u32, file: u32, start: u64, end: u64, text: &str, kind: ValueFlowNodeKind) -> ValueFlowNode {
    ValueFlowNode {
        func: FuncId::new(func),
        span: span(file, start, end),
        value_text: text.to_string(),
        kind,
    }
}

fn build_pool_view(builder: &StringPoolBuilder) -> (Vec<u8>, Vec<u8>, u32) {
    (
        builder.bytes().to_vec(),
        builder.offsets_bytes(),
        u32::try_from(builder.len()).unwrap(),
    )
}

#[test]
fn empty_entry_roundtrips() {
    let entry = ValueFlowEntry::default();
    let mut pool = StringPoolBuilder::new();
    let bytes = encode(&entry, &mut |s| pool.intern(s));
    let (pool_bytes, pool_offsets, count) = build_pool_view(&pool);
    let view = StringPoolView::new(&pool_bytes, &pool_offsets, count).expect("pool");
    let decoded = decode(&bytes, &view).expect("decode");
    assert!(decoded.graph.nodes.is_empty());
    assert!(decoded.graph.forward.is_empty());
    assert!(decoded.graph.backward.is_empty());
    assert!(decoded.returning_seeds.is_empty());
    // `ValueFlowEntry::default()` constructs a default `ValueFlowGraph`,
    // whose `Precision::default()` is `Unknown` (the conservative
    // sentinel) — distinct from `ValueFlowGraph::new()` which uses
    // `Exact` as its starting precision.
    assert_eq!(decoded.graph.precision, Precision::Unknown);
    assert!(!decoded.graph.saturated);
}

#[test]
fn single_edge_graph_roundtrips() {
    let mut graph = ValueFlowGraph::new();
    let a = node(1, 0, 0, 4, "args", ValueFlowNodeKind::Param);
    let b = node(1, 0, 10, 14, "user", ValueFlowNodeKind::AssignTarget);
    graph.add_edge(ValueFlowEdge {
        from: a.clone(),
        to: b.clone(),
        precision: Precision::Exact,
        via_span: span(0, 8, 14),
    });
    let mut returning = AHashSet::default();
    returning.insert("args".to_string());
    let entry = ValueFlowEntry {
        graph,
        returning_seeds: returning,
    };
    let mut pool = StringPoolBuilder::new();
    let bytes = encode(&entry, &mut |s| pool.intern(s));
    let (pool_bytes, pool_offsets, count) = build_pool_view(&pool);
    let view = StringPoolView::new(&pool_bytes, &pool_offsets, count).expect("pool");
    let decoded = decode(&bytes, &view).expect("decode");
    assert_eq!(decoded.graph.nodes, entry.graph.nodes);
    assert_eq!(decoded.graph.forward, entry.graph.forward);
    assert_eq!(decoded.graph.backward, entry.graph.backward);
    assert_eq!(decoded.returning_seeds, entry.returning_seeds);
    assert_eq!(decoded.graph.precision, Precision::Exact);
}

#[test]
fn multi_edge_graph_roundtrips_with_dedup() {
    let mut graph = ValueFlowGraph::new();
    let a = node(1, 0, 0, 1, "a", ValueFlowNodeKind::Param);
    let b = node(1, 0, 2, 3, "b", ValueFlowNodeKind::AssignTarget);
    let c = node(1, 0, 4, 5, "c", ValueFlowNodeKind::CallArg);
    graph.add_edge(ValueFlowEdge {
        from: a.clone(),
        to: b.clone(),
        precision: Precision::Exact,
        via_span: span(0, 1, 2),
    });
    graph.add_edge(ValueFlowEdge {
        from: b.clone(),
        to: c.clone(),
        precision: Precision::OverApproximate,
        via_span: span(0, 3, 4),
    });
    let entry = ValueFlowEntry {
        graph,
        returning_seeds: AHashSet::default(),
    };
    let mut pool = StringPoolBuilder::new();
    let bytes = encode(&entry, &mut |s| pool.intern(s));
    let (pool_bytes, pool_offsets, count) = build_pool_view(&pool);
    let view = StringPoolView::new(&pool_bytes, &pool_offsets, count).expect("pool");
    let decoded = decode(&bytes, &view).expect("decode");
    // Forward / backward should match exactly. The edge with
    // OverApproximate precision must round-trip with the same
    // discriminant.
    assert_eq!(decoded.graph.precision, entry.graph.precision);
    assert_eq!(decoded.graph.forward, entry.graph.forward);
    assert_eq!(decoded.graph.backward, entry.graph.backward);
    // Pool must contain exactly the unique strings.
    assert_eq!(pool.len(), 3);
    assert!(pool.get(0).is_some());
    assert!(pool.get(1).is_some());
    assert!(pool.get(2).is_some());
    let mut entries: Vec<&str> = (0..3u32).filter_map(|i| pool.get(i)).collect();
    entries.sort_unstable();
    assert_eq!(entries, vec!["a", "b", "c"]);
}

#[test]
fn shared_strings_dedupe_in_pool() {
    // Build two graphs where every node shares the same value_text.
    // Encoding both into the same pool should keep the pool size at 1.
    let mut pool = StringPoolBuilder::new();
    for func in 0..5u32 {
        let mut graph = ValueFlowGraph::new();
        let n = node(func, 0, 0, 4, "shared", ValueFlowNodeKind::Param);
        graph.nodes.insert(n);
        let entry = ValueFlowEntry {
            graph,
            returning_seeds: AHashSet::default(),
        };
        let _ = encode(&entry, &mut |s| pool.intern(s));
    }
    assert_eq!(pool.len(), 1, "shared text must intern to one id");
}

#[test]
fn unknown_string_id_is_typed_error() {
    // Decode an entry whose `value_text_id` references a string
    // not present in the pool.
    let on_disk = OnDiskEntry {
        nodes: vec![OnDiskNode {
            func: 0,
            span_file: 0,
            span_start: 0,
            span_end: 1,
            value_text_id: 99,
            kind: 0,
        }],
        edges: Vec::new(),
        forward: Vec::new(),
        backward: Vec::new(),
        precision: Precision::Exact,
        saturated: false,
        returning_seeds: Vec::new(),
    };
    let bytes = bincode::serialize(&on_disk).unwrap();
    let pool_bytes = Vec::<u8>::new();
    let mut offsets = Vec::new();
    offsets.extend_from_slice(&0u32.to_le_bytes());
    let view = StringPoolView::new(&pool_bytes, &offsets, 0).expect("empty pool");
    match decode(&bytes, &view) {
        Err(DecodeError::UnknownStringId { id, count }) => {
            assert_eq!(id, 99);
            assert_eq!(count, 0);
        }
        other => panic!("expected UnknownStringId, got {other:?}"),
    }
}

#[test]
fn unknown_node_idx_is_typed_error() {
    // Edge references node index 5 but only 1 node exists.
    let mut pool = StringPoolBuilder::new();
    let _ = pool.intern("x");
    let on_disk = OnDiskEntry {
        nodes: vec![OnDiskNode {
            func: 0,
            span_file: 0,
            span_start: 0,
            span_end: 1,
            value_text_id: 0,
            kind: 0,
        }],
        edges: vec![OnDiskEdge {
            from_idx: 0,
            to_idx: 5,
            via_span_file: 0,
            via_span_start: 0,
            via_span_end: 0,
            precision: Precision::Exact,
        }],
        forward: Vec::new(),
        backward: Vec::new(),
        precision: Precision::Exact,
        saturated: false,
        returning_seeds: Vec::new(),
    };
    let bytes = bincode::serialize(&on_disk).unwrap();
    let pool_bytes = pool.bytes().to_vec();
    let pool_offsets = pool.offsets_bytes();
    let view = StringPoolView::new(&pool_bytes, &pool_offsets, 1).expect("pool");
    match decode(&bytes, &view) {
        Err(DecodeError::UnknownNodeIdx { idx, .. }) => {
            assert_eq!(idx, 5);
        }
        other => panic!("expected UnknownNodeIdx, got {other:?}"),
    }
}
