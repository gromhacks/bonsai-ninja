use super::*;
use crate::workspace_adapter;
use crate::{SymbolicFieldGraph, SymbolicFieldTransform, SymbolicFieldTransformKind, NO_SYMBOLIC_STRING};
use bonsai_callgraph::{CallEdge, CallGraph, EdgeKind, EdgeProvenance, ResolvedCallGraph};
use bonsai_common::{Precision, SymbolId};
use bonsai_lang_api::{Decl, DeclIndex, DeclKind, FieldWrite, FlowEvent, ModulePath, Visibility};

fn span(file: u32, start: u64, end: u64) -> Span {
    Span::new(bonsai_common::FileId::new(file), start, end)
}

#[test]
fn structural_boundary_index_groups_exact_callees_without_hash_buckets() {
    let caller = FuncId::new(10);
    let first_site = span(0, 20, 30);
    let second_site = span(0, 40, 50);
    let rows = vec![
        ContextBoundaryKey {
            caller,
            callee: FuncId::new(13),
            span: first_site,
        },
        ContextBoundaryKey {
            caller,
            callee: FuncId::new(12),
            span: second_site,
        },
        ContextBoundaryKey {
            caller,
            callee: FuncId::new(11),
            span: first_site,
        },
        ContextBoundaryKey {
            caller,
            callee: FuncId::new(13),
            span: first_site,
        },
    ];
    let index = StructuralBoundaryIndex::new(rows);

    assert_eq!(
        index
            .for_site(caller, first_site)
            .iter()
            .map(|key| key.callee)
            .collect::<Vec<_>>(),
        vec![FuncId::new(11), FuncId::new(13)]
    );
    assert_eq!(
        index
            .for_site(caller, second_site)
            .iter()
            .map(|key| key.callee)
            .collect::<Vec<_>>(),
        vec![FuncId::new(12)]
    );
    assert!(index.for_site(FuncId::new(99), first_site).is_empty());
}

#[test]
fn contextual_boundary_demand_remaps_only_synthetic_same_site_endpoints() {
    let caller = FuncId::new(10);
    let callee = FuncId::new(11);
    let compatibility_owner = FuncId::new(12);
    let site = span(0, 20, 30);
    let mut segment = crate::segment::IdgSegment::new();
    let argument_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(site),
        idx: 0,
    });
    let parameter_place = segment.intern_place(Place::Param { idx: 0 });
    let synthetic_place = segment.intern_place(Place::Yield);
    let argument = segment.intern_node(caller, argument_place);
    let parameter = segment.intern_node(callee, parameter_place);
    let synthetic = segment.intern_node(compatibility_owner, synthetic_place);
    segment.add_edge(IdgEdge::inter_call_arg(
        argument,
        parameter,
        site,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.add_edge(IdgEdge::inter_call_arg(
        argument,
        synthetic,
        site,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.record_func(caller);
    segment.record_func(callee);
    segment.record_func(compatibility_owner);

    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));
    let runtime = service.build_contextual_summary_runtime(&[], Some(Precision::Narrowed), None);
    let mut rows = Vec::new();
    runtime
        .calls_by_from
        .visit(NodeId(argument.0), |edge| rows.push(edge));

    assert!(rows
        .iter()
        .any(|edge| edge.key.callee == callee && edge.target == parameter));
    assert!(rows
        .iter()
        .any(|edge| edge.key.callee == callee && edge.target == synthetic));
    assert!(
        rows.iter().all(|edge| edge.key.callee != compatibility_owner),
        "synthetic compatibility ownership must be attributed to the exact structural callee: {rows:?}"
    );
}

#[test]
fn contextual_boundary_spool_merges_runs_without_losing_or_duplicating_facts() {
    let row_count = CONTEXTUAL_BOUNDARY_RUN_ROWS + 17;
    let mut spool = ContextBoundarySpool::new();
    for source in (0..row_count).rev() {
        let source = u32::try_from(source).expect("test source fits u32");
        spool.push(
            NodeId(source),
            ContextBoundaryEdge {
                key: ContextBoundaryKey {
                    caller: FuncId::new(1),
                    callee: FuncId::new(2),
                    span: span(0, 20, 30),
                },
                target: NodeId(source + 1),
                cross_call: None,
            },
        );
    }
    spool.push(
        NodeId(7),
        ContextBoundaryEdge {
            key: ContextBoundaryKey {
                caller: FuncId::new(1),
                callee: FuncId::new(2),
                span: span(0, 20, 30),
            },
            target: NodeId(8),
            cross_call: None,
        },
    );

    let (rows, reverse) = spool.finish(true);
    assert_eq!(rows.edges.len(), row_count);
    assert_eq!(rows.sources.len(), row_count);
    assert_eq!(rows.offsets.len(), row_count + 1);
    assert_eq!(rows.sources.first(), Some(&NodeId(0)));
    assert_eq!(rows.sources.last(), Some(&NodeId(row_count as u32 - 1)));
    assert_eq!(reverse.len(), row_count);
    assert_eq!(reverse.first(), Some(&(NodeId(1), WsNodeId(0))));
}

#[test]
fn contextual_fixed_width_rows_round_trip_every_boundary_field() {
    let cross_call = CrossCallEdge {
        caller: FuncId::new(11),
        callee: FuncId::new(12),
        call_span: span(3, 101, 149),
        arg_idx: 7,
        param_idx: 9,
        precision: Precision::OverApproximate,
        call_kind: CallEdgeKind::Indirect,
        relation: CrossCallRelation::Capture,
    };
    let heap = HeapBoundaryEdge {
        target: WsNodeId(37),
        cross_call: Some(cross_call),
    };
    let mut heap_row = Vec::new();
    encode_heap_boundary_edge(&mut heap_row, &heap);
    assert_eq!(heap_row.len(), CONTEXTUAL_HEAP_EDGE_BYTES);
    let decoded_heap = decode_heap_boundary_edge(&heap_row);
    assert_eq!(decoded_heap.target, heap.target);
    assert_eq!(decoded_heap.cross_call, heap.cross_call);

    let boundary = ContextBoundaryEdge {
        key: ContextBoundaryKey {
            caller: FuncId::new(21),
            callee: FuncId::new(22),
            span: span(4, 211, 233),
        },
        target: NodeId(41),
        cross_call: Some(cross_call),
    };
    let mut boundary_row = Vec::new();
    encode_context_boundary_edge(&mut boundary_row, &boundary);
    assert_eq!(boundary_row.len(), CONTEXTUAL_BOUNDARY_EDGE_BYTES);
    let decoded_boundary = decode_context_boundary_edge(&boundary_row);
    assert_eq!(decoded_boundary.key, boundary.key);
    assert_eq!(decoded_boundary.target, boundary.target);
    assert_eq!(decoded_boundary.cross_call, boundary.cross_call);
}

#[test]
fn packed_symbolic_strings_preserve_exact_sorted_utf8_identity() {
    let values = vec![
        "0.deep.field".to_string(),
        "alpha".to_string(),
        "alpha.beta".to_string(),
        "λ.field".to_string(),
    ];
    let table = PackedStringTable::from_sorted(values.clone());
    assert_eq!(table.len(), values.len());
    for (index, value) in values.iter().enumerate() {
        let id = u32::try_from(index).expect("test field index fits u32");
        assert_eq!(table.get(id), Some(value.as_str()));
        assert_eq!(table.find(value), Some(id));
    }
    assert_eq!(table.find("alpha.gamma"), None);
    assert_eq!(table.get(values.len() as u32), None);
}

#[test]
fn packed_symbolic_strings_find_joined_paths_without_allocation() {
    let table = PackedStringTable::from_sorted(vec![
        "_data".to_string(),
        "_data.cmd".to_string(),
        "cmd".to_string(),
        "user".to_string(),
    ]);
    assert_eq!(table.find_joined("_data", "cmd"), table.find("_data.cmd"));
    assert_eq!(table.find_joined("_data", "user"), None);
    assert_eq!(table.find_joined("", "cmd"), None);
}

#[test]
fn symbolic_base_rebases_preserve_nested_path_identity_both_directions() {
    let segment = SegmentId(3);
    let func = FuncId::new(9);
    let mut symbolic = SymbolicFieldGraph::new();
    let root = symbolic.intern_base(segment, func, "self");
    let nested = symbolic.intern_base(segment, func, "self._data");
    let fields = PackedStringTable::from_sorted(vec![
        "_data".to_string(),
        "_data.cmd".to_string(),
        "cmd".to_string(),
        "user".to_string(),
    ]);
    let rebases = SymbolicBaseRebaseIndex::from_specs(SymbolicBaseRebaseIndex::specs(&symbolic), &fields);
    let runtime = SymbolicRuntimeIndex {
        fields,
        base_rebases: rebases,
        ..SymbolicRuntimeIndex::default()
    };

    let cmd = runtime.field_id("cmd").expect("cmd field");
    let nested_cmd = runtime.field_id("_data.cmd").expect("nested cmd field");
    let to_root = runtime
        .base_rebases
        .outgoing(nested)
        .iter()
        .find(|row| row.target == root)
        .copied()
        .expect("nested-to-root rebase");
    assert_eq!(runtime.rebased_field(to_root, cmd), Some(nested_cmd));

    let to_nested = runtime
        .base_rebases
        .outgoing(root)
        .iter()
        .find(|row| row.target == nested)
        .copied()
        .expect("root-to-nested rebase");
    assert_eq!(runtime.rebased_field(to_nested, nested_cmd), Some(cmd));
    assert_eq!(
        runtime.rebased_field(to_nested, runtime.field_id("user").expect("user field")),
        None,
        "an unrelated sibling cannot be projected into the nested base"
    );
}

#[test]
fn symbolic_fact_pager_round_trips_sparse_fixed_width_pages() {
    let mut pager = SymbolicFactPager::new(3);
    let page = SymbolicFactPage {
        offsets: vec![0, 1, 1].into_boxed_slice(),
        facts: vec![SymbolicFactTemplate {
            base: 7,
            field: 11,
            span: 13,
        }]
        .into_boxed_slice(),
    };
    pager.write_page(SegmentId(2), &page);

    assert!(pager.page(SegmentId(0)).is_none());
    let decoded = pager.page(SegmentId(2)).expect("written symbolic fact page");
    assert!(decoded.get(NodeId(1)).is_empty());
    let facts = decoded.get(NodeId(0));
    assert_eq!(facts.len(), 1);
    assert_eq!((facts[0].base, facts[0].field, facts[0].span), (7, 11, 13));
}

#[test]
fn symbolic_worklist_facts_are_fixed_width_and_drop_unused_interprocedural_spans() {
    assert_eq!(std::mem::size_of::<SymbolicNodeFact>(), 16);
    assert_eq!(std::mem::size_of::<SymbolicFactIdentity>(), 12);
    let local = SymbolicNodeFact::new(1, 2, Some(3), false, 4);
    assert_eq!(local.span_id(), Some(3));
    assert!(!local.is_interprocedural());

    let interprocedural = SymbolicNodeFact::new(1, 2, Some(99), true, 4);
    assert_eq!(interprocedural.span_id(), None);
    assert!(interprocedural.is_interprocedural());
}

#[test]
fn symbolic_local_provenance_is_retained_only_for_order_sensitive_bases() {
    let first = SymbolicFactSpan::from(span(0, 10, 11));
    let second = SymbolicFactSpan::from(span(0, 20, 21));
    let runtime = SymbolicRuntimeIndex {
        spans: vec![first, second].into_boxed_slice(),
        // Base 3 has an outgoing transform whose source-order predicate reads
        // provenance; base 2 has no such consumer.
        ordering_sensitive_bases: Box::new([1_u64 << 3]),
        ..SymbolicRuntimeIndex::default()
    };

    assert_eq!(runtime.local_provenance_id(3, span(0, 10, 11)), Some(0));
    assert_eq!(runtime.local_provenance_id(3, span(0, 20, 21)), Some(1));
    assert_eq!(runtime.local_provenance_id(2, span(0, 10, 11)), None);
    assert_eq!(runtime.local_provenance_id(2, span(0, 20, 21)), None);

    let insensitive_first =
        SymbolicNodeFact::new(2, 7, runtime.local_provenance_id(2, span(0, 10, 11)), false, 0);
    let insensitive_second =
        SymbolicNodeFact::new(2, 7, runtime.local_provenance_id(2, span(0, 20, 21)), false, 0);
    assert_eq!(
        insensitive_first.identity(),
        insensitive_second.identity(),
        "unused AST write positions must not multiply exact fact states"
    );

    let sensitive_first =
        SymbolicNodeFact::new(3, 7, runtime.local_provenance_id(3, span(0, 10, 11)), false, 0);
    let sensitive_second =
        SymbolicNodeFact::new(3, 7, runtime.local_provenance_id(3, span(0, 20, 21)), false, 0);
    assert_ne!(
        sensitive_first.identity(),
        sensitive_second.identity(),
        "source-order predicates require distinct AST write positions"
    );
}

#[test]
fn symbolic_worklist_spills_exact_fact_states_and_preserves_every_context() {
    let mut demanded = closure_fact_store();
    demanded.insert(u128::from(symbolic_fact_key(7, 11)));
    let demand = SymbolicFieldDemand {
        facts: demanded,
        wildcard_bases: closure_fact_store(),
    };
    let mut worklist = SymbolicClosureWorklist::new(1, 0, None, None, None, &demand);
    let first = SymbolicNodeFact::new(7, 11, Some(13), false, 3);
    let second_context = SymbolicNodeFact::new(7, 11, Some(13), false, 5);
    assert_eq!(SymbolicNodeFact::from_state_key(first.state_key()), first);

    worklist.enqueue_fact_state(first);
    worklist.enqueue_fact_state(first);
    worklist.enqueue_fact_state(second_context);

    assert_eq!(worklist.facts.len(), 2);
    assert_eq!(worklist.pending_facts.len(), 2);

    let mut contexts = [
        worklist.next_fact().expect("first exact fact").context,
        worklist.next_fact().expect("second exact fact").context,
    ];
    contexts.sort_unstable();
    assert_eq!(contexts, [3, 5]);
}

#[test]
fn root_closure_visited_promotes_from_sparse_to_dense_without_changing_membership() {
    let node_count = 4096usize;
    let dense_bytes = node_count.div_ceil(u8::BITS as usize);
    let sparse_entry_bytes = std::mem::size_of::<u32>() + std::mem::size_of::<usize>();
    let promotion_count = dense_bytes.div_ceil(sparse_entry_bytes);
    let mut visited = RootClosureVisited::new(node_count, 1);
    assert!(matches!(visited, RootClosureVisited::Sparse { .. }));

    for raw in 0..promotion_count {
        assert!(visited.insert(NodeId(raw as u32)));
    }
    assert!(matches!(visited, RootClosureVisited::Dense(_)));
    for raw in 0..promotion_count {
        assert!(!visited.insert(NodeId(raw as u32)), "promotion lost node {raw}");
    }
    assert!(
        !visited.insert(NodeId(node_count as u32)),
        "out-of-range nodes must stay excluded"
    );
}

#[test]
fn contextual_closure_visited_spills_exact_states_and_erases_context_only_in_results() {
    let node_count = 4096usize;
    let mut visited = ContextualClosureVisited::new(node_count);

    assert!(visited.insert(1, NodeId(7)));
    assert!(!visited.insert(1, NodeId(7)));
    assert!(visited.insert(2, NodeId(7)));
    for raw in 0..64 {
        visited.insert(1, NodeId(raw as u32));
    }
    assert!(
        !visited.insert(1, NodeId(node_count as u32)),
        "out-of-range contextual nodes must stay excluded"
    );

    let nodes = visited.erased_nodes();
    assert_eq!(
        nodes.iter().filter(|node| **node == NodeId(7)).count(),
        1,
        "the public closure result erases context after exact state evaluation"
    );
    assert_eq!(visited.len(), 65, "distinct context/node states remain exact");
    assert_eq!(nodes.len(), 64, "the context-erased result contains unique nodes");
}

#[test]
fn closure_result_unions_root_and_context_states_in_node_order() {
    let mut visited = ClosureVisited::new(32, 1);
    assert!(visited.insert(NodeId(17), 0));
    assert!(visited.insert(NodeId(3), 0));
    assert!(visited.insert(NodeId(9), 1));
    assert!(visited.insert(NodeId(3), 2));

    assert_eq!(
        visited.nodes(),
        vec![NodeId(3), NodeId(9), NodeId(17)],
        "context erasure must preserve every reached node exactly once in deterministic order"
    );
}

#[test]
fn call_context_tabulation_is_finite_and_replays_recursive_returns() {
    let first = ContextBoundaryKey {
        caller: FuncId::new(1),
        callee: FuncId::new(2),
        span: span(0, 10, 20),
    };
    let second = ContextBoundaryKey {
        caller: FuncId::new(2),
        callee: FuncId::new(1),
        span: span(1, 30, 40),
    };
    let mut contexts = CallContexts::new();
    let (first_context, first_registered) = contexts.register_call(0, first);
    let (second_context, second_registered) = contexts.register_call(first_context, second);
    assert!(first_registered && second_registered);

    // Re-entering an existing boundary records another tabulation caller; it
    // never allocates the recursive call string first→second→first→… .
    let (recursive_context, recursive_registered) = contexts.register_call(second_context, first);
    assert_eq!(recursive_context, first_context);
    assert!(recursive_registered);
    assert_eq!(contexts.boundaries.len(), 3);

    let returned = NodeId(17);
    let mut callers = contexts.complete_node_return(first_context, returned);
    callers.sort_unstable();
    assert_eq!(callers, vec![0, second_context]);

    // A caller discovered after completion receives the cached summary.
    let late_context = contexts.context_for(ContextBoundaryKey {
        caller: FuncId::new(3),
        callee: FuncId::new(1),
        span: span(2, 50, 60),
    });
    let (_, late_registered) = contexts.register_call(late_context, first);
    assert!(late_registered);
    assert_eq!(contexts.returned_node_batch(first_context, None), vec![returned]);
}

#[test]
fn call_context_return_nodes_replay_from_exact_bounded_batches() {
    let boundary = ContextBoundaryKey {
        caller: FuncId::new(1),
        callee: FuncId::new(2),
        span: span(0, 10, 20),
    };
    let mut contexts = CallContexts::new();
    contexts.returned_nodes = SpillSet::new(64, 128, 128, true);
    let (context, registered) = contexts.register_call(0, boundary);
    assert!(registered);

    let count = CONTEXT_REPLAY_BATCH_ENTRIES + 3;
    for raw in 0..count {
        assert_eq!(
            contexts.complete_node_return(context, NodeId(raw as u32)),
            vec![0],
            "every new return must replay to the registered caller"
        );
    }
    assert!(
        contexts
            .complete_node_return(context, NodeId((count - 1) as u32))
            .is_empty(),
        "duplicate returns must remain deduplicated after spilling"
    );

    let first = contexts.returned_node_batch(context, None);
    assert_eq!(first.len(), CONTEXT_REPLAY_BATCH_ENTRIES);
    let cursor = (u128::from(context) << 96) | u128::from(first.last().expect("first page").0);
    let second = contexts.returned_node_batch(context, Some(cursor));
    assert_eq!(
        second,
        vec![
            NodeId(count as u32 - 3),
            NodeId(count as u32 - 2),
            NodeId(count as u32 - 1)
        ]
    );
}

#[test]
fn symbolic_call_provenance_uses_ast_argument_and_formal_slots() {
    let call_span = span(0, 20, 40);
    let mut caller_decl = empty_decl(1, 0, "caller");
    caller_decl.params = vec!["box".to_string()];
    caller_decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "forward".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 28, 31),
            name: None,
            value_text: "box".to_string(),
            place: Some("box".to_string()),
            source_names: vec!["box".to_string()],
        }],
    }];
    let mut callee_decl = empty_decl(2, 1, "forward");
    callee_decl.params = vec!["payload".to_string()];
    let global = build_index(vec![caller_decl, callee_decl]);
    let caller = func_id(&global, "caller");
    let callee = func_id(&global, "forward");

    let mut graph = SymbolicFieldGraph::new();
    let source = graph.intern_base(crate::workspace::SegmentId(0), caller, "box");
    let target = graph.intern_base(crate::workspace::SegmentId(1), callee, "payload");
    let transform = SymbolicFieldTransform {
        source,
        target,
        exact_field: NO_SYMBOLIC_STRING,
        call_span,
        write_span: call_span,
        precision: Precision::Exact,
        call_kind: EdgeKind::Direct,
        kind: SymbolicFieldTransformKind::Argument,
        arg_idx: 0,
        param_idx: 0,
        allow_out_of_order_source: false,
    };
    let (arg_idx, param_idx) = symbolic_cross_call_slots(&transform);

    assert_eq!(arg_idx, 0);
    assert_eq!(param_idx, 0);
    assert_eq!(
        symbolic_cross_call_relation(transform.kind),
        Some(CrossCallRelation::Argument)
    );
}

fn payload_map_flow() -> bonsai_lang_api::ExpressionFlow {
    bonsai_lang_api::ExpressionFlow {
        aggregate_fields: vec![
            bonsai_lang_api::ExpressionField {
                name: "cmd".to_string(),
                value_span: None,
                value: bonsai_lang_api::ExpressionFlow::from_place("payload.cmd"),
            },
            bonsai_lang_api::ExpressionField {
                name: "user".to_string(),
                value_span: None,
                value: bonsai_lang_api::ExpressionFlow::from_place("payload.user"),
            },
        ],
        ..Default::default()
    }
}

fn empty_decl(symbol: u32, file: u32, name: &str) -> Decl {
    Decl {
        symbol: SymbolId::new(symbol),
        kind: DeclKind::Function,
        name: name.to_string(),
        qualified_name: None,
        module_path: ModulePath::default(),
        span: span(file, 0, 100),
        name_span: span(file, 0, 10),
        visibility: Visibility::Public,
        parent: None,
        body_span: Some(span(file, 10, 100)),
        flow_events: Vec::new(),
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn build_index(decls: Vec<Decl>) -> GlobalIndex {
    let mut by_file: AHashMap<bonsai_common::FileId, Vec<Decl>> = AHashMap::new();
    for d in decls {
        by_file.entry(d.span.file).or_default().push(d);
    }
    let mut idx = GlobalIndex::new();
    for (file, defs) in by_file {
        idx.insert(DeclIndex {
            file,
            defs,
            ..DeclIndex::default()
        });
    }
    idx
}

fn func_id(idx: &GlobalIndex, name: &str) -> FuncId {
    for file in idx.all_files() {
        for decl in idx.functions_in(file) {
            if decl.name == name {
                return FuncId::new(decl.symbol.raw());
            }
        }
    }
    unreachable!("function {name} not in index")
}

fn func_id_at_start(idx: &GlobalIndex, name: &str, start: u64) -> FuncId {
    for file in idx.all_files() {
        for decl in idx.functions_in(file) {
            if decl.name == name && decl.span.start == start {
                return FuncId::new(decl.symbol.raw());
            }
        }
    }
    unreachable!("function {name}@{start} not in index")
}

fn resolved_graph(edges: impl IntoIterator<Item = (FuncId, FuncId, Span)>) -> ResolvedCallGraph {
    let mut cg = CallGraph::new();
    for (from, to, span) in edges {
        cg.add_edge(CallEdge {
            from,
            to,
            span,
            kind: EdgeKind::Direct,
            precision: Precision::Narrowed,
            provenance: EdgeProvenance::direct_symbol(),
        });
    }
    ResolvedCallGraph::from_call_graph(cg)
}

fn build(decls: Vec<Decl>) -> (Arc<GlobalIndex>, Arc<IdgWorkspace>) {
    let idx = build_index(decls);
    let cg = ResolvedCallGraph::default();
    let ws = workspace_adapter::build(&idx, &cg);
    (Arc::new(idx), Arc::new(ws))
}

fn build_with_edges(
    decls: Vec<Decl>,
    edges: impl FnOnce(&GlobalIndex) -> Vec<(FuncId, FuncId, Span)>,
) -> (Arc<GlobalIndex>, Arc<IdgWorkspace>) {
    let idx = build_index(decls);
    let cg = resolved_graph(edges(&idx));
    let ws = workspace_adapter::build(&idx, &cg);
    (Arc::new(idx), Arc::new(ws))
}

#[test]
fn empty_service_has_zero_segments() {
    let idx = Arc::new(GlobalIndex::new());
    let ws = Arc::new(IdgWorkspace::new());
    let svc = IdgQueryService::new(ws, idx);
    assert_eq!(svc.segment_count(), 0);
    assert_eq!(svc.intra_edge_count(), 0);
    assert_eq!(svc.cross_file_edge_count(), 0);
}

#[test]
fn compact_function_node_lookup_is_exact_for_non_monotonic_node_insertion() {
    let func = FuncId::new(7);
    let mut segment = crate::segment::IdgSegment::new();
    let param_zero = segment.intern_place(Place::Param { idx: 0 });
    let return_place = segment.intern_place(Place::Return);
    let param_one = segment.intern_place(Place::Param { idx: 1 });

    // Deliberately intern nodes in a different order from their PlaceIds.
    // Warm query lookup must derive ordering from compiler identities, not
    // assume an adapter happened to emit nodes monotonically.
    let return_node = segment.intern_node(func, return_place);
    let param_one_node = segment.intern_node(func, param_one);
    let param_zero_node = segment.intern_node(func, param_zero);
    segment.record_func(func);

    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));

    assert_eq!(
        service.param_nodes_of(func),
        vec![WsNodeId(param_zero_node.0), WsNodeId(param_one_node.0)]
    );
    assert_eq!(service.return_node_of(func), Some(WsNodeId(return_node.0)));
}

#[test]
fn persisted_query_accelerator_restores_exact_narrowed_runtime() {
    let func = FuncId::new(7);
    let mut segment = crate::segment::IdgSegment::new();
    let param_place = segment.intern_place(Place::Param { idx: 0 });
    let return_place = segment.intern_place(Place::Return);
    let param = segment.intern_node(func, param_place);
    let returned = segment.intern_node(func, return_place);
    segment.add_edge(IdgEdge::intra_assign(param, returned, span(0, 1, 2)));
    segment.record_func(func);

    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let workspace = Arc::new(workspace);
    let compiler = IdgQueryService::new(Arc::clone(&workspace), Arc::new(GlobalIndex::new()));
    let payload = compiler
        .compile_default_query_accelerator()
        .expect("compile query accelerator");
    let mut workspace = Arc::try_unwrap(workspace).expect("compiler released workspace");
    workspace.install_query_accelerator(payload);

    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("accelerated-idg.factstore");
    workspace
        .save_to_disk(&sidecar, 0xA11C_E1A7)
        .expect("save accelerated sidecar");
    assert_eq!(
        IdgWorkspace::validate_accelerated_sidecar_layout_with_pipeline(&sidecar, 0xA11C_E1A7,)
            .expect("accelerated layout"),
        1
    );
    let loaded = IdgQueryService::load_from_disk(&sidecar, 0xA11C_E1A7, Arc::new(GlobalIndex::new()))
        .expect("load accelerated sidecar")
        .expect("current accelerated sidecar");

    assert!(
        loaded.unified.read().is_some(),
        "a warm service must install the validated compiler index during open"
    );
    assert!(
        loaded
            .unified
            .read()
            .as_ref()
            .and_then(|unified| unified.symbolic_runtime.get())
            .is_none(),
        "opening a semantic generation must keep the independently decodable symbolic runtime lazy"
    );
    let params = loaded.param_nodes_of(func);
    let return_node = loaded.return_node_of(func).expect("return node");
    assert_eq!(params, vec![WsNodeId(param.0)]);
    assert!(loaded.forward_closure(&params).contains(&return_node));
    {
        let unified = loaded.unified.read();
        let contextual = unified
            .as_ref()
            .expect("warm unified address space")
            .contextual_summaries
            .read();
        assert!(matches!(
            contextual
                .get(&Some(Precision::Narrowed))
                .map(|runtime| &runtime.reach),
            Some(ContextualReach::Paged { .. })
        ));
    }
    assert!(
        loaded
            .unified
            .read()
            .as_ref()
            .and_then(|unified| unified.symbolic_runtime.get())
            .is_some(),
        "the first unscoped closure must hydrate the exact persisted symbolic runtime"
    );
    let allowed = AHashSet::from([func]);
    assert!(loaded
        .forward_closure_within_funcs_with_max_precision(&params, &allowed, Some(Precision::Narrowed),)
        .contains(&return_node));
    let relevance =
        loaded.target_relevance_with_max_precision(&[return_node], None, Some(Precision::Narrowed));
    assert!(relevance.admits_any(&params));
    assert!(
        loaded.scoped_contextual_summary.lock().is_none(),
        "a dense warm scope should reuse the validated global representation"
    );
    assert!(
        loaded.scoped_symbolic_runtime.lock().is_none(),
        "a warm scope must page the validated global symbolic representation"
    );
}

#[test]
fn persisted_query_accelerator_accepts_source_oriented_return_evidence() {
    let caller = FuncId::new(7);
    let callee = FuncId::new(8);
    let unrelated_caller = FuncId::new(9);
    let call_span = span(0, 20, 30);
    let unrelated_span = span(0, 31, 39);
    let mut segment = crate::segment::IdgSegment::new();
    let caller_arg_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(call_span),
        idx: 0,
    });
    let caller_ret_place = segment.intern_place(Place::CallRet {
        site: crate::place::CallSiteId(call_span),
    });
    let callee_param_place = segment.intern_place(Place::Param { idx: 0 });
    let callee_return_place = segment.intern_place(Place::Return);
    let unrelated_arg_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(unrelated_span),
        idx: 0,
    });
    let caller_arg = segment.intern_node(caller, caller_arg_place);
    let caller_ret = segment.intern_node(caller, caller_ret_place);
    let callee_param = segment.intern_node(callee, callee_param_place);
    let callee_return = segment.intern_node(callee, callee_return_place);
    let unrelated_arg = segment.intern_node(unrelated_caller, unrelated_arg_place);
    segment.add_edge(IdgEdge::intra_assign(
        callee_param,
        callee_return,
        span(0, 40, 50),
    ));
    segment.add_edge(IdgEdge::inter_call_arg(
        caller_arg,
        callee_param,
        call_span,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.add_edge(IdgEdge::inter_return(
        callee_return,
        caller_ret,
        call_span,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.add_edge(IdgEdge::inter_call_arg(
        unrelated_arg,
        callee_param,
        unrelated_span,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.record_func(caller);
    segment.record_func(callee);
    segment.record_func(unrelated_caller);

    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let workspace = Arc::new(workspace);
    let compiler = IdgQueryService::new(Arc::clone(&workspace), Arc::new(GlobalIndex::new()));
    let payload = compiler
        .compile_default_query_accelerator()
        .expect("compile query accelerator");
    let mut workspace = Arc::try_unwrap(workspace).expect("compiler released workspace");
    workspace.install_query_accelerator(payload);

    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("call-return-accelerated-idg.factstore");
    workspace
        .save_to_disk(&sidecar, 0xCA11_AB1E)
        .expect("save accelerated sidecar");
    let loaded = IdgQueryService::load_from_disk(&sidecar, 0xCA11_AB1E, Arc::new(GlobalIndex::new()))
        .expect("load accelerated sidecar")
        .expect("current accelerated sidecar");
    let evidence = loaded.semantic_cross_call_edges_with_max_precision(Some(Precision::Narrowed));
    assert!(evidence.iter().any(|edge| {
        edge.relation == CrossCallRelation::Return
            && edge.caller == callee
            && edge.callee == caller
            && edge.call_span == call_span
    }));
    let allowed: AHashSet<_> = [caller, callee, unrelated_caller].into_iter().collect();
    let relevance = loaded.target_relevance_from_source_within_funcs_with_max_precision(
        caller,
        &[WsNodeId(caller_ret.0)],
        None,
        &allowed,
        Some(Precision::Narrowed),
    );
    assert!(
        relevance.admits_any(&[WsNodeId(caller_arg.0)]),
        "source-rooted reverse return must activate the exact callee and return through its matching argument"
    );
    assert!(
        !relevance.admits_any(&[WsNodeId(unrelated_arg.0)]),
        "a shared callee must not pull an unrelated caller into a source-rooted target proof"
    );

    let unrooted = loaded.forward_closure_evidence_within_funcs_with_max_precision(
        &[WsNodeId(callee_param.0)],
        &allowed,
        Some(Precision::Narrowed),
    );
    assert!(
        unrooted.nodes.contains(&WsNodeId(caller_ret.0)),
        "a rule-matched source in a helper may flow into each resolved caller"
    );
    let rooted = loaded
        .forward_closure_evidence_rooted_at_func_within_funcs_and_relevance_with_max_precision(
            &[WsNodeId(callee_param.0)],
            callee,
            &allowed,
            None,
            Some(Precision::Narrowed),
        );
    assert!(rooted.nodes.contains(&WsNodeId(callee_return.0)));
    assert!(
        !rooted.nodes.contains(&WsNodeId(caller_ret.0)),
        "an entry-rooted query must not escape into an unrelated caller"
    );
    assert_eq!(
        loaded.rooted_scalar_target_precheck_with_max_precision(
            &[WsNodeId(caller_arg.0)],
            caller,
            &[WsNodeId(caller_ret.0)],
            Some(Precision::Narrowed),
        ),
        Some(true),
        "contextual scalar summaries must preserve exact callee-return reachability"
    );
    assert_eq!(
        loaded.rooted_scalar_target_precheck_with_max_precision(
            &[WsNodeId(caller_ret.0)],
            caller,
            &[WsNodeId(caller_arg.0)],
            Some(Precision::Narrowed),
        ),
        Some(false),
        "the scalar summary precheck must provide an exact negative proof"
    );
}

#[test]
fn malformed_query_accelerator_is_rejected() {
    let mut workspace = IdgWorkspace::new();
    let mut segment = crate::segment::IdgSegment::new();
    segment.record_func(FuncId::new(1));
    workspace.register_segment(segment);
    let frame = |payload: &[u8]| {
        let mut file = tempfile::tempfile().expect("accelerator frame");
        file.write_all(payload).expect("write accelerator frame");
        file.seek(SeekFrom::Start(0)).expect("rewind accelerator frame");
        crate::workspace::CompiledQueryAcceleratorFrame {
            file: Arc::new(file),
            bytes: payload.len() as u64,
        }
    };
    workspace.install_query_accelerator(crate::workspace::CompiledQueryAccelerator {
        core: frame(&[0xC1, 0x00]),
        contextual: frame(&[]),
        symbolic_header: frame(&[]),
        blobs: Arc::from(Vec::new().into_boxed_slice()),
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("bad-accelerator.factstore");
    workspace
        .save_to_disk(&sidecar, 0xBAD0_0A81)
        .expect("save malformed accelerator fixture");
    assert!(IdgQueryService::load_from_disk(&sidecar, 0xBAD0_0A81, Arc::new(GlobalIndex::new()),).is_err());
}

#[test]
fn symbolic_argument_transform_reaches_exact_callee_field_without_expanded_edges() {
    let caller = FuncId::new(1);
    let middle = FuncId::new(2);
    let callee = FuncId::new(3);
    let scalar_middle = FuncId::new(4);
    let scalar_sink = FuncId::new(5);
    let mut caller_segment = crate::segment::IdgSegment::new();
    let box_name = caller_segment.strings.intern("box");
    let live_name = caller_segment.strings.intern("live");
    let unrelated_name = caller_segment.strings.intern("unrelated");
    let param_place = caller_segment.intern_place(Place::Param { idx: 0 });
    let unrelated_param_place = caller_segment.intern_place(Place::Param { idx: 1 });
    let field_write_place = caller_segment.intern_place(Place::Write {
        name: box_name,
        path: smallvec::smallvec![live_name],
        span: span(0, 10, 11),
    });
    let unrelated_write_place = caller_segment.intern_place(Place::Write {
        name: box_name,
        path: smallvec::smallvec![unrelated_name],
        span: span(0, 12, 13),
    });
    let param_node = caller_segment.intern_node(caller, param_place);
    let unrelated_param_node = caller_segment.intern_node(caller, unrelated_param_place);
    let field_write = caller_segment.intern_node(caller, field_write_place);
    let unrelated_write = caller_segment.intern_node(caller, unrelated_write_place);
    caller_segment.add_edge(IdgEdge::intra_assign(param_node, field_write, span(0, 10, 11)));
    caller_segment.add_edge(IdgEdge::intra_assign(
        unrelated_param_node,
        unrelated_write,
        span(0, 12, 13),
    ));
    caller_segment.record_func(caller);

    let mut middle_segment = crate::segment::IdgSegment::new();
    middle_segment.record_func(middle);

    let mut callee_segment = crate::segment::IdgSegment::new();
    let arg_name = callee_segment.strings.intern("arg");
    let live_name = callee_segment.strings.intern("live");
    let field_read_place = callee_segment.intern_place(Place::Read {
        name: arg_name,
        path: smallvec::smallvec![live_name],
    });
    let return_place = callee_segment.intern_place(Place::Return);
    let field_read = callee_segment.intern_node(callee, field_read_place);
    let return_node = callee_segment.intern_node(callee, return_place);
    callee_segment.add_edge(IdgEdge::intra_assign(field_read, return_node, span(1, 30, 31)));
    callee_segment.record_func(callee);

    // These owners deliberately contain no projected storage.  A generic
    // suffix-preserving transform relation may pass a scalar through them,
    // but it must not invent `scalar.live` merely because `box.live` exists
    // elsewhere in the program.
    let mut scalar_middle_segment = crate::segment::IdgSegment::new();
    scalar_middle_segment.record_func(scalar_middle);
    let mut scalar_sink_segment = crate::segment::IdgSegment::new();
    scalar_sink_segment.record_func(scalar_sink);

    let mut workspace = IdgWorkspace::new();
    let caller_segment_id = workspace.register_segment(caller_segment);
    let middle_segment_id = workspace.register_segment(middle_segment);
    let callee_segment_id = workspace.register_segment(callee_segment);
    let scalar_middle_segment_id = workspace.register_segment(scalar_middle_segment);
    let scalar_sink_segment_id = workspace.register_segment(scalar_sink_segment);
    let mut symbolic = SymbolicFieldGraph::new();
    let source = symbolic.intern_base(caller_segment_id, caller, "box");
    let middle_input = symbolic.intern_base(middle_segment_id, middle, "arg");
    let target = symbolic.intern_base(callee_segment_id, callee, "arg");
    let scalar_input = symbolic.intern_base(scalar_middle_segment_id, scalar_middle, "value");
    let scalar_output = symbolic.intern_base(scalar_sink_segment_id, scalar_sink, "value");
    symbolic.push_transform(SymbolicFieldTransform {
        source,
        target: middle_input,
        exact_field: NO_SYMBOLIC_STRING,
        call_span: span(0, 20, 25),
        write_span: span(0, 20, 25),
        precision: Precision::Exact,
        call_kind: EdgeKind::Direct,
        kind: SymbolicFieldTransformKind::Argument,
        arg_idx: 0,
        param_idx: 0,
        allow_out_of_order_source: false,
    });
    symbolic.push_transform(SymbolicFieldTransform {
        source: middle_input,
        target,
        exact_field: NO_SYMBOLIC_STRING,
        call_span: span(0, 26, 29),
        write_span: span(0, 26, 29),
        precision: Precision::Exact,
        call_kind: EdgeKind::Direct,
        kind: SymbolicFieldTransformKind::Argument,
        arg_idx: 0,
        param_idx: 0,
        allow_out_of_order_source: false,
    });
    symbolic.push_transform(SymbolicFieldTransform {
        source,
        target: scalar_input,
        exact_field: NO_SYMBOLIC_STRING,
        call_span: span(0, 32, 35),
        write_span: span(0, 32, 35),
        precision: Precision::Exact,
        call_kind: EdgeKind::Direct,
        kind: SymbolicFieldTransformKind::Argument,
        arg_idx: 0,
        param_idx: 0,
        allow_out_of_order_source: false,
    });
    symbolic.push_transform(SymbolicFieldTransform {
        source: scalar_input,
        target: scalar_output,
        exact_field: NO_SYMBOLIC_STRING,
        call_span: span(0, 36, 39),
        write_span: span(0, 36, 39),
        precision: Precision::Exact,
        call_kind: EdgeKind::Direct,
        kind: SymbolicFieldTransformKind::Argument,
        arg_idx: 0,
        param_idx: 0,
        allow_out_of_order_source: false,
    });
    workspace.set_symbolic_field(symbolic);

    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));
    let params = service.param_nodes_of(caller);
    let evidence =
        service.forward_closure_evidence_with_max_precision(&[params[0]], Some(Precision::Narrowed));
    let reached: AHashSet<WsNodeId> = service.forward_closure(&[params[0]]).into_iter().collect();
    let unrelated_reached: AHashSet<WsNodeId> = service.forward_closure(&[params[1]]).into_iter().collect();
    let callee_return = service.return_node_of(callee).expect("callee return");
    assert!(
        reached.contains(&callee_return),
        "symbolic access-path transforms must reach arg.live through both wrappers without physical cross-field edges"
    );
    assert!(
        !unrelated_reached.contains(&callee_return),
        "symbolic access paths must not promote the unrelated sibling field"
    );
    assert_eq!(
        evidence
            .cross_calls
            .iter()
            .map(|edge| (edge.caller, edge.callee, edge.relation))
            .collect::<Vec<_>>(),
        vec![
            (caller, middle, CrossCallRelation::Argument),
            (middle, callee, CrossCallRelation::Argument),
        ],
        "closure evidence must preserve every fired AST access-path boundary in dataflow order"
    );

    let allowed_funcs: AHashSet<FuncId> = [caller, middle].into_iter().collect();
    let scoped = service.forward_closure_evidence_within_funcs_with_max_precision(
        &[params[0]],
        &allowed_funcs,
        Some(Precision::Narrowed),
    );
    assert!(
        !scoped.nodes.contains(&callee_return),
        "a compiler-proven function scope must reject symbolic transforms into unrelated functions"
    );
    assert_eq!(
        scoped
            .cross_calls
            .iter()
            .map(|edge| (edge.caller, edge.callee))
            .collect::<Vec<_>>(),
        vec![(caller, middle)],
        "provenance must contain exactly the admitted symbolic call boundaries"
    );
    assert!(
        service
            .forward_target_nodes_cut_within_funcs_with_max_precision(
                &[params[0]],
                &[callee_return],
                &allowed_funcs,
                Some(Precision::Narrowed),
            )
            .is_empty(),
        "a target outside the compiler-proven scope must not admit the broader graph"
    );

    let all_funcs: AHashSet<FuncId> = [caller, middle, callee].into_iter().collect();
    let relevance =
        service.target_relevance_with_max_precision(&[callee_return], None, Some(Precision::Narrowed));
    assert!(
        relevance.admits_any(&[params[0]]),
        "backward relevance must retain the AST-derived symbolic target path"
    );
    assert!(
        !relevance.admits_any(&[params[1]]),
        "backward relevance must reject an unrelated sibling-field seed"
    );
    assert_eq!(
        service.funcs_admitted_by_target_relevance(
            &[FuncId::new(u32::MAX), caller, middle, callee],
            &relevance,
        ),
        vec![caller, callee],
        "source prefiltering must preserve input order and every function that owns a relevant seed node"
    );
    let relevant = service.forward_closure_evidence_within_funcs_and_relevance_with_max_precision(
        &[params[0]],
        &all_funcs,
        &relevance,
        Some(Precision::Narrowed),
    );
    assert!(relevant.nodes.contains(&callee_return));
    assert_eq!(
        relevant
            .cross_calls
            .iter()
            .map(|edge| (edge.caller, edge.callee, edge.relation))
            .collect::<Vec<_>>(),
        evidence
            .cross_calls
            .iter()
            .map(|edge| (edge.caller, edge.callee, edge.relation))
            .collect::<Vec<_>>(),
        "target pruning must preserve every realized symbolic boundary on the target path"
    );

    let corridor_funcs: AHashSet<FuncId> = [caller, middle].into_iter().collect();
    let corridor_relevance = service.target_relevance_within_funcs_with_max_precision(
        &[callee_return],
        None,
        &corridor_funcs,
        Some(Precision::Narrowed),
    );
    assert!(
        !corridor_relevance.admits_any(&[params[0]]),
        "a target outside the compiler corridor must not contribute demand to that corridor"
    );
}

#[test]
fn symbolic_read_consumption_preserves_write_order_for_earlier_copies() {
    let func = FuncId::new(1);
    let mut segment = crate::segment::IdgSegment::new();
    let object = segment.strings.intern("object");
    let earlier = segment.strings.intern("earlier");
    let field = segment.strings.intern("field");
    let param = segment.intern_place(Place::Param { idx: 0 });
    let later_write = segment.intern_place(Place::Write {
        name: object,
        path: smallvec::smallvec![field],
        span: span(0, 20, 21),
    });
    let object_read = segment.intern_place(Place::Read {
        name: object,
        path: smallvec::smallvec![field],
    });
    let earlier_read = segment.intern_place(Place::Read {
        name: earlier,
        path: smallvec::smallvec![field],
    });
    let return_place = segment.intern_place(Place::Return);
    let param = segment.intern_node(func, param);
    let later_write = segment.intern_node(func, later_write);
    let _object_read = segment.intern_node(func, object_read);
    let earlier_read = segment.intern_node(func, earlier_read);
    let return_node = segment.intern_node(func, return_place);
    segment.add_edge(IdgEdge::intra_assign(param, later_write, span(0, 20, 21)));
    segment.add_edge(IdgEdge::intra_assign(earlier_read, return_node, span(0, 12, 13)));
    segment.record_func(func);

    let mut workspace = IdgWorkspace::new();
    let segment_id = workspace.register_segment(segment);
    let mut symbolic = SymbolicFieldGraph::new();
    let source = symbolic.intern_base(segment_id, func, "object");
    let target = symbolic.intern_base(segment_id, func, "earlier");
    symbolic.push_transform(SymbolicFieldTransform {
        source,
        target,
        exact_field: NO_SYMBOLIC_STRING,
        call_span: span(0, 10, 11),
        write_span: span(0, 10, 11),
        precision: Precision::Exact,
        call_kind: EdgeKind::Direct,
        kind: SymbolicFieldTransformKind::Copy,
        arg_idx: u32::MAX,
        param_idx: u32::MAX,
        allow_out_of_order_source: false,
    });
    workspace.set_symbolic_field(symbolic);

    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));
    let reached: AHashSet<_> = service
        .forward_closure(&[service.param_nodes_of(func)[0]])
        .into_iter()
        .collect();
    assert!(
        !reached.contains(&WsNodeId(return_node.0)),
        "consuming the later object.field fact at its shared read must not \
         erase provenance and flow backward through the earlier aggregate copy"
    );
}

#[test]
fn target_relevance_reverses_exact_scalar_field_returns() {
    let callee = FuncId::new(4);
    let caller = FuncId::new(5);
    let callee_write_span = span(0, 10, 20);
    let unrelated_write_span = span(0, 21, 30);
    let call_span = span(1, 40, 55);
    let caller_write_span = span(1, 56, 62);

    let mut callee_segment = crate::segment::IdgSegment::new();
    let object = callee_segment.strings.intern("object");
    let selected = callee_segment.strings.intern("selected");
    let unrelated = callee_segment.strings.intern("unrelated");
    let selected_param = callee_segment.intern_place(Place::Param { idx: 0 });
    let unrelated_param = callee_segment.intern_place(Place::Param { idx: 1 });
    let selected_write = callee_segment.intern_place(Place::Write {
        name: object,
        path: smallvec::smallvec![selected],
        span: callee_write_span,
    });
    let unrelated_write = callee_segment.intern_place(Place::Write {
        name: object,
        path: smallvec::smallvec![unrelated],
        span: unrelated_write_span,
    });
    let selected_param = callee_segment.intern_node(callee, selected_param);
    let unrelated_param = callee_segment.intern_node(callee, unrelated_param);
    let selected_write = callee_segment.intern_node(callee, selected_write);
    let unrelated_write = callee_segment.intern_node(callee, unrelated_write);
    callee_segment.add_edge(IdgEdge::intra_assign(
        selected_param,
        selected_write,
        callee_write_span,
    ));
    callee_segment.add_edge(IdgEdge::intra_assign(
        unrelated_param,
        unrelated_write,
        unrelated_write_span,
    ));
    callee_segment.record_func(callee);

    let mut caller_segment = crate::segment::IdgSegment::new();
    let result = caller_segment.strings.intern("result");
    let result_write = caller_segment.intern_place(Place::Write {
        name: result,
        path: smallvec::smallvec![],
        span: caller_write_span,
    });
    let return_place = caller_segment.intern_place(Place::Return);
    let result_write = caller_segment.intern_node(caller, result_write);
    let return_node = caller_segment.intern_node(caller, return_place);
    caller_segment.add_edge(IdgEdge::intra_assign(
        result_write,
        return_node,
        caller_write_span,
    ));
    caller_segment.record_func(caller);

    let mut workspace = IdgWorkspace::new();
    let callee_segment_id = workspace.register_segment(callee_segment);
    let caller_segment_id = workspace.register_segment(caller_segment);
    let mut symbolic = SymbolicFieldGraph::new();
    let source = symbolic.intern_base(callee_segment_id, callee, "object");
    let target = symbolic.intern_base(caller_segment_id, caller, "result");
    let exact_field = symbolic.intern_string("selected");
    symbolic.push_transform(SymbolicFieldTransform {
        source,
        target,
        exact_field,
        call_span,
        write_span: caller_write_span,
        precision: Precision::Exact,
        call_kind: EdgeKind::Direct,
        kind: SymbolicFieldTransformKind::ScalarReturn,
        arg_idx: u32::MAX,
        param_idx: u32::MAX,
        allow_out_of_order_source: false,
    });
    workspace.set_symbolic_field(symbolic);

    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));
    let params = service.param_nodes_of(callee);
    let target = service.return_node_of(caller).expect("caller return");
    let allowed_funcs: AHashSet<FuncId> = [callee, caller].into_iter().collect();
    let relevance = service.target_relevance_with_max_precision(&[target], None, Some(Precision::Narrowed));
    assert!(relevance.admits_any(&[params[0]]));
    assert!(
        !relevance.admits_any(&[params[1]]),
        "the inverse scalar-return relation must retain only the exact consumed suffix"
    );
    let evidence = service.forward_closure_evidence_within_funcs_and_relevance_with_max_precision(
        &[params[0]],
        &allowed_funcs,
        &relevance,
        Some(Precision::Narrowed),
    );
    assert!(evidence.nodes.contains(&target));
    assert_eq!(evidence.cross_calls.len(), 1);
    assert_eq!(evidence.cross_calls[0].relation, CrossCallRelation::Return);
}

#[test]
fn target_relevance_keeps_scalar_seeds_for_unmodeled_projected_places() {
    let func = FuncId::new(18);
    let mut segment = crate::segment::IdgSegment::new();
    let object = segment.strings.intern("object");
    let field = segment.strings.intern("field");
    let param_place = segment.intern_place(Place::Param { idx: 0 });
    let projected_place = segment.intern_place(Place::Read {
        name: object,
        path: smallvec::smallvec![field],
    });
    let param = segment.intern_node(func, param_place);
    let projected = segment.intern_node(func, projected_place);
    segment.record_func(func);

    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));
    let relevance = service.target_relevance_with_max_precision(
        &[WsNodeId(projected.0)],
        None,
        Some(Precision::Narrowed),
    );

    assert!(
        !relevance.pruning_complete,
        "a projected place without symbolic access-path facts must mark the backward relation incomplete"
    );
    assert!(
        relevance.admits_any(&[WsNodeId(param.0)]),
        "a projected place without an exact symbolic fact must not let the backward pruning proof reject a scalar receiver seed"
    );
}

#[test]
fn unified_address_space_is_lazily_built() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, idx);
    // Trigger materialisation.
    let params = svc.param_nodes_of(FuncId::new(0));
    assert!(!params.is_empty());
}

#[test]
fn param_node_enumeration_includes_positions_above_u8_range() {
    let mut decl = empty_decl(1, 0, "wide");
    decl.params = (0..300).map(|idx| format!("p{idx}")).collect();
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let func = func_id(&idx, "wide");
    let params = svc.param_nodes_of(func);
    assert_eq!(params.len(), 300);
    let point = svc.resolve_point(params[299]).expect("param 299 point");
    assert_eq!(point.kind, PointKind::Param);
    assert_eq!(point.name, "p299");
}

#[test]
fn compiler_return_summary_preserves_positions_above_u8_range() {
    let mut decl = empty_decl(1, 0, "wide_return");
    decl.params = (0..300).map(|idx| format!("p{idx}")).collect();
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 30),
        value_name: Some("p299".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("p299"),
    }];
    let (idx, ws) = build(vec![decl]);
    let func = func_id(&idx, "wide_return");
    let service = IdgQueryService::new(ws, idx);
    let summaries =
        service.return_taint_param_indices_for_funcs_with_max_precision(&[func], Some(Precision::Narrowed));
    assert_eq!(summaries.get(&func), Some(&vec![299]));
}

#[test]
fn forward_closure_from_param_reaches_return() {
    // f(x) returns x — closure of param node should hit Return.
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, idx);
    let func_id = FuncId::new(0);
    let params = svc.param_nodes_of(func_id);
    assert_eq!(params.len(), 1);
    let ret = svc
        .return_node_of(func_id)
        .expect("Return node should exist for callable");
    let closure = svc.forward_closure(&params);
    assert!(closure.contains(&ret), "Param→Return closure missing Return");
}

#[test]
fn template_interpolation_param_reaches_return() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["bio".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 80),
        value_name: None,
        value_text: Some("`<div class=\"bio\">${bio}</div>`".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec!["bio".to_string()]),
    }];
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, idx.clone());
    let f = func_id(&idx, "f");
    let params = svc.param_nodes_for_names(f, &["bio".to_string()], idx.as_ref());
    assert_eq!(params.len(), 1);
    let ret = svc
        .return_node_of(f)
        .expect("Return node should exist for callable");
    let closure = svc.forward_closure(&params);
    assert!(
        closure.contains(&ret),
        "template interpolation Param→Return closure missing Return"
    );
}

#[test]
fn forward_closure_with_max_precision_prunes_worse_edges() {
    let func = FuncId::new(7);
    let mut seg = crate::segment::IdgSegment::new();
    let p0 = seg.intern_place(Place::Param { idx: 0 });
    let p1 = seg.intern_place(Place::Write {
        name: 1,
        path: Default::default(),
        span: span(0, 10, 20),
    });
    let p2 = seg.intern_place(Place::Return);
    let n0 = seg.intern_node(func, p0);
    let n1 = seg.intern_node(func, p1);
    let n2 = seg.intern_node(func, p2);
    seg.add_edge(IdgEdge::intra_assign(n0, n1, span(0, 10, 20)));
    seg.add_edge(IdgEdge::new(
        n1,
        n2,
        crate::edge::EdgeMeta {
            precision: Precision::OverApproximate,
            kind: crate::edge::IdgEdgeKind::IntraAssign,
            call_kind: bonsai_callgraph::EdgeKind::Indirect,
            via_span: span(0, 20, 30),
        },
    ));
    seg.record_func(func);
    let mut ws = IdgWorkspace::new();
    ws.register_segment(seg);
    let svc = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));

    let seed = svc.param_nodes_of(func);
    let default = svc.forward_closure(&seed);
    let full = svc.forward_closure_with_max_precision(&seed, None);
    let strict = svc.forward_closure_with_max_precision(&seed, Some(Precision::Narrowed));
    let ret = svc.return_node_of(func).unwrap();
    assert!(!default.contains(&ret), "default closure must be semantic-only");
    assert!(
        full.contains(&ret),
        "explicit diagnostic closure should traverse every edge"
    );
    assert!(
        !strict.contains(&ret),
        "strict closure must not traverse an over-approximate edge"
    );
}

#[test]
fn target_node_cut_accepts_exact_unresolved_aggregate_argument_evidence() {
    let func = FuncId::new(8);
    let call_span = span(0, 40, 55);
    let mut segment = crate::segment::IdgSegment::new();
    let opts = segment.strings.intern("opts");
    let to = segment.strings.intern("to");
    let param_place = segment.intern_place(Place::Param { idx: 0 });
    let field_write_place = segment.intern_place(Place::Write {
        name: opts,
        path: smallvec::smallvec![to],
        span: span(0, 20, 30),
    });
    let call_arg_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(call_span),
        idx: 0,
    });
    let param = segment.intern_node(func, param_place);
    let field_write = segment.intern_node(func, field_write_place);
    let call_arg = segment.intern_node(func, call_arg_place);
    segment.add_edge(IdgEdge::intra_assign(param, field_write, span(0, 20, 30)));
    segment.add_edge(IdgEdge::new(
        field_write,
        call_arg,
        crate::edge::EdgeMeta {
            precision: Precision::Exact,
            kind: crate::edge::IdgEdgeKind::IntraAggregateConsume,
            call_kind: EdgeKind::Direct,
            via_span: call_span,
        },
    ));
    segment.record_func(func);
    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));

    let seeds = service.param_nodes_of(func);
    let target_nodes = service.nodes_at_span(func, call_span);
    assert_eq!(
        target_nodes
            .iter()
            .filter_map(|node| service.call_arg_identity(*node))
            .collect::<Vec<_>>(),
        vec![(func, call_span, 0)],
        "call-argument identity must come from the unified compiler index"
    );
    let allowed_funcs: AHashSet<FuncId> = [func].into_iter().collect();
    let scoped_relevance = service.target_relevance_within_funcs_with_max_precision(
        &target_nodes,
        None,
        &allowed_funcs,
        Some(Precision::Narrowed),
    );
    let scoped = service.forward_closure_within_funcs_and_relevance_with_max_precision(
        &seeds,
        &allowed_funcs,
        &scoped_relevance,
        Some(Precision::Narrowed),
    );
    assert_eq!(
        service.tainted_call_args_in_reachable_nodes_for_funcs(&scoped, Some(&allowed_funcs)),
        vec![(func, call_span, 0)],
        "scoped aggregate evidence must render without reopening a global runtime"
    );
    assert!(
        service.ensure_unified().symbolic_runtime.get().is_none(),
        "a target-scoped call projection must reuse its scoped compiler runtime"
    );
    let scalar = service.forward_closure(&seeds);
    assert!(
        target_nodes.iter().all(|target| !scalar.contains(target)),
        "aggregate-consumption evidence must not become scalar reachability"
    );
    let cut =
        service.forward_target_nodes_cut_with_max_precision(&seeds, &target_nodes, Some(Precision::Narrowed));
    assert_eq!(
        cut, scalar,
        "the exact argument evidence must satisfy the target cut"
    );
    assert_eq!(
        service.tainted_call_args_in_reachable_nodes(&cut),
        vec![(func, call_span, 0)]
    );
    let relevance =
        service.target_relevance_with_max_precision(&target_nodes, None, Some(Precision::Narrowed));
    assert!(
        relevance.admits_any(&seeds),
        "aggregate-consumption targets must reverse to their exact scalar inputs"
    );
    let relevant = service.forward_closure_within_funcs_and_relevance_with_max_precision(
        &seeds,
        &allowed_funcs,
        &relevance,
        Some(Precision::Narrowed),
    );
    assert_eq!(relevant, scalar);
    assert_eq!(
        service.tainted_call_args_in_reachable_nodes(&relevant),
        vec![(func, call_span, 0)]
    );
}

#[test]
fn batched_span_targets_match_scalar_lookup_and_report_unresolved_fallbacks() {
    let func = FuncId::new(8);
    let call_span = span(0, 40, 55);
    let missing_span = span(0, 90, 95);
    let mut segment = crate::segment::IdgSegment::new();
    let call_arg_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(call_span),
        idx: 0,
    });
    segment.intern_node(func, call_arg_place);
    segment.record_func(func);
    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));

    let scalar = service.nodes_at_span(func, call_span);
    let (batched, unresolved) = service.nodes_and_unresolved_funcs_at_spans(&[
        (func, call_span),
        (func, call_span),
        (func, missing_span),
    ]);

    assert_eq!(
        batched, scalar,
        "batch lookup must preserve exact AST endpoint identity"
    );
    assert_eq!(
        unresolved,
        [func].into_iter().collect(),
        "one unrepresented target span keeps its owning function as a conservative fallback"
    );
}

#[test]
fn target_relevance_starts_sparse_until_relation_density_requires_promotion() {
    let worklist = TargetRelevanceWorklist::new(10_000_000);
    assert!(matches!(
        worklist.relevance.nodes,
        RootClosureVisited::Sparse { ref reached, node_count: 10_000_000 } if reached.is_empty()
    ));
}

#[test]
fn within_function_closure_excludes_reachable_callee_nodes() {
    let caller = FuncId::new(7);
    let callee = FuncId::new(8);
    let mut caller_seg = crate::segment::IdgSegment::new();
    let caller_param = caller_seg.intern_place(Place::Param { idx: 0 });
    let caller_write = caller_seg.intern_place(Place::Write {
        name: 1,
        path: Default::default(),
        span: span(0, 10, 20),
    });
    let caller_param_node = caller_seg.intern_node(caller, caller_param);
    let caller_write_node = caller_seg.intern_node(caller, caller_write);
    caller_seg.add_edge(IdgEdge::intra_assign(
        caller_param_node,
        caller_write_node,
        span(0, 10, 20),
    ));
    caller_seg.record_func(caller);

    let mut callee_seg = crate::segment::IdgSegment::new();
    let callee_param = callee_seg.intern_place(Place::Param { idx: 0 });
    let callee_param_node = callee_seg.intern_node(callee, callee_param);
    callee_seg.record_func(callee);

    let mut ws = IdgWorkspace::new();
    let caller_segment = ws.register_segment(caller_seg);
    let callee_segment = ws.register_segment(callee_seg);
    ws.cross_file_mut().push(crate::workspace::CrossFileEdge {
        from_segment: caller_segment,
        to_segment: callee_segment,
        edge: IdgEdge::inter_call_arg(
            caller_write_node,
            callee_param_node,
            span(0, 20, 30),
            Precision::Exact,
            bonsai_callgraph::EdgeKind::Direct,
        ),
    });
    let svc = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let seed = svc.param_nodes_of(caller);

    let global = svc.forward_closure_with_max_precision(&seed, Some(Precision::Narrowed));
    let allowed_funcs: AHashSet<FuncId> = [caller].into_iter().collect();
    let local =
        svc.forward_closure_within_funcs_with_max_precision(&seed, &allowed_funcs, Some(Precision::Narrowed));
    assert_eq!(global.len(), 3);
    assert_eq!(local.len(), 2);
    assert!(local
        .iter()
        .all(|node| svc.resolve_point(*node).is_some_and(|point| point.func == caller)));
    assert!(
        svc.scoped_contextual_summary.lock().is_none(),
        "an already-compiled global contextual relation is filtered by the exact function scope instead of duplicated"
    );
    assert!(
        svc.scoped_symbolic_runtime.lock().is_none(),
        "an already-compiled global symbolic relation is filtered by the exact function scope instead of duplicated"
    );

    let all_funcs: AHashSet<FuncId> = [caller, callee].into_iter().collect();
    assert_eq!(
        svc.cross_call_edges_in_reachable_nodes_filtered_with_max_precision(
            &global,
            Some(Precision::Narrowed),
            Some(&all_funcs),
        ),
        svc.cross_call_edges_in_reachable_nodes_with_max_precision(&global, Some(Precision::Narrowed),),
        "demand-decoded scoped cross-call evidence must equal the canonical global evidence"
    );
    let scoped_calls = svc.scoped_cross_calls.lock();
    let scoped_calls = scoped_calls
        .as_ref()
        .expect("function-scoped evidence caches its exact cross-call index");
    assert_eq!(scoped_calls.funcs.as_ref(), &[caller, callee]);

    let targets: AHashSet<FuncId> = [callee].into_iter().collect();
    assert_eq!(
        svc.semantic_function_corridor_with_max_precision(&[caller], &targets, Some(Precision::Narrowed),),
        [caller, callee].into_iter().collect(),
        "the numeric semantic corridor must retain the complete caller-to-callee path"
    );
}

#[test]
fn cross_call_edges_in_closure_with_max_precision_prunes_worse_edges() {
    let caller = FuncId::new(7);
    let callee = FuncId::new(8);
    let call_span = span(0, 20, 30);
    let mut seg = crate::segment::IdgSegment::new();
    let call_arg = seg.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(call_span),
        idx: 0,
    });
    let callee_param = seg.intern_place(Place::Param { idx: 0 });
    let call_arg_node = seg.intern_node(caller, call_arg);
    let callee_param_node = seg.intern_node(callee, callee_param);
    seg.add_edge(IdgEdge::inter_call_arg(
        call_arg_node,
        callee_param_node,
        call_span,
        Precision::OverApproximate,
        bonsai_callgraph::EdgeKind::Indirect,
    ));
    seg.record_func(caller);
    seg.record_func(callee);
    let mut ws = IdgWorkspace::new();
    ws.register_segment(seg);
    let svc = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let unified = svc.ensure_unified();
    let seed = IdgQueryService::ws_node_for(&unified, SegmentId(0), call_arg_node)
        .expect("call-arg node should be addressable");

    let default = svc.cross_call_edges_in_closure(&[seed]);
    let full = svc.cross_call_edges_in_closure_with_max_precision(&[seed], None);
    let semantic = svc.cross_call_edges_in_closure_with_max_precision(&[seed], Some(Precision::Narrowed));

    assert!(
        default.is_empty(),
        "default closure must not expose an over-approximate propagation edge"
    );
    assert_eq!(
        full.len(),
        1,
        "explicit diagnostic closure should expose the diagnostic edge"
    );
    assert!(
        semantic.is_empty(),
        "semantic closure must not expose an over-approximate propagation edge"
    );
}

#[test]
fn backward_closure_from_return_reaches_param() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, idx);
    let func_id = FuncId::new(0);
    let params = svc.param_nodes_of(func_id);
    let ret = svc.return_node_of(func_id).unwrap();
    let backward = svc.backward_closure(&[ret]);
    for p in &params {
        assert!(backward.contains(p), "backward(Return) missing param");
    }
}

#[test]
fn compiler_return_summaries_compose_calls_and_mutual_recursion() {
    let f = FuncId::new(70);
    let g = FuncId::new(71);
    let f_calls_g = span(0, 20, 30);
    let g_calls_f = span(0, 50, 60);
    let mut segment = crate::segment::IdgSegment::new();

    let f_param_place = segment.intern_place(Place::Param { idx: 0 });
    let f_arg_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(f_calls_g),
        idx: 0,
    });
    let f_call_ret_place = segment.intern_place(Place::CallRet {
        site: crate::place::CallSiteId(f_calls_g),
    });
    let return_place = segment.intern_place(Place::Return);
    let f_param = segment.intern_node(f, f_param_place);
    let f_arg = segment.intern_node(f, f_arg_place);
    let f_call_ret = segment.intern_node(f, f_call_ret_place);
    let f_return = segment.intern_node(f, return_place);

    let g_param_place = segment.intern_place(Place::Param { idx: 0 });
    let g_arg_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(g_calls_f),
        idx: 0,
    });
    let g_call_ret_place = segment.intern_place(Place::CallRet {
        site: crate::place::CallSiteId(g_calls_f),
    });
    let g_param = segment.intern_node(g, g_param_place);
    let g_arg = segment.intern_node(g, g_arg_place);
    let g_call_ret = segment.intern_node(g, g_call_ret_place);
    let g_return = segment.intern_node(g, return_place);

    segment.add_edge(IdgEdge::intra_assign(f_param, f_arg, f_calls_g));
    segment.add_edge(IdgEdge::intra_assign(f_call_ret, f_return, f_calls_g));
    segment.add_edge(IdgEdge::inter_call_arg(
        f_arg,
        g_param,
        f_calls_g,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.add_edge(IdgEdge::inter_return(
        g_return,
        f_call_ret,
        f_calls_g,
        Precision::Exact,
        EdgeKind::Direct,
    ));

    segment.add_edge(IdgEdge::intra_assign(g_param, g_arg, g_calls_f));
    segment.add_edge(IdgEdge::intra_assign(g_call_ret, g_return, g_calls_f));
    segment.add_edge(IdgEdge::inter_call_arg(
        g_arg,
        f_param,
        g_calls_f,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.add_edge(IdgEdge::inter_return(
        f_return,
        g_call_ret,
        g_calls_f,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    // The concrete base arm in g seeds the mutually-recursive fixed point.
    segment.add_edge(IdgEdge::intra_assign(g_param, g_return, span(0, 70, 80)));
    segment.record_func(f);
    segment.record_func(g);

    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));
    let only_f = AHashSet::from_iter([f]);
    let narrow = service.return_taint_param_indices_for_funcs_within_funcs_with_max_precision(
        &[f],
        &only_f,
        Some(Precision::Narrowed),
    );
    assert_eq!(
        narrow.get(&f),
        Some(&Vec::new()),
        "excluding the recursive callee changes only this explicit compiler scope"
    );
    assert!(
        service.return_summaries.lock().is_empty(),
        "a scoped negative must never populate the canonical global cache"
    );
    let full_scope = AHashSet::from_iter([f, g]);
    let unified = service.ensure_unified();
    let contextual =
        service.ensure_contextual_summary_runtime(&unified, Some(Precision::Narrowed), Some(&full_scope));
    let compiled_batch = Arc::clone(
        &service
            .scoped_contextual_summary
            .lock()
            .as_ref()
            .expect("full scoped compiler batch")
            .batch,
    );
    let scoped = service.return_taint_param_indices_for_funcs_within_funcs_with_max_precision(
        &[f, g],
        &full_scope,
        Some(Precision::Narrowed),
    );
    assert_eq!(scoped.get(&f), Some(&vec![0]));
    assert_eq!(scoped.get(&g), Some(&vec![0]));
    let contextual_after =
        service.ensure_contextual_summary_runtime(&unified, Some(Precision::Narrowed), Some(&full_scope));
    let cached_after = service.scoped_contextual_summary.lock();
    let cached_after = cached_after.as_ref().expect("reused scoped compiler batch");
    assert!(Arc::ptr_eq(&contextual, &contextual_after));
    assert!(
        Arc::ptr_eq(&compiled_batch, &cached_after.batch),
        "return attribution must reuse the target-cut compiler batch"
    );
    let summaries =
        service.return_taint_param_indices_for_funcs_with_max_precision(&[f, g], Some(Precision::Narrowed));

    assert_eq!(summaries.get(&f), Some(&vec![0]));
    assert_eq!(summaries.get(&g), Some(&vec![0]));
    let cached = service
        .return_summaries
        .lock()
        .get(&Some(Precision::Narrowed))
        .map(|cache| cache.covered.clone())
        .expect("precision cache");
    assert_eq!(cached, AHashSet::from_iter([f, g]));
    assert_eq!(
        service
            .return_taint_param_indices_for_funcs_with_max_precision(&[f], Some(Precision::Narrowed))
            .get(&f),
        Some(&vec![0]),
        "single-function consumers must reuse the prewarmed compiler summary"
    );
}

#[test]
fn compiler_return_summaries_respect_the_precision_scope() {
    let func = FuncId::new(72);
    let mut segment = crate::segment::IdgSegment::new();
    let param_place = segment.intern_place(Place::Param { idx: 0 });
    let return_place = segment.intern_place(Place::Return);
    let param = segment.intern_node(func, param_place);
    let ret = segment.intern_node(func, return_place);
    segment.add_edge(IdgEdge::new(
        param,
        ret,
        crate::edge::EdgeMeta {
            precision: Precision::OverApproximate,
            kind: crate::edge::IdgEdgeKind::IntraReturn,
            call_kind: EdgeKind::Indirect,
            via_span: span(0, 20, 30),
        },
    ));
    segment.record_func(func);
    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));

    let semantic =
        service.return_taint_param_indices_for_funcs_with_max_precision(&[func], Some(Precision::Narrowed));
    let diagnostic = service.return_taint_param_indices_for_funcs_with_max_precision(&[func], None);
    assert!(semantic.get(&func).is_some_and(Vec::is_empty));
    assert_eq!(diagnostic.get(&func), Some(&vec![0]));
}

#[test]
fn symbolic_return_summary_matches_the_originating_call_site() {
    let caller = FuncId::new(75);
    let callee = FuncId::new(76);
    let first_call = span(0, 30, 40);
    let second_call = span(0, 50, 60);
    let mut segment = crate::segment::IdgSegment::new();
    let first_base = segment.strings.intern("first");
    let second_base = segment.strings.intern("second");
    let live_field = segment.strings.intern("live");
    let dead_field = segment.strings.intern("dead");
    let callee_base = segment.strings.intern("arg");
    let caller_param_0 = segment.intern_place(Place::Param { idx: 0 });
    let caller_param_1 = segment.intern_place(Place::Param { idx: 1 });
    let caller_param_2 = segment.intern_place(Place::Param { idx: 2 });
    let first_write = segment.intern_place(Place::Write {
        name: first_base,
        path: smallvec::smallvec![live_field],
        span: span(0, 10, 20),
    });
    let second_live_write = segment.intern_place(Place::Write {
        name: second_base,
        path: smallvec::smallvec![live_field],
        span: span(0, 20, 30),
    });
    let second_dead_write = segment.intern_place(Place::Write {
        name: second_base,
        path: smallvec::smallvec![dead_field],
        span: span(0, 21, 29),
    });
    let first_ret = segment.intern_place(Place::CallRet {
        site: crate::place::CallSiteId(first_call),
    });
    let second_ret = segment.intern_place(Place::CallRet {
        site: crate::place::CallSiteId(second_call),
    });
    let caller_return = segment.intern_place(Place::Return);
    let callee_read = segment.intern_place(Place::Read {
        name: callee_base,
        path: smallvec::smallvec![live_field],
    });
    let callee_return = segment.intern_place(Place::Return);

    let caller_param_0 = segment.intern_node(caller, caller_param_0);
    let caller_param_1 = segment.intern_node(caller, caller_param_1);
    let caller_param_2 = segment.intern_node(caller, caller_param_2);
    let first_write = segment.intern_node(caller, first_write);
    let second_live_write = segment.intern_node(caller, second_live_write);
    let second_dead_write = segment.intern_node(caller, second_dead_write);
    let first_ret = segment.intern_node(caller, first_ret);
    let second_ret = segment.intern_node(caller, second_ret);
    let caller_return = segment.intern_node(caller, caller_return);
    let callee_read = segment.intern_node(callee, callee_read);
    let callee_return = segment.intern_node(callee, callee_return);

    segment.add_edge(IdgEdge::intra_assign(
        caller_param_0,
        first_write,
        span(0, 10, 20),
    ));
    segment.add_edge(IdgEdge::intra_assign(
        caller_param_1,
        second_live_write,
        span(0, 20, 30),
    ));
    segment.add_edge(IdgEdge::intra_assign(
        caller_param_2,
        first_write,
        span(0, 10, 20),
    ));
    segment.add_edge(IdgEdge::intra_assign(
        caller_param_2,
        second_dead_write,
        span(0, 21, 29),
    ));
    segment.add_edge(IdgEdge::intra_assign(second_ret, caller_return, second_call));
    segment.add_edge(IdgEdge::intra_assign(callee_read, callee_return, span(0, 70, 80)));
    segment.add_edge(IdgEdge::inter_return(
        callee_return,
        first_ret,
        first_call,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.add_edge(IdgEdge::inter_return(
        callee_return,
        second_ret,
        second_call,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.record_func(caller);
    segment.record_func(callee);

    let mut workspace = IdgWorkspace::new();
    let segment_id = workspace.register_segment(segment);
    let mut symbolic = SymbolicFieldGraph::new();
    let first = symbolic.intern_base(segment_id, caller, "first");
    let second = symbolic.intern_base(segment_id, caller, "second");
    let arg = symbolic.intern_base(segment_id, callee, "arg");
    for (source, call_span) in [(first, first_call), (second, second_call)] {
        symbolic.push_transform(SymbolicFieldTransform {
            source,
            target: arg,
            exact_field: NO_SYMBOLIC_STRING,
            call_span,
            write_span: call_span,
            precision: Precision::Exact,
            call_kind: EdgeKind::Direct,
            kind: SymbolicFieldTransformKind::Argument,
            arg_idx: 0,
            param_idx: 0,
            allow_out_of_order_source: false,
        });
    }
    workspace.set_symbolic_field(symbolic);
    let sidecar_dir = tempfile::tempdir().expect("tempdir");
    let sidecar = sidecar_dir.path().join("symbolic-context.factstore");
    workspace
        .save_to_disk(&sidecar, 0x51DE_CAFE)
        .expect("save symbolic query sidecar");
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));
    let summaries =
        service.return_taint_param_indices_for_funcs_with_max_precision(&[caller], Some(Precision::Narrowed));

    assert_eq!(
        summaries.get(&caller),
        Some(&vec![1]),
        "only the live field entering the returned call may reach the caller return"
    );
    let params = service.param_nodes_of(caller);
    let caller_return = service.return_node_of(caller).expect("caller return");
    let first_closure: AHashSet<_> = service.forward_closure(&[params[0]]).into_iter().collect();
    let second_closure: AHashSet<_> = service.forward_closure(&[params[1]]).into_iter().collect();
    let mixed_closure: AHashSet<_> = service.forward_closure(&[params[2]]).into_iter().collect();
    assert!(
        !first_closure.contains(&caller_return),
        "ordinary forward closure must keep symbolic call/return boundaries matched"
    );
    assert!(second_closure.contains(&caller_return));
    assert!(
        !mixed_closure.contains(&caller_return),
        "a live field in the first call must not combine with a dead field that activates the returned call"
    );

    let paged = IdgWorkspace::load_query_from_disk(&sidecar, 0x51DE_CAFE)
        .expect("open symbolic query sidecar")
        .expect("current symbolic query sidecar");
    let paged = IdgQueryService::new(Arc::new(paged), Arc::new(GlobalIndex::new()));
    let paged_summaries =
        paged.return_taint_param_indices_for_funcs_with_max_precision(&[caller], Some(Precision::Narrowed));
    assert_eq!(paged_summaries.get(&caller), Some(&vec![1]));
    let paged_params = paged.param_nodes_of(caller);
    let paged_return = paged.return_node_of(caller).expect("paged caller return");
    assert!(!paged.forward_closure(&[paged_params[0]]).contains(&paged_return));
    assert!(paged.forward_closure(&[paged_params[1]]).contains(&paged_return));
    assert!(!paged.forward_closure(&[paged_params[2]]).contains(&paged_return));
}

#[test]
fn local_storage_summaries_never_absorb_callee_storage() {
    let caller = FuncId::new(73);
    let callee = FuncId::new(74);
    let call_span = span(0, 30, 40);
    let mut segment = crate::segment::IdgSegment::new();
    let before_name = segment.strings.intern("before");
    let deep_name = segment.strings.intern("deep");
    let caller_param_place = segment.intern_place(Place::Param { idx: 0 });
    let before_place = segment.intern_place(Place::Write {
        name: before_name,
        path: Default::default(),
        span: span(0, 10, 20),
    });
    let call_arg_place = segment.intern_place(Place::CallArg {
        site: crate::place::CallSiteId(call_span),
        idx: 0,
    });
    let callee_param_place = segment.intern_place(Place::Param { idx: 0 });
    let deep_place = segment.intern_place(Place::Write {
        name: deep_name,
        path: Default::default(),
        span: span(0, 50, 60),
    });
    let caller_param = segment.intern_node(caller, caller_param_place);
    let before = segment.intern_node(caller, before_place);
    let call_arg = segment.intern_node(caller, call_arg_place);
    let callee_param = segment.intern_node(callee, callee_param_place);
    let deep = segment.intern_node(callee, deep_place);
    segment.add_edge(IdgEdge::intra_assign(caller_param, before, span(0, 10, 20)));
    segment.add_edge(IdgEdge::intra_assign(before, call_arg, call_span));
    segment.add_edge(IdgEdge::inter_call_arg(
        call_arg,
        callee_param,
        call_span,
        Precision::Exact,
        EdgeKind::Direct,
    ));
    segment.add_edge(IdgEdge::intra_assign(callee_param, deep, span(0, 50, 60)));
    segment.record_func(caller);
    segment.record_func(callee);
    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    let service = IdgQueryService::new(Arc::new(workspace), Arc::new(GlobalIndex::new()));

    let summaries = service.local_storage_taint_by_param_for_funcs_with_max_precision(
        &[caller, callee],
        Some(Precision::Narrowed),
    );
    assert_eq!(summaries.get(&caller), Some(&vec![vec!["before".to_string()]]));
    assert_eq!(summaries.get(&callee), Some(&vec![vec!["deep".to_string()]]));
}

#[test]
fn reaches_is_consistent_with_forward_closure() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, idx);
    let func_id = FuncId::new(0);
    let params = svc.param_nodes_of(func_id);
    let ret = svc.return_node_of(func_id).unwrap();
    for p in &params {
        assert!(svc.reaches(*p, ret));
    }
}

#[test]
fn resolve_point_returns_param_for_param_node() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["arg0".to_string(), "arg1".to_string()];
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, idx);
    let func_id = FuncId::new(0);
    let params = svc.param_nodes_of(func_id);
    assert_eq!(params.len(), 2);
    let p0 = svc.resolve_point(params[0]).unwrap();
    assert_eq!(p0.kind, PointKind::Param);
    // Names match the decl's params.
    assert_eq!(p0.func, func_id);
    assert!(p0.name == "arg0" || p0.name == "arg1");
}

#[test]
fn read_or_write_nodes_for_names_locates_local_assign_target() {
    // f(x) does `local = x; helper(local)`. Looking up "local"
    // should find both the Write node from the assign and the
    // Read node from the call arg — both interned in the segment
    // string pool.
    let mut f = empty_decl(1, 0, "f");
    f.params = vec!["x".to_string()];
    f.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "local".to_string(),
            source_name: Some("x".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(0, 30, 40),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 33, 38),
                name: None,
                value_text: "local".to_string(),
                place: Some("local".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];
    let (idx, ws) = build(vec![f]);
    let svc = IdgQueryService::new(ws, idx);
    let func_for = |name: &str| {
        for f in svc.global.all_files() {
            for decl in svc.global.functions_in(f) {
                if decl.name == name {
                    return FuncId::new(decl.symbol.raw());
                }
            }
        }
        unreachable!("function {name} not in index")
    };
    let f_id = func_for("f");
    let nodes = svc.read_or_write_nodes_for_names(f_id, &["local".to_string()]);
    assert!(!nodes.is_empty(), "should locate IDG nodes for `local`");
}

#[test]
fn reachable_name_lookup_preserves_exact_projected_writes() {
    let mut f = empty_decl(1, 0, "set_header");
    f.params = vec!["response".to_string(), "user_input".to_string()];
    f.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "cd".to_string(),
            source_name: Some("user_input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user_input".to_string()],
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 30, 50),
            target: "response.headers.Content-Disposition".to_string(),
            source_name: Some("cd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["cd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 60, 70),
            target: "response.headers.Location".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
        },
    ];
    let (idx, ws) = build(vec![f]);
    let func = func_id(&idx, "set_header");
    let service = IdgQueryService::new(ws, idx.clone());
    let seeds = service.param_nodes_for_names(func, &["user_input".to_string()], idx.as_ref());
    let closure: AHashSet<_> = service.forward_closure(&seeds).into_iter().collect();
    let names = service.read_or_write_names_in_reachable_nodes(func, &closure);

    assert!(names.contains("cd"));
    assert!(names.contains("response.headers.Content-Disposition"));
    assert!(
        !names.contains("response.headers.Location"),
        "exact projected lookup must not taint sibling header fields"
    );

    let inventory = service.read_or_write_names_of_func(func);
    assert!(inventory.contains("cd"));
    assert!(inventory.contains("user_input"));
    assert!(inventory.contains("response.headers.Content-Disposition"));
    assert!(inventory.contains("response.headers.Location"));
    assert!(
        !inventory.contains("response"),
        "projected IDG places must remain exact instead of inventing a bare container: {inventory:?}"
    );
}

#[test]
fn source_seed_span_fallback_does_not_cross_functions_in_same_segment() {
    let f = empty_decl(1, 0, "f");
    let mut g = empty_decl(2, 0, "g");
    g.flow_events = vec![FlowEvent::Call {
        span: span(0, 30, 40),
        name: "helper".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 35, 39),
            name: None,
            value_text: "other".to_string(),
            place: Some("other".to_string()),
            source_names: vec!["other".to_string()],
        }],
    }];
    let (idx, ws) = build(vec![f, g]);
    let svc = IdgQueryService::new(ws, idx);

    let nodes = svc.source_seed_nodes_at_span(func_id(&svc.global, "f"), span(0, 32, 36));
    assert!(
        nodes.is_empty(),
        "fallback seed lookup for f must not return g's same-file read nodes"
    );
}

#[test]
fn read_or_write_nodes_for_names_maps_wildcard_seed_to_projected_read_only() {
    let mut f = empty_decl(1, 0, "f");
    f.params = vec!["args".to_string()];
    f.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 40),
        name: "search".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 27, 33),
            name: None,
            value_text: "args.q".to_string(),
            place: Some("args.q".to_string()),
            source_names: vec!["args.q".to_string(), "args".to_string()],
        }],
    }];
    let (idx, ws) = build(vec![f]);
    let f_id = func_id(&idx, "f");
    let svc = IdgQueryService::new(ws, idx);

    let wildcard_nodes = svc.read_or_write_nodes_for_names(f_id, &["args.*".to_string()]);
    assert!(
        !wildcard_nodes.is_empty(),
        "wildcard container seed should locate projected `args.q` reads"
    );

    let exact_nodes = svc.read_or_write_nodes_for_names(f_id, &["args.q".to_string()]);
    assert!(
        !exact_nodes.is_empty(),
        "exact projected seed should locate the matching read"
    );

    let sibling_nodes = svc.read_or_write_nodes_for_names(f_id, &["user.*".to_string()]);
    assert!(
        sibling_nodes.is_empty(),
        "wildcard seed must not match sibling containers"
    );
}

#[test]
fn read_or_write_nodes_for_names_maps_dotted_wildcard_seed_to_projected_read() {
    let mut f = empty_decl(1, 0, "f");
    f.params = vec!["req".to_string()];
    f.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 60),
        name: "setHeader".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![
            bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 30, 45),
                name: None,
                value_text: "req.query.theme".to_string(),
                place: Some("req.query.theme".to_string()),
                source_names: vec!["req.query.theme".to_string(), "req.query".to_string()],
            },
            bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 46, 55),
                name: None,
                value_text: "req.body.theme".to_string(),
                place: Some("req.body.theme".to_string()),
                source_names: vec!["req.body.theme".to_string(), "req.body".to_string()],
            },
        ],
    }];
    let (idx, ws) = build(vec![f]);
    let f_id = func_id(&idx, "f");
    let svc = IdgQueryService::new(ws, idx);

    let wildcard_nodes = svc.read_or_write_nodes_for_names(f_id, &["req.query.*".to_string()]);
    assert!(
        !wildcard_nodes.is_empty(),
        "dotted wildcard seed should locate projected `req.query.theme` reads"
    );

    let sibling_nodes = svc.read_or_write_nodes_for_names(f_id, &["req.session.*".to_string()]);
    assert!(
        sibling_nodes.is_empty(),
        "dotted wildcard seed must not match sibling request containers"
    );
}

#[test]
fn nodes_for_name_after_span_resolves_projected_output_arg_carrier() {
    let mut f = empty_decl(1, 0, "f");
    f.flow_events = vec![
        FlowEvent::Call {
            span: span(0, 20, 30),
            name: "copy".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![
                bonsai_lang_api::CallArg {
                    passing_mode: Default::default(),
                    span: span(0, 25, 32),
                    name: None,
                    value_text: "env.cmd".to_string(),
                    place: Some("env.cmd".to_string()),
                    source_names: vec!["env.cmd".to_string(), "env".to_string()],
                },
                bonsai_lang_api::CallArg {
                    passing_mode: Default::default(),
                    span: span(0, 34, 37),
                    name: None,
                    value_text: "raw".to_string(),
                    place: Some("raw".to_string()),
                    source_names: vec!["raw".to_string()],
                },
            ],
        },
        FlowEvent::Call {
            span: span(0, 50, 60),
            name: "strlen".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 57, 64),
                name: None,
                value_text: "env.cmd".to_string(),
                place: Some("env.cmd".to_string()),
                source_names: vec!["env.cmd".to_string(), "env".to_string()],
            }],
        },
    ];
    let (idx, ws) = build(vec![f]);
    let f_id = func_id(&idx, "f");
    let svc = IdgQueryService::new(ws, idx);

    let nodes = svc.nodes_for_name_after_span(f_id, "env.cmd", span(0, 20, 30));
    assert!(
        !nodes.is_empty(),
        "projected output-arg transfer must be able to seed `env.cmd` nodes"
    );
    assert!(
        nodes
            .iter()
            .filter_map(|node| svc.resolve_point(*node))
            .any(|point| point.kind == PointKind::Write && point.name == "env.cmd"),
        "configured output arg should create a precise field write node, got {nodes:?}"
    );
}

#[test]
fn cross_call_edges_in_closure_reports_callarg_to_param() {
    let mut f = empty_decl(1, 0, "f");
    f.params = vec!["x".to_string()];
    f.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 30),
        name: "g".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 22, 23),
            name: None,
            value_text: "x".to_string(),
            place: Some("x".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut g = empty_decl(2, 1, "g");
    g.params = vec!["arg".to_string()];
    g.flow_events = Vec::new();
    let (idx, ws) = build_with_edges(vec![f, g], |idx| {
        vec![(func_id(idx, "f"), func_id(idx, "g"), span(0, 20, 30))]
    });
    let svc = IdgQueryService::new(ws, idx);
    let func_for = |name: &str| {
        for f in svc.global.all_files() {
            for decl in svc.global.functions_in(f) {
                if decl.name == name {
                    return FuncId::new(decl.symbol.raw());
                }
            }
        }
        unreachable!("function {name} not in index")
    };
    let f_id = func_for("f");
    let g_id = func_for("g");
    let f_params = svc.param_nodes_of(f_id);
    let edges = svc.cross_call_edges_in_closure(&f_params);
    assert!(
        edges.iter().any(|e| {
            e.caller == f_id
                && e.callee == g_id
                && e.arg_idx == 0
                && e.param_idx == 0
                && e.relation == crate::service::CrossCallRelation::Argument
        }),
        "expected one CallArg→Param edge for f→g, got {edges:?}",
    );
}

#[test]
fn cross_call_edges_skip_unreachable_calls() {
    // Closure starting from a node unrelated to any call site
    // returns an empty list — proves the closure filter is wired.
    let mut f = empty_decl(1, 0, "f");
    f.params = vec!["x".to_string()];
    let (idx, ws) = build(vec![f]);
    let svc = IdgQueryService::new(ws, idx);
    let edges = svc.cross_call_edges_in_closure(&[]);
    assert!(edges.is_empty());
}

#[test]
fn cross_file_call_reaches_callee_from_caller_param() {
    // f(x) calls g(x); g returns its arg. Closure of f's param
    // should reach g's Return, then funnel back to f's CallRet
    // node — proving cross-file edges are queryable.
    let mut f = empty_decl(1, 0, "f");
    f.params = vec!["x".to_string()];
    f.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 30),
        name: "g".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 22, 23),
            name: None,
            value_text: "x".to_string(),
            place: Some("x".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut g = empty_decl(2, 1, "g");
    g.params = vec!["arg".to_string()];
    g.flow_events = vec![FlowEvent::Return {
        span: span(1, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("arg"),
    }];
    let (idx, ws) = build_with_edges(vec![f, g], |idx| {
        vec![(func_id(idx, "f"), func_id(idx, "g"), span(0, 20, 30))]
    });
    let svc = IdgQueryService::new(ws, idx);

    // GlobalIndex remaps symbols on insert. The first inserted
    // file's first function gets FuncId 0, but order depends on
    // hash-map iteration. Use the per-name lookup instead.
    let func_for = |name: &str| {
        for f in svc.global.all_files() {
            for decl in svc.global.functions_in(f) {
                if decl.name == name {
                    return FuncId::new(decl.symbol.raw());
                }
            }
        }
        unreachable!("function {name} not in index")
    };
    let f_id = func_for("f");
    let g_id = func_for("g");

    let f_params = svc.param_nodes_of(f_id);
    let g_return = svc.return_node_of(g_id).unwrap();
    let closure = svc.forward_closure(&f_params);
    assert!(
        closure.contains(&g_return),
        "f's param closure should reach g's Return via CallArg→Param→…→Return"
    );
}

#[test]
fn field_argument_forwarding_preserves_sibling_fields_through_passthrough_calls() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["user".to_string(), "cmd".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "payload.user".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(0, 21, 30),
            target: "payload.cmd".to_string(),
            source_name: Some("cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(0, 40, 50),
            name: "middle".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 43, 49),
                name: None,
                value_text: "payload".to_string(),
                place: Some("payload".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut middle = empty_decl(2, 1, "middle");
    middle.params = vec!["envelope".to_string()];
    middle.flow_events = vec![FlowEvent::Call {
        span: span(1, 60, 70),
        name: "run".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(1, 64, 68),
            name: None,
            value_text: "envelope".to_string(),
            place: Some("envelope".to_string()),
            source_names: Vec::new(),
        }],
    }];

    let mut run = empty_decl(3, 2, "run");
    run.params = vec!["data".to_string()];
    run.flow_events = vec![
        FlowEvent::Assign {
            span: span(2, 80, 90),
            target: "seen".to_string(),
            source_name: Some("data.user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(2, 100, 110),
            name: "sink_user".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(2, 105, 109),
                name: None,
                value_text: "seen".to_string(),
                place: Some("seen".to_string()),
                source_names: Vec::new(),
            }],
        },
        FlowEvent::Assign {
            span: span(2, 120, 130),
            target: "out".to_string(),
            source_name: Some("data.cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(2, 140, 150),
            name: "sink_cmd".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(2, 144, 148),
                name: None,
                value_text: "out".to_string(),
                place: Some("out".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let (idx, ws) = build_with_edges(vec![entry, middle, run], |idx| {
        vec![
            (func_id(idx, "entry"), func_id(idx, "middle"), span(0, 40, 50)),
            (func_id(idx, "middle"), func_id(idx, "run"), span(1, 60, 70)),
        ]
    });
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");
    let user_seed = svc.param_nodes_for_names(entry_id, &["user".to_string()], &idx);
    let cmd_seed = svc.param_nodes_for_names(entry_id, &["cmd".to_string()], &idx);

    let user_calls = svc.tainted_call_args_in_closure(&user_seed);
    assert!(
        user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 100, 110) && *idx == 0),
        "user field should reach only the matching sink_user arg: {user_calls:?}"
    );
    assert!(
        !user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 140, 150) && *idx == 0),
        "user field must not taint sibling cmd sink: {user_calls:?}"
    );

    let cmd_calls = svc.tainted_call_args_in_closure(&cmd_seed);
    assert!(
        cmd_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 140, 150) && *idx == 0),
        "cmd field should reach only the matching sink_cmd arg: {cmd_calls:?}"
    );
    assert!(
        !cmd_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 100, 110) && *idx == 0),
        "cmd field must not taint sibling user sink: {cmd_calls:?}"
    );

    let cross_calls = svc.cross_call_edges_in_closure(&cmd_seed);
    assert!(
        cross_calls.iter().any(|edge| {
            edge.call_span == span(1, 60, 70)
                && edge.relation == crate::service::CrossCallRelation::Argument
                && edge.relation.is_renderable_call()
        }),
        "a projected value crossing a resolved AST call must retain renderable argument provenance: {cross_calls:?}"
    );
}

#[test]
fn sibling_field_taint_does_not_promote_container_argument_to_sink() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["user".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 1, 9),
            target: "raw".to_string(),
            source_name: None,
            source_call: Some("source".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: span(0, 10, 80),
            target: "env".to_string(),
            source_name: None,
            source_call: Some("len".to_string()),
            source_call_args: vec!["raw".to_string()],
            source_names: vec![
                "Cmd".to_string(),
                "User".to_string(),
                "raw".to_string(),
                "user".to_string(),
            ],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: span(0, 10, 80),
            target: "env.Cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 10, 80),
            target: "env.User".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 90, 100),
            name: "orchestrate".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 94, 97),
                name: None,
                value_text: "&env".to_string(),
                place: Some("&env".to_string()),
                source_names: vec!["env".to_string()],
            }],
        },
    ];

    let mut orchestrate = empty_decl(2, 1, "orchestrate");
    orchestrate.params = vec!["env".to_string()];
    orchestrate.flow_events = vec![
        FlowEvent::Assign {
            span: span(1, 110, 120),
            target: "cmd".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["env".to_string(), "env.Cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(1, 121, 130),
            target: "user".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["env".to_string(), "env.User".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(1, 140, 210),
            target: "valid".to_string(),
            source_name: None,
            source_call: Some("len".to_string()),
            source_call_args: vec!["cmd".to_string()],
            source_names: vec![
                "Cmd".to_string(),
                "User".to_string(),
                "cmd".to_string(),
                "user".to_string(),
            ],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: span(1, 140, 210),
            target: "valid.Cmd".to_string(),
            source_name: Some("cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(1, 140, 210),
            target: "valid.User".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(1, 220, 230),
            name: "persist".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 224, 229),
                name: None,
                value_text: "valid".to_string(),
                place: Some("valid".to_string()),
                source_names: vec!["valid".to_string()],
            }],
        },
    ];

    let mut persist = empty_decl(3, 2, "persist");
    persist.params = vec!["data".to_string()];
    persist.flow_events = vec![
        FlowEvent::Assign {
            span: span(2, 240, 250),
            target: "c".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["data".to_string(), "data.Cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(2, 260, 270),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(2, 264, 265),
                name: None,
                value_text: "c".to_string(),
                place: Some("c".to_string()),
                source_names: vec!["c".to_string()],
            }],
        },
    ];

    let mut execute = empty_decl(4, 3, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(3, 300, 310),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(3, 305, 308),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(vec![entry, orchestrate, persist, execute], |idx| {
        vec![
            (
                func_id(idx, "entry"),
                func_id(idx, "orchestrate"),
                span(0, 90, 100),
            ),
            (
                func_id(idx, "orchestrate"),
                func_id(idx, "persist"),
                span(1, 220, 230),
            ),
            (
                func_id(idx, "persist"),
                func_id(idx, "execute"),
                span(2, 260, 270),
            ),
        ]
    });
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");

    let raw_seed = svc.read_or_write_nodes_for_names(entry_id, &["raw".to_string()]);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 300, 310) && *idx == 0),
        "raw cmd field should reach the command sink: {raw_calls:?}"
    );

    let user_seed = svc.param_nodes_for_names(entry_id, &["user".to_string()], &idx);
    let user_calls = svc.tainted_call_args_in_closure(&user_seed);
    assert!(
        !user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 300, 310) && *idx == 0),
        "user sibling field must not reach the command sink: {user_calls:?}"
    );
    assert!(
        !user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(0, 90, 100) && *idx == 0),
        "user field must not promote the whole env argument: {user_calls:?}"
    );
}

#[test]
fn unresolved_whole_aggregate_call_reports_reachable_field_without_scalar_flow() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["input".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "opts.to".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["input".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 30, 40),
            name: "external_send".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 34, 38),
                name: None,
                value_text: "opts".to_string(),
                place: Some("opts".to_string()),
                source_names: vec!["opts".to_string()],
            }],
        },
    ];

    let (idx, ws) = build(vec![entry]);
    let entry_id = func_id(&idx, "entry");
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let seeds = svc.param_nodes_for_names(entry_id, &["input".to_string()], &idx);
    let closure = svc.forward_closure(&seeds);
    assert!(
        !closure.iter().any(|node| {
            svc.resolve_point(*node).is_some_and(|point| {
                point.kind == crate::service::PointKind::CallArg && point.span == span(0, 30, 40)
            })
        }),
        "aggregate-consumption evidence must not enter scalar reachability"
    );
    assert_eq!(
        svc.tainted_call_args_in_reachable_nodes(&closure),
        vec![(entry_id, span(0, 30, 40), 0)],
        "an unresolved whole-object consumer still observes current fields"
    );
}

#[test]
fn module_path_method_call_forwards_field_precise_argument() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string(), "user".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "valid.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 21, 30),
            target: "valid.user".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 40, 55),
            name: "store::persist".to_string(),
            receiver: Some("store".to_string()),
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Method,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 50, 54),
                name: None,
                value_text: "valid".to_string(),
                place: Some("valid".to_string()),
                source_names: vec!["valid".to_string()],
            }],
        },
    ];

    let mut persist = empty_decl(2, 1, "persist");
    persist.params = vec!["envelope".to_string()];
    persist.flow_events = vec![
        FlowEvent::Assign {
            span: span(1, 70, 85),
            target: "cmd".to_string(),
            source_name: Some("envelope.cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["envelope.cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(1, 90, 105),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 98, 101),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
    ];

    let mut execute = empty_decl(3, 2, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(2, 120, 135),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(2, 125, 128),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(vec![entry, persist, execute], |idx| {
        vec![
            (func_id(idx, "entry"), func_id(idx, "persist"), span(0, 40, 55)),
            (func_id(idx, "persist"), func_id(idx, "execute"), span(1, 90, 105)),
        ]
    });
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");

    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 120, 135) && *idx == 0),
        "module-path method call should forward valid.cmd into envelope.cmd: {raw_calls:?}"
    );

    let user_seed = svc.param_nodes_for_names(entry_id, &["user".to_string()], &idx);
    let user_calls = svc.tainted_call_args_in_closure(&user_seed);
    assert!(
        !user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 120, 135) && *idx == 0),
        "sibling field must not promote through module-path method arg forwarding: {user_calls:?}"
    );
}

#[test]
fn aggregate_yield_field_forwards_to_exact_loop_binding_field() {
    let generator_call = span(0, 40, 52);
    let sink_call = span(0, 70, 82);
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: generator_call,
            target: "item".to_string(),
            source_name: None,
            source_call: Some("generate".to_string()),
            source_call_args: vec!["raw".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::YieldResult),
        },
        FlowEvent::Call {
            span: sink_call,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 75, 81),
                name: None,
                value_text: "item.value".to_string(),
                place: Some("item.value".to_string()),
                source_names: vec!["item.value".to_string()],
            }],
        },
    ];

    let mut generate = empty_decl(2, 1, "generate");
    generate.params = vec!["input".to_string()];
    generate.flow_events = vec![FlowEvent::Yield {
        span: span(1, 20, 38),
        value_text: Some("{'value': input}".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                name: "value".to_string(),
                value_span: Some(span(1, 30, 35)),
                value: bonsai_lang_api::ExpressionFlow::from_place("input"),
            }],
            ..Default::default()
        },
    }];

    let (idx, ws) = build_with_edges(vec![entry, generate], |idx| {
        vec![(func_id(idx, "entry"), func_id(idx, "generate"), generator_call)]
    });
    let service = IdgQueryService::new(ws, Arc::clone(&idx));
    let seeds = service.param_nodes_for_names(func_id(&idx, "entry"), &["raw".to_string()], idx.as_ref());
    let calls = service.tainted_call_args_in_closure(&seeds);
    assert!(
        calls
            .iter()
            .any(|(_, span, index)| *span == sink_call && *index == 0),
        "exact yielded field must reach the matching loop-binding field: {calls:?}"
    );
}

#[test]
fn returned_container_field_forwards_to_assigned_object_argument() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string(), "user".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 21, 30),
            target: "env.user".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 40, 55),
            target: "valid".to_string(),
            source_name: None,
            source_call: Some("validate".to_string()),
            source_call_args: vec!["env".to_string()],
            source_names: vec!["validate".to_string(), "env".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(0, 70, 85),
            name: "persist".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 78, 83),
                name: None,
                value_text: "valid".to_string(),
                place: Some("valid".to_string()),
                source_names: vec!["valid".to_string()],
            }],
        },
    ];

    let mut validate = empty_decl(2, 1, "validate");
    validate.params = vec!["payload".to_string()];
    validate.flow_events = vec![FlowEvent::Return {
        span: span(1, 100, 140),
        value_name: None,
        value_text: Some("{\"cmd\": payload.cmd, \"user\": payload.user}".to_string()),
        value_flow: payload_map_flow(),
    }];

    let mut persist = empty_decl(3, 2, "persist");
    persist.params = vec!["data".to_string()];
    persist.flow_events = vec![
        FlowEvent::Assign {
            span: span(2, 150, 165),
            target: "cmd".to_string(),
            source_name: Some("data.cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["data.cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(2, 170, 185),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(2, 178, 181),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
    ];

    let mut execute = empty_decl(4, 3, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(3, 200, 215),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(3, 205, 208),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(vec![entry, validate, persist, execute], |idx| {
        vec![
            (func_id(idx, "entry"), func_id(idx, "validate"), span(0, 40, 55)),
            (func_id(idx, "entry"), func_id(idx, "persist"), span(0, 70, 85)),
            (
                func_id(idx, "persist"),
                func_id(idx, "execute"),
                span(2, 170, 185),
            ),
        ]
    });
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");

    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 200, 215) && *idx == 0),
        "returned cmd field should reach the command sink: {raw_calls:?}"
    );

    let user_seed = svc.param_nodes_for_names(entry_id, &["user".to_string()], &idx);
    let user_calls = svc.tainted_call_args_in_closure(&user_seed);
    assert!(
        !user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 200, 215) && *idx == 0),
        "returned user sibling field must not reach the command sink: {user_calls:?}"
    );
}

#[test]
fn returned_container_field_forwards_through_constructor_receiver_state() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string(), "user".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 21, 30),
            target: "env.user".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 40, 55),
            target: "valid".to_string(),
            source_name: None,
            source_call: Some("validate".to_string()),
            source_call_args: vec!["env".to_string()],
            source_names: vec!["validate".to_string(), "env".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: span(0, 70, 95),
            target: "repo".to_string(),
            source_name: None,
            source_call: Some("Repository".to_string()),
            source_call_args: vec!["valid".to_string()],
            source_names: vec!["Repository".to_string(), "valid".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(0, 110, 130),
            name: "repo.persist".to_string(),
            receiver: Some("repo".to_string()),
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut validate = empty_decl(2, 1, "validate");
    validate.params = vec!["payload".to_string()];
    validate.flow_events = vec![FlowEvent::Return {
        span: span(1, 100, 140),
        value_name: None,
        value_text: Some("{\"cmd\": payload.cmd, \"user\": payload.user}".to_string()),
        value_flow: payload_map_flow(),
    }];

    let mut repository_class = empty_decl(3, 2, "Repository");
    repository_class.kind = DeclKind::Class;
    repository_class.flow_events = Vec::new();

    let mut init = empty_decl(4, 2, "__init__");
    init.kind = DeclKind::Constructor;
    init.parent = Some(repository_class.symbol);
    init.params = vec!["self".to_string(), "data".to_string()];
    init.receiver_param_index = Some(0);
    init.receiver_field_writes = vec![FieldWrite {
        span: span(2, 150, 170),
        target: "self._data".to_string(),
        source_param_indices: vec![1],
    }];

    let mut persist = empty_decl(5, 2, "persist");
    persist.kind = DeclKind::Method;
    persist.parent = Some(repository_class.symbol);
    persist.params = vec!["self".to_string()];
    persist.receiver_param_index = Some(0);
    persist.flow_events = vec![
        FlowEvent::Assign {
            span: span(2, 180, 200),
            target: "cmd".to_string(),
            source_name: Some("self._data.cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["self._data.cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(2, 210, 225),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(2, 218, 221),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
    ];

    let mut execute = empty_decl(6, 3, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(3, 240, 255),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(3, 245, 248),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(
        vec![entry, validate, repository_class, init, persist, execute],
        |idx| {
            vec![
                (func_id(idx, "entry"), func_id(idx, "validate"), span(0, 40, 55)),
                (func_id(idx, "entry"), func_id(idx, "__init__"), span(0, 70, 95)),
                (func_id(idx, "entry"), func_id(idx, "persist"), span(0, 110, 130)),
                (
                    func_id(idx, "persist"),
                    func_id(idx, "execute"),
                    span(2, 210, 225),
                ),
            ]
        },
    );
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");

    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 240, 255) && *idx == 0),
        "returned cmd field should reach through constructor receiver state to sink: {raw_calls:?}"
    );
    let mut target_funcs = ahash::AHashSet::default();
    target_funcs.insert(func_id(&idx, "entry"));
    target_funcs.insert(func_id(&idx, "persist"));
    target_funcs.insert(func_id(&idx, "execute"));
    let cut =
        svc.forward_target_func_cut_with_max_precision(&raw_seed, &target_funcs, Some(Precision::Narrowed));
    let cut_calls = svc.tainted_call_args_in_reachable_nodes(&cut);
    assert!(
        cut_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 240, 255) && *idx == 0),
        "target-function cut must keep constructor receiver-state dependency nodes: {cut_calls:?}"
    );

    let user_seed = svc.param_nodes_for_names(entry_id, &["user".to_string()], &idx);
    let user_calls = svc.tainted_call_args_in_closure(&user_seed);
    assert!(
        !user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 240, 255) && *idx == 0),
        "returned user sibling field must not reach constructor-backed command sink: {user_calls:?}"
    );
}

#[test]
fn constructor_scalar_arguments_project_to_returned_object_fields() {
    let constructor_site = span(0, 40, 48);
    let sink_site = span(2, 210, 225);

    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string(), "user".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 30, 70),
            target: "envelope".to_string(),
            source_name: None,
            source_call: Some("Envelope".to_string()),
            source_call_args: vec!["raw".to_string(), "user".to_string()],
            source_names: vec!["raw".to_string(), "user".to_string()],
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: constructor_site,
            name: "Envelope".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Constructor,
            args: vec![
                bonsai_lang_api::CallArg {
                    passing_mode: Default::default(),
                    span: span(0, 49, 52),
                    name: None,
                    value_text: "raw".to_string(),
                    place: Some("raw".to_string()),
                    source_names: vec!["raw".to_string()],
                },
                bonsai_lang_api::CallArg {
                    passing_mode: Default::default(),
                    span: span(0, 54, 58),
                    name: None,
                    value_text: "user".to_string(),
                    place: Some("user".to_string()),
                    source_names: vec!["user".to_string()],
                },
            ],
        },
        FlowEvent::Call {
            span: span(0, 80, 95),
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 88, 96),
                name: None,
                value_text: "envelope".to_string(),
                place: Some("envelope".to_string()),
                source_names: vec!["envelope".to_string()],
            }],
        },
    ];

    let mut envelope_class = empty_decl(2, 1, "Envelope");
    envelope_class.kind = DeclKind::Class;

    let mut envelope_ctor = empty_decl(3, 1, "Envelope");
    envelope_ctor.kind = DeclKind::Constructor;
    envelope_ctor.parent = Some(envelope_class.symbol);
    envelope_ctor.params = vec!["cmd".to_string(), "user".to_string()];
    envelope_ctor.implicit_receiver_names = vec!["this".to_string()];
    envelope_ctor.receiver_field_writes = vec![
        FieldWrite {
            span: span(1, 100, 103),
            target: "this.cmd".to_string(),
            source_param_indices: vec![0],
        },
        FieldWrite {
            span: span(1, 105, 109),
            target: "this.user".to_string(),
            source_param_indices: vec![1],
        },
    ];

    let mut consume = empty_decl(4, 2, "consume");
    consume.params = vec!["envelope".to_string()];
    consume.flow_events = vec![FlowEvent::Call {
        span: sink_site,
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(2, 218, 222),
            name: None,
            value_text: "envelope.cmd".to_string(),
            place: Some("envelope.cmd".to_string()),
            source_names: vec!["envelope.cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(vec![entry, envelope_class, envelope_ctor, consume], |idx| {
        vec![
            (func_id(idx, "entry"), func_id(idx, "Envelope"), constructor_site),
            (func_id(idx, "entry"), func_id(idx, "consume"), span(0, 80, 95)),
        ]
    });
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");

    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == sink_site && *idx == 0),
        "constructor cmd argument must project to the returned object's cmd field: {raw_calls:?}"
    );

    let user_seed = svc.param_nodes_for_names(entry_id, &["user".to_string()], &idx);
    let user_calls = svc.tainted_call_args_in_closure(&user_seed);
    assert!(
        !user_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == sink_site && *idx == 0),
        "constructor sibling fields must remain isolated: {user_calls:?}"
    );
}

#[test]
fn return_expression_constructor_state_flows_to_inline_factory_receiver() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 42, 46),
            name: "Repository::wrap".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 47, 50),
                name: None,
                value_text: "env".to_string(),
                place: Some("env".to_string()),
                source_names: vec!["env".to_string()],
            }],
        },
        FlowEvent::Call {
            span: span(0, 58, 61),
            name: "Repository::wrap(env)->run".to_string(),
            receiver: Some("Repository::wrap(env)".to_string()),
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut base_class = empty_decl(2, 1, "BaseRepository");
    base_class.kind = DeclKind::Class;

    let mut repository_class = empty_decl(8, 1, "Repository");
    repository_class.kind = DeclKind::Class;
    repository_class.bases = vec!["BaseRepository".to_string()];

    let mut ctor = empty_decl(3, 1, "__construct");
    ctor.kind = DeclKind::Constructor;
    ctor.parent = Some(base_class.symbol);
    ctor.params = vec!["data".to_string()];
    ctor.implicit_receiver_names = vec!["this".to_string()];
    ctor.receiver_field_writes = vec![FieldWrite {
        span: span(1, 90, 95),
        target: "this.data".to_string(),
        source_param_indices: vec![0],
    }];

    let mut wrap = empty_decl(4, 1, "wrap");
    wrap.kind = DeclKind::Method;
    wrap.parent = Some(repository_class.symbol);
    wrap.params = vec!["data".to_string()];
    wrap.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 110, 116),
            name: "static".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Constructor,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 117, 121),
                name: None,
                value_text: "data".to_string(),
                place: Some("data".to_string()),
                source_names: vec!["data".to_string()],
            }],
        },
        FlowEvent::Return {
            span: span(1, 100, 125),
            value_name: None,
            value_text: Some("new static(data)".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                call_sites: vec![span(1, 110, 116)],
                ..Default::default()
            },
        },
    ];

    let mut run = empty_decl(5, 1, "run");
    run.kind = DeclKind::Method;
    run.parent = Some(repository_class.symbol);
    run.implicit_receiver_names = vec!["$this".to_string()];
    run.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 200, 207),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 201, 210),
                name: None,
                value_text: "$this->cmd()".to_string(),
                place: Some("$this.cmd".to_string()),
                source_names: vec![
                    "$this.cmd".to_string(),
                    "$this".to_string(),
                    "this".to_string(),
                    "this.cmd".to_string(),
                ],
            }],
        },
        FlowEvent::Call {
            span: span(1, 205, 208),
            name: "$this->cmd".to_string(),
            receiver: Some("$this".to_string()),
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut cmd = empty_decl(6, 1, "cmd");
    cmd.kind = DeclKind::Method;
    cmd.parent = Some(base_class.symbol);
    cmd.implicit_receiver_names = vec!["$this".to_string()];
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 300, 315),
        value_name: None,
        value_text: Some("$this->data['cmd']".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("$this.data.cmd"),
    }];

    let mut execute = empty_decl(7, 2, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(2, 400, 405),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(2, 401, 404),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(
        vec![entry, base_class, repository_class, ctor, wrap, run, cmd, execute],
        |idx| {
            vec![
                (func_id(idx, "entry"), func_id(idx, "wrap"), span(0, 42, 46)),
                (func_id(idx, "entry"), func_id(idx, "run"), span(0, 58, 61)),
                (
                    func_id(idx, "wrap"),
                    func_id(idx, "__construct"),
                    span(1, 110, 116),
                ),
                (func_id(idx, "run"), func_id(idx, "cmd"), span(1, 205, 208)),
                (func_id(idx, "run"), func_id(idx, "execute"), span(1, 200, 207)),
            ]
        },
    );
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");
    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    assert!(!raw_seed.is_empty(), "raw param seed should exist");
    let raw_closure = svc.forward_closure(&raw_seed);
    let raw_points: Vec<String> = raw_closure
        .iter()
        .filter_map(|node| {
            svc.resolve_point(*node).map(|point| {
                format!(
                    "{:?}:{}@{}..{}",
                    point.kind, point.name, point.span.start, point.span.end
                )
            })
        })
        .collect();
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(1, 200, 207) && *idx == 0),
        "constructor state returned from inline factory receiver must reach execute: calls={raw_calls:?} closure={raw_points:?}"
    );
}

#[test]
fn returned_factory_assignment_receiver_field_flows_to_method_call() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 40, 52),
            name: "persist".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 48, 51),
                name: None,
                value_text: "env".to_string(),
                place: Some("env".to_string()),
                source_names: vec!["env".to_string()],
            }],
        },
    ];

    let mut repository_class = empty_decl(2, 1, "Repository");
    repository_class.kind = DeclKind::Class;

    let mut init = empty_decl(3, 1, "initialize");
    init.kind = DeclKind::Constructor;
    init.parent = Some(repository_class.symbol);
    init.params = vec!["data".to_string()];
    init.implicit_receiver_names = vec!["self".to_string()];
    init.flow_events = vec![FlowEvent::Assign {
        span: span(1, 70, 80),
        target: "self.data".to_string(),
        source_name: Some("data".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["data".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];

    let mut wrap = empty_decl(4, 1, "wrap");
    wrap.kind = DeclKind::Method;
    wrap.parent = Some(repository_class.symbol);
    wrap.params = vec!["data".to_string()];
    wrap.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 110, 116),
            name: "new".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Constructor,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 117, 121),
                name: None,
                value_text: "data".to_string(),
                place: Some("data".to_string()),
                source_names: vec!["data".to_string()],
            }],
        },
        FlowEvent::Return {
            span: span(1, 110, 125),
            value_name: None,
            value_text: Some("new(data)".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                call_sites: vec![span(1, 110, 116)],
                ..Default::default()
            },
        },
    ];

    let mut persist = empty_decl(5, 1, "persist");
    persist.params = vec!["envelope".to_string()];
    persist.flow_events = vec![
        FlowEvent::Assign {
            span: span(1, 150, 175),
            target: "repo".to_string(),
            source_name: None,
            source_call: Some("Repository.wrap".to_string()),
            source_call_args: vec!["envelope".to_string()],
            source_names: vec!["Repository".to_string(), "wrap".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(1, 162, 177),
            name: "Repository.wrap".to_string(),
            receiver: Some("Repository".to_string()),
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 178, 186),
                name: None,
                value_text: "envelope".to_string(),
                place: Some("envelope".to_string()),
                source_names: vec!["envelope".to_string()],
            }],
        },
        FlowEvent::Call {
            span: span(1, 190, 198),
            name: "repo.run".to_string(),
            receiver: Some("repo".to_string()),
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut run = empty_decl(6, 1, "run");
    run.kind = DeclKind::Method;
    run.parent = Some(repository_class.symbol);
    run.implicit_receiver_names = vec!["self".to_string()];
    run.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 210, 214),
            name: "cmd".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Call {
            span: span(1, 220, 230),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 228, 231),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
    ];

    let mut cmd = empty_decl(7, 1, "cmd");
    cmd.kind = DeclKind::Method;
    cmd.parent = Some(repository_class.symbol);
    cmd.implicit_receiver_names = vec!["self".to_string()];
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 240, 253),
        value_name: None,
        value_text: Some("self.data[:cmd]".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("self.data.cmd"),
    }];

    let mut execute = empty_decl(8, 2, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(2, 300, 305),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(2, 301, 304),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(
        vec![entry, repository_class, init, wrap, persist, run, cmd, execute],
        |idx| {
            vec![
                (func_id(idx, "entry"), func_id(idx, "persist"), span(0, 40, 52)),
                (func_id(idx, "persist"), func_id(idx, "wrap"), span(1, 162, 177)),
                (
                    func_id(idx, "wrap"),
                    func_id(idx, "initialize"),
                    span(1, 110, 116),
                ),
                (func_id(idx, "persist"), func_id(idx, "run"), span(1, 190, 198)),
                (func_id(idx, "run"), func_id(idx, "cmd"), span(1, 210, 214)),
                (func_id(idx, "run"), func_id(idx, "execute"), span(1, 220, 230)),
            ]
        },
    );
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");
    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 300, 305) && *idx == 0),
        "constructor state returned through a factory assignment must taint repo.run() receiver fields: {raw_calls:?}"
    );
}

#[test]
fn returned_factory_assignment_receiver_field_flows_through_super_method() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 40, 52),
            name: "persist".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 48, 51),
                name: None,
                value_text: "env".to_string(),
                place: Some("env".to_string()),
                source_names: vec!["env".to_string()],
            }],
        },
    ];

    let mut repository_class = empty_decl(2, 1, "Repository");
    repository_class.kind = DeclKind::Class;

    let mut audited_class = empty_decl(3, 1, "AuditedRepository");
    audited_class.kind = DeclKind::Class;
    audited_class.bases = vec!["Repository".to_string()];

    let mut init = empty_decl(4, 1, "initialize");
    init.kind = DeclKind::Constructor;
    init.parent = Some(repository_class.symbol);
    init.params = vec!["data".to_string()];
    init.implicit_receiver_names = vec!["self".to_string()];
    init.flow_events = vec![FlowEvent::Assign {
        span: span(1, 70, 80),
        target: "self.data".to_string(),
        source_name: Some("data".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["data".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];

    let mut wrap = empty_decl(5, 1, "wrap");
    wrap.kind = DeclKind::Method;
    wrap.parent = Some(repository_class.symbol);
    wrap.params = vec!["data".to_string()];
    wrap.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 110, 116),
            name: "new".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Constructor,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 117, 121),
                name: None,
                value_text: "data".to_string(),
                place: Some("data".to_string()),
                source_names: vec!["data".to_string()],
            }],
        },
        FlowEvent::Return {
            span: span(1, 110, 125),
            value_name: None,
            value_text: Some("new(data)".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                call_sites: vec![span(1, 110, 116)],
                ..Default::default()
            },
        },
    ];

    let mut persist = empty_decl(6, 1, "persist");
    persist.params = vec!["envelope".to_string()];
    persist.flow_events = vec![
        FlowEvent::Assign {
            span: span(1, 150, 175),
            target: "repo".to_string(),
            source_name: None,
            source_call: Some("AuditedRepository.wrap".to_string()),
            source_call_args: vec!["envelope".to_string()],
            source_names: vec!["AuditedRepository".to_string(), "wrap".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(1, 162, 177),
            name: "AuditedRepository.wrap".to_string(),
            receiver: Some("AuditedRepository".to_string()),
            receiver_types: vec!["AuditedRepository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 178, 186),
                name: None,
                value_text: "envelope".to_string(),
                place: Some("envelope".to_string()),
                source_names: vec!["envelope".to_string()],
            }],
        },
        FlowEvent::Call {
            span: span(1, 190, 198),
            name: "repo.run".to_string(),
            receiver: Some("repo".to_string()),
            receiver_types: vec!["AuditedRepository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut audited_run = empty_decl(7, 1, "run");
    audited_run.kind = DeclKind::Method;
    audited_run.parent = Some(audited_class.symbol);
    audited_run.implicit_receiver_names = vec!["self".to_string()];
    audited_run.span = span(1, 300, 340);
    audited_run.name_span = span(1, 300, 303);
    audited_run.flow_events = vec![FlowEvent::Call {
        span: span(1, 315, 320),
        name: "super.run".to_string(),
        receiver: Some("super".to_string()),
        receiver_types: vec!["Repository".to_string()],
        call_kind: bonsai_lang_api::CallKind::Method,
        args: Vec::new(),
    }];

    let mut base_run = empty_decl(8, 1, "run");
    base_run.kind = DeclKind::Method;
    base_run.parent = Some(repository_class.symbol);
    base_run.implicit_receiver_names = vec!["self".to_string()];
    base_run.span = span(1, 360, 430);
    base_run.name_span = span(1, 360, 363);
    base_run.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 370, 373),
            name: "cmd".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Call {
            span: span(1, 390, 405),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 398, 401),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
    ];

    let mut cmd = empty_decl(9, 1, "cmd");
    cmd.kind = DeclKind::Method;
    cmd.parent = Some(repository_class.symbol);
    cmd.implicit_receiver_names = vec!["self".to_string()];
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 440, 455),
        value_name: None,
        value_text: Some("self.data[:cmd]".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("self.data.cmd"),
    }];

    let mut execute = empty_decl(10, 2, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(2, 500, 510),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(2, 504, 507),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(
        vec![
            entry,
            repository_class,
            audited_class,
            init,
            wrap,
            persist,
            audited_run,
            base_run,
            cmd,
            execute,
        ],
        |idx| {
            vec![
                (func_id(idx, "entry"), func_id(idx, "persist"), span(0, 40, 52)),
                (func_id(idx, "persist"), func_id(idx, "wrap"), span(1, 162, 177)),
                (
                    func_id(idx, "wrap"),
                    func_id(idx, "initialize"),
                    span(1, 110, 116),
                ),
                (
                    func_id(idx, "persist"),
                    func_id_at_start(idx, "run", 300),
                    span(1, 190, 198),
                ),
                (
                    func_id_at_start(idx, "run", 300),
                    func_id_at_start(idx, "run", 360),
                    span(1, 315, 320),
                ),
                (
                    func_id_at_start(idx, "run", 360),
                    func_id(idx, "cmd"),
                    span(1, 370, 373),
                ),
                (
                    func_id_at_start(idx, "run", 360),
                    func_id(idx, "execute"),
                    span(1, 390, 405),
                ),
            ]
        },
    );
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");
    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 500, 510) && *idx == 0),
        "factory receiver field must flow through subclass super method to sink: {raw_calls:?}"
    );
}

#[test]
fn inline_factory_receiver_field_flows_through_super_and_bare_accessor() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 40, 52),
            name: "persist".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 48, 51),
                name: None,
                value_text: "env".to_string(),
                place: Some("env".to_string()),
                source_names: vec!["env".to_string()],
            }],
        },
    ];

    let mut repository_class = empty_decl(2, 1, "Repository");
    repository_class.kind = DeclKind::Class;
    repository_class.bases = vec!["BaseRepository".to_string()];

    let mut audited_class = empty_decl(3, 1, "AuditedRepository");
    audited_class.kind = DeclKind::Class;
    audited_class.bases = vec!["Repository".to_string()];

    let mut base_class = empty_decl(13, 1, "BaseRepository");
    base_class.kind = DeclKind::Class;

    let mut base_ctor = empty_decl(4, 1, "BaseRepository");
    base_ctor.kind = DeclKind::Constructor;
    base_ctor.parent = Some(base_class.symbol);
    base_ctor.params = vec!["data".to_string()];
    base_ctor.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
    base_ctor.receiver_field_writes = vec![FieldWrite {
        span: span(1, 70, 90),
        target: "this.data".to_string(),
        source_param_indices: vec![0],
    }];

    let mut repository_ctor = empty_decl(5, 1, "Repository");
    repository_ctor.kind = DeclKind::Constructor;
    repository_ctor.parent = Some(repository_class.symbol);
    repository_ctor.params = vec!["data".to_string()];
    repository_ctor.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
    repository_ctor.receiver_field_writes = vec![FieldWrite {
        span: span(1, 70, 90),
        target: "this.data".to_string(),
        source_param_indices: vec![0],
    }];
    repository_ctor.flow_events = vec![FlowEvent::Call {
        span: span(1, 100, 120),
        name: "BaseRepository".to_string(),
        receiver: None,
        receiver_types: vec!["BaseRepository".to_string()],
        call_kind: bonsai_lang_api::CallKind::Constructor,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(1, 115, 119),
            name: None,
            value_text: "data".to_string(),
            place: Some("data".to_string()),
            source_names: vec!["data".to_string()],
        }],
    }];

    let mut audited_ctor = empty_decl(6, 1, "AuditedRepository");
    audited_ctor.kind = DeclKind::Constructor;
    audited_ctor.parent = Some(audited_class.symbol);
    audited_ctor.params = vec!["data".to_string()];
    audited_ctor.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
    audited_ctor.receiver_field_writes = vec![FieldWrite {
        span: span(1, 70, 90),
        target: "this.data".to_string(),
        source_param_indices: vec![0],
    }];
    audited_ctor.flow_events = vec![FlowEvent::Call {
        span: span(1, 130, 150),
        name: "Repository".to_string(),
        receiver: None,
        receiver_types: vec!["Repository".to_string()],
        call_kind: bonsai_lang_api::CallKind::Constructor,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(1, 145, 149),
            name: None,
            value_text: "data".to_string(),
            place: Some("data".to_string()),
            source_names: vec!["data".to_string()],
        }],
    }];

    let mut wrap = empty_decl(7, 1, "wrap");
    wrap.kind = DeclKind::Method;
    wrap.parent = Some(repository_class.symbol);
    wrap.params = vec!["data".to_string()];
    wrap.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 160, 178),
            name: "AuditedRepository".to_string(),
            receiver: None,
            receiver_types: vec!["AuditedRepository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Constructor,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 179, 183),
                name: None,
                value_text: "data".to_string(),
                place: Some("data".to_string()),
                source_names: vec!["data".to_string()],
            }],
        },
        FlowEvent::Return {
            span: span(1, 156, 184),
            value_name: None,
            value_text: Some("new AuditedRepository(data)".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                call_sites: vec![span(1, 160, 178)],
                ..Default::default()
            },
        },
    ];

    let mut persist = empty_decl(8, 1, "persist");
    persist.params = vec!["envelope".to_string()];
    persist.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 200, 215),
            name: "Repository.wrap".to_string(),
            receiver: Some("Repository".to_string()),
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 216, 224),
                name: None,
                value_text: "envelope".to_string(),
                place: Some("envelope".to_string()),
                source_names: vec!["envelope".to_string()],
            }],
        },
        FlowEvent::Call {
            span: span(1, 200, 235),
            name: "Repository.wrap(envelope).run".to_string(),
            receiver: Some("Repository.wrap(envelope)".to_string()),
            receiver_types: vec!["AuditedRepository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut audited_run = empty_decl(9, 1, "run");
    audited_run.kind = DeclKind::Method;
    audited_run.parent = Some(audited_class.symbol);
    audited_run.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
    audited_run.span = span(1, 300, 340);
    audited_run.name_span = span(1, 300, 303);
    audited_run.flow_events = vec![FlowEvent::Call {
        span: span(1, 320, 330),
        name: "super.run".to_string(),
        receiver: Some("super".to_string()),
        receiver_types: vec!["Repository".to_string()],
        call_kind: bonsai_lang_api::CallKind::Method,
        args: Vec::new(),
    }];

    let mut base_run = empty_decl(10, 1, "run");
    base_run.kind = DeclKind::Method;
    base_run.parent = Some(repository_class.symbol);
    base_run.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
    base_run.span = span(1, 360, 430);
    base_run.name_span = span(1, 360, 363);
    base_run.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 370, 373),
            name: "cmd".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Function,
            args: Vec::new(),
        },
        FlowEvent::Assign {
            span: span(1, 370, 373),
            target: "c".to_string(),
            source_name: None,
            source_call: Some("cmd".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(1, 390, 405),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(1, 398, 401),
                name: None,
                value_text: "c".to_string(),
                place: Some("c".to_string()),
                source_names: vec!["c".to_string()],
            }],
        },
    ];

    let mut cmd = empty_decl(11, 1, "cmd");
    cmd.kind = DeclKind::Method;
    cmd.parent = Some(repository_class.symbol);
    cmd.implicit_receiver_names = vec!["this".to_string()];
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 440, 455),
        value_name: None,
        value_text: Some("data.cmd".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("data.cmd"),
    }];

    let mut execute = empty_decl(12, 2, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(2, 500, 510),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(2, 504, 507),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(
        vec![
            entry,
            base_class,
            repository_class,
            audited_class,
            base_ctor,
            repository_ctor,
            audited_ctor,
            wrap,
            persist,
            audited_run,
            base_run,
            cmd,
            execute,
        ],
        |idx| {
            vec![
                (func_id(idx, "entry"), func_id(idx, "persist"), span(0, 40, 52)),
                (func_id(idx, "persist"), func_id(idx, "wrap"), span(1, 200, 215)),
                (
                    func_id(idx, "wrap"),
                    func_id(idx, "AuditedRepository"),
                    span(1, 160, 178),
                ),
                (
                    func_id(idx, "AuditedRepository"),
                    func_id(idx, "Repository"),
                    span(1, 130, 150),
                ),
                (
                    func_id(idx, "Repository"),
                    func_id(idx, "BaseRepository"),
                    span(1, 100, 120),
                ),
                (
                    func_id(idx, "persist"),
                    func_id_at_start(idx, "run", 300),
                    span(1, 200, 235),
                ),
                (
                    func_id_at_start(idx, "run", 300),
                    func_id_at_start(idx, "run", 360),
                    span(1, 320, 330),
                ),
                (
                    func_id_at_start(idx, "run", 360),
                    func_id(idx, "cmd"),
                    span(1, 370, 373),
                ),
                (
                    func_id_at_start(idx, "run", 360),
                    func_id(idx, "execute"),
                    span(1, 390, 405),
                ),
            ]
        },
    );
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");
    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_closure = svc.forward_closure(&raw_seed);
    let raw_points: Vec<String> = raw_closure
        .iter()
        .filter_map(|node| {
            svc.resolve_point(*node).map(|point| {
                format!(
                    "{:?}:{}@{}..{}",
                    point.kind, point.name, point.span.start, point.span.end
                )
            })
        })
        .collect();
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 500, 510) && *idx == 0),
        "inline factory receiver field must flow through super.run and bare cmd accessor: calls={raw_calls:?} closure={raw_points:?}"
    );
}

#[test]
fn returned_container_field_forwards_through_super_constructor_receiver_state() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string(), "user".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 21, 30),
            target: "env.user".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 40, 55),
            target: "valid".to_string(),
            source_name: None,
            source_call: Some("validate".to_string()),
            source_call_args: vec!["env".to_string()],
            source_names: vec!["validate".to_string(), "env".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: span(0, 70, 100),
            target: "repo".to_string(),
            source_name: None,
            source_call: Some("AuditedRepository".to_string()),
            source_call_args: vec!["valid".to_string(), "user".to_string()],
            source_names: vec![
                "AuditedRepository".to_string(),
                "valid".to_string(),
                "user".to_string(),
            ],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(0, 110, 130),
            name: "repo.persist".to_string(),
            receiver: Some("repo".to_string()),
            receiver_types: vec!["AuditedRepository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut validate = empty_decl(2, 1, "validate");
    validate.params = vec!["payload".to_string()];
    validate.flow_events = vec![FlowEvent::Return {
        span: span(1, 100, 140),
        value_name: None,
        value_text: Some("{\"cmd\": payload.cmd, \"user\": payload.user}".to_string()),
        value_flow: payload_map_flow(),
    }];

    let mut repository_class = empty_decl(3, 2, "Repository");
    repository_class.kind = DeclKind::Class;
    repository_class.flow_events = Vec::new();

    let mut audited_class = empty_decl(4, 2, "AuditedRepository");
    audited_class.kind = DeclKind::Class;
    audited_class.bases = vec!["Repository".to_string()];
    audited_class.flow_events = Vec::new();

    let mut base_init = empty_decl(5, 2, "__init__");
    base_init.kind = DeclKind::Constructor;
    base_init.parent = Some(repository_class.symbol);
    base_init.span = span(2, 145, 172);
    base_init.name_span = span(2, 146, 154);
    base_init.body_span = Some(span(2, 154, 172));
    base_init.params = vec!["self".to_string(), "data".to_string()];
    base_init.receiver_param_index = Some(0);
    base_init.receiver_field_writes = vec![FieldWrite {
        span: span(2, 150, 170),
        target: "self._data".to_string(),
        source_param_indices: vec![1],
    }];

    let mut audited_init = empty_decl(6, 2, "__init__");
    audited_init.kind = DeclKind::Constructor;
    audited_init.parent = Some(audited_class.symbol);
    audited_init.span = span(2, 172, 206);
    audited_init.name_span = span(2, 173, 181);
    audited_init.body_span = Some(span(2, 181, 206));
    audited_init.params = vec!["self".to_string(), "data".to_string(), "who".to_string()];
    audited_init.receiver_param_index = Some(0);
    audited_init.receiver_field_writes = vec![FieldWrite {
        span: span(2, 190, 205),
        target: "self.who".to_string(),
        source_param_indices: vec![2],
    }];
    audited_init.flow_events = vec![FlowEvent::Call {
        span: span(2, 175, 185),
        name: "super().__init__".to_string(),
        receiver: Some("super()".to_string()),
        receiver_types: vec!["Repository".to_string()],
        call_kind: bonsai_lang_api::CallKind::Method,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(2, 181, 185),
            name: None,
            value_text: "data".to_string(),
            place: Some("data".to_string()),
            source_names: vec!["data".to_string()],
        }],
    }];

    let mut persist = empty_decl(7, 2, "persist");
    persist.kind = DeclKind::Method;
    persist.parent = Some(repository_class.symbol);
    persist.params = vec!["self".to_string()];
    persist.receiver_param_index = Some(0);
    persist.flow_events = vec![
        FlowEvent::Assign {
            span: span(2, 210, 230),
            target: "cmd".to_string(),
            source_name: Some("self._data.cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["self._data.cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(2, 240, 255),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(2, 248, 251),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
    ];

    let mut execute = empty_decl(8, 3, "execute");
    execute.params = vec!["cmd".to_string()];
    execute.flow_events = vec![FlowEvent::Call {
        span: span(3, 270, 285),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(3, 275, 278),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(
        vec![
            entry,
            validate,
            repository_class,
            audited_class,
            base_init,
            audited_init,
            persist,
            execute,
        ],
        |idx| {
            let init_with_param_count = |param_count: usize| {
                for file in idx.all_files() {
                    for decl in idx.decls_in(file) {
                        if decl.name == "__init__" && decl.params.len() == param_count {
                            return FuncId::new(decl.symbol.raw());
                        }
                    }
                }
                unreachable!("constructor with {param_count} params not in index")
            };
            vec![
                (func_id(idx, "entry"), func_id(idx, "validate"), span(0, 40, 55)),
                (func_id(idx, "entry"), init_with_param_count(3), span(0, 70, 100)),
                (
                    init_with_param_count(3),
                    init_with_param_count(2),
                    span(2, 175, 185),
                ),
                (func_id(idx, "entry"), func_id(idx, "persist"), span(0, 110, 130)),
                (
                    func_id(idx, "persist"),
                    func_id(idx, "execute"),
                    span(2, 240, 255),
                ),
            ]
        },
    );
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let entry_id = func_id(&idx, "entry");
    let raw_seed = svc.param_nodes_for_names(entry_id, &["raw".to_string()], &idx);
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(3, 270, 285) && *idx == 0),
        "returned cmd field should reach through super constructor receiver state: {raw_calls:?}"
    );
}

#[test]
fn c_indexed_argv_copy_reaches_address_of_struct_field_read() {
    let mut entry = empty_decl(1, 0, "main");
    entry.params = vec!["argc".to_string(), "argv".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "raw".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["argv".to_string(), "argv.1".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(0, 30, 40),
            target: "env.cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(0, 50, 60),
            name: "orchestrate".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 52, 56),
                name: None,
                value_text: "&env".to_string(),
                place: Some("&env".to_string()),
                source_names: vec!["env".to_string()],
            }],
        },
    ];

    let mut orchestrate = empty_decl(2, 1, "orchestrate");
    orchestrate.params = vec!["env".to_string()];
    orchestrate.flow_events = vec![FlowEvent::Call {
        span: span(1, 70, 80),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(1, 75, 79),
            name: None,
            value_text: "env->cmd".to_string(),
            place: Some("env.cmd".to_string()),
            source_names: vec!["env.cmd".to_string()],
        }],
    }];

    let (idx, ws) = build_with_edges(vec![entry, orchestrate], |idx| {
        vec![(func_id(idx, "main"), func_id(idx, "orchestrate"), span(0, 50, 60))]
    });
    let svc = IdgQueryService::new(ws, Arc::clone(&idx));
    let main_id = func_id(&idx, "main");
    let argv_seed = svc.param_nodes_for_names(main_id, &["argv".to_string()], &idx);
    let calls = svc.tainted_call_args_in_closure(&argv_seed);

    assert!(
        calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(1, 70, 80) && *idx == 0),
        "argv[1] copied into env.cmd should reach the callee's env.cmd sink without tainting the whole struct: {calls:?}"
    );
}
