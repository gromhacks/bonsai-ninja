use super::*;
use crate::edge::IdgEdgeKind;
use crate::node::NodeId;
use crate::place::Place;
use crate::query::ReachabilityIndex;
use crate::transfer::{
    transfer_function_for, transfer_function_for_with_options,
    transfer_function_for_with_options_and_compiler_facts,
    transfer_function_for_with_options_and_syntax_facts, TransferOptions,
};
use crate::{IdgQueryService, PointKind, WsNodeId};
use bonsai_common::{FileId, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{
    AssignValueKind, CallArg, CallKind, Decl, DeclKind, FieldWrite, FlowEvent, ModulePath, Visibility,
};
use std::sync::Arc;

fn span(start: u64, end: u64) -> Span {
    Span::new(FileId::new(0), start, end)
}

fn empty_decl(sym: u32, name: &str) -> Decl {
    Decl {
        symbol: SymbolId::new(sym),
        kind: DeclKind::Function,
        name: name.to_string(),
        qualified_name: None,
        module_path: ModulePath::default(),
        span: span(0, 100),
        name_span: span(0, 10),
        visibility: Visibility::Public,
        parent: None,
        body_span: Some(span(10, 100)),
        flow_events: Vec::new(),
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        receiver_field_initializers: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

#[test]
fn storage_normalization_memo_scales_by_bytes_without_capping_analysis() {
    assert_eq!(
        storage_normalization_cache_capacity_for_limit(Some(3 * 1024 * 1024 * 1024)),
        12_288
    );
    assert_eq!(
        storage_normalization_cache_capacity_for_limit(Some(64 * 1024 * 1024)),
        MIN_STORAGE_NORMALIZATION_CACHE_ENTRIES,
        "constrained machines retain a small memo and recompute evicted syntax paths"
    );
    assert_eq!(
        storage_normalization_cache_capacity_for_limit(None),
        MAX_STORAGE_NORMALIZATION_CACHE_ENTRIES
    );
}

/// Mock resolver: a fixed map from (caller_func, callee_name)
/// to candidate FuncIds. All resolved as Direct + Exact.
struct MockResolver {
    table: AHashMap<(FuncId, String), Vec<FuncId>>,
    callback_bindings: AHashMap<(FuncId, u32), Vec<FuncId>>,
    callback_origins: AHashMap<(FuncId, u32, FuncId), Vec<CallbackBindingOrigin>>,
    callable_args: AHashMap<(FuncId, String), Vec<FuncId>>,
    callable_arg_spans: AHashMap<(FuncId, Span), Vec<FuncId>>,
    local_bindings: AHashSet<(FuncId, FuncId)>,
    imported_bindings: AHashMap<(FuncId, String), String>,
}

impl MockResolver {
    fn new() -> Self {
        Self {
            table: AHashMap::new(),
            callback_bindings: AHashMap::new(),
            callback_origins: AHashMap::new(),
            callable_args: AHashMap::new(),
            callable_arg_spans: AHashMap::new(),
            local_bindings: AHashSet::new(),
            imported_bindings: AHashMap::new(),
        }
    }

    fn add(&mut self, caller: FuncId, name: &str, callees: Vec<FuncId>) {
        self.table.insert((caller, name.to_string()), callees);
    }

    fn add_local_binding(&mut self, caller: FuncId, callee: FuncId) {
        self.local_bindings.insert((caller, callee));
    }

    fn add_callback_binding(&mut self, host: FuncId, param_idx: u32, callees: Vec<FuncId>) {
        self.callback_bindings.insert((host, param_idx), callees);
    }

    fn add_callback_origin(
        &mut self,
        host: FuncId,
        param_idx: u32,
        callback: FuncId,
        origin: CallbackBindingOrigin,
    ) {
        self.callback_origins
            .entry((host, param_idx, callback))
            .or_default()
            .push(origin);
    }

    fn add_callable_arg(&mut self, caller: FuncId, arg_text: &str, callees: Vec<FuncId>) {
        self.callable_args.insert((caller, arg_text.to_string()), callees);
    }

    fn add_callable_arg_span(&mut self, caller: FuncId, arg_span: Span, callees: Vec<FuncId>) {
        self.callable_arg_spans.insert((caller, arg_span), callees);
    }

    fn add_imported_binding(&mut self, func: FuncId, binding: &str, target: &str) {
        self.imported_bindings
            .insert((func, binding.to_string()), target.to_string());
    }
}

impl CalleeResolver for MockResolver {
    fn resolve(
        &self,
        caller: FuncId,
        _site: Span,
        callee_name: &str,
        _receiver: Option<&str>,
        _receiver_types: &[String],
        _call_kind: CallKind,
    ) -> Vec<ResolvedCallee> {
        self.table
            .get(&(caller, callee_name.to_string()))
            .into_iter()
            .flatten()
            .map(|f| ResolvedCallee {
                func: *f,
                edge_kind: CallEdgeKind::Direct,
            })
            .collect()
    }

    fn is_local_callable_binding(&self, caller: FuncId, callee: FuncId) -> bool {
        self.local_bindings.contains(&(caller, callee))
    }

    fn callback_bindings(&self, host: FuncId, param_idx: u32) -> Vec<ResolvedCallee> {
        self.callback_bindings
            .get(&(host, param_idx))
            .into_iter()
            .flatten()
            .map(|func| ResolvedCallee {
                func: *func,
                edge_kind: CallEdgeKind::Indirect,
            })
            .collect()
    }

    fn callback_binding_origins(
        &self,
        host: FuncId,
        param_idx: u32,
        callback: FuncId,
    ) -> Vec<CallbackBindingOrigin> {
        self.callback_origins
            .get(&(host, param_idx, callback))
            .cloned()
            .unwrap_or_default()
    }

    fn callable_arg(&self, caller: FuncId, arg_text: &str) -> Vec<ResolvedCallee> {
        self.callable_args
            .get(&(caller, arg_text.to_string()))
            .into_iter()
            .flatten()
            .map(|func| ResolvedCallee {
                func: *func,
                edge_kind: CallEdgeKind::Indirect,
            })
            .collect()
    }

    fn callable_args_in_span(&self, caller: FuncId, arg_span: Span) -> Vec<ResolvedCallee> {
        self.callable_arg_spans
            .get(&(caller, arg_span))
            .into_iter()
            .flatten()
            .map(|func| ResolvedCallee {
                func: *func,
                edge_kind: CallEdgeKind::Indirect,
            })
            .collect()
    }

    fn callable_is_inline_in_span(&self, caller: FuncId, _arg_span: Span, candidate: FuncId) -> bool {
        self.local_bindings.contains(&(caller, candidate))
    }

    fn imported_binding_target(&self, func: FuncId, binding: &str, _at_span: Span) -> Option<String> {
        self.imported_bindings.get(&(func, binding.to_string())).cloned()
    }
}

#[test]
fn exact_inline_callback_capture_write_reaches_later_call_argument_and_clean_overwrite_kills_it() {
    let host_func = FuncId::new(1);
    let callback_func = FuncId::new(2);
    let invocation_span = span(20, 30);
    let callback_arg_span = span(31, 60);
    let callback_write_span = span(70, 78);
    let sink_span = span(90, 99);

    let host_events = |clean_after_callback: bool| {
        let mut events = vec![
            FlowEvent::Assign {
                span: span(10, 18),
                target: "term".to_string(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: true,
                value_kind: Some(AssignValueKind::Literal),
            },
            FlowEvent::Call {
                span: invocation_span,
                name: "items.forEach".to_string(),
                receiver: Some("items".to_string()),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: vec![CallArg {
                    passing_mode: Default::default(),
                    span: callback_arg_span,
                    name: None,
                    value_text: "callback".to_string(),
                    place: None,
                    source_names: Vec::new(),
                }],
            },
        ];
        if clean_after_callback {
            events.push(FlowEvent::Assign {
                span: span(80, 88),
                target: "term".to_string(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: Some(AssignValueKind::Literal),
            });
        }
        events.push(FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(95, 98),
                name: None,
                value_text: "prefix + term".to_string(),
                place: None,
                source_names: vec!["term".to_string()],
            }],
        });
        events
    };
    let options = TransferOptions {
        callback_invocations: vec![crate::transfer::CallbackInvocationSpec {
            callee: "items.forEach".to_string(),
            callback_arg_index: 0,
            callback_map_field_path: Vec::new(),
            forwarded_argument_field_path: Vec::new(),
            forwarded_callback_param_index: None,
            forwarded_args_from: None,
            receiver_to_callback_param: Some(0),
            callback_return_result_offset: 0,
            resolved_call_sites: vec![invocation_span],
            resolved_callback_targets: vec![(invocation_span, callback_func)],
        }],
        ..TransferOptions::default()
    };
    let mut callback = empty_decl(callback_func.raw(), "callback");
    callback.params = vec!["item".to_string()];
    callback.flow_events = vec![FlowEvent::Assign {
        span: callback_write_span,
        target: "term".to_string(),
        source_name: Some("item".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::Compound),
    }];

    let build = |clean_after_callback: bool| {
        let mut host = empty_decl(host_func.raw(), "host");
        host.params = vec!["items".to_string()];
        host.flow_events = host_events(clean_after_callback);
        let mut resolver = MockResolver::new();
        resolver.add_callable_arg_span(host_func, callback_arg_span, vec![callback_func]);
        resolver.add_local_binding(host_func, callback_func);
        stitch_idg(
            vec![
                transfer_function_for_with_options(&host, &options),
                transfer_function_for(&callback),
            ],
            &resolver,
            &StaticF2S(AHashMap::from([
                (host_func, SegmentId(0)),
                (callback_func, SegmentId(0)),
            ])),
        )
    };
    let reaches_sink = |ws: IdgWorkspace| {
        let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
        let evidence = service.forward_closure_evidence_within_funcs(
            &service.param_nodes_of(host_func),
            &AHashSet::from([host_func, callback_func]),
        );
        let tainted = service
            .tainted_call_args_in_reachable_nodes(&evidence.nodes)
            .clone();
        tainted
            .iter()
            .any(|(func, site, index)| *func == host_func && *site == sink_span && *index == 0)
    };

    assert!(
        reaches_sink(build(false)),
        "the exact collection callback must publish its captured write into a later call argument"
    );
    assert!(
        !reaches_sink(build(true)),
        "a later clean write must kill the callback-published value before the call argument"
    );
}

/// FuncToSegment that maps each FuncId via a precomputed map.
struct StaticF2S(AHashMap<FuncId, SegmentId>);

impl FuncToSegment for StaticF2S {
    fn segment_for(&self, func: FuncId) -> Option<SegmentId> {
        self.0.get(&func).copied()
    }
}

fn node_place(segment: &IdgSegment, node: NodeId) -> Option<&Place> {
    segment
        .nodes
        .get(node)
        .and_then(|node| segment.places.get(node.place))
}

fn call_arg_idx(segment: &IdgSegment, node: NodeId) -> Option<u32> {
    match node_place(segment, node)? {
        Place::CallArg { idx, .. } => Some(*idx),
        _ => None,
    }
}

#[test]
fn segment_endpoint_scan_index_preserves_canonical_node_and_edge_rows() {
    let first_func = FuncId::new(0);
    let second_func = FuncId::new(1);
    let mut first = empty_decl(first_func.raw(), "first");
    first.params = vec!["input".to_string()];
    first.flow_events = vec![FlowEvent::Assign {
        span: span(20, 30),
        target: "copy".to_string(),
        source_name: Some("input".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::Compound),
    }];
    let mut second = empty_decl(second_func.raw(), "second");
    second.params = vec!["value".to_string()];
    second.flow_events = vec![FlowEvent::Assign {
        span: span(40, 50),
        target: "result".to_string(),
        source_name: Some("value".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::Compound),
    }];
    let ws = stitch_idg(
        vec![transfer_function_for(&first), transfer_function_for(&second)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([
            (first_func, SegmentId(0)),
            (second_func, SegmentId(0)),
        ])),
    );
    let segment = ws.segment(SegmentId(0)).expect("shared segment");
    let funcs = [first_func, second_func];
    let index = SegmentEndpointScanIndex::new(segment, &funcs);

    for func in funcs {
        let expected = segment
            .nodes
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.func == func)
            .map(|(node, _)| NodeId(u32::try_from(node).expect("test node id")))
            .collect::<Vec<_>>();
        assert_eq!(index.function_nodes(func), expected);
    }
    for node in 0..segment.nodes.nodes.len() {
        let node = NodeId(u32::try_from(node).expect("test node id"));
        let expected_incoming = segment
            .edges
            .iter()
            .filter(|edge| edge.to == node)
            .copied()
            .collect::<Vec<_>>();
        let expected_outgoing = segment
            .edges
            .iter()
            .filter(|edge| edge.from == node)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            index.incoming(segment, node).copied().collect::<Vec<_>>(),
            expected_incoming
        );
        assert_eq!(
            index.outgoing(segment, node).copied().collect::<Vec<_>>(),
            expected_outgoing
        );
    }
}

fn param_idx(segment: &IdgSegment, node: NodeId) -> Option<u32> {
    match node_place(segment, node)? {
        Place::Param { idx } => Some(*idx),
        _ => None,
    }
}

#[test]
fn empty_outputs_produce_empty_workspace() {
    let resolver = MockResolver::new();
    let f2s = StaticF2S(AHashMap::new());
    let ws = stitch_idg(Vec::new(), &resolver, &f2s);
    assert_eq!(ws.segment_count(), 0);
    assert_eq!(ws.total_edge_count(), 0);
}

#[test]
fn single_function_no_calls_creates_one_segment() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let out = transfer_function_for(&decl);

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    let f2s = StaticF2S(f2s_map);
    let resolver = MockResolver::new();
    let ws = stitch_idg(vec![out], &resolver, &f2s);

    assert_eq!(ws.segment_count(), 1);
    assert!(ws.segment_for_func(FuncId::new(1)).is_some());
    // Three intra edges: Param→Read(x), Read(x)→Return, and
    // x→return-field storage for field-sensitive return propagation.
    assert_eq!(ws.intra_edge_count(), 3);
}

#[test]
fn spooled_stitch_preserves_the_exact_canonical_graph() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let output = transfer_function_for(&decl);
    let batches = || vec![vec![(SegmentId(0), vec![output.clone()])]];
    let resolver = MockResolver::new();

    let queryable = stitch_idg_from_segment_batches(batches(), 1, &resolver, true, false, None);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spooled-idg.factstore");
    let persisted = stitch_idg_from_spooled_segment_batches(
        batches(),
        1,
        &resolver,
        SpooledStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: None,
        },
    )
    .expect("spooled stitch");
    persisted
        .save_into_disk(&path, 0x51DE_CAFE)
        .expect("persist spooled graph");
    let persisted = IdgWorkspace::load_from_disk(&path, 0x51DE_CAFE)
        .expect("load spooled graph")
        .expect("spooled graph exists");

    let queryable_wire = bonsai_common::wire::encode(&queryable).expect("encode queryable IDG");
    let persisted_wire = bonsai_common::wire::encode(&persisted).expect("encode persisted IDG");
    assert_eq!(persisted_wire, queryable_wire);
}

#[test]
fn spooled_stitch_rejects_duplicate_compiler_segments_without_panicking() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["x".to_string()];
    let output = transfer_function_for(&decl);
    let batches = vec![vec![
        (SegmentId(0), vec![output.clone()]),
        (SegmentId(0), vec![output]),
    ]];
    let resolver = MockResolver::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("duplicate-segment.factstore");

    let error = stitch_idg_from_spooled_segment_batches(
        batches,
        2,
        &resolver,
        SpooledStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: None,
        },
    )
    .expect_err("duplicate compiler segment must be rejected");

    assert!(matches!(error, crate::IdgError::Invariant(message) if message.contains("repeated segment 0")));
}

#[test]
fn spooled_sidecar_preserves_cross_segment_calls_byte_for_byte() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["source".to_string()];
    caller.flow_events = vec![FlowEvent::Call {
        span: span(20, 30),
        name: "callee".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(24, 29),
            name: None,
            value_text: "source".to_string(),
            place: Some("source".to_string()),
            source_names: vec!["source".to_string()],
        }],
    }];
    let mut callee = empty_decl(2, "callee");
    callee.params = vec!["value".to_string()];
    callee.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(40, 50),
        value_name: Some("value".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("value"),
    }];
    let caller_out = transfer_function_for(&caller);
    let callee_out = transfer_function_for(&callee);
    let batches = || {
        vec![vec![
            (SegmentId(0), vec![caller_out.clone()]),
            // Compiler schedules are keyed by source-file segment and may
            // contain gaps for files without functions. Workspace segment ids
            // remain dense and must be translated explicitly on pass two.
            (SegmentId(2), vec![callee_out.clone()]),
        ]]
    };
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "callee", vec![FuncId::new(2)]);
    let queryable = stitch_idg_from_segment_batches(batches(), 2, &resolver, true, false, None);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cross-segment.factstore");
    let persisted = stitch_idg_from_spooled_segment_batches(
        batches(),
        2,
        &resolver,
        SpooledStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: None,
        },
    )
    .expect("spooled stitch");
    assert_eq!(
        persisted.cross_file_edge_count(),
        queryable.cross_file().len(),
        "sidecar compilation must count every disk-spooled cross edge"
    );
    assert!(
        persisted.cross_file().is_empty(),
        "sidecar compilation must not retain its canonical cross-edge vector in memory"
    );
    persisted
        .save_into_disk(&path, 0xC205_5E6A)
        .expect("persist cross-segment spool");
    let persisted = IdgWorkspace::load_from_disk(&path, 0xC205_5E6A)
        .expect("load cross-segment sidecar")
        .expect("cross-segment sidecar exists");

    assert_eq!(queryable.cross_file().len(), 2);
    assert_eq!(
        bonsai_common::wire::encode(&persisted).expect("encode persisted cross-segment IDG"),
        bonsai_common::wire::encode(&queryable).expect("encode queryable cross-segment IDG")
    );
}

#[test]
fn spooled_sidecar_preserves_symbolic_field_graph_byte_for_byte() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["source".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 18),
            target: "box.live".to_string(),
            source_name: Some("source".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(18, 20),
            target: "copy".to_string(),
            source_name: Some("box".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(20, 35),
            name: "callee".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(27, 30),
                name: None,
                value_text: "box".to_string(),
                place: Some("box".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];
    let mut callee = empty_decl(2, "callee");
    callee.params = vec!["arg".to_string()];
    callee.flow_events = vec![FlowEvent::Call {
        span: span(40, 55),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(45, 53),
            name: None,
            value_text: "arg.live".to_string(),
            place: Some("arg.live".to_string()),
            source_names: vec!["arg.live".to_string()],
        }],
    }];
    let caller_out = transfer_function_for(&caller);
    let callee_out = transfer_function_for(&callee);
    let batches = || {
        vec![vec![
            (SegmentId(0), vec![caller_out.clone()]),
            (SegmentId(1), vec![callee_out.clone()]),
        ]]
    };
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "callee", vec![FuncId::new(2)]);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("symbolic.factstore");
    for symbolic_funcs in [
        AHashSet::from([FuncId::new(1), FuncId::new(2)]),
        AHashSet::from([FuncId::new(1)]),
    ] {
        let queryable =
            stitch_idg_from_segment_batches(batches(), 2, &resolver, true, true, Some(&symbolic_funcs));
        if symbolic_funcs.contains(&FuncId::new(1)) {
            assert!(
                queryable
                    .symbolic_field()
                    .transforms()
                    .iter()
                    .any(|transform| transform.kind == SymbolicFieldTransformKind::Copy),
                "fixture must exercise the symbolic copy spool"
            );
        }
        let persisted = stitch_idg_from_spooled_segment_batches(
            batches(),
            2,
            &resolver,
            SpooledStitchOptions {
                spool_path: &path,
                include_field_argument_forwarding: true,
                symbolic_field_forwarding: true,
                symbolic_funcs: Some(&symbolic_funcs),
                capture_funcs: None,
            },
        )
        .expect("spooled symbolic stitch");
        assert_eq!(
            persisted.symbolic_transform_count(),
            queryable.symbolic_field().transforms().len(),
            "sidecar compilation must count every disk-spooled symbolic transform"
        );
        assert!(
            persisted.symbolic_field().transforms().is_empty(),
            "sidecar compilation must not retain symbolic transforms in memory"
        );
        persisted
            .save_into_disk(&path, 0x51A0_B01C)
            .expect("persist symbolic transform spool");
        let persisted = IdgWorkspace::load_from_disk(&path, 0x51A0_B01C)
            .expect("load symbolic sidecar")
            .expect("symbolic sidecar exists");

        assert_eq!(
            bonsai_common::wire::encode(&persisted).expect("encode persisted symbolic IDG"),
            bonsai_common::wire::encode(&queryable).expect("encode queryable symbolic IDG")
        );
    }
}

#[test]
fn receiver_consumers_follow_declared_metadata_not_identifier_spelling() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["obj".to_string()];
    caller.flow_events = vec![
        FlowEvent::Call {
            span: span(20, 30),
            name: "consume".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Call {
            span: span(40, 50),
            name: "ordinary".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut declared = empty_decl(2, "consume");
    declared.kind = DeclKind::Method;
    declared.implicit_receiver_names = vec!["me".to_string()];
    declared.flow_events = vec![FlowEvent::Call {
        span: span(60, 70),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(65, 67),
            name: None,
            value_text: "me".to_string(),
            place: Some("me".to_string()),
            source_names: vec!["me".to_string()],
        }],
    }];

    let mut ordinary = empty_decl(3, "ordinary");
    ordinary.kind = DeclKind::Method;
    ordinary.implicit_receiver_names = vec!["me".to_string()];
    ordinary.flow_events = vec![FlowEvent::Call {
        span: span(80, 90),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(85, 87),
            name: None,
            value_text: "ordinary_value".to_string(),
            place: Some("ordinary_value".to_string()),
            source_names: vec!["ordinary_value".to_string()],
        }],
    }];

    let funcs = [FuncId::new(1), FuncId::new(2), FuncId::new(3)];
    let f2s = StaticF2S(funcs.into_iter().map(|func| (func, SegmentId(0))).collect());
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "consume", vec![FuncId::new(2)]);
    resolver.add(FuncId::new(1), "ordinary", vec![FuncId::new(3)]);
    let ws = stitch_idg(
        vec![
            transfer_function_for(&caller),
            transfer_function_for(&declared),
            transfer_function_for(&ordinary),
        ],
        &resolver,
        &f2s,
    );
    let segment = ws.segment(SegmentId(0)).expect("single segment");

    let edge_targets_named = |callee: FuncId, expected: &str| {
        segment.edges.iter().any(|edge| {
            if edge.meta.kind != IdgEdgeKind::InterCallArg {
                return false;
            }
            let Some(from_node) = segment.nodes.get(edge.from) else {
                return false;
            };
            let Some(to_node) = segment.nodes.get(edge.to) else {
                return false;
            };
            if from_node.func != FuncId::new(1)
                || to_node.func != callee
                || call_arg_idx(segment, edge.from) != Some(u32::MAX)
            {
                return false;
            }
            matches!(
                node_place(segment, edge.to),
                Some(Place::Read { name, path })
                    if path.is_empty() && segment.strings.get(*name) == Some(expected)
            )
        })
    };

    assert!(edge_targets_named(FuncId::new(2), "me"));
    assert!(
        !edge_targets_named(FuncId::new(3), "ordinary_value"),
        "an ordinary identifier must not become a receiver consumer"
    );
}

#[test]
fn two_funcs_in_same_segment_call_each_other_no_cross_file_edge() {
    // f calls g; both in segment 0.
    let mut f = empty_decl(1, "f");
    f.flow_events = vec![FlowEvent::Call {
        span: span(20, 30),
        name: "g".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(22, 23),
            name: None,
            value_text: "x".to_string(),
            place: Some("x".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut g = empty_decl(2, "g");
    g.params = vec!["arg".to_string()];

    let out_f = transfer_function_for(&f);
    let out_g = transfer_function_for(&g);

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(0));
    let f2s = StaticF2S(f2s_map);

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "g", vec![FuncId::new(2)]);

    let ws = stitch_idg(vec![out_f, out_g], &resolver, &f2s);

    assert_eq!(ws.segment_count(), 1);
    // Cross-file index should be empty — both funcs same segment.
    assert!(ws.cross_file().is_empty());
}

#[test]
fn same_named_value_argument_is_not_invented_as_a_callback() {
    let mut host = empty_decl(1, "host");
    host.params = vec!["payload".to_string(), "text".to_string()];
    host.flow_events = vec![FlowEvent::Call {
        span: span(20, 40),
        name: "client.send".to_string(),
        receiver: Some("client".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: vec![
            CallArg {
                passing_mode: Default::default(),
                span: span(28, 31),
                name: None,
                value_text: "payload".to_string(),
                place: Some("payload".to_string()),
                source_names: Vec::new(),
            },
            CallArg {
                passing_mode: Default::default(),
                span: span(33, 37),
                name: None,
                value_text: "text".to_string(),
                place: Some("text".to_string()),
                source_names: Vec::new(),
            },
        ],
    }];
    let mut same_named_method = empty_decl(2, "text");
    same_named_method.params = vec!["value".to_string()];

    let mut resolver = MockResolver::new();
    resolver.add_callable_arg(FuncId::new(1), "text", vec![FuncId::new(2)]);
    let ws = stitch_idg(
        vec![
            transfer_function_for(&host),
            transfer_function_for(&same_named_method),
        ],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
    );

    assert!(
        ws.cross_file().edges.iter().all(|edge| {
            edge.edge.meta.kind != IdgEdgeKind::InterCallArg
                || ws
                    .segment(edge.to_segment)
                    .and_then(|segment| segment.nodes.get(edge.edge.to))
                    .is_none_or(|node| node.func != FuncId::new(2))
        }),
        "ordinary values need AST/type evidence before they can invoke a same-named declaration: {:#?}",
        ws.cross_file().edges
    );
}

#[test]
fn rule_compiled_callback_return_reaches_only_the_declared_tuple_result() {
    let host_func = FuncId::new(1);
    let callback_func = FuncId::new(2);
    let invocation_span = span(20, 25);
    let callback_arg_span = span(26, 50);
    let assignment_span = span(10, 52);
    let sink_span = span(70, 78);

    let mut host = empty_decl(host_func.raw(), "host");
    host.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "ok".to_string(),
            source_name: None,
            source_call: Some("runtime_call".to_string()),
            source_call_args: vec!["callback".to_string()],
            source_names: vec![format!(
                "{}0",
                bonsai_lang_api::kit::SYNTHETIC_TUPLE_RESULT_PREFIX
            )],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: assignment_span,
            target: "value".to_string(),
            source_name: None,
            source_call: Some("runtime_call".to_string()),
            source_call_args: vec!["callback".to_string()],
            source_names: vec![format!(
                "{}1",
                bonsai_lang_api::kit::SYNTHETIC_TUPLE_RESULT_PREFIX
            )],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: invocation_span,
            name: "runtime_call".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: callback_arg_span,
                name: None,
                value_text: "callback".to_string(),
                place: None,
                source_names: Vec::new(),
            }],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(75, 76),
                name: None,
                value_text: "value".to_string(),
                place: Some("value".to_string()),
                source_names: vec!["value".to_string()],
            }],
        },
    ];
    let options = TransferOptions {
        callback_invocations: vec![crate::transfer::CallbackInvocationSpec {
            callee: "runtime_call".to_string(),
            callback_arg_index: 0,
            callback_map_field_path: Vec::new(),
            forwarded_argument_field_path: Vec::new(),
            forwarded_callback_param_index: None,
            forwarded_args_from: None,
            receiver_to_callback_param: None,
            callback_return_result_offset: 1,
            resolved_call_sites: vec![invocation_span],
            resolved_callback_targets: Vec::new(),
        }],
        ..TransferOptions::default()
    };

    let mut callback = empty_decl(callback_func.raw(), "callback");
    callback.params = vec!["source".to_string()];
    callback.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: callback_arg_span,
        value_name: Some("source".to_string()),
        value_text: Some("source".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("source"),
    }];

    let mut resolver = MockResolver::new();
    resolver.add_callable_arg_span(host_func, callback_arg_span, vec![callback_func]);
    let ws = stitch_idg(
        vec![
            transfer_function_for_with_options(&host, &options),
            transfer_function_for(&callback),
        ],
        &resolver,
        &StaticF2S(AHashMap::from([
            (host_func, SegmentId(0)),
            (callback_func, SegmentId(0)),
        ])),
    );
    let segment = ws.segment(SegmentId(0)).expect("shared segment");
    let storage = |node: NodeId| {
        node_place(segment, node)
            .and_then(|place| place_storage_name(segment, place))
            .unwrap_or_default()
    };
    assert!(segment.edges.iter().any(|edge| {
        edge.meta.kind == IdgEdgeKind::InterReturn
            && matches!(node_place(segment, edge.from), Some(Place::Return))
            && storage(edge.to) == format!("value.{}1", bonsai_lang_api::kit::SYNTHETIC_TUPLE_RESULT_PREFIX)
    }));
    assert!(!segment.edges.iter().any(|edge| {
        edge.meta.kind == IdgEdgeKind::InterReturn
            && storage(edge.to) == format!("ok.{}0", bonsai_lang_api::kit::SYNTHETIC_TUPLE_RESULT_PREFIX)
    }));

    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let seed = service.param_nodes_of(callback_func);
    let evidence =
        service.forward_closure_evidence_within_funcs(&seed, &AHashSet::from([host_func, callback_func]));
    assert!(
        service
            .tainted_call_args_in_reachable_nodes(&evidence.nodes)
            .iter()
            .any(|(func, site, index)| *func == host_func && *site == sink_span && *index == 0),
        "the callback return must reach the sink through tuple result one"
    );
    assert!(evidence.cross_calls.iter().any(|edge| {
        edge.caller == callback_func
            && edge.callee == host_func
            && edge.call_span == invocation_span
            && edge.relation == crate::CrossCallRelation::Return
    }));
}

#[test]
fn rule_compiled_direct_callback_return_preserves_aggregate_fields() {
    let host_func = FuncId::new(1);
    let callback_func = FuncId::new(2);
    let invocation_span = span(20, 25);
    let callback_arg_span = span(26, 50);
    let assignment_span = span(10, 52);
    let sink_span = span(70, 78);

    let mut host = empty_decl(host_func.raw(), "host");
    host.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "value".to_string(),
            source_name: None,
            source_call: Some("runtime_call".to_string()),
            source_call_args: vec!["callback".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: invocation_span,
            name: "runtime_call".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: callback_arg_span,
                name: None,
                value_text: "callback".to_string(),
                place: None,
                source_names: Vec::new(),
            }],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(75, 76),
                name: None,
                value_text: "value.cmd".to_string(),
                place: Some("value.cmd".to_string()),
                source_names: vec!["value.cmd".to_string()],
            }],
        },
    ];
    let options = TransferOptions {
        callback_invocations: vec![crate::transfer::CallbackInvocationSpec {
            callee: "runtime_call".to_string(),
            callback_arg_index: 0,
            callback_map_field_path: Vec::new(),
            forwarded_argument_field_path: Vec::new(),
            forwarded_callback_param_index: None,
            forwarded_args_from: None,
            receiver_to_callback_param: None,
            callback_return_result_offset: 0,
            resolved_call_sites: vec![invocation_span],
            resolved_callback_targets: Vec::new(),
        }],
        ..TransferOptions::default()
    };

    let mut callback = empty_decl(callback_func.raw(), "callback");
    callback.params = vec!["source".to_string()];
    callback.flow_events = vec![FlowEvent::Return {
        value_kind: Some(AssignValueKind::Compound),
        span: callback_arg_span,
        value_name: None,
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                name: "cmd".to_string(),
                value_span: Some(callback_arg_span),
                value: bonsai_lang_api::ExpressionFlow::from_place("source"),
            }],
            ..Default::default()
        },
    }];

    let mut resolver = MockResolver::new();
    resolver.add_callable_arg_span(host_func, callback_arg_span, vec![callback_func]);
    let ws = stitch_idg(
        vec![
            transfer_function_for_with_options(&host, &options),
            transfer_function_for(&callback),
        ],
        &resolver,
        &StaticF2S(AHashMap::from([
            (host_func, SegmentId(0)),
            (callback_func, SegmentId(0)),
        ])),
    );
    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let seed = service.param_nodes_of(callback_func);
    let evidence =
        service.forward_closure_evidence_within_funcs(&seed, &AHashSet::from([host_func, callback_func]));
    assert!(
        service
            .tainted_call_args_in_reachable_nodes(&evidence.nodes)
            .iter()
            .any(|(func, site, index)| *func == host_func && *site == sink_span && *index == 0),
        "the callback's exact returned cmd field must reach the assigned host result"
    );
}

#[test]
fn two_funcs_in_different_segments_call_creates_cross_file_edges() {
    let mut f = empty_decl(1, "f");
    f.flow_events = vec![FlowEvent::Call {
        span: span(20, 30),
        name: "g".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(22, 23),
            name: None,
            value_text: "x".to_string(),
            place: Some("x".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut g = empty_decl(2, "g");
    g.params = vec!["arg".to_string()];
    g.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("arg"),
    }];

    let out_f = transfer_function_for(&f);
    let out_g = transfer_function_for(&g);

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    let f2s = StaticF2S(f2s_map);

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "g", vec![FuncId::new(2)]);

    let ws = stitch_idg(vec![out_f, out_g], &resolver, &f2s);

    // Two segments registered.
    assert_eq!(ws.segment_count(), 2);
    // Cross-file edges expected:
    //   f.CallArg(site, 0) → g.Param(0)  (1 edge)
    //   g.Return → f.CallRet(site)        (1 edge)
    assert_eq!(ws.cross_file().len(), 2);
    // One InterCallArg + one InterReturn.
    let kinds: Vec<IdgEdgeKind> = ws.cross_file().edges.iter().map(|e| e.edge.meta.kind).collect();
    assert!(kinds.contains(&IdgEdgeKind::InterCallArg));
    assert!(kinds.contains(&IdgEdgeKind::InterReturn));
}

#[test]
fn callback_formal_position_above_255_resolves_without_truncation() {
    let mut host = empty_decl(1, "host");
    host.params = (0..299)
        .map(|idx| format!("p{idx}"))
        .chain(std::iter::once("callback".to_string()))
        .collect();
    host.flow_events = vec![FlowEvent::Call {
        span: span(20, 35),
        name: "callback".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(28, 30),
            name: None,
            value_text: "p0".to_string(),
            place: Some("p0".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut callback = empty_decl(2, "bound_callback");
    callback.params = vec!["value".to_string()];

    let mut resolver = MockResolver::new();
    resolver.add_callback_binding(FuncId::new(1), 299, vec![FuncId::new(2)]);
    let ws = stitch_idg(
        vec![transfer_function_for(&host), transfer_function_for(&callback)],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("host segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callback segment");
    assert!(
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterCallArg
                && call_arg_idx(caller_segment, edge.edge.from) == Some(0)
                && param_idx(callee_segment, edge.edge.to) == Some(0)
                && edge.edge.meta.call_kind == CallEdgeKind::Indirect
        }),
        "callback formal 299 must resolve to the bound callback"
    );
}

#[test]
fn receiver_form_callback_uses_exact_adapter_binding_identity() {
    let mut host = empty_decl(1, "host");
    host.params = vec!["callback".to_string(), "value".to_string()];
    host.flow_events = vec![FlowEvent::Call {
        span: span(20, 40),
        name: "callback.accept".to_string(),
        receiver: Some("callback".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(36, 39),
            name: None,
            value_text: "value".to_string(),
            place: Some("value".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut callback = empty_decl(2, "bound_callback");
    callback.params = vec!["input".to_string()];

    let mut resolver = MockResolver::new();
    resolver.add_callback_binding(FuncId::new(1), 0, vec![FuncId::new(2)]);
    let ws = stitch_idg(
        vec![transfer_function_for(&host), transfer_function_for(&callback)],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("host segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callback segment");
    assert!(
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterCallArg
                && call_arg_idx(caller_segment, edge.edge.from) == Some(0)
                && param_idx(callee_segment, edge.edge.to) == Some(0)
                && edge.edge.meta.call_kind == CallEdgeKind::Indirect
        }),
        "adapter-emitted receiver binding must resolve the callback"
    );
}

#[test]
fn unresolved_call_emits_no_inter_edge() {
    let mut f = empty_decl(1, "f");
    f.flow_events = vec![FlowEvent::Call {
        span: span(20, 30),
        name: "missing".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: Vec::new(),
    }];

    let out_f = transfer_function_for(&f);

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    let f2s = StaticF2S(f2s_map);
    let resolver = MockResolver::new(); // empty — `missing` unresolved.

    let ws = stitch_idg(vec![out_f], &resolver, &f2s);
    assert!(ws.cross_file().is_empty());
}

#[test]
fn compatibility_mode_stitches_unresolved_assignment_args_to_result() {
    let mut f = empty_decl(1, "f");
    f.params = vec!["input".to_string()];
    f.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 40),
            target: "out".to_string(),
            source_name: None,
            source_call: Some("external_transform".to_string()),
            source_call_args: vec!["input".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(24, 36),
            name: "external_transform".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(31, 35),
                name: None,
                value_text: "input".to_string(),
                place: Some("input".to_string()),
                source_names: vec!["input".to_string()],
            }],
        },
    ];
    let options = TransferOptions {
        include_unresolved_call_result_passthrough: true,
        ..TransferOptions::default()
    };
    let out_f = transfer_function_for_with_options(&f, &options);

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    let mut resolver = MockResolver::new();
    // A declaration-like resolver hit with no transferred function body is
    // still external from the IDG's perspective and must use the fallback.
    resolver.add(FuncId::new(1), "external_transform", vec![FuncId::new(99)]);
    let ws = stitch_idg(vec![out_f], &resolver, &StaticF2S(f2s_map));
    let segment = ws
        .segment_for_func(FuncId::new(1))
        .and_then(|id| ws.segment(id))
        .expect("segment");
    assert!(segment.edges.iter().any(|edge| {
        matches!(
            node_place(segment, edge.from),
            Some(Place::CallArg { idx: 0, .. })
        ) && matches!(node_place(segment, edge.to), Some(Place::CallRet { .. }))
    }));
}

#[test]
fn receiver_only_policy_stitches_syntax_classified_method_receiver_to_result() {
    let mut f = empty_decl(1, "f");
    f.params = vec!["client".to_string()];
    f.flow_events = vec![FlowEvent::Call {
        span: span(20, 40),
        name: "client.capacity".to_string(),
        receiver: Some("client".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    }];
    let options = TransferOptions {
        include_unresolved_receiver_result_passthrough: true,
        ..TransferOptions::default()
    };
    let out_f = transfer_function_for_with_options(&f, &options);
    assert_eq!(out_f.call_sites[0].explicit_args_count, 0);
    assert!(
        out_f.call_sites[0].receiver_arg_node.is_some(),
        "the adapter-shaped zero-arg method should expose its receiver carrier"
    );

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    let ws = stitch_idg(vec![out_f], &MockResolver::new(), &StaticF2S(f2s_map));
    let segment = ws
        .segment_for_func(FuncId::new(1))
        .and_then(|id| ws.segment(id))
        .expect("segment");
    assert!(segment.edges.iter().any(|edge| {
        matches!(
            node_place(segment, edge.from),
            Some(Place::CallArg { idx: u32::MAX, .. })
        ) && matches!(node_place(segment, edge.to), Some(Place::CallRet { .. }))
    }));
}

#[test]
fn tainted_method_receiver_does_not_taint_literal_explicit_argument() {
    let call_span = span(30, 42);
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["client".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 60),
            target: "_".to_string(),
            source_name: None,
            source_call: Some("client.send".to_string()),
            source_call_args: vec!["\"fixed request\"".to_string()],
            source_names: vec!["client".to_string(), "payload".to_string()],
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: call_span,
            name: "client.send".to_string(),
            receiver: Some("client".to_string()),
            receiver_types: vec!["Client".to_string()],
            call_kind: CallKind::Method,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(43, 58),
                name: Some("payload".to_string()),
                value_text: "\"fixed request\"".to_string(),
                place: None,
                source_names: Vec::new(),
            }],
        },
    ];

    let options = TransferOptions::compiler_semantics(vec!["swift".to_string()]);
    let ws = stitch_idg(
        vec![transfer_function_for_with_options(&caller, &options)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let closure = service.forward_closure(&service.param_nodes_of(FuncId::new(1)));
    let tainted_call_inputs = service.tainted_call_args_in_reachable_nodes(&closure);

    assert!(
        tainted_call_inputs.iter().any(|(func, site, index)| {
            *func == FuncId::new(1) && *site == call_span && *index == u32::MAX
        }),
        "the receiver parameter must reach the compiler's receiver slot: {tainted_call_inputs:#?}"
    );
    assert!(
        tainted_call_inputs
            .iter()
            .all(|(func, site, index)| { *func != FuncId::new(1) || *site != call_span || *index != 0 }),
        "a tainted receiver must not taint an independent literal argument: {tainted_call_inputs:#?}"
    );
}

#[test]
fn resolved_nonmutator_does_not_copy_arguments_into_receiver_in_security_mode() {
    let call_span = span(20, 40);
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["client".to_string(), "input".to_string()];
    caller.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "client.observe".to_string(),
        receiver: Some("client".to_string()),
        receiver_types: vec!["Client".to_string()],
        call_kind: CallKind::Method,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(32, 37),
            name: None,
            value_text: "input".to_string(),
            place: Some("input".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut callee = empty_decl(2, "observe");
    callee.params = vec!["self".to_string(), "value".to_string()];
    callee.receiver_param_index = Some(0);

    let security_options = TransferOptions {
        include_diagnostic_field_flows: false,
        include_receiver_method_propagation: false,
        include_field_argument_forwarding: true,
        include_unresolved_call_result_passthrough: true,
        include_unresolved_receiver_result_passthrough: false,
        ..TransferOptions::default()
    };
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "client.observe", vec![FuncId::new(2)]);
    let ws = stitch_idg(
        vec![
            transfer_function_for_with_options(&caller, &security_options),
            transfer_function_for_with_options(&callee, &security_options),
        ],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");

    assert!(
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterCallArg
                && call_arg_idx(caller_segment, edge.edge.from) == Some(0)
                && param_idx(callee_segment, edge.edge.to) == Some(1)
        }),
        "the resolver-proven argument must still stitch to its formal parameter"
    );
    assert!(
        !caller_segment.edges.iter().any(|edge| {
            edge.meta.kind == IdgEdgeKind::IntraAssign
                && matches!(
                    node_place(caller_segment, edge.to),
                    Some(Place::Write { span, .. }) if *span == call_span
                )
                && place_storage_name(
                    caller_segment,
                    node_place(caller_segment, edge.to).expect("receiver write"),
                )
                .as_deref()
                    == Some("client")
        }),
        "unresolved-result fallback must not invent an exact argument-to-receiver state write for a resolved nonmutator"
    );
}

#[test]
fn syntax_classified_constructor_stitches_args_to_result_without_compatibility_mode() {
    let mut f = empty_decl(1, "f");
    f.params = vec!["input".to_string()];
    f.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 40),
            target: "boxed".to_string(),
            source_name: None,
            source_call: Some("ExternalBox".to_string()),
            source_call_args: vec!["input".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: span(24, 36),
            name: "ExternalBox".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Constructor,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(31, 35),
                name: None,
                value_text: "input".to_string(),
                place: Some("input".to_string()),
                source_names: vec!["input".to_string()],
            }],
        },
    ];
    let out_f = transfer_function_for(&f);
    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    let ws = stitch_idg(vec![out_f], &MockResolver::new(), &StaticF2S(f2s_map));
    let segment = ws
        .segment_for_func(FuncId::new(1))
        .and_then(|id| ws.segment(id))
        .expect("segment");
    assert!(segment.edges.iter().any(|edge| {
        matches!(
            node_place(segment, edge.from),
            Some(Place::CallArg { idx: 0, .. })
        ) && matches!(node_place(segment, edge.to), Some(Place::CallRet { .. }))
    }));
}

#[test]
fn virtual_dispatch_emits_one_edge_per_candidate() {
    // f calls "method"; resolver returns two candidates (g, h).
    let mut f = empty_decl(1, "f");
    f.flow_events = vec![FlowEvent::Call {
        span: span(20, 30),
        name: "method".to_string(),
        receiver: Some("obj".to_string()),
        receiver_types: vec!["Iface".to_string()],
        call_kind: bonsai_lang_api::CallKind::Method,
        args: Vec::new(),
    }];
    let g = empty_decl(2, "g");
    let h = empty_decl(3, "h");

    let outs = vec![
        transfer_function_for(&f),
        transfer_function_for(&g),
        transfer_function_for(&h),
    ];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    f2s_map.insert(FuncId::new(3), SegmentId(2));
    let f2s = StaticF2S(f2s_map);
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "method", vec![FuncId::new(2), FuncId::new(3)]);

    let ws = stitch_idg(outs, &resolver, &f2s);
    // Two candidates × at least 1 edge per candidate
    // (the InterReturn). Args count is 0 so no CallArg edges.
    // → at least 2 cross-file edges (two InterReturns).
    assert!(ws.cross_file().len() >= 2);
}

#[test]
fn method_receiver_param_stitches_without_shifting_explicit_args() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["repo".to_string(), "payload".to_string()];
    caller.flow_events = vec![FlowEvent::Call {
        span: span(20, 40),
        name: "persist".to_string(),
        receiver: Some("repo".to_string()),
        receiver_types: vec!["Repository".to_string()],
        call_kind: CallKind::Method,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(31, 38),
            name: None,
            value_text: "payload".to_string(),
            place: Some("payload".to_string()),
            source_names: Vec::new(),
        }],
    }];

    let mut callee = empty_decl(2, "persist");
    callee.params = vec!["self".to_string(), "cmd".to_string()];
    callee.receiver_param_index = Some(0);

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    let f2s = StaticF2S(f2s_map);

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "persist", vec![FuncId::new(2)]);

    let ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&callee)],
        &resolver,
        &f2s,
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");
    let arg_to_param = ws
        .cross_file()
        .edges
        .iter()
        .filter(|edge| edge.edge.meta.kind == IdgEdgeKind::InterCallArg)
        .map(|edge| {
            (
                call_arg_idx(caller_segment, edge.edge.from),
                param_idx(callee_segment, edge.edge.to),
            )
        })
        .collect::<Vec<_>>();

    assert!(
        arg_to_param.contains(&(Some(u32::MAX), Some(0))),
        "receiver slot should stitch to self param: {arg_to_param:?}"
    );
    assert!(
        arg_to_param.contains(&(Some(0), Some(1))),
        "explicit arg should stitch to first non-receiver param: {arg_to_param:?}"
    );
    assert!(
        !arg_to_param.contains(&(Some(0), Some(0))),
        "explicit arg must not be shifted into receiver param: {arg_to_param:?}"
    );
}

#[test]
fn three_hundred_positional_arguments_reach_distinct_parameters() {
    const POSITION_COUNT: usize = 300;
    let call_span = span(20, 40);
    let mut caller = empty_decl(1, "caller");
    caller.params = (0..POSITION_COUNT).map(|idx| format!("p{idx}")).collect();
    caller.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "callee".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: (0..POSITION_COUNT)
            .map(|idx| CallArg {
                passing_mode: Default::default(),
                span: span(21 + idx as u64, 22 + idx as u64),
                name: None,
                value_text: format!("p{idx}"),
                place: Some(format!("p{idx}")),
                source_names: Vec::new(),
            })
            .collect(),
    }];
    let mut callee = empty_decl(2, "callee");
    callee.params = (0..POSITION_COUNT).map(|idx| format!("q{idx}")).collect();

    let caller_output = transfer_function_for(&caller);
    assert_eq!(caller_output.call_sites[0].args_count, 300);
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "callee", vec![FuncId::new(2)]);
    let ws = stitch_idg(
        vec![caller_output, transfer_function_for(&callee)],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");
    let param_299 = caller_segment
        .places
        .lookup(&Place::Param { idx: 299 })
        .and_then(|place| caller_segment.nodes.lookup(FuncId::new(1), place))
        .expect("caller param 299");
    let arg_255 = caller_segment
        .places
        .lookup(&Place::CallArg {
            site: CallSiteId(call_span),
            idx: 255,
        })
        .and_then(|place| caller_segment.nodes.lookup(FuncId::new(1), place))
        .expect("real call arg 255");
    let arg_299 = caller_segment
        .places
        .lookup(&Place::CallArg {
            site: CallSiteId(call_span),
            idx: 299,
        })
        .and_then(|place| caller_segment.nodes.lookup(FuncId::new(1), place))
        .expect("real call arg 299");
    assert_ne!(arg_255, arg_299, "positions 255 and 299 must remain distinct");
    assert!(
        caller_segment
            .places
            .lookup(&Place::CallArg {
                site: CallSiteId(call_span),
                idx: u32::MAX,
            })
            .is_none(),
        "the receiver sentinel must not alias real argument 255"
    );
    let local_reach = ReachabilityIndex::new(caller_segment.nodes.len(), &caller_segment.edges);
    assert!(
        local_reach.reaches(param_299, arg_299),
        "caller parameter 299 must propagate into call argument 299"
    );
    assert!(
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterCallArg
                && call_arg_idx(caller_segment, edge.edge.from) == Some(299)
                && param_idx(callee_segment, edge.edge.to) == Some(299)
        }),
        "call argument 299 must stitch to callee parameter 299"
    );
}

#[test]
fn named_arg_stitches_to_matching_param_not_position() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["payload".to_string()];
    caller.flow_events = vec![FlowEvent::Call {
        span: span(20, 48),
        name: "helper".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(27, 40),
            name: Some("name".to_string()),
            value_text: "payload".to_string(),
            place: Some("payload".to_string()),
            source_names: Vec::new(),
        }],
    }];

    let mut callee = empty_decl(2, "helper");
    callee.params = vec!["prefix".to_string(), "name".to_string()];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    let f2s = StaticF2S(f2s_map);

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "helper", vec![FuncId::new(2)]);

    let ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&callee)],
        &resolver,
        &f2s,
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");
    let arg_to_param = ws
        .cross_file()
        .edges
        .iter()
        .filter(|edge| edge.edge.meta.kind == IdgEdgeKind::InterCallArg)
        .map(|edge| {
            (
                call_arg_idx(caller_segment, edge.edge.from),
                param_idx(callee_segment, edge.edge.to),
            )
        })
        .collect::<Vec<_>>();

    assert!(
        arg_to_param.contains(&(Some(0), Some(1))),
        "named arg should stitch to matching `name` param: {arg_to_param:?}"
    );
    assert!(
        !arg_to_param.contains(&(Some(0), Some(0))),
        "named arg must not fall through to the first positional param: {arg_to_param:?}"
    );
}

#[test]
fn field_argument_forwarding_preserves_matching_field_path() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["src".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 18),
            target: "box.cmd".to_string(),
            source_name: Some("src".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(30, 45),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(37, 40),
                name: None,
                value_text: "box".to_string(),
                place: Some("box".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut callee = empty_decl(2, "helper");
    callee.params = vec!["arg".to_string()];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    let f2s = StaticF2S(f2s_map);

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "helper", vec![FuncId::new(2)]);

    let ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&callee)],
        &resolver,
        &f2s,
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");
    let forwards_cmd_field = ws.cross_file().edges.iter().any(|edge| {
        edge.edge.meta.kind == IdgEdgeKind::InterFieldCallArg
            && place_storage_name(
                caller_segment,
                node_place(caller_segment, edge.edge.from).expect("from place"),
            )
            .as_deref()
                == Some("box.cmd")
            && place_storage_name(
                callee_segment,
                node_place(callee_segment, edge.edge.to).expect("to place"),
            )
            .as_deref()
                == Some("arg.cmd")
    });

    assert!(
        forwards_cmd_field,
        "expected worklist field forwarding from caller box.cmd to callee arg.cmd: {:?}",
        ws.cross_file().edges
    );
}

#[test]
fn aggregate_call_argument_projects_only_matching_fields_into_resolved_formal() {
    let call_span = span(20, 40);
    let sink_span = span(70, 85);
    let argument_span = span(28, 39);
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["payload".to_string(), "harmless".to_string()];
    caller.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: argument_span,
            name: None,
            value_text: "aggregate".to_string(),
            place: None,
            source_names: vec!["payload".to_string(), "harmless".to_string()],
        }],
    }];
    let argument_fact = bonsai_lang_api::CallArgumentValueFact {
        call_span,
        argument_index: 0,
        argument_span,
        direct_call_span: None,
        value_kind: None,
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![
                bonsai_lang_api::ExpressionField {
                    name: "target".to_string(),
                    value_span: Some(span(29, 32)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("payload"),
                },
                bonsai_lang_api::ExpressionField {
                    name: "sibling".to_string(),
                    value_span: Some(span(33, 38)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("harmless"),
                },
            ],
            ..Default::default()
        },
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    };

    let mut consume = empty_decl(2, "consume");
    consume.params = vec!["envelope".to_string()];
    consume.flow_events = vec![
        FlowEvent::Assign {
            span: span(55, 65),
            target: "selected".to_string(),
            source_name: Some("envelope.target".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["envelope.target".to_string()],
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Destructure),
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(75, 82),
                name: None,
                value_text: "selected".to_string(),
                place: Some("selected".to_string()),
                source_names: vec!["selected".to_string()],
            }],
        },
    ];

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "consume", vec![FuncId::new(2)]);
    let caller_output = transfer_function_for_with_options_and_compiler_facts(
        &caller,
        &TransferOptions::default(),
        &[],
        &[],
        &[argument_fact],
        &[],
    );
    let consume_output = transfer_function_for(&consume);
    let ws = stitch_idg_with_field_forwarding_mode(
        vec![caller_output.clone(), consume_output.clone()],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
        true,
        true,
    );
    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let reaches_sink = |name: &str| {
        let seeds = service.read_or_write_nodes_for_names(FuncId::new(1), &[name.to_string()]);
        service
            .forward_closure(&seeds)
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(2), sink_span, 0)))
    };
    assert!(
        reaches_sink("payload"),
        "the exact aggregate target field must project into envelope.target"
    );
    assert!(
        !reaches_sink("harmless"),
        "a sibling aggregate field must not collapse into envelope.target"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("aggregate-argument.factstore");
    let persisted = stitch_idg_from_spooled_segment_batches(
        vec![vec![
            (SegmentId(0), vec![caller_output]),
            (SegmentId(1), vec![consume_output]),
        ]],
        2,
        &resolver,
        SpooledStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: true,
            symbolic_funcs: None,
            capture_funcs: None,
        },
    )
    .expect("spooled aggregate-argument stitch");
    persisted
        .save_into_disk(&path, 0xA66E_6A7E)
        .expect("persist aggregate-argument graph");
    let spooled = IdgWorkspace::load_from_disk(&path, 0xA66E_6A7E)
        .expect("load aggregate-argument graph")
        .expect("aggregate-argument graph exists");
    let spooled_service = IdgQueryService::new(Arc::new(spooled), Arc::new(GlobalIndex::new()));
    let spooled_reaches_sink = |name: &str| {
        let seeds = spooled_service.read_or_write_nodes_for_names(FuncId::new(1), &[name.to_string()]);
        spooled_service
            .forward_closure(&seeds)
            .iter()
            .any(|node| spooled_service.call_arg_identity(*node) == Some((FuncId::new(2), sink_span, 0)))
    };
    assert!(
        spooled_reaches_sink("payload"),
        "spooled replay must project the exact aggregate target field through the formal destructure"
    );
    assert!(
        !spooled_reaches_sink("harmless"),
        "spooled replay must keep a sibling aggregate field out of the selected formal projection"
    );
}

#[test]
fn spooled_static_callback_map_forwards_the_exact_argument_field() {
    let host_func = FuncId::new(1);
    let callback_func = FuncId::new(2);
    let assignment_span = span(20, 30);
    // The adapter-owned call identity may be the callee token rather than the
    // enclosing invocation. Its argument is evaluated after that token.
    let call_span = span(40, 47);
    let argument_span = span(48, 80);
    let sink_span = span(85, 95);

    let mut host = empty_decl(host_func.raw(), "host");
    host.params = vec!["input".to_string()];
    host.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "variables".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["input".to_string()],
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Call {
            span: call_span,
            name: "graphql".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: argument_span,
                name: None,
                value_text: "options".to_string(),
                place: None,
                source_names: vec!["root".to_string(), "variables".to_string()],
            }],
        },
    ];
    let argument_values = [bonsai_lang_api::CallArgumentValueFact {
        call_span,
        argument_index: 0,
        argument_span,
        direct_call_span: None,
        value_kind: Some(AssignValueKind::Compound),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![
                bonsai_lang_api::ExpressionField {
                    name: "rootValue".to_string(),
                    value_span: Some(span(52, 56)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("root"),
                },
                bonsai_lang_api::ExpressionField {
                    name: "variableValues".to_string(),
                    value_span: Some(span(60, 69)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("variables"),
                },
            ],
            ..Default::default()
        },
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];
    let options = TransferOptions {
        callback_invocations: vec![crate::transfer::CallbackInvocationSpec {
            callee: "graphql".to_string(),
            callback_arg_index: 0,
            callback_map_field_path: vec!["rootValue".to_string()],
            forwarded_argument_field_path: vec!["variableValues".to_string()],
            forwarded_callback_param_index: Some(1),
            forwarded_args_from: None,
            receiver_to_callback_param: None,
            callback_return_result_offset: 0,
            resolved_call_sites: vec![call_span],
            resolved_callback_targets: vec![(call_span, callback_func)],
        }],
        ..TransferOptions::default()
    };

    let mut callback = empty_decl(callback_func.raw(), "products");
    callback.params = vec!["parent".to_string(), "args".to_string()];
    callback.flow_events = vec![FlowEvent::Call {
        span: sink_span,
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(90, 94),
            name: None,
            value_text: "args".to_string(),
            place: Some("args".to_string()),
            source_names: vec!["args".to_string()],
        }],
    }];

    let host_output = transfer_function_for_with_options_and_compiler_facts(
        &host,
        &options,
        &[],
        &[],
        &argument_values,
        &[],
    );
    let callback_output = transfer_function_for(&callback);
    let resolver = MockResolver::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("static-callback-map.factstore");
    let persisted = stitch_idg_from_spooled_segment_batches(
        vec![vec![
            (SegmentId(0), vec![host_output]),
            (SegmentId(1), vec![callback_output]),
        ]],
        2,
        &resolver,
        SpooledStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: Some(&AHashSet::new()),
        },
    )
    .expect("spooled static callback-map stitch");
    persisted
        .save_into_disk(&path, 0xCA11_BA4C)
        .expect("persist static callback-map graph");
    let persisted = IdgWorkspace::load_from_disk(&path, 0xCA11_BA4C)
        .expect("load static callback-map graph")
        .expect("static callback-map graph exists");
    let service = IdgQueryService::new(Arc::new(persisted), Arc::new(GlobalIndex::new()));
    let seeds = service.read_or_write_nodes_for_names(host_func, &["input".to_string()]);
    assert!(!seeds.is_empty(), "host input must exist in the compiler graph");
    let reached = service.forward_closure(&seeds);
    assert!(
        reached.iter().any(|node| {
            service.call_arg_identity(*node) == Some((callback_func, sink_span, 0))
        }),
        "spooled replay must retain the exact temporary.variableValues producer and forward it into resolver args"
    );
}

#[test]
fn imported_module_field_state_uses_exact_target_identity_across_resolved_call() {
    let source_span = span(5, 14);
    let call_span = span(30, 45);
    let sink_span = span(70, 90);
    let mut caller = empty_decl(1, "caller");
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(2, 14),
            target: "carrier".to_string(),
            source_name: None,
            source_call: Some("runtime.input".to_string()),
            source_call_args: Vec::new(),
            source_names: vec!["runtime".to_string()],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: source_span,
            name: "runtime.input".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
        FlowEvent::Assign {
            span: span(15, 25),
            target: "local_module.target".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["carrier".to_string(), "carrier.value".to_string()],
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: call_span,
            name: "downstream".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
    ];
    let mut downstream = empty_decl(2, "downstream");
    downstream.flow_events = vec![FlowEvent::Call {
        span: sink_span,
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(78, 88),
            name: None,
            value_text: "other_alias.target".to_string(),
            place: Some("other_alias.target".to_string()),
            source_names: vec!["other_alias.target".to_string()],
        }],
    }];

    let build = |callee_target: &str| {
        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "downstream", vec![FuncId::new(2)]);
        resolver.add_imported_binding(FuncId::new(1), "local_module", "workspace.shared");
        resolver.add_imported_binding(FuncId::new(2), "other_alias", callee_target);
        stitch_idg(
            vec![transfer_function_for(&caller), transfer_function_for(&downstream)],
            &resolver,
            &StaticF2S(AHashMap::from([
                (FuncId::new(1), SegmentId(0)),
                (FuncId::new(2), SegmentId(1)),
            ])),
        )
    };
    let closure_result = |ws: IdgWorkspace| {
        let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
        let seeds = service.source_seed_nodes_at_span(FuncId::new(1), source_span);
        assert!(
            !seeds.is_empty(),
            "the exact source-call span must resolve to IDG seed nodes"
        );
        let reaches_sink = service
            .forward_closure(&seeds)
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(2), sink_span, 0)));
        let evidence = service.forward_closure_evidence(&seeds);
        let target_nodes = service.nodes_at_span(FuncId::new(2), sink_span);
        let allowed_funcs = AHashSet::from([FuncId::new(1), FuncId::new(2)]);
        let relevance = service.target_relevance_within_funcs(&target_nodes, None, &allowed_funcs);
        let seeds_are_relevant = relevance.admits_any(&seeds);
        let relevant =
            service.forward_closure_evidence_within_funcs_and_relevance(&seeds, &allowed_funcs, &relevance);
        let relevant_reaches_sink = relevant
            .nodes
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(2), sink_span, 0)));
        (
            reaches_sink,
            evidence.cross_calls,
            seeds_are_relevant,
            relevant_reaches_sink,
        )
    };
    let (resident_reaches_sink, resident_cross_calls, resident_relevant, resident_relevant_reaches_sink) =
        closure_result(build("workspace.shared"));
    assert!(
        resident_reaches_sink,
        "different local aliases of the same exact import target must share projected state"
    );
    assert!(
        resident_cross_calls.iter().any(|edge| {
            edge.caller == FuncId::new(1)
                && edge.callee == FuncId::new(2)
                && edge.call_span == call_span
                && edge.relation == crate::service::CrossCallRelation::SharedStateCall
                && edge.relation.is_renderable_call()
        }),
        "shared projected state at an exact call must retain renderable, non-positional lineage: {resident_cross_calls:?}"
    );
    assert!(
        resident_relevant && resident_relevant_reaches_sink,
        "backward target demand and the scoped forward closure must consume the shared-state edge"
    );
    let (
        wrong_target_reaches_sink,
        wrong_target_cross_calls,
        _wrong_target_relevant,
        wrong_target_relevant_reaches_sink,
    ) = closure_result(build("workspace.unrelated"));
    assert!(
        !wrong_target_reaches_sink,
        "same-spelled fields on different imported targets must remain disjoint"
    );
    assert!(
        wrong_target_cross_calls
            .iter()
            .all(|edge| edge.relation != crate::service::CrossCallRelation::SharedStateCall),
        "a different imported target must not emit shared field-state lineage"
    );
    assert!(
        !wrong_target_relevant_reaches_sink,
        "target-scoped closure must not reach a same-spelled field from another imported target"
    );

    let build_spooled = |callee_target: &str| {
        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "downstream", vec![FuncId::new(2)]);
        resolver.add_imported_binding(FuncId::new(1), "local_module", "workspace.shared");
        resolver.add_imported_binding(FuncId::new(2), "other_alias", callee_target);
        let caller_output = transfer_function_for(&caller);
        let downstream_output = transfer_function_for(&downstream);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("imported-state.factstore");
        let persisted = stitch_idg_from_spooled_segment_batches(
            vec![vec![
                (SegmentId(0), vec![caller_output]),
                (SegmentId(1), vec![downstream_output]),
            ]],
            2,
            &resolver,
            SpooledStitchOptions {
                spool_path: &path,
                include_field_argument_forwarding: true,
                symbolic_field_forwarding: false,
                symbolic_funcs: None,
                capture_funcs: None,
            },
        )
        .expect("spooled imported-state stitch");
        persisted
            .save_into_disk(&path, 0x1A90_27ED)
            .expect("persist imported-state graph");
        IdgWorkspace::load_from_disk(&path, 0x1A90_27ED)
            .expect("load imported-state graph")
            .expect("imported-state graph exists")
    };
    let (spooled_reaches_sink, spooled_cross_calls, spooled_relevant, spooled_relevant_reaches_sink) =
        closure_result(build_spooled("workspace.shared"));
    assert!(
        spooled_reaches_sink,
        "spooled typed replay must retain exact shared imported-field state"
    );
    assert!(
        spooled_cross_calls.iter().any(|edge| {
            edge.caller == FuncId::new(1)
                && edge.callee == FuncId::new(2)
                && edge.call_span == call_span
                && edge.relation == crate::service::CrossCallRelation::SharedStateCall
        }),
        "spooled replay must retain the same typed field-state lineage as resident stitching"
    );
    assert!(
        spooled_relevant && spooled_relevant_reaches_sink,
        "spooled backward demand and scoped closure must consume the persisted shared-state edge"
    );
    let (
        spooled_collision_reaches_sink,
        spooled_collision_cross_calls,
        _spooled_collision_relevant,
        spooled_collision_relevant_reaches_sink,
    ) = closure_result(build_spooled("workspace.unrelated"));
    assert!(
        !spooled_collision_reaches_sink,
        "spooled typed replay must keep different import targets disjoint"
    );
    assert!(
        spooled_collision_cross_calls
            .iter()
            .all(|edge| edge.relation != crate::service::CrossCallRelation::SharedStateCall),
        "spooled replay must not invent shared state for another import target"
    );
    assert!(
        !spooled_collision_relevant_reaches_sink,
        "spooled target-scoped closure must reject another imported target"
    );
}

#[test]
fn imported_shared_field_state_rejects_siblings_post_call_writes_and_ambiguous_callees() {
    let call_span = span(30, 45);
    let sink_span = span(70, 90);
    let downstream = |symbol: u32| {
        let mut decl = empty_decl(symbol, "downstream");
        decl.flow_events = vec![FlowEvent::Call {
            span: sink_span,
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(78, 88),
                name: None,
                value_text: "reader_alias.target".to_string(),
                place: Some("reader_alias.target".to_string()),
                source_names: vec!["reader_alias.target".to_string()],
            }],
        }];
        decl
    };
    let build = |write_span: Span, field: &str, callees: Vec<FuncId>| {
        let mut caller = empty_decl(1, "caller");
        caller.params = vec!["payload".to_string()];
        caller.flow_events = vec![
            FlowEvent::Call {
                span: call_span,
                name: "dispatch".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: Vec::new(),
            },
            FlowEvent::Assign {
                span: write_span,
                target: format!("writer_alias.{field}"),
                source_name: Some("payload".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            },
        ];
        caller.flow_events.sort_by_key(|event| event.span().start);

        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "dispatch", callees);
        resolver.add_imported_binding(FuncId::new(1), "writer_alias", "workspace.shared");
        resolver.add_imported_binding(FuncId::new(2), "reader_alias", "workspace.shared");
        resolver.add_imported_binding(FuncId::new(3), "reader_alias", "workspace.shared");
        stitch_idg(
            vec![
                transfer_function_for(&caller),
                transfer_function_for(&downstream(2)),
                transfer_function_for(&downstream(3)),
            ],
            &resolver,
            &StaticF2S(AHashMap::from([
                (FuncId::new(1), SegmentId(0)),
                (FuncId::new(2), SegmentId(1)),
                (FuncId::new(3), SegmentId(2)),
            ])),
        )
    };
    let closure_result = |ws: IdgWorkspace| {
        let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
        let seeds = service.read_or_write_nodes_for_names(FuncId::new(1), &["payload".to_string()]);
        let evidence = service.forward_closure_evidence(&seeds);
        let reaches_sink = evidence
            .nodes
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(2), sink_span, 0)));
        (reaches_sink, evidence.cross_calls)
    };

    let (sibling_reaches, sibling_calls) =
        closure_result(build(span(15, 25), "sibling", vec![FuncId::new(2)]));
    assert!(
        !sibling_reaches,
        "a sibling projected field must remain disconnected"
    );
    assert!(
        sibling_calls
            .iter()
            .all(|edge| edge.relation != crate::service::CrossCallRelation::SharedStateCall),
        "a sibling field must not emit shared-state lineage"
    );

    let (post_call_reaches, post_call_calls) =
        closure_result(build(span(50, 60), "target", vec![FuncId::new(2)]));
    assert!(
        !post_call_reaches,
        "a write after the call must not flow backward"
    );
    assert!(
        post_call_calls
            .iter()
            .all(|edge| edge.relation != crate::service::CrossCallRelation::SharedStateCall),
        "a post-call write must not emit shared-state lineage"
    );

    let (ambiguous_reaches, ambiguous_calls) = closure_result(build(
        span(15, 25),
        "target",
        vec![FuncId::new(2), FuncId::new(3)],
    ));
    assert!(
        !ambiguous_reaches,
        "shared state must fail closed when a call has more than one resolved target"
    );
    assert!(
        ambiguous_calls
            .iter()
            .all(|edge| edge.relation != crate::service::CrossCallRelation::SharedStateCall),
        "ambiguous call targets must not emit shared-state lineage"
    );
}

#[test]
fn imported_module_field_state_preserves_projected_rhs_flow_across_resolved_call() {
    let call_span = span(40, 55);
    let sink_span = span(80, 100);
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["payload".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "request.value".to_string(),
            source_name: Some("payload".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(22, 35),
            target: "local_module.target".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["request".to_string(), "request.value".to_string()],
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: call_span,
            name: "downstream".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
    ];
    let mut downstream = empty_decl(2, "downstream");
    downstream.flow_events = vec![FlowEvent::Call {
        span: sink_span,
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(88, 98),
            name: None,
            value_text: "other_alias.target".to_string(),
            place: Some("other_alias.target".to_string()),
            source_names: vec!["other_alias.target".to_string()],
        }],
    }];

    let build = |callee_target: &str| {
        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "downstream", vec![FuncId::new(2)]);
        resolver.add_imported_binding(FuncId::new(1), "local_module", "workspace.shared");
        resolver.add_imported_binding(FuncId::new(2), "other_alias", callee_target);
        stitch_idg(
            vec![transfer_function_for(&caller), transfer_function_for(&downstream)],
            &resolver,
            &StaticF2S(AHashMap::from([
                (FuncId::new(1), SegmentId(0)),
                (FuncId::new(2), SegmentId(1)),
            ])),
        )
    };
    let reaches_sink = |ws: IdgWorkspace| {
        let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
        let seeds = service.read_or_write_nodes_for_names(FuncId::new(1), &["payload".to_string()]);
        service
            .forward_closure(&seeds)
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(2), sink_span, 0)))
    };
    assert!(
        reaches_sink(build("workspace.shared")),
        "an exact projected RHS must reach the same imported module field across the resolved call"
    );
    assert!(
        !reaches_sink(build("workspace.unrelated")),
        "an exact projected RHS must not cross into the same field on another imported module"
    );
}

#[test]
fn spooled_higher_order_environment_uses_compact_projected_places() {
    let registration_span = span(30, 45);
    let invocation_span = span(60, 68);
    let sink_span = span(80, 95);
    let mut entry = empty_decl(1, "entry");
    entry.params = vec!["payload".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(15, 25),
            target: "thunk.payload".to_string(),
            source_name: Some("payload".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: registration_span,
            name: "apply".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(36, 42),
                name: None,
                value_text: "thunk".to_string(),
                place: Some("thunk".to_string()),
                source_names: vec!["thunk".to_string()],
            }],
        },
    ];
    let mut apply = empty_decl(2, "apply");
    apply.params = vec!["callback".to_string()];
    apply.flow_events = vec![FlowEvent::Call {
        span: invocation_span,
        name: "callback".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: Vec::new(),
    }];
    let mut callback = empty_decl(3, "callback_body");
    callback.params = vec!["payload".to_string()];
    callback.flow_events = vec![FlowEvent::Call {
        span: sink_span,
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(86, 93),
            name: None,
            value_text: "payload".to_string(),
            place: Some("payload".to_string()),
            source_names: vec!["payload".to_string()],
        }],
    }];

    let build = |binding: &str, fingerprint: u64| {
        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "apply", vec![FuncId::new(2)]);
        resolver.add_callback_binding(FuncId::new(2), 0, vec![FuncId::new(3)]);
        resolver.add_callback_origin(
            FuncId::new(2),
            0,
            FuncId::new(3),
            CallbackBindingOrigin {
                caller: FuncId::new(1),
                call_site: registration_span,
                binding: Some(binding.to_string()),
            },
        );
        let batches = vec![vec![
            (
                SegmentId(0),
                vec![transfer_function_for(&entry), transfer_function_for(&callback)],
            ),
            (SegmentId(1), vec![transfer_function_for(&apply)]),
        ]];
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("higher-order-environment.factstore");
        let persisted = stitch_idg_from_spooled_segment_batches(
            batches,
            3,
            &resolver,
            SpooledStitchOptions {
                spool_path: &path,
                include_field_argument_forwarding: true,
                symbolic_field_forwarding: false,
                symbolic_funcs: None,
                capture_funcs: Some(&AHashSet::from_iter([FuncId::new(3)])),
            },
        )
        .expect("spooled higher-order stitch");
        persisted
            .save_into_disk(&path, fingerprint)
            .expect("persist higher-order graph");
        IdgWorkspace::load_from_disk(&path, fingerprint)
            .expect("load higher-order graph")
            .expect("higher-order graph exists")
    };
    let closure_result = |ws: IdgWorkspace| {
        let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
        let seeds = service.read_or_write_nodes_for_names(FuncId::new(1), &["payload".to_string()]);
        let reaches_sink = service
            .forward_closure(&seeds)
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(3), sink_span, 0)));
        let evidence = service.forward_closure_evidence(&seeds);
        (reaches_sink, evidence.cross_calls)
    };
    let (positive_reaches_sink, positive_cross_calls) = closure_result(build("thunk", 0xC411_BA6E));
    assert!(
        positive_reaches_sink,
        "spooled replay must retain caller field state for a resolved higher-order callback"
    );
    assert!(
        positive_cross_calls.iter().any(|edge| {
            edge.caller == FuncId::new(1)
                && edge.callee == FuncId::new(3)
                && edge.relation == crate::service::CrossCallRelation::Capture
        }),
        "the exact scalar capture boundary must remain renderable after projected state is spooled"
    );
    let (collision_reaches_sink, collision_cross_calls) = closure_result(build("ordinary", 0xC011_1510));
    assert!(
        !collision_reaches_sink,
        "a callback origin without the exact projected binding must remain disconnected"
    );
    assert!(
        collision_cross_calls.iter().all(|edge| {
            edge.caller != FuncId::new(1)
                || edge.callee != FuncId::new(3)
                || edge.relation != crate::service::CrossCallRelation::Capture
        }),
        "the same-spelled callback without exact projected state must not invent capture lineage"
    );
}

fn symbolic_field_forwarding_reachability(callee_read: &str) -> ([AHashSet<usize>; 2], usize) {
    symbolic_field_forwarding_reachability_for_reads(&[callee_read], false)
}

fn symbolic_field_forwarding_reachability_for_reads(
    callee_reads: &[&str],
    mixed_capabilities: bool,
) -> ([AHashSet<usize>; 2], usize) {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["live_src".to_string(), "dead_src".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 18),
            target: "box.live".to_string(),
            source_name: Some("live_src".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(20, 28),
            target: "box.dead".to_string(),
            source_name: Some("dead_src".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(30, 45),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(37, 40),
                name: None,
                value_text: "box".to_string(),
                place: Some("box".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];
    let mut callee = empty_decl(2, "helper");
    callee.params = vec!["arg".to_string()];
    callee.flow_events = callee_reads
        .iter()
        .enumerate()
        .map(|(index, callee_read)| {
            let start = 50 + u64::try_from(index).expect("test call index") * 20;
            FlowEvent::Call {
                span: span(start, start + 15),
                name: "sink".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: vec![CallArg {
                    passing_mode: Default::default(),
                    span: span(start + 5, start + 12),
                    name: None,
                    value_text: (*callee_read).to_string(),
                    place: Some((*callee_read).to_string()),
                    source_names: vec![(*callee_read).to_string()],
                }],
            }
        })
        .collect();
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "helper", vec![FuncId::new(2)]);
    let caller_transfer = transfer_function_for(&caller);
    let callee_transfer = transfer_function_for(&callee);
    let symbolic_funcs = mixed_capabilities.then(|| AHashSet::from([FuncId::new(1)]));
    let ws = stitch_idg_with_selective_field_forwarding_mode(
        vec![caller_transfer, callee_transfer],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
        true,
        true,
        symbolic_funcs.as_ref(),
    );
    let symbolic_transform_count = ws.symbolic_field().transforms().len();
    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let params = service.param_nodes_of(FuncId::new(1));
    assert_eq!(params.len(), 2);
    let reached_terminals = params
        .iter()
        .map(|seed| {
            service
                .forward_closure(&[*seed])
                .into_iter()
                .filter_map(|node| service.resolve_point(node))
                .filter(|point| point.func == FuncId::new(2) && point.kind == PointKind::CallArg)
                .filter_map(|point| {
                    callee_reads.iter().enumerate().find_map(|(index, _)| {
                        let start = 50 + u64::try_from(index).expect("test call index") * 20;
                        (point.span == span(start, start + 15)).then_some(index)
                    })
                })
                .collect()
        })
        .collect::<Vec<AHashSet<usize>>>();
    (
        [reached_terminals[0].clone(), reached_terminals[1].clone()],
        symbolic_transform_count,
    )
}

#[test]
fn symbolic_field_forwarding_uses_exact_ast_projection() {
    let ([live, dead], symbolic_transform_count) = symbolic_field_forwarding_reachability("arg.live");
    assert_eq!(live, AHashSet::from([0]));
    assert!(dead.is_empty());
    assert_eq!(symbolic_transform_count, 1);
}

#[test]
fn symbolic_field_forwarding_preserves_whole_object_ast_reads() {
    let ([live, dead], _) = symbolic_field_forwarding_reachability("arg");
    assert_eq!(live, AHashSet::from([0]));
    assert_eq!(dead, AHashSet::from([0]));
}

#[test]
fn whole_object_symbolic_read_does_not_erase_exact_projection() {
    let ([live, dead], _) = symbolic_field_forwarding_reachability_for_reads(&["arg", "arg.live"], false);
    assert_eq!(live, AHashSet::from([0, 1]));
    assert_eq!(dead, AHashSet::from([0]));
}

#[test]
fn symbolic_argument_relation_replaces_concrete_fallback_without_losing_projection() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["box".to_string()];
    caller.flow_events = vec![
        FlowEvent::Call {
            span: span(12, 20),
            name: "observe".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(14, 19),
                name: None,
                value_text: "box.cmd".to_string(),
                place: Some("box.cmd".to_string()),
                source_names: vec!["box.cmd".to_string()],
            }],
        },
        FlowEvent::Call {
            span: span(30, 40),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(32, 38),
                name: None,
                value_text: "box".to_string(),
                place: Some("box".to_string()),
                source_names: vec!["box".to_string()],
            }],
        },
    ];
    let mut callee = empty_decl(2, "helper");
    callee.params = vec!["arg".to_string()];
    callee.flow_events = vec![FlowEvent::Call {
        span: span(60, 72),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(65, 71),
            name: None,
            value_text: "arg.cmd".to_string(),
            place: Some("arg.cmd".to_string()),
            source_names: vec!["arg.cmd".to_string()],
        }],
    }];
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "helper", vec![FuncId::new(2)]);
    let ws = stitch_idg_with_field_forwarding_mode(
        vec![transfer_function_for(&caller), transfer_function_for(&callee)],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
        true,
        true,
    );

    assert!(
        !ws.cross_file()
            .edges
            .iter()
            .any(|edge| edge.edge.meta.kind == IdgEdgeKind::InterFieldCallArg),
        "complete adapters must not duplicate symbolic argument transforms as concrete fallback edges"
    );
    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let seeds = service.read_or_write_nodes_for_names(FuncId::new(1), &["box.cmd".to_string()]);
    assert!(
        !seeds.is_empty(),
        "caller projected read must be represented in compiler IR"
    );
    let reached = service.forward_closure(&seeds);
    assert!(
        reached
            .iter()
            .any(|node| { service.call_arg_identity(*node) == Some((FuncId::new(2), span(60, 72), 0)) }),
        "the symbolic fixed point must carry box.cmd into helper arg.cmd without a duplicate concrete edge"
    );
}

#[test]
fn mixed_adapter_capabilities_keep_incomplete_field_places_eager() {
    let ([live, dead], symbolic_transform_count) =
        symbolic_field_forwarding_reachability_for_reads(&["arg.live", "arg.dead"], true);
    assert_eq!(live, AHashSet::from([0]));
    assert_eq!(dead, AHashSet::from([1]));
    assert_eq!(symbolic_transform_count, 0);
}

#[test]
fn field_argument_forwarding_worklist_deduplicates_split_views_but_not_writers() {
    let shallow_key = FieldPlaceKey {
        seg_id: SegmentId(0),
        func: FuncId::new(1),
        base: "box".to_string(),
        writes: true,
    };
    let deep_key = FieldPlaceKey {
        seg_id: SegmentId(0),
        func: FuncId::new(1),
        base: "box.nested".to_string(),
        writes: true,
    };
    let shallow_hit = FieldPlaceHit {
        field: "nested.cmd".to_string(),
        node: NodeId(7),
        span: Some(span(10, 18)),
    };
    let deep_hit = FieldPlaceHit {
        field: "cmd".to_string(),
        node: NodeId(7),
        span: Some(span(10, 18)),
    };
    let mut pending = Vec::new();
    let mut enqueued = AHashSet::default();

    enqueue_field_write(&shallow_key, &shallow_hit, &mut pending, &mut enqueued);
    enqueue_field_write(&deep_key, &deep_hit, &mut pending, &mut enqueued);

    assert_eq!(pending.len(), 1);
    assert_eq!(enqueued.len(), 1);
    assert_eq!(
        pending.last().copied(),
        Some(PendingFieldWrite {
            seg_id: SegmentId(0),
            func: FuncId::new(1),
            node: NodeId(7),
        })
    );

    enqueue_field_write(
        &shallow_key,
        &FieldPlaceHit {
            field: "nested.cmd".to_string(),
            node: NodeId(8),
            span: Some(span(20, 28)),
        },
        &mut pending,
        &mut enqueued,
    );

    assert_eq!(
        pending.len(),
        2,
        "distinct AST/IDG writers must retain their provenance"
    );
    assert_eq!(enqueued.len(), 2);
}

#[test]
fn synthetic_field_write_interning_canonicalizes_storage_split_views() {
    let decl = empty_decl(1, "canonical_field_write");
    let mut ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let initial_nodes = ws.segment(SegmentId(0)).expect("segment").nodes.len();
    let cache = SyntheticFieldWriteCache::from_workspace(&ws);

    let (first, _, first_is_new) = SyntheticFieldWriteCache::ensure(
        &mut ws,
        SegmentId(0),
        FuncId::new(1),
        "box",
        "nested.cmd",
        span(10, 18),
    )
    .expect("first synthetic write");
    let (second, _, second_is_new) = SyntheticFieldWriteCache::ensure(
        &mut ws,
        SegmentId(0),
        FuncId::new(1),
        "box.nested",
        "cmd",
        span(10, 18),
    )
    .expect("same storage through another split");

    assert!(first_is_new);
    assert!(!second_is_new);
    assert_eq!(first, second);
    assert!(cache.is_generated(SegmentId(0), FuncId::new(1), first));
    let (third, _, third_is_new) = SyntheticFieldWriteCache::ensure(
        &mut ws,
        SegmentId(0),
        FuncId::new(1),
        "box.nested",
        "cmd",
        span(20, 28),
    )
    .expect("same storage at a distinct statement");
    assert!(third_is_new);
    assert_ne!(
        first, third,
        "distinct AST writes must preserve statement identity"
    );
    let segment = ws.segment(SegmentId(0)).expect("segment");
    assert_eq!(segment.nodes.len(), initial_nodes + 2);
    assert!(cache.is_generated(SegmentId(0), FuncId::new(1), third));
    assert_eq!(
        place_storage_name(segment, node_place(segment, first).expect("synthetic place")).as_deref(),
        Some("box.nested.cmd")
    );
}

#[test]
fn synthetic_parameter_fields_merge_across_call_spans() {
    let decl = empty_decl(1, "canonical_parameter_field");
    let mut ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let mut cache = SyntheticFieldWriteCache::from_workspace(&ws);
    let first = cache
        .ensure_parameter(
            &mut ws,
            SegmentId(0),
            FuncId::new(1),
            "arg",
            "value",
            span(10, 18),
        )
        .expect("first caller");
    let second = cache
        .ensure_parameter(
            &mut ws,
            SegmentId(0),
            FuncId::new(1),
            "arg",
            "value",
            span(30, 38),
        )
        .expect("second caller");

    assert!(first.2);
    assert!(!second.2);
    assert_eq!(first.0, second.0);
    assert_eq!(first.1, second.1);
}

#[test]
fn syntactic_field_universe_keeps_numeric_and_deep_adapter_paths() {
    let mut decl = empty_decl(1, "field_universe");
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "tuple.0.payload.value".to_string(),
            source_name: Some("seed".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(30, 40),
            target: "map.42.command".to_string(),
            source_name: Some("seed".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];
    let ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let full_index = FieldPlaceIndex::from_workspace(&ws);
    let universe = full_index.syntactic_field_universe();

    for field in [
        "0.payload.value",
        "payload.value",
        "value",
        "42.command",
        "command",
    ] {
        assert!(
            universe.contains(field),
            "missing exact adapter field suffix `{field}`"
        );
    }
    assert!(!universe.contains("child.child.value"));

    let requested = AHashSet::from([FieldPlaceKey {
        seg_id: SegmentId(0),
        func: FuncId::new(1),
        base: "tuple".to_string(),
        writes: true,
    }]);
    let focused = FieldPlaceIndex::from_workspace_for_keys(&ws, &requested);
    let focused_universe = focused.syntactic_field_universe();
    assert!(
        focused_universe.contains("42.command"),
        "field-row filtering must not discard an adapter-proven suffix needed by later synthetic composition"
    );
    let tuple_hits = focused
        .field_hits_for_normalized_base(SegmentId(0), FuncId::new(1), "tuple", true)
        .expect("requested AST base remains indexed");
    assert!(tuple_hits.iter().any(|hit| hit.field == "0.payload.value"));
    assert!(
        focused
            .field_hits_for_normalized_base(SegmentId(0), FuncId::new(1), "map", true)
            .is_none(),
        "unrequested bases must not duplicate unrelated workspace field strings"
    );
}

#[test]
fn syntactic_field_universe_composes_resolved_receiver_selector_demand() {
    let mut getter = empty_decl(2, "cmd");
    getter.kind = DeclKind::Method;
    getter.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(60, 68),
        value_name: Some("self.cmd".to_string()),
        value_text: Some("self.cmd".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("self.cmd"),
    }];
    let ws = stitch_idg(
        vec![transfer_function_for(&getter)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(2), SegmentId(0))])),
    );
    let requested = AHashSet::from([FieldPlaceKey {
        seg_id: SegmentId(0),
        func: FuncId::new(2),
        base: "self".to_string(),
        writes: false,
    }]);
    let mut index = FieldPlaceIndex::from_workspace_for_keys(&ws, &requested);
    let mut universe = index.take_syntactic_field_universe();
    assert!(universe.contains("cmd"));
    assert!(!universe.contains("data.cmd"));

    universe.record_argument_projection_demands(
        &index,
        &[Arc::new(FieldArgStitch {
            caller: FuncId::new(1),
            caller_seg: SegmentId(1),
            callee: FuncId::new(2),
            callee_seg: SegmentId(0),
            actual_arg: "repo.data".to_string(),
            param_name: "self".to_string(),
            call_span: span(30, 45),
            argument_value_span: None,
            call_kind: bonsai_callgraph::EdgeKind::Direct,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
            allow_out_of_order_source: false,
        })],
    );
    assert!(
        universe.contains("data.cmd"),
        "receiver `repo.data` plus the resolved accessor read `self.cmd` proves the finite suffix `data.cmd`"
    );
}

#[test]
fn syntactic_field_universe_composes_nested_aggregate_return_call_paths_once() {
    let mut inner = empty_decl(2, "inner");
    inner.params = vec!["seed".to_string()];
    inner.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "data.Cmd".to_string(),
            source_name: Some("seed".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["seed".to_string()],
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Compound),
        },
        FlowEvent::Return {
            value_kind: Some(AssignValueKind::Compound),
            span: span(30, 55),
            value_name: None,
            value_text: None,
            value_flow: bonsai_lang_api::ExpressionFlow {
                aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                    name: "data".to_string(),
                    value_span: Some(span(45, 49)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("data"),
                }],
                ..Default::default()
            },
        },
    ];
    let ws = stitch_idg(
        vec![transfer_function_for(&inner)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(2), SegmentId(0))])),
    );
    let requested = AHashSet::from([FieldPlaceKey {
        seg_id: SegmentId(0),
        func: FuncId::new(2),
        base: crate::transfer::RETURN_FIELD_BASE.to_string(),
        writes: true,
    }]);
    let mut index = FieldPlaceIndex::from_workspace_for_keys(&ws, &requested);
    let mut universe = index.take_syntactic_field_universe();
    assert!(universe.contains("data.Cmd"));
    assert!(!universe.contains("Repository.data.Cmd"));

    universe.record_nested_return_projection_demands(
        &index,
        &[Arc::new(ReturnFieldStitch {
            caller: FuncId::new(3),
            caller_seg: SegmentId(1),
            callee: FuncId::new(2),
            callee_seg: SegmentId(0),
            source_base: crate::transfer::RETURN_FIELD_BASE.to_string(),
            target_base: format!("{}.Repository", crate::transfer::RETURN_FIELD_BASE),
            call_span: span(60, 70),
            write_span: span(55, 75),
            call_kind: bonsai_callgraph::EdgeKind::Direct,
        })],
    );
    assert!(
        universe.contains("Repository.data.Cmd"),
        "the aggregate AST prefix and exact returned descendant must compose into one finite demand"
    );
    assert!(
        !universe.contains("Repository.Repository.data.Cmd"),
        "one nested return site must not feed its own synthesized prefix back into the field language"
    );
}

#[test]
fn field_copy_fanout_is_not_truncated() {
    let mut decl = empty_decl(1, "fanout");
    decl.params = vec!["seed".to_string()];
    decl.flow_events.push(FlowEvent::Assign {
        span: span(10, 20),
        target: "source.cmd".to_string(),
        source_name: Some("seed".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    });
    for index in 0..6_u64 {
        decl.flow_events.push(FlowEvent::Assign {
            span: span(30 + index * 10, 35 + index * 10),
            target: format!("copy{index}"),
            source_name: Some("source".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        });
    }

    let ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let segment = ws.segment(SegmentId(0)).expect("fanout segment");
    let copied_targets = segment
        .edges
        .iter()
        .filter(|edge| edge.meta.kind == IdgEdgeKind::IntraAssign)
        .filter_map(|edge| {
            let from = place_storage_name(segment, node_place(segment, edge.from)?)?;
            let to = place_storage_name(segment, node_place(segment, edge.to)?)?;
            (from == "source.cmd" && to.starts_with("copy") && to.strip_suffix(".cmd").is_some())
                .then_some(to)
        })
        .collect::<AHashSet<_>>();

    assert_eq!(
        copied_targets.len(),
        6,
        "every syntax-derived copy destination must receive the matching field: copied={copied_targets:?} edges={:?}",
        segment.edges
    );
}

#[test]
fn lexically_later_field_write_does_not_flow_backward_through_an_earlier_copy() {
    let mut decl = empty_decl(1, "straight_line_copy");
    decl.params = vec!["seed".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "a".to_string(),
            source_name: Some("b".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(30, 40),
            target: "b.cmd".to_string(),
            source_name: Some("seed".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];

    let ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let segment = ws.segment(SegmentId(0)).expect("straight-line segment");
    let has_backward_copy = segment.edges.iter().any(|edge| {
        edge.meta.kind == IdgEdgeKind::IntraAssign
            && place_storage_name(segment, node_place(segment, edge.from).expect("source place")).as_deref()
                == Some("b.cmd")
            && place_storage_name(segment, node_place(segment, edge.to).expect("target place")).as_deref()
                == Some("a.cmd")
    });

    assert!(
        !has_backward_copy,
        "a later field write must not travel backward through an earlier straight-line copy: {:?}",
        segment.edges
    );
}

#[test]
fn later_field_write_flows_through_an_earlier_copy_only_via_a_structural_loop_back_edge() {
    let mut decl = empty_decl(1, "loop_carried_copy");
    decl.params = vec!["seed".to_string()];
    decl.flow_events = vec![FlowEvent::Loop {
        span: span(10, 80),
        loop_kind: bonsai_lang_api::LoopKind::While,
        label: None,
        condition_events: Vec::new(),
        update_events: Vec::new(),
        body: vec![
            FlowEvent::Assign {
                span: span(20, 30),
                target: "a".to_string(),
                source_name: Some("b".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: true,
                value_kind: None,
            },
            FlowEvent::Assign {
                span: span(40, 50),
                target: "b.cmd".to_string(),
                source_name: Some("seed".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            },
        ],
    }];

    let ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let segment = ws.segment(SegmentId(0)).expect("loop segment");
    let has_loop_carried_copy = segment.edges.iter().any(|edge| {
        edge.meta.kind == IdgEdgeKind::IntraAssign
            && place_storage_name(segment, node_place(segment, edge.from).expect("source place")).as_deref()
                == Some("b.cmd")
            && place_storage_name(segment, node_place(segment, edge.to).expect("target place")).as_deref()
                == Some("a.cmd")
    });

    assert!(
        has_loop_carried_copy,
        "the structured Loop body proves that the later write reaches the earlier copy on the next iteration: {:?}",
        segment.edges
    );
}

#[test]
fn loop_header_event_is_not_mistaken_for_a_loop_body_back_edge() {
    let mut decl = empty_decl(1, "loop_header_copy");
    decl.params = vec!["seed".to_string()];
    // Adapters emit loop-header operations beside the Loop event, not inside
    // its body. Its source span is contained by the loop AST span, so this
    // regression also proves that the stitcher uses structured event nesting
    // rather than raw span containment.
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(12, 18),
            target: "a".to_string(),
            source_name: Some("b".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Loop {
            span: span(10, 80),
            loop_kind: bonsai_lang_api::LoopKind::While,
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![FlowEvent::Assign {
                span: span(40, 50),
                target: "b.cmd".to_string(),
                source_name: Some("seed".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            }],
        },
    ];

    let ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let segment = ws.segment(SegmentId(0)).expect("loop-header segment");
    let has_false_back_edge = segment.edges.iter().any(|edge| {
        edge.meta.kind == IdgEdgeKind::IntraAssign
            && place_storage_name(segment, node_place(segment, edge.from).expect("source place")).as_deref()
                == Some("b.cmd")
            && place_storage_name(segment, node_place(segment, edge.to).expect("target place")).as_deref()
                == Some("a.cmd")
    });

    assert!(
        !has_false_back_edge,
        "span containment alone must not manufacture a loop-carried field copy: {:?}",
        segment.edges
    );
}

#[test]
fn self_referential_field_copy_reaches_a_finite_statement_order_fixpoint() {
    let mut decl = empty_decl(1, "self_ref");
    decl.params = vec!["seed".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "a.x".to_string(),
            source_name: Some("seed".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(30, 40),
            target: "a.child.link".to_string(),
            source_name: Some("a".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];

    let ws = stitch_idg(
        vec![transfer_function_for(&decl)],
        &MockResolver::new(),
        &StaticF2S(AHashMap::from([(FuncId::new(1), SegmentId(0))])),
    );
    let segment = ws.segment(SegmentId(0)).expect("self-reference segment");
    let storage_names = segment
        .places
        .places
        .iter()
        .filter_map(|place| place_storage_name(segment, place))
        .collect::<AHashSet<_>>();

    assert!(
        storage_names.contains("a.child.link.x"),
        "the copy must preserve the pre-statement field value: {storage_names:?}"
    );
    assert!(
        !storage_names.contains("a.child.link.child.link.x"),
        "a statement must not consume its own synthetic destination and grow an unbounded access path: {storage_names:?}"
    );
}

#[test]
fn call_return_field_cycle_reaches_only_the_ast_demanded_suffix_closure() {
    let assignment_span = span(30, 60);
    let call_span = span(35, 50);
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["seed".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "a.x".to_string(),
            source_name: Some("seed".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: assignment_span,
            target: "a.child".to_string(),
            source_name: None,
            source_call: Some("grow".to_string()),
            source_call_args: vec!["a".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: call_span,
            name: "grow".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(40, 41),
                name: None,
                value_text: "a".to_string(),
                place: Some("a".to_string()),
                source_names: Vec::new(),
            }],
        },
        // This exact adapter-emitted access path supplies the finite demand
        // for two recursive `child` suffixes.
        FlowEvent::Call {
            span: span(70, 80),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(75, 78),
                name: None,
                value_text: "a.child.child.x".to_string(),
                place: Some("a.child.child.x".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut callee = empty_decl(2, "grow");
    callee.params = vec!["value".to_string()];
    callee.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(90, 100),
        value_name: Some("value".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("value"),
    }];

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "grow", vec![FuncId::new(2)]);
    let ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&callee)],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
        ])),
    );
    let segment = ws.segment(SegmentId(0)).expect("caller segment");
    let generated_paths = segment
        .places
        .places
        .iter()
        .filter_map(|place| match place {
            Place::Write { span, .. } if *span == assignment_span => place_storage_name(segment, place),
            _ => None,
        })
        .collect::<AHashSet<_>>();

    assert!(
        generated_paths.contains("a.child.child.x"),
        "the exact two-level AST demand must survive the call/return closure: {generated_paths:?}"
    );
    assert!(
        !generated_paths.contains("a.child.child.child.child.x"),
        "recursive call/return base substitution must not invent an unbounded suffix language: {generated_paths:?}"
    );
}

#[test]
fn deep_field_argument_forwarding_preserves_the_complete_storage_path() {
    let caller_base = "root.a.b.c";
    let field = "payload.command.value";
    let caller_storage = format!("{caller_base}.{field}");
    let callee_storage = format!("arg.{field}");

    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["seed".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: caller_storage.clone(),
            source_name: Some("seed".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(30, 40),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(35, 36),
                name: None,
                value_text: caller_base.to_string(),
                place: Some(caller_base.to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut helper = empty_decl(2, "helper");
    helper.params = vec!["arg".to_string()];
    helper.flow_events = vec![FlowEvent::Call {
        span: span(50, 60),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(55, 56),
            name: None,
            value_text: callee_storage.clone(),
            place: Some(callee_storage.clone()),
            source_names: Vec::new(),
        }],
    }];

    let f2s = StaticF2S(AHashMap::from([
        (FuncId::new(1), SegmentId(0)),
        (FuncId::new(2), SegmentId(1)),
    ]));
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "helper", vec![FuncId::new(2)]);
    let ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&helper)],
        &resolver,
        &f2s,
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");

    assert!(
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterFieldCallArg
                && place_storage_name(
                    caller_segment,
                    node_place(caller_segment, edge.edge.from).expect("caller place"),
                )
                .as_deref()
                    == Some(caller_storage.as_str())
                && place_storage_name(
                    callee_segment,
                    node_place(callee_segment, edge.edge.to).expect("callee place"),
                )
                .as_deref()
                    == Some(callee_storage.as_str())
        }),
        "the full deep storage path must cross the resolved call boundary: {:?}",
        ws.cross_file().edges
    );
}

#[test]
fn mutable_out_parameter_write_flows_back_to_post_call_consumers() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["src".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(12, 18),
            target: "out".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(30, 42),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![
                CallArg {
                    passing_mode: Default::default(),
                    span: span(37, 38),
                    name: None,
                    value_text: "src".to_string(),
                    place: Some("src".to_string()),
                    source_names: Vec::new(),
                },
                CallArg {
                    passing_mode: bonsai_lang_api::ArgumentPassingMode::WriteBack,
                    span: span(39, 41),
                    name: None,
                    value_text: "&mut out".to_string(),
                    place: Some("out".to_string()),
                    source_names: Vec::new(),
                },
            ],
        },
        FlowEvent::Call {
            span: span(50, 60),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(55, 58),
                name: None,
                value_text: "out".to_string(),
                place: Some("out".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut helper = empty_decl(2, "helper");
    helper.params = vec!["p".to_string(), "out".to_string()];
    helper.flow_events = vec![FlowEvent::Assign {
        span: span(70, 78),
        target: "out".to_string(),
        source_name: Some("p".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    let f2s = StaticF2S(f2s_map);
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "helper", vec![FuncId::new(2)]);

    let ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&helper)],
        &resolver,
        &f2s,
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");
    let write_back = ws.cross_file().edges.iter().find(|edge| {
        edge.edge.meta.kind == IdgEdgeKind::InterReturn
            && write_place_storage_and_span(
                callee_segment,
                node_place(callee_segment, edge.edge.from).expect("callee write place"),
            )
            .is_some_and(|(name, write_span)| name == "out" && write_span == span(70, 78))
            && write_place_storage_and_span(
                caller_segment,
                node_place(caller_segment, edge.edge.to).expect("caller write place"),
            )
            .is_some_and(|(name, write_span)| name == "out" && write_span == span(30, 42))
    });
    let write_back = write_back.expect("callee out write should stitch to caller out write");
    let reaches_sink = caller_segment.edges.iter().any(|edge| {
        edge.from == write_back.edge.to
            && matches!(
                node_place(caller_segment, edge.to),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == span(50, 60)
            )
    });
    assert!(reaches_sink, "write-back must reach the post-call sink consumer");
}

#[test]
fn mutable_out_parameter_write_does_not_bypass_later_clean_overwrite() {
    let mut caller = empty_decl(1, "caller");
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(12, 18),
            target: "out".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(30, 42),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: bonsai_lang_api::ArgumentPassingMode::WriteBack,
                span: span(37, 41),
                name: None,
                value_text: "&mut out".to_string(),
                place: Some("out".to_string()),
                source_names: Vec::new(),
            }],
        },
        FlowEvent::Assign {
            span: span(44, 48),
            target: "out".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(50, 60),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(55, 58),
                name: None,
                value_text: "out".to_string(),
                place: Some("out".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    let ws = stitch_idg(
        vec![transfer_function_for(&caller)],
        &MockResolver::new(),
        &StaticF2S(f2s_map),
    );
    let consumers = scalar_post_call_consumer_edges(&ws, SegmentId(0), FuncId::new(1), "out", span(30, 42));
    assert!(
        consumers.is_empty(),
        "a later clean overwrite must kill write-back before the sink: {consumers:?}"
    );
}

#[test]
fn lexical_capture_stitch_is_name_preserving_and_local_binding_scoped() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["args".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 40),
            target: "closure".to_string(),
            source_name: Some("args".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(50, 60),
            name: "closure".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
    ];
    let mut closure = empty_decl(2, "closure");
    closure.flow_events = vec![FlowEvent::Call {
        span: span(70, 82),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(75, 79),
            name: None,
            value_text: "args".to_string(),
            place: Some("args".to_string()),
            source_names: vec!["args".to_string()],
        }],
    }];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    let f2s = StaticF2S(f2s_map);
    let mut local_resolver = MockResolver::new();
    local_resolver.add(FuncId::new(1), "closure", vec![FuncId::new(2)]);
    local_resolver.add_local_binding(FuncId::new(1), FuncId::new(2));
    let local_ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&closure)],
        &local_resolver,
        &f2s,
    );

    let has_capture_edge = |ws: &IdgWorkspace| {
        let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
        let closure_segment = ws.segment(SegmentId(1)).expect("closure segment");
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterCallArg
                && write_place_storage_and_span(
                    caller_segment,
                    node_place(caller_segment, edge.edge.from).expect("capture source place"),
                )
                .is_some_and(|(name, _)| name == "args")
                && matches!(
                    node_place(closure_segment, edge.edge.to),
                    Some(place @ Place::Read { .. })
                        if place_storage_name(closure_segment, place).as_deref() == Some("args")
                )
        })
    };
    assert!(
        has_capture_edge(&local_ws),
        "resolver-proven local callable must receive its matching captured writer"
    );

    let caller_output = transfer_function_for(&caller);
    let closure_output = transfer_function_for(&closure);
    let batches = || {
        vec![vec![
            (SegmentId(0), vec![caller_output.clone()]),
            (SegmentId(1), vec![closure_output.clone()]),
        ]]
    };
    let capture_funcs = AHashSet::from_iter([FuncId::new(2)]);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("local-capture.factstore");
    let persisted = stitch_idg_from_spooled_segment_batches(
        batches(),
        2,
        &local_resolver,
        SpooledStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: Some(&capture_funcs),
        },
    )
    .expect("spooled capture stitch");
    persisted
        .save_into_disk(&path, 0xCA97_0AEE)
        .expect("persist capture graph");
    let persisted = IdgWorkspace::load_from_disk(&path, 0xCA97_0AEE)
        .expect("load capture graph")
        .expect("capture graph exists");
    assert!(
        has_capture_edge(&persisted),
        "persistence capture filtering must retain resolver-proven callable targets"
    );

    let mut ordinary_resolver = MockResolver::new();
    ordinary_resolver.add(FuncId::new(1), "closure", vec![FuncId::new(2)]);
    let ordinary_ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&closure)],
        &ordinary_resolver,
        &f2s,
    );
    assert!(
        !has_capture_edge(&ordinary_ws),
        "ordinary functions must not capture same-named caller locals"
    );
}

#[test]
fn method_without_receiver_field_consumers_does_not_synthesize_receiver_field_forwarding() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["src".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "obj.secret".to_string(),
            source_name: Some("src".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(30, 45),
            name: "noop".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];

    let callee = empty_decl(2, "noop");

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(1));
    let f2s = StaticF2S(f2s_map);

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "noop", vec![FuncId::new(2)]);

    let ws = stitch_idg(
        vec![transfer_function_for(&caller), transfer_function_for(&callee)],
        &resolver,
        &f2s,
    );
    let callee_segment = ws.segment(SegmentId(1)).expect("callee segment");
    let callee_places = callee_segment
        .places
        .places
        .iter()
        .filter_map(|place| place_storage_name(callee_segment, place))
        .collect::<Vec<_>>();

    assert!(
        !callee_places.iter().any(|place| place == "receiver.secret"),
        "ordinary method calls without receiver-field consumers must not synthesize receiver field writes: {callee_places:?}"
    );
}

#[test]
fn resolved_method_receiver_field_writes_return_to_the_calling_object() {
    let capture_span = span(20, 35);
    let sink_span = span(50, 65);
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["input".to_string()];
    caller.flow_events = vec![
        FlowEvent::Call {
            span: capture_span,
            name: "obj.capture".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(30, 34),
                name: None,
                value_text: "input".to_string(),
                place: Some("input".to_string()),
                source_names: vec!["input".to_string()],
            }],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(55, 64),
                name: None,
                value_text: "obj.query".to_string(),
                place: Some("obj.query".to_string()),
                source_names: vec!["obj.query".to_string()],
            }],
        },
    ];

    let mut capture = empty_decl(2, "capture");
    capture.kind = DeclKind::Method;
    capture.params = vec!["input".to_string()];
    capture.implicit_receiver_names = vec!["this".to_string()];
    capture.receiver_field_writes = vec![FieldWrite {
        span: span(80, 92),
        target: "this.query".to_string(),
        source_param_indices: vec![0],
    }];
    capture.flow_events = vec![FlowEvent::Assign {
        span: span(80, 92),
        target: "this.query".to_string(),
        source_name: Some("input".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];

    let f2s = StaticF2S(AHashMap::from([
        (FuncId::new(1), SegmentId(0)),
        (FuncId::new(2), SegmentId(1)),
    ]));
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "obj.capture", vec![FuncId::new(2)]);
    let compiler_options = TransferOptions::compiler_semantics(Vec::new());
    let ws = stitch_idg(
        vec![
            transfer_function_for_with_options(&caller, &compiler_options),
            transfer_function_for_with_options(&capture, &compiler_options),
        ],
        &resolver,
        &f2s,
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let capture_segment = ws.segment(SegmentId(1)).expect("capture segment");

    assert!(
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterFieldReturn
                && place_storage_name(
                    capture_segment,
                    node_place(capture_segment, edge.edge.from).expect("capture write"),
                )
                .as_deref()
                    == Some("this.query")
                && place_storage_name(
                    caller_segment,
                    node_place(caller_segment, edge.edge.to).expect("caller write"),
                )
                .as_deref()
                    == Some("obj.query")
        }),
        "resolved method field mutation must write back to the exact caller receiver: {:?}",
        ws.cross_file().edges
    );
}

#[test]
fn compiler_semantics_chain_receiver_write_back_through_accessor_return() {
    let capture_span = span(20, 35);
    let accessor_span = span(40, 52);
    let sink_span = span(60, 75);
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["input".to_string(), "safe".to_string()];
    caller.flow_events = vec![
        FlowEvent::Call {
            span: capture_span,
            name: "obj.capture".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: vec![
                CallArg {
                    passing_mode: Default::default(),
                    span: span(28, 30),
                    name: None,
                    value_text: "input".to_string(),
                    place: Some("input".to_string()),
                    source_names: vec!["input".to_string()],
                },
                CallArg {
                    passing_mode: Default::default(),
                    span: span(31, 34),
                    name: None,
                    value_text: "safe".to_string(),
                    place: Some("safe".to_string()),
                    source_names: vec!["safe".to_string()],
                },
            ],
        },
        FlowEvent::Assign {
            span: span(38, 54),
            target: "selected".to_string(),
            source_name: None,
            source_call: Some("obj.resource".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: accessor_span,
            name: "obj.resource".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(67, 73),
                name: None,
                value_text: "selected".to_string(),
                place: Some("selected".to_string()),
                source_names: vec!["selected".to_string()],
            }],
        },
    ];

    let mut capture = empty_decl(2, "capture");
    capture.kind = DeclKind::Method;
    capture.params = vec!["input".to_string(), "safe".to_string()];
    capture.implicit_receiver_names = vec!["this".to_string()];
    capture.receiver_field_writes = vec![
        FieldWrite {
            span: span(80, 90),
            target: "this.query".to_string(),
            source_param_indices: vec![0],
        },
        FieldWrite {
            span: span(91, 100),
            target: "this.other".to_string(),
            source_param_indices: vec![1],
        },
    ];
    capture.flow_events = vec![
        FlowEvent::Assign {
            span: span(80, 90),
            target: "this.query".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(91, 100),
            target: "this.other".to_string(),
            source_name: Some("safe".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];

    let mut accessor = empty_decl(3, "resource");
    accessor.kind = DeclKind::Method;
    accessor.implicit_receiver_names = vec!["this".to_string()];
    accessor.receiver_state_sources = vec!["this.query.resource".to_string()];
    accessor.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(110, 120),
        value_name: Some("this.query.resource".to_string()),
        value_text: Some("this.query.resource".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("this.query.resource"),
    }];

    let compiler_options = TransferOptions::compiler_semantics(Vec::new());
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "obj.capture", vec![FuncId::new(2)]);
    resolver.add(FuncId::new(1), "obj.resource", vec![FuncId::new(3)]);
    let ws = stitch_idg(
        vec![
            transfer_function_for_with_options(&caller, &compiler_options),
            transfer_function_for_with_options(&capture, &compiler_options),
            transfer_function_for_with_options(&accessor, &compiler_options),
        ],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
            (FuncId::new(3), SegmentId(2)),
        ])),
    );
    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let reaches_sink = |name: &str| {
        let seeds = service.read_or_write_nodes_for_names(FuncId::new(1), &[name.to_string()]);
        service
            .forward_closure(&seeds)
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(1), sink_span, 0)))
    };
    assert!(
        reaches_sink("input"),
        "the exact receiver field write must flow through the zero-argument accessor return"
    );
    assert!(
        !reaches_sink("safe"),
        "a sibling receiver field must not flow through the accessor return"
    );
}

#[test]
fn parameterless_receiver_accessor_forwards_the_exact_object_field() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["src".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 18),
            target: "value.cmd".to_string(),
            source_name: Some("src".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(30, 45),
            name: "cmd".to_string(),
            receiver: Some("value".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];

    let mut getter = empty_decl(2, "cmd");
    getter.kind = DeclKind::Method;
    getter.implicit_receiver_names = vec!["self".to_string(), "super".to_string()];
    getter.receiver_state_sources = vec!["self.cmd".to_string()];
    getter.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(60, 68),
        value_name: Some("self.cmd".to_string()),
        value_text: Some("self.cmd".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("self.cmd"),
    }];

    let f2s = StaticF2S(AHashMap::from([
        (FuncId::new(1), SegmentId(0)),
        (FuncId::new(2), SegmentId(1)),
    ]));
    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "cmd", vec![FuncId::new(2)]);
    let compiler_options = TransferOptions::compiler_semantics(Vec::new());

    let ws = stitch_idg(
        vec![
            transfer_function_for_with_options(&caller, &compiler_options),
            transfer_function_for_with_options(&getter, &compiler_options),
        ],
        &resolver,
        &f2s,
    );
    let caller_segment = ws.segment(SegmentId(0)).expect("caller segment");
    let getter_segment = ws.segment(SegmentId(1)).expect("getter segment");
    assert!(
        ws.cross_file().edges.iter().any(|edge| {
            edge.edge.meta.kind == IdgEdgeKind::InterFieldCallArg
                && place_storage_name(
                    caller_segment,
                    node_place(caller_segment, edge.edge.from).expect("caller place"),
                )
                .as_deref()
                    == Some("value.cmd")
                && place_storage_name(
                    getter_segment,
                    node_place(getter_segment, edge.edge.to).expect("getter place"),
                )
                .as_deref()
                    == Some("self.cmd")
        }),
        "a parameter-less accessor must map value.cmd to its declared self.cmd receiver field: {:?}",
        ws.cross_file().edges
    );
}

#[test]
fn returned_fields_flow_through_a_nested_call_receiver_without_collapsing_siblings() {
    let inner_call_span = span(20, 24);
    let inner_expression_span = span(15, 35);
    let outer_call_span = span(40, 43);
    let sink_span = span(80, 92);

    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["input".to_string()];
    // PHP and several other grammars lower the outer call before the nested
    // receiver call. Receiver/result bridging is span-based and must not
    // depend on FlowEvent order.
    caller.flow_events = vec![
        FlowEvent::Call {
            span: outer_call_span,
            name: "run".to_string(),
            receiver: Some("Factory::wrap(input)".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Call {
            span: inner_call_span,
            name: "wrap".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(28, 33),
                name: None,
                value_text: "input".to_string(),
                place: Some("input".to_string()),
                source_names: vec!["input".to_string()],
            }],
        },
    ];
    let receiver_facts = vec![bonsai_lang_api::CallReceiverFact {
        call_span: outer_call_span,
        receiver_span: inner_expression_span,
        value_flow: bonsai_lang_api::ExpressionFlow {
            call_sites: vec![inner_expression_span],
            ..Default::default()
        },
        role: bonsai_lang_api::CallReceiverRole::Value,
        static_value: None,
    }];

    let mut wrap = empty_decl(2, "wrap");
    wrap.params = vec!["data".to_string()];
    wrap.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(50, 70),
        value_name: None,
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                name: "data".to_string(),
                value_span: Some(span(55, 68)),
                value: bonsai_lang_api::ExpressionFlow {
                    aggregate_fields: vec![
                        bonsai_lang_api::ExpressionField {
                            name: "cmd".to_string(),
                            value_span: Some(span(58, 61)),
                            value: bonsai_lang_api::ExpressionFlow::from_place("data.cmd"),
                        },
                        bonsai_lang_api::ExpressionField {
                            name: "user".to_string(),
                            value_span: Some(span(63, 67)),
                            value: bonsai_lang_api::ExpressionFlow::from_place("data.user"),
                        },
                    ],
                    ..Default::default()
                },
            }],
            ..Default::default()
        },
    }];

    let mut run = empty_decl(3, "run");
    run.implicit_receiver_names = vec!["this".to_string()];
    run.receiver_state_sources = vec!["this.data".to_string()];
    run.flow_events = vec![FlowEvent::Call {
        span: sink_span,
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(85, 90),
            name: None,
            value_text: "this.data.cmd".to_string(),
            place: Some("this.data.cmd".to_string()),
            source_names: vec!["this.data.cmd".to_string()],
        }],
    }];

    let caller_transfer = transfer_function_for_with_options_and_syntax_facts(
        &caller,
        &TransferOptions::default(),
        &[],
        &receiver_facts,
    );
    let temporary_receiver = caller_transfer
        .call_sites
        .iter()
        .find(|site| site.site.0 == outer_call_span)
        .and_then(|site| site.receiver_storage_base.as_deref());
    assert!(
        temporary_receiver.is_some_and(|base| base.starts_with("__bonsai_receiver_")),
        "nested call receiver must lower to a span-derived storage identity: {temporary_receiver:?}"
    );

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "wrap", vec![FuncId::new(2)]);
    resolver.add(FuncId::new(1), "run", vec![FuncId::new(3)]);
    let ws = stitch_idg_with_field_forwarding_mode(
        vec![
            caller_transfer,
            transfer_function_for(&wrap),
            transfer_function_for(&run),
        ],
        &resolver,
        &StaticF2S(AHashMap::from([
            (FuncId::new(1), SegmentId(0)),
            (FuncId::new(2), SegmentId(1)),
            (FuncId::new(3), SegmentId(2)),
        ])),
        true,
        false,
    );
    let service = IdgQueryService::new(Arc::new(ws), Arc::new(GlobalIndex::new()));
    let cmd_seeds =
        service.read_or_write_nodes_for_names(FuncId::new(2), &["__bonsai_return.data.cmd".to_string()]);
    let user_seeds =
        service.read_or_write_nodes_for_names(FuncId::new(2), &["__bonsai_return.data.user".to_string()]);
    assert!(!cmd_seeds.is_empty() && !user_seeds.is_empty());

    let reaches_sink = |seeds: &[WsNodeId]| {
        service
            .forward_closure(seeds)
            .iter()
            .any(|node| service.call_arg_identity(*node) == Some((FuncId::new(3), sink_span, 0)))
    };
    assert!(
        reaches_sink(&cmd_seeds),
        "the exact returned data.cmd field must reach the chained receiver's matching field read"
    );
    assert!(
        !reaches_sink(&user_seeds),
        "a sibling returned data.user field must not be promoted into data.cmd"
    );
}

#[test]
fn same_segment_field_argument_forwarding_treats_synthetic_param_fields_as_inputs() {
    let mut caller = empty_decl(1, "caller");
    caller.params = vec!["src".to_string()];
    caller.flow_events = vec![
        FlowEvent::Assign {
            span: span(70, 78),
            target: "box.cmd".to_string(),
            source_name: Some("src".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(80, 95),
            name: "helper".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(87, 90),
                name: None,
                value_text: "box".to_string(),
                place: Some("box".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut helper = empty_decl(2, "helper");
    helper.params = vec!["arg".to_string()];
    helper.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 18),
            target: "tmp".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["arg.cmd".to_string()],
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(20, 35),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(27, 30),
                name: None,
                value_text: "arg".to_string(),
                place: Some("arg".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let mut sink = empty_decl(3, "sink");
    sink.params = vec!["value".to_string()];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(0));
    f2s_map.insert(FuncId::new(3), SegmentId(0));
    let f2s = StaticF2S(f2s_map);

    let mut resolver = MockResolver::new();
    resolver.add(FuncId::new(1), "helper", vec![FuncId::new(2)]);
    resolver.add(FuncId::new(2), "sink", vec![FuncId::new(3)]);

    let ws = stitch_idg(
        vec![
            transfer_function_for(&caller),
            transfer_function_for(&helper),
            transfer_function_for(&sink),
        ],
        &resolver,
        &f2s,
    );
    let segment = ws.segment(SegmentId(0)).expect("single segment");
    let forwards_cmd_field = segment.edges.iter().any(|edge| {
        edge.meta.kind == IdgEdgeKind::InterFieldCallArg
            && place_storage_name(segment, node_place(segment, edge.from).expect("from place")).as_deref()
                == Some("arg.cmd")
            && place_storage_name(segment, node_place(segment, edge.to).expect("to place")).as_deref()
                == Some("value.cmd")
    });

    assert!(
        forwards_cmd_field,
        "expected helper arg.cmd to forward to sink value.cmd despite caller call span ordering"
    );

    let forwards_cmd_read = segment.edges.iter().any(|edge| {
        edge.meta.kind == IdgEdgeKind::IntraFieldRead
            && place_storage_name(segment, node_place(segment, edge.from).expect("from place")).as_deref()
                == Some("arg.cmd")
            && place_storage_name(segment, node_place(segment, edge.to).expect("to place")).as_deref()
                == Some("arg.cmd")
    });

    assert!(
        forwards_cmd_read,
        "synthetic param field writes must connect to matching field reads with IntraFieldRead"
    );
}
