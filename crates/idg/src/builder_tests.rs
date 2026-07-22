use super::*;
use crate::edge::IdgEdgeKind;
use crate::node::NodeId;
use crate::place::Place;
use crate::query::ReachabilityIndex;
use crate::transfer::{transfer_function_for, transfer_function_for_with_options, TransferOptions};
use crate::{IdgQueryService, PointKind};
use bonsai_common::{FileId, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{CallArg, CallKind, Decl, DeclKind, FlowEvent, ModulePath, Visibility};
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

/// Mock resolver: a fixed map from (caller_func, callee_name)
/// to candidate FuncIds. All resolved as Direct + Exact.
struct MockResolver {
    table: AHashMap<(FuncId, String), Vec<FuncId>>,
    callback_bindings: AHashMap<(FuncId, u32), Vec<FuncId>>,
    callable_args: AHashMap<(FuncId, String), Vec<FuncId>>,
    callable_arg_spans: AHashMap<(FuncId, Span), Vec<FuncId>>,
    local_bindings: AHashSet<(FuncId, FuncId)>,
}

impl MockResolver {
    fn new() -> Self {
        Self {
            table: AHashMap::new(),
            callback_bindings: AHashMap::new(),
            callable_args: AHashMap::new(),
            callable_arg_spans: AHashMap::new(),
            local_bindings: AHashSet::new(),
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

    fn add_callable_arg(&mut self, caller: FuncId, arg_text: &str, callees: Vec<FuncId>) {
        self.callable_args.insert((caller, arg_text.to_string()), callees);
    }

    fn add_callable_arg_span(&mut self, caller: FuncId, arg_span: Span, callees: Vec<FuncId>) {
        self.callable_arg_spans.insert((caller, arg_span), callees);
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
                precision: Precision::Exact,
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
                precision: Precision::Narrowed,
            })
            .collect()
    }

    fn callable_arg(&self, caller: FuncId, arg_text: &str) -> Vec<ResolvedCallee> {
        self.callable_args
            .get(&(caller, arg_text.to_string()))
            .into_iter()
            .flatten()
            .map(|func| ResolvedCallee {
                func: *func,
                edge_kind: CallEdgeKind::Indirect,
                precision: Precision::Narrowed,
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
                precision: Precision::Narrowed,
            })
            .collect()
    }
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
fn relowered_stitch_preserves_the_exact_canonical_graph() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
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
    let path = dir.path().join("relowered-idg.factstore");
    let relowered = stitch_idg_from_relowered_segment_batches(
        batches(),
        batches(),
        1,
        &resolver,
        ReloweredStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: None,
        },
    )
    .expect("spooled relowering");
    relowered
        .save_into_disk(&path, 0x51DE_CAFE)
        .expect("persist spooled graph");
    let relowered = IdgWorkspace::load_from_disk(&path, 0x51DE_CAFE)
        .expect("load spooled graph")
        .expect("spooled graph exists");

    let queryable_wire = bonsai_common::wire::encode(&queryable).expect("encode queryable IDG");
    let relowered_wire = bonsai_common::wire::encode(&relowered).expect("encode relowered IDG");
    assert_eq!(relowered_wire, queryable_wire);
}

#[test]
fn relowered_sidecar_preserves_cross_segment_calls_byte_for_byte() {
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
    let relowered = stitch_idg_from_relowered_segment_batches(
        batches(),
        batches(),
        2,
        &resolver,
        ReloweredStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: None,
        },
    )
    .expect("spooled relowering");
    assert_eq!(
        relowered.cross_file_edge_count(),
        queryable.cross_file().len(),
        "sidecar compilation must count every disk-spooled cross edge"
    );
    assert!(
        relowered.cross_file().is_empty(),
        "sidecar compilation must not retain its canonical cross-edge vector in memory"
    );
    relowered
        .save_into_disk(&path, 0xC205_5E6A)
        .expect("persist cross-segment spool");
    let relowered = IdgWorkspace::load_from_disk(&path, 0xC205_5E6A)
        .expect("load cross-segment sidecar")
        .expect("cross-segment sidecar exists");

    assert_eq!(queryable.cross_file().len(), 2);
    assert_eq!(
        bonsai_common::wire::encode(&relowered).expect("encode relowered cross-segment IDG"),
        bonsai_common::wire::encode(&queryable).expect("encode queryable cross-segment IDG")
    );
}

#[test]
fn relowered_sidecar_preserves_symbolic_field_graph_byte_for_byte() {
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
        let relowered = stitch_idg_from_relowered_segment_batches(
            batches(),
            batches(),
            2,
            &resolver,
            ReloweredStitchOptions {
                spool_path: &path,
                include_field_argument_forwarding: true,
                symbolic_field_forwarding: true,
                symbolic_funcs: Some(&symbolic_funcs),
                capture_funcs: None,
            },
        )
        .expect("spooled symbolic relowering");
        assert_eq!(
            relowered.symbolic_transform_count(),
            queryable.symbolic_field().transforms().len(),
            "sidecar compilation must count every disk-spooled symbolic transform"
        );
        assert!(
            relowered.symbolic_field().transforms().is_empty(),
            "sidecar compilation must not retain symbolic transforms in memory"
        );
        relowered
            .save_into_disk(&path, 0x51A0_B01C)
            .expect("persist symbolic transform spool");
        let relowered = IdgWorkspace::load_from_disk(&path, 0x51A0_B01C)
            .expect("load symbolic sidecar")
            .expect("symbolic sidecar exists");

        assert_eq!(
            bonsai_common::wire::encode(&relowered).expect("encode relowered symbolic IDG"),
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
fn callable_argument_routes_method_receiver_to_callback_without_outer_callee() {
    let mut host = empty_decl(1, "host");
    host.params = vec!["items".to_string()];
    host.flow_events = vec![FlowEvent::Call {
        span: span(20, 30),
        name: "items.traverse".to_string(),
        receiver: Some("items".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(25, 29),
            name: None,
            value_text: "&method(:step)".to_string(),
            place: Some("&method(:step)".to_string()),
            source_names: Vec::new(),
        }],
    }];
    let mut callback = empty_decl(2, "step");
    callback.params = vec!["item".to_string()];

    let mut f2s_map = AHashMap::new();
    f2s_map.insert(FuncId::new(1), SegmentId(0));
    f2s_map.insert(FuncId::new(2), SegmentId(0));
    let f2s = StaticF2S(f2s_map);
    let mut resolver = MockResolver::new();
    resolver.add_callable_arg_span(FuncId::new(1), span(25, 29), vec![FuncId::new(2)]);

    let ws = stitch_idg(
        vec![transfer_function_for(&host), transfer_function_for(&callback)],
        &resolver,
        &f2s,
    );
    let segment = ws.segment(SegmentId(0)).expect("shared segment");

    assert!(
        segment.edges.iter().any(|edge| {
            let Some(from) = segment.nodes.get(edge.from) else {
                return false;
            };
            let Some(to) = segment.nodes.get(edge.to) else {
                return false;
            };
            from.func == FuncId::new(1)
                && to.func == FuncId::new(2)
                && call_arg_idx(segment, edge.from) == Some(u32::MAX)
                && param_idx(segment, edge.to) == Some(0)
                && edge.meta.kind == IdgEdgeKind::InterCallArg
        }),
        "AST-resolved callable arguments must route the collection receiver to the callback parameter without resolving the outer library method: {:#?}",
        segment.edges
    );
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
            && edge.meta.precision == Precision::Narrowed
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
    let universe = FieldPlaceIndex::from_workspace(&ws).syntactic_field_universe();

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
    let relowered = stitch_idg_from_relowered_segment_batches(
        batches(),
        batches(),
        2,
        &local_resolver,
        ReloweredStitchOptions {
            spool_path: &path,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_funcs: None,
            capture_funcs: Some(&capture_funcs),
        },
    )
    .expect("spooled capture relowering");
    relowered
        .save_into_disk(&path, 0xCA97_0AEE)
        .expect("persist capture graph");
    let relowered = IdgWorkspace::load_from_disk(&path, 0xCA97_0AEE)
        .expect("load capture graph")
        .expect("capture graph exists");
    assert!(
        has_capture_edge(&relowered),
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
