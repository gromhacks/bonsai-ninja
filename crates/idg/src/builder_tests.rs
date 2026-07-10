use super::*;
use crate::edge::IdgEdgeKind;
use crate::node::NodeId;
use crate::place::Place;
use crate::transfer::{transfer_function_for, transfer_function_for_with_options, TransferOptions};
use bonsai_common::{FileId, SymbolId};
use bonsai_lang_api::{CallArg, CallKind, Decl, DeclKind, FlowEvent, ModulePath, Visibility};

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
    callable_args: AHashMap<(FuncId, String), Vec<FuncId>>,
    callable_arg_spans: AHashMap<(FuncId, Span), Vec<FuncId>>,
    local_bindings: AHashSet<(FuncId, FuncId)>,
}

impl MockResolver {
    fn new() -> Self {
        Self {
            table: AHashMap::new(),
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

fn call_arg_idx(segment: &IdgSegment, node: NodeId) -> Option<u8> {
    match node_place(segment, node)? {
        Place::CallArg { idx, .. } => Some(*idx),
        _ => None,
    }
}

fn param_idx(segment: &IdgSegment, node: NodeId) -> Option<u8> {
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
                && call_arg_idx(segment, edge.from) == Some(u8::MAX)
                && param_idx(segment, edge.to) == Some(0)
                && edge.meta.kind == IdgEdgeKind::InterCallArg
        }),
        "AST-resolved callable arguments must route the collection receiver to the callback parameter without resolving the outer library method: {:#?}",
        segment.edges
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
        !out_f.call_sites[0].call_arg_nodes.is_empty(),
        "the adapter-shaped zero-arg method should still expose its synthetic carrier"
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
            Some(Place::CallArg { idx: u8::MAX, .. })
        ) && matches!(node_place(segment, edge.to), Some(Place::CallRet { .. }))
    }));
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
        arg_to_param.contains(&(Some(u8::MAX), Some(0))),
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
        edge.edge.meta.kind == IdgEdgeKind::InterCallArg
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
fn field_argument_forwarding_worklist_deduplicates_pending_writes() {
    let key = FieldPlaceKey {
        seg_id: SegmentId(0),
        func: FuncId::new(1),
        base: "box".to_string(),
        writes: true,
    };
    let hit = FieldPlaceHit {
        field: "cmd".to_string(),
        node: NodeId(7),
        span: Some(span(10, 18)),
    };
    let mut pending = VecDeque::new();
    let mut enqueued = AHashSet::default();

    enqueue_field_write(key.clone(), hit.clone(), &mut pending, &mut enqueued);
    enqueue_field_write(key, hit, &mut pending, &mut enqueued);

    assert_eq!(pending.len(), 1);
    assert_eq!(enqueued.len(), 1);
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
        edge.meta.kind == IdgEdgeKind::InterCallArg
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
