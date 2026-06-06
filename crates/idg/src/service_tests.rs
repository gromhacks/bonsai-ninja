use super::*;
use crate::workspace_adapter;
use bonsai_callgraph::{CallEdge, CallGraph, EdgeKind, ResolvedCallGraph};
use bonsai_common::{Precision, SymbolId};
use bonsai_lang_api::{Decl, DeclIndex, DeclKind, FieldWrite, FlowEvent, ModulePath, Visibility};

fn span(file: u32, start: u64, end: u64) -> Span {
    Span::new(bonsai_common::FileId::new(file), start, end)
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
            refs: Vec::new(),
            strings: Vec::new(),
            comments: Vec::new(),
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
fn unified_address_space_is_lazily_built() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
    }];
    let (idx, ws) = build(vec![decl]);
    let svc = IdgQueryService::new(ws, idx);
    // Trigger materialisation.
    let params = svc.param_nodes_of(FuncId::new(0));
    assert!(!params.is_empty());
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
fn reaches_is_consistent_with_forward_closure() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["x".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        span: span(0, 20, 30),
        value_name: Some("x".to_string()),
        value_text: None,
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
                    span: span(0, 25, 32),
                    name: None,
                    value_text: "env.cmd".to_string(),
                    place: Some("env.cmd".to_string()),
                    source_names: vec!["env.cmd".to_string(), "env".to_string()],
                },
                bonsai_lang_api::CallArg {
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
        edges
            .iter()
            .any(|e| { e.caller == f_id && e.callee == g_id && e.arg_idx == 0 && e.param_idx == 0 }),
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
fn returned_container_field_forwards_to_assigned_object_argument() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["raw".to_string(), "user".to_string()];
    entry.flow_events = vec![
        FlowEvent::Assign {
            span: span(0, 10, 20),
            target: "env".to_string(),
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
        },
    ];

    let mut run = empty_decl(5, 1, "run");
    run.kind = DeclKind::Method;
    run.parent = Some(repository_class.symbol);
    run.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 200, 207),
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
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
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 300, 315),
        value_name: None,
        value_text: Some("$this->data['cmd']".to_string()),
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
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 240, 253),
        value_name: None,
        value_text: Some("self.data[:cmd]".to_string()),
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
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 440, 455),
        value_name: None,
        value_text: Some("self.data[:cmd]".to_string()),
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

    let mut base_ctor = empty_decl(4, 1, "BaseRepository");
    base_ctor.kind = DeclKind::Constructor;
    base_ctor.params = vec!["data".to_string()];
    base_ctor.receiver_field_writes = vec![FieldWrite {
        span: span(1, 70, 90),
        target: "this.data".to_string(),
        source_param_indices: vec![0],
    }];

    let mut repository_ctor = empty_decl(5, 1, "Repository");
    repository_ctor.kind = DeclKind::Constructor;
    repository_ctor.params = vec!["data".to_string()];
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
            span: span(1, 115, 119),
            name: None,
            value_text: "data".to_string(),
            place: Some("data".to_string()),
            source_names: vec!["data".to_string()],
        }],
    }];

    let mut audited_ctor = empty_decl(6, 1, "AuditedRepository");
    audited_ctor.kind = DeclKind::Constructor;
    audited_ctor.params = vec!["data".to_string()];
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
            span: span(1, 145, 149),
            name: None,
            value_text: "data".to_string(),
            place: Some("data".to_string()),
            source_names: vec!["data".to_string()],
        }],
    }];

    let mut wrap = empty_decl(7, 1, "wrap");
    wrap.kind = DeclKind::Method;
    wrap.params = vec!["data".to_string()];
    wrap.flow_events = vec![
        FlowEvent::Call {
            span: span(1, 160, 178),
            name: "AuditedRepository".to_string(),
            receiver: None,
            receiver_types: vec!["AuditedRepository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Constructor,
            args: vec![bonsai_lang_api::CallArg {
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
    cmd.flow_events = vec![FlowEvent::Return {
        span: span(1, 440, 455),
        value_name: None,
        value_text: Some("data.cmd".to_string()),
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
    let raw_calls = svc.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls
            .iter()
            .any(|(_, call_span, idx)| *call_span == span(2, 500, 510) && *idx == 0),
        "inline factory receiver field must flow through super.run and bare cmd accessor: {raw_calls:?}"
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
