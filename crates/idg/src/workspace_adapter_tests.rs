use super::*;
use ahash::AHashMap;
use bonsai_callgraph::{CallEdge, CallGraph, EdgeKind, ResolvedCallGraph};
use bonsai_common::{Precision, Span, SymbolId};
use bonsai_lang_api::{Decl, DeclKind, FlowEvent, ModulePath, Visibility};

fn span(file: u32, start: u64, end: u64) -> Span {
    Span::new(FileId::new(file), start, end)
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
    }
}

fn build_index(decls: Vec<Decl>) -> GlobalIndex {
    // Group decls by their file id, build one `DeclIndex` per
    // file, and insert all of them. `GlobalIndex::insert` is
    // per-file, not per-decl.
    let mut by_file: AHashMap<FileId, Vec<Decl>> = AHashMap::new();
    for d in decls {
        by_file.entry(d.span.file).or_default().push(d);
    }
    let mut idx = GlobalIndex::new();
    let mut files: Vec<(FileId, Vec<Decl>)> = by_file.into_iter().collect();
    files.sort_by_key(|(file, _)| file.raw());
    for (file, defs) in files {
        idx.insert(bonsai_lang_api::DeclIndex {
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

#[test]
fn empty_workspace_produces_empty_idg() {
    let idx = GlobalIndex::new();
    let cg = ResolvedCallGraph::default();
    let ws = build(&idx, &cg);
    assert_eq!(ws.segment_count(), 0);
}

#[test]
fn one_function_one_file_yields_one_segment() {
    let mut decl = empty_decl(1, 0, "f");
    decl.params = vec!["x".to_string()];
    let idx = build_index(vec![decl]);
    let cg = ResolvedCallGraph::default();
    let ws = build(&idx, &cg);
    assert_eq!(ws.segment_count(), 1);
    // GlobalIndex remaps SymbolId on insert, so the FuncId
    // we look up is the post-remap one (0 — first symbol
    // inserted into a fresh GlobalIndex).
    assert!(ws.segment_for_func(FuncId::new(0)).is_some());
}

#[test]
fn two_files_with_call_creates_cross_file_edges_when_callgraph_resolves() {
    // file 0: f calls g
    let mut f = empty_decl(1, 0, "f");
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
    // file 1: g(arg) returns arg
    let mut g = empty_decl(2, 1, "g");
    g.params = vec!["arg".to_string()];
    g.flow_events = vec![FlowEvent::Return {
        span: span(1, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
    }];

    let idx = build_index(vec![f, g]);
    let cg = resolved_graph([(func_id(&idx, "f"), func_id(&idx, "g"), span(0, 20, 30))]);

    let ws = build(&idx, &cg);
    assert_eq!(ws.segment_count(), 2);
    // Two cross-file edges: CallArg→Param, Return→CallRet.
    assert_eq!(ws.cross_file().len(), 2);
}

#[test]
fn callee_token_call_site_stitches_full_expression_callgraph_edge() {
    // Some adapters anchor FlowEvent::Call at the callee token
    // (`execute`) while the callgraph resolver anchors the same
    // dispatch at the full expression (`Executor.execute(cmd)`).
    // The stitcher must treat those contained spans as one semantic
    // call site, while callee-name filtering still chooses the
    // correct target.
    let mut f = empty_decl(1, 0, "f");
    f.flow_events = vec![FlowEvent::Call {
        span: span(0, 30, 37),
        name: "Executor.execute".to_string(),
        receiver: Some("Executor".to_string()),
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Method,
        args: vec![bonsai_lang_api::CallArg {
            span: span(0, 38, 41),
            name: None,
            value_text: "cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: vec!["cmd".to_string()],
        }],
    }];
    let mut execute = empty_decl(2, 1, "execute");
    execute.params = vec!["cmd".to_string()];

    let idx = build_index(vec![f, execute]);
    let f_id = func_id(&idx, "f");
    let execute_id = func_id(&idx, "execute");
    let cg = resolved_graph([(f_id, execute_id, span(0, 21, 42))]);

    let ws = build(&idx, &cg);
    assert_eq!(
        ws.cross_file().len(),
        2,
        "callee-token flow event span must stitch to full-expression callgraph edge"
    );
}

#[test]
fn higher_order_callback_stitches_invocation_arg_to_bound_function_param() {
    let mut entry = empty_decl(1, 0, "entry");
    entry.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 30),
        name: "runCb".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![
            bonsai_lang_api::CallArg {
                span: span(0, 21, 29),
                name: None,
                value_text: "executor".to_string(),
                place: Some("executor".to_string()),
                source_names: vec!["executor".to_string()],
            },
            bonsai_lang_api::CallArg {
                span: span(0, 31, 32),
                name: None,
                value_text: "t".to_string(),
                place: Some("t".to_string()),
                source_names: vec!["t".to_string()],
            },
        ],
    }];

    let mut run_cb = empty_decl(2, 1, "runCb");
    run_cb.params = vec!["cb".to_string(), "value".to_string()];
    run_cb.flow_events = vec![FlowEvent::Call {
        span: span(1, 120, 130),
        name: "cb".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            span: span(1, 123, 128),
            name: None,
            value_text: "value".to_string(),
            place: Some("value".to_string()),
            source_names: vec!["value".to_string()],
        }],
    }];

    let mut executor = empty_decl(3, 2, "executor");
    executor.params = vec!["cmd".to_string()];

    let idx = build_index(vec![entry, run_cb, executor]);
    let entry_id = func_id(&idx, "entry");
    let run_cb_id = func_id(&idx, "runCb");
    let executor_id = func_id(&idx, "executor");
    let cg = resolved_graph([(entry_id, run_cb_id, span(0, 20, 30))]);

    let ws = build(&idx, &cg);
    let run_cb_segment = ws.segment_for_func(run_cb_id).expect("runCb segment");
    let executor_segment = ws.segment_for_func(executor_id).expect("executor segment");
    let callback_arg_edges = ws
        .cross_file()
        .edges
        .iter()
        .filter(|cross| {
            cross.from_segment == run_cb_segment
                && cross.to_segment == executor_segment
                && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
                && cross.edge.meta.call_kind == EdgeKind::Indirect
                && cross.edge.meta.via_span == span(1, 120, 130)
        })
        .count();

    assert_eq!(
        callback_arg_edges, 1,
        "callback invocation `cb(value)` must pass invocation arg `value` into bound function `executor(cmd)`"
    );
}

#[test]
fn repeated_calls_to_same_callee_do_not_duplicate_candidates_per_site() {
    let mut f = empty_decl(1, 0, "f");
    let call = |start, end| FlowEvent::Call {
        span: span(0, start, end),
        name: "g".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            span: span(0, start + 1, start + 2),
            name: None,
            value_text: "x".to_string(),
            place: Some("x".to_string()),
            source_names: Vec::new(),
        }],
    };
    f.flow_events = vec![call(20, 30), call(40, 50)];

    let mut g = empty_decl(2, 1, "g");
    g.params = vec!["arg".to_string()];
    g.flow_events = vec![FlowEvent::Return {
        span: span(1, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
    }];

    let idx = build_index(vec![f, g]);
    let f_id = func_id(&idx, "f");
    let g_id = func_id(&idx, "g");
    let cg = resolved_graph([(f_id, g_id, span(0, 20, 30)), (f_id, g_id, span(0, 40, 50))]);
    assert_eq!(
        cg.callees_of(f_id).count(),
        2,
        "fixture should contain two callgraph rows for the two sites"
    );

    let ws = build(&idx, &cg);
    // Each syntactic call site needs one CallArg->Param and one
    // Return->CallRet edge. The resolver must not replay the
    // other callgraph row at each site and create 8 parallel edges.
    assert_eq!(ws.cross_file().len(), 4);
}

#[test]
fn same_method_name_on_different_receiver_types_stitches_by_exact_site() {
    let mut f = empty_decl(1, 0, "f");
    let call = |start, end, receiver: &str, receiver_type: &str| FlowEvent::Call {
        span: span(0, start, end),
        name: format!("{receiver}.run"),
        receiver: Some(receiver.to_string()),
        receiver_types: vec![receiver_type.to_string()],
        call_kind: bonsai_lang_api::CallKind::Method,
        args: vec![bonsai_lang_api::CallArg {
            span: span(0, start + 1, start + 2),
            name: None,
            value_text: "x".to_string(),
            place: Some("x".to_string()),
            source_names: Vec::new(),
        }],
    };
    f.flow_events = vec![call(20, 30, "a", "A"), call(40, 50, "b", "B")];

    let mut class_a = empty_decl(2, 1, "A");
    class_a.kind = DeclKind::Class;
    let mut run_a = empty_decl(3, 1, "run");
    run_a.kind = DeclKind::Method;
    run_a.parent = Some(SymbolId::new(2));
    run_a.params = vec!["arg".to_string()];
    run_a.flow_events = vec![FlowEvent::Return {
        span: span(1, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
    }];

    let mut class_b = empty_decl(4, 2, "B");
    class_b.kind = DeclKind::Class;
    let mut run_b = empty_decl(5, 2, "run");
    run_b.kind = DeclKind::Method;
    run_b.parent = Some(SymbolId::new(4));
    run_b.params = vec!["arg".to_string()];
    run_b.flow_events = vec![FlowEvent::Return {
        span: span(2, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
    }];

    let idx = build_index(vec![f, class_a, run_a, class_b, run_b]);
    let f_id = func_id(&idx, "f");
    let run_ids: Vec<FuncId> = idx
        .all_files()
        .flat_map(|file| idx.functions_in(file))
        .filter(|decl| decl.name == "run")
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .collect();
    assert_eq!(run_ids.len(), 2, "fixture should contain two run methods");
    let cg = resolved_graph([
        (f_id, run_ids[0], span(0, 20, 30)),
        (f_id, run_ids[1], span(0, 40, 50)),
    ]);
    assert_eq!(
        cg.callees_of(f_id).count(),
        2,
        "fixture should resolve one receiver-specific callee per call site"
    );

    let ws = build(&idx, &cg);
    assert_eq!(
        ws.cross_file().len(),
        4,
        "each site should stitch only its own receiver-resolved method"
    );
}

#[test]
fn unresolved_call_skipped_silently() {
    let mut f = empty_decl(1, 0, "f");
    f.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 30),
        name: "missing".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: Vec::new(),
    }];
    let idx = build_index(vec![f]);
    let cg = ResolvedCallGraph::default();
    let ws = build(&idx, &cg);
    assert_eq!(ws.segment_count(), 1);
    assert!(ws.cross_file().is_empty());
}
