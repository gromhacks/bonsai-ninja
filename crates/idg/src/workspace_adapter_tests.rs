use super::*;
use ahash::AHashMap;
use bonsai_callgraph::{CallEdge, CallGraph, EdgeKind, EdgeProvenance, ResolvedCallGraph};
use bonsai_common::{Precision, Span, SymbolId};
use bonsai_lang_api::{Decl, DeclKind, FlowEvent, ModulePath, Visibility};

#[test]
fn ordered_transfer_window_restores_canonical_segment_publication() {
    fn complete(work: AdmittedTransferWork<'_>) -> CompletedTransferWork<'_> {
        CompletedTransferWork {
            index: work.index,
            outcome: Ok((
                SegmentId(u32::try_from(work.index).expect("fixture segment id")),
                vec![TransferOutput::new(FuncId::new(
                    u32::try_from(work.index).expect("fixture function id"),
                ))],
            )),
            permit: work.permit,
        }
    }

    let source_bytes = [0_u64; 4];
    let permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
    let can_overlap = {
        let first = permits.acquire(0);
        let second = permits.try_acquire(0);
        let can_overlap = second.is_some();
        drop(second);
        drop(first);
        can_overlap
    };

    let completed_segments = std::cell::Cell::new(0_usize);
    let report_progress = |event| {
        if event == PersistenceBuildProgress::TransferSegmentCompleted {
            completed_segments.set(completed_segments.get() + 1);
        }
    };
    let published = std::thread::scope(|scope| {
        let worker_count = usize::from(can_overlap) + 1;
        let (work_tx, work_rx) = std::sync::mpsc::sync_channel(worker_count);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(worker_count);
        scope.spawn(move || {
            if can_overlap {
                let first = work_rx.recv().expect("first admitted transfer");
                let second = work_rx.recv().expect("second admitted transfer");
                result_tx
                    .send(complete(second))
                    .expect("publish later physical completion");
                result_tx
                    .send(complete(first))
                    .expect("publish delayed canonical completion");
            }
            for work in work_rx {
                result_tx
                    .send(complete(work))
                    .expect("publish transfer completion");
            }
        });

        OrderedTransferBatches::new(
            work_tx,
            result_rx,
            &source_bytes,
            &permits,
            worker_count,
            Some(&report_progress),
        )
        .flatten()
        .map(|(segment, _)| segment)
        .collect::<Vec<_>>()
    });

    assert_eq!(
        published,
        vec![SegmentId(0), SegmentId(1), SegmentId(2), SegmentId(3)]
    );
    assert_eq!(completed_segments.get(), published.len());
}

#[test]
fn path_module_resolution_uses_only_adapter_extensions() {
    assert_eq!(
        import_module_candidates("src.app", "./render.ts", &["js", "ts"]),
        vec!["src.render"]
    );
    assert_eq!(
        import_module_candidates("src.app", "./render.ts", &[]),
        vec!["src.render.ts"]
    );
}

#[test]
fn path_module_resolution_accepts_dot_prefixed_adapter_extensions() {
    assert_eq!(
        import_module_candidates("src.app", "./render.tsx", &[".tsx"]),
        vec!["src.render"]
    );
}

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
            ..bonsai_lang_api::DeclIndex::default()
        });
    }
    idx
}

#[test]
fn positional_aggregate_resolution_uses_declared_layout_order() {
    let mut events = vec![FlowEvent::AggregateAssign {
        span: span(0, 20, 40),
        target: "env".to_string(),
        type_name: Some("Envelope".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow {
            tuple_items: vec![
                bonsai_lang_api::ExpressionFlow::from_place("kind"),
                bonsai_lang_api::ExpressionFlow::from_place("raw"),
                bonsai_lang_api::ExpressionFlow::from_place("user"),
            ],
            ..Default::default()
        },
    }];
    let layouts = AHashMap::from([(
        "Envelope".to_string(),
        vec!["kind".to_string(), "cmd".to_string(), "user".to_string()],
    )]);
    resolve_aggregate_assignments(&mut events, &[], &layouts);

    let FlowEvent::AggregateAssign { value_flow, .. } = &events[0] else {
        unreachable!();
    };
    assert!(value_flow.tuple_items.is_empty());
    assert_eq!(
        value_flow
            .aggregate_fields
            .iter()
            .map(|field| (field.name.as_str(), field.value.place.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            ("kind", Some("kind")),
            ("cmd", Some("raw")),
            ("user", Some("user"))
        ]
    );
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

fn func_id_in_file(idx: &GlobalIndex, file: u32, name: &str) -> FuncId {
    for decl in idx.functions_in(FileId::new(file)) {
        if decl.name == name {
            return FuncId::new(decl.symbol.raw());
        }
    }
    unreachable!("function {name} not in file {file}")
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

#[test]
fn nested_full_expression_edge_indexes_only_the_resolved_callee_event() {
    let outer_span = span(0, 20, 50);
    let inner_span = span(0, 35, 40);
    let events = vec![
        FlowEvent::Call {
            span: outer_span,
            name: "client.send".to_string(),
            receiver: Some("client".to_string()),
            receiver_types: vec!["Client".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: vec![bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 31, 45),
                name: None,
                value_text: "request.field()".to_string(),
                place: None,
                source_names: vec!["request".to_string(), "field".to_string()],
            }],
        },
        FlowEvent::Call {
            span: inner_span,
            name: "request.field".to_string(),
            receiver: Some("request".to_string()),
            receiver_types: vec!["Request".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        },
    ];

    assert_eq!(
        call_event_spans_matching_edge(&events, outer_span, Some("field"), false),
        vec![inner_span],
        "the resolved inner getter must not be replayed at the containing host call"
    );

    let mut caller = empty_decl(1, 0, "caller");
    caller.flow_events = events;
    let mut field = empty_decl(2, 1, "field");
    field.kind = DeclKind::Method;
    let idx = build_index(vec![caller, field]);
    let caller_id = func_id(&idx, "caller");
    let field_id = func_id(&idx, "field");
    let graph = resolved_graph([(caller_id, field_id, outer_span)]);
    let by_site = call_edges_for_caller(&graph, &idx, None, caller_id);

    assert!(by_site.edges(inner_span).next().is_some());
    assert!(
        by_site.edges(outer_span).next().is_none(),
        "a resolved inner edge must not also resolve the containing host call"
    );
}

#[test]
fn empty_workspace_produces_empty_idg() {
    let idx = GlobalIndex::new();
    let cg = ResolvedCallGraph::default();
    let ws = build(&idx, &cg);
    assert_eq!(ws.segment_count(), 0);
}

#[test]
fn streamed_transfer_bodies_match_fully_resident_idg() {
    let file = FileId::new(44);
    let mut function = empty_decl(0, file.raw(), "identity");
    function.params = vec!["input".to_string()];
    function.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(file.raw(), 20, 30),
        value_text: Some("input".to_string()),
        value_name: Some("input".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("input"),
    }];
    let body = bonsai_lang_api::DeclIndex {
        file,
        defs: vec![function],
        ..Default::default()
    };

    let mut resident = GlobalIndex::new();
    resident.insert_preprocessed(body.clone());
    resident.finalize_semantic_facts();
    let graph = ResolvedCallGraph::build_with(&resident, |_| AHashMap::new());
    let expected = build_for_persistence_with_file_semantics_and_options(
        &resident,
        &graph,
        ClosureIdgFileSemantics::new(
            |_| AHashMap::new(),
            |_| Some("test"),
            |_| None,
            |_| &[] as &'static [&'static str],
        ),
        &TransferOptions::default(),
    )
    .expect("resident persistence build");

    let mut headers = GlobalIndex::new();
    headers.insert_linkage_header_preprocessed(body.clone());
    headers.finalize_semantic_facts();
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar = dir.path().join("streaming-idg.factstore");
    let actual = build_for_persistence_streaming_with_file_semantics_and_options(
        &headers,
        &graph,
        ClosureIdgFileSemantics::new(
            |_| AHashMap::new(),
            |_| Some("test"),
            |_| None,
            |_| &[] as &'static [&'static str],
        ),
        &TransferOptions::default(),
        &sidecar,
        |requested| (requested == file).then(|| headers.remap_file_to_existing_symbols(body.clone())),
    )
    .expect("streaming persistence build");

    assert_eq!(actual.segment_count(), expected.segment_count());
    assert_eq!(actual.func_count(), expected.func_count());
    assert_eq!(actual.total_edge_count(), expected.total_edge_count());
    assert_eq!(
        bonsai_common::wire::encode(&actual).expect("encode streamed IDG"),
        bonsai_common::wire::encode(&expected).expect("encode resident IDG")
    );
}

#[test]
fn field_canonicalization_uses_adapter_receiver_metadata() {
    let receiver_names = vec!["me".to_string()];
    assert_eq!(canonical_field_name("me.data.cmd", &receiver_names), "data.cmd");
    assert_eq!(
        canonical_field_name("ordinary.data.cmd", &receiver_names),
        "ordinary.data.cmd",
        "ordinary identifiers must not be stripped as receiver prefixes"
    );
}

#[test]
fn qualified_import_target_uses_member_index_then_module_validation() {
    let mut storage = empty_decl(1, 0, "Repository");
    storage.kind = DeclKind::Class;
    storage.module_path = ModulePath::from_segments(["storage"]);
    let mut sibling = empty_decl(2, 1, "Repository");
    sibling.kind = DeclKind::Class;
    sibling.module_path = ModulePath::from_segments(["other"]);
    let mut unrelated = empty_decl(3, 2, "Service");
    unrelated.kind = DeclKind::Class;
    unrelated.module_path = ModulePath::from_segments(["storage"]);
    let idx = build_index(vec![storage, sibling, unrelated]);
    let classes = class_symbols_by_name_for_files(&idx, None);

    let matches = class_symbols_matching_import_target(
        &idx,
        &classes,
        "storage.Repository",
        bonsai_lang_api::ModulePathSyntax::none(),
    );
    assert_eq!(matches.len(), 1);
    assert_eq!(idx.declaring_file(matches[0]), Some(FileId::new(0)));
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
            passing_mode: Default::default(),
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
        value_kind: None,
        span: span(1, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("arg"),
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
            passing_mode: Default::default(),
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
fn exact_site_edge_stitches_when_exported_decl_name_differs_from_call_alias() {
    let call_span = span(0, 20, 35);
    let mut f = empty_decl(1, 0, "f");
    f.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "render".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![
            bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 27, 29),
                name: None,
                value_text: "el".to_string(),
                place: Some("el".to_string()),
                source_names: vec!["el".to_string()],
            },
            bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 31, 35),
                name: None,
                value_text: "html".to_string(),
                place: Some("html".to_string()),
                source_names: vec!["html".to_string()],
            },
        ],
    }];
    let mut default_export = empty_decl(2, 1, "default");
    default_export.params = vec!["el".to_string(), "html".to_string()];

    let idx = build_index(vec![f, default_export]);
    let f_id = func_id(&idx, "f");
    let default_id = func_id(&idx, "default");
    let cg = resolved_graph([(f_id, default_id, call_span)]);

    let no_alias_ws = build(&idx, &cg);
    assert_eq!(
        no_alias_ws.cross_file().len(),
        3,
        "the compiler-resolved exact-site target is authoritative even when exported and local spellings differ"
    );

    let ws = build_with_aliases(&idx, &cg, |file| {
        let mut aliases = AHashMap::new();
        if file == FileId::new(0) {
            aliases.insert("render".to_string(), "default".to_string());
        }
        aliases
    });
    let caller_seg = ws.segment_for_func(f_id).expect("caller segment");
    let callee_seg = ws.segment_for_func(default_id).expect("callee segment");
    let arg_edges = ws
        .cross_file()
        .edges
        .iter()
        .filter(|cross| {
            cross.from_segment == caller_seg
                && cross.to_segment == callee_seg
                && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
                && cross.edge.meta.via_span == call_span
        })
        .count();

    assert_eq!(
        arg_edges, 2,
        "alias metadata must preserve the same two exact argument stitches without duplicating the resolved edge"
    );
}

#[test]
fn exact_site_constructor_edge_stitches_class_call_arguments_across_modules() {
    let call_span = span(0, 20, 35);
    let mut caller = empty_decl(1, 0, "entry");
    caller.module_path = ModulePath::from_segments(["pipeline"]);
    caller.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "Repository".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 31, 34),
            name: None,
            value_text: "raw".to_string(),
            place: Some("raw".to_string()),
            source_names: vec!["raw".to_string()],
        }],
    }];

    let mut repository_class = empty_decl(2, 1, "Repository");
    repository_class.kind = DeclKind::Class;
    repository_class.module_path = ModulePath::from_segments(["storage"]);
    repository_class.flow_events = Vec::new();

    let mut init = empty_decl(3, 1, "__init__");
    init.kind = DeclKind::Constructor;
    init.module_path = ModulePath::from_segments(["storage"]);
    init.parent = Some(repository_class.symbol);
    init.params = vec!["self".to_string(), "data".to_string()];
    init.receiver_param_index = Some(0);

    let idx = build_index(vec![caller, repository_class, init]);
    let caller_id = func_id(&idx, "entry");
    let init_id = func_id(&idx, "__init__");
    let cg = resolved_graph([(caller_id, init_id, call_span)]);

    let ws = build(&idx, &cg);
    let caller_seg = ws.segment_for_func(caller_id).expect("caller segment");
    let init_seg = ws.segment_for_func(init_id).expect("constructor segment");
    let arg_edges = ws
        .cross_file()
        .edges
        .iter()
        .filter(|cross| {
            cross.from_segment == caller_seg
                && cross.to_segment == init_seg
                && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
                && cross.edge.meta.via_span == call_span
        })
        .count();

    assert_eq!(
        arg_edges, 1,
        "site-specific semantic constructor edges must stitch class-call arguments even when fallback class lookup is module-scoped"
    );
}

#[test]
fn qualified_new_edge_stitches_to_initialize_constructor() {
    let call_span = span(0, 20, 27);
    let mut caller = empty_decl(1, 0, "entry");
    caller.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "Box.new".to_string(),
        receiver: Some("Box".to_string()),
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Constructor,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 28, 31),
            name: None,
            value_text: "raw".to_string(),
            place: Some("raw".to_string()),
            source_names: vec!["raw".to_string()],
        }],
    }];

    let mut box_class = empty_decl(2, 1, "Box");
    box_class.kind = DeclKind::Class;
    box_class.flow_events = Vec::new();

    let mut init = empty_decl(3, 1, "initialize");
    init.kind = DeclKind::Constructor;
    init.parent = Some(box_class.symbol);
    init.params = vec!["value".to_string()];

    let idx = build_index(vec![caller, box_class, init]);
    let caller_id = func_id(&idx, "entry");
    let init_id = func_id(&idx, "initialize");
    let cg = resolved_graph([(caller_id, init_id, call_span)]);
    let ws = build(&idx, &cg);
    let caller_seg = ws.segment_for_func(caller_id).expect("caller segment");
    let init_seg = ws.segment_for_func(init_id).expect("constructor segment");

    assert!(ws.cross_file().edges.iter().any(|cross| {
        cross.from_segment == caller_seg
            && cross.to_segment == init_seg
            && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
            && cross.edge.meta.via_span == call_span
    }));
}

#[test]
fn constructor_fallback_indexes_structs_by_scope_without_sibling_fanout() {
    let call_span = span(0, 20, 35);
    let mut caller = empty_decl(1, 0, "entry");
    caller.module_path = ModulePath::from_segments(["copy_0"]);
    caller.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "Envelope".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 30, 33),
            name: None,
            value_text: "raw".to_string(),
            place: Some("raw".to_string()),
            source_names: vec!["raw".to_string()],
        }],
    }];

    let mut local_struct = empty_decl(2, 1, "Envelope");
    local_struct.kind = DeclKind::Struct;
    local_struct.module_path = ModulePath::from_segments(["copy_0"]);
    local_struct.visibility = Visibility::Module;
    local_struct.flow_events = Vec::new();
    let mut local_init = empty_decl(3, 1, "Envelope");
    local_init.kind = DeclKind::Constructor;
    local_init.module_path = ModulePath::from_segments(["copy_0"]);
    local_init.visibility = Visibility::Module;
    local_init.parent = Some(local_struct.symbol);
    local_init.params = vec!["cmd".to_string()];

    let mut sibling_struct = empty_decl(2, 2, "Envelope");
    sibling_struct.kind = DeclKind::Struct;
    sibling_struct.module_path = ModulePath::from_segments(["copy_1"]);
    sibling_struct.visibility = Visibility::Module;
    sibling_struct.flow_events = Vec::new();
    let mut sibling_init = empty_decl(3, 2, "Envelope");
    sibling_init.kind = DeclKind::Constructor;
    sibling_init.module_path = ModulePath::from_segments(["copy_1"]);
    sibling_init.visibility = Visibility::Module;
    sibling_init.parent = Some(sibling_struct.symbol);
    sibling_init.params = vec!["cmd".to_string()];

    let idx = build_index(vec![
        caller,
        local_struct,
        local_init,
        sibling_struct,
        sibling_init,
    ]);
    let caller_id = func_id(&idx, "entry");
    let local_init_id = func_id_in_file(&idx, 1, "Envelope");
    let sibling_init_id = func_id_in_file(&idx, 2, "Envelope");
    let ws = build(&idx, &ResolvedCallGraph::default());
    let caller_seg = ws.segment_for_func(caller_id).expect("caller segment");
    let local_init_seg = ws
        .segment_for_func(local_init_id)
        .expect("local constructor segment");
    let sibling_init_seg = ws
        .segment_for_func(sibling_init_id)
        .expect("sibling constructor segment");

    let local_arg_edges = ws
        .cross_file()
        .edges
        .iter()
        .filter(|cross| {
            cross.from_segment == caller_seg
                && cross.to_segment == local_init_seg
                && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
                && cross.edge.meta.via_span == call_span
        })
        .count();
    let sibling_arg_edges = ws
        .cross_file()
        .edges
        .iter()
        .filter(|cross| {
            cross.from_segment == caller_seg
                && cross.to_segment == sibling_init_seg
                && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
                && cross.edge.meta.via_span == call_span
        })
        .count();

    assert_eq!(
        local_arg_edges, 1,
        "constructor fallback must route function-style struct calls to the local module constructor"
    );
    assert_eq!(
        sibling_arg_edges, 0,
        "constructor fallback must not fan out to same-named sibling module structs"
    );
}

#[test]
fn nested_indirect_constructor_edge_does_not_replace_outer_class_call() {
    let call_span = span(0, 20, 45);
    let arg_span = span(0, 38, 44);
    let module = ModulePath::from_segments(["storage"]);
    let mut caller = empty_decl(1, 0, "persist");
    caller.module_path = module.clone();
    caller.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "AuditedRepository".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: arg_span,
            name: None,
            value_text: "envelope".to_string(),
            place: Some("envelope".to_string()),
            source_names: vec!["envelope".to_string()],
        }],
    }];

    let mut audited_class = empty_decl(2, 1, "AuditedRepository");
    audited_class.kind = DeclKind::Class;
    audited_class.module_path = module.clone();
    let mut audited_ctor = empty_decl(3, 1, "AuditedRepository");
    audited_ctor.kind = DeclKind::Constructor;
    audited_ctor.module_path = module.clone();
    audited_ctor.parent = Some(audited_class.symbol);
    audited_ctor.params = vec!["data".to_string()];

    let mut unrelated_class = empty_decl(4, 2, "Envelope");
    unrelated_class.kind = DeclKind::Class;
    unrelated_class.module_path = module.clone();
    let mut unrelated_ctor = empty_decl(5, 2, "Envelope");
    unrelated_ctor.kind = DeclKind::Constructor;
    unrelated_ctor.module_path = module;
    unrelated_ctor.parent = Some(unrelated_class.symbol);
    unrelated_ctor.params = vec!["cmd".to_string()];

    let idx = build_index(vec![
        caller,
        audited_class,
        audited_ctor,
        unrelated_class,
        unrelated_ctor,
    ]);
    let caller_id = func_id(&idx, "persist");
    let audited_ctor_id = func_id_in_file(&idx, 1, "AuditedRepository");
    let unrelated_ctor_id = func_id_in_file(&idx, 2, "Envelope");
    let mut cg = CallGraph::new();
    cg.add_edge(CallEdge {
        from: caller_id,
        to: unrelated_ctor_id,
        span: arg_span,
        kind: EdgeKind::Indirect,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::callable_value("nested callable argument"),
    });
    let ws = build(&idx, &ResolvedCallGraph::from_call_graph(cg));
    let caller_segment = ws.segment_for_func(caller_id).expect("caller segment");
    let audited_segment = ws
        .segment_for_func(audited_ctor_id)
        .expect("audited constructor segment");
    let unrelated_segment = ws
        .segment_for_func(unrelated_ctor_id)
        .expect("unrelated constructor segment");

    assert!(ws.cross_file().edges.iter().any(|cross| {
        cross.from_segment == caller_segment
            && cross.to_segment == audited_segment
            && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
            && cross.edge.meta.via_span == call_span
    }));
    assert!(ws.cross_file().edges.iter().all(|cross| {
        cross.from_segment != caller_segment
            || cross.to_segment != unrelated_segment
            || cross.edge.meta.kind != crate::edge::IdgEdgeKind::InterCallArg
            || cross.edge.meta.via_span != call_span
    }));
}

#[test]
fn higher_order_callback_binding_stays_in_same_directory_scope() {
    let mut entry_a = empty_decl(1, 0, "entry");
    entry_a.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 30),
        name: "runCb".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![
            bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 21, 29),
                name: None,
                value_text: "executor".to_string(),
                place: Some("executor".to_string()),
                source_names: vec!["executor".to_string()],
            },
            bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
                span: span(0, 31, 32),
                name: None,
                value_text: "t".to_string(),
                place: Some("t".to_string()),
                source_names: vec!["t".to_string()],
            },
        ],
    }];
    let mut run_cb_a = empty_decl(2, 1, "runCb");
    run_cb_a.params = vec!["cb".to_string(), "value".to_string()];
    run_cb_a.flow_events = vec![FlowEvent::Call {
        span: span(1, 120, 130),
        name: "cb".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(1, 123, 128),
            name: None,
            value_text: "value".to_string(),
            place: Some("value".to_string()),
            source_names: vec!["value".to_string()],
        }],
    }];
    let mut executor_a = empty_decl(3, 2, "executor");
    executor_a.params = vec!["cmd".to_string()];

    let mut entry_b = empty_decl(4, 3, "entry");
    entry_b.flow_events = entry_a.flow_events.clone();
    for event in &mut entry_b.flow_events {
        if let FlowEvent::Call { span, args, .. } = event {
            *span = Span::new(FileId::new(3), span.start, span.end);
            for arg in args {
                arg.span = Span::new(FileId::new(3), arg.span.start, arg.span.end);
            }
        }
    }
    let mut run_cb_b = empty_decl(5, 4, "runCb");
    run_cb_b.params = run_cb_a.params.clone();
    run_cb_b.flow_events = run_cb_a.flow_events.clone();
    for event in &mut run_cb_b.flow_events {
        if let FlowEvent::Call { span, args, .. } = event {
            *span = Span::new(FileId::new(4), span.start, span.end);
            for arg in args {
                arg.span = Span::new(FileId::new(4), arg.span.start, arg.span.end);
            }
        }
    }
    let mut executor_b = empty_decl(6, 5, "executor");
    executor_b.params = vec!["cmd".to_string()];

    let idx = build_index(vec![entry_a, run_cb_a, executor_a, entry_b, run_cb_b, executor_b]);
    let entry_a_id = func_id_in_file(&idx, 0, "entry");
    let run_cb_a_id = func_id_in_file(&idx, 1, "runCb");
    let executor_a_id = func_id_in_file(&idx, 2, "executor");
    let entry_b_id = func_id_in_file(&idx, 3, "entry");
    let run_cb_b_id = func_id_in_file(&idx, 4, "runCb");
    let executor_b_id = func_id_in_file(&idx, 5, "executor");
    let mut cg = CallGraph::new();
    for (from, to, call_span, callback, callback_span) in [
        (
            entry_a_id,
            run_cb_a_id,
            span(0, 20, 30),
            executor_a_id,
            span(0, 21, 29),
        ),
        (
            entry_b_id,
            run_cb_b_id,
            span(3, 20, 30),
            executor_b_id,
            span(3, 21, 29),
        ),
    ] {
        cg.add_edge(CallEdge {
            from,
            to,
            span: call_span,
            kind: EdgeKind::Direct,
            precision: Precision::Narrowed,
            provenance: EdgeProvenance::direct_symbol(),
        });
        cg.add_edge(CallEdge {
            from,
            to: callback,
            span: callback_span,
            kind: EdgeKind::Indirect,
            precision: Precision::Narrowed,
            provenance: EdgeProvenance::callable_value("argument resolved as callable reference"),
        });
    }
    let cg = ResolvedCallGraph::from_call_graph(cg);

    let ws = build_with_file_info_and_paths(
        &idx,
        &cg,
        |_| AHashMap::new(),
        |_| Some("dart"),
        |file| match file.raw() {
            0 => Some("/w/flow_a/entry.dart".to_string()),
            1 => Some("/w/flow_a/run.dart".to_string()),
            2 => Some("/w/flow_a/executor.dart".to_string()),
            3 => Some("/w/flow_b/entry.dart".to_string()),
            4 => Some("/w/flow_b/run.dart".to_string()),
            5 => Some("/w/flow_b/executor.dart".to_string()),
            _ => None,
        },
    );

    let callback_edges = |from: FuncId, to: FuncId| {
        let from_segment = ws.segment_for_func(from).expect("from segment");
        let to_segment = ws.segment_for_func(to).expect("to segment");
        ws.cross_file()
            .edges
            .iter()
            .filter(|cross| {
                cross.from_segment == from_segment
                    && cross.to_segment == to_segment
                    && cross.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
                    && cross.edge.meta.call_kind == EdgeKind::Indirect
            })
            .count()
    };

    assert_eq!(callback_edges(run_cb_a_id, executor_a_id), 1);
    assert_eq!(callback_edges(run_cb_a_id, executor_b_id), 0);
    assert_eq!(callback_edges(run_cb_b_id, executor_b_id), 1);
    assert_eq!(callback_edges(run_cb_b_id, executor_a_id), 0);
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
                passing_mode: Default::default(),
                span: span(0, 21, 29),
                name: None,
                value_text: "executor".to_string(),
                place: Some("executor".to_string()),
                source_names: vec!["executor".to_string()],
            },
            bonsai_lang_api::CallArg {
                passing_mode: Default::default(),
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
            passing_mode: Default::default(),
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
    let mut cg = CallGraph::new();
    cg.add_edge(CallEdge {
        from: entry_id,
        to: run_cb_id,
        span: span(0, 20, 30),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });
    cg.add_edge(CallEdge {
        from: entry_id,
        to: executor_id,
        span: span(0, 21, 29),
        kind: EdgeKind::Indirect,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::callable_value("argument resolved as callable reference"),
    });
    let cg = ResolvedCallGraph::from_call_graph(cg);

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
fn ordinary_object_parameter_is_not_reinterpreted_as_same_named_callback() {
    let module = ModulePath::from_segments(["analysis"]);
    let mut entry = empty_decl(1, 0, "entry");
    entry.module_path = module.clone();
    entry.flow_events = vec![FlowEvent::Call {
        span: span(0, 20, 40),
        name: "simpleAnalyze".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 30, 38),
            name: None,
            value_text: "analyzer".to_string(),
            place: Some("analyzer".to_string()),
            source_names: vec!["analyzer".to_string()],
        }],
    }];

    let mut simple_analyze = empty_decl(2, 1, "simpleAnalyze");
    simple_analyze.module_path = module.clone();
    simple_analyze.params = vec!["analyzer".to_string()];
    simple_analyze.flow_events = vec![FlowEvent::Call {
        span: span(1, 120, 150),
        name: "analyzer.tokenStream".to_string(),
        receiver: Some("analyzer".to_string()),
        receiver_types: vec!["Analyzer".to_string()],
        call_kind: bonsai_lang_api::CallKind::Method,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(1, 140, 145),
            name: None,
            value_text: "text".to_string(),
            place: Some("text".to_string()),
            source_names: vec!["text".to_string()],
        }],
    }];

    let mut same_named_method = empty_decl(3, 2, "analyzer");
    same_named_method.module_path = module;
    same_named_method.params = vec!["value".to_string()];

    let idx = build_index(vec![entry, simple_analyze, same_named_method]);
    let entry_id = func_id(&idx, "entry");
    let simple_analyze_id = func_id(&idx, "simpleAnalyze");
    let same_named_method_id = func_id(&idx, "analyzer");
    let cg = resolved_graph([(entry_id, simple_analyze_id, span(0, 20, 40))]);
    let ws = build(&idx, &cg);
    let simple_analyze_segment = ws
        .segment_for_func(simple_analyze_id)
        .expect("simpleAnalyze segment");
    let same_named_segment = ws
        .segment_for_func(same_named_method_id)
        .expect("same-named method segment");

    assert!(
        ws.cross_file().edges.iter().all(|cross| {
            cross.from_segment != simple_analyze_segment
                || cross.to_segment != same_named_segment
                || cross.edge.meta.kind != crate::edge::IdgEdgeKind::InterCallArg
        }),
        "member access on an object parameter is not a callback invocation without an indirect callgraph edge: {:#?}",
        ws.cross_file().edges
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
            passing_mode: Default::default(),
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
        value_kind: None,
        span: span(1, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("arg"),
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
            passing_mode: Default::default(),
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
        value_kind: None,
        span: span(1, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("arg"),
    }];

    let mut class_b = empty_decl(4, 2, "B");
    class_b.kind = DeclKind::Class;
    let mut run_b = empty_decl(5, 2, "run");
    run_b.kind = DeclKind::Method;
    run_b.parent = Some(SymbolId::new(4));
    run_b.params = vec!["arg".to_string()];
    run_b.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(2, 50, 60),
        value_name: Some("arg".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("arg"),
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

#[test]
fn typed_child_receiver_stitches_to_inherited_cross_file_method() {
    let call_span = span(0, 40, 55);
    let mut entry = empty_decl(1, 0, "entry");
    entry.params = vec!["input".to_string()];
    entry.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "child.helper".to_string(),
        receiver: Some("child".to_string()),
        receiver_types: vec!["Child".to_string()],
        call_kind: bonsai_lang_api::CallKind::Method,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(0, 51, 54),
            name: None,
            value_text: "input".to_string(),
            place: Some("input".to_string()),
            source_names: vec!["input".to_string()],
        }],
    }];

    let mut child = empty_decl(2, 0, "Child");
    child.kind = DeclKind::Class;
    child.bases = vec!["Base".to_string()];

    let mut base = empty_decl(3, 1, "Base");
    base.kind = DeclKind::Class;
    let mut helper = empty_decl(4, 1, "helper");
    helper.kind = DeclKind::Method;
    helper.parent = Some(base.symbol);
    helper.params = vec!["value".to_string()];

    let idx = build_index(vec![entry, child, base, helper]);
    let entry_id = func_id(&idx, "entry");
    let helper_id = func_id(&idx, "helper");
    let ws = build(&idx, &ResolvedCallGraph::default());
    let entry_segment = ws.segment_for_func(entry_id).expect("entry segment");
    let helper_segment = ws.segment_for_func(helper_id).expect("helper segment");

    assert!(ws.cross_file().edges.iter().any(|edge| {
        edge.from_segment == entry_segment
            && edge.to_segment == helper_segment
            && edge.edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg
            && edge.edge.meta.via_span == call_span
    }));
}
