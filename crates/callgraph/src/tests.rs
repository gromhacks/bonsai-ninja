use super::*;
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{CallKind, DeclIndex, ModulePath, Visibility};

fn decl(file: FileId, local_symbol: u32, name: &str, flow_events: Vec<FlowEvent>) -> Decl {
    decl_with(file, local_symbol, name, DeclKind::Function, None, flow_events)
}

fn decl_with(
    file: FileId,
    local_symbol: u32,
    name: &str,
    kind: DeclKind,
    parent: Option<u32>,
    flow_events: Vec<FlowEvent>,
) -> Decl {
    let start = u64::from(local_symbol) * 10;
    let span = Span::new(file, start, start + u64::try_from(name.len()).unwrap_or(0));
    Decl {
        symbol: SymbolId::new(local_symbol),
        kind,
        name: name.to_string(),
        qualified_name: Some(name.to_string()),
        module_path: ModulePath::default(),
        span,
        name_span: span,
        visibility: Visibility::Public,
        parent: parent.map(SymbolId::new),
        body_span: Some(span),
        flow_events,
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

fn call(file: FileId, name: &str) -> FlowEvent {
    FlowEvent::Call {
        span: Span::new(file, 0, u64::try_from(name.len()).unwrap_or(0)),
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: Vec::new(),
    }
}

fn call_with_args(file: FileId, name: &str, args: &[&str]) -> FlowEvent {
    FlowEvent::Call {
        span: Span::new(file, 0, u64::try_from(name.len()).unwrap_or(0)),
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: args
            .iter()
            .enumerate()
            .map(|(idx, arg)| CallArg {
                passing_mode: Default::default(),
                span: Span::new(
                    file,
                    idx as u64,
                    idx as u64 + u64::try_from(arg.len()).unwrap_or(0),
                ),
                name: None,
                value_text: (*arg).to_string(),
                place: Some((*arg).to_string()),
                source_names: vec![(*arg).to_string()],
            })
            .collect(),
    }
}

fn method_call(file: FileId, name: &str, receiver: &str, receiver_types: &[&str]) -> FlowEvent {
    FlowEvent::Call {
        span: Span::new(file, 0, u64::try_from(name.len()).unwrap_or(0)),
        name: name.to_string(),
        receiver: Some(receiver.to_string()),
        receiver_types: receiver_types.iter().map(|ty| (*ty).to_string()).collect(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    }
}

fn callable_binding(file: FileId, target: &str, source_name: &str) -> FlowEvent {
    FlowEvent::Assign {
        span: Span::new(file, 0, u64::try_from(target.len()).unwrap_or(0)),
        target: target.to_string(),
        source_name: Some(source_name.to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn assign_call(file: FileId, target: &str, source_call: &str) -> FlowEvent {
    FlowEvent::Assign {
        span: Span::new(file, 100, 100 + u64::try_from(source_call.len()).unwrap_or(0)),
        target: target.to_string(),
        source_name: None,
        source_call: Some(source_call.to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn mark_implicit_receiver(mut decl: Decl, receiver: &str) -> Decl {
    decl.implicit_receiver_names = vec![receiver.to_string()];
    decl
}

fn with_module_path(mut decl: Decl, segments: &[&str]) -> Decl {
    decl.module_path = ModulePath::from_segments(segments.iter().copied());
    decl
}

fn with_params(mut decl: Decl, params: &[&str]) -> Decl {
    decl.params = params.iter().map(|param| (*param).to_string()).collect();
    decl
}

fn with_params_and_types(mut decl: Decl, params: &[(&str, &str)]) -> Decl {
    decl.params = params.iter().map(|(name, _)| (*name).to_string()).collect();
    decl.type_aliases = params
        .iter()
        .map(|(name, ty)| bonsai_lang_api::TypeAliasBinding {
            name: (*name).to_string(),
            type_name: (*ty).to_string(),
        })
        .collect();
    decl
}

#[test]
fn broad_actual_type_does_not_prove_specific_dispatch_type() {
    let universal = &["Object"];
    assert_eq!(type_name_match_score("Service", "Object", universal), Some(1));
    assert_eq!(type_name_match_score("Object", "Service", universal), None);
    assert_eq!(
        type_name_match_score("Service", "Object", &[]),
        None,
        "a shared backend must not infer another language's universal type spelling"
    );
    assert_eq!(type_name_match_score("unknown", "Service", universal), None);
    assert!(!type_name_matches("unknown", "Service", universal));
}

fn insert_file(global: &mut GlobalIndex, file: FileId, defs: Vec<Decl>) {
    global.insert(DeclIndex {
        file,
        defs,
        refs: Vec::new(),
        assignment_values: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
        call_receivers: Vec::new(),
        runtime_type_narrowings: Vec::new(),
        branch_conditions: Vec::new(),
    });
}

fn build_graph(
    global: &GlobalIndex,
    language_for_file: impl Fn(FileId) -> Option<&'static str>,
) -> ResolvedCallGraph {
    ResolvedCallGraph::build_with_file_info(
        global,
        |_| AHashMap::new(),
        |_| AHashMap::new(),
        |_| None,
        |_| &[],
        language_for_file,
    )
}

fn build_graph_with_capabilities(
    global: &GlobalIndex,
    language_for_file: impl Fn(FileId) -> Option<&'static str>,
    capabilities_for_file: impl Fn(FileId) -> LanguageCapabilities,
) -> ResolvedCallGraph {
    ResolvedCallGraph::build_with_file_semantics(
        global,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |_| AHashMap::new(),
            |_| None,
            language_for_file,
            capabilities_for_file,
        ),
    )
}

fn build_graph_with_paths(
    global: &GlobalIndex,
    path_for_file: impl Fn(FileId) -> Option<String>,
    language_for_file: impl Fn(FileId) -> Option<&'static str>,
) -> ResolvedCallGraph {
    ResolvedCallGraph::build_with_file_info(
        global,
        |_| AHashMap::new(),
        |_| AHashMap::new(),
        path_for_file,
        |_| &[],
        language_for_file,
    )
}

fn build_graph_with_paths_and_capabilities(
    global: &GlobalIndex,
    path_for_file: impl Fn(FileId) -> Option<String>,
    language_for_file: impl Fn(FileId) -> Option<&'static str>,
    capabilities_for_file: impl Fn(FileId) -> LanguageCapabilities,
) -> ResolvedCallGraph {
    ResolvedCallGraph::build_with_file_semantics(
        global,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |_| AHashMap::new(),
            path_for_file,
            language_for_file,
            capabilities_for_file,
        ),
    )
}

#[test]
fn direct_call_edges_carry_exact_symbol_provenance() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(file, 0, "entry", vec![call(file, "handler")]),
            decl(file, 1, "handler", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let handler = FuncId::new(global.find_by_name("handler")[0].raw());
    let edge = cg
        .callees_of(entry)
        .find(|edge| edge.to == handler)
        .expect("entry -> handler edge");

    assert_eq!(edge.provenance.resolver_stage, "exact_symbol");
    assert!(edge.provenance.evidence.contains("unique callable"));
    assert!(edge.provenance.confidence >= 90);
}

#[test]
fn local_callable_declaration_shadows_same_named_import() {
    let entry_file = FileId::new(1);
    let imported_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        entry_file,
        vec![
            with_module_path(decl(entry_file, 0, "helper", Vec::new()), &["entry"]),
            with_module_path(
                decl(entry_file, 1, "entry", vec![call(entry_file, "helper")]),
                &["entry"],
            ),
        ],
    );
    insert_file(
        &mut global,
        imported_file,
        vec![with_module_path(
            decl(imported_file, 0, "helper", Vec::new()),
            &["remote"],
        )],
    );

    let cg = ResolvedCallGraph::build_with_file_info(
        &global,
        |_| AHashMap::new(),
        |file| {
            if file == entry_file {
                AHashMap::from_iter([(
                    "helper".to_string(),
                    AliasTarget::Member {
                        module: "remote".to_string(),
                        member: "helper".to_string(),
                    },
                )])
            } else {
                AHashMap::new()
            }
        },
        |_| None,
        |_| &[],
        |_| Some("python"),
    );
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let local_helper = global
        .find_by_name("helper")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(entry_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("local helper");
    let imported_helper = global
        .find_by_name("helper")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(imported_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("imported helper");
    let targets = cg.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>();

    assert_eq!(targets, vec![local_helper]);
    assert!(!targets.contains(&imported_helper));
}

#[test]
fn typed_receiver_edges_carry_receiver_type_provenance() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl_with(file, 0, "Service", DeclKind::Class, None, Vec::new()),
            decl_with(file, 1, "run", DeclKind::Method, Some(0), Vec::new()),
            decl(
                file,
                2,
                "entry",
                vec![method_call(file, "service.run", "service", &["Service"])],
            ),
        ],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let run = FuncId::new(global.find_by_name("run")[0].raw());
    let edge = cg
        .callees_of(entry)
        .find(|edge| edge.to == run)
        .expect("entry -> Service.run edge");

    assert_eq!(edge.provenance.resolver_stage, "receiver_type");
    assert!(edge.provenance.evidence.contains("receiver"));
    assert!(edge.provenance.confidence >= 80);
}

fn func_id_by_name_and_parent(global: &GlobalIndex, name: &str, parent_name: &str) -> FuncId {
    let symbol = global
        .find_by_name(name)
        .iter()
        .copied()
        .find(|symbol| {
            global
                .decl_of(*symbol)
                .and_then(|decl| decl.parent)
                .and_then(|parent| global.decl_of(parent))
                .is_some_and(|parent| parent.name == parent_name)
        })
        .expect("decl with requested parent");
    FuncId::new(symbol.raw())
}

#[test]
fn callgraph_dedupes_exact_duplicate_edges() {
    let file = FileId::new(1);
    let from = FuncId::new(1);
    let to = FuncId::new(2);
    let span = Span::new(file, 10, 20);
    let mut graph = CallGraph::new();
    let edge = CallEdge {
        from,
        to,
        span,
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    };

    graph.add_edge(edge.clone());
    graph.add_edge(edge);
    graph.add_edge(CallEdge {
        from,
        to,
        span: Span::new(file, 10, 25),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from,
        to,
        span: Span::new(file, 30, 40),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });

    assert_eq!(graph.edges.len(), 2, "exact duplicate edge should be stored once");
    assert_eq!(graph.callees(from).count(), 2);
    assert_eq!(graph.callers(to).count(), 2);
}

#[test]
fn resolved_path_enumeration_ranks_shortest_semantic_paths() {
    let file = FileId::new(1);
    let entry = FuncId::new(1);
    let mid = FuncId::new(2);
    let alt = FuncId::new(3);
    let sink = FuncId::new(4);
    let mut graph = CallGraph::new();
    graph.add_edge(CallEdge {
        from: entry,
        to: mid,
        span: Span::new(file, 10, 11),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from: mid,
        to: sink,
        span: Span::new(file, 20, 21),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from: entry,
        to: alt,
        span: Span::new(file, 30, 31),
        kind: EdgeKind::Direct,
        precision: Precision::Exact,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from: alt,
        to: sink,
        span: Span::new(file, 40, 41),
        kind: EdgeKind::Direct,
        precision: Precision::Exact,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from: entry,
        to: sink,
        span: Span::new(file, 50, 51),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });

    let resolved = ResolvedCallGraph::from_call_graph(graph);
    let (paths, truncation) = enumerate_paths_resolved(&resolved, entry, sink, 8, 8, 64);

    assert_eq!(truncation, PathTruncation::None);
    assert_eq!(paths.len(), 3);
    assert_eq!(paths[0].funcs, vec![entry, sink]);
    assert_eq!(paths[1].funcs, vec![entry, alt, sink]);
    assert_eq!(paths[1].precision, Precision::Exact);
    assert_eq!(paths[2].funcs, vec![entry, mid, sink]);
    assert_eq!(paths[2].precision, Precision::Narrowed);
}

#[test]
fn resolved_path_enumeration_ignores_nonsemantic_edges() {
    let file = FileId::new(1);
    let entry = FuncId::new(1);
    let sink = FuncId::new(2);
    let mut graph = CallGraph::new();
    graph.add_edge(CallEdge {
        from: entry,
        to: sink,
        span: Span::new(file, 10, 11),
        kind: EdgeKind::Unknown,
        precision: Precision::OverApproximate,
        provenance: EdgeProvenance::default(),
    });

    let resolved = ResolvedCallGraph::from_call_graph(graph);
    let (paths, truncation) = enumerate_paths_resolved(&resolved, entry, sink, 8, 8, 64);

    assert!(paths.is_empty());
    assert_eq!(truncation, PathTruncation::None);
}

#[test]
fn resolved_path_enumeration_exact_path_cap_is_not_truncated() {
    let file = FileId::new(1);
    let entry = FuncId::new(1);
    let sink = FuncId::new(2);
    let mut graph = CallGraph::new();
    graph.add_edge(CallEdge {
        from: entry,
        to: sink,
        span: Span::new(file, 10, 11),
        kind: EdgeKind::Direct,
        precision: Precision::Exact,
        provenance: EdgeProvenance::direct_symbol(),
    });

    let resolved = ResolvedCallGraph::from_call_graph(graph);
    let (paths, truncation) = enumerate_paths_resolved(&resolved, entry, sink, 1, 8, 64);

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].funcs, vec![entry, sink]);
    assert_eq!(truncation, PathTruncation::None);
}

#[test]
fn resolved_path_enumeration_reports_max_paths_only_when_extra_path_exists() {
    let file = FileId::new(1);
    let entry = FuncId::new(1);
    let mid = FuncId::new(2);
    let sink = FuncId::new(3);
    let mut graph = CallGraph::new();
    graph.add_edge(CallEdge {
        from: entry,
        to: sink,
        span: Span::new(file, 10, 11),
        kind: EdgeKind::Direct,
        precision: Precision::Exact,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from: entry,
        to: mid,
        span: Span::new(file, 20, 21),
        kind: EdgeKind::Direct,
        precision: Precision::Exact,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from: mid,
        to: sink,
        span: Span::new(file, 30, 31),
        kind: EdgeKind::Direct,
        precision: Precision::Exact,
        provenance: EdgeProvenance::direct_symbol(),
    });

    let resolved = ResolvedCallGraph::from_call_graph(graph);
    let (paths, truncation) = enumerate_paths_resolved(&resolved, entry, sink, 1, 8, 64);

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].funcs, vec![entry, sink]);
    assert_eq!(truncation, PathTruncation::MaxPaths);
}

#[test]
fn resolved_path_enumeration_reports_depth_truncation() {
    let file = FileId::new(1);
    let entry = FuncId::new(1);
    let mid = FuncId::new(2);
    let sink = FuncId::new(3);
    let mut graph = CallGraph::new();
    graph.add_edge(CallEdge {
        from: entry,
        to: mid,
        span: Span::new(file, 10, 11),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });
    graph.add_edge(CallEdge {
        from: mid,
        to: sink,
        span: Span::new(file, 20, 21),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::direct_symbol(),
    });

    let resolved = ResolvedCallGraph::from_call_graph(graph);
    let (paths, truncation) = enumerate_paths_resolved(&resolved, entry, sink, 8, 1, 64);

    assert!(paths.is_empty());
    assert_eq!(truncation, PathTruncation::MaxDepth);
}

#[test]
fn callgraph_keeps_same_language_resolved_edges() {
    let caller_file = FileId::new(1);
    let callee_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(caller_file, 0, "entry", vec![call(caller_file, "tokenize")]),
            &["app"],
        )],
    );
    insert_file(
        &mut global,
        callee_file,
        vec![with_module_path(
            decl(callee_file, 0, "tokenize", Vec::new()),
            &["app"],
        )],
    );

    let cg = build_graph(&global, |_| Some("ruby"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let tokenize = FuncId::new(global.find_by_name("tokenize")[0].raw());

    let edges = cg.callees_of(entry).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, tokenize);
}

#[test]
fn typed_projected_receiver_resolves_method_without_bare_fanout() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let repository = with_module_path(
        decl_with(file, 0, "Repository", DeclKind::Class, None, Vec::new()),
        &["storage"],
    );
    let audited = with_module_path(
        decl_with(file, 1, "AuditedRepository", DeclKind::Class, None, Vec::new()),
        &["storage"],
    );
    let mut repo_run = with_params(
        with_module_path(
            decl_with(file, 2, "run", DeclKind::Function, Some(0), Vec::new()),
            &["storage"],
        ),
        &["self"],
    );
    repo_run.receiver_param_index = Some(0);
    let mut audited_run = with_params(
        with_module_path(
            decl_with(
                file,
                3,
                "run",
                DeclKind::Function,
                Some(1),
                vec![method_call(file, "self.0.run", "self.0", &["Repository"])],
            ),
            &["storage"],
        ),
        &["self"],
    );
    audited_run.receiver_param_index = Some(0);
    let mut trait_run = with_params(
        with_module_path(
            decl_with(file, 4, "run", DeclKind::Function, None, Vec::new()),
            &["storage"],
        ),
        &["self"],
    );
    trait_run.receiver_param_index = Some(0);
    insert_file(
        &mut global,
        file,
        vec![repository, audited, repo_run, audited_run, trait_run],
    );

    let cg = build_graph(&global, |_| Some("rust"));
    let audited_run_id = func_id_by_name_and_parent(&global, "run", "AuditedRepository");
    let repo_run_id = func_id_by_name_and_parent(&global, "run", "Repository");
    let edges = cg.callees_of(audited_run_id).collect::<Vec<_>>();

    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, repo_run_id);
}

#[test]
fn typed_receiver_import_alias_path_prevents_duplicate_class_fanout() {
    let exec_a_file = FileId::new(1);
    let exec_b_file = FileId::new(2);
    let storage_a_file = FileId::new(3);
    let storage_b_file = FileId::new(4);
    let mut global = GlobalIndex::new();

    let runner_a = with_module_path(
        decl_with(
            exec_a_file,
            10,
            "CommandRunner",
            DeclKind::Class,
            None,
            Vec::new(),
        ),
        &["flow_00000_executor"],
    );
    let execute_a = with_params(
        with_module_path(
            decl_with(
                exec_a_file,
                11,
                "execute",
                DeclKind::Function,
                Some(10),
                Vec::new(),
            ),
            &["flow_00000_executor"],
        ),
        &["self", "cmd"],
    );
    let runner_b = with_module_path(
        decl_with(
            exec_b_file,
            20,
            "CommandRunner",
            DeclKind::Class,
            None,
            Vec::new(),
        ),
        &["flow_00001_executor"],
    );
    let execute_b = with_params(
        with_module_path(
            decl_with(
                exec_b_file,
                21,
                "execute",
                DeclKind::Function,
                Some(20),
                Vec::new(),
            ),
            &["flow_00001_executor"],
        ),
        &["self", "cmd"],
    );
    let tx_a = with_module_path(
        decl_with(
            storage_a_file,
            30,
            "Transaction",
            DeclKind::Class,
            None,
            Vec::new(),
        ),
        &["flow_00000_storage"],
    );
    let perform_a = with_params(
        with_module_path(
            decl_with(
                storage_a_file,
                31,
                "perform",
                DeclKind::Function,
                Some(30),
                vec![method_call(
                    storage_a_file,
                    "self.runner.execute",
                    "self.runner",
                    &["CommandRunner"],
                )],
            ),
            &["flow_00000_storage"],
        ),
        &["self", "cmd"],
    );
    let tx_b = with_module_path(
        decl_with(
            storage_b_file,
            40,
            "Transaction",
            DeclKind::Class,
            None,
            Vec::new(),
        ),
        &["flow_00001_storage"],
    );
    let perform_b = with_params(
        with_module_path(
            decl_with(
                storage_b_file,
                41,
                "perform",
                DeclKind::Function,
                Some(40),
                vec![method_call(
                    storage_b_file,
                    "self.runner.execute",
                    "self.runner",
                    &["CommandRunner"],
                )],
            ),
            &["flow_00001_storage"],
        ),
        &["self", "cmd"],
    );
    insert_file(&mut global, exec_a_file, vec![runner_a, execute_a]);
    insert_file(&mut global, exec_b_file, vec![runner_b, execute_b]);
    insert_file(&mut global, storage_a_file, vec![tx_a, perform_a]);
    insert_file(&mut global, storage_b_file, vec![tx_b, perform_b]);

    let path_for_file = |file: FileId| match file.raw() {
        1 => Some("/tmp/work/shard_000/flow_00000_executor.py".to_string()),
        2 => Some("/tmp/work/shard_001/flow_00001_executor.py".to_string()),
        3 => Some("/tmp/work/shard_000/flow_00000_storage.py".to_string()),
        4 => Some("/tmp/work/shard_001/flow_00001_storage.py".to_string()),
        _ => None,
    };
    let aliases_a = AHashMap::from_iter([(
        "CommandRunner".to_string(),
        AliasTarget::Member {
            module: "shard_000.flow_00000_executor".to_string(),
            member: "CommandRunner".to_string(),
        },
    )]);
    let storage_a_module = ModulePath::from_segments(["flow_00000_storage"]);
    {
        let ctx = ResolveContext::new(storage_a_file, &storage_a_module)
            .with_alias_map(&aliases_a)
            .with_file_path_lookup(&path_for_file);
        let hits = resolve_class(&global, "CommandRunner", &ctx);
        assert_eq!(hits.len(), 1);
        assert_eq!(global.declaring_file(hits[0]), Some(exec_a_file));
    }

    let cg = ResolvedCallGraph::build_with_file_info(
        &global,
        |_| AHashMap::new(),
        |file| match file.raw() {
            3 => AHashMap::from_iter([(
                "CommandRunner".to_string(),
                AliasTarget::Member {
                    module: "shard_000.flow_00000_executor".to_string(),
                    member: "CommandRunner".to_string(),
                },
            )]),
            4 => AHashMap::from_iter([(
                "CommandRunner".to_string(),
                AliasTarget::Member {
                    module: "shard_001.flow_00001_executor".to_string(),
                    member: "CommandRunner".to_string(),
                },
            )]),
            _ => AHashMap::new(),
        },
        path_for_file,
        |_| &[],
        |_| Some("python"),
    );
    let func_id_in_file = |name: &str, file: FileId| {
        global
            .find_by_name(name)
            .iter()
            .copied()
            .find(|symbol| global.declaring_file(*symbol) == Some(file))
            .map(|symbol| FuncId::new(symbol.raw()))
            .expect("function in file")
    };
    let perform_a_id = func_id_in_file("perform", storage_a_file);
    let perform_b_id = func_id_in_file("perform", storage_b_file);
    let execute_a_id = func_id_in_file("execute", exec_a_file);
    let execute_b_id = func_id_in_file("execute", exec_b_file);
    let edges_a = cg.callees_of(perform_a_id).collect::<Vec<_>>();
    let edges_b = cg.callees_of(perform_b_id).collect::<Vec<_>>();

    assert_eq!(edges_a.len(), 1, "flow A must not fan out: {edges_a:?}");
    assert_eq!(edges_a[0].to, execute_a_id);
    assert_eq!(edges_b.len(), 1, "flow B must not fan out: {edges_b:?}");
    assert_eq!(edges_b[0].to, execute_b_id);
}

#[test]
fn elixir_function_clauses_emit_narrowed_virtual_edges() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let entry = with_module_path(
        decl(
            file,
            0,
            "entry",
            vec![call_with_args(file, "helper", &["payload"])],
        ),
        &["Example"],
    );
    let clause_one = with_params(
        with_module_path(decl(file, 1, "helper", Vec::new()), &["Example"]),
        &["payload"],
    );
    let clause_two = with_params(
        with_module_path(decl(file, 2, "helper", Vec::new()), &["Example"]),
        &["_arg0"],
    );
    insert_file(&mut global, file, vec![entry, clause_one, clause_two]);

    let cg = build_graph_with_capabilities(
        &global,
        |_| Some("elixir"),
        |_| LanguageCapabilities {
            callable_declaration_family: CallableDeclarationFamily::FunctionClauses,
            ..LanguageCapabilities::unsupported()
        },
    );
    let entry_id = FuncId::new(global.find_by_name("entry")[0].raw());
    let helper_ids = global
        .find_by_name("helper")
        .iter()
        .map(|sym| FuncId::new(sym.raw()))
        .collect::<AHashSet<_>>();
    let edges = cg.callees_of(entry_id).collect::<Vec<_>>();

    assert_eq!(edges.len(), 2);
    assert!(edges.iter().all(|edge| edge.kind == EdgeKind::Virtual));
    assert!(edges.iter().all(|edge| edge.precision == Precision::Narrowed));
    assert_eq!(
        edges.iter().map(|edge| edge.to).collect::<AHashSet<_>>(),
        helper_ids
    );
}

#[test]
fn unqualified_call_does_not_resolve_unique_public_sibling_module() {
    let caller_file = FileId::new(1);
    let callee_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(caller_file, 0, "entry", vec![call(caller_file, "helper")]),
            &["app", "controller"],
        )],
    );
    insert_file(
        &mut global,
        callee_file,
        vec![with_module_path(
            decl(callee_file, 0, "helper", Vec::new()),
            &["app", "service"],
        )],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let helper = FuncId::new(global.find_by_name("helper")[0].raw());

    assert_eq!(cg.callees_of(entry).count(), 0);
    assert_eq!(cg.callers_of(helper).count(), 0);
}

#[test]
fn kotlin_same_directory_top_level_call_resolves_across_file_modules() {
    let caller_file = FileId::new(1);
    let callee_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(caller_file, 0, "handler", vec![call(caller_file, "runPipeline")]),
            &["app"],
        )],
    );
    insert_file(
        &mut global,
        callee_file,
        vec![with_module_path(
            decl(callee_file, 0, "runPipeline", Vec::new()),
            &["pipeline"],
        )],
    );

    let cg = build_graph_with_paths_and_capabilities(
        &global,
        |file| match file.raw() {
            1 => Some("fixture/app.kt".to_string()),
            2 => Some("fixture/pipeline.kt".to_string()),
            _ => None,
        },
        |_| Some("kotlin"),
        |_| LanguageCapabilities {
            same_directory_unqualified_calls: true,
            ..LanguageCapabilities::unsupported()
        },
    );
    let handler = FuncId::new(global.find_by_name("handler")[0].raw());
    let run_pipeline = FuncId::new(global.find_by_name("runPipeline")[0].raw());
    let edges = cg.callees_of(handler).collect::<Vec<_>>();

    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, run_pipeline);
}

#[test]
fn rust_crate_root_member_import_resolves_by_path_not_leaf_fanout() {
    let caller_file = FileId::new(1);
    let micro_file = FileId::new(2);
    let admin_file = FileId::new(3);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(caller_file, 0, "entry", vec![call(caller_file, "get_user")]),
            &["gateway"],
        )],
    );
    insert_file(
        &mut global,
        micro_file,
        vec![with_module_path(
            decl(micro_file, 0, "get_user", Vec::new()),
            &["user_service"],
        )],
    );
    insert_file(
        &mut global,
        admin_file,
        vec![with_module_path(
            decl(admin_file, 0, "get_user", Vec::new()),
            &["user_service"],
        )],
    );
    let alias_targets = AHashMap::from_iter([(
        "get_user".to_string(),
        AliasTarget::Member {
            module: "crate::micro::user_service".to_string(),
            member: "get_user".to_string(),
        },
    )]);

    let cg = ResolvedCallGraph::build_with_file_semantics(
        &global,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |file| {
                if file == caller_file {
                    alias_targets.clone()
                } else {
                    AHashMap::new()
                }
            },
            |file| match file {
                f if f == caller_file => Some("/repo/examples/rust/micro/gateway.rs".to_string()),
                f if f == micro_file => Some("/repo/examples/rust/micro/user_service.rs".to_string()),
                f if f == admin_file => Some("/repo/examples/rust/admin/user_service.rs".to_string()),
                _ => None,
            },
            |_| Some("rust"),
            |_| LanguageCapabilities {
                module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                    rooted_prefixes: &["crate::", "self::"],
                    repeatable_rooted_prefixes: &["super::"],
                },
                ..LanguageCapabilities::unsupported()
            },
        ),
    );
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let micro_get_user = FuncId::new(global.decls_in(micro_file)[0].symbol.raw());
    let admin_get_user = FuncId::new(global.decls_in(admin_file)[0].symbol.raw());
    let callees = cg.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>();

    assert_eq!(callees, vec![micro_get_user]);
    assert_eq!(cg.callers_of(admin_get_user).count(), 0);
}

#[test]
fn callgraph_drops_implicit_cross_language_resolved_edges() {
    let ruby_file = FileId::new(1);
    let cpp_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        ruby_file,
        vec![decl(ruby_file, 0, "entry", vec![call(ruby_file, "tokenize")])],
    );
    insert_file(
        &mut global,
        cpp_file,
        vec![decl(cpp_file, 0, "tokenize", Vec::new())],
    );

    let cg = build_graph(&global, |file| {
        if file == ruby_file {
            Some("ruby")
        } else if file == cpp_file {
            Some("cpp")
        } else {
            None
        }
    });
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());

    assert_eq!(cg.callees_of(entry).count(), 0);
}

#[test]
fn c_callgraph_uses_makefile_build_targets_to_avoid_cross_binary_fanout() {
    struct TempTree(std::path::PathBuf);
    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bonsai-callgraph-build-target-{}-{nonce}",
        std::process::id()
    ));
    let _guard = TempTree(root.clone());
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("Makefile"),
        "SERVER_OBJ=module.o debug.o\nCLI_OBJ=cli.o redisassert.o\n",
    )
    .unwrap();
    for file in ["module.c", "debug.c", "redisassert.c", "cli.c"] {
        std::fs::write(src.join(file), "\n").unwrap();
    }

    let module_file = FileId::new(1);
    let debug_file = FileId::new(2);
    let redisassert_file = FileId::new(3);
    let cli_file = FileId::new(4);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        module_file,
        vec![decl(
            module_file,
            0,
            "RM__Assert",
            vec![call(module_file, "_serverAssert")],
        )],
    );
    insert_file(
        &mut global,
        debug_file,
        vec![decl(debug_file, 0, "_serverAssert", Vec::new())],
    );
    insert_file(
        &mut global,
        redisassert_file,
        vec![decl(redisassert_file, 0, "_serverAssert", Vec::new())],
    );
    insert_file(
        &mut global,
        cli_file,
        vec![decl(cli_file, 0, "cliMain", Vec::new())],
    );

    let mut paths = AHashMap::new();
    paths.insert(module_file, src.join("module.c").to_string_lossy().into_owned());
    paths.insert(debug_file, src.join("debug.c").to_string_lossy().into_owned());
    paths.insert(
        redisassert_file,
        src.join("redisassert.c").to_string_lossy().into_owned(),
    );
    paths.insert(cli_file, src.join("cli.c").to_string_lossy().into_owned());

    let cg = ResolvedCallGraph::build_with_file_semantics(
        &global,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |_| AHashMap::new(),
            |file| paths.get(&file).cloned(),
            |_| Some("c"),
            |_| LanguageCapabilities {
                same_directory_unqualified_calls: true,
                build_target_linkage: true,
                callable_declaration_family: CallableDeclarationFamily::SameSignature,
                ..LanguageCapabilities::unsupported()
            },
        ),
    );
    let entry = FuncId::new(global.find_by_name("RM__Assert")[0].raw());
    let debug_assert = FuncId::new(
        global
            .find_by_name("_serverAssert")
            .iter()
            .copied()
            .find(|sym| global.declaring_file(*sym) == Some(debug_file))
            .unwrap()
            .raw(),
    );

    let edges = cg.callees_of(entry).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, debug_assert);
    assert_eq!(edges[0].kind, EdgeKind::Direct);
    assert_eq!(edges[0].precision, Precision::Narrowed);
}

#[test]
fn cpp_unqualified_cross_file_call_resolves_unique_linked_candidate() {
    let caller_file = FileId::new(1);
    let callee_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                0,
                "handle_request",
                vec![call(caller_file, "get_user")],
            ),
            &["gateway"],
        )],
    );
    insert_file(
        &mut global,
        callee_file,
        vec![with_module_path(
            decl(callee_file, 0, "get_user", Vec::new()),
            &["user_service"],
        )],
    );

    let cg = build_graph_with_capabilities(
        &global,
        |_| Some("cpp"),
        |_| LanguageCapabilities {
            same_directory_unqualified_calls: true,
            build_target_linkage: true,
            ..LanguageCapabilities::unsupported()
        },
    );
    let handle = FuncId::new(global.find_by_name("handle_request")[0].raw());
    let get_user = FuncId::new(global.find_by_name("get_user")[0].raw());
    let edges = cg.callees_of(handle).collect::<Vec<_>>();

    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, get_user);
    assert_eq!(edges[0].precision, Precision::Narrowed);
}

#[test]
fn overloaded_call_uses_adapter_type_aliases_to_avoid_fanout() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    let caller = with_params_and_types(
        with_module_path(
            decl(
                caller_file,
                0,
                "entry",
                vec![call_with_args(
                    caller_file,
                    "printResults",
                    &["statement", "sql", "response"],
                )],
            ),
            &["owasp", "benchmark"],
        ),
        &[
            ("statement", "PreparedStatement"),
            ("statement", "Statement"),
            ("sql", "String"),
            ("response", "HttpServletResponse"),
        ],
    );
    let http_overload = with_params_and_types(
        with_module_path(
            decl(helper_file, 1, "printResults", Vec::new()),
            &["owasp", "benchmark"],
        ),
        &[
            ("statement", "Statement"),
            ("sql", "String"),
            ("response", "HttpServletResponse"),
        ],
    );
    let xml_overload = with_params_and_types(
        with_module_path(
            decl(helper_file, 2, "printResults", Vec::new()),
            &["owasp", "benchmark"],
        ),
        &[
            ("statement", "Statement"),
            ("sql", "String"),
            ("resp", "List<XMLMessage>"),
        ],
    );
    let result_set_overload = with_params_and_types(
        with_module_path(
            decl(helper_file, 3, "printResults", Vec::new()),
            &["owasp", "benchmark"],
        ),
        &[
            ("rs", "ResultSet"),
            ("sql", "String"),
            ("response", "HttpServletResponse"),
        ],
    );
    insert_file(&mut global, caller_file, vec![caller]);
    insert_file(
        &mut global,
        helper_file,
        vec![http_overload.clone(), xml_overload, result_set_overload],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let http = FuncId::new(http_overload.symbol.raw());

    let edges = cg.callees_of(entry).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1, "typed overload should not fan out: {edges:?}");
    assert_eq!(edges[0].to, http);
    assert_eq!(edges[0].precision, Precision::Narrowed);
}

#[test]
fn overloaded_call_drops_candidates_when_type_evidence_is_missing() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl(
            caller_file,
            0,
            "entry",
            vec![call_with_args(caller_file, "printResults", &["a", "b", "c"])],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![
            with_params_and_types(
                decl(helper_file, 1, "printResults", Vec::new()),
                &[("a", "A"), ("b", "B"), ("c", "C")],
            ),
            with_params_and_types(
                decl(helper_file, 2, "printResults", Vec::new()),
                &[("a", "A"), ("b", "B"), ("c", "D")],
            ),
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());

    let edges = cg.callees_of(entry).collect::<Vec<_>>();
    assert_eq!(
        edges.len(),
        0,
        "missing caller type evidence must not fan out ambiguously"
    );
}

#[test]
fn overloaded_call_uses_structured_constructor_type_to_avoid_fanout() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                0,
                "entry",
                vec![
                    FlowEvent::Call {
                        span: Span::new(caller_file, 10, 28),
                        name: "File".to_string(),
                        receiver: None,
                        receiver_types: vec!["File".to_string()],
                        call_kind: CallKind::Constructor,
                        args: Vec::new(),
                    },
                    FlowEvent::Call {
                        span: Span::new(caller_file, 0, 50),
                        name: "getLinesFromFile".to_string(),
                        receiver: None,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        args: vec![CallArg {
                            passing_mode: Default::default(),
                            span: Span::new(caller_file, 8, 30),
                            name: None,
                            value_text: "rendering-only".to_string(),
                            place: None,
                            source_names: Vec::new(),
                        }],
                    },
                ],
            ),
            &["owasp", "benchmark"],
        )],
    );
    let file_overload = with_params_and_types(
        with_module_path(
            decl(helper_file, 1, "getLinesFromFile", Vec::new()),
            &["owasp", "benchmark"],
        ),
        &[("file", "File")],
    );
    let string_overload = with_params_and_types(
        with_module_path(
            decl(helper_file, 2, "getLinesFromFile", Vec::new()),
            &["owasp", "benchmark"],
        ),
        &[("filename", "String")],
    );
    let file_class = with_module_path(
        decl_with(helper_file, 3, "File", DeclKind::Class, None, Vec::new()),
        &["owasp", "benchmark"],
    );
    let file_constructor = with_module_path(
        decl_with(
            helper_file,
            4,
            "allocate",
            DeclKind::Constructor,
            Some(3),
            Vec::new(),
        ),
        &["owasp", "benchmark"],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![
            file_overload.clone(),
            string_overload.clone(),
            file_class,
            file_constructor,
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let file_target = FuncId::new(file_overload.symbol.raw());

    let targets = cg.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>();
    assert!(
        targets.contains(&file_target),
        "structured constructor argument type should select the File overload: {targets:?}"
    );
    assert!(
        !targets.contains(&FuncId::new(string_overload.symbol.raw())),
        "the incompatible String overload must be removed: {targets:?}"
    );
}

#[test]
fn bare_call_prefers_nested_lexical_callable_in_caller_body() {
    let file = FileId::new(1);
    let other_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    let mut caller = decl(
        file,
        1,
        "hide",
        vec![FlowEvent::Call {
            span: Span::new(file, 50, 58),
            name: "complete".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        }],
    );
    caller.span = Span::new(file, 0, 200);
    caller.name_span = Span::new(file, 0, 4);
    caller.body_span = Some(Span::new(file, 5, 195));
    let mut nested_complete = decl(file, 2, "complete", Vec::new());
    nested_complete.span = Span::new(file, 120, 180);
    nested_complete.name_span = Span::new(file, 130, 138);
    nested_complete.body_span = Some(Span::new(file, 140, 175));
    let mut sibling_complete = decl(file, 3, "complete", Vec::new());
    sibling_complete.span = Span::new(file, 220, 260);
    sibling_complete.name_span = Span::new(file, 220, 228);
    sibling_complete.body_span = Some(Span::new(file, 230, 255));
    insert_file(
        &mut global,
        file,
        vec![caller, nested_complete.clone(), sibling_complete],
    );
    insert_file(
        &mut global,
        other_file,
        vec![decl(other_file, 4, "complete", Vec::new())],
    );

    let cg = build_graph(&global, |_| Some("javascript"));
    let hide = FuncId::new(global.find_by_name("hide")[0].raw());
    let nested = global
        .decls_in(file)
        .iter()
        .find(|decl| decl.name == "complete" && decl.name_span.start == 130)
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .expect("nested complete");

    let edges = cg.callees_of(hide).collect::<Vec<_>>();
    assert_eq!(
        edges.len(),
        1,
        "lexical local callable should win over same-name siblings: {edges:?}"
    );
    assert_eq!(edges[0].to, nested);
    assert_eq!(edges[0].precision, Precision::Narrowed);
}

#[test]
fn bare_method_call_prefers_same_class_implicit_receiver() {
    let caller_file = FileId::new(1);
    let other_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl_with(
                caller_file,
                0,
                "BenchmarkTest00001",
                DeclKind::Class,
                None,
                Vec::new(),
            ),
            mark_implicit_receiver(
                decl_with(
                    caller_file,
                    1,
                    "doGet",
                    DeclKind::Method,
                    Some(0),
                    vec![call(caller_file, "doPost")],
                ),
                "this",
            ),
            decl_with(caller_file, 2, "doPost", DeclKind::Method, Some(0), Vec::new()),
        ],
    );
    insert_file(
        &mut global,
        other_file,
        vec![
            decl_with(
                other_file,
                0,
                "BenchmarkTest00002",
                DeclKind::Class,
                None,
                Vec::new(),
            ),
            decl_with(other_file, 1, "doPost", DeclKind::Method, Some(0), Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let do_get = FuncId::new(global.find_by_name("doGet")[0].raw());
    let same_class_do_post = global
        .decls_in(caller_file)
        .iter()
        .find(|decl| decl.name == "doPost")
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .expect("same-class doPost");

    let edges = cg.callees_of(do_get).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, same_class_do_post);
    assert_eq!(cg.callers_of(same_class_do_post).count(), 1);
}

#[test]
fn bare_implicit_receiver_call_resolves_inherited_base_accessor() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let base = with_module_path(
        decl_with(file, 0, "Base", DeclKind::Class, None, Vec::new()),
        &["app"],
    );
    let accessor = with_module_path(
        decl_with(file, 1, "cmd", DeclKind::Method, Some(0), Vec::new()),
        &["app"],
    );
    let mut child = with_module_path(
        decl_with(file, 2, "Repository", DeclKind::Class, None, Vec::new()),
        &["app"],
    );
    child.bases = vec!["Base".to_string()];
    let run = mark_implicit_receiver(
        with_module_path(
            decl_with(file, 3, "run", DeclKind::Method, Some(2), vec![call(file, "cmd")]),
            &["app"],
        ),
        "this",
    );
    insert_file(&mut global, file, vec![base, accessor, child, run]);

    let cg = build_graph(&global, |_| Some("kotlin"));
    let run = FuncId::new(global.find_by_name("run")[0].raw());
    let accessor = FuncId::new(global.find_by_name("cmd")[0].raw());
    let edges = cg.callees_of(run).collect::<Vec<_>>();

    assert!(
        edges.iter().any(|edge| edge.to == accessor),
        "implicit receiver dispatch must traverse adapter-declared class bases: {edges:?}"
    );
}

#[test]
fn typed_child_receiver_resolves_inherited_base_method() {
    let base_file = FileId::new(1);
    let entry_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    let base = with_module_path(
        decl_with(base_file, 0, "Base", DeclKind::Class, None, Vec::new()),
        &["app"],
    );
    let helper = with_params(
        with_module_path(
            decl_with(base_file, 1, "helper", DeclKind::Method, Some(0), Vec::new()),
            &["app"],
        ),
        &["p"],
    );
    let mut child = with_module_path(
        decl_with(entry_file, 0, "Child", DeclKind::Class, None, Vec::new()),
        &["app"],
    );
    child.bases = vec!["Base".to_string()];
    let entry = with_params(
        with_module_path(
            decl_with(
                entry_file,
                1,
                "entry",
                DeclKind::Function,
                None,
                vec![FlowEvent::Call {
                    span: Span::new(entry_file, 10, 29),
                    name: "new Child().helper".to_string(),
                    receiver: Some("new Child()".to_string()),
                    receiver_types: vec!["Child".to_string(), "Base".to_string()],
                    call_kind: CallKind::Method,
                    args: vec![CallArg {
                        passing_mode: Default::default(),
                        span: Span::new(entry_file, 30, 34),
                        name: None,
                        value_text: "args".to_string(),
                        place: Some("args".to_string()),
                        source_names: vec!["args".to_string()],
                    }],
                }],
            ),
            &["app"],
        ),
        &["args"],
    );
    insert_file(&mut global, base_file, vec![base, helper.clone()]);
    insert_file(&mut global, entry_file, vec![child, entry]);
    global.finalize_semantic_facts();

    let cg = build_graph(&global, |_| Some("javascript"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let helper = FuncId::new(helper.symbol.raw());
    let edges = cg.callees_of(entry).collect::<Vec<_>>();
    assert!(
        edges.iter().any(|edge| edge.to == helper),
        "typed Child receiver should dispatch to inherited Base.helper; got {edges:?}"
    );
}

#[test]
fn super_receiver_resolves_base_method_from_override_context() {
    let file = FileId::new(1);
    let repo = 1;
    let audited = 2;
    let base_run = 3;
    let override_run = 4;
    let mut global = GlobalIndex::new();

    let mut repo_class = decl_with(file, repo, "Repository", DeclKind::Class, None, Vec::new());
    repo_class.body_span = Some(Span::new(file, 0, 100));
    let mut audited_class = decl_with(
        file,
        audited,
        "AuditedRepository",
        DeclKind::Class,
        None,
        Vec::new(),
    );
    audited_class.body_span = Some(Span::new(file, 100, 220));
    audited_class.bases = vec!["Repository".to_string()];
    let base = decl_with(file, base_run, "run", DeclKind::Method, Some(repo), Vec::new());
    let override_method = decl_with(
        file,
        override_run,
        "run",
        DeclKind::Method,
        Some(audited),
        vec![FlowEvent::Call {
            span: Span::new(file, 150, 159),
            name: "super.run".to_string(),
            receiver: Some("super".to_string()),
            receiver_types: vec!["Repository".to_string()],
            call_kind: CallKind::Method,
            args: Vec::new(),
        }],
    );
    insert_file(
        &mut global,
        file,
        vec![repo_class, audited_class, base.clone(), override_method],
    );
    global.finalize_semantic_facts();

    let cg = ResolvedCallGraph::build_with_file_semantics(
        &global,
        CallGraphFileSemantics::new(
            |_| ahash::AHashMap::new(),
            |_| ahash::AHashMap::new(),
            |_| None,
            |_| Some("swift"),
            |_| LanguageCapabilities {
                super_receiver_tokens: &["super"],
                ..LanguageCapabilities::unsupported()
            },
        ),
    );
    let from = func_id_by_name_and_parent(&global, "run", "AuditedRepository");
    let to = func_id_by_name_and_parent(&global, "run", "Repository");
    let edges = cg.callees_of(from).collect::<Vec<_>>();
    assert!(
        edges.iter().any(|edge| edge.to == to),
        "super.run should resolve to Repository.run from AuditedRepository.run; got {edges:?}"
    );
}

#[test]
fn projected_receiver_type_wins_over_root_assigned_type() {
    let file = FileId::new(1);
    let repo = 1;
    let audited = 2;
    let repo_run = 3;
    let audited_run = 4;
    let mut global = GlobalIndex::new();

    let repo_class = decl_with(file, repo, "Repository", DeclKind::Class, None, Vec::new());
    let mut audited_class = decl_with(
        file,
        audited,
        "AuditedRepository",
        DeclKind::Class,
        None,
        Vec::new(),
    );
    audited_class.bases = vec!["Repository".to_string()];
    let base_method = decl_with(file, repo_run, "Run", DeclKind::Method, Some(repo), Vec::new());
    let override_method = with_params_and_types(
        decl_with(
            file,
            audited_run,
            "Run",
            DeclKind::Method,
            Some(audited),
            vec![method_call(
                file,
                "a.Repository.Run",
                "a.Repository",
                &["Repository"],
            )],
        ),
        &[("a", "AuditedRepository")],
    );
    insert_file(
        &mut global,
        file,
        vec![repo_class, audited_class, base_method, override_method],
    );
    global.finalize_semantic_facts();

    let cg = build_graph(&global, |_| Some("go"));
    let from = func_id_by_name_and_parent(&global, "Run", "AuditedRepository");
    let to = func_id_by_name_and_parent(&global, "Run", "Repository");
    let edges = cg.callees_of(from).collect::<Vec<_>>();
    assert!(
        edges.iter().any(|edge| edge.to == to),
        "a.Repository.Run must resolve to Repository.Run, not the AuditedRepository override; got {edges:?}"
    );
    assert!(
        !edges.iter().any(|edge| edge.to == from),
        "projected receiver dispatch must not create a self-edge; got {edges:?}"
    );
}

#[test]
fn bare_method_call_without_adapter_implicit_receiver_does_not_fan_out() {
    let caller_file = FileId::new(1);
    let other_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl_with(caller_file, 0, "Owner", DeclKind::Class, None, Vec::new()),
            decl_with(
                caller_file,
                1,
                "entry",
                DeclKind::Method,
                Some(0),
                vec![call(caller_file, "target")],
            ),
            decl_with(caller_file, 2, "target", DeclKind::Method, Some(0), Vec::new()),
        ],
    );
    insert_file(
        &mut global,
        other_file,
        vec![
            decl_with(other_file, 0, "Other", DeclKind::Class, None, Vec::new()),
            decl_with(other_file, 1, "target", DeclKind::Method, Some(0), Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());

    let edges = cg.callees_of(entry).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1, "bare method call must stay semantically narrowed");
    assert_eq!(edges[0].precision, Precision::Narrowed);
    let target = global
        .decl_of(SymbolId::new(edges[0].to.raw()))
        .expect("callee decl exists");
    assert_eq!(target.name_span.file, caller_file);
}

#[test]
fn unresolved_external_receiver_method_does_not_fall_back_to_bare_workspace_name() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl_with(caller_file, 0, "Servlet", DeclKind::Class, None, Vec::new()),
            mark_implicit_receiver(
                decl_with(
                    caller_file,
                    1,
                    "doPost",
                    DeclKind::Method,
                    Some(0),
                    vec![method_call(
                        caller_file,
                        "theCookie.getName().equals",
                        "theCookie.getName()",
                        &["Cookie"],
                    )],
                ),
                "this",
            ),
        ],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![
            decl_with(helper_file, 0, "Certificate", DeclKind::Class, None, Vec::new()),
            decl_with(helper_file, 1, "equals", DeclKind::Method, Some(0), Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let do_post = FuncId::new(global.find_by_name("doPost")[0].raw());
    let equals = FuncId::new(global.find_by_name("equals")[0].raw());

    assert_eq!(cg.callees_of(do_post).count(), 0);
    assert_eq!(cg.callers_of(equals).count(), 0);
}

#[test]
fn unresolved_untyped_receiver_method_does_not_fall_back_to_bare_workspace_name() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl_with(
            caller_file,
            0,
            "entry",
            DeclKind::Function,
            None,
            vec![method_call(caller_file, "cookieName.equals", "cookieName", &[])],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![
            decl_with(helper_file, 0, "Certificate", DeclKind::Class, None, Vec::new()),
            decl_with(helper_file, 1, "equals", DeclKind::Method, Some(0), Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let equals = FuncId::new(global.find_by_name("equals")[0].raw());

    assert_eq!(cg.callees_of(entry).count(), 0);
    assert_eq!(cg.callers_of(equals).count(), 0);
}

#[test]
fn dynamic_parameter_receiver_resolves_only_unique_same_file_method() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl_with(file, 0, "Box", DeclKind::Class, None, Vec::new()),
            decl_with(file, 1, "run", DeclKind::Method, Some(0), Vec::new()),
            with_params(
                decl_with(
                    file,
                    2,
                    "entry",
                    DeclKind::Function,
                    None,
                    vec![method_call(file, "arg.run", "arg", &[])],
                ),
                &["arg"],
            ),
        ],
    );

    let cg = build_graph(&global, |_| Some("javascript"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let run = FuncId::new(global.find_by_name("run")[0].raw());
    assert_eq!(
        cg.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![run]
    );

    let mut ambiguous = GlobalIndex::new();
    insert_file(
        &mut ambiguous,
        file,
        vec![
            decl_with(file, 0, "A", DeclKind::Class, None, Vec::new()),
            decl_with(file, 1, "run", DeclKind::Method, Some(0), Vec::new()),
            decl_with(file, 2, "B", DeclKind::Class, None, Vec::new()),
            decl_with(file, 3, "run", DeclKind::Method, Some(2), Vec::new()),
            with_params(
                decl_with(
                    file,
                    4,
                    "entry",
                    DeclKind::Function,
                    None,
                    vec![method_call(file, "arg.run", "arg", &[])],
                ),
                &["arg"],
            ),
        ],
    );
    let cg = build_graph(&ambiguous, |_| Some("javascript"));
    let entry = FuncId::new(ambiguous.find_by_name("entry")[0].raw());
    assert_eq!(
        cg.callees_of(entry).count(),
        0,
        "ambiguous local method names must not fan out from an untyped receiver"
    );
}

#[test]
fn static_class_receiver_method_resolves_without_bare_name_fanout() {
    let caller_file = FileId::new(1);
    let repo_file = FileId::new(2);
    let other_file = FileId::new(3);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            with_module_path(
                decl_with(caller_file, 0, "Controller", DeclKind::Class, None, Vec::new()),
                &["app"],
            ),
            with_module_path(
                decl_with(
                    caller_file,
                    1,
                    "handle",
                    DeclKind::Method,
                    Some(0),
                    vec![method_call(caller_file, "Repository.search", "Repository", &[])],
                ),
                &["app"],
            ),
        ],
    );
    insert_file(
        &mut global,
        repo_file,
        vec![
            with_module_path(
                decl_with(repo_file, 0, "Repository", DeclKind::Class, None, Vec::new()),
                &["app"],
            ),
            with_module_path(
                decl_with(repo_file, 1, "search", DeclKind::Method, Some(0), Vec::new()),
                &["app"],
            ),
        ],
    );
    insert_file(
        &mut global,
        other_file,
        vec![
            with_module_path(
                decl_with(other_file, 0, "Other", DeclKind::Class, None, Vec::new()),
                &["other"],
            ),
            with_module_path(
                decl_with(other_file, 1, "search", DeclKind::Method, Some(0), Vec::new()),
                &["other"],
            ),
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let handle = FuncId::new(global.find_by_name("handle")[0].raw());
    let repo_search = global
        .decls_in(repo_file)
        .iter()
        .find(|decl| decl.name == "search")
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .expect("Repository.search");

    let edges = cg.callees_of(handle).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, repo_search);
    assert_eq!(cg.callers_of(repo_search).count(), 1);
}

#[test]
fn folded_receiver_identity_comes_from_adapter_metadata() {
    let file = FileId::new(1);
    let mut caller = decl(file, 0, "handle", Vec::new());
    caller.implicit_receiver_names = vec!["$this".to_string(), "self".to_string()];

    assert!(folded_call_name_receiver_is_instance("$this", &caller, &[]));
    assert!(folded_call_name_receiver_is_instance("self", &caller, &[]));
    assert!(folded_call_name_receiver_is_instance(
        "super",
        &caller,
        &["super"]
    ));
    assert!(
        !folded_call_name_receiver_is_instance("Repository", &caller, &[]),
        "a class qualifier is not an instance merely because source syntax used a qualified call"
    );
}

#[test]
fn module_alias_receiver_method_resolves_before_unresolved_receiver_bailout() {
    let caller_file = FileId::new(1);
    let storage_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl(
            caller_file,
            0,
            "orchestrate",
            vec![method_call(caller_file, "Store.persist", "Store", &[])],
        )],
    );
    insert_file(
        &mut global,
        storage_file,
        vec![decl(storage_file, 0, "persist", Vec::new())],
    );

    let cg = ResolvedCallGraph::build_with_file_info(
        &global,
        |_| AHashMap::new(),
        |file| {
            if file == caller_file {
                AHashMap::from_iter([(
                    "Store".to_string(),
                    AliasTarget::Member {
                        module: "storage".to_string(),
                        member: "Storage".to_string(),
                    },
                )])
            } else {
                AHashMap::new()
            }
        },
        |file| {
            if file == storage_file {
                Some("storage.ex".to_string())
            } else {
                None
            }
        },
        |_| &[],
        |_| Some("elixir"),
    );
    let orchestrate = FuncId::new(global.find_by_name("orchestrate")[0].raw());
    let persist = FuncId::new(global.find_by_name("persist")[0].raw());

    let edges = cg.callees_of(orchestrate).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, persist);
}

#[test]
fn import_qualified_call_does_not_retry_bare_tail() {
    let caller_file = FileId::new(1);
    let local_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(caller_file, 0, "entry", vec![call(caller_file, "fmt.Println")]),
            &["app"],
        )],
    );
    insert_file(
        &mut global,
        local_file,
        vec![with_module_path(
            decl(local_file, 0, "Println", Vec::new()),
            &["app"],
        )],
    );

    let cg = ResolvedCallGraph::build_with_file_info(
        &global,
        |file| {
            if file == caller_file {
                AHashMap::from_iter([("fmt".to_string(), "fmt".to_string())])
            } else {
                AHashMap::new()
            }
        },
        |file| {
            if file == caller_file {
                AHashMap::from_iter([(
                    "fmt".to_string(),
                    AliasTarget::Namespace {
                        module: "fmt".to_string(),
                    },
                )])
            } else {
                AHashMap::new()
            }
        },
        |file| {
            if file == local_file {
                Some("app/print.go".to_string())
            } else {
                Some("app/main.go".to_string())
            }
        },
        |_| &[],
        |_| Some("go"),
    );
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());

    assert!(
        cg.callees_of(entry).next().is_none(),
        "fmt.Println must resolve through the fmt import target or stay unresolved; \
             retrying bare Println fabricates an edge to the local app.Println"
    );
}

#[test]
fn bare_namespace_call_requires_adapter_default_export_semantics() {
    let caller_file = FileId::new(1);
    let exported_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(caller_file, 0, "entry", vec![call(caller_file, "worker")]),
            &["app", "main"],
        )],
    );
    insert_file(
        &mut global,
        exported_file,
        vec![with_module_path(
            decl(exported_file, 0, "default", Vec::new()),
            &["app", "worker"],
        )],
    );

    let build = |default_export_names: &'static [&'static str]| {
        ResolvedCallGraph::build_with_file_semantics(
            &global,
            CallGraphFileSemantics::new(
                |_| AHashMap::new(),
                |file| {
                    if file == caller_file {
                        AHashMap::from_iter([(
                            "worker".to_string(),
                            AliasTarget::Namespace {
                                module: "./worker.js".to_string(),
                            },
                        )])
                    } else {
                        AHashMap::new()
                    }
                },
                |file| {
                    Some(
                        if file == exported_file {
                            "app/worker.js"
                        } else {
                            "app/main.js"
                        }
                        .to_string(),
                    )
                },
                |_| Some("fixture"),
                move |file| LanguageCapabilities {
                    module_default_export_names: if file == caller_file {
                        default_export_names
                    } else {
                        &[]
                    },
                    ..LanguageCapabilities::unsupported()
                },
            ),
        )
    };
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let default_export = FuncId::new(global.find_by_name("default")[0].raw());

    let without_syntax = build(&[]);
    assert!(without_syntax.callees_of(entry).next().is_none());

    let with_syntax = build(&["default"]);
    assert_eq!(
        with_syntax
            .callees_of(entry)
            .map(|edge| edge.to)
            .collect::<Vec<_>>(),
        vec![default_export]
    );
}

#[test]
fn module_qualified_receiver_method_resolves_by_module_path_without_bare_fanout() {
    let caller_file = FileId::new(1);
    let executor_file = FileId::new(2);
    let other_file = FileId::new(3);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl(
            caller_file,
            0,
            "main",
            vec![method_call(
                caller_file,
                "Mega.Executor.execute",
                "Mega.Executor",
                &[],
            )],
        )],
    );
    insert_file(
        &mut global,
        executor_file,
        vec![with_module_path(
            decl(executor_file, 0, "execute", Vec::new()),
            &["Mega", "Executor"],
        )],
    );
    insert_file(
        &mut global,
        other_file,
        vec![with_module_path(
            decl(other_file, 0, "execute", Vec::new()),
            &["Other", "Executor"],
        )],
    );

    let cg = build_graph(&global, |_| Some("elixir"));
    let main = FuncId::new(global.find_by_name("main")[0].raw());
    let executor_execute = global
        .decls_in(executor_file)
        .iter()
        .find(|decl| decl.name == "execute")
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .expect("Mega.Executor.execute");
    let other_execute = global
        .decls_in(other_file)
        .iter()
        .find(|decl| decl.name == "execute")
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .expect("Other.Executor.execute");

    let edges = cg.callees_of(main).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, executor_execute);
    assert_eq!(cg.callers_of(other_execute).count(), 0);
}

#[test]
fn java_package_local_static_calls_do_not_fan_out_to_sibling_packages() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let caller_pkg = ["mega", "flow0"];
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                1,
                "handle",
                vec![
                    method_call(caller_file, "Pipeline.orchestrate", "Pipeline", &[]),
                    assign_call(caller_file, "r", "Pipeline.orchestrate"),
                ],
            ),
            &caller_pkg,
        )],
    );

    for idx in 0..16u32 {
        let file = FileId::new(10 + idx);
        let class_symbol = 100 + idx * 10;
        let method_symbol = class_symbol + 1;
        let pkg_tail = format!("flow{idx}");
        let pkg = ["mega", pkg_tail.as_str()];
        insert_file(
            &mut global,
            file,
            vec![
                with_module_path(
                    decl_with(file, class_symbol, "Pipeline", DeclKind::Class, None, Vec::new()),
                    &pkg,
                ),
                with_module_path(
                    decl_with(
                        file,
                        method_symbol,
                        "orchestrate",
                        DeclKind::Function,
                        Some(class_symbol),
                        Vec::new(),
                    ),
                    &pkg,
                ),
            ],
        );
    }

    let cg = build_graph(&global, |_| Some("java"));
    let handle = FuncId::new(global.find_by_name("handle")[0].raw());
    let same_package_orchestrate = global
        .find_by_name("orchestrate")
        .iter()
        .copied()
        .find(|symbol| {
            global
                .decl_of(*symbol)
                .is_some_and(|decl| decl.module_path.matches(&ModulePath::from_segments(caller_pkg)))
        })
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("same-package orchestrate");

    let edges = cg.callees_of(handle).collect::<Vec<_>>();
    assert_eq!(
        edges.len(),
        2,
        "explicit call and assignment-source call should each keep one same-package target: {edges:?}"
    );
    assert!(
        edges.iter().all(|edge| edge.to == same_package_orchestrate),
        "sibling packages must not be retained as Java same-language candidates: {edges:?}"
    );
}

#[test]
fn local_scope_retention_uses_same_directory_when_modules_are_absent() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let local_file = FileId::new(2);
    let sibling_file = FileId::new(3);
    insert_file(
        &mut global,
        caller_file,
        vec![decl(caller_file, 1, "run", Vec::new())],
    );
    insert_file(
        &mut global,
        local_file,
        vec![decl(local_file, 2, "execute", Vec::new())],
    );
    insert_file(
        &mut global,
        sibling_file,
        vec![decl(sibling_file, 3, "execute", Vec::new())],
    );
    let caller_decl = global
        .find_by_name("run")
        .first()
        .and_then(|symbol| global.decl_of(*symbol))
        .expect("caller declaration");
    let local_execute = global
        .find_by_name("execute")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(local_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("local execute");
    let sibling_execute = global
        .find_by_name("execute")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(sibling_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("sibling execute");
    let mut candidates = vec![local_execute, sibling_execute];

    retain_local_scope_candidates_when_present(
        &global,
        caller_decl,
        &|file| match file {
            f if f == caller_file => Some("/workspace/flow1/app.cpp".to_string()),
            f if f == local_file => Some("/workspace/flow1/executor.cpp".to_string()),
            f if f == sibling_file => Some("/workspace/flow2/executor.cpp".to_string()),
            _ => None,
        },
        &mut candidates,
    );

    assert_eq!(candidates, vec![local_execute]);
}

#[test]
fn cpp_receiver_methods_do_not_fan_out_to_sibling_directories() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let sibling_file = FileId::new(2);
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl_with(
                caller_file,
                10,
                "BaseRepository",
                DeclKind::Class,
                None,
                Vec::new(),
            ),
            decl_with(caller_file, 11, "cmd", DeclKind::Method, Some(10), Vec::new()),
            decl(
                caller_file,
                12,
                "run",
                vec![method_call(caller_file, "repo.cmd", "repo", &["BaseRepository"])],
            ),
        ],
    );
    insert_file(
        &mut global,
        sibling_file,
        vec![
            decl_with(
                sibling_file,
                20,
                "BaseRepository",
                DeclKind::Class,
                None,
                Vec::new(),
            ),
            decl_with(sibling_file, 21, "cmd", DeclKind::Method, Some(20), Vec::new()),
        ],
    );

    let cg = build_graph_with_paths(
        &global,
        |file| match file {
            f if f == caller_file => Some("/workspace/flow1/storage.cpp".to_string()),
            f if f == sibling_file => Some("/workspace/flow2/storage.cpp".to_string()),
            _ => None,
        },
        |_| Some("cpp"),
    );
    let run = FuncId::new(global.find_by_name("run")[0].raw());
    let local_cmd = global
        .find_by_name("cmd")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(caller_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("local cmd");
    let sibling_cmd = global
        .find_by_name("cmd")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(sibling_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("sibling cmd");

    let edges = cg.callees_of(run).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, local_cmd);
    assert_eq!(cg.callers_of(sibling_cmd).count(), 0);
}

#[test]
fn typed_local_receiver_chain_does_not_fall_back_to_module_path() {
    let caller_file = FileId::new(1);
    let cache_module_file = FileId::new(2);
    let other_cache_file = FileId::new(3);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl_with(caller_file, 0, "CacheHolder", DeclKind::Struct, None, Vec::new()),
            decl(
                caller_file,
                1,
                "entry",
                vec![method_call(
                    caller_file,
                    "cache.funcs.get",
                    "cache.funcs",
                    &["CacheHolder"],
                )],
            ),
        ],
    );
    insert_file(
        &mut global,
        cache_module_file,
        vec![with_module_path(
            decl(cache_module_file, 0, "get", Vec::new()),
            &["cache", "funcs"],
        )],
    );
    insert_file(
        &mut global,
        other_cache_file,
        vec![with_module_path(
            decl(other_cache_file, 0, "get", Vec::new()),
            &["other", "cache", "funcs"],
        )],
    );

    let cg = build_graph(&global, |_| Some("rust"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());

    assert_eq!(
        cg.callees_of(entry).count(),
        0,
        "typed local receiver chain must not be reinterpreted as a workspace module path"
    );
}

#[test]
fn receiver_method_does_not_resolve_through_same_named_local_callable_binding() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl(
            caller_file,
            0,
            "entry",
            vec![
                callable_binding(caller_file, "execute", "handler"),
                method_call(caller_file, "service.execute", "service", &[]),
            ],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![decl(helper_file, 0, "handler", Vec::new())],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let handler = FuncId::new(global.find_by_name("handler")[0].raw());

    assert_eq!(cg.callees_of(entry).count(), 0);
    assert_eq!(cg.callers_of(handler).count(), 0);
}

#[test]
fn receiver_projected_callable_binding_resolves_receiver_form_invocation() {
    let caller_file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl(
                caller_file,
                0,
                "entry",
                vec![
                    callable_binding(caller_file, "service.execute", "handler"),
                    method_call(caller_file, "execute", "service", &[]),
                ],
            ),
            decl(caller_file, 1, "handler", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let handler = FuncId::new(global.find_by_name("handler")[0].raw());
    let entry_decl = global
        .decl_of(global.find_by_name("entry")[0])
        .expect("entry decl");
    let bindings = collect_local_callable_bindings(&entry_decl.flow_events, &global, entry_decl);
    assert_eq!(
        bindings.get("service.execute"),
        Some(&handler),
        "projected callable assignment should be collected as a local callable binding"
    );
    assert_eq!(
        collect_local_callable_binding_targets(&bindings, "execute", Some("service"), false),
        vec![handler],
        "receiver-form invocation should look up the projected callable binding"
    );
    let alias_index = WorkspaceAliasIndex::build(&global);
    let callable_index = WorkspaceCallableBindingIndex::build(&global);
    let indexed_bindings = collect_local_callable_bindings_with_alias_index(
        &entry_decl.flow_events,
        &global,
        entry_decl,
        &AHashMap::new(),
        &alias_index,
        Some(&callable_index),
        bonsai_lang_api::ModulePathSyntax::none(),
    );
    assert_eq!(
        indexed_bindings.get("service.execute"),
        Some(&handler),
        "indexed callgraph collector should preserve projected callable bindings"
    );

    let edge = cg
        .callees_of(entry)
        .find(|edge| edge.to == handler)
        .unwrap_or_else(|| {
            panic!(
                "callable stored in receiver-projected storage should resolve when invoked as receiver.method(); got {:?}",
                cg.callees_of(entry).collect::<Vec<_>>()
            )
        });
    assert_eq!(edge.provenance.resolver_stage, "callable_value");
    assert!(edge.provenance.evidence.contains("projected callable binding"));
    assert!(edge.provenance.confidence >= 80);
}

#[test]
fn workspace_alias_index_materializes_module_suffixes() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let mut module_decl = decl(file, 0, "persist", Vec::new());
    module_decl.module_path = ModulePath::from_segments(["services", "storage"]);
    insert_file(&mut global, file, vec![module_decl]);

    let index = WorkspaceAliasIndex::build(&global);
    for alias in ["services::storage", "services.storage", "storage"] {
        assert!(
            index.contains(alias, bonsai_lang_api::ModulePathSyntax::none()),
            "syntax-derived module suffix `{alias}` should be indexed"
        );
    }
    assert!(!index.contains(
        "crate::services::storage",
        bonsai_lang_api::ModulePathSyntax::none()
    ));
    assert!(index.contains(
        "crate::services::storage",
        bonsai_lang_api::ModulePathSyntax {
            rooted_prefixes: &["crate::", "self::"],
            repeatable_rooted_prefixes: &["super::"],
        }
    ));
    assert!(!index.contains("unrelated", bonsai_lang_api::ModulePathSyntax::none()));
}

#[test]
fn receiver_projected_callable_binding_resolves_assignment_rhs_invocation() {
    let caller_file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl(
                caller_file,
                0,
                "entry",
                vec![
                    callable_binding(caller_file, "service.execute", "handler"),
                    FlowEvent::Assign {
                        span: Span::new(caller_file, 30, 60),
                        target: "result".to_string(),
                        source_name: None,
                        source_call: Some("service.execute".to_string()),
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: false,
                        value_kind: Some(AssignValueKind::CallResult),
                    },
                ],
            ),
            decl(caller_file, 1, "handler", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let handler = FuncId::new(global.find_by_name("handler")[0].raw());

    let edge = cg.callees_of(entry).find(|edge| edge.to == handler).expect(
        "callable stored in receiver-projected storage should resolve when invoked in Assign::source_call",
    );
    assert_eq!(edge.provenance.resolver_stage, "callable_value");
    assert!(edge.provenance.evidence.contains("projected callable binding"));
    assert!(edge.provenance.confidence >= 80);
}

#[test]
fn containing_statement_assignment_does_not_shadow_call_inside_expression() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "entry",
                vec![
                    FlowEvent::Call {
                        span: Span::new(file, 20, 30),
                        name: "tokenize".to_string(),
                        receiver: None,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        args: Vec::new(),
                    },
                    FlowEvent::Assign {
                        span: Span::new(file, 10, 40),
                        target: "tokenize".to_string(),
                        source_name: None,
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: vec!["tokenize".to_string()],
                        declares_new_binding: false,
                        value_kind: Some(AssignValueKind::Compound),
                    },
                ],
            ),
            decl(file, 1, "tokenize", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("go"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let tokenize = FuncId::new(global.find_by_name("tokenize")[0].raw());

    assert!(
        cg.callees_of(entry).any(|edge| edge.to == tokenize),
        "synthetic assignment spanning the call expression must not suppress the real call edge"
    );
}

#[test]
fn prior_local_value_assignment_still_shadows_workspace_callable() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "entry",
                vec![
                    FlowEvent::Assign {
                        span: Span::new(file, 1, 10),
                        target: "execute".to_string(),
                        source_name: None,
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: false,
                        value_kind: Some(AssignValueKind::Literal),
                    },
                    FlowEvent::Call {
                        span: Span::new(file, 20, 30),
                        name: "execute".to_string(),
                        receiver: None,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        args: Vec::new(),
                    },
                ],
            ),
            decl(file, 1, "execute", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());

    assert_eq!(
        cg.callees_of(entry).count(),
        0,
        "a real earlier local value binding should still shadow a same-named workspace callable"
    );
}

#[test]
fn callback_argument_resolves_when_outer_callee_is_unresolved() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "entry",
                vec![call_with_args(file, "external.readFile", &["path", "onRead"])],
            ),
            decl(file, 1, "onRead", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("javascript"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let callback = FuncId::new(global.find_by_name("onRead")[0].raw());

    assert!(
        cg.callees_of(entry)
            .any(|edge| edge.to == callback && edge.kind == EdgeKind::Indirect),
        "a compiler-resolved callback argument must survive an unresolved outer API call"
    );
}

#[test]
fn quoted_runtime_callable_variable_resolves_to_workspace_function() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "entry",
                vec![
                    FlowEvent::Assign {
                        span: Span::new(file, 10, 24),
                        target: "$cb".to_string(),
                        source_name: Some("'helper'".to_string()),
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: false,
                        value_kind: Some(AssignValueKind::Literal),
                    },
                    call_with_args(file, "$cb", &["arg"]),
                ],
            ),
            decl(file, 1, "helper", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("php"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let helper = FuncId::new(global.find_by_name("helper")[0].raw());

    assert!(
        cg.callees_of(entry).any(|edge| edge.to == helper),
        "quoted callable literal assigned to a runtime callable variable should resolve when invoked"
    );
}

#[test]
fn quoted_literal_assignment_without_runtime_callable_target_is_not_callback_binding() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "entry",
                vec![
                    FlowEvent::Assign {
                        span: Span::new(file, 10, 24),
                        target: "cb".to_string(),
                        source_name: Some("\"helper\"".to_string()),
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: false,
                        value_kind: Some(AssignValueKind::Literal),
                    },
                    call_with_args(file, "cb", &["arg"]),
                ],
            ),
            decl(file, 1, "helper", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("javascript"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let helper = FuncId::new(global.find_by_name("helper")[0].raw());

    assert!(
        !cg.callees_of(entry).any(|edge| edge.to == helper),
        "ordinary quoted data literals must not become callback aliases"
    );
}

#[test]
fn returned_lambda_factory_assignment_resolves_local_callable_call() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();

    let mut factory = decl(
        file,
        1,
        "makeJoiner",
        vec![FlowEvent::Return {
            span: Span::new(file, 120, 180),
            value_name: None,
            value_text: Some("func(acc, tok string) string { return tok }".to_string()),
            value_flow: Default::default(),
        }],
    );
    factory.span = Span::new(file, 100, 190);
    factory.name_span = Span::new(file, 100, 110);
    factory.body_span = Some(Span::new(file, 110, 190));

    let mut returned_lambda = with_params(decl(file, 2, "<lambda@1:1>", Vec::new()), &["acc", "tok"]);
    returned_lambda.span = Span::new(file, 130, 180);
    returned_lambda.name_span = Span::new(file, 130, 142);
    returned_lambda.body_span = Some(Span::new(file, 150, 180));

    let entry = decl(
        file,
        0,
        "entry",
        vec![
            FlowEvent::Assign {
                span: Span::new(file, 200, 230),
                target: "joiner".to_string(),
                source_name: None,
                source_call: Some("makeJoiner".to_string()),
                source_call_args: vec!["\" \"".to_string()],
                source_names: vec!["makeJoiner".to_string()],
                declares_new_binding: true,
                value_kind: Some(AssignValueKind::CallResult),
            },
            call_with_args(file, "joiner", &["joined", "t"]),
        ],
    );
    insert_file(&mut global, file, vec![entry, factory, returned_lambda]);

    let cg = build_graph(&global, |_| Some("go"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let lambda = FuncId::new(global.find_by_name("<lambda@1:1>")[0].raw());

    assert!(
        cg.callees_of(entry).any(|edge| edge.to == lambda),
        "local callable returned by a closure factory should resolve when invoked through its assigned variable"
    );
}

#[test]
fn object_constructor_assignment_is_not_callback_binding() {
    let caller_file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![
            decl_with(
                caller_file,
                0,
                "Envelope",
                DeclKind::Constructor,
                None,
                Vec::new(),
            ),
            decl(
                caller_file,
                1,
                "handle_request",
                vec![
                    FlowEvent::Assign {
                        span: Span::new(caller_file, 10, 40),
                        target: "envelope".to_string(),
                        source_name: Some("Envelope".to_string()),
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: vec!["Envelope".to_string(), "raw".to_string(), "user".to_string()],
                        declares_new_binding: true,
                        value_kind: Some(AssignValueKind::Compound),
                    },
                    call_with_args(caller_file, "orchestrateAsync", &["envelope"]),
                ],
            ),
            decl(caller_file, 2, "orchestrateAsync", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("dart"));
    let entry = FuncId::new(global.find_by_name("handle_request")[0].raw());
    let envelope_ctor = FuncId::new(global.find_by_name("Envelope")[0].raw());
    let orchestrate = FuncId::new(global.find_by_name("orchestrateAsync")[0].raw());
    let edges = cg.callees_of(entry).collect::<Vec<_>>();

    assert!(
        edges.iter().any(|edge| edge.to == orchestrate),
        "ordinary data argument must still resolve the real call target"
    );
    assert!(
        !edges
            .iter()
            .any(|edge| edge.to == envelope_ctor && edge.kind == EdgeKind::Indirect),
        "constructor result must not be treated as a callback alias"
    );
}

#[test]
fn parameter_argument_is_not_same_named_constructor_callback() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl_with(file, 0, "Envelope", DeclKind::Constructor, None, Vec::new()),
            with_params(
                decl(
                    file,
                    1,
                    "persist",
                    vec![FlowEvent::Call {
                        span: Span::new(file, 20, 40),
                        name: "AuditedRepository".to_string(),
                        receiver: None,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Constructor,
                        args: vec![CallArg {
                            passing_mode: Default::default(),
                            span: Span::new(file, 30, 38),
                            name: None,
                            value_text: "envelope".to_string(),
                            place: Some("envelope".to_string()),
                            source_names: vec!["envelope".to_string()],
                        }],
                    }],
                ),
                &["envelope"],
            ),
            decl_with(
                file,
                2,
                "AuditedRepository",
                DeclKind::Constructor,
                None,
                Vec::new(),
            ),
        ],
    );

    let cg = build_graph(&global, |_| Some("dart"));
    let persist = FuncId::new(global.find_by_name("persist")[0].raw());
    let envelope_ctor = FuncId::new(global.find_by_name("Envelope")[0].raw());
    let audited_ctor = FuncId::new(global.find_by_name("AuditedRepository")[0].raw());
    let edges = cg.callees_of(persist).collect::<Vec<_>>();

    assert!(
        edges.iter().any(|edge| edge.to == audited_ctor),
        "the AST call target must resolve to its constructor: {edges:#?}"
    );
    assert!(
        edges.iter().all(|edge| edge.to != envelope_ctor),
        "the lexical parameter must shadow the same-spelled constructor in callback lookup: {edges:#?}"
    );
}

#[test]
fn assign_source_call_emits_edge_at_assignment_span_for_bare_call() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(file, 0, "top", vec![assign_call(file, "cmd", "mid")]),
            decl(file, 1, "mid", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("python"));
    let top = FuncId::new(global.find_by_name("top")[0].raw());
    let mid = FuncId::new(global.find_by_name("mid")[0].raw());

    let edges = cg.callees_of(top).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, mid);
    assert_eq!(edges[0].span, Span::new(file, 100, 103));
}

#[test]
fn assign_source_call_does_not_duplicate_explicit_call_edge() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "top",
                vec![
                    FlowEvent::Assign {
                        span: Span::new(file, 100, 120),
                        target: "user_id".to_string(),
                        source_name: None,
                        source_call: Some("mid".to_string()),
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: false,
                        value_kind: None,
                    },
                    FlowEvent::Call {
                        span: Span::new(file, 110, 113),
                        name: "mid".to_string(),
                        receiver: None,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        args: Vec::new(),
                    },
                ],
            ),
            decl(file, 1, "mid", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("python"));
    let top = FuncId::new(global.find_by_name("top")[0].raw());
    let mid = FuncId::new(global.find_by_name("mid")[0].raw());

    let edges = cg.callees_of(top).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, mid);
    assert_eq!(edges[0].span, Span::new(file, 110, 113));

    let caller_decl = global.decl_of(SymbolId::new(top.raw())).expect("top decl");
    let span = find_call_span_resolved(
        &caller_decl.flow_events,
        mid,
        "mid",
        &global,
        &AHashMap::new(),
        &AHashMap::new(),
        caller_decl,
    )
    .expect("resolved call span");
    assert_eq!(span, Span::new(file, 110, 113));
}

#[test]
fn constructor_assignment_narrows_constructor_edge_to_assigned_type() {
    let file = FileId::new(1);
    let repo = 1;
    let audited = 2;
    let base_ctor = 3;
    let audited_ctor = 4;
    let orchestrate = 5;
    let mut global = GlobalIndex::new();

    let mut repo_class = decl_with(file, repo, "Repository", DeclKind::Class, None, Vec::new());
    repo_class.body_span = Some(Span::new(file, 0, 100));
    let mut audited_class = decl_with(
        file,
        audited,
        "AuditedRepository",
        DeclKind::Class,
        None,
        Vec::new(),
    );
    audited_class.body_span = Some(Span::new(file, 100, 220));
    audited_class.bases = vec!["Repository".to_string()];
    let mut base_init = decl_with(
        file,
        base_ctor,
        "__init__",
        DeclKind::Constructor,
        Some(repo),
        Vec::new(),
    );
    base_init.span = Span::new(file, 20, 40);
    base_init.name_span = Span::new(file, 24, 32);
    base_init.body_span = Some(Span::new(file, 32, 40));
    let mut audited_init = decl_with(
        file,
        audited_ctor,
        "__init__",
        DeclKind::Constructor,
        Some(audited),
        Vec::new(),
    );
    audited_init.span = Span::new(file, 140, 180);
    audited_init.name_span = Span::new(file, 144, 152);
    audited_init.body_span = Some(Span::new(file, 152, 180));
    let mut caller = decl(
        file,
        orchestrate,
        "orchestrate",
        vec![
            FlowEvent::Call {
                span: Span::new(file, 310, 330),
                name: "AuditedRepository".to_string(),
                receiver: None,
                receiver_types: vec!["AuditedRepository".to_string()],
                call_kind: CallKind::Constructor,
                args: Vec::new(),
            },
            FlowEvent::Assign {
                span: Span::new(file, 300, 340),
                target: "repo".to_string(),
                source_name: None,
                source_call: Some("AuditedRepository".to_string()),
                source_call_args: vec!["valid".to_string()],
                source_names: vec!["AuditedRepository".to_string(), "valid".to_string()],
                declares_new_binding: false,
                value_kind: Some(AssignValueKind::CallResult),
            },
        ],
    );
    caller.body_span = Some(Span::new(file, 280, 360));
    insert_file(
        &mut global,
        file,
        vec![repo_class, audited_class, base_init, audited_init, caller],
    );

    let cg = build_graph(&global, |_| Some("python"));
    let from = FuncId::new(global.find_by_name("orchestrate")[0].raw());
    let audited_init_id = func_id_by_name_and_parent(&global, "__init__", "AuditedRepository");
    let base_init_id = func_id_by_name_and_parent(&global, "__init__", "Repository");
    let edges = cg.callees_of(from).collect::<Vec<_>>();

    assert!(
        edges.iter().any(|edge| edge.to == audited_init_id),
        "constructor assignment should resolve to AuditedRepository.__init__: {edges:?}"
    );
    assert!(
        !edges.iter().any(|edge| edge.to == base_init_id),
        "constructor assignment must not also fan out to Repository.__init__: {edges:?}"
    );
}

#[test]
fn constructor_call_uses_nearest_inherited_constructor_when_subclass_declares_none() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let base = 1;
    let child = 2;
    let mut base_class = decl_with(file, base, "Repository", DeclKind::Class, None, Vec::new());
    base_class.body_span = Some(Span::new(file, 0, 100));
    let mut child_class = decl_with(
        file,
        child,
        "AuditedRepository",
        DeclKind::Class,
        None,
        Vec::new(),
    );
    child_class.body_span = Some(Span::new(file, 100, 200));
    child_class.bases = vec!["Repository".to_string()];
    let base_init = decl_with(
        file,
        3,
        "Repository",
        DeclKind::Constructor,
        Some(base),
        Vec::new(),
    );
    let caller = decl(
        file,
        4,
        "persist",
        vec![FlowEvent::Call {
            span: Span::new(file, 300, 320),
            name: "AuditedRepository".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Constructor,
            args: Vec::new(),
        }],
    );
    insert_file(
        &mut global,
        file,
        vec![base_class, child_class, base_init, caller],
    );

    let graph = build_graph(&global, |_| Some("swift"));
    let persist = FuncId::new(global.find_by_name("persist")[0].raw());
    let inherited_init = func_id_by_name_and_parent(&global, "Repository", "Repository");
    assert_eq!(
        graph.callees_of(persist).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![inherited_init]
    );
}

#[test]
fn constructor_call_resolves_by_kind_and_class_parent_not_method_spelling() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let class = decl_with(file, 1, "Box", DeclKind::Class, None, Vec::new());
    let constructor = decl_with(file, 2, "forge", DeclKind::Constructor, Some(1), Vec::new());
    let caller = decl(
        file,
        3,
        "entry",
        vec![FlowEvent::Call {
            span: Span::new(file, 100, 120),
            name: "forge".to_string(),
            receiver: Some("Box".to_string()),
            receiver_types: vec!["Box".to_string()],
            call_kind: CallKind::Constructor,
            args: Vec::new(),
        }],
    );
    insert_file(&mut global, file, vec![class, constructor, caller]);

    let graph = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let constructor = func_id_by_name_and_parent(&global, "forge", "Box");
    assert_eq!(
        graph.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![constructor]
    );
}

#[test]
fn receiverless_qualified_factory_constructor_uses_adapter_receiver_type() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let class = decl_with(file, 1, "AuditedRepository", DeclKind::Class, None, Vec::new());
    let constructor = with_params(
        decl_with(file, 2, "wrap", DeclKind::Constructor, Some(1), Vec::new()),
        &["data"],
    );
    let repository = decl_with(file, 4, "Repository", DeclKind::Class, None, Vec::new());
    let repository_constructor = with_params(
        decl_with(file, 5, "new", DeclKind::Constructor, Some(4), Vec::new()),
        &["data"],
    );
    let caller = decl(
        file,
        3,
        "persist",
        vec![FlowEvent::Call {
            span: Span::new(file, 100, 140),
            name: "AuditedRepository::wrap".to_string(),
            receiver: None,
            receiver_types: vec!["AuditedRepository".to_string(), "Repository".to_string()],
            call_kind: CallKind::Constructor,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: Span::new(file, 130, 138),
                name: None,
                value_text: "envelope".to_string(),
                place: Some("envelope".to_string()),
                source_names: vec!["envelope".to_string()],
            }],
        }],
    );
    insert_file(
        &mut global,
        file,
        vec![class, constructor, repository, repository_constructor, caller],
    );

    let graph = build_graph(&global, |_| Some("rust"));
    let persist = FuncId::new(global.find_by_name("persist")[0].raw());
    let constructor = func_id_by_name_and_parent(&global, "wrap", "AuditedRepository");
    assert_eq!(
        graph.callees_of(persist).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![constructor]
    );
}

#[test]
fn receiverless_ast_constructor_call_resolves_named_parent_before_member_lookup() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let mut base_class = decl_with(file, 1, "Base", DeclKind::Class, None, Vec::new());
    let mut repository_class = decl_with(file, 2, "Repository", DeclKind::Class, None, Vec::new());
    repository_class.bases = vec!["Base".to_string()];
    let mut audited_class = decl_with(file, 3, "Audited", DeclKind::Class, None, Vec::new());
    audited_class.bases = vec!["Repository".to_string()];
    base_class.body_span = Some(Span::new(file, 0, 100));
    repository_class.body_span = Some(Span::new(file, 100, 200));
    audited_class.body_span = Some(Span::new(file, 200, 400));

    let base_ctor = with_params(
        decl_with(file, 4, "Base", DeclKind::Constructor, Some(1), Vec::new()),
        &["data"],
    );
    let repository_ctor = with_params(
        decl_with(file, 5, "Repository", DeclKind::Constructor, Some(2), Vec::new()),
        &["data"],
    );
    let audited_ctor = with_params(
        decl_with(
            file,
            6,
            "Audited",
            DeclKind::Constructor,
            Some(3),
            vec![FlowEvent::Call {
                span: Span::new(file, 260, 280),
                name: "Repository".to_string(),
                receiver: None,
                receiver_types: vec!["Repository".to_string(), "Base".to_string()],
                call_kind: CallKind::Constructor,
                args: vec![CallArg {
                    passing_mode: Default::default(),
                    span: Span::new(file, 270, 274),
                    name: None,
                    value_text: "data".to_string(),
                    place: Some("data".to_string()),
                    source_names: vec!["data".to_string()],
                }],
            }],
        ),
        &["data"],
    );
    insert_file(
        &mut global,
        file,
        vec![
            base_class,
            repository_class,
            audited_class,
            base_ctor,
            repository_ctor,
            audited_ctor,
        ],
    );

    let graph = build_graph(&global, |_| Some("scala"));
    let audited = func_id_by_name_and_parent(&global, "Audited", "Audited");
    let repository = func_id_by_name_and_parent(&global, "Repository", "Repository");
    let base = func_id_by_name_and_parent(&global, "Base", "Base");
    let targets = graph.callees_of(audited).map(|edge| edge.to).collect::<Vec<_>>();
    assert_eq!(targets, vec![repository]);
    assert!(!targets.contains(&base), "{targets:?}");
}

#[test]
fn super_constructor_resolves_direct_parent_not_transitive_ancestors() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let mut base_class = decl_with(file, 1, "Base", DeclKind::Class, None, Vec::new());
    let mut repo_class = decl_with(file, 2, "Repository", DeclKind::Class, None, Vec::new());
    repo_class.bases = vec!["Base".to_string()];
    let mut audited_class = decl_with(file, 3, "Audited", DeclKind::Class, None, Vec::new());
    audited_class.bases = vec!["Repository".to_string()];
    base_class.body_span = Some(Span::new(file, 0, 100));
    repo_class.body_span = Some(Span::new(file, 100, 200));
    audited_class.body_span = Some(Span::new(file, 200, 400));

    let mut base_ctor = with_params(
        decl_with(file, 4, "Base", DeclKind::Constructor, Some(1), Vec::new()),
        &["data"],
    );
    base_ctor.span = Span::new(file, 20, 80);
    base_ctor.name_span = Span::new(file, 20, 24);
    base_ctor.body_span = Some(Span::new(file, 24, 80));
    let mut repo_ctor = with_params(
        decl_with(file, 5, "Repository", DeclKind::Constructor, Some(2), Vec::new()),
        &["data"],
    );
    repo_ctor.span = Span::new(file, 120, 180);
    repo_ctor.name_span = Span::new(file, 120, 130);
    repo_ctor.body_span = Some(Span::new(file, 130, 180));
    let mut audited_ctor = with_params(
        decl_with(
            file,
            6,
            "Audited",
            DeclKind::Constructor,
            Some(3),
            vec![FlowEvent::Call {
                span: Span::new(file, 260, 280),
                name: "Repository".to_string(),
                receiver: Some("super".to_string()),
                receiver_types: vec!["Repository".to_string(), "Base".to_string()],
                call_kind: CallKind::Constructor,
                args: vec![CallArg {
                    passing_mode: Default::default(),
                    span: Span::new(file, 270, 274),
                    name: None,
                    value_text: "data".to_string(),
                    place: Some("data".to_string()),
                    source_names: vec!["data".to_string()],
                }],
            }],
        ),
        &["data"],
    );
    audited_ctor.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
    audited_ctor.span = Span::new(file, 240, 300);
    audited_ctor.name_span = Span::new(file, 240, 247);
    audited_ctor.body_span = Some(Span::new(file, 247, 300));
    insert_file(
        &mut global,
        file,
        vec![
            base_class,
            repo_class,
            audited_class,
            base_ctor,
            repo_ctor,
            audited_ctor,
        ],
    );

    let graph = ResolvedCallGraph::build_with_file_semantics(
        &global,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |_| AHashMap::new(),
            |_| None,
            |_| Some("java"),
            |_| LanguageCapabilities {
                super_receiver_tokens: &["super"],
                ..LanguageCapabilities::unsupported()
            },
        ),
    );
    let audited = func_id_by_name_and_parent(&global, "Audited", "Audited");
    let repository = func_id_by_name_and_parent(&global, "Repository", "Repository");
    let base = func_id_by_name_and_parent(&global, "Base", "Base");
    let caller_decl = global
        .decl_of(SymbolId::new(audited.raw()))
        .expect("audited constructor");
    let FlowEvent::Call {
        name,
        receiver,
        receiver_types,
        call_kind,
        span,
        args,
    } = &caller_decl.flow_events[0]
    else {
        panic!("expected constructor call");
    };
    let helper_targets = collect_call_event_targets_with_context_aliases_and_super_tokens(
        &global,
        name,
        receiver.as_deref(),
        receiver_types,
        *call_kind,
        *span,
        args,
        caller_decl,
        &AHashMap::new(),
        &|_| None,
        &[],
        &[],
        &["super"],
    );
    let targets = graph.callees_of(audited).map(|edge| edge.to).collect::<Vec<_>>();

    assert_eq!(helper_targets, vec![repository]);
    assert!(targets.contains(&repository), "{targets:?}");
    assert!(!targets.contains(&base), "{targets:?}");
}

#[test]
fn class_shaped_function_call_does_not_infer_a_constructor() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let class = decl_with(file, 1, "Widget", DeclKind::Class, None, Vec::new());
    let constructor = decl_with(file, 2, "allocate", DeclKind::Constructor, Some(1), Vec::new());
    let caller = decl(file, 3, "entry", vec![call(file, "Widget")]);
    insert_file(&mut global, file, vec![class, constructor, caller]);

    let graph = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    assert_eq!(
        graph.callees_of(entry).count(),
        0,
        "uppercase spelling is not constructor evidence"
    );
}

#[test]
fn ambiguous_bare_call_constructs_only_with_adapter_capability_and_resolved_class() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let class = decl_with(file, 1, "Widget", DeclKind::Class, None, Vec::new());
    let constructor = decl_with(file, 2, "allocate", DeclKind::Constructor, Some(1), Vec::new());
    let caller = decl(file, 3, "entry", vec![call(file, "Widget")]);
    insert_file(&mut global, file, vec![class, constructor, caller]);

    let graph = ResolvedCallGraph::build_with_file_semantics(
        &global,
        CallGraphFileSemantics::new(
            |_| ahash::AHashMap::new(),
            |_| ahash::AHashMap::new(),
            |_| None,
            |_| Some("python"),
            |_| LanguageCapabilities {
                bare_call_constructor_syntax: true,
                ..LanguageCapabilities::unsupported()
            },
        ),
    );
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let constructor = func_id_by_name_and_parent(&global, "allocate", "Widget");
    assert_eq!(
        graph.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![constructor]
    );
}

#[test]
fn returned_constructor_type_comes_from_expression_call_site_not_text() {
    let file = FileId::new(1);
    let call_span = Span::new(file, 40, 60);
    let mut global = GlobalIndex::new();
    let class = decl_with(file, 1, "Product", DeclKind::Class, None, Vec::new());
    let constructor = decl_with(
        file,
        2,
        "build_anyhow",
        DeclKind::Constructor,
        Some(1),
        Vec::new(),
    );
    let factory = decl(
        file,
        3,
        "factory",
        vec![
            FlowEvent::Call {
                span: call_span,
                name: "build_anyhow".to_string(),
                receiver: Some("Product".to_string()),
                receiver_types: vec!["Product".to_string()],
                call_kind: CallKind::Constructor,
                args: Vec::new(),
            },
            FlowEvent::Return {
                span: Span::new(file, 35, 65),
                value_name: None,
                value_text: Some("misleading_render_text".to_string()),
                value_flow: bonsai_lang_api::ExpressionFlow {
                    call_sites: vec![Span::new(file, call_span.start, 65)],
                    ..Default::default()
                },
            },
        ],
    );
    insert_file(&mut global, file, vec![class, constructor, factory]);
    let factory = global
        .find_by_name("factory")
        .first()
        .and_then(|symbol| global.decl_of(*symbol))
        .expect("globally remapped factory declaration");

    let mut types = Vec::new();
    collect_constructed_return_type_names(&global, factory, &AHashMap::new(), factory, &mut types);
    assert_eq!(types, vec!["Product".to_string()]);
}

#[test]
fn assigned_subclass_receiver_resolves_inherited_method_from_class_context() {
    let caller_file = FileId::new(1);
    let storage_file = FileId::new(2);
    let repo = 1;
    let audited = 2;
    let persist = 3;
    let orchestrate = 4;
    let mut global = GlobalIndex::new();

    let mut caller = decl(
        caller_file,
        orchestrate,
        "orchestrate",
        vec![
            FlowEvent::Assign {
                span: Span::new(caller_file, 100, 130),
                target: "repo".to_string(),
                source_name: None,
                source_call: Some("AuditedRepository".to_string()),
                source_call_args: vec!["valid".to_string()],
                source_names: vec!["AuditedRepository".to_string(), "valid".to_string()],
                declares_new_binding: false,
                value_kind: None,
            },
            FlowEvent::Call {
                span: Span::new(caller_file, 150, 165),
                name: "repo.persist".to_string(),
                receiver: Some("repo".to_string()),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
        ],
    );
    caller.module_path = ModulePath::from_segments(["pipeline"]);
    let mut repo_class = decl_with(
        storage_file,
        repo,
        "Repository",
        DeclKind::Class,
        None,
        Vec::new(),
    );
    repo_class.module_path = ModulePath::from_segments(["storage"]);
    repo_class.body_span = Some(Span::new(storage_file, 0, 100));
    let mut audited_class = decl_with(
        storage_file,
        audited,
        "AuditedRepository",
        DeclKind::Class,
        None,
        Vec::new(),
    );
    audited_class.module_path = ModulePath::from_segments(["storage"]);
    audited_class.body_span = Some(Span::new(storage_file, 100, 200));
    audited_class.bases = vec!["Repository".to_string()];
    let mut persist_method = decl_with(
        storage_file,
        persist,
        "persist",
        DeclKind::Method,
        Some(repo),
        Vec::new(),
    );
    persist_method.module_path = ModulePath::from_segments(["storage"]);
    persist_method.span = Span::new(storage_file, 20, 80);
    persist_method.name_span = Span::new(storage_file, 24, 31);
    persist_method.body_span = Some(Span::new(storage_file, 31, 80));

    insert_file(&mut global, caller_file, vec![caller]);
    insert_file(
        &mut global,
        storage_file,
        vec![repo_class, audited_class, persist_method],
    );
    let alias_targets = AHashMap::from_iter([(
        "AuditedRepository".to_string(),
        AliasTarget::Member {
            module: "storage".to_string(),
            member: "AuditedRepository".to_string(),
        },
    )]);

    let cg = ResolvedCallGraph::build_with_file_info(
        &global,
        |_| AHashMap::new(),
        |file| {
            if file == caller_file {
                alias_targets.clone()
            } else {
                AHashMap::new()
            }
        },
        |file| {
            if file == storage_file {
                Some("storage.py".to_string())
            } else {
                Some("pipeline.py".to_string())
            }
        },
        |_| &[],
        |_| Some("python"),
    );
    let from = FuncId::new(global.find_by_name("orchestrate")[0].raw());
    let persist_id = FuncId::new(global.find_by_name("persist")[0].raw());
    let edges = cg.callees_of(from).collect::<Vec<_>>();

    assert!(
        edges.iter().any(|edge| edge.to == persist_id),
        "assigned subclass receiver should dispatch inherited persist: {edges:?}"
    );
}

#[test]
fn alias_qualified_call_with_receiver_resolves_as_module_call() {
    let caller_file = FileId::new(1);
    let storage_file = FileId::new(2);
    let mut global = GlobalIndex::new();

    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                1,
                "orchestrate",
                vec![FlowEvent::Call {
                    span: Span::new(caller_file, 100, 116),
                    name: "store::persist".to_string(),
                    receiver: Some("store".to_string()),
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Method,
                    args: Vec::new(),
                }],
            ),
            &["pipeline"],
        )],
    );
    insert_file(
        &mut global,
        storage_file,
        vec![with_module_path(
            decl(storage_file, 1, "persist", Vec::new()),
            &["storage"],
        )],
    );
    let alias_targets = AHashMap::from_iter([(
        "store".to_string(),
        AliasTarget::Member {
            module: "crate".to_string(),
            member: "storage".to_string(),
        },
    )]);

    let cg = ResolvedCallGraph::build_with_file_info(
        &global,
        |file| {
            if file == caller_file {
                AHashMap::from_iter([("store".to_string(), "storage".to_string())])
            } else {
                AHashMap::new()
            }
        },
        |file| {
            if file == caller_file {
                alias_targets.clone()
            } else {
                AHashMap::new()
            }
        },
        |file| {
            if file == storage_file {
                Some("src/storage.rs".to_string())
            } else {
                Some("src/pipeline.rs".to_string())
            }
        },
        |_| &[],
        |_| Some("rust"),
    );
    let from = FuncId::new(global.find_by_name("orchestrate")[0].raw());
    let persist = FuncId::new(global.find_by_name("persist")[0].raw());
    let edges = cg.callees_of(from).collect::<Vec<_>>();

    assert!(
        edges.iter().any(|edge| edge.to == persist),
        "alias-qualified module call should not be blocked as unresolved instance receiver: {edges:?}"
    );
}

#[test]
fn assign_source_call_does_not_duplicate_nested_try_call_edge() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "top",
                vec![
                    FlowEvent::Assign {
                        span: Span::new(file, 100, 140),
                        target: "user_id".to_string(),
                        source_name: None,
                        source_call: Some("mid".to_string()),
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: false,
                        value_kind: None,
                    },
                    FlowEvent::Try {
                        span: Span::new(file, 110, 130),
                        body: vec![FlowEvent::Call {
                            span: Span::new(file, 116, 119),
                            name: "mid".to_string(),
                            receiver: None,
                            receiver_types: Vec::new(),
                            call_kind: CallKind::Function,
                            args: Vec::new(),
                        }],
                        catch_events: Vec::new(),
                        finally_events: Vec::new(),
                        catch_param: None,
                        catch_types: Vec::new(),
                    },
                ],
            ),
            decl(file, 1, "mid", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("rust"));
    let top = FuncId::new(global.find_by_name("top")[0].raw());
    let mid = FuncId::new(global.find_by_name("mid")[0].raw());

    let edges = cg.callees_of(top).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to, mid);
    assert_eq!(edges[0].span, Span::new(file, 116, 119));
}

#[test]
fn assign_source_call_member_without_class_receiver_does_not_bare_tail_fallback() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl(
            caller_file,
            0,
            "entry",
            vec![assign_call(caller_file, "result", "service.execute")],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![decl(helper_file, 0, "execute", Vec::new())],
    );

    let cg = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let execute = FuncId::new(global.find_by_name("execute")[0].raw());

    assert_eq!(cg.callees_of(entry).count(), 0);
    assert_eq!(cg.callers_of(execute).count(), 0);
}

#[test]
fn call_event_target_helper_does_not_resolve_unresolved_receiver_method() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    let caller = decl_with(caller_file, 0, "entry", DeclKind::Function, None, Vec::new());
    insert_file(&mut global, caller_file, vec![caller.clone()]);
    insert_file(
        &mut global,
        helper_file,
        vec![
            decl_with(helper_file, 0, "Certificate", DeclKind::Class, None, Vec::new()),
            decl_with(helper_file, 1, "equals", DeclKind::Method, Some(0), Vec::new()),
        ],
    );

    let targets = collect_call_event_targets_with_context_and_aliases(
        &global,
        "cookieName.equals",
        Some("cookieName"),
        &[],
        CallKind::Method,
        Span::new(caller_file, 20, 30),
        &[],
        &caller,
        &AHashMap::new(),
        &|_| None,
        &[],
    );

    assert!(
        targets.is_empty(),
        "untyped receiver method resolved to {targets:?}"
    );
}

#[test]
fn call_event_target_helper_resolves_module_qualified_receiver_without_bare_fanout() {
    let caller_file = FileId::new(1);
    let executor_file = FileId::new(2);
    let other_file = FileId::new(3);
    let mut global = GlobalIndex::new();
    let caller = decl(
        caller_file,
        0,
        "main",
        vec![method_call(
            caller_file,
            "Mega.Executor.execute",
            "Mega.Executor",
            &[],
        )],
    );
    insert_file(&mut global, caller_file, vec![caller.clone()]);
    insert_file(
        &mut global,
        executor_file,
        vec![with_module_path(
            decl(executor_file, 0, "execute", Vec::new()),
            &["Mega", "Executor"],
        )],
    );
    insert_file(
        &mut global,
        other_file,
        vec![with_module_path(
            decl(other_file, 0, "execute", Vec::new()),
            &["Other", "Executor"],
        )],
    );
    let executor_execute = global
        .decls_in(executor_file)
        .iter()
        .find(|decl| decl.name == "execute")
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .expect("Mega.Executor.execute");

    let targets = collect_call_event_targets_with_context_and_aliases(
        &global,
        "Mega.Executor.execute",
        Some("Mega.Executor"),
        &[],
        CallKind::Method,
        Span::new(caller_file, 20, 30),
        &[],
        &caller,
        &AHashMap::new(),
        &|_| None,
        &[],
    );

    assert_eq!(targets, vec![executor_execute]);
}

#[test]
fn call_event_target_helper_resolves_alias_receiver_before_bailout() {
    let caller_file = FileId::new(1);
    let storage_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    let caller = decl(
        caller_file,
        0,
        "orchestrate",
        vec![method_call(caller_file, "Store.persist", "Store", &[])],
    );
    insert_file(&mut global, caller_file, vec![caller.clone()]);
    insert_file(
        &mut global,
        storage_file,
        vec![decl(storage_file, 0, "persist", Vec::new())],
    );
    let alias_targets = AHashMap::from_iter([(
        "Store".to_string(),
        AliasTarget::Member {
            module: "storage".to_string(),
            member: "Storage".to_string(),
        },
    )]);
    let persist = FuncId::new(global.find_by_name("persist")[0].raw());

    let targets = collect_call_event_targets_with_context_and_aliases(
        &global,
        "Store.persist",
        Some("Store"),
        &[],
        CallKind::Method,
        Span::new(caller_file, 20, 30),
        &[],
        &caller,
        &alias_targets,
        &|file| (file == storage_file).then(|| "storage.ex".to_string()),
        &[],
    );

    assert_eq!(targets, vec![persist]);
}

#[test]
fn typed_external_receiver_method_does_not_fall_back_to_workspace_method() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl_with(
            caller_file,
            0,
            "doPost",
            DeclKind::Method,
            None,
            vec![method_call(caller_file, "value.equals", "value", &["String"])],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![
            decl_with(helper_file, 0, "Certificate", DeclKind::Class, None, Vec::new()),
            decl_with(helper_file, 1, "equals", DeclKind::Method, Some(0), Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let do_post = FuncId::new(global.find_by_name("doPost")[0].raw());
    let equals = FuncId::new(global.find_by_name("equals")[0].raw());

    assert_eq!(cg.callees_of(do_post).count(), 0);
    assert_eq!(cg.callers_of(equals).count(), 0);
}

#[test]
fn assign_source_call_typed_external_member_does_not_fall_back_to_workspace_method() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl(
            caller_file,
            0,
            "doPost",
            vec![FlowEvent::Assign {
                span: Span::new(caller_file, 100, 112),
                target: "ok".to_string(),
                source_name: None,
                source_call: Some("value.equals".to_string()),
                source_call_args: vec!["\"BenchmarkTest00521\"".to_string()],
                source_names: vec!["value".to_string(), "value.equals".to_string()],
                declares_new_binding: false,
                value_kind: Some(AssignValueKind::CallResult),
            }],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![
            decl_with(helper_file, 0, "Certificate", DeclKind::Class, None, Vec::new()),
            decl_with(helper_file, 1, "equals", DeclKind::Method, Some(0), Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let do_post = FuncId::new(global.find_by_name("doPost")[0].raw());
    let equals = FuncId::new(global.find_by_name("equals")[0].raw());

    assert_eq!(cg.callees_of(do_post).count(), 0);
    assert_eq!(cg.callers_of(equals).count(), 0);
}

#[test]
fn nested_call_result_argument_is_not_callback_reference() {
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![decl(
            caller_file,
            0,
            "doPost",
            vec![call_with_args(caller_file, "guard", &["cookie.getName()"])],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![decl(helper_file, 0, "getName", Vec::new())],
    );

    let cg = build_graph(&global, |_| Some("java"));
    let do_post = FuncId::new(global.find_by_name("doPost")[0].raw());
    let get_name = FuncId::new(global.find_by_name("getName")[0].raw());

    assert!(!cg
        .callees_of(do_post)
        .any(|edge| edge.to == get_name && edge.kind == EdgeKind::Indirect));
    assert_eq!(cg.callers_of(get_name).count(), 0);
}
