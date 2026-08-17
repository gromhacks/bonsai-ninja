use super::*;
use crate::chains::{enumerate_paths_resolved, PathTruncation};
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{CallKind, DeclIndex, ModulePath, Visibility, NO_CONSTRUCTOR_METHOD_NAMES};

#[test]
fn compact_callgraph_wire_rebuilds_adjacency_and_provenance() {
    assert!(std::mem::size_of::<EdgeProvenance>() <= 16);
    let caller = FuncId::new(1);
    let callee = FuncId::new(2);
    let mut graph = CallGraph::new();
    graph.add_edge(CallEdge {
        from: caller,
        to: callee,
        span: Span::new(FileId::new(3), 10, 14),
        kind: EdgeKind::Direct,
        precision: Precision::Narrowed,
        provenance: EdgeProvenance::receiver_dispatch(),
    });

    let encoded = bonsai_common::wire::encode(&graph).expect("encode compact callgraph");
    let restored: CallGraph = bonsai_common::wire::decode(&encoded).expect("decode compact callgraph");
    let edge = restored
        .callees(caller)
        .next()
        .expect("deserialize rebuilds outgoing adjacency");
    assert_eq!(edge.to, callee);
    assert_eq!(edge.provenance.resolver_stage(), "receiver_type");
    assert_eq!(edge.provenance.confidence(), 82);
    assert_eq!(restored.callers(callee).count(), 1);
}

#[test]
fn human_readable_provenance_keeps_the_public_json_contract() {
    let provenance = EdgeProvenance::receiver_dispatch();
    let value = serde_json::to_value(&provenance).expect("serialize provenance JSON");
    assert_eq!(value["resolver_stage"], "receiver_type");
    assert!(value["evidence"]
        .as_str()
        .is_some_and(|text| text.contains("receiver type")));
    assert_eq!(value["confidence"], 82);
    assert!(value.get("kind").is_none());
    assert!(value.get("custom").is_none());

    let restored: EdgeProvenance = serde_json::from_value(value).expect("deserialize provenance JSON");
    assert_eq!(restored, provenance);
}

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
        args: call_args(file, args),
    }
}

fn call_args(file: FileId, args: &[&str]) -> Vec<CallArg> {
    args.iter()
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
        .collect()
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
fn same_signature_family_uses_parameter_types_not_parameter_spelling() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            with_params_and_types(decl(file, 0, "work", Vec::new()), &[("value", "Input")]),
            with_params_and_types(decl(file, 1, "work", Vec::new()), &[("_value", "Input")]),
            with_params_and_types(decl(file, 2, "work", Vec::new()), &[("value", "Other")]),
        ],
    );
    let candidates = global
        .find_by_name("work")
        .iter()
        .copied()
        .map(|symbol| FuncId::new(symbol.raw()))
        .collect::<Vec<_>>();

    assert!(candidate_set_is_same_decl_family(
        &global,
        &candidates[..2],
        CallableDeclarationFamily::SameSignature,
    ));
    assert!(!candidate_set_is_same_decl_family(
        &global,
        &[candidates[0], candidates[2]],
        CallableDeclarationFamily::SameSignature,
    ));
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
        ..DeclIndex::default()
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

#[test]
fn qualified_function_identity_does_not_inject_a_receiver_argument() {
    let file = FileId::new(1);
    let mut target = with_params(decl(file, 0, "method", Vec::new()), &["self", "value"]);
    target.qualified_name = Some("box.method".to_string());
    let caller = with_params(
        decl(
            file,
            1,
            "entry",
            vec![call_with_args(file, "box.method", &["box", "input"])],
        ),
        &["input"],
    );
    let mut global = GlobalIndex::new();
    insert_file(&mut global, file, vec![target, caller]);

    let graph = build_graph(&global, |_| Some("syntactic"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let method = FuncId::new(global.find_by_name("box.method")[0].raw());
    assert_eq!(
        graph.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![method],
        "a qualified function value maps its explicit arguments directly"
    );
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

#[test]
fn split_class_identity_survives_receiver_evidence_filtering() {
    let implementation_file = FileId::new(70);
    let caller_file = FileId::new(71);
    let implementation = with_module_path(
        decl_with(implementation_file, 1, "Base", DeclKind::Class, None, Vec::new()),
        &["workspace", "Base"],
    );
    let helper = with_module_path(
        decl_with(
            implementation_file,
            2,
            "helper",
            DeclKind::Method,
            Some(1),
            Vec::new(),
        ),
        &["workspace", "Base"],
    );

    let mut base_interface = with_module_path(
        decl_with(caller_file, 1, "Base", DeclKind::Class, None, Vec::new()),
        &["workspace", "Base"],
    );
    base_interface.body_span = None;
    let mut child_interface = with_module_path(
        decl_with(caller_file, 2, "Child", DeclKind::Class, None, Vec::new()),
        &["workspace", "Child"],
    );
    child_interface.bases = vec!["Base".to_string()];
    child_interface.body_span = None;
    let mut child_implementation = with_module_path(
        decl_with(caller_file, 3, "Child", DeclKind::Class, None, Vec::new()),
        &["workspace", "Child"],
    );
    child_implementation.bases = vec!["Base".to_string()];
    child_implementation.body_span = None;
    let entry = with_module_path(
        decl(
            caller_file,
            4,
            "entry",
            vec![method_call(caller_file, "obj.helper", "obj", &["Child", "Base"])],
        ),
        &["workspace", "Entry"],
    );

    let mut global = GlobalIndex::new();
    insert_file(&mut global, implementation_file, vec![implementation, helper]);
    insert_file(
        &mut global,
        caller_file,
        vec![base_interface, child_interface, child_implementation, entry],
    );
    global.finalize_semantic_facts();

    let graph = build_graph_with_capabilities(
        &global,
        |_| Some("objc"),
        |_| LanguageCapabilities::partial_baseline(),
    );
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let helper = FuncId::new(global.find_by_name("helper")[0].raw());
    assert!(
        graph.callees_of(entry).any(|edge| edge.to == helper),
        "a split class implementation must retain the method reached through its interface identity"
    );
}

#[test]
fn streamed_file_bodies_match_fully_resident_callgraph() {
    let target_file = FileId::new(90);
    let caller_file = FileId::new(91);
    let target_index = DeclIndex {
        file: target_file,
        defs: vec![decl(target_file, 0, "target", Vec::new())],
        ..DeclIndex::default()
    };
    let caller_index = DeclIndex {
        file: caller_file,
        defs: vec![decl(caller_file, 0, "caller", vec![call(caller_file, "target")])],
        ..DeclIndex::default()
    };

    let mut resident = GlobalIndex::new();
    resident.insert_preprocessed(target_index.clone());
    resident.insert_preprocessed(caller_index.clone());
    resident.finalize_semantic_facts();
    let expected = build_graph(&resident, |_| Some("test"));

    let mut headers = GlobalIndex::new();
    headers.insert_header_preprocessed(target_index.clone());
    headers.insert_header_preprocessed(caller_index.clone());
    headers.finalize_semantic_facts();
    let bodies = AHashMap::from([(target_file, target_index), (caller_file, caller_index)]);
    let actual = ResolvedCallGraph::build_with_file_semantics_streaming(
        &headers,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |_| AHashMap::new(),
            |_| None,
            |_| Some("test"),
            |_| LanguageCapabilities::unsupported(),
        ),
        |file| {
            bodies
                .get(&file)
                .cloned()
                .map(|index| headers.remap_file_to_existing_symbols(index))
        },
    );

    assert_eq!(
        bonsai_common::wire::encode(&actual).expect("encode streamed callgraph"),
        bonsai_common::wire::encode(&expected).expect("encode resident callgraph")
    );
}

#[test]
fn streamed_factory_return_types_preserve_receiver_dispatch() {
    let file = FileId::new(92);
    let mut repository = decl_with(file, 0, "Repository", DeclKind::Class, None, Vec::new());
    repository.body_span = Some(Span::new(file, 0, 200));
    let mut audited = decl_with(file, 1, "AuditedRepository", DeclKind::Class, None, Vec::new());
    audited.body_span = Some(Span::new(file, 200, 400));
    audited.bases = vec!["Repository".to_string()];

    let returned_call = Span::new(file, 440, 443);
    let returned_expression = Span::new(file, 440, 449);
    let mut wrap = decl_with(
        file,
        2,
        "wrap",
        DeclKind::Method,
        Some(0),
        vec![
            FlowEvent::Call {
                span: returned_call,
                name: "new".to_string(),
                receiver: None,
                receiver_types: vec!["Repository".to_string()],
                call_kind: CallKind::Constructor,
                args: Vec::new(),
            },
            FlowEvent::Return {
                span: returned_expression,
                value_text: Some("new()".to_string()),
                value_name: None,
                value_kind: Some(AssignValueKind::CallResult),
                value_flow: bonsai_lang_api::ExpressionFlow {
                    call_sites: vec![returned_expression],
                    ..Default::default()
                },
            },
        ],
    );
    wrap.body_span = Some(Span::new(file, 420, 460));

    let base_run = decl_with(file, 3, "run", DeclKind::Method, Some(0), Vec::new());
    let child_run = decl_with(file, 4, "run", DeclKind::Method, Some(1), Vec::new());
    let assign_span = Span::new(file, 500, 540);
    let mut persist = decl(
        file,
        5,
        "persist",
        vec![
            FlowEvent::Assign {
                span: assign_span,
                target: "repo".to_string(),
                source_name: None,
                source_call: Some("AuditedRepository.wrap".to_string()),
                source_call_args: Vec::new(),
                source_names: vec!["AuditedRepository".to_string(), "wrap".to_string()],
                declares_new_binding: false,
                value_kind: Some(AssignValueKind::CallResult),
            },
            FlowEvent::Call {
                span: Span::new(file, 510, 532),
                name: "AuditedRepository.wrap".to_string(),
                receiver: Some("AuditedRepository".to_string()),
                receiver_types: vec!["AuditedRepository".to_string(), "Repository".to_string()],
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
            FlowEvent::Call {
                span: Span::new(file, 550, 558),
                name: "repo.run".to_string(),
                receiver: Some("repo".to_string()),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
        ],
    );
    persist.body_span = Some(Span::new(file, 480, 580));
    let index = DeclIndex {
        file,
        defs: vec![repository, audited, wrap, base_run, child_run, persist],
        ..DeclIndex::default()
    };

    let mut headers = GlobalIndex::new();
    headers.insert_linkage_header_preprocessed(index.clone());
    headers.finalize_semantic_facts();
    let graph = ResolvedCallGraph::build_with_file_semantics_streaming(
        &headers,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |_| AHashMap::new(),
            |_| None,
            |_| Some("test"),
            |_| LanguageCapabilities::unsupported(),
        ),
        |requested| (requested == file).then(|| headers.remap_file_to_existing_symbols(index.clone())),
    );

    let persist = FuncId::new(headers.find_by_name("persist")[0].raw());
    let base_run = func_id_by_name_and_parent(&headers, "run", "Repository");
    let child_run = func_id_by_name_and_parent(&headers, "run", "AuditedRepository");
    let targets = graph.callees_of(persist).map(|edge| edge.to).collect::<Vec<_>>();
    assert!(
        targets.contains(&base_run),
        "factory result must type repo.run: {targets:?}"
    );
    assert!(
        !targets.contains(&child_run),
        "compact return typing must not fan out across an ambiguous method name: {targets:?}"
    );
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

    assert_eq!(edge.provenance.resolver_stage(), "exact_symbol");
    assert!(edge.provenance.evidence().contains("unique callable"));
    assert!(edge.provenance.confidence() >= 90);
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

    assert_eq!(edge.provenance.resolver_stage(), "receiver_type");
    assert!(edge.provenance.evidence().contains("receiver"));
    assert!(edge.provenance.confidence() >= 80);
}

#[test]
fn resolved_graph_persists_names_for_exact_edge_endpoints() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(file, 0, "entry", vec![call(file, "target")]),
            decl(file, 1, "target", Vec::new()),
        ],
    );

    let graph = build_graph(&global, |_| Some("fixture"));
    let entry = FuncId::new(global.find_by_name("entry")[0].raw());
    let target = FuncId::new(global.find_by_name("target")[0].raw());
    assert_eq!(graph.node_name(entry), Some("entry"));
    assert_eq!(graph.node_name(target), Some("target"));

    let encoded = bonsai_common::wire::encode(&graph).expect("encode resolved graph");
    let decoded: ResolvedCallGraph = bonsai_common::wire::decode(&encoded).expect("decode resolved graph");
    assert_eq!(decoded.node_name(entry), Some("entry"));
    assert_eq!(decoded.node_name(target), Some("target"));
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
fn resolved_graph_between_keeps_all_target_paths_and_drops_sibling_branches() {
    let file = FileId::new(1);
    let source = FuncId::new(1);
    let left = FuncId::new(2);
    let right = FuncId::new(3);
    let target = FuncId::new(4);
    let decoy = FuncId::new(5);
    let mut graph = CallGraph::new();
    for (from, to, offset) in [
        (source, left, 10),
        (left, target, 20),
        (source, right, 30),
        (right, target, 40),
        (source, decoy, 50),
    ] {
        graph.add_edge(CallEdge {
            from,
            to,
            span: Span::new(file, offset, offset + 1),
            kind: EdgeKind::Direct,
            precision: Precision::Exact,
            provenance: EdgeProvenance::direct_symbol(),
        });
    }

    let corridor = ResolvedCallGraph::from_call_graph(graph).between(&[source], &[target], None);
    let edges = corridor
        .inner()
        .edges
        .iter()
        .map(|edge| (edge.from, edge.to))
        .collect::<AHashSet<_>>();
    assert_eq!(edges.len(), 4);
    assert!(edges.contains(&(source, left)));
    assert!(edges.contains(&(left, target)));
    assert!(edges.contains(&(source, right)));
    assert!(edges.contains(&(right, target)));
    assert!(!edges.iter().any(|(from, to)| *from == decoy || *to == decoy));
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
fn resolved_path_enumeration_prunes_branches_that_cannot_reach_target() {
    let file = FileId::new(1);
    let entry = FuncId::new(1);
    let sink = FuncId::new(10_000);
    let mut graph = CallGraph::new();
    for raw in 2..1_000 {
        graph.add_edge(CallEdge {
            from: entry,
            to: FuncId::new(raw),
            span: Span::new(file, u64::from(raw), u64::from(raw) + 1),
            kind: EdgeKind::Direct,
            precision: Precision::Exact,
            provenance: EdgeProvenance::direct_symbol(),
        });
    }
    graph.add_edge(CallEdge {
        from: entry,
        to: sink,
        span: Span::new(file, 20_000, 20_001),
        kind: EdgeKind::Direct,
        precision: Precision::Exact,
        provenance: EdgeProvenance::direct_symbol(),
    });

    let resolved = ResolvedCallGraph::from_call_graph(graph);
    let (paths, truncation) = enumerate_paths_resolved(&resolved, entry, sink, 1, 0, 2);

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].funcs, vec![entry, sink]);
    assert_eq!(truncation, PathTruncation::None);
}

#[test]
fn resolved_path_zero_depth_and_probe_limits_mean_uncapped() {
    let file = FileId::new(1);
    let funcs: Vec<FuncId> = (1..=32).map(FuncId::new).collect();
    let mut graph = CallGraph::new();
    for pair in funcs.windows(2) {
        graph.add_edge(CallEdge {
            from: pair[0],
            to: pair[1],
            span: Span::new(file, u64::from(pair[0].raw()), u64::from(pair[0].raw()) + 1),
            kind: EdgeKind::Direct,
            precision: Precision::Exact,
            provenance: EdgeProvenance::direct_symbol(),
        });
    }

    let resolved = ResolvedCallGraph::from_call_graph(graph);
    let (paths, truncation) =
        enumerate_paths_resolved(&resolved, funcs[0], *funcs.last().expect("sink"), 1, 0, 0);

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].funcs, funcs);
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
        vec![with_module_path(
            decl(
                caller_file,
                0,
                "entry",
                vec![call_with_args(caller_file, "printResults", &["a", "b", "c"])],
            ),
            &["app"],
        )],
    );
    insert_file(
        &mut global,
        helper_file,
        vec![
            with_module_path(
                with_params_and_types(
                    decl(helper_file, 1, "printResults", Vec::new()),
                    &[("a", "A"), ("b", "B"), ("c", "C")],
                ),
                &["app"],
            ),
            with_module_path(
                with_params_and_types(
                    decl(helper_file, 2, "printResults", Vec::new()),
                    &[("a", "A"), ("b", "B"), ("c", "D")],
                ),
                &["app"],
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
    let unresolved = vec![(
        entry,
        Span::new(
            caller_file,
            0,
            u64::try_from("printResults".len()).expect("name length"),
        ),
    )];
    assert_eq!(
        cg.unresolved_workspace_call_sites().collect::<Vec<_>>(),
        unresolved,
        "workspace candidates without enough compiler evidence must be reported exactly"
    );

    let encoded = bonsai_common::wire::encode(&cg).expect("encode graph with resolver gap");
    let decoded: ResolvedCallGraph =
        bonsai_common::wire::decode(&encoded).expect("decode graph with resolver gap");
    assert_eq!(
        decoded.unresolved_workspace_call_sites().collect::<Vec<_>>(),
        vec![(
            entry,
            Span::new(
                caller_file,
                0,
                u64::try_from("printResults".len()).expect("name length"),
            ),
        )]
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
    assert!(
        cg.unresolved_workspace_call_sites().next().is_none(),
        "an untyped dynamic receiver is not workspace evidence merely because an unrelated method shares its tail"
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
fn instance_field_chain_is_not_reinterpreted_as_a_module_qualified_call() {
    let caller_file = FileId::new(1);
    let context_file = FileId::new(2);
    let mut global = GlobalIndex::new();
    let mut caller = with_module_path(
        decl(
            caller_file,
            0,
            "stashContextPreservingRequestHeaders",
            vec![method_call(
                caller_file,
                "context.transientHeaders.get",
                "context.transientHeaders",
                &[],
            )],
        ),
        &["org", "elasticsearch", "common", "util", "concurrent"],
    );
    caller.type_aliases = vec![
        bonsai_lang_api::TypeAliasBinding {
            name: "context".to_string(),
            type_name: "ThreadContextStruct".to_string(),
        },
        bonsai_lang_api::TypeAliasBinding {
            name: "transientHeaders".to_string(),
            type_name: "Map".to_string(),
        },
    ];
    let class = with_module_path(
        decl_with(
            context_file,
            0,
            "ContextMappings",
            DeclKind::Class,
            None,
            Vec::new(),
        ),
        &[
            "org",
            "elasticsearch",
            "search",
            "suggest",
            "completion",
            "context",
        ],
    );
    let method = with_module_path(
        decl_with(context_file, 1, "get", DeclKind::Method, Some(0), Vec::new()),
        &[
            "org",
            "elasticsearch",
            "search",
            "suggest",
            "completion",
            "context",
        ],
    );
    insert_file(&mut global, caller_file, vec![caller]);
    insert_file(&mut global, context_file, vec![class, method]);

    let context_method = global
        .decls_in(context_file)
        .iter()
        .find(|decl| decl.name == "get")
        .expect("ContextMappings.get");
    assert!(
        !receiver_matches_decl_module(
            "context.transientHeaders",
            context_method,
            context_file,
            &|file| (file == context_file).then(|| {
                "/repo/org/elasticsearch/search/suggest/completion/context/ContextMappings.java".to_string()
            }),
            bonsai_lang_api::ModulePathSyntax::none(),
        ),
        "an AST field chain cannot use the import-only terminal-trailer match"
    );

    let graph = build_graph(&global, |_| Some("java"));
    let caller = FuncId::new(global.find_by_name("stashContextPreservingRequestHeaders")[0].raw());

    assert_eq!(
        graph.callees_of(caller).count(),
        0,
        "a field-chain receiver needs type/import evidence; package suffix coincidence is not resolution"
    );
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
fn qualified_receiver_type_does_not_dispatch_to_same_named_local_type() {
    let caller_file = FileId::new(1);
    let scheduler_file = FileId::new(2);
    let mut global = GlobalIndex::new();

    let mut local_handle = with_module_path(
        decl_with(caller_file, 2, "Handle", DeclKind::Struct, None, Vec::new()),
        &["tokio", "runtime", "handle"],
    );
    local_handle.qualified_name = Some("tokio.runtime.handle.Handle".to_string());
    let mut local_spawn = with_module_path(
        with_params(
            decl_with(caller_file, 0, "spawn", DeclKind::Method, Some(2), Vec::new()),
            &["self"],
        ),
        &["tokio", "runtime", "handle"],
    );
    local_spawn.receiver_param_index = Some(0);
    local_spawn.qualified_name = Some("tokio.runtime.handle.spawn".to_string());
    let mut entry = with_module_path(
        with_params(
            decl_with(
                caller_file,
                1,
                "spawn_named",
                DeclKind::Method,
                Some(2),
                vec![method_call(
                    caller_file,
                    "self.inner.spawn",
                    "self.inner",
                    &["scheduler.Handle"],
                )],
            ),
            &["self"],
        ),
        &["tokio", "runtime", "handle"],
    );
    entry.receiver_param_index = Some(0);
    entry.type_aliases = vec![bonsai_lang_api::TypeAliasBinding {
        name: "self.inner".to_string(),
        type_name: "scheduler.Handle".to_string(),
    }];
    insert_file(&mut global, caller_file, vec![local_spawn, entry, local_handle]);

    let mut scheduler_handle = with_module_path(
        decl_with(scheduler_file, 1, "Handle", DeclKind::Enum, None, Vec::new()),
        &["tokio", "runtime", "scheduler"],
    );
    scheduler_handle.qualified_name = Some("tokio.runtime.scheduler.Handle".to_string());
    let mut scheduler_spawn = with_module_path(
        with_params(
            decl_with(scheduler_file, 0, "spawn", DeclKind::Method, Some(1), Vec::new()),
            &["self"],
        ),
        &["tokio", "runtime", "scheduler"],
    );
    scheduler_spawn.receiver_param_index = Some(0);
    scheduler_spawn.qualified_name = Some("tokio.runtime.scheduler.spawn".to_string());
    insert_file(
        &mut global,
        scheduler_file,
        vec![scheduler_spawn, scheduler_handle],
    );

    let caller_body = global.file_index(caller_file).expect("caller body").clone();
    let scheduler_body = global.file_index(scheduler_file).expect("scheduler body").clone();
    let mut headers = GlobalIndex::new();
    headers.insert_header_preprocessed(caller_body.clone());
    headers.insert_header_preprocessed(scheduler_body.clone());
    headers.finalize_semantic_facts();
    let remapped_caller_body = headers.remap_file_to_existing_symbols(caller_body.clone());
    let remapped_entry = remapped_caller_body
        .defs
        .iter()
        .find(|decl| decl.name == "spawn_named")
        .expect("remapped spawn_named");
    let FlowEvent::Call {
        name,
        receiver,
        receiver_types,
        call_kind,
        span,
        ..
    } = remapped_entry.flow_events.first().expect("spawn call")
    else {
        panic!("expected spawn call")
    };
    let alias_targets = AHashMap::from_iter([(
        "scheduler".to_string(),
        AliasTarget::Member {
            module: "crate::runtime".to_string(),
            member: "scheduler".to_string(),
        },
    )]);
    let mut method_cache =
        MethodCandidateCache::with_peer_class_index(build_shared_peer_class_index(&headers));
    let direct_targets = collect_receiver_method_targets(
        &headers,
        remapped_entry,
        &alias_targets,
        &|_| None,
        receiver.as_deref(),
        receiver_types,
        *call_kind,
        name,
        *span,
        &[],
        bonsai_lang_api::ModulePathSyntax {
            rooted_prefixes: &["crate::", "self::"],
            repeatable_rooted_prefixes: &["super::"],
        },
        &mut method_cache,
    );
    let graph = ResolvedCallGraph::build_with_file_semantics_streaming(
        &headers,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |file| {
                if file == caller_file {
                    AHashMap::from_iter([(
                        "scheduler".to_string(),
                        AliasTarget::Member {
                            module: "crate::runtime".to_string(),
                            member: "scheduler".to_string(),
                        },
                    )])
                } else {
                    AHashMap::new()
                }
            },
            |_| None,
            |_| Some("rust"),
            |_| LanguageCapabilities {
                module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                    rooted_prefixes: &["crate::", "self::"],
                    repeatable_rooted_prefixes: &["super::"],
                },
                ..LanguageCapabilities::unsupported()
            },
        ),
        |file| match file {
            file if file == caller_file => Some(headers.remap_file_to_existing_symbols(caller_body.clone())),
            file if file == scheduler_file => {
                Some(headers.remap_file_to_existing_symbols(scheduler_body.clone()))
            }
            _ => None,
        },
    );
    let entry = FuncId::new(headers.find_by_name("spawn_named")[0].raw());
    let local_spawn = headers
        .find_by_name("spawn")
        .iter()
        .copied()
        .find(|symbol| headers.declaring_file(*symbol) == Some(caller_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("local Handle::spawn");
    let scheduler_spawn = headers
        .find_by_name("spawn")
        .iter()
        .copied()
        .find(|symbol| headers.declaring_file(*symbol) == Some(scheduler_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("scheduler Handle::spawn");
    let targets = graph.callees_of(entry).map(|edge| edge.to).collect::<Vec<_>>();

    assert_eq!(direct_targets, vec![scheduler_spawn]);
    assert_eq!(targets, vec![scheduler_spawn]);
    assert!(!targets.contains(&local_spawn));
}

#[test]
fn qualified_associated_call_accepts_ast_declared_constructor_target() {
    let caller_file = FileId::new(10);
    let type_file = FileId::new(11);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                0,
                "spawn",
                vec![FlowEvent::Call {
                    span: Span::new(caller_file, 10, 20),
                    name: "SpawnMeta::new_unnamed".to_string(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args: call_args(caller_file, &["size"]),
                }],
            ),
            &["tokio", "runtime"],
        )],
    );
    let mut spawn_meta = with_module_path(
        decl_with(type_file, 0, "SpawnMeta", DeclKind::Struct, None, Vec::new()),
        &["tokio", "util", "trace"],
    );
    spawn_meta.qualified_name = Some("tokio.util.trace.SpawnMeta".to_string());
    let mut constructor = with_params(
        with_module_path(
            decl_with(
                type_file,
                1,
                "new_unnamed",
                DeclKind::Constructor,
                Some(0),
                Vec::new(),
            ),
            &["tokio", "util", "trace"],
        ),
        &["original_size"],
    );
    constructor.qualified_name = Some("tokio.util.trace.new_unnamed".to_string());
    insert_file(&mut global, type_file, vec![spawn_meta, constructor]);

    let graph = ResolvedCallGraph::build_with_file_semantics(
        &global,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |file| {
                if file == caller_file {
                    AHashMap::from_iter([(
                        "SpawnMeta".to_string(),
                        AliasTarget::Namespace {
                            module: "crate::util::trace::SpawnMeta".to_string(),
                        },
                    )])
                } else {
                    AHashMap::new()
                }
            },
            |_| None,
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
    let caller = FuncId::new(global.find_by_name("spawn")[0].raw());
    let constructor = FuncId::new(global.find_by_name("new_unnamed")[0].raw());

    assert_eq!(
        graph.callees_of(caller).map(|edge| edge.to).collect::<Vec<_>>(),
        [constructor]
    );
}

#[test]
fn rooted_associated_function_call_resolves_method_declaration_without_receiver() {
    let caller_file = FileId::new(14);
    let type_file = FileId::new(15);
    let export_file = FileId::new(16);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                0,
                "spawn_named",
                vec![FlowEvent::Call {
                    span: Span::new(caller_file, 10, 20),
                    name: "crate::runtime::task::Id::next".to_string(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args: Vec::new(),
                }],
            ),
            &["tokio", "runtime", "handle"],
        )],
    );
    let mut id = with_module_path(
        decl_with(type_file, 0, "Id", DeclKind::Struct, None, Vec::new()),
        &["tokio", "runtime", "task", "id"],
    );
    id.qualified_name = Some("tokio.runtime.task.id.Id".to_string());
    let mut next = with_module_path(
        decl_with(type_file, 1, "next", DeclKind::Method, Some(0), Vec::new()),
        &["tokio", "runtime", "task", "id"],
    );
    next.qualified_name = Some("tokio.runtime.task.id.next".to_string());
    insert_file(&mut global, type_file, vec![id, next]);
    let mut exported_id = with_module_path(
        decl_with(export_file, 0, "Id", DeclKind::Import, None, Vec::new()),
        &["tokio", "runtime", "task"],
    );
    exported_id.qualified_name = Some("tokio.runtime.task.Id".to_string());
    exported_id.visibility = bonsai_lang_api::Visibility::Crate;
    exported_id.bases = vec!["id::Id".to_string()];
    insert_file(&mut global, export_file, vec![exported_id]);

    let caller_decl = global
        .file_index(caller_file)
        .and_then(|index| index.defs.iter().find(|decl| decl.name == "spawn_named"))
        .expect("caller decl");
    let module_syntax = bonsai_lang_api::ModulePathSyntax {
        rooted_prefixes: &["crate::", "self::"],
        repeatable_rooted_prefixes: &["super::"],
    };
    let resolve_context = bonsai_resolve::ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_module_path_syntax(module_syntax);
    let exported_classes =
        bonsai_resolve::resolve_class(&global, "crate::runtime::task::Id", &resolve_context);
    let exported_id = global
        .find_by_name("Id")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(export_file))
        .expect("export facade symbol");
    assert_eq!(exported_classes, [exported_id]);

    let mut method_cache = MethodCandidateCache::default();
    let direct_targets = collect_type_qualified_method_targets(
        &global,
        caller_decl,
        &AHashMap::new(),
        &|_| None,
        "crate::runtime::task::Id::next",
        module_syntax,
        &mut method_cache,
    );
    let next_target = FuncId::new(global.find_by_name("next")[0].raw());
    assert_eq!(direct_targets, [next_target]);

    let graph = build_graph_with_capabilities(
        &global,
        |_| Some("rust"),
        |_| LanguageCapabilities {
            module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                rooted_prefixes: &["crate::", "self::"],
                repeatable_rooted_prefixes: &["super::"],
            },
            ..LanguageCapabilities::unsupported()
        },
    );
    let caller = FuncId::new(global.find_by_name("spawn_named")[0].raw());
    let next = next_target;

    assert_eq!(
        graph.callees_of(caller).map(|edge| edge.to).collect::<Vec<_>>(),
        [next]
    );
}

#[test]
fn rust_conditional_same_signature_declarations_form_one_semantic_family() {
    let caller_file = FileId::new(12);
    let target_file = FileId::new(13);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                0,
                "spawn_named",
                vec![call_with_args(
                    caller_file,
                    "crate::util::trace::task",
                    &["future", "kind", "meta", "id"],
                )],
            ),
            &["tokio", "runtime"],
        )],
    );
    let conditional = |symbol, params: &[&str]| {
        let mut decl = with_params(
            with_module_path(
                decl(target_file, symbol, "task", Vec::new()),
                &["tokio", "util", "trace"],
            ),
            params,
        );
        decl.qualified_name = Some("tokio.util.trace.task".to_string());
        decl
    };
    insert_file(
        &mut global,
        target_file,
        vec![
            conditional(0, &["task", "kind", "meta", "id"]),
            conditional(1, &["task", "_kind", "_meta", "_id"]),
        ],
    );

    let graph = build_graph_with_capabilities(
        &global,
        |_| Some("rust"),
        |_| LanguageCapabilities {
            module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                rooted_prefixes: &["crate::", "self::"],
                repeatable_rooted_prefixes: &["super::"],
            },
            callable_declaration_family: CallableDeclarationFamily::SameSignature,
            ..LanguageCapabilities::unsupported()
        },
    );
    let caller = FuncId::new(global.find_by_name("spawn_named")[0].raw());
    let edges = graph.callees_of(caller).collect::<Vec<_>>();

    assert_eq!(edges.len(), 2);
    assert!(edges.iter().all(|edge| edge.kind == EdgeKind::Virtual));
    assert!(edges.iter().all(|edge| edge.precision == Precision::Narrowed));
}

#[test]
fn receiverless_qualified_external_call_never_falls_back_to_bare_tail() {
    let caller_file = FileId::new(17);
    let unrelated_file = FileId::new(18);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                0,
                "spawn",
                vec![FlowEvent::Call {
                    span: Span::new(caller_file, 10, 20),
                    name: "external::Box::pin".to_string(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args: call_args(caller_file, &["future"]),
                }],
            ),
            &["tokio", "runtime"],
        )],
    );
    insert_file(
        &mut global,
        unrelated_file,
        vec![with_module_path(
            with_params(decl(unrelated_file, 0, "pin", Vec::new()), &["future"]),
            &["tokio", "unrelated"],
        )],
    );

    let graph = build_graph_with_capabilities(
        &global,
        |_| Some("rust"),
        |_| LanguageCapabilities {
            module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                rooted_prefixes: &["crate::", "self::"],
                repeatable_rooted_prefixes: &["super::"],
            },
            ..LanguageCapabilities::unsupported()
        },
    );
    let caller = FuncId::new(global.find_by_name("spawn")[0].raw());

    assert_eq!(graph.callees_of(caller).count(), 0);
    assert_eq!(graph.unresolved_workspace_call_sites().count(), 0);
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
        bonsai_lang_api::LanguageCapabilities {
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            ..bonsai_lang_api::LanguageCapabilities::partial_baseline()
        },
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
    assert_eq!(edge.provenance.resolver_stage(), "callable_value");
    assert!(edge.provenance.evidence().contains("projected callable binding"));
    assert!(edge.provenance.confidence() >= 80);
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
    assert_eq!(edge.provenance.resolver_stage(), "callable_value");
    assert!(edge.provenance.evidence().contains("projected callable binding"));
    assert!(edge.provenance.confidence() >= 80);
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
fn compound_argument_is_not_resolved_as_a_same_named_callback() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    insert_file(
        &mut global,
        file,
        vec![
            decl(
                file,
                0,
                "add_api_route",
                vec![FlowEvent::Call {
                    span: Span::new(file, 20, 80),
                    name: "route_class".to_string(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args: vec![CallArg {
                        passing_mode: Default::default(),
                        span: Span::new(file, 32, 50),
                        name: None,
                        value_text: "self.prefix + path".to_string(),
                        place: None,
                        source_names: vec!["self.prefix".to_string(), "path".to_string()],
                    }],
                }],
            ),
            decl(file, 1, "path", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("python"));
    let caller = FuncId::new(global.find_by_name("add_api_route")[0].raw());
    let unrelated_path = FuncId::new(global.find_by_name("path")[0].raw());
    assert!(
        cg.callees_of(caller).all(|edge| edge.to != unrelated_path),
        "AST-proven compound data must not be reinterpreted as a callable reference"
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
                        source_name: Some("helper".to_string()),
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: false,
                        value_kind: Some(AssignValueKind::CallableReference),
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
            value_kind: Some(AssignValueKind::CallableReference),
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
fn yield_result_binding_does_not_emit_a_second_call_edge() {
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
                    FlowEvent::Call {
                        span: Span::new(file, 100, 110),
                        name: "each_token".to_string(),
                        receiver: None,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        args: Vec::new(),
                    },
                    FlowEvent::Assign {
                        span: Span::new(file, 111, 130),
                        target: "token".to_string(),
                        source_name: None,
                        source_call: Some("each_token".to_string()),
                        source_call_args: Vec::new(),
                        source_names: Vec::new(),
                        declares_new_binding: true,
                        value_kind: Some(bonsai_lang_api::AssignValueKind::YieldResult),
                    },
                ],
            ),
            decl(file, 1, "each_token", Vec::new()),
        ],
    );

    let cg = build_graph(&global, |_| Some("ruby"));
    let top = FuncId::new(global.find_by_name("top")[0].raw());
    let edges = cg.callees_of(top).collect::<Vec<_>>();
    assert_eq!(edges.len(), 1, "yield binding fabricated a call edge: {edges:#?}");
    assert_eq!(edges[0].span, Span::new(file, 100, 110));
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
fn unresolved_external_constructor_does_not_fall_back_to_enclosing_class() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let class = decl_with(file, 1, "ThreadContext", DeclKind::Class, None, Vec::new());
    let constructor = decl_with(
        file,
        2,
        "ThreadContext",
        DeclKind::Constructor,
        Some(1),
        Vec::new(),
    );
    let caller = decl_with(
        file,
        3,
        "getRequestHeadersToCopy",
        DeclKind::Method,
        Some(1),
        vec![FlowEvent::Call {
            span: Span::new(file, 100, 120),
            name: "HashSet<>".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Constructor,
            args: Vec::new(),
        }],
    );
    insert_file(&mut global, file, vec![class, constructor, caller]);

    let caller_decl = global
        .find_by_name("getRequestHeadersToCopy")
        .first()
        .and_then(|symbol| global.decl_of(*symbol))
        .expect("caller declaration");
    let resolve_ctx = ResolveContext::new(file, &caller_decl.module_path);
    assert!(global.find_by_name("HashSet<>").is_empty());
    assert!(resolve_callable_with_context(&global, "HashSet<>", &resolve_ctx).is_empty());
    assert!(collect_constructor_targets_for_class_call(
        &ConstructorResolutionContext {
            global: &global,
            caller_decl,
            alias_targets: &AHashMap::new(),
            path_for_file: &|_| None,
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_index: None,
        },
        "HashSet<>",
        None,
        &[],
        false,
    )
    .is_empty());

    let graph = build_graph_with_capabilities(
        &global,
        |_| Some("java"),
        |_| LanguageCapabilities {
            constructor_method_names: NO_CONSTRUCTOR_METHOD_NAMES,
            ..LanguageCapabilities::partial_baseline()
        },
    );
    let caller = FuncId::new(global.find_by_name("getRequestHeadersToCopy")[0].raw());

    let edges = graph.callees_of(caller).collect::<Vec<_>>();
    assert!(
        edges.is_empty(),
        "an unresolved Java `new External(...)` is not construction of the lexical class: {edges:#?}"
    );
}

#[test]
fn adapter_declared_constructor_method_can_target_enclosing_class() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let class = decl_with(file, 1, "Repository", DeclKind::Class, None, Vec::new());
    let constructor = decl_with(file, 2, "initialize", DeclKind::Constructor, Some(1), Vec::new());
    let caller = decl_with(
        file,
        3,
        "factory",
        DeclKind::Method,
        Some(1),
        vec![FlowEvent::Call {
            span: Span::new(file, 100, 110),
            name: "new".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Constructor,
            args: Vec::new(),
        }],
    );
    insert_file(&mut global, file, vec![class, constructor, caller]);

    let graph = build_graph_with_capabilities(
        &global,
        |_| Some("ruby"),
        |_| LanguageCapabilities {
            constructor_method_names: &["initialize", "new"],
            ..LanguageCapabilities::partial_baseline()
        },
    );
    let caller = FuncId::new(global.find_by_name("factory")[0].raw());
    let constructor = func_id_by_name_and_parent(&global, "initialize", "Repository");

    assert_eq!(
        graph.callees_of(caller).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![constructor]
    );
}

#[test]
fn implicit_class_receiver_constructor_uses_lexical_class_and_inherited_initializer() {
    let file = FileId::new(1);
    let mut global = GlobalIndex::new();
    let base = decl_with(file, 1, "BaseRepository", DeclKind::Class, None, Vec::new());
    let mut repository = decl_with(file, 2, "Repository", DeclKind::Class, None, Vec::new());
    repository.bases = vec!["BaseRepository".to_string()];
    let constructor = decl_with(
        file,
        3,
        "__construct",
        DeclKind::Constructor,
        Some(base.symbol.raw()),
        Vec::new(),
    );
    let factory = decl_with(
        file,
        4,
        "wrap",
        DeclKind::Method,
        Some(repository.symbol.raw()),
        vec![FlowEvent::Call {
            span: Span::new(file, 100, 110),
            name: "static".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Constructor,
            args: Vec::new(),
        }],
    );
    insert_file(&mut global, file, vec![base, repository, constructor, factory]);

    let graph = build_graph_with_capabilities(
        &global,
        |_| Some("php"),
        |_| LanguageCapabilities {
            constructor_method_names: &["__construct"],
            implicit_receiver_tokens: &["$this", "self", "static"],
            ..LanguageCapabilities::partial_baseline()
        },
    );
    let factory = FuncId::new(global.find_by_name("wrap")[0].raw());
    let constructor = func_id_by_name_and_parent(&global, "__construct", "BaseRepository");

    assert_eq!(
        graph.callees_of(factory).map(|edge| edge.to).collect::<Vec<_>>(),
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
                name: "super".to_string(),
                receiver: Some("super".to_string()),
                receiver_types: Vec::new(),
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

fn streamed_receiver_field_initializer_targets_method(competing_function: bool) -> Vec<FuncId> {
    let dependency_file = FileId::new(1);
    let owner_file = FileId::new(2);
    let module = ModulePath::from_segments(["sample"]);

    let mut dependency_class = decl_with(dependency_file, 1, "lower", DeclKind::Class, None, Vec::new());
    dependency_class.module_path.clone_from(&module);
    let mut dependency_constructor = decl_with(
        dependency_file,
        2,
        "lower",
        DeclKind::Constructor,
        Some(1),
        Vec::new(),
    );
    dependency_constructor.module_path.clone_from(&module);
    let mut work = decl_with(dependency_file, 3, "work", DeclKind::Method, Some(1), Vec::new());
    work.module_path.clone_from(&module);
    let mut dependency_defs = vec![dependency_class, dependency_constructor, work];
    if competing_function {
        let mut function = decl(dependency_file, 4, "lower", Vec::new());
        function.module_path.clone_from(&module);
        dependency_defs.push(function);
    }

    let mut owner_class = decl_with(owner_file, 1, "Owner", DeclKind::Class, None, Vec::new());
    owner_class.module_path.clone_from(&module);
    let mut owner_constructor = decl_with(owner_file, 2, "Owner", DeclKind::Constructor, Some(1), Vec::new());
    owner_constructor.module_path.clone_from(&module);
    owner_constructor.implicit_receiver_names = vec!["this".to_string()];
    owner_constructor.receiver_field_initializers = vec![bonsai_lang_api::ReceiverFieldInitializer {
        span: Span::new(owner_file, 20, 35),
        target: "this.dependency".to_string(),
        call_name: "lower".to_string(),
        call_kind: CallKind::Function,
        call_receiver: None,
        call_receiver_types: Vec::new(),
    }];
    let mut run = decl_with(
        owner_file,
        3,
        "run",
        DeclKind::Method,
        Some(1),
        vec![method_call(owner_file, "dependency.work", "dependency", &[])],
    );
    run.module_path.clone_from(&module);
    run.implicit_receiver_names = vec!["this".to_string()];
    let owner_index = DeclIndex {
        file: owner_file,
        defs: vec![owner_class, owner_constructor, run],
        ..DeclIndex::default()
    };
    let dependency_index = DeclIndex {
        file: dependency_file,
        defs: dependency_defs,
        ..DeclIndex::default()
    };

    let mut headers = GlobalIndex::new();
    headers.insert_header_preprocessed(dependency_index.clone());
    headers.insert_header_preprocessed(owner_index.clone());
    headers.finalize_semantic_facts();
    let run = FuncId::new(headers.find_by_name("run")[0].raw());
    let graph = ResolvedCallGraph::build_with_file_semantics_streaming(
        &headers,
        CallGraphFileSemantics::new(
            |_| AHashMap::new(),
            |_| AHashMap::new(),
            |file| {
                Some(
                    if file == owner_file {
                        "Owner.swift"
                    } else {
                        "Dependency.swift"
                    }
                    .to_string(),
                )
            },
            |_| Some("fixture"),
            |_| LanguageCapabilities {
                bare_call_constructor_syntax: true,
                same_directory_unqualified_calls: true,
                implicit_receiver_tokens: &["this"],
                ..LanguageCapabilities::unsupported()
            },
        ),
        |file| {
            let index = if file == owner_file {
                owner_index.clone()
            } else {
                dependency_index.clone()
            };
            let mut remapped = headers.remap_file_to_existing_symbols(index);
            if file == owner_file {
                // Model sparse IDG demand: only the requested method body is
                // resident. Its constructor fact survives solely in headers.
                remapped.defs.retain(|decl| decl.name == "run");
            }
            Some(remapped)
        },
    );
    graph.callees_of(run).map(|edge| edge.to).collect()
}

#[test]
fn streamed_header_field_initializer_resolves_lowercase_cross_file_constructor() {
    let targets = streamed_receiver_field_initializer_targets_method(false);
    assert_eq!(
        targets.len(),
        1,
        "exact constructor header must type field dispatch: {targets:?}"
    );
}

#[test]
fn streamed_header_field_initializer_rejects_function_constructor_ambiguity() {
    let targets = streamed_receiver_field_initializer_targets_method(true);
    assert!(
        targets.is_empty(),
        "a same-named function makes constructor result typing ambiguous: {targets:?}"
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
                value_kind: Some(AssignValueKind::CallResult),
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
fn alias_qualified_module_call_does_not_consume_a_signature_argument() {
    let caller_file = FileId::new(1);
    let extract_file = FileId::new(2);
    let mut global = GlobalIndex::new();

    insert_file(
        &mut global,
        caller_file,
        vec![with_module_path(
            decl(
                caller_file,
                1,
                "upload",
                vec![FlowEvent::Call {
                    span: Span::new(caller_file, 100, 130),
                    name: "extract.UnpackTar".to_string(),
                    receiver: Some("extract".to_string()),
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Method,
                    args: call_args(caller_file, &["input", "\"/var/data/uploads\""]),
                }],
            ),
            &["controllers"],
        )],
    );
    insert_file(
        &mut global,
        extract_file,
        vec![with_module_path(
            with_params(decl(extract_file, 1, "UnpackTar", Vec::new()), &["src", "base"]),
            &["internal", "extract"],
        )],
    );
    let alias_targets = AHashMap::from_iter([(
        "extract".to_string(),
        AliasTarget::Namespace {
            module: "app/internal/extract".to_string(),
        },
    )]);

    let graph = ResolvedCallGraph::build_with_file_info(
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
            if file == extract_file {
                Some("internal/extract/tar.go".to_string())
            } else {
                Some("controllers/upload.go".to_string())
            }
        },
        |_| &[],
        |_| Some("go"),
    );
    let upload = FuncId::new(global.find_by_name("upload")[0].raw());
    let unpack = FuncId::new(global.find_by_name("UnpackTar")[0].raw());

    assert_eq!(
        graph.callees_of(upload).map(|edge| edge.to).collect::<Vec<_>>(),
        vec![unpack],
        "the imported namespace qualifies the callee but is not a runtime receiver argument"
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
