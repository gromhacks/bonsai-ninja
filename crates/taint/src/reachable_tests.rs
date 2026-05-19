use super::*;
use bonsai_common::{FileId, Span};
use bonsai_idg::{segment::IdgSegment, CallSiteId, IdgEdge, IdgQueryService, IdgWorkspace, Place};
use bonsai_lang_api::LanguageRegistry;
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn span() -> Span {
    Span {
        file: FileId::new(0),
        start: 0,
        end: 1,
    }
}

fn empty_db() -> bonsai_db::AnalyzerDb {
    bonsai_db::AnalyzerDb::new(Arc::new(Vfs::new()), Arc::new(LanguageRegistry::new()))
}

fn service_from_segment(segment: IdgSegment) -> IdgQueryService {
    let mut workspace = IdgWorkspace::new();
    workspace.register_segment(segment);
    IdgQueryService::new(Arc::new(workspace), Arc::new(bonsai_index::GlobalIndex::new()))
}

#[test]
fn reachable_assignment_rhs_metadata_is_surfaced() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "cmd".to_string(),
        source_name: Some("legacy_input".to_string()),
        source_call: Some("pkg.transform".to_string()),
        source_call_args: vec!["user_input".to_string()],
        source_names: vec!["request.args".to_string(), "fallback".to_string()],
        declares_new_binding: false,
        value_kind: None,
    }];

    let mut kinded = KindedTokens::default();
    collect_flow_event_tokens_kinded(&events, &mut kinded);
    assert!(kinded.by_kind[&FactKind::Write].contains("cmd"));
    for expected in ["legacy_input", "request.args", "fallback"] {
        assert!(
            kinded.by_kind[&FactKind::Read].contains(expected),
            "missing read token {expected}"
        );
    }
    for expected in ["pkg.transform", "transform"] {
        assert!(
            kinded.by_kind[&FactKind::Call].contains(expected),
            "missing call token {expected}"
        );
    }
    assert!(kinded.by_kind[&FactKind::Arg].contains("user_input"));
}

#[test]
fn taint_entry_flow_facts_include_short_call_tail() {
    let events = vec![FlowEvent::Call {
        span: span(),
        name: "pkg.execute".to_string(),
        receiver: Some("pkg".to_string()),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: Vec::new(),
        receiver_types: Vec::new(),
    }];

    let mut facts = KindedTokens::default();
    collect_flow_facts(&events, &mut facts);
    assert!(facts.by_kind[&FactKind::Call].contains("pkg.execute"));
    assert!(facts.by_kind[&FactKind::Call].contains("execute"));
}

#[test]
fn default_source_return_idg_query_is_semantic_only() {
    let func = FuncId::new(7);
    let mut segment = IdgSegment::new();
    let param = segment.intern_place(Place::Param { idx: 0 });
    let ret = segment.intern_place(Place::Return);
    let param_node = segment.intern_node(func, param);
    let ret_node = segment.intern_node(func, ret);
    segment.add_edge(IdgEdge::new(
        param_node,
        ret_node,
        bonsai_idg::EdgeMeta {
            precision: Precision::OverApproximate,
            kind: bonsai_idg::IdgEdgeKind::IntraReturn,
            call_kind: bonsai_callgraph::EdgeKind::Indirect,
            via_span: span(),
        },
    ));
    segment.record_func(func);
    let service = service_from_segment(segment);
    let db = empty_db();

    assert!(
        source_seed_reaches_return_from_idg_with_max_precision(
            func,
            &TokenSet::default(),
            None,
            &[],
            &[],
            None,
            &db,
            &service,
        ),
        "explicit diagnostic precision scope can traverse the over-approximate edge"
    );
    assert!(
        !source_seed_reaches_return_from_idg(func, &TokenSet::default(), None, &[], &[], &db, &service,),
        "default public wrapper must not treat over-approximate IDG reachability as semantic"
    );
}

#[test]
fn default_entry_taint_graph_idg_query_is_semantic_only() {
    let caller = FuncId::new(7);
    let callee = FuncId::new(8);
    let call_span = Span {
        file: FileId::new(0),
        start: 10,
        end: 20,
    };
    let mut segment = IdgSegment::new();
    let caller_param = segment.intern_place(Place::Param { idx: 0 });
    let call_arg = segment.intern_place(Place::CallArg {
        site: CallSiteId(call_span),
        idx: 0,
    });
    let callee_param = segment.intern_place(Place::Param { idx: 0 });
    let caller_param_node = segment.intern_node(caller, caller_param);
    let call_arg_node = segment.intern_node(caller, call_arg);
    let callee_param_node = segment.intern_node(callee, callee_param);
    segment.add_edge(IdgEdge::intra_assign(caller_param_node, call_arg_node, call_span));
    segment.add_edge(IdgEdge::inter_call_arg(
        call_arg_node,
        callee_param_node,
        call_span,
        Precision::OverApproximate,
        bonsai_callgraph::EdgeKind::Indirect,
    ));
    segment.record_func(caller);
    segment.record_func(callee);
    let service = service_from_segment(segment);
    let db = empty_db();

    let diagnostic = entry_taint_graph_from_idg_with_max_precision(
        caller,
        &TokenSet::default(),
        None,
        &[],
        &[],
        &[],
        &[],
        None,
        &db,
        &service,
    );
    assert_eq!(
        diagnostic.call_records.len(),
        1,
        "explicit diagnostic precision scope can expose the over-approximate call edge"
    );

    let semantic = entry_taint_graph_from_idg(caller, &TokenSet::default(), None, &[], &[], &db, &service);
    assert!(
        semantic.call_records.is_empty(),
        "default public wrapper must not expose over-approximate call edges as taint evidence"
    );
    assert_eq!(semantic.precision, Precision::Exact);
}

#[test]
fn source_output_arg_names_keep_anchor_seed_precise() {
    let func = FuncId::new(7);
    let anchor = Span {
        file: FileId::new(0),
        start: 10,
        end: 20,
    };
    let pre_span = Span {
        file: FileId::new(0),
        start: 1,
        end: 5,
    };
    let post_span = Span {
        file: FileId::new(0),
        start: 30,
        end: 35,
    };
    let mut segment = IdgSegment::new();
    let buf = segment.strings.intern("buf");
    let ret_place = segment.intern_place(Place::CallRet {
        site: CallSiteId(anchor),
    });
    let source_write_place = segment.intern_place(Place::write(buf, anchor));
    let pre_write_place = segment.intern_place(Place::write(buf, pre_span));
    let post_write_place = segment.intern_place(Place::write(buf, post_span));
    segment.intern_node(func, ret_place);
    segment.intern_node(func, source_write_place);
    segment.intern_node(func, pre_write_place);
    segment.intern_node(func, post_write_place);
    segment.record_func(func);
    let service = service_from_segment(segment);
    let db = empty_db();

    let nodes = source_seed_nodes_from_idg(
        func,
        &TokenSet::default(),
        Some(anchor),
        &["buf".to_string()],
        db.global_index().as_ref(),
        &service,
    );
    let ret_ws = service.call_ret_node_at_site(func, anchor).expect("ret node");
    let source_output_ws = service
        .source_seed_nodes_at_span(func, anchor)
        .into_iter()
        .find(|node| {
            service
                .resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::Write && point.span == anchor)
        })
        .expect("source output write");
    let output_nodes = service.nodes_for_name_after_span(func, "buf", anchor);
    assert!(
        output_nodes.iter().any(|node| {
            service
                .resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::Write && point.span == post_span)
        }),
        "test setup should expose the post-source output write"
    );
    assert!(
        output_nodes.iter().all(|node| {
            service
                .resolve_point(*node)
                .is_none_or(|point| point.span != pre_span)
        }),
        "post-source output lookup should exclude pre-source clean writes"
    );

    assert!(nodes.contains(&ret_ws), "anchor CallRet remains a source seed");
    assert!(
        nodes.contains(&source_output_ws),
        "the source call's output write remains a source seed"
    );
    assert!(
        output_nodes.iter().all(|node| {
            !nodes.contains(node)
                || service
                    .resolve_point(*node)
                    .is_some_and(|point| point.span == anchor)
        }),
        "anchored output-arg sources must not directly seed later carrier writes"
    );
}

#[test]
fn rulepack_declared_receiver_result_passthrough_seeds_call_return() {
    let func = FuncId::new(0);
    let call_span = Span {
        file: FileId::new(0),
        start: 10,
        end: 35,
    };
    let mut segment = IdgSegment::new();
    let param = segment.intern_place(Place::Param { idx: 0 });
    let receiver_arg = segment.intern_place(Place::CallArg {
        site: CallSiteId(call_span),
        idx: u8::MAX,
    });
    let call_ret = segment.intern_place(Place::CallRet {
        site: CallSiteId(call_span),
    });
    let param_node = segment.intern_node(func, param);
    let receiver_arg_node = segment.intern_node(func, receiver_arg);
    let _ret_node = segment.intern_node(func, call_ret);
    segment.add_edge(IdgEdge::intra_assign(param_node, receiver_arg_node, call_span));
    segment.record_func(func);
    let service = service_from_segment(segment);

    let mut global = bonsai_index::GlobalIndex::new();
    let file = FileId::new(0);
    let span = Span::new(file, 0, 40);
    global.insert(bonsai_lang_api::DeclIndex {
        file,
        refs: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
        defs: vec![bonsai_lang_api::Decl {
            symbol: SymbolId::new(0),
            kind: bonsai_lang_api::DeclKind::Function,
            name: "decode".to_string(),
            qualified_name: Some("decode".to_string()),
            module_path: bonsai_lang_api::ModulePath::default(),
            span,
            name_span: span,
            visibility: bonsai_lang_api::Visibility::Private,
            parent: None,
            body_span: Some(span),
            flow_events: vec![bonsai_lang_api::FlowEvent::Call {
                span: call_span,
                name: "removingPercentEncoding".to_string(),
                receiver: Some("input".to_string()),
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Method,
                args: Vec::new(),
            }],
            has_implicit_returns: false,
            params: vec!["input".to_string()],
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
        }],
    });

    let mut seed_nodes = service.param_nodes_of(func);
    let ret_node = service
        .call_ret_node_at_site(func, call_span)
        .expect("call return node");
    assert!(
        !seed_nodes.contains(&ret_node),
        "return should not be seeded before rulepack passthrough semantics"
    );
    apply_call_result_passthrough_fixpoint(
        &mut seed_nodes,
        &[crate::inter::CallResultPassthrough {
            callee: "removingPercentEncoding".to_string(),
            input_arg_indices: Vec::new(),
            input_receiver: true,
        }],
        &global,
        &service,
        Some(Precision::Narrowed),
    );

    assert!(
        seed_nodes.contains(&ret_node),
        "receiver-result passthrough must seed the matching call return"
    );

    let mut regex_seed_nodes = service.param_nodes_of(func);
    apply_call_result_passthrough_fixpoint(
        &mut regex_seed_nodes,
        &[crate::inter::CallResultPassthrough {
            callee: r"regex:^[A-Za-z_$][A-Za-z0-9_$\.]*PercentEncoding$".to_string(),
            input_arg_indices: Vec::new(),
            input_receiver: true,
        }],
        &global,
        &service,
        Some(Precision::Narrowed),
    );

    assert!(
        regex_seed_nodes.contains(&ret_node),
        "regex callee passthrough from rulepack semantics must seed the matching call return"
    );
}

#[test]
fn call_result_passthrough_matches_erlang_remote_separator() {
    assert!(
        call_result_passthrough_matches("string:to_upper", "string.to_upper"),
        "rulepack attribute callees and Erlang remote-call callees must normalize to the same qualified shape"
    );
}
