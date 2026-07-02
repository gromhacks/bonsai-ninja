use super::*;
use ahash::AHashMap;
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
fn graph_seed_skips_call_target_components_but_keeps_value_carriers() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "restored".to_string(),
        source_name: None,
        source_call: Some("pickle.loads".to_string()),
        source_call_args: vec!["decoded".to_string()],
        source_names: vec![
            "pickle".to_string(),
            "pickle.loads".to_string(),
            "loads".to_string(),
            "decoded".to_string(),
        ],
        declares_new_binding: false,
        value_kind: None,
    }];

    let mut seed = TokenSet::default();
    collect_assign_targets(&events, &mut seed, false);
    collect_graph_seed_tokens(&events, &mut seed);

    assert!(
        seed.contains("restored"),
        "assignment target remains a graph carrier"
    );
    assert!(seed.contains("decoded"), "argument/value carrier remains seeded");
    for call_component in ["pickle", "pickle.loads", "loads"] {
        assert!(
            !seed.contains(call_component),
            "call target component `{call_component}` must not become a taint source"
        );
    }
}

#[test]
fn graph_seed_skips_singular_call_target_source_name() {
    for source_name in ["pickle", "pickle.loads", "loads"] {
        let events = vec![FlowEvent::Assign {
            span: span(),
            target: "restored".to_string(),
            source_name: Some(source_name.to_string()),
            source_call: Some("pickle.loads".to_string()),
            source_call_args: vec!["decoded".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        }];

        let mut seed = TokenSet::default();
        collect_assign_targets(&events, &mut seed, false);
        collect_graph_seed_tokens(&events, &mut seed);

        assert!(seed.contains("restored"));
        assert!(seed.contains("decoded"));
        assert!(
            !seed.contains(source_name),
            "`source_name={source_name}` is a callable target component, not a value carrier"
        );
    }
}

#[test]
fn graph_seed_keeps_singular_non_call_source_name() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "decoded".to_string(),
        source_name: Some("session_data".to_string()),
        source_call: Some("base64.b64decode".to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];

    let mut seed = TokenSet::default();
    collect_assign_targets(&events, &mut seed, false);
    collect_graph_seed_tokens(&events, &mut seed);

    assert!(seed.contains("decoded"));
    assert!(
        seed.contains("session_data"),
        "non-call RHS names remain graph value carriers"
    );
    assert!(!seed.contains("base64"));
    assert!(!seed.contains("b64decode"));
}

#[test]
fn call_target_component_filter_handles_common_qualified_forms() {
    for (source, call) in [
        ("os", "os.path.join"),
        ("os.path", "os.path.join"),
        ("join", "os.path.join"),
        ("pkg", "pkg::run"),
        ("run", "pkg::run"),
        ("obj", "obj->method"),
        ("method", "obj->method"),
    ] {
        assert!(
            source_name_is_call_target_component(source, Some(call)),
            "`{source}` should be recognized as a component of `{call}`"
        );
    }
    assert!(
        !source_name_is_call_target_component("decoded", Some("pickle.loads")),
        "real argument/value carriers must not be filtered as call target components"
    );
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
    let value = segment.strings.intern("value");
    let ret_place = segment.intern_place(Place::CallRet {
        site: CallSiteId(anchor),
    });
    let source_write_place = segment.intern_place(Place::write(buf, anchor));
    let projected_read_place = segment.intern_place(Place::Read {
        name: buf,
        path: vec![value].into(),
    });
    let pre_write_place = segment.intern_place(Place::write(buf, pre_span));
    let post_write_place = segment.intern_place(Place::write(buf, post_span));
    segment.intern_node(func, ret_place);
    segment.intern_node(func, source_write_place);
    segment.intern_node(func, projected_read_place);
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
        nodes.iter().any(|node| {
            service
                .resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::Read && point.name == "buf.value")
        }),
        "an anchored output-arg source must seed projected carrier reads"
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
fn anchored_empty_source_seed_does_not_fallback_to_all_params() {
    let func = FuncId::new(8);
    let anchor = Span {
        file: FileId::new(0),
        start: 10,
        end: 20,
    };
    let mut segment = IdgSegment::new();
    let param_place = segment.intern_place(Place::Param { idx: 0 });
    segment.intern_node(func, param_place);
    segment.record_func(func);
    let service = service_from_segment(segment);
    let db = empty_db();

    let nodes = source_seed_nodes_from_idg(
        func,
        &TokenSet::default(),
        Some(anchor),
        &[],
        db.global_index().as_ref(),
        &service,
    );

    assert!(
        nodes.is_empty(),
        "a concrete anchored source with no resolved source node must not widen to every parameter"
    );
}

#[test]
fn anchored_call_return_seed_does_not_include_same_name_reads_or_writes() {
    let func = FuncId::new(9);
    let anchor = Span {
        file: FileId::new(0),
        start: 10,
        end: 20,
    };
    let later = Span {
        file: FileId::new(0),
        start: 40,
        end: 60,
    };
    let mut segment = IdgSegment::new();
    let source_name = segment.strings.intern("request.args.get");
    let call_ret = segment.intern_place(Place::CallRet {
        site: CallSiteId(anchor),
    });
    let same_name_read = segment.intern_place(Place::Read {
        name: source_name,
        path: Vec::new().into(),
    });
    let same_name_write = segment.intern_place(Place::write(source_name, later));
    segment.intern_node(func, call_ret);
    segment.intern_node(func, same_name_read);
    segment.intern_node(func, same_name_write);
    segment.record_func(func);
    let service = service_from_segment(segment);
    let db = empty_db();
    let seeds = TokenSet::from_iter(["request.args.get".to_string()]);

    let nodes = source_seed_nodes_from_idg(
        func,
        &seeds,
        Some(anchor),
        &[],
        db.global_index().as_ref(),
        &service,
    );
    let ret_ws = service.call_ret_node_at_site(func, anchor).expect("ret node");
    let same_name_nodes = service.read_or_write_nodes_for_names(func, &["request.args.get".to_string()]);

    assert!(nodes.contains(&ret_ws), "anchor CallRet remains a source seed");
    assert!(
        same_name_nodes.iter().all(|node| !nodes.contains(node)),
        "anchored call-return sources must not widen to same-named reads/writes elsewhere in the function"
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
            is_variadic: false,
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
        None,
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
        None,
    );

    assert!(
        regex_seed_nodes.contains(&ret_node),
        "regex callee passthrough from rulepack semantics must seed the matching call return"
    );
}

#[test]
fn rulepack_declared_arg_result_passthrough_accepts_descendant_container_input() {
    let func = FuncId::new(0);
    let call_span = Span {
        file: FileId::new(0),
        start: 10,
        end: 35,
    };
    let write_span = Span {
        file: FileId::new(0),
        start: 1,
        end: 5,
    };
    let mut segment = IdgSegment::new();
    let payload = segment.strings.intern("payload");
    let cmd = segment.strings.intern("cmd");
    let payload_cmd = segment.intern_place(Place::write_field(payload, cmd, write_span));
    let call_ret = segment.intern_place(Place::CallRet {
        site: CallSiteId(call_span),
    });
    let _payload_cmd_node = segment.intern_node(func, payload_cmd);
    let _ret_node = segment.intern_node(func, call_ret);
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
            name: "normalize".to_string(),
            qualified_name: Some("normalize".to_string()),
            module_path: bonsai_lang_api::ModulePath::default(),
            span,
            name_span: span,
            visibility: bonsai_lang_api::Visibility::Private,
            parent: None,
            body_span: Some(span),
            flow_events: vec![bonsai_lang_api::FlowEvent::Call {
                span: call_span,
                name: "reduce".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: vec![
                    bonsai_lang_api::CallArg {
                        span: call_span,
                        name: None,
                        value_text: "lambda a, b: f\"{a} {b}\"".to_string(),
                        place: None,
                        source_names: Vec::new(),
                    },
                    bonsai_lang_api::CallArg {
                        span: call_span,
                        name: None,
                        value_text: "[payload]".to_string(),
                        place: None,
                        source_names: vec!["payload".to_string()],
                    },
                    bonsai_lang_api::CallArg {
                        span: call_span,
                        name: None,
                        value_text: "\"\"".to_string(),
                        place: None,
                        source_names: Vec::new(),
                    },
                ],
            }],
            has_implicit_returns: false,
            params: vec!["payload".to_string()],
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        }],
    });

    let mut seed_nodes = service.read_or_write_nodes_for_names(func, &["payload.*".to_string()]);
    assert!(
        !seed_nodes.is_empty(),
        "test setup should expose the payload.cmd descendant seed"
    );
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
            callee: "reduce".to_string(),
            input_arg_indices: vec![1],
            input_receiver: false,
        }],
        &global,
        &service,
        Some(Precision::Narrowed),
        None,
    );

    assert!(
        seed_nodes.contains(&ret_node),
        "configured passthroughs must treat tainted descendants of selected container args as tainted inputs"
    );
}

#[test]
fn call_result_passthrough_matches_erlang_remote_separator() {
    assert!(
        call_result_passthrough_matches("string:to_upper", "string.to_upper"),
        "rulepack attribute callees and Erlang remote-call callees must normalize to the same qualified shape"
    );
}

#[test]
fn call_result_passthrough_regex_alternatives_do_not_prefilter_to_last_branch() {
    assert!(
        call_result_passthrough_matches(
            "NSString.stringWithFormat",
            r"regex:^(?:.*\.)?(stringWithFormat|localizedStringWithFormat|initWithFormat|stringByAppendingFormat)$",
        ),
        "regex passthrough prefilter must not reject earlier alternation branches"
    );
}

#[test]
fn configured_passthrough_nested_call_return_is_not_pruned_as_clean() {
    let db = empty_db();
    let global = db.global_index();
    let call_summary = CallEventSummary {
        name: ":os.cmd".to_string(),
        args_value_text: vec!["String.to_charlist(cmd)".to_string()],
        args_span: vec![span()],
        args_place: vec![None],
        receiver: None,
    };
    let passthroughs = vec![crate::inter::CallResultPassthrough {
        callee: "String.to_charlist".to_string(),
        input_arg_indices: vec![0],
        input_receiver: false,
    }];
    let compiled = compile_call_result_passthroughs(&passthroughs);
    let mut call_summary_cache = AHashMap::default();
    let mut function_summary_cache = AHashMap::default();
    let mut callee_name_cache = CalleeNameCache::default();

    assert!(
        !tainted_arg_is_clean_nested_call_return(
            FuncId::new(0),
            0,
            &call_summary,
            &[],
            &db,
            global.as_ref(),
            &mut call_summary_cache,
            &mut function_summary_cache,
            &compiled,
            &mut callee_name_cache,
        ),
        "configured passthrough calls preserve taint and must remain visible to sink arg constraints"
    );
}

#[test]
fn unmodeled_nested_call_return_is_pruned_as_clean() {
    let db = empty_db();
    let global = db.global_index();
    let call_summary = CallEventSummary {
        name: "sink".to_string(),
        args_value_text: vec!["clean_return(cmd)".to_string()],
        args_span: vec![span()],
        args_place: vec![None],
        receiver: None,
    };
    let mut call_summary_cache = AHashMap::default();
    let mut function_summary_cache = AHashMap::default();
    let mut callee_name_cache = CalleeNameCache::default();

    assert!(
        tainted_arg_is_clean_nested_call_return(
            FuncId::new(0),
            0,
            &call_summary,
            &[],
            &db,
            global.as_ref(),
            &mut call_summary_cache,
            &mut function_summary_cache,
            &[],
            &mut callee_name_cache,
        ),
        "unresolved and unmodeled nested call returns should still be treated as clean"
    );
}

// audit re-apply: RED before / GREEN after for M2. `collect_tainted_writes_req

#[test]
fn collect_tainted_writes_requires_identifier_token_match() {
    // Tainted local is the short name `id`. The Assign RHS textually
    // CONTAINS `id` as a substring of `uuid`, but never reads the bare
    // `id` token. The substring matcher fabricated a Write row here;
    // the token matcher must not.
    let mut tainted_names = AHashSet::default();
    tainted_names.insert("id".to_string());

    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "row".to_string(),
        source_name: Some("uuid".to_string()),
        source_call: None,
        source_call_args: vec!["sizeof(uuid)".to_string()],
        source_names: vec!["valid".to_string(), "hidden".to_string()],
        declares_new_binding: false,
        value_kind: None,
    }];

    let mut out: Vec<crate::inter::TaintedCall> = Vec::new();
    collect_tainted_writes(&events, FuncId::new(0), &tainted_names, None, &mut out);
    assert!(
        out.is_empty(),
        "substring of a tainted name (`id` in `uuid`/`valid`/`hidden`) must not fabricate a Write row; got {out:#?}"
    );
}

#[test]
fn collect_tainted_writes_keeps_whole_identifier_and_dotted_member() {
    // Positive guard so the M2 tightening does not drop real Write
    // rows (the pinned mega_flow `.cmd` pipeline relies on the bare
    // tainted token `cmd` matching inside the member access `data.cmd`).
    let mut tainted_names = AHashSet::default();
    tainted_names.insert("cmd".to_string());

    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "out".to_string(),
        source_name: Some("data.cmd".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];

    let mut out: Vec<crate::inter::TaintedCall> = Vec::new();
    collect_tainted_writes(&events, FuncId::new(0), &tainted_names, None, &mut out);
    assert_eq!(
        out.len(),
        1,
        "a whole tainted token inside a member access must still emit a Write row; got {out:#?}"
    );
    assert_eq!(out[0].kind, crate::inter::TaintedCallKind::Write);
    assert_eq!(out[0].name, "out");
    assert_eq!(out[0].tainted_args.len(), 1);
    assert_eq!(out[0].tainted_args[0].value_text, "data.cmd");
}
