use super::*;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("erlang grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set erlang grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse erlang source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn import_attribute_emits_local_member_bindings() {
    let imports = parse_import_specs("-import(util, [helper/1, other/2]).\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "util"
            && spec.alias.is_none()
            && spec.original_name.is_none()
            && !spec.is_wildcard
            && spec.scope == ImportScope::Module
    }));
    for imported in ["helper", "other"] {
        assert!(
            imports.iter().any(|spec| {
                spec.module == "util"
                    && spec.alias.is_none()
                    && spec.original_name.as_deref() == Some(imported)
                    && !spec.is_wildcard
                    && spec.scope == ImportScope::Local
            }),
            "missing resolver-local Erlang import for {imported}"
        );
    }
}

#[test]
fn fun_ref_assignment_emits_clean_callable_alias() {
    let src = "Cb = fun helper/1";
    let span = bonsai_common::Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());
    let event = FlowEvent::Assign {
        span,
        target: "Cb".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["helper".to_string()],
        declares_new_binding: true,
        value_kind: None,
    };
    let value_start = u64::try_from(src.find("fun").expect("RHS start")).unwrap();
    let facts = [bonsai_lang_api::AssignmentValueFact {
        assignment_span: span,
        target: Some("Cb".to_string()),
        target_span: Some(bonsai_common::Span::new(FileId::new(0), 0, 2)),
        value_span: bonsai_common::Span::new(FileId::new(0), value_start, span.end),
        call_sites: Vec::new(),
        value_flow: Default::default(),
        exact_callable_return: None,
        exact_static_call_args: None,
        direct_call_name: None,
        direct_call_receiver: None,
    }];
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&facts);

    let alias = erlang_fun_ref_alias_assignment(&event, src, &assignment_values).expect("fun ref alias");

    assert!(matches!(
        alias,
        FlowEvent::Assign {
            target,
            source_name: Some(source),
            source_call: None,
            source_names,
            ..
        } if target == "Cb" && source == "helper" && source_names.is_empty()
    ));
}

fn call_event(name: &str) -> FlowEvent {
    FlowEvent::Call {
        span: bonsai_common::Span::new(FileId::new(0), 0, 1),
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: Vec::new(),
    }
}

#[test]
fn exception_rewrite_preserves_logger_error_calls() {
    let mut events = vec![call_event("logger:error")];

    rewrite_erlang_throw_calls(&mut events);

    assert!(matches!(
        events.as_slice(),
        [FlowEvent::Call { name, .. }] if name == "logger:error"
    ));
}

#[test]
fn exception_rewrite_keeps_bare_and_erlang_exception_bifs() {
    for name in [
        "throw",
        "error",
        "exit",
        "erlang:throw",
        "erlang:error",
        "erlang.exit",
    ] {
        let mut events = vec![call_event(name)];

        rewrite_erlang_throw_calls(&mut events);

        assert!(
            matches!(events.as_slice(), [FlowEvent::Throw { .. }]),
            "expected {name} to rewrite to Throw, got {events:?}"
        );
    }
}

#[test]
fn zero_arity_clause_has_no_synthetic_param_slot() {
    let src = "load_all_users() -> ok.";
    let span = bonsai_common::Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());

    let params = erlang_clause_param_slots(src, span, "load_all_users").expect("params");

    assert!(params.is_empty());
}

#[test]
fn list_cons_param_pattern_emits_entry_bindings() {
    let src = "process_batch([Token | Rest]) -> run_user(Token).";
    let span = bonsai_common::Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());
    let mut decl = bonsai_lang_api::Decl {
        symbol: bonsai_common::SymbolId::new(0),
        kind: bonsai_lang_api::DeclKind::Function,
        name: "process_batch".to_string(),
        qualified_name: Some("process_batch".to_string()),
        module_path: bonsai_lang_api::ModulePath::default(),
        span,
        name_span: span,
        visibility: Visibility::Public,
        parent: None,
        body_span: Some(span),
        flow_events: Vec::new(),
        has_implicit_returns: false,
        params: vec!["_Arg0".to_string()],
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    };

    augment_erlang_param_pattern_bindings(&mut decl, src);

    let bindings = decl
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name: Some(source),
                ..
            } => Some((target.as_str(), source.as_str())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(bindings.contains(&("Token", "_Arg0")), "{bindings:?}");
    assert!(bindings.contains(&("Rest", "_Arg0")), "{bindings:?}");
}

#[test]
fn collection_transform_assignments_expose_collection_sources() {
    let span = bonsai_common::Span::new(FileId::new(0), 0, 1);
    let mut events = vec![
        FlowEvent::Assign {
            span,
            target: "Stripped".to_string(),
            source_name: None,
            source_call: Some("lists:map".to_string()),
            source_call_args: vec!["fun string:strip/1".to_string(), "RawTokens".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span,
            target: "Joined".to_string(),
            source_name: None,
            source_call: Some("lists:foldl".to_string()),
            source_call_args: vec![
                "fun(Tok, Acc) -> Acc ++ Tok end".to_string(),
                "\"\"".to_string(),
                "Tokens".to_string(),
            ],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
    ];

    normalize_erlang_access_events(&mut events, "", &AssignmentValueIndex::default());
    bonsai_lang_api::normalize_call_result_assignment_sources(&mut events);
    augment_erlang_collection_transform_flow_events(&mut events);

    assert!(matches!(
        &events[0],
        FlowEvent::Assign { source_names, .. } if source_names == &vec!["RawTokens".to_string()]
    ));
    assert!(matches!(
        &events[1],
        FlowEvent::Assign { source_names, .. } if source_names == &vec!["Tokens".to_string()]
    ));
}

#[test]
fn list_comprehension_assignment_exposes_generator_sources() {
    let src = r#"RawTokens = [Part || Part <- string:tokens(Cmd, " ")]"#;
    let span = bonsai_common::Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());
    let mut events = vec![FlowEvent::Assign {
        span,
        target: "RawTokens".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["Part".to_string()],
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];
    let value_start = u64::try_from(src.find('[').expect("RHS start")).unwrap();
    let facts = [bonsai_lang_api::AssignmentValueFact {
        assignment_span: span,
        target: Some("RawTokens".to_string()),
        target_span: Some(bonsai_common::Span::new(
            FileId::new(0),
            0,
            u64::try_from("RawTokens".len()).unwrap(),
        )),
        value_span: bonsai_common::Span::new(FileId::new(0), value_start, span.end),
        call_sites: Vec::new(),
        value_flow: Default::default(),
        exact_callable_return: None,
        exact_static_call_args: None,
        direct_call_name: None,
        direct_call_receiver: None,
    }];
    let assignment_values = AssignmentValueIndex::new(&facts);

    normalize_erlang_access_events(&mut events, src, &assignment_values);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign");
    };
    assert!(source_names.contains(&"Cmd".to_string()), "{source_names:?}");
}
