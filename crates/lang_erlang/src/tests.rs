use super::*;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("erlang grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set erlang grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse erlang source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn remote_and_local_call_refs_use_exact_callee_nodes_once() {
    let src = r#"
-module(user_service).
get_user(Token) -> auth_service:verify_token(Token).
update_user(Token) -> verify_token(Token).
"#;
    let language = language_from_pack(PACK_NAME).expect("erlang grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set erlang grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse erlang source");
    let refs = bonsai_lang_api::kit::extract_call_refs(&tree, FileId::new(0), src.as_bytes(), &HANDLER);
    let names = refs
        .iter()
        .map(|reference| reference.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "auth_service:verify_token")
            .count(),
        1,
        "{names:?}"
    );
    assert!(names.contains(&"verify_token"), "{names:?}");
    assert!(
        !names.iter().any(|name| matches!(*name, "Token" | "UserId")),
        "{names:?}"
    );
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
    let aliases = std::collections::BTreeMap::from([(span, "helper".to_string())]);
    let alias = erlang_fun_ref_alias_assignment(&event, &aliases).expect("fun ref alias");

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

#[test]
fn fun_ref_call_argument_emits_exact_callable_place() {
    let mut events = vec![FlowEvent::Call {
        span: bonsai_common::Span::new(FileId::new(0), 0, 20),
        name: "invoke".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: bonsai_common::Span::new(FileId::new(0), 7, 19),
            name: None,
            value_text: "fun helper/1".to_string(),
            place: None,
            source_names: vec!["helper".to_string()],
        }],
    }];

    let arg_span = match &events[0] {
        FlowEvent::Call { args, .. } => args[0].span,
        _ => unreachable!(),
    };
    let fun_refs = std::collections::BTreeMap::from([(arg_span, "helper".to_string())]);
    normalize_erlang_access_events(&mut events, &fun_refs);

    assert!(matches!(
        events.as_slice(),
        [FlowEvent::Call { name, args, .. }]
            if name == "invoke"
                && args.first().is_some_and(|arg| {
                    arg.value_text == "helper"
                        && arg.place.as_deref() == Some("helper")
                        && arg.source_names == ["helper"]
                })
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
    let language = language_from_pack(PACK_NAME).expect("erlang grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set erlang grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse erlang source");
    let plans = collect_erlang_parameter_pattern_plans(&tree, FileId::new(0), src.as_bytes());
    assert_eq!(plans.len(), 1, "{plans:#?}");
    assert!(plans[0].params.is_empty(), "{plans:#?}");
}

#[test]
fn list_cons_param_pattern_emits_entry_bindings() {
    let src = "process_batch([Token | Rest]) -> run_user(Token).";
    let language = language_from_pack(PACK_NAME).expect("erlang grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set erlang grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse erlang source");
    let plans = collect_erlang_parameter_pattern_plans(&tree, FileId::new(0), src.as_bytes());
    assert_eq!(plans.len(), 1, "{plans:#?}");
    assert_eq!(plans[0].params, ["_Arg0"]);
    let bindings = plans[0]
        .bindings
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
fn list_comprehension_assignment_exposes_generator_sources() {
    let src = r#"-module(main).
run(Cmd) ->
    RawTokens = [Part || Part <- string:tokens(Cmd, " ")],
    RawTokens.
"#;
    let language = language_from_pack(PACK_NAME).expect("erlang grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set erlang grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse erlang source");
    let clause = collect_kinds(&tree, &["function_clause"])
        .into_iter()
        .find(|clause| {
            clause
                .child_by_field_name("name")
                .is_some_and(|name| node_text(&name, src.as_bytes()) == "run")
        })
        .expect("run clause");
    let body = clause.child_by_field_name("body").expect("run body");
    let events = walk_flow_events(body, FileId::new(0), src.as_bytes(), &HANDLER, &[]);
    let binding = events.iter().find_map(|event| match event {
        FlowEvent::Assign {
            target,
            source_call,
            source_call_args,
            ..
        } if target == "Part" => Some((source_call.as_deref(), source_call_args.as_slice())),
        _ => None,
    });
    assert_eq!(
        binding,
        Some((
            Some("string:tokens"),
            ["Cmd".to_string(), "\" \"".to_string()].as_slice()
        )),
        "generator binding must come from exact Tree-sitter call facts: {events:#?}"
    );
}
