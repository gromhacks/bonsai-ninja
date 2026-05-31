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

    let alias = erlang_fun_ref_alias_assignment(&event, src).expect("fun ref alias");

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
