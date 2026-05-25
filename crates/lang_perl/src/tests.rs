use super::*;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse perl source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn use_qw_exports_emit_resolution_local_member_imports() {
    let imports = parse_import_specs("use AuthService qw(verify_token run_admin_command);\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "AuthService"
            && spec.alias.is_none()
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    for exported in ["verify_token", "run_admin_command"] {
        assert!(
            imports.iter().any(|spec| {
                spec.module == "AuthService"
                    && spec.alias.is_none()
                    && spec.original_name.as_deref() == Some(exported)
                    && spec.scope == ImportScope::Local
            }),
            "missing resolver-local Perl import for {exported}"
        );
    }
}

#[test]
fn inheritance_pragmas_do_not_emit_callable_member_imports() {
    let imports = parse_import_specs("use parent qw(BaseRole OtherRole);\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "parent"
            && spec.alias.is_none()
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(
        imports.iter().all(|spec| spec.scope != ImportScope::Local),
        "inheritance pragmas should not create callable import aliases: {imports:?}"
    );
}

#[test]
fn coderef_assignment_emits_clean_callable_alias() {
    let src = "my $cb = \\&helper;";
    let span = Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());
    let event = FlowEvent::Assign {
        span,
        target: "$cb".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["helper".to_string()],
        declares_new_binding: true,
        value_kind: None,
    };

    let alias = perl_coderef_alias_assignment(&event, src).expect("coderef alias");

    assert!(matches!(
        alias,
        FlowEvent::Assign {
            target,
            source_name: Some(source),
            source_call: None,
            source_names,
            ..
        } if target == "$cb" && source == "helper" && source_names.is_empty()
    ));
}

#[test]
fn direct_array_argv_binding_infers_perl_param() {
    let src = "my @items = @_;";
    let span = Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());
    let event = FlowEvent::Assign {
        span,
        target: "items".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["_".to_string()],
        declares_new_binding: true,
        value_kind: None,
    };

    let (_, vars) = perl_list_binding_at(&event, src).expect("direct @_ binding");

    assert_eq!(vars, vec!["@items".to_string()]);
}

#[test]
fn map_grep_topic_call_rewrites_topic_arg_to_collection() {
    let src = "sub handle { my @items = @_; map { step($_); } @items; }";
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse perl source");

    let events = synthesize_map_grep_topic_call_events(&tree, src.as_bytes(), FileId::new(0));

    assert!(events.iter().any(|(_, event)| {
        matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "step"
                    && args
                        .iter()
                        .any(|arg| arg.value_text == "@items"
                            && arg.source_names == vec!["@items".to_string(), "items".to_string()])
        )
    }));
}

#[test]
fn eval_die_dollar_at_rewrites_to_try_throw_alias_catch() {
    let src = "sub handle { my $token = shift; eval { die $token; }; if ($@) { my $e = $@; sink($e); } }\nsub sink { my ($s) = @_; }\n";
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.pl", src)]);
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle decl");

    let (body, catch_events, catch_param) = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Try {
                body,
                catch_events,
                catch_param,
                ..
            } => Some((body, catch_events, catch_param)),
            _ => None,
        })
        .expect("eval/die should lower to Try");

    assert_eq!(catch_param.as_deref(), Some("$e"));
    assert!(
        body.iter().any(|event| matches!(
            event,
            FlowEvent::Throw {
                value_name: Some(value),
                ..
            } if value == "$token"
        )),
        "try body should contain a Throw carrying $token: {body:#?}"
    );
    assert!(
        catch_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Assign { span, .. } if perl_assignment_rhs_is_dollar_at(src, *span))),
        "the `$@` alias assignment should become the catch binding: {catch_events:#?}"
    );
    assert!(
        catch_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "sink")),
        "catch body should retain the sink call: {catch_events:#?}"
    );
}
