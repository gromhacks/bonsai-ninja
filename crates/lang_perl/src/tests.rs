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
