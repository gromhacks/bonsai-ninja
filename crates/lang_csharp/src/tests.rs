use super::*;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("csharp grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set csharp grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse csharp source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn using_static_emits_statement_import_and_local_wildcard_binding() {
    let imports = parse_import_specs("using static App.Util;\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "App.Util"
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "App.Util"
            && spec.alias.is_none()
            && spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Local
    }));
}

#[test]
fn using_static_classification_comes_from_the_grammar_token() {
    let imports = parse_import_specs("using /* trivia */ static App.Util;\n");

    assert!(imports
        .iter()
        .any(|spec| { spec.module == "App.Util" && spec.is_wildcard && spec.scope == ImportScope::Local }));
}

#[test]
fn ordinary_using_does_not_emit_local_wildcard_binding() {
    let imports = parse_import_specs("using App;\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "App"
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(
        imports.iter().all(|spec| spec.scope != ImportScope::Local),
        "ordinary namespace usings should not import callable members: {imports:?}"
    );
}
