use super::*;

#[test]
fn method_symbol_reference_is_adapter_owned_and_rejects_ordinary_calls() {
    let language = language_from_pack(PACK_NAME).expect("ruby grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set ruby grammar");
    let src = "cb = method(:helper)\nvalue = method(name)\n";
    let tree = parser.parse(src, None).expect("parse ruby source");
    let refs = collect_kinds(&tree, &["call", "method_call"])
        .into_iter()
        .filter_map(|node| extract_ruby_callable_reference(node, src.as_bytes()))
        .collect::<Vec<_>>();
    assert_eq!(refs, vec!["helper"]);
}

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("ruby grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set ruby grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse ruby source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn require_relative_emits_statement_import_and_local_wildcard_binding() {
    let imports = parse_import_specs("require_relative 'helpers'\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.is_none()
            && spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Local
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.as_deref() == Some("Helpers")
            && spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Local
    }));
    assert!(!imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.as_deref() == Some("Helpers")
            && spec.scope == ImportScope::Module
    }));
}

#[test]
fn autoload_does_not_emit_wildcard_callable_import() {
    let imports = parse_import_specs("autoload :Helpers, 'helpers'\n");

    assert!(imports.iter().all(|spec| !spec.is_wildcard));
}
