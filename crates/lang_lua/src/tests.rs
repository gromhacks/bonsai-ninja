use super::*;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("lua grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set lua grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse lua source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn require_member_assignment_emits_local_member_binding() {
    let imports = parse_import_specs("local helper = require('util').helper\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "util"
            && spec.alias.is_none()
            && spec.original_name.is_none()
            && !spec.is_wildcard
            && spec.scope == ImportScope::Module
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "util"
            && spec.alias.as_deref() == Some("helper")
            && spec.original_name.as_deref() == Some("helper")
            && !spec.is_wildcard
            && spec.scope == ImportScope::Local
    }));
}

#[test]
fn plain_require_assignment_remains_namespace_binding_only() {
    let imports = parse_import_specs("local util = require('util')\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "util"
            && spec.alias.as_deref() == Some("util")
            && spec.original_name.is_none()
            && !spec.is_wildcard
            && spec.scope == ImportScope::Module
    }));
    assert!(
        imports.iter().all(|spec| spec.scope != ImportScope::Local),
        "plain require assignment should not invent member imports: {imports:?}"
    );
}
