use bonsai_lang_api::{DeclKind, LanguageAdapter};
use std::sync::Arc;

#[test]
fn type_spec_kind_comes_from_its_tree_sitter_type_node() {
    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_go::GoAdapter::new());
    let workspace = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "types.go",
            r#"
package sample

type Record struct { Value string }
type Reader interface { Read([]byte) (int, error) }
type UserID string
"#,
        )],
    );
    let file = *workspace.db().vfs().all_files().first().expect("fixture file");
    let index = workspace.db().decl_index(file).expect("Go declaration index");

    for (name, expected) in [
        ("Record", DeclKind::Struct),
        ("Reader", DeclKind::Interface),
        ("UserID", DeclKind::TypeAlias),
    ] {
        let declaration = index
            .defs
            .iter()
            .find(|declaration| declaration.name == name)
            .unwrap_or_else(|| panic!("missing declaration {name}"));
        assert_eq!(declaration.kind, expected, "{name}");
    }
}
