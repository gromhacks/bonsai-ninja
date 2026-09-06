use bonsai_lang_api::{DeclIndex, DeclKind};
use std::sync::Arc;

fn lower(source: &str) -> Arc<DeclIndex> {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[("Identity.kt", source)],
    );
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("Kotlin declarations")
}

#[test]
fn interpolated_when_results_are_not_finite_literal_selections() {
    for result in [r#""$key""#, r#""prefix ${key}""#, r#""""$key""""#] {
        let index = lower(&format!(
            r#"fun selected(key: String) = when (key) {{ "first" -> "safe"; else -> {result} }}"#
        ));
        assert!(
            index.finite_literal_selections.is_empty(),
            "{result}: {:?}",
            index.finite_literal_selections
        );
    }
}

#[test]
fn qualified_base_types_retain_their_provider_identity() {
    let index = lower(
        "class First : alpha.Parent()\nclass Second : beta.Parent()\nclass Handler : external.Listener\n",
    );
    for (name, base) in [
        ("First", "alpha.Parent"),
        ("Second", "beta.Parent"),
        ("Handler", "external.Listener"),
    ] {
        let class = index
            .defs
            .iter()
            .find(|decl| decl.name == name && decl.kind == DeclKind::Class)
            .unwrap();
        assert_eq!(class.bases, [base], "{name}");
    }
}
