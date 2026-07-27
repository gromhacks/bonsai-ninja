use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_vfs::Vfs;
use std::sync::Arc;

#[test]
fn membership_guards_and_literal_sets_are_compiler_facts() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "guards.py".to_string(),
        Arc::<str>::from(
            r#"
ALLOWED = {"a", "b"}

def check(value):
    if value not in ALLOWED:
        return
    if not value in ALLOWED:
        return
    if value in ALLOWED:
        pass
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");

    let membership: Vec<_> = index
        .branch_conditions
        .iter()
        .filter_map(|fact| fact.membership.as_ref())
        .collect();
    assert_eq!(membership.len(), 3, "{membership:#?}");
    assert!(
        membership
            .iter()
            .all(|fact| fact.subject == "value" && fact.collection == "ALLOWED"),
        "{membership:#?}"
    );
    assert_eq!(
        membership
            .iter()
            .map(|fact| fact.then_contains)
            .collect::<Vec<_>>(),
        vec![false, false, true],
        "{membership:#?}"
    );

    let set_flow = index
        .assignment_values
        .iter()
        .find(|fact| !fact.value_flow.tuple_items.is_empty())
        .expect("literal set assignment flow");
    assert_eq!(set_flow.value_flow.tuple_items.len(), 2, "{set_flow:#?}");
    assert!(
        set_flow.value_flow.tuple_items.iter().all(|item| item.is_empty()),
        "literal set items must carry no value dependencies: {set_flow:#?}"
    );
}
