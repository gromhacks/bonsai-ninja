use super::*;

#[test]
fn function_reference_assignment_emits_clean_callable_alias() {
    use bonsai_lang_api::{AssignValueKind, LanguageAdapter};
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Callbacks.kt",
            r#"
fun helper(value: String) = value

fun apply(value: String): String {
  val cb = ::helper
  return cb(value)
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let apply = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "apply")
        .expect("apply declaration");
    let aliases = apply
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                value_kind,
                ..
            } if target == "cb" => Some((source_name, source_call, source_names, value_kind)),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(aliases.len(), 1, "callable reference should be one compiler fact");
    assert_eq!(aliases[0].0.as_deref(), Some("helper"));
    assert_eq!(aliases[0].1.as_deref(), None);
    assert!(aliases[0].2.is_empty());
    assert_eq!(aliases[0].3, &Some(AssignValueKind::CallableReference));
}
