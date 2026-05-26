use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.kt", "fun main() {}")]);
}

#[test]
fn annotated_parameters_bind_annotation_to_value_name() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
import javax.ws.rs.MatrixParam

class App {
  fun handle(@MatrixParam("id") value: String, stmt: Statement) {
    stmt.executeQuery(value)
  }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert_eq!(handle.params, ["value", "stmt"]);
    assert_eq!(handle.param_annotations.len(), handle.params.len());
    assert_eq!(handle.param_annotations[0], ["MatrixParam"]);
    assert!(handle.param_annotations[1].is_empty());
}
