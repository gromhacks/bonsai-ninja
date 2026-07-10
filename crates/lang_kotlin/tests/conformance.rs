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

#[test]
fn property_declarations_use_declared_property_name_not_modifier() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
abstract class BaseRepository(val data: Envelope) {
  private val state: RepoState = RepoState.Active
  open val cmd: String get() = data.cmd
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let constructor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "BaseRepository" && !decl.params.is_empty())
        .expect("synthetic BaseRepository constructor");

    let targets = constructor
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(targets.contains(&"state"));
    assert!(targets.contains(&"cmd"));
    assert!(!targets.contains(&"private"));
    assert!(!targets.contains(&"open"));
}

#[test]
fn typed_property_constructor_is_classified_from_adapter_facts() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
import java.io.File

fun Factory(input: String): String = input

fun handle(input: String) {
  val f = File("/data", input)
  val text: String = Factory(input)
  f.readText()
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
    let calls = handle
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, call_kind, .. } => Some((name.as_str(), *call_kind)),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(calls.contains(&("File", CallKind::Constructor)), "{calls:?}");
    assert!(calls.contains(&("Factory", CallKind::Function)), "{calls:?}");
}
