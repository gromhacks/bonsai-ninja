use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.kt", "fun main() {}")]);
}

#[test]
fn jump_expression_lowering_distinguishes_throw_and_return() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
fun handle(token: String) {
  try { throw RuntimeException(token) }
  catch (e: Exception) { sink(e.message ?: "") }
}
fun identity(value: String): String { return value }
fun sink(value: String) {}
"#,
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let body = handle.flow_events.iter().find_map(|event| match event {
        FlowEvent::Try { body, .. } => Some(body),
        _ => None,
    });
    assert!(
        body.is_some_and(|body| body.iter().any(
            |event| matches!(event, FlowEvent::Throw { value_name: Some(value), .. } if value == "token")
        )),
        "Kotlin throw payload was not lowered from the parsed jump expression: {:#?}",
        handle.flow_events
    );

    let identity = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "identity")
        .expect("identity declaration");
    assert!(identity
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Return { value_name: Some(value), .. } if value == "value")));
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
fn custom_getter_qualifies_constructor_property_as_receiver_state() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
data class Envelope(val cmd: String)

abstract class BaseRepository(val data: Envelope) {
  open val cmd: String get() = data.cmd
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let getter = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "cmd" && decl.params.is_empty())
        .expect("custom property getter");
    let value_flow = getter
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Return { value_flow, .. } => Some(value_flow),
            _ => None,
        })
        .expect("getter return flow");
    assert_eq!(value_flow.place.as_deref(), Some("this.data.cmd"));
    assert_eq!(
        value_flow
            .projection
            .as_ref()
            .map(|projection| (projection.base.as_str(), projection.path.as_slice())),
        Some(("this", ["data".to_string(), "cmd".to_string()].as_slice()))
    );
    assert_eq!(value_flow.source_names, ["this.data.cmd"]);
}

#[test]
fn primary_constructor_delegation_is_an_exact_constructor_call() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
open class Base(val data: String)
class Child(data: String) : Base(data)
"#,
        )],
    );
    let global = ws.db().global_index();
    let child = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Child" && matches!(decl.kind, bonsai_lang_api::DeclKind::Constructor))
        .expect("Child primary constructor");
    assert!(
        child.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                args,
                ..
            } if name == "Base"
                && args.first().and_then(|arg| arg.place.as_deref()) == Some("data")
        )),
        "base delegation must come from constructor_invocation syntax: {:#?}",
        child.flow_events
    );
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
