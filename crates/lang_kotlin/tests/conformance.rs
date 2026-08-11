use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.kt", "fun main() {}")]);
}

#[test]
fn navigation_calls_emit_exact_receiver_and_member_facts() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            "fun example(stream: Stream) { stream.close(); stream.read() }",
        )],
    );
    let global = ws.db().global_index();
    let example = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "example")
        .expect("example declaration");
    let calls = example
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, receiver, .. } => Some((name.as_str(), receiver.as_deref())),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(calls.contains(&("stream.close", Some("stream"))), "{calls:?}");
    assert!(calls.contains(&("stream.read", Some("stream"))), "{calls:?}");
    assert!(calls.iter().all(|(name, _)| !name.contains("..")), "{calls:?}");
}

#[test]
fn nested_method_chain_receivers_join_their_semantic_call_spans() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "App.kt",
            r#"fun flow(command: String) = command.trim().lowercase().repeat(2)"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let flow = index
        .defs
        .iter()
        .find(|decl| decl.name == "flow")
        .expect("flow declaration");
    let mut calls = flow
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call {
                span,
                name,
                receiver: Some(_),
                ..
            } if ["trim", "lowercase", "repeat"]
                .iter()
                .any(|method| bonsai_common::short_qualified_tail(name) == *method) =>
            {
                Some((*span, name.as_str()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    calls.sort_by_key(|(span, _)| span.end - span.start);
    assert_eq!(calls.len(), 3, "events={:#?}", flow.flow_events);

    for (index_in_chain, (span, name)) in calls.into_iter().enumerate() {
        let fact = index
            .call_receivers
            .iter()
            .find(|fact| fact.call_span == span)
            .unwrap_or_else(|| panic!("missing receiver fact for {name} at {span:?}"));
        if index_in_chain == 0 {
            assert_eq!(fact.value_flow.place.as_deref(), Some("command"));
        } else {
            assert!(
                !fact.value_flow.call_sites.is_empty(),
                "nested receiver for {name} must retain its inner semantic call: {fact:#?}"
            );
        }
    }
}

#[test]
fn string_templates_expose_only_parsed_interpolation_reads() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
fun render(cmd: String, unrelated: String) {
  sink("prefix $cmd")
  sink("the words cmd and unrelated are literals")
}
fun sink(value: String) {}
"#,
        )],
    );
    let global = ws.db().global_index();
    let render = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "render")
        .expect("render declaration");
    let calls = render
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "sink" => Some(args),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(calls.len(), 2, "events={:#?}", render.flow_events);
    assert_eq!(calls[0][0].source_names, ["cmd"]);
    assert!(calls[0][0].source_names.iter().all(|name| name != "unrelated"));
    assert!(
        calls[1][0].source_names.is_empty(),
        "literal text is not an identifier read"
    );
}

#[test]
fn when_subject_declaration_binds_the_subject_expression() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.kt",
            "fun main(subject: String) { when (val value = subject) { else -> sink(value) } }\nfun sink(value: String) {}",
        )],
    );
    let global = ws.db().global_index();
    let main = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    let mut facts = Vec::new();
    collect_assignments(&main.flow_events, &mut facts);
    assert!(
        facts
            .iter()
            .any(|(target, source)| target == "value" && source.as_deref() == Some("subject")),
        "missing value <- subject: {facts:#?}"
    );
    assert!(facts.iter().all(|(target, _)| target != "String"));

    fn collect_assignments(events: &[FlowEvent], out: &mut Vec<(String, Option<String>)>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    target, source_name, ..
                } => out.push((target.clone(), source_name.clone())),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_assignments(then_events, out);
                    collect_assignments(else_events, out);
                }
                _ => {}
            }
        }
    }
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
fn secondary_constructor_delegation_is_exact_and_precedes_its_body() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
open class Base(val value: String)

class Child(val value: String) : Base(value) {
  constructor(value: String, marker: Int) : this(value) { record(marker) }
}

class Direct : Base {
  private val ready = prepare()
  constructor(value: String) : super(value) { record(value) }
}

class Outer {
  class Nested(val value: String) {
    constructor() : this("")
  }
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let constructors = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .filter(|decl| decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .collect::<Vec<_>>();

    let child = constructors
        .iter()
        .copied()
        .find(|decl| decl.name == "Child" && decl.params.len() == 2)
        .expect("Child secondary constructor");
    assert!(matches!(
        child.flow_events.first(),
        Some(FlowEvent::Call {
            name,
            receiver: None,
            call_kind: CallKind::Constructor,
            args,
            ..
        }) if name == "Child"
            && args.first().and_then(|arg| arg.place.as_deref()) == Some("value")
    ));
    assert!(child
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "record")));

    let direct = constructors
        .iter()
        .copied()
        .find(|decl| decl.name == "Direct" && decl.params.len() == 1)
        .expect("Direct secondary constructor");
    assert_eq!(
        constructors.iter().filter(|decl| decl.name == "Direct").count(),
        1,
        "a class with only secondary constructors has no implicit primary constructor"
    );
    assert!(matches!(
        direct.flow_events.first(),
        Some(FlowEvent::Call {
            name,
            receiver: Some(receiver),
            call_kind: CallKind::Constructor,
            args,
            ..
        }) if name == "super"
            && receiver == "super"
            && args.first().and_then(|arg| arg.place.as_deref()) == Some("value")
    ));
    let direct_calls = direct
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(direct_calls, ["super", "prepare", "record"]);

    assert_eq!(
        constructors.iter().filter(|decl| decl.name == "Outer").count(),
        1,
        "nested secondary constructors must not attach to their outer class"
    );
    assert_eq!(
        constructors.iter().filter(|decl| decl.name == "Nested").count(),
        2,
        "nested class owns its primary and secondary constructors"
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
  init { activate(state) }
  open val cmd: String get() = data.cmd
  fun ignored() { deactivate(state) }
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

    assert!(targets.contains(&"this.state"));
    assert!(
        !targets.iter().any(|target| target.ends_with("cmd")),
        "a computed getter is not primary-constructor execution: {targets:?}"
    );
    assert!(!targets.contains(&"private"));
    assert!(!targets.contains(&"open"));

    let calls = constructor
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(calls.contains(&"activate"), "init blocks execute: {calls:?}");
    assert!(
        !calls.contains(&"deactivate"),
        "sibling method bodies do not execute during construction: {calls:?}"
    );
}

#[test]
fn constructor_classification_uses_declarations_not_capitalization() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
import java.io.File

fun Factory(input: String): String = input
class lower

fun handle(input: String) {
  val f = File("/data", input)
  val text: String = Factory(input)
  val local = lower()
  f.readText()
  local.toString()
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

    assert!(calls.contains(&("File", CallKind::Function)), "{calls:?}");
    assert!(calls.contains(&("Factory", CallKind::Function)), "{calls:?}");
    assert!(calls.contains(&("lower", CallKind::Constructor)), "{calls:?}");
}

#[test]
fn implicit_primary_constructor_owns_class_property_initializers() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            ("Dependency.kt", "package sample\nclass lower\n"),
            (
                "Owner.kt",
                r#"
package sample
class Owner {
  private val dependency = lower()
  fun run() { dependency.work() }
}
"#,
            ),
        ],
    );
    let global = ws.db().global_index();
    let constructor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Owner" && decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .expect("implicit Owner constructor");
    assert!(
        constructor.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                ..
            } if target == "this.dependency" && source_call == "lower"
        )),
        "class property initializer must be receiver-qualified compiler IR: {:#?}",
        constructor.flow_events
    );
}
