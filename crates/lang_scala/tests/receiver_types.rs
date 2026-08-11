use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{CallKind, DeclKind, FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("Storage.scala".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_scala::ScalaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn collect_calls(events: &[FlowEvent], out: &mut Vec<(String, Vec<String>)>) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver_types, ..
            } => out.push((name.clone(), receiver_types.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls(then_events, out);
                collect_calls(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls(body, out);
                collect_calls(catch_events, out);
                collect_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn class_methods_have_parent_and_companion_factory_receiver_is_typed() {
    let db = db_with(
        r#"
package demo

class Repository(val cmd: String) {
  def run(): Int = 1
}

class AuditedRepository(cmd: String) extends Repository(cmd) {
  override def run(): Int = super.run()
}

object Repository {
  def wrap(data: String): AuditedRepository = new AuditedRepository(data)
}

object Storage {
  def persist(envelope: String): Int = Repository.wrap(envelope).run()
}
"#,
    );
    let global = db.global_index();
    let mut audited_symbol = None;
    let mut audited_run_parent = None;
    let mut persist_calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            match (decl.name.as_str(), decl.kind) {
                ("AuditedRepository", DeclKind::Class) if decl.span.start < 170 => {
                    audited_symbol = Some(decl.symbol);
                    assert_eq!(decl.bases, vec!["Repository"]);
                }
                ("run", DeclKind::Method) if decl.span.start > 120 => audited_run_parent = decl.parent,
                ("persist", DeclKind::Method) => collect_calls(&decl.flow_events, &mut persist_calls),
                _ => {}
            }
        }
    }
    assert_eq!(audited_run_parent, audited_symbol);
    assert!(
        persist_calls
            .iter()
            .any(|(name, _)| name == "Repository.wrap(envelope).run"),
        "factory receiver call should be surfaced: {persist_calls:?}"
    );
}

#[test]
fn parameterless_member_selection_is_not_invented_as_a_call() {
    let db = db_with(
        r#"
object Transformer {
  def transform(value: String): String = {
    val upper = value.toUpperCase
    upper
  }
}
"#,
    );
    let global = db.global_index();
    let transform = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "transform")
        .expect("transform declaration");
    let mut calls = Vec::new();
    collect_calls(&transform.flow_events, &mut calls);
    assert!(
        calls.iter().all(|(name, _)| name != "value.toUpperCase"),
        "a field_expression is ambiguous and must not gain call semantics without resolution: {calls:?}"
    );
}

#[test]
fn lowercase_declared_types_and_bases_remain_semantic_facts() {
    let db = db_with(
        r#"
class lower { def run(value: String): Unit = () }
class child extends lower
object App {
  def handle(value: String): Unit = {
    val declared = new lower()
    declared.run(value)
  }
}
"#,
    );
    let global = db.global_index();
    let child = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "child")
        .expect("child declaration");
    assert_eq!(child.bases, ["lower"]);
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let mut calls = Vec::new();
    collect_calls(&handle.flow_events, &mut calls);
    assert!(
        calls.iter().any(|(name, types)| {
            name.rsplit('.').next() == Some("run") && types.iter().any(|ty| ty == "lower")
        }),
        "calls: {calls:?}"
    );
}

#[test]
fn base_constructor_named_compound_arg_uses_ast_facts() {
    let db = db_with(
        r#"
final case class Envelope(command: String)
class Parent(value: String)
class Child(env: Envelope) extends Parent(value = env.command)
"#,
    );
    let global = db.global_index();
    let child_ctor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.kind == DeclKind::Constructor && decl.name == "Child")
        .expect("Child constructor");
    let parent_arg = child_ctor.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } if name == "Parent" => args.first(),
        _ => None,
    });
    let arg = parent_arg.unwrap_or_else(|| panic!("Parent constructor call: {:?}", child_ctor.flow_events));
    assert_eq!(arg.name.as_deref(), Some("value"));
    assert_eq!(arg.place.as_deref(), Some("env.command"));
    assert!(
        arg.source_names.iter().any(|source| source == "env.command"),
        "compound constructor arg must carry AST member place: {arg:?}"
    );
}

#[test]
fn infix_value_is_not_rewritten_as_named_argument() {
    let db = db_with(
        r#"
object App {
  def handle(input: String): Unit = {
    Logger.error(input + "x")
    Logger.info(message = input)
  }
}
"#,
    );
    let global = db.global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let error_arg = handle.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } if name == "Logger.error" => args.first(),
        _ => None,
    });
    let error_arg = error_arg.unwrap_or_else(|| panic!("Logger.error call: {:?}", handle.flow_events));
    assert_eq!(error_arg.name, None);
    assert_eq!(error_arg.value_text, "input + \"x\"");
    assert!(error_arg.source_names.iter().any(|source| source == "input"));

    let named_arg = handle.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } if name == "Logger.info" => args.first(),
        _ => None,
    });
    let named_arg = named_arg.unwrap_or_else(|| panic!("Logger.info call: {:?}", handle.flow_events));
    assert_eq!(named_arg.name.as_deref(), Some("message"));
    assert_eq!(named_arg.place.as_deref(), Some("input"));

    assert!(handle.flow_events.iter().any(|event| {
        matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Operator,
                ..
            } if name == "+"
        )
    }));
}

#[test]
fn constructor_val_property_types_accessor_receiver_from_ast() {
    let db = db_with(
        r#"
case class Envelope(cmd: String)
abstract class BaseRepository(val data: Envelope) {
  def command: String = data.cmd
}
"#,
    );
    let global = db.global_index();
    let command = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "command")
        .expect("command accessor");
    let projected_place = command.flow_events.iter().find_map(|event| match event {
        FlowEvent::Return { value_flow, .. } => value_flow.place.as_deref(),
        _ => None,
    });
    assert!(
        projected_place.is_some_and(|place| place == "this.data.cmd"),
        "constructor `val data: Envelope` must keep the implicit-this compiler place on the exact projected field read: {:?}",
        command.flow_events
    );
}
