use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AssignValueKind, FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("a.rb".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_ruby::RubyAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

fn ruby_decl_events(source: &str, name: &str) -> Vec<FlowEvent> {
    let db = db_with(source);
    let index = db.global_index();
    let events = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == name)
        .unwrap_or_else(|| panic!("{name} declaration should index"))
        .flow_events
        .clone();
    events
}

fn contains_branch(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Branch { .. } => true,
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            contains_branch(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => contains_branch(body) || contains_branch(catch_events) || contains_branch(finally_events),
        _ => false,
    })
}

fn contains_loop(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Loop { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => contains_loop(then_events) || contains_loop(else_events),
        FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => contains_loop(body),
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => contains_loop(body) || contains_loop(catch_events) || contains_loop(finally_events),
        _ => false,
    })
}

#[test]
fn ruby_static_element_keys_are_structural_read_refs() {
    let source = r#"
require "rack"

def query(env)
  # QUERY_STRING in a comment is not a read.
  ignored = "QUERY_STRING"
  value = env["QUERY_STRING"]
  env["QUERY_STRING"] = ignored
  value
end
"#;
    let db = db_with(source);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("ruby declaration index");
    let refs = index
        .refs
        .iter()
        .filter(|reference| reference.name.ends_with("QUERY_STRING"))
        .collect::<Vec<_>>();

    assert_eq!(refs.len(), 1, "only the parsed element read should surface");
    assert_eq!(refs[0].name, "env.QUERY_STRING");
    let start = usize::try_from(refs[0].span.start).expect("span start");
    let end = usize::try_from(refs[0].span.end).expect("span end");
    assert_eq!(&source[start..end], "QUERY_STRING");
}

#[test]
fn ruby_super_return_emits_semantic_super_call_and_base() {
    let db = db_with(
        r#"
class Repository
  def run
    sink(cmd)
  end
end

class AuditedRepository < Repository
  def run
    super
  end
end
"#,
    );
    let index = db.global_index();
    let audited = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "AuditedRepository")
        .expect("AuditedRepository class should index");
    assert_eq!(audited.bases, vec!["Repository"]);

    let events = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .filter(|decl| decl.name == "run")
        .find(|decl| {
            decl.qualified_name
                .as_deref()
                .is_some_and(|name| name.contains("AuditedRepository"))
        })
        .expect("AuditedRepository.run should index")
        .flow_events
        .clone();

    assert!(
        events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                call_kind: bonsai_lang_api::CallKind::Method,
                ..
            } if name == "super.run" && receiver == "super"
        )),
        "terminal super should surface a semantic super.run call: {events:?}"
    );
}

#[test]
fn ruby_if_modifier_emits_branch_event() {
    let events = ruby_decl_events(
        r#"
class Repo
  def run(items)
    items.each do |it|
      handle(it) if it
    end
  end
end
"#,
        "run",
    );

    assert!(
        contains_branch(&events),
        "Ruby `expr if cond` should emit a Branch event; events: {events:?}"
    );
}

#[test]
fn ruby_each_block_emits_loop_event() {
    let events = ruby_decl_events(
        r#"
class Repo
  def run(items)
    items.each do |it|
      handle(it)
    end
  end
end
"#,
        "run",
    );

    assert!(
        contains_loop(&events),
        "Ruby `items.each do` should emit a Loop event; events: {events:?}"
    );
}

#[test]
fn ruby_custom_block_parameter_is_bound_to_the_call_yield_endpoint() {
    let events = ruby_decl_events(
        r#"
def helper(args)
  yield args
end

def entry(args)
  helper(args) do |value|
    sink(value)
  end
end
"#,
        "entry",
    );

    let call_span = events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { span, name, .. } if name == "helper" => Some(*span),
            _ => None,
        })
        .expect("helper call should be adapter-lowered");
    let (binding_span, source_call) = events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                value_kind: Some(AssignValueKind::YieldResult),
                ..
            } if target == "value" => Some((*span, source_call.as_deref())),
            _ => None,
        })
        .expect("Ruby block parameter should be a typed yield-result binding");

    assert_eq!(source_call, Some("helper"));
    assert_eq!(
        binding_span, call_span,
        "yield-result binding must use the resolved AST call identity"
    );
}

#[test]
fn ruby_begin_assignment_uses_compound_operands_not_nested_raise_call() {
    let events = ruby_decl_events(
        r#"
class Repo
  def run(envelope, routed, user)
    valid = begin
      raise 'empty' if routed.to_s.empty?
      { **envelope, cmd: routed, user: user }
    rescue
      { **envelope, cmd: routed.to_s, user: user }
    end
    persist(valid)
  end
end
"#,
        "run",
    );

    let valid_assignment = events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_names,
                ..
            } if target == "valid" => Some((source_call, source_names)),
            _ => None,
        })
        .expect("valid assignment should be indexed");

    assert_eq!(valid_assignment.0, &None);
    assert!(valid_assignment.1.iter().any(|name| name == "envelope"));
    assert!(valid_assignment.1.iter().any(|name| name == "routed"));
    assert!(valid_assignment.1.iter().any(|name| name == "user"));
}
