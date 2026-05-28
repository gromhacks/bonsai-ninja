use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
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
