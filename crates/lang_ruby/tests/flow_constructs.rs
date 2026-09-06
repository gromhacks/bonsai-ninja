use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AssignValueKind, FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    db_with_path("a.rb", source)
}

fn db_with_path(path: &str, source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write(path.to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_ruby::RubyAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

#[test]
fn erb_instance_variable_call_arguments_are_typed_places() {
    let db = db_with_path("show.html.erb", "<%= raw @comment %>\n");
    let file = db.vfs().all_files().into_iter().next().expect("ERB file");
    let index = db.global_index();
    let module = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "__module__")
        .expect("ERB expression should be wrapped in a module declaration");
    assert_eq!(module.params, ["self.comment"]);
    assert_eq!(module.param_annotations, [Vec::<String>::new()]);
    let events = &module.flow_events;

    let arg = events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "raw" => args.first(),
            _ => None,
        })
        .expect("raw call argument should be adapter-lowered");
    assert_eq!(arg.value_text, "self.comment");
    assert_eq!(arg.place.as_deref(), Some("self.comment"));
    assert_eq!(arg.source_names, vec!["self.comment"]);

    let syntax = db
        .compiler_syntax_header_uncached(file)
        .expect("ERB compiler syntax header");
    assert!(
        syntax.calls.iter().any(|call| call.name == "raw"),
        "ERB adapter calls must survive in the compact compiler header: {syntax:#?}"
    );
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

#[test]
fn a_returning_method_named_raise_is_not_a_syntactic_throw() {
    let events = ruby_decl_events(
        "def raise(value)\n  value\nend\ndef forward(value)\n  raise(value)\n  sink(value)\nend\n",
        "forward",
    );
    assert!(events.iter().any(|event| matches!(event,
        FlowEvent::Call { name, .. } if name == "raise")));
    assert!(events.iter().any(|event| matches!(event,
        FlowEvent::Call { name, .. } if name == "sink")));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FlowEvent::Throw { .. })),
        "a method spelling cannot prove an unconditional exception: {events:#?}"
    );
}

#[test]
fn unbound_identifier_receiver_is_a_zero_arg_call_result() {
    let events = ruby_decl_events(
        "def entry\n  value = read_input.to_s\n  local = 'ok'\n  local.to_s\nend\n",
        "entry",
    );

    assert!(events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, receiver: None, args, .. }
            if name == "read_input" && args.is_empty()
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign {
            target,
            source_call: Some(source_call),
            value_kind: Some(AssignValueKind::CallResult),
            ..
        } if target == "read_input" && source_call == "read_input"
    )));
    assert!(
        !events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, receiver: None, .. } if name == "local"
        )),
        "a method-local receiver must stay a local read: {events:#?}"
    );
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

fn contains_call(events: &[FlowEvent], expected: &str) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Call { name, .. } => name == expected,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => contains_call(then_events, expected) || contains_call(else_events, expected),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            contains_call(body, expected)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            contains_call(body, expected)
                || contains_call(catch_events, expected)
                || contains_call(finally_events, expected)
        }
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
fn hash_field_values_retain_sources_nested_in_call_arguments() {
    let events = ruby_decl_events(
        r#"
def build(input)
  options = { command: normalize(input) }
  sink(options[:command])
end
"#,
        "build",
    );
    let sources = events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target, source_names, ..
            } if target == "options.command" => Some(source_names),
            _ => None,
        })
        .expect("hash field assignment");
    assert!(
        sources.iter().any(|source| source == "input"),
        "the grammar-declared argument_list must expose nested input: {events:#?}"
    );
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
fn qualified_superclass_retains_exact_identity_and_resolver_tail() {
    let db = db_with(
        r#"
class UsersController < ActionController::Base
  def show
    params["id"]
  end
end
"#,
    );
    let index = db.global_index();
    let controller = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "UsersController")
        .expect("UsersController class should index");
    assert_eq!(
        controller.bases,
        ["ActionController::Base", "Base"],
        "qualified class identity is required for precise framework ancestry, while the tail preserves ordinary method resolution"
    );
}

#[test]
fn include_and_prepend_modules_join_the_exact_instance_ancestor_chain() {
    let db = db_with(
        r#"
class OrdersWorker
  include Shoryuken::Worker
  prepend Audited

  def perform(message, body)
    body
  end
end
"#,
    );
    let index = db.global_index();
    let worker = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "OrdersWorker")
        .expect("OrdersWorker class should index");

    assert_eq!(
        worker.bases,
        ["Shoryuken::Worker", "Worker", "Audited"],
        "Ruby mixin ancestry must come from parsed class-body include/prepend arguments"
    );
}

#[test]
fn ruby_if_modifier_emits_branch_event() {
    let db = db_with(
        r#"
class Repo
  def run(items)
    items.each do |it|
      handle(it) if it
    end
  end
end
"#,
    );
    let index = db.global_index();
    let events = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name.starts_with("<lambda@") && decl.params == ["it"])
        .expect("Ruby trailing block should own a lambda declaration")
        .flow_events
        .clone();

    assert!(
        contains_branch(&events),
        "Ruby `expr if cond` should emit a Branch event; events: {events:?}"
    );
}

#[test]
fn ruby_for_syntax_emits_loop_event() {
    let events = ruby_decl_events(
        r#"
class Repo
  def run(items)
    for it in items
      handle(it)
    end
  end
end
"#,
        "run",
    );

    assert!(
        contains_loop(&events),
        "Ruby `for` syntax should emit a Loop event; events: {events:?}"
    );
}

#[test]
fn ruby_method_block_body_is_analyzed_without_guessing_loop_semantics() {
    let db = db_with(
        r#"
class Repo
  def run(items)
    items.each do |it|
      handle(it)
    end
  end
end
"#,
    );
    let index = db.global_index();
    let callback = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name.starts_with("<lambda@") && decl.params == ["it"])
        .expect("Ruby trailing block should own a lambda declaration");
    let events = callback.flow_events.clone();

    assert!(
        !contains_loop(&events),
        "external method identity cannot prove a language loop: {events:?}"
    );
    assert!(
        contains_call(&events, "handle"),
        "the compiler-owned block body must remain analyzable: {events:?}"
    );
}

#[test]
fn chained_constructor_receiver_carries_ast_declared_type() {
    let events = ruby_decl_events(
        r#"
class Util
  def helper(value)
    sink(value)
  end
end

def entry(input)
  Util.new.helper(input)
end
"#,
        "entry",
    );

    assert!(
        events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                receiver_types,
                call_kind: bonsai_lang_api::CallKind::Method,
                ..
            } if name == "Util.new.helper"
                && receiver == "Util.new"
                && receiver_types == &["Util"]
        )),
        "Ruby's constructor selector must type the temporary receiver from its CST: {events:#?}"
    );
}

#[test]
fn ruby_custom_block_parameter_is_bound_to_the_call_yield_endpoint() {
    let db = db_with(
        r#"
def helper(args)
  yield args
end

def passive(args)
  args
end

def entry(args)
  helper(args) do |value|
    sink(value)
  end
  passive(args) do |value|
    must_not_execute(value)
  end
end
"#,
    );
    let file = db.vfs().all_files()[0];
    let compiler = db.decl_index(file).expect("Ruby compiler index");
    let helper = compiler
        .defs
        .iter()
        .find(|decl| decl.name == "helper")
        .expect("helper declaration");
    assert!(
        helper
            .flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Yield { .. })),
        "the yielding callee must own its exact Yield endpoint: {helper:#?}"
    );
    assert!(helper.params.iter().any(|param| param == "<ruby-yield-block>"));
    assert!(contains_call(&helper.flow_events, "<ruby-yield-block>"));
    let passive = compiler
        .defs
        .iter()
        .find(|decl| decl.name == "passive")
        .expect("non-yielding helper declaration");
    assert!(
        passive.params.iter().all(|param| param != "<ruby-yield-block>")
            && !contains_call(&passive.flow_events, "<ruby-yield-block>"),
        "a trailing block is not proof that a callee invokes it: {passive:#?}"
    );
    let callback = compiler
        .defs
        .iter()
        .find(|decl| decl.name.starts_with("<lambda@") && contains_call(&decl.flow_events, "sink"))
        .expect("trailing block callback declaration");
    assert!(contains_call(&callback.flow_events, "sink"));
    assert!(
        compiler.call_argument_values.iter().any(|fact| {
            fact.inline_callback_span == Some(callback.span) && fact.inline_callback_params == ["value"]
        }),
        "the call argument table must bind the exact callback span and parameter"
    );
}

#[test]
fn ruby_local_proc_call_normalizes_only_the_exact_lambda_binding() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_ruby::RubyAdapter::new())],
        &[(
            "a.rb",
            r#"
def entry(args, dynamic)
  callback = ->(value) { sink(value) }
  callback.call(args)
  dynamic.call(args)
end
"#,
        )],
    );
    let global = workspace.db().global_index();
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    let callback = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .filter(|decl| decl.name == "callback")
        .collect::<Vec<_>>();
    assert_eq!(
        callback.len(),
        1,
        "the arrow lambda body wrapper must not create a second callable declaration"
    );
    let callback = callback[0];
    assert!(entry.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call {
            name,
            receiver: None,
            call_kind: bonsai_lang_api::CallKind::Function,
            ..
        } if name == "callback"
    )));
    assert!(entry.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call {
            name,
            receiver: Some(receiver),
            call_kind: bonsai_lang_api::CallKind::Method,
            ..
        } if name == "dynamic.call" && receiver == "dynamic"
    )));
    let graph = workspace.resolved_call_graph();
    assert!(graph.local_callable_bindings().any(|(caller, name, target)| {
        caller == bonsai_common::FuncId::new(entry.symbol.raw())
            && name == "callback"
            && target == bonsai_common::FuncId::new(callback.symbol.raw())
    }));
    assert!(
        graph
            .callees_of(bonsai_common::FuncId::new(entry.symbol.raw()))
            .any(|edge| edge.to == bonsai_common::FuncId::new(callback.symbol.raw())),
        "the exact local Proc invocation must resolve to its bound lambda: {:#?}",
        entry.flow_events,
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

#[test]
fn ruby_property_writer_lowers_to_an_assignment_scoped_place() {
    let events = ruby_decl_events(
        r#"
def update(response, value)
  response.headers = value
end
"#,
        "update",
    );

    assert!(
        events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_name, .. }
                if target == "response.headers" && source_name.as_deref() == Some("value")
        )),
        "events={events:#?}"
    );
}

#[test]
fn executable_class_body_and_trailing_block_are_exact_callback_facts() {
    let db = db_with(
        r#"
class App < Framework::Base
  route do |request|
    sink(request)
  end
end
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Ruby file");
    let index = db.decl_index(file).expect("Ruby declaration index");
    let class_body = index
        .defs
        .iter()
        .find(|decl| decl.name.starts_with("<class-body@"))
        .expect("Ruby class body must retain its executable registration calls");
    let (route_span, block_span) = class_body
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { span, name, args, .. } if name == "route" => {
                args.first().map(|argument| (*span, argument.span))
            }
            _ => None,
        })
        .expect("class-body route call must include its trailing block argument");
    assert_eq!(
        class_body.parent,
        index
            .defs
            .iter()
            .find(|decl| decl.name == "App")
            .map(|decl| decl.symbol)
    );
    assert!(
        index.call_argument_values.iter().any(|fact| {
            fact.call_span == route_span
                && fact.argument_index == 0
                && fact.argument_span == block_span
                && fact.inline_callback_params == ["request"]
                && fact.inline_callback_span == Some(block_span)
        }),
        "Ruby trailing block must lower to one exact inline callback fact: {:#?}",
        index.call_argument_values
    );
}
