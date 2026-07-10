use bonsai_conformance::run_language_suite;
use bonsai_lang_api::{AssignValueKind, FlowEvent};
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [(
            "main.ex",
            "defmodule Main do\n  def main do\n    helper()\n  end\n  def helper do\n    :ok\n  end\nend\n"
        )]
    );
}

#[test]
fn macro_control_flow_is_structured() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(items) do\n    try do\n      Enum.each(items, fn it ->\n        if it != nil, do: sink(it)\n      end)\n    rescue\n      e -> {:error, e}\n    end\n  end\nend\n".to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let decl = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run decl should exist");

    assert!(
        contains_try(&decl.flow_events),
        "expected Elixir try macro to emit Try: {:?}",
        decl.flow_events
    );
    assert!(
        contains_loop(&decl.flow_events),
        "expected Enum.each to emit Loop: {:?}",
        decl.flow_events
    );
    assert!(
        contains_branch(&decl.flow_events),
        "expected Elixir if macro to emit Branch: {:?}",
        decl.flow_events
    );
}

#[test]
fn if_expression_assignment_uses_branch_values_not_condition_call() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def cond_(), do: true\n  def run(args) do\n    x = args\n    x = if cond_() do \"clean1\" else \"clean2\" end\n    sink(x)\n  end\nend\n".to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let decl = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run decl should exist");

    let clean_overwrite = decl
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } if target == "x" && value_kind == &Some(AssignValueKind::Literal) => {
                Some((source_call, source_call_args, source_names))
            }
            _ => None,
        })
        .expect("if expression assignment should be normalized as a clean overwrite");

    assert_eq!(clean_overwrite.0, &None);
    assert!(clean_overwrite.1.is_empty());
    assert!(clean_overwrite.2.is_empty());
}

#[test]
fn map_literal_emits_field_scoped_assignments() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(args) do\n    b = %{tainted: args, clean: \"safe\"}\n    sink(b.clean)\n  end\nend\n".to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let run = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run decl should exist");

    assert!(run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "b.tainted" && source_names == &["args"]
    )));
    assert!(run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "b.clean" && source_names.is_empty()
    )));
}

#[test]
fn value_dot_access_is_a_field_read_not_a_method_call() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(c) do\n    size = c.capacity * 2\n    System.version()\n    sink(size)\n  end\nend\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let run = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run decl should exist");

    assert!(run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "size" && source_names == &["c.capacity"]
    )));
    assert!(!run
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "c.capacity")));
    assert!(run
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "System.version")));
    assert!(idx
        .refs
        .iter()
        .any(|reference| reference.kind == bonsai_lang_api::RefKind::Read && reference.name == "capacity"));
}

#[test]
fn local_function_value_invocation_emits_structural_call() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(args) do\n    closure = fn -> sink(args) end\n    closure.()\n  end\nend\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let run = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run decl should exist");

    assert!(
        run.flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "closure")),
        "function-value invocation should be a Call fact: {:?}",
        run.flow_events
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
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => contains_loop(body) || contains_loop(catch_events) || contains_loop(finally_events),
        _ => false,
    })
}

fn contains_try(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Try { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => contains_try(then_events) || contains_try(else_events),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            contains_try(body)
        }
        _ => false,
    })
}
