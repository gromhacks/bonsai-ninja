use bonsai_conformance::run_language_suite;
use bonsai_lang_api::FlowEvent;
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
