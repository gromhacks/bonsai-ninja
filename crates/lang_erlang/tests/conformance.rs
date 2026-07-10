use bonsai_conformance::run_language_suite;
use bonsai_lang_api::FlowEvent;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [(
            "main.erl",
            "-module(main).\n-export([main/0]).\nmain() -> helper().\nhelper() -> ok.\n"
        )]
    );
}

#[test]
fn functional_loop_case_and_tail_return_are_structured() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.erl".to_string(),
            "-module(main).\n-export([run/2, handle/2]).\nrun(Conn, Items) ->\n  try\n    lists:foreach(fun(It) ->\n      case It of\n        undefined -> ok;\n        _ -> handle(Conn, It)\n      end\n    end, Items)\n  catch\n    _:E -> {error, E}\n  end.\nhandle(Conn, X) ->\n  Y = transform(Conn, X),\n  Y.\ntransform(_Conn, X) -> X.\n".to_string(),
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
    let handle = idx
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle decl should exist");

    assert!(
        contains_loop(&run.flow_events),
        "expected lists:foreach to emit Loop: {:?}",
        run.flow_events
    );
    assert!(
        contains_branch(&run.flow_events),
        "expected Erlang case to emit Branch: {:?}",
        run.flow_events
    );
    assert!(
        handle.flow_events.iter().any(|event| {
            matches!(event, FlowEvent::Return { value_name: Some(value_name), .. } if value_name == "Y")
        }),
        "expected Erlang tail expression to emit Return(value_name=Y): {:?}",
        handle.flow_events
    );
}

#[test]
fn map_literal_emits_field_scoped_assignments() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.erl".to_string(),
            "-module(main).\n-export([run/1]).\nrun(Args) -> B = #{tainted => Args, clean => \"safe\"}, sink(maps:get(clean, B)).\n".to_string(),
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
            if target == "B.tainted" && source_names == &["Args"]
    )));
    assert!(run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "B.clean" && source_names.is_empty()
    )));
    assert!(run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, args, .. }
            if name == "sink"
                && args.first().is_some_and(|arg| {
                    arg.value_text == "B.clean"
                        && arg.place.as_deref() == Some("B.clean")
                        && arg.source_names.iter().any(|source| source == "B.clean")
                })
    )));
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
