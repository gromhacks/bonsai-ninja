use bonsai_conformance::run_language_suite;
use bonsai_lang_api::{AssignValueKind, FlowEvent};
use std::sync::Arc;

fn collect_assign_targets(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } => out.push(target.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assign_targets(then_events, out);
                collect_assign_targets(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assign_targets(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assign_targets(body, out);
                collect_assign_targets(catch_events, out);
                collect_assign_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

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
fn atom_list_call_argument_retains_exact_static_sequence_values() {
    use bonsai_lang_api::StaticScalarValue;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "state.ex".to_string(),
            r#"
defmodule State do
  def decode(blob), do: :erlang.binary_to_term(blob, [:safe])
  def dynamic(blob, option), do: :erlang.binary_to_term(blob, [option])
end
"#
            .to_string(),
        )],
    );
    let workspace = runner.workspace();
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Elixir compiler index");
    let calls = index
        .call_argument_values
        .iter()
        .filter(|fact| fact.argument_index == 1)
        .collect::<Vec<_>>();

    assert!(
        calls.iter().any(|fact| {
            fact.exact_static_sequence_values.as_ref()
                == Some(&vec![Some(StaticScalarValue::String("safe".to_string()))])
        }),
        "the exact atom list must be compiler data: {calls:#?}"
    );
    assert!(
        calls
            .iter()
            .any(|fact| { fact.exact_static_sequence_values.as_ref() == Some(&vec![None]) }),
        "a dynamic list item must remain unknown: {calls:#?}"
    );
}

#[test]
fn module_use_arguments_are_generic_owner_facts_for_destructured_parameters() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            r#"defmodule Controller do
  use Web, :controller
  def show(conn, %{"id" => id}), do: {conn, id}
end

defmodule Worker do
  use Jobs, :worker
  def show(context, %{"id" => id}), do: {context, id}
end
"#
            .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let controller = idx
        .defs
        .iter()
        .find(|decl| decl.qualified_name.as_deref() == Some("Controller"))
        .expect("controller module declaration");
    let worker = idx
        .defs
        .iter()
        .find(|decl| decl.qualified_name.as_deref() == Some("Worker"))
        .expect("worker module declaration");
    assert_eq!(controller.bases, vec!["use_arg_controller".to_string()]);
    assert_eq!(worker.bases, vec!["use_arg_worker".to_string()]);

    let shows = idx
        .defs
        .iter()
        .filter(|decl| decl.name == "show")
        .collect::<Vec<_>>();
    assert_eq!(shows.len(), 2);
    assert!(shows.iter().any(|decl| decl.parent == Some(controller.symbol)));
    assert!(shows.iter().any(|decl| decl.parent == Some(worker.symbol)));
    assert!(shows
        .iter()
        .all(|decl| decl.params.get(1).is_some_and(|param| param == "_arg1")));
}

#[test]
fn macro_control_flow_is_structured() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(items) do\n    try do\n      for it <- items do\n        if it != nil, do: sink(it)\n      end\n    rescue\n      e -> {:error, e}\n    end\n  end\nend\n".to_string(),
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
        "expected Elixir for macro to emit Loop: {:?}",
        decl.flow_events
    );
    assert!(
        contains_branch(&decl.flow_events),
        "expected Elixir if macro to emit Branch: {:?}",
        decl.flow_events
    );
    assert!(
        contains_call(&decl.flow_events, "sink"),
        "the compiler-special for body must execute in run's flow: {:?}",
        decl.flow_events
    );
}

#[test]
fn external_enum_callback_keeps_separate_scope_without_invented_execution() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(items) do\n    Enum.each(items, fn item -> sink(item) end)\n  end\nend\n"
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
        .expect("run declaration");
    let callback = idx
        .defs
        .iter()
        .find(|decl| decl.name.starts_with("<lambda@") && contains_call(&decl.flow_events, "sink"))
        .expect("Enum.each callback declaration");

    assert!(contains_call(&run.flow_events, "Enum.each"));
    assert!(
        !contains_call(&run.flow_events, "sink"),
        "an external call accepting a callback is not compiler proof that it executes: {run:#?}"
    );
    assert!(idx.call_argument_values.iter().any(|fact| {
        fact.inline_callback_span == Some(callback.span) && fact.inline_callback_params == ["item"]
    }));
    let graph = ws.resolved_call_graph();
    assert!(
        graph
            .callees_of(bonsai_common::FuncId::new(run.symbol.raw()))
            .all(|edge| edge.to != bonsai_common::FuncId::new(callback.symbol.raw())),
        "the unresolved external Enum callback must remain a callable value, not an execution edge"
    );
}

#[test]
fn case_patterns_bind_values_but_not_map_keys_or_atoms() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            r#"defmodule Main do
  def run(subject) do
    case subject do
      %{value: value, nested: %{item: item}} -> sink(value, item)
      {:ok, result} -> sink(result)
    end
  end
end
"#
            .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let run = idx.defs.iter().find(|decl| decl.name == "run").expect("run decl");
    let mut targets = Vec::new();
    collect_assign_targets(&run.flow_events, &mut targets);

    for expected in ["value", "item", "result"] {
        assert!(
            targets.iter().any(|target| target == expected),
            "missing {expected}: {targets:?}"
        );
    }
    assert!(
        !targets
            .iter()
            .any(|target| matches!(target.as_str(), "nested" | "ok")),
        "{targets:?}"
    );
}

#[test]
fn guarded_case_arm_emits_exact_relational_compiler_evidence() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "guard.ex".to_string(),
            r#"defmodule Gateway do
  @trusted ~w(service.internal archive.internal)
  @dynamic load_hosts()

  def safe(target) do
    case Decoder.parse(target) do
      %Decoder{protocol: "secure", server: server} when server in @trusted ->
        Client.fetch(target, [], redirects: false)
      _ -> ""
    end
  end

  def wrong_parser(target) do
    case Other.parse(target) do
      %Other{protocol: "secure", server: server} when server in @trusted ->
        Client.fetch(target, [], redirects: false)
      _ -> ""
    end
  end

  def dynamic_collection(target) do
    case Decoder.parse(target) do
      %Decoder{protocol: "secure", server: server} when server in @dynamic ->
        Client.fetch(target, [], redirects: false)
      _ -> ""
    end
  end
end
"#
            .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Elixir declaration index");
    assert_eq!(index.compiler_guards.len(), 2, "{:#?}", index.compiler_guards);

    let safe = index
        .compiler_guards
        .iter()
        .find(|fact| {
            fact.evidence
                .contains(&"scrutinee-call:Decoder.parse".to_string())
        })
        .expect("exact static guarded arm");
    for required in [
        "scrutinee-root-unshadowed",
        "pattern-type:Decoder",
        "pattern-type=scrutinee-root",
        "static-field:protocol=string:secure",
        "finite-string-membership-field:server",
        "guarded-argument:0=scrutinee-argument:0",
        "guarded-static-field:2.redirects=boolean:false",
    ] {
        assert!(
            safe.evidence.iter().any(|fact| fact == required),
            "missing {required}: {safe:#?}; arguments={:#?}",
            index.call_argument_values
        );
    }
    assert!(index
        .compiler_guards
        .iter()
        .any(|fact| fact.evidence.contains(&"scrutinee-call:Other.parse".to_string())));
    assert!(index
        .compiler_guards
        .iter()
        .all(|fact| !fact.evidence.iter().any(|evidence| evidence.contains("@dynamic"))));

    let collision = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        vec![(
            "collision.ex".to_string(),
            r#"defmodule Decoder do
  defstruct [:protocol, :server]
  def parse(value), do: value
end

defmodule Gateway do
  @trusted ~w(service.internal archive.internal)
  def run(target) do
    case Decoder.parse(target) do
      %Decoder{protocol: "secure", server: server} when server in @trusted ->
        Client.fetch(target, [], redirects: false)
      _ -> ""
    end
  end
end
"#
            .to_string(),
        )],
    );
    let collision_ws = collision.workspace();
    let collision_file = collision_ws.vfs().all_files()[0];
    let collision_index = collision_ws
        .db()
        .decl_index(collision_file)
        .expect("collision declaration index");
    let local = collision_index
        .compiler_guards
        .iter()
        .find(|fact| {
            fact.evidence
                .contains(&"scrutinee-call:Decoder.parse".to_string())
        })
        .expect("local same-spelled syntax remains a candidate");
    assert!(
        !local.evidence.contains(&"scrutinee-root-unshadowed".to_string()),
        "a same-file module must not receive runtime-global evidence: {local:#?}"
    );
}

#[test]
fn piped_map_argument_retains_exact_fields_and_formal_pattern_projection() {
    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        vec![(
            "projection.ex".to_string(),
            r#"defmodule Gateway do
  def dispatch(%{"value" => value}) do
    %{selected: value, sibling: "constant", mode: :strict}
    |> Worker.consume()
  end
end

defmodule Worker do
  def consume(%{selected: selected} = envelope) do
    sink(selected)
  end
end
"#
            .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Elixir compiler index");
    let dispatch = index
        .defs
        .iter()
        .find(|decl| decl.name == "dispatch")
        .expect("dispatch declaration");
    let call_span = dispatch
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name == "Worker.consume" => Some(*span),
            _ => None,
        })
        .expect("resolved piped call");
    let call = index
        .call_argument_values
        .iter()
        .find(|fact| {
            fact.value_flow
                .aggregate_fields
                .iter()
                .any(|field| field.name == "selected")
        })
        .unwrap_or_else(|| {
            panic!(
                "piped map argument fact missing from compiler index: {:#?}",
                index.call_argument_values
            )
        });
    assert_eq!(
        call.call_span, call_span,
        "aggregate argument evidence must share the exact lowered call identity"
    );
    let selected = call
        .value_flow
        .aggregate_fields
        .iter()
        .find(|field| field.name == "selected")
        .expect("selected aggregate field");
    assert_eq!(selected.value.place.as_deref(), Some("value"));
    let sibling = call
        .value_flow
        .aggregate_fields
        .iter()
        .find(|field| field.name == "sibling")
        .expect("sibling aggregate field");
    assert!(sibling.value.place.is_none());
    assert!(sibling.value.source_names.is_empty());
    assert!(call.exact_static_aggregate_fields.iter().any(|field| {
        field.path == ["mode"]
            && field.value == bonsai_lang_api::StaticScalarValue::String("strict".to_string())
    }));

    let consume = index
        .defs
        .iter()
        .find(|decl| decl.name == "consume")
        .expect("consume declaration");
    assert!(consume.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign {
            target,
            source_name: Some(source),
            ..
        } if target == "selected" && source == "envelope.selected"
    )));
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
fn cond_expression_assignment_preserves_branch_value_dependencies() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(input) do\n    routed = input\n    routed = cond do\n      routed == \"\" -> routed\n      true -> routed\n    end\n    sink(routed)\n  end\nend\n"
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
    let routed_assignments = run
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                value_kind,
                ..
            } if target == "routed" => Some((source_name, source_call, source_names, value_kind)),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(routed_assignments.len(), 2, "{:#?}", run.flow_events);
    let second = routed_assignments[1];
    assert_eq!(second.0, &None, "{:#?}", run.flow_events);
    assert_eq!(second.1, &None, "{:#?}", run.flow_events);
    assert_eq!(second.2, &["routed".to_string()], "{:#?}", run.flow_events);
    assert_eq!(
        second.3,
        &Some(AssignValueKind::Compound),
        "{:#?}",
        run.flow_events
    );
}

#[test]
fn case_expression_assignment_preserves_arm_value_dependencies_not_subject_calls() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(input) do\n    selected = case String.length(input) do\n      0 -> \"clean\"\n      _ -> input\n    end\n    sink(selected)\n  end\nend\n"
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
    let selected = run
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
            } if target == "selected" => Some((source_call, source_call_args, source_names, value_kind)),
            _ => None,
        })
        .expect("case assignment");

    assert_eq!(selected.0, &None);
    assert!(selected.1.is_empty());
    assert_eq!(selected.2, &["input".to_string()]);
    assert_eq!(selected.3, &Some(AssignValueKind::Compound));
}

#[test]
fn try_expression_assignment_preserves_body_and_rescue_values() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(primary, fallback) do\n    value = try do\n      primary\n    rescue\n      _ -> fallback\n    end\n    sink(value)\n  end\nend\n"
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
    let assignment = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_names,
                value_kind,
                ..
            } if target == "value" => Some((source_call, source_names, value_kind)),
            _ => None,
        })
        .expect("value assignment");

    assert_eq!(assignment.0, &None, "{:#?}", run.flow_events);
    assert_eq!(
        assignment.1,
        &["fallback".to_string(), "primary".to_string()],
        "{:#?}",
        run.flow_events
    );
    assert_eq!(assignment.2, &Some(AssignValueKind::Compound));
}

#[test]
fn maps_returned_from_try_join_each_field_without_callee_name_sources() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(envelope, routed, user) do\n    valid = try do\n      %{envelope | cmd: routed, user: user, length: String.length(routed)}\n    rescue\n      _ -> %{envelope | cmd: routed, user: user, length: 0}\n    end\n    sink(valid.cmd)\n  end\nend\n"
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
    let field = |wanted: &str| {
        run.flow_events
            .iter()
            .find(|event| matches!(event, FlowEvent::Assign { target, .. } if target == wanted))
    };

    assert!(matches!(
        field("valid.cmd"),
        Some(FlowEvent::Assign { source_names, .. }) if source_names == &["routed".to_string()]
    ));
    assert!(matches!(
        field("valid.user"),
        Some(FlowEvent::Assign { source_names, .. }) if source_names == &["user".to_string()]
    ));
    assert!(field("valid.length").is_some());
    assert!(run.flow_events.iter().all(|event| !matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target.starts_with("valid.")
                && source_names.iter().any(|source| source == "String" || source == "length")
    )));
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

    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_names, .. }
                if target == "size" && source_names == &["c.capacity"]
        )),
        "events={:?}",
        run.flow_events
    );
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
fn atom_qualified_call_preserves_complete_target() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(value) do\n    :runtime.stop(value)\n  end\nend\n".to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let run = idx.defs.iter().find(|decl| decl.name == "run").expect("run decl");

    assert!(run
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == ":runtime.stop")));
}

#[test]
fn exact_value_field_assignment_is_a_projection_not_a_call_result() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(envelope) do\n    cmd = envelope.payload.cmd\n    sink(cmd)\n  end\nend\n"
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
        FlowEvent::Assign {
            target,
            source_name: Some(source),
            source_call: None,
            source_call_args,
            value_kind: Some(AssignValueKind::Compound),
            ..
        } if target == "cmd" && source == "envelope.payload.cmd" && source_call_args.is_empty()
    )));
    assert!(!run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, .. }
            if name == "envelope.payload" || name == "envelope.payload.cmd"
    )));
    let fact = idx
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("cmd"))
        .expect("cmd assignment fact");
    assert_eq!(fact.value_flow.place.as_deref(), Some("envelope.payload.cmd"));
    assert!(fact.call_sites.is_empty());
    assert_eq!(fact.direct_call_name, None);
}

#[test]
fn value_field_argument_does_not_hide_its_real_enclosing_call() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(envelope) do\n    cmd = normalize(envelope.cmd)\n    sink(cmd)\n  end\nend\n"
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

    assert!(run
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "normalize")));
    assert!(!run
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "envelope.cmd")));
    assert!(run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign {
            target,
            source_call: Some(source_call),
            ..
        } if target == "cmd" && source_call == "normalize"
    )));
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

#[test]
fn guarded_function_head_retains_signature_body_and_pipe_argument_order() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(input, suffix) when is_binary(input) do\n    input |> transform(suffix)\n  end\nend\n"
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
        .expect("guarded run declaration");

    assert_eq!(run.params, ["input", "suffix"]);
    let args = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "transform" => Some(args),
            _ => None,
        })
        .expect("pipeline target call");
    assert_eq!(
        args.iter().map(|arg| arg.place.as_deref()).collect::<Vec<_>>(),
        vec![Some("input"), Some("suffix")]
    );
}

#[test]
fn parameter_patterns_emit_field_element_and_descendant_bindings() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def handle(%{event: {kind, [first | rest]}}) do\n    sink(kind, first, rest)\n  end\nend\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let handle = idx
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert_eq!(handle.params, ["_arg0"]);
    let bindings = handle
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_names,
                value_kind: Some(AssignValueKind::Destructure),
                ..
            } => Some((target.as_str(), source_names.as_slice())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(bindings.contains(&("kind", &["_arg0.event.0".to_string()][..])));
    assert!(bindings.contains(&("first", &["_arg0.event.1.0".to_string()][..])));
    assert!(bindings.contains(&("rest", &["_arg0.event.1.*".to_string()][..])));
}

#[test]
fn access_call_distinguishes_literal_atom_and_dynamic_keys() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.ex".to_string(),
            "defmodule Main do\n  def run(map, key) do\n    sink(map[:cmd], map[key])\n  end\nend\n"
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
        .expect("run declaration");
    let args = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "sink" => Some(args),
            _ => None,
        })
        .expect("sink call");

    assert_eq!(args[0].place.as_deref(), Some("map.cmd"));
    assert_ne!(args[1].place.as_deref(), Some("map.key"));
    assert!(args[1].source_names.iter().any(|name| name == "map"));
    assert!(args[1].source_names.iter().any(|name| name == "key"));
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
