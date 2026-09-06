use bonsai_lang_api::{DeclIndex, FlowEvent};
use std::sync::Arc;

fn lower(source: &str) -> Arc<DeclIndex> {
    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        vec![("identity.ex".to_string(), source.to_string())],
    );
    let workspace = runner.workspace();
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("Elixir declarations")
}

fn guarded(attributes: &str, body: &str) -> String {
    format!(
        r#"defmodule Gateway do
  {attributes}
  def run(target, other) do
    case Decoder.parse(target) do
      %Decoder{{protocol: "secure", server: server}} when server in @trusted ->
        {body}
      _ -> ""
    end
  end
end
"#
    )
}

#[test]
fn dynamic_or_conditional_attribute_definitions_cannot_supply_a_finite_guard() {
    for attributes in [
        "@trusted ~w(service.internal)\n  @trusted load_hosts()",
        "@trusted load_hosts()\n  @trusted ~w(service.internal)",
        "if enabled?(), do: (@trusted ~w(service.internal))",
        "@trusted ~w(service.internal)a",
        "@trusted ~w(service.internal)c",
        "import CustomSigils, only: [sigil_w: 2]\n  @trusted ~w(service.internal)",
    ] {
        let index = lower(&guarded(attributes, "sink(target, [], redirects: false)"));
        assert!(
            index.compiler_guards.is_empty(),
            "{attributes}: {:?}",
            index.compiler_guards
        );
    }
}

#[test]
fn finite_attribute_evidence_is_owned_by_its_exact_module() {
    let source = format!(
        "defmodule Other do\n  @trusted ~w(service.internal)\nend\n{}",
        guarded("@trusted load_hosts()", "sink(target, [], redirects: false)")
    );
    let index = lower(&source);
    assert!(index.compiler_guards.is_empty(), "{:?}", index.compiler_guards);

    let source = format!(
        "defmodule Other do\n  @trusted load_hosts()\nend\n{}",
        guarded(
            "@trusted ~w(service.internal)",
            "sink(target, [], redirects: false)"
        )
    );
    let index = lower(&source);
    assert_eq!(index.compiler_guards.len(), 1, "{:?}", index.compiler_guards);
}

#[test]
fn a_guard_cannot_authorize_a_rebound_or_shadowed_call_argument() {
    for body in [
        "target = other\n        sink(target, [], redirects: false)",
        "fn target -> sink(target, [], redirects: false) end",
    ] {
        let index = lower(&guarded("@trusted ~w(service.internal)", body));
        assert!(
            index.compiler_guards.iter().all(|fact| !fact
                .evidence
                .iter()
                .any(|evidence| { evidence == "guarded-argument:0=scrutinee-argument:0" })),
            "{body}: {:?}",
            index.compiler_guards
        );
    }
}

#[test]
fn quoted_remote_target_names_preserve_internal_whitespace() {
    let index = lower("defmodule App do\n  def run(value), do: :\"with space\".consume(value)\nend\n");
    let run = index.defs.iter().find(|decl| decl.name == "run").unwrap();
    assert!(
        run.flow_events.iter().any(|event| matches!(
            event, FlowEvent::Call { name, .. } if name == ":\"with space\".consume"
        )),
        "{:?}",
        run.flow_events
    );
}

#[test]
fn nested_local_callable_invocations_do_not_execute_in_the_outer_function() {
    let index = lower("defmodule App do\n  def run(callback), do: fn -> callback.() end\nend\n");
    let run = index.defs.iter().find(|decl| decl.name == "run").unwrap();
    assert!(
        run.flow_events.iter().all(|event| !matches!(
            event, FlowEvent::Call { name, .. } if name == "callback"
        )),
        "{:?}",
        run.flow_events
    );
    assert!(index
        .defs
        .iter()
        .filter(|decl| decl.symbol != run.symbol)
        .any(|decl| {
            decl.flow_events
                .iter()
                .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "callback"))
        }));
}
