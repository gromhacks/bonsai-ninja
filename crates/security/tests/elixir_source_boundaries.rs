//! Exact Elixir callback source-boundary coverage.
//!
//! Framework identities remain in rule data. These tests prove that the
//! adapter's ordinary callable/parameter facts seed the production IDG while
//! a same-shaped application callback stays outside the boundary.

use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn workspace(source: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("processor.ex", source);
    ws
}

#[test]
fn broadway_message_parameter_seeds_the_production_idg_without_name_collision() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let positive = workspace(
        r#"alias Broadway
defmodule Processor do
  def handle_message(_processor, message, context) do
    System.cmd(message, [])
    context
  end
end
"#,
    );
    let report = bonsai_security::run_taint_analysis(&positive, &pack, Default::default())
        .expect("Broadway taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.source.rule_id == "elixir.broadway.message"),
        "the exact Broadway callback parameter must reach the command sink: {:#?}",
        report.findings
    );

    let collision = workspace(
        r#"alias Broadway
defmodule Processor do
  def deliver(_processor, message, context) do
    System.cmd(message, [])
    context
  end
end
"#,
    );
    let report = bonsai_security::run_taint_analysis(&collision, &pack, Default::default())
        .expect("collision-negative taint analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.source.rule_id != "elixir.broadway.message"),
        "same-arity application callbacks must not acquire Broadway source semantics: {:#?}",
        report.findings
    );
}

#[test]
fn controller_role_seeds_named_and_destructured_payloads_without_worker_collision() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let positive = workspace(
        r#"defmodule Controller do
  use Web, :controller
  def execute(_conn, %{"command" => command}) do
    System.cmd("sh", ["-c", command])
  end
end
"#,
    );
    let report = bonsai_security::run_taint_analysis(&positive, &pack, Default::default())
        .expect("controller taint analysis");
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "elixir.phoenix.params"
                && finding.finding.sink.rule_id == "elixir.cmdi.system_cmd_shell_args"
        }),
        "the syntax-proven controller payload must reach the shell argument: {:#?}",
        report.findings
    );

    let collision = workspace(
        r#"defmodule Worker do
  use Jobs, :worker
  def execute(_context, %{"command" => command}) do
    System.cmd("sh", ["-c", command])
  end
end
"#,
    );
    let report = bonsai_security::run_taint_analysis(&collision, &pack, Default::default())
        .expect("worker collision-negative taint analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.source.rule_id != "elixir.phoenix.params"),
        "same-shaped application callbacks without the controller role must remain ordinary data: {:#?}",
        report.findings
    );
}

#[test]
fn controller_input_survives_case_expression_result_but_not_literal_arms() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let positive = workspace(
        r#"defmodule Controller do
  use Web, :controller
  def show(_conn, params) do
    value = Map.get(params, "q", "")
    heading = case String.length(value) do
      0 -> "everything"
      _ -> value
    end
    Phoenix.HTML.raw(heading)
  end
end
"#,
    );
    let report = bonsai_security::run_taint_analysis(&positive, &pack, Default::default())
        .expect("case-expression taint analysis");
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "elixir.phoenix.params"
                && finding.finding.sink.rule_id == "elixir.xss.phoenix_html_raw"
        }),
        "an arm that returns the request-derived value must taint the case result: {:#?}",
        report.findings
    );

    let collision = workspace(
        r#"defmodule Controller do
  use Web, :controller
  def show(_conn, params) do
    value = Map.get(params, "q", "")
    heading = case String.length(value) do
      0 -> "everything"
      _ -> "something"
    end
    Phoenix.HTML.raw(heading)
  end
end
"#,
    );
    let report = bonsai_security::run_taint_analysis(&collision, &pack, Default::default())
        .expect("literal-arm collision analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "elixir.xss.phoenix_html_raw"),
        "literal-only case arms must overwrite the input-derived condition: {:#?}",
        report.findings
    );
}
