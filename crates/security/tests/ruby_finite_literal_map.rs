use std::path::{Path, PathBuf};

use bonsai_security::{FindingStatus, TaintAnalysisOptions};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

#[test]
fn finite_literal_map_selector_requires_one_dominating_unmodified_local_map() {
    let source = r#"
require "actionpack"
require "activerecord"

def proven
  input = request.query_parameters()
  choices = {"first" => "printf alpha", "second" => "printf beta"}
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

def wrong_selector
  input = request.query_parameters()
  choices = {"first" => "printf alpha"}
  selected = choices.lookup(input, "printf fallback")
  find_by_sql(selected)
end

def non_map
  input = request.query_parameters()
  choices = build_choices(input)
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

def dynamic_value
  input = request.query_parameters()
  choices = {"first" => input}
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

def dynamic_fallback
  input = request.query_parameters()
  choices = {"first" => "printf alpha"}
  selected = choices.fetch(input, input)
  find_by_sql(selected)
end

def mutated
  input = request.query_parameters()
  choices = {"first" => "printf alpha"}
  choices["second"] = input
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

def alias_escape
  input = request.query_parameters()
  choices = {"first" => "printf alpha"}
  escaped = choices
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

def reassigned
  input = request.query_parameters()
  choices = {"first" => "printf alpha"}
  choices = {"second" => "printf beta"}
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

def branch_ambiguous
  input = request.query_parameters()
  if input
    choices = {"first" => "printf alpha"}
  else
    choices = {"second" => "printf beta"}
  end
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

def sibling_with_static_map
  input = request.query_parameters()
  choices = {"first" => "printf alpha"}
  choices.fetch(input, "printf fallback")
end

def sibling_collision
  input = request.query_parameters()
  choices = build_choices(input)
  selected = choices.fetch(input, "printf fallback")
  find_by_sql(selected)
end

class OrderRepo
  SORTABLE = {"total" => :total, "created_at" => :created_at}.freeze
  MUTABLE = {"total" => :total}

  def self.constant_proven
    input = request.query_parameters()
    selected = SORTABLE.fetch(input, :id)
    find_by_sql(selected)
  end

  def self.constant_nested_proven
    input = request.query_parameters()
    find_by_sql(SORTABLE.fetch(input, :id))
  end

  def self.constant_nested_escape
    input = request.query_parameters()
    find_by_sql(SORTABLE.fetch(input, :id).to_s + input)
  end

  def self.mutable_constant
    input = request.query_parameters()
    selected = MUTABLE.fetch(input, :id)
    find_by_sql(selected)
  end
end
"#;
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("finite_map.rb", source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let report = bonsai_security::run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("Ruby finite-map taint analysis");

    let sql_finding = |function: &str| {
        report
            .findings
            .iter()
            .find(|finding| {
                finding.finding.sink.rule_id == "ruby.sqli.ar_find_by_sql"
                    && finding.finding.sink.enclosing_fn.as_deref() == Some(function)
            })
            .unwrap_or_else(|| panic!("missing SQL finding for {function}: {:#?}", report.findings))
    };

    let proven = &sql_finding("proven").finding;
    assert_eq!(proven.status, FindingStatus::Sanitized, "{proven:#?}");
    assert!(
        proven
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "ruby.sanitizer.finite_literal_map_fetch"),
        "the exact matcher-approved selector call must receive sanitizer credit: {proven:#?}"
    );

    let constant_proven = &sql_finding("constant_proven").finding;
    assert_eq!(
        constant_proven.status,
        FindingStatus::Sanitized,
        "a frozen complete constant map with a literal-symbol fallback is finite: {constant_proven:#?}"
    );
    assert!(
        constant_proven
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "ruby.sanitizer.finite_literal_map_fetch"),
        "the exact constant-map selector must receive sanitizer credit: {constant_proven:#?}"
    );

    let constant_nested_proven = &sql_finding("constant_nested_proven").finding;
    assert_eq!(
        constant_nested_proven.status,
        FindingStatus::Sanitized,
        "an exact selector nested directly in the consumer remains finite: {constant_nested_proven:#?}"
    );

    for function in [
        "wrong_selector",
        "non_map",
        "dynamic_value",
        "dynamic_fallback",
        "mutated",
        "alias_escape",
        "reassigned",
        "branch_ambiguous",
        "sibling_collision",
        "mutable_constant",
        "constant_nested_escape",
    ] {
        let finding = &sql_finding(function).finding;
        assert_eq!(
            finding.status,
            FindingStatus::Unsanitized,
            "{function} must retain an unsanitized finding: {finding:#?}"
        );
        assert!(
            finding
                .sanitizers_seen
                .iter()
                .all(|sanitizer| sanitizer.rule_id != "ruby.sanitizer.finite_literal_map_fetch"),
            "{function} must not borrow finite-map sanitizer credit: {finding:#?}"
        );
    }
}
