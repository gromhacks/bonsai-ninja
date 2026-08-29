//! End-to-end C++ source-boundary coverage for compiler-lowered stream
//! extraction. The adapter test owns the CST contract; these tests prove the
//! exact rule consumes that fact and the IDG seeds only the output carrier.

use bonsai_security::{
    load_rulepack, run_taint_analysis, source_inventory, SecurityInventoryOptions, TaintAnalysisOptions,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn analyze(source: &str) -> (Vec<String>, Vec<String>) {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write("stream.cpp".to_string(), Arc::<str>::from(source));
    let pack = load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let compiler_calls = ws
        .db()
        .decl_index(file)
        .expect("C++ declaration index")
        .defs
        .iter()
        .flat_map(|decl| decl.flow_events.iter())
        .filter_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { name, receiver, .. } => Some((name.clone(), receiver.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        compiler_calls
            .iter()
            .any(|(name, receiver)| name == ">>" && receiver.as_deref() == Some("std::cin"))
            || !source.contains("std::cin"),
        "C++ compiler facts must retain the exact stream operator before rule matching: {compiler_calls:#?}"
    );
    let cin_rule = pack
        .all_rules()
        .into_iter()
        .find(|rule| rule.id == "cpp.input.cin_read")
        .expect("bundled C++ cin source rule");
    let direct_matches = bonsai_security::match_rule_against_facts(&ws, cin_rule);
    assert!(
        !source.contains("std::cin") || !direct_matches.is_empty(),
        "the exact source rule must consume the compiler call fact: rule={cin_rule:#?}, calls={compiler_calls:#?}"
    );
    let sources = source_inventory(&ws, &pack, SecurityInventoryOptions::default())
        .expect("source inventory")
        .into_iter()
        .map(|item| item.rule_id)
        .collect();
    let sinks = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default())
        .expect("taint analysis")
        .findings
        .into_iter()
        .map(|finding| finding.finding.sink.rule_id)
        .collect();
    (sources, sinks)
}

#[test]
fn std_cin_extraction_seeds_the_compiler_proven_destination() {
    let (sources, sinks) = analyze(
        r#"
#include <cstdlib>
#include <iostream>
#include <string>
int main() {
  std::string command;
  std::cin >> command;
  return std::system(command.c_str());
}
"#,
    );
    assert!(
        sources.iter().any(|id| id == "cpp.input.cin_read"),
        "exact stream extraction source must be inventoried: {sources:?}"
    );
    assert!(
        sinks.iter().any(|id| id.contains("cmdi")),
        "the output carrier must reach the command sink through the IDG: {sinks:?}"
    );
}

#[test]
fn same_named_member_and_numeric_shift_do_not_become_stdin_sources() {
    let (sources, sinks) = analyze(
        r#"
#include <cstdlib>
#include <iostream>
struct Input { int cin; };
int main() {
  Input local{8};
  int shifted = local.cin >> 1;
  return shifted == 4 ? std::system("echo safe") : 1;
}
"#,
    );
    assert!(
        sources.iter().all(|id| id != "cpp.input.cin_read"),
        "only exact std::cin extraction may satisfy the rule: {sources:?}"
    );
    assert!(
        sinks.iter().all(|id| !id.contains("cmdi")),
        "a numeric shift must not create a stdin taint flow: {sinks:?}"
    );
}

#[test]
fn typed_crow_body_inside_route_lambda_reaches_a_sink() {
    let (sources, sinks) = analyze(
        r#"
#include <crow.h>
#include <cstdlib>
void register_routes(crow::SimpleApp& app) {
  CROW_ROUTE(app, "/run")([](const crow::request& req) {
    auto command = req.body;
    return std::system(command.c_str());
  });
}
"#,
    );
    assert!(
        sources.iter().any(|id| id == "cpp.input.crow_request_body"),
        "the typed lambda parameter must make the exact Crow body source reachable: {sources:?}"
    );
    assert!(
        sinks.iter().any(|id| id.contains("cmdi")),
        "the compiler-proven body carrier must reach the command sink: {sinks:?}"
    );
}

#[test]
fn same_body_field_on_a_local_lambda_parameter_is_not_a_crow_source() {
    let (sources, _) = analyze(
        r#"
#include <crow.h>
struct LocalRequest { const char *body; };
void register_routes() {
  auto handler = [](const LocalRequest& req) { return req.body; };
  consume(handler);
}
"#,
    );
    assert!(
        sources.iter().all(|id| id != "cpp.input.crow_request_body"),
        "the body field requires the compiler-proven Crow request type: {sources:?}"
    );
}
