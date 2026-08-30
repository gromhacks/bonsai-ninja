use bonsai_security::{run_taint_analysis, FindingStatus, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn analyze(options: TaintAnalysisOptions, decoder_options: &str) -> bonsai_security::TaintAnalysisReport {
    let source = format!(
        r#"-include_lib("cowboy/include/cowboy.hrl").
-module(example).
-export([decode/1]).
decode(Req) ->
    {{ok, Body, _Req1}} = cowboy_req:read_body(Req),
    binary_to_term(Body, {decoder_options}).
"#
    );
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write("src/example.erl", Arc::<str>::from(source));
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    run_taint_analysis(&workspace, &pack, options).expect("run Erlang taint analysis")
}

#[test]
fn exact_safe_option_clears_the_deserialization_finding() {
    let report = analyze(TaintAnalysisOptions::default(), "[safe]");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "erlang.deser.binary_to_term_2"),
        "the exact adapter-decoded safe option must clear the relevant sink class: {:#?}",
        report.findings
    );

    let diagnostic = analyze(
        TaintAnalysisOptions {
            show_sanitized: true,
            ..Default::default()
        },
        "[safe]",
    );
    let finding = diagnostic
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "erlang.deser.binary_to_term_2")
        .expect("sanitized diagnostic finding");
    assert_eq!(finding.finding.status, FindingStatus::Sanitized);
    assert!(finding
        .finding
        .sanitizers_seen
        .iter()
        .any(|sanitizer| sanitizer.rule_id == "erlang.sanitizer.binary_to_term_safe"));
}

#[test]
fn dynamic_decoder_options_remain_unsafe() {
    let report = analyze(TaintAnalysisOptions::default(), "Options");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "erlang.deser.binary_to_term_2")
        .unwrap_or_else(|| panic!("dynamic options must remain unsafe: {:#?}", report.findings));
    assert_eq!(finding.finding.status, FindingStatus::Unsanitized);
}
