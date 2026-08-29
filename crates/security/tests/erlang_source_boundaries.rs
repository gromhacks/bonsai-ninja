//! Erlang callback source boundaries must be owned by parsed module behaviour
//! facts. Function names and arity alone are deliberate collision negatives.

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

fn workspace(source: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("server.erl".to_string(), Arc::<str>::from(source));
    ws
}

fn source_ids(source: &str) -> Vec<String> {
    let ws = workspace(source);
    let pack = load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    source_inventory(&ws, &pack, SecurityInventoryOptions::default())
        .expect("Erlang source inventory")
        .into_iter()
        .map(|source| source.rule_id)
        .collect()
}

#[test]
fn gen_server_callbacks_require_exact_module_behaviour_ownership() {
    let positive = source_ids(
        r#"
-module(server).
-behaviour(gen_server).
-export([handle_call/3, handle_cast/2]).
handle_call(Request, From, State) -> {reply, Request, State}.
handle_cast(Message, State) -> {noreply, State}.
"#,
    );
    for expected in [
        "erlang.source.gen_server_handle_call",
        "erlang.source.gen_server_handle_cast",
    ] {
        assert!(
            positive.iter().any(|id| id == expected),
            "missing {expected}: {positive:?}"
        );
    }

    for collision in [
        r#"
-module(server).
-export([handle_call/3, handle_cast/2]).
handle_call(Request, From, State) -> {reply, Request, State}.
handle_cast(Message, State) -> {noreply, State}.
"#,
        r#"
-module(server).
-behaviour(application).
-export([handle_call/3, handle_cast/2]).
handle_call(Request, From, State) -> {reply, Request, State}.
handle_cast(Message, State) -> {noreply, State}.
"#,
    ] {
        let ids = source_ids(collision);
        assert!(
            ids.iter().all(|id| !id.starts_with("erlang.source.gen_server_")),
            "same callback spelling without gen_server ownership must fail closed: {ids:?}"
        );
    }
}

#[test]
fn gen_server_messages_enter_the_idg() {
    let ws = workspace(
        r#"
-module(server).
-behaviour(gen_server).
-export([handle_call/3, handle_cast/2]).
handle_call(Request, From, State) -> {reply, os:cmd(Request), State}.
handle_cast(Message, State) -> os:cmd(Message), {noreply, State}.
"#,
    );
    let pack = load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("Erlang taint analysis");
    let source_rules = report
        .findings
        .iter()
        .map(|finding| finding.finding.source.rule_id.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "erlang.source.gen_server_handle_call",
        "erlang.source.gen_server_handle_cast",
    ] {
        assert!(
            source_rules.contains(&expected),
            "{expected} must propagate to os:cmd through the production IDG: {source_rules:?}"
        );
    }
}

#[test]
fn qualified_request_map_matches_enter_the_idg_without_local_spelling_collisions() {
    let positive = workspace(
        r#"
-module(handler).
-export([init/2]).
init(Req, State) ->
    #{host := Host} = cowboy_req:match_qs([{host, [], <<>>}], Req),
    os:cmd(Host),
    {ok, Req, State}.
"#,
    );
    let pack = load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let report =
        run_taint_analysis(&positive, &pack, TaintAnalysisOptions::default()).expect("Erlang taint analysis");
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "erlang.source.cowboy_match_qs"
                && finding.finding.sink.rule_id == "erlang.cmdi.os_cmd"
        }),
        "qualified request result destructuring must reach the sink: {:#?}",
        report.findings
    );

    let collision = workspace(
        r#"
-module(handler).
-export([init/2]).
init(Req, State) ->
    #{host := Host} = local_cowboy_req:match_qs([{host, [], <<>>}], Req),
    os:cmd(Host),
    {ok, Req, State}.
"#,
    );
    let collision_report = run_taint_analysis(&collision, &pack, TaintAnalysisOptions::default())
        .expect("Erlang collision analysis");
    assert!(
        collision_report
            .findings
            .iter()
            .all(|finding| { finding.finding.source.rule_id != "erlang.source.cowboy_match_qs" }),
        "same terminal spelling on another parsed module must fail closed: {:#?}",
        collision_report.findings
    );
}
