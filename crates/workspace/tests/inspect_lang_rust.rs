#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn rs() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_rust::RustAdapter::new())
}

#[test]
fn cross_module_chain_via_use() {
    let w = ws_multi(
        rs(),
        &[
            (
                "/w/gateway.rs",
                "use super::user_service::update_user;\nfn handle_request(t: &str) { update_user(t); }\n",
            ),
            (
                "/w/user_service.rs",
                "use super::auth::run_admin_command;\nfn update_user(t: &str) { run_admin_command(t); }\n",
            ),
            (
                "/w/auth.rs",
                "use std::process::Command;\nfn run_admin_command(cmd: &str) { Command::new(cmd).status(); }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handle_request", "run_admin_command");
}

#[test]
fn chain_through_match_for_loop_while() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/a.rs",
            "fn entry(x: i32, xs: &[i32]) {\n\
               match x { 0 => a(), 1 => b(), _ => c() }\n\
               for v in xs { step(*v); }\n\
               while cond() { d(); }\n\
             }\nfn a() { sink(); }\nfn b() { sink(); }\nfn c() { sink(); }\nfn step(_: i32) { sink(); }\nfn cond() -> bool { false }\nfn d() { sink(); }\nfn sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "c", "step", "d"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn try_block_path_indexed() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/a.rs",
            "fn entry() { try { happy()?; Ok::<(),()>(()) }; }\nfn happy() -> Result<(),()> { sink(); Ok(()) }\nfn sink() {}\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn use_alias_and_wildcard() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/a.rs",
            "use std::collections::HashMap as Map;\nuse std::io::*;\nfn f() {}\n",
        )],
    );
    assert!(query_hits(&w, "std::collections").has_import("std::collections"));
    assert!(query_hits(&w, "std::io").has_import("std::io"));
}

#[test]
fn attribute_matches_decorator_query() {
    let w = ws_multi(rs(), &[("/w/a.rs", "#[derive(Debug)]\nstruct Foo;\n")]);
    assert!(query_hits(&w, "derive").has_decorator("derive"));
}

#[test]
fn macro_invocation_is_indexed_call() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/a.rs",
            "fn entry() { handler!(); }\nfn handler() { sink(); }\nfn sink() {}\n",
        )],
    );
    // Macro invocations surface as Call events and resolve to the fn
    // with the same short name, so the full chain `entry → handler →
    // sink` should be enumerated.
    assert_chain_contains(&w, "sink", &["entry", "handler", "sink"]);
}

#[test]
fn inspect_filter_resolves_use_as_alias() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/a.rs",
            "mod auth { pub fn run_admin_command(_: &str) {} }\n\
             use auth::run_admin_command as run_admin;\n\
             fn handle_request(cmd: &str) { run_admin(cmd); }\n",
        )],
    );
    // Querying by the ORIGINAL imported symbol must find the chain
    // through the alias.
    let chains = enumerate_chains(&w, "run_admin_command", 32);
    assert!(
        chains.iter().any(|c| c.iter().any(|h| h == "handle_request")),
        "alias chain missing: {chains:?}"
    );
}

#[test]
fn inspect_filter_from_to_through_match_arm() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/a.rs",
            "fn entry(x: i32) { match x { 0 => a(), _ => b() } }\n\
             fn a() { sink(); }\nfn b() { sink(); }\nfn sink() {}\n",
        )],
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("entry"),
            to: Some("sink"),
            ..Default::default()
        },
    );
    // Intermediate-hop --from on the else branch.
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("b"),
            ..Default::default()
        },
    );
}

#[test]
fn rust_fuzzy_from_across_node_types() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/h.rs",
            "use std::fs;\n\
             fn process(_s: &str) {}\n\
             fn handle_request(_q: &str) {\n\
                 let request_url = \"/api/request\";\n\
                 process(request_url);\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handle_request");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handle_request", "req");
    assert_fuzzy_substring("handle_request", "REQUEST");
    assert_hit_text_match("/api/request", "req");
    assert_sibling_flow_filter_keeps(&w, "handle_request", "request", "process");
}

#[test]
fn rust_filter_rejects_unrelated_hits() {
    let w = ws_multi(rs(), &[("/w/m.rs", "fn entry() { println!(\"hi\"); }\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "println", "nowhere", "nothere");
}
