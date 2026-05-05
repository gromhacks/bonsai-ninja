#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn erl() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_erlang::ErlangAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        erl(),
        &[
            (
                "/w/gateway.erl",
                "-module(gateway).\n\
                 -export([handle_request/1]).\n\
                 handle_request(T) ->\n\
                     user_service:update_user(T).\n",
            ),
            (
                "/w/user_service.erl",
                "-module(user_service).\n\
                 -export([update_user/1]).\n\
                 update_user(T) ->\n\
                     auth:run_admin_command(T).\n",
            ),
            (
                "/w/auth.erl",
                "-module(auth).\n\
                 -export([run_admin_command/1]).\n\
                 run_admin_command(Cmd) ->\n\
                     os:cmd(Cmd).\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handle_request", "run_admin_command");
}

#[test]
fn chain_through_case_if_try() {
    let w = ws_multi(
        erl(),
        &[(
            "/w/a.erl",
            "-module(a).\n\
             -export([entry/1]).\n\
             entry(X) ->\n\
                 case X of\n\
                     1 -> a();\n\
                     _ -> b()\n\
                 end,\n\
                 if X > 0 -> c(); true -> d() end,\n\
                 try e() catch _:_ -> recover() end.\n\
             a() -> sink().\n\
             b() -> sink().\n\
             c() -> sink().\n\
             d() -> sink().\n\
             e() -> sink().\n\
             recover() -> sink().\n\
             sink() -> ok.\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "c", "d", "e", "recover"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn module_qualified_call() {
    let w = ws_multi(
        erl(),
        &[(
            "/w/a.erl",
            "-module(a).\n\
             -export([entry/0]).\n\
             entry() -> lists:map(fun helper/1, [1,2,3]).\n\
             helper(X) -> X.\n",
        )],
    );
    // `lists:map` surfaces as a call event in entry's flow.
    let h = query_hits(&w, "lists:map");
    assert!(
        h.has_call("entry", "lists:map"),
        "lists:map call not indexed under entry: {h:?}"
    );
}

#[test]
fn function_decl_with_export_compiles() {
    // Module + export attributes are Erlang prelude — the adapter
    // doesn't index them as separate symbols, but the function body
    // they preface MUST still parse and produce a decl.
    let w = ws_multi(
        erl(),
        &[(
            "/w/a.erl",
            "-module(a).\n\
             -export([f/0]).\n\
             f() -> ok.\n",
        )],
    );
    let h = query_hits(&w, "f");
    assert!(h.has_decl("f"), "function decl after attributes missing: {h:?}");
}

#[test]
fn regex_query_on_erlang_decls() {
    let w = ws_multi(
        erl(),
        &[(
            "/w/a.erl",
            "-module(a).\n\
             run_admin_command() -> ok.\n\
             run_user_command() -> ok.\n\
             handle() -> ok.\n",
        )],
    );
    let h = query_hits_regex(&w, "^run_.*_command$");
    assert!(h.has_decl("run_admin_command"));
    assert!(h.has_decl("run_user_command"));
}

#[test]
fn inspect_filter_from_to_through_case() {
    let w = ws_multi(
        erl(),
        &[(
            "/w/a.erl",
            "-module(a).\n\
             entry(X) ->\n\
                 case X of\n\
                     1 -> happy();\n\
                     _ -> recover()\n\
                 end.\n\
             happy() -> sink().\n\
             recover() -> sink().\n\
             sink() -> ok.\n",
        )],
    );
    for via in ["happy", "recover"] {
        assert_filters_keep(
            &w,
            "sink",
            "sink",
            InspectFilters {
                from: Some(via),
                to: Some("sink"),
                ..Default::default()
            },
        );
    }
}

#[test]
fn erlang_fuzzy_from_across_node_types() {
    let w = ws_multi(
        erl(),
        &[(
            "/w/h.erl",
            "-module(h).\n\
             process(S) -> S.\n\
             handle_request(Q) ->\n\
                 RequestUrl = \"/api/request\",\n\
                 process(RequestUrl).\n",
        )],
    );
    assert_function_named(&w, "handle_request");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handle_request", "req");
    assert_fuzzy_substring("handle_request", "REQUEST");
    assert_hit_text_match("/api/request", "req");
}

#[test]
fn erlang_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        erl(),
        &[(
            "/w/m.erl",
            "-module(m).\n\
             entry() -> io:format(\"hi~n\").\n",
        )],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "io:format", "nowhere", "nothere");
}
