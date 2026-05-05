#[path = "inspect_harness.rs"]
mod h;

use bonsai_common::{FuncId, SymbolId};
use h::*;
use std::sync::Arc;

fn go() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_go::GoAdapter::new())
}

#[test]
fn cross_package_chain_via_function_calls() {
    let w = ws_multi(
        go(),
        &[
            (
                "/w/gateway.go",
                "package m\nfunc handleRequest(t string) { updateUser(t) }\n",
            ),
            (
                "/w/user_service.go",
                "package m\nfunc updateUser(t string) { runAdminCommand(t) }\n",
            ),
            (
                "/w/auth.go",
                "package m\nimport \"os/exec\"\nfunc runAdminCommand(cmd string) { exec.Command(cmd).Run() }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_switch_for_defer() {
    let w = ws_multi(
        go(),
        &[(
            "/w/a.go",
            "package m\nfunc entry(x int, xs []int) {\n\
               switch x { case 0: a(); case 1: b(); default: c() }\n\
               for _, v := range xs { step(v) }\n\
               defer cleanup()\n\
               d()\n\
             }\nfunc a() { sink() }\nfunc b() { sink() }\nfunc c() { sink() }\nfunc step(int) { sink() }\nfunc cleanup() { sink() }\nfunc d() { sink() }\nfunc sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "c", "step", "cleanup", "d"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn import_variants_alias_and_dot() {
    let w = ws_multi(
        go(),
        &[(
            "/w/a.go",
            "package m\nimport f \"fmt\"\nimport . \"strings\"\nfunc g() { f.Println(ToUpper(\"x\")) }\n",
        )],
    );
    assert!(query_hits(&w, "fmt").has_import("fmt"));
    assert!(query_hits(&w, "strings").has_import("strings"));
}

#[test]
fn regex_query_on_go_decls() {
    let w = ws_multi(
        go(),
        &[(
            "/w/a.go",
            "package m\nfunc runAdminCommand() {}\nfunc runUserCommand() {}\nfunc handle() {}\n",
        )],
    );
    let h = query_hits_regex(&w, "^run.*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_defer_and_switch() {
    let w = ws_multi(
        go(),
        &[(
            "/w/a.go",
            "package m\nfunc entry(x int) { switch x { case 0: a(); default: b() }; defer cleanup() }\n\
             func a() { sink() }\nfunc b() { sink() }\nfunc cleanup() { sink() }\nfunc sink() {}\n",
        )],
    );
    for via in ["a", "b", "cleanup"] {
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
fn go_fuzzy_from_across_node_types() {
    let w = ws_multi(
        go(),
        &[(
            "/w/h.go",
            "package main\n\
             import \"net/http\"\n\
             var _ = http.StatusOK\n\
             func Process(s string) {}\n\
             func HandleRequest(q string) {\n\
                 requestUrl := \"/api/request\"\n\
                 Process(requestUrl)\n\
             }\n",
        )],
    );
    assert_function_named(&w, "HandleRequest");
    assert_function_named(&w, "Process");
    assert_fuzzy_substring("HandleRequest", "req");
    assert_fuzzy_substring("HandleRequest", "REQ");
    assert_hit_text_match("/api/request", "req");
    assert_sibling_flow_filter_keeps(&w, "HandleRequest", "request", "Process");
}

/// Go `go funcCall()` (goroutine launch) and `defer funcCall()` —
/// the inner call must surface under the enclosing function. Both
/// are flow-relevant: the call will execute, just asynchronously /
/// deferred.
#[test]
fn go_goroutine_and_defer_calls_captured() {
    let w = ws_multi(
        go(),
        &[(
            "/w/m.go",
            "package main\nfunc Entry() { go doA(); defer doB() }\n",
        )],
    );
    assert!(
        calls_contains(&w, "Entry", "doA"),
        "goroutine call `doA` missing under `Entry`"
    );
    assert!(
        calls_contains(&w, "Entry", "doB"),
        "defer call `doB` missing under `Entry`"
    );
}

#[test]
fn go_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        go(),
        &[(
            "/w/m.go",
            "package main\nimport \"fmt\"\nfunc Entry() { fmt.Println(\"hi\") }\n",
        )],
    );
    assert_function_named(&w, "Entry");
    assert_filter_rejects_unrelated(&w, "Entry", "fmt.Println", "nowhere", "nothere");
}

#[test]
fn resolved_graph_links_same_module_package_selector_call() {
    let w = ws_multi(
        go(),
        &[
            (
                "/w/api/files.go",
                "package api\n\
                 import \"example.com/app/service\"\n\
                 func Handle(name string) { service.LoadFile(name) }\n",
            ),
            (
                "/w/service/store.go",
                "package service\n\
                 func LoadFile(name string) { ReadDisk(name) }\n\
                 func ReadDisk(name string) {}\n",
            ),
        ],
    );
    assert_resolved_edge(&w, "Handle", "LoadFile");
}

fn assert_resolved_edge(w: &bonsai_workspace::Workspace, caller: &str, callee: &str) {
    let global = w.db().global_index();
    let caller_id = func_id_by_name(w, caller);
    let graph = w.resolved_call_graph();
    let callees = graph
        .callees_of(caller_id)
        .filter_map(|edge| global.decl_of(SymbolId::new(edge.to.raw())))
        .map(|decl| decl.name.as_str())
        .collect::<Vec<_>>();
    assert!(
        callees.contains(&callee),
        "expected resolved edge {caller} -> {callee}, got {callees:?}"
    );
}

fn func_id_by_name(w: &bonsai_workspace::Workspace, name: &str) -> FuncId {
    let global = w.db().global_index();
    global
        .find_by_name(name)
        .iter()
        .find_map(|sym| global.decl_of(*sym).map(|_| FuncId::new(sym.raw())))
        .unwrap_or_else(|| panic!("missing function `{name}`"))
}
