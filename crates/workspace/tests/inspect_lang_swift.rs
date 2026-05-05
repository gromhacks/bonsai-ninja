#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn sw() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_swift::SwiftAdapter::new())
}

#[test]
fn cross_file_chain_via_class_methods() {
    let w = ws_multi(
        sw(),
        &[
            (
                "/w/Gateway.swift",
                "class Gateway { func handleRequest(_ t: String) { UserService().updateUser(t) } }\n",
            ),
            (
                "/w/UserService.swift",
                "class UserService { func updateUser(_ t: String) { AuthService().runAdminCommand(t) } }\n",
            ),
            (
                "/w/AuthService.swift",
                "class AuthService { func runAdminCommand(_ cmd: String) { executeShell(cmd) } }\nfunc executeShell(_ c: String) {}\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_switch_for_in_while() {
    let w = ws_multi(
        sw(),
        &[(
            "/w/A.swift",
            "func entry(x: Int, xs: [Int]) {\n\
               switch x { case 0: a(); case 1: b(); default: c() }\n\
               for v in xs { step(v) }\n\
               while cond() { d() }\n\
             }\nfunc a() { sink() }\nfunc b() { sink() }\nfunc c() { sink() }\nfunc step(_: Int) { sink() }\nfunc cond() -> Bool { return false }\nfunc d() { sink() }\nfunc sink() {}\n",
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
fn import_framework() {
    let w = ws_multi(sw(), &[("/w/A.swift", "import Foundation\nfunc f() {}\n")]);
    assert!(query_hits(&w, "Foundation").has_import("Foundation"));
}

#[test]
fn attribute_matches_decorator() {
    let w = ws_multi(sw(), &[("/w/A.swift", "@objc class Widget { }\n")]);
    assert!(query_hits(&w, "objc").has_decorator("objc"));
}

#[test]
fn regex_query_on_swift_decls() {
    let w = ws_multi(
        sw(),
        &[(
            "/w/A.swift",
            "func runAdminCommand() {}\nfunc runUserCommand() {}\nfunc handle() {}\n",
        )],
    );
    let h = query_hits_regex(&w, "^run.*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_switch() {
    let w = ws_multi(
        sw(),
        &[(
            "/w/A.swift",
            "func entry(x: Int) { switch x { case 0: a(); default: b() } }\n\
             func a() { sink() }\nfunc b() { sink() }\nfunc sink() {}\n",
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
fn swift_fuzzy_from_across_node_types() {
    let w = ws_multi(
        sw(),
        &[(
            "/w/h.swift",
            "import Foundation\n\
             func process(_ s: String) {}\n\
             func handleRequest(_ q: String) {\n    \
                 let requestUrl = \"/api/request\"\n    \
                 process(requestUrl)\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handleRequest");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handleRequest", "req");
    assert_fuzzy_substring("handleRequest", "REQUEST");
    assert_hit_text_match("/api/request", "req");
    assert_sibling_flow_filter_keeps(&w, "handleRequest", "request", "process");
}

#[test]
fn swift_filter_rejects_unrelated_hits() {
    let w = ws_multi(sw(), &[("/w/m.swift", "func entry() { print(\"hi\") }\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "print", "nowhere", "nothere");
}
