#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn cpp() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_cpp::CppAdapter::new())
}

#[test]
fn cross_file_chain_via_class_methods() {
    let w = ws_multi(
        cpp(),
        &[
            (
                "/w/Gateway.cpp",
                "#include \"UserService.h\"\nclass Gateway { public: void handleRequest(const std::string& t) { UserService().updateUser(t); } };\n",
            ),
            (
                "/w/UserService.cpp",
                "#include \"AuthService.h\"\nclass UserService { public: void updateUser(const std::string& t) { AuthService().runAdminCommand(t); } };\n",
            ),
            (
                "/w/AuthService.cpp",
                "#include <cstdlib>\nclass AuthService { public: void runAdminCommand(const std::string& cmd) { std::system(cmd.c_str()); } };\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_branch_loop_try_co_await() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/a.cpp",
            "#include <coroutine>\nvoid entry(int x, int n, task<int>& aw) {\n\
               if (x > 0) a(); else b();\n\
               for (int i = 0; i < n; ++i) step(i);\n\
               try { d(); } catch (const std::exception& e) { recover(); }\n\
             }\nvoid a() { sink(); }\nvoid b() { sink(); }\nvoid step(int) { sink(); }\nvoid d() { sink(); }\nvoid recover() { sink(); }\nvoid sink() {}\ntask<int> awaitable() { co_await other(); co_return 1; }\ntask<int> other() { sink(); co_return 0; }\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "recover", "other"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn include_and_using_namespace_surface_imports() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/a.cpp",
            "#include <vector>\nusing namespace std;\nvoid f() {}\n",
        )],
    );
    assert!(query_hits(&w, "vector").has_import("vector"));
    assert!(query_hits(&w, "std").has_import("std"));
}

#[test]
fn inspect_filter_from_to_through_try_catch() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/a.cpp",
            "void entry() { try { happy(); } catch (const std::exception& e) { recover(); } }\n\
             void happy() { sink(); }\nvoid recover() { sink(); }\nvoid sink() {}\n",
        )],
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("happy"),
            to: Some("sink"),
            ..Default::default()
        },
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("recover"),
            ..Default::default()
        },
    );
}

/// Same regression shape as C: `function_definition` has no `name` field,
/// so the name extractor must descend through `declarator` instead of
/// grabbing the first identifier (which would be the return type).
#[test]
fn cpp_function_name_not_return_type() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/svc.cpp",
            "struct User {}; \n\
             User* getUser(const char* t) { return nullptr; }\n",
        )],
    );
    assert_function_named(&w, "getUser");
    // `User` is a struct, not a function — make sure it wasn't indexed
    // as a function-like decl.
    assert_no_function_named(&w, "User");
}

#[test]
fn cpp_fuzzy_from_across_node_types() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/h.cpp",
            "#include <string>\n\
             void process(const std::string& s) {}\n\
             void handleRequest(const std::string& q) {\n\
                 auto requestUrl = std::string(\"/api/request\");\n\
                 process(requestUrl);\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handleRequest");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handleRequest", "req");
    assert_fuzzy_substring("handleRequest", "REQ");
    assert_hit_text_match("/api/request", "req");
    assert_sibling_flow_filter_keeps(&w, "handleRequest", "request", "process");
}

#[test]
fn cpp_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/m.cpp",
            "#include <cstdio>\nvoid entry() { std::printf(\"hi\"); }\n",
        )],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "std::printf", "nowhere", "nothere");
}
