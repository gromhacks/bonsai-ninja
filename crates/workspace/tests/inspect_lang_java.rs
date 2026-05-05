//! Inspect coverage for Java — cross-file chains, flow constructs, import
//! variants (wildcard, static), query kinds, annotations.

#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn java() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_java::JavaAdapter::new())
}

#[test]
fn cross_class_chain_to_exec() {
    let w = ws_multi(
        java(),
        &[
            (
                "/w/Gateway.java",
                "import svc.UserService;\npublic class Gateway { void handleRequest(String token) { new UserService().updateUser(token); } }\n",
            ),
            (
                "/w/svc/UserService.java",
                "package svc;\nimport auth.AuthService;\npublic class UserService { void updateUser(String token) { new AuthService().runAdminCommand(token); } }\n",
            ),
            (
                "/w/auth/AuthService.java",
                "package auth;\npublic class AuthService { void runAdminCommand(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); } }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
    assert_chain_from_to(&w, "handleRequest", "updateUser");
}

#[test]
fn chain_through_branch_loop_try() {
    let w = ws_multi(
        java(),
        &[(
            "/w/A.java",
            "class A { void entry(boolean c, int[] xs) {\n\
               if (c) a(); else b();\n\
               for (int x : xs) step(x);\n\
               try { d(); } catch (Exception e) { recover(); } finally { cleanup(); }\n\
             } void a() { sink(); } void b() { sink(); } void step(int x) { sink(); } void d() { sink(); } void recover() { sink(); } void cleanup() { sink(); } void sink() {} }\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|c| c.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn try_with_resources_path_indexed() {
    let w = ws_multi(
        java(),
        &[(
            "/w/A.java",
            "class A { void entry() throws Exception { try (var s = open()) { use(s); } } Resource open() { return null; } void use(Resource s) { sink(); } void sink() {} static class Resource implements AutoCloseable { public void close() {} } }\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn imports_wildcard_and_static_resolve() {
    let w = ws_multi(
        java(),
        &[(
            "/w/A.java",
            "import java.util.*;\nimport static java.lang.Math.PI;\nclass A { void f() {} }\n",
        )],
    );
    assert!(query_hits(&w, "java.util").has_import("java.util"));
    assert!(query_hits(&w, "Math").has_import("Math"));
}

#[test]
fn annotation_matches_decorator_query() {
    let w = ws_multi(java(), &[("/w/A.java", "class A { @Deprecated void f() {} }")]);
    assert!(query_hits(&w, "Deprecated").has_decorator("Deprecated"));
}

#[test]
fn regex_query_prefix_and_enum() {
    let w = ws_multi(
        java(),
        &[(
            "/w/A.java",
            "class A { void runAdminCommand() {} void runUserCommand() {} void handle() {} }",
        )],
    );
    let h = query_hits_regex(&w, "^run.*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_branch_and_loop() {
    let w = ws_multi(
        java(),
        &[(
            "/w/A.java",
            "class A { void entry(boolean c, int[] xs) {\n\
               if (c) a(); else b();\n\
               for (int x : xs) step(x);\n\
             } void a() { sink(); } void b() { sink(); } void step(int x) { sink(); } void sink() {} }",
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
    // Intermediate via loop body.
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("step"),
            ..Default::default()
        },
    );
}

#[test]
fn java_fuzzy_from_across_node_types() {
    let w = ws_multi(
        java(),
        &[(
            "/w/S.java",
            "import java.util.List;\n\
             class S {\n\
                 static void process(String s) {}\n\
                 static void handleRequest(String q) {\n\
                     String requestUrl = \"/api/request\";\n\
                     process(requestUrl);\n\
                 }\n\
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
fn java_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        java(),
        &[(
            "/w/M.java",
            "class M { static void entry() { System.out.println(\"hi\"); } }\n",
        )],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "System.out.println", "nowhere", "nothere");
}
