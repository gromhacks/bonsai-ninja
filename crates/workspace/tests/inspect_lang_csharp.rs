#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn cs() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_csharp::CSharpAdapter::new())
}

#[test]
fn cross_class_chain() {
    let w = ws_multi(
        cs(),
        &[
            (
                "/w/Gateway.cs",
                "class Gateway { public void HandleRequest(string t) { new UserService().UpdateUser(t); } }\n",
            ),
            (
                "/w/UserService.cs",
                "class UserService { public void UpdateUser(string t) { new AuthService().RunAdminCommand(t); } }\n",
            ),
            (
                "/w/AuthService.cs",
                "class AuthService { public void RunAdminCommand(string cmd) { System.Diagnostics.Process.Start(cmd); } }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "HandleRequest", "RunAdminCommand");
}

#[test]
fn chain_through_branch_loop_try_using_yield() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/A.cs",
            "class A {\n\
               public void Entry(bool c, int[] xs) {\n\
                 if (c) A1(); else B1();\n\
                 foreach (var x in xs) Step(x);\n\
                 try { D(); } catch (System.Exception e) { Recover(); } finally { Cleanup(); }\n\
                 using (var r = Open()) { Use(r); }\n\
                 foreach (var v in Gen()) Consume(v);\n\
               }\n\
               public void A1() { Sink(); }\n\
               public void B1() { Sink(); }\n\
               public void Step(int x) { Sink(); }\n\
               public void D() { Sink(); }\n\
               public void Recover() { Sink(); }\n\
               public void Cleanup() { Sink(); }\n\
               public System.IDisposable Open() { return null; }\n\
               public void Use(System.IDisposable d) { Sink(); }\n\
               public System.Collections.Generic.IEnumerable<int> Gen() { yield return 1; }\n\
               public void Consume(int v) { Sink(); }\n\
               public void Sink() {}\n\
             }\n",
        )],
    );
    let chains = enumerate_chains(&w, "Sink", 64);
    for via in ["A1", "B1", "Step", "D", "Recover", "Cleanup", "Use", "Consume"] {
        assert!(
            chains.iter().any(|c| c.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn using_directive_surfaces_import() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/A.cs",
            "using System;\nusing Foo = System.Console;\nclass A { }\n",
        )],
    );
    assert!(query_hits(&w, "System").has_import("System"));
}

#[test]
fn attribute_matches_decorator_query() {
    let w = ws_multi(
        cs(),
        &[("/w/A.cs", "class A { [System.Obsolete] public void F() {} }\n")],
    );
    assert!(query_hits(&w, "Obsolete").has_decorator("Obsolete"));
}

#[test]
fn regex_query_on_cs_decls() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/A.cs",
            "class A { public void RunAdminCommand() {} public void RunUserCommand() {} public void Handle() {} }\n",
        )],
    );
    let h = query_hits_regex(&w, "^Run.*Command$");
    assert!(h.has_decl("RunAdminCommand"));
    assert!(h.has_decl("RunUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_using_block() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/A.cs",
            "class A {\n  public void Entry() { using (var r = Open()) { Use(r); } }\n\
             public System.IDisposable Open() { return null; }\n\
             public void Use(System.IDisposable d) { Sink(); }\n\
             public void Sink() {}\n}",
        )],
    );
    assert_filters_keep(
        &w,
        "Sink",
        "Sink",
        InspectFilters {
            from: Some("Entry"),
            to: Some("Sink"),
            ..Default::default()
        },
    );
}

#[test]
fn csharp_fuzzy_from_across_node_types() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/S.cs",
            "using System;\n\
             class S {\n\
                 static void Process(string s) { }\n\
                 static void HandleRequest(string q) {\n\
                     var requestUrl = \"/api/request\";\n\
                     Process(requestUrl);\n\
                 }\n\
             }\n",
        )],
    );
    assert_function_named(&w, "HandleRequest");
    assert_function_named(&w, "Process");
    assert_fuzzy_substring("HandleRequest", "req");
    assert_fuzzy_substring("HandleRequest", "REQUEST");
    assert_hit_text_match("/api/request", "req");
    assert_sibling_flow_filter_keeps(&w, "HandleRequest", "request", "Process");
}

#[test]
fn csharp_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/M.cs",
            "class M { static void Entry() { System.Console.WriteLine(\"hi\"); } }\n",
        )],
    );
    assert_function_named(&w, "Entry");
    assert_filter_rejects_unrelated(&w, "Entry", "System.Console.WriteLine", "nowhere", "nothere");
}
