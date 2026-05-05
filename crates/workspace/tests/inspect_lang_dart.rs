#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn dart() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_dart::DartAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        dart(),
        &[
            (
                "/w/gateway.dart",
                "import 'user_service.dart';\n\
                 void handleRequest(String t) { updateUser(t); }\n",
            ),
            (
                "/w/user_service.dart",
                "import 'auth.dart';\n\
                 void updateUser(String t) { runAdminCommand(t); }\n",
            ),
            (
                "/w/auth.dart",
                "import 'dart:io';\n\
                 void runAdminCommand(String cmd) { Process.runSync('sh', ['-c', cmd]); }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_if_for_while_try() {
    let w = ws_multi(
        dart(),
        &[(
            "/w/a.dart",
            "void entry(int x) {\n\
               if (x > 0) { a(); } else { b(); }\n\
               for (var i = 0; i < 3; i++) { step(); }\n\
               while (cond()) { d(); }\n\
               try { e(); } catch (ex) { recover(); } finally { cleanup(); }\n\
             }\n\
             void a() { sink(); }\n\
             void b() { sink(); }\n\
             void step() { sink(); }\n\
             bool cond() { return false; }\n\
             void d() { sink(); }\n\
             void e() { sink(); }\n\
             void recover() { sink(); }\n\
             void cleanup() { sink(); }\n\
             void sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "e", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn method_call_resolves_through_class() {
    let w = ws_multi(
        dart(),
        &[(
            "/w/a.dart",
            "class Svc {\n\
               void update(String t) { sink(t); }\n\
             }\n\
             void entry() {\n\
               var svc = Svc();\n\
               svc.update('x');\n\
             }\n\
             void sink(String t) {}\n",
        )],
    );
    // Method dispatch lands as a call event — check `update` appears
    // `update` should be both a captured decl (the method) AND a call
    // (svc.update inside entry).
    let h = query_hits(&w, "update");
    assert!(h.has_decl("update"), "update method decl missing: {h:?}");
    assert!(!h.calls.is_empty(), "svc.update call missing: {h:?}");
}

#[test]
fn async_await_chain_preserved() {
    let w = ws_multi(
        dart(),
        &[(
            "/w/a.dart",
            "Future<void> entry() async {\n\
               await fetch();\n\
             }\n\
             Future<void> fetch() async { await sink(); }\n\
             Future<void> sink() async {}\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn import_is_surfaced_as_import() {
    let w = ws_multi(
        dart(),
        &[(
            "/w/a.dart",
            "import 'package:flutter/material.dart';\n\
             import './local.dart' as loc;\n\
             void f() {}\n",
        )],
    );
    // Native Dart import extractor: package + path-style imports both
    // surface as ImportSpec entries. Substring match on the URI is
    // enough since we keep the full module path.
    assert!(query_hits(&w, "flutter").has_import("flutter"));
    assert!(query_hits(&w, "local.dart").has_import("local"));
}

#[test]
fn regex_query_on_dart_decls() {
    let w = ws_multi(
        dart(),
        &[(
            "/w/a.dart",
            "void runAdminCommand() {}\n\
             void runUserCommand() {}\n\
             void handle() {}\n",
        )],
    );
    let h = query_hits_regex(&w, "^run[A-Z].*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_branches() {
    let w = ws_multi(
        dart(),
        &[(
            "/w/a.dart",
            "void entry(int c) { if (c > 0) { happy(); } else { recover(); } }\n\
             void happy() { sink(); }\n\
             void recover() { sink(); }\n\
             void sink() {}\n",
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
fn dart_fuzzy_from_across_node_types() {
    let w = ws_multi(
        dart(),
        &[(
            "/w/h.dart",
            "import 'dart:io';\n\
             void process(String s) {}\n\
             void handleRequest(String q) {\n\
               var requestUrl = \"/api/request\";\n\
               process(requestUrl);\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handleRequest");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handleRequest", "req");
    assert_fuzzy_substring("handleRequest", "REQUEST");
    assert_hit_text_match("/api/request", "req");
}

#[test]
fn dart_filter_rejects_unrelated_hits() {
    let w = ws_multi(dart(), &[("/w/m.dart", "void entry() { print('hi'); }\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "print", "nowhere", "nothere");
}
