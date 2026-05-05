//! Inspect coverage for TypeScript — cross-module chains, flow
//! constructs, import variants (type, default, namespace), query kinds.

#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn ts() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())
}

#[test]
fn cross_module_chain() {
    let w = ws_multi(
        ts(),
        &[
            (
                "/w/gateway.ts",
                "import { updateUser } from './user_service';\n\
                 export function handleRequest(token: string): void { updateUser(token); }\n",
            ),
            (
                "/w/user_service.ts",
                "import { runAdminCommand } from './auth';\n\
                 export function updateUser(tok: string): void { runAdminCommand(tok); }\n",
            ),
            (
                "/w/auth.ts",
                "import { exec } from 'child_process';\n\
                 export function runAdminCommand(cmd: string): void { exec(cmd); }\n",
            ),
        ],
    );
    assert_chain_contains(
        &w,
        "runAdminCommand",
        &["handleRequest", "updateUser", "runAdminCommand"],
    );
}

#[test]
fn chain_through_typed_if_else_loop_try() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/a.ts",
            "function entry(c: boolean, xs: number[]): void {\n\
               if (c) { a(); } else { b(); }\n\
               for (const x of xs) { c_branch(x); }\n\
               try { d(); } catch (e) { recover(); } finally { cleanup(); }\n\
             }\n\
             function a() { sink(); }\nfunction b() { sink(); }\nfunction c_branch(_: number) { sink(); }\nfunction d() { sink(); }\nfunction recover() { sink(); }\nfunction cleanup() { sink(); }\nfunction sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "c_branch", "d", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|c| c.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn await_through_typed_async() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/a.ts",
            "async function entry(): Promise<number> { return await step(); }\n\
             async function step(): Promise<number> { return sink(); }\n\
             function sink(): number { return 1; }\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn import_type_and_named_rename_alias() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/a.ts",
            "import type { Widget } from './widget';\nimport { readFile as rf } from 'fs';\nimport * as path from 'path';\nfunction f() {}\n",
        )],
    );
    assert!(query_hits(&w, "widget").has_import("widget"));
    assert!(query_hits(&w, "fs").has_import("fs"));
    assert!(query_hits(&w, "path").has_import("path"));
}

#[test]
fn regex_query_narrows_to_prefix() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/a.ts",
            "function handleUserRequest(): void {}\nfunction handleAdminRequest(): void {}\nfunction runStep(): void {}\n",
        )],
    );
    let h = query_hits_regex(&w, "^handle.*Request$");
    assert!(h.has_decl("handleUserRequest"));
    assert!(h.has_decl("handleAdminRequest"));
    assert!(!h.has_decl("runStep"));
}

#[test]
fn decorator_on_class_matches() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/a.ts",
            "@sealed\nclass Widget {}\nfunction sealed(x: unknown) { return x; }\n",
        )],
    );
    assert!(query_hits(&w, "sealed").has_decorator("sealed"));
}

#[test]
fn filter_from_to_cross_module() {
    let w = ws_multi(
        ts(),
        &[
            (
                "/w/gateway.ts",
                "import { updateUser } from './user_service';\n\
                 export function handleRequest(t: string): void { updateUser(t); }\n",
            ),
            (
                "/w/user_service.ts",
                "import { runAdminCommand } from './auth';\n\
                 export function updateUser(t: string): void { runAdminCommand(t); }\n",
            ),
            (
                "/w/auth.ts",
                "import { exec } from 'child_process';\n\
                 export function runAdminCommand(cmd: string): void { exec(cmd); }\n",
            ),
        ],
    );
    assert_filters_keep(
        &w,
        "runAdminCommand",
        "exec",
        InspectFilters {
            from: Some("handleRequest"),
            to: Some("exec"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_resolves_ts_named_rename_alias() {
    let w = ws_multi(
        ts(),
        &[
            (
                "/w/gateway.ts",
                "import { runAdminCommand as runAdmin } from './auth';\n\
                 export function handleRequest(cmd: string): void { runAdmin(cmd); }\n",
            ),
            (
                "/w/auth.ts",
                "export function runAdminCommand(cmd: string): void {}\n",
            ),
        ],
    );
    assert_chain_contains(&w, "runAdminCommand", &["handleRequest", "runAdminCommand"]);
}

#[test]
fn string_literal_and_var_queries() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/a.ts",
            "function f(): string { let tok: string = 'bearer'; tok = 'refreshed'; const q: string = \"SELECT * FROM users\"; return q; }\n",
        )],
    );
    assert!(query_hits(&w, "SELECT").has_string("SELECT"));
    // TS / JS `let`/`const` bindings come through as `lexical_declaration`
    // nodes (not in the assignment_kinds set today), so the test targets
    // the follow-up reassignment — which IS captured as an
    // assignment_expression.
    assert!(query_hits(&w, "tok").has_assign("f", "tok"));
}

#[test]
fn ts_fuzzy_from_across_node_types() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/h.ts",
            "import { readFile } from 'fs';\n\
             function process(s: string): void {}\n\
             function handleRequest(q: string): void {\n    \
                 const requestUrl: string = '/api/request';\n    \
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
fn ts_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        ts(),
        &[("/w/m.ts", "function entry(): void { console.log('hi'); }\n")],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "console.log", "nowhere", "nothere");
}
