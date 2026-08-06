//! Inspect coverage for JavaScript — cross-module chains, every flow
//! construct, import variants, query kinds.

#[path = "inspect_harness.rs"]
mod h;

use bonsai_common::{FuncId, SymbolId};
use h::*;
use std::sync::Arc;

fn js() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())
}

#[test]
fn cross_module_chain_to_exec() {
    let w = ws_multi(
        js(),
        &[
            (
                "/w/gateway.js",
                "import { updateUser } from './user_service.js';\n\
                 export function handleRequest(req) { updateUser(req.token); }\n",
            ),
            (
                "/w/user_service.js",
                "import { runAdminCommand } from './auth.js';\n\
                 export function updateUser(tok) { runAdminCommand(tok); }\n",
            ),
            (
                "/w/auth.js",
                "import { exec } from 'child_process';\n\
                 export function runAdminCommand(cmd) { exec(cmd); }\n",
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
fn receiver_callback_chain_to_sink() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function entry(items) { items.forEach(cb); }\n\
             function cb(item) { sink(item); }\n\
             function sink(x) {}\n",
        )],
    );
    assert_chain_contains(&w, "sink", &["entry", "cb", "sink"]);
}

#[test]
fn chain_through_if_else() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function entry(c) { if (c) left(); else right(); }\n\
             function left() { sink(); }\n\
             function right() { sink(); }\n\
             function sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 16);
    assert!(chains.iter().any(|c| c.contains(&"left".to_string())));
    assert!(chains.iter().any(|c| c.contains(&"right".to_string())));
}

#[test]
fn chain_through_try_catch_finally() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function entry() { try { happy(); } catch (e) { recover(); } finally { cleanup(); } }\n\
             function happy() { sink(); }\n\
             function recover() { sink(); }\n\
             function cleanup() { sink(); }\n\
             function sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 16);
    for via in ["happy", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|c| c.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn chain_through_for_of_and_while() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function entry(xs) { for (const x of xs) handle(x); while (cond()) tick(); }\n\
             function handle(x) { sink(x); }\n\
             function tick() { sink(); }\n\
             function cond() { return false; }\n\
             function sink() {}\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn generator_yield_surfaces_called_callees() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function* gen() { yield produce(); }\nfunction produce() { return 1; }\nfunction entry() { for (const v of gen()) consume(v); }\nfunction consume(v) { sink(v); }\nfunction sink() {}\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "produce");
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn await_chain_preserved() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "async function entry() { const r = await fetch(); store(r); }\n\
             async function fetch() { return await net(); }\n\
             async function net() { return sink(); }\n\
             function store() {}\n\
             function sink() {}\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn switch_case_arms_contribute_edges() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function entry(x) { switch (x) { case 0: zero(); break; case 1: one(); break; default: fallback(); } }\n\
             function zero() { sink(); }\n\
             function one() { sink(); }\n\
             function fallback() { sink(); }\n\
             function sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 16);
    for arm in ["zero", "one", "fallback"] {
        assert!(
            chains.iter().any(|c| c.contains(&arm.to_string())),
            "switch arm {arm} missing: {chains:?}"
        );
    }
}

#[test]
fn query_import_variants() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "import fs from 'fs';\nimport * as path from 'path';\nimport { readFile as read } from 'fs/promises';\n\
             function f() {}\n",
        )],
    );
    assert!(query_hits(&w, "fs").has_import("fs"));
    assert!(query_hits(&w, "path").has_import("path"));
    assert!(!query_hits(&w, "read").imports.is_empty());
    assert!(query_hits(&w, "promises").has_import("promises"));
}

#[test]
fn query_regex_for_prefix_pattern() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function runAdminCommand() {}\nfunction runUserCommand() {}\nfunction handle() {}\n",
        )],
    );
    let h = query_hits_regex(&w, "^run.*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
    assert!(!h.has_decl("handle"));
}

#[test]
fn class_method_call_resolves_cross_file() {
    let w = ws_multi(
        js(),
        &[
            (
                "/w/gateway.js",
                "import { Service } from './service.js';\nfunction handle() { new Service().run(); }\n",
            ),
            (
                "/w/service.js",
                "import { sink } from './sink.js';\nexport class Service { run() { sink(); } }\n",
            ),
            ("/w/sink.js", "export function sink() {}\n"),
        ],
    );
    assert_chain_from_to(&w, "handle", "run");
    assert_chain_from_to(&w, "handle", "sink");
}

#[test]
fn resolved_graph_links_commonjs_namespace_require_member_call() {
    let w = ws_multi(
        js(),
        &[
            (
                "/w/api/search.js",
                "const db = require('../db/bookings');\n\
                 function handle(code) { return db.searchByCode(code); }\n",
            ),
            (
                "/w/db/bookings.js",
                "function searchByCode(code) { return query(code); }\n\
                 function query(code) { return code; }\n\
                 module.exports = { searchByCode };\n",
            ),
        ],
    );
    assert_resolved_edge(&w, "handle", "searchByCode");
}

#[test]
fn resolved_graph_links_commonjs_namespace_require_exports_assignment() {
    let w = ws_multi(
        js(),
        &[
            (
                "/w/api/search.js",
                "const db = require('../db/bookings');\n\
                 function handle(code) { return db.searchByCode(code); }\n",
            ),
            (
                "/w/db/bookings.js",
                "exports.searchByCode = function (code) { return query(code); };\n\
                 function query(code) { return code; }\n",
            ),
        ],
    );
    assert_resolved_edge(&w, "handle", "exports.searchByCode");
}

#[test]
fn resolved_graph_links_commonjs_default_require_callable_module_exports_function() {
    let w = ws_multi(
        js(),
        &[
            (
                "/w/api/render.js",
                "const render = require('../views/render');\n\
                 function handle(el, html) { return render(el, html); }\n",
            ),
            (
                "/w/views/render.js",
                "module.exports = function render(el, html) { el.innerHTML = html; };\n",
            ),
        ],
    );
    // The public `default` alias remains in the declaration index, but the
    // resolved callgraph points at the canonical named function body.
    assert_resolved_edge(&w, "handle", "render");
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

#[test]
fn decorator_matches_query() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "@sealed\nclass Widget {}\nfunction sealed(x) { return x; }\n",
        )],
    );
    assert!(query_hits(&w, "sealed").has_decorator("sealed"));
}

#[test]
fn string_literal_query() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function f() { const q = \"SELECT * FROM users WHERE id = 1\"; return q; }\n",
        )],
    );
    assert!(query_hits(&w, "SELECT").has_string("SELECT"));
}

#[test]
fn var_assignment_query() {
    let w = ws_multi(
        js(),
        &[(
            "/w/a.js",
            "function f() { userToken = req.body.token; return userToken; }\n",
        )],
    );
    assert!(query_hits(&w, "userToken").has_assign("f", "userToken"));
}

#[test]
fn filter_from_to_cross_module_with_hit_text() {
    let w = ws_multi(
        js(),
        &[
            (
                "/w/gateway.js",
                "import { updateUser } from './user_service.js';\n\
                 export function handleRequest(tok) { updateUser(tok); }\n",
            ),
            (
                "/w/user_service.js",
                "import { runAdminCommand } from './auth.js';\n\
                 export function updateUser(tok) { runAdminCommand(tok); }\n",
            ),
            (
                "/w/auth.js",
                "import { exec } from 'child_process';\n\
                 export function runAdminCommand(cmd) { exec(cmd); }\n",
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
    // Intermediate-hop --from matches the middle of the chain.
    assert_filters_keep(
        &w,
        "runAdminCommand",
        "exec",
        InspectFilters {
            from: Some("updateUser"),
            ..Default::default()
        },
    );
    assert_filters_drop(
        &w,
        "runAdminCommand",
        "exec",
        InspectFilters {
            from: Some("totally_fake_fn"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_resolves_js_named_rename_alias() {
    // `import { foo as bar } from 'mod'; bar()` — the call text is
    // `bar`, but the caller-map also indexes under the original name
    // `foo`. Query by either must land the flow.
    let w = ws_multi(
        js(),
        &[
            (
                "/w/gateway.js",
                "import { runAdminCommand as runAdmin } from './auth.js';\n\
                 export function handleRequest(cmd) { runAdmin(cmd); }\n",
            ),
            (
                "/w/auth.js",
                "import { exec } from 'child_process';\n\
                 export function runAdminCommand(cmd) { exec(cmd); }\n",
            ),
        ],
    );
    assert_chain_contains(&w, "runAdminCommand", &["handleRequest", "runAdminCommand"]);
    let via_alias = enumerate_chains(&w, "runAdmin", 32);
    assert!(
        via_alias.iter().any(|c| c.len() >= 2),
        "alias chain missing: {via_alias:?}"
    );
}

#[test]
fn js_fuzzy_from_across_node_types() {
    let w = ws_multi(
        js(),
        &[(
            "/w/h.js",
            "import fs from 'fs';\n\
             function process(s) {}\n\
             function handleRequest(q) {\n\
                 const requestUrl = '/api/request';\n\
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
fn js_filter_rejects_unrelated_hits() {
    let w = ws_multi(js(), &[("/w/m.js", "function entry() { console.log('hi'); }\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "console.log", "nowhere", "nothere");
}
