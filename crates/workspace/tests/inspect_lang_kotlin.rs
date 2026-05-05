//! Inspect coverage for Kotlin — the original regression case.

#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn kt() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())
}

#[test]
fn cross_class_chain_to_exec() {
    let w = ws_multi(
        kt(),
        &[
            (
                "/w/Gateway.kt",
                "package micro\nclass Gateway { fun handleRequest(token: String) { UserService().updateUser(token) } }\n",
            ),
            (
                "/w/UserService.kt",
                "package micro\nclass UserService { fun updateUser(tok: String) { AuthService().runAdminCommand(tok) } }\n",
            ),
            (
                "/w/AuthService.kt",
                "package micro\nclass AuthService { fun runAdminCommand(cmd: String) { Runtime.getRuntime().exec(cmd) } }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_when_for_try() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/A.kt",
            "fun entry(x: Int) { when (x) { 0 -> a(); else -> b() }; for (i in 0..3) step(i); try { c() } catch (e: Exception) { recover() } finally { cleanup() } }\nfun a() { sink() }\nfun b() { sink() }\nfun step(i: Int) { sink() }\nfun c() { sink() }\nfun recover() { sink() }\nfun cleanup() { sink() }\nfun sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "c", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|c| c.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn imports_alias_and_wildcard() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/A.kt",
            "package p\nimport kotlin.io.println as p\nimport kotlin.collections.*\nfun f() {}\n",
        )],
    );
    assert!(query_hits(&w, "println").has_import("println"));
    assert!(query_hits(&w, "collections").has_import("collections"));
}

#[test]
fn annotation_query_matches() {
    let w = ws_multi(kt(), &[("/w/A.kt", "@Deprecated(\"old\") fun f() {}\n")]);
    assert!(query_hits(&w, "Deprecated").has_decorator("Deprecated"));
}

#[test]
fn regex_query_on_kt_decls() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/A.kt",
            "fun runAdminCommand() {}\nfun runUserCommand() {}\nfun handle() {}\n",
        )],
    );
    let h = query_hits_regex(&w, "^run.*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_resolves_kotlin_import_as_alias() {
    // `import x.y.z as w; w()` — chain-query-by-original must resolve.
    let w = ws_multi(
        kt(),
        &[(
            "/w/A.kt",
            "package micro\nimport micro.AuthService.runAdminCommand as runAdmin\n\
             object AuthService { fun runAdminCommand(cmd: String) {} }\n\
             fun handleRequest(cmd: String) { runAdmin(cmd) }\n",
        )],
    );
    let via_original = enumerate_chains(&w, "runAdminCommand", 32);
    assert!(
        via_original
            .iter()
            .any(|c| c.iter().any(|h| h == "handleRequest")),
        "Kotlin alias chain missing: {via_original:?}"
    );
}

#[test]
fn inspect_filter_from_to_through_when() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/A.kt",
            "fun entry(x: Int) { when (x) { 0 -> a(); else -> b() } }\n\
             fun a() { sink() }\nfun b() { sink() }\nfun sink() {}\n",
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
}

#[test]
fn kotlin_fuzzy_from_across_node_types() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/s.kt",
            "import java.util.List\n\
             fun process(s: String) {}\n\
             fun handleRequest(q: String) {\n\
                 val requestUrl = \"/api/request\"\n\
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
fn kotlin_filter_rejects_unrelated_hits() {
    let w = ws_multi(kt(), &[("/w/m.kt", "fun entry() { println(\"hi\") }\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "println", "nowhere", "nothere");
}

/// Drift guard for the alias-resolution source-of-truth contract.
///
/// `db.imports_for(file)` MUST surface the kotlin adapter's
/// canonical shape for `import x.y.z as Z`:
///
///   ImportSpec { module: "x.y", alias: Some("Z"), original_name: Some("z") }
///
/// And `bonsai_resolve::alias_map_for_file(&imports)` MUST produce
/// `Z → z`, NOT `Z → "x.y.z"`. The latter is the
/// `bonsai_lang_api::kit::extract_generic_imports` shape — re-routing
/// through the generic extractor would fail this test.
///
/// This pinned both:
///   1. that the kotlin adapter still produces the corrected
///      pass-8 import shape, AND
///   2. that callers continue to source aliases from the cached
///      adapter ImportIndex (via `db.imports_for`), not the
///      grammar-agnostic generic extractor.
///
/// If a future refactor regresses either piece, this test fails
/// before any downstream taint / inspect test does.
#[test]
fn kotlin_import_alias_routes_through_adapter_import_index() {
    let w = ws_multi(kt(), &[("/w/A.kt", "package p\nimport x.y.z as Z\nfun f() {}\n")]);
    let db = w.db();
    let file = db
        .global_index()
        .all_files()
        .next()
        .expect("workspace has one file");

    let imports = db.imports_for(file);
    let aliased = imports
        .iter()
        .find(|i| i.alias.as_deref() == Some("Z"))
        .expect("aliased import for `Z` present");
    assert_eq!(
        aliased.module, "x.y",
        "module must be the path PREFIX (adapter shape), not the full dotted path \
         (generic-extractor shape) — got {aliased:?}"
    );
    assert_eq!(
        aliased.original_name.as_deref(),
        Some("z"),
        "original_name must be the bare symbol — got {aliased:?}"
    );

    let alias_map = bonsai_resolve::alias_map_for_file(&imports);
    let resolved = alias_map.get("Z").map(String::as_str);
    assert_eq!(
        resolved,
        Some("z"),
        "Z must resolve to the bare symbol `z`, not the dotted module path. \
         alias_map = {alias_map:?}"
    );
    assert!(
        !resolved.unwrap_or_default().contains('.'),
        "alias target must not be dotted (would re-create the pass-8 double-tail bug). \
         alias_map = {alias_map:?}"
    );
}
