#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn php() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_php::PhpAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        php(),
        &[
            (
                "/w/gateway.php",
                "<?php\nrequire_once 'user_service.php';\nfunction handleRequest($t) { updateUser($t); }\n",
            ),
            (
                "/w/user_service.php",
                "<?php\nrequire_once 'auth.php';\nfunction updateUser($t) { runAdminCommand($t); }\n",
            ),
            (
                "/w/auth.php",
                "<?php\nfunction runAdminCommand($cmd) { shell_exec($cmd); }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_branch_loop_try_yield() {
    let w = ws_multi(
        php(),
        &[(
            "/w/a.php",
            "<?php\nfunction entry($c, $xs) {\n\
               if ($c) { a(); } else { b(); }\n\
               foreach ($xs as $x) { step($x); }\n\
               try { d(); } catch (\\Exception $e) { recover(); } finally { cleanup(); }\n\
               foreach (gen() as $v) { consume($v); }\n\
             }\nfunction a() { sink(); }\nfunction b() { sink(); }\nfunction step($x) { sink(); }\nfunction d() { sink(); }\nfunction recover() { sink(); }\nfunction cleanup() { sink(); }\nfunction gen() { yield produce(); }\nfunction produce() {}\nfunction consume($v) { sink(); }\nfunction sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "recover", "cleanup", "consume"] {
        assert!(
            chains.iter().any(|c| c.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
    // entry uses gen() in foreach, so produce() should be reachable from entry.
    assert_chain_from_to(&w, "entry", "produce");
}

#[test]
fn use_namespace_and_alias() {
    let w = ws_multi(
        php(),
        &[(
            "/w/a.php",
            "<?php\nuse App\\Service;\nuse App\\Client as C;\nfunction f() {}\n",
        )],
    );
    assert!(query_hits(&w, "App").has_import("App"));
    assert!(!query_hits(&w, "C").imports.is_empty() || query_hits(&w, "Client").has_import("Client"));
}

#[test]
fn php8_attribute_matches_decorator() {
    let w = ws_multi(php(), &[("/w/a.php", "<?php\n#[Deprecated]\nfunction f() {}\n")]);
    assert!(query_hits(&w, "Deprecated").has_decorator("Deprecated"));
}

#[test]
fn inspect_filter_resolves_php_use_as_alias() {
    // `use App\Service as S; S::run()` — the caller-map indexes under
    // both the local name `S` and the original `Service`.
    let w = ws_multi(
        php(),
        &[(
            "/w/a.php",
            "<?php\nnamespace App;\nclass Service { public static function run() {} }\n\
             use App\\Service as S;\n\
             function handle() { S::run(); }\n",
        )],
    );
    // PHP's `S::run` short-tails to `run` (method call through a
    // namespace alias). Whether queried by the method name or the
    // original class, at least one enumeration must reach `handle`.
    let via_method = enumerate_chains(&w, "run", 32);
    assert!(
        via_method.iter().any(|c| c.iter().any(|h| h == "handle")),
        "PHP alias chain missing: {via_method:?}"
    );
}

#[test]
fn inspect_filter_from_to_through_try_catch() {
    let w = ws_multi(
        php(),
        &[(
            "/w/a.php",
            "<?php\nfunction entry() { try { happy(); } catch (\\Exception $e) { recover(); } }\n\
             function happy() { sink(); }\n\
             function recover() { sink(); }\n\
             function sink() {}\n",
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
            to: Some("sink"),
            ..Default::default()
        },
    );
}

#[test]
fn php_fuzzy_from_across_node_types() {
    let w = ws_multi(
        php(),
        &[(
            "/w/h.php",
            "<?php\n\
             function process($s) {}\n\
             function handle_request($q) {\n\
                 $request_url = \"/api/request\";\n\
                 process($request_url);\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handle_request");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handle_request", "req");
    assert_fuzzy_substring("handle_request", "REQUEST");
    assert_hit_text_match("/api/request", "req");
    assert_sibling_flow_filter_keeps(&w, "handle_request", "request", "process");
}

#[test]
fn php_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        php(),
        &[("/w/m.php", "<?php\nfunction entry() { echo \"hi\"; }\n")],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "echo", "nowhere", "nothere");
}
