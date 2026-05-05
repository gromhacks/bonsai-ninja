#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn pl() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_perl::PerlAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        pl(),
        &[
            (
                "/w/gateway.pl",
                "sub handle_request { my ($t) = @_; update_user($t); }\n",
            ),
            (
                "/w/user_service.pl",
                "sub update_user { my ($t) = @_; run_admin_command($t); }\n",
            ),
            (
                "/w/auth.pl",
                "sub run_admin_command { my ($cmd) = @_; system($cmd); }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handle_request", "run_admin_command");
}

#[test]
fn chain_through_if_for_while_try() {
    let w = ws_multi(
        pl(),
        &[(
            "/w/a.pl",
            "use feature 'try';\nsub entry {\n  my ($x) = @_;\n  if ($x) { a(); } else { b(); }\n  for (my $i = 0; $i < 3; $i++) { step($i); }\n  while (cond()) { d(); }\n  try { e(); } catch ($ex) { recover(); }\n}\nsub a { sink(); }\nsub b { sink(); }\nsub step { sink(); }\nsub cond { return 0; }\nsub d { sink(); }\nsub e { sink(); }\nsub recover { sink(); }\nsub sink { }\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "e", "recover"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn use_statement_is_import() {
    let w = ws_multi(pl(), &[("/w/a.pl", "use strict;\nuse warnings;\nsub f { }\n")]);
    assert!(query_hits(&w, "strict").has_import("strict"));
    assert!(query_hits(&w, "warnings").has_import("warnings"));
}

#[test]
fn attribute_matches_decorator() {
    let w = ws_multi(pl(), &[("/w/a.pl", "sub f :lvalue { return 1; }\n")]);
    assert!(query_hits(&w, "lvalue").has_decorator("lvalue"));
}

#[test]
fn inspect_filter_from_to_through_if_while() {
    let w = ws_multi(
        pl(),
        &[(
            "/w/a.pl",
            "sub entry { my ($x) = @_; if ($x) { a(); } else { b(); } while (cond()) { d(); } }\nsub a { sink(); }\nsub b { sink(); }\nsub cond { 0 }\nsub d { sink(); }\nsub sink { }\n",
        )],
    );
    for via in ["a", "b", "d"] {
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
fn perl_fuzzy_from_across_node_types() {
    let w = ws_multi(
        pl(),
        &[(
            "/w/h.pl",
            "use strict;\n\
             sub process { my ($s) = @_; }\n\
             sub handle_request {\n\
                 my ($q) = @_;\n\
                 my $request_url = \"/api/request\";\n\
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
fn perl_filter_rejects_unrelated_hits() {
    let w = ws_multi(pl(), &[("/w/m.pl", "sub entry { print \"hi\\n\"; }\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "print", "nowhere", "nothere");
}
