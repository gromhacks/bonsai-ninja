#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn rb() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_ruby::RubyAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        rb(),
        &[
            (
                "/w/gateway.rb",
                "require_relative 'user_service'\ndef handle_request(t)\n  update_user(t)\nend\n",
            ),
            (
                "/w/user_service.rb",
                "require_relative 'auth'\ndef update_user(t)\n  run_admin_command(t)\nend\n",
            ),
            ("/w/auth.rb", "def run_admin_command(cmd)\n  system(cmd)\nend\n"),
        ],
    );
    assert_chain_from_to(&w, "handle_request", "run_admin_command");
}

#[test]
fn chain_through_if_case_while_begin_rescue() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/a.rb",
            "def entry(x)\n  if x > 0\n    a()\n  else\n    b()\n  end\n  case x\n  when 1 then c()\n  else d()\n  end\n  i = 0\n  while i < 3\n    step()\n    i += 1\n  end\n  begin\n    e()\n  rescue StandardError => ex\n    recover()\n  ensure\n    cleanup()\n  end\nend\ndef a() sink() end\ndef b() sink() end\ndef c() sink() end\ndef d() sink() end\ndef step() sink() end\ndef e() sink() end\ndef recover() sink() end\ndef cleanup() sink() end\ndef sink() end\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "c", "d", "step", "e", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn yield_surfaces_in_flow() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/a.rb",
            "def gen\n  yield produce()\nend\ndef produce\n  sink()\nend\ndef sink\nend\n",
        )],
    );
    // gen yields produce(); sink is reachable all the way up to gen.
    assert_chain_contains(&w, "sink", &["gen", "produce", "sink"]);
}

#[test]
fn require_is_surfaced_as_ref() {
    let w = ws_multi(rb(), &[("/w/a.rb", "require 'json'\ndef f() end\n")]);
    // Ruby's require is a bare method call; the harness indexes it as a ref.
    let h = query_hits(&w, "require");
    assert!(
        !h.refs.is_empty() || !h.calls.is_empty(),
        "require missing: {h:?}"
    );
}

#[test]
fn regex_query_on_rb_decls() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/a.rb",
            "def run_admin_command() end\ndef run_user_command() end\ndef handle() end\n",
        )],
    );
    let h = query_hits_regex(&w, "^run_.*_command$");
    assert!(h.has_decl("run_admin_command"));
    assert!(h.has_decl("run_user_command"));
}

#[test]
fn inspect_filter_from_to_through_begin_rescue() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/a.rb",
            "def entry\n  begin\n    happy()\n  rescue StandardError => ex\n    recover()\n  ensure\n    cleanup()\n  end\nend\ndef happy() sink() end\ndef recover() sink() end\ndef cleanup() sink() end\ndef sink() end\n",
        )],
    );
    for via in ["happy", "recover", "cleanup"] {
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
fn ruby_fuzzy_from_across_node_types() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/h.rb",
            "def process(s)\nend\n\
             def handle_request(q)\n  \
                 request_url = \"/api/request\"\n  \
                 process(request_url)\nend\n",
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
fn ruby_filter_rejects_unrelated_hits() {
    let w = ws_multi(rb(), &[("/w/m.rb", "def entry\n  puts \"hi\"\nend\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "puts", "nowhere", "nothere");
}
