#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn ex() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_elixir::ElixirAdapter::new())
}

#[test]
fn cross_file_chain() {
    // Use the full `def ... do ... end` form so the body is a
    // `do_block` node (the kit's body fallback searches for
    // `do_block` children).
    let w = ws_multi(
        ex(),
        &[
            (
                "/w/gateway.ex",
                "defmodule Gateway do\n\
                   def handle_request(t) do\n\
                     UserService.update_user(t)\n\
                   end\n\
                 end\n",
            ),
            (
                "/w/user_service.ex",
                "defmodule UserService do\n\
                   def update_user(t) do\n\
                     Auth.run_admin_command(t)\n\
                   end\n\
                 end\n",
            ),
            (
                "/w/auth.ex",
                "defmodule Auth do\n\
                   def run_admin_command(cmd) do\n\
                     :ok\n\
                   end\n\
                 end\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handle_request", "run_admin_command");
}

#[test]
fn chain_through_case_cond_try() {
    let w = ws_multi(
        ex(),
        &[(
            "/w/a.ex",
            "defmodule A do\n\
               def entry(x) do\n\
                 case x do\n\
                   1 -> a()\n\
                   _ -> b()\n\
                 end\n\
                 cond do\n\
                   x > 0 -> c()\n\
                   true -> d()\n\
                 end\n\
                 try do\n\
                   e()\n\
                 rescue\n\
                   _ -> recover()\n\
                 end\n\
               end\n\
               def a do\n                 sink()\n               end\n\
               def b do\n                 sink()\n               end\n\
               def c do\n                 sink()\n               end\n\
               def d do\n                 sink()\n               end\n\
               def e do\n                 sink()\n               end\n\
               def recover do\n                 sink()\n               end\n\
               def sink do\n                 :ok\n               end\n\
             end\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "c", "d", "e", "recover"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn defp_private_fn_is_indexed() {
    let w = ws_multi(
        ex(),
        &[(
            "/w/a.ex",
            "defmodule A do\n\
               def entry(x) do\n                 helper(x)\n               end\n\
               defp helper(x) do\n                 sink(x)\n               end\n\
               def sink(x) do\n                 x\n               end\n\
             end\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn call_to_aliased_module_is_indexed() {
    // `MyApp.Auth.run_admin_command(x)` → the qualified call appears
    // as a call event; short-tail resolution maps `run_admin_command`
    // to the decl in auth.ex.
    let w = ws_multi(
        ex(),
        &[
            (
                "/w/a.ex",
                "defmodule A do\n\
                   def f(x) do\n                     MyApp.Auth.run_admin_command(x)\n                   end\n\
                 end\n",
            ),
            (
                "/w/auth.ex",
                "defmodule MyApp.Auth do\n\
                   def run_admin_command(cmd) do\n                     :ok\n                   end\n\
                 end\n",
            ),
        ],
    );
    // The qualified call `MyApp.Auth.run_admin_command(x)` resolves
    // via short-tail to `run_admin_command`, which is also the decl.
    let h = query_hits(&w, "run_admin_command");
    assert!(h.has_decl("run_admin_command"), "decl missing: {h:?}");
    assert!(!h.calls.is_empty(), "qualified call not indexed: {h:?}");
}

#[test]
fn regex_query_on_elixir_decls() {
    let w = ws_multi(
        ex(),
        &[(
            "/w/a.ex",
            "defmodule A do\n\
               def run_admin_command, do: :ok\n\
               def run_user_command, do: :ok\n\
               def handle, do: :ok\n\
             end\n",
        )],
    );
    let h = query_hits_regex(&w, "^run_.*_command$");
    assert!(h.has_decl("run_admin_command"));
    assert!(h.has_decl("run_user_command"));
}

#[test]
fn inspect_filter_from_to_through_branches() {
    let w = ws_multi(
        ex(),
        &[(
            "/w/a.ex",
            "defmodule A do\n\
               def entry(c) do\n\
                 if c > 0 do\n                   happy()\n                 else\n                   recover()\n                 end\n\
               end\n\
               def happy do\n                 sink()\n               end\n\
               def recover do\n                 sink()\n               end\n\
               def sink do\n                 :ok\n               end\n\
             end\n",
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
fn elixir_fuzzy_from_across_node_types() {
    let w = ws_multi(
        ex(),
        &[(
            "/w/h.ex",
            "defmodule H do\n\
               def process(s), do: s\n\
               def handle_request(q) do\n\
                 request_url = \"/api/request\"\n\
                 process(request_url)\n\
               end\n\
             end\n",
        )],
    );
    assert_function_named(&w, "handle_request");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handle_request", "req");
    assert_fuzzy_substring("handle_request", "REQUEST");
    assert_hit_text_match("/api/request", "req");
}

#[test]
fn elixir_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        ex(),
        &[(
            "/w/m.ex",
            "defmodule M do\n\
               def entry, do: IO.puts(\"hi\")\n\
             end\n",
        )],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "IO.puts", "nowhere", "nothere");
}
