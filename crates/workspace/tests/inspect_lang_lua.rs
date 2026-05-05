#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn lua() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_lua::LuaAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        lua(),
        &[
            (
                "/w/gateway.lua",
                "local user_service = require('user_service')\n\
                 function handleRequest(t) user_service.updateUser(t) end\n",
            ),
            (
                "/w/user_service.lua",
                "local M = {}\n\
                 local auth = require('auth')\n\
                 function M.updateUser(t) auth.runAdminCommand(t) end\n\
                 return M\n",
            ),
            (
                "/w/auth.lua",
                "local M = {}\n\
                 function M.runAdminCommand(cmd) os.execute(cmd) end\n\
                 return M\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_if_for_while_pcall() {
    let w = ws_multi(
        lua(),
        &[(
            "/w/a.lua",
            "function entry(x)\n\
               if x > 0 then a() else b() end\n\
               for i = 1, 3 do step() end\n\
               while cond() do d() end\n\
               local ok, err = pcall(e)\n\
               if not ok then recover() end\n\
             end\n\
             function a() sink() end\n\
             function b() sink() end\n\
             function step() sink() end\n\
             function cond() return false end\n\
             function d() sink() end\n\
             function e() sink() end\n\
             function recover() sink() end\n\
             function sink() end\n",
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
fn method_call_resolves_via_dotted_name() {
    let w = ws_multi(
        lua(),
        &[(
            "/w/a.lua",
            "local M = {}\n\
             function M.update(t) M.sink(t) end\n\
             function M.sink(t) end\n\
             function entry() M.update('x') end\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "update");
}

#[test]
fn require_is_surfaced_as_ref() {
    let w = ws_multi(
        lua(),
        &[("/w/a.lua", "local json = require('cjson')\nfunction f() end\n")],
    );
    // The Lua adapter surfaces `require('cjson')` as a real ImportSpec
    // (cjson module + json alias).
    let h = query_hits(&w, "cjson");
    assert!(h.has_import("cjson"), "cjson import missing: {h:?}");
    let h2 = query_hits(&w, "json");
    assert!(h2.has_import("cjson"), "json alias missing: {h2:?}");
}

#[test]
fn regex_query_on_lua_decls() {
    let w = ws_multi(
        lua(),
        &[(
            "/w/a.lua",
            "function runAdminCommand() end\n\
             function runUserCommand() end\n\
             function handle() end\n",
        )],
    );
    let h = query_hits_regex(&w, "^run[A-Z].*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_branches() {
    let w = ws_multi(
        lua(),
        &[(
            "/w/a.lua",
            "function entry(c)\n\
               if c > 0 then happy() else recover() end\n\
             end\n\
             function happy() sink() end\n\
             function recover() sink() end\n\
             function sink() end\n",
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
fn lua_fuzzy_from_across_node_types() {
    let w = ws_multi(
        lua(),
        &[(
            "/w/h.lua",
            "function process(s) end\n\
             function handleRequest(q)\n\
               local request_url = \"/api/request\"\n\
               process(request_url)\n\
             end\n",
        )],
    );
    assert_function_named(&w, "handleRequest");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handleRequest", "req");
    assert_fuzzy_substring("handleRequest", "REQUEST");
    assert_hit_text_match("/api/request", "req");
}

#[test]
fn lua_filter_rejects_unrelated_hits() {
    let w = ws_multi(lua(), &[("/w/m.lua", "function entry() print('hi') end\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "print", "nowhere", "nothere");
}
