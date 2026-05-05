//! Extensive inspect coverage for Python — every flow construct, every
//! import variant, every query kind, and cross-module chain
//! enumeration. Built as a regression gate: if inspect stops working
//! end-to-end for a Python codebase, this file fails loudly.
//!
//! Organized by scenario:
//!
//! 1. Cross-module call chains (the headline).
//! 2. Flow-construct coverage (branch, loop, try/except/finally, with,
//!    yield, await) — every one must be traversable from inspect.
//! 3. Import variants — `import x`, `import x as y`, `from x import y`,
//!    `from x import y as z`, `from . import x`, `from x import *`.
//! 4. Query kinds — substring vs regex vs alias.
//! 5. Classes + decorators + string sinks.

#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn py() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_python::PythonAdapter::new())
}

// ===========================================================================
// 1. Cross-module flow tracing
// ===========================================================================

#[test]
fn three_file_chain_reaches_os_system() {
    let w = ws_multi(
        py(),
        &[
            (
                "/w/gateway.py",
                "from user_service import update_user\n\
                 def handle_request():\n    update_user(request.args.get('token'))\n",
            ),
            (
                "/w/user_service.py",
                "from auth_service import run_admin_command\n\
                 def update_user(token):\n    run_admin_command(token)\n",
            ),
            (
                "/w/auth_service.py",
                "import os\n\
                 def run_admin_command(cmd):\n    os.system('notify ' + cmd)\n",
            ),
        ],
    );
    assert_chain_contains(
        &w,
        "run_admin_command",
        &["handle_request", "update_user", "run_admin_command"],
    );
}

#[test]
fn method_call_resolves_through_class_instance() {
    let w = ws_multi(
        py(),
        &[
            (
                "/w/gateway.py",
                "from user_service import UserService\n\
                 def handle():\n    svc = UserService()\n    svc.update(token)\n",
            ),
            (
                "/w/user_service.py",
                "from auth import sink\n\
                 class UserService:\n    def update(self, token):\n        sink(token)\n",
            ),
            ("/w/auth.py", "def sink(x):\n    exec(x)\n"),
        ],
    );
    assert_chain_from_to(&w, "handle", "update");
    assert_chain_from_to(&w, "handle", "sink");
}

#[test]
fn chain_through_branch_then_and_else() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry(cond):\n    if cond:\n        left()\n    else:\n        right()\n\
             def left():\n    sink()\n\
             def right():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    // Both branch arms should surface chains to sink.
    assert_chain_from_to(&w, "entry", "sink");
    let chains = enumerate_chains(&w, "sink", 16);
    let through_left = chains.iter().any(|c| c.contains(&"left".to_string()));
    let through_right = chains.iter().any(|c| c.contains(&"right".to_string()));
    assert!(through_left, "missing then-branch chain: {chains:?}");
    assert!(through_right, "missing else-branch chain: {chains:?}");
}

#[test]
fn chain_through_loop_body() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry(items):\n    for x in items:\n        handler(x)\n\
             def handler(x):\n    sink(x)\n\
             def sink(x):\n    pass\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn chain_through_try_except_finally() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry():\n    try:\n        happy()\n    except ValueError:\n        recover()\n    finally:\n        cleanup()\n\
             def happy():\n    sink()\n\
             def recover():\n    sink()\n\
             def cleanup():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 16);
    let via_happy = chains.iter().any(|c| c.contains(&"happy".to_string()));
    let via_recover = chains.iter().any(|c| c.contains(&"recover".to_string()));
    let via_cleanup = chains.iter().any(|c| c.contains(&"cleanup".to_string()));
    assert!(via_happy, "try-body path missing: {chains:?}");
    assert!(via_recover, "except path missing: {chains:?}");
    assert!(via_cleanup, "finally path missing: {chains:?}");
}

#[test]
fn chain_through_with_context_manager() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry():\n    with open('x') as f:\n        use(f)\n\
             def use(f):\n    sink(f)\n\
             def sink(f):\n    pass\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn chain_through_generator_yield() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry():\n    for v in gen():\n        consume(v)\n\
             def gen():\n    yield produce()\n\
             def produce():\n    return 1\n\
             def consume(v):\n    sink(v)\n\
             def sink(v):\n    pass\n",
        )],
    );
    // gen() calls produce(); entry() calls gen() and consume() which calls sink().
    assert_chain_from_to(&w, "entry", "sink");
    assert_chain_from_to(&w, "entry", "produce");
}

#[test]
fn async_await_chain_preserved() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "async def entry():\n    r = await fetch()\n    await store(r)\n\
             async def fetch():\n    return await net()\n\
             async def net():\n    return sink()\n\
             async def store(x):\n    pass\n\
             def sink():\n    pass\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn higher_order_callback_chain() {
    // inspect at least captures the top-level calls; the cross-module
    // tracer (not chain-enum) is what resolves callbacks. Here we assert
    // that the call-sites are indexed.
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry():\n    run(cb)\n\
             def run(f):\n    f()\n\
             def cb():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    // `entry → run` and `cb → sink` should both be indexed edges.
    let chains_to_run = enumerate_chains(&w, "run", 16);
    let chains_to_sink = enumerate_chains(&w, "sink", 16);
    assert!(
        chains_to_run
            .iter()
            .any(|c| c.first().map(String::as_str) == Some("entry")),
        "entry→run missing: {chains_to_run:?}"
    );
    assert!(
        chains_to_sink
            .iter()
            .any(|c| c.first().map(String::as_str) == Some("cb")),
        "cb→sink missing: {chains_to_sink:?}"
    );
}

// ===========================================================================
// 2. Query-kind matrix
// ===========================================================================

#[test]
fn query_decl_name_substring() {
    let w = ws_multi(py(), &[("/w/a.py", "def run_admin_command():\n    pass\n")]);
    let h = query_hits(&w, "run_admin");
    assert!(h.has_decl("run_admin_command"));
}

#[test]
fn query_qualified_call() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "import os\ndef f():\n    os.system('x')\n    jwt.decode(t)\n",
        )],
    );
    let h = query_hits(&w, "os.system");
    assert!(h.has_call("f", "os.system"));
    let h2 = query_hits(&w, "jwt");
    assert!(h2.has_call("f", "jwt.decode"));
}

#[test]
fn query_variable_assignment() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def f():\n    user_id = verify(tok)\n    secret_key = 'x'\n",
        )],
    );
    let h = query_hits(&w, "user_id");
    assert!(h.has_assign("f", "user_id"));
    let h2 = query_hits(&w, "secret_key");
    assert!(h2.has_assign("f", "secret_key"));
}

#[test]
fn query_string_literal() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def f():\n    q = \"SELECT * FROM users\"\n    u = 'https://evil.com'\n",
        )],
    );
    assert!(query_hits(&w, "SELECT").has_string("SELECT"));
    assert!(query_hits(&w, "evil.com").has_string("evil.com"));
}

#[test]
fn query_decorator() {
    let w = ws_multi(py(), &[("/w/a.py", "@audited\ndef f():\n    pass\n")]);
    assert!(query_hits(&w, "audited").has_decorator("audited"));
}

#[test]
fn query_regex_matches_prefix_pattern() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def run_admin_command(): pass\n\
             def run_user_command(): pass\n\
             def handle(): pass\n",
        )],
    );
    let h = query_hits_regex(&w, "^run_.*_command$");
    assert!(h.has_decl("run_admin_command"));
    assert!(h.has_decl("run_user_command"));
    assert!(!h.has_decl("handle"));
}

// ===========================================================================
// 3. Import variants
// ===========================================================================

#[test]
fn query_plain_import() {
    let w = ws_multi(py(), &[("/w/a.py", "import os\ndef f(): os.system('x')\n")]);
    assert!(query_hits(&w, "os").has_import("os"));
}

#[test]
fn query_import_as_alias() {
    let w = ws_multi(
        py(),
        &[("/w/a.py", "import numpy as np\ndef f(): np.array([])\n")],
    );
    assert!(query_hits(&w, "numpy").has_import("numpy"));
    // Alias text is also matched.
    assert!(!query_hits(&w, "np").imports.is_empty());
}

#[test]
fn query_from_x_import_y() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "from flask import request\ndef f(): request.args.get('t')\n",
        )],
    );
    assert!(query_hits(&w, "flask").has_import("flask"));
}

#[test]
fn query_from_x_import_y_as_z() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "from flask import request as req\ndef f(): req.args.get('t')\n",
        )],
    );
    // Both the module and the alias should match.
    assert!(query_hits(&w, "flask").has_import("flask"));
    assert!(!query_hits(&w, "req").imports.is_empty());
}

#[test]
fn query_from_dot_relative_import() {
    let w = ws_multi(
        py(),
        &[("/w/pkg/a.py", "from . import helpers\ndef f(): helpers.do()\n")],
    );
    // Relative imports show up as `.` in the module field.
    let h = query_hits(&w, ".");
    assert!(!h.imports.is_empty());
}

#[test]
fn query_from_x_import_star_wildcard() {
    let w = ws_multi(
        py(),
        &[("/w/a.py", "from os.path import *\ndef f(): exists('/tmp')\n")],
    );
    let h = query_hits(&w, "os.path");
    assert!(h.has_import("os.path"));
}

// ===========================================================================
// 4. Branch-split labeling scenario
// ===========================================================================

#[test]
fn branch_split_enumerates_both_paths_to_same_sink() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry(cond):\n    if cond:\n        via_left()\n    else:\n        via_right()\n\
             def via_left():\n    sink()\n\
             def via_right():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 16);
    let left = chains
        .iter()
        .any(|c| c.as_slice() == ["entry", "via_left", "sink"]);
    let right = chains
        .iter()
        .any(|c| c.as_slice() == ["entry", "via_right", "sink"]);
    assert!(left, "then-arm chain missing: {chains:?}");
    assert!(right, "else-arm chain missing: {chains:?}");
}

// ===========================================================================
// 5. Decorators and classes as flow participants
// ===========================================================================

#[test]
fn decorator_is_reported_alongside_decl() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "@app.route('/api')\n@audited\ndef handle():\n    pass\n",
        )],
    );
    let h = query_hits(&w, "audited");
    assert!(h.has_decorator("audited"));
}

#[test]
fn class_method_chain_is_indexed() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "class Service:\n    def run(self):\n        self.helper()\n    def helper(self):\n        sink()\n\
             def sink():\n    pass\n",
        )],
    );
    // The enumerated chain starts at the top-most root (`run`); helper
    // shows up as an intermediate hop.
    assert_chain_contains(&w, "sink", &["run", "helper", "sink"]);
}

// ===========================================================================
// 6. Recursion / cycles must not hang
// ===========================================================================

#[test]
fn recursive_call_does_not_loop_forever() {
    let w = ws_multi(py(), &[("/w/a.py", "def recurse(n):\n    if n: recurse(n-1)\n")]);
    // Even when `recurse` calls itself, enumerate_chains must return in
    // bounded time and surface some chain (possibly a self-cycle).
    let chains = enumerate_chains(&w, "recurse", 16);
    assert!(!chains.is_empty(), "enumeration should not truncate to nothing");
}

// ===========================================================================
// 7. Every flow-construct kind contributes to indexed edges
// ===========================================================================

#[test]
fn assignment_rhs_call_is_indexed_as_edge() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry():\n    x = helper()\n    return x\n\
             def helper():\n    return sink()\n\
             def sink():\n    return 1\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

#[test]
fn return_expression_call_is_indexed_as_edge() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry():\n    return helper()\n\
             def helper():\n    return sink()\n\
             def sink():\n    return 1\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "sink");
}

// ===========================================================================
// 8. --from / --to filter semantics
//
// Pins the CLI's `inspect --from X --to Y` behavior: fuzzy match of the
// needle anywhere in the chain OR the hit text, both flags ANDed. These
// tests codify the contract for the Python adapter specifically —
// every other language re-tests a subset against its own idioms.
// ===========================================================================

#[test]
fn filter_from_entry_to_sink_keeps_cross_module_flow() {
    let w = ws_multi(
        py(),
        &[
            (
                "/w/gateway.py",
                "from user_service import update_user\n\
                 def handle_request():\n    update_user(request.args.get('token'))\n",
            ),
            (
                "/w/user_service.py",
                "from auth_service import run_admin_command\n\
                 def update_user(tok):\n    run_admin_command(tok)\n",
            ),
            (
                "/w/auth_service.py",
                "import os\n\
                 def run_admin_command(cmd):\n    os.system('notify ' + cmd)\n",
            ),
        ],
    );
    // --from handle_request --to os.system: entry matches first hop,
    // os.system matches the hit text (NOT any chain element).
    assert_filters_keep(
        &w,
        "run_admin_command",
        "os.system",
        InspectFilters {
            from: Some("handle_request"),
            to: Some("os.system"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_from_matches_intermediate_hop_not_just_entry() {
    // `--from update_user` should keep the flow even though
    // `update_user` is the middle hop, not the entry.
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def handle_request():\n    update_user()\n\
             def update_user():\n    run_admin_command()\n\
             def run_admin_command():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("update_user"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_to_matches_hit_text_when_chain_ends_at_enclosing_fn() {
    // The chain for an os.system call-hit ends at `run_admin_command`
    // (the enclosing function), not at `os.system`. `--to os.system`
    // must still keep it — the match is against the hit text.
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "import os\n\
             def entry():\n    run_admin_command('id')\n\
             def run_admin_command(cmd):\n    os.system('notify ' + cmd)\n",
        )],
    );
    // Model the hit by treating run_admin_command as the target and
    // "os.system" as the hit text — same as the CLI does for call hits.
    assert_filters_keep(
        &w,
        "run_admin_command",
        "os.system",
        InspectFilters {
            to: Some("os.system"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_to_nonexistent_drops_every_chain() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def handle():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    assert_filters_drop(
        &w,
        "sink",
        "sink",
        InspectFilters {
            to: Some("totally_fake_fn"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_traverses_branch_arms() {
    // --from matches a hop inside a then-branch; --to matches the sink.
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry(c):\n    if c:\n        via_left()\n    else:\n        via_right()\n\
             def via_left():\n    sink()\n\
             def via_right():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("via_left"),
            to: Some("sink"),
            ..Default::default()
        },
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("via_right"),
            to: Some("sink"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_traverses_loop_body() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry(items):\n    for x in items:\n        handler(x)\n\
             def handler(x):\n    sink(x)\n\
             def sink(x):\n    pass\n",
        )],
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("handler"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_traverses_try_except_finally() {
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def entry():\n    try:\n        happy()\n    except ValueError:\n        recover()\n    finally:\n        cleanup()\n\
             def happy():\n    sink()\n\
             def recover():\n    sink()\n\
             def cleanup():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    for via in ["happy", "recover", "cleanup"] {
        assert_filters_keep(
            &w,
            "sink",
            "sink",
            InspectFilters {
                from: Some(via),
                ..Default::default()
            },
        );
    }
}

#[test]
fn filter_standalone_mode_without_query() {
    // The CLI lets users run `inspect --from X --to Y` with no
    // `--query`. At the harness level "no query" means every fact
    // matches the primary matcher, so filter resolution reduces to
    // chain_matches_filters — which is what this helper checks.
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "def handle_request():\n    update_user()\n\
             def update_user():\n    run_admin_command()\n\
             def run_admin_command():\n    sink()\n\
             def sink():\n    pass\n",
        )],
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("request"),
            to: Some("sink"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_with_import_alias_resolves_through_original_name() {
    // `from x import y as z; z()` — the call at the call-site uses the
    // alias `z`, but the caller-map ALSO indexes the edge under the
    // original name `y`. So `enumerate_chains(y)` finds the flow even
    // though no source text says "y()".
    let w = ws_multi(
        py(),
        &[
            (
                "/w/gateway.py",
                "from auth_service import run_admin_command as run_admin\n\
                 def handle_request(cmd):\n    run_admin(cmd)\n",
            ),
            (
                "/w/auth_service.py",
                "import os\n\
                 def run_admin_command(cmd):\n    os.system('x ' + cmd)\n",
            ),
        ],
    );
    // Query by the ORIGINAL imported symbol (not the alias) — must
    // resolve through the alias to find the call.
    assert_chain_contains(&w, "run_admin_command", &["handle_request", "run_admin_command"]);
    // Query by the local alias — also finds the flow.
    let via_alias = enumerate_chains(&w, "run_admin", 32);
    assert!(
        via_alias.iter().any(|c| c.len() >= 2),
        "alias chain missing: {via_alias:?}"
    );
    // --from handle_request --to os.system fuzzy-matches through the flow.
    assert_filters_keep(
        &w,
        "run_admin_command",
        "os.system",
        InspectFilters {
            from: Some("handle_request"),
            to: Some("os.system"),
            ..Default::default()
        },
    );
}

#[test]
fn filter_resolves_import_as_module_alias() {
    // `import x as y` — module alias. Usage is `y.foo()` which
    // short-tails to `foo` automatically, so the original import
    // doesn't need a symbol-alias remap. Verify the chain works.
    let w = ws_multi(
        py(),
        &[("/w/a.py", "import os as o\ndef entry():\n    o.system('x')\n")],
    );
    let h = query_hits(&w, "o.system");
    assert!(
        h.has_call("entry", "o.system"),
        "module-alias call not indexed: {h:?}"
    );
}

#[test]
fn filter_resolves_from_dot_import_relative() {
    let w = ws_multi(
        py(),
        &[
            ("/w/pkg/__init__.py", "from .auth import run_admin_command\n"),
            (
                "/w/pkg/auth.py",
                "import os\ndef run_admin_command(cmd):\n    os.system('x')\n",
            ),
            (
                "/w/pkg/gateway.py",
                "from . import auth\ndef handle(cmd):\n    auth.run_admin_command(cmd)\n",
            ),
        ],
    );
    // `auth.run_admin_command` short-tails to `run_admin_command`.
    assert_chain_from_to(&w, "handle", "run_admin_command");
}

#[test]
fn filter_multiple_from_import_as_aliases_in_one_line() {
    // `from x import a as A, b as B` — tests that the parser handles
    // multiple commas and picks up the last alias rename correctly.
    let w = ws_multi(
        py(),
        &[(
            "/w/a.py",
            "from auth import run_admin_command as ra, verify_token as vt\n\
             def handle():\n    ra(); vt()\n",
        )],
    );
    // The last rename `verify_token as vt` is the one the extractor
    // captures today. Chain to verify_token must resolve via vt alias.
    let chains = enumerate_chains(&w, "verify_token", 32);
    assert!(
        chains.iter().any(|c| c.iter().any(|h| h == "handle")),
        "second alias chain missing: {chains:?}"
    );
}

/// Per-lang coverage: every node type must be reachable by a fuzzy
/// substring filter. `req` matches `request`, `handleRequest`,
/// `update_request_log` — case-insensitive.
#[test]
fn python_fuzzy_from_across_node_types() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "import os\n\
             URL_PREFIX = \"/api/request\"\n\
             def process(payload):\n    pass\n\
             def handle_request(q):\n    \
                 request_url = URL_PREFIX + q\n    \
                 process(request_url)\n",
        )],
    );
    assert_function_named(&w, "handle_request");
    assert_function_named(&w, "process");
    // fuzzy char-by-char: `req` → `request`, `REQ` → `REQUEST`
    assert_fuzzy_substring("handle_request", "req");
    assert_fuzzy_substring("handle_request", "REQ");
    assert_hit_text_match("/api/request", "req");
    // Import hit text: needle `os` fuzzy-matches `os` in imports
    assert_hit_text_match("os", "o");
    assert_sibling_flow_filter_keeps(&w, "handle_request", "request", "process");
}

/// `with open('f') as fh:` — the init call (`open('f')`) must surface
/// as a call inside the enclosing function. Previously the using
/// handler only walked the body field, losing the init.
#[test]
fn python_with_init_call_captured() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def driver():\n    with open('f') as fh:\n        pass\n",
        )],
    );
    assert!(
        calls_contains(&w, "driver", "open"),
        "`with open('f')` init call not captured under `driver`"
    );
}

/// `match X():` — the discriminant call (`X()`) must surface inside
/// the enclosing function. Grammars use `subject`/`value` fields for
/// match, not `condition`.
#[test]
fn python_match_discriminant_call_captured() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def driver(x):\n    match kind():\n        case _: pass\n",
        )],
    );
    assert!(
        calls_contains(&w, "driver", "kind"),
        "match discriminant call `kind()` not captured under `driver`"
    );
}

/// Short-circuit operators (`and`/`or`) — calls on BOTH sides must be
/// captured even though one side is conditional.
#[test]
fn python_short_circuit_calls_captured() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def driver():\n    x = compute() or fallback()\n    y = validate() and save()\n",
        )],
    );
    for name in ["compute", "fallback", "validate", "save"] {
        assert!(
            calls_contains(&w, "driver", name),
            "short-circuit call `{name}` not captured under `driver`"
        );
    }
}

/// Ternary `a if b else c` — both branches' calls must surface.
#[test]
fn python_ternary_calls_captured() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def driver():\n    return process() if check() else reject()\n",
        )],
    );
    for name in ["process", "check", "reject"] {
        assert!(
            calls_contains(&w, "driver", name),
            "ternary call `{name}` not captured under `driver`"
        );
    }
}

#[test]
fn python_filter_rejects_unrelated_hits() {
    let w = ws_multi(py(), &[("/w/m.py", "def entry():\n    print(\"hi\")\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "print", "nowhere", "nothere");
}
