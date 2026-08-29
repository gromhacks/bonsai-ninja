//! Regression coverage for framework APIs supplied by the runtime or an
//! inherited controller context rather than a literal import in each source
//! file.
//!
//! Package identity remains rule data. The matcher may accept either an exact
//! compiler import or language-scoped dependency-manifest evidence; it must
//! not require applications to write non-idiomatic imports merely to satisfy a
//! source rule.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

static CACHE_ENV_LOCK: Mutex<()> = Mutex::new(());

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn with_indexed_workspace<T>(root: &Path, f: impl FnOnce(&bonsai_workspace::Workspace) -> T) -> T {
    let _cache_env_guard = CACHE_ENV_LOCK.lock().expect("cache environment lock");
    let cache = tempfile::tempdir().expect("temporary external analysis cache");
    let previous_cache = std::env::var_os("BONSAI_WORKSPACE_DIR");
    std::env::set_var("BONSAI_WORKSPACE_DIR", cache.path());
    let ws = bonsai_workspace::Workspace::index(root, bonsai_adapters::all_languages_registry())
        .expect("index source workspace");
    let result = f(&ws);
    match previous_cache {
        Some(value) => std::env::set_var("BONSAI_WORKSPACE_DIR", value),
        None => std::env::remove_var("BONSAI_WORKSPACE_DIR"),
    }
    result
}

fn inventory_rule_ids(root: &Path) -> Vec<String> {
    with_indexed_workspace(root, |ws| {
        let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
        bonsai_security::source_inventory(ws, &pack, bonsai_security::SecurityInventoryOptions::default())
            .expect("source inventory")
            .into_iter()
            .map(|source| source.rule_id)
            .collect()
    })
}

#[test]
fn exact_owned_sources_accept_manifest_or_compiler_owner_provenance() {
    let cases = [(
        "ruby",
        "Gemfile",
        "gem \"actionpack\"\n",
        "users_controller.rb",
        "class UsersController < ActionController::Base\n  def show\n    value = params[:id]\n  end\nend\n",
        "ruby.source.params_read",
    )];

    for (language, manifest, manifest_text, source, source_text, expected_rule) in cases {
        let workspace = tempfile::tempdir().expect("temporary source workspace");
        std::fs::write(workspace.path().join(manifest), manifest_text).expect("write dependency manifest");
        std::fs::write(workspace.path().join(source), source_text).expect("write source file");

        let ids = inventory_rule_ids(workspace.path());
        assert!(
            ids.iter().any(|id| id == expected_rule),
            "{language} runtime/inherited framework source must be enabled by its language manifest without a literal source-file import; expected {expected_rule}, got {ids:?}"
        );

        let package_absent = tempfile::tempdir().expect("temporary package-absent workspace");
        std::fs::write(package_absent.path().join(source), source_text)
            .expect("write package-absent source file");
        let absent_ids = inventory_rule_ids(package_absent.path());
        assert!(
            absent_ids.iter().any(|id| id == expected_rule),
            "{language} source rule {expected_rule} has an exact compiler-owned enclosing class/base, so it must not require a redundant package token; got {absent_ids:?}"
        );
    }

    // One language's manifest must never authorize another adapter's rule
    // data in a mixed workspace.
    let workspace = tempfile::tempdir().expect("temporary mixed workspace");
    std::fs::write(workspace.path().join("Gemfile"), "gem \"actionpack\"\n").expect("write Ruby manifest");
    std::fs::write(
        workspace.path().join("unrelated.lua"),
        "local function handle()\n  return params[\"id\"]\nend\n",
    )
    .expect("write unrelated Lua source");

    let ids = inventory_rule_ids(workspace.path());
    assert!(
        ids.iter().all(|id| !id.starts_with("ruby.source.")),
        "Ruby manifest packages must not project Ruby source rules onto Lua compiler facts: {ids:?}"
    );

    // A same-language import in an unrelated sibling is intentionally weaker
    // than a dependency manifest: it proves only that one file uses the
    // package, not that a generic source-shaped value in another file belongs
    // to that framework.
    let sibling_import = tempfile::tempdir().expect("temporary sibling-import workspace");
    std::fs::write(sibling_import.path().join("boot.rb"), "require \"actionpack\"\n")
        .expect("write sibling package import");
    std::fs::write(
        sibling_import.path().join("plain.rb"),
        "def helper(params)\n  value = params[:id]\nend\n",
    )
    .expect("write unrelated source-shaped Ruby code");
    let sibling_ids = inventory_rule_ids(sibling_import.path());
    assert!(
        sibling_ids.iter().all(|id| id != "ruby.source.params_read"),
        "a sibling import alone must not authorize a generic source rule in another file: {sibling_ids:?}"
    );
}

#[test]
fn exact_runtime_and_module_qualified_sources_do_not_require_nonidiomatic_manifests() {
    let cases = [
        (
            "lua",
            "handler.lua",
            "local function handle()\n  local args = ngx.req.get_uri_args()\n  return args\nend\n",
            "lua.source.openresty_get_uri_args",
            "local ngx = { req = { get_uri_args = function() return {} end } }\nlocal function handle()\n  return ngx.req.get_uri_args()\nend\n",
        ),
        (
            "erlang",
            "handler.erl",
            "-module(handler).\n-export([handle/1]).\nhandle(Req) -> cowboy_req:match_qs([{q, [], <<>>}], Req).\n",
            "erlang.source.cowboy_match_qs",
            "-module(handler).\n-export([handle/1]).\nhandle(Req) -> application_req:match_qs([{q, [], <<>>}], Req).\n",
        ),
    ];

    for (language, source, source_text, expected_rule, collision_text) in cases {
        let workspace = tempfile::tempdir().expect("temporary exact-source workspace");
        std::fs::write(workspace.path().join(source), source_text).expect("write exact source file");
        let ids = inventory_rule_ids(workspace.path());
        assert!(
            ids.iter().any(|id| id == expected_rule),
            "{language} exact runtime/module-qualified source must not require a non-idiomatic package manifest; expected {expected_rule}, got {ids:?}"
        );

        let collision = tempfile::tempdir().expect("temporary exact-source collision workspace");
        std::fs::write(collision.path().join(source), collision_text)
            .expect("write exact-source collision file");
        let collision_ids = inventory_rule_ids(collision.path());
        assert!(
            collision_ids.iter().all(|id| id != expected_rule),
            "{language} local/wrong-module collision must not satisfy {expected_rule}: {collision_ids:?}"
        );
    }
}

#[test]
fn inherited_framework_sources_use_exact_transitive_compiler_ancestry() {
    let workspace = tempfile::tempdir().expect("temporary Rails workspace");
    std::fs::write(workspace.path().join("Gemfile"), "gem \"actionpack\"\n").expect("write Ruby manifest");
    std::fs::write(
        workspace.path().join("application_controller.rb"),
        "class ApplicationController < ActionController::Base\nend\n",
    )
    .expect("write framework base controller");
    std::fs::write(
        workspace.path().join("users_controller.rb"),
        "class UsersController < ApplicationController\n  def show\n    value = params[:id]\n  end\nend\n",
    )
    .expect("write inherited controller");

    let (ids, users_bases) = with_indexed_workspace(workspace.path(), |ws| {
        let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
        let ids = bonsai_security::source_inventory(
            ws,
            &pack,
            bonsai_security::SecurityInventoryOptions::default(),
        )
        .expect("source inventory")
        .into_iter()
        .map(|source| source.rule_id)
        .collect::<Vec<_>>();
        let ancestry = ws.compiler_receiver_ancestry();
        let users_file = ws
            .db()
            .vfs()
            .all_files()
            .into_iter()
            .find(|file| {
                ws.db()
                    .vfs()
                    .path(*file)
                    .is_ok_and(|path| path.ends_with("users_controller.rb"))
            })
            .expect("users controller file");
        let mut index = ws
            .db()
            .compiler_file_object_uncached(users_file)
            .and_then(|object| object.declarations)
            .expect("users controller compiler body");
        ancestry.apply_to_decl_index(&mut index);
        let bases = index
            .defs
            .iter()
            .find(|decl| decl.name == "UsersController")
            .expect("users controller declaration")
            .bases
            .clone();
        (ids, bases)
    });
    assert!(
        users_bases.iter().any(|base| base == "ActionController::Base"),
        "compiler ancestry must expand the inherited controller before rule matching: {users_bases:?}"
    );
    assert!(
        ids.iter().any(|id| id == "ruby.source.params_read"),
        "a source in a transitive framework subclass must retain the manifest package and exact compiler ancestry: {ids:?}"
    );
}
