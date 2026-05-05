//! P1.2: Lua module-table return idiom. `local M = {}; ...; return M`
//! declares `M` as the file's exported surface. Functions attached to
//! the table (`function M.foo(...)`) keep `Public`; sibling top-level
//! free functions become `Visibility::Module` so the resolver narrows
//! cross-file candidate sets.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageRegistry, Visibility};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("m.lua".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_lua::LuaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

fn visibility_of(db: &AnalyzerDb, name: &str) -> Visibility {
    let g = db.global_index();
    g.find_by_name(name)
        .iter()
        .find_map(|s| g.decl_of(*s).cloned())
        .map(|d| d.visibility)
        .unwrap_or(Visibility::Public)
}

#[test]
fn module_table_export_marks_unlisted_globals_module_private() {
    let src = r#"
local M = {}
function M.public_fn(x) return x end
function exposed_global(x) return M.public_fn(x) end
return M
"#;
    let db = db_with(src);
    assert_eq!(
        visibility_of(&db, "public_fn"),
        Visibility::Public,
        "M.public_fn is exported via the module table"
    );
    assert_eq!(
        visibility_of(&db, "exposed_global"),
        Visibility::Module,
        "free top-level function not on M is module-private"
    );
}

#[test]
fn no_module_return_keeps_default_public() {
    // Files without `return M` (script-style files, top-level
    // statements) keep the default visibility — narrowing is gated
    // on the module-export idiom being present.
    let src = r#"
function exposed_global(x) return x end
print(exposed_global("hi"))
"#;
    let db = db_with(src);
    assert_eq!(
        visibility_of(&db, "exposed_global"),
        Visibility::Public,
        "files without `return M` skip the narrowing"
    );
}

#[test]
fn computed_return_skips_narrowing() {
    // `return setmetatable(M, {})` is not a bare-identifier return;
    // we don't try to resolve metatable-wrapped exports.
    let src = r#"
local M = {}
function M.api(x) return x end
function helper_global(x) return x end
return setmetatable(M, {})
"#;
    let db = db_with(src);
    assert_eq!(
        visibility_of(&db, "helper_global"),
        Visibility::Public,
        "non-bare-identifier return falls open"
    );
}

#[test]
fn local_function_remains_private() {
    // `local function` is already chunk-private. The module-export
    // narrowing should not change that.
    let src = r#"
local M = {}
function M.api(x) return helper(x) end
local function helper(x) return x end
return M
"#;
    let db = db_with(src);
    assert_eq!(
        visibility_of(&db, "helper"),
        Visibility::Private,
        "local functions stay Private (chunk-scoped)"
    );
    assert_eq!(visibility_of(&db, "api"), Visibility::Public);
}
