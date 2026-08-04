//! P1.2: Lua module-table return idiom. `local M = {}; ...; return M`
//! declares `M` as the file's exported surface. Functions attached to
//! the table (`function M.foo(...)`) keep `Public`; sibling top-level
//! free functions become `Visibility::Module` so the resolver narrows
//! cross-file candidate sets.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{CallKind, FlowEvent, ImportScope, LanguageRegistry, Visibility};
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

#[test]
fn module_table_export_binding_is_resolver_only_import_scope() {
    let src = r#"
local M = {}
function M.api(x) return x end
return M
"#;
    let db = db_with(src);
    let file = db.vfs().all_files()[0];
    let imports = db.imports_for(file);

    assert!(
        imports.iter().any(|imp| {
            imp.module == "m"
                && imp.alias.as_deref() == Some("M")
                && !imp.is_wildcard
                && imp.scope == ImportScope::Local
        }),
        "Lua module table export must stay as resolver-only local binding: {imports:?}"
    );
    assert!(
        !imports.iter().any(|imp| {
            imp.module == "m" && imp.alias.as_deref() == Some("M") && imp.scope == ImportScope::Module
        }),
        "Lua module table export is not an import statement and must not be Module-scope: {imports:?}"
    );
}

#[test]
fn anonymous_function_decl_uses_local_binding_name() {
    let db = db_with("function entry(args)\n  local f = function(x) sink(x) end\n  f(args)\nend\n");
    let global = db.global_index();
    let block = global
        .find_by_name("f")
        .iter()
        .find_map(|symbol| global.decl_of(*symbol))
        .unwrap_or_else(|| {
            panic!("anonymous function must be indexed as local binding `f`; global: {global:?}")
        });

    assert_eq!(block.params, ["x"]);
    assert!(
        block.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, .. } if name == "sink"
        )),
        "anonymous function declaration must own sink(x); got {:?}",
        block.flow_events
    );
}

#[test]
fn dotted_table_call_keeps_explicit_receiver_argument() {
    let db = db_with(
        "local Box = {}\nfunction Box.method(self, p) sink(p) end\nfunction entry(args) Box.method(Box, args) end\n",
    );
    let global = db.global_index();
    let entry = global
        .find_by_name("entry")
        .iter()
        .find_map(|symbol| global.decl_of(*symbol))
        .expect("entry declaration");

    assert!(entry.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, call_kind: CallKind::Function, args, .. }
            if name == "Box.method" && args.len() == 2
    )));
    let method = global
        .find_by_name("method")
        .iter()
        .find_map(|symbol| global.decl_of(*symbol))
        .expect("table member declaration");
    assert_eq!(
        method.qualified_name.as_deref(),
        Some("Box.method"),
        "the Tree-sitter declaration owner must survive into semantic identity"
    );
}

#[test]
fn table_literal_emits_field_scoped_assignments() {
    let db = db_with(
        "function entry(raw, user)\n  local envelope = { cmd = '' .. raw, user = user, clean = 'ok' }\n  sink(envelope.cmd)\nend\n",
    );
    let global = db.global_index();
    let entry = global
        .find_by_name("entry")
        .iter()
        .find_map(|symbol| global.decl_of(*symbol))
        .expect("entry declaration");

    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_names, .. }
                if target == "envelope.cmd" && source_names == &["raw"]
        )),
        "table cmd field should retain only its exact source: {:?}",
        entry.flow_events
    );
    assert!(entry.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "envelope.user" && source_names == &["user"]
    )));
    assert!(entry.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, value_kind, .. }
            if target == "envelope.clean"
                && source_names.is_empty()
                && *value_kind == Some(bonsai_lang_api::AssignValueKind::Literal)
    )));
}
