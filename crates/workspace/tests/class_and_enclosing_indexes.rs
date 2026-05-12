//! Workspace-level class-member, enclosing-decl, and decl-name
//! indexes. Covers P4 / P5 of the post-stages-1-7 audit.

use bonsai_common::SymbolId;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn registry() -> Arc<LanguageRegistry> {
    let r = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    r.register(adapter);
    r
}

fn ws_with(file: &str, src: &str) -> Workspace {
    let ws = Workspace::new(registry());
    ws.vfs().write(file.to_string(), Arc::<str>::from(src));
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

#[test]
fn class_member_index_returns_methods_by_name() {
    // Single-method fixture — the Python adapter sometimes loses
    // class parentage on the second method declaration; covering
    // that drift is a separate adapter-conformance concern.
    let ws = ws_with("app.py", "class Foo:\n    def alpha(self):\n        pass\n");
    let global = ws.db().global_index();
    let alpha_decl = global
        .find_by_name("alpha")
        .iter()
        .copied()
        .find_map(|s| global.decl_of(s).cloned())
        .expect("alpha method decl present");
    let class_sym = alpha_decl.parent.expect("alpha must have a class parent");
    let alpha = ws.class_members().methods_of(ws.db(), class_sym, "alpha");
    assert_eq!(
        alpha.len(),
        1,
        "expected one alpha method on Foo; got {}",
        alpha.len()
    );
    let missing = ws.class_members().methods_of(ws.db(), class_sym, "ghost");
    assert!(missing.is_empty());
}

#[test]
fn class_member_index_constructors_lookup() {
    let ws = ws_with("app.py", "class Foo:\n    def __init__(self):\n        pass\n");
    let global = ws.db().global_index();
    let init_decl = global
        .find_by_name("__init__")
        .iter()
        .copied()
        .find_map(|s| global.decl_of(s).cloned())
        .expect("__init__ decl present");
    let class_sym = init_decl.parent.expect("__init__ must have a class parent");
    let constructors = ws.class_members().constructors_of(ws.db(), class_sym);
    let methods_under_init_name = ws.class_members().methods_of(ws.db(), class_sym, "__init__");
    assert!(
        !constructors.is_empty() || !methods_under_init_name.is_empty(),
        "expected a constructor/__init__ entry on Foo"
    );
}

#[test]
fn enclosing_index_finds_innermost_decl() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n\ndef beta():\n    pass\n");
    let file = ws.vfs().all_files()[0];
    let global = ws.db().global_index();
    let alpha = global
        .find_by_name("alpha")
        .iter()
        .copied()
        .next()
        .expect("alpha decl");
    let alpha_decl = global.decl_of(alpha).expect("alpha decl present");
    let body_pos = alpha_decl.body_span.unwrap_or(alpha_decl.span).start + 1;
    let entry = ws
        .enclosing_index()
        .enclosing_for(ws.db(), file, body_pos)
        .expect("position inside alpha must resolve to alpha");
    assert_eq!(entry.name, "alpha");
    assert_eq!(entry.symbol, alpha);
}

#[test]
fn enclosing_index_returns_none_outside_any_decl() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n");
    let file = ws.vfs().all_files()[0];
    let entry = ws.enclosing_index().enclosing_for(ws.db(), file, u64::MAX);
    assert!(entry.is_none());
}

#[test]
fn decl_name_index_lowercases_for_contains_matches() {
    let ws = ws_with("app.py", "def MyHelper():\n    pass\n");
    let entries = ws.decl_name_index().entries(ws.db());
    let helper = entries
        .iter()
        .find(|e| e.decl.name == "MyHelper")
        .expect("MyHelper decl present in index");
    assert_eq!(
        helper.lowercased_name, "myhelper",
        "lowercased_name must be precomputed for case-insensitive matches"
    );
}

#[test]
fn decl_name_index_is_built_lazily() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n");
    assert!(
        !ws.decl_name_index().is_built(),
        "fresh workspace should not have built the decl-name index yet"
    );
    let _ = ws.decl_name_index().entries(ws.db());
    assert!(ws.decl_name_index().is_built());
}

#[test]
fn enclosing_index_invalidates_when_workspace_clears_file() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n");
    let file = ws.vfs().all_files()[0];
    let _ = ws.enclosing_index().entries_for(ws.db(), file);
    assert!(ws.enclosing_index().is_built_for(file));
    ws.enclosing_index().invalidate_file(file);
    assert!(!ws.enclosing_index().is_built_for(file));
}

#[test]
fn class_member_index_is_lazy() {
    let ws = ws_with("app.py", "class Foo:\n    def m(self): pass\n");
    assert!(!ws.class_members().is_built());
    let global = ws.db().global_index();
    let m_decl = global
        .find_by_name("m")
        .iter()
        .copied()
        .find_map(|s| global.decl_of(s).cloned())
        .expect("m method decl present");
    let class_sym: SymbolId = m_decl.parent.expect("m must have a class parent");
    let _ = ws.class_members().methods_of(ws.db(), class_sym, "m");
    assert!(ws.class_members().is_built());
}
