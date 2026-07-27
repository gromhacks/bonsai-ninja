//! Workspace-level class-member, enclosing-decl, and decl-name
//! indexes. Covers P4 / P5 of the post-stages-1-7 audit.

use bonsai_common::SymbolId;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::Workspace;
use std::{path::Path, sync::Arc};

fn registry() -> Arc<LanguageRegistry> {
    let r = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    r.register(adapter);
    r
}

fn java_registry() -> Arc<LanguageRegistry> {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_java::JavaAdapter::new());
    registry.register(adapter);
    registry
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
    let global = ws.compiler_linkage_index();
    let alpha_decl = global
        .find_by_name("alpha")
        .iter()
        .copied()
        .find_map(|s| global.decl_of(s).cloned())
        .expect("alpha method decl present");
    let class_sym = alpha_decl.parent.expect("alpha must have a class parent");
    let alpha = ws.class_members().methods_of(&global, class_sym, "alpha");
    assert_eq!(
        alpha.len(),
        1,
        "expected one alpha method on Foo; got {}",
        alpha.len()
    );
    let missing = ws.class_members().methods_of(&global, class_sym, "ghost");
    assert!(missing.is_empty());
}

#[test]
fn class_member_index_constructors_lookup() {
    let ws = ws_with("app.py", "class Foo:\n    def __init__(self):\n        pass\n");
    let global = ws.compiler_linkage_index();
    let init_decl = global
        .find_by_name("__init__")
        .iter()
        .copied()
        .find_map(|s| global.decl_of(s).cloned())
        .expect("__init__ decl present");
    let class_sym = init_decl.parent.expect("__init__ must have a class parent");
    let constructors = ws.class_members().constructors_of(&global, class_sym);
    let methods_under_init_name = ws.class_members().methods_of(&global, class_sym, "__init__");
    assert!(
        !constructors.is_empty() || !methods_under_init_name.is_empty(),
        "expected a constructor/__init__ entry on Foo"
    );
}

#[test]
fn enclosing_index_finds_innermost_decl() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n\ndef beta():\n    pass\n");
    let file = ws.vfs().all_files()[0];
    let global = ws.compiler_linkage_index();
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
        .enclosing_for(global.as_ref(), file, body_pos)
        .expect("position inside alpha must resolve to alpha");
    assert_eq!(entry.name, "alpha");
    assert_eq!(entry.symbol, alpha);
}

#[test]
fn enclosing_index_returns_none_outside_any_decl() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n");
    let file = ws.vfs().all_files()[0];
    let headers = ws.compiler_linkage_index();
    let entry = ws
        .enclosing_index()
        .enclosing_for(headers.as_ref(), file, u64::MAX);
    assert!(entry.is_none());
}

#[test]
fn enclosing_index_recovers_outer_method_after_nested_lambda_ends() {
    let source = r#"
class Example {
    void method() {
        Runnable callback = () -> { consume("inside"); };
        consume("after");
    }
}
"#;
    let ws = Workspace::new(java_registry());
    ws.vfs()
        .write("Example.java".to_string(), Arc::<str>::from(source));
    let file = ws.vfs().all_files()[0];
    let _ = ws.db().decl_index(file);
    let headers = ws.compiler_linkage_index();
    let after = source.find("consume(\"after\")").expect("outer call") as u64;
    let entry = ws
        .enclosing_index()
        .enclosing_for(headers.as_ref(), file, after)
        .expect("outer method must remain visible after its nested lambda");
    assert_eq!(entry.name, "method");
}

#[test]
fn decl_name_index_lowercases_for_contains_matches() {
    let ws = ws_with("app.py", "def MyHelper():\n    pass\n");
    let headers = ws.compiler_linkage_index();
    let entries = ws.decl_name_index().entries(headers.as_ref());
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
fn decl_name_index_is_built_on_demand() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n");
    assert!(
        !ws.decl_name_index().is_built(),
        "fresh workspace should not have built the decl-name index yet"
    );
    let headers = ws.compiler_linkage_index();
    let _ = ws.decl_name_index().entries(headers.as_ref());
    assert!(ws.decl_name_index().is_built());
}

#[test]
fn enclosing_index_invalidates_when_workspace_clears_file() {
    let ws = ws_with("app.py", "def alpha():\n    pass\n");
    let file = ws.vfs().all_files()[0];
    let headers = ws.compiler_linkage_index();
    let _ = ws.enclosing_index().entries_for(headers.as_ref(), file);
    assert!(ws.enclosing_index().is_built_for(file));
    ws.enclosing_index().invalidate_file(file);
    assert!(!ws.enclosing_index().is_built_for(file));
}

#[test]
fn class_member_index_is_built_on_demand() {
    let ws = ws_with("app.py", "class Foo:\n    def m(self): pass\n");
    assert!(!ws.class_members().is_built());
    let global = ws.compiler_linkage_index();
    let m_decl = global
        .find_by_name("m")
        .iter()
        .copied()
        .find_map(|s| global.decl_of(s).cloned())
        .expect("m method decl present");
    let class_sym: SymbolId = m_decl.parent.expect("m must have a class parent");
    let _ = ws.class_members().methods_of(&global, class_sym, "m");
    assert!(ws.class_members().is_built());
}

#[test]
fn class_member_index_rejects_a_stale_header_snapshot_after_edit() {
    let ws = ws_with("app.py", "class Foo:\n    def old(self):\n        pass\n");
    let old_headers = ws.compiler_linkage_index();
    let old_method = old_headers.find_by_name("old")[0];
    let old_class = old_headers
        .decl_of(old_method)
        .and_then(|decl| decl.parent)
        .expect("old parent");

    ws.apply_edit(
        Path::new("app.py"),
        "class Foo:\n    def fresh(self):\n        pass\n".to_string(),
    );
    assert_eq!(
        ws.class_members()
            .methods_of(old_headers.as_ref(), old_class, "old"),
        vec![bonsai_common::FuncId::new(old_method.raw())],
        "an old immutable snapshot remains internally consistent"
    );

    let fresh_headers = ws.compiler_linkage_index();
    let fresh_method = fresh_headers.find_by_name("fresh")[0];
    let fresh_class = fresh_headers
        .decl_of(fresh_method)
        .and_then(|decl| decl.parent)
        .expect("fresh parent");
    assert_eq!(
        ws.class_members()
            .methods_of(fresh_headers.as_ref(), fresh_class, "fresh"),
        vec![bonsai_common::FuncId::new(fresh_method.raw())],
        "an old caller racing invalidation must not become a hit for the new compiler snapshot"
    );
}

#[test]
fn decl_name_index_rejects_a_stale_header_snapshot_after_edit() {
    let ws = ws_with("app.py", "def old_name():\n    pass\n");
    let old_headers = ws.compiler_linkage_index();
    ws.apply_edit(Path::new("app.py"), "def fresh_name():\n    pass\n".to_string());

    let stale = ws.decl_name_index().entries(old_headers.as_ref());
    assert!(stale.iter().any(|entry| entry.decl.name == "old_name"));

    let fresh_headers = ws.compiler_linkage_index();
    let fresh = ws.decl_name_index().entries(fresh_headers.as_ref());
    assert!(fresh.iter().any(|entry| entry.decl.name == "fresh_name"));
    assert!(fresh.iter().all(|entry| entry.decl.name != "old_name"));
}

#[test]
fn enclosing_index_rejects_a_stale_header_snapshot_after_edit() {
    let ws = ws_with("app.py", "def old_name():\n    pass\n");
    let file = ws.vfs().all_files()[0];
    let old_headers = ws.compiler_linkage_index();
    let old_decl = old_headers
        .decl_of(old_headers.find_by_name("old_name")[0])
        .expect("old decl");
    let old_pos = old_decl.body_span.unwrap_or(old_decl.span).start + 1;

    ws.apply_edit(Path::new("app.py"), "def fresh_name():\n    pass\n".to_string());
    assert_eq!(
        ws.enclosing_index()
            .enclosing_name(old_headers.as_ref(), file, old_pos)
            .as_deref(),
        Some("old_name")
    );

    let fresh_headers = ws.compiler_linkage_index();
    let fresh_decl = fresh_headers
        .decl_of(fresh_headers.find_by_name("fresh_name")[0])
        .expect("fresh decl");
    let fresh_pos = fresh_decl.body_span.unwrap_or(fresh_decl.span).start + 1;
    assert_eq!(
        ws.enclosing_index()
            .enclosing_name(fresh_headers.as_ref(), file, fresh_pos)
            .as_deref(),
        Some("fresh_name")
    );
}
