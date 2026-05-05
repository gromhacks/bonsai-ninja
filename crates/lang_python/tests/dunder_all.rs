//! P1.1: `__all__` public-surface narrowing. A top-level
//! `__all__ = [...]` declares the module's explicit exports; decls
//! whose name isn't in the list become `Visibility::Module` so the
//! resolver narrows cross-module candidate sets.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageRegistry, Visibility};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("a.py".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
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
fn dunder_all_narrows_unlisted_top_level_decls() {
    let src = r#"
__all__ = ["public_api"]

def public_api(x):
    return helper(x)

def helper(x):
    return x
"#;
    let db = db_with(src);
    assert_eq!(
        visibility_of(&db, "public_api"),
        Visibility::Public,
        "name listed in __all__ stays Public"
    );
    assert_eq!(
        visibility_of(&db, "helper"),
        Visibility::Module,
        "top-level name absent from __all__ becomes Module-private"
    );
}

#[test]
fn dunder_all_tuple_form_works() {
    let src = r#"
__all__ = ("api_a", "api_b")

def api_a(): pass
def api_b(): pass
def internal(): pass
"#;
    let db = db_with(src);
    assert_eq!(visibility_of(&db, "api_a"), Visibility::Public);
    assert_eq!(visibility_of(&db, "api_b"), Visibility::Public);
    assert_eq!(visibility_of(&db, "internal"), Visibility::Module);
}

#[test]
fn no_dunder_all_keeps_default_public() {
    let src = r#"
def helper(x): return x
def public_api(x): return helper(x)
"#;
    let db = db_with(src);
    // Without __all__, every top-level name remains Public (the
    // dunder rule is the only narrowing).
    assert_eq!(visibility_of(&db, "helper"), Visibility::Public);
    assert_eq!(visibility_of(&db, "public_api"), Visibility::Public);
}

#[test]
fn computed_dunder_all_falls_open() {
    // `__all__ = list(SOMETHING)` is not a literal list/tuple of
    // strings; we deliberately do not narrow in that case.
    let src = r#"
_NAMES = ["api_a"]
__all__ = list(_NAMES)

def api_a(): pass
def helper(): pass
"#;
    let db = db_with(src);
    assert_eq!(visibility_of(&db, "helper"), Visibility::Public);
}

#[test]
fn dunder_all_does_not_affect_class_methods() {
    // Class methods are nested decls; __all__ controls module-level
    // surface only.
    let src = r#"
__all__ = ["Cls"]

class Cls:
    def public_method(self): pass
    def helper_method(self): pass

def utility(): pass
"#;
    let db = db_with(src);
    assert_eq!(visibility_of(&db, "Cls"), Visibility::Public);
    // Methods stay at Public since __all__ doesn't gate them.
    assert_eq!(visibility_of(&db, "public_method"), Visibility::Public);
    assert_eq!(visibility_of(&db, "helper_method"), Visibility::Public);
    // utility (top-level, not in __all__) becomes Module.
    assert_eq!(visibility_of(&db, "utility"), Visibility::Module);
}
