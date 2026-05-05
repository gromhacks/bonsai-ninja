//! P0.2: JavaScript class-bases extraction. The JS adapter populates
//! `Decl.bases` from `class Foo extends Bar { ... }` so the resolver
//! can narrow virtual-dispatch candidate sets the same way TypeScript
//! and Python already do.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn js_db(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("a.js".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

fn bases_of(db: &AnalyzerDb, name: &str) -> Vec<String> {
    let g = db.global_index();
    g.find_by_name(name)
        .iter()
        .find_map(|s| g.decl_of(*s).cloned())
        .map(|d| d.bases)
        .unwrap_or_default()
}

#[test]
fn class_extends_populates_bases() {
    let db = js_db("class Echo extends WebSocketHandler { handle(msg) { return msg; } }\n");
    let bases = bases_of(&db, "Echo");
    assert_eq!(
        bases,
        vec!["WebSocketHandler".to_string()],
        "extends clause must populate Decl.bases"
    );
}

#[test]
fn class_without_extends_has_empty_bases() {
    let db = js_db("class Standalone { f() {} }\n");
    let bases = bases_of(&db, "Standalone");
    assert!(bases.is_empty(), "no extends clause = empty bases, got {bases:?}");
}

#[test]
fn class_extends_qualified_name_uses_tail() {
    // Real-world idiom: `class MyError extends framework.BaseError`.
    // We canonicalise to the tail name so cross-module resolver lookups
    // match by simple name.
    let db = js_db("class MyError extends framework.BaseError {}\n");
    let bases = bases_of(&db, "MyError");
    assert_eq!(
        bases,
        vec!["BaseError".to_string()],
        "qualified extends should canonicalise to tail name"
    );
}
