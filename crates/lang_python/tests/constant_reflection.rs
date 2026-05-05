//! P2.1: Python constant-string reflection rewriting. The Python
//! adapter rewrites `getattr(obj, "literal", default)` /
//! `setattr(obj, "literal", value)` / `hasattr(obj, "literal")` into
//! the synthesized attribute call `obj.literal(...)` so the engine
//! resolves dispatch by name like a normal method call. Dynamic
//! forms (`getattr(obj, runtime_name)`) stay unrewritten and the
//! engine's `reflection: Unsupported` rule continues to gate them.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
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

fn calls_in(db: &AnalyzerDb, fn_name: &str) -> Vec<(String, Option<String>)> {
    let g = db.global_index();
    let mut out = Vec::new();
    for f in g.all_files() {
        for decl in g.decls_in(f) {
            if decl.name != fn_name {
                continue;
            }
            walk(&decl.flow_events, &mut out);
        }
    }
    out
}

fn walk(events: &[FlowEvent], out: &mut Vec<(String, Option<String>)>) {
    for e in events {
        match e {
            FlowEvent::Call { name, receiver, .. } => out.push((name.clone(), receiver.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk(then_events, out);
                walk(else_events, out);
            }
            FlowEvent::Loop { body, .. } => walk(body, out),
            _ => {}
        }
    }
}

#[test]
fn constant_getattr_rewrites_to_attribute_call() {
    let src = r#"
def main(obj, x):
    getattr(obj, "process")(x)
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "main");
    let has_rewrite = calls
        .iter()
        .any(|(name, recv)| name == "obj.process" && recv.as_deref() == Some("obj"));
    let has_raw_getattr = calls.iter().any(|(name, _)| name == "getattr");
    assert!(
        has_rewrite,
        "expected synthesized obj.process call after rewrite, got {calls:?}"
    );
    assert!(
        !has_raw_getattr,
        "raw getattr call must be rewritten away, not duplicated; got {calls:?}"
    );
}

#[test]
fn dynamic_getattr_stays_unrewritten() {
    let src = r#"
def main(obj, name):
    getattr(obj, name)()
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "main");
    let has_raw_getattr = calls.iter().any(|(name, _)| name == "getattr");
    assert!(
        has_raw_getattr,
        "dynamic getattr (non-literal second arg) must stay as `getattr` for the engine to gate; \
         got {calls:?}"
    );
}

#[test]
fn constant_setattr_rewrites() {
    let src = r#"
def main(obj, value):
    setattr(obj, "prop", value)
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "main");
    assert!(
        calls.iter().any(|(name, _)| name == "obj.prop"),
        "expected synthesized obj.prop from setattr rewrite, got {calls:?}"
    );
}

#[test]
fn constant_hasattr_rewrites() {
    let src = r#"
def main(obj):
    if hasattr(obj, "feature"):
        pass
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "main");
    assert!(
        calls.iter().any(|(name, _)| name == "obj.feature"),
        "expected synthesized obj.feature from hasattr rewrite, got {calls:?}"
    );
}

#[test]
fn single_quoted_literal_rewrites() {
    // Python equivalent quotes — both `"x"` and `'x'` should rewrite.
    let src = r#"
def main(obj, value):
    setattr(obj, 'prop', value)
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "main");
    assert!(
        calls.iter().any(|(name, _)| name == "obj.prop"),
        "single-quoted literal also rewrites, got {calls:?}"
    );
}
