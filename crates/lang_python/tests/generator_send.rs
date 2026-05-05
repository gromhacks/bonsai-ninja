//! P3.3: Python `gen.send(value)` rewriting. The adapter recognizes
//! the `g = gen(); g.send(value)` pattern and rewrites the send call
//! into a synthesized direct call to the generator factory `gen` with
//! `value` as a positional arg, so the engine's interprocedural
//! propagation taints the generator's body when `value` is tainted.

#![allow(clippy::case_sensitive_file_extension_comparisons)]

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

fn calls_in(db: &AnalyzerDb, fn_name: &str) -> Vec<String> {
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

fn walk(events: &[FlowEvent], out: &mut Vec<String>) {
    for e in events {
        match e {
            FlowEvent::Call { name, .. } => out.push(name.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk(then_events, out);
                walk(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } => walk(body, out),
            _ => {}
        }
    }
}

#[test]
fn gen_send_rewrites_to_factory_call() {
    let src = r#"
def gen():
    while True:
        x = yield
        sink(x)

def driver(tainted):
    g = gen()
    next(g)
    g.send(tainted)
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "driver");
    assert!(
        calls.iter().any(|n| n == "gen"),
        "expected synthesized direct call to gen() factory after send rewrite, got {calls:?}"
    );
    // The two distinct gen calls (the original `gen()` factory call
    // and the rewritten send) BOTH appear as `gen`. The engine's
    // interprocedural taint will follow the second one's args into
    // gen's body.
    let gen_count = calls.iter().filter(|n| *n == "gen").count();
    assert!(
        gen_count >= 2,
        "expected at least two `gen` calls (factory + rewritten send), got {gen_count} in {calls:?}"
    );
}

#[test]
fn dynamic_send_target_stays_unrewritten() {
    // `gens[i].send(...)` — the receiver isn't a bare-identifier
    // bound to a known factory, so the rewrite skips it. The raw
    // `.send` call survives.
    let src = r#"
def driver(gens, tainted, i):
    gens[i].send(tainted)
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "driver");
    let has_send = calls.iter().any(|n| n.ends_with(".send"));
    assert!(has_send, "dynamic send must stay unrewritten; got {calls:?}");
}
