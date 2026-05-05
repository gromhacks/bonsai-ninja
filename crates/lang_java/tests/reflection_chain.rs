//! P3.2: Java reflection-chain rewriting. The adapter recognizes
//! `Class.forName("X").getMethod("Y").invoke(target, args)` and
//! rewrites the `m.invoke(...)` call into a synthesized direct call
//! `X.Y(args)` so the resolver narrows like a normal method dispatch.
//! Dynamic forms (computed string args) stay unrewritten.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("C.java".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

fn calls_in(db: &AnalyzerDb, fn_name: &str) -> Vec<(String, Option<String>, Vec<String>)> {
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

fn walk(events: &[FlowEvent], out: &mut Vec<(String, Option<String>, Vec<String>)>) {
    for e in events {
        match e {
            FlowEvent::Call {
                name, receiver, args, ..
            } => out.push((
                name.clone(),
                receiver.clone(),
                args.iter().map(|a| a.value_text.clone()).collect(),
            )),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk(then_events, out);
                walk(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk(body, out);
                walk(catch_events, out);
                walk(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn class_forname_get_method_invoke_rewrites_to_direct_call() {
    let src = r#"
class C {
  void entry(String tainted) throws Exception {
    Class<?> c = Class.forName("Sink");
    java.lang.reflect.Method m = c.getMethod("run", String.class);
    m.invoke(null, tainted);
  }
}
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "entry");
    let synthesized = calls.iter().find(|(name, _, _)| name == "Sink.run").cloned();
    assert!(
        synthesized.is_some(),
        "expected synthesized Sink.run call after reflection rewrite, got {calls:?}"
    );
    if let Some((_name, receiver, args)) = synthesized {
        assert_eq!(receiver.as_deref(), Some("Sink"));
        assert_eq!(
            args,
            vec!["tainted".to_string()],
            "the leading null/target arg should be stripped, leaving only real args"
        );
    }
    assert!(
        !calls.iter().any(|(name, _, _)| name == "m.invoke"),
        "raw m.invoke must be rewritten away, not duplicated; got {calls:?}"
    );
}

#[test]
fn dynamic_method_name_stays_unrewritten() {
    // Computed method name — adapter cannot resolve a target, so the
    // raw `m.invoke` call survives and the engine's reflection
    // rule-load-rejection still applies.
    let src = r#"
class C {
  void entry(String tainted, String methodName) throws Exception {
    Class<?> c = Class.forName("Sink");
    java.lang.reflect.Method m = c.getMethod(methodName);
    m.invoke(null, tainted);
  }
}
"#;
    let db = db_with(src);
    let calls = calls_in(&db, "entry");
    assert!(
        calls.iter().any(|(name, _, _)| name == "m.invoke"),
        "dynamic getMethod arg must leave the chain unrewritten; got {calls:?}"
    );
}
