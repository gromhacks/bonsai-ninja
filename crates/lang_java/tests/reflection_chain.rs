//! Java reflection remains explicit unresolved runtime evidence. Literal
//! class and method strings do not authorize the frontend to invent a direct
//! call edge because class loaders and reflective lookup are runtime state.

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
fn literal_reflection_chain_stays_unresolved() {
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
    assert!(
        calls.iter().any(|(name, _, _)| name == "m.invoke"),
        "the exact reflective call must remain visible, got {calls:?}"
    );
    assert!(
        !calls.iter().any(|(name, _, _)| name == "Sink.run"),
        "literal reflection must not create a guessed Sink.run edge, got {calls:?}"
    );
}

#[test]
fn dynamic_method_name_stays_unrewritten() {
    // Computed method names follow the same exact contract.
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
