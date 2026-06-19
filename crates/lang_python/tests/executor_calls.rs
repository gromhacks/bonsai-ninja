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

fn calls_in(db: &AnalyzerDb, fn_name: &str) -> Vec<(String, Vec<String>)> {
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

fn walk(events: &[FlowEvent], out: &mut Vec<(String, Vec<String>)>) {
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => {
                out.push((
                    name.clone(),
                    args.iter().map(|arg| arg.value_text.clone()).collect(),
                ));
            }
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
fn asyncio_to_thread_emits_call_to_callable_argument() {
    let db = db_with(
        r#"
import asyncio

async def load_asset(path):
    return await asyncio.to_thread(_read_bytes, path)

def _read_bytes(p):
    return open(p).read()
"#,
    );
    let calls = calls_in(&db, "load_asset");
    assert!(
        calls
            .iter()
            .any(|(name, args)| name == "_read_bytes" && args == &vec!["path".to_string()]),
        "expected synthetic _read_bytes(path) call from asyncio.to_thread, got {calls:?}"
    );
}
