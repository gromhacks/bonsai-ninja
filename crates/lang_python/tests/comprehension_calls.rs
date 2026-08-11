//! Python comprehensions can hide sink calls in their iterable clause:
//! `[x for x in tree.xpath(expr)]`. The generic walker surfaced the
//! comprehension body call (`str(x)`) but missed the iterable call,
//! which made taint sinks inside comprehensions invisible.

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

fn calls_in(db: &AnalyzerDb, fn_name: &str) -> Vec<(String, Vec<Vec<String>>)> {
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

fn walk(events: &[FlowEvent], out: &mut Vec<(String, Vec<Vec<String>>)>) {
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => out.push((
                name.clone(),
                args.iter().map(|arg| arg.source_names.clone()).collect(),
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
fn iterable_call_in_list_comprehension_is_a_call_event() {
    let db = db_with(
        r#"
def search(tree, expr):
    return [str(s) for s in tree.xpath(expr)]
"#,
    );
    let calls = calls_in(&db, "search");
    assert!(
        calls.iter().any(|(name, arg_sources)| name == "tree.xpath"
            && arg_sources
                .iter()
                .any(|sources| sources.iter().any(|source| source == "expr"))),
        "expected tree.xpath(expr) call from comprehension iterable, got {calls:?}"
    );
}

#[test]
fn comprehension_binds_target_from_iterable_without_overwriting_iterable() {
    let db = db_with(
        r#"
def filter_parts(parts):
    return [p for p in parts if p]
"#,
    );
    let global = db.global_index();
    let declaration = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "filter_parts")
        .expect("filter_parts declaration");
    let assignments = declaration
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                ..
            } => Some((target.as_str(), source_name.as_deref(), source_names.as_slice())),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(
        assignments.iter().any(|(target, source, sources)| {
            *target == "p" && *source == Some("parts") && sources.iter().any(|name| name == "parts")
        }),
        "the Tree-sitter `left` binding must receive the `right` iterable: {assignments:?}"
    );
    assert!(
        !assignments
            .iter()
            .any(|(target, source, _)| *target == "parts" && *source == Some("p")),
        "a comprehension must not manufacture the reversed overwrite `parts = p`: {assignments:?}"
    );
}
