use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn call_argument_places(source: &str) -> Vec<(String, Option<String>)> {
    let vfs = Arc::new(Vfs::new());
    vfs.write("sample.py".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let mut out = Vec::new();

    fn walk(events: &[FlowEvent], out: &mut Vec<(String, Option<String>)>) {
        for event in events {
            match event {
                FlowEvent::Call { name, args, .. } if name == "sink" => {
                    out.extend(args.iter().map(|arg| (arg.value_text.clone(), arg.place.clone())));
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    walk(then_events, out);
                    walk(else_events, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => walk(body, out),
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

    let global = db.global_index();
    for file in global.all_files() {
        for declaration in global.decls_in(file) {
            walk(&declaration.flow_events, &mut out);
        }
    }
    out
}

fn return_places(source: &str) -> Vec<(String, Option<String>, Option<String>)> {
    let vfs = Arc::new(Vfs::new());
    vfs.write("sample.py".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let global = db.global_index();
    let mut out = Vec::new();

    fn walk(
        declaration: &str,
        events: &[FlowEvent],
        out: &mut Vec<(String, Option<String>, Option<String>)>,
    ) {
        for event in events {
            match event {
                FlowEvent::Return {
                    value_name,
                    value_flow,
                    ..
                } => out.push((
                    declaration.to_string(),
                    value_name.clone(),
                    value_flow.place.clone(),
                )),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    walk(declaration, then_events, out);
                    walk(declaration, else_events, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => walk(declaration, body, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(declaration, body, out);
                    walk(declaration, catch_events, out);
                    walk(declaration, finally_events, out);
                }
                _ => {}
            }
        }
    }

    for file in global.all_files() {
        for declaration in global.decls_in(file) {
            walk(&declaration.name, &declaration.flow_events, &mut out);
        }
    }
    out.sort();
    out
}

#[test]
fn static_subscripts_are_exact_compiler_places() {
    let places =
        call_argument_places("def entry(obj):\n    sink(obj['other'])\n    sink(obj[\"nested\"]['leaf'])\n");
    assert_eq!(
        places,
        vec![
            ("obj['other']".to_string(), Some("obj.other".to_string())),
            (
                "obj[\"nested\"]['leaf']".to_string(),
                Some("obj.nested.leaf".to_string()),
            ),
        ]
    );
}

#[test]
fn dynamic_subscripts_do_not_claim_an_exact_field() {
    let places = call_argument_places("def entry(obj, key):\n    sink(obj[key])\n");
    assert_eq!(
        places,
        vec![("obj[key]".to_string(), Some("obj.*".to_string()))],
        "a dynamic key addresses an unknown descendant, never a made-up exact field"
    );
}

#[test]
fn static_subscript_returns_are_exact_compiler_places() {
    let places = return_places(
        "def leaf(obj):\n    return obj['value']\n\ndef nested(obj):\n    return obj['nested']['leaf']\n",
    );
    assert_eq!(
        places,
        vec![
            (
                "leaf".to_string(),
                Some("obj.value".to_string()),
                Some("obj.value".to_string()),
            ),
            (
                "nested".to_string(),
                Some("obj.nested.leaf".to_string()),
                Some("obj.nested.leaf".to_string()),
            ),
        ]
    );
}

#[test]
fn dynamic_subscript_returns_remain_aggregate_reads() {
    let places = return_places("def entry(obj, key):\n    return obj[key]\n");
    assert_eq!(
        places,
        vec![("entry".to_string(), None, Some("obj.*".to_string()),)],
        "a dynamic key must remain an explicit wildcard descendant place"
    );
}
