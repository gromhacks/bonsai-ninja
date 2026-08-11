use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_python::PythonAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.py", "def main():\n    pass")]);
}

#[test]
fn match_patterns_bind_only_capture_positions_to_the_subject() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.py",
            r#"def main(subject, limit):
    match subject:
        case {"value": value, "nested": {"item": item}, **rest} if limit:
            sink(value, item, rest)
        case Point(x=px, y=py) as point:
            sink(px, py, point)
"#,
        )],
    );
    let global = ws.db().global_index();
    let main = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    let mut facts = Vec::new();
    collect_assignments(&main.flow_events, &mut facts);
    for (target, source) in [
        ("value", "subject.value"),
        ("item", "subject.nested.item"),
        ("rest", "subject.*"),
        ("px", "subject.x"),
        ("py", "subject.y"),
        ("point", "subject"),
    ] {
        assert!(
            facts
                .iter()
                .any(|(actual, actual_source)| actual == target && actual_source.as_deref() == Some(source)),
            "missing {target} <- {source}: {facts:#?}"
        );
    }
    for non_binding in ["nested", "x", "y", "Point", "limit"] {
        assert!(
            facts.iter().all(|(target, _)| target != non_binding),
            "value/key syntax became a binding: {non_binding}: {facts:#?}"
        );
    }

    fn collect_assignments(events: &[FlowEvent], out: &mut Vec<(String, Option<String>)>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    target, source_name, ..
                } => out.push((target.clone(), source_name.clone())),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_assignments(then_events, out);
                    collect_assignments(else_events, out);
                }
                _ => {}
            }
        }
    }
}
