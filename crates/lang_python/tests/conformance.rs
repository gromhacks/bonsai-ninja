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

#[test]
fn projected_call_argument_does_not_become_the_outer_call_result() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.py",
            r#"def main(envelope):
    direct = envelope.get("cmd")
    either = envelope.get("cmd") or envelope.get("fallback")
    repo = Repository({}, who=envelope.get("user"))
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

    assert!(
        facts
            .iter()
            .any(|(target, source)| target == "direct" && source.as_deref() == Some("envelope.cmd")),
        "a direct keyed read is the assignment value: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|(target, source)| target == "either" && source.as_deref() == Some("envelope.cmd"))
            && facts.iter().any(|(target, source)| {
                target == "either" && source.as_deref() == Some("envelope.fallback")
            }),
        "value-composition keeps each exact keyed operand: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .all(|(target, source)| target != "repo" || source.as_deref() != Some("envelope.user")),
        "a nested constructor argument must not be rewritten as the constructed object: {facts:#?}"
    );

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
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_assignments(body, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect_assignments(body, out);
                    collect_assignments(catch_events, out);
                    collect_assignments(finally_events, out);
                }
                _ => {}
            }
        }
    }
}
