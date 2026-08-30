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
fn repeated_match_capture_names_remain_owned_by_each_case_arm() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.py",
            r#"def validate(payload):
    match payload:
        case {"tag": "left", "value": value, **rest}:
            return {"cmd": value, **rest}
        case {"tag": "right", "value": value, **rest}:
            return {"cmd": value, **rest}
        case _:
            raise ValueError(payload)
"#,
        )],
    );
    let global = ws.db().global_index();
    let validate = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "validate")
        .expect("validate declaration");

    fn collect(events: &[FlowEvent], target: &str, spans: &mut Vec<bonsai_common::Span>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    span,
                    target: actual,
                    source_name,
                    ..
                } if actual == target && source_name.as_deref() == Some("payload.value") => {
                    spans.push(*span);
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect(then_events, target, spans);
                    collect(else_events, target, spans);
                }
                _ => {}
            }
        }
    }

    let mut spans = Vec::new();
    collect(&validate.flow_events, "value", &mut spans);
    spans.sort();
    spans.dedup();
    assert_eq!(
        spans.len(),
        2,
        "same-spelled captures in distinct case arms are distinct compiler writes: {:#?}",
        validate.flow_events
    );
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

#[test]
fn dictionary_assignments_use_tree_sitter_aggregate_flow() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.py",
            r#"def main(raw, prior):
    envelope = {"cmd": raw, **prior}
    return envelope["cmd"]
"#,
        )],
    );
    let global = ws.db().global_index();
    let main = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    let aggregate = main.flow_events.iter().find_map(|event| match event {
        FlowEvent::AggregateAssign {
            target, value_flow, ..
        } if target == "envelope" => Some(value_flow),
        _ => None,
    });
    let aggregate = aggregate.expect("dictionary AggregateAssign");
    assert!(
        aggregate
            .aggregate_fields
            .iter()
            .any(|field| field.name == "cmd" && field.value.place.as_deref() == Some("raw")),
        "static field must come from the parsed pair node: {aggregate:#?}"
    );
    assert!(
        aggregate
            .spreads
            .iter()
            .any(|spread| spread.place.as_deref() == Some("prior")),
        "spread must come from the parsed dictionary_splat node: {aggregate:#?}"
    );
}

#[test]
fn conditional_dictionary_value_preserves_exact_field_flow() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.py",
            r#"def main(raw, enabled):
    payload = ({"cmd": raw} if enabled else None)
    return payload
"#,
        )],
    );
    let global = ws.db().global_index();
    let main = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    let aggregate = main.flow_events.iter().find_map(|event| match event {
        FlowEvent::AggregateAssign {
            target, value_flow, ..
        } if target == "payload" => Some(value_flow),
        _ => None,
    });
    let aggregate = aggregate.expect("conditional dictionary AggregateAssign");
    assert!(aggregate
        .aggregate_fields
        .iter()
        .any(|field| { field.name == "cmd" && field.value.place.as_deref() == Some("raw") }));
}
