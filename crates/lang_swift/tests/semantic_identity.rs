use std::sync::Arc;

#[test]
fn computed_getters_lower_calls_and_keep_callback_bodies_separate() {
    let source = r#"struct Widget {
    var body: String {
        makeView().observe { value in consume(value) }
    }
    var explicit: String {
        let value = produce()
        return transform(value)
    }
}
"#;
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[("Getter.swift", source)],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).unwrap();
    let body = index.defs.iter().find(|decl| decl.name == "body").unwrap();
    let calls = body
        .flow_events
        .iter()
        .filter_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(calls.iter().any(|name| name.ends_with("observe")), "{calls:?}");
    assert!(calls.contains(&"makeView"), "{calls:?}");
    assert!(
        !calls.contains(&"consume"),
        "callback body must have its own owner"
    );
    let registration = body
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { name, span, .. } if name.ends_with("observe") => Some(*span),
            _ => None,
        })
        .unwrap();
    let callback = bonsai_lang_api::call_argument_value_fact(&index.call_argument_values, registration, 0)
        .expect("computed-getter callback argument projection");
    assert_eq!(callback.inline_callback_params, ["value"]);
    assert!(callback.inline_callback_span.is_some());
    let explicit = index.defs.iter().find(|decl| decl.name == "explicit").unwrap();
    assert!(explicit.flow_events.iter().any(|event| matches!(event,
        bonsai_lang_api::FlowEvent::Call { name, .. } if name == "produce")));
    assert!(explicit.flow_events.iter().any(|event| matches!(event,
        bonsai_lang_api::FlowEvent::Call { name, .. } if name == "transform")));
    assert_eq!(
        explicit
            .flow_events
            .iter()
            .filter(|event| matches!(event, bonsai_lang_api::FlowEvent::Return { .. }))
            .count(),
        1
    );
}

#[test]
fn interpolated_switch_results_are_not_finite_literal_selections() {
    for result in [r#""\(key)""#, r##"#"\#(key)"#"##] {
        let source = format!(
            r#"func selected(_ key: String) -> String {{
  return switch key {{
    case "first": "safe"
    default: {result}
  }}
}}
"#
        );
        let workspace = bonsai_testkit::workspace_with(
            vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
            &[("Identity.swift", &source)],
        );
        let file = workspace.vfs().all_files()[0];
        let index = workspace.db().decl_index(file).expect("Swift declarations");
        assert!(
            index.finite_literal_selections.is_empty(),
            "{result}: {:?}",
            index.finite_literal_selections
        );
    }
}
