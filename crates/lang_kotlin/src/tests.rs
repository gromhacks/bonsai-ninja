use super::*;

#[test]
fn function_reference_assignment_emits_clean_callable_alias() {
    let src = b"val cb = ::helper";
    let span = bonsai_common::Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());
    let event = FlowEvent::Assign {
        span,
        target: "cb".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["helper".to_string()],
        declares_new_binding: true,
        value_kind: None,
    };

    let alias = kotlin_function_reference_alias_assignment(&event, src).expect("function reference alias");

    assert!(matches!(
        alias,
        FlowEvent::Assign {
            target,
            source_name: Some(source),
            source_call: None,
            source_names,
            ..
        } if target == "cb" && source == "helper" && source_names.is_empty()
    ));
}
