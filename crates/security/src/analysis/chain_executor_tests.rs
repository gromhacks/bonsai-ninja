use super::*;

fn sink(rule_id: &str, span: Span) -> RuleMatch {
    RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: rule_id.to_string(),
        language: "java".to_string(),
        file: "Example.java".to_string(),
        line: 1,
        column: 1,
        span,
        match_text: "execute".to_string(),
        enclosing_fn: Some("run".to_string()),
    }
}

fn call(span: Span) -> TaintedCall {
    TaintedCall {
        parent_trace_id: None,
        caller: FuncId::new(1),
        name: "execute".to_string(),
        call_span: span,
        tainted_args: Vec::new(),
        tainted_receiver: None,
        tainted_receiver_source_names: Vec::new(),
        kind: bonsai_taint::TaintedCallKind::Call,
    }
}

fn call_sink_rule() -> Rule {
    let mut rule: Rule = serde_yaml::from_str(
        r#"
id: java.test.call
enabled: true
language: java
tag: test
match:
  kind: call
  callee:
    name: execute
description: Typed evidence fixture.
"#,
    )
    .expect("rule parses");
    rule.kind = RuleKind::Sink;
    rule
}

#[test]
fn duplicate_rules_at_one_span_are_one_endpoint_identity() {
    let call = call(Span::new(FileId::new(1), 10, 30));
    let span = Span::new(FileId::new(1), 12, 20);
    let first = sink("java.first", span);
    let second = sink("java.second", span);

    assert_eq!(
        unique_named_overlap_span(&[&first, &second], "java", &call),
        Some(span)
    );
}

#[test]
fn nested_same_name_spans_remain_ambiguous() {
    let call = call(Span::new(FileId::new(1), 10, 30));
    let outer = sink("java.outer", Span::new(FileId::new(1), 11, 29));
    let inner = sink("java.inner", Span::new(FileId::new(1), 14, 20));

    let unique = unique_named_overlap_span(&[&outer, &inner], "java", &call);
    assert_eq!(unique, None);
    assert!(!sink_endpoint_identity_is_proven(
        &call,
        &outer,
        MatchKind::Call,
        false,
        unique
    ));
    assert!(!sink_endpoint_identity_is_proven(
        &call,
        &inner,
        MatchKind::Call,
        false,
        unique
    ));
}

#[test]
fn exact_span_wins_over_other_overlapping_endpoints() {
    let call = call(Span::new(FileId::new(1), 10, 30));
    let exact = sink("java.exact", call.call_span);
    let nested = sink("java.nested", Span::new(FileId::new(1), 14, 20));
    let unique = unique_named_overlap_span(&[&exact, &nested], "java", &call);

    assert!(sink_endpoint_identity_is_proven(
        &call,
        &exact,
        MatchKind::Call,
        true,
        unique
    ));
    assert!(!sink_endpoint_identity_is_proven(
        &call,
        &nested,
        MatchKind::Call,
        true,
        unique
    ));
}

#[test]
fn typed_return_statement_proves_nested_return_expression_endpoint() {
    let statement_span = Span::new(FileId::new(1), 10, 40);
    let expression_span = Span::new(FileId::new(1), 17, 39);
    let mut evidence = call(statement_span);
    evidence.kind = bonsai_taint::TaintedCallKind::Return;
    evidence.name = "return".to_string();
    let mut return_sink = sink("javascript.xss.html_return", expression_span);
    return_sink.language = "javascript".to_string();
    return_sink.match_text = "`<h1>${name}</h1>`".to_string();

    assert!(sink_endpoint_identity_is_proven(
        &evidence,
        &return_sink,
        MatchKind::Return,
        false,
        None
    ));
}

#[test]
fn synthetic_evidence_cannot_compete_with_call_sinks() {
    let span = Span::new(FileId::new(1), 10, 30);
    let rule = call_sink_rule();
    let mut evidence = call(span);
    assert!(tainted_call_kind_matches_sink(&evidence, &rule));

    evidence.kind = bonsai_taint::TaintedCallKind::Write;
    evidence.name = "assigned_value".to_string();
    assert!(!tainted_call_kind_matches_sink(&evidence, &rule));

    evidence.kind = bonsai_taint::TaintedCallKind::Return;
    evidence.name = "return".to_string();
    assert!(!tainted_call_kind_matches_sink(&evidence, &rule));
}
