//! Tests for the rulepack matcher's call-site, regex, and constraint
//! evaluators. Extracted from `matcher/mod.rs` so the matcher's
//! production code is reviewable in one read without scrolling past
//! the test fixtures.

use super::*;

fn span() -> Span {
    Span {
        file: FileId::new(0),
        start: 7,
        end: 15,
    }
}

fn rule_from_yaml(yaml: &str, kind: crate::rule::RuleKind) -> Rule {
    let mut rule: Rule = serde_yaml::from_str(yaml).expect("rule yaml parses");
    rule.kind = kind;
    rule
}

#[test]
fn collect_calls_includes_assignment_source_call_metadata() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "result".to_string(),
        source_name: None,
        source_call: Some("os.system".to_string()),
        source_call_args: vec!["cmd".to_string(), "env".to_string()],
        source_names: Vec::new(),
    }];

    let calls = collect_calls(&events);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].callee, "os.system");
    assert_eq!(calls[0].span, span());
    assert_eq!(calls[0].origin, CallFactOrigin::AssignmentSourceCall);
    assert_eq!(
        calls[0]
            .args
            .iter()
            .map(|arg| arg.value_text.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd", "env"]
    );
}

#[test]
fn assignment_source_call_facts_inherit_receiver_type_aliases() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "value".to_string(),
        source_name: None,
        source_call: Some("cookie.getValue".to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
    }];
    let mut calls = collect_calls(&events);
    enrich_call_fact_receiver_types(
        &mut calls,
        &[TypeAliasBinding {
            name: "cookie".to_string(),
            type_name: "jakarta.servlet.http.Cookie".to_string(),
        }],
    );

    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].receiver_types,
        vec!["jakarta.servlet.http.Cookie".to_string()],
        "matcher-synthesized assignment source calls must retain semantic receiver type evidence"
    );
}

#[test]
fn collect_calls_drops_assignment_source_call_shadowed_by_real_call() {
    let events = vec![
        FlowEvent::Call {
            name: "eval".to_string(),
            receiver: None,
            args: vec![
                CallArg {
                    span: span(),
                    name: None,
                    place: None,
                    source_names: Vec::new(),
                    value_text: "py_expr".to_string(),
                },
                CallArg {
                    span: span(),
                    name: None,
                    place: None,
                    source_names: Vec::new(),
                    value_text: "{\"attributes\": attributes}".to_string(),
                },
            ],
            receiver_types: Vec::new(),
            span: span(),
            call_kind: CallKind::Function,
        },
        FlowEvent::Assign {
            span: span(),
            target: "result".to_string(),
            source_name: None,
            source_call: Some("eval".to_string()),
            source_call_args: vec!["py_expr".to_string(), "{\"attributes\": attributes}".to_string()],
            source_names: Vec::new(),
        },
    ];

    let calls = collect_calls(&events);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].callee, "eval");
    assert_eq!(calls[0].origin, CallFactOrigin::RealCall);
    assert!(calls[0].receiver_types.is_empty());
    assert_eq!(
        calls[0]
            .args
            .iter()
            .map(|arg| arg.value_text.as_str())
            .collect::<Vec<_>>(),
        vec!["py_expr", "{\"attributes\": attributes}"]
    );
}

#[test]
fn receiver_type_facts_match_type_method_rules_without_receiver_names() {
    let attr = vec!["Cookie".to_string(), "getValue".to_string()];
    assert!(callee_matches_with_receiver_types(
        "c.getValue",
        &["Cookie".to_string()],
        None,
        Some(&attr),
        None,
    ));
    assert!(callee_matches_with_receiver_types(
        "c.getValue",
        &["jakarta.servlet.http.Cookie".to_string()],
        None,
        Some(&attr),
        None,
    ));
    assert!(!callee_matches_with_receiver_types(
        "c.getValue",
        &["Header".to_string()],
        None,
        Some(&attr),
        None,
    ));
}

#[test]
fn package_gated_regex_accepts_semantic_receiver_type_context() {
    let rule = rule_from_yaml(
        r#"
id: kotlin.sqli.connection_createstatement_execute
enabled: true
language: kotlin
tag: sql-injection
severity: high
packages: [java.sql]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.createStatement\\(\\)\\.executeQuery$"
description: JDBC chained execute query.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let mut aliases = std::collections::HashMap::new();
    aliases.insert(
        "Connection".to_string(),
        AliasTarget::Type {
            type_name: "java.sql.Connection".to_string(),
        },
    );

    assert!(
        prepared.call_context_allows(
            "conn.createStatement().executeQuery",
            &["Connection".to_string()],
            &aliases,
            &AHashSet::new(),
        ),
        "receiver-type facts expand through imports before package matching"
    );
    let file_packages = AHashSet::from_iter(["java.sql".to_string()]);
    assert!(
        !prepared.call_context_allows(
            "conn.createStatement().executeQuery",
            &[],
            &std::collections::HashMap::new(),
            &file_packages,
        ),
        "sink rules need call-site receiver or alias evidence; file imports alone are too broad"
    );
    let source_rule = rule_from_yaml(
        r#"
id: python.source.request_args_get
enabled: true
language: python
trust: remote
packages: [flask]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.args\\.get$"
description: Flask request args source.
"#,
        crate::rule::RuleKind::Source,
    );
    let source_prepared = PreparedRule::new(&source_rule).expect("source rule prepares");
    let source_file_packages = AHashSet::from_iter(["flask".to_string()]);
    assert!(
        source_prepared.call_context_allows(
            "req.args.get",
            &[],
            &std::collections::HashMap::new(),
            &source_file_packages,
        ),
        "source rules may use file-level package evidence for dynamic request receiver extraction"
    );
    let lifecycle_rule = rule_from_yaml(
        r#"
id: go.race.mutex_unlock
enabled: true
language: go
tag: race
packages: [sync]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.Unlock$"
description: Lifecycle audit-pair transition.
"#,
        crate::rule::RuleKind::Sink,
    );
    let lifecycle_prepared = PreparedRule::new(&lifecycle_rule).expect("lifecycle rule prepares");
    let lifecycle_file_packages = AHashSet::from_iter(["sync".to_string()]);
    assert!(
        lifecycle_prepared.call_context_allows(
            "mu.Unlock",
            &[],
            &std::collections::HashMap::new(),
            &lifecycle_file_packages,
        ),
        "lifecycle audit-pair rules may use file-level package evidence for transition sites"
    );
    assert!(
        !prepared.call_context_allows(
            "client.createStatement().executeQuery",
            &[],
            &std::collections::HashMap::new(),
            &AHashSet::new(),
        ),
        "without import, alias, or receiver-type evidence, package-gated regexes fail closed"
    );
}

#[test]
fn return_flow_reads_strip_call_callee_but_keep_argument_reads() {
    let mut reads = Vec::new();
    collect_flow_read_sites(
        &[FlowEvent::Return {
            span: span(),
            value_text: Some("params(input)".to_string()),
            value_name: None,
        }],
        &mut reads,
    );
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].1, vec!["input"]);

    reads.clear();
    collect_flow_read_sites(
        &[FlowEvent::Return {
            span: span(),
            value_text: Some(r#"render(params["name"])"#.to_string()),
            value_name: None,
        }],
        &mut reads,
    );
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].1, vec!["params", "name"]);
}

#[test]
fn method_chain_fallback_requires_chain_head_match() {
    let attr = vec!["Command".to_string(), "new".to_string()];

    assert!(callee_matches(
        r#"Command::new("sh").arg("-c").output"#,
        None,
        Some(&attr),
        None
    ));
    assert!(callee_matches(
        r#"std/process/Command::new("sh").arg("-c").output"#,
        None,
        Some(&attr),
        None
    ));
    assert!(
        !callee_matches(r#"callbacks.add(Command::new("sh"))"#, None, Some(&attr), None),
        "callback-passing expressions must not match the inner method-chain head"
    );
    assert!(
        !callee_matches(
            r#"callbacks.add(std/process/Command::new("sh"))"#,
            None,
            Some(&attr),
            None
        ),
        "import-path chain heads inside callback arguments must not match"
    );
}

#[test]
fn same_receiver_call_count_constraint_requires_repeated_receiver() {
    let constraint = vec![ConstraintKind::SameReceiverCallCountAtLeast {
        same_receiver_call_count_at_least: 2,
    }];
    let constraint_regexes =
        compile_constraint_regexes("test.same_receiver", &constraint).expect("non-regex constraints compile");

    assert!(constraints_pass(ConstraintEval {
        rule_id: "test.same_receiver",
        callee: "balance.lock",
        args: &[],
        receiver_types: &[],
        span: Span::new(FileId::new(0), 0, 0),
        call_origin: None,
        constraints: &constraint,
        constraint_regexes: &constraint_regexes,
        receiver_call_count: Some(2),
        assignment_texts: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
    }));
    assert!(!constraints_pass(ConstraintEval {
        rule_id: "test.same_receiver",
        callee: "stdin.lock",
        args: &[],
        receiver_types: &[],
        span: Span::new(FileId::new(0), 0, 0),
        call_origin: None,
        constraints: &constraint,
        constraint_regexes: &constraint_regexes,
        receiver_call_count: Some(1),
        assignment_texts: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
    }));
    assert!(!constraints_pass(ConstraintEval {
        rule_id: "test.same_receiver",
        callee: "lock",
        args: &[],
        receiver_types: &[],
        span: Span::new(FileId::new(0), 0, 0),
        call_origin: None,
        constraints: &constraint,
        constraint_regexes: &constraint_regexes,
        receiver_call_count: None,
        assignment_texts: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
    }));
}

#[test]
fn invalid_constraint_regex_fails_closed() {
    let constraint = vec![ConstraintKind::AnyArgMatchesRegex {
        any_arg_matches_regex: "[".to_string(),
    }];
    assert!(
        compile_constraint_regexes("test.invalid_regex", &constraint).is_none(),
        "invalid constraint regexes must fail rule preparation instead of silently compiling to None"
    );
}

#[test]
fn prepared_rule_drops_rule_with_invalid_constraint_regex() {
    let rule = rule_from_yaml(
        r#"
id: python.sqli.invalid_constraint_regex
enabled: true
language: python
tag: sql-injection
severity: high
cwe: [CWE-89]
match:
  kind: call
  callee:
    name: execute
constraints:
  - any_arg_matches_regex: "["
match_examples:
  - name: example
    code: "def demo(cursor, sql): cursor.execute(sql)"
description: Invalid regex fixture.
"#,
        crate::rule::RuleKind::Sink,
    );

    assert!(
        PreparedRule::new(&rule).is_none(),
        "an invalid constraint regex should disable the full rule for this analysis run"
    );
}

#[test]
fn empty_inferred_type_alias_does_not_panic() {
    let mut aliases = std::collections::HashMap::new();
    aliases.insert(
        "client".to_string(),
        AliasTarget::Type {
            type_name: String::new(),
        },
    );
    let attr = vec!["HttpClient".to_string(), "execute".to_string()];

    assert_eq!(
        callee_or_alias_matches("client.execute", &[], None, Some(&attr), None, &aliases),
        None
    );
}

#[test]
fn receiver_method_call_counts_group_by_receiver_and_method() {
    let calls = vec![
        test_call_fact("balance.lock", CallFactOrigin::RealCall),
        test_call_fact("balance.lock", CallFactOrigin::RealCall),
        test_call_fact("stdin.lock", CallFactOrigin::RealCall),
        test_call_fact("balance.clone", CallFactOrigin::RealCall),
        test_call_fact("balance.lock", CallFactOrigin::AssignmentSourceCall),
    ];
    let counts = receiver_method_call_counts(&calls);

    assert_eq!(
        counts
            .get(&receiver_method_key("balance.lock").expect("balance key"))
            .copied(),
        Some(2)
    );
    assert_eq!(
        counts
            .get(&receiver_method_key("stdin.lock").expect("stdin key"))
            .copied(),
        Some(1)
    );
    assert_eq!(
        counts
            .get(&receiver_method_key("balance.clone").expect("clone key"))
            .copied(),
        Some(1)
    );
}

#[test]
fn arg_value_identifier_fallback_ignores_quoted_literals() {
    assert!(
        !arg_matches_tainted_value(r#""SELECT * FROM users WHERE name = ?""#, "name"),
        "identifier fallback must not treat words inside string literals as variable references"
    );
    assert!(arg_matches_tainted_value("fmt.Sprintf(query, name)", "name"));
}

fn test_call_fact(callee: &str, origin: CallFactOrigin) -> CallFact {
    CallFact {
        callee: callee.to_string(),
        span: span(),
        args: Vec::new(),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        origin,
    }
}

// --- P3: integer-literal parsing + arg_lt/arg_le/arg_gt/arg_ge tests ---

#[test]
fn parse_int_literal_decimal_forms() {
    assert_eq!(super::parse_int_literal("1024"), Some(1024));
    assert_eq!(super::parse_int_literal("-5"), Some(-5));
    assert_eq!(super::parse_int_literal("+42"), Some(42));
    assert_eq!(super::parse_int_literal("1_000_000"), Some(1_000_000));
    assert_eq!(super::parse_int_literal(" 256 "), Some(256));
}

#[test]
fn parse_int_literal_hex_oct_bin() {
    assert_eq!(super::parse_int_literal("0xFF"), Some(255));
    assert_eq!(super::parse_int_literal("0Xff"), Some(255));
    assert_eq!(super::parse_int_literal("0o777"), Some(0o777));
    assert_eq!(super::parse_int_literal("0b1010"), Some(0b1010));
    assert_eq!(super::parse_int_literal("0B1111_0000"), Some(0b1111_0000));
}

#[test]
fn parse_int_literal_rejects_non_literals() {
    // Variables and expressions must never speculate to a value.
    assert_eq!(super::parse_int_literal("size"), None);
    assert_eq!(super::parse_int_literal("2048 + 0"), None);
    assert_eq!(super::parse_int_literal("Math.pow(2, 10)"), None);
    assert_eq!(super::parse_int_literal(""), None);
    assert_eq!(super::parse_int_literal("null"), None);
}

#[test]
fn arg_int_compare_threshold_semantics() {
    let args = vec![CallArg {
        span: span(),
        name: None,
        place: None,
        source_names: Vec::new(),
        value_text: "1024".to_string(),
    }];
    // arg_lt: 2048 should pass (1024 < 2048).
    assert!(super::arg_int_compare(&args, 0, |literal| literal < 2048));
    // arg_lt: 1024 fails on equality.
    assert!(!super::arg_int_compare(&args, 0, |literal| literal < 1024));
    // arg_le: 1024 passes on equality.
    assert!(super::arg_int_compare(&args, 0, |literal| literal <= 1024));
    // arg_gt: 512 passes (1024 > 512).
    assert!(super::arg_int_compare(&args, 0, |literal| literal > 512));
    // arg_ge: 1024 passes on equality.
    assert!(super::arg_int_compare(&args, 0, |literal| literal >= 1024));
}

#[test]
fn arg_int_compare_unknown_arg_fails_conservatively() {
    let args = vec![CallArg {
        span: span(),
        name: None,
        place: None,
        source_names: Vec::new(),
        value_text: "user_size".to_string(),
    }];
    // Variable arg → no literal → constraint fails. This is the
    // conservative choice: don't speculate.
    assert!(!super::arg_int_compare(&args, 0, |_| true));
}

#[test]
fn arg_int_compare_out_of_bounds_fails() {
    let args = vec![CallArg {
        span: span(),
        name: None,
        place: None,
        source_names: Vec::new(),
        value_text: "1024".to_string(),
    }];
    // index 1 is out of bounds — constraint fails.
    assert!(!super::arg_int_compare(&args, 1, |_| true));
}
