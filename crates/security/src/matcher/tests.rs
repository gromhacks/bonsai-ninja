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
fn flow_read_attribute_match_requires_actual_qualified_token() {
    let split_callback_tokens = vec!["req".to_string(), "err.path".to_string()];
    assert!(
        !tokens_contain_attribute(&split_callback_tokens, "req.path"),
        "separate `req` and `err.path` tokens must not synthesize `req.path`"
    );

    let query_tokens = vec!["req.query.wsdl".to_string(), "req.query".to_string()];
    assert!(
        tokens_contain_attribute(&query_tokens, "req.query"),
        "real qualified request reads should still match their source rule"
    );
}

#[test]
fn canonical_flow_read_uses_ast_rhs_span_instead_of_assignment_punctuation() {
    let file = FileId::new(0);
    let source = "req.query = sanitize(req.query)";
    let assignment_span = Span::new(file, 0, source.len() as u64);
    let value_start = source.find("sanitize").unwrap() as u64;
    let value_span = Span::new(file, value_start, source.len() as u64);
    let facts = [bonsai_lang_api::AssignmentValueFact {
        assignment_span,
        target_span: Some(Span::new(file, 0, "req.query".len() as u64)),
        value_span,
        call_sites: Vec::new(),
        value_flow: Default::default(),
        direct_call_name: None,
        direct_call_receiver: None,
    }];
    let values = AssignmentValueIndex::new(&facts);

    let matched =
        canonical_flow_read_match_span_in_source(file, assignment_span, "req.query", &values, source);

    assert_eq!(matched.start, source.rfind("req.query").unwrap() as u64);
    assert_eq!(matched.end - matched.start, "req.query".len() as u64);
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
        declares_new_binding: false,
        value_kind: None,
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
        declares_new_binding: false,
        value_kind: None,
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
                    passing_mode: Default::default(),
                    span: span(),
                    name: None,
                    place: None,
                    source_names: Vec::new(),
                    value_text: "py_expr".to_string(),
                },
                CallArg {
                    passing_mode: Default::default(),
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
            declares_new_binding: false,
            value_kind: None,
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
fn text_prefilter_requires_package_and_context_anchors() {
    let hibernate = rule_from_yaml(
        r#"
id: java.hibernate.session_get
enabled: true
language: java
trust: database
tag: db-input
packages: ["org.hibernate"]
match:
  kind: call
  callee:
    attribute: [Session, get]
description: Hibernate Session.get.
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&hibernate).expect("rule prepares");
    assert!(
        !prepared.text_possible_in("class App { Object get(Session s) { return s.get(id); } }", None),
        "package-gated rules should not force parsing files with only receiver/tail text"
    );
    assert!(
        prepared.text_possible_in(
            "import org.hibernate.*; class App { Object get(Session s) { return s.get(id); } }",
            None
        ),
        "package text plus structured target text should remain parseable"
    );

    let main_args = rule_from_yaml(
        r#"
id: java.source.main_args
enabled: true
language: java
trust: local
tag: cli-input
match:
  kind: param
  target:
    name: args
    in_method: [main]
constraints:
  - enclosing_modifier_in: [static]
description: Java main args.
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&main_args).expect("rule prepares");
    assert!(!prepared.text_possible_in("void mainForTest(String args) {}", None));
    assert!(prepared.text_possible_in("public static void main(String[] args) {}", None));
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
    let direct_rule = rule_from_yaml(
        r#"
id: python.test.gql_execute
enabled: true
language: python
tag: command-injection
severity: high
packages: [gql]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.execute$"
description: gql execute.
"#,
        crate::rule::RuleKind::Sink,
    );
    let direct_prepared = PreparedRule::new(&direct_rule).expect("direct package rule prepares");
    assert!(
        direct_prepared.call_context_allows(
            "gql.execute",
            &[],
            &std::collections::HashMap::new(),
            &AHashSet::new(),
        ),
        "direct package-qualified calls must satisfy receiver-agnostic package gates"
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
fn anchored_receiver_regexes_keep_terminal_call_keys_and_text_anchors() {
    let rule = rule_from_yaml(
        r#"
id: python.test.gql_execute
enabled: true
language: python
tag: command-injection
severity: high
packages: [gql]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.execute$"
description: gql execute.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let source = r#"
import gql

def handler(payload):
    return gql.execute(payload)
"#;

    assert_eq!(
        regex_literal_anchor_tokens("^[A-Za-z_$][A-Za-z0-9_$]*\\.execute$"),
        vec!["execute".to_string()],
        "regex character classes must not become impossible text anchors"
    );
    assert!(
        regex_literal_anchor_tokens("^CC_MD5(_Init|_Update|_Final)?$").is_empty(),
        "optional regex suffixes must not become mandatory text anchors"
    );
    assert!(
        regex_literal_anchor_tokens(r"^(ElementTree|ET)\.XML$").is_empty(),
        "alternative regex branches must not become mandatory text anchors"
    );
    assert!(
        regex_terminal_call_key("^(list|binary)_to_atom$").is_none(),
        "prefix alternatives must not be keyed by a non-candidate suffix"
    );
    assert!(
        regex_terminal_call_key("^_?is_safe_url$").is_none(),
        "optional leading underscores must not be keyed without the underscore"
    );
    assert_eq!(
        regex_terminal_call_key(r"^[A-Za-z_$][A-Za-z0-9_$]*\.\$queryRawUnsafe$"),
        Some("queryRawUnsafe".to_string()),
        "regex-derived call keys must use the same sigil-stripping as call candidates"
    );
    assert_eq!(
        regex_prefix_literal_anchor_token("^ResponseEntity(?:<.*>)?$").as_deref(),
        Some("ResponseEntity"),
        "anchored constructor regexes should contribute their required prefix to text prefiltering"
    );
    assert_eq!(
        regex_required_literal_anchor_tokens(r"::|__\$\{"),
        vec!["::".to_string(), "__${".to_string()],
        "literal return regex alternatives should contribute safe exact text anchors"
    );
    let file_packages = AHashSet::from_iter(["gql".to_string()]);
    assert!(
        prepared.text_possible_in(source, Some(&file_packages)),
        "text prefilter must keep source files that contain the terminal call"
    );
    assert_eq!(
        prepared_regex_call_keys(&prepared),
        vec!["execute".to_string()],
        "call-rule index should key anchored receiver regexes by the terminal method"
    );
    let alias_map = std::collections::HashMap::new();
    let keys = call_candidate_keys("gql.execute", &alias_map);
    assert!(
        keys.iter().any(|key| key == "execute"),
        "call candidate keys should include the terminal method: {keys:?}"
    );
    assert_eq!(
        callee_or_alias_matches(
            "gql.execute",
            &[],
            prepared.name,
            prepared.attribute,
            prepared.regex.as_ref(),
            &alias_map,
        )
        .as_deref(),
        Some("gql.execute"),
        "callee matcher should evaluate anchored regexes against the emitted callee"
    );
    assert!(
        prepared.call_context_allows("gql.execute", &[], &alias_map, &AHashSet::new()),
        "direct package-qualified calls must satisfy package gates without file imports"
    );
}

#[test]
fn text_prefilter_uses_short_attribute_and_regex_terminal_anchors() {
    let short_attr_rule = rule_from_yaml(
        r#"
id: java.test.response_ok
enabled: true
language: java
tag: xss
severity: high
packages: [org.springframework.http]
match:
  kind: call
  callee:
    attribute: [ResponseEntity, ok]
description: ResponseEntity ok.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&short_attr_rule).expect("rule prepares");
    let workspace_package =
        AHashSet::from_iter([workspace_import_package_marker("org.springframework.http")]);
    assert!(
        !prepared.text_possible_in("class A { void f() { run(value); } }", Some(&workspace_package)),
        "workspace package evidence alone must not make a short-attribute rule parse every file"
    );
    assert!(
        prepared.text_possible_in(
            "class A { void f(String value) { ResponseEntity.ok(value); } }",
            Some(&workspace_package),
        ),
        "short method attributes should keep files containing the actual call"
    );
    assert!(
        prepared.text_possible_in(
            "class A { void f(String value) { ResponseEntity::ok(value); } }",
            Some(&workspace_package),
        ),
        "short method attributes should keep static separator call forms"
    );

    let regex_rule = rule_from_yaml(
        r#"
id: java.test.jdbc_query
enabled: true
language: java
tag: sql-injection
severity: high
packages: [org.springframework.jdbc]
match:
  kind: call
  callee:
    regex: "(^|\\.)(JdbcTemplate|[jJ][dD][bB][cC][tT]emplate)\\.query$"
description: JDBC query.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&regex_rule).expect("rule prepares");
    let workspace_package =
        AHashSet::from_iter([workspace_import_package_marker("org.springframework.jdbc")]);
    assert!(
        !prepared.text_possible_in(
            "class A { void f() { execute(value); } }",
            Some(&workspace_package)
        ),
        "terminal regex keys should keep package-gated regex rules from parsing unrelated files"
    );
    assert!(
        prepared.text_possible_in(
            "class A { void f(JdbcTemplate jdbcTemplate) { jdbcTemplate.query(sql); } }",
            Some(&workspace_package),
        ),
        "terminal regex keys should keep real candidate call files"
    );

    let search_rule = rule_from_yaml(
        r#"
id: java.test.ldap_search
enabled: true
language: java
tag: ldap-injection
severity: high
packages: [javax.naming.directory]
match:
  kind: call
  callee:
    name: search
description: LDAP search.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&search_rule).expect("rule prepares");
    let workspace_package = AHashSet::from_iter([workspace_import_package_marker("javax.naming.directory")]);
    assert!(
        !prepared.text_possible_in_mode(
            "class ElasticsearchHandler { String name = \"Elasticsearch\"; }",
            Some(&workspace_package),
            ConstraintMode::SinkInventory,
        ),
        "plain words containing a call name must not satisfy broad call-name prefiltering"
    );
    assert!(
        prepared.text_possible_in_mode(
            "class App { void f(DirContext ctx, String q) { ctx.search(\"ou=users\", q, null); } }",
            Some(&workspace_package),
            ConstraintMode::SinkInventory,
        ),
        "real call syntax should satisfy broad call-name prefiltering"
    );
    assert!(
        call_text_anchor_possible_in("x = cond ? STDIN.gets : \"safe\"", "gets", "ruby"),
        "Ruby command/no-arg call syntax without parentheses must remain prefilter-possible"
    );
    assert!(
        call_text_anchor_possible_in("include $tainted;", "include", "php"),
        "PHP include/require constructs normalized as calls must remain prefilter-possible"
    );
    assert!(
        !call_text_anchor_possible_in("class ElasticsearchHandler {}", "search", "java"),
        "Java call prefilter should still reject identifiers embedded in larger words"
    );

    let raw_html_rule = rule_from_yaml(
        r#"
id: java.test.raw_html_return
enabled: true
language: java
tag: xss
severity: high
match:
  kind: return
  target:
    regex: '(?is)<\s*(?:!doctype|html|body|script|div|span|p|a|img|svg|iframe|h[1-6]|ul|ol|li|table|form|input|textarea|button|br|hr)\b|&lt;'
description: Raw HTML return.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&raw_html_rule).expect("rule prepares");
    assert!(
        !prepared.text_possible_in("class Box<T> { List<String> values; }", None),
        "Java generics must not satisfy the raw-HTML return prefilter"
    );
    assert!(
        prepared.text_possible_in("class App { String f(String n) { return \"<div>\" + n; } }", None),
        "real HTML tag literals should satisfy the raw-HTML return prefilter"
    );
}

#[test]
fn base_name_not_in_blocks_module_decoder_bases() {
    let rule = rule_from_yaml(
        r#"
id: python.passthrough.bytes_decode_receiver
enabled: true
language: python
tag: passthrough-decode
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$\\.]*\\.decode$"
    base_name_not_in: [jsonpickle]
description: Receiver decode passthrough.
"#,
        crate::rule::RuleKind::Sanitizer,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");

    assert!(prepared.base_name_allows("raw.decode"));
    assert!(prepared.base_name_allows("self.raw.decode"));
    assert!(!prepared.base_name_allows("jsonpickle.decode"));
}

#[test]
fn return_flow_reads_strip_call_callee_but_keep_argument_reads() {
    let mut reads = Vec::new();
    collect_flow_read_sites(
        &[FlowEvent::Return {
            span: span(),
            value_text: Some("params(input)".to_string()),
            value_name: None,
            value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec!["input".to_string()]),
        }],
        &[],
        &[],
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
            value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec![
                "params".to_string(),
                "name".to_string(),
            ]),
        }],
        &[],
        &[],
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
        ast_arg_values: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
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
        ast_arg_values: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
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
        ast_arg_values: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
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
        passing_mode: Default::default(),
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
        passing_mode: Default::default(),
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
        passing_mode: Default::default(),
        span: span(),
        name: None,
        place: None,
        source_names: Vec::new(),
        value_text: "1024".to_string(),
    }];
    // index 1 is out of bounds — constraint fails.
    assert!(!super::arg_int_compare(&args, 1, |_| true));
}

#[test]
fn write_fact_uses_structured_assignment_operands() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "decoder.Strict".to_string(),
        source_name: Some("false".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["false".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
    }];

    let writes = super::collect_writes(&events);
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].target, "decoder.Strict");
    assert_eq!(writes[0].argument.value_text, "false");
    assert_eq!(writes[0].argument.source_names, ["false"]);
    assert_eq!(writes[0].ast_values, ["false"]);
}

#[test]
fn branch_condition_ast_values_have_no_hidden_cap() {
    let events = (0..8_192)
        .map(|index| FlowEvent::Branch {
            span: span(),
            condition: Some(format!("allowed[{index}]")),
            then_events: Vec::new(),
            else_events: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut values = Vec::new();
    super::collect_branch_condition_values(&events, &mut values);
    assert_eq!(values.len(), events.len());
    assert_eq!(values.last().map(String::as_str), Some("allowed[8191]"));
}

#[test]
fn collect_calls_uses_ast_call_event_for_yielded_expression() {
    // `yield exec(cmd)` / C# `yield return Sink(x)` lowers both the value
    // event and its parsed call. The matcher must consume that real call
    // rather than re-parsing `Yield::value_text`.
    let events = vec![
        FlowEvent::Call {
            span: span(),
            name: "exec".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
        FlowEvent::Yield {
            span: span(),
            value_text: Some("exec(cmd)".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec!["cmd".to_string()]),
        },
    ];
    let calls = collect_calls(&events);
    assert_eq!(
        calls.len(),
        1,
        "a sink in the yielded value must become a CallFact"
    );
    assert_eq!(calls[0].callee, "exec");
    assert_eq!(calls[0].origin, CallFactOrigin::RealCall);
    assert_eq!(
        calls[0]
            .args
            .iter()
            .map(|arg| arg.value_text.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd"]
    );
}

#[test]
fn collect_calls_ignores_non_call_yield_value() {
    // A bare `yield x` carries no call; do not synthesize a CallFact.
    let events = vec![FlowEvent::Yield {
        span: span(),
        value_text: Some("x".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    assert!(collect_calls(&events).is_empty());
}

// audit re-apply: H10 RED-before/GREEN-after (matcher portion): before adding

#[test]
fn receiver_root_name_strips_kotlin_safe_call_sigil() {
    // H10: safe-call receivers (`stmt?.executeQuery`) leave `call_receiver_text`
    // returning `stmt?`; the root must still resolve to `stmt`.
    assert_eq!(receiver_root_name("stmt?"), Some("stmt".to_string()));
    assert_eq!(receiver_root_name("obj?.field"), Some("obj".to_string()));
}

#[test]
fn safe_call_receiver_inherits_type_alias() {
    // H10 integration: `stmt?.executeQuery(query)` must adopt the alias
    // type of `stmt` so the matcher's [Statement, executeQuery] rule fires.
    let events = vec![FlowEvent::Call {
        name: "stmt?.executeQuery".to_string(),
        receiver: Some("stmt?".to_string()),
        args: Vec::new(),
        receiver_types: Vec::new(),
        span: span(),
        call_kind: CallKind::Method,
    }];
    let mut calls = collect_calls(&events);
    enrich_call_fact_receiver_types(
        &mut calls,
        &[TypeAliasBinding {
            name: "stmt".to_string(),
            type_name: "java.sql.Statement".to_string(),
        }],
    );
    let real = calls
        .iter()
        .find(|c| c.callee == "stmt?.executeQuery")
        .expect("real call fact present");
    assert_eq!(
        real.receiver_types,
        vec!["java.sql.Statement".to_string()],
        "safe-call receiver must inherit the alias type of its root binding"
    );
}
