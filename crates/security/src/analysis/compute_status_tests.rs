//! Tests for `compute_status` and the status-merge invariants. Extracted
//! from `analysis/mod.rs` for navigability — `compute_status` evolves
//! independently of the rest of the analysis pipeline and the tests
//! exercise sanitizer credit + non-crediting tag classification.

use super::*;
use crate::finding::FindingMatch;
use crate::loader::LanguagePack;
use bonsai_taint::TaintedCallKind;

fn sanitizer(tag: Option<&str>) -> FindingMatch {
    FindingMatch {
        rule_id: "test.san.x".to_string(),
        file: "test.py".to_string(),
        line: 1,
        column: 1,
        text: String::new(),
        enclosing_fn: None,
        tag: tag.map(str::to_string),
        severity: None,
        category: None,
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    }
}

fn validation_rule_from_yaml(yaml: &str) -> Rule {
    let mut rule: Rule = serde_yaml::from_str(yaml).expect("rule yaml parses");
    rule.kind = RuleKind::Sink;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("bonsai-rule-{}-{stamp}.yml", rule.id.replace('.', "_")));
    std::fs::write(
        &path,
        format!("- id: {}\n  language: {}\n", rule.id, rule.language),
    )
    .expect("write temp rule source");
    rule.source_path = path.display().to_string();
    rule
}

#[test]
fn strict_source_text_matching_does_not_seed_receivers_or_siblings() {
    assert!(security_text_matches_source_strict("os.getenv", "os.getenv"));
    assert!(security_text_matches_source_strict("getenv", "os.getenv"));
    assert!(security_text_matches_source_strict("req.query", "req.query"));
    assert!(security_text_matches_source_strict("query", "req.query"));

    assert!(!security_text_matches_source_strict("os", "os.getenv"));
    assert!(!security_text_matches_source_strict("os.system", "os.getenv"));
    assert!(!security_text_matches_source_strict("req", "req.query"));
    assert!(!security_text_matches_source_strict("req.user", "req.query"));
    assert!(!security_text_matches_source_strict("req.session", "req.query"));
    assert!(!security_text_matches_source_strict("headers", "req.query"));
}

#[test]
fn clean_overwrite_target_keys_extract_compound_sink_operands() {
    assert_eq!(clean_overwrite_target_keys("x"), vec!["x"]);
    assert_eq!(clean_overwrite_target_keys("\"-c \" + x"), vec!["x"]);
    assert_eq!(
        clean_overwrite_target_keys("format!(\"{}\", cmd)"),
        vec!["cmd", "format"]
    );
    assert_eq!(
        clean_overwrite_target_keys("\"x inside string\""),
        Vec::<String>::new()
    );
}

#[test]
fn clean_conditional_value_part_rejects_value_identifiers() {
    assert!(
        clean_conditional_value_part("cond ? \"clean-then\" : \"clean-else\"")
            .is_some_and(value_part_contains_only_clean_literals)
    );
    assert!(clean_conditional_value_part(
        "if cond { \"clean-then\".to_string() } else { \"clean-else\".to_string() }"
    )
    .is_some_and(value_part_contains_only_clean_literals));
    assert!(
        !clean_conditional_value_part("cond ? user_value : \"clean-else\"")
            .is_some_and(value_part_contains_only_clean_literals)
    );
}

#[test]
fn clean_output_call_overwrites_only_with_clean_values() {
    let args = vec![
        bonsai_lang_api::CallArg {
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 3),
            name: None,
            value_text: "buf".to_string(),
            place: Some("buf".to_string()),
            source_names: vec!["buf".to_string()],
        },
        bonsai_lang_api::CallArg {
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 5, 16),
            name: None,
            value_text: "sizeof(buf)".to_string(),
            place: None,
            source_names: Vec::new(),
        },
        bonsai_lang_api::CallArg {
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 18, 22),
            name: None,
            value_text: "\"%s\"".to_string(),
            place: None,
            source_names: Vec::new(),
        },
        bonsai_lang_api::CallArg {
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 24, 31),
            name: None,
            value_text: "\"clean\"".to_string(),
            place: None,
            source_names: Vec::new(),
        },
    ];
    assert!(clean_output_call_overwrites_target("snprintf", &args, "buf"));

    let mut tainted_value = args;
    tainted_value[3].value_text = "user_value".to_string();
    assert!(!clean_output_call_overwrites_target(
        "snprintf",
        &tainted_value,
        "buf"
    ));
}

#[test]
fn try_region_clean_overwrite_requires_all_continuing_paths() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let target = "t";
    let clean_t = clean_assign_event(target, 10, 20);
    let clean_finally = clean_assign_event(target, 30, 40);

    assert!(
        !try_region_clean_overwrites_target(&ws, &[], &[clean_t.clone()], &[], target),
        "a clean catch arm alone is only one exceptional path, not a definite overwrite"
    );
    assert!(
        try_region_clean_overwrites_target(&ws, &[clean_t.clone()], &[clean_t.clone()], &[], target),
        "normal and caught paths both overwrite the target"
    );
    assert!(
        try_region_clean_overwrites_target(&ws, &[], &[], &[clean_finally], target),
        "finally/ensure cleanup is path-unconditional for continuing paths"
    );
}

fn clean_assign_event(target: &str, start: u64, end: u64) -> bonsai_lang_api::FlowEvent {
    bonsai_lang_api::FlowEvent::Assign {
        span: bonsai_common::Span::new(bonsai_common::FileId::new(1), start, end),
        target: target.to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
    }
}

fn single_rule_pack(rule: Rule) -> Rulepack {
    let mut pack = Rulepack::default();
    pack.packs.insert(
        rule.language.clone(),
        LanguagePack {
            language: rule.language.clone(),
            sinks: vec![rule],
            ..LanguagePack::default()
        },
    );
    pack
}

#[test]
fn validator_reports_when_package_signal_is_not_adapter_visible() {
    // Use a dotted-but-fictitious package so the maven-artifact
    // validator does not fire — we want to exercise only the
    // adapter-visibility warning here.
    let rule = validation_rule_from_yaml(
        r"
id: java.template.velocity_engine_evaluate
enabled: true
language: java
tag: ssti
severity: high
packages: [org.example.velocity.engine.core]
imports: [org.example.velocity]
cwe: [CWE-1336]
match:
  kind: call
  callee:
    regex: '^[A-Za-z_$][A-Za-z0-9_$]*\.evaluate$'
match_examples:
  - name: velocity instance
    code: |
      import org.apache.velocity.app.VelocityEngine;
      class App {
        void handle(VelocityEngine engine, String input) {
          engine.evaluate(input);
        }
      }
    expect_match_text: [engine.evaluate]
description: VelocityEngine.evaluate(tainted template) reaches server-side template execution.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert_eq!(
        report.errors, 0,
        "package/import visibility drift in match examples is warning-level; got errors: {:#?}",
        report.issues
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "match-example-missing-import"
                && issue.level == "warning"
                && issue.message.contains("org.example.velocity.engine.core")),
        "expected missing-import warning, got {:#?}",
        report.issues
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "package-signal-not-adapter-visible"
                && issue.level == "warning"
                && issue.message.contains("org.example.velocity.engine.core")),
        "expected adapter-visible package warning, got {:#?}",
        report.issues
    );
}

#[test]
fn validator_accepts_adapter_visible_package_signal() {
    let rule = validation_rule_from_yaml(
        r"
id: java.template.velocity_engine_evaluate
enabled: true
language: java
tag: ssti
severity: high
packages: [org.apache.velocity]
imports: [org.apache.velocity]
cwe: [CWE-1336]
match:
  kind: call
  callee:
    attribute: [VelocityEngine, evaluate]
match_examples:
  - name: velocity instance
    code: |
      import org.apache.velocity.app.VelocityEngine;
      class App {
        void handle(VelocityEngine engine, String input) {
          engine.evaluate(input);
        }
      }
    expect_match_text: [engine.evaluate]
description: VelocityEngine.evaluate(tainted template) reaches server-side template execution.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert_eq!(
        report.errors, 0,
        "unexpected validator errors: {:#?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.code == "package-signal-not-adapter-visible"),
        "adapter-visible package should not warn: {:#?}",
        report.issues
    );
}

#[test]
fn validator_accepts_java_fully_qualified_package_signal() {
    let rule = validation_rule_from_yaml(
        r"
id: java.ldapi.dir_context_search
enabled: true
language: java
tag: ldapi
severity: high
packages: [javax.naming.directory]
imports: [javax.naming.directory]
cwe: [CWE-90]
match:
  kind: call
  callee:
    regex: '^[A-Za-z_$][A-Za-z0-9_$]*\.search$'
match_examples:
  - name: fqn initial dir context
    code: |
      class App {
        void handle(String input) throws Exception {
          javax.naming.directory.InitialDirContext ctx = new javax.naming.directory.InitialDirContext();
          ctx.search(input, input, null);
        }
      }
    expect_match_text: [ctx.search]
description: InitialDirContext.search with attacker-controlled LDAP filter reaches LDAP injection.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert_eq!(
        report.errors, 0,
        "unexpected validator errors: {:#?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.code == "match-example-missing-import"),
        "FQN package evidence should satisfy the missing-import check: {:#?}",
        report.issues
    );
}

#[test]
fn hardcoded_receiver_regex_detector_flags_lowercase_receivers() {
    assert_eq!(
        lowercase_receiver_token_from_regex(r"^cur\.execute$"),
        Some("cur".to_string())
    );
    assert_eq!(
        lowercase_receiver_token_from_regex(r"^(env|template_env)\.from_string$"),
        Some("env|template_env".to_string())
    );
    // Receiver-agnostic regex returns None — the prefix `[a-z_]` is
    // not a lowercase identifier token.
    assert_eq!(
        lowercase_receiver_token_from_regex(r"^[a-z_][A-Za-z0-9_]*\.execute$"),
        None
    );
    assert_eq!(
        lowercase_receiver_token_from_regex(r"^render_template_string$"),
        None
    );
}

#[test]
fn receiver_agnostic_regex_detector_recognizes_canonical_form() {
    assert!(regex_prefix_is_receiver_agnostic(
        r"^[A-Za-z_$][A-Za-z0-9_$]*\.body$"
    ));
    assert!(regex_prefix_is_receiver_agnostic(
        r"^[A-Za-z_][A-Za-z0-9_]*\.execute$"
    ));
    // Specific lowercase prefix — not receiver-agnostic.
    assert!(!regex_prefix_is_receiver_agnostic(r"^request\.body$"));
    // Uppercase Type prefix — also not receiver-agnostic.
    assert!(!regex_prefix_is_receiver_agnostic(r"^HttpRequest\.body$"));
}

#[test]
fn distro_smell_detector_flags_per_language_distribution_names() {
    // Java/Kotlin/Scala: Maven coordinate `groupId-artifactId`.
    assert!(package_signal_distro_smell("java", "spring-expression").is_some());
    assert!(package_signal_distro_smell("kotlin", "kafka-clients").is_some());
    assert!(package_signal_distro_smell("scala", "akka-http").is_some());
    // Real JVM packages have dots — never flagged.
    assert!(package_signal_distro_smell("java", "org.springframework.expression").is_none());
    assert!(package_signal_distro_smell("kotlin", "com.hubspot.jinjava").is_none());
    // Single-token packages without hyphens are fine.
    assert!(package_signal_distro_smell("java", "httpx").is_none());
    // Python: PyPI distros never appear as imports.
    assert!(package_signal_distro_smell("python", "python-jose").is_some());
    assert!(package_signal_distro_smell("python", "argon2-cffi").is_some());
    assert!(package_signal_distro_smell("python", "flask").is_none());
    assert!(package_signal_distro_smell("python", "google.cloud.storage").is_none());
    // Rust: crate hyphens become underscores in `use`.
    assert!(package_signal_distro_smell("rust", "percent-encoding").is_some());
    assert!(package_signal_distro_smell("rust", "percent_encoding").is_none());
    // Swift: SwiftPM hyphens vs CamelCase modules.
    assert!(package_signal_distro_smell("swift", "async-http-client").is_some());
    assert!(package_signal_distro_smell("swift", "AsyncHTTPClient").is_none());
    // Perl/Dart: hyphens are illegal in `use` / pub package names.
    assert!(package_signal_distro_smell("perl", "Net-LDAP").is_some());
    assert!(package_signal_distro_smell("perl", "Net::LDAP").is_none());
    assert!(package_signal_distro_smell("dart", "dart-core").is_some());
    // Languages whose imports legitimately carry hyphens — never flagged.
    assert!(package_signal_distro_smell("javascript", "sanitize-html").is_none());
    assert!(package_signal_distro_smell("typescript", "@adonisjs/core").is_none());
    assert!(package_signal_distro_smell("ruby", "rest-client").is_none());
    assert!(package_signal_distro_smell("lua", "lua-resty-string").is_none());
    assert!(package_signal_distro_smell("c", "linux-gpio").is_none());
    assert!(package_signal_distro_smell("cpp", "cpp-httplib").is_none());
    assert!(package_signal_distro_smell("go", "github.com/foo/bar").is_none());
    assert!(package_signal_distro_smell("php", "Foo\\Bar").is_none());
    assert!(package_signal_distro_smell("erlang", "mongodb-erlang").is_none());
    assert!(package_signal_distro_smell("solidity", "./Foo.sol").is_none());
}

#[test]
fn validator_reports_invalid_rule_and_constraint_regexes() {
    let rule = validation_rule_from_yaml(
        r#"
id: python.sqli.invalid_regex
enabled: false
language: python
tag: sql-injection
severity: high
cwe: [CWE-89]
disabled_reason:
  code: over-broad
match:
  kind: call
  callee:
    regex: "^(execute"
constraints:
  - arg_matches_regex:
      index: 0
      regex: "["
description: Disabled placeholder with invalid regexes for validator coverage.
"#,
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    let invalid_regex_issues = report
        .issues
        .iter()
        .filter(|issue| issue.code == "match-example-regex-invalid")
        .count();
    assert_eq!(
        invalid_regex_issues, 2,
        "expected target and constraint regex errors, got {:#?}",
        report.issues
    );
}

#[test]
fn validator_requires_disabled_reason_on_disabled_rules() {
    let rule = validation_rule_from_yaml(
        r"
id: python.sqli.disabled_without_reason
enabled: false
language: python
tag: sql-injection
severity: high
cwe: [CWE-89]
match:
  kind: call
  callee:
    name: execute
description: Disabled placeholder rule with enough metadata to isolate missing disabled_reason.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "missing-disabled-reason"),
        "expected missing disabled_reason error, got {:#?}",
        report.issues
    );
}

#[test]
fn validator_summarizes_disabled_reason_codes() {
    let rule = validation_rule_from_yaml(
        r"
id: python.sqli.disabled_with_reason
enabled: false
disabled_reason:
  code: requires-constraint
language: python
tag: sql-injection
severity: high
cwe: [CWE-89]
match:
  kind: call
  callee:
    name: execute
description: Disabled placeholder rule waiting on an argument-shape constraint.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert_eq!(report.errors, 0, "unexpected errors: {:#?}", report.issues);
    assert_eq!(report.disabled_rule_count, 1);
    assert_eq!(report.disabled_waiting_reenable_count, 1);
    assert_eq!(
        report.disabled_reason_counts.get("requires-constraint").copied(),
        Some(1)
    );
}

#[test]
fn path_filter_directory_entries_match_components_only() {
    assert!(path_filter_matches("repo/tests/test_app.py", "tests/"));
    assert!(path_filter_matches("tests/test_app.py", "tests/"));
    assert!(path_filter_matches(r"repo\tests\test_app.py", "tests/"));
    assert!(!path_filter_matches("repo/contest/test_app.py", "test/"));
    assert!(!path_filter_matches("repo/latest/app.py", "test/"));
}

#[test]
fn path_filter_keeps_file_suffix_and_plain_substring_filters() {
    assert!(path_filter_matches("repo/pkg/service_test.go", "_test.go"));
    assert!(path_filter_matches(
        "repo/src/test/java/AppTest.java",
        "src/test/"
    ));
    assert!(path_filter_matches(
        "repo/src/main/java/AppTest.java",
        "Test.java"
    ));
    assert!(path_filter_matches("repo/src/main.py", "main.py"));
    assert!(!path_filter_matches("repo/src/main.py", "test.py"));
}

#[test]
fn source_sink_dedup_uses_byte_span_not_display_position() {
    let first = rule_match_with_span(10, 20);
    let second = rule_match_with_span(30, 40);
    let mut first_flow = tainted_call_with_span("sink", 10, 20);
    first_flow.parent_trace_id = Some(1);
    let mut second_flow = tainted_call_with_span("sink", 10, 20);
    second_flow.parent_trace_id = Some(2);

    assert_eq!(first.line, second.line);
    assert_eq!(first.column, second.column);
    assert_ne!(
        source_sink_flow_emission_key(0, &first, &first_flow),
        source_sink_flow_emission_key(0, &second, &first_flow)
    );
    assert_ne!(
        source_sink_flow_emission_key(0, &first, &first_flow),
        source_sink_flow_emission_key(0, &first, &second_flow),
        "two real lineages to the same sink site must remain distinct until flow-level grouping"
    );
}

// The text-fallback heuristic that previously joined a tainted
// call to a sink whose match_text *contained* the call's bare
// name has been removed — `tainted_call_matches_sink` is now
// strictly span-overlap. These tests pin the new contract:
// matching is purely semantic, never identifier-text-driven.

#[test]
fn tainted_call_does_not_match_sink_when_spans_disjoint_even_if_name_aligns() {
    // Same callee name as the sink's match_text and a perfect
    // tail-equality, but the spans don't overlap. The old
    // text-fallback would have accepted; the new strict gate
    // rejects.
    let call = tainted_call_with_name("query");
    let sink = rule_match_with_text_and_span("db.query(sql)", 30, 40);
    assert!(
        !tainted_call_matches_sink(&call, &sink),
        "span overlap is the only gate; matching identifier text is not enough"
    );
}

#[test]
fn tainted_call_does_not_match_sink_via_builder_terminal_text() {
    // Builder-chain terminal callee text alignment was a frequent
    // text-fallback positive case. The new strict gate rejects it
    // because the call's span (100..110) is disjoint from the
    // sink's span (30..40).
    let call = tainted_call_with_name("Run");
    let sink = rule_match_with_text_and_span(r#"execpkg.Command("/bin/sh", "-c", cmd).Run"#, 30, 40);
    assert!(
        !tainted_call_matches_sink(&call, &sink),
        "builder-terminal text equality is no longer a substitute for span overlap"
    );
}

#[test]
fn tainted_call_does_not_match_sink_when_callee_text_is_substring() {
    let call = tainted_call_with_name("myquery");
    let sink = rule_match_with_text_and_span("query", 30, 40);
    assert!(
        !tainted_call_matches_sink(&call, &sink),
        "substring text matching never produced a finding; remove confirms"
    );
}

#[test]
fn tainted_call_matches_sink_when_spans_overlap() {
    // The matcher already located the sink at this exact
    // program point, and the taint engine recorded a tainted
    // call there. Span overlap is the semantic gate that
    // attributes the finding.
    let call = tainted_call_with_span("query", 30, 40);
    let sink = rule_match_with_text_and_span("db.query(sql)", 30, 40);
    assert!(tainted_call_matches_sink(&call, &sink));
}

#[test]
fn taint_lineage_reconstructs_parent_edge_chain() {
    let source = FuncId::new(10);
    let middle = FuncId::new(20);
    let sink_func = FuncId::new(30);
    let unrelated = FuncId::new(40);
    let records = vec![
        tainted_edge(1, None, source, middle, 10),
        tainted_edge(2, Some(1), middle, sink_func, 20),
        tainted_edge(3, None, source, unrelated, 5),
    ];
    let terminal = TaintedCall {
        parent_trace_id: Some(2),
        caller: sink_func,
        name: "sink".to_string(),
        call_span: Span::new(bonsai_common::FileId::new(1), 30, 31),
        tainted_args: Vec::new(),
        tainted_receiver: None,
        kind: TaintedCallKind::Call,
    };

    let lineage = lineage_records_for_call(&records, &terminal).expect("lineage");
    let trace_ids: Vec<u64> = lineage.iter().map(|record| record.trace_id).collect();
    assert_eq!(trace_ids, vec![1, 2]);
    assert_eq!(
        chain_funcs_for_lineage(&lineage, source, sink_func),
        Some(vec![source, middle, sink_func])
    );
}

#[test]
fn taint_lineage_requires_recorded_parent_trace() {
    let source = FuncId::new(10);
    let middle = FuncId::new(20);
    let sink_func = FuncId::new(30);
    let records = vec![tainted_edge(1, None, source, middle, 10)];
    let terminal = TaintedCall {
        parent_trace_id: Some(999),
        caller: sink_func,
        name: "sink".to_string(),
        call_span: Span::new(bonsai_common::FileId::new(1), 30, 31),
        tainted_args: Vec::new(),
        tainted_receiver: None,
        kind: TaintedCallKind::Call,
    };

    assert!(
        lineage_records_for_call(&records, &terminal).is_none(),
        "missing lineage evidence must not be replaced with a call-graph-only path"
    );
}

#[test]
fn precision_filter_keeps_only_requested_confidence() {
    assert!(finding_precision_within("exact", Precision::Narrowed));
    assert!(finding_precision_within("narrowed", Precision::Narrowed));
    assert!(!finding_precision_within("over-approximate", Precision::Narrowed));
    assert!(!finding_precision_within("unknown", Precision::Narrowed));
}

fn tainted_edge(
    trace_id: u64,
    parent_trace_id: Option<u64>,
    caller: FuncId,
    callee: FuncId,
    start: u64,
) -> TaintedCallEdge {
    TaintedCallEdge {
        trace_id,
        parent_trace_id,
        caller,
        callee,
        call_span: Span::new(bonsai_common::FileId::new(1), start, start + 1),
        tainted_args: Vec::new(),
        precision: Precision::Narrowed,
    }
}

fn tainted_call_with_span(name: &str, start: u32, end: u32) -> TaintedCall {
    TaintedCall {
        parent_trace_id: None,
        caller: FuncId::new(1),
        name: name.to_string(),
        call_span: Span::new(bonsai_common::FileId::new(1), u64::from(start), u64::from(end)),
        tainted_args: Vec::new(),
        tainted_receiver: None,
        kind: TaintedCallKind::Call,
    }
}

fn tainted_call_with_name(name: &str) -> TaintedCall {
    TaintedCall {
        parent_trace_id: None,
        caller: FuncId::new(1),
        name: name.to_string(),
        call_span: Span::new(bonsai_common::FileId::new(1), 100, 110),
        tainted_args: Vec::new(),
        tainted_receiver: None,
        kind: TaintedCallKind::Call,
    }
}

fn rule_match_with_span(start: u32, end: u32) -> RuleMatch {
    rule_match_with_text_and_span("sink", start, end)
}

fn rule_match_with_text_and_span(match_text: &str, start: u32, end: u32) -> RuleMatch {
    RuleMatch {
        rule_id: "python.test.sink".to_string(),
        language: "python".to_string(),
        file: "app.py".to_string(),
        line: 1,
        column: 1,
        span: Span::new(bonsai_common::FileId::new(1), u64::from(start), u64::from(end)),
        match_text: match_text.to_string(),
        enclosing_fn: Some("handler".to_string()),
    }
}

#[test]
fn nested_sanitizer_inside_tainted_sink_arg_is_dataflow_connected() {
    let src = rule_match_with_text_and_span("Input", 0, 5);
    let san = rule_match_with_text_and_span("uri_string:quote", 120, 136);
    let sink_tainted_args = [TaintedArgInfo {
        index: 0,
        value_text: "[\"ping \", uri_string:quote(Input)]".to_string(),
    }];

    // GREEN after fix: the tainted carrier `Input` is wrapped INSIDE the
    // anchored `uri_string:quote(...)` call, so credit stands.
    assert!(sanitizer_is_nested_in_tainted_sink_arg(
        &src,
        &san,
        &sink_tainted_args
    ));
}

#[test]
fn nested_sanitizer_with_renamed_dynamic_value_is_dataflow_connected() {
    let src = rule_match_with_text_and_span("request.getHeaderNames", 0, 22);
    let san = rule_match_with_text_and_span("org.owasp.esapi.ESAPI.encoder().encodeForHTML", 120, 166);
    let sink_tainted_args = [TaintedArgInfo {
        index: 0,
        value_text: "\"Sensitive value '\" + org.owasp.esapi.ESAPI.encoder().encodeForHTML(new String(input)) + \"' hashed and stored<br/>\"".to_string(),
    }];

    assert!(sanitizer_is_nested_in_tainted_sink_arg(
        &src,
        &san,
        &sink_tainted_args
    ));
}

#[test]
fn nested_sanitizer_inside_sink_arg_can_attach_after_sink_callee_token() {
    let src = RuleMatch {
        match_text: "Input".to_string(),
        line: 1,
        column: 1,
        span: Span::new(bonsai_common::FileId::new(1), 0, 5),
        ..rule_match_with_text_and_span("Input", 0, 5)
    };
    let snk = RuleMatch {
        match_text: "os:cmd".to_string(),
        line: 3,
        column: 5,
        span: Span::new(bonsai_common::FileId::new(1), 100, 106),
        ..rule_match_with_text_and_span("os:cmd", 100, 106)
    };
    let san = RuleMatch {
        match_text: "uri_string:quote".to_string(),
        line: 3,
        column: 20,
        span: Span::new(bonsai_common::FileId::new(1), 120, 136),
        ..rule_match_with_text_and_span("uri_string:quote", 120, 136)
    };
    let sink_tainted_args = [TaintedArgInfo {
        index: 0,
        value_text: "[\"ping \", uri_string:quote(Input)]".to_string(),
    }];

    let func = FuncId::new(1);
    assert!(sanitizer_can_attach(
        &src,
        func,
        &san,
        func,
        &snk,
        func,
        &sink_tainted_args,
        true,
        false
    ));
}

#[test]
fn dataflow_connected_sanitizer_after_sink_does_not_attach_by_default() {
    let src = rule_match_with_text_and_span("Input", 0, 5);
    let snk = RuleMatch {
        match_text: "exec".to_string(),
        line: 3,
        column: 5,
        span: Span::new(bonsai_common::FileId::new(1), 100, 106),
        ..rule_match_with_text_and_span("exec", 100, 106)
    };
    let san = RuleMatch {
        match_text: "escape".to_string(),
        line: 4,
        column: 5,
        span: Span::new(bonsai_common::FileId::new(1), 150, 156),
        ..rule_match_with_text_and_span("escape", 150, 156)
    };
    let func = FuncId::new(1);

    assert!(!sanitizer_can_attach(
        &src,
        func,
        &san,
        func,
        &snk,
        func,
        &[],
        true,
        false
    ));
}

#[test]
fn path_construction_containment_can_attach_after_join_sink() {
    let src = rule_match_with_text_and_span("name", 0, 4);
    let snk = RuleMatch {
        match_text: "filepath.Join".to_string(),
        line: 3,
        column: 18,
        span: Span::new(bonsai_common::FileId::new(1), 100, 113),
        ..rule_match_with_text_and_span("filepath.Join", 100, 113)
    };
    let san = RuleMatch {
        match_text: "filepath.Rel".to_string(),
        line: 4,
        column: 17,
        span: Span::new(bonsai_common::FileId::new(1), 150, 162),
        ..rule_match_with_text_and_span("filepath.Rel", 150, 162)
    };
    let func = FuncId::new(1);

    assert!(sanitizer_can_attach(
        &src,
        func,
        &san,
        func,
        &snk,
        func,
        &[],
        true,
        true
    ));
}

#[test]
fn group_id_hashes_shared_tail_not_full_flow_chain() {
    let first = vec!["entry_a".to_string(), "service".to_string(), "sink".to_string()];
    let second = vec!["entry_b".to_string(), "service".to_string(), "sink".to_string()];

    assert_ne!(flow_id_for_chain_names(&first), flow_id_for_chain_names(&second));
    assert_eq!(
        group_id_for_chain_names(&first),
        group_id_for_chain_names(&second)
    );
    assert_ne!(
        &flow_id_for_chain_names(&first)[2..],
        &group_id_for_chain_names(&first)[2..],
        "flow and group IDs must not alias when the shared tail differs from the full chain",
    );
}

#[test]
fn empty_chain_is_unsanitized() {
    assert_eq!(
        compute_status(&[], Some("sql-injection")),
        FindingStatus::Unsanitized
    );
}

#[test]
fn same_tag_credit_is_sanitized() {
    let chain = [sanitizer(Some("sql-injection"))];
    assert_eq!(
        compute_status(&chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );
}

#[test]
fn cross_tag_credit_is_sanitized() {
    let chain = [sanitizer(Some("html-encode"))];
    assert_eq!(compute_status(&chain, Some("xss")), FindingStatus::Sanitized);
}

#[test]
fn wrong_context_real_sanitizer_is_wrong_context() {
    let chain = [sanitizer(Some("html-encode"))];
    assert_eq!(
        compute_status(&chain, Some("open-redirect")),
        FindingStatus::WrongContext
    );
}

#[test]
fn passthrough_only_chain_is_unsanitized_not_wrong_context() {
    let chain = [sanitizer(Some("passthrough-decode"))];
    assert_eq!(compute_status(&chain, Some("xss")), FindingStatus::Unsanitized);
}

#[test]
fn validation_only_chain_is_unsanitized() {
    let chain = [sanitizer(Some("validation"))];
    assert_eq!(
        compute_status(&chain, Some("sql-injection")),
        FindingStatus::Unsanitized
    );
}

#[test]
fn allowlist_and_shape_sanitizers_credit_targeted_sink_families() {
    let chain = [sanitizer(Some("allowlist-validate"))];
    assert_eq!(
        compute_status(&chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );
    assert_eq!(compute_status(&chain, Some("ssrf")), FindingStatus::Sanitized);

    let regex_chain = [sanitizer(Some("regex-validate"))];
    assert_eq!(
        compute_status(&regex_chain, Some("path-traversal")),
        FindingStatus::Sanitized
    );

    let chars_chain = [sanitizer(Some("char-allowlist"))];
    assert_eq!(
        compute_status(&chars_chain, Some("header-injection")),
        FindingStatus::Sanitized
    );
}

#[test]
fn go_header_char_allowlist_condition_recognizes_printable_guard() {
    assert!(header_char_allowlist_condition(
        "ch >= 0x20 && ch != 0x7f && ch != '\"' && ch != '\\\\'",
        "ch"
    ));
    assert!(!header_char_allowlist_condition("ch != '\\r'", "ch"));
    assert!(!header_char_allowlist_condition(
        "other >= 0x20 && other != 0x7f",
        "ch"
    ));
}

#[test]
fn parameter_and_same_origin_sanitizers_credit_contextual_sinks() {
    let db_chain = [sanitizer(Some("db-bind-parameter"))];
    assert_eq!(
        compute_status(&db_chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );

    let redirect_chain = [sanitizer(Some("same-origin-path"))];
    assert_eq!(
        compute_status(&redirect_chain, Some("open-redirect")),
        FindingStatus::Sanitized
    );

    let xpath_chain = [sanitizer(Some("xpath-parameter"))];
    assert_eq!(
        compute_status(&xpath_chain, Some("xpath-injection")),
        FindingStatus::Sanitized
    );
}

#[test]
fn untagged_only_chain_is_unsanitized() {
    let chain = [sanitizer(None)];
    assert_eq!(compute_status(&chain, Some("xss")), FindingStatus::Unsanitized);
}

#[test]
fn passthrough_plus_real_wrong_context_is_wrong_context() {
    let chain = [
        sanitizer(Some("passthrough-decode")),
        sanitizer(Some("html-encode")),
    ];
    assert_eq!(
        compute_status(&chain, Some("open-redirect")),
        FindingStatus::WrongContext
    );
}

#[test]
fn credit_after_wrong_context_short_circuits_to_sanitized() {
    let chain = [sanitizer(Some("html-encode")), sanitizer(Some("sql-injection"))];
    assert_eq!(
        compute_status(&chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );
}

// ── Distribution-name + ungated-regex validator integration ────────

#[test]
fn validator_rejects_maven_artifact_in_java_packages_field() {
    // `kafka-clients` is a Maven coordinate, not a Java package
    // string the adapter sees in `import` lines. Catch at load.
    let rule = validation_rule_from_yaml(
        r"
id: java.source.kafka_consumer_record
enabled: true
language: java
tag: queue-input
severity: low
packages: [kafka-clients]
cwe: [CWE-20]
match:
  kind: call
  callee:
    attribute: [ConsumerRecord, value]
match_examples:
  - name: kafka consumer record
    code: |
      import org.apache.kafka.clients.consumer.ConsumerRecord;
      class App {
        void handle(ConsumerRecord<?,?> rec) { Object v = rec.value(); }
      }
    expect_match_text: [rec.value]
description: ConsumerRecord.value() exposes attacker-controlled queue payload to downstream handlers.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    let distro = report
        .issues
        .iter()
        .filter(|i| i.code == "package-is-distribution-name")
        .collect::<Vec<_>>();
    assert!(
        !distro.is_empty(),
        "expected package-is-distribution-name error, got {:#?}",
        report.issues
    );
    assert!(
        distro.iter().any(|i| i.message.contains("kafka-clients")),
        "error should name the offending signal, got {:#?}",
        distro
    );
    assert!(
        distro.iter().all(|i| i.level == "error"),
        "distribution-name issues must be error-level"
    );
}

#[test]
fn validator_accepts_hyphenated_npm_package_in_javascript() {
    // Hyphens are legitimate in npm/JS imports
    // (`require("sanitize-html")`), so the validator must NOT
    // fire for JS — only the language-aware list (Java/Kotlin/
    // Scala/Python/Rust/Swift/Perl/Dart).
    assert!(package_signal_distro_smell("javascript", "sanitize-html").is_none());
    assert!(package_signal_distro_smell("typescript", "@adonisjs/core").is_none());
    assert!(package_signal_distro_smell("ruby", "rest-client").is_none());
    assert!(package_signal_distro_smell("lua", "lua-resty-string").is_none());
}

#[test]
fn validator_rejects_pypi_distribution_name_in_python_packages_field() {
    // `python-jose` is a PyPI distribution; the adapter only
    // sees `jose` in `import` statements.
    let rule = validation_rule_from_yaml(
        r"
id: python.jwt.jose_decode
enabled: true
language: python
tag: untrusted-token
severity: medium
packages: [python-jose]
cwe: [CWE-345]
match:
  kind: call
  callee:
    attribute: [jwt, decode]
match_examples:
  - name: jose decode
    code: |
      from jose import jwt
      def handle(token):
          return jwt.decode(token, key='x')
    expect_match_text: [jwt.decode]
description: jose.jwt.decode without verification reads attacker-controlled JWT payload.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == "package-is-distribution-name"
                && i.message.contains("python-jose")
                && i.level == "error"),
        "expected python distribution-name error, got {:#?}",
        report.issues
    );
}

#[test]
fn validator_rejects_receiver_agnostic_regex_without_package_gate() {
    // A regex that accepts any receiver but lacks `packages:`
    // collides with peer rules' match_examples in unrelated
    // files because the matcher's regex path can't gate by
    // file imports.
    let rule = validation_rule_from_yaml(
        r"
id: javascript.xss.body_assignment
enabled: true
language: javascript
tag: xss
severity: high
cwe: [CWE-79]
match:
  kind: call
  callee:
    regex: ^[A-Za-z_$][A-Za-z0-9_$]*\.body$
match_examples:
  - name: ungated body
    code: |
      function handle(ctx) {
        ctx.body = unsafe;
      }
    expect_match_text: [ctx.body]
description: Writing tainted data into a response body without escaping causes reflected XSS.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == "receiver-agnostic-regex-without-package-gate" && i.level == "error"),
        "expected receiver-agnostic regex error, got {:#?}",
        report.issues
    );
}

#[test]
fn validator_accepts_receiver_agnostic_regex_with_package_gate() {
    // Same regex shape as the rejected case above, but
    // `packages:` gates it with adapter-visible import context at runtime.
    let rule = validation_rule_from_yaml(
        r"
id: javascript.xss.koa_body_assignment
enabled: true
language: javascript
tag: xss
severity: high
cwe: [CWE-79]
packages: [koa]
imports: [koa]
match:
  kind: call
  callee:
    regex: ^[A-Za-z_$][A-Za-z0-9_$]*\.body$
match_examples:
  - name: koa context body
    code: |
      const Koa = require('koa');
      const app = new Koa();
      app.use(async ctx => {
        ctx.body = userHtml;
      });
    expect_match_text: [ctx.body]
description: Writing tainted data into Koa ctx.body without escaping causes reflected XSS.
",
    );
    let pack = single_rule_pack(rule);
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.code == "receiver-agnostic-regex-without-package-gate"),
        "package-gated regex must not be flagged: {:#?}",
        report.issues
    );
}

// audit re-apply: M4: three regression tests pinning the over-credit fix. `esc
#[test]
fn sanitizer_on_static_literal_concatenated_with_taint_does_not_credit() {
    // M4 regression: `escapeHtml("static") + Input` -- the sanitizer
    // wraps a STATIC literal and the tainted `Input` is concatenated
    // OUTSIDE the call. RED before fix (unanchored `contains("escapeHtml")`
    // credited it, mislabeling a real flow `Sanitized`); GREEN after.
    let src = rule_match_with_text_and_span("Input", 0, 5);
    let san = rule_match_with_text_and_span("escapeHtml", 120, 130);
    let sink_tainted_args = [TaintedArgInfo {
        index: 0,
        value_text: "escapeHtml(\"static\") + Input".to_string(),
    }];

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &src,
        &san,
        &sink_tainted_args
    ));
}

#[test]
fn sanitizer_on_other_dynamic_value_concatenated_with_taint_does_not_credit() {
    // The sanitizer wraps `other`, while the tainted carrier `Input`
    // remains outside the sanitizer call.
    let src = rule_match_with_text_and_span("Input", 0, 5);
    let san = rule_match_with_text_and_span("escapeHtml", 120, 130);
    let sink_tainted_args = [TaintedArgInfo {
        index: 0,
        value_text: "escapeHtml(other) + Input".to_string(),
    }];

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &src,
        &san,
        &sink_tainted_args
    ));
}

#[test]
fn sanitizer_callee_as_substring_of_longer_identifier_does_not_credit() {
    // M4 regression: the callee appears only as the tail of a longer
    // identifier (`myEscapeHtml`), never as an actual call of `escapeHtml`.
    // RED before fix (substring `contains`); GREEN after (anchored call form).
    let src = rule_match_with_text_and_span("Input", 0, 5);
    let san = rule_match_with_text_and_span("escapeHtml", 120, 130);
    let sink_tainted_args = [TaintedArgInfo {
        index: 0,
        value_text: "myEscapeHtml(Input)".to_string(),
    }];

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &src,
        &san,
        &sink_tainted_args
    ));
}

#[test]
fn sanitizer_callee_as_field_name_without_call_does_not_credit() {
    // M4 regression: the callee text appears as a field/identifier with
    // no `(` call form (`config.escapeHtml = Input`). RED before fix
    // (bare substring); GREEN after (call-form anchor required).
    let src = rule_match_with_text_and_span("Input", 0, 5);
    let san = rule_match_with_text_and_span("escapeHtml", 120, 130);
    let sink_tainted_args = [TaintedArgInfo {
        index: 0,
        value_text: "config.escapeHtml = Input".to_string(),
    }];

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &src,
        &san,
        &sink_tainted_args
    ));
}
