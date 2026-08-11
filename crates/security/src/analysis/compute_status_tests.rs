//! Tests for `compute_status` and the status-merge invariants. Extracted
//! from `analysis/mod.rs` for navigability — `compute_status` evolves
//! independently of the rest of the analysis pipeline and the tests
//! exercise sanitizer credit + non-crediting tag classification.

use super::*;
use crate::finding::{FindingMatch, TaintedArgInfo};
use crate::loader::LanguagePack;
use bonsai_common::path_filter_matches;
use bonsai_taint::TaintedCallKind;

fn sanitizer(tag: Option<&str>) -> FindingMatch {
    FindingMatch {
        origin: MatchOrigin::Rulepack,
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

fn bundled_metadata() -> &'static RulepackMetadata {
    static METADATA: std::sync::OnceLock<RulepackMetadata> = std::sync::OnceLock::new();
    METADATA.get_or_init(|| {
        crate::loader::load_rulepack(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("security-patterns"),
        )
        .expect("bundled rulepack")
        .metadata
    })
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
fn clean_overwrite_target_key_does_not_guess_compound_expression_operands() {
    assert_eq!(clean_overwrite_target_key("x").as_deref(), Some("x"));
    assert!(clean_overwrite_target_key("\"-c \" + x").is_none());
    assert!(clean_overwrite_target_key("format!(\"{}\", cmd)").is_none());
    assert!(clean_overwrite_target_key("\"x inside string\"").is_none());
}

#[test]
fn tainted_argument_evidence_preserves_structured_ast_operands() {
    let span = bonsai_common::Span::new(bonsai_common::FileId::new(1), 10, 30);
    let events = [FlowEvent::Call {
        span,
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            span,
            passing_mode: Default::default(),
            name: None,
            value_text: "prefix + command".to_string(),
            place: None,
            source_names: vec!["prefix".to_string(), "command".to_string()],
        }],
    }];
    let tainted = bonsai_taint::TaintedArgAtCall {
        index: 0,
        value_text: "prefix + command".to_string(),
        place: None,
        source_names: vec!["prefix".to_string(), "command".to_string()],
    };

    let info = tainted_arg_info_from_events(&events, span, &tainted);
    assert_eq!(info.source_names, ["prefix", "command"]);
    assert_eq!(tainted_arg_target_keys(&info), ["command", "prefix"]);
}

#[test]
fn clean_output_call_overwrites_only_with_clean_values() {
    let call_span = bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 40);
    let overwrites = [CleanOutputOverwrite {
        callee: "snprintf".to_string(),
        output_arg_index: 0,
        value_start_arg_index: 2,
    }];
    let args = vec![
        bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 3),
            name: None,
            value_text: "buf".to_string(),
            place: Some("buf".to_string()),
            source_names: vec!["buf".to_string()],
        },
        bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 5, 16),
            name: None,
            value_text: "sizeof(buf)".to_string(),
            place: None,
            source_names: Vec::new(),
        },
        bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 18, 22),
            name: None,
            value_text: "\"%s\"".to_string(),
            place: None,
            source_names: Vec::new(),
        },
        bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 24, 31),
            name: None,
            value_text: "\"clean\"".to_string(),
            place: None,
            source_names: Vec::new(),
        },
    ];
    let argument_values = [2_usize, 3_usize].map(|argument_index| bonsai_lang_api::CallArgumentValueFact {
        call_span,
        argument_index,
        argument_span: args[argument_index].span,
        direct_call_span: None,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
        inline_callback_params: Vec::new(),
        value_flow: Default::default(),
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    });
    assert!(clean_output_call_overwrites_target(
        &overwrites,
        call_span,
        &argument_values,
        "snprintf",
        &args,
        "buf"
    ));
    assert!(!clean_output_call_overwrites_target(
        &[],
        call_span,
        &argument_values,
        "snprintf",
        &args,
        "buf"
    ));

    let project_overwrite = [CleanOutputOverwrite {
        callee: "project.write_clean".to_string(),
        output_arg_index: 0,
        value_start_arg_index: 2,
    }];
    assert!(clean_output_call_overwrites_target(
        &project_overwrite,
        call_span,
        &argument_values,
        "project.write_clean",
        &args,
        "buf"
    ));

    let mut tainted_value = args;
    tainted_value[3].value_text = "user_value".to_string();
    tainted_value[3].place = Some("user_value".to_string());
    tainted_value[3].source_names = vec!["user_value".to_string()];
    assert!(!clean_output_call_overwrites_target(
        &overwrites,
        call_span,
        &argument_values,
        "snprintf",
        &tainted_value,
        "buf"
    ));

    tainted_value[3].value_text = "USER_VALUE".to_string();
    tainted_value[3].place = Some("USER_VALUE".to_string());
    tainted_value[3].source_names = vec!["USER_VALUE".to_string()];
    assert!(
        !clean_output_call_overwrites_target(
            &overwrites,
            call_span,
            &argument_values,
            "snprintf",
            &tainted_value,
            "buf"
        ),
        "identifier capitalization is not compiler evidence that a value is constant"
    );
}

#[test]
fn try_region_clean_overwrite_requires_all_continuing_paths() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let policy = CleanOverwritePolicy::new(&ws, &[]);
    let target = "t";
    let clean_t = clean_assign_event(target, 10, 20);
    let clean_finally = clean_assign_event(target, 30, 40);

    assert!(
        !try_region_clean_overwrites_target(policy, &[], &[clean_t.clone()], &[], target),
        "a clean catch arm alone is only one exceptional path, not a definite overwrite"
    );
    assert!(
        try_region_clean_overwrites_target(policy, &[clean_t.clone()], &[clean_t.clone()], &[], target,),
        "normal and caught paths both overwrite the target"
    );
    assert!(
        try_region_clean_overwrites_target(policy, &[], &[], &[clean_finally], target),
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

fn single_rule_pack(mut rule: Rule) -> Rulepack {
    // Focused rules bypass the production loader, so inherit the same
    // rulepack-owned package/tag/category defaults explicitly. This keeps
    // validator tests faithful without attaching the bundled pack's complete
    // taxonomy to a deliberately one-rule fixture.
    bundled_metadata().apply_rule_defaults(&mut rule);
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
fn validator_rejects_stale_rulepack_taxonomy_metadata() {
    let rule = validation_rule_from_yaml(
        r"
id: python.test.sink
enabled: true
language: python
tag: test-sink
severity: high
cwe: [CWE-20]
match:
  kind: call
  callee: {name: sink}
match_examples:
  - name: test sink
    code: |
      def demo(value):
          sink(value)
    expect_match_text: [sink]
description: Test sink.
",
    );
    let mut pack = single_rule_pack(rule);
    pack.metadata
        .sanitizer_credits
        .insert("missing-sanitizer".to_string(), vec!["missing-sink".to_string()]);

    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "unknown-sanitizer-credit-tag"));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "unknown-sanitizer-credit-sink-tag"));
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
fn workspace_relative_path_filters_ignore_generated_ancestors() {
    let root = std::path::Path::new("/repo/target/chosen-workspace");
    assert!(
        !path_filter_matches_with_root(Some(root), "/repo/target/chosen-workspace/app.py", "target/"),
        "workspace-relative filters must not exclude a project merely because an ancestor is named target"
    );
    assert!(
        path_filter_matches_with_root(
            Some(root),
            "/repo/target/chosen-workspace/target/generated.py",
            "target/"
        ),
        "workspace-relative filters must still exclude matching paths inside the selected project"
    );
}

#[test]
fn workspace_relative_test_filters_ignore_test_ancestors() {
    let root = std::path::Path::new("/repo/tests/chosen-workspace");
    let patterns = &bundled_metadata().test_path_patterns;
    assert!(
        !path_is_excluded_with_root(
            Some(root),
            "/repo/tests/chosen-workspace/app.py",
            &[],
            true,
            patterns,
        ),
        "--exclude-tests must not classify a selected workspace as tests because a parent is named tests"
    );
    assert!(
        path_is_excluded_with_root(
            Some(root),
            "/repo/tests/chosen-workspace/tests/test_app.py",
            &[],
            true,
            patterns,
        ),
        "--exclude-tests must still apply to test paths inside the selected workspace"
    );
}

#[test]
fn workspace_relative_from_test_flag_ignores_test_ancestors() {
    let root = std::path::Path::new("/repo/tests/chosen-workspace");
    let patterns = &bundled_metadata().test_path_patterns;
    assert!(!path_is_test_file_with_root(
        Some(root),
        "/repo/tests/chosen-workspace/app.py",
        patterns,
    ));
    assert!(path_is_test_file_with_root(
        Some(root),
        "/repo/tests/chosen-workspace/tests/test_app.py",
        patterns,
    ));
}

#[test]
fn explicit_absolute_path_filters_still_match_absolute_paths() {
    let root = std::path::Path::new("/repo/target/chosen-workspace");
    assert!(path_filter_matches_with_root(
        Some(root),
        "/repo/target/chosen-workspace/app.py",
        "/repo/target/chosen-workspace/app.py"
    ));
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
        tainted_receiver_source_names: Vec::new(),
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
fn taint_lineage_keeps_helper_across_nested_return_stitch() {
    let source = FuncId::new(10);
    let helper = FuncId::new(20);
    let sink_func = FuncId::new(30);
    let records = vec![
        tainted_edge(1, None, source, helper, 10),
        // IDG Return -> CallRet stitch back to the function containing
        // `sink(helper(input))`.
        tainted_edge(2, Some(1), helper, source, 20),
        tainted_edge(3, Some(2), source, sink_func, 30),
    ];
    let terminal = TaintedCall {
        parent_trace_id: Some(3),
        caller: sink_func,
        name: "sink".to_string(),
        call_span: Span::new(bonsai_common::FileId::new(1), 40, 41),
        tainted_args: Vec::new(),
        tainted_receiver: None,
        tainted_receiver_source_names: Vec::new(),
        kind: TaintedCallKind::Call,
    };

    let lineage = lineage_records_for_call(&records, &terminal).expect("nested return lineage");
    assert_eq!(
        chain_funcs_for_lineage(&lineage, source, sink_func),
        Some(vec![source, helper, sink_func]),
        "display compaction must omit the caller revisit without erasing the helper body"
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
        tainted_receiver_source_names: Vec::new(),
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
    assert!(
        !finding_precision_within("over-approximate", Precision::Unknown),
        "diagnostic-only precision must never become public finding evidence"
    );
    assert!(
        !finding_precision_within("unknown", Precision::Unknown),
        "unknown precision must remain diagnostic-only even under a broad caller cap"
    );
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
        edge_kind: bonsai_callgraph::EdgeKind::Direct,
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
        tainted_receiver_source_names: Vec::new(),
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
        tainted_receiver_source_names: Vec::new(),
        kind: TaintedCallKind::Call,
    }
}

fn rule_match_with_span(start: u32, end: u32) -> RuleMatch {
    rule_match_with_text_and_span("sink", start, end)
}

fn rule_match_with_text_and_span(match_text: &str, start: u32, end: u32) -> RuleMatch {
    RuleMatch {
        origin: MatchOrigin::Rulepack,
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

struct NestedCallFixture {
    ws: Workspace,
    func: FuncId,
    src: RuleMatch,
    san: RuleMatch,
    snk: RuleMatch,
    sink_tainted_args: Vec<TaintedArgInfo>,
}

fn nested_call_fixture(
    sink_argument: &str,
    source_match: &str,
    sanitizer_match: &str,
    sanitizer_event_tail: Option<&str>,
) -> NestedCallFixture {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let source = format!("function handler(Input, input, other) {{ sink({sink_argument}); }}");
    ws.vfs()
        .write("fixture.js".to_string(), std::sync::Arc::<str>::from(source));
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("declaration index");
    let decl = index
        .defs
        .iter()
        .find(|decl| decl.name == "handler")
        .expect("handler declaration");
    let FlowEvent::Call {
        span: sink_span,
        args: sink_args,
        ..
    } = call_event_by_tail(&decl.flow_events, "sink").expect("sink call event")
    else {
        unreachable!("call lookup returns a call event")
    };
    let sink_arg = sink_args.first().expect("sink argument");
    let sanitizer_span = sanitizer_event_tail
        .and_then(|tail| call_event_by_tail(&decl.flow_events, tail))
        .and_then(|event| match event {
            FlowEvent::Call { span, .. } => Some(*span),
            _ => None,
        })
        .unwrap_or(sink_arg.span);
    let func = FuncId::new(decl.symbol.raw());
    let src = RuleMatch {
        span: decl.name_span,
        match_text: source_match.to_string(),
        ..rule_match_with_text_and_span(source_match, 0, 0)
    };
    let san = RuleMatch {
        span: sanitizer_span,
        match_text: sanitizer_match.to_string(),
        ..rule_match_with_text_and_span(sanitizer_match, 0, 0)
    };
    let snk = RuleMatch {
        span: *sink_span,
        match_text: "sink".to_string(),
        ..rule_match_with_text_and_span("sink", 0, 0)
    };
    let sink_tainted_args = vec![TaintedArgInfo {
        index: 0,
        value_text: sink_arg.value_text.clone(),
        place: sink_arg.place.clone(),
        source_names: sink_arg.source_names.clone(),
    }];
    drop(index);
    NestedCallFixture {
        ws,
        func,
        src,
        san,
        snk,
        sink_tainted_args,
    }
}

fn call_event_by_tail<'a>(events: &'a [FlowEvent], tail: &str) -> Option<&'a FlowEvent> {
    for event in events {
        if let FlowEvent::Call { name, .. } = event {
            if clean_overwrite_callee_tail(name) == clean_overwrite_callee_tail(tail) {
                return Some(event);
            }
        }
        let nested = match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => call_event_by_tail(then_events, tail).or_else(|| call_event_by_tail(else_events, tail)),
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                call_event_by_tail(body, tail)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => call_event_by_tail(body, tail)
                .or_else(|| call_event_by_tail(catch_events, tail))
                .or_else(|| call_event_by_tail(finally_events, tail)),
            _ => None,
        };
        if nested.is_some() {
            return nested;
        }
    }
    None
}

fn java_builder_fixture(body: &str) -> (Workspace, FuncId, Span, Span) {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let source = format!(
        "class App {{ void handle(DocumentBuilderFactory factory, DocumentBuilder builder, String input, boolean flag) throws Exception {{ {body} }} }}"
    );
    ws.vfs()
        .write("Fixture.java".to_string(), std::sync::Arc::<str>::from(source));
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("declaration index");
    let decl = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let sanitizer_span = match call_event_by_tail(&decl.flow_events, "setFeature") {
        Some(FlowEvent::Call { span, .. }) => *span,
        _ => panic!("setFeature call event"),
    };
    let sink_span = match call_event_by_tail(&decl.flow_events, "parse") {
        Some(FlowEvent::Call { span, .. }) => *span,
        _ => panic!("parse call event"),
    };
    let func = FuncId::new(decl.symbol.raw());
    drop(index);
    (ws, func, sanitizer_span, sink_span)
}

#[test]
fn xxe_builder_creation_uses_structured_assignment_and_call_facts() {
    let (ws, func, sanitizer_span, sink_span) = java_builder_fixture(
        r#"factory.setFeature("disallow-doctype-decl", true);
           builder = factory.newDocumentBuilder();
           builder.parse(input);"#,
    );
    let builder_targets = [RuleTarget {
        name: Some("newDocumentBuilder".to_string()),
        ..RuleTarget::default()
    }];
    assert!(builder_created_from_factory_before_sink(
        &ws,
        func,
        sanitizer_span,
        sink_span,
        "builder",
        "factory",
        &builder_targets,
    ));
}

#[test]
fn conditional_xxe_builder_creation_does_not_dominate_later_sink() {
    let (ws, func, sanitizer_span, sink_span) = java_builder_fixture(
        r#"factory.setFeature("disallow-doctype-decl", true);
           if (flag) { builder = factory.newDocumentBuilder(); }
           builder.parse(input);"#,
    );
    let builder_targets = [RuleTarget {
        name: Some("newDocumentBuilder".to_string()),
        ..RuleTarget::default()
    }];
    assert!(!builder_created_from_factory_before_sink(
        &ws,
        func,
        sanitizer_span,
        sink_span,
        "builder",
        "factory",
        &builder_targets,
    ));
}

#[test]
fn nested_sanitizer_inside_tainted_sink_arg_is_dataflow_connected() {
    let fixture = nested_call_fixture(
        "[\"ping \", uri_string.quote(Input)]",
        "Input",
        "uri_string.quote",
        Some("quote"),
    );

    // GREEN after fix: the tainted carrier `Input` is wrapped INSIDE the
    // anchored `uri_string:quote(...)` call, so credit stands.
    assert!(sanitizer_is_nested_in_tainted_sink_arg(
        &fixture.ws,
        fixture.func,
        &fixture.src,
        &fixture.san,
        &fixture.snk,
        &fixture.sink_tainted_args,
    ));
}

#[test]
fn nested_sanitizer_with_renamed_dynamic_value_is_dataflow_connected() {
    let fixture = nested_call_fixture(
        "\"Sensitive value '\" + org.owasp.esapi.ESAPI.encoder().encodeForHTML(new String(input)) + \"' hashed and stored<br/>\"",
        "request.getHeaderNames",
        "org.owasp.esapi.ESAPI.encoder().encodeForHTML",
        Some("encodeForHTML"),
    );

    assert!(sanitizer_is_nested_in_tainted_sink_arg(
        &fixture.ws,
        fixture.func,
        &fixture.src,
        &fixture.san,
        &fixture.snk,
        &fixture.sink_tainted_args,
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
    let func = FuncId::new(1);
    assert!(sanitizer_can_attach(
        &src, func, &san, func, &snk, func, true, true, false
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
        &src, func, &san, func, &snk, func, false, true, false
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
        &src, func, &san, func, &snk, func, false, true, true
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

fn finding_match_for_grouping(rule_id: &str, line: u32, text: &str) -> FindingMatch {
    FindingMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: rule_id.to_string(),
        file: "app.py".to_string(),
        line,
        column: 1,
        text: text.to_string(),
        enclosing_fn: Some("handle".to_string()),
        tag: Some("http-input".to_string()),
        severity: None,
        category: Some("http-input".to_string()),
        trust: Some("remote".to_string()),
        payload_types: vec!["query".to_string()],
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    }
}

fn sink_match_for_grouping() -> FindingMatch {
    let mut sink = finding_match_for_grouping("python.cmdi.os_system", 50, "os.system");
    sink.file = "sink.py".to_string();
    sink.enclosing_fn = Some("run".to_string());
    sink.tag = Some("command-injection".to_string());
    sink.category = Some("process-exec".to_string());
    sink.severity = Some(Severity::Critical);
    sink.trust = None;
    sink.payload_types.clear();
    sink.tainted_args = vec![TaintedArgInfo {
        index: 0,
        value_text: "cmd".to_string(),
        ..TaintedArgInfo::default()
    }];
    sink
}

fn finding_with_flow_for_grouping(
    finding_id: &str,
    source_line: u32,
    source_value: &str,
    flow_id: &str,
) -> FindingWithChain {
    let source = finding_match_for_grouping("python.flask.request_args_get", source_line, "request.args.get");
    let sink = sink_match_for_grouping();
    let taint_path = vec![TaintPropagationStep {
        caller: "handle".to_string(),
        callee: "run".to_string(),
        file: "app.py".to_string(),
        line: 20,
        column: 5,
        tainted_args: vec![TaintPropagationArg {
            index: 0,
            value_text: source_value.to_string(),
            param_name: "cmd".to_string(),
        }],
    }];
    FindingWithChain {
        finding: Finding {
            finding_id: finding_id.to_string(),
            language: "python".to_string(),
            source,
            sink,
            sanitizers_seen: Vec::new(),
            taint_transforms_seen: Vec::new(),
            group_id: Some("G:sharedtail".to_string()),
            representative_flow_id: Some(flow_id.to_string()),
            analysis_complete: true,
            analysis_incomplete_reasons: Vec::new(),
            chain_display: vec!["handle".to_string(), "run".to_string()],
            taint_path,
            alternate_flows: Vec::new(),
            hops: Vec::new(),
            tag: Some("command-injection".to_string()),
            severity: Some(Severity::Critical),
            precision: "narrowed".to_string(),
            cwe: vec!["CWE-78".to_string()],
            owasp: Vec::new(),
            status: FindingStatus::Unsanitized,
            from_test: false,
        },
        chain_funcs: vec![FuncId::new(1), FuncId::new(2)],
    }
}

fn combined_terminal_finding(sink_rule_id: &str, chain_funcs: Vec<FuncId>) -> CombinedFindingWithChain {
    let mut item = finding_with_flow_for_grouping("S:terminal", 11, "token", "F:terminal");
    item.finding.sink.rule_id = sink_rule_id.to_string();
    item.finding.chain_display = chain_funcs
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("fn_{idx}"))
        .collect();
    item.chain_funcs = chain_funcs;
    CombinedFindingWithChain {
        finding: item.finding,
        chain_funcs: item.chain_funcs,
        additional_sources: Vec::new(),
        additional_sinks: Vec::new(),
        member_finding_ids: Vec::new(),
    }
}

#[test]
fn rulepack_terminal_priority_drops_only_strictly_downstream_duplicate() {
    let preferred_rule = validation_rule_from_yaml(
        r"
id: python.cmdi.project_boundary
enabled: true
language: python
tag: command-injection
severity: critical
cwe: [CWE-78]
analysis_semantics:
  sink_terminal_priority: 100
match:
  kind: call
  callee:
    name: project_boundary
description: Canonical project boundary.
",
    );
    let downstream_rule = validation_rule_from_yaml(
        r"
id: python.cmdi.transport
enabled: true
language: python
tag: command-injection
severity: critical
cwe: [CWE-78]
match:
  kind: call
  callee:
    name: transport
description: Downstream transport.
",
    );
    let mut pack = Rulepack::default();
    pack.packs.insert(
        "python".to_string(),
        LanguagePack {
            language: "python".to_string(),
            sinks: vec![preferred_rule, downstream_rule],
            ..LanguagePack::default()
        },
    );

    let mut preferred = combined_terminal_finding(
        "python.cmdi.project_boundary",
        vec![FuncId::new(1), FuncId::new(2)],
    );
    preferred.finding.tag = Some("template-injection".to_string());
    preferred.finding.cwe = vec!["CWE-1336".to_string()];
    let mut downstream = combined_terminal_finding(
        "python.cmdi.transport",
        vec![FuncId::new(1), FuncId::new(2), FuncId::new(3)],
    );
    downstream.finding.tag = Some("xss".to_string());
    downstream.finding.cwe = vec!["CWE-79".to_string()];
    let sibling = combined_terminal_finding("python.cmdi.transport", vec![FuncId::new(1), FuncId::new(4)]);
    let mut findings = vec![preferred, downstream, sibling];

    drop_rulepack_terminal_dominated_findings(&mut findings, &pack, None);

    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .any(|item| item.finding.sink.rule_id == "python.cmdi.project_boundary"));
    assert!(findings
        .iter()
        .find(|item| item.finding.sink.rule_id == "python.cmdi.project_boundary")
        .is_some_and(|item| item
            .additional_sinks
            .iter()
            .any(|sink| sink.rule_id == "python.cmdi.transport")));
    assert!(findings.iter().any(|item| {
        item.finding.sink.rule_id == "python.cmdi.transport"
            && item.chain_funcs == vec![FuncId::new(1), FuncId::new(4)]
    }));
}

#[test]
fn combined_finding_retains_every_distinct_representative_flow() {
    let pack = Rulepack::default();
    let groups = combine_findings_by_source_flow(
        vec![
            finding_with_flow_for_grouping("S:token", 11, "token", "F:token-flow"),
            finding_with_flow_for_grouping("S:action", 12, "action", "F:action-flow"),
        ],
        &pack,
    );

    assert_eq!(groups.len(), 1, "one concrete sink is one finding");
    let group = &groups[0];
    assert_eq!(group.finding.source.line, 11);
    assert_eq!(
        group.finding.taint_path[0].tainted_args[0].value_text, "token",
        "the primary source and path must stay paired"
    );
    assert_eq!(group.finding.alternate_flows.len(), 1);
    let alternate = &group.finding.alternate_flows[0];
    assert_eq!(alternate.source.line, 12);
    assert_eq!(
        alternate.taint_path[0].tainted_args[0].value_text, "action",
        "the alternate source and path must stay paired"
    );
    assert_eq!(group.additional_sources.len(), 1);
    assert_eq!(group.member_finding_ids.len(), 2);
}

#[test]
fn combined_finding_drops_only_same_route_argument_supersets() {
    let pack = Rulepack::default();
    let narrow = finding_with_flow_for_grouping("S:narrow", 11, "token", "F:narrow");
    let mut broad = finding_with_flow_for_grouping("S:broad", 11, "token", "F:broad");
    broad.finding.taint_path[0]
        .tainted_args
        .push(TaintPropagationArg {
            index: 1,
            value_text: "constant".to_string(),
            param_name: "base".to_string(),
        });

    let groups = combine_findings_by_source_flow(vec![broad, narrow], &pack);

    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].finding.representative_flow_id.as_deref(),
        Some("F:narrow")
    );
    assert!(
        groups[0].finding.alternate_flows.is_empty(),
        "the same source and call route must not retain a less precise argument superset"
    );
    assert_eq!(
        groups[0].member_finding_ids.len(),
        2,
        "the suppressed proof remains addressable as a member id"
    );
}

#[test]
fn combined_finding_preserves_argument_supersets_from_distinct_source_sites() {
    let pack = Rulepack::default();
    let narrow = finding_with_flow_for_grouping("S:narrow", 11, "token", "F:narrow");
    let mut broad = finding_with_flow_for_grouping("S:broad", 13, "token", "F:broad");
    broad.finding.taint_path[0]
        .tainted_args
        .push(TaintPropagationArg {
            index: 1,
            value_text: "constant".to_string(),
            param_name: "base".to_string(),
        });

    let groups = combine_findings_by_source_flow(vec![broad, narrow], &pack);

    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].finding.alternate_flows.len(),
        1,
        "separate source occurrences are separate provenance even when their call routes match"
    );
    assert_eq!(groups[0].additional_sources.len(), 1);
}

#[test]
fn combined_finding_keeps_route_mitigation_evidence_paired() {
    let pack = Rulepack::default();
    let unsanitized = finding_with_flow_for_grouping("S:raw", 11, "raw", "F:raw");
    let mut sanitized = finding_with_flow_for_grouping("S:clean", 12, "clean", "F:clean");
    sanitized.finding.status = FindingStatus::Sanitized;
    sanitized.finding.from_test = true;
    sanitized.finding.sanitizers_seen.push(finding_match_for_grouping(
        "python.sanitizer.allowlist",
        30,
        "allowlist",
    ));

    let groups = combine_findings_by_source_flow(vec![sanitized, unsanitized], &pack);

    assert_eq!(groups.len(), 1);
    let finding = &groups[0].finding;
    assert_eq!(finding.status, FindingStatus::Unsanitized);
    assert!(
        !finding.from_test,
        "one production route keeps the combined sink production-relevant"
    );
    assert_eq!(finding.representative_flow_id.as_deref(), Some("F:raw"));
    assert!(
        finding.sanitizers_seen.is_empty(),
        "an alternate route's sanitizer must not be attached to the representative route"
    );
    assert_eq!(finding.alternate_flows.len(), 1);
    assert_eq!(finding.alternate_flows[0].status, FindingStatus::Sanitized);
    assert_eq!(finding.alternate_flows[0].sanitizers_seen.len(), 1);
}

#[test]
fn combined_findings_keep_distinct_calls_on_one_source_line() {
    let pack = Rulepack::default();
    let first = finding_with_flow_for_grouping("S:first", 11, "token", "F:first");
    let mut second = finding_with_flow_for_grouping("S:second", 11, "token", "F:second");
    second.finding.sink.column += 10;

    let groups = combine_findings_by_source_flow(vec![first, second], &pack);

    assert_eq!(
        groups.len(),
        2,
        "exact sink columns keep two same-line calls independently reportable"
    );
}

#[test]
fn combined_finding_keeps_primary_sink_evidence_paired_across_alias_rules() {
    let pack = Rulepack::default();
    let mut primary = finding_with_flow_for_grouping("S:primary", 11, "token", "F:primary");
    primary.finding.sink.rule_id = "python.cmdi.z_primary".to_string();
    primary.finding.sink.tainted_args[0].value_text = "token".to_string();
    let mut alias = finding_with_flow_for_grouping("S:alias", 12, "action", "F:alias");
    alias.finding.sink.rule_id = "python.cmdi.a_alias".to_string();
    alias.finding.sink.tainted_args[0].value_text = "action".to_string();

    let groups = combine_findings_by_source_flow(vec![alias, primary], &pack);

    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.finding.source.line, 11);
    assert_eq!(group.finding.sink.rule_id, "python.cmdi.z_primary");
    assert_eq!(group.finding.sink.tainted_args[0].value_text, "token");
    assert_eq!(group.additional_sinks.len(), 1);
    assert_eq!(group.additional_sinks[0].rule_id, "python.cmdi.a_alias");
}

#[test]
fn combined_findings_keep_pattern_and_taint_evidence_separate() {
    let pack = Rulepack::default();
    let taint = finding_with_flow_for_grouping("S:taint", 11, "token", "F:taint");
    let mut pattern = finding_with_flow_for_grouping("S:pattern", 11, "token", "F:pattern");
    pattern.finding.source.origin = MatchOrigin::Pattern;
    pattern.finding.source.category = Some("pattern".to_string());
    pattern.finding.source.rule_id = "pattern:python.cmdi.os_system".to_string();
    pattern.finding.taint_path.clear();

    let groups = combine_findings_by_source_flow(vec![taint, pattern], &pack);

    assert_eq!(
        groups.len(),
        2,
        "source-independent and source-to-sink evidence have different report contracts"
    );
}

#[test]
fn empty_chain_is_unsanitized() {
    assert_eq!(
        compute_status(bundled_metadata(), &[], Some("sql-injection")),
        FindingStatus::Unsanitized
    );
}

#[test]
fn same_tag_credit_is_sanitized() {
    let chain = [sanitizer(Some("sql-injection"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );
}

#[test]
fn cross_tag_credit_is_sanitized() {
    let chain = [sanitizer(Some("html-encode"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("xss")),
        FindingStatus::Sanitized
    );
}

#[test]
fn wrong_context_real_sanitizer_is_wrong_context() {
    let chain = [sanitizer(Some("html-encode"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("open-redirect")),
        FindingStatus::WrongContext
    );
}

#[test]
fn passthrough_only_chain_is_unsanitized_not_wrong_context() {
    let chain = [sanitizer(Some("passthrough-decode"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("xss")),
        FindingStatus::Unsanitized
    );
}

#[test]
fn validation_only_chain_is_unsanitized() {
    let chain = [sanitizer(Some("validation"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("sql-injection")),
        FindingStatus::Unsanitized
    );
}

#[test]
fn allowlist_and_shape_sanitizers_credit_targeted_sink_families() {
    let chain = [sanitizer(Some("allowlist-validate"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("ssrf")),
        FindingStatus::Sanitized
    );

    let regex_chain = [sanitizer(Some("regex-validate"))];
    assert_eq!(
        compute_status(bundled_metadata(), &regex_chain, Some("path-traversal")),
        FindingStatus::Sanitized
    );

    let chars_chain = [sanitizer(Some("char-allowlist"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chars_chain, Some("header-injection")),
        FindingStatus::Sanitized
    );
}

#[test]
fn compiler_proofs_use_the_selected_sink_tag_without_wildcard_taxonomy() {
    let code_chain = [sanitizer(Some("code-injection"))];
    assert_eq!(
        compute_status(bundled_metadata(), &code_chain, Some("code-injection")),
        FindingStatus::Sanitized
    );
    let command_chain = [sanitizer(Some("command-injection"))];
    assert_eq!(
        compute_status(bundled_metadata(), &command_chain, Some("command-injection")),
        FindingStatus::Sanitized
    );
    let xss_chain = [sanitizer(Some("xss"))];
    assert_eq!(
        compute_status(bundled_metadata(), &xss_chain, Some("xss")),
        FindingStatus::Sanitized
    );
}

#[test]
fn parameter_and_same_origin_sanitizers_credit_contextual_sinks() {
    let db_chain = [sanitizer(Some("db-bind-parameter"))];
    assert_eq!(
        compute_status(bundled_metadata(), &db_chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );

    let redirect_chain = [sanitizer(Some("same-origin-path"))];
    assert_eq!(
        compute_status(bundled_metadata(), &redirect_chain, Some("open-redirect")),
        FindingStatus::Sanitized
    );

    let xpath_chain = [sanitizer(Some("xpath-parameter"))];
    assert_eq!(
        compute_status(bundled_metadata(), &xpath_chain, Some("xpath-injection")),
        FindingStatus::Sanitized
    );
}

#[test]
fn local_trust_severity_is_capped_at_medium() {
    assert_eq!(cap_local_trust_severity(Severity::Critical), Severity::Medium);
    assert_eq!(cap_local_trust_severity(Severity::High), Severity::Medium);
    assert_eq!(cap_local_trust_severity(Severity::Medium), Severity::Medium);
    assert_eq!(cap_local_trust_severity(Severity::Low), Severity::Low);
    assert_eq!(cap_local_trust_severity(Severity::Info), Severity::Info);
}

#[test]
fn untagged_only_chain_is_unsanitized() {
    let chain = [sanitizer(None)];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("xss")),
        FindingStatus::Unsanitized
    );
}

#[test]
fn passthrough_plus_real_wrong_context_is_wrong_context() {
    let chain = [
        sanitizer(Some("passthrough-decode")),
        sanitizer(Some("html-encode")),
    ];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("open-redirect")),
        FindingStatus::WrongContext
    );
}

#[test]
fn credit_after_wrong_context_short_circuits_to_sanitized() {
    let chain = [sanitizer(Some("html-encode")), sanitizer(Some("sql-injection"))];
    assert_eq!(
        compute_status(bundled_metadata(), &chain, Some("sql-injection")),
        FindingStatus::Sanitized
    );
}

// ── Distribution-name + ungated-regex validator integration ────────

#[test]
fn validator_reports_package_signal_missing_from_adapter_import_facts() {
    // Compare rule data with compiler import facts instead of guessing
    // package-manager naming conventions in shared analysis.
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
    let mismatches = report
        .issues
        .iter()
        .filter(|i| i.code == "package-signal-not-adapter-visible")
        .collect::<Vec<_>>();
    assert!(
        !mismatches.is_empty(),
        "expected adapter-visible package warning, got {:#?}",
        report.issues
    );
    assert!(
        mismatches.iter().any(|i| i.message.contains("kafka-clients")),
        "warning should name the offending signal, got {:#?}",
        mismatches
    );
    assert!(
        mismatches.iter().all(|i| i.level == "warning"),
        "adapter-visible mismatches must be warnings"
    );
}

#[test]
fn validator_reports_python_package_signal_missing_from_adapter_import_facts() {
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
            .any(|i| i.code == "package-signal-not-adapter-visible"
                && i.message.contains("python-jose")
                && i.level == "warning"),
        "expected adapter-visible package warning, got {:#?}",
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
    let fixture = nested_call_fixture(
        "escapeHtml(\"static\") + Input",
        "Input",
        "escapeHtml",
        Some("escapeHtml"),
    );

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &fixture.ws,
        fixture.func,
        &fixture.src,
        &fixture.san,
        &fixture.snk,
        &fixture.sink_tainted_args,
    ));
}

#[test]
fn sanitizer_on_other_dynamic_value_concatenated_with_taint_does_not_credit() {
    // The sanitizer wraps `other`, while the tainted carrier `Input`
    // remains outside the sanitizer call.
    let fixture = nested_call_fixture(
        "escapeHtml(other) + Input",
        "Input",
        "escapeHtml",
        Some("escapeHtml"),
    );

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &fixture.ws,
        fixture.func,
        &fixture.src,
        &fixture.san,
        &fixture.snk,
        &fixture.sink_tainted_args,
    ));
}

#[test]
fn sanitizer_callee_as_substring_of_longer_identifier_does_not_credit() {
    // M4 regression: the callee appears only as the tail of a longer
    // identifier (`myEscapeHtml`), never as an actual call of `escapeHtml`.
    // RED before fix (substring `contains`); GREEN after (anchored call form).
    let fixture = nested_call_fixture("myEscapeHtml(Input)", "Input", "escapeHtml", Some("myEscapeHtml"));

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &fixture.ws,
        fixture.func,
        &fixture.src,
        &fixture.san,
        &fixture.snk,
        &fixture.sink_tainted_args,
    ));
}

#[test]
fn sanitizer_callee_as_field_name_without_call_does_not_credit() {
    // M4 regression: the callee text appears as a field/identifier with
    // no `(` call form (`config.escapeHtml = Input`). RED before fix
    // (bare substring); GREEN after (call-form anchor required).
    let fixture = nested_call_fixture("config.escapeHtml = Input", "Input", "escapeHtml", None);

    assert!(!sanitizer_is_nested_in_tainted_sink_arg(
        &fixture.ws,
        fixture.func,
        &fixture.src,
        &fixture.san,
        &fixture.snk,
        &fixture.sink_tainted_args,
    ));
}
