use bonsai_security::{load_rulepack, validate_pack, PackInventoryOptions};
use std::path::{Path, PathBuf};

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn validate(root: &Path) -> bonsai_security::PackValidationReport {
    let pack = load_rulepack(root).expect("rulepack loads");
    validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    )
}

#[test]
fn predicate_result_domain_requires_a_terminal_rejection_proof() {
    let tmp = TempDir::new("predicate-result-domain");
    write(
        &tmp.path().join("langs/lua/sanitizers/predicate.yml"),
        r#"- id: lua.test.predicate_domain
  enabled: true
  language: lua
  tag: validation
  match:
    kind: call
    callee: { name: validate }
  analysis_semantics:
    sanitizer_guard:
      all_arguments: true
      predicate_falsey_result_is_null: true
  match_examples:
  - code: 'local function run(value) return validate(value) end'
  description: An invalid predicate model without a terminal rejection proof.
"#,
    );
    let report = validate(tmp.path());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "invalid-analysis-semantics"
                && issue.message.contains("predicate_falsey_result_is_null")),
        "{:#?}",
        report.issues
    );
}

#[test]
fn expect_no_match_reports_unexpected_owner_match() {
    let tmp = TempDir::new("negative-unexpected");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [os, system]
  match_examples:
  - name: positive
    code: |
      import os
      def example(user_input):
          return os.system(user_input)
  - name: negative
    code: |
      import os
      def example(user_input):
          return os.system(user_input)
    expect_no_match: true
  description: os.system test rule with a deliberately failing negative.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "match-example-unexpected-match"),
        "{:#?}",
        report.issues
    );
}

#[test]
fn expect_no_match_passes_when_owner_rule_does_not_match() {
    let tmp = TempDir::new("negative-ok");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [os, system]
  match_examples:
  - name: positive
    code: |
      import os
      def example(user_input):
          return os.system(user_input)
  - name: negative
    code: |
      def example(user_input):
          return print(user_input)
    expect_no_match: true
  description: os.system test rule with a passing negative.
"#,
    );

    let report = validate(tmp.path());
    assert_eq!(report.errors, 0, "{:#?}", report.issues);
}

#[test]
fn clean_receiver_overwrite_rejects_non_call_matches() {
    let tmp = TempDir::new("clean-receiver-non-call");
    write(
        &tmp.path().join("langs/perl/sanitizers/all.yml"),
        r#"- id: perl.sanitizer.invalid_receiver_overwrite
  enabled: true
  language: perl
  tag: char-allowlist
  match:
    kind: read
    target:
      name: value
  taint_semantics:
    clean_receiver_overwrite: true
  description: Invalid non-call receiver overwrite fixture.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        report.issues.iter().any(|issue| {
            issue.code == "invalid-taint-semantics" && issue.message.contains("requires match.kind `call`")
        }),
        "{:#?}",
        report.issues
    );
}

#[test]
fn clean_receiver_overwrite_rejects_missing_callee() {
    let tmp = TempDir::new("clean-receiver-no-callee");
    write(
        &tmp.path().join("langs/perl/sanitizers/all.yml"),
        r#"- id: perl.sanitizer.invalid_receiver_overwrite
  enabled: true
  language: perl
  tag: char-allowlist
  match:
    kind: call
  taint_semantics:
    clean_receiver_overwrite: true
  description: Invalid callee-free receiver overwrite fixture.
"#,
    );

    let error = load_rulepack(tmp.path()).expect_err("callee-free call rule must fail to load");
    assert!(format!("{error:?}").contains("MissingCallee"), "{error:#?}");
}

#[test]
fn return_typing_rejects_regex_only_callable_identity() {
    let tmp = TempDir::new("regex-return-typing");
    write(
        &tmp.path().join("langs/python/typing/factories.yml"),
        r#"- id: python.typing.ambiguous_factory
  enabled: true
  language: python
  returns_type: ExternalValue
  match:
    kind: call
    callee:
      regex: '^(provider_a|provider_b)\\.create$'
  match_examples:
  - name: provider factory
    code: |
      import provider_a
      value = provider_a.create()
    expect_match_text: [provider_a.create]
  description: A regex-only provider identity cannot define an exact compiler return type.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "non-exact-return-typing-target"),
        "{:#?}",
        report.issues
    );
}

#[test]
fn configured_factory_guard_accepts_an_aggregate_only_proof() {
    let tmp = TempDir::new("configured-factory-aggregate-only");
    write(
        &tmp.path().join("langs/javascript/sinks/configured.yml"),
        r#"- id: javascript.test.configured_consumer
  enabled: true
  language: javascript
  tag: configured-consumer
  severity: high
  cwe: [CWE-20]
  match:
    kind: call
    callee:
      attribute: [Consumer, use]
  analysis_semantics:
    configured_argument_factory_guard:
      sink_argument_index: 0
      factory:
        attribute: [Factory, build]
      required_aggregate_argument:
        argument_index: 1
        required_fields:
        - path: [guard]
          value: {kind: boolean, value: false}
  match_examples:
  - name: configured consumer
    code: |
      function run(value) { return Consumer.use(value); }
  description: Aggregate-only configured factory validation fixture.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        !report.issues.iter().any(|issue| {
            issue.rule_id.as_deref() == Some("javascript.test.configured_consumer")
                && issue.code == "invalid-analysis-semantics"
        }),
        "{:#?}",
        report.issues
    );
}

#[test]
fn configured_factory_guard_rejects_missing_or_duplicate_configuration_proofs() {
    let tmp = TempDir::new("configured-factory-invalid-proof");
    write(
        &tmp.path().join("langs/javascript/sinks/configured.yml"),
        r#"- id: javascript.test.missing_configuration
  enabled: true
  language: javascript
  tag: configured-consumer
  severity: high
  cwe: [CWE-20]
  match:
    kind: call
    callee:
      attribute: [Consumer, use]
  analysis_semantics:
    configured_argument_factory_guard:
      sink_argument_index: 0
      factory:
        attribute: [Factory, build]
  match_examples:
  - name: consumer
    code: |
      function run(value) { return Consumer.use(value); }
  description: Missing configured factory proof validation fixture.
- id: javascript.test.duplicate_aggregate_field
  enabled: true
  language: javascript
  tag: configured-consumer
  severity: high
  cwe: [CWE-20]
  match:
    kind: call
    callee:
      attribute: [Consumer, send]
  analysis_semantics:
    configured_argument_factory_guard:
      sink_argument_index: 0
      factory:
        attribute: [Factory, build]
      required_aggregate_argument:
        argument_index: 1
        required_fields:
        - path: [guard]
          value: {kind: boolean, value: false}
        - path: [guard]
          value: {kind: boolean, value: true}
  match_examples:
  - name: consumer
    code: |
      function run(value) { return Consumer.send(value); }
  description: Duplicate configured factory aggregate path validation fixture.
"#,
    );

    let report = validate(tmp.path());
    let invalid_ids: std::collections::BTreeSet<_> = report
        .issues
        .iter()
        .filter(|issue| issue.code == "invalid-analysis-semantics")
        .filter_map(|issue| issue.rule_id.as_deref())
        .collect();
    assert!(
        invalid_ids.contains("javascript.test.missing_configuration"),
        "{:#?}",
        report.issues
    );
    assert!(
        invalid_ids.contains("javascript.test.duplicate_aggregate_field"),
        "{:#?}",
        report.issues
    );
}

#[test]
fn character_escape_rejects_invalid_provider_targets() {
    let tmp = TempDir::new("character-escape-invalid-provider");
    write(
        &tmp.path().join("langs/javascript/sinks/xss.yml"),
        r#"- id: javascript.test.invalid_escape_provider
  enabled: true
  language: javascript
  tag: xss
  severity: high
  cwe: [CWE-79]
  match:
    kind: call
    callee:
      name: render
  constraints:
  - arg_tainted: {index: 0}
  analysis_semantics:
    character_escape:
      value_arg_indices: [0]
      required_mappings:
      - {input: "<", output: "&lt;"}
      accepted_providers:
      - operation: {}
        factory:
          regex: "["
  match_examples:
  - name: render dynamic value
    code: |
      function example(value) { return render(value); }
    expect_match_text: [render]
  description: Invalid provider targets must fail pack validation.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        report.issues.iter().any(|issue| {
            issue.rule_id.as_deref() == Some("javascript.test.invalid_escape_provider")
                && issue.code == "invalid-analysis-semantics"
                && issue.message.contains("character_escape.accepted_providers")
        }),
        "{:#?}",
        report.issues
    );
}

#[test]
fn containment_guard_rejects_overlapping_candidate_and_base_argument_roles() {
    let tmp = TempDir::new("containment-overlapping-roles");
    write(
        &tmp.path().join("langs/dart/sinks/path.yml"),
        r#"- id: dart.test.overlapping_containment_roles
  enabled: true
  language: dart
  tag: path-traversal
  severity: high
  cwe: [CWE-22]
  match:
    kind: call
    callee:
      name: consume
  analysis_semantics:
    guard_profile: path-consumer-containment
    path_consumer_containment_guard:
      canonicalizer: {attribute: [paths, canonical]}
      path_constructor: {attribute: [paths, combine]}
      containment_check: {attribute: [paths, within]}
      containment_check_candidate_arg_index: 0
      containment_check_base_arg_index: 0
      sink_path_arg_index: 0
      path_constructor_base_arg_index: 0
      containment_check_is_segment_aware: true
      boundary_places: []
  match_examples:
  - name: consumer
    code: |
      void run(String value) { consume(value); }
  description: Overlapping containment-role validation fixture.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        report.issues.iter().any(|issue| {
            issue.rule_id.as_deref() == Some("dart.test.overlapping_containment_roles")
                && issue.code == "invalid-analysis-semantics"
        }),
        "{:#?}",
        report.issues
    );
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for attempt in 0..100 {
            let path = base.join(format!(
                "bonsai-validate-{tag}-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            if std::fs::create_dir(&path).is_ok() {
                return Self { path };
            }
        }
        panic!("create temp dir");
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
