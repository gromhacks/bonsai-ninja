use bonsai_security::{
    match_rules_against_facts,
    rule::{Rule, RuleKind},
};
use std::sync::Arc;

fn ws_with(file_name: &str, code: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(file_name.to_string(), Arc::<str>::from(code));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn rule_from_yaml(yaml: &str, kind: RuleKind) -> Rule {
    let mut rule: Rule = serde_yaml::from_str(yaml).expect("rule yaml parses");
    rule.kind = kind;
    rule
}

fn velocity_evaluate_rule() -> Rule {
    rule_from_yaml(
        r#"
id: java.template.velocity_engine_evaluate
enabled: true
language: java
tag: ssti
severity: high
cwe: [CWE-1336]
match:
  kind: call
  callee:
    attribute: [VelocityEngine, evaluate]
description: VelocityEngine.evaluate(tainted) — SSTI to RCE.
"#,
        RuleKind::Sink,
    )
}

#[test]
fn type_attribute_rule_does_not_tail_match_untyped_receiver() {
    let ws = ws_with(
        "Demo.java",
        r#"
import org.apache.velocity.app.VelocityEngine;

class Demo {
  void demo(String input) {
    Object engine = new Object();
    engine.evaluate(input);
  }
}
"#,
    );
    let rule = velocity_evaluate_rule();

    let hits = match_rules_against_facts(&ws, &[&rule]);

    assert!(
        hits.is_empty(),
        "attribute rules must not match local receiver method names without semantic receiver types: {hits:?}"
    );
}

#[test]
fn type_attribute_rule_matches_semantic_receiver_type() {
    let ws = ws_with(
        "Demo.java",
        r#"
import org.apache.velocity.app.VelocityEngine;

class Demo {
  void demo(String input) {
    VelocityEngine engine = new VelocityEngine();
    engine.evaluate(input);
  }
}
"#,
    );
    let rule = velocity_evaluate_rule();

    let hits = match_rules_against_facts(&ws, &[&rule]);

    assert!(
        hits.iter()
            .any(|hit| hit.rule_id == rule.id && hit.match_text == "engine.evaluate"),
        "semantic receiver type should make engine.evaluate match [VelocityEngine, evaluate], got {hits:?}"
    );
}

#[test]
fn sanitizer_attribute_rule_requires_exact_or_semantic_receiver() {
    let ws = ws_with(
        "app.py",
        r#"
def render(safe_helper, value):
    return safe_helper.escape(value)
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: python.sanitizer.html_escaper_escape
enabled: true
language: python
tag: xss
severity: low
match:
  kind: call
  callee:
    attribute: [HtmlEscaper, escape]
description: HtmlEscaper.escape sanitizer.
"#,
        RuleKind::Sanitizer,
    );

    let hits = match_rules_against_facts(&ws, &[&rule]);

    assert!(
        hits.is_empty(),
        "sanitizers must not tail-match arbitrary receiver methods without semantic receiver facts: {hits:?}"
    );
}

#[test]
fn module_attribute_rule_matches_exact_module_receiver() {
    let ws = ws_with(
        "app.py",
        r#"
import os

def run(cmd):
    return os.system(cmd)
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: python.cmdi.os_system
enabled: true
language: python
tag: command-injection
severity: critical
cwe: [CWE-78]
match:
  kind: call
  callee:
    attribute: [os, system]
description: os.system command execution.
"#,
        RuleKind::Sink,
    );

    let hits = match_rules_against_facts(&ws, &[&rule]);

    assert!(
        hits.iter()
            .any(|hit| hit.rule_id == rule.id && hit.match_text == "os.system"),
        "exact module-qualified calls should still match strict attribute rules, got {hits:?}"
    );
}

#[test]
fn self_receiver_prefix_is_not_stripped_for_regex_matching() {
    let ws = ws_with(
        "app.py",
        r#"
import tornado

def read_header(name):
    return self.request.headers.get(name)
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: python.web.request_headers_get
enabled: true
language: python
trust: remote
tag: http-input
packages: [tornado]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.headers\\.get$"
description: Generic direct request.headers.get source.
"#,
        RuleKind::Source,
    );

    let hits = match_rules_against_facts(&ws, &[&rule]);

    assert!(
        hits.is_empty(),
        "generic direct request.headers.get regex must not match nested self.request.headers.get: {hits:?}"
    );
}
