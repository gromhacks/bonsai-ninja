//! Per-file package-gated lax-tail matching tests.
//!
//! The matcher's `LaxTail::OnlyWhenPackaged` policy lets a sink rule
//! written as `[Class, lowercase_verb]` lax-match an instance call
//! `<recv>.<verb>(...)` ONLY when the file under analysis imports
//! one of the rule's declared packages. These tests exercise that
//! gate end-to-end against the real `bonsai_workspace::Workspace`,
//! the real adapter import index, and the real matcher — so a
//! regression in any of: rule loading, import-index normalisation,
//! the package-set computation, or the gate predicate, is caught
//! here.

use bonsai_security::{
    match_rules_against_facts,
    rule::{Rule, RuleKind},
};
use std::sync::Arc;

fn ws_with(language: &str, file_name: &str, code: &str) -> bonsai_workspace::Workspace {
    let _ = language;
    ws_with_files(&[(file_name, code)])
}

fn ws_with_files(files: &[(&str, &str)]) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    for (file_name, code) in files {
        ws.vfs().write((*file_name).to_string(), Arc::<str>::from(*code));
    }
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

/// Build a `Rule` from raw YAML. `Rule::kind` is `#[serde(skip)]` —
/// the loader normally fills it from the rule's directory layout, so
/// tests have to set it explicitly to drive the matcher's
/// kind-aware policy choices.
fn rule_from_yaml(yaml: &str, kind: RuleKind) -> Rule {
    let mut rule: Rule = serde_yaml::from_str(yaml).expect("rule yaml parses");
    rule.kind = kind;
    rule
}

/// Sink rule: `[VelocityEngine, evaluate]` with `packages: [org.apache.velocity]`.
/// This is the canonical case from CB2-SSTI-JV-081 — it represents
/// every `[Class, lowercase_verb]` rule in the rulepack.
fn velocity_evaluate_rule() -> Rule {
    rule_from_yaml(
        r#"
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
  - name: example
    code: "void demo() { VelocityEngine.evaluate(input); }"
description: VelocityEngine.evaluate(tainted) — SSTI to RCE.
"#,
        RuleKind::Sink,
    )
}

/// A second rule whose verb is the SAME (`evaluate`) but whose
/// declared package is a DIFFERENT library (`commons-jexl3`). Used
/// to prove the package gate disambiguates which rule fires when
/// multiple rules share a lowercase verb.
fn jexl_evaluate_rule() -> Rule {
    rule_from_yaml(
        r#"
id: java.code.jexl_engine_evaluate
enabled: true
language: java
tag: code-injection
severity: high
packages: [org.apache.commons.jexl3]
imports: [org.apache.commons.jexl3]
cwe: [CWE-94]
match:
  kind: call
  callee:
    attribute: [JexlEngine, evaluate]
match_examples:
  - name: example
    code: "void demo() { JexlEngine.evaluate(input); }"
description: JexlEngine.evaluate(tainted) — JEXL code injection.
"#,
        RuleKind::Sink,
    )
}

fn httpx_async_client_request_rule() -> Rule {
    rule_from_yaml(
        r#"
id: python.ssrf.httpx_async_client_request_test
enabled: true
language: python
tag: ssrf
severity: high
packages: [httpx]
imports: [httpx]
cwe: [CWE-918]
match:
  kind: call
  callee:
    attribute: [AsyncClient, request]
match_examples:
  - name: example
    code: "async def demo(client, url): await client.request('GET', url)"
description: httpx AsyncClient.request.
"#,
        RuleKind::Sink,
    )
}

fn jose_jwt_verify_rule() -> Rule {
    rule_from_yaml(
        r#"
id: elixir.jwt.jose_jwt_verify_test
enabled: true
language: elixir
tag: jwt
severity: high
packages: [JOSE.JWT]
imports: [JOSE.JWT]
cwe: [CWE-347]
match:
  kind: call
  callee:
    attribute: [JOSE, JWT, verify]
match_examples:
  - name: example
    code: "def verify(token), do: JOSE.JWT.verify(token)"
description: JOSE.JWT.verify.
"#,
        RuleKind::Sink,
    )
}

#[test]
fn only_when_packaged_fires_for_instance_form_with_matching_import() {
    // The file imports a class under the rule's declared package
    // root (`org.apache.velocity`) and calls `engine.evaluate(...)`
    // (lowercase instance receiver). The lax-tail gate should fire
    // and the rule should match.
    let code = r#"
import org.apache.velocity.app.VelocityEngine;
class Renderer {
    void render(String input) {
        VelocityEngine engine = new VelocityEngine();
        engine.evaluate(input);
    }
}
"#;
    let ws = ws_with("java", "Renderer.java", code);
    let rule = velocity_evaluate_rule();
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        matches
            .iter()
            .any(|m| m.match_text.ends_with("engine.evaluate") || m.match_text == "engine.evaluate"),
        "expected engine.evaluate to lax-match `[VelocityEngine, evaluate]` when the file \
         imports org.apache.velocity; got matches: {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn only_when_packaged_skips_instance_form_without_matching_import() {
    // Same call shape (`engine.evaluate(...)`) but the file imports
    // a DIFFERENT package (`org.apache.commons.jexl3`, not
    // `org.apache.velocity`). The Velocity rule's lax-tail must
    // not fire — its `OnlyWhenPackaged` gate should hold.
    let code = r#"
import org.apache.commons.jexl3.JexlEngine;
class Renderer {
    void render(String input) {
        JexlEngine engine = new JexlEngine();
        engine.evaluate(input);
    }
}
"#;
    let ws = ws_with("java", "Renderer.java", code);
    let rule = velocity_evaluate_rule();
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        !matches.iter().any(|m| m.match_text.ends_with("engine.evaluate")),
        "Velocity rule must NOT lax-match `engine.evaluate` in a file that imports \
         org.apache.commons.jexl3 instead of org.apache.velocity; got matches: {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn only_when_packaged_disambiguates_two_rules_with_same_verb() {
    // Two rules with the same lowercase verb (`evaluate`) but
    // different `packages:`. Each fires only in the file that
    // imports its package — never both for the same call.
    let velocity_rule = velocity_evaluate_rule();
    let jexl_rule = jexl_evaluate_rule();

    let velocity_code = r#"
import org.apache.velocity.app.VelocityEngine;
class A {
    void demo(String input) {
        VelocityEngine engine = new VelocityEngine();
        engine.evaluate(input);
    }
}
"#;
    let jexl_code = r#"
import org.apache.commons.jexl3.JexlEngine;
class B {
    void demo(String input) {
        JexlEngine engine = new JexlEngine();
        engine.evaluate(input);
    }
}
"#;

    let velocity_ws = ws_with("java", "A.java", velocity_code);
    let jexl_ws = ws_with("java", "B.java", jexl_code);

    let velocity_hits = match_rules_against_facts(&velocity_ws, &[&velocity_rule, &jexl_rule]);
    let jexl_hits = match_rules_against_facts(&jexl_ws, &[&velocity_rule, &jexl_rule]);

    let velocity_ids: Vec<&str> = velocity_hits.iter().map(|m| m.rule_id.as_str()).collect();
    let jexl_ids: Vec<&str> = jexl_hits.iter().map(|m| m.rule_id.as_str()).collect();

    // In the Velocity-importing file, only the Velocity rule
    // lax-matches `engine.evaluate`; the JEXL rule must NOT fire
    // (this is the core anti-collision invariant).
    assert!(
        velocity_ids.contains(&"java.template.velocity_engine_evaluate"),
        "Velocity rule should fire in velocity-importing file; got {:?}",
        velocity_ids
    );
    assert!(
        !velocity_ids.contains(&"java.code.jexl_engine_evaluate"),
        "JEXL rule must NOT fire in velocity-importing file; got {:?}",
        velocity_ids
    );

    // Symmetric for the JEXL-importing file.
    assert!(
        jexl_ids.contains(&"java.code.jexl_engine_evaluate"),
        "JEXL rule should fire in jexl-importing file; got {:?}",
        jexl_ids
    );
    assert!(
        !jexl_ids.contains(&"java.template.velocity_engine_evaluate"),
        "Velocity rule must NOT fire in jexl-importing file; got {:?}",
        jexl_ids
    );
}

#[test]
fn only_when_packaged_skips_module_receiver_but_keeps_instance_receiver() {
    // The file imports `httpx`, so `[AsyncClient, request]` may lax-
    // match true instance calls such as `client.request(...)`. It
    // must not also claim the module-form `httpx.request(...)`,
    // which belongs to the stricter `[httpx, request]` rule.
    let rule = httpx_async_client_request_rule();
    let ws = ws_with_files(&[
        (
            "client_form.py",
            r#"
import httpx

async def fetch(client, url):
    return await client.request("GET", url)
"#,
        ),
        (
            "module_form.py",
            r#"
import httpx

async def fetch(url):
    return await httpx.request("GET", url)
"#,
        ),
    ]);

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        matches
            .iter()
            .any(|m| m.file.ends_with("client_form.py") && m.match_text.ends_with("client.request")),
        "expected imported instance form to match; got {:?}",
        matches
            .iter()
            .map(|m| (m.file.clone(), m.match_text.clone()))
            .collect::<Vec<_>>()
    );
    assert!(
        !matches
            .iter()
            .any(|m| m.file.ends_with("module_form.py") && m.match_text.ends_with("httpx.request")),
        "module receiver must not be claimed by OnlyWhenPackaged lax-tail; got {:?}",
        matches
            .iter()
            .map(|m| (m.file.clone(), m.match_text.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn only_when_packaged_skips_colon_prefixed_remote_calls() {
    // Elixir atom-module remote calls carry their module identity in
    // the colon-prefixed receiver. The lax-tail branch must not
    // convert `:jose_jwt.verify(...)` into a `[JOSE, JWT, verify]`
    // instance match just because the file also imports JOSE.JWT.
    let rule = jose_jwt_verify_rule();
    let ws = ws_with(
        "elixir",
        "jwt_demo.ex",
        r#"
defmodule JwtDemo do
  alias JOSE.JWT

  def verify(token) do
    :jose_jwt.verify(token)
  end
end
"#,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        matches.is_empty(),
        "colon-prefixed remote calls must not be lax-tail matches; got {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn only_when_packaged_skips_short_verbs() {
    // `[Session, get]` — `get` is 3 chars, below the >= 5 floor.
    // Even with a matching import, lax-tail must not fire on a
    // generic short verb. Otherwise `req.args.get(...)` would
    // spuriously match the SSRF Session.get rule, which is what
    // broke the assignment-chain audit on the first attempt.
    let rule = rule_from_yaml(
        r#"
id: python.ssrf.requests_session_get_test
enabled: true
language: python
tag: ssrf
severity: high
packages: [requests]
imports: [requests]
cwe: [CWE-918]
match:
  kind: call
  callee:
    attribute: [Session, get]
match_examples:
  - name: example
    code: "def demo(): Session.get(input)"
description: requests.Session().get.
"#,
        RuleKind::Sink,
    );
    let code = r#"
import requests
def handler(req):
    value = req.args.get("c1")
    return value
"#;
    let ws = ws_with("python", "app.py", code);
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        !matches.iter().any(|m| m.match_text.contains("args.get")),
        "Short verb `get` must never lax-match even with package import; \
         got {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn only_when_packaged_skips_generic_lowercase_verbs() {
    // `read` is 4 chars — below the floor — so even with a
    // matching import the lax-tail must not fire on `f.read(...)`
    // for a `[Class, read]` rule.
    let rule = rule_from_yaml(
        r#"
id: python.deser.foo_read_test
enabled: true
language: python
tag: deserialization
severity: high
packages: [foopkg]
imports: [foopkg]
cwe: [CWE-502]
match:
  kind: call
  callee:
    attribute: [FooReader, read]
match_examples:
  - name: example
    code: "def demo(): FooReader.read(input)"
description: FooReader.read(tainted).
"#,
        RuleKind::Sink,
    );
    let code = r#"
import foopkg
def handler(f):
    return f.read()
"#;
    let ws = ws_with("python", "app.py", code);
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        matches.is_empty(),
        "4-char verb `read` must not lax-match; got {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn camelcase_verb_still_lax_matches_without_packages() {
    // The Always policy (camelCase verb) must keep working
    // independently of `packages:` — that's the pre-existing
    // behaviour and the new package gate must not regress it.
    let rule = rule_from_yaml(
        r#"
id: java.sqli.statement_execute_query_test
enabled: true
language: java
tag: sql-injection
severity: high
cwe: [CWE-89]
match:
  kind: call
  callee:
    attribute: [Statement, executeQuery]
match_examples:
  - name: example
    code: "void demo() { Statement.executeQuery(sql); }"
description: Statement.executeQuery(tainted).
"#,
        RuleKind::Sink,
    );
    let code = r#"
class Demo {
    void run(java.sql.Statement stmt, String sql) {
        stmt.executeQuery(sql);
    }
}
"#;
    let ws = ws_with("java", "Demo.java", code);
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        matches.iter().any(|m| m.match_text.ends_with("executeQuery")),
        "camelCase verb must lax-match without needing a package gate; got {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn sanitizers_lax_match_unconditionally() {
    // Sanitizers are LaxTail::Always regardless of packages or
    // verb shape. False negatives on sanitizers turn into false
    // positives on findings, so the policy is intentionally
    // permissive.
    let rule = rule_from_yaml(
        r#"
id: python.sanitizer.escape_test
enabled: true
language: python
tag: sanitizer
match:
  kind: call
  callee:
    attribute: [HtmlEscaper, escape]
description: HTML escape.
"#,
        RuleKind::Sanitizer,
    );
    let code = r#"
def safe(x):
    return safe_helper.escape(x)
"#;
    let ws = ws_with("python", "app.py", code);
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        matches.iter().any(|m| m.match_text.ends_with("escape")),
        "Sanitizer rules must lax-match by tail unconditionally; got {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn off_policy_holds_for_lowercase_first_attribute() {
    // The `[lowercase_pkg, verb]` shape (e.g. `[os, system]`) has
    // a non-type-like first attribute, so `rule_lax_tail` returns
    // `Off`. Even with a matching import, the rule must NOT
    // lax-match an unrelated `c.system(...)` call. This protects
    // against the original concern about Go's `http.PostForm`
    // shape from `c.PostForm`.
    let rule = rule_from_yaml(
        r#"
id: python.cmdi.os_system_test
enabled: true
language: python
tag: command-injection
severity: high
packages: [os]
imports: [os]
cwe: [CWE-78]
match:
  kind: call
  callee:
    attribute: [os, system]
match_examples:
  - name: example
    code: "def demo(): os.system(cmd)"
description: os.system(tainted).
"#,
        RuleKind::Sink,
    );
    let code = r#"
import os
def handler(c, cmd):
    return c.system(cmd)
"#;
    let ws = ws_with("python", "app.py", code);
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        !matches.iter().any(|m| m.match_text == "c.system"),
        "lowercase-first-attr rule must stay strict — `c.system` must NOT lax-match \
         `[os, system]`; got {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn no_imports_means_no_only_when_packaged_match() {
    // The conformance test guardrail: in synthetic example
    // workspaces with no imports, OnlyWhenPackaged rules must
    // stay silent. This is what prevents the cross-library
    // collision the first attempt at Fix #2 broke.
    let rule = velocity_evaluate_rule();
    let code = r#"
class Stub {
    void demo(String input) {
        engine.evaluate(input);
    }
}
"#;
    let ws = ws_with("java", "Stub.java", code);
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        !matches.iter().any(|m| m.match_text.contains("engine.evaluate")),
        "OnlyWhenPackaged must stay off without an import; got {:?}",
        matches.iter().map(|m| m.match_text.clone()).collect::<Vec<_>>()
    );
}
