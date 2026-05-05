//! Engine primitive integration tests for the four primitives that
//! landed alongside the audit-pair rule pack:
//!
//! - **P4 — `MatchKind::Missing` walker**. A rule with `kind: missing`
//!   fires on a function that does *not* contain a call to the rule's
//!   declared `match.callee` target. Used by audit-pair lifecycle
//!   rules (handler missing CSRF check, missing rate-limit, missing
//!   output escape).
//!
//! - **P1 — `RequiresRuntimeType`**. A rule with
//!   `requires_runtime_type` fires only when the named arg has been
//!   provably narrowed by a preceding `instanceof X` /
//!   `isinstance(_, X)` / `_ is X` / `typeof _ === "X"` predicate.
//!
//! - **P5 — `MustAlias`**. A rule with `must_alias` fires only when
//!   two args at the same call site share a must-alias root through
//!   the per-decl assignment chain (`let y = x;` → `must_alias(x, y)`).
//!
//! - **P6 — `RequiresState`**. A rule with `requires_state` fires only
//!   when the named binding is in the expected lifecycle state at
//!   the call site. Adapters do not yet emit
//!   `FlowEvent::ResourceTransition` events, so `requires_state`
//!   today fails closed for any expected state — these tests pin
//!   that conservative behaviour so a future adapter rollout can
//!   tighten the expectation incrementally.

use bonsai_lang_api::LanguageRegistry;
use bonsai_security::{load_rulepack, match_rule_against_facts, run_taint_analysis, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn python_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

// ---------------------------------------------------------------- P4

/// `kind: missing` fires on a Flask-style handler that does not call
/// the rule's expected CSRF-check target.
#[test]
fn missing_walker_fires_when_target_absent_from_decl() {
    let tmp = TempDir::new("p4_absent");
    write(
        &tmp.path().join("langs/python/sinks/csrf_missing.yml"),
        r#"- id: python.test.missing_csrf
  enabled: true
  language: python
  tag: csrf
  severity: high
  cwe: [CWE-352]
  match:
    kind: missing
    callee:
      attribute: [csrf, validate]
  description: "test rule"
  match_examples:
  - name: positive missing csrf
    code: |
      def handler(user_input):
          return user_input
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("python.test.missing_csrf").expect("rule");

    let ws = python_ws(
        r#"
def handler(user_input):
    return user_input
"#,
    );
    let matches = match_rule_against_facts(&ws, rule);
    assert!(
        !matches.is_empty(),
        "Missing rule should fire on handler that omits csrf.validate; got {:?}",
        matches
    );
}

/// `kind: missing` does *not* fire when the expected target is
/// present anywhere in the decl body.
#[test]
fn missing_walker_silent_when_target_present() {
    let tmp = TempDir::new("p4_present");
    write(
        &tmp.path().join("langs/python/sinks/csrf_missing.yml"),
        r#"- id: python.test.missing_csrf_present
  enabled: true
  language: python
  tag: csrf
  severity: high
  cwe: [CWE-352]
  match:
    kind: missing
    callee:
      attribute: [csrf, validate]
  description: "test rule"
  match_examples:
  - name: positive missing csrf
    code: |
      def handler(user_input):
          return user_input
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.missing_csrf_present")
        .expect("rule");

    let ws = python_ws(
        r#"
def handler(user_input):
    csrf.validate(user_input)
    return user_input
"#,
    );
    let matches = match_rule_against_facts(&ws, rule);
    assert!(
        matches.is_empty(),
        "Missing rule should NOT fire when target is present; got {:?}",
        matches
    );
}

/// `kind: missing` with `enclosing_decorator_in:` only fires on
/// handler-shaped decls (those carrying a route decorator).
#[test]
fn missing_walker_decorator_scope_filters_helpers() {
    let tmp = TempDir::new("p4_decorator");
    write(
        &tmp.path().join("langs/python/sinks/csrf_missing_decor.yml"),
        r#"- id: python.test.missing_csrf_route
  enabled: true
  language: python
  tag: csrf
  severity: high
  cwe: [CWE-352]
  match:
    kind: missing
    callee:
      attribute: [csrf, validate]
  constraints:
  - enclosing_decorator_in: [route, post, get]
  description: "test rule"
  match_examples:
  - name: positive missing csrf on route
    code: |
      from flask import app
      @app.route("/x")
      def handler(user_input):
          return user_input
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.missing_csrf_route")
        .expect("rule");

    let scoped = python_ws(
        r#"
from flask import app
@app.route("/x")
def handler(user_input):
    return user_input
"#,
    );
    let matches = match_rule_against_facts(&scoped, rule);
    assert!(
        !matches.is_empty(),
        "Missing rule with decorator scope should fire on route handler; got {:?}",
        matches
    );

    let unscoped = python_ws(
        r#"
def helper(x):
    return x
"#,
    );
    let matches = match_rule_against_facts(&unscoped, rule);
    assert!(
        matches.is_empty(),
        "Missing rule with decorator scope should NOT fire on plain helper; got {:?}",
        matches
    );
}

// ---------------------------------------------------------------- P1

/// `requires_runtime_type` fails closed when the engine has no
/// narrowing record for the named arg — even if the type is
/// declared at parameter level. This pins the conservative behaviour
/// (we never speculate) so future engine work can tighten without
/// turning existing rules into false positives.
#[test]
fn requires_runtime_type_fails_closed_without_narrowing() {
    let tmp = TempDir::new("p1_no_narrow");
    write(
        &tmp.path().join("langs/python/sinks/runtime_type.yml"),
        r#"- id: python.test.runtime_type_required
  enabled: true
  language: python
  tag: typed-sink
  severity: medium
  cwe: [CWE-704]
  match:
    kind: call
    callee:
      name: trust
  constraints:
  - requires_runtime_type:
      index: 0
      type: TrustedShape
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def handler(payload):
          if isinstance(payload, TrustedShape):
              trust(payload)
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.runtime_type_required")
        .expect("rule");

    // Without isinstance, the runtime_type lattice has nothing for
    // `payload`. The constraint must fail closed.
    let no_narrowing = python_ws(
        r#"
def handler(payload):
    trust(payload)
"#,
    );
    let report = run_taint_analysis(
        &no_narrowing,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report.findings.iter().all(|f| f.finding.sink.rule_id != rule.id),
        "requires_runtime_type without a narrowing must NOT fire; got {:?}",
        report.findings
    );
}

/// `requires_runtime_type` fires when a preceding
/// `isinstance(payload, T)` predicate narrows the arg's name to the
/// expected type.
#[test]
fn requires_runtime_type_fires_after_isinstance() {
    let tmp = TempDir::new("p1_narrow");
    write(
        &tmp.path().join("langs/python/sinks/runtime_type.yml"),
        r#"- id: python.test.runtime_type_narrowed
  enabled: true
  language: python
  tag: typed-sink
  severity: medium
  cwe: [CWE-704]
  match:
    kind: call
    callee:
      name: dispatch
  constraints:
  - requires_runtime_type:
      index: 0
      type: TrustedShape
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def handler(payload):
          if isinstance(payload, TrustedShape):
              dispatch(payload)
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.runtime_type_narrowed")
        .expect("rule");

    let narrowed = python_ws(
        r#"
def handler(payload):
    if isinstance(payload, TrustedShape):
        dispatch(payload)
"#,
    );
    let matches = match_rule_against_facts(&narrowed, rule);
    assert!(
        !matches.is_empty(),
        "requires_runtime_type should fire after isinstance narrowing; got {:?}",
        matches
    );
}

// ---------------------------------------------------------------- P5

/// `must_alias` requires the two named args to share an assignment
/// chain root within the same decl. Same-name on both sides is the
/// trivial must-alias.
#[test]
fn must_alias_trivial_same_name() {
    let tmp = TempDir::new("p5_same");
    write(
        &tmp.path().join("langs/python/sinks/must_alias.yml"),
        r#"- id: python.test.must_alias_same
  enabled: true
  language: python
  tag: lifecycle
  severity: medium
  cwe: [CWE-672]
  match:
    kind: call
    callee:
      name: pair
  constraints:
  - must_alias:
      source_arg: 0
      sink_arg: 1
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def handler(fd):
          pair(fd, fd)
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("python.test.must_alias_same").expect("rule");

    let same = python_ws(
        r#"
def handler(fd):
    pair(fd, fd)
"#,
    );
    let matches = match_rule_against_facts(&same, rule);
    assert!(
        !matches.is_empty(),
        "must_alias should fire when both args share a name; got {:?}",
        matches
    );

    let different = python_ws(
        r#"
def handler(fd1, fd2):
    pair(fd1, fd2)
"#,
    );
    let matches = match_rule_against_facts(&different, rule);
    assert!(
        matches.is_empty(),
        "must_alias should NOT fire on distinct names; got {:?}",
        matches
    );
}

/// `must_alias` follows simple rename chains (`y = x; pair(x, y)`).
#[test]
fn must_alias_through_assignment_chain() {
    let tmp = TempDir::new("p5_chain");
    write(
        &tmp.path().join("langs/python/sinks/must_alias.yml"),
        r#"- id: python.test.must_alias_chain
  enabled: true
  language: python
  tag: lifecycle
  severity: medium
  cwe: [CWE-672]
  match:
    kind: call
    callee:
      name: pair
  constraints:
  - must_alias:
      source_arg: 0
      sink_arg: 1
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def handler(fd):
          alias = fd
          pair(fd, alias)
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.must_alias_chain")
        .expect("rule");

    let aliased = python_ws(
        r#"
def handler(fd):
    alias = fd
    pair(fd, alias)
"#,
    );
    let matches = match_rule_against_facts(&aliased, rule);
    assert!(
        !matches.is_empty(),
        "must_alias should follow simple rename chains; got {:?}",
        matches
    );
}

/// `must_alias` does NOT promote a call-RHS into an alias. `y = f(x)`
/// is not aliasing because `f` may return any value.
#[test]
fn must_alias_does_not_follow_call_rhs() {
    let tmp = TempDir::new("p5_call_rhs");
    write(
        &tmp.path().join("langs/python/sinks/must_alias.yml"),
        r#"- id: python.test.must_alias_call
  enabled: true
  language: python
  tag: lifecycle
  severity: medium
  cwe: [CWE-672]
  match:
    kind: call
    callee:
      name: pair
  constraints:
  - must_alias:
      source_arg: 0
      sink_arg: 1
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def handler(fd):
          alias = fd
          pair(fd, alias)
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("python.test.must_alias_call").expect("rule");

    let unrelated_call = python_ws(
        r#"
def handler(fd):
    alias = transform(fd)
    pair(fd, alias)
"#,
    );
    let matches = match_rule_against_facts(&unrelated_call, rule);
    assert!(
        matches.is_empty(),
        "must_alias should NOT promote a call-RHS into an alias; got {:?}",
        matches
    );
}

// ---------------------------------------------------------------- P6

/// `requires_state` fails closed today because adapters do not emit
/// `FlowEvent::ResourceTransition` events. This pins the conservative
/// behaviour: rules declaring `requires_state` are dormant until the
/// adapter wires the relevant transition events. When that happens
/// the matcher will start firing automatically without any rule
/// rewrite.
#[test]
fn requires_state_fails_closed_until_adapter_emits_transitions() {
    let tmp = TempDir::new("p6_dormant");
    write(
        &tmp.path().join("langs/python/sinks/state.yml"),
        r#"- id: python.test.requires_state_dormant
  enabled: true
  language: python
  tag: lifecycle
  severity: medium
  cwe: [CWE-672]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: fd
      expected: open
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def handler():
          fd = open("p")
          read(fd)
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.requires_state_dormant")
        .expect("rule");

    let ws = python_ws(
        r#"
def handler():
    fd = open("p")
    read(fd)
"#,
    );
    let matches = match_rule_against_facts(&ws, rule);
    assert!(
        matches.is_empty(),
        "requires_state must fail closed until adapters emit transitions; got {:?}",
        matches
    );
}

// ---------------------------------------------------------------- helpers

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bonsai-engine-primitive-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
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
