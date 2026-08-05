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

#[test]
fn arg_tainted_index_requires_taint_view_and_filters_literals() {
    let tmp = TempDir::new("index");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.os_system_arg_tainted
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [os, system]
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: positive
    code: |
      import os
      def handler(user_input):
          return os.system(user_input)
  - name: negative
    code: |
      import os
      def handler(user_input):
          return os.system("safe")
    expect_no_match: true
  description: os.system only fires when the command argument is tainted.
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.os_system_arg_tainted")
        .expect("rule");

    let tainted = python_ws(
        r#"
import os
def handler(user_input):
    return os.system(user_input)
"#,
    );
    assert!(
        match_rule_against_facts(&tainted, rule).is_empty(),
        "pre-taint matcher must not fire arg_tainted rules"
    );
    let report = run_taint_analysis(
        &tainted,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == rule.id),
        "{:#?}",
        report.findings
    );

    let literal = python_ws(
        r#"
import os
def handler(user_input):
    return os.system("safe")
"#,
    );
    let report = run_taint_analysis(
        &literal,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(report.findings.is_empty(), "{:#?}", report.findings);

    let absent = python_ws(
        r#"
import os
def handler(user_input):
    return os.system()
"#,
    );
    let report = run_taint_analysis(
        &absent,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

#[test]
fn dual_role_call_result_cannot_taint_its_own_input() {
    let tmp = TempDir::new("dual-role-call");
    write(
        &tmp.path().join("langs/python/sources/dual.yml"),
        r#"- id: python.test.dual_role_source
  enabled: true
  language: python
  trust: local
  tag: local-input
  match:
    kind: call
    callee:
      attribute: [io, read]
  match_examples:
  - name: source shape
    code: |
      import io
      def handler():
          return io.read("safe.txt")
  description: The call result is input data.
"#,
    );
    write(
        &tmp.path().join("langs/python/sinks/dual.yml"),
        r#"- id: python.test.dual_role_sink
  enabled: true
  language: python
  tag: path-traversal
  severity: high
  cwe: [CWE-22]
  match:
    kind: call
    callee:
      attribute: [io, read]
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: tainted path
    code: |
      import io
      def handler(path):
          return io.read(path)
  description: The call consumes a filesystem path.
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let literal = python_ws(
        r#"
import io
def handler():
    return io.read("safe.txt")
"#,
    );
    let report = run_taint_analysis(
        &literal,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report.findings.is_empty(),
        "a call result cannot flow backwards into its own already-evaluated argument: {:#?}",
        report.findings
    );
}

#[test]
fn sink_restricted_concrete_source_does_not_erase_inferred_param_for_other_sinks() {
    let tmp = TempDir::new("sink-restricted-source");
    write(
        &tmp.path().join("langs/python/sources/blob.yml"),
        r#"- id: python.test.deserialization_blob
  enabled: true
  language: python
  trust: remote
  tag: caller-input
  match:
    kind: param
    target:
      name: payload
  constraints:
  - sink_tag_in: [insecure-deserialization]
  match_examples:
  - name: payload parameter
    code: |
      def handler(payload):
          return payload
  description: Generic blob source restricted to deserialization sinks.
"#,
    );
    write(
        &tmp.path().join("langs/python/sinks/nosql.yml"),
        r#"- id: python.test.nosql
  enabled: true
  language: python
  tag: nosql-injection
  severity: high
  cwe: [CWE-943]
  match:
    kind: call
    callee:
      name: dangerous
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: tainted payload
    code: |
      def handler(payload):
          dangerous(payload)
  description: NoSQL sink consuming a caller-controlled payload.
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let ws = python_ws(
        r#"
def handler(payload):
    dangerous(payload)
"#,
    );
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "python.test.nosql"
                && finding.finding.source.rule_id.starts_with("entry-point.")
        }),
        "a source restricted to another sink tag must not suppress the compatible inferred source: {:#?}",
        report.findings
    );
}

#[test]
fn arg_tainted_kw_resolves_named_call_arg() {
    let tmp = TempDir::new("kw");
    write(
        &tmp.path().join("langs/python/sinks/eval.yml"),
        r#"- id: python.test.kw_run
  enabled: true
  language: python
  tag: code-eval
  severity: critical
  cwe: [CWE-94]
  match:
    kind: call
    callee:
      name: run
  constraints:
  - arg_tainted:
      kw: cmd
  match_examples:
  - name: positive
    code: |
      def handler(user_input):
          return run(cmd=user_input)
  - name: negative
    code: |
      def handler(user_input):
          return run(cmd="safe")
    expect_no_match: true
  description: Named argument taint predicate test rule.
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let ws = python_ws(
        r#"
def handler(user_input):
    return run(cmd=user_input)
"#,
    );
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
}

#[test]
fn any_arg_tainted_matches_any_syntactic_call_argument() {
    let tmp = TempDir::new("any");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.any_arg_tainted
  enabled: true
  language: python
  tag: command-injection
  severity: high
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      name: dangerous
  constraints:
  - any_arg_tainted: true
  match_examples:
  - name: positive second arg
    code: |
      def handler(user_input):
          return dangerous("fixed", user_input)
  - name: negative literals
    code: |
      def handler(user_input):
          return dangerous("fixed", "safe")
    expect_no_match: true
  description: Any syntactic argument can carry the dangerous payload.
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("python.test.any_arg_tainted").expect("rule");

    let pre_taint = python_ws(
        r#"
def handler(user_input):
    return dangerous("fixed", user_input)
"#,
    );
    assert!(
        match_rule_against_facts(&pre_taint, rule).is_empty(),
        "pre-taint matcher must not fire any_arg_tainted rules"
    );

    let tainted_second = python_ws(
        r#"
def handler(user_input):
    return dangerous("fixed", user_input)
"#,
    );
    let report = run_taint_analysis(
        &tainted_second,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == rule.id),
        "tainted second arg must report; findings={:#?}",
        report.findings
    );

    let literal_args = python_ws(
        r#"
def handler(user_input):
    return dangerous("fixed", "safe")
"#,
    );
    let report = run_taint_analysis(
        &literal_args,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(report.findings.is_empty(), "{:#?}", report.findings);

    let no_args = python_ws(
        r#"
def handler(user_input):
    return dangerous()
"#,
    );
    let report = run_taint_analysis(
        &no_args,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

#[test]
fn arg_tainted_index_ignores_assignment_write_operands_and_other_call_args() {
    let tmp = TempDir::new("eval-index");
    write(
        &tmp.path().join("langs/python/sinks/eval.yml"),
        r#"- id: python.test.eval_first_arg_tainted
  enabled: true
  language: python
  tag: code-injection
  severity: critical
  cwe: [CWE-94]
  match:
    kind: call
    callee:
      name: eval
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: positive
    code: |
      def handler(user_input):
          result = eval(user_input, {})
          return result
  - name: negative
    code: |
      def handler(user_input):
          attrs = {"value": user_input}
          expr = "1 + 1"
          result = eval(expr, {"attrs": attrs})
          return result
    expect_no_match: true
  description: eval() only fires when the expression argument itself is tainted.
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.eval_first_arg_tainted")
        .expect("rule");

    let clean_expr_tainted_globals = python_ws(
        r#"
def handler(user_input):
    attrs = {"value": user_input}
    expr = "1 + 1"
    result = eval(expr, {"attrs": attrs})
    return result
"#,
    );
    let report = run_taint_analysis(
        &clean_expr_tainted_globals,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != rule.id),
        "tainted globals/write operands must not satisfy eval arg 0; findings={:#?}",
        report.findings
    );

    let tainted_expr = python_ws(
        r#"
def handler(user_input):
    result = eval(user_input, {})
    return result
"#,
    );
    let report = run_taint_analysis(
        &tainted_expr,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == rule.id),
        "tainted eval expression must still report; findings={:#?}",
        report.findings
    );
}

#[test]
fn write_arg_tainted_requires_tainted_assignment_rhs() {
    let tmp = TempDir::new("write-index");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.write_arg_tainted
  enabled: true
  language: python
  tag: command-injection
  severity: high
  cwe: [CWE-78]
  match:
    kind: write
    target:
      name: dangerous_slot
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: tainted write
    code: |
      def handler(user_input):
          dangerous_slot = user_input
  - name: clean write negative
    code: |
      def handler(user_input):
          dangerous_slot = "safe"
    expect_no_match: true
  description: write sinks only fire when the assigned value is tainted.
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("python.test.write_arg_tainted")
        .expect("rule");

    let tainted_write = python_ws(
        r#"
def handler(user_input):
    dangerous_slot = user_input
"#,
    );
    assert!(
        match_rule_against_facts(&tainted_write, rule).is_empty(),
        "pre-taint matcher must not fire arg_tainted write rules"
    );
    let report = run_taint_analysis(
        &tainted_write,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == rule.id),
        "tainted write RHS must satisfy arg_tainted write sink; findings={:#?}",
        report.findings
    );

    let clean_write_with_sibling_taint = python_ws(
        r#"
def handler(user_input):
    marker = user_input
    dangerous_slot = "safe"
"#,
    );
    let report = run_taint_analysis(
        &clean_write_with_sibling_taint,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != rule.id),
        "tainted sibling writes must not satisfy clean target write; findings={:#?}",
        report.findings
    );
}

#[test]
fn matcher_policy_fingerprint_was_bumped_for_arg_tainted() {
    // Bumped 0x0011 → 0x0012 when the matcher gained
    // arg_lt/arg_le/arg_gt/arg_ge constraints (P3 — constants tracking).
    // Bumped 0x0012 → 0x0013 when the matcher gained
    // requires_runtime_type (P1 schema) and MatchKind::Missing (P4 schema).
    // Bumped 0x0013 → 0x0014 when:
    //   - MatchKind::Missing walker landed (P4 evaluation)
    //   - RequiresRuntimeType moved from pass-through to lexical
    //     type-test evaluation (P1 evaluation)
    //   - EnclosingDecoratorIn / MustAlias / RequiresState
    //     constraints were added (P5/P6 schemas + intra-procedural
    //     must-alias evaluation).
    // Bumped 0x0014 → 0x0015 when adapters started emitting
    // `FlowEvent::Lifecycle` events for free / close / unlock /
    // cancel / move transitions and the engine's
    // `collect_lifecycle_states` consumes them. Rules that opt
    // into `requires_state` start firing for the affected
    // languages.
    // Bumped 0x0015 → 0x0016 when MatchKind::Missing gained a
    // `search_depth` field that opts the walker into BFS through
    // the call graph for cross-procedural absence checks.
    // Bumped 0x0016 → 0x0017 when P1 RequiresRuntimeType moved
    // from a flow-insensitive name→type map to a CFG-aware
    // narrowing list bound to the then-branch span. Rules using
    // `requires_runtime_type` now fail closed outside the
    // guarded block.
    // Bumped 0x0017 → 0x0018 when `any_arg_tainted` landed so
    // rulepack sink policies can depend on taint in any syntactic
    // call argument without duplicating per-position rules.
    // Bumped 0x0018 → 0x0019 when receiver/constructor matching
    // started normalizing inline qualified constructors and carrier
    // args with tainted descendants became sink arg evidence.
    // Bumped 0x0019 → 0x001a when receiver/attribute matching
    // stopped skipping middle chain segments; typed receiver rules
    // now require exact API paths or adapter-emitted receiver-type
    // facts instead of tail fallback.
    // Bumped 0x001a → 0x001b when receiver-name constraints were
    // removed from the schema and receiver-state taint propagation
    // became rulepack-declared via taint_semantics instead of an
    // engine-owned method-tail list.
    // Bumped 0x002b → 0x002c when `arg_tainted` and
    // `any_arg_tainted` started accepting synthetic write evidence
    // for `MatchKind::Write` rules while remaining call-only for
    // call/new rules.
    // Bumped 0x002c → 0x002d when resolver/call-flow semantics
    // stopped using broad public-name fallback for cross-file class
    // dispatch and synthetic anonymous callback entrypoints.
    // Bumped 0x002d → 0x0035 across the package-gate, receiver-type,
    // IDG callback-source, and field-sensitive flow policy changes:
    // cached graph facts can now change for FQN-gated calls,
    // typed receiver/factory dispatch, configured callback source
    // arguments, and member/subscript assignment precision.
    // Bumped 0x0034 → 0x0035 when call-result argument-carrier pruning
    // started canonicalizing adapter-owned identifier sigils, changing
    // Perl/PHP IDG reachability and invalidating warm graph facts.
    // Bumped 0x0035 → 0x0036 when typed receiver evidence became
    // authoritative and qualified/import matching moved to structural
    // compiler names, changing cached matcher and reachability facts.
    // Bumped 0x0036 → 0x0038 when regex rules began consuming authoritative
    // adapter receiver types without collapsing fluent call receivers, and
    // typed guard joins gained exact configured aggregate/substitution
    // semantics.
    assert_eq!(
        bonsai_security::MATCHER_POLICY_FINGERPRINT,
        0x4d41_5443_4845_525f_504f_4c49_4359_0038_u128
    );
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bonsai-arg-tainted-{tag}-{}-{}",
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
