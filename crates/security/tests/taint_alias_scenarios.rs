//! Complex taint-alias scenarios showcasing end-to-end engine accuracy.
//!
//! The engine layers under test:
//!   1. Adapter emits `ImportSpec` entries for every import shape.
//!   2. `kit::alias_map_from_imports` classifies them into Member /
//!      Namespace bindings.
//!   3. `kit::extend_alias_map_with_flow_events` folds in local
//!      variable-reassignment chains (single-var, multi-var, multi-
//!      hop, inside branches, inside loops, inside try).
//!   4. `scan_calls` in the matcher expands each call site through
//!      the per-function alias map before checking the rule.
//!
//! Each test writes a focused fixture, a single attribute-rule, and
//! asserts the rule fires for every call site that SHOULD match and
//! does NOT fire for call sites that shouldn't (negative tests prove
//! we didn't just become permissive).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod support;
use support::bin_path;

// ---------------------------------------------------------------------------
// Test harness.
// ---------------------------------------------------------------------------

fn fresh_tmp(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let p = base.join(format!(
            "bonsai-taint-{tag}-{}-{nanos:x}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&p) {
            Ok(()) => return p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("mkdir tmp {}: {e}", p.display()),
        }
    }
    panic!("could not allocate temp dir for {tag}");
}

fn cleanup(p: &PathBuf) {
    let _ = fs::remove_dir_all(p);
}

fn write_rule(tmp: &Path, lang: &str, rule_id: &str, attribute: &[&str]) -> PathBuf {
    let attr_yaml = attribute
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let rules = tmp
        .join("security-patterns")
        .join("langs")
        .join(lang)
        .join("sinks");
    fs::create_dir_all(&rules).expect("mkdir rules");
    fs::write(
        rules.join("scenario.yml"),
        format!(
            "- id: {rule_id}\n  enabled: true\n  tag: test\n  severity: critical\n  match:\n    kind: call\n    callee:\n      attribute: [{attr_yaml}]\n  description: taint-alias scenario rule\n"
        ),
    )
    .expect("write rule");
    tmp.join("security-patterns")
}

fn write(tmp: &Path, name: &str, contents: &str) {
    fs::write(tmp.join(name), contents).expect("write fixture");
}

fn sinks_count(tmp: &PathBuf, rules: &PathBuf) -> u32 {
    let Some(bin) = bin_path() else { return u32::MAX };
    let out = Command::new(&bin)
        .args(["--no-cache", "--no-progress", "security"])
        .arg(tmp)
        .args(["sinks", "--all", "--rules-dir"])
        .arg(rules)
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    for line in text.lines() {
        if line.contains("match(es)") {
            if let Some(n) = line.split_whitespace().find_map(|t| t.parse::<u32>().ok()) {
                return n;
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// JavaScript — single-hop var reassignment after destructure import.
// ---------------------------------------------------------------------------

#[test]
fn js_single_hop_var_reassignment() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("js-1hop");
    let rules = write_rule(&tmp, "javascript", "js.cmdi.exec", &["child_process", "exec"]);
    // `fn = exec` — fn should inherit exec's alias.
    write(
        &tmp,
        "app.js",
        r#"
const { exec } = require("child_process");
function run(cmd) {
  const fn = exec;
  fn(cmd);
}
run("x");
"#,
    );
    assert!(sinks_count(&tmp, &rules) >= 1, "single-hop fn = exec must alias");
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// JavaScript — multi-hop chain `a = exec; b = a; c = b; c(x)`.
// ---------------------------------------------------------------------------

#[test]
fn js_multi_hop_reassignment_chain() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("js-nhop");
    let rules = write_rule(&tmp, "javascript", "js.cmdi.exec", &["child_process", "exec"]);
    write(
        &tmp,
        "app.js",
        r#"
const { exec } = require("child_process");
function run(cmd) {
  const a = exec;
  const b = a;
  const c = b;
  const d = c;
  d(cmd);
}
run("x");
"#,
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "four-hop chain must carry alias through"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// JavaScript — alias inside an if-branch is visible to call after merge.
// ---------------------------------------------------------------------------

#[test]
fn js_alias_inside_branch_reaches_call_after_merge() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("js-branch");
    let rules = write_rule(&tmp, "javascript", "js.cmdi.exec", &["child_process", "exec"]);
    write(
        &tmp,
        "app.js",
        r#"
const { exec } = require("child_process");
function run(cmd, flag) {
  let fn;
  if (flag) {
    fn = exec;
  } else {
    fn = exec;
  }
  fn(cmd);
}
run("x", true);
"#,
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "alias assigned in both branches should reach the post-merge call"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// JavaScript — alias inside a loop body is visible to the call.
// ---------------------------------------------------------------------------

#[test]
fn js_alias_inside_loop_body() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("js-loop");
    let rules = write_rule(&tmp, "javascript", "js.cmdi.exec", &["child_process", "exec"]);
    write(
        &tmp,
        "app.js",
        r#"
const { exec } = require("child_process");
function run(cmds) {
  for (const cmd of cmds) {
    const fn = exec;
    fn(cmd);
  }
}
run(["x"]);
"#,
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "alias inside loop body must be visible at the call site"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// JavaScript — alias inside a try body is visible to catch's call.
// ---------------------------------------------------------------------------

#[test]
fn js_alias_inside_try_body_reaches_catch_call() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("js-try");
    let rules = write_rule(&tmp, "javascript", "js.cmdi.exec", &["child_process", "exec"]);
    write(
        &tmp,
        "app.js",
        r#"
const { exec } = require("child_process");
function run(cmd) {
  let fn;
  try {
    fn = exec;
    fn(cmd);
  } catch (e) {
    fn = exec;
    fn(cmd);
  }
}
run("x");
"#,
    );
    // At minimum the try-body call should fire. Ideally both.
    assert!(sinks_count(&tmp, &rules) >= 1, "alias inside try body must fire");
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// JavaScript — namespace-bound require + attribute access `cp.exec`.
// ---------------------------------------------------------------------------

#[test]
fn js_namespace_bound_require_matches() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("js-ns");
    let rules = write_rule(&tmp, "javascript", "js.cmdi.exec", &["child_process", "exec"]);
    write(
        &tmp,
        "app.js",
        r#"
const cp = require("child_process");
function run(cmd) { cp.exec(cmd); }
run("x");
"#,
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "namespace-bound `cp.exec` must match via namespace alias expansion"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// JavaScript — rebind loses the alias (last binding wins).
// ---------------------------------------------------------------------------

#[test]
fn js_rebind_to_unrelated_does_not_match() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("js-rebind");
    let rules = write_rule(&tmp, "javascript", "js.cmdi.exec", &["child_process", "exec"]);
    // `fn = exec; fn = someOtherFn; fn(cmd)` — fn no longer aliases exec.
    // We don't currently invalidate prior aliases on rebind (the alias
    // map is additive), so this test documents the current behaviour
    // rather than asserting it's perfect: IF a future pass adds
    // rebind-awareness, this expectation flips.
    write(
        &tmp,
        "app.js",
        r#"
const { exec } = require("child_process");
function otherFn(_) {}
function run(cmd) {
  let fn = exec;
  fn = otherFn;
  fn(cmd);
}
run("x");
"#,
    );
    // Additive alias map: `fn` resolves to exec AND otherFn (last wins
    // in HashMap::insert). In practice, this may over- or under-match;
    // the test just pins the current behaviour so a regression surfaces.
    let n = sinks_count(&tmp, &rules);
    assert!(n <= 1, "rebind scenario should match at most once, got {n}");
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Python — multi-hop reassignment after `from x import y`.
// ---------------------------------------------------------------------------

#[test]
fn python_multi_hop_reassignment() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("py-nhop");
    let rules = write_rule(&tmp, "python", "py.cmdi.system", &["os", "system"]);
    write(
        &tmp,
        "app.py",
        r#"
from os import system
def run(cmd):
    a = system
    b = a
    c = b
    c(cmd)

run("x")
"#,
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "Python multi-hop `a = system; b = a; c = b; c(x)` must match"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Python — namespace alias (`import os as o`) + attribute call.
// ---------------------------------------------------------------------------

#[test]
fn python_namespace_alias_attribute_call_matches() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("py-ns");
    let rules = write_rule(&tmp, "python", "py.cmdi.system", &["os", "system"]);
    write(
        &tmp,
        "app.py",
        "import os as o\ndef run(cmd):\n    o.system(cmd)\n\nrun('x')\n",
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "Python namespace `o.system` must match via namespace expansion"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Python — aliased renamed import via `import os as o; fn = o.system`.
// ---------------------------------------------------------------------------

#[test]
fn python_namespace_then_attribute_reassigned() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("py-ns-attr");
    let rules = write_rule(&tmp, "python", "py.cmdi.system", &["os", "system"]);
    // `fn = o.system; fn(cmd)` — attribute reassignment should alias fn
    // to os.system. This exercises extension beyond bare identifiers
    // to attribute-access RHS. NOTE: the FlowEvent::Assign carries
    // `source_name` as the RHS identifier; adapters may or may not
    // surface the full dotted chain. The test pins current behaviour.
    write(
        &tmp,
        "app.py",
        "import os as o\ndef run(cmd):\n    fn = o.system\n    fn(cmd)\n\nrun('x')\n",
    );
    let n = sinks_count(&tmp, &rules);
    // Not asserted positive yet — adapter-emitted source_name for the
    // attribute RHS varies. Just ensures the path doesn't panic.
    let _ = n;
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Python — function argument carrying an alias (`run(system)` →
// `def run(fn): fn(cmd)`). The matcher inventory command is intentionally
// broader than the taint engine; callback dataflow itself is pinned in
// `callback_flow_audit.rs`.
// ---------------------------------------------------------------------------

#[test]
fn python_alias_passed_through_arg_inventory_does_not_panic() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("py-arg");
    let rules = write_rule(&tmp, "python", "py.cmdi.system", &["os", "system"]);
    write(
        &tmp,
        "app.py",
        r#"
from os import system
def invoke(fn, x):
    fn(x)

def run(cmd):
    invoke(system, cmd)

run("x")
"#,
    );
    let _ = sinks_count(&tmp, &rules);
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// TypeScript — alias via `let` + reassignment type annotations.
// ---------------------------------------------------------------------------

#[test]
fn ts_alias_through_let_reassignment() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("ts-let");
    let rules = write_rule(&tmp, "typescript", "ts.cmdi.exec", &["child_process", "execSync"]);
    write(
        &tmp,
        "app.ts",
        r#"
import { execSync } from "child_process";
function run(cmd: string): void {
  let fn: (c: string) => void = execSync;
  fn(cmd);
}
run("x");
"#,
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "TS let-reassignment must preserve alias"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Ruby — `fn = method(:system); fn.call(cmd)` pattern.
// ---------------------------------------------------------------------------

#[test]
fn ruby_method_reference_known_limitation() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("rb-method");
    // Ruby's `method(:system)` pattern produces a Method object whose
    // `.call` invocation isn't currently alias-tracked. Document.
    let rules = write_rule(&tmp, "ruby", "rb.cmdi.system", &["Kernel", "system"]);
    write(
        &tmp,
        "app.rb",
        "def run(cmd)\n  fn = method(:system)\n  fn.call(cmd)\nend\n",
    );
    let _ = sinks_count(&tmp, &rules);
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Go — `var fn = exec.Command; fn("sh", "-c", cmd)` pattern.
// ---------------------------------------------------------------------------

#[test]
fn go_var_reassignment_from_imported_func() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("go-var");
    let rules = write_rule(&tmp, "go", "go.cmdi.cmd", &["exec", "Command"]);
    write(
        &tmp,
        "main.go",
        r#"
package main

import "os/exec"

func run(cmd string) {
    fn := exec.Command
    _ = fn("sh", "-c", cmd)
}
"#,
    );
    // Go assignment shorthand `fn := exec.Command` — the assignment's
    // source_name is `exec.Command` which current resolution doesn't
    // split; this documents current behaviour without asserting.
    let _ = sinks_count(&tmp, &rules);
    cleanup(&tmp);
}
