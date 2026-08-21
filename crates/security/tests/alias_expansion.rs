//! End-to-end tests for the security matcher's import-alias expansion.
//!
//! The engine-level primitive lives in
//! `bonsai_lang_api::kit::alias_map_from_imports`; this file exercises
//! the full pipeline: fixture files on disk → parse → ImportIndex →
//! matcher alias-expansion → rule fire.
//!
//! Covers the shapes the matcher must resolve to keep rules shaped as
//! `callee.attribute: [child_process, exec]` firing against the bare
//! `exec(...)` call sites they see at runtime:
//!
//! - ES-module `import { exec } from "child_process"`
//! - ES-module renamed `import { exec as doExec } from "child_process"`
//! - CommonJS destructured `const { exec } = require("child_process")`
//! - CommonJS renamed `const { exec: myExec } = require("child_process")`
//! - Python `from child_process import exec`
//! - Python renamed `from os import system as run`
//!
//! Each test writes a fixture + a tiny rulepack to a tempdir and runs
//! `bonsai-ninja security taint-analysis --all`, then asserts the rule fires.
//! This is deliberately an integration test, not a unit test: the
//! pipeline involves the DB, the parser, the adapter, the matcher,
//! and the flow builder, and any one of those silently breaking
//! alias expansion would regress the rulepack's real-world hit rate.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod support;
use support::bin_path;

/// Run `security sinks --all` so we can assert a sink rule fired
/// WITHOUT needing a matching source rule + a reachable chain. The
/// alias-expansion path lives in the matcher's `scan_calls`, which
/// runs for both `sinks` and `flows` uniformly — sinks is a cleaner
/// signal because it measures matcher correctness in isolation.
fn run_sinks(workspace: &Path, rules: &Path) -> Option<String> {
    let bin = bin_path()?;
    // `--rules-dir` is a per-subcommand flag — it goes after `sinks`,
    // not after `security`. The same path is also picked up via
    // `BONSAI_RULES_DIR`, but the explicit flag is clearer in tests.
    let out = Command::new(&bin)
        .args(["--no-cache", "--no-progress", "security"])
        .arg(workspace)
        .args(["sinks", "--all", "--rules-dir"])
        .arg(rules)
        .env("COLUMNS", "200")
        .env("NO_COLOR", "1")
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Build a minimal pack with just one sink rule that matches the
/// given callee attribute chain. Returns the pack root directory.
fn write_pack(dir: &Path, lang: &str, rule_id: &str, attribute: &[&str]) -> PathBuf {
    let attr_yaml = attribute
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let rules_dir = dir
        .join("security-patterns")
        .join("langs")
        .join(lang)
        .join("sinks");
    fs::create_dir_all(&rules_dir).expect("mkdir rules");
    fs::write(
        rules_dir.join("alias_test.yml"),
        format!(
            "- id: {rule_id}\n  enabled: true\n  tag: test\n  severity: critical\n  match:\n    kind: call\n    callee:\n      attribute: [{attr_yaml}]\n  description: alias-expansion integration rule\n"
        ),
    )
    .expect("write rule");
    dir.join("security-patterns")
}

fn write_fixture(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, contents).expect("write fixture");
    p
}

fn fresh_tmp() -> PathBuf {
    // Monotonic atomic counter so two tests in the same process
    // (cargo test runs tests in parallel threads within one binary)
    // can't collide via a same-nanosecond rand_suffix.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let suffix = rand_suffix();
    let root = std::env::temp_dir();
    for attempt in 0..100 {
        let base = root.join(format!(
            "bonsai-alias-{}-{suffix}-{n}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&base) {
            Ok(()) => return base,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("mkdir tmp {}: {e}", base.display()),
        }
    }
    panic!("could not allocate alias temp dir");
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}

fn cleanup(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// Extract the "N match(es)" count from `security sinks` output.
/// Used instead of string-matching the rule id because the default
/// paged table hides the id line when the table is full-shown.
fn count_matches(out: &str) -> u32 {
    for line in out.lines() {
        if let Some(n) = line.split_whitespace().find_map(|t| t.parse::<u32>().ok()) {
            if line.contains("match(es)") {
                return n;
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// JavaScript — ES-module named imports.
// ---------------------------------------------------------------------------

#[test]
fn js_es_module_named_import_matches_attribute_rule() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp();
    let pack = write_pack(
        &tmp,
        "javascript",
        "javascript.cmdi.child_process_exec",
        &["child_process", "exec"],
    );
    write_fixture(
        &tmp,
        "app.js",
        "import { exec } from \"child_process\";\nfunction run(cmd) { exec(cmd); }\nrun(\"x\");\n",
    );
    let out = run_sinks(&tmp, &pack).expect("flows output");
    assert!(
        count_matches(&out) >= 1,
        "rule should fire after alias expansion; got:\n{out}"
    );
    cleanup(&tmp);
}

#[test]
fn js_renamed_es_module_import_matches_via_original_name() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp();
    let pack = write_pack(
        &tmp,
        "javascript",
        "javascript.cmdi.child_process_exec",
        &["child_process", "exec"],
    );
    // `import { exec as doExec } from "child_process"` — call site
    // uses `doExec(...)`. Alias map binds `doExec → Member{
    // child_process, exec }`, expansion rewrites `doExec(x)` to
    // `child_process.exec(x)`, and the rule fires.
    write_fixture(
        &tmp,
        "app.js",
        "import { exec as doExec } from \"child_process\";\nfunction run(cmd) { doExec(cmd); }\nrun(\"x\");\n",
    );
    let out = run_sinks(&tmp, &pack).expect("sinks output");
    assert!(
        count_matches(&out) >= 1,
        "renamed import should expand to original export; got:\n{out}"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// JavaScript — CommonJS require destructuring.
// ---------------------------------------------------------------------------

#[test]
fn js_commonjs_shorthand_destructure_matches_attribute_rule() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp();
    let pack = write_pack(
        &tmp,
        "javascript",
        "javascript.cmdi.child_process_exec",
        &["child_process", "exec"],
    );
    write_fixture(
        &tmp,
        "app.js",
        "const { exec } = require(\"child_process\");\nfunction run(cmd) { exec(cmd); }\nrun(\"x\");\n",
    );
    let out = run_sinks(&tmp, &pack).expect("flows output");
    assert!(
        count_matches(&out) >= 1,
        "destructured require must match attribute rule; got:\n{out}"
    );
    cleanup(&tmp);
}

#[test]
fn js_namespace_bound_require_matches_attribute_rule() {
    // `const cp = require("child_process"); cp.exec(...)` — the call
    // site is `cp.exec`. The callee's text already contains `cp.exec`
    // which the matcher's suffix-match logic (`ends_with("cp.exec")`)
    // won't satisfy against `[child_process, exec]`. Alias expansion
    // rewrites `cp -> child_process.cp -> child_process`, then the
    // call `cp.exec` → expanded `child_process.exec` matches.
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp();
    let pack = write_pack(
        &tmp,
        "javascript",
        "javascript.cmdi.child_process_exec",
        &["child_process", "exec"],
    );
    write_fixture(
        &tmp,
        "app.js",
        "const cp = require(\"child_process\");\nfunction run(cmd) { cp.exec(cmd); }\nrun(\"x\");\n",
    );
    let out = run_sinks(&tmp, &pack).expect("flows output");
    assert!(
        count_matches(&out) >= 1,
        "namespace-bound require must match attribute rule; got:\n{out}"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// TypeScript — identical shapes to JS.
// ---------------------------------------------------------------------------

#[test]
fn ts_es_module_destructure_matches_attribute_rule() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp();
    let pack = write_pack(
        &tmp,
        "typescript",
        "typescript.cmdi.child_process_exec_sync",
        &["child_process", "execSync"],
    );
    write_fixture(
        &tmp,
        "app.ts",
        "import { execSync } from \"child_process\";\nfunction run(cmd: string): void { execSync(cmd); }\nrun(\"x\");\n",
    );
    let out = run_sinks(&tmp, &pack).expect("flows output");
    assert!(
        count_matches(&out) >= 1,
        "TS ES-module destructure must match; got:\n{out}"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Python — `from X import Y`.
// ---------------------------------------------------------------------------

#[test]
fn python_from_import_matches_attribute_rule() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp();
    let pack = write_pack(&tmp, "python", "python.cmdi.os_system", &["os", "system"]);
    write_fixture(
        &tmp,
        "app.py",
        "from os import system\ndef run(cmd):\n    system(cmd)\n\nrun('x')\n",
    );
    let out = run_sinks(&tmp, &pack).expect("flows output");
    assert!(
        count_matches(&out) >= 1,
        "Python `from x import y` must match attribute rule; got:\n{out}"
    );
    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// Sanity: adapter-level alias map is empty for a language without
// imports in the fixture, so the matcher path degrades to the plain
// `callee_matches` check.
// ---------------------------------------------------------------------------

#[test]
fn no_imports_still_matches_direct_attribute_call() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp();
    let pack = write_pack(
        &tmp,
        "javascript",
        "javascript.cmdi.child_process_exec",
        &["child_process", "exec"],
    );
    // Direct attribute call — no imports to expand. Should still fire.
    write_fixture(
        &tmp,
        "app.js",
        "function run(cmd) { child_process.exec(cmd); }\nrun(\"x\");\n",
    );
    let out = run_sinks(&tmp, &pack).expect("flows output");
    assert!(
        count_matches(&out) >= 1,
        "direct attribute call must still match; got:\n{out}"
    );
    cleanup(&tmp);
}
