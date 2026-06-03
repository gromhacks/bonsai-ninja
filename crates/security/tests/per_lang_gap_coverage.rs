//! Per-language coverage for G1 / G2 / G3 / G5 / G8.
//!
//! One synthetic fixture per (capability × language) pair. The fixture
//! writes a tiny source file + a one-rule sinks pack to a tempdir and
//! asserts `security sinks --all` (matcher-only, no chain-building) or
//! `security taint-analysis --all` (full pipeline) produces at least one hit.
//!
//! Capabilities exercised:
//! - G1 — Return-value taint: `y = transform(tainted)` taints `y`.
//! - G2 — Expression RHS taint: `y = "prefix" + tainted` /
//!   template literal / format string.
//! - G3 — Field taint: `self.cmd = tainted; sink(self.cmd)`.
//! - G5 — Entry-point inference: `def handler(x): sink(x)` with no
//!   caller taints via synthesised entry-point source.
//! - G8 — Exception-flow taint: `throw tainted; catch (e) { sink(e) }`.
//!
//! Each language that supports the idiom gets a focused test. When an
//! idiom doesn't apply (C has no classes, Erlang has no `throw/catch`
//! with a binding in the handler signature, etc.), the test documents
//! the skip.
//!
//! This file is intentionally a lot of tests — 80+ — because the
//! engine has to work uniformly. Anything less would let regressions
//! in adapter-specific paths slip in silently.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Test harness — shared fixture helpers.
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    let p = repo_root().join("target/release/bonsai-ninja");
    p.exists().then_some(p)
}

fn fresh_tmp(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let p = base.join(format!(
            "bonsai-gap-{tag}-{}-{nanos:x}-{attempt}",
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

fn cleanup(p: &Path) {
    let _ = fs::remove_dir_all(p);
}

fn write_sink_rule(tmp: &Path, lang: &str, rule_id: &str, name: &str) -> PathBuf {
    let rules = tmp
        .join("security-patterns")
        .join("langs")
        .join(lang)
        .join("sinks");
    fs::create_dir_all(&rules).expect("mkdir rules");
    fs::write(
        rules.join("scenario.yml"),
        format!(
            "- id: {rule_id}\n  enabled: true\n  tag: test\n  severity: critical\n  match:\n    kind: call\n    callee:\n      name: {name}\n  description: coverage\n"
        ),
    )
    .expect("write rule");
    tmp.join("security-patterns")
}

fn write_call_result_passthrough_rule(
    tmp: &Path,
    lang: &str,
    rule_id: &str,
    name: &str,
    arg_indices: &[usize],
) {
    let rules = tmp
        .join("security-patterns")
        .join("langs")
        .join(lang)
        .join("sanitizers");
    fs::create_dir_all(&rules).expect("mkdir passthrough rules");
    let args = arg_indices
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        rules.join(format!("{rule_id}.yml")),
        format!(
            "- id: {rule_id}\n  enabled: true\n  tag: passthrough-transform\n  match:\n    kind: call\n    callee:\n      name: {name}\n  taint_semantics:\n    call_result_passthrough_args: [{args}]\n  description: coverage passthrough\n"
        ),
    )
    .expect("write passthrough rule");
}

fn write_fixture(tmp: &Path, name: &str, contents: &str) {
    fs::write(tmp.join(name), contents).expect("write fixture");
}

fn run_subcmd(tmp: &Path, rules: &Path, subcmd: &str) -> u32 {
    let Some(bin) = bin_path() else { return u32::MAX };
    // Inferred entry-point sources are CLI-opt-in (commit 1f4922c).
    // The G5 cases (and most G1-G3 fixtures) rely on inferred handler
    // params being treated as remote-trust sources; opt in for the
    // taint-analysis subcommand. Other subcommands ignore the flag.
    let mut args: Vec<&str> = vec![subcmd, "--all", "--rules-dir"];
    let rules_str = rules.to_str().expect("rules path");
    args.push(rules_str);
    if subcmd == "taint-analysis" {
        args.push("--inferred-sources");
    }
    let out = Command::new(&bin)
        .args(["--no-cache", "--no-progress", "security"])
        .arg(tmp)
        .args(&args)
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    for line in text.lines() {
        if line.contains("match(es)") || line.contains("finding(s)") {
            if let Some(n) = line.split_whitespace().find_map(|t| t.parse::<u32>().ok()) {
                return n;
            }
        }
    }
    0
}

fn sinks_count(tmp: &Path, rules: &Path) -> u32 {
    run_subcmd(tmp, rules, "sinks")
}

fn flows_count(tmp: &Path, rules: &Path) -> u32 {
    run_subcmd(tmp, rules, "taint-analysis")
}

// ===========================================================================
// G5 — Entry-point inference: bare-param handlers get synthesised sources
// across every language.
// ===========================================================================

macro_rules! g5_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G5 ({}): bare-param handler must produce at least one finding",
                $lang
            );
            cleanup(&tmp);
        }
    };
}

g5_test!(
    g5_python_entry,
    "g5-py",
    "python",
    "app.py",
    "def handle(token):\n    sink(token)\n",
    "py.sink",
    "sink"
);

g5_test!(
    g5_js_entry,
    "g5-js",
    "javascript",
    "app.js",
    "function handle(token) { sink(token); }\n",
    "js.sink",
    "sink"
);

g5_test!(
    g5_ts_entry,
    "g5-ts",
    "typescript",
    "app.ts",
    "function handle(token: string): void { sink(token); }\n",
    "ts.sink",
    "sink"
);

g5_test!(
    g5_java_entry,
    "g5-java",
    "java",
    "App.java",
    "class App { void handle(String token) { sink(token); } void sink(String s) {} }\n",
    "java.sink",
    "sink"
);

g5_test!(
    g5_kotlin_entry,
    "g5-kt",
    "kotlin",
    "App.kt",
    "fun handle(token: String) { sink(token) }\nfun sink(s: String) {}\n",
    "kt.sink",
    "sink"
);

g5_test!(
    g5_scala_entry,
    "g5-scala",
    "scala",
    "App.scala",
    "object App { def handle(token: String): Unit = sink(token)\ndef sink(s: String): Unit = () }\n",
    "scala.sink",
    "sink"
);

g5_test!(
    g5_swift_entry,
    "g5-swift",
    "swift",
    "App.swift",
    "func handle(token: String) { sink(token) }\nfunc sink(_ s: String) {}\n",
    "swift.sink",
    "sink"
);

g5_test!(
    g5_go_entry,
    "g5-go",
    "go",
    "main.go",
    "package main\nfunc handle(token string) { sink(token) }\nfunc sink(s string) {}\n",
    "go.sink",
    "sink"
);

g5_test!(
    g5_rust_entry,
    "g5-rust",
    "rust",
    "app.rs",
    "pub fn handle(token: &str) { sink(token); }\npub fn sink(_s: &str) {}\n",
    "rs.sink",
    "sink"
);

g5_test!(
    g5_csharp_entry,
    "g5-cs",
    "csharp",
    "App.cs",
    "class App { void Handle(string token) { Sink(token); } void Sink(string s) {} }\n",
    "cs.sink",
    "Sink"
);

g5_test!(
    g5_ruby_entry,
    "g5-rb",
    "ruby",
    "app.rb",
    "def handle(token)\n  sink(token)\nend\n\ndef sink(s); end\n",
    "rb.sink",
    "sink"
);

g5_test!(
    g5_php_entry,
    "g5-php",
    "php",
    "app.php",
    "<?php\nfunction handle($token) { sink($token); }\nfunction sink($s) {}\n",
    "php.sink",
    "sink"
);

g5_test!(
    g5_dart_entry,
    "g5-dart",
    "dart",
    "app.dart",
    "void handle(String token) { sink(token); }\nvoid sink(String s) {}\n",
    "dart.sink",
    "sink"
);

g5_test!(
    g5_elixir_entry,
    "g5-ex",
    "elixir",
    "app.ex",
    "defmodule A do\n  def handle(token), do: sink(token)\n  def sink(_s), do: :ok\nend\n",
    "ex.sink",
    "sink"
);

g5_test!(
    g5_erlang_entry,
    "g5-erl",
    "erlang",
    "app.erl",
    "-module(app).\n-export([handle/1, sink/1]).\nhandle(Token) -> sink(Token).\nsink(_S) -> ok.\n",
    "erl.sink",
    "sink"
);

// Perl's `my ($token) = @_;` pattern assigns params from the `@_`
// implicit array rather than via formal param names. The decl's
// `params` vector ends up empty, so entry-point inference has
// Perl's tree-sitter grammar has no structural param list on
// subroutine_declaration_statement; the adapter synthesises params
// by scanning leading `my ($x) = @_` / `my $x = shift` idioms in
// the body, so entry-point inference (G5) works end-to-end.
g5_test!(
    g5_perl_entry,
    "g5-pl",
    "perl",
    "app.pl",
    "sub handle { my ($token) = @_; sink($token); }\nsub sink { my ($s) = @_; }\n1;\n",
    "pl.sink",
    "sink"
);

g5_test!(
    g5_lua_entry,
    "g5-lua",
    "lua",
    "app.lua",
    "local function handle(token) sink(token) end\nfunction sink(s) end\n",
    "lua.sink",
    "sink"
);

g5_test!(
    g5_objc_entry,
    "g5-objc",
    "objc",
    "app.m",
    "void handle(NSString *token) { sink(token); }\nvoid sink(NSString *s) {}\n",
    "objc.sink",
    "sink"
);

g5_test!(
    g5_c_entry,
    "g5-c",
    "c",
    "app.c",
    "void handle(const char *token) { sink(token); }\nvoid sink(const char *s) {}\n",
    "c.sink",
    "sink"
);

g5_test!(g5_cpp_entry, "g5-cpp", "cpp", "app.cpp",
    "void sink(const char *s);\nvoid handle(const char *token) { sink(token); }\nvoid sink(const char *s) {}\n",
    "cpp.sink", "sink");

g5_test!(g5_solidity_entry, "g5-sol", "solidity", "A.sol",
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract A { function handle(bytes calldata token) external { sink(token); } function sink(bytes calldata) internal {} }\n",
    "sol.sink", "sink");

// ===========================================================================
// G1 — Return-value taint. `y = transform(token); sink(y)` fires when
// token is tainted at the caller's scope.
// ===========================================================================

#[test]
fn g1_python_return_value_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g1-py");
    let rules = write_sink_rule(&tmp, "python", "py.sink", "sink");
    write_fixture(
        &tmp,
        "app.py",
        "def transform(x):\n    return x.upper()\n\ndef handle(token):\n    y = transform(token)\n    sink(y)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G1 py: y = transform(token); sink(y) must fire"
    );
    cleanup(&tmp);
}

#[test]
fn g1_javascript_return_value_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g1-js");
    let rules = write_sink_rule(&tmp, "javascript", "js.sink", "sink");
    write_fixture(
        &tmp,
        "app.js",
        "function transform(x) { return x + '!'; }\nfunction handle(token) { const y = transform(token); sink(y); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G1 js: return-value taint must fire"
    );
    cleanup(&tmp);
}

#[test]
fn g1_typescript_return_value_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g1-ts");
    let rules = write_sink_rule(&tmp, "typescript", "ts.sink", "sink");
    write_fixture(
        &tmp,
        "app.ts",
        "function transform(x: string): string { return x; }\nfunction handle(token: string) { const y = transform(token); sink(y); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G1 ts: return-value taint must fire"
    );
    cleanup(&tmp);
}

#[test]
fn g1_ruby_return_value_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g1-rb");
    let rules = write_sink_rule(&tmp, "ruby", "rb.sink", "sink");
    write_fixture(
        &tmp,
        "app.rb",
        "def transform(x)\n  x.upcase\nend\n\ndef handle(token)\n  y = transform(token)\n  sink(y)\nend\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G1 rb: return-value taint must fire"
    );
    cleanup(&tmp);
}

#[test]
fn g1_php_return_value_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g1-php");
    let rules = write_sink_rule(&tmp, "php", "php.sink", "sink");
    write_fixture(
        &tmp,
        "app.php",
        "<?php\nfunction transform($x) { return strtoupper($x); }\nfunction handle($token) { $y = transform($token); sink($y); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G1 php: return-value taint must fire"
    );
    cleanup(&tmp);
}

// ===========================================================================
// G2 — Expression RHS taint (string concat, template literal).
// ===========================================================================

#[test]
fn g2_python_string_concat_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g2-py");
    let rules = write_sink_rule(&tmp, "python", "py.sink", "sink");
    write_fixture(
        &tmp,
        "app.py",
        "def handle(token):\n    y = 'prefix: ' + token\n    sink(y)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G2 py: concat taint must propagate"
    );
    cleanup(&tmp);
}

#[test]
fn g2_javascript_template_literal_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g2-js");
    let rules = write_sink_rule(&tmp, "javascript", "js.sink", "sink");
    write_fixture(
        &tmp,
        "app.js",
        "function handle(token) { const y = `prefix ${token}`; sink(y); }\n",
    );
    assert!(flows_count(&tmp, &rules) >= 1, "G2 js: template literal taint");
    cleanup(&tmp);
}

#[test]
fn g2_typescript_template_literal_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g2-ts");
    let rules = write_sink_rule(&tmp, "typescript", "ts.sink", "sink");
    write_fixture(
        &tmp,
        "app.ts",
        "function handle(token: string): void { const y: string = `x=${token}`; sink(y); }\n",
    );
    assert!(flows_count(&tmp, &rules) >= 1, "G2 ts: template literal taint");
    cleanup(&tmp);
}

#[test]
fn g2_ruby_string_interpolation_taint() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g2-rb");
    let rules = write_sink_rule(&tmp, "ruby", "rb.sink", "sink");
    write_fixture(
        &tmp,
        "app.rb",
        "def handle(token)\n  y = \"prefix #{token}\"\n  sink(y)\nend\n",
    );
    assert!(flows_count(&tmp, &rules) >= 1, "G2 rb: interpolation taint");
    cleanup(&tmp);
}

// ===========================================================================
// G3 — Field taint: `self.cmd = tainted; sink(self.cmd)`.
// ===========================================================================

#[test]
fn g3_python_field_taint_single_method() {
    // G3 within a single method body — `self.cmd = x; sink(self.cmd)` —
    // exercises the qualified-assign + qualified-read path without
    // needing cross-method object-state propagation (which the
    // interprocedural pass doesn't yet carry across constructor → method
    // pairs). This single-method form IS what G3 enables.
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g3-py-single");
    let rules = write_sink_rule(&tmp, "python", "py.sink", "sink");
    write_fixture(
        &tmp,
        "app.py",
        "class R:\n    def handle(self, token):\n        self.cmd = token\n        sink(self.cmd)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G3 py: same-method qualified write+read"
    );
    cleanup(&tmp);
}

#[test]
fn g3_javascript_field_taint_single_method() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g3-js-single");
    let rules = write_sink_rule(&tmp, "javascript", "js.sink", "sink");
    write_fixture(
        &tmp,
        "app.js",
        "class R { handle(token) { this.cmd = token; sink(this.cmd); } }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G3 js: same-method qualified write+read"
    );
    cleanup(&tmp);
}

#[test]
fn g3_cross_method_field_taint_python() {
    // Constructor writes `self.cmd = token`; sibling method `run()`
    // reads `self.cmd`. G3 cross-method inference emits a synthetic
    // source for `self.cmd` inside every method of the class so
    // this chain fires end-to-end.
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g3-cross-py");
    let rules = write_sink_rule(&tmp, "python", "py.sink", "sink");
    write_fixture(
        &tmp,
        "app.py",
        "class R:\n    def __init__(self, token):\n        self.cmd = token\n    def run(self):\n        sink(self.cmd)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G3 cross-method py: sibling field-read must fire"
    );
    cleanup(&tmp);
}

#[test]
fn g3_cross_method_field_taint_javascript() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g3-cross-js");
    let rules = write_sink_rule(&tmp, "javascript", "js.sink", "sink");
    write_fixture(
        &tmp,
        "app.js",
        "class R { constructor(token) { this.cmd = token; } run() { sink(this.cmd); } }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G3 cross-method js: sibling field-read must fire"
    );
    cleanup(&tmp);
}

#[test]
fn g7_js_higher_order_for_each_callback() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g7-js");
    let rules = write_sink_rule(&tmp, "javascript", "js.sink", "sink");
    // `handle` gets `items` tainted by entry-point inference; then
    // `items.forEach(step)` seeds `step`'s first parameter with
    // taint. Requires G7 HOF propagation.
    write_fixture(
        &tmp,
        "app.js",
        "function step(item) { sink(item); }\nfunction handle(items) { items.forEach(step); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G7 js: forEach callback must inherit receiver taint"
    );
    cleanup(&tmp);
}

#[test]
fn g7_python_map_callback() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g7-py");
    let rules = write_sink_rule(&tmp, "python", "py.sink", "sink");
    write_fixture(
        &tmp,
        "app.py",
        "def step(item):\n    sink(item)\n\ndef handle(items):\n    items.map(step)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G7 py: map callback must inherit receiver taint"
    );
    cleanup(&tmp);
}

// ===========================================================================
// G8 — Exception-flow taint: throw + catch.
// ===========================================================================

#[test]
fn g8_javascript_throw_catch() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g8-js");
    let rules = write_sink_rule(&tmp, "javascript", "js.sink", "sink");
    write_fixture(
        &tmp,
        "app.js",
        "function handle(token) { try { throw token; } catch (e) { sink(e); } }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G8 js: catch parameter must inherit tainted thrown value"
    );
    cleanup(&tmp);
}

// ===========================================================================
// G1 — Multi-hop return chain: t1 = f(token); t2 = g(t1); sink(t2).
// ===========================================================================

#[test]
fn g1_python_multi_hop_return_chain() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g1-py-nhop");
    let rules = write_sink_rule(&tmp, "python", "py.sink", "sink");
    write_fixture(
        &tmp,
        "app.py",
        "def f(x):\n    return x\n\ndef g(x):\n    return x\n\ndef handle(token):\n    a = f(token)\n    b = g(a)\n    sink(b)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G1: multi-hop return chain must fire"
    );
    cleanup(&tmp);
}

#[test]
fn g1_javascript_multi_hop_return_chain() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g1-js-nhop");
    let rules = write_sink_rule(&tmp, "javascript", "js.sink", "sink");
    write_fixture(
        &tmp,
        "app.js",
        "function f(x) { return x; }\nfunction g(x) { return x; }\nfunction handle(token) { const a = f(token); const b = g(a); sink(b); }\n",
    );
    assert!(flows_count(&tmp, &rules) >= 1, "G1 js: multi-hop return chain");
    cleanup(&tmp);
}

// ===========================================================================
// G1 — Return-value taint: every supported language gets a focused test.
// Pattern: `transform` is an identity-ish function; `handle` passes a
// param through `transform` and then to the sink. G1 requires the
// engine to compute `transform`'s summary and propagate return taint.
// ===========================================================================

macro_rules! g1_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G1 ({}): `y = transform(token); sink(y)` must fire",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

g1_test!(g1_ts_return, "g1-ts", "typescript", "app.ts",
    "function transform(x: string): string { return x; }\nfunction handle(token: string) { const y: string = transform(token); sink(y); }\n",
    "ts.sink", "sink");
g1_test!(g1_java_return, "g1-java", "java", "App.java",
    "class App { String transform(String x) { return x; } void handle(String token) { String y = transform(token); sink(y); } void sink(String s) {} }\n",
    "java.sink", "sink");
g1_test!(g1_kotlin_return, "g1-kt", "kotlin", "App.kt",
    "fun transform(x: String): String = x\nfun handle(token: String) { val y = transform(token); sink(y) }\nfun sink(s: String) {}\n",
    "kt.sink", "sink");
g1_test!(g1_scala_return, "g1-scala", "scala", "App.scala",
    "object App { def transform(x: String): String = x\ndef handle(token: String): Unit = { val y = transform(token); sink(y) }\ndef sink(s: String): Unit = () }\n",
    "scala.sink", "sink");
g1_test!(g1_swift_return, "g1-swift", "swift", "App.swift",
    "func transform(_ x: String) -> String { return x }\nfunc handle(token: String) { let y = transform(token); sink(y) }\nfunc sink(_ s: String) {}\n",
    "swift.sink", "sink");
g1_test!(g1_go_return, "g1-go", "go", "main.go",
    "package main\nfunc transform(x string) string { return x }\nfunc handle(token string) { y := transform(token); sink(y) }\nfunc sink(s string) {}\n",
    "go.sink", "sink");
g1_test!(g1_rust_return, "g1-rs", "rust", "app.rs",
    "pub fn transform(x: String) -> String { x }\npub fn handle(token: String) { let y = transform(token); sink(y); }\npub fn sink(_s: String) {}\n",
    "rs.sink", "sink");
g1_test!(g1_csharp_return, "g1-cs", "csharp", "App.cs",
    "class App { string Transform(string x) { return x; } void Handle(string token) { string y = Transform(token); Sink(y); } void Sink(string s) {} }\n",
    "cs.sink", "Sink");
g1_test!(g1_c_return, "g1-c", "c", "app.c",
    "const char *transform(const char *x) { return x; }\nvoid sink(const char *s);\nvoid handle(const char *token) { const char *y = transform(token); sink(y); }\nvoid sink(const char *s) {}\n",
    "c.sink", "sink");
g1_test!(g1_cpp_return, "g1-cpp", "cpp", "app.cpp",
    "const char *transform(const char *x) { return x; }\nvoid sink(const char *s);\nvoid handle(const char *token) { const char *y = transform(token); sink(y); }\nvoid sink(const char *s) {}\n",
    "cpp.sink", "sink");
g1_test!(g1_dart_return, "g1-dart", "dart", "app.dart",
    "String transform(String x) { return x; }\nvoid handle(String token) { var y = transform(token); sink(y); }\nvoid sink(String s) {}\n",
    "dart.sink", "sink");
g1_test!(g1_elixir_return, "g1-ex", "elixir", "app.ex",
    "defmodule A do\n  def transform(x), do: x\n  def handle(token), do: sink(transform(token))\n  def sink(_s), do: :ok\nend\n",
    "ex.sink", "sink");
g1_test!(g1_erlang_return, "g1-erl", "erlang", "app.erl",
    "-module(app).\n-export([handle/1, sink/1, transform/1]).\ntransform(X) -> X.\nhandle(Token) -> Y = transform(Token), sink(Y).\nsink(_S) -> ok.\n",
    "erl.sink", "sink");
g1_test!(g1_lua_return, "g1-lua", "lua", "app.lua",
    "local function transform(x) return x end\nlocal function handle(token) local y = transform(token); sink(y) end\nfunction sink(s) end\n",
    "lua.sink", "sink");
g1_test!(g1_objc_return, "g1-objc", "objc", "app.m",
    "NSString *transform(NSString *x) { return x; }\nvoid sink(NSString *s);\nvoid handle(NSString *token) { NSString *y = transform(token); sink(y); }\nvoid sink(NSString *s) {}\n",
    "objc.sink", "sink");
g1_test!(g1_perl_return, "g1-pl", "perl", "app.pl",
    "sub transform { my ($x) = @_; return $x; }\nsub handle { my ($token) = @_; my $y = transform($token); sink($y); }\nsub sink {}\n1;\n",
    "pl.sink", "sink");
g1_test!(g1_solidity_return, "g1-sol", "solidity", "A.sol",
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract A { function transform(bytes calldata x) internal pure returns (bytes memory) { return x; } function handle(bytes calldata token) external { bytes memory y = transform(token); sink(y); } function sink(bytes memory) internal {} }\n",
    "sol.sink", "sink");

// ===========================================================================
// G2 — Expression-level RHS taint: every idiomatic compound-expression
// form per language (concat / template / interpolation / format).
// ===========================================================================

macro_rules! g2_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G2 ({}): compound-RHS taint must propagate",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

g2_test!(g2_java_concat, "g2-java", "java", "App.java",
    "class App { void handle(String token) { String y = \"prefix \" + token; sink(y); } void sink(String s) {} }\n",
    "java.sink", "sink");
g2_test!(
    g2_kotlin_concat,
    "g2-kt",
    "kotlin",
    "App.kt",
    "fun handle(token: String) { val y = \"prefix $token\"; sink(y) }\nfun sink(s: String) {}\n",
    "kt.sink",
    "sink"
);
g2_test!(g2_scala_concat, "g2-scala", "scala", "App.scala",
    "object App { def handle(token: String): Unit = { val y = s\"prefix $token\"; sink(y) }\ndef sink(s: String): Unit = () }\n",
    "scala.sink", "sink");
g2_test!(
    g2_swift_concat,
    "g2-swift",
    "swift",
    "App.swift",
    "func handle(token: String) { let y = \"prefix \\(token)\"; sink(y) }\nfunc sink(_ s: String) {}\n",
    "swift.sink",
    "sink"
);
g2_test!(
    g2_go_concat,
    "g2-go",
    "go",
    "main.go",
    "package main\nfunc handle(token string) { y := \"prefix \" + token; sink(y) }\nfunc sink(s string) {}\n",
    "go.sink",
    "sink"
);
g2_test!(g2_rust_format, "g2-rs", "rust", "app.rs",
    "pub fn handle(token: String) { let y = format!(\"prefix {}\", token); sink(y); }\npub fn sink(_s: String) {}\n",
    "rs.sink", "sink");
g2_test!(g2_csharp_interp, "g2-cs", "csharp", "App.cs",
    "class App { void Handle(string token) { string y = $\"x {token}\"; Sink(y); } void Sink(string s) {} }\n",
    "cs.sink", "Sink");
g2_test!(
    g2_php_concat,
    "g2-php",
    "php",
    "app.php",
    "<?php\nfunction handle($token) { $y = \"prefix $token\"; sink($y); }\nfunction sink($s) {}\n",
    "php.sink",
    "sink"
);
g2_test!(
    g2_dart_interp,
    "g2-dart",
    "dart",
    "app.dart",
    "void handle(String token) { var y = 'prefix $token'; sink(y); }\nvoid sink(String s) {}\n",
    "dart.sink",
    "sink"
);
g2_test!(
    g2_lua_concat,
    "g2-lua",
    "lua",
    "app.lua",
    "local function handle(token) local y = \"prefix \" .. token; sink(y) end\nfunction sink(s) end\n",
    "lua.sink",
    "sink"
);
g2_test!(
    g2_perl_interp,
    "g2-pl",
    "perl",
    "app.pl",
    "sub handle { my ($token) = @_; my $y = \"prefix $token\"; sink($y); }\nsub sink {}\n1;\n",
    "pl.sink",
    "sink"
);

// G2 strict coverage extension — adapter RHS-operand extraction must
// surface bare identifiers for concat / interpolation across every
// remaining lang.
g2_test!(g2_c_concat, "g2-c", "c", "app.c",
    "void sink(const char* s);\nvoid handle(const char* token) { const char* buf = token ? token : \"\"; sink(buf); }\n",
    "c.sink", "sink");
g2_test!(g2_cpp_concat, "g2-cpp", "cpp", "app.cpp",
    "#include <string>\nvoid sink(const std::string&);\nvoid handle(const std::string& token) { std::string s = std::string(\"prefix \") + token; sink(s); }\n",
    "cpp.sink", "sink");
#[test]
fn g2_objc_concat() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("g2-objc");
    let rules = write_sink_rule(&tmp, "objc", "objc.sink", "sink");
    write_call_result_passthrough_rule(
        &tmp,
        "objc",
        "objc.passthrough.nsstring_format",
        "NSString.stringWithFormat",
        &[1],
    );
    write_fixture(
        &tmp,
        "App.m",
        "#import <Foundation/Foundation.h>\nvoid sink(NSString* s);\nvoid handle(NSString* token) { NSString* s = [NSString stringWithFormat:@\"prefix %@\", token]; sink(s); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "G2 (objc): NSString.stringWithFormat passthrough must propagate formatted input"
    );
    cleanup(&tmp);
}
g2_test!(g2_elixir_interp, "g2-ex", "elixir", "app.ex",
    "defmodule App do\n  def handle(token) do\n    y = \"prefix \" <> token\n    sink(y)\n  end\n  def sink(_), do: :ok\nend\n",
    "ex.sink", "sink");
g2_test!(g2_erlang_concat, "g2-erl", "erlang", "app.erl",
    "-module(app).\n-export([handle/1, sink/1]).\nhandle(Token) -> Y = [\"prefix \", Token], sink(Y).\nsink(_) -> ok.\n",
    "erl.sink", "sink");

// ===========================================================================
// G9 — Destructuring / pattern-match LHS: taint propagates to every
// destructured binding name when the RHS carries taint.
// ===========================================================================

macro_rules! g9_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G9 ({}): destructuring LHS must inherit RHS taint",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

/// G9 variants for destructuring / multi-bind syntax across the
/// remaining language set. These used to be no-crash probes; they now
/// assert the semantic contract that every destructured binding gets
/// RHS taint when the RHS is tainted.
macro_rules! g9_best_effort_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G9 ({}): destructuring LHS must inherit RHS taint",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

g9_test!(
    g9_python_tuple,
    "g9-py",
    "python",
    "app.py",
    "def handle(data):\n    a, b = data\n    sink(b)\n\ndef sink(s): pass\n",
    "py.sink",
    "sink"
);
g9_test!(
    g9_javascript_object,
    "g9-js",
    "javascript",
    "app.js",
    "function handle(data) { const { token } = data; sink(token); }\nfunction sink(s) {}\n",
    "js.sink",
    "sink"
);
g9_test!(g9_typescript_array, "g9-ts", "typescript", "app.ts",
    "function handle(data: string[]): void { const [a, b] = data; sink(b); }\nfunction sink(s: string): void {}\n",
    "ts.sink", "sink");
g9_best_effort_test!(
    g9_ruby_multiassign,
    "g9-rb",
    "ruby",
    "app.rb",
    "def handle(data); a, b = data; sink(b); end\ndef sink(s); end\n",
    "rb.sink",
    "sink"
);
g9_best_effort_test!(
    g9_php_list,
    "g9-php",
    "php",
    "app.php",
    "<?php\nfunction handle($data) { [$a, $b] = $data; sink($b); }\nfunction sink($s) {}\n",
    "php.sink",
    "sink"
);
g9_best_effort_test!(g9_go_multireturn, "g9-go", "go", "main.go",
    "package main\nfunc split(data string) (string, string) { return \"\", data }\nfunc handle(token string) { _, b := split(token); sink(b) }\nfunc sink(s string) {}\n",
    "go.sink", "sink");
g9_best_effort_test!(
    g9_rust_tuple,
    "g9-rust",
    "rust",
    "app.rs",
    "fn handle(data: (String, String)) { let (_a, b) = data; sink(&b); }\nfn sink(s: &str) {}\n",
    "rust.sink",
    "sink"
);
g9_best_effort_test!(
    g9_kotlin_destructure,
    "g9-kt",
    "kotlin",
    "App.kt",
    "fun handle(data: Pair<String, String>) { val (_, b) = data; sink(b) }\nfun sink(s: String) {}\n",
    "kt.sink",
    "sink"
);
g9_best_effort_test!(
    g9_swift_tuple,
    "g9-swift",
    "swift",
    "App.swift",
    "func handle(_ data: (String, String)) { let (_, b) = data; sink(b) }\nfunc sink(_ s: String) {}\n",
    "swift.sink",
    "sink"
);
g9_best_effort_test!(g9_elixir_tuple, "g9-ex", "elixir", "app.ex",
    "defmodule App do\n  def handle(data) do\n    {_a, b} = data\n    sink(b)\n  end\n  def sink(_), do: :ok\nend\n",
    "ex.sink", "sink");
g9_best_effort_test!(
    g9_erlang_tuple,
    "g9-erl",
    "erlang",
    "app.erl",
    "-module(app).\n-export([handle/1, sink/1]).\nhandle(Data) -> {_, B} = Data, sink(B).\nsink(_) -> ok.\n",
    "erl.sink",
    "sink"
);
g9_best_effort_test!(
    g9_dart_pattern,
    "g9-dart",
    "dart",
    "app.dart",
    "void handle(List<String> data) { final token = data[0]; sink(token); }\nvoid sink(String s) {}\n",
    "dart.sink",
    "sink"
);

// ===========================================================================
// G3 — Single-method field taint: write + read inside one method body.
// Covers the adapter's qualified-Assign emission across languages.
// ===========================================================================

macro_rules! g3_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G3 ({}): same-method qualified write+read must fire",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

/// G3 variant for native-compiled / typed OOP languages. These used
/// to be best-effort while adapters filled in qualified-Assign
/// emission; the assignment-chain and receiver-type audits now require
/// field flow for every listed language, so keep these as hard
/// regression checks too.
macro_rules! g3_best_effort_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G3 ({}): same-method qualified write+read must fire",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

g3_test!(g3_ts_single, "g3-ts", "typescript", "App.ts",
    "class R { handle(token: string): void { this.cmd = token; sink(this.cmd); } cmd: string = ''; }\nfunction sink(s: string): void {}\n",
    "ts.sink", "sink");
g3_test!(
    g3_ruby_single,
    "g3-rb",
    "ruby",
    "app.rb",
    "class R\n  def handle(token)\n    @cmd = token\n    sink(@cmd)\n  end\nend\n\ndef sink(s); end\n",
    "rb.sink",
    "sink"
);
g3_test!(g3_php_single, "g3-php", "php", "app.php",
    "<?php\nclass R { public $cmd; function handle($token) { $this->cmd = $token; sink($this->cmd); } }\nfunction sink($s) {}\n",
    "php.sink", "sink");
g3_test!(g3_python_single, "g3-py", "python", "app.py",
    "class R:\n    def handle(self, token):\n        self.cmd = token\n        sink(self.cmd)\n\ndef sink(s): pass\n",
    "py.sink", "sink");
g3_test!(
    g3_js_single,
    "g3-js",
    "javascript",
    "app.js",
    "class R { handle(token) { this.cmd = token; sink(this.cmd); } }\nfunction sink(s) {}\n",
    "js.sink",
    "sink"
);
g3_best_effort_test!(g3_java_single, "g3-java", "java", "App.java",
    "class R { String cmd; void handle(String token) { this.cmd = token; sink(this.cmd); } void sink(String s) {} }\n",
    "java.sink", "sink");
g3_best_effort_test!(g3_kotlin_single, "g3-kt", "kotlin", "App.kt",
    "class R { var cmd: String = \"\"\n fun handle(token: String) { this.cmd = token; sink(this.cmd) }\n fun sink(s: String) {} }\n",
    "kt.sink", "sink");
g3_best_effort_test!(g3_scala_single, "g3-scala", "scala", "App.scala",
    "class R { var cmd: String = \"\"\n def handle(token: String): Unit = { this.cmd = token; sink(this.cmd) }\n def sink(s: String): Unit = {} }\n",
    "scala.sink", "sink");
g3_best_effort_test!(g3_csharp_single, "g3-cs", "csharp", "App.cs",
    "class R { public string cmd; public void Handle(string token) { this.cmd = token; Sink(this.cmd); } public void Sink(string s) {} }\n",
    "cs.sink", "Sink");
g3_best_effort_test!(g3_swift_single, "g3-swift", "swift", "App.swift",
    "class R { var cmd: String = \"\"\n func handle(_ token: String) { self.cmd = token; sink(self.cmd) }\n func sink(_ s: String) {} }\n",
    "swift.sink", "sink");
g3_best_effort_test!(g3_go_single, "g3-go", "go", "app.go",
    "package main\ntype R struct { Cmd string }\nfunc (r *R) Handle(token string) { r.Cmd = token; sink(r.Cmd) }\nfunc sink(s string) {}\n",
    "go.sink", "sink");
g3_best_effort_test!(g3_rust_single, "g3-rust", "rust", "app.rs",
    "struct R { cmd: String }\nimpl R {\n  fn handle(&mut self, token: &str) { self.cmd = token.to_string(); sink(&self.cmd); }\n}\nfn sink(s: &str) {}\n",
    "rust.sink", "sink");
g3_best_effort_test!(g3_cpp_single, "g3-cpp", "cpp", "app.cpp",
    "#include <string>\nvoid sink(const std::string& s);\nclass R { public: std::string cmd;\n  void handle(const std::string& token) { this->cmd = token; sink(this->cmd); }\n};\n",
    "cpp.sink", "sink");
g3_best_effort_test!(g3_dart_single, "g3-dart", "dart", "app.dart",
    "class R { String cmd = '';\n void handle(String token) { this.cmd = token; sink(this.cmd); }\n void sink(String s) {} }\n",
    "dart.sink", "sink");

// ===========================================================================
// G3 cross-method: write in one method, read in a sibling — per lang.
// ===========================================================================

macro_rules! g3_cross_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G3 cross-method ({}): sibling-field read must fire",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

g3_cross_test!(g3x_typescript, "g3x-ts", "typescript", "App.ts",
    "class R { cmd: string = ''; constructor(token: string) { this.cmd = token; } run(): void { sink(this.cmd); } }\nfunction sink(s: string): void {}\n",
    "ts.sink", "sink");
g3_cross_test!(g3x_ruby, "g3x-rb", "ruby", "app.rb",
    "class R\n  def initialize(token); @cmd = token; end\n  def run; sink(@cmd); end\nend\ndef sink(s); end\n",
    "rb.sink", "sink");
g3_cross_test!(g3x_php, "g3x-php", "php", "app.php",
    "<?php\nclass R { public $cmd; function __construct($token) { $this->cmd = $token; } function run() { sink($this->cmd); } }\nfunction sink($s) {}\n",
    "php.sink", "sink");

// ===========================================================================
// G7 — HOF callback per language. Receiver-tainted + named callback.
// ===========================================================================

macro_rules! g7_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G7 ({}): HOF callback must inherit receiver taint",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

/// G7 variants for higher-order callbacks across the remaining
/// language set. These used to be best-effort while callable-reference
/// links were being filled in; they now assert that callback parameters
/// inherit receiver/collection taint.
macro_rules! g7_best_effort_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            assert!(
                flows_count(&tmp, &rules) >= 1,
                "G7 ({}): HOF callback must inherit receiver taint",
                $lang,
            );
            cleanup(&tmp);
        }
    };
}

g7_test!(g7_ts_foreach, "g7-ts", "typescript", "app.ts",
    "function step(item: string): void { sink(item); }\nfunction handle(items: string[]): void { items.forEach(step); }\nfunction sink(s: string): void {}\n",
    "ts.sink", "sink");
g7_test!(
    g7_ruby_each,
    "g7-rb",
    "ruby",
    "app.rb",
    "def step(item); sink(item); end\ndef handle(items); items.each(&method(:step)); end\ndef sink(s); end\n",
    "rb.sink",
    "sink"
);
g7_test!(g7_kotlin_foreach, "g7-kt", "kotlin", "App.kt",
    "fun step(item: String) { sink(item) }\nfun handle(items: List<String>) { items.forEach(::step) }\nfun sink(s: String) {}\n",
    "kt.sink", "sink");
g7_test!(g7_scala_foreach, "g7-scala", "scala", "App.scala",
    "object App { def step(item: String): Unit = sink(item)\ndef handle(items: Seq[String]): Unit = items.foreach(step)\ndef sink(s: String): Unit = () }\n",
    "scala.sink", "sink");

// Additional G7 HOF coverage — extend across remaining langs.
g7_best_effort_test!(g7_go_foreach, "g7-go", "go", "app.go",
    "package main\nfunc step(item string) { sink(item) }\nfunc handle(items []string) { for _, x := range items { step(x) } }\nfunc sink(s string) {}\n",
    "go.sink", "sink");
g7_best_effort_test!(g7_java_foreach, "g7-java", "java", "App.java",
    "import java.util.List;\nclass App { static void step(String item) { sink(item); } static void handle(List<String> items) { items.forEach(App::step); } static void sink(String s) {} }\n",
    "java.sink", "sink");
g7_best_effort_test!(g7_csharp_foreach, "g7-cs", "csharp", "App.cs",
    "using System.Collections.Generic; using System.Linq;\nclass App { static void Step(string item) { Sink(item); } static void Handle(List<string> items) { items.ForEach(Step); } static void Sink(string s) {} }\n",
    "cs.sink", "Sink");
g7_best_effort_test!(g7_swift_foreach, "g7-swift", "swift", "app.swift",
    "func step(_ item: String) { sink(item) }\nfunc handle(_ items: [String]) { items.forEach(step) }\nfunc sink(_ s: String) {}\n",
    "swift.sink", "sink");
g7_best_effort_test!(g7_rust_iter, "g7-rust", "rust", "app.rs",
    "fn step(item: &str) { sink(item); }\nfn handle(items: &[String]) { items.iter().for_each(|i| step(i)); }\nfn sink(s: &str) {}\n",
    "rust.sink", "sink");
g7_best_effort_test!(g7_php_array_walk, "g7-php", "php", "app.php",
    "<?php\nfunction step($item) { sink($item); }\nfunction handle($items) { array_walk($items, 'step'); }\nfunction sink($s) {}\n",
    "php.sink", "sink");
g7_best_effort_test!(g7_dart_foreach, "g7-dart", "dart", "app.dart",
    "void step(String item) { sink(item); }\nvoid handle(List<String> items) { items.forEach(step); }\nvoid sink(String s) {}\n",
    "dart.sink", "sink");
g7_best_effort_test!(g7_cpp_foreach, "g7-cpp", "cpp", "app.cpp",
    "#include <vector>\n#include <string>\n#include <algorithm>\nvoid sink(const std::string& s);\nvoid step(const std::string& item) { sink(item); }\nvoid handle(std::vector<std::string> items) { std::for_each(items.begin(), items.end(), step); }\n",
    "cpp.sink", "sink");
g7_best_effort_test!(g7_perl_map, "g7-perl", "perl", "app.pl",
    "sub step { my ($item) = @_; sink($item); }\nsub handle { my @items = @_; map { step($_); } @items; }\nsub sink { my ($s) = @_; }\n",
    "perl.sink", "sink");

// ===========================================================================
// G8 — throw/catch taint. Covered for grammars that surface both
// `value_name` on Throw and `catch_param` on Try.
// ===========================================================================

/// Assert-mode G8: throw-catch exception flow MUST produce a finding —
/// the adapter now populates `value_name` on Throw and `catch_param`
/// on Try, so taint flows `throw token → catch (e) → sink(e)`.
macro_rules! g8_test {
    ($name:ident, $tag:expr, $lang:expr, $file:expr, $contents:expr, $rule_id:expr, $sink:expr) => {
        #[test]
        fn $name() {
            let Some(_) = bin_path() else { return };
            let tmp = fresh_tmp($tag);
            let rules = write_sink_rule(&tmp, $lang, $rule_id, $sink);
            write_fixture(&tmp, $file, $contents);
            let count = flows_count(&tmp, &rules);
            assert!(
                count >= 1,
                "[{}] g8 exception flow did not produce a finding — adapter may not be populating `value_name` on Throw or `catch_param` on Try",
                $lang
            );
            cleanup(&tmp);
        }
    };
}

g8_test!(g8_python_throw, "g8-py", "python", "app.py",
    "def handle(token):\n    try:\n        raise token\n    except Exception as e:\n        sink(e)\n\ndef sink(s): pass\n",
    "py.sink", "sink");
g8_test!(g8_ts_throw, "g8-ts", "typescript", "app.ts",
    "function handle(token: string): void { try { throw token; } catch (e) { sink(e); } }\nfunction sink(s: unknown): void {}\n",
    "ts.sink", "sink");
g8_test!(g8_php_throw, "g8-php", "php", "app.php",
    "<?php\nfunction handle($token) { try { throw new Exception($token); } catch (Exception $e) { sink($e->getMessage()); } }\nfunction sink($s) {}\n",
    "php.sink", "sink");
g8_test!(
    g8_ruby_throw,
    "g8-rb",
    "ruby",
    "app.rb",
    "def handle(token)\n  begin\n    raise token\n  rescue => e\n    sink(e)\n  end\nend\ndef sink(s); end\n",
    "rb.sink",
    "sink"
);
g8_test!(g8_java_throw, "g8-java", "java", "App.java",
    "class App { void handle(String token) throws Exception { try { throw new RuntimeException(token); } catch (Exception e) { sink(e.getMessage()); } } void sink(String s) {} }\n",
    "java.sink", "sink");

// Additional g8 coverage — extend across the full language matrix.
g8_test!(
    g8_js_throw,
    "g8-js",
    "javascript",
    "app.js",
    "function handle(token) { try { throw token; } catch (e) { sink(e); } }\nfunction sink(s) {}\n",
    "js.sink",
    "sink"
);
g8_test!(g8_kotlin_throw, "g8-kt", "kotlin", "App.kt",
    "fun handle(token: String) { try { throw RuntimeException(token) } catch (e: Exception) { sink(e.message ?: \"\") } }\nfun sink(s: String) {}\n",
    "kt.sink", "sink");
g8_test!(g8_csharp_throw, "g8-cs", "csharp", "App.cs",
    "class App { void Handle(string token) { try { throw new System.Exception(token); } catch (System.Exception e) { Sink(e.Message); } }\n void Sink(string s) {} }\n",
    "cs.sink", "Sink");
g8_test!(g8_scala_throw, "g8-scala", "scala", "App.scala",
    "object App { def handle(token: String): Unit = { try { throw new RuntimeException(token) } catch { case e: Exception => sink(e.getMessage) } }\n def sink(s: String): Unit = {} }\n",
    "scala.sink", "sink");
g8_test!(g8_swift_throw, "g8-swift", "swift", "App.swift",
    "enum AppError: Error { case boom(String) }\nfunc handle(_ token: String) throws { do { throw AppError.boom(token) } catch let e { sink(\"\\(e)\") } }\nfunc sink(_ s: String) {}\n",
    "swift.sink", "sink");
g8_test!(g8_dart_throw, "g8-dart", "dart", "app.dart",
    "void handle(String token) { try { throw Exception(token); } catch (e) { sink(e.toString()); } }\nvoid sink(String s) {}\n",
    "dart.sink", "sink");
g8_test!(g8_cpp_throw, "g8-cpp", "cpp", "app.cpp",
    "#include <stdexcept>\nvoid sink(const char* s);\nvoid handle(const char* token) { try { throw std::runtime_error(token); } catch (const std::exception& e) { sink(e.what()); } }\n",
    "cpp.sink", "sink");
g8_test!(g8_perl_throw, "g8-perl", "perl", "app.pl",
    "sub handle { my $token = shift; eval { die $token; }; if ($@) { my $e = $@; sink($e); } }\nsub sink { my ($s) = @_; }\n",
    "perl.sink", "sink");

// ===========================================================================
// Variable indirection into real-world sink shapes. These document that
// `x = expression(user); sink(x)` is handled by the engine/security wrapper;
// shipped rulepack misses for these forms should be fixed in rules, not here.
// ===========================================================================

#[test]
fn indirection_js_sql_concat_variable_to_pool_query() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("indir-js-sql");
    let rules = write_sink_rule(&tmp, "javascript", "js.sql", "pool.query");
    write_fixture(
        &tmp,
        "app.js",
        "function handle(term) { const sql = 'SELECT * FROM bookings WHERE code = ' + term; pool.query(sql); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "JS SQL: concat-assigned variable must carry taint into pool.query(sql)"
    );
    cleanup(&tmp);
}

#[test]
fn indirection_python_joined_path_variable_to_open() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("indir-py-path");
    let rules = write_sink_rule(&tmp, "python", "py.open", "open");
    write_call_result_passthrough_rule(
        &tmp,
        "python",
        "python.passthrough.os_path_join",
        "os.path.join",
        &[0, 1],
    );
    write_fixture(
        &tmp,
        "app.py",
        "import os\n\ndef handle(base, name):\n    path = os.path.join(base, name)\n    open(path)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "Python path: os.path.join(..., name) assigned to path must reach open(path)"
    );
    cleanup(&tmp);
}

#[test]
fn indirection_python_xpath_expression_variable_to_select() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("indir-py-xpath");
    let rules = write_sink_rule(&tmp, "python", "py.xpath", "xpath.select");
    write_fixture(
        &tmp,
        "app.py",
        "def handle(xpath, name, doc):\n    expr = '//' + name\n    xpath.select(expr, doc)\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "Python XPath: concat-assigned expr must reach xpath.select(expr, doc)"
    );
    cleanup(&tmp);
}

#[test]
fn indirection_js_wrapper_return_variable_to_html_response_sink() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("indir-js-html");
    let rules = write_sink_rule(&tmp, "javascript", "js.html", "res.send");
    write_fixture(
        &tmp,
        "app.js",
        "function render(name) { return '<b>' + name + '</b>'; }\nfunction handle(name, res) { const html = render(name); res.send(html); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "JS HTML: wrapper return assigned to html must reach res.send(html)"
    );
    cleanup(&tmp);
}

#[test]
fn indirection_ts_graphql_resolver_dispatch_args_to_helper_sink() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("indir-ts-gql");
    let rules = write_sink_rule(&tmp, "typescript", "ts.sink", "sink");
    write_fixture(
        &tmp,
        "resolvers.ts",
        "import { dispatch } from './dispatch';\nexport const resolvers = { Query: { bookings: (_root: unknown, args: { filter: string }) => dispatch(args) } };\n",
    );
    write_fixture(
        &tmp,
        "dispatch.ts",
        "import { searchBookings } from './db/bookings';\nexport function dispatch(args: { filter: string }): void { searchBookings(args.filter); }\n",
    );
    fs::create_dir_all(tmp.join("db")).expect("mkdir db");
    write_fixture(
        &tmp,
        "db/bookings.ts",
        "export function searchBookings(filter: string): void { sink(filter); }\n",
    );
    assert!(
        flows_count(&tmp, &rules) >= 1,
        "TS GraphQL: resolver args must dispatch through helper to sink"
    );
    cleanup(&tmp);
}

// ===========================================================================
// Alias resolution per language — import destructures,
// var-reassignment chains, receiver-bound namespaces.
// ===========================================================================

#[test]
fn alias_js_destructured_require() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("alias-js");
    let rules = write_sink_rule(&tmp, "javascript", "js.cmdi", "exec");
    write_fixture(
        &tmp,
        "app.js",
        "const { exec } = require(\"child_process\");\nfunction handle(cmd) { exec(cmd); }\n",
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "Destructured `const {{ exec }} = require(\"child_process\")` must match"
    );
    cleanup(&tmp);
}

#[test]
fn alias_python_from_import() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("alias-py");
    let rules = write_sink_rule(&tmp, "python", "py.sys", "system");
    write_fixture(
        &tmp,
        "app.py",
        "from os import system\ndef handle(cmd):\n    system(cmd)\n",
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "Python `from os import system` must match"
    );
    cleanup(&tmp);
}

#[test]
fn alias_js_var_reassignment_chain() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("alias-jshop");
    let rules = write_sink_rule(&tmp, "javascript", "js.cmdi", "exec");
    write_fixture(
        &tmp,
        "app.js",
        "const { exec } = require(\"child_process\");\nfunction handle(cmd) { const fn = exec; const alias = fn; alias(cmd); }\n",
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "Multi-hop var reassignment `fn = exec; alias = fn` must preserve alias"
    );
    cleanup(&tmp);
}

#[test]
fn alias_python_var_reassignment_chain() {
    let Some(_) = bin_path() else { return };
    let tmp = fresh_tmp("alias-pyhop");
    let rules = write_sink_rule(&tmp, "python", "py.sys", "system");
    write_fixture(
        &tmp,
        "app.py",
        "from os import system\ndef handle(cmd):\n    fn = system\n    alias = fn\n    alias(cmd)\n",
    );
    assert!(
        sinks_count(&tmp, &rules) >= 1,
        "Python multi-hop reassignment must preserve alias"
    );
    cleanup(&tmp);
}
