//! Callback / higher-order flow audit — per-language stress test
//! that taint propagates through function values passed as
//! arguments.
//!
//! Each fixture under `examples/<lang>/callback_flow/` has:
//!
//!   `pass_to_callback()`:
//!     t = source()
//!     run(executor, t)         // callback `executor` invoked with `t`
//!     # `executor` runs t through a sink. Engine should connect the
//!     # source to the sink via the callback dispatch.
//!
//! Per `docs/contributing/taint-engine-spec.mdx § Adapter Contract`: adapters
//! expose calls + call args + identifier-shaped values; the engine
//! is responsible for resolving `<callback_arg>(t)` against
//! workspace functions and propagating taint.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("callback_flow");
    if !p.is_dir() {
        return None;
    }
    let has_file = std::fs::read_dir(&p)
        .ok()?
        .any(|e| e.ok().map(|e| e.path().is_file()).unwrap_or(false));
    has_file.then_some(p)
}

fn rules_root() -> PathBuf {
    repo_root().join("security-patterns")
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Expected {
    Pass,
    #[allow(dead_code)]
    Pending,
}

const LANG_TABLE: &[(&str, Expected)] = &[
    ("c", Expected::Pass),
    ("cpp", Expected::Pass),
    ("csharp", Expected::Pass),
    ("dart", Expected::Pass),
    ("elixir", Expected::Pass),
    ("erlang", Expected::Pass),
    ("go", Expected::Pass),
    ("java", Expected::Pass),
    ("javascript", Expected::Pass),
    ("kotlin", Expected::Pass),
    ("lua", Expected::Pass),
    ("objc", Expected::Pass),
    ("perl", Expected::Pass),
    ("php", Expected::Pass),
    ("python", Expected::Pass),
    ("ruby", Expected::Pass),
    ("rust", Expected::Pass),
    ("scala", Expected::Pass),
    ("solidity", Expected::Pass),
    ("swift", Expected::Pass),
    ("typescript", Expected::Pass),
];

fn run_taint_for(lang: &str) -> Result<bonsai_security::TaintAnalysisReport, String> {
    let ws_root = fixture_root(lang).ok_or_else(|| "missing fixture".to_string())?;
    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules_root()).map_err(|e| format!("rulepack load: {e}"))?;
    let ws = bonsai_workspace::Workspace::index(&ws_root, registry)
        .map_err(|e| format!("index workspace: {e}"))?;
    bonsai_security::run_taint_analysis(&ws, &pack, Default::default())
        .map_err(|e| format!("taint_analysis: {e}"))
}

#[derive(Debug)]
struct Result_ {
    lang: &'static str,
    skipped: Option<String>,
    findings: usize,
}

fn audit_one(lang: &'static str) -> Result_ {
    let report = match run_taint_for(lang) {
        Ok(r) => r,
        Err(reason) => {
            return Result_ {
                lang,
                skipped: Some(reason),
                findings: 0,
            }
        }
    };
    Result_ {
        lang,
        skipped: None,
        findings: report.findings.len(),
    }
}

#[test]
fn callback_flow_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== callback-flow audit ===");
    eprintln!("{:<11} {:>9}  {:<22}  status", "lang", "findings", "expected");
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass",
            Expected::Pending => "Pending",
        };
        let status = if matches!(expected, Expected::Pending) {
            "skipped (pending)"
        } else if r.skipped.is_some() {
            "fixture missing"
        } else {
            match (expected, r.findings) {
                (Expected::Pass, n) if n >= 1 => "ok",
                (Expected::Pass, _) => "REGRESSION: callback flow not connected",
                (Expected::Pending, _) => unreachable!(),
            }
        };
        eprintln!("{:<11} {:>9}  {:<22}  {status}", r.lang, r.findings, exp);
    }

    let regressions: Vec<String> = results
        .iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pending => None,
            Expected::Pass => {
                if r.skipped.is_some() {
                    Some(format!("{}: fixture missing", r.lang))
                } else if r.findings == 0 {
                    Some(format!("{}: callback flow not connected", r.lang))
                } else {
                    None
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("callback-flow audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

/// Regression: an arrow function that is an object-literal property
/// value INSIDE a call argument — e.g. a Hapi config-object route
/// handler `server.route({ handler: (request) => { ... } })`, or a
/// callback stored in an array/config literal — must have its body
/// analyzed. Previously `lambda_is_inlined_call_argument` saw the
/// enclosing call and skipped the arrow from Pass-2b decl synthesis,
/// while the direct-call-argument inliner never descended into the
/// object literal — so the handler body (and every source/sink inside
/// it) was invisible. (WS3 framework inline/object-literal handler gap.)
#[test]
fn object_config_route_handler_body_is_analyzed() {
    let dir = std::env::temp_dir().join("bonsai_objcfg_handler_audit");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(
        dir.join("m.js"),
        "const cp = require('child_process');\n\
         const Hapi = require('@hapi/hapi');\n\
         server.route({ method: 'GET', path: '/x', handler: (request, h) => { cp.exec(request.query.q); } });\n",
    )
    .expect("write");
    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack");
    let ws = bonsai_workspace::Workspace::index(&dir, registry).expect("index");
    let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("taint");
    let n = report.findings.len();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        n >= 1,
        "Hapi object-config route handler body must be analyzed (request.query -> cp.exec), got {n} findings"
    );
}

/// WS3 coercion passthrough (Go). A Go type conversion `string(b)` /
/// `string([]byte(input))` changes representation but preserves
/// attacker-controlled content — the analogue of Python `str()`/`bytes()`
/// (which are registered passthrough). Before `go.passthrough.string_conversion`
/// the `string(...)` conversion-call dropped taint, so
/// `x := string([]byte(input)); exec.Command(x)` did not fire while the
/// direct `exec.Command(input)` did. (`[]byte(x)` assignments already
/// propagate via the adapter; only the `string(...)` call needed a rule.)
#[test]
fn go_string_conversion_preserves_taint() {
    let dir = std::env::temp_dir().join("bonsai_go_string_conv_audit");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(
        dir.join("m.go"),
        "package main\n\
         import \"os/exec\"\n\
         func h(input string) {\n\
         \tx := string([]byte(input))\n\
         \texec.Command(x)\n\
         }\n",
    )
    .expect("write");
    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack");
    let ws = bonsai_workspace::Workspace::index(&dir, registry).expect("index");
    let report = bonsai_security::run_taint_analysis(
        &ws,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("taint");
    let n = report.findings.len();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        n >= 1,
        "Go `string([]byte(input))` must preserve taint into exec.Command, got {n} findings"
    );
}

/// WS3 coercion passthrough (Lua / Elixir). `tostring(v)` (Lua) and
/// `to_string(term)` (Elixir) change representation but preserve
/// attacker-controlled content — the analogues of Python `str()` / Go
/// `string()`. Before `lua.passthrough.tostring` /
/// `elixir.sanitizer.passthrough.to_string` these coercion calls dropped
/// taint. (Numeric `tonumber` stays non-passthrough, like `int()`.)
#[test]
fn lua_tostring_preserves_taint() {
    assert!(
        coercion_findings("lua", "lua", "function h(input) os.execute(tostring(input)) end\n") >= 1,
        "Lua tostring(input) must preserve taint into os.execute"
    );
}

#[test]
fn elixir_to_string_preserves_taint() {
    let src = "defmodule App do\n  def h(input), do: System.cmd(to_string(input), [])\nend\n";
    assert!(
        coercion_findings("elixir", "ex", src) >= 1,
        "Elixir to_string(input) must preserve taint into System.cmd"
    );
}

/// WS3 conditional reassignment (Elixir engine fix). The INLINE keyword-list
/// conditional `cmd = if flag, do: input, else: ""` bound to a variable used to
/// drop taint (only the multi-line `do ... end` block form and the
/// conditional-as-direct-call-arg form propagated). `elixir_do_else_body` now
/// also parses the inline `do:`/`else:` form so its branch values flow to the LHS.
#[test]
fn elixir_inline_keyword_conditional_preserves_taint() {
    let src = "defmodule App do\n  def h(input, flag) do\n    cmd = if flag, do: input, else: \"\"\n    System.shell(cmd)\n  end\nend\n";
    assert!(
        coercion_findings("elixir_inline_if", "ex", src) >= 1,
        "Elixir inline `if flag, do: input` reassignment must preserve taint into System.shell"
    );
    // No-tainted-branch control must NOT produce a finding (no false positive).
    let safe = "defmodule App do\n  def h(flag) do\n    cmd = if flag, do: \"safe\", else: \"ok\"\n    System.shell(cmd)\n  end\nend\n";
    assert_eq!(
        coercion_findings("elixir_inline_if_safe", "ex", safe),
        0,
        "Elixir inline if with only literal branches must not create a finding"
    );
}

/// WS3 free-function string coercion. The method/operator coercion forms already
/// propagated, but the free-function/module forms dropped taint until the
/// per-language audit added these passthroughs. (js/ts `String(p)` failed
/// specifically when used INLINE as a sink arg.)
#[test]
fn free_function_string_coercion_preserves_taint() {
    // scala String.valueOf (mirrors java)
    let scala = "object App {\n  def h(input: String): Unit = {\n    val v = String.valueOf(input)\n    Runtime.getRuntime().exec(v)\n  }\n}\n";
    assert!(
        coercion_findings("scala_valueof", "scala", scala) >= 1,
        "scala String.valueOf(input) must preserve taint"
    );
    // rust String::from (.to_string()/format! already worked)
    let rust = "use std::process::Command;\nfn run(p: &str) {\n    Command::new(String::from(p));\n}\n";
    assert!(
        coercion_findings("rust_string_from", "rs", rust) >= 1,
        "rust String::from(p) must preserve taint"
    );
    // erlang lists:flatten (the os:cmd(lists:flatten(io_lib:format(...))) idiom)
    let erlang = "-module(example).\n-export([test/1]).\ntest(Input) ->\n  S = lists:flatten(io_lib:format(\"~s\", [Input])),\n  os:cmd(S).\n";
    assert!(
        coercion_findings("erlang_flatten", "erl", erlang) >= 1,
        "erlang lists:flatten(io_lib:format(...)) must preserve taint"
    );
    // ruby Kernel String() (x.to_s already worked)
    let ruby = "def example(input)\n  system(String(input))\nend\n";
    assert!(
        coercion_findings("ruby_string", "rb", ruby) >= 1,
        "ruby system(String(input)) must preserve taint"
    );
    // js/ts String() used INLINE as a sink argument
    let js = "const child_process = require(\"child_process\");\nfunction demo(input) {\n  return child_process.exec(String(input));\n}\n";
    assert!(
        coercion_findings("js_string", "js", js) >= 1,
        "js exec(String(input)) inline must preserve taint"
    );
    let ts = "const child_process = require(\"child_process\");\nfunction demo(input: string) {\n  return child_process.exec(String(input));\n}\n";
    assert!(
        coercion_findings("ts_string", "ts", ts) >= 1,
        "ts exec(String(input)) inline must preserve taint"
    );
}

fn coercion_findings(tag: &str, ext: &str, src: &str) -> usize {
    let dir = std::env::temp_dir().join(format!("bonsai_coercion_{tag}_audit"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join(format!("m.{ext}")), src).expect("write");
    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack");
    let ws = bonsai_workspace::Workspace::index(&dir, registry).expect("index");
    let report = bonsai_security::run_taint_analysis(
        &ws,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("taint");
    let n = report.findings.len();
    let _ = std::fs::remove_dir_all(&dir);
    n
}

/// WS3 coercion passthrough (Erlang). `binary_to_list(B)` /
/// `unicode:characters_to_list(Data)` change representation but preserve
/// attacker-controlled content — the analogues of Python `str()` / Go
/// `string()`. Before `erlang.passthrough.binary_to_list` /
/// `erlang.passthrough.unicode_characters_to_list` these dropped taint.
/// (Numeric `integer_to_list` stays non-passthrough, like `int()`. Swift
/// `String(...)` is intentionally NOT registered — too generic a callee;
/// see the note in swift/sanitizers/all.yml.)
#[test]
fn erlang_binary_to_list_preserves_taint() {
    assert!(
        coercion_findings("erlang_b2l", "erl", "h(Input) -> os:cmd(binary_to_list(Input)).\n") >= 1,
        "Erlang binary_to_list(Input) must preserve taint into os:cmd"
    );
    assert!(
        coercion_findings("erlang_c2l", "erl", "h(Input) -> os:cmd(unicode:characters_to_list(Input)).\n") >= 1,
        "Erlang unicode:characters_to_list(Input) must preserve taint into os:cmd"
    );
}

/// WS3 module-function-return passthrough (base64 decode). Decoding a
/// base64 payload changes representation but preserves attacker-controlled
/// content — the goal's "module-function returns not propagated
/// (base64.*decode)". Probed across langs: python `base64.b64decode` and
/// js `Buffer.from(x,'base64')` already passed; php `base64_decode`, ruby
/// `Base64.decode64`, js/ts `atob` dropped taint → added passthrough rules.
#[test]
fn base64_decode_preserves_taint_across_langs() {
    assert!(
        coercion_findings("php_b64", "php", "<?php\nfunction h($input){ system(base64_decode($input)); }\n") >= 1,
        "PHP base64_decode must preserve taint"
    );
    assert!(
        coercion_findings("ruby_b64", "rb", "require 'base64'\ndef h(input)\n  system(Base64.decode64(input))\nend\n") >= 1,
        "Ruby Base64.decode64 must preserve taint"
    );
    assert!(
        coercion_findings("js_atob", "js", "const cp=require('child_process')\nfunction h(input){ cp.exec(atob(input)) }\n") >= 1,
        "JS atob must preserve taint"
    );
    assert!(
        coercion_findings("ts_atob", "ts", "const cp=require('child_process')\nfunction h(input: string){ cp.exec(atob(input)) }\n") >= 1,
        "TS atob must preserve taint"
    );
}

/// WS3 module-function-return passthrough (JSON parse). Parsing an
/// attacker JSON string yields an attacker-controlled value — the goal's
/// "module-function returns not propagated (json.loads)". Python
/// `json.loads` already passed; php `json_decode`, ruby/js/ts `JSON.parse`
/// dropped taint → added passthrough rules.
#[test]
fn json_parse_preserves_taint_across_langs() {
    assert!(
        coercion_findings("php_json", "php", "<?php\nfunction h($input){ system(json_decode($input)); }\n") >= 1,
        "PHP json_decode must preserve taint"
    );
    assert!(
        coercion_findings("ruby_json", "rb", "require 'json'\ndef h(input)\n  system(JSON.parse(input))\nend\n") >= 1,
        "Ruby JSON.parse must preserve taint"
    );
    assert!(
        coercion_findings("js_json", "js", "const cp=require('child_process')\nfunction h(input){ cp.exec(JSON.parse(input)) }\n") >= 1,
        "JS JSON.parse must preserve taint"
    );
    assert!(
        coercion_findings("ts_json", "ts", "const cp=require('child_process')\nfunction h(input: string){ cp.exec(JSON.parse(input)) }\n") >= 1,
        "TS JSON.parse must preserve taint"
    );
}

/// WS3 comprehension / generator-expression sink analysis. A sink call
/// inside a comprehension must be analyzed and the loop variable tainted
/// from the iterable. The basic list-comp worked, but two shapes missed:
/// (1) a generator expression passed AS a call argument
/// (`any(os.system(t) for t in items)`) — python exposes the genexpr
/// directly as the call's `arguments` field, so it must be walked as a
/// comprehension, not iterated; (2) a NESTED comprehension
/// (`[os.system(t) for row in rows for t in row]`) — the chained
/// bindings must be emitted before the body so taint flows
/// rows -> row -> t. Shared-kit fix (walk_into comprehension handling).
#[test]
fn comprehension_and_generator_sinks_are_analyzed() {
    assert!(
        coercion_findings("py_genexpr_call", "py", "import os\ndef h(items):\n    any(os.system(t) for t in items)\n") >= 1,
        "generator expr as call arg must taint the sink"
    );
    assert!(
        coercion_findings("py_genexpr_list", "py", "import os\ndef h(items):\n    list(os.system(t) for t in items)\n") >= 1,
        "generator expr in list() must taint the sink"
    );
    assert!(
        coercion_findings("py_nested_comp", "py", "import os\ndef h(rows):\n    [os.system(t) for row in rows for t in row]\n") >= 1,
        "nested comprehension must chain rows -> row -> t into the sink"
    );
    // regression: the basic single-clause list comp still fires.
    assert!(
        coercion_findings("py_list_comp", "py", "import os\ndef h(items):\n    [os.system(t) for t in items]\n") >= 1,
        "single-clause list comprehension must still taint the sink"
    );
}

/// WS3 module-return passthrough (hex decode). Hex decoding preserves
/// attacker content (hex string -> bytes), the analogue of base64/json
/// decode. python `binascii.unhexlify` / `bytes.fromhex` and php
/// `hex2bin` dropped taint -> added passthrough rules. (url-decode and
/// querystring-parse already passthrough.)
#[test]
fn hex_decode_preserves_taint_across_langs() {
    assert!(
        coercion_findings("py_unhex", "py", "import os, binascii\ndef h(input):\n    os.system(binascii.unhexlify(input))\n") >= 1,
        "python binascii.unhexlify must preserve taint"
    );
    assert!(
        coercion_findings("py_fromhex", "py", "import os\ndef h(input):\n    os.system(bytes.fromhex(input))\n") >= 1,
        "python bytes.fromhex must preserve taint"
    );
    assert!(
        coercion_findings("php_hex2bin", "php", "<?php\nfunction h($input){ system(hex2bin($input)); }\n") >= 1,
        "php hex2bin must preserve taint"
    );
}

/// WS3 module-return passthrough (safe YAML parse). The SAFE yaml parser
/// (`yaml.safe_load` / `YAML.safe_load`) is NOT a deserialization sink,
/// but it parses attacker YAML into a value that stays attacker-
/// controlled — so taint must flow through it (analogue of json.loads).
/// It had no rule and dropped taint. (The UNSAFE `yaml.load`/`YAML.load`
/// remain deser SINKS — unchanged.)
#[test]
fn yaml_safe_load_preserves_taint() {
    assert!(
        coercion_findings("py_yaml", "py", "import os, yaml\ndef h(input):\n    os.system(yaml.safe_load(input))\n") >= 1,
        "python yaml.safe_load must preserve taint"
    );
    assert!(
        coercion_findings("ruby_yaml", "rb", "require 'yaml'\ndef h(input)\n  system(YAML.safe_load(input))\nend\n") >= 1,
        "ruby YAML.safe_load must preserve taint"
    );
}

/// WS3 module-return passthrough (Go base64, chained-selector callee).
/// `base64.StdEncoding.DecodeString(input)` is a method on a package-var
/// receiver (`base64.StdEncoding` is a `*base64.Encoding`) — a chained
/// selector callee. It returns `([]byte, error)`; the decoded bytes stay
/// attacker-controlled. Keyed via `attribute: [<Encoding>, DecodeString]`
/// (the std-lib `base64` package name can't be a `regex:` receiver — the
/// validator rejects hardcoded lowercase receivers). The multi-return
/// propagates to the first assigned var; `string(b)` carries it onward
/// via go.passthrough.string_conversion.
#[test]
fn go_base64_decodestring_preserves_taint() {
    for enc in ["StdEncoding", "URLEncoding", "RawStdEncoding", "RawURLEncoding"] {
        let src = format!(
            "package main\nimport (\"os/exec\"; \"encoding/base64\")\nfunc h(input string){{ b,_:=base64.{enc}.DecodeString(input); exec.Command(string(b)) }}\n"
        );
        assert!(
            coercion_findings(&format!("go_b64_{enc}"), "go", &src) >= 1,
            "go base64.{enc}.DecodeString must preserve taint into exec.Command"
        );
    }
}
