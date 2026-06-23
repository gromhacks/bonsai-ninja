//! End-to-end tests locking in the `--limit` default on dump
//! commands (`dump-edges`, `dump-callgraph`, `dump-ast`).
//!
//! Without these caps, Redis emits megabytes of output per
//! invocation — dump-edges alone produced ~13 MB / ~3 M tokens
//! before. Each test asserts:
//!
//!   * the command runs without error on a small fixture;
//!   * passing `--limit N` truncates to N rows / files and
//!     prints the same "showing N of TOTAL" notice every
//!     browse command uses;
//!   * `--limit 0` is the explicit opt-out (uncapped);
//!   * `--format json --all` is the explicit exhaustive script
//!     mode; default JSON may page when a result exceeds context.
//!
//! Tests skip silently when the release binary hasn't been built.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    let p = repo_root().join("target/release/bonsai-ninja");
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "skipping dump-limits test: release binary not built ({})",
            p.display()
        );
        None
    }
}

fn ws() -> PathBuf {
    repo_root().join("examples/python/micro")
}

fn run(args: &[&str]) -> Option<String> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    full.push("--no-progress");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja {:?} exited with {}: stderr={}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

// ---------------------------------------------------------------------------
// dump-edges
// ---------------------------------------------------------------------------

#[test]
fn dump_edges_limit_truncates_and_prints_notice() {
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    let Some(out) = run(&["dump-edges", ws_str, "--limit", "2"]) else {
        return;
    };
    // Truncation notice uses the shared helper — same wording across
    // every capped command in the CLI. The text is part of the UX
    // contract.
    assert!(
        out.contains("showing 2 of"),
        "dump-edges --limit 2 missed the truncation notice:\n{out}"
    );
    assert!(
        out.contains("--limit 0, --all, or --context uncapped for all"),
        "dump-edges truncation hint missing:\n{out}"
    );
}

#[test]
fn dump_edges_limit_zero_is_uncapped() {
    let ws = ws();
    let Some(out) = run(&["dump-edges", ws.to_str().unwrap(), "--limit", "0"]) else {
        return;
    };
    // Uncapped: no truncation notice regardless of the row count.
    assert!(
        !out.contains("showing"),
        "dump-edges --limit 0 should NOT truncate or print the notice:\n{out}"
    );
}

#[test]
fn dump_edges_json_all_is_uncapped() {
    let ws = ws();
    let Some(out) = run(&[
        "dump-edges",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--all",
        "--limit",
        "1",
    ]) else {
        return;
    };
    let v: serde_json::Value =
        serde_json::from_str(&out).expect("dump-edges --format json returned invalid JSON");
    // Even with --limit 1, JSON returns everything. The Python micro
    // has more than one edge (handle_request calls get_user +
    // update_user at minimum), so >= 2 is a robust lower bound.
    let count = v.as_array().map(Vec::len).unwrap_or(0);
    assert!(
        count >= 2,
        "dump-edges JSON should ignore --limit; got {count} edges:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// dump-callgraph
// ---------------------------------------------------------------------------

#[test]
fn dump_callgraph_limit_truncates_and_prints_notice() {
    let ws = ws();
    let Some(out) = run(&["dump-callgraph", ws.to_str().unwrap(), "--limit", "2"]) else {
        return;
    };
    assert!(
        out.contains("showing 2 of"),
        "dump-callgraph --limit 2 missed the truncation notice:\n{out}"
    );
}

#[test]
fn dump_callgraph_json_all_is_uncapped() {
    let ws = ws();
    let Some(out) = run(&[
        "dump-callgraph",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--all",
        "--limit",
        "1",
    ]) else {
        return;
    };
    let v: serde_json::Value =
        serde_json::from_str(&out).expect("dump-callgraph --format json returned invalid JSON");
    let count = v.as_array().map(Vec::len).unwrap_or(0);
    assert!(
        count >= 2,
        "dump-callgraph JSON should ignore --limit; got {count} rows:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// dump-ast
// ---------------------------------------------------------------------------

#[test]
fn dump_ast_limit_truncates_and_prints_notice() {
    let ws = ws();
    // Python micro has 4 files — cap to 1 to force truncation.
    let Some(out) = run(&["dump-ast", ws.to_str().unwrap(), "--limit", "1"]) else {
        return;
    };
    assert!(
        out.contains("showing 1 of"),
        "dump-ast --limit 1 missed the truncation notice:\n{out}"
    );
}

#[test]
fn dump_ast_json_all_is_uncapped() {
    let ws = ws();
    let Some(out) = run(&[
        "dump-ast",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--all",
        "--limit",
        "1",
    ]) else {
        return;
    };
    let v: serde_json::Value =
        serde_json::from_str(&out).expect("dump-ast --format json returned invalid JSON");
    let count = v.as_array().map(Vec::len).unwrap_or(0);
    assert!(
        count >= 2,
        "dump-ast JSON should ignore --limit; got {count} files:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// Browse code cells — adjacent rows may point at the same source line, but
// default text output repeats the code instead of collapsing it to a marker.
// Pagination is the size-control mechanism.
// ---------------------------------------------------------------------------

#[test]
fn calls_repeats_adjacent_same_code_rows() {
    let ws = ws();
    // Python micro has two calls at `gateway.py:11:13` that share
    // the line `token = request.args.get("token")`. The default
    // render should keep the code visible rather than folding it.
    let Some(out) = run(&["calls", ws.to_str().unwrap()]) else {
        return;
    };
    assert!(
        !out.contains("↑ same") && out.contains("request.args.get"),
        "browse output should render source code, not the old fold marker:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// Var-extraction hygiene — regression guards for the adapter bugs
// turned up by the full-sweep audit:
//
//   * Dart: `var user = getUser(token)` was reported as callee
//     `user.getUser` because the selector walker greedily accepted
//     the assignment LHS as a receiver.
//   * C#: `var action = req.Query[...]` emitted a second `vars` row
//     with target `action = req.Query[...].ToString()` because
//     `variable_declarator` has no named identifier child in
//     tree-sitter-c-sharp.
//   * Go: multi-return `result, _ := foo()` kept the whole tuple as
//     the target.
//   * Perl: `my $query = ...` kept the `my` keyword in the target.
//   * Solidity: `bytes32 t` kept the type in the target.
//   * Rust: multi-line method chains kept embedded newlines +
//     indentation in the callee name.
//   * Rust / Scala: multi-line arg values kept newlines.
//
// Each assertion pins the specific bad shape the audit fixed so a
// regression in any adapter walker re-surfaces it loudly.
// ---------------------------------------------------------------------------

fn bin_and_ws(lang: &str) -> Option<(PathBuf, PathBuf)> {
    let bin = bin_path()?;
    let ws = repo_root().join(format!("examples/{lang}/micro"));
    ws.is_dir().then_some((bin, ws))
}

fn json_rows(lang: &str, cmd: &str) -> Option<Vec<serde_json::Value>> {
    let (bin, ws) = bin_and_ws(lang)?;
    let out = Command::new(&bin)
        .args([cmd, ws.to_str().unwrap(), "--format", "json", "--no-color"])
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(out.status.success(), "{lang} {cmd}: non-zero exit");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("invalid JSON");
    Some(v.as_array().cloned().unwrap_or_default())
}

#[test]
fn dart_callee_names_not_polluted_by_assignment_lhs() {
    let Some(rows) = json_rows("dart", "calls") else {
        return;
    };
    // Pre-fix these appeared: `user.getUser`, `result.updateUser`,
    // `userId.verifyToken`. None of those are method calls — they
    // were the walker mistakenly stitching the assignment LHS to
    // the callee. Assert the plain function forms surfaced instead.
    let callees: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.get("callee").and_then(|v| v.as_str()))
        .collect();
    for bad in &["user.getUser", "result.updateUser", "userId.verifyToken"] {
        assert!(
            !callees.contains(bad),
            "dart regressed: callee `{bad}` should not appear; got {callees:?}"
        );
    }
    for good in &["getUser", "updateUser", "verifyToken"] {
        assert!(
            callees.contains(good),
            "dart regressed: expected plain callee `{good}` missing; got {callees:?}"
        );
    }
}

#[test]
fn var_targets_never_contain_assignment_rhs() {
    for lang in &[
        "c",
        "cpp",
        "csharp",
        "dart",
        "elixir",
        "erlang",
        "go",
        "java",
        "javascript",
        "kotlin",
        "lua",
        "objc",
        "perl",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "solidity",
        "swift",
        "typescript",
    ] {
        let Some(rows) = json_rows(lang, "vars") else {
            continue;
        };
        for r in &rows {
            let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                !name.contains('='),
                "{lang}: var target `{name}` contains `=` — adapter regressed"
            );
            assert!(
                !name.contains('\n'),
                "{lang}: var target `{name}` contains newline — adapter regressed"
            );
            assert!(
                !name.contains(' '),
                "{lang}: var target `{name}` contains whitespace — should be single identifier"
            );
        }
    }
}

#[test]
fn callee_names_never_contain_newlines() {
    for lang in &[
        "c",
        "cpp",
        "csharp",
        "dart",
        "elixir",
        "erlang",
        "go",
        "java",
        "javascript",
        "kotlin",
        "lua",
        "objc",
        "perl",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "solidity",
        "swift",
        "typescript",
    ] {
        let Some(rows) = json_rows(lang, "calls") else {
            continue;
        };
        for r in &rows {
            let callee = r.get("callee").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                !callee.contains('\n'),
                "{lang}: callee `{callee:?}` contains newline — kit should \
                 normalise whitespace in multi-line method chains"
            );
        }
    }
}

#[test]
fn arg_values_never_contain_newlines() {
    for lang in &[
        "c",
        "cpp",
        "csharp",
        "dart",
        "elixir",
        "erlang",
        "go",
        "java",
        "javascript",
        "kotlin",
        "lua",
        "objc",
        "perl",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "solidity",
        "swift",
        "typescript",
    ] {
        let Some(rows) = json_rows(lang, "args") else {
            continue;
        };
        for r in &rows {
            let value = r.get("value").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                !value.contains('\n'),
                "{lang}: arg value `{value:?}` contains newline — kit should \
                 normalise whitespace in multi-line struct literals / closures"
            );
        }
    }
}

#[test]
fn imports_surface_the_specific_symbol_on_multi_symbol_lines() {
    // Python `from .auth_service import verify_token, run_admin_command`
    // used to render two visually-identical import rows because the
    // CLI dropped `original_name`. After the fix each row shows the
    // specific symbol it represents. JSON also includes the field.
    let Some(ws) = Some(repo_root().join("examples/python/micro")) else {
        return;
    };
    let Some(bin) = bin_path() else { return };
    let out = Command::new(&bin)
        .args(["imports", ws.to_str().unwrap(), "--format", "json", "--no-color"])
        .output()
        .expect("run bonsai-ninja");
    assert!(out.status.success(), "imports --format json failed");
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("invalid imports JSON");
    // Two symbols come from .auth_service on __init__.py:1.
    let init_auth: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r.get("file")
                .and_then(|v| v.as_str())
                .is_some_and(|f| f.ends_with("__init__.py"))
                && r.get("module").and_then(|v| v.as_str()) == Some(".auth_service")
        })
        .collect();
    assert_eq!(
        init_auth.len(),
        2,
        "expected 2 rows for .auth_service in __init__.py, got {}:\n{rows:#?}",
        init_auth.len()
    );
    let mut originals: Vec<&str> = init_auth
        .iter()
        .filter_map(|r| r.get("original_name").and_then(|v| v.as_str()))
        .collect();
    originals.sort_unstable();
    assert_eq!(
        originals,
        vec!["run_admin_command", "verify_token"],
        "imports should surface the specific symbol per row; got {originals:?}"
    );
}

#[test]
fn dart_refs_find_calls_through_selector_walker() {
    // Dart's tree-sitter grammar models calls as
    // `identifier selector(argument_part)` — not a unified
    // call-kind node — so the generic `extract_call_refs` walker
    // used to miss every Dart call. `refs verifyToken` then
    // returned zero despite two call sites in the fixture. After
    // adding a Dart-specific branch to `extract_call_refs` the
    // lookup returns both.
    let Some(bin) = bin_path() else { return };
    let ws = repo_root().join("examples/dart/micro");
    let out = Command::new(&bin)
        .args([
            "refs",
            ws.to_str().unwrap(),
            "verifyToken",
            "--format",
            "json",
            "--no-color",
        ])
        .output()
        .expect("run bonsai-ninja");
    assert!(out.status.success(), "dart refs failed");
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("invalid dart refs JSON");
    assert!(
        rows.len() >= 2,
        "dart refs verifyToken should find >=2 calls; got {}:\n{rows:#?}",
        rows.len()
    );
    for r in &rows {
        assert_eq!(r.get("symbol").and_then(|v| v.as_str()), Some("verifyToken"));
        assert_eq!(r.get("kind").and_then(|v| v.as_str()), Some("call"));
    }
}

#[test]
fn args_no_duplicate_entries_at_same_site() {
    // C and C++ used to emit the same argument twice because
    // multiple nested call-kind nodes (`assignment_expression`
    // wrapping a call) both fire through the flow walker. The
    // browse layer now dedups on `(callee, file, line, col,
    // position, value)`.
    for lang in &[
        "c",
        "cpp",
        "csharp",
        "dart",
        "elixir",
        "erlang",
        "go",
        "java",
        "javascript",
        "kotlin",
        "lua",
        "objc",
        "perl",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "solidity",
        "swift",
        "typescript",
    ] {
        let Some(rows) = json_rows(lang, "args") else {
            continue;
        };
        let mut seen = std::collections::HashSet::new();
        for r in &rows {
            let key = (
                r.get("file").and_then(|v| v.as_str()).unwrap_or(""),
                r.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("column").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("position").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("callee").and_then(|v| v.as_str()).unwrap_or(""),
                r.get("value").and_then(|v| v.as_str()).unwrap_or(""),
            );
            assert!(seen.insert(key), "{lang}: duplicate arg row at {key:?}");
        }
    }
}

#[test]
fn vars_default_render_has_no_same_code_fold_marker() {
    let ws = ws();
    let Some(out) = run(&["vars", ws.to_str().unwrap()]) else {
        return;
    };
    assert!(
        !out.contains("↑ same"),
        "default vars output should not fold source code cells:\n{out}"
    );
}
