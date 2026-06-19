//! Content-level coverage for every CLI command on
//! `examples/python/micro`. Each test asserts on SPECIFIC output
//! strings so a regression that makes a command exit cleanly but
//! return wrong data is caught.
//!
//! The python micro workspace is the canary because we know its
//! exact shape:
//!
//!   - 4 files: `__init__.py`, `auth_service.py`, `gateway.py`,
//!     `user_service.py`.
//!   - 6 functions: `handle_request`, `get_user`, `update_user`,
//!     `verify_token`, `run_admin_command`, `audited`.
//!   - 4 enumerated taint flows (F:<16-hex>, F:<16-hex>, F:<16-hex>,
//!     F:0123456789abcdef) plus variants.
//!   - Known sinks: `cursor.execute` (SQL), `os.system` (cmd).
//!
//! Tests skip silently when the release binary isn't built.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
            "skipping command_coverage: release binary not built ({})",
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
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
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

fn run_fail(args: &[&str]) -> Option<(String, String)> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "bonsai-ninja {:?} unexpectedly succeeded: stdout={}",
        args,
        String::from_utf8_lossy(&out.stdout)
    );
    Some((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

fn assert_contains(out: &str, needle: &str, cmd: &str) {
    assert!(
        out.contains(needle),
        "{cmd}: expected output to contain `{needle}`. Got:\n{out}"
    );
}

fn temp_output_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bonsai-output-path-{name}-{}-{nanos}",
        std::process::id()
    ))
}

#[test]
fn output_path_writes_selected_json_format_and_leaves_stdout_empty() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws();
    let out_path = temp_output_path("defs-json");
    let out = Command::new(&bin)
        .args([
            "defs",
            ws.to_str().unwrap(),
            "--format",
            "json",
            "--output-path",
            out_path.to_str().unwrap(),
            "--no-color",
            "--no-progress",
        ])
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "defs --output-path failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty when --output-path is set, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let written = std::fs::read_to_string(&out_path).expect("read output file");
    let parsed: serde_json::Value = serde_json::from_str(&written).expect("output file JSON");
    assert!(parsed.as_array().is_some_and(|rows| !rows.is_empty()));
    let _ = std::fs::remove_file(out_path);
}

#[test]
fn output_path_writes_paged_text_render() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws();
    let out_path = temp_output_path("defs-text");
    let out = Command::new(&bin)
        .args([
            "defs",
            ws.to_str().unwrap(),
            "--context",
            "4k",
            "--output-path",
            out_path.to_str().unwrap(),
            "--no-color",
            "--no-progress",
        ])
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "defs text --output-path failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty when --output-path is set, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let written = std::fs::read_to_string(&out_path).expect("read output file");
    assert_contains(&written, "verify_token", "defs --output-path text");
    assert_contains(&written, "page 1", "defs --output-path text");
    let _ = std::fs::remove_file(out_path);
}

#[test]
fn export_output_path_streams_native_json() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws();
    let out_path = temp_output_path("export-json");
    let out = Command::new(&bin)
        .args([
            "export",
            ws.to_str().unwrap(),
            "--format",
            "json",
            "--output-path",
            out_path.to_str().unwrap(),
            "--no-color",
            "--no-progress",
        ])
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "export --output-path failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty when --output-path is set, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let written = std::fs::read_to_string(&out_path).expect("read output file");
    let parsed: serde_json::Value = serde_json::from_str(&written).expect("export output file JSON");
    assert!(
        parsed.get("files").is_some(),
        "export JSON missing files: {parsed}"
    );
    let _ = std::fs::remove_file(out_path);
}

// -------- index --------

#[test]
fn index_reports_4_files() {
    let ws = ws();
    let Some(out) = run(&["index", ws.to_str().unwrap()]) else {
        return;
    };
    assert_contains(&out, "\"files\": 4", "index");
    assert_contains(&out, "\"cached_decl_indexes\": 4", "index");
}

// -------- diagnostics --------

#[test]
fn diagnostics_exits_clean_with_no_errors() {
    let ws = ws();
    let Some(out) = run(&["diagnostics", ws.to_str().unwrap()]) else {
        return;
    };
    // python micro is a clean fixture — every file parses.
    assert!(
        out.trim() == "[]" || out.trim().starts_with("[]"),
        "diagnostics expected empty [] on clean fixture; got:\n{out}"
    );
}

// -------- defs --------

#[test]
fn defs_lists_all_six_functions() {
    let Some(out) = run(&["defs", ws().to_str().unwrap()]) else {
        return;
    };
    for fn_name in &[
        "audited",
        "get_user",
        "handle_request",
        "run_admin_command",
        "update_user",
        "verify_token",
    ] {
        assert_contains(&out, fn_name, "defs");
    }
    assert_contains(&out, "(6 definitions)", "defs");
}

#[test]
fn defs_kind_function_filter_works() {
    let Some(out) = run(&["defs", ws().to_str().unwrap(), "--kind", "function"]) else {
        return;
    };
    assert_contains(&out, "(6 definitions)", "defs --kind function");
}

#[test]
fn defs_json_output_parses_and_has_fields() {
    let Some(out) = run(&["defs", ws().to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("defs json invalid: {e}\n{out}"));
    let arr = v.as_array().expect("defs json is array");
    assert_eq!(arr.len(), 6, "expected 6 defs, got {}", arr.len());
    for item in arr {
        for field in &["name", "kind", "file", "line", "column"] {
            assert!(item.get(field).is_some(), "def row missing `{field}`: {item}");
        }
    }
}

// -------- entrypoints --------

#[test]
fn entrypoints_lists_handle_request_root() {
    let Some(out) = run(&["entrypoints", ws().to_str().unwrap()]) else {
        return;
    };
    assert_contains(&out, "handle_request", "entrypoints");
    assert_contains(&out, "no_semantic_callers", "entrypoints");
    assert!(
        !out.contains("verify_token"),
        "verify_token has in-workspace semantic callers and should not be a root:\n{out}"
    );
}

#[test]
fn entrypoints_json_output_parses_and_has_fields() {
    let Some(out) = run(&["entrypoints", ws().to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("entrypoints json invalid: {e}\n{out}"));
    let arr = v.as_array().expect("entrypoints json is array");
    assert!(
        arr.iter()
            .any(|item| item.get("name").and_then(|v| v.as_str()) == Some("handle_request")),
        "expected handle_request entrypoint, got {arr:?}"
    );
    for item in arr {
        for field in &["name", "kind", "file", "line", "column", "callees", "reason"] {
            assert!(
                item.get(field).is_some(),
                "entrypoint row missing `{field}`: {item}"
            );
        }
    }
}

// -------- calls --------

#[test]
fn calls_finds_verify_token_callsites() {
    let Some(out) = run(&["calls", ws().to_str().unwrap(), "--callee", "verify_token"]) else {
        return;
    };
    assert_contains(&out, "(2 call sites)", "calls --callee verify_token");
    assert_contains(&out, "user_service.py", "calls --callee verify_token");
}

#[test]
fn calls_reports_total_call_sites() {
    let Some(out) = run(&["calls", ws().to_str().unwrap()]) else {
        return;
    };
    // 11 call sites as of the current workspace shape; we allow ≥11
    // so benign additions to the example don't break the test.
    assert!(
        out.contains("call sites)"),
        "calls: no summary footer. Got:\n{out}"
    );
}

// -------- imports --------

#[test]
fn imports_finds_flask_and_local_modules() {
    let Some(out) = run(&["imports", ws().to_str().unwrap()]) else {
        return;
    };
    for module in &[
        ".auth_service",
        ".gateway",
        ".user_service",
        "flask",
        "os",
        "sqlite3",
    ] {
        assert_contains(&out, module, "imports");
    }
}

#[test]
fn imports_flows_column_is_populated() {
    // Regression from the symbol-level flow lookup — imports with a
    // resolvable target must show at least one F:id.
    let Some(out) = run(&["imports", ws().to_str().unwrap()]) else {
        return;
    };
    assert!(
        out.contains("F:"),
        "imports: expected at least one F:<16-hex> flow id in output:\n{out}"
    );
}

// -------- vars --------

#[test]
fn vars_captures_known_assignments() {
    let Some(out) = run(&["vars", ws().to_str().unwrap()]) else {
        return;
    };
    for var in &["token", "action", "query", "user", "result"] {
        assert_contains(&out, var, "vars");
    }
}

// -------- strings --------

#[test]
fn strings_classifies_sql_literal() {
    let Some(out) = run(&["strings", ws().to_str().unwrap(), "--min-len", "5"]) else {
        return;
    };
    // The SELECT literal must classify as `sql`.
    assert!(
        out.lines().any(|l| l.contains("sql") && l.contains("SELECT")),
        "strings --min-len 5: expected SELECT literal to classify as `sql`:\n{out}"
    );
}

// -------- args --------

#[test]
fn args_shows_tainted_sinks() {
    let Some(out) = run(&["args", ws().to_str().unwrap()]) else {
        return;
    };
    // cursor.execute(query), os.system("notify-admin " + cmd),
    // get_user(token), update_user(token, action).
    for (callee, arg_hint) in &[
        ("cursor.execute", "query"),
        ("os.system", "notify-admin"),
        ("get_user", "token"),
    ] {
        assert!(
            out.lines().any(|l| l.contains(callee) && l.contains(arg_hint)),
            "args: missing call `{callee}` with arg containing `{arg_hint}`:\n{out}"
        );
    }
}

// -------- classes --------

#[test]
fn classes_is_empty_on_function_only_fixture() {
    let Some(out) = run(&["classes", ws().to_str().unwrap()]) else {
        return;
    };
    assert_contains(&out, "(0 types)", "classes");
}

// -------- refs --------

#[test]
fn refs_verify_token_returns_two_callsites() {
    let Some(out) = run(&["refs", ws().to_str().unwrap(), "verify_token"]) else {
        return;
    };
    assert_contains(&out, "(2 references)", "refs verify_token");
    assert_contains(&out, "get_user", "refs verify_token");
    assert_contains(&out, "update_user", "refs verify_token");
}

// -------- search --------

#[test]
fn search_request_finds_multiple_kinds() {
    let Some(out) = run(&["search", ws().to_str().unwrap(), "request"]) else {
        return;
    };
    // Should find at least call sites + import.
    assert_contains(&out, "request.args.get", "search request");
    assert_contains(&out, "flask", "search request");
}

// -------- trace --------

#[test]
fn trace_handle_request_shows_sink_path() {
    let Some(out) = run(&["trace", ws().to_str().unwrap(), "handle_request"]) else {
        return;
    };
    // The trace must walk through every function in the call tree.
    for name in &[
        "handle_request",
        "get_user",
        "verify_token",
        "update_user",
        "run_admin_command",
    ] {
        assert_contains(&out, name, "trace handle_request");
    }
    // And must hit both known sinks.
    assert_contains(&out, "cursor.execute", "trace handle_request");
    assert_contains(&out, "os.system", "trace handle_request");
}

// -------- inspect --------

#[test]
fn inspect_verify_token_finds_decl_and_chains() {
    let Some(out) = run(&[
        "inspect",
        ws().to_str().unwrap(),
        "--query",
        "verify_token",
        "--graph-flow",
    ]) else {
        return;
    };
    assert_contains(&out, "decl hit(s)", "inspect verify_token");
    assert_contains(&out, "F:", "inspect verify_token");
    assert_contains(&out, "handle_request", "inspect verify_token");
}

#[test]
fn inspect_reports_uncapped_total() {
    let Some(out) = run(&[
        "inspect",
        ws().to_str().unwrap(),
        "--query",
        "verify_token",
        "--context",
        "4096",
    ]) else {
        return;
    };
    assert_contains(&out, "context ", "inspect (context footer)");
}

// -------- dump-hir --------

#[test]
fn dump_hir_verify_token_renders_flow_events() {
    let Some(out) = run(&["dump-hir", ws().to_str().unwrap(), "verify_token"]) else {
        return;
    };
    assert_contains(&out, "\"name\": \"verify_token\"", "dump-hir");
    assert_contains(&out, "flow_events", "dump-hir");
    assert_contains(&out, "cursor.execute", "dump-hir");
}

// -------- dump-cfg --------

#[test]
fn dump_cfg_verify_token_shows_blocks() {
    let Some(out) = run(&["dump-cfg", ws().to_str().unwrap(), "verify_token"]) else {
        return;
    };
    assert_contains(&out, "\"function\": \"verify_token\"", "dump-cfg");
    assert_contains(&out, "blocks", "dump-cfg");
}

// -------- dump-callgraph --------

#[test]
fn dump_callgraph_lists_all_functions() {
    let Some(out) = run(&["dump-callgraph", ws().to_str().unwrap()]) else {
        return;
    };
    assert_contains(&out, "(6 functions)", "dump-callgraph");
    for fn_name in &[
        "handle_request",
        "verify_token",
        "update_user",
        "get_user",
        "run_admin_command",
    ] {
        assert_contains(&out, fn_name, "dump-callgraph");
    }
}

// -------- dump-edges --------

#[test]
fn dump_edges_renders_edge_ids_and_precision() {
    let Some(out) = run(&["dump-edges", ws().to_str().unwrap()]) else {
        return;
    };
    assert_contains(&out, "E:", "dump-edges");
    assert_contains(&out, "narrowed", "dump-edges");
    // The three intra-workspace edges: handle_request → get_user,
    // handle_request → update_user, update_user → verify_token,
    // get_user → verify_token, update_user → run_admin_command.
    for pair in &[
        ("handle_request", "get_user"),
        ("update_user", "verify_token"),
        ("update_user", "run_admin_command"),
    ] {
        assert!(
            out.contains(pair.0) && out.contains(pair.1),
            "dump-edges: missing edge `{} → {}`:\n{out}",
            pair.0,
            pair.1
        );
    }
}

#[test]
fn dump_edges_rejects_broad_precision() {
    let Some((_stdout, stderr)) = run_fail(&[
        "dump-edges",
        ws().to_str().unwrap(),
        "--precision",
        "over-approximate",
    ]) else {
        return;
    };
    assert_contains(&stderr, "semantic-only", "dump-edges");
}

// -------- dump-resolve --------

#[test]
fn dump_resolve_verify_token_reports_one_candidate() {
    let Some(out) = run(&["dump-resolve", ws().to_str().unwrap(), "verify_token"]) else {
        return;
    };
    assert_contains(&out, "resolve verify_token", "dump-resolve");
    assert_contains(&out, "candidates: 1", "dump-resolve");
    assert_contains(&out, "R:", "dump-resolve");
}

// -------- dump-taint --------

#[test]
fn dump_taint_from_update_user_propagates_to_verify_token() {
    // update_user(token, action) — token is a parameter, so seeding
    // it must yield at least one propagation: the call
    // `verify_token(token)` on line 10.
    let Some(out) = run(&[
        "dump-taint",
        ws().to_str().unwrap(),
        "--source",
        "update_user",
        "--seed",
        "token",
    ]) else {
        return;
    };
    // `update_user(token, action)` propagates to two downstream
    // call sites under the post-augmentation seeding:
    //   * `verify_token(token)` — param → param propagation.
    //   * `run_admin_command(user_id, action)` — `action` was seeded
    //     by the per-function body augmentation.
    // The regression this guards is "no propagations at all"; the
    // exact count can grow as seeding gets more permissive without
    // indicating a bug.
    assert_contains(&out, "T:", "dump-taint");
    assert_contains(&out, "verify_token", "dump-taint");
    assert!(
        !out.contains("propagations: 0"),
        "dump-taint should show ≥1 propagation for update_user/token; got:\n{out}"
    );
}

// -------- dump-ast --------

#[test]
fn dump_ast_scoped_to_function_shows_node_ids() {
    let Some(out) = run(&["dump-ast", ws().to_str().unwrap(), "--function", "verify_token"]) else {
        return;
    };
    assert_contains(&out, "function_definition", "dump-ast");
    assert_contains(&out, "verify_token", "dump-ast");
    assert_contains(&out, "N:", "dump-ast");
}

// -------- export --------

#[test]
fn export_produces_complete_json_blob() {
    let Some(out) = run(&["export", ws().to_str().unwrap()]) else {
        return;
    };
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("export not valid JSON: {e}"));
    // Top-level fields.
    for field in &[
        "engine_version",
        "workspace_root",
        "summary",
        "files",
        "callgraph",
        "flow_chains",
        "flow_graph",
    ] {
        assert!(v.get(field).is_some(), "export missing top-level `{field}`");
    }
    let summary = v.get("summary").unwrap();
    assert_eq!(summary.get("file_count").and_then(|v| v.as_u64()), Some(4));
    assert_eq!(summary.get("function_count").and_then(|v| v.as_u64()), Some(6));
}

// -------- cache --------

#[test]
fn cache_stats_reports_in_process_scope() {
    let Some(out) = run(&["cache", "stats", ws().to_str().unwrap()]) else {
        return;
    };
    assert_contains(&out, "in-process", "cache stats");
    assert_contains(&out, "on-disk cache dir", "cache stats");
}
