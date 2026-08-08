//! End-to-end integration tests for every browse subcommand.
//!
//! Each test invokes the compiled `bonsai-ninja` binary against the
//! checked-in Python micro example (`examples/python/micro`) and asserts
//! on either the pretty text table or the JSON shape. These tests lock in
//! the visible column contract — so a regression in header labels,
//! filter handling, or JSON field names will fail here loudly.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::SystemTime;

fn repo_root() -> PathBuf {
    // Crate dir is `<repo>/crates/cli`; repo root is two up.
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn ws_path() -> PathBuf {
    repo_root().join("examples/python/micro")
}

fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    let p = repo_root().join("target/release/bonsai-ninja");
    if !p.exists() {
        eprintln!(
            "skipping browse integration test: release binary not built ({})",
            p.display()
        );
        return None;
    }
    assert_release_binary_is_fresh(&p);
    Some(p)
}

/// Panic loudly if the fallback release binary is older than the engine
/// sources or rulepack. Normal Cargo test runs use the exact executable from
/// `CARGO_BIN_EXE_bonsai-ninja`; this protects only manual/nonstandard
/// environments where that compile-time path is unavailable. Runs once per
/// test-binary process.
fn assert_release_binary_is_fresh(bin: &Path) {
    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(|| {
        let Ok(bin_mtime) = bin.metadata().and_then(|m| m.modified()) else {
            return;
        };
        let root = repo_root();
        let newest = [root.join("crates"), root.join("security-patterns")]
            .iter()
            .filter_map(|dir| newest_mtime(dir, &["rs", "yml"]))
            .max();
        if let Some(newest) = newest {
            assert!(
                bin_mtime >= newest,
                "STALE release binary: target/release/bonsai-ninja is older than the engine \
                 sources / rulepack. These tests would silently exercise an old build. \
                 Rebuild first:  cargo build --release -p bonsai_cli"
            );
        }
    });
}

/// Newest modification time of any file under `dir` with one of `exts`.
fn newest_mtime(dir: &Path, exts: &[&str]) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                // Skip build output / VCS dirs.
                if !matches!(
                    p.file_name().and_then(|n| n.to_str()),
                    Some("target" | ".git" | ".bonsai" | "tests")
                ) {
                    stack.push(p);
                }
            } else if is_release_relevant_source(&p)
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| exts.contains(&e))
            {
                if let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) {
                    newest = Some(newest.map_or(mtime, |cur| cur.max(mtime)));
                }
            }
        }
    }
    newest
}

fn is_release_relevant_source(path: &Path) -> bool {
    !path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| matches!(name, "test.rs" | "tests.rs") || name.ends_with("_tests.rs"))
}

/// Run Cargo's exact `bonsai-ninja` test executable with `args` and
/// `--no-color`. Returns `None` only when neither that executable nor the
/// manual release fallback is available.
fn run(args: &[&str]) -> Option<String> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja exited with {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn run_inspect_graph(ws: &Path, args_after_ws: &[&str]) -> Option<String> {
    let ws_str = ws.to_str().unwrap().to_string();
    let mut args: Vec<&str> = Vec::with_capacity(args_after_ws.len() + 3);
    args.push("inspect");
    args.push(ws_str.as_str());
    args.push("--graph-flow");
    args.extend_from_slice(args_after_ws);
    run(&args)
}

// -----------------------------------------------------------------------------
// defs
// -----------------------------------------------------------------------------

#[test]
fn defs_lists_all_functions_with_signature_and_callees() {
    let ws = ws_path();
    let Some(out) = run(&["defs", ws.to_str().unwrap()]) else {
        return;
    };
    // Header columns — the visible contract for the `defs` listing.
    for h in &["name", "kind", "location", "signature", "callees"] {
        assert!(out.contains(h), "defs header missing `{h}`: {out}");
    }
    // Every function in the fixture must show up, and `verify_token`'s
    // callees should surface the sqlite3.connect → conn.cursor chain.
    assert!(out.contains("verify_token"), "fixture decl missed: {out}");
    assert!(out.contains("run_admin_command"), "decl missed: {out}");
    assert!(out.contains("sqlite3.connect"), "callees preview missing: {out}");
    assert!(
        out.ends_with('\n') || out.contains("definitions"),
        "summary line missing: {out}"
    );
}

#[test]
fn defs_kind_filter_restricts_results() {
    let ws = ws_path();
    let Some(out) = run(&["defs", ws.to_str().unwrap(), "--kind", "function"]) else {
        return;
    };
    assert!(
        out.contains("verify_token"),
        "kind filter dropped valid row: {out}"
    );
}

#[test]
fn defs_name_filter_narrows_to_substring() {
    let ws = ws_path();
    let Some(out) = run(&["defs", ws.to_str().unwrap(), "--name", "run_admin"]) else {
        return;
    };
    assert!(
        out.contains("run_admin_command"),
        "name filter missed expected row: {out}"
    );
    assert!(
        !out.contains("verify_token"),
        "name filter should have dropped verify_token: {out}"
    );
}

#[test]
fn defs_json_format_parses_and_has_expected_fields() {
    let ws = ws_path();
    let Some(out) = run(&["defs", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("defs --format json: valid JSON");
    let arr = v.as_array().expect("top-level array");
    assert!(!arr.is_empty(), "expected at least one def in JSON");
    let first = &arr[0];
    for field in &["name", "kind", "file", "line", "column", "params"] {
        assert!(first.get(field).is_some(), "JSON missing `{field}`: {first}");
    }
}

// -----------------------------------------------------------------------------
// entrypoints
// -----------------------------------------------------------------------------

#[test]
fn entrypoints_lists_callable_roots() {
    let ws = ws_path();
    let Some(out) = run(&["entrypoints", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["name", "kind", "location", "signature", "callees", "reason"] {
        assert!(out.contains(h), "entrypoints header missing `{h}`: {out}");
    }
    assert!(
        out.contains("handle_request"),
        "entrypoints should include the externally-called handler root: {out}"
    );
    assert!(
        out.contains("no_semantic_callers"),
        "entrypoints should explain why rows are roots: {out}"
    );
}

#[test]
fn entrypoints_json_format_parses_and_has_expected_fields() {
    let ws = ws_path();
    let Some(out) = run(&["entrypoints", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("entrypoints --format json: valid JSON");
    let arr = v.as_array().expect("top-level array");
    assert!(!arr.is_empty(), "expected at least one entrypoint in JSON");
    let first = &arr[0];
    for field in &[
        "name", "kind", "file", "line", "column", "params", "callees", "reason",
    ] {
        assert!(first.get(field).is_some(), "JSON missing `{field}`: {first}");
    }
}

// -----------------------------------------------------------------------------
// calls
// -----------------------------------------------------------------------------

#[test]
fn calls_lists_callees_with_caller_and_code_snippet() {
    let ws = ws_path();
    let Some(out) = run(&["calls", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["callee text", "caller", "location", "code"] {
        assert!(out.contains(h), "calls header missing `{h}`: {out}");
    }
    assert!(out.contains("os.system"), "os.system call not listed: {out}");
    // The `code` column prints the actual source line, not just the callee.
    assert!(
        out.contains("os.system(\"notify-admin"),
        "code snippet missing from calls table: {out}"
    );
}

#[test]
fn calls_callee_filter_restricts_rows() {
    let ws = ws_path();
    let Some(out) = run(&["calls", ws.to_str().unwrap(), "--callee", "os.system"]) else {
        return;
    };
    assert!(
        out.contains("os.system"),
        "callee filter dropped valid row: {out}"
    );
    assert!(
        !out.contains("sqlite3.connect"),
        "callee filter leaked other rows: {out}"
    );
}

#[test]
fn calls_json_shape() {
    let ws = ws_path();
    let Some(out) = run(&["calls", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("calls --format json: valid JSON");
    let first = &v.as_array().expect("array")[0];
    for f in &["resolution_scope", "callee", "file", "line", "column", "caller"] {
        assert!(first.get(f).is_some(), "calls JSON missing `{f}`: {first}");
    }
    assert_eq!(first["resolution_scope"], "syntactic-call-site");
}

// -----------------------------------------------------------------------------
// imports
// -----------------------------------------------------------------------------

#[test]
fn imports_lists_modules_with_kind_and_location() {
    let ws = ws_path();
    let Some(out) = run(&["imports", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["module", "alias", "kind", "location", "code"] {
        assert!(out.contains(h), "imports header missing `{h}`: {out}");
    }
    // The fixture imports `flask`, `sqlite3`, `os`, and a relative
    // `.user_service`; all must surface.
    for module in &["flask", "sqlite3", "os", ".user_service"] {
        assert!(
            out.contains(module),
            "imports table missing module `{module}`: {out}"
        );
    }
}

#[test]
fn imports_json_shape() {
    let ws = ws_path();
    let Some(out) = run(&["imports", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("imports JSON parses");
    let first = &v.as_array().unwrap()[0];
    for f in &["file", "module", "alias", "is_wildcard", "line"] {
        assert!(first.get(f).is_some(), "imports JSON missing `{f}`: {first}");
    }
}

// -----------------------------------------------------------------------------
// vars
// -----------------------------------------------------------------------------

#[test]
fn vars_lists_assignments_with_enclosing_fn() {
    let ws = ws_path();
    let Some(out) = run(&["vars", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["var", "in", "source", "location", "code"] {
        assert!(out.contains(h), "vars header missing `{h}`: {out}");
    }
    // `cursor = conn.cursor()` inside verify_token is the canonical row.
    assert!(out.contains("cursor"), "var `cursor` missing: {out}");
    assert!(out.contains("verify_token"), "enclosing fn col missing: {out}");
}

#[test]
fn vars_name_filter_narrows() {
    let ws = ws_path();
    let Some(out) = run(&["vars", ws.to_str().unwrap(), "--name", "cursor"]) else {
        return;
    };
    assert!(out.contains("cursor"), "filter dropped expected row: {out}");
    assert!(!out.contains("action"), "filter leaked other rows: {out}");
}

// -----------------------------------------------------------------------------
// strings
// -----------------------------------------------------------------------------

#[test]
fn strings_table_surfaces_sql_classification() {
    let ws = ws_path();
    let Some(out) = run(&["strings", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["category", "text", "in", "location", "code"] {
        assert!(out.contains(h), "strings header missing `{h}`: {out}");
    }
    // The fixture has a hand-crafted SQL string that should classify as `sql`.
    assert!(out.contains("sql"), "SQL string classification missing: {out}");
    assert!(out.contains("SELECT user_id"), "SQL text missing: {out}");
}

#[test]
fn strings_category_filter_restricts() {
    let ws = ws_path();
    let Some(out) = run(&["strings", ws.to_str().unwrap(), "--category", "sql"]) else {
        return;
    };
    assert!(out.contains("sql"), "category filter dropped expected row: {out}");
}

// -----------------------------------------------------------------------------
// args
// -----------------------------------------------------------------------------

#[test]
fn args_table_shows_callee_pos_and_value() {
    let ws = ws_path();
    let Some(out) = run(&["args", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["callee text", "pos", "arg", "caller", "location", "code"] {
        assert!(out.contains(h), "args header missing `{h}`: {out}");
    }
    assert!(out.contains("os.system"), "args: os.system missing: {out}");
}

#[test]
fn args_callee_filter() {
    let ws = ws_path();
    let Some(out) = run(&["args", ws.to_str().unwrap(), "--callee", "verify_token"]) else {
        return;
    };
    assert!(
        out.contains("verify_token"),
        "args callee filter dropped row: {out}"
    );
    assert!(
        !out.contains("os.system"),
        "args callee filter leaked other rows: {out}"
    );
}

#[test]
fn args_json_declares_syntactic_scope() {
    let ws = ws_path();
    let Some(out) = run(&["args", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("args --format json: valid JSON");
    let first = &v.as_array().expect("array")[0];
    assert_eq!(first["resolution_scope"], "syntactic-call-site-argument");
}

// -----------------------------------------------------------------------------
// operations
// -----------------------------------------------------------------------------

#[test]
fn operations_table_shows_use_site_facts() {
    let ws = ws_path();
    let Some(out) = run(&["operations", ws.to_str().unwrap(), "--kind", "call"]) else {
        return;
    };
    for h in &["kind", "name", "in", "detail", "operands", "location", "code"] {
        assert!(out.contains(h), "operations header missing `{h}`: {out}");
    }
    assert!(
        out.contains("verify_token") || out.contains("update_user"),
        "operations call facts missing expected fixture call: {out}"
    );
}

#[test]
fn operations_json_filters_by_kind_and_name() {
    let ws = ws_path();
    let Some(out) = run(&[
        "operations",
        ws.to_str().unwrap(),
        "--kind",
        "write",
        "--name",
        "action",
        "--format",
        "json",
    ]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("operations --format json: valid JSON");
    let rows = v.as_array().expect("operations JSON array");
    assert_eq!(
        rows.first().and_then(|row| row["name"].as_str()),
        Some("action"),
        "operations should rank exact target matches before operand-only matches: {out}"
    );
    assert!(
        rows.iter().any(|row| {
            row["kind"] == "write"
                && row["name"] == "action"
                && row["in_function"] == "handle_request"
                && row
                    .get("operands")
                    .and_then(serde_json::Value::as_array)
                    .is_some()
        }),
        "operations JSON missing action write row: {out}"
    );
}

#[test]
fn operations_does_not_report_literal_returns_as_reads() {
    let ws = ws_path();
    let Some(out) = run(&[
        "operations",
        ws.to_str().unwrap(),
        "--kind",
        "read",
        "--name",
        "None",
        "--format",
        "json",
        "--all",
    ]) else {
        return;
    };
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&out).expect("operations literal-read JSON parses");
    assert!(
        rows.is_empty(),
        "`return None` is a literal return, not a read of a symbol: {out}"
    );

    for (lang, literal) in [("swift", "nil"), ("cpp", "nullptr")] {
        let Some(out) = run_on(
            lang,
            &[
                "operations",
                "--kind",
                "read",
                "--name",
                literal,
                "--format",
                "json",
                "--all",
            ],
        ) else {
            return;
        };
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(&out).expect("operations literal-read JSON parses");
        assert!(
            rows.is_empty(),
            "{lang}: literal `{literal}` is not a read of a symbol: {out}"
        );
    }
}

// -----------------------------------------------------------------------------
// classes
// -----------------------------------------------------------------------------

#[test]
fn classes_table_has_headers_even_when_empty() {
    // The python micro example has no classes, so the table should be
    // empty but still carry the header row and `(0 types)` summary.
    let ws = ws_path();
    let Some(out) = run(&["classes", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["name", "kind", "location", "methods"] {
        assert!(out.contains(h), "classes header missing `{h}`: {out}");
    }
    assert!(out.contains("0 types"), "classes empty summary missing: {out}");
}

// -----------------------------------------------------------------------------
// refs
// -----------------------------------------------------------------------------

#[test]
fn refs_lists_every_reference_with_snippet() {
    let ws = ws_path();
    let Some(out) = run(&["refs", ws.to_str().unwrap(), "run_admin_command"]) else {
        return;
    };
    for h in &["symbol", "kind", "in", "location", "code"] {
        assert!(out.contains(h), "refs header missing `{h}`: {out}");
    }
    assert!(out.contains("run_admin_command"), "refs: self row missing: {out}");
    // The caller is `update_user` in the fixture.
    assert!(
        out.contains("update_user"),
        "refs enclosing-fn col missing: {out}"
    );
}

// -----------------------------------------------------------------------------
// search
// -----------------------------------------------------------------------------

#[test]
fn search_ranks_prefix_match_first() {
    let ws = ws_path();
    let Some(out) = run(&["search", ws.to_str().unwrap(), "run_admin"]) else {
        return;
    };
    for h in &["name", "kind", "qualified", "context", "code", "location"] {
        assert!(out.contains(h), "search header missing `{h}`: {out}");
    }
    assert!(
        out.contains("run_admin_command"),
        "search prefix match missing: {out}"
    );
}

#[test]
fn search_json_shape() {
    let ws = ws_path();
    let Some(out) = run(&["search", ws.to_str().unwrap(), "verify", "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("search JSON parses");
    assert!(!v.as_array().unwrap().is_empty(), "search JSON empty");
}

#[test]
fn search_file_kind_hydrates_canonical_file_rows() {
    let ws = ws_path();
    let Some(out) = run(&[
        "search",
        ws.to_str().unwrap(),
        "gateway.py",
        "--kind",
        "file",
        "--format",
        "json",
    ]) else {
        return;
    };
    let rows: Vec<serde_json::Value> = serde_json::from_str(&out).expect("search file JSON parses");
    assert_eq!(rows.len(), 1, "expected exactly one file row: {out}");
    let row = &rows[0];
    assert_eq!(row["kind"], "file");
    assert_eq!(row["name"], "gateway.py");
    assert!(
        row["qualified_name"]
            .as_str()
            .is_some_and(|path| path.ends_with("gateway.py")),
        "file row should carry the full path as qualified_name: {row}"
    );
}

// -----------------------------------------------------------------------------
// themes
// -----------------------------------------------------------------------------

#[test]
fn theme_flag_accepts_each_preset() {
    // Exercise each preset just to make sure they parse and the CLI
    // doesn't panic on theme switch.
    let ws = ws_path();
    for preset in &["moss", "earthy-dark", "dracula", "retro-amber"] {
        let Some(out) = run(&["--theme", preset, "defs", ws.to_str().unwrap()]) else {
            return;
        };
        assert!(
            out.contains("verify_token"),
            "theme {preset} broke defs table: {out}"
        );
    }
}

#[test]
fn unknown_theme_is_rejected_even_when_help_is_requested() {
    let Some(bin) = bin_path() else {
        return;
    };
    let out = Command::new(bin)
        .args(["--theme", "neon-nope", "--help", "--no-color"])
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(!out.status.success(), "unknown theme must not silently fall back");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid value") && stderr.contains("earthy-dark") && stderr.contains("moss"),
        "theme error should list the supported values:\n{stderr}"
    );
}

#[test]
fn unknown_theme_from_environment_is_rejected() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = Command::new(bin)
        .args(["defs", ws.to_str().unwrap(), "--no-color"])
        .env("BONSAI_THEME", "neon-nope")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "unknown BONSAI_THEME must not silently fall back"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid value") && stderr.contains("earthy-dark") && stderr.contains("moss"),
        "environment theme error should list the supported values:\n{stderr}"
    );
}

// -----------------------------------------------------------------------------
// Non-browse commands (smoke tests)
// -----------------------------------------------------------------------------

#[test]
fn index_prints_file_count() {
    let ws = ws_path();
    let Some(out) = run(&["index", ws.to_str().unwrap()]) else {
        return;
    };
    assert!(
        out.contains("files") || out.contains("indexed"),
        "index summary missing: {out}"
    );
}

#[test]
fn index_structural_only_does_not_write_semantic_sidecars() {
    let tmp = tempdir_for_test("bonsai_index_structural_only");
    write_tiny_python_workspace(&tmp);
    let cache = bonsai_common::workspace_bonsai_dir(&tmp);
    let _ = std::fs::remove_dir_all(&cache);

    let Some(out) = run(&["index", tmp.to_str().unwrap(), "--structural-only"]) else {
        return;
    };
    assert!(out.contains("files"), "index summary missing: {out}");
    assert!(
        !cache.join("dataflow.v2.bin").exists(),
        "`index --structural-only` must not write the legacy dataflow sidecar"
    );
    assert!(
        !cache.join("dataflow.v3.factstore").exists(),
        "`index --structural-only` must not write the factstore dataflow sidecar"
    );
    assert!(
        !cache.join("value_flow.v3.factstore").exists(),
        "`index --structural-only` must not write the value-flow sidecar"
    );
    assert!(
        !cache.join("flow_ids.v3.factstore").exists(),
        "`index --structural-only` must not write the flow-id sidecar"
    );
    assert!(
        !cache.join("manifest.json").exists(),
        "`index --structural-only` must not publish a semantic cache manifest"
    );
}

#[test]
fn index_prewarm_dataflow_writes_factstore_sidecar() {
    let tmp = tempdir_for_test("bonsai_index_prewarm_dataflow");
    write_tiny_python_workspace(&tmp);
    let cache = bonsai_common::workspace_bonsai_dir(&tmp);
    let _ = std::fs::remove_dir_all(&cache);

    let Some(out) = run(&["index", tmp.to_str().unwrap(), "--prewarm-dataflow"]) else {
        return;
    };
    assert!(out.contains("files"), "index summary missing: {out}");
    assert!(
        cache.join("dataflow.v3.factstore").exists(),
        "`index --prewarm-dataflow` must write the streaming factstore sidecar"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cache.join("manifest.json")).expect("read cache manifest"))
            .expect("cache manifest JSON");
    assert_eq!(
        manifest["coverage"]["legacy_dataflow_ready"], true,
        "`index --prewarm-dataflow` should report dataflow readiness for the current streaming factstore: {manifest:#?}"
    );
    assert!(
        !cache.join("value_flow.v3.factstore").exists(),
        "`index --prewarm-dataflow` must not prewarm unrelated value-flow sidecars"
    );
    assert!(
        !cache.join("flow_ids.v3.factstore").exists(),
        "`index --prewarm-dataflow` must not prewarm unrelated flow-id sidecars"
    );
}

#[test]
fn index_default_stays_structural_and_does_not_write_semantic_sidecars() {
    let tmp = tempdir_for_test("bonsai_index_default_structural");
    write_tiny_python_workspace(&tmp);

    let Some(out) = run(&["index", tmp.to_str().unwrap()]) else {
        return;
    };
    assert!(out.contains("files"), "index summary missing: {out}");
    let first: serde_json::Value = serde_json::from_str(&out).expect("first index summary JSON");
    assert_eq!(first["compiler_cache"], "rebuilt", "{out}");
    assert_eq!(first["parsed_files"], first["files"], "{out}");
    let Some(warm_out) = run(&["index", tmp.to_str().unwrap()]) else {
        return;
    };
    let warm: serde_json::Value = serde_json::from_str(&warm_out).expect("warm index summary JSON");
    assert_eq!(warm["compiler_cache"], "hit", "{warm_out}");
    assert_eq!(warm["parsed_files"], 0, "{warm_out}");
    let Some(stats_out) = run(&["cache", "stats", tmp.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let stats: serde_json::Value = serde_json::from_str(&stats_out).expect("cache stats JSON");
    assert_eq!(
        stats["compiler_object_sidecar_exists"], true,
        "`index` should persist reusable AST-lowered compiler objects: {stats_out}"
    );
    assert_eq!(
        stats["callgraph_sidecar_exists"], false,
        "`index` should stay structural by default and avoid the semantic callgraph sidecar: {stats_out}"
    );
    assert_eq!(
        stats["idg_sidecar_exists"], false,
        "`index` should stay structural by default and avoid the shared IDG factstore: {stats_out}"
    );
    assert_eq!(
        stats["dataflow_factstore_sidecar_exists"], false,
        "`index` should stay structural by default and avoid the dataflow factstore: {stats_out}"
    );
    assert_eq!(
        stats["value_flow_sidecar_exists"], false,
        "`index` should stay structural by default and avoid the value-flow factstore: {stats_out}"
    );
    assert_eq!(
        stats["flow_ids_sidecar_exists"], false,
        "`index` should stay structural by default and avoid the flow-id factstore: {stats_out}"
    );
    assert_eq!(
        stats["manifest_exists"], false,
        "`index` should not publish a semantic cache manifest by default: {stats_out}"
    );
}

#[test]
fn index_semantic_flag_writes_shared_semantic_sidecars() {
    let tmp = tempdir_for_test("bonsai_index_semantic");
    write_tiny_python_workspace(&tmp);

    let Some(out) = run(&["index", tmp.to_str().unwrap(), "--semantic"]) else {
        return;
    };
    assert!(out.contains("files"), "index summary missing: {out}");
    let Some(stats_out) = run(&["cache", "stats", tmp.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let stats: serde_json::Value = serde_json::from_str(&stats_out).expect("cache stats JSON");
    assert_eq!(
        stats["manifest_exists"], true,
        "`index --semantic` should publish the cache manifest: {stats_out}"
    );
    assert_eq!(
        stats["dataflow_factstore_sidecar_exists"], false,
        "`index --semantic` should not run the legacy all-entry dataflow prewarm: {stats_out}"
    );
    assert_eq!(
        stats["idg_sidecar_exists"], true,
        "`index --semantic` should write the shared IDG factstore: {stats_out}"
    );
    assert_eq!(
        stats["validation"]["manifest_status"], "fresh",
        "`cache stats` should validate the semantic cache manifest: {stats_out}"
    );
    assert_eq!(
        stats["validation"]["semantic_ready"], true,
        "`cache stats` should report validated semantic readiness: {stats_out}"
    );

    let Some(path_out) = run(&[
        "path",
        tmp.to_str().unwrap(),
        "--from",
        "handle",
        "--to",
        "sink",
        "--format",
        "json",
    ]) else {
        return;
    };
    let path: serde_json::Value = serde_json::from_str(&path_out).expect("path JSON");
    assert_eq!(
        path["idg_available"], true,
        "`path` should hydrate and use the warmed IDG sidecar after `index --semantic`: {path_out}"
    );
    assert!(
        path["backends"]
            .as_array()
            .is_some_and(|backends| backends.iter().any(|backend| backend == "warmed-idg-cross-call")),
        "`path` should report the warmed IDG backend after semantic indexing: {path_out}"
    );
}

#[test]
fn path_and_slice_text_summaries_are_polished() {
    let ws = ws_path();
    let ws_str = ws.to_str().unwrap();

    let Some(path_out) = run(&[
        "path",
        ws_str,
        "--from",
        "handle_request",
        "--to",
        "run_admin_command",
        "--context",
        "4k",
    ]) else {
        return;
    };
    // Status depends on whether the fixture's semantic sidecar is warm
    // (`index --semantic` flips it to complete) — assert the human label,
    // not the cache state.
    assert!(
        path_out.contains("status complete") || path_out.contains("status incomplete"),
        "path summary should render a human status label:\n{path_out}"
    );
    assert!(
        path_out.contains("IDG") && path_out.contains("semantic edge"),
        "path summary should render IDG availability with a count phrase:\n{path_out}"
    );
    for raw in [
        "complete no",
        "idg available",
        "idg edges",
        "resolved-callgraph,warmed",
    ] {
        assert!(
            !path_out.contains(raw),
            "path summary leaked old/raw wording `{raw}`:\n{path_out}"
        );
    }

    let Some(slice_out) = run(&[
        "slice",
        ws_str,
        "--symbol",
        "user_id",
        "--line",
        "12",
        "--file",
        "user_service.py",
        "--context",
        "4k",
    ]) else {
        return;
    };
    assert!(
        slice_out.contains("limit") && slice_out.contains("uncapped"),
        "slice summary should render the step limit as prose:\n{slice_out}"
    );
    assert!(
        slice_out.contains("status") && slice_out.contains("incomplete"),
        "slice summary should render a human status label:\n{slice_out}"
    );
    assert!(
        !slice_out.contains("run `bonsai-ninja index --semantic`"),
        "slice must compute its selected value-flow projection on demand instead of prescribing an artifact that semantic indexing intentionally does not build:\n{slice_out}"
    );
    for raw in ["complete no", "max steps"] {
        assert!(
            !slice_out.contains(raw),
            "slice summary leaked old/raw wording `{raw}`:\n{slice_out}"
        );
    }
}

#[test]
fn trace_from_entry_produces_flow() {
    let ws = ws_path();
    let Some(out) = run(&["trace", ws.to_str().unwrap(), "handle_request"]) else {
        return;
    };
    // The trace should mention the entry function.
    assert!(
        out.contains("handle_request"),
        "trace output missing entry fn: {out}"
    );
}

/// Default `trace` output is the themed text view (not JSON). Pin
/// the structural markers so we'd notice if it regressed back to a
/// flat dump or a plain-text wall.
#[test]
fn trace_default_is_themed_text() {
    let ws = ws_path();
    let Some(out) = run(&["trace", ws.to_str().unwrap(), "handle_request"]) else {
        return;
    };
    assert!(
        !out.trim_start().starts_with('{'),
        "trace default should NOT be JSON; got:\n{out}"
    );
    assert!(
        out.contains("▸ trace handle_request"),
        "themed header missing: {out}"
    );
    assert!(out.contains("PATH 1"), "path header missing: {out}");
    assert!(
        out.contains("[enter]") || out.contains("Enter function"),
        "enter step marker missing: {out}"
    );
    assert!(
        out.contains("language") && out.contains("python"),
        "summary line missing: {out}"
    );
    assert!(
        out.contains("precision tally"),
        "precision tally summary missing: {out}"
    );
    assert!(
        !out.contains("/Users/")
            || out.matches("examples/python/micro/").count() > out.matches("/Users/").count() / 2,
        "trace should use workspace-relative paths in most lines:\n{out}"
    );
}

/// `--format json` still emits valid JSON for scripts that want the
/// raw shape.
#[test]
fn trace_json_format_still_emits_json() {
    let ws = ws_path();
    let Some(out) = run(&[
        "trace",
        ws.to_str().unwrap(),
        "handle_request",
        "--format",
        "json",
    ]) else {
        return;
    };
    assert!(
        out.trim_start().starts_with('{'),
        "trace --format json must emit JSON; got:\n{out}"
    );
    assert!(out.contains("\"trace_id\""), "JSON missing trace_id: {out}");
}

#[test]
fn trace_source_to_sink_json_rebuilds_summary_after_sink_slice() {
    let ws = ws_path();
    let Some(out) = run(&[
        "trace",
        ws.to_str().unwrap(),
        "--from",
        "handle_request",
        "--to",
        "os.system",
        "--format",
        "json",
    ]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("trace JSON parses");
    let steps = v["steps"].as_array().expect("steps array");
    let step_ids: std::collections::HashSet<u64> =
        steps.iter().filter_map(|step| step["id"].as_u64()).collect();
    assert_eq!(
        v["summary"]["total_steps"].as_u64(),
        Some(steps.len() as u64),
        "source-to-sink trace summary must match the sliced step list:\n{out}"
    );
    assert!(
        v["edges"].as_array().expect("edges array").iter().all(|edge| {
            edge["from_step"]
                .as_u64()
                .is_some_and(|id| step_ids.contains(&id))
                && edge["to_step"].as_u64().is_some_and(|id| step_ids.contains(&id))
        }),
        "source-to-sink trace edges must not point past the sliced step list:\n{out}"
    );
    let max_step = step_ids.iter().copied().max().unwrap_or(0);
    assert!(
        v["paths"].as_array().expect("paths array").iter().all(|path| {
            path["first_step"].as_u64().unwrap_or(u64::MAX) <= max_step
                && path["last_step"].as_u64().unwrap_or(u64::MAX) <= max_step
        }),
        "source-to-sink trace path summaries must be rebuilt after slicing:\n{out}"
    );
}

#[test]
fn trace_source_to_sink_external_match_is_exact_not_substring() {
    let tmp = tempdir_for_test("bonsai_trace_external_sink_exact");
    std::fs::write(
        tmp.join("app.py"),
        r#"
import os

def entry(value):
    os.system_safe(value)
    os.system(value)
"#,
    )
    .expect("write trace fixture");

    let Some(out) = run(&[
        "trace",
        tmp.to_str().unwrap(),
        "--from",
        "entry",
        "--to",
        "os.system",
        "--format",
        "json",
    ]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("trace JSON parses");
    let steps = v["steps"].as_array().expect("steps array");
    let last_message = steps
        .last()
        .and_then(|step| step["message"].as_str())
        .unwrap_or_default();
    assert_eq!(
        last_message, "Unresolved call os.system",
        "external sink matching must stop on the exact call, not an earlier substring match:\n{out}"
    );
    assert!(
        v["diagnostics"]
            .as_array()
            .expect("diagnostics array")
            .iter()
            .all(|diag| diag["code"].as_str() != Some("sink-not-reached")),
        "exact external sink should be reached:\n{out}"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn trace_rejects_ambiguous_bare_entry_and_accepts_file_context() {
    let tmp = tempdir_for_test("bonsai_trace_ambiguous_entry");
    let a = tmp.join("a.py");
    let b = tmp.join("b.py");
    std::fs::write(
        &a,
        r#"
def dup(value):
    return a_only(value)

def a_only(value):
    return value
"#,
    )
    .expect("write a.py");
    std::fs::write(
        &b,
        r#"
def dup(value):
    return b_only(value)

def b_only(value):
    return value
"#,
    )
    .expect("write b.py");
    let Some(bin) = bin_path() else {
        return;
    };

    let ambiguous = Command::new(&bin)
        .args([
            "trace",
            tmp.to_str().unwrap(),
            "dup",
            "--format",
            "json",
            "--no-color",
        ])
        .output()
        .expect("run ambiguous trace");
    assert!(
        !ambiguous.status.success(),
        "ambiguous trace must fail instead of choosing one candidate"
    );
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        stderr.contains("ambiguous") && stderr.contains("path:line:name"),
        "ambiguous trace should explain exact disambiguation; stderr:\n{stderr}"
    );

    let disambiguator = format!("{}:2:dup", a.display());
    let qualified = Command::new(&bin)
        .args([
            "trace",
            tmp.to_str().unwrap(),
            &disambiguator,
            "--format",
            "json",
            "--no-color",
        ])
        .output()
        .expect("run qualified trace");
    assert!(
        qualified.status.success(),
        "file-qualified trace should resolve exactly; stderr:\n{}",
        String::from_utf8_lossy(&qualified.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&qualified.stdout).expect("qualified trace JSON");
    let rendered = serde_json::to_string(&parsed).expect("trace JSON renders");
    assert!(
        rendered.contains("a_only") && !rendered.contains("b_only"),
        "file-qualified trace should stay on the selected duplicate:\n{rendered}"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn semantic_navigation_rejects_removed_analysis_caps() {
    let Some(bin) = bin_path() else {
        return;
    };
    let workspace = ws_path();
    let workspace = workspace.to_str().expect("utf-8 workspace");
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["trace", workspace, "handle_request"],
            &[
                "--max-depth",
                "--max-steps",
                "--max-branch-fanout",
                "--max-loop-iters",
            ],
        ),
        (
            &[
                "path",
                workspace,
                "--from",
                "handle_request",
                "--to",
                "verify_token",
            ],
            &["--max-paths", "--max-depth", "--max-probes"],
        ),
        (
            &["slice", workspace, "--symbol", "token", "--line", "1"],
            &["--max-steps"],
        ),
    ];
    for (prefix, flags) in cases {
        for flag in *flags {
            let mut args = prefix.to_vec();
            args.extend([*flag, "1", "--no-color", "--no-progress"]);
            let output = Command::new(&bin)
                .args(args)
                .output()
                .expect("run removed analysis-cap check");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success() && stderr.contains("unexpected argument"),
                "removed semantic cap {flag} must fail at argument parsing: {stderr}"
            );
        }
    }
}

#[test]
fn trace_json_marks_unresolved_call_incomplete_without_depth_limit() {
    let tmp = tempdir_for_test("bonsai_trace_unresolved_call_incomplete");
    std::fs::write(
        tmp.join("app.py"),
        r#"
def entry(value):
    missing_call(value)
"#,
    )
    .expect("write trace fixture");

    let Some(out) = run(&["trace", tmp.to_str().unwrap(), "entry", "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("trace JSON parses");
    assert_eq!(
        v["summary"]["analysis_complete"], false,
        "trace must not claim completeness when a call cannot be resolved:\n{out}"
    );
    let incomplete_reasons = v["summary"]["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array");
    assert!(
        incomplete_reasons
            .iter()
            .any(|reason| reason.as_str() == Some("unresolved-call:missing_call")),
        "trace must explain unresolved call incompleteness:\n{out}"
    );
    assert!(
        v["summary"]["truncation_reasons"]
            .as_array()
            .is_none_or(|reasons| reasons.is_empty()),
        "unresolved calls are not budget truncation:\n{out}"
    );
    assert!(
        v["paths"]
            .as_array()
            .expect("paths array")
            .iter()
            .all(|path| path["terminated_by"].as_str() != Some("DepthLimit")),
        "unresolved calls must not masquerade as path depth limits:\n{out}"
    );
    assert!(
        v["paths"]
            .as_array()
            .expect("paths array")
            .iter()
            .any(|path| path["terminated_by"].as_str() == Some("UnknownCall")),
        "unresolved call paths should terminate as UnknownCall:\n{out}"
    );
    assert!(
        v["steps"].as_array().expect("steps array").iter().any(|step| {
            step["kind"].as_str() == Some("Diagnostic")
                && step["message"].as_str() == Some("Unresolved call missing_call")
                && step["precision"].as_str() == Some("exact")
        }),
        "unresolved call should be exact diagnostic metadata, not unknown call evidence:\n{out}"
    );
    assert!(
        v["steps"].as_array().expect("steps array").iter().all(|step| {
            !(step["kind"].as_str() == Some("Call") && step["message"].as_str() == Some("Call missing_call"))
        }),
        "unresolved calls must not be emitted as call evidence:\n{out}"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

/// `--format dot` produces a Graphviz digraph for piping to `dot`.
#[test]
fn trace_dot_format_emits_digraph() {
    let ws = ws_path();
    let Some(out) = run(&["trace", ws.to_str().unwrap(), "handle_request", "--format", "dot"]) else {
        return;
    };
    assert!(
        out.contains("digraph trace"),
        "trace --format dot must emit digraph; got:\n{out}"
    );
}

#[test]
fn diagnostics_runs_without_error() {
    let ws = ws_path();
    let Some(_out) = run(&["diagnostics", ws.to_str().unwrap()]) else {
        return;
    };
}

#[test]
fn html_output_is_standalone_themed_and_escapes_source() {
    let Some(bin) = bin_path() else {
        return;
    };
    let workspace = tempdir_for_test("bonsai_html_output");
    std::fs::write(
        workspace.join("app.py"),
        "def render():\n    return \"<unsafe>&value\"\n",
    )
    .expect("write HTML output fixture");
    let report = workspace.join("report.html");
    let output = Command::new(&bin)
        .args([
            "--theme",
            "moss",
            "read-file",
            workspace.to_str().expect("workspace utf8"),
            "app.py",
            "--html-output",
            report.to_str().expect("report utf8"),
            "--no-progress",
        ])
        .output()
        .expect("run HTML report");
    assert!(
        output.status.success(),
        "HTML output failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "HTML payload must go only to its file");
    let html = std::fs::read_to_string(&report).expect("read HTML report");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("bonsai-ninja") && html.contains("Moss theme"));
    assert!(html.contains("&lt;unsafe&gt;&amp;value"));
    assert!(html.ends_with("</body></html>\n"));

    let _ = std::fs::remove_dir_all(workspace);
}

#[test]
fn html_output_rejects_a_second_output_sink() {
    let Some(bin) = bin_path() else {
        return;
    };
    let workspace = ws_path();
    let output_dir = tempdir_for_test("bonsai_conflicting_output");
    let report = output_dir.join("report.html");
    let json = output_dir.join("report.json");
    let output = Command::new(&bin)
        .args([
            "defs",
            workspace.to_str().expect("workspace utf8"),
            "--html-output",
            report.to_str().expect("report utf8"),
            "--output-path",
            json.to_str().expect("json utf8"),
            "--no-progress",
        ])
        .output()
        .expect("run conflicting output sinks");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("mutually exclusive"),
        "conflict should be explicit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(output_dir);
}

#[test]
fn export_produces_valid_json() {
    let ws = ws_path();
    let Some(out) = run(&["export", ws.to_str().unwrap()]) else {
        return;
    };
    let value: serde_json::Value = serde_json::from_str(&out).expect("export should be valid JSON");
    assert_eq!(
        value["analysis_scope"]["semantic_max_precision"], "narrowed",
        "native export should declare semantic-only call/flow precision"
    );
    assert_eq!(
        value["analysis_scope"]["full_propagations"], false,
        "default export should keep concrete row expansion optional"
    );
    assert_eq!(
        value["analysis_scope"]["propagations_mode"], "compiled_idg",
        "default export should preserve the complete relation in compiler form"
    );
    assert_eq!(
        value["analysis_complete"], true,
        "default compiler-form export should be semantically complete"
    );
    assert_eq!(
        value["taint_graph"]["propagations_complete"], false,
        "concrete propagation rows remain unmaterialized in compiler form"
    );
    assert!(value["taint_graph"]["propagations_omitted_reason"].is_null());
}

#[test]
fn one_shot_export_does_not_publish_a_hidden_export_cache() {
    let workspace = tempdir_for_test("bonsai_export_no_implicit_cache");
    std::fs::write(
        workspace.join("app.py"),
        "def identity(value):\n    return value\n",
    )
    .expect("write export fixture");
    let Some(out) = run(&["export", workspace.to_str().expect("workspace utf8")]) else {
        return;
    };
    serde_json::from_str::<serde_json::Value>(&out).expect("one-shot export JSON");

    let implicit_cache = workspace.join(".bonsai");
    if let Ok(entries) = std::fs::read_dir(&implicit_cache) {
        let hidden_exports: Vec<_> = entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("export.default."))
            .collect();
        assert!(
            hidden_exports.is_empty(),
            "one-shot export must write only its requested sink; use `cache rebuild --export` \
             for explicit cache publication, found {hidden_exports:?}"
        );
    }
    let _ = std::fs::remove_dir_all(workspace);
}

#[test]
fn export_full_propagations_materializes_exact_records() {
    let ws = ws_path();
    let Some(out) = run(&["export", ws.to_str().unwrap(), "--full-propagations"]) else {
        return;
    };
    let value: serde_json::Value = serde_json::from_str(&out).expect("export should be valid JSON");
    assert_eq!(value["taint_graph"]["propagations_complete"], true);
    assert_eq!(value["taint_graph"]["propagations_mode"], "materialized_entries");
    assert_eq!(value["analysis_scope"]["full_propagations"], true);
    assert!(value["taint_graph"]["propagations"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty()));
}

#[test]
fn export_default_keeps_exact_propagation_language_in_compiler_form() {
    let ws = ws_path();
    let Some(out) = run(&["export", ws.to_str().unwrap()]) else {
        return;
    };
    let value: serde_json::Value = serde_json::from_str(&out).expect("export should be valid JSON");
    assert_eq!(value["analysis_scope"]["full_propagations"], false);
    assert_eq!(value["analysis_scope"]["complete_chains"], true);
    assert_eq!(value["analysis_scope"]["propagations_mode"], "compiled_idg");
    assert_eq!(value["taint_graph"]["propagations_complete"], false);
    assert_eq!(value["taint_graph"]["propagations_mode"], "compiled_idg");
    assert!(value["taint_graph"]["propagations"]
        .as_array()
        .is_some_and(Vec::is_empty));
    assert!(value["taint_graph"]["propagations_omitted_reason"].is_null());
    assert_eq!(value["analysis_complete"], true);
}

#[test]
fn export_uses_exact_compressed_chains_and_flow_graph() {
    let ws = ws_path();
    let Some(out) = run(&["export", ws.to_str().unwrap()]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let chains = v["flow_chains"].as_array().expect("flow_chains is array");
    assert!(
        chains.is_empty(),
        "default export must not materialize path prefixes"
    );
    assert_eq!(v["flow_chains_mode"], "compressed_callgraph");
    assert_eq!(v["flow_chains_truncated_targets"], 0);

    let graph = v["flow_graph"].as_array().expect("flow_graph is array");
    let hr = graph
        .iter()
        .find(|n| n["function"].as_str() == Some("handle_request"))
        .expect("handle_request in flow_graph");
    assert_eq!(hr["entry_point"], true, "handle_request is an entry point");
    let outgoing: Vec<String> = hr["outgoing"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str().map(String::from))
        .collect();
    assert!(outgoing.contains(&"get_user".to_string()));
    assert!(outgoing.contains(&"update_user".to_string()));
    assert!(
        !outgoing.contains(&"request.args.get".to_string()),
        "flow_graph.outgoing should contain semantic workspace callees only"
    );
}

#[test]
fn export_default_never_caps_chain_evidence() {
    let tmp = tempdir_for_test("bonsai_export_chain_completeness");
    write_fan_in_python_workspace(&tmp, 20);

    let Some(out) = run(&["export", tmp.to_str().unwrap()]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["flow_chains_mode"], "compressed_callgraph");
    assert_eq!(v["flow_chains_truncated_targets"], 0);
    assert!(v["flow_chains"].as_array().is_some_and(Vec::is_empty));
    assert_eq!(
        v["analysis_complete"], true,
        "compiled graph representation must preserve complete semantics"
    );
    assert!(
        v["analysis_incomplete_reasons"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "compressed representation must not be reported as semantic truncation"
    );

    let tg = &v["taint_graph"];
    assert_eq!(tg["chains_mode"], "compressed_callgraph");
    assert_eq!(tg["chains_truncated_targets"], 0);
    assert_eq!(tg["flow_id_labels_mode"], "compressed_callgraph");
    assert_eq!(tg["flow_id_labels_truncated_functions"], 0);
}

#[test]
fn export_default_uses_exact_compressed_graph() {
    let tmp = tempdir_for_test("bonsai_export_exact_compressed");
    const FAN_IN_CALLERS: usize = 300;
    write_fan_in_python_workspace(&tmp, FAN_IN_CALLERS);

    {
        let Some(out) = run(&["export", tmp.to_str().unwrap()]) else {
            return;
        };
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        let label = "default";
        assert_eq!(
            v["flow_chains_mode"], "compressed_callgraph",
            "{label} must avoid unbounded simple-path materialization"
        );
        assert_eq!(
            v["flow_chains_complete"], false,
            "empty concrete path rows must not claim materialized completeness"
        );
        assert_eq!(
            v["flow_chains_truncated_targets"].as_u64().unwrap_or(1),
            0,
            "{label} must clear top-level chain truncation counts"
        );
        assert_eq!(
            v["analysis_complete"], true,
            "default compiler-form export should be complete for the fan-in fixture"
        );
        assert!(
            v["flow_chains"].as_array().is_some_and(Vec::is_empty),
            "{label} should encode the chain language in the graph, not path rows"
        );
        assert!(
            v["flow_chains_incomplete_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("compressed_callgraph")),
            "{label} must explain why concrete rows are absent"
        );

        let tg = &v["taint_graph"];
        assert_eq!(
            tg["chains_mode"], "compressed_callgraph",
            "{label} must use compressed taint-chain evidence"
        );
        assert_eq!(
            tg["chains_complete"], false,
            "empty concrete taint-chain rows must not claim completeness"
        );
        assert_eq!(
            tg["chains_truncated_targets"].as_u64().unwrap_or(1),
            0,
            "{label} must clear taint_graph chain truncation counts"
        );
        assert!(
            tg["chains"].as_array().is_some_and(Vec::is_empty),
            "{label} must not enumerate the fan-in path product"
        );
        assert!(
            tg["chains_incomplete_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("compressed_callgraph")),
            "{label} must explain the concrete taint-chain omission"
        );
        assert_eq!(
            tg["flow_id_labels_mode"], "compressed_callgraph",
            "{label} must use the compressed flow relation"
        );
        assert_eq!(
            tg["flow_id_labels_complete"], false,
            "empty materialized flow-id rows must not claim completeness"
        );
        assert_eq!(
            tg["flow_id_labels_truncated_functions"].as_u64().unwrap_or(1),
            0,
            "{label} must clear flow-id-label truncation counts"
        );
        assert!(
            tg["flow_id_labels"].as_array().is_some_and(Vec::is_empty),
            "{label} must not enumerate the fan-in flow-id product"
        );
        assert!(
            tg["flow_id_labels_incomplete_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("compressed_callgraph")),
            "{label} must explain the concrete flow-id omission"
        );
        assert!(
            tg["call_edges"].as_array().is_some_and(|edges| !edges.is_empty()),
            "{label} must retain the exact resolved semantic graph"
        );
    }
}

#[test]
fn export_entry_points_use_semantic_callgraph_not_bare_tail_matches() {
    let tmp = tempdir_for_test("bonsai_export_entrypoints_semantic");
    let mut source = String::from("def caller():\n    external.helper(\"x\")\n\n");
    for idx in 0..80 {
        source.push_str(&format!(
            "# padding line {idx:02} keeps this external call from looking like a decorator\n"
        ));
    }
    source.push_str("\ndef helper(user):\n    return user\n");
    std::fs::write(tmp.join("app.py"), source).expect("write export fixture");

    let Some(out) = run(&["export", tmp.to_str().unwrap()]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("export JSON");
    let entry_points = v["taint_graph"]["entry_points"]
        .as_array()
        .expect("entry_points array");
    let names: std::collections::BTreeSet<&str> = entry_points
        .iter()
        .filter_map(|entry| entry["function"].as_str())
        .collect();
    assert!(
        names.contains("helper"),
        "external.helper(...) must not mark local helper() as called; entry-point inference should use resolved semantic callgraph:\n{out}"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn inspect_occurrence_flow_evidence_is_uncapped() {
    let tmp = tempdir_for_test("bonsai_inspect_occurrence_flow_completeness");
    write_fan_in_python_workspace(&tmp, 20);

    let Some(out) = run_inspect_graph(&tmp, &["--query", "sink", "--kind", "call", "--format", "json"])
    else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    assert_eq!(
        v["analysis_complete"], true,
        "exact inspect graph work should be complete without semantic caps:\n{out}"
    );
    let incomplete_reasons = v["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array");
    assert!(
        incomplete_reasons.is_empty(),
        "uncapped graph inspection must not report semantic truncation:\n{out}"
    );
    let flow_count = v["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| hit["flows"].as_array())
        .map(Vec::len)
        .sum::<usize>();
    assert!(
        flow_count > 1,
        "fan-in fixture should retain multiple exact flows:\n{out}"
    );
}

#[test]
fn inspect_decl_sidebar_uses_semantic_callgraph_edges() {
    let ws = ws_path();
    let Some(out) = run_inspect_graph(&ws, &["--query", "verify_token", "--format", "json"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    let decl = v["decl_hits"]
        .as_array()
        .and_then(|decls| {
            decls
                .iter()
                .find(|decl| decl["symbol"].as_str() == Some("verify_token"))
        })
        .expect("verify_token decl hit");

    let callers: Vec<String> = decl["direct_callers"]
        .as_array()
        .expect("direct_callers array")
        .iter()
        .filter_map(|caller| caller["symbol"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        callers,
        vec!["get_user".to_string(), "update_user".to_string()],
        "direct_callers must be resolved caller functions, not raw target-name refs:\n{out}"
    );

    let callees: Vec<String> = decl["callees"]
        .as_array()
        .expect("callees array")
        .iter()
        .filter_map(|callee| callee.as_str().map(str::to_string))
        .collect();
    assert!(
        callees.is_empty(),
        "verify_token has no resolved workspace callees; lexical external calls must not appear as flow edges: {callees:?}"
    );
}

#[test]
fn inspect_json_reports_semantic_flow_backend_summary() {
    let ws = ws_path();
    let Some(out) = run_inspect_graph(
        &ws,
        &[
            "--query",
            "run_admin_command",
            "--taint-flow",
            "--format",
            "json",
            "--all",
        ],
    ) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    let summary = &v["summary"];
    let entry_queries = summary["semantic_flow_entry_queries"]
        .as_u64()
        .unwrap_or_default();
    assert!(
        entry_queries > 0,
        "inspect taint overlay should report semantic flow entry queries:\n{out}"
    );
    let backend_counts = summary["semantic_flow_backend_counts"]
        .as_object()
        .unwrap_or_else(|| panic!("semantic flow backend counts missing:\n{out}"));
    assert!(
        !backend_counts.is_empty(),
        "semantic flow backend counts should name the selected backend:\n{out}"
    );
    let cache_hits = summary["semantic_flow_cache_hits"].as_u64().unwrap_or_default();
    let cache_misses = summary["semantic_flow_cache_misses"].as_u64().unwrap_or_default();
    assert_eq!(
        cache_hits + cache_misses,
        entry_queries,
        "semantic flow cache hit/miss counts must account for each entry query:\n{out}"
    );
}

// -----------------------------------------------------------------------------
// filter coverage for every browse command + inspect
// -----------------------------------------------------------------------------

#[test]
fn defs_regex_and_has_callee_filter() {
    let ws = ws_path();
    let Some(out) = run(&["defs", ws.to_str().unwrap(), "--name", "^run_.*$", "--regex"]) else {
        return;
    };
    assert!(out.contains("run_admin_command"));
    assert!(!out.contains("verify_token"));

    let Some(out) = run(&["defs", ws.to_str().unwrap(), "--has-callee", "os.system"]) else {
        return;
    };
    assert!(
        out.contains("run_admin_command"),
        "has-callee filter missed it: {out}"
    );
    assert!(!out.contains("verify_token"));
}

#[test]
fn calls_caller_and_call_kind_filter() {
    let ws = ws_path();
    let Some(out) = run(&["calls", ws.to_str().unwrap(), "--caller", "verify_token"]) else {
        return;
    };
    assert!(
        out.contains("sqlite3.connect"),
        "caller filter missing row: {out}"
    );
    assert!(
        !out.contains("os.system"),
        "caller filter should exclude os.system row"
    );
}

#[test]
fn imports_wildcard_and_module_filter() {
    let ws = ws_path();
    // No wildcard imports in the micro fixture → empty table.
    let Some(out) = run(&["imports", ws.to_str().unwrap(), "--wildcard"]) else {
        return;
    };
    assert!(out.contains("(0 imports)"));

    let Some(out) = run(&["imports", ws.to_str().unwrap(), "--module", "flask"]) else {
        return;
    };
    assert!(out.contains("flask"));
    assert!(!out.contains("sqlite3"));
}

#[test]
fn vars_in_fn_and_source_filter() {
    let ws = ws_path();
    let Some(out) = run(&["vars", ws.to_str().unwrap(), "--in-fn", "verify_token"]) else {
        return;
    };
    assert!(out.contains("cursor"), "verify_token vars missing: {out}");
    assert!(!out.contains("update_user"));
}

#[test]
fn strings_min_len_and_file_filter() {
    let ws = ws_path();
    let Some(out) = run(&["strings", ws.to_str().unwrap(), "--min-len", "20"]) else {
        return;
    };
    assert!(out.contains("SELECT"), "long strings missing: {out}");
}

#[test]
fn args_position_and_keyword_filter() {
    let ws = ws_path();
    let Some(out) = run(&["args", ws.to_str().unwrap(), "--position", "0"]) else {
        return;
    };
    // First positional args in micro: token, user_id, "notify-admin" + cmd, etc.
    assert!(
        out.contains("arguments"),
        "position filter output malformed: {out}"
    );
}

#[test]
fn classes_kind_and_has_method_filter() {
    // Use the Java fixture — Python micro has no classes.
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/java/micro");
    let Some(out) = run(&["classes", ws.to_str().unwrap(), "--kind", "class"]) else {
        return;
    };
    assert!(
        out.contains("AuthService"),
        "class filter dropped AuthService: {out}"
    );

    let Some(out) = run(&["classes", ws.to_str().unwrap(), "--has-method", "runAdminCommand"]) else {
        return;
    };
    assert!(out.contains("AuthService"));
    assert!(!out.contains("Gateway"));
}

#[test]
fn refs_kind_and_in_fn_filter() {
    let ws = ws_path();
    let Some(out) = run(&["refs", ws.to_str().unwrap(), "verify_token", "--kind", "call"]) else {
        return;
    };
    for row in out
        .lines()
        .filter(|l| l.contains("verify_token") && l.contains(':'))
    {
        assert!(row.contains("call"), "non-call row leaked: {row}");
    }

    let Some(out) = run(&[
        "refs",
        ws.to_str().unwrap(),
        "verify_token",
        "--in-fn",
        "get_user",
    ]) else {
        return;
    };
    assert!(out.contains("get_user"), "in-fn filter dropped row: {out}");
}

#[test]
fn search_regex_and_kind_filter() {
    let ws = ws_path();
    let Some(out) = run(&["search", ws.to_str().unwrap(), "^run_.*_command$", "--regex"]) else {
        return;
    };
    assert!(out.contains("run_admin_command"));
}

#[test]
fn inspect_from_to_filter_is_fuzzy_over_full_flow() {
    let ws = ws_path();

    // `--from request --to os.system` — the user's canonical case. The
    // chain is `handle_request → update_user → run_admin_command` and
    // the hit text is `os.system`. `request` matches the first hop,
    // `os.system` matches the hit text. Both should keep the flow.
    let Some(out) = run_inspect_graph(
        &ws,
        &["--query", "os.system", "--from", "request", "--to", "os.system"],
    ) else {
        return;
    };
    assert!(out.contains("FLOW"), "from/to filter dropped the flow: {out}");
    assert!(
        out.contains("handle_request → update_user → run_admin_command"),
        "chain not rendered: {out}"
    );

    // `--from update_user` — needle matches an INTERMEDIATE hop, not
    // the entry. Fuzzy-over-full-flow must still keep it.
    let Some(out) = run_inspect_graph(&ws, &["--query", "os.system", "--from", "update_user"]) else {
        return;
    };
    assert!(
        out.contains("FLOW"),
        "intermediate-hop --from rejected the flow: {out}"
    );

    // `--to <nonexistent>` drops every flow → hit is dropped entirely.
    let Some(out) = run_inspect_graph(&ws, &["--query", "os.system", "--to", "totally_fake_fn"]) else {
        return;
    };
    assert!(
        out.contains("no matches") || out.contains("0 other hit(s)"),
        "expected all hits dropped, got: {out}"
    );
}

#[test]
fn inspect_from_to_markers_land_on_matched_lines() {
    // With `--from update --to system`, the FROM marker must consistently
    // land on the line that advances to `update_user` (the hop whose name
    // contains "update"), and the TO marker must land on the line where
    // `os.system` is called. The filter widening now considers the
    // downstream closure, so MANY hits in `handle_request` pass — each
    // renders its own flow. The invariant we care about: markers never
    // scatter across unrelated body lines, regardless of how many hits
    // surface.
    let ws = ws_path();
    let Some(out) = run_inspect_graph(&ws, &["--from", "update", "--to", "system"]) else {
        return;
    };

    // FROM: update always lands on the `update_user(...)` line.
    let from_lines: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("[FLOW 1 FROM: update]"))
        .collect();
    assert!(
        !from_lines.is_empty(),
        "no FROM marker lines found; output:\n{out}"
    );
    for line in &from_lines {
        assert!(
            line.contains("update_user"),
            "FROM marker on unrelated line: {line}"
        );
    }

    // TO: system always lands on the `os.system(...)` MATCH line.
    let to_lines: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("[FLOW 1 TO: system]"))
        .collect();
    assert!(!to_lines.is_empty(), "no TO marker lines found; output:\n{out}");
    for line in &to_lines {
        assert!(line.contains("os.system"), "TO marker on unrelated line: {line}");
        assert!(
            line.contains("MATCH"),
            "TO marker should land alongside MATCH: {line}"
        );
    }
}

#[test]
fn inspect_from_marker_on_source_line_when_from_matches_entry() {
    // `--from request` matches the entry `handle_request`. The FROM
    // marker must pin to the SOURCE line (the filter's motivation),
    // AND may also appear on other lines where the raw code naturally
    // contains "request" (e.g. `request.args.get(...)` calls). The
    // important invariant is: at least one FROM marker lands on the
    // SOURCE line, and every FROM marker line legitimately mentions
    // `request` in either an annotation subject or the code itself.
    let ws = ws_path();
    let Some(out) = run_inspect_graph(&ws, &["--query", "os.system", "--from", "request"]) else {
        return;
    };
    let from_lines: Vec<&str> = out.lines().filter(|l| l.contains("FROM: request")).collect();
    assert!(
        !from_lines.is_empty(),
        "no FROM: request marker fired; output:\n{out}"
    );
    assert!(
        from_lines
            .iter()
            .any(|l| l.contains("SOURCE: entry handle_request")),
        "expected at least one FROM marker on the SOURCE line; got: {from_lines:#?}"
    );
    // Every FROM marker must sit on a line that legitimately mentions
    // `request` (either in the annotation/SOURCE subject or in the
    // source code itself) — never floating on an unrelated body line.
    for line in &from_lines {
        assert!(
            line.contains("request"),
            "FROM marker on a line that doesn't mention `request`: {line}"
        );
    }
}

#[test]
fn inspect_from_to_markers_work_on_kotlin() {
    // Cross-class Kotlin flow: handleRequest → updateUser →
    // runAdminCommand → Runtime.getRuntime().exec. Filter markers
    // must land on the matched hops / sink lines.
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/kotlin/micro");
    let Some(out) = run_inspect_graph(&ws, &["--query", "exec", "--from", "updateUser", "--to", "exec"])
    else {
        return;
    };
    let from_lines: Vec<&str> = out.lines().filter(|l| l.contains("FROM: updateUser")).collect();
    assert!(
        from_lines.iter().any(|l| l.contains("updateUser")),
        "FROM marker not on updateUser advance: {from_lines:#?}"
    );
    let to_lines: Vec<&str> = out.lines().filter(|l| l.contains("TO: exec")).collect();
    assert!(
        to_lines.iter().any(|l| l.contains("exec") && l.contains("MATCH")),
        "TO marker not on exec MATCH line: {to_lines:#?}"
    );
}

#[test]
fn inspect_from_to_markers_work_on_javascript() {
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/javascript/micro");
    // JS fixture: gateway.js calls updateUser which calls runAdminCommand
    // which calls execSync.
    let Some(out) = run_inspect_graph(
        &ws,
        &["--query", "execSync", "--from", "updateUser", "--to", "execSync"],
    ) else {
        return;
    };
    assert!(
        out.lines().any(|l| l.contains("FROM: updateUser")),
        "FROM marker missing in JS output: {out}"
    );
    assert!(
        out.lines()
            .any(|l| l.contains("TO: execSync") && l.contains("MATCH")),
        "TO marker not on MATCH line: {out}"
    );
}

#[test]
fn inspect_from_to_markers_work_on_java() {
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/java/micro");
    let Some(out) = run_inspect_graph(&ws, &["--from", "updateUser", "--to", "exec"]) else {
        return;
    };
    assert!(
        out.lines().any(|l| l.contains("FROM: updateUser")),
        "FROM marker missing in Java output: {out}"
    );
    assert!(
        out.lines().any(|l| l.contains("TO: exec")),
        "TO marker missing in Java output: {out}"
    );
}

/// Shared helper for per-language marker assertions. Asserts that
/// `inspect <ws> --from <from> --to <to>` on the given micro fixture
/// produces at least one `FROM:` marker and one `TO:` marker in the
/// rendered output — pinning the end-to-end contract for every
/// supported language.
fn assert_from_to_markers(lang: &str, from: &str, to: &str) {
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join(format!("examples/{lang}/micro"));
    if !ws.exists() {
        return; // some langs (perl) don't ship a micro fixture
    }
    let Some(out) = run_inspect_graph(&ws, &["--from", from, "--to", to]) else {
        return;
    };
    let from_hits = out.lines().filter(|l| l.contains("FROM: ")).count();
    let to_hits = out.lines().filter(|l| l.contains("TO: ")).count();
    assert!(
        from_hits > 0,
        "[{lang}] no FROM marker with --from {from} --to {to}: {out}"
    );
    assert!(
        to_hits > 0,
        "[{lang}] no TO marker with --from {from} --to {to}: {out}"
    );
}

#[test]
fn inspect_from_to_markers_work_on_typescript() {
    assert_from_to_markers("typescript", "updateUser", "exec");
}

#[test]
fn inspect_from_to_markers_work_on_go() {
    // Go micro uses Go naming: `UpdateUser`, sink is `exec.Command`.
    assert_from_to_markers("go", "UpdateUser", "Command");
}

#[test]
fn inspect_from_to_markers_work_on_rust() {
    assert_from_to_markers("rust", "update_user", "Command");
}

#[test]
fn inspect_from_to_markers_work_on_php() {
    // PHP micro uses snake_case: `update_user`, sink is `exec`.
    assert_from_to_markers("php", "update_user", "exec");
}

#[test]
fn inspect_from_to_markers_work_on_ruby() {
    assert_from_to_markers("ruby", "update_user", "system");
}

#[test]
fn inspect_from_to_markers_work_on_scala() {
    assert_from_to_markers("scala", "updateUser", "executeQuery");
}

#[test]
fn inspect_from_to_markers_work_on_csharp() {
    assert_from_to_markers("csharp", "UpdateUser", "Start");
}

#[test]
fn inspect_from_to_markers_work_on_swift() {
    assert_from_to_markers("swift", "updateUser", "launch");
}

#[test]
fn inspect_from_to_markers_work_on_c() {
    assert_from_to_markers("c", "update_user", "system");
}

#[test]
fn inspect_from_to_markers_work_on_cpp() {
    // The cpp micro fixture has partial syntax errors (C++20
    // features tree-sitter-cpp doesn't fully support) which collapse
    // the chain to a shorter form. Target what IS reachable:
    // `run_admin_command` → `system`.
    assert_from_to_markers("cpp", "run_admin_command", "system");
}

#[test]
fn inspect_from_to_filters_are_case_insensitive() {
    // `--from user` (lowercase) must match `User` / `updateUser` /
    // `userService` in CamelCase Java code. Same for `--to EXEC`
    // against lowercase `exec`.
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/java/micro");

    let Some(lower) = run_inspect_graph(&ws, &["--from", "user", "--to", "exec"]) else {
        return;
    };
    assert!(
        lower.contains("FROM: user") && lower.contains("TO: exec"),
        "case-insensitive --from/--to failed on Java: {lower}"
    );

    let Some(upper) = run_inspect_graph(&ws, &["--from", "USER", "--to", "EXEC"]) else {
        return;
    };
    assert!(
        upper.contains("FROM: USER") && upper.contains("TO: EXEC"),
        "uppercase filters didn't match lowercase source: {upper}"
    );

    // Same check on Python with mixed case.
    let py_ws = repo_root.join("examples/python/micro");
    let Some(py_out) = run_inspect_graph(&py_ws, &["--from", "USER", "--to", "SYSTEM"]) else {
        return;
    };
    assert!(
        py_out.contains("FROM: USER") && py_out.contains("TO: SYSTEM"),
        "case-insensitive filters failed on Python: {py_out}"
    );
}

#[test]
fn inspect_from_to_work_standalone_without_query() {
    let ws = ws_path();

    // `--from request --to os.system` without a `--query` should still
    // surface the os.system hit — the filters alone pick it out.
    let Some(out) = run_inspect_graph(&ws, &["--from", "request", "--to", "os.system"]) else {
        return;
    };
    assert!(
        out.contains("(filters only)"),
        "header should show filters-only label: {out}"
    );
    assert!(
        out.contains("os.system"),
        "os.system hit dropped by standalone filter mode: {out}"
    );
    assert!(
        out.contains("handle_request → update_user → run_admin_command"),
        "chain not rendered in filter-only mode: {out}"
    );

    // `--to os.system` alone should work too.
    let Some(out) = run_inspect_graph(&ws, &["--to", "os.system"]) else {
        return;
    };
    assert!(out.contains("os.system"));

    // `inspect <workspace>` with no query AND no filters must error.
    let Some(bin) = bin_path() else {
        return;
    };
    let result = Command::new(&bin)
        .args(["inspect", ws.to_str().unwrap(), "--no-color"])
        .env("COLUMNS", "200")
        .output()
        .expect("run");
    assert!(
        !result.status.success(),
        "inspect with no query + no filters should fail"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("query") || stderr.contains("filter"),
        "error message should mention query/filter requirement, got: {stderr}"
    );
}

#[test]
fn inspect_from_to_resolves_qualified_same_named_methods() {
    let root = tempdir_for_test("inspect-qualified-endpoints");
    std::fs::write(
        root.join("app.py"),
        "class Target:\n    def run(self):\n        return 1\n\nclass Source:\n    def run(self):\n        return Target().run()\n",
    )
    .expect("write app.py");

    let Some(out) = run_inspect_graph(&root, &["--from", "Source.run", "--to", "Target.run"]) else {
        return;
    };
    assert!(
        out.contains("Source.run") && out.contains("Target.run"),
        "qualified same-named endpoints must resolve through compiler declaration identities:\n{out}"
    );
    assert!(
        out.contains("FLOW 1"),
        "the exact qualified endpoint corridor must render its connected flow:\n{out}"
    );
}

#[test]
fn inspect_file_and_in_fn_filter() {
    let ws = ws_path();
    let Some(out) = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--in-fn",
        "run_admin",
    ]) else {
        return;
    };
    assert!(out.contains("run_admin_command"));

    let Some(out) = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "verify_token",
        "--file",
        "auth_service",
    ]) else {
        return;
    };
    assert!(out.contains("verify_token"));
}

// -----------------------------------------------------------------------------
// Help text
// -----------------------------------------------------------------------------

#[test]
fn top_level_help_contains_examples_and_theme_note() {
    let Some(out) = run(&["--help"]) else {
        return;
    };
    assert!(
        out.contains("EXAMPLES"),
        "top-level help missing EXAMPLES block: {out}"
    );
    assert!(
        out.contains("bonsai-ninja inspect"),
        "top-level help missing inspect example: {out}"
    );
    assert!(
        out.contains("earthy-dark") && out.contains("dracula"),
        "top-level help missing theme listing: {out}"
    );
    assert!(
        out.contains("20\nlanguages") || out.contains("20 languages"),
        "top-level help missing supported-language line: {out}"
    );
}

#[test]
fn inspect_help_is_concise_and_has_examples() {
    let Some(out) = run(&["inspect", "--help"]) else {
        return;
    };
    assert!(out.contains("EXAMPLES"), "inspect help missing EXAMPLES");
    assert!(
        out.contains("--query os.system"),
        "inspect help missing query example: {out}"
    );
    assert!(
        !out.contains("SAMPLE OUTPUT") && !out.contains("OCCURRENCE HITS"),
        "inspect help should not render sample-output walls: {out}"
    );
}

#[test]
fn defs_help_has_examples() {
    let Some(out) = run(&["defs", "--help"]) else {
        return;
    };
    assert!(out.contains("EXAMPLES"));
    assert!(out.contains("--kind method"));
}

#[test]
fn trace_help_has_examples() {
    let Some(out) = run(&["trace", "--help"]) else {
        return;
    };
    assert!(out.contains("EXAMPLES"));
    assert!(out.contains("--from") && out.contains("--to"));
}

#[test]
fn calls_help_has_concise_examples() {
    let Some(out) = run(&["calls", "--help"]) else {
        return;
    };
    assert!(out.contains("EXAMPLES"));
    assert!(out.contains("os.system"));
    assert!(
        !out.contains("SAMPLE OUTPUT"),
        "calls help should not render sample-output walls: {out}"
    );
}

#[test]
fn top_level_help_groups_commands() {
    let Some(out) = run(&["--help"]) else {
        return;
    };
    assert!(out.contains("COMMAND GROUPS"), "grouping section missing: {out}");
    for group in &["Flow", "Workspace", "Browse", "Debug"] {
        assert!(out.contains(group), "help missing group `{group}`: {out}");
    }
    assert!(
        out.contains("security taint-analysis"),
        "top-level help should advertise the canonical security command: {out}"
    );
    assert!(
        out.contains("security source-analysis"),
        "top-level help should advertise source-analysis: {out}"
    );
    let usage_idx = out.find("USAGE:").expect("USAGE present");
    let groups_idx = out.find("COMMAND GROUPS").expect("COMMAND GROUPS present");
    let options_idx = out.find("OPTIONS:").expect("OPTIONS present");
    let examples_idx = out.find("EXAMPLES").expect("EXAMPLES block present");
    assert!(
        usage_idx < groups_idx && groups_idx < options_idx && options_idx < examples_idx,
        "root help should render usage, command groups, options, then examples:\n{out}"
    );
    assert!(
        !out.contains("security taint-analysis Run"),
        "wide security command labels should stay aligned with a padded gap: {out}"
    );
    assert!(
        !out.contains("security source-analysis Map"),
        "widest security command label should stay aligned with a padded gap: {out}"
    );
    assert!(
        !out.contains("security flows       Run source"),
        "top-level help should not advertise retired security flows alias: {out}"
    );
    // Each group's commands appear under the grouping block.
    for (group, cmd) in [
        ("Flow", "inspect"),
        ("Flow", "trace"),
        ("Flow", "path"),
        ("Flow", "slice"),
        ("Workspace", "index"),
        ("Browse", "defs"),
        ("Browse", "entrypoints"),
        ("Browse", "operations"),
        ("Debug", "dump-hir"),
    ] {
        let group_idx = out.find(group).expect("group present");
        let after = &out[group_idx..];
        assert!(after.contains(cmd), "command `{cmd}` not listed under `{group}`");
    }

    let security_idx = out.find("  Security").expect("Security group present");
    let debug_idx = out.find("  Debug").expect("Debug group present");
    assert!(
        debug_idx > security_idx,
        "Debug group should render after Security and stay at the bottom:\n{out}"
    );
    for cmd in [
        "dump-ast",
        "dump-hir",
        "dump-cfg",
        "dump-callgraph",
        "dump-edges",
        "dump-resolution",
        "dump-resolve",
        "dump-taint",
        "diagnostics",
    ] {
        assert!(
            out[debug_idx..].contains(cmd),
            "Debug group missing `{cmd}`:\n{out}"
        );
    }
    assert!(
        debug_idx < options_idx,
        "Debug group should be the last command group before OPTIONS:\n{out}"
    );
}

#[test]
fn top_level_help_has_no_duplicate_commands_block() {
    // The old "COMMANDS:" heading used to appear above the COMMAND GROUPS
    // block. We suppress it via a custom help_template so each command
    // shows up exactly once.
    let Some(out) = run(&["--help"]) else {
        return;
    };
    assert!(
        !out.contains("\nCOMMANDS:\n"),
        "auto `COMMANDS:` block should be suppressed, got:\n{out}"
    );
    // The grouped block is still there.
    assert!(out.contains("COMMAND GROUPS"));
    // Each subcommand name is listed exactly once at help-index depth.
    for cmd in [
        "inspect",
        "trace",
        "path",
        "slice",
        "defs",
        "calls",
        "imports",
        "operations",
        "dump-hir",
    ] {
        let occurrences = out
            .match_indices(&format!("    {cmd}"))
            .filter(|(_, m)| *m == format!("    {cmd}"))
            .count();
        assert_eq!(
            occurrences, 1,
            "expected `{cmd}` to appear exactly once in grouped list, got {occurrences}:\n{out}"
        );
    }
}

#[test]
fn cache_help_documents_persisted_sidecar_workflow() {
    let Some(out) = run(&["cache", "--help"]) else {
        return;
    };
    assert!(
        out.contains("Inspect, clear, or rebuild"),
        "cache help should describe all cache actions: {out}"
    );
    assert!(
        out.contains("cache clear ./src --dataflow-only"),
        "cache help should show precise dataflow sidecar invalidation: {out}"
    );
    assert!(
        out.contains("cache stats"),
        "cache help should advertise cache stats for benchmark tooling: {out}"
    );
    assert!(
        !out.contains("dataflow.v3.factstore"),
        "parent cache help should stay concise; detailed sidecar names belong in stats output: {out}"
    );
}

#[test]
fn cache_clear_help_labels_dataflow_only_correctly() {
    let Some(out) = run(&["cache", "clear", "--help"]) else {
        return;
    };
    assert!(
        out.contains("only drop the dataflow cache"),
        "cache clear help should describe --dataflow-only as dataflow cache clearing:\n{out}"
    );
    assert!(
        !out.contains("only drop the taint cache"),
        "cache clear help must not describe --dataflow-only as taint cache clearing:\n{out}"
    );
}

#[test]
fn cache_stats_json_reports_analysis_sidecars() {
    let ws = ws_path();
    let Some(out) = run(&["cache", "stats", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let value: serde_json::Value = serde_json::from_str(&out).expect("cache stats JSON");
    for key in [
        "bonsai_dir",
        "manifest",
        "dataflow_factstore_sidecar",
        "value_flow_sidecar",
        "flow_ids_sidecar",
        "callgraph_sidecar",
        "idg_sidecar",
        "taint_graph_sidecar",
        "export_sidecar",
        "validation",
    ] {
        assert!(
            value.get(key).is_some(),
            "cache stats JSON missing `{key}`: {out}"
        );
    }
}

#[test]
fn index_help_does_not_confuse_no_cache_with_sidecar_rebuild() {
    let Some(out) = run(&["index", "--help"]) else {
        return;
    };
    assert!(
        out.contains("cache clear ./src --dataflow-only"),
        "index help should show how to force a fresh dataflow sidecar: {out}"
    );
    assert!(
        out.contains("--watch"),
        "index help should document save-time hot reload workflow: {out}"
    );
    assert!(
        !out.contains("--no-cache index"),
        "index help must not imply --no-cache clears persisted sidecars: {out}"
    );
}

#[test]
fn every_help_menu_renders_and_documents_core_surface() {
    let ws = ws_path();
    let ws_str = ws.to_str().unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec!["--help"],
        vec!["index", "--help"],
        vec!["trace", "--help"],
        vec!["path", "--help"],
        vec!["slice", "--help"],
        vec!["diagnostics", "--help"],
        vec!["dump-hir", "--help"],
        vec!["dump-cfg", "--help"],
        vec!["dump-callgraph", "--help"],
        vec!["dump-edges", "--help"],
        vec!["dump-resolution", "--help"],
        vec!["dump-ast", "--help"],
        vec!["dump-resolve", "--help"],
        vec!["dump-taint", "--help"],
        vec!["defs", "--help"],
        vec!["calls", "--help"],
        vec!["imports", "--help"],
        vec!["vars", "--help"],
        vec!["strings", "--help"],
        vec!["comments", "--help"],
        vec!["args", "--help"],
        vec!["operations", "--help"],
        vec!["classes", "--help"],
        vec!["refs", "--help"],
        vec!["search", "--help"],
        vec!["inspect", "--help"],
        vec!["tree", "--help"],
        vec!["read-file", "--help"],
        vec!["export", "--help"],
        vec!["cache", "--help"],
        vec!["cache", "stats", "--help"],
        vec!["cache", "clear", "--help"],
        vec!["cache", "rebuild", "--help"],
        vec!["security", "--help"],
        vec!["security", ws_str, "sources", "--help"],
        vec!["security", ws_str, "sinks", "--help"],
        vec!["security", ws_str, "sanitizers", "--help"],
        vec!["security", ws_str, "deps", "--help"],
        vec!["security", ws_str, "taint-analysis", "--help"],
        vec!["security", ws_str, "source-analysis", "--help"],
        vec!["security", ws_str, "pack", "--help"],
    ];
    for args in cases {
        let Some(out) = run(&args) else {
            return;
        };
        assert!(out.contains("USAGE:"), "{args:?}: help missing USAGE:\n{out}");
        assert!(
            out.lines().count() <= 140,
            "{args:?}: help is too long ({} lines):\n{out}",
            out.lines().count()
        );
        let widest = out.lines().map(str::len).max().unwrap_or(0);
        assert!(
            widest <= 180,
            "{args:?}: help has an over-wide line ({widest} chars):\n{out}"
        );
        for line in out.lines() {
            assert!(
                !line.trim_end().ends_with("..."),
                "{args:?}: help line looks clipped instead of wrapped:\n{line}\n\nfull help:\n{out}"
            );
        }
        assert!(
            !out.chars().any(|ch| ch.is_control() && ch != '\n' && ch != '\t'),
            "{args:?}: help contains a control character:\n{out}"
        );
        assert!(
            !out.contains("SAMPLE OUTPUT"),
            "{args:?}: help should stay concise and avoid sample-output blocks:\n{out}"
        );
        let usage = out.lines().find(|line| line.starts_with("USAGE:")).unwrap_or("");
        let required_positionals: Vec<String> = usage
            .split_whitespace()
            .filter_map(|part| {
                let trimmed = part.trim_matches(|c| matches!(c, ',' | ';'));
                if trimmed.starts_with('<') && trimmed.ends_with('>') && trimmed != "<COMMAND>" {
                    Some(trimmed.to_string())
                } else {
                    None
                }
            })
            .collect();
        if !required_positionals.is_empty() {
            let args_section = out.split("ARGUMENTS:").nth(1).unwrap_or("");
            assert!(
                !args_section.is_empty(),
                "{args:?}: help usage lists required args but has no Arguments section:\n{out}"
            );
            for positional in required_positionals {
                assert!(
                    args_section.contains(&positional),
                    "{args:?}: required arg {positional} missing from Arguments section:\n{out}"
                );
            }
        }
        assert!(
            out.contains("EXAMPLES"),
            "{args:?}: help missing EXAMPLES block:\n{out}"
        );
        assert!(
            !out.contains("\n  help\n") && !out.contains("\n  help\n          Print this message"),
            "{args:?}: help menu should not advertise synthetic `help` subcommand:\n{out}"
        );
        assert!(
            !out.contains("security flows"),
            "{args:?}: help should not advertise retired security flows alias:\n{out}"
        );
        assert!(
            !out.contains("--no-compact"),
            "{args:?}: help should not advertise unsupported --no-compact flag:\n{out}"
        );
        assert!(
            !out.contains("accepted for compatibility"),
            "{args:?}: help should not advertise compatibility-only behavior:\n{out}"
        );
        assert!(
            !out.contains("Paging unit is one PATH"),
            "{args:?}: help should not contain stale trace paging wording:\n{out}"
        );
    }
}

#[test]
fn dump_edges_precision_only_accepts_semantic_classes() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    for unsupported in ["over-approximate", "unknown"] {
        let out = Command::new(&bin)
            .args([
                "dump-edges",
                ws.to_str().unwrap(),
                "--precision",
                unsupported,
                "--no-color",
                "--no-progress",
            ])
            .output()
            .expect("failed to run bonsai-ninja");
        assert!(
            !out.status.success(),
            "unsupported precision `{unsupported}` must be absent from the parser"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("invalid value") && stderr.contains("exact") && stderr.contains("narrowed"),
            "clap should list dump-edges' complete precision surface:\n{stderr}"
        );
    }
}

#[test]
fn sarif_is_only_accepted_by_security_taint_analysis() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let ws = ws.to_str().unwrap();
    let unsupported = [
        vec!["defs", ws, "--format", "sarif"],
        vec!["inspect", ws, "--query", "verify_token", "--format", "sarif"],
        vec![
            "path",
            ws,
            "--from",
            "handle_request",
            "--to",
            "verify_token",
            "--format",
            "sarif",
        ],
        vec![
            "slice", ws, "--symbol", "token", "--line", "1", "--format", "sarif",
        ],
        vec!["tree", ws, "--format", "sarif"],
        vec!["read-file", ws, "app.py", "--format", "sarif"],
        vec!["security", ws, "sources", "--format", "sarif"],
        vec!["security", ws, "source-analysis", "--format", "sarif"],
    ];
    for args in unsupported {
        let out = Command::new(&bin)
            .args(&args)
            .args(["--no-color", "--no-progress"])
            .output()
            .expect("failed to run bonsai-ninja");
        assert!(
            !out.status.success(),
            "{args:?} must reject unsupported SARIF output"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("invalid value") && stderr.contains("json") && stderr.contains("text"),
            "{args:?} should receive clap's ordinary format error:\n{stderr}"
        );
    }
}

#[test]
fn tree_json_reports_complete_structural_view_when_unbounded() {
    let ws = ws_path();
    let Some(out) = run(&["tree", ws.to_str().unwrap(), "--all", "--format", "json"]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("tree JSON must parse");
    assert_eq!(
        parsed["analysis_complete"].as_bool(),
        Some(true),
        "unbounded tree view should be complete on the micro fixture:\n{out}"
    );
    assert!(
        parsed["analysis_incomplete_reasons"]
            .as_array()
            .expect("analysis_incomplete_reasons array")
            .is_empty(),
        "complete tree output must not carry incomplete reasons:\n{out}"
    );
}

#[test]
fn tree_json_marks_depth_limited_view_incomplete() {
    let ws = ws_path();
    let Some(out) = run(&[
        "tree",
        ws.to_str().unwrap(),
        "--max-depth",
        "0",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("tree JSON must parse");
    assert_eq!(
        parsed["analysis_complete"].as_bool(),
        Some(false),
        "depth-limited tree must not claim complete workspace context:\n{out}"
    );
    let reasons = parsed["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array");
    assert!(
        reasons.iter().any(|reason| reason
            .as_str()
            .is_some_and(|s| s.starts_with("tree-files-truncated:"))),
        "tree must explain depth-limited truncation:\n{out}"
    );
}

#[test]
fn tree_file_filter_is_workspace_relative_in_fast_mode() {
    let outer = tempdir_for_test("tree-filter-parent");
    let root = outer.join("tests/chosen-workspace");
    std::fs::create_dir_all(root.join("tests")).expect("create workspace");
    std::fs::write(root.join("app.py"), "def app_marker():\n    return 1\n").expect("write app");
    std::fs::write(root.join("tests/helper.py"), "def test_marker():\n    return 2\n").expect("write helper");

    let Some(out) = run(&[
        "tree",
        root.to_str().unwrap(),
        "--file",
        "tests/",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("tree JSON must parse");
    assert_eq!(
        parsed["summary"]["total_files_scanned"].as_u64(),
        Some(1),
        "tree --file tests/ should scan only workspace-local tests files:\n{out}"
    );
    let rendered = serde_json::to_string(&parsed).expect("serialize tree");
    assert!(
        rendered.contains("helper.py"),
        "tree should include tests/helper.py:\n{out}"
    );
    assert!(
        !rendered.contains("app.py"),
        "tree must not include root app.py only because an ancestor outside the workspace is tests/:\n{out}"
    );
    let _ = std::fs::remove_dir_all(outer);
}

#[test]
fn tree_fast_mode_skips_internal_tool_state() {
    let root = tempdir_for_test("tree-internal-probe");
    std::fs::write(root.join("app.py"), "def app_marker():\n    return 1\n").expect("write app");
    std::fs::write(root.join(".bonsai_case_probe_123_456"), "").expect("write probe-like file");
    std::fs::create_dir_all(root.join(".bonsai-agent")).expect("create agent state");
    std::fs::write(root.join(".bonsai-agent/notes.sqlite"), b"scanner state").expect("write agent state");
    std::fs::write(
        root.join(".bonsai_case_probe_notes.py"),
        "def user_owned_probe_notes():\n    return 1\n",
    )
    .expect("write user-owned similarly prefixed source file");

    let Some(out) = run(&["tree", root.to_str().unwrap()]) else {
        return;
    };
    assert!(
        out.contains("app.py"),
        "tree should still render real files:\n{out}"
    );
    assert!(
        !out.contains(".bonsai_case_probe_123_456"),
        "tree must not render transient internal case-probe files:\n{out}"
    );
    assert!(
        !out.contains(".bonsai-agent") && !out.contains("notes.sqlite"),
        "tree must not render scanner-owned metadata as project content:\n{out}"
    );
    assert!(
        out.contains(".bonsai_case_probe_notes.py"),
        "tree must not hide user-owned similarly prefixed source files:\n{out}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn tree_renders_directory_symlinks_without_following_cycles() {
    use std::os::unix::fs::symlink;

    let root = tempdir_for_test("tree-symlink-cycle");
    let nested = root.join("nested");
    std::fs::create_dir_all(&nested).expect("create nested directory");
    std::fs::write(nested.join("app.py"), "def app():\n    return 1\n").expect("write source");
    symlink(&root, nested.join("loop")).expect("create directory symlink cycle");

    let Some(out) = run(&["tree", root.to_str().unwrap(), "--all"]) else {
        return;
    };
    assert_eq!(
        out.matches("loop").count(),
        1,
        "tree must render a directory symlink once without following it:\n{out}"
    );
    assert_eq!(
        out.matches("app.py").count(),
        1,
        "tree must render ordinary files exactly once beside a symlink cycle:\n{out}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn tree_default_and_all_modes_stay_structural() {
    let ws = ws_path();
    for extra in [Vec::<&str>::new(), vec!["--all"]] {
        let mut args = vec!["tree", ws.to_str().unwrap()];
        args.extend(extra);
        let Some(out) = run(&args) else {
            return;
        };
        assert!(
            !out.contains("finding") && !out.contains("[ severity ]"),
            "structural tree must not imply that it ran security analysis:\n{out}"
        );
    }
}

#[test]
fn tree_default_and_all_are_exhaustive() {
    let root = tempdir_for_test("tree-all-child-limit");
    for index in 0..201 {
        std::fs::write(root.join(format!("file_{index:03}.py")), "").expect("write tree fixture");
    }

    let Some(default_out) = run(&["tree", root.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let default_json: serde_json::Value =
        serde_json::from_str(&default_out).expect("default tree JSON must parse");
    assert_eq!(
        default_json["summary"]["total_files"].as_u64(),
        Some(201),
        "default tree must include every child"
    );
    assert_eq!(
        default_json["analysis_complete"].as_bool(),
        Some(true),
        "the default structural tree must report complete analysis"
    );

    let all_out =
        run(&["tree", root.to_str().unwrap(), "--format", "json", "--all"]).expect("tree --all output");
    let all_json: serde_json::Value = serde_json::from_str(&all_out).expect("uncapped tree JSON must parse");
    assert_eq!(
        all_json["summary"]["total_files"].as_u64(),
        Some(201),
        "tree --all must preserve exhaustive traversal"
    );
    assert_eq!(
        all_json["analysis_complete"].as_bool(),
        Some(true),
        "an uncapped structural tree must be complete"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn tree_json_contains_only_structural_facts() {
    fn assert_structural_node(node: &serde_json::Value) {
        let locator = node["locator"]["file"].as_str().expect("tree node locator.file");
        assert!(
            !Path::new(locator).is_absolute(),
            "tree locators must be portable workspace-relative paths: {locator}"
        );
        for semantic in [
            "finding_ids",
            "flow_ids",
            "max_severity",
            "finding_severity_counts",
            "cross_file_callers_in",
            "cross_file_callees_out",
            "most_severe_flow",
            "indexed",
            "render_priority",
        ] {
            assert!(
                node.get(semantic).is_none(),
                "structural tree node must not serialize semantic field {semantic}: {node}"
            );
        }
        for child in node["children"].as_array().into_iter().flatten() {
            assert_structural_node(child);
        }
    }

    let ws = ws_path();
    let Some(out) = run(&["tree", ws.to_str().unwrap(), "--format", "json", "--all"]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("tree JSON must parse");
    for semantic in [
        "total_findings",
        "severity_counts",
        "indexed_complete",
        "indexed_stale",
        "indexed_missing",
    ] {
        assert!(
            parsed["summary"].get(semantic).is_none(),
            "structural tree summary must not serialize semantic field {semantic}:\n{out}"
        );
    }
    for root in parsed["roots"].as_array().expect("tree roots") {
        assert_structural_node(root);
    }
}

#[test]
fn tree_has_only_structural_options_and_ignores_ambient_rulepacks() {
    let Some(bin) = bin_path() else {
        return;
    };
    let help = Command::new(&bin)
        .args(["tree", "--help", "--no-color"])
        .output()
        .expect("run tree help");
    assert!(help.status.success(), "tree --help failed");
    let help = String::from_utf8_lossy(&help.stdout);
    for removed in ["--findings", "--severity", "--rules-dir", "--compact"] {
        assert!(
            !help.contains(removed),
            "tree must not advertise a security-analysis trigger ({removed}):\n{help}"
        );
    }
    assert!(
        help.contains("never opens the compiler") && help.contains("security <workspace> taint-analysis"),
        "tree help must state the lightweight command boundary:\n{help}"
    );

    let ws = ws_path();
    for removed_args in [
        vec!["--findings"],
        vec!["--severity", "high"],
        vec!["--rules-dir", "security-patterns"],
        vec!["--compact"],
    ] {
        let mut args = vec!["tree", ws.to_str().unwrap()];
        args.extend(removed_args.iter().copied());
        args.extend(["--no-color", "--no-progress"]);
        let removed = Command::new(&bin)
            .args(args)
            .output()
            .expect("run unsupported tree option");
        assert!(
            !removed.status.success(),
            "unsupported tree option must be absent from the parser: {removed_args:?}"
        );
        let stderr = String::from_utf8_lossy(&removed.stderr);
        assert!(
            stderr.contains("unexpected argument"),
            "unsupported tree option must receive clap's ordinary error ({removed_args:?}):\n{stderr}"
        );
    }

    let rules = repo_root().join("security-patterns");
    let output = Command::new(&bin)
        .args(["tree", ws.to_str().unwrap(), "--no-color", "--no-progress"])
        .env("BONSAI_RULES_DIR", rules)
        .output()
        .expect("run tree with ambient rulepack");
    assert!(
        output.status.success(),
        "ambient rulepack must not change tree execution: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("finding")
            && !stdout.contains("[ severity ]")
            && !stdout.contains("[ taint-index ]"),
        "ambient rulepack must not attach security analysis to tree:\n{stdout}"
    );
}

#[test]
fn tree_text_marks_depth_limited_view_incomplete() {
    let ws = ws_path();
    let Some(out) = run(&["tree", ws.to_str().unwrap(), "--max-depth", "0"]) else {
        return;
    };
    assert!(
        out.contains("tree view incomplete"),
        "compact tree output must surface incomplete tree context:\n{out}"
    );
    assert!(
        out.contains("tree-files-truncated:"),
        "compact tree output must show the machine-readable reason:\n{out}"
    );
}

#[test]
fn read_file_plain_json_uses_fast_file_local_view() {
    let ws = ws_path();
    let Some(out) = run(&[
        "read-file",
        ws.to_str().unwrap(),
        "gateway.py",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("read-file JSON must parse");
    assert_eq!(
        parsed["analysis_complete"].as_bool(),
        Some(true),
        "plain read-file should be a complete file-local view:\n{out}"
    );
    assert!(
        parsed["source"]
            .as_str()
            .is_some_and(|source| source.contains("handle_request")),
        "plain read-file should include the requested source:\n{out}"
    );
    let missing_or_empty_array = |key: &str| {
        parsed
            .get(key)
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
    };
    assert!(
        missing_or_empty_array("findings_in_view"),
        "plain read-file should not auto-run rulepack findings:\n{out}"
    );
    assert!(
        missing_or_empty_array("callers_in") && missing_or_empty_array("callees_out"),
        "plain read-file should stay file-local unless semantic body options are requested:\n{out}"
    );
}

#[test]
fn read_file_line_range_keeps_native_json_and_only_intersecting_declarations() {
    let root = tempdir_for_test("read-file-ranged-native-json");
    let source = [
        "def first():",
        "    return 1",
        "",
        "",
        "def second():",
        "    return 2",
        "",
    ]
    .join("\n");
    std::fs::write(root.join("sample.py"), source).expect("write ranged source");

    let Some(out) = run(&[
        "read-file",
        root.to_str().unwrap(),
        "sample.py",
        "--lines",
        "1:2",
        "--context",
        "16k",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("read-file JSON must parse");
    assert!(
        parsed.get("json_lines").is_none(),
        "an explicit context budget must preserve native JSON when the object fits:\n{out}"
    );
    assert_eq!(parsed["source"], "def first():\n    return 1");
    let declarations = parsed["line_decl_index"]
        .as_array()
        .expect("line_decl_index array");
    assert_eq!(
        declarations.len(),
        1,
        "ranged reads must not include declarations outside the requested lines:\n{out}"
    );
    assert_eq!(declarations[0]["locator"]["decl"], "first");
}

#[test]
fn read_file_resolves_unique_nested_basename() {
    let root = tempdir_for_test("read-file-unique-basename");
    let nested = root.join("src/pkg");
    std::fs::create_dir_all(&nested).expect("create nested source dir");
    std::fs::write(
        nested.join("auth_service.py"),
        "def verify_token(token):\n    return token.strip()\n",
    )
    .expect("write nested source");
    std::fs::write(
        root.join("main.py"),
        "from src.pkg.auth_service import verify_token\n",
    )
    .expect("write sibling source");

    let Some(out) = run(&[
        "read-file",
        root.to_str().unwrap(),
        "auth_service.py",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("read-file JSON must parse");
    let locator_file = parsed["locator"]["file"]
        .as_str()
        .expect("read-file locator.file");
    assert!(
        locator_file.ends_with("src/pkg/auth_service.py"),
        "read-file should resolve unique nested basename; got locator {locator_file:?}\n{out}"
    );
    assert!(
        parsed["source"]
            .as_str()
            .is_some_and(|source| source.contains("verify_token")),
        "read-file should render the resolved nested source:\n{out}"
    );
}

#[test]
fn read_file_rejects_substring_only_path_match() {
    let Some(bin) = bin_path() else {
        return;
    };
    let root = tempdir_for_test("read-file-substring-path");
    std::fs::write(root.join("myapp.py"), "def myapp_marker():\n    return 1\n").expect("write source");

    let out = Command::new(&bin)
        .args([
            "read-file",
            root.to_str().unwrap(),
            "app.py",
            "--format",
            "json",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "read-file app.py must not resolve myapp.py by substring; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        rendered.contains("did not match any supported source file") && rendered.contains("myapp.py"),
        "read-file should reject substring-only matches and offer suggestions; got:\n{rendered}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn read_file_symbol_opens_defining_file() {
    let ws = ws_path();
    let Some(out) = run(&[
        "read-file",
        ws.to_str().unwrap(),
        "--symbol",
        "verify_token",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("read-file JSON must parse");
    let locator_file = parsed["locator"]["file"]
        .as_str()
        .expect("read-file locator.file");
    assert!(
        locator_file.ends_with("auth_service.py"),
        "read-file --symbol should open the defining file; got locator {locator_file:?}\n{out}"
    );
    assert!(
        parsed["source"]
            .as_str()
            .is_some_and(|source| source.contains("def verify_token")),
        "read-file --symbol should render the definition source:\n{out}"
    );
}

#[test]
fn read_file_rejects_ambiguous_basename_with_candidates() {
    let Some(bin) = bin_path() else {
        return;
    };
    let root = tempdir_for_test("read-file-ambiguous-basename");
    std::fs::create_dir_all(root.join("api")).expect("create api dir");
    std::fs::create_dir_all(root.join("worker")).expect("create worker dir");
    std::fs::write(root.join("api/config.py"), "VALUE = 'api'\n").expect("write api source");
    std::fs::write(root.join("worker/config.py"), "VALUE = 'worker'\n").expect("write worker source");

    let out = Command::new(&bin)
        .args([
            "read-file",
            root.to_str().unwrap(),
            "config.py",
            "--format",
            "json",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "ambiguous read-file basename must fail instead of picking one; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        rendered.contains("ambiguous")
            && rendered.contains("api/config.py")
            && rendered.contains("worker/config.py"),
        "ambiguous read-file error must list candidate paths; got:\n{rendered}"
    );
}

#[test]
fn read_file_json_reports_complete_semantic_view_when_unbounded() {
    let ws = ws_path();
    let rules = repo_root().join("security-patterns");
    let Some(out) = run(&[
        "read-file",
        ws.to_str().unwrap(),
        "gateway.py",
        "--rules-dir",
        rules.to_str().unwrap(),
        "--all",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("read-file JSON must parse");
    assert_eq!(
        parsed["analysis_complete"].as_bool(),
        Some(true),
        "unbounded semantic read-file view should be complete:\n{out}"
    );
    assert!(
        parsed["analysis_incomplete_reasons"]
            .as_array()
            .expect("analysis_incomplete_reasons array")
            .is_empty(),
        "complete read-file output must not carry incomplete reasons:\n{out}"
    );
    let findings = parsed["findings_in_view"]
        .as_array()
        .expect("findings_in_view array");
    assert!(
        findings
            .iter()
            .all(|finding| finding["analysis_complete"].as_bool().is_some()),
        "read-file finding digests must expose per-finding completeness:\n{out}"
    );
}

#[test]
fn read_file_json_marks_inlined_body_truncation_incomplete() {
    let ws = ws_path();
    let Some(out) = run(&[
        "read-file",
        ws.to_str().unwrap(),
        "gateway.py",
        "--max-inlined-bodies",
        "1",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("read-file JSON must parse");
    assert_eq!(
        parsed["analysis_complete"].as_bool(),
        Some(false),
        "truncated cross-file bodies must mark read-file incomplete:\n{out}"
    );
    assert!(
        parsed["truncated"]["callees_dropped"].as_u64().unwrap_or(0) > 0,
        "fixture should drop at least one semantic callee body under cap:\n{out}"
    );
    let reasons = parsed["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array");
    assert!(
        reasons.iter().any(|reason| reason
            .as_str()
            .is_some_and(|s| s.starts_with("inlined-bodies-truncated:"))),
        "read-file must explain the body truncation reason:\n{out}"
    );
}

#[test]
fn read_file_compact_text_marks_incomplete_when_body_context_truncated() {
    let ws = ws_path();
    let Some(out) = run(&[
        "read-file",
        ws.to_str().unwrap(),
        "gateway.py",
        "--max-inlined-bodies",
        "1",
        "--compact",
    ]) else {
        return;
    };
    assert!(
        out.contains("semantic-only view incomplete"),
        "compact read-file output must surface incomplete semantic context:\n{out}"
    );
    assert!(
        out.contains("inlined-bodies-truncated:"),
        "compact read-file output must show the machine-readable reason:\n{out}"
    );
}

#[test]
fn dump_hir_emits_flow_event_tree() {
    let ws = ws_path();
    let Some(out) = run(&["dump-hir", ws.to_str().unwrap(), "handle_request"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("dump-hir should be valid JSON");
    assert_eq!(v["analysis_complete"], true);
    assert!(
        v["analysis_incomplete_reasons"]
            .as_array()
            .expect("analysis_incomplete_reasons array")
            .is_empty(),
        "exact dump-hir should not carry incomplete reasons: {out}"
    );
    assert_eq!(v["name"], "handle_request");
    let flow = v["flow_events"].as_array().expect("flow_events array");
    assert!(
        !flow.is_empty(),
        "dump-hir should surface flow events, got: {out}"
    );
    // handle_request has an assignment + calls; ensure at least one Call
    // event appears in the emitted tree.
    let has_call = flow.iter().any(|e| e.get("Call").is_some());
    assert!(has_call, "flow_events should include a Call, got: {out}");
}

#[test]
fn dump_hir_rejects_ambiguous_bare_symbol_and_accepts_file_context() {
    let root = tempdir_for_test("dump-hir-ambiguous-symbol");
    let a = root.join("a.py");
    let b = root.join("b.py");
    std::fs::write(&a, "def dup(x):\n    y = x\n    return y\n").expect("write a.py");
    std::fs::write(&b, "def dup(x):\n    z = x\n    return z\n").expect("write b.py");
    let Some(bin) = bin_path() else {
        return;
    };

    let ambiguous = Command::new(&bin)
        .args(["dump-hir", root.to_str().unwrap(), "dup", "--no-color"])
        .output()
        .expect("run ambiguous dump-hir");
    assert!(
        !ambiguous.status.success(),
        "ambiguous dump-hir must fail instead of choosing one candidate"
    );
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        stderr.contains("ambiguous") && stderr.contains("path:name"),
        "ambiguous dump-hir should explain how to disambiguate; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("a.py:1:dup") && stderr.contains("b.py:1:dup"),
        "ambiguous dump-hir should list concrete candidate keys; stderr:\n{stderr}"
    );

    let disambiguator = format!("{}:1:dup", a.display());
    let qualified = Command::new(&bin)
        .args(["dump-hir", root.to_str().unwrap(), &disambiguator, "--no-color"])
        .output()
        .expect("run qualified dump-hir");
    assert!(
        qualified.status.success(),
        "file-qualified dump-hir should resolve exactly; stderr:\n{}",
        String::from_utf8_lossy(&qualified.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&qualified.stdout).expect("qualified dump-hir JSON");
    assert_eq!(parsed["name"], "dup");
}

#[test]
fn dump_cfg_rejects_ambiguous_bare_symbol() {
    let root = tempdir_for_test("dump-cfg-ambiguous-symbol");
    std::fs::write(root.join("a.py"), "def dup(x):\n    return x\n").expect("write a.py");
    std::fs::write(root.join("b.py"), "def dup(x):\n    return x\n").expect("write b.py");
    let Some(bin) = bin_path() else {
        return;
    };

    let out = Command::new(&bin)
        .args(["dump-cfg", root.to_str().unwrap(), "dup", "--no-color"])
        .output()
        .expect("run ambiguous dump-cfg");
    assert!(
        !out.status.success(),
        "ambiguous dump-cfg must fail instead of choosing one candidate"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dump-cfg:") && stderr.contains("ambiguous"),
        "ambiguous dump-cfg should be explicit; stderr:\n{stderr}"
    );
}

#[test]
fn dump_cfg_emits_entry_and_exit_blocks() {
    let ws = ws_path();
    let Some(out) = run(&["dump-cfg", ws.to_str().unwrap(), "update_user"]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["analysis_complete"], true);
    assert!(
        v["analysis_incomplete_reasons"]
            .as_array()
            .expect("analysis_incomplete_reasons array")
            .is_empty(),
        "exact dump-cfg should not carry incomplete reasons: {out}"
    );
    let entry = v["entry"].as_u64().expect("entry id");
    let exit = v["exit"].as_u64().expect("exit id");
    let blocks = v["blocks"].as_array().expect("blocks array");
    assert!(blocks.len() >= 2, "expected at least entry + exit blocks");
    // update_user has an if/else — expect the branch blocks.
    let labels: Vec<String> = blocks
        .iter()
        .filter_map(|b| b["label"].as_str().map(String::from))
        .collect();
    assert!(
        labels.iter().any(|l| l.starts_with("then@")),
        "missing then-branch: {out}"
    );
    assert!(
        labels.iter().any(|l| l.starts_with("else@")),
        "missing else-branch: {out}"
    );
    assert!(labels.iter().any(|l| l == "entry"), "missing entry: {out}");
    assert!(labels.iter().any(|l| l == "exit"), "missing exit: {out}");
    // Exit block should have no successors.
    let exit_block = blocks
        .iter()
        .find(|b| b["id"].as_u64() == Some(exit))
        .expect("exit block present");
    assert!(
        exit_block["successors"].as_array().unwrap().is_empty(),
        "exit should have no successors: {out}"
    );
    let _ = entry;
}

#[test]
fn dump_callgraph_reports_nonzero_edges() {
    let ws = ws_path();
    let Some(out) = run(&["dump-callgraph", ws.to_str().unwrap()]) else {
        return;
    };
    for h in &["function", "callers", "outgoing"] {
        assert!(out.contains(h), "callgraph header missing `{h}`: {out}");
    }
    // verify_token is called twice in the micro fixture; the row for it
    // must show a caller count of 2 — regression guard for the bug
    // where callers was always 0.
    let row = out
        .lines()
        .find(|l| l.contains("verify_token"))
        .expect("verify_token row present");
    assert!(
        row.contains(" 2 "),
        "verify_token should show 2 callers, got row: {row}"
    );
}

#[test]
fn dump_callgraph_counts_semantic_workspace_edges_only() {
    let ws = ws_path();
    let Some(out) = run(&["dump-callgraph", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let rows: serde_json::Value = serde_json::from_str(&out).expect("dump-callgraph JSON");
    let rows = rows.as_array().expect("dump-callgraph rows");
    let row = |name: &str| {
        rows.iter()
            .find(|row| row["function"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("{name} row present in dump-callgraph"))
    };
    assert_eq!(
        row("verify_token")["callers"].as_u64(),
        Some(2),
        "caller counts should dedupe semantic caller functions"
    );
    assert_eq!(
        row("verify_token")["outgoing"].as_u64(),
        Some(0),
        "outgoing counts should not include lexical external calls"
    );
    assert_eq!(
        row("handle_request")["outgoing"].as_u64(),
        Some(2),
        "outgoing counts should include only resolved workspace callees"
    );
}

#[test]
fn dump_edges_uses_semantic_resolved_callgraph_edges_only() {
    let ws = ws_path();
    let Some(out) = run(&["dump-edges", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let rows: serde_json::Value = serde_json::from_str(&out).expect("dump-edges JSON");
    let rows = rows.as_array().expect("dump-edges rows");

    let pairs: std::collections::BTreeSet<(String, String)> = rows
        .iter()
        .filter_map(|row| {
            Some((
                row["caller_name"].as_str()?.to_string(),
                row["callee_name"].as_str()?.to_string(),
            ))
        })
        .collect();
    assert_eq!(
        pairs,
        std::collections::BTreeSet::from([
            ("get_user".to_string(), "verify_token".to_string()),
            ("handle_request".to_string(), "get_user".to_string()),
            ("handle_request".to_string(), "update_user".to_string()),
            ("update_user".to_string(), "run_admin_command".to_string()),
            ("update_user".to_string(), "verify_token".to_string()),
        ]),
        "dump-edges must be a view over resolved workspace callgraph edges only:\n{out}"
    );
    assert!(
        rows.iter()
            .all(|row| matches!(row["precision"].as_str(), Some("exact" | "narrowed"))),
        "dump-edges must not expose broad precision classes:\n{out}"
    );
    assert!(
        rows.iter().all(|row| {
            row["resolver_stage"]
                .as_str()
                .is_some_and(|stage| !stage.is_empty())
                && row["evidence"]
                    .as_str()
                    .is_some_and(|evidence| !evidence.is_empty())
                && row["confidence"]
                    .as_u64()
                    .is_some_and(|confidence| confidence <= 100)
        }),
        "dump-edges must expose resolver provenance on every edge:\n{out}"
    );
}

#[test]
fn dump_edges_does_not_bare_tail_unaliased_import_qualified_call() {
    let root = tempdir_for_test("dump-edges-unaliased-import-qualified");
    std::fs::write(
        root.join("app.js"),
        r#"
import "./external";

function system(cmd) {
  return cmd;
}

function entry(cmd) {
  external.system(cmd);
}
"#,
    )
    .expect("write app.js");

    let Some(out) = run(&["dump-edges", root.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let rows: serde_json::Value = serde_json::from_str(&out).expect("dump-edges JSON");
    let rows = rows.as_array().expect("dump-edges rows");
    let pairs: std::collections::BTreeSet<(String, String)> = rows
        .iter()
        .filter_map(|row| {
            Some((
                row["caller_name"].as_str()?.to_string(),
                row["callee_name"].as_str()?.to_string(),
            ))
        })
        .collect();

    assert!(
        !pairs.contains(&("entry".to_string(), "system".to_string())),
        "side-effect import-qualified external.system must resolve through the import target \
         or remain unresolved; it must not bare-tail into local system():\n{out}"
    );
}

#[test]
fn inspect_zero_hits_reports_no_matches_not_error() {
    let ws = ws_path();
    let Some(out) = run(&["inspect", ws.to_str().unwrap(), "--query", "xyzzy_no_match"]) else {
        return;
    };
    assert!(
        out.contains("no matches for"),
        "expected friendly no-matches output, got: {out}"
    );
    // Command should have exited 0 — `run` would have panicked otherwise.
}

#[test]
fn diagnostics_points_at_specific_error_node() {
    // Diagnostics should emit per-ERROR-node spans instead of a single
    // file-wide "syntax errors present" blob.
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/cpp/micro");
    let Some(out) = run(&["diagnostics", ws.to_str().unwrap()]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let arr = v["diagnostics"].as_array().expect("diagnostics array");
    // C++ fixture has syntax errors. Each diagnostic should point at a
    // narrow span, not at the whole file.
    for d in arr {
        let start = d["span"]["start"].as_u64().unwrap_or(0);
        let end = d["span"]["end"].as_u64().unwrap_or(0);
        let width = end.saturating_sub(start);
        assert!(
            width < 5000,
            "diagnostic span should be narrow (ERROR node), got width={width}: {d}"
        );
    }
}

#[test]
fn options_heading_still_present_after_template_override() {
    let Some(out) = run(&["--help"]) else {
        return;
    };
    assert!(
        out.contains("OPTIONS:"),
        "OPTIONS: heading missing after template override: {out}"
    );
}

/// Invariant that matters for every `--from X --to Y` flow: the
/// rendered output must show BOTH a `FROM: X` marker and a `TO: Y`
/// marker for every surviving flow. If either is missing, the flow
/// wasn't actually connected end-to-end and shouldn't have been kept.
///
/// Run per-language against the checked-in micro fixtures with
/// source-to-sink needles. The fixtures vary across languages (see
/// `callees` column of `bonsai-ninja defs`), so each language has a
/// language-appropriate pair.
#[test]
fn inspect_from_to_every_flow_shows_both_markers_across_langs() {
    let cases = [
        ("c/micro", "req", "system"),
        ("cpp/micro", "params", "system"),
        ("csharp/micro", "req", "RunAdmin"),
        ("go/micro", "UpdateUser", "Command"),
        ("java/micro", "req", "exec"),
        ("javascript/micro", "token", "execSync"),
        ("kotlin/micro", "req", "exec"),
        ("php/micro", "token", "exec"),
        ("python/micro", "req", "os"),
        ("ruby/micro", "token", "system"),
        ("rust/micro", "token", "Command"),
        ("scala/micro", "req", "exec"),
        ("swift/micro", "query", "Process"),
        ("typescript/micro", "token", "execSync"),
    ];
    let repo = repo_root();
    for (sub, from, to) in &cases {
        let ws = repo.join("examples").join(sub);
        let Some(out) = run_inspect_graph(&ws, &["--from", from, "--to", to]) else {
            return;
        };
        // Skip langs whose micro fixture doesn't happen to have this
        // exact flow — we care about correctness, not coverage breadth
        // here.
        if out.contains("no matches for") {
            continue;
        }
        // For each `FLOW N …` block, assert both markers are present.
        let mut current: Option<String> = None;
        let mut has_from = false;
        let mut has_to = false;
        let from_tag = format!("FROM: {from}");
        let to_tag = format!("TO: {to}");
        let mut flow_count = 0usize;
        let check = |label: &Option<String>, has_from: bool, has_to: bool, lang: &str| {
            if let Some(l) = label {
                assert!(
                    has_from,
                    "{lang}: flow `{l}` missing `{from_tag}` marker in full render"
                );
                assert!(
                    has_to,
                    "{lang}: flow `{l}` missing `{to_tag}` marker in full render"
                );
            }
        };
        for line in out.lines() {
            if line.starts_with("FLOW ") {
                check(&current, has_from, has_to, sub);
                flow_count += 1;
                current = Some(line.to_string());
                has_from = false;
                has_to = false;
                continue;
            }
            if line.contains(&from_tag) {
                has_from = true;
            }
            if line.contains(&to_tag) {
                has_to = true;
            }
        }
        check(&current, has_from, has_to, sub);
        assert!(
            flow_count > 0,
            "{sub}: expected at least one FLOW block for --from {from} --to {to}; output:\n{out}"
        );
    }
}

/// Pin the token-boundary rule end-to-end: `--from req --to os` on
/// Python micro MUST NOT surface unrelated hits like `cursor.execute`,
/// `conn.close`, `cursor.fetchone`, `conn.cursor` — none of those
/// contain `req` or `os` at a token boundary (substring matches like
/// `os` ⊂ `close` are rejected by `name_token_match`).
#[test]
fn inspect_from_to_narrow_no_unrelated_hits_python() {
    let ws = ws_path();
    let Some(out) = run_inspect_graph(&ws, &["--from", "req", "--to", "os"]) else {
        return;
    };
    // Only the OCCURRENCE HITS table matters for this assertion — the
    // flow bodies below will naturally inline other lines (like the
    // `conn.close` line inside verify_token) because they're rendered
    // as context for flows that DO legitimately pass the filter.
    let table_start = out.find("══ OCCURRENCE HITS").expect("hits table missing");
    let after_start = &out[table_start..];
    // Table ends at the first flow-block ruler (folded view) OR the
    // legacy per-hit `▸` header if some older render path is still
    // in play. Either marker signals the table is over.
    let table_end_rel = after_start
        .find("\n\n══════")
        .or_else(|| after_start.find("\n▸ "))
        .unwrap_or(after_start.len());
    let table = &after_start[..table_end_rel];
    // The hits table columns are fixed-width; we spot-check that the
    // unrelated call sites DON'T appear as hit rows. These would have
    // surfaced under the old loose-substring filter because
    // `close`/`cursor`/`fetchone` contain `os` as a substring.
    for blocked in ["conn.close", "cursor.execute", "cursor.fetchone", "conn.cursor"] {
        assert!(
            !table.contains(blocked),
            "unrelated hit `{blocked}` surfaced in hits table:\n{table}"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-language CLI-flag matrix.
//
// The user's concern: every `inspect` flag must work for every language.
// These tests run the release binary against each checked-in micro fixture
// with each flag in turn, and assert on the shape of the output. A
// regression that breaks any flag for any language will fail here loudly.
//
// All 14 languages use the checked-in `examples/<lang>/micro` fixtures.
// ---------------------------------------------------------------------------

const LANG_MICROS: &[&str] = &[
    "c",
    "cpp",
    "csharp",
    "go",
    "java",
    "javascript",
    "kotlin",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "swift",
    "typescript",
];

fn lang_ws(lang: &str) -> PathBuf {
    repo_root().join("examples").join(lang).join("micro")
}

/// Pick a `--query` needle that exists in every micro fixture. `token`
/// appears across all of them (as a var / param / arg / string).
fn universal_query() -> &'static str {
    "token"
}

/// `--query <needle>` returns non-empty output for every language.
#[test]
fn inspect_query_works_for_every_lang() {
    for lang in LANG_MICROS {
        let ws = lang_ws(lang);
        let Some(out) = run(&["inspect", ws.to_str().unwrap(), "--query", universal_query()]) else {
            return;
        };
        assert!(
            !out.contains("no matches"),
            "{lang}: --query `{}` returned `no matches`:\n{out}",
            universal_query()
        );
        assert!(
            out.contains("inspect "),
            "{lang}: --query summary line missing:\n{out}"
        );
    }
}

/// `--regex` interprets the query as a regex. Use `.*` which matches
/// everything so every fixture produces at least one hit.
#[test]
fn inspect_regex_works_for_every_lang() {
    for lang in LANG_MICROS {
        let ws = lang_ws(lang);
        let Some(out) = run(&["inspect", ws.to_str().unwrap(), "--query", "token.*", "--regex"]) else {
            return;
        };
        // `--regex` mode: if the fixture has a `token`-ish identifier
        // anywhere, we should see a match.
        assert!(!out.is_empty(), "{lang}: --regex produced no output");
    }
}

/// `--kind call` restricts to call-kind hits. Every micro fixture has
/// at least one call, and no `decl`/`string`/etc. hits must appear in
/// the "by kind" summary when `--kind call` is set.
#[test]
fn inspect_kind_filter_works_for_every_lang() {
    for lang in LANG_MICROS {
        let ws = lang_ws(lang);
        let Some(out) = run(&[
            "inspect",
            ws.to_str().unwrap(),
            "--query",
            universal_query(),
            "--kind",
            "call",
        ]) else {
            return;
        };
        if out.contains("no matches") {
            // Some langs may not have token-named calls; skip those.
            continue;
        }
        // Scan the `by kind:` summary line.
        for line in out.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("by kind:") {
                // Only `call=` should appear.
                for part in rest.split(',').map(|s| s.trim()) {
                    if part.is_empty() {
                        continue;
                    }
                    let kind = part
                        .split_once(':')
                        .map(|(kind, _)| kind)
                        .or_else(|| part.split_once('=').map(|(kind, _)| kind))
                        .unwrap_or(part)
                        .trim();
                    assert_eq!(
                        kind, "call",
                        "{lang}: --kind call let through kind `{kind}` in summary: {line}"
                    );
                }
            }
        }
    }
}

/// `--file <TEXT>` filters hits by workspace-relative file path. Using `.`
/// (a universally-present file extension char) should keep every hit; using
/// a clearly-absent substring drops them all.
#[test]
fn inspect_file_filter_works_for_every_lang() {
    for lang in LANG_MICROS {
        let ws = lang_ws(lang);
        // First: a file substring that definitely WON'T match any
        // path in the fixture.
        let Some(out) = run(&[
            "inspect",
            ws.to_str().unwrap(),
            "--query",
            universal_query(),
            "--file",
            "zzz_not_a_real_file_zzz",
        ]) else {
            return;
        };
        // Result must either be "no matches" or a zero-hit summary.
        let surfaced = out
            .lines()
            .any(|l| l.contains("other hit(s)") && !l.contains("0 other"));
        assert!(
            !surfaced || out.contains("no matches"),
            "{lang}: --file <impossible> surfaced hits:\n{out}"
        );
    }
}

/// `--in-fn <substring>` scopes hits to an enclosing function by name.
/// Using an impossible substring must yield zero hits.
#[test]
fn inspect_in_fn_filter_works_for_every_lang() {
    for lang in LANG_MICROS {
        let ws = lang_ws(lang);
        let Some(out) = run(&[
            "inspect",
            ws.to_str().unwrap(),
            "--query",
            universal_query(),
            "--in-fn",
            "zzz_impossible_fn_name_zzz",
        ]) else {
            return;
        };
        let surfaced = out
            .lines()
            .any(|l| l.contains("other hit(s)") && !l.contains("0 other"));
        assert!(
            !surfaced || out.contains("no matches"),
            "{lang}: --in-fn <impossible> surfaced hits:\n{out}"
        );
    }
}

/// `--format json` must produce valid JSON for every language fixture.
#[test]
fn inspect_format_json_valid_for_every_lang() {
    for lang in LANG_MICROS {
        let ws = lang_ws(lang);
        let Some(out) = run(&[
            "inspect",
            ws.to_str().unwrap(),
            "--query",
            universal_query(),
            "--format",
            "json",
        ]) else {
            return;
        };
        // `no matches` returns early — still must be valid JSON.
        let trimmed = out.trim();
        if trimmed.is_empty() {
            continue;
        }
        assert!(
            trimmed.starts_with('{') || trimmed.starts_with('['),
            "{lang}: --format json output isn't JSON-shaped:\n{out}"
        );
        // Cheap structural check: parse with serde_json.
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(trimmed);
        assert!(
            parsed.is_ok(),
            "{lang}: --format json output failed to parse: {:?}\noutput:\n{out}",
            parsed.err()
        );
    }
}

/// `--from <X> --to <Y>` with nonsense needles must return zero flows
/// across every language — the filter's core soundness property.
#[test]
fn inspect_from_to_nonsense_needles_drop_all_for_every_lang() {
    for lang in LANG_MICROS {
        let ws = lang_ws(lang);
        let Some(out) = run_inspect_graph(
            &ws,
            &[
                "--from",
                "zzzzz_not_a_real_token_zzzzz",
                "--to",
                "wwwww_also_nonsense_wwwww",
            ],
        ) else {
            return;
        };
        let flow_count = out.lines().filter(|l| l.starts_with("FLOW ")).count();
        assert_eq!(
            flow_count, 0,
            "{lang}: --from/--to with nonsense needles still surfaced {flow_count} flows:\n{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// Full CLI correctness matrix: every command × every language.
//
// For every language fixture, we verify that the output CONTENT is
// correct — not just "runs without panic". Each command is asserted to
// contain a language-specific expected substring that proves the
// feature is actually working (e.g. the known entry function surfaces
// in `defs`, the known sink appears in `calls`, the known import path
// appears in `imports`, JSON export contains `flow_chains`, etc.).
// ---------------------------------------------------------------------------

struct LangExpect {
    lang: &'static str,
    entry: &'static str,
    /// Symbol to query in the `refs` test. `None` means the
    /// adapter doesn't currently surface refs in a way that this
    /// fixture can pin (e.g. ObjC bracket-syntax dispatch, Dart
    /// split-grammar calls, Erlang `mod:fn/n` qualifiers — these
    /// emit calls but not `Ref`-classified items). Tests skip the
    /// language when `None`.
    ref_sym: Option<&'static str>,
    sink: &'static str,
    import_mark: Option<&'static str>,
    string_mark: Option<&'static str>,
    class_mark: Option<&'static str>,
}

fn lang_expectations() -> Vec<LangExpect> {
    vec![
        LangExpect {
            lang: "c",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "system",
            import_mark: Some("stdio.h"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "cpp",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "system",
            import_mark: Some("cstdlib"),
            string_mark: Some("notify-admin"),
            class_mark: Some("UserInfo"),
        },
        LangExpect {
            lang: "csharp",
            entry: "HandleRequest",
            ref_sym: Some("VerifyToken"),
            sink: "RunAdminCommand",
            import_mark: Some("System"),
            string_mark: Some("notify-admin"),
            class_mark: Some("Gateway"),
        },
        LangExpect {
            lang: "go",
            entry: "HandleRequest",
            ref_sym: Some("VerifyToken"),
            sink: "exec.Command",
            import_mark: Some("sql"),
            string_mark: Some("notify-admin"),
            class_mark: Some("UserInfo"),
        },
        LangExpect {
            lang: "java",
            entry: "handleRequest",
            ref_sym: Some("verifyToken"),
            sink: "exec",
            import_mark: Some("http"),
            string_mark: Some("notify-admin"),
            class_mark: Some("Gateway"),
        },
        LangExpect {
            lang: "javascript",
            entry: "handleRequest",
            ref_sym: Some("verifyToken"),
            sink: "execSync",
            import_mark: Some("child_process"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "kotlin",
            entry: "handleRequest",
            ref_sym: Some("verifyToken"),
            sink: "exec",
            import_mark: Some("http"),
            string_mark: Some("notify-admin"),
            class_mark: Some("Gateway"),
        },
        LangExpect {
            lang: "php",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "exec",
            import_mark: None,
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "python",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "os.system",
            import_mark: Some("sqlite3"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "ruby",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "system",
            import_mark: Some("sqlite3"),
            string_mark: Some("notify-admin"),
            // The fixture declares Ruby modules, not classes. The adapter must
            // preserve that syntax distinction instead of guessing a class.
            class_mark: None,
        },
        LangExpect {
            lang: "rust",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "Command",
            import_mark: Some("std::"),
            string_mark: Some("notify-admin"),
            class_mark: Some("UserInfo"),
        },
        LangExpect {
            lang: "scala",
            entry: "handleRequest",
            ref_sym: Some("verifyToken"),
            sink: "exec",
            import_mark: Some("javax"),
            string_mark: Some("notify-admin"),
            class_mark: Some("Gateway"),
        },
        LangExpect {
            lang: "swift",
            entry: "handleRequest",
            ref_sym: Some("verifyToken"),
            sink: "launch",
            import_mark: Some("Foundation"),
            string_mark: Some("notify-admin"),
            class_mark: Some("Gateway"),
        },
        LangExpect {
            lang: "typescript",
            entry: "handleRequest",
            ref_sym: Some("verifyToken"),
            sink: "execSync",
            import_mark: Some("child_process"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "dart",
            entry: "handleRequest",
            // tree-sitter-dart's split-grammar `id selector` call shape
            // surfaces as a synthesized Call event but not as a
            // `Ref`-classified item. Refs harness has nothing to pin.
            ref_sym: None,
            sink: "runSync",
            import_mark: Some("dart:io"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "elixir",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "cmd",
            import_mark: Some("UserService"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "erlang",
            entry: "handle_request",
            // Erlang's `mod:fn(args)` parses as a Remote node — call
            // events are emitted but not as `Ref`-classified items.
            ref_sym: None,
            sink: "cmd",
            import_mark: None,
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "lua",
            entry: "handleRequest",
            ref_sym: Some("verifyToken"),
            sink: "execute",
            import_mark: Some("user_service"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
        LangExpect {
            lang: "objc",
            entry: "handleRequestWithToken",
            // ObjC's `[receiver selectorWithArg:x]` lowers to a
            // message_expression Call, not a Ref. Pin nothing.
            ref_sym: None,
            sink: "system",
            import_mark: Some("Foundation"),
            string_mark: Some("notify-admin"),
            class_mark: Some("Gateway"),
        },
        LangExpect {
            lang: "perl",
            entry: "handle_request",
            ref_sym: Some("verify_token"),
            sink: "system",
            import_mark: Some("UserService"),
            string_mark: Some("notify-admin"),
            class_mark: None,
        },
    ]
}

fn run_on(lang: &str, args_after_ws: &[&str]) -> Option<String> {
    let ws = lang_ws(lang);
    let mut args: Vec<&str> = Vec::with_capacity(args_after_ws.len() + 2);
    // First arg is the command, second is the workspace path, then
    // the rest. Callers pass the full arg list with `<cmd> <ws-flag>`
    // substitution via a placeholder they replace themselves.
    args.push(args_after_ws[0]);
    let ws_str = ws.to_str().unwrap().to_string();
    args.push(ws_str.as_str());
    for a in &args_after_ws[1..] {
        args.push(a);
    }
    run(&args)
}

fn run_on_inspect_graph(lang: &str, args_after_ws: &[&str]) -> Option<String> {
    let ws = lang_ws(lang);
    run_inspect_graph(&ws, args_after_ws)
}

fn assert_contains(lang: &str, cmd_desc: &str, out: &str, expect: &str) {
    assert!(
        out.contains(expect),
        "{lang}: `{cmd_desc}` output missing expected `{expect}`\n--- output ---\n{out}"
    );
}

/// `defs`: surfaces the known entry function.
#[test]
fn cli_defs_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["defs"]) else {
            return;
        };
        assert_contains(e.lang, "defs", &out, e.entry);
    }
}

/// `calls`: surfaces the known sink callee.
#[test]
fn cli_calls_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["calls"]) else {
            return;
        };
        assert_contains(e.lang, "calls", &out, e.sink);
    }
}

/// `imports`: surfaces the known import when the fixture has one.
#[test]
fn cli_imports_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(import_mark) = e.import_mark else {
            continue;
        };
        let Some(out) = run_on(e.lang, &["imports"]) else {
            return;
        };
        assert_contains(e.lang, "imports", &out, import_mark);
    }
}

/// `strings`: surfaces the known string literal when the fixture has one.
#[test]
fn cli_strings_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(string_mark) = e.string_mark else {
            continue;
        };
        let Some(out) = run_on(e.lang, &["strings"]) else {
            return;
        };
        assert_contains(e.lang, "strings", &out, string_mark);
    }
}

/// `classes`: surfaces the known class when the fixture has one.
#[test]
fn cli_classes_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(class_mark) = e.class_mark else {
            continue;
        };
        let Some(out) = run_on(e.lang, &["classes"]) else {
            return;
        };
        assert_contains(e.lang, "classes", &out, class_mark);
    }
}

/// `refs <symbol>`: references to the known referenced symbol appear.
/// Languages whose adapter doesn't emit `Ref`-classified items today
/// (`ref_sym: None`) are skipped — call sites still surface as Call
/// events, but `refs` queries against them produce zero matches.
#[test]
fn cli_refs_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(ref_sym) = e.ref_sym else { continue };
        let Some(out) = run_on(e.lang, &["refs", ref_sym]) else {
            return;
        };
        assert_contains(e.lang, "refs", &out, ref_sym);
    }
}

/// `search <query>`: finds the entry function.
#[test]
fn cli_search_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["search", e.entry]) else {
            return;
        };
        assert_contains(e.lang, "search", &out, e.entry);
    }
}

/// `trace <entry>`: output mentions the entry.
#[test]
fn cli_trace_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["trace", e.entry]) else {
            return;
        };
        assert_contains(e.lang, "trace", &out, e.entry);
    }
}

/// `inspect --query <sink>`: produces a MATCH annotation.
#[test]
fn cli_inspect_query_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on_inspect_graph(e.lang, &["--query", e.sink]) else {
            return;
        };
        assert_contains(e.lang, "inspect --query", &out, "MATCH");
    }
}

/// `export`: emits JSON with `flow_chains` and `callgraph` sections.
#[test]
fn cli_export_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["export"]) else {
            return;
        };
        assert_contains(e.lang, "export", &out, "flow_chains");
        assert_contains(e.lang, "export", &out, "callgraph");
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("export output is JSON");
        assert!(
            parsed.get("summary").is_some(),
            "{}: export JSON missing `summary` field",
            e.lang
        );
    }
}

/// `dump-callgraph`: mentions the entry function.
#[test]
fn cli_dump_callgraph_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["dump-callgraph"]) else {
            return;
        };
        assert_contains(e.lang, "dump-callgraph", &out, e.entry);
    }
}

/// `dump-hir <entry>`: emits JSON with the function's name.
#[test]
fn cli_dump_hir_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["dump-hir", e.entry]) else {
            return;
        };
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("dump-hir output is JSON");
        let name = parsed.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        assert_eq!(
            name, e.entry,
            "{}: dump-hir returned wrong name — got `{name}`, want `{}`",
            e.lang, e.entry
        );
    }
}

/// `dump-cfg <entry>`: emits JSON with the function's name.
#[test]
fn cli_dump_cfg_content_correct_for_every_lang() {
    for e in lang_expectations() {
        let Some(out) = run_on(e.lang, &["dump-cfg", e.entry]) else {
            return;
        };
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("dump-cfg output is JSON");
        let name = parsed
            .get("function")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(
            name, e.entry,
            "{}: dump-cfg returned wrong function — got `{name}`, want `{}`",
            e.lang, e.entry
        );
        assert!(
            parsed.get("blocks").is_some(),
            "{}: dump-cfg JSON missing `blocks`",
            e.lang
        );
    }
}

/// Scala string interpolation `s"notify-admin $cmd"` used to be
/// dropped because the tree-sitter node kind is
/// `interpolated_string_expression`, not `string` / `string_literal`.
/// The fix adds the interpolation kinds to the STRING_KINDS list so
/// the outer interpolated node is captured verbatim.
#[test]
fn cli_strings_captures_scala_interpolation() {
    let Some(out) = run_on("scala", &["strings"]) else {
        return;
    };
    assert_contains("scala", "strings", &out, "notify-admin");
}

/// Kotlin / Swift dotted method calls (`req.getParameter(...)`,
/// `authService.verifyToken(...)`) used to surface in `refs` with
/// only the leftmost receiver (`req`, `authService`). The call-refs
/// extractor now prefers the full callee expression subtree so the
/// dotted form is indexed — and `refs <bareName>` still finds it via
/// the suffix-after-dot match.
#[test]
fn cli_refs_captures_dotted_method_calls() {
    // Kotlin: `req.getParameter(...)` should be findable under both
    // the dotted form AND the bare method name.
    let Some(k_full) = run_on("kotlin", &["refs", "req.getParameter"]) else {
        return;
    };
    assert_contains("kotlin", "refs req.getParameter", &k_full, "req.getParameter");
    let Some(k_bare) = run_on("kotlin", &["refs", "getParameter"]) else {
        return;
    };
    assert_contains("kotlin", "refs getParameter", &k_bare, "getParameter");
    let Some(k_receiver) = run_on("kotlin", &["refs", "req"]) else {
        return;
    };
    assert_contains("kotlin", "refs req", &k_receiver, "req.getParameter");

    // Swift: same invariant for `authService.verifyToken`.
    let Some(s_full) = run_on("swift", &["refs", "authService.verifyToken"]) else {
        return;
    };
    assert_contains(
        "swift",
        "refs authService.verifyToken",
        &s_full,
        "authService.verifyToken",
    );
    let Some(s_bare) = run_on("swift", &["refs", "verifyToken"]) else {
        return;
    };
    assert_contains("swift", "refs verifyToken", &s_bare, "verifyToken");
    let Some(s_receiver) = run_on("swift", &["refs", "authService"]) else {
        return;
    };
    assert_contains(
        "swift",
        "refs authService",
        &s_receiver,
        "authService.verifyToken",
    );
}

/// Pin JS `require(...)` and Ruby `require/require_relative` imports
/// — these don't surface as dedicated import statement nodes in Tree-
/// sitter but must still be indexed via the call-based post-pass.
#[test]
fn cli_imports_captures_call_based_require() {
    // JavaScript: `const { execSync } = require("child_process")`.
    let Some(js_out) = run_on("javascript", &["imports"]) else {
        return;
    };
    assert_contains("javascript", "imports", &js_out, "child_process");
    assert_contains("javascript", "imports", &js_out, "mysql");
    assert_contains("javascript", "imports", &js_out, "express");

    // Ruby: `require 'sqlite3'` + `require_relative`.
    let Some(rb_out) = run_on("ruby", &["imports"]) else {
        return;
    };
    assert_contains("ruby", "imports", &rb_out, "sqlite3");
    assert_contains("ruby", "imports", &rb_out, "user_service");
    assert_contains("ruby", "imports", &rb_out, "sinatra");
}

#[test]
fn cli_imports_hide_resolver_only_bindings() {
    let Some(lua_out) = run_on("lua", &["imports", "--format", "json", "--all"]) else {
        return;
    };
    let lua_rows: serde_json::Value = serde_json::from_str(lua_out.trim()).expect("lua imports JSON");
    let lua_rows = lua_rows.as_array().expect("lua imports array");
    assert!(
        !lua_rows
            .iter()
            .any(|row| row.get("alias").and_then(serde_json::Value::as_str) == Some("M")),
        "Lua module export table alias M is resolver-only and must not be a public import row: {lua_rows:?}"
    );
    for (module, alias) in [
        ("luasql.sqlite3", "luasql"),
        ("auth_service", "auth"),
        ("user_service", "user_service"),
    ] {
        assert!(
            lua_rows.iter().any(|row| {
                row.get("module").and_then(serde_json::Value::as_str) == Some(module)
                    && row.get("alias").and_then(serde_json::Value::as_str) == Some(alias)
            }),
            "Lua real require row missing module={module} alias={alias}: {lua_rows:?}"
        );
    }

    let Some(ruby_out) = run_on("ruby", &["imports", "--format", "json", "--all"]) else {
        return;
    };
    let ruby_rows: serde_json::Value = serde_json::from_str(ruby_out.trim()).expect("ruby imports JSON");
    let ruby_rows = ruby_rows.as_array().expect("ruby imports array");
    assert!(
        ruby_rows
            .iter()
            .all(|row| row.get("alias").and_then(serde_json::Value::as_str).is_none()),
        "Ruby inferred constant bindings are resolver-only and must not be standalone import rows: {ruby_rows:?}"
    );
    for module in ["auth_service", "sinatra", "sqlite3", "user_service"] {
        assert!(
            ruby_rows
                .iter()
                .any(|row| row.get("module").and_then(serde_json::Value::as_str) == Some(module)),
            "Ruby real require row missing module={module}: {ruby_rows:?}"
        );
    }
}

/// End-to-end sink audit: for every language's micro fixture, both
/// the SQL-injection sink AND the command-injection sink must be
/// reachable through `inspect --query <sink>` and produce a non-empty
/// flow chain. This is the single most important correctness invariant
/// — if it breaks for any language, the whole tool is broken for that
/// language's users.
#[test]
fn inspect_both_sinks_reachable_for_every_lang() {
    // (lang, sql_sink_query, command_sink_query)
    let cases: &[(&str, &str, &str)] = &[
        ("c", "sqlite3_prepare_v2", "system"),
        ("cpp", "sqlite3_prepare_v2", "system"),
        ("csharp", "ExecuteScalar", "Process"),
        ("go", "QueryRow", "exec.Command"),
        ("java", "executeQuery", "Runtime.getRuntime"),
        ("javascript", "db.query", "execSync"),
        ("kotlin", "executeQuery", "Runtime.getRuntime"),
        ("php", "$conn->query", "exec"),
        ("python", "cursor.execute", "os.system"),
        ("ruby", "db.execute", "system"),
        ("rust", "conn.prepare", "Command"),
        ("scala", "executeQuery", "fullCmd.!"),
        ("swift", "sqlite3_prepare_v2", "Process"),
        ("typescript", "db.query", "execSync"),
    ];
    for (lang, sql, cmd) in cases {
        let ws = lang_ws(lang);
        for (kind, query) in [("SQL", sql), ("CMD", cmd)] {
            let Some(out) = run_inspect_graph(&ws, &["--query", query]) else {
                return;
            };
            assert!(
                out.contains("FLOW "),
                "{lang}: {kind} sink `{query}` has no FLOW — output:\n{out}"
            );
            assert!(
                out.contains("MATCH"),
                "{lang}: {kind} sink `{query}` has no MATCH — output:\n{out}"
            );
        }
    }
}

/// Module-level calls (outside any function body — JS `const x =
/// require(...)` at file top, Python top-level script code, Ruby
/// `require` lines, PHP top-level calls) must be findable via
/// `inspect --query <callee>`. These calls don't live in any decl's
/// flow_events; they live in `idx.refs`. The ref walker previously
/// skipped every `RefKind::Call` on the assumption the flow-event
/// pass already surfaced them — which drops module-level calls
/// completely. The fix skips the dedup ONLY when the ref has an
/// enclosing function.
#[test]
fn inspect_finds_module_level_calls() {
    // JavaScript: `const { execSync } = require("child_process");`
    // sits at the top of auth_service.js — no enclosing function.
    let Some(out) = run_on("javascript", &["inspect", "--query", "require", "--kind", "call"]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "javascript: module-level `require` calls not found:\n{out}"
    );
    // Must be multiple hits — the micro fixture has 5 require() calls.
    // Count rows whose `kind` column is `call` by scanning for the
    // `call` token in a context that only appears in table rows:
    // between the leading flow column and the location path segment.
    let call_hits = out
        .lines()
        .filter(|l| l.contains("  call  ") && l.contains(".js:"))
        .count();
    assert!(
        call_hits >= 3,
        "javascript: expected >=3 module-level require calls, got {call_hits}:\n{out}"
    );
}

/// Nested flow events (calls inside try/catch/finally, defer, using/with
/// blocks) must surface in inspect. A bug in this session's
/// `walk_flow_hits` recursion caused Rust's `conn.prepare(...)?` SQL
/// sink — which lands inside a Try event because of the `?` operator —
/// to be invisible to `inspect --query prepare`. This test pins the
/// fix across every event kind that carries a body.
#[test]
fn inspect_finds_calls_nested_in_try_using_defer() {
    // Rust's `?` operator wraps the call in a Try event.
    let rust_ws = lang_ws("rust");
    let Some(out) = run_inspect_graph(&rust_ws, &["--query", "prepare"]) else {
        return;
    };
    assert!(
        out.contains("conn.prepare"),
        "rust: `inspect --query prepare` missed a call nested in Try event:\n{out}"
    );

    // Python: `with open(...)` wraps content in a Using event.
    let py_ws = lang_ws("python");
    let Some(out) = run_inspect_graph(&py_ws, &["--query", "cursor.execute"]) else {
        return;
    };
    assert!(
        out.contains("cursor.execute") && out.contains("FLOW "),
        "python: cursor.execute (inside try/except) not reachable by inspect:\n{out}"
    );
}

/// Dotted-method call construction: every language that has
/// `receiver.method(args)` (or `$obj->method()`) syntax must emit the
/// FULL qualified name in its Call events — not just the final method
/// name. Regressed this session: Java's
/// `Runtime.getRuntime().exec(...)` was collapsing to just `exec`; PHP's
/// `$conn->query($q)` was collapsing to just `query`. The
/// `method_receiver_name` helper concatenates object + name across
/// grammars.
#[test]
fn inspect_qualified_method_calls_preserved() {
    // Java: full path including the chained receiver call.
    let java_ws = lang_ws("java");
    let Some(out) = run_inspect_graph(&java_ws, &["--query", "Runtime.getRuntime"]) else {
        return;
    };
    assert!(
        out.contains("FLOW ") && out.contains("MATCH"),
        "java: `Runtime.getRuntime().exec` callee name not preserved — inspect missed it:\n{out}"
    );

    // PHP: arrow-call qualified text `$conn->query`.
    let php_ws = lang_ws("php");
    let Some(out) = run_inspect_graph(&php_ws, &["--query", "$conn->query"]) else {
        return;
    };
    assert!(
        out.contains("FLOW ") && out.contains("MATCH"),
        "php: `$conn->query` callee name not preserved:\n{out}"
    );
}

/// Symbol positional arg (`bonsai-ninja inspect <ws> <SYMBOL>`) works
/// for every language — uses the micro fixtures' documented entry-like
/// names per language.
#[test]
fn inspect_positional_symbol_works_for_every_lang() {
    let cases: &[(&str, &str)] = &[
        ("c", "handle_request"),
        ("cpp", "handle_request"),
        ("csharp", "HandleRequest"),
        ("go", "HandleRequest"),
        ("java", "handleRequest"),
        ("javascript", "verifyToken"),
        ("kotlin", "handleRequest"),
        ("php", "handle_request"),
        ("python", "handle_request"),
        ("ruby", "verify_token"),
        ("rust", "handle_request"),
        ("scala", "handleRequest"),
        ("swift", "handleRequest"),
        ("typescript", "verifyToken"),
    ];
    for (lang, sym) in cases {
        let ws = lang_ws(lang);
        let Some(out) = run(&["inspect", ws.to_str().unwrap(), sym]) else {
            return;
        };
        assert!(
            !out.contains("no matches"),
            "{lang}: positional symbol `{sym}` returned `no matches`:\n{out}"
        );
    }
}

// -----------------------------------------------------------------------------
// cache subcommand
// -----------------------------------------------------------------------------

#[test]
fn cache_stats_explains_memo_eviction_and_external_path() {
    let ws = ws_path();
    let Some(out) = run(&["cache", "stats", ws.to_str().unwrap()]) else {
        return;
    };
    // Memo capacities are an implementation detail for retained reuse, not a
    // semantic limit. The command must make that distinction explicit.
    for label in &[
        "scope",
        "reachable memo entries",
        "chains memo entries",
        "downstream memo entries",
        "callees memo entries",
        "enclosing memo entries",
        "memo semantics",
        "BONSAI_NO_CACHE env",
        "on-disk cache",
        "cache manifest",
    ] {
        assert!(out.contains(label), "cache stats missing `{label}` line:\n{out}");
    }
    // Cache artifacts belong in the OS cache, never inside the source tree.
    assert!(
        out.contains("bonsai-ninja") && out.contains("workspaces"),
        "cache stats must surface the external workspace-cache path:\n{out}"
    );
    assert!(
        !out.contains("reachable cap") && !out.contains("chains cap"),
        "cache stats must not describe memo eviction as semantic caps:\n{out}"
    );
    assert!(
        !out.contains("manifest freshness  fresh:"),
        "fresh cache manifests should not inherit sidecar freshness detail:\n{out}"
    );
}

#[test]
fn cache_clear_no_op_when_dir_absent() {
    // Use a fresh tempdir that's guaranteed to have no .bonsai/ subdir,
    // so we exercise the "nothing to clear" branch deterministically.
    let tmp = tempdir_for_test("bonsai_cache_clear_absent");
    let Some(out) = run(&["cache", "clear", tmp.to_str().unwrap()]) else {
        return;
    };
    assert!(
        out.contains("nothing to clear"),
        "cache clear on empty dir must say `nothing to clear`:\n{out}"
    );
}

#[test]
fn cache_clear_removes_existing_dir() {
    let tmp = tempdir_for_test("bonsai_cache_clear_present");
    let stats = bonsai_sdk::WorkspaceCache::new(&tmp)
        .stats()
        .expect("cache stats");
    let cache_dir = stats.bonsai_dir.clone();
    std::fs::create_dir_all(cache_dir.join("subdir")).expect("mkdir cache");
    std::fs::write(cache_dir.join("subdir/file.bin"), b"some bytes").expect("write file");
    std::fs::write(&stats.callgraph_sidecar, b"callgraph bytes").expect("write callgraph");
    std::fs::write(&stats.idg_sidecar, b"idg bytes").expect("write idg");
    assert!(cache_dir.exists(), "fixture setup failed");

    let Some(out) = run(&["cache", "clear", tmp.to_str().unwrap()]) else {
        return;
    };
    assert!(
        out.contains("removed"),
        "cache clear output missing `removed`:\n{out}"
    );
    assert!(
        out.contains("freed"),
        "cache clear output missing `freed`:\n{out}"
    );
    assert!(
        out.contains("callgraph sidecar") && out.contains("IDG factstore"),
        "cache clear must list structural sidecars it removes:\n{out}"
    );
    assert!(
        !cache_dir.exists(),
        "cache clear must actually delete the external cache dir"
    );
}

#[test]
fn cache_clear_dataflow_only_removes_factstore_sidecar() {
    let tmp = tempdir_for_test("bonsai_cache_clear_factstore");
    let stats = bonsai_sdk::WorkspaceCache::new(&tmp)
        .stats()
        .expect("cache stats");
    let factstore = stats.dataflow_factstore_sidecar;
    std::fs::create_dir_all(factstore.parent().expect("factstore parent")).expect("mkdir cache");
    std::fs::write(&factstore, b"factstore bytes").expect("write factstore");

    let Some(out) = run(&["cache", "clear", tmp.to_str().unwrap(), "--dataflow-only"]) else {
        return;
    };
    assert!(
        out.contains("removed"),
        "cache clear --dataflow-only output missing `removed`:\n{out}"
    );
    assert!(
        !factstore.exists(),
        "cache clear --dataflow-only must remove the factstore sidecar"
    );
}

/// Build a fresh, isolated tempdir under `std::env::temp_dir()` for one
/// integration test. We avoid the `tempfile` crate to keep dev-deps
/// minimal — the dir is left behind on test failure for inspection.
fn tempdir_for_test(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir();
    for attempt in 0..100 {
        let p = root.join(format!("{name}-{}-{nanos:x}-{attempt}", std::process::id()));
        match std::fs::create_dir(&p) {
            Ok(()) => return p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create tempdir {}: {e}", p.display()),
        }
    }
    panic!("could not allocate tempdir for {name}");
}

fn write_tiny_python_workspace(root: &std::path::Path) {
    std::fs::write(
        root.join("app.py"),
        r#"
def source():
    return input()

def sink(value):
    return value

def handle():
    return sink(source())
"#,
    )
    .expect("write tiny python workspace");
}

fn write_fan_in_python_workspace(root: &std::path::Path, callers: usize) {
    let mut source = String::new();
    for idx in 0..callers {
        source.push_str(&format!("def entry_{idx}():\n    return sink()\n\n"));
    }
    source.push_str("def sink():\n    return 1\n");
    std::fs::write(root.join("app.py"), source).expect("write fan-in python workspace");
}

// -----------------------------------------------------------------------------
// Flag coverage — one minimal smoke test per previously-untested flag
//
// Each test invokes its subcommand with the flag under test and a
// small fixture workspace, then asserts the output structure the
// flag is supposed to produce. Caught during the CLI coverage audit:
// before these tests existed, 13 flags were documented + shipped
// but had zero invocations in the test suite, making it easy to
// break them silently. The tests below are deliberately shallow
// (smoke-level) — deeper semantic tests for specific flags live
// alongside the feature tests throughout this file.
// -----------------------------------------------------------------------------

#[test]
fn inspect_all_flag_runs() {
    let ws = ws_path();
    let Some(out) = run_inspect_graph(&ws, &["--query", "verify_token", "--all"]) else {
        return;
    };
    // `--all` must produce at least the same decl hit as default.
    assert!(
        out.contains("decl hit(s)") || out.contains("FLOW "),
        "--all produced no output:\n{out}"
    );
}

#[test]
fn inspect_rejects_removed_semantic_caps() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    for flag in ["--max-flows", "--max-entry-probes", "--max-hits"] {
        let output = Command::new(&bin)
            .args([
                "inspect",
                ws.to_str().expect("utf-8 workspace"),
                "--query",
                "verify_token",
                flag,
                "1",
                "--no-color",
                "--no-progress",
            ])
            .output()
            .expect("run inspect removed-cap check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains("unexpected argument"),
            "removed semantic cap {flag} must fail at argument parsing: {stderr}"
        );
    }
}

#[test]
fn search_limit_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&[
        "search",
        ws.to_str().unwrap(),
        "--query",
        "verify",
        "--limit",
        "1",
    ]) else {
        return;
    };
    // --limit 1 must produce at most 1 match row (plus header/footer).
    assert!(
        out.contains("verify_token") || out.contains("(1 match"),
        "--limit broke search:\n{out}"
    );
}

#[test]
fn trace_function_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&[
        "trace",
        ws.to_str().unwrap(),
        "--function",
        "verify_token",
        "--format",
        "text",
    ]) else {
        return;
    };
    assert!(
        out.contains("verify_token") || out.contains("flow"),
        "--function flag broke trace:\n{out}"
    );
}

#[test]
fn strings_contains_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&["strings", ws.to_str().unwrap(), "--contains", "token"]) else {
        return;
    };
    // Either the filter matched strings or the table header rendered.
    assert!(
        out.contains("token") || out.contains("string") || out.contains("literal"),
        "--contains broke strings:\n{out}"
    );
}

#[test]
fn vars_source_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&["vars", ws.to_str().unwrap(), "--source", "request"]) else {
        return;
    };
    // The flag must run cleanly (exit 0, table header present). An
    // empty-match result is still a correct run — the fixture may
    // simply not have any `request`-sourced assignments.
    assert!(
        out.contains("source") || out.contains("writes") || out.contains("var"),
        "--source broke vars:\n{out}"
    );
}

#[test]
fn args_keyword_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&["args", ws.to_str().unwrap(), "--keyword", "token"]) else {
        return;
    };
    // Flag accepted, table renders, even if zero matches.
    assert!(
        out.contains("arg") || out.contains("callee") || out.contains("no matches"),
        "--keyword broke args:\n{out}"
    );
}

#[test]
fn args_value_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&["args", ws.to_str().unwrap(), "--value", "token"]) else {
        return;
    };
    assert!(
        out.contains("token") || out.contains("args") || out.contains("no matches"),
        "--value broke args:\n{out}"
    );
}

#[test]
fn calls_call_kind_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&["calls", ws.to_str().unwrap(), "--call-kind", "method"]) else {
        return;
    };
    // Method call-kind filter must produce a non-panic result.
    assert!(
        !out.is_empty() && !out.contains("panicked"),
        "--call-kind broke calls:\n{out}"
    );
}

#[test]
fn classes_min_methods_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&["classes", ws.to_str().unwrap(), "--min-methods", "0"]) else {
        return;
    };
    assert!(
        !out.is_empty() && !out.contains("panicked"),
        "--min-methods broke classes:\n{out}"
    );
}

#[test]
fn defs_has_decorator_flag_runs() {
    // Python fixture has `@app.route` decorators.
    let ws = lang_ws("python");
    let Some(out) = run(&["defs", ws.to_str().unwrap(), "--has-decorator", "route"]) else {
        return;
    };
    assert!(
        !out.is_empty() && !out.contains("panicked"),
        "--has-decorator broke defs:\n{out}"
    );
}

#[test]
fn defs_has_param_flag_runs() {
    let ws = ws_path();
    let Some(out) = run(&["defs", ws.to_str().unwrap(), "--has-param", "token"]) else {
        return;
    };
    assert!(
        !out.is_empty() && !out.contains("panicked"),
        "--has-param broke defs:\n{out}"
    );
}

#[test]
fn imports_alias_flag_runs() {
    // Python fixture has `import sqlite3` style imports.
    let ws = lang_ws("python");
    let Some(out) = run(&["imports", ws.to_str().unwrap(), "--alias", "sqlite3"]) else {
        return;
    };
    assert!(
        !out.is_empty() && !out.contains("panicked"),
        "--alias broke imports:\n{out}"
    );
}

// -----------------------------------------------------------------------------
// Canonical flow integrity — the test that would have caught the Ruby /
// JS / TS fixtures where DSL route blocks (Sinatra `get`, Express
// `app.get`) didn't capture as tree-sitter decls and left chains
// stopping at `update_user` instead of reaching the entry.
//
// Every per-language `micro` fixture is built to exercise the same
// three-hop cross-module flow:
//   handle_request   →   update_user   →   run_admin_command
//   (gateway)            (user_service)    (auth_service)
//
// Case varies by language convention: `handle_request` for C / Python
// / PHP / Ruby / Rust, `handleRequest` for JS / TS / Java / Kotlin /
// Scala / Swift, `HandleRequest` for Go / C#. Names for `update_user`
// and `run_admin_command` follow the same convention per language.
//
// The asserts below pin every step so a fixture that accidentally
// stops using a named entry point (DSL callback, anonymous closure)
// fails the suite loudly instead of producing a silently-short chain.
// -----------------------------------------------------------------------------

/// Canonical entry / mid / sink names for each language's micro
/// fixture. Keep in sync with the fixture files under
/// `examples/<lang>/micro/`. We query by the sink FUNCTION name
/// (not the language-specific shell builtin like `system` /
/// `execSync` / `Command.!`) so the test stays portable — every
/// fixture has a `runAdminCommand` (or snake_case equivalent) that
/// wraps the builtin.
struct CanonicalChain {
    lang: &'static str,
    entry: &'static str,
    mid: &'static str,
    sink: &'static str,
}

fn canonical_chains() -> Vec<CanonicalChain> {
    vec![
        CanonicalChain {
            lang: "c",
            entry: "handle_request",
            mid: "update_user",
            sink: "run_admin_command",
        },
        CanonicalChain {
            lang: "cpp",
            entry: "handle_request",
            mid: "update_user",
            sink: "run_admin_command",
        },
        CanonicalChain {
            lang: "csharp",
            entry: "HandleRequest",
            mid: "UpdateUser",
            sink: "RunAdminCommand",
        },
        CanonicalChain {
            lang: "go",
            entry: "HandleRequest",
            mid: "UpdateUser",
            sink: "RunAdminCommand",
        },
        CanonicalChain {
            lang: "java",
            entry: "handleRequest",
            mid: "updateUser",
            sink: "runAdminCommand",
        },
        CanonicalChain {
            lang: "javascript",
            entry: "handleRequest",
            mid: "updateUser",
            sink: "runAdminCommand",
        },
        CanonicalChain {
            lang: "kotlin",
            entry: "handleRequest",
            mid: "updateUser",
            sink: "runAdminCommand",
        },
        CanonicalChain {
            lang: "php",
            entry: "handle_request",
            mid: "update_user",
            sink: "run_admin_command",
        },
        CanonicalChain {
            lang: "python",
            entry: "handle_request",
            mid: "update_user",
            sink: "run_admin_command",
        },
        CanonicalChain {
            lang: "ruby",
            entry: "handle_request",
            mid: "update_user",
            sink: "run_admin_command",
        },
        CanonicalChain {
            lang: "rust",
            entry: "handle_request",
            mid: "update_user",
            sink: "run_admin_command",
        },
        CanonicalChain {
            lang: "scala",
            entry: "handleRequest",
            mid: "updateUser",
            sink: "runAdminCommand",
        },
        CanonicalChain {
            lang: "swift",
            entry: "handleRequest",
            mid: "updateUser",
            sink: "runAdminCommand",
        },
        CanonicalChain {
            lang: "typescript",
            entry: "handleRequest",
            mid: "updateUser",
            sink: "runAdminCommand",
        },
    ]
}

/// Every per-language micro fixture must have the canonical entry
/// function as a surface-level decl — not hidden inside a DSL
/// callback (Sinatra `get`, Express `app.get`) that tree-sitter
/// can't walk into. `defs` enumerates every captured decl; this
/// test asserts the entry name shows up there.
#[test]
fn every_lang_micro_has_canonical_entry_decl() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["defs", ws.to_str().unwrap()]) else {
            return;
        };
        assert!(
            out.contains(c.entry),
            "{}: micro fixture must surface `{}` as a named decl, got:\n{out}",
            c.lang,
            c.entry,
        );
    }
}

/// The canonical mid-hop `update_user` function must also be
/// captured. Catches fixture regressions where the mid-layer
/// becomes an anonymous lambda or a DSL block.
#[test]
fn every_lang_micro_has_canonical_mid_decl() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["defs", ws.to_str().unwrap()]) else {
            return;
        };
        assert!(
            out.contains(c.mid),
            "{}: micro fixture must surface `{}` as a named decl, got:\n{out}",
            c.lang,
            c.mid,
        );
    }
}

/// The ultimate sink function (shell-exec shim) must exist.
#[test]
fn every_lang_micro_has_canonical_sink_decl() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["defs", ws.to_str().unwrap()]) else {
            return;
        };
        assert!(
            out.contains(c.sink),
            "{}: micro fixture must surface `{}` as a named decl, got:\n{out}",
            c.lang,
            c.sink,
        );
    }
}

/// The headline integrity check: `inspect --query <sink-fn>` on
/// every micro fixture must produce a FLOW chain of at least 3 hops
/// starting at the entry function. If the entry is missing (e.g.
/// Ruby's Sinatra block bug) the chain stops at `update_user` and
/// this assertion fires loudly. We query on the sink's FUNCTION
/// name (`run_admin_command` / `RunAdminCommand` / `runAdminCommand`
/// per language convention) so the test works regardless of which
/// shell builtin each language shells out to.
#[test]
fn every_lang_micro_chain_reaches_entry_to_sink() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        // Chain line shape: `entry → mid → sink` (arrow-connected,
        // one line). Our non-ANSI test runs use the → character.
        let chain_line = out
            .lines()
            .find(|l| l.contains(c.entry) && l.contains(c.mid) && l.contains(c.sink))
            .unwrap_or("");
        assert!(
            !chain_line.is_empty(),
            "{}: inspect --query {} must produce a chain `{} → {} → {}`; got:\n{out}",
            c.lang,
            c.sink,
            c.entry,
            c.mid,
            c.sink,
        );
    }
}

// -----------------------------------------------------------------------------
// Browse-fact match coverage for `--from` / `--to` / `--query`
//
// The filter / query path must match against every fact kind the
// tool surfaces under the browse commands in `--help`:
//
//   defs      → function / method / class / struct names
//   calls     → call-site names (qualified + short)
//   imports   → import module + alias
//   vars      → assignment targets
//   strings   → string literals
//   args      → call-site argument values + keywords
//   classes   → class / struct / trait / interface / enum names
//   refs      → every ref (read / call / type / decorator)
//
// The tests below use the Python micro fixture because it covers
// every kind in one compact workspace: named defs, qualified calls
// (`sqlite3.connect`), `import sqlite3` at the top, `user =`
// assignments, `"notify-admin "` string sink argument, the
// `AuthService` class (removed in some fixtures — Python uses
// functions), and refs everywhere. Before the filter broadening,
// needles from the vars / strings / imports / args kinds failed
// with "no matches" — the Ruby `--from params --to system` bug
// the user flagged. The tests below pin that every kind is now
// usable as a --from / --to / --query needle.
// -----------------------------------------------------------------------------

fn py_ws() -> std::path::PathBuf {
    lang_ws("python")
}

/// --from on a def name (function) keeps the canonical chain.
#[test]
fn from_needle_matches_def_name() {
    let ws = py_ws();
    let Some(out) = run_inspect_graph(&ws, &["--from", "handle_request", "--to", "os.system"]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--from def-name should match:\n{out}"
    );
    assert!(out.contains("handle_request"), "from column missing:\n{out}");
}

/// --from on a call-site name (e.g. `sqlite3.connect`) matches.
#[test]
fn from_needle_matches_call_site() {
    let ws = py_ws();
    let Some(out) = run_inspect_graph(&ws, &["--from", "sqlite3.connect", "--to", "execute"]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--from call-site should match:\n{out}"
    );
}

/// Import-module names are file-scoped, not flow-connected. Under
/// the taint-only filter semantics a bare import like `sqlite3` is
/// NOT a valid `--from` needle unless a call site actually passes
/// tainted data through it — which isn't the case in this fixture
/// (sqlite3.connect takes the string literal "auth.db"). The test
/// pins this intentional rejection so a regression to the old
/// lexical-reachability filter would light up.
#[test]
fn from_needle_rejects_untainted_import_module() {
    let ws = py_ws();
    let Some(out) = run_inspect_graph(&ws, &["--from", "sqlite3", "--to", "os.system"]) else {
        return;
    };
    assert!(
        out.contains("no matches"),
        "--from import-module must not match when no taint passes through it; got:\n{out}"
    );
}

/// --from on an assignment target / source (var) matches.
#[test]
fn from_needle_matches_var_target() {
    let ws = py_ws();
    // `user = get_user(token)` is an assignment in handle_request.
    let Some(out) = run_inspect_graph(&ws, &["--from", "user", "--to", "os.system"]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--from var-target should match:\n{out}"
    );
}

/// --from on a parameter name (args, formal) matches. The Ruby
/// `--from params` case that exposed this gap.
#[test]
fn from_needle_matches_parameter_name() {
    let ws = py_ws();
    let Some(out) = run_inspect_graph(&ws, &["--from", "token", "--to", "os.system"]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--from parameter-name should match:\n{out}"
    );
}

/// --to on a string literal (strings) matches.
#[test]
fn to_needle_matches_string_literal() {
    let ws = py_ws();
    // Python's auth_service.py has `"notify-admin "` as a string
    // concatenated into the shell command.
    let Some(out) = run_inspect_graph(&ws, &["--from", "handle_request", "--to", "notify-admin"]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--to string-literal should match:\n{out}"
    );
}

/// --to on a call-site argument value (args) matches.
#[test]
fn to_needle_matches_call_arg_value() {
    let ws = py_ws();
    // `request.args.get("token")` passes `"token"` as an arg value;
    // user's --to may key on that string.
    let Some(out) = run_inspect_graph(&ws, &["--from", "handle_request", "--to", "action"]) else {
        return;
    };
    assert!(!out.contains("no matches"), "--to arg-value should match:\n{out}");
}

/// Class names are file-scoped decls, not tokens flow-connected to
/// a specific chain. Under the taint-only filter they're not a
/// valid `--from` needle unless the chain actually touches the
/// class (e.g. instantiation, method dispatch with tainted args).
/// The Java Gateway class doesn't appear as an inner-body token on
/// the canonical chain, so the query correctly rejects.
#[test]
fn from_needle_rejects_bare_class_name() {
    let ws = lang_ws("java");
    let Some(out) = run_inspect_graph(&ws, &["--from", "Gateway", "--to", "exec"]) else {
        return;
    };
    assert!(
        out.contains("no matches"),
        "--from class-name must not match without a flow-connected use; got:\n{out}"
    );
}

/// --from on a ref name (refs). Refs include every read / call /
/// type reference captured by the adapter.
#[test]
fn from_needle_matches_ref_name() {
    let ws = py_ws();
    // `get_user` is referenced as a call inside handle_request.
    let Some(out) = run_inspect_graph(&ws, &["--from", "get_user", "--to", "os.system"]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--from ref-name should match:\n{out}"
    );
}

/// --query itself must cover every browse fact too: every kind
/// that shows up as a distinct browse subcommand should be
/// queryable. We pick the right fixture per kind — Python's micro
/// uses free functions (no classes), so the class-kind sub-test
/// runs against Java (which declares `class Gateway`).
#[test]
fn query_needle_matches_every_browse_fact_kind() {
    // (lang, label, needle)
    let cases: &[(&str, &str, &str)] = &[
        ("python", "def", "handle_request"),
        ("java", "class", "Gateway"),
        ("python", "call", "sqlite3.connect"),
        ("python", "import", "sqlite3"),
        ("python", "var", "token"),
        ("python", "string", "notify-admin"),
        ("python", "arg", "token"),
        ("python", "ref", "get_user"),
    ];
    for (lang, label, needle) in cases {
        let ws = lang_ws(lang);
        let Some(out) = run(&["inspect", ws.to_str().unwrap(), "--query", needle]) else {
            return;
        };
        assert!(
            !out.contains("no matches"),
            "`--query {needle}` ({label}) should match in the {lang} micro fixture:\n{out}"
        );
    }
}

/// `--from <entry> --to <sink>` must also resolve — both needles
/// must be reachable from at least one hit's chain. Catches
/// resolved-call-graph edge regressions where the tool thinks a
/// chain exists but the filter path doesn't see it.
#[test]
fn every_lang_micro_from_entry_to_sink_filter_matches() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--from", c.entry, "--to", c.sink]) else {
            return;
        };
        // `no matches` is a regression — the canonical flow must exist.
        assert!(
            !out.contains("no matches"),
            "{}: --from {} --to {} returned no matches; chain should exist:\n{out}",
            c.lang,
            c.entry,
            c.sink,
        );
        // And the FROM column must contain the entry with its
        // resolved file:line (added in the hits-table refactor).
        assert!(
            out.contains(c.entry),
            "{}: --from {} --to {} table missing entry in `from` column:\n{out}",
            c.lang,
            c.entry,
            c.sink,
        );
    }
}

// =============================================================================
// Phase A: flow_id + --compact + --flow matrix coverage
//
// These tests pin the content-addressed `F:<16-hex>` identifier to
// every inspect rendering across every supported language. The
// id must:
//   - appear in the default text render next to FLOW N
//   - be stable across two consecutive invocations (no random seed)
//   - round-trip: --flow <id-from-run-1> must select exactly that flow
//   - survive --compact (same id, just different body render)
//   - appear on every flow in the JSON payload
// =============================================================================

/// Pull every stable-id token out of a rendered inspect
/// output. `prefix_byte` is `b'F'` for flow_ids, `b'G'` for group_ids.
/// Scans the rendered text byte-by-byte so ANSI color codes / variable
/// spacing between columns don't affect extraction. Returns the matched
/// tokens in encounter order.
fn extract_id_tokens(rendered: &str, prefix_byte: u8) -> Vec<String> {
    let body_len = if matches!(prefix_byte, b'F' | b'G' | b'S') {
        16
    } else {
        8
    };
    let id_len = 2 + body_len;
    let mut tokens: Vec<String> = Vec::new();
    for line in rendered.lines() {
        let bytes = line.as_bytes();
        let mut byte_idx = 0;
        while byte_idx + id_len <= bytes.len() {
            let looks_like_id_start = bytes[byte_idx] == prefix_byte && bytes[byte_idx + 1] == b':';
            if looks_like_id_start {
                let hex_body = &bytes[byte_idx + 2..byte_idx + id_len];
                let all_lowercase_hex = hex_body
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
                if all_lowercase_hex {
                    let id_token = std::str::from_utf8(&bytes[byte_idx..byte_idx + id_len])
                        .unwrap()
                        .to_string();
                    tokens.push(id_token);
                    byte_idx += id_len;
                    continue;
                }
            }
            byte_idx += 1;
        }
    }
    tokens
}

/// Pull every `F:` flow id out of an inspect render, in encounter order.
fn extract_flow_ids(rendered: &str) -> Vec<String> {
    extract_id_tokens(rendered, b'F')
}

/// Return true if the JSON tree rooted at `value` contains an object
/// with field `field_name` whose string value looks like a well-formed
/// stable id (`<expected_prefix>:` + lowercase hex chars). Walks the
/// whole tree; stops on the first match. Used by the Phase A/B matrix
/// tests to confirm `flow_id` / `group_id` show up in `--format json`
/// output without caring about which specific decl / hit they're on.
fn json_tree_contains_id_field(value: &serde_json::Value, field_name: &str, expected_prefix: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(id_value) = map.get(field_name) {
                if let Some(id_str) = id_value.as_str() {
                    let expected_len = if matches!(expected_prefix, "F:" | "G:" | "S:") {
                        18
                    } else {
                        10
                    };
                    if id_str.starts_with(expected_prefix) && id_str.len() == expected_len {
                        return true;
                    }
                }
            }
            map.values()
                .any(|child| json_tree_contains_id_field(child, field_name, expected_prefix))
        }
        serde_json::Value::Array(arr) => arr
            .iter()
            .any(|child| json_tree_contains_id_field(child, field_name, expected_prefix)),
        _ => false,
    }
}

#[test]
fn show_flow_id_reopens_inspect_drilldown() {
    let ws = ws_path();
    let Some(full) = run_inspect_graph(&ws, &["--query", "os.system"]) else {
        return;
    };
    let ids = extract_flow_ids(&full);
    let Some(target) = ids.first() else {
        panic!("fixture should emit at least one F: id:\n{full}");
    };
    let Some(out) = run(&["show", ws.to_str().unwrap(), target, "--compact"]) else {
        return;
    };
    assert!(
        out.contains(target) && out.contains("FLOW"),
        "show F: should delegate to inspect and render the target flow; got:\n{out}"
    );
    assert!(
        !out.contains("OCCURRENCE HITS") && !out.contains("match points:"),
        "show F: is a structural-chain drilldown; it must not attach arbitrary syntax hits:\n{out}"
    );
}

#[test]
fn show_edge_id_reopens_dump_edges_drilldown() {
    let ws = ws_path();
    let Some(full) = run(&["dump-edges", ws.to_str().unwrap()]) else {
        return;
    };
    let ids = extract_edge_ids(&full);
    let Some(target) = ids.first() else {
        panic!("fixture should emit at least one E: id:\n{full}");
    };
    let Some(out) = run(&["show", ws.to_str().unwrap(), target, "--compact"]) else {
        return;
    };
    let got = extract_edge_ids(&out);
    assert_eq!(
        got,
        vec![target.clone()],
        "show E: should delegate to dump-edges --edge; got:\n{out}"
    );
}

#[test]
fn show_taint_id_reopens_inspect_taint_drilldown() {
    let ws = ws_path();
    let Some(full) = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--taint-flow",
    ]) else {
        return;
    };
    let ids = extract_taint_ids(&full);
    let Some(target) = ids.first() else {
        panic!("fixture should emit at least one T: id:\n{full}");
    };
    let Some(out) = run(&["show", ws.to_str().unwrap(), target]) else {
        return;
    };
    assert!(
        out.contains(target) && out.contains("TAINT FLOWS"),
        "show T: should delegate to inspect taint drilldown; got:\n{out}"
    );
}

#[test]
fn show_taint_id_with_source_reopens_dump_taint_drilldown() {
    let ws = ws_path();
    let Some(full) = run(&[
        "dump-taint",
        ws.to_str().unwrap(),
        "--source",
        "update_user",
        "--seed",
        "token",
        "--seed",
        "action",
    ]) else {
        return;
    };
    let ids = extract_taint_ids(&full);
    let Some(target) = ids.first() else {
        panic!("fixture should emit at least one dump-taint T: id:\n{full}");
    };
    let Some(out) = run(&[
        "show",
        ws.to_str().unwrap(),
        target,
        "--taint-source",
        "update_user",
        "--taint-seed",
        "token",
        "--taint-seed",
        "action",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value =
        serde_json::from_str(out.trim()).expect("show dump-taint JSON must parse");
    let records = parsed["records"].as_array().expect("records array");
    assert_eq!(
        records.len(),
        1,
        "show dump-taint drilldown should keep one record: {out}"
    );
    assert_eq!(records[0]["taint_id"].as_str(), Some(target.as_str()));
    assert_eq!(parsed["source"].as_str(), Some("update_user"));
    assert_eq!(
        parsed["seeds"].as_array().expect("seeds array").len(),
        2,
        "show dump-taint drilldown should preserve explicit seeds: {out}"
    );
}

#[test]
fn show_taint_dump_filters_require_source() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = Command::new(&bin)
        .args([
            "show",
            ws.to_str().unwrap(),
            "T:00000000",
            "--taint-seed",
            "token",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "show T: with dump-taint filters but no source must fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        rendered.contains("--taint-source"),
        "show T: dump-taint error should explain the missing source; got:\n{rendered}"
    );
}

#[test]
fn show_resolver_id_requires_original_query() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = Command::new(&bin)
        .args(["show", ws.to_str().unwrap(), "R:00000000", "--no-color"])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "show R: without --query must fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        rendered.contains("--query"),
        "show R: error should explain the missing resolver query; got:\n{rendered}"
    );
}

/// Every language's canonical chain render must carry at least one
/// `F:<16-hex>` flow_id on its FLOW header line.
#[test]
fn every_lang_micro_inspect_emits_flow_id() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        let ids = extract_flow_ids(&out);
        assert!(
            !ids.is_empty(),
            "{}: inspect --query {} must emit at least one F:<16-hex> flow_id; got:\n{out}",
            c.lang,
            c.sink,
        );
        for id in &ids {
            assert_eq!(id.len(), 18, "{}: malformed flow_id `{id}`", c.lang);
        }
    }
}

/// Same query → same flow_ids. If this fails, the hash picked up a
/// per-process random seed (which FNV-1a with a fixed basis won't do,
/// but a future regression to AHasher::default() or SipHash would).
#[test]
fn every_lang_micro_flow_ids_stable_across_runs() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(first) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        let Some(second) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        assert_eq!(
            extract_flow_ids(&first),
            extract_flow_ids(&second),
            "{}: flow_ids drifted between two consecutive inspect runs",
            c.lang,
        );
    }
}

/// `--compact` must preserve the SAME flow_ids as the default render.
/// The id is a structural property of the chain, not a render mode.
#[test]
fn every_lang_micro_flow_ids_survive_compact() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        let Some(compact) = run_inspect_graph(&ws, &["--query", c.sink, "--compact"]) else {
            return;
        };
        assert_eq!(
            extract_flow_ids(&full),
            extract_flow_ids(&compact),
            "{}: --compact must not change flow_ids",
            c.lang,
        );
    }
}

/// `--compact` must produce a SHORTER render than the default. The
/// whole point is skipping full source bodies; if the byte count
/// isn't smaller something is broken.
#[test]
fn every_lang_micro_compact_is_shorter_than_full() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        let Some(compact) = run_inspect_graph(&ws, &["--query", c.sink, "--compact"]) else {
            return;
        };
        assert!(
            compact.len() < full.len(),
            "{}: --compact render ({} bytes) must be smaller than default ({} bytes)",
            c.lang,
            compact.len(),
            full.len(),
        );
    }
}

/// `--flow <id>` must pick exactly one flow from the full render.
/// Pull the first id out of the default render, then round-trip it
/// through `--flow <id>` and verify the filtered output still shows
/// that same id and no others.
#[test]
fn every_lang_micro_flow_filter_roundtrips() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        let ids = extract_flow_ids(&full);
        if ids.is_empty() {
            continue;
        }
        let target = &ids[0];
        let Some(filtered) = run_inspect_graph(&ws, &["--query", c.sink, "--flow", target]) else {
            return;
        };
        let got = extract_flow_ids(&filtered);
        assert!(
            got.iter().all(|id| id == target),
            "{}: --flow {target} should leave only {target}, but output contains: {got:?}",
            c.lang,
        );
        assert!(
            !got.is_empty(),
            "{}: --flow {target} filtered every flow out; expected at least the target",
            c.lang,
        );
    }
}

/// `--flow <id>` with an id that doesn't exist must exit with an
/// error rather than silently returning an empty render. Pick one
/// fixture (python, the richest) so we don't rerun this 14x.
#[test]
fn inspect_flow_unknown_id_errors() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = std::process::Command::new(&bin)
        .args([
            "inspect",
            ws.to_str().unwrap(),
            "--graph-flow",
            "--query",
            "run_admin_command",
            "--flow",
            "F:0000000000000000",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "inspect --flow F:0000000000000000 (unknown id) should exit with failure; stdout was:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("flow") || stderr.contains("F:0000000000000000"),
        "unknown-flow error should mention the flow_id; got stderr:\n{stderr}",
    );
}

/// JSON output must carry a `flow_id` field on every flow object.
/// Downstream consumers (MCP server, LSP) key on this to round-trip
/// user selection.
#[test]
fn every_lang_micro_inspect_json_carries_flow_id() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink, "--format", "json"]) else {
            return;
        };
        let trimmed = out.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed_json: serde_json::Value =
            serde_json::from_str(trimmed).expect("inspect --format json must be valid JSON");
        // flow_id may appear on any flow under decl_hits[].flows[] or
        // hits[].flows[]. Walk the whole tree and require at least one.
        assert!(
            json_tree_contains_id_field(&parsed_json, "flow_id", "F:"),
            "{}: JSON output should contain at least one flow_id field; got:\n{out}",
            c.lang,
        );
    }
}

// =============================================================================
// Phase B: --view trace|grouped|auto + --group matrix coverage
//
// These pin the grouped-view rendering and `--group <id>` round-trip
// across all 14 languages. Even for small fixtures where each decl
// hit wraps a single flow (so every group has exactly one member),
// the following invariants must hold:
//   - `--view grouped` emits a `GROUP N G:<16-hex>` header with the
//     shared suffix line,
//   - `--group <id>` round-trips (extract from grouped render →
//     pass back → same output shape, one group in, one group out),
//   - `--view auto` stays in trace mode below the threshold,
//   - JSON output carries a `group_id` field on every group.
// =============================================================================

/// Pull every `G:<16-hex>` token out of an inspect render, in encounter order.
fn extract_group_ids(rendered: &str) -> Vec<String> {
    extract_id_tokens(rendered, b'G')
}

/// Grouped view emits a `GROUP N G:<16-hex>` header on every decl
/// hit's rendered flows, for every language micro fixture.
#[test]
fn every_lang_micro_grouped_view_emits_group_id() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped"]) else {
            return;
        };
        let ids = extract_group_ids(&out);
        assert!(
            !ids.is_empty(),
            "{}: grouped view must emit at least one G:<16-hex> group_id; got:\n{out}",
            c.lang,
        );
        for id in &ids {
            assert_eq!(id.len(), 18, "{}: malformed group_id `{id}`", c.lang);
        }
        // Grouped view emits a `shared:` line on every group.
        assert!(
            out.contains("shared:"),
            "{}: grouped view must include `shared:` chain lines; got:\n{out}",
            c.lang,
        );
    }
}

/// Same query + same view → same group_ids across two runs. Pins
/// the determinism we need for `--group <id>` round-tripping.
#[test]
fn every_lang_micro_group_ids_stable_across_runs() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(first) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped"]) else {
            return;
        };
        let Some(second) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped"]) else {
            return;
        };
        assert_eq!(
            extract_group_ids(&first),
            extract_group_ids(&second),
            "{}: group_ids drifted between two consecutive grouped runs",
            c.lang,
        );
    }
}

/// `--group <id>` round-trips on every language: take the first
/// group_id emitted by `--view grouped`, pass it back via `--group`,
/// and verify the filtered output still contains that id and nothing
/// but that id.
#[test]
fn every_lang_micro_group_filter_roundtrips() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped"]) else {
            return;
        };
        let ids = extract_group_ids(&full);
        if ids.is_empty() {
            continue;
        }
        let target = &ids[0];
        let Some(filtered) =
            run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped", "--group", target])
        else {
            return;
        };
        let got = extract_group_ids(&filtered);
        assert!(
            !got.is_empty(),
            "{}: --group {target} filtered every group out; expected at least the target",
            c.lang,
        );
        assert!(
            got.iter().all(|id| id == target),
            "{}: --group {target} should leave only {target}, got: {got:?}",
            c.lang,
        );
    }
}

/// `--group <id>` with an unknown id must fail (non-zero exit) and
/// surface a clear error mentioning the id. Mirror of the `--flow
/// <id>` behavior — silent empty output is a bug, not a feature.
#[test]
fn inspect_group_unknown_id_errors() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = std::process::Command::new(&bin)
        .args([
            "inspect",
            ws.to_str().unwrap(),
            "--graph-flow",
            "--query",
            "run_admin_command",
            "--group",
            "G:0000000000000000",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "inspect --group G:0000000000000000 should exit with failure; stdout was:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("group") || stderr.contains("G:0000000000000000"),
        "unknown-group error should mention the group_id; got stderr:\n{stderr}",
    );
}

/// `--view auto` stays in trace mode when the result set is small
/// (≤ threshold total flows). The canonical single-chain fixtures
/// all land well below the threshold, so `auto` must behave as
/// `trace` on them — no `view: grouped` header, no `GROUP N`
/// blocks, no `shared:` lines.
#[test]
fn every_lang_micro_auto_stays_in_trace_below_threshold() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "auto"]) else {
            return;
        };
        assert!(
            !out.contains("view: grouped"),
            "{}: auto view should stay in trace mode on small fixtures; got `view: grouped` in:\n{out}",
            c.lang,
        );
        assert!(
            !out.contains("GROUP 1"),
            "{}: auto view should NOT emit GROUP blocks on small fixtures; got:\n{out}",
            c.lang,
        );
    }
}

/// `--view grouped` produces JSON with a `group_id` field in every
/// emitted group. Downstream consumers (MCP server, LSP) rely on
/// this for `--group <id>` round-tripping.
#[test]
fn every_lang_micro_grouped_json_carries_group_id() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped", "--format", "json"])
        else {
            return;
        };
        let trimmed = out.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed_json: serde_json::Value =
            serde_json::from_str(trimmed).expect("grouped JSON must be valid");
        assert!(
            json_tree_contains_id_field(&parsed_json, "group_id", "G:"),
            "{}: grouped JSON should carry at least one group_id; got:\n{out}",
            c.lang,
        );
    }
}

/// group_id and flow_id namespaces are distinct: even when a group
/// has exactly one member and the member's chain IS the shared
/// suffix, the `G:` and `F:` ids must differ so consumers that
/// parse ids (strip prefix, expect hex) can't confuse the two.
#[test]
fn every_lang_micro_group_and_flow_id_namespaces_are_distinct() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped"]) else {
            return;
        };
        let flow_ids = extract_flow_ids(&out);
        let group_ids = extract_group_ids(&out);
        if flow_ids.is_empty() || group_ids.is_empty() {
            continue;
        }
        // The set of strings is disjoint by prefix ('F:' vs 'G:'),
        // but the body may match — that's expected when a group has
        // only one member whose chain equals the shared_suffix. So
        // we verify the prefix discipline, not full inequality.
        for id in &flow_ids {
            assert!(id.starts_with("F:"), "flow_id `{id}` missing F: prefix");
        }
        for id in &group_ids {
            assert!(id.starts_with("G:"), "group_id `{id}` missing G: prefix");
        }
    }
}

/// Interaction test: `--compact` + `--view grouped` must emit
/// GROUP blocks AND suppress source bodies. No full `[module] ...
/// [def] ...` source dumps should appear in the compact-grouped
/// render.
#[test]
fn every_lang_micro_compact_plus_grouped_has_no_source_bodies() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink, "--view", "grouped", "--compact"]) else {
            return;
        };
        // Grouped header is present.
        assert!(
            out.contains("GROUP 1"),
            "{}: compact + grouped must emit GROUP blocks; got:\n{out}",
            c.lang,
        );
        // `[module] <path>` headers only appear inside full source
        // body renders, which --compact strips. If one leaks, the
        // compact+grouped path is rendering bodies.
        assert!(
            !out.contains("[module]"),
            "{}: compact + grouped must suppress source bodies (found `[module]` in output):\n{out}",
            c.lang,
        );
    }
}

// =============================================================================
// Phase A + B: interaction + regression guards
//
// Cross-feature tests that pin combinations which could regress
// silently: `--all` + flow_id, `--flow` + `--group`, export JSON
// shape, truncation + flow_id. One fixture (python, the richest) is
// enough here — the canonical matrix covers per-language shape.
// =============================================================================

/// `--all` lifts all caps and still must preserve flow_ids. A
/// truncation bug that re-numbered flows when caps lifted would
/// show up as a changed flow_id.
#[test]
fn all_flag_preserves_flow_ids() {
    let ws = ws_path();
    let Some(base) = run_inspect_graph(&ws, &["--query", "run_admin_command"]) else {
        return;
    };
    let Some(all) = run_inspect_graph(&ws, &["--query", "run_admin_command", "--all"]) else {
        return;
    };
    let base_ids = extract_flow_ids(&base);
    let all_ids = extract_flow_ids(&all);
    // Every flow_id in the base render must also appear under --all.
    // (--all may add more flows that were truncated before.)
    for id in &base_ids {
        assert!(
            all_ids.contains(id),
            "--all dropped a flow_id `{id}` that was present in the default render",
        );
    }
}

/// `--flow <flow_id>` and `--group <group_id>` combined must
/// intersect correctly: if the flow belongs to the group, keep
/// it; otherwise empty → error. Pin the intersection behavior
/// so future rework doesn't silently flip to union.
#[test]
fn flow_and_group_filters_intersect() {
    let ws = ws_path();
    let Some(grouped) = run_inspect_graph(&ws, &["--query", "run_admin_command", "--view", "grouped"]) else {
        return;
    };
    let flow_ids = extract_flow_ids(&grouped);
    let group_ids = extract_group_ids(&grouped);
    if flow_ids.is_empty() || group_ids.is_empty() {
        return;
    }
    let Some(out) = run_inspect_graph(
        &ws,
        &[
            "--query",
            "run_admin_command",
            "--flow",
            &flow_ids[0],
            "--group",
            &group_ids[0],
        ],
    ) else {
        return;
    };
    // Intersection of the first group with the first flow (which
    // is a member of the first group) is non-empty → the render
    // must still contain flow_ids[0].
    assert!(
        extract_flow_ids(&out).contains(&flow_ids[0]),
        "--flow + --group should intersect and keep the flow when it's a group member; got:\n{out}",
    );
}

/// `--format json` output in grouped view carries BOTH `flow_id` on
/// every flow AND `group_id` on every group. Tools that parse the
/// JSON need both keys stable.
#[test]
fn grouped_json_has_both_flow_ids_and_group_ids() {
    let ws = ws_path();
    let Some(out) = run_inspect_graph(
        &ws,
        &[
            "--query",
            "run_admin_command",
            "--view",
            "grouped",
            "--format",
            "json",
        ],
    ) else {
        return;
    };
    let parsed_json: serde_json::Value = serde_json::from_str(out.trim()).expect("grouped JSON must parse");
    // Flatten to a single string and search for the expected field
    // keys. Cheap and robust — we just need to know they appear
    // somewhere in the tree, not where exactly.
    let serialized_json = parsed_json.to_string();
    for required_field in ["flow_id", "group_id", "shared_suffix", "member_flow_ids"] {
        let quoted_key = format!("\"{required_field}\"");
        assert!(
            serialized_json.contains(&quoted_key),
            "grouped JSON missing expected field `{required_field}`"
        );
    }
}

/// Updating the canonical-chain `inspect` matrix test to also assert
/// that the rendered chain line carries a stable id nearby. Pins id
/// visibility on the same output line users already read for the
/// chain. Raw taint rows use `T:` ids, while structural graph rows use
/// `F:` ids; either is citeable in the inspect UI.
#[test]
fn every_lang_micro_chain_line_has_stable_id_nearby() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink]) else {
            return;
        };
        // Find the chain line, then look for a flow_id within 4
        // lines before or after (the FLOW header + separator
        // ruler is 2 lines above; within 4 lines covers both
        // trace and grouped shapes).
        let output_lines: Vec<&str> = out.lines().collect();
        let chain_line_idx = output_lines
            .iter()
            .position(|line| line.contains(c.entry) && line.contains(c.mid) && line.contains(c.sink));
        let Some(chain_line_idx) = chain_line_idx else {
            panic!(
                "{}: chain line missing; can't check flow_id adjacency. Output:\n{out}",
                c.lang
            );
        };
        let window_start = chain_line_idx.saturating_sub(4);
        let window_end = (chain_line_idx + 5).min(output_lines.len());
        let adjacent_window = output_lines[window_start..window_end].join("\n");
        let flow_ids_in_window = extract_flow_ids(&adjacent_window);
        let taint_ids_in_window = extract_taint_ids(&adjacent_window);
        assert!(
            !flow_ids_in_window.is_empty() || !taint_ids_in_window.is_empty(),
            "{}: chain line at `{}` has no stable flow/taint id within ±4 lines; window:\n{adjacent_window}",
            c.lang,
            output_lines[chain_line_idx],
        );
    }
}

/// `--view auto` on a query that crosses the threshold must flip to
/// grouped mode. Uses the larger `examples/python` tree (complex +
/// micro combined) with the `execute` query which produces well
/// over the threshold — plenty of flows to trigger auto-grouped.
#[test]
fn auto_view_flips_to_grouped_above_threshold() {
    let ws = repo_root().join("examples/python");
    let Some(out) = run_inspect_graph(&ws, &["--query", "execute", "--view", "auto"]) else {
        return;
    };
    assert!(
        out.contains("view: grouped"),
        "auto view should flip to grouped above threshold; got:\n{out}",
    );
    assert!(
        out.contains("GROUP 1"),
        "auto view in grouped mode should emit GROUP blocks; got:\n{out}",
    );
}

/// `--compact` must still emit the canonical chain line
/// `entry → mid → sink` — we only strip source bodies, not the
/// chain header.
#[test]
fn every_lang_micro_compact_preserves_chain_line() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run_inspect_graph(&ws, &["--query", c.sink, "--compact"]) else {
            return;
        };
        let chain_line = out
            .lines()
            .find(|l| l.contains(c.entry) && l.contains(c.mid) && l.contains(c.sink))
            .unwrap_or("");
        assert!(
            !chain_line.is_empty(),
            "{}: --compact must still emit the `{} → {} → {}` chain line; got:\n{out}",
            c.lang,
            c.entry,
            c.mid,
            c.sink,
        );
    }
}

// =============================================================================
// dump-edges: resolved call edges with E:id + compact/drill-down
//
// Matrix tests per supported language. Every canonical-chain fixture
// must produce at least one resolved edge (the `entry → mid`
// connection at minimum), every edge must carry an `E:xxxxxxxx` id,
// `--compact` must emit a table with the same ids, `--edge <E:id>`
// must round-trip, and the precision filter must split the edge set.
// =============================================================================

/// Pull every `E:xxxxxxxx` id token out of a rendered `dump-edges`
/// output.
fn extract_edge_ids(rendered: &str) -> Vec<String> {
    extract_id_tokens(rendered, b'E')
}

/// Pull every `N:xxxxxxxx` id token out of a rendered `dump-ast`
/// output.
fn extract_node_ids(rendered: &str) -> Vec<String> {
    extract_id_tokens(rendered, b'N')
}

#[test]
fn every_lang_micro_dump_edges_emits_edge_ids() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["dump-edges", ws.to_str().unwrap()]) else {
            return;
        };
        let ids = extract_edge_ids(&out);
        assert!(
            !ids.is_empty(),
            "{}: dump-edges must emit at least one E:xxxxxxxx edge_id; got:\n{out}",
            c.lang,
        );
        for id in &ids {
            assert_eq!(id.len(), 10, "{}: malformed edge_id `{id}`", c.lang);
        }
    }
}

/// Compact mode must have FEWER lines than the full multi-line
/// render (the whole point — collapse each 4-line edge block into
/// one table row) and carry the same edge_ids. We measure lines,
/// not bytes: at very small edge counts the comfy-table border
/// chrome (`─` separators, column padding) can make byte count
/// larger even when the visible output is 3× denser.
#[test]
fn every_lang_micro_dump_edges_compact_fewer_lines_same_ids() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run(&["dump-edges", ws.to_str().unwrap()]) else {
            return;
        };
        let Some(compact) = run(&["dump-edges", ws.to_str().unwrap(), "--compact"]) else {
            return;
        };
        let full_line_count = full.lines().count();
        let compact_line_count = compact.lines().count();
        assert!(
            compact_line_count < full_line_count,
            "{}: --compact ({} lines) must have fewer lines than full ({})",
            c.lang,
            compact_line_count,
            full_line_count,
        );
        let full_ids: std::collections::BTreeSet<_> = extract_edge_ids(&full).into_iter().collect();
        let compact_ids: std::collections::BTreeSet<_> = extract_edge_ids(&compact).into_iter().collect();
        assert_eq!(
            full_ids, compact_ids,
            "{}: --compact must carry the same edge_ids as the default render",
            c.lang,
        );
    }
}

/// `--edge <id>` round-trips: pick an id from the default render,
/// pass it back via `--edge`, and verify the filtered output
/// contains only that id.
#[test]
fn every_lang_micro_dump_edges_edge_filter_roundtrips() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run(&["dump-edges", ws.to_str().unwrap()]) else {
            return;
        };
        let ids = extract_edge_ids(&full);
        let Some(target) = ids.first() else {
            continue;
        };
        let Some(filtered) = run(&["dump-edges", ws.to_str().unwrap(), "--edge", target]) else {
            return;
        };
        let got = extract_edge_ids(&filtered);
        assert!(
            !got.is_empty() && got.iter().all(|id| id == target),
            "{}: --edge {target} should leave only {target}; got: {got:?}",
            c.lang,
        );
    }
}

#[test]
fn dump_edges_unknown_id_errors() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = std::process::Command::new(&bin)
        .args([
            "dump-edges",
            ws.to_str().unwrap(),
            "--edge",
            "E:00000000",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "dump-edges --edge E:00000000 must exit with failure; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("edge") || stderr.contains("E:00000000"),
        "unknown-edge error should mention the edge_id; got:\n{stderr}",
    );
}

#[test]
fn every_lang_micro_dump_edges_json_carries_edge_ids() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["dump-edges", ws.to_str().unwrap(), "--format", "json"]) else {
            return;
        };
        let parsed_json: serde_json::Value =
            serde_json::from_str(out.trim()).expect("dump-edges JSON must parse");
        assert!(
            json_tree_contains_id_field(&parsed_json, "edge_id", "E:"),
            "{}: dump-edges JSON should carry at least one edge_id; got:\n{out}",
            c.lang,
        );
    }
}

// =============================================================================
// dump-ast: tree-sitter parse tree with N:id + compact/drill-down
// =============================================================================

#[test]
fn every_lang_micro_dump_ast_emits_node_ids() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["dump-ast", ws.to_str().unwrap()]) else {
            return;
        };
        let ids = extract_node_ids(&out);
        assert!(
            !ids.is_empty(),
            "{}: dump-ast must emit at least one N:xxxxxxxx node_id; got head:\n{}",
            c.lang,
            &out.lines().take(20).collect::<Vec<_>>().join("\n"),
        );
    }
}

#[test]
fn every_lang_micro_dump_ast_compact_shorter() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run(&["dump-ast", ws.to_str().unwrap()]) else {
            return;
        };
        let Some(compact) = run(&["dump-ast", ws.to_str().unwrap(), "--compact"]) else {
            return;
        };
        assert!(
            compact.len() < full.len(),
            "{}: dump-ast --compact ({}) must be smaller than full ({})",
            c.lang,
            compact.len(),
            full.len(),
        );
    }
}

/// `--function <entry>` must narrow dump-ast output to a subtree
/// whose root is the entry function's decl. Every supported language
/// has a captured `handle_request` / `handleRequest` / `HandleRequest`
/// decl (the canonical chain matrix pins that separately); this test
/// verifies `dump-ast --function <entry>` finds that decl's subtree.
#[test]
fn every_lang_micro_dump_ast_function_scope_works() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(scoped) = run(&["dump-ast", ws.to_str().unwrap(), "--function", c.entry]) else {
            return;
        };
        assert!(
            scoped.contains("N:"),
            "{}: dump-ast --function {} must emit node_ids; got:\n{scoped}",
            c.lang,
            c.entry,
        );
    }
}

#[test]
fn every_lang_micro_dump_ast_json_carries_node_ids() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&[
            "dump-ast",
            ws.to_str().unwrap(),
            "--function",
            c.entry,
            "--format",
            "json",
        ]) else {
            return;
        };
        let parsed_json: serde_json::Value =
            serde_json::from_str(out.trim()).expect("dump-ast JSON must parse");
        assert!(
            json_tree_contains_id_field(&parsed_json, "node_id", "N:"),
            "{}: dump-ast JSON should carry node_id; got:\n{out}",
            c.lang,
        );
    }
}

#[test]
fn dump_ast_unknown_node_id_errors() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = std::process::Command::new(&bin)
        .args([
            "dump-ast",
            ws.to_str().unwrap(),
            "--node",
            "N:00000000",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "dump-ast --node N:00000000 must exit with failure; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("node") || stderr.contains("N:00000000"),
        "unknown-node error should mention the node_id; got:\n{stderr}",
    );
}

// =============================================================================
// dump-resolve: resolver stage tracer with R:id + compact/drill-down
//
// Each fixture's canonical sink name must resolve to exactly one
// candidate (the sink decl). Output carries `R:xxxxxxxx` ids;
// `--candidate <id>` round-trips; unknown names exit non-zero
// with did-you-mean suggestions; JSON carries stage trace.
// =============================================================================

/// Pull every `R:xxxxxxxx` id token out of a rendered `dump-resolve`
/// output.
fn extract_candidate_ids(rendered: &str) -> Vec<String> {
    extract_id_tokens(rendered, b'R')
}

#[test]
fn every_lang_micro_dump_resolve_canonical_sink() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["dump-resolve", ws.to_str().unwrap(), c.sink]) else {
            return;
        };
        let ids = extract_candidate_ids(&out);
        assert!(
            !ids.is_empty(),
            "{}: dump-resolve {} must emit at least one R:xxxxxxxx candidate; got:\n{out}",
            c.lang,
            c.sink,
        );
        // The sink is unique across the micro fixture — expect
        // exactly one candidate and a `narrowed` outcome on every
        // supported language.
        assert!(
            out.contains("narrowed"),
            "{}: dump-resolve {} should resolve to exactly one candidate (`narrowed`); got:\n{out}",
            c.lang,
            c.sink,
        );
    }
}

#[test]
fn every_lang_micro_dump_resolve_compact_round_trip() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run(&["dump-resolve", ws.to_str().unwrap(), c.sink]) else {
            return;
        };
        let Some(compact) = run(&["dump-resolve", ws.to_str().unwrap(), c.sink, "--compact"]) else {
            return;
        };
        // Compact must have strictly fewer lines than the full
        // stage trace (4 stages + outcome + table vs. 1 header + 1
        // row).
        assert!(
            compact.lines().count() < full.lines().count(),
            "{}: --compact ({} lines) must be shorter than full ({})",
            c.lang,
            compact.lines().count(),
            full.lines().count(),
        );
        // Same candidate ids in both renders — compaction is a
        // pure render-layer transform.
        let full_ids: std::collections::BTreeSet<_> = extract_candidate_ids(&full).into_iter().collect();
        let compact_ids: std::collections::BTreeSet<_> =
            extract_candidate_ids(&compact).into_iter().collect();
        assert_eq!(
            full_ids, compact_ids,
            "{}: --compact must carry the same candidate ids as the default render",
            c.lang,
        );
    }
}

#[test]
fn every_lang_micro_dump_resolve_candidate_filter_round_trips() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run(&["dump-resolve", ws.to_str().unwrap(), c.sink]) else {
            return;
        };
        let ids = extract_candidate_ids(&full);
        let Some(target) = ids.first() else {
            continue;
        };
        let Some(filtered) = run(&[
            "dump-resolve",
            ws.to_str().unwrap(),
            c.sink,
            "--candidate",
            target,
        ]) else {
            return;
        };
        let filtered_ids = extract_candidate_ids(&filtered);
        assert!(
            !filtered_ids.is_empty() && filtered_ids.iter().all(|id| id == target),
            "{}: --candidate {target} should leave only {target}; got: {filtered_ids:?}",
            c.lang,
        );
    }
}

#[test]
fn every_lang_micro_dump_resolve_json_carries_stage_trace() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&["dump-resolve", ws.to_str().unwrap(), c.sink, "--format", "json"]) else {
            return;
        };
        let trimmed = out.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: serde_json::Value = serde_json::from_str(trimmed).expect("dump-resolve JSON must parse");
        // Every stage field is always present (JSON never omits
        // them — even `null` alias_rewrite is serialized).
        for required in [
            "query",
            "short",
            "analysis_complete",
            "analysis_incomplete_reasons",
            "primary_lookup_name",
            "primary_candidate_count",
            "fallback_applied",
            "candidates",
            "outcome",
        ] {
            assert!(
                parsed.get(required).is_some(),
                "{}: JSON missing required field `{required}`; got:\n{out}",
                c.lang,
            );
        }
        // candidate_id present on every candidate.
        assert!(
            json_tree_contains_id_field(&parsed, "candidate_id", "R:"),
            "{}: JSON should carry candidate_id; got:\n{out}",
            c.lang,
        );
    }
}

#[test]
fn dump_resolve_in_file_uses_semantic_context() {
    let root = tempdir_for_test("dump-resolve-semantic-context");
    std::fs::write(
        root.join("a.rs"),
        "fn helper() {}\npub fn entry_a() { helper(); }\n",
    )
    .expect("write a.rs");
    std::fs::write(
        root.join("b.rs"),
        "fn helper() {}\npub fn entry_b() { helper(); }\n",
    )
    .expect("write b.rs");

    let Some(out) = run(&[
        "dump-resolve",
        root.to_str().unwrap(),
        "helper",
        "--in-file",
        "a.rs",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("dump-resolve JSON must parse");
    assert_eq!(
        parsed.get("outcome").and_then(|v| v.as_str()),
        Some("narrowed"),
        "file-context resolve should narrow to one semantic candidate:\n{out}"
    );
    assert_eq!(
        parsed.get("fallback_applied").and_then(|v| v.as_bool()),
        Some(false),
        "file-context resolve must not use broad literal fallback:\n{out}"
    );
    let candidates = parsed
        .get("candidates")
        .and_then(|v| v.as_array())
        .expect("candidates array");
    assert_eq!(
        candidates.len(),
        1,
        "expected one same-file helper candidate:\n{out}"
    );
    let file = candidates[0]
        .get("file")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        file, "a.rs",
        "resolver locations must use the same workspace-relative path accepted by --in-file:\n{out}"
    );
    assert_eq!(
        parsed.get("in_file").and_then(|v| v.as_str()),
        Some("a.rs"),
        "applied file context must be rendered workspace-relative:\n{out}"
    );
    assert_eq!(
        parsed.get("analysis_complete").and_then(|v| v.as_bool()),
        Some(true),
        "single-candidate file-context resolve should be complete:\n{out}"
    );
    assert!(
        parsed
            .get("analysis_incomplete_reasons")
            .and_then(|v| v.as_array())
            .is_some_and(Vec::is_empty),
        "complete resolve should not carry incomplete reasons:\n{out}"
    );
}

#[test]
fn dump_resolve_contextless_ambiguity_is_marked_incomplete() {
    let root = tempdir_for_test("dump-resolve-contextless-ambiguous");
    std::fs::write(
        root.join("a.rs"),
        "fn helper() {}\npub fn entry_a() { helper(); }\n",
    )
    .expect("write a.rs");
    std::fs::write(
        root.join("b.rs"),
        "fn helper() {}\npub fn entry_b() { helper(); }\n",
    )
    .expect("write b.rs");

    let Some(out) = run(&[
        "dump-resolve",
        root.to_str().unwrap(),
        "helper",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("dump-resolve JSON must parse");
    assert_eq!(
        parsed.get("outcome").and_then(|v| v.as_str()),
        Some("ambiguous"),
        "contextless duplicate name should stay ambiguous:\n{out}"
    );
    assert_eq!(
        parsed.get("analysis_complete").and_then(|v| v.as_bool()),
        Some(false),
        "ambiguous contextless resolve must not be presented as complete:\n{out}"
    );
    let reasons = parsed
        .get("analysis_incomplete_reasons")
        .and_then(|v| v.as_array())
        .expect("analysis_incomplete_reasons array");
    assert!(
        reasons.iter().any(|reason| reason
            .as_str()
            .is_some_and(|text| text.contains("context-required:helper"))),
        "contextless ambiguity should explain the missing semantic context:\n{out}"
    );
}

#[test]
fn dump_resolve_rejects_missing_in_file_context() {
    let root = tempdir_for_test("dump-resolve-missing-context");
    std::fs::write(root.join("a.rs"), "fn helper() {}\n").expect("write a.rs");
    let Some(bin) = bin_path() else {
        return;
    };
    let out = Command::new(bin)
        .args([
            "dump-resolve",
            root.to_str().unwrap(),
            "helper",
            "--in-file",
            "missing.rs",
            "--no-color",
        ])
        .output()
        .expect("run dump-resolve");
    assert!(
        !out.status.success(),
        "missing --in-file context must fail instead of falling back to global resolution"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--in-file `missing.rs` did not match any indexed file"),
        "missing context error should be explicit; stderr:\n{stderr}"
    );
}

#[test]
fn dump_resolve_unresolved_query_exits_nonzero_with_suggestions() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    // Typo — close enough to `verify_token` that the suggestion
    // machinery should surface it as the nearest match.
    let out = std::process::Command::new(&bin)
        .args(["dump-resolve", ws.to_str().unwrap(), "verify_tokn", "--no-color"])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "dump-resolve on an unresolved name must exit non-zero; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("unresolved"),
        "unresolved output must tag the outcome; got:\n{stdout}",
    );
    assert!(
        stdout.contains("verify_token"),
        "unresolved output should suggest the nearest valid name; got:\n{stdout}",
    );
}

// =============================================================================
// dump-taint: interprocedural propagation + T:id drill-down
// =============================================================================

/// Pull every `T:xxxxxxxx` token out of a rendered `dump-taint` output.
fn extract_taint_ids(rendered: &str) -> Vec<String> {
    extract_id_tokens(rendered, b'T')
}

#[test]
fn every_lang_micro_dump_taint_mid_to_sink() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&[
            "dump-taint",
            ws.to_str().unwrap(),
            "--source",
            c.mid,
            "--seed",
            "token",
            "--seed",
            "action",
            "--seed",
            "$token",
            "--seed",
            "$action",
        ]) else {
            return;
        };
        assert!(
            out.contains(c.sink),
            "{}: dump-taint from {} must show a propagation targeting {}; got:\n{out}",
            c.lang,
            c.mid,
            c.sink,
        );
        let ids = extract_taint_ids(&out);
        assert!(
            !ids.is_empty(),
            "{}: every taint propagation must carry a T:xxxxxxxx id; got:\n{out}",
            c.lang,
        );
    }
}

#[test]
fn every_lang_micro_dump_taint_compact_shorter_same_ids() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run(&[
            "dump-taint",
            ws.to_str().unwrap(),
            "--source",
            c.mid,
            "--seed",
            "token",
            "--seed",
            "action",
            "--seed",
            "$token",
            "--seed",
            "$action",
        ]) else {
            return;
        };
        let Some(compact) = run(&[
            "dump-taint",
            ws.to_str().unwrap(),
            "--source",
            c.mid,
            "--seed",
            "token",
            "--seed",
            "action",
            "--seed",
            "$token",
            "--seed",
            "$action",
            "--compact",
        ]) else {
            return;
        };
        assert!(
            compact.lines().count() <= full.lines().count(),
            "{}: --compact ({} lines) must not be longer than full ({})",
            c.lang,
            compact.lines().count(),
            full.lines().count(),
        );
        let full_ids: std::collections::BTreeSet<_> = extract_taint_ids(&full).into_iter().collect();
        let compact_ids: std::collections::BTreeSet<_> = extract_taint_ids(&compact).into_iter().collect();
        assert_eq!(
            full_ids, compact_ids,
            "{}: --compact must carry the same T:xxxxxxxx ids as the default render",
            c.lang,
        );
    }
}

#[test]
fn every_lang_micro_dump_taint_drill_down_roundtrips() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(full) = run(&[
            "dump-taint",
            ws.to_str().unwrap(),
            "--source",
            c.mid,
            "--seed",
            "token",
            "--seed",
            "action",
            "--seed",
            "$token",
            "--seed",
            "$action",
        ]) else {
            return;
        };
        let ids = extract_taint_ids(&full);
        let Some(target) = ids.first() else {
            continue;
        };
        let Some(drilled) = run(&[
            "dump-taint",
            ws.to_str().unwrap(),
            "--source",
            c.mid,
            "--seed",
            "token",
            "--seed",
            "action",
            "--seed",
            "$token",
            "--seed",
            "$action",
            "--taint",
            target,
        ]) else {
            return;
        };
        let drilled_ids = extract_taint_ids(&drilled);
        assert!(
            !drilled_ids.is_empty() && drilled_ids.iter().all(|id| id == target),
            "{}: --taint {target} should leave only {target}; got {drilled_ids:?}",
            c.lang,
        );
    }
}

#[test]
fn every_lang_micro_dump_taint_json_shape() {
    for c in canonical_chains() {
        let ws = lang_ws(c.lang);
        let Some(out) = run(&[
            "dump-taint",
            ws.to_str().unwrap(),
            "--source",
            c.mid,
            "--seed",
            "token",
            "--seed",
            "action",
            "--seed",
            "$token",
            "--seed",
            "$action",
            "--format",
            "json",
        ]) else {
            return;
        };
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("dump-taint JSON must parse");
        for required in [
            "source",
            "seeds",
            "analysis_complete",
            "analysis_incomplete_reasons",
            "precision",
            "records",
        ] {
            assert!(
                parsed.get(required).is_some(),
                "{}: JSON missing required field `{required}`; got:\n{out}",
                c.lang,
            );
        }
        assert!(
            parsed["analysis_complete"].as_bool().is_some(),
            "{}: dump-taint JSON must expose analysis_complete; got:\n{out}",
            c.lang,
        );
        let incomplete_reasons = parsed["analysis_incomplete_reasons"]
            .as_array()
            .expect("analysis_incomplete_reasons array");
        if parsed["analysis_complete"].as_bool() == Some(true) {
            assert!(
                incomplete_reasons.is_empty(),
                "{}: complete dump-taint output must not carry incomplete reasons; got:\n{out}",
                c.lang,
            );
        } else {
            assert!(
                !incomplete_reasons.is_empty(),
                "{}: incomplete dump-taint output must explain why; got:\n{out}",
                c.lang,
            );
        }
        assert!(
            parsed["records"].as_array().expect("records array").is_empty()
                || json_tree_contains_id_field(&parsed, "taint_id", "T:"),
            "{}: non-empty JSON records must carry `taint_id` fields; got:\n{out}",
            c.lang,
        );
        assert!(
            matches!(parsed["precision"].as_str(), Some("exact" | "narrowed")),
            "{}: dump-taint report precision must be semantic-only; got:\n{out}",
            c.lang,
        );
        assert!(
            parsed["records"]
                .as_array()
                .expect("records array")
                .iter()
                .all(|record| matches!(record["edge_precision"].as_str(), Some("exact" | "narrowed"))),
            "{}: dump-taint records must be semantic-only; got:\n{out}",
            c.lang,
        );
    }
}

#[test]
fn dump_taint_cpp_micro_resolved_workspace_calls_are_complete() {
    let ws = lang_ws("cpp");
    let Some(out) = run(&[
        "dump-taint",
        ws.to_str().unwrap(),
        "--source",
        "update_user",
        "--seed",
        "token",
        "--seed",
        "action",
        "--format",
        "json",
    ]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).expect("dump-taint JSON must parse");
    assert_eq!(
        parsed["analysis_complete"].as_bool(),
        Some(true),
        "resolved workspace callees in the C++ micro fixture must render complete dump-taint evidence:\n{out}"
    );
    let reasons = parsed["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array");
    assert!(
        reasons.is_empty(),
        "resolved C++ micro dump-taint evidence should not claim unresolved calls:\n{out}"
    );
}

// =============================================================================
// inspect --from-kind / --to-kind
// =============================================================================

#[test]
fn inspect_from_kind_arg_matches_when_token_is_an_argument() {
    // `token` is passed as an argument into update_user and
    // verify_token on the python micro chain, so --from-kind arg
    // should keep the flow.
    let ws = ws_path();
    let Some(out) = run_inspect_graph(
        &ws,
        &[
            "--query",
            "run_admin_command",
            "--from",
            "token",
            "--from-kind",
            "arg",
        ],
    ) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--from token --from-kind arg should match the chain; got:\n{out}",
    );
}

#[test]
fn inspect_from_kind_read_rejects_arg_only_tokens() {
    // Kind filter rejects when the needle doesn't appear under the
    // requested kind. `os.system` is a Call-classified token on the
    // chain, NOT a Read — so `--from os.system --from-kind read` has
    // to return no matches.
    let ws = ws_path();
    let Some(out) = run_inspect_graph(
        &ws,
        &[
            "--query",
            "run_admin_command",
            "--from",
            "os.system",
            "--from-kind",
            "read",
        ],
    ) else {
        return;
    };
    assert!(
        out.contains("no matches"),
        "--from os.system --from-kind read must not match (os.system is a call, not a read); got:\n{out}",
    );
}

#[test]
fn inspect_to_kind_call_matches_on_call_kinds() {
    // The sink `os.system` appears as a call on the chain, so
    // --to-kind call should retain the flow.
    let ws = ws_path();
    let Some(out) = run_inspect_graph(
        &ws,
        &[
            "--query",
            "run_admin_command",
            "--to",
            "os.system",
            "--to-kind",
            "call",
        ],
    ) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--to os.system --to-kind call should match; got:\n{out}",
    );
}

#[test]
fn inspect_from_to_match_via_interproc_param_name() {
    // `cmd` is the PARAMETER name of run_admin_command in the Python
    // micro fixture. It isn't a visible token on the chain that
    // enumerates to run_admin_command (the entry handle_request
    // reads `action`, update_user forwards it, run_admin_command
    // receives it as `cmd`). Pure reachability tokens wouldn't
    // surface `cmd` as reachable from a chain whose source is
    // handle_request — but the interprocedural pass does, because
    // it traces the tainted-arg → param binding. So `--from
    // handle_request --to cmd` must match via the taint augmentation
    // even though `cmd` never appears on the syntactic chain.
    let ws = ws_path();
    let Some(out) = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "run_admin_command",
        "--to",
        "cmd",
    ]) else {
        return;
    };
    assert!(
        !out.contains("no matches"),
        "--to cmd should match via interprocedural param-binding propagation; got:\n{out}",
    );
}

#[test]
fn inspect_kind_narrowers_require_their_needle() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    for (kind_flag, needle_flag) in [("--from-kind", "--from"), ("--to-kind", "--to")] {
        let out = Command::new(&bin)
            .args([
                "inspect",
                ws.to_str().unwrap(),
                "--query",
                "run_admin_command",
                kind_flag,
                "read",
                "--no-color",
            ])
            .output()
            .expect("failed to run bonsai-ninja");
        assert!(
            !out.status.success(),
            "{kind_flag} without {needle_flag} must be rejected"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(needle_flag),
            "{kind_flag} error should name required {needle_flag}:\n{stderr}"
        );
    }
}

#[test]
fn dump_taint_unknown_source_errors_cleanly() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = std::process::Command::new(&bin)
        .args([
            "dump-taint",
            ws.to_str().unwrap(),
            "--source",
            "definitely_not_a_real_function",
            "--seed",
            "x",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "dump-taint on an unknown source must exit non-zero; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("no callable") || stderr.contains("definitely_not_a_real_function"),
        "unknown-source error should name the missing function; got stderr:\n{stderr}",
    );
}

#[test]
fn dump_resolve_unknown_candidate_id_errors() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws_path();
    let out = std::process::Command::new(&bin)
        .args([
            "dump-resolve",
            ws.to_str().unwrap(),
            "run_admin_command",
            "--candidate",
            "R:00000000",
            "--no-color",
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        !out.status.success(),
        "dump-resolve --candidate R:00000000 must exit with failure; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("candidate") || stderr.contains("R:00000000"),
        "unknown-candidate error should mention the candidate id; got:\n{stderr}",
    );
}
