//! Integration tests for the CLI's `inspect` command output shape.
//!
//! These invoke the compiled binary and assert on the text it produces so
//! that the terminology ("MATCH" not "SINK") and downstream-expansion
//! behavior don't regress.

use std::path::PathBuf;
use std::process::Command;

fn ws_path() -> PathBuf {
    // Tests run with the crate dir as CWD; the repo-root examples live two
    // levels up.
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../../examples/python/micro");
    p.canonicalize().expect("examples/python/micro not found")
}

fn bin_path() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../../target/release/bonsai-ninja");
    p
}

fn require_binary_built() -> Option<PathBuf> {
    let b = bin_path();
    if b.exists() {
        Some(b)
    } else {
        eprintln!(
            "skipping inspect integration test: release binary not built ({})",
            b.display()
        );
        None
    }
}

fn tempdir_for_test(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir();
    for attempt in 0..100 {
        let td = root.join(format!("{prefix}-{}-{nanos:x}-{attempt}", std::process::id()));
        match std::fs::create_dir(&td) {
            Ok(()) => return td,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create tempdir {}: {e}", td.display()),
        }
    }
    panic!("could not allocate tempdir for {prefix}");
}

fn run(args: &[&str]) -> String {
    let Some(bin) = require_binary_built() else {
        return String::new();
    };
    let out = Command::new(bin)
        .args(args)
        .arg("--no-color")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja exited with {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn inspect_uses_match_not_sink() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "run_admin_command"]);
    assert!(!out.contains("SINK"), "output still contains SINK: {out}");
    assert!(out.contains("MATCH"), "output missing MATCH annotation: {out}");
}

#[test]
fn inspect_fuzzy_substring_matches_decl() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "run_admin"]);
    assert!(
        out.contains("run_admin_command"),
        "expected fuzzy match to surface run_admin_command: {out}"
    );
}

#[test]
fn inspect_request_shows_downstream_chain() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "request"]);
    // The request match lives in handle_request, which is the root. Its
    // downstream should reach run_admin_command and os.system transitively.
    assert!(
        out.contains("run_admin_command"),
        "expected downstream to include run_admin_command: {out}"
    );
    assert!(
        out.contains("os.system"),
        "expected downstream to include os.system: {out}"
    );
}

#[test]
fn inspect_qualified_call_name_preserved() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "os.system"]);
    assert!(out.contains("os.system"), "qualified call name missing: {out}");
    // Should have a flow from root -> update_user -> run_admin_command.
    assert!(
        out.contains("run_admin_command"),
        "flow chain missing in output: {out}"
    );
}

#[test]
fn inspect_regex_flag_works() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "--regex", "^run_admin_.*"]);
    assert!(out.contains("run_admin_command"), "regex match missing: {out}");
}

#[test]
fn inspect_reports_hit_counts_by_kind() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "request"]);
    assert!(out.contains("by kind:"), "hit-kind summary missing: {out}");
}

#[test]
fn inspect_accepts_query_flag() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "--query", "run_admin"]);
    assert!(
        out.contains("run_admin_command"),
        "--query flag did not resolve fuzzy match: {out}"
    );
}

#[test]
fn inspect_symbol_flag_still_works_as_alias() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "--symbol", "run_admin"]);
    assert!(
        out.contains("run_admin_command"),
        "legacy --symbol alias broken: {out}"
    );
}

#[test]
fn inspect_kind_filter_restricts_output() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    // Filtering to calls-only should not surface the decl match block.
    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--kind",
        "call",
        "run_admin_command",
    ]);
    assert!(
        out.contains("by kind:") && out.contains("call="),
        "missing call-kind summary: {out}"
    );
    assert!(
        !out.contains("== run_admin_command (function)"),
        "decl block should not appear under --kind call: {out}"
    );
}

#[test]
fn inspect_call_hit_surfaces_full_upstream_chain() {
    // Regression: on a qualified call hit (`authService.runAdminCommand`
    // inside UserService.updateUser), the flow for the SINK call
    // `Runtime.getRuntime().exec` should trace all the way up to the
    // entry point `handleRequest`, not collapse to just the containing
    // function. This reproduces the Kotlin-micro regression where cross-
    // class method calls short-circuited the caller-map lookup.
    if require_binary_built().is_none() {
        return;
    }
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/kotlin/micro");
    let out = run(&["inspect", ws.to_str().unwrap(), "--query", "exec"]);
    assert!(
        out.contains("handleRequest → updateUser → runAdminCommand"),
        "expected full cross-class chain for exec hit, got:\n{out}"
    );
    assert!(
        out.contains("FLOW 1 SOURCE: entry handleRequest"),
        "expected SOURCE annotation at handleRequest, got:\n{out}"
    );
}

#[test]
fn inspect_flow_bodies_show_class_owner_context() {
    if require_binary_built().is_none() {
        return;
    }
    let Some(bin) = require_binary_built() else {
        return;
    };
    let td = tempdir_for_test("bonsai_owner_context_test");
    let src = "class Gateway {\n\
  void handle(String cmd) { sink(cmd); }\n\
  void sink(String cmd) { Runtime.getRuntime().exec(cmd); }\n\
}\n";
    std::fs::write(td.join("Gateway.java"), src).unwrap();
    let out = Command::new(bin)
        .args(["inspect", td.to_str().unwrap(), "--query", "exec", "--no-color"])
        .output()
        .expect("run bonsai-ninja");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[class] Gateway"),
        "flow render dropped class owner context:\n{stdout}"
    );
    assert!(
        stdout.contains("[def] handle(cmd)") || stdout.contains("[def] sink(cmd)"),
        "flow render dropped function header:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&td);
}

#[test]
fn inspect_flow_labels_use_letter_suffix_on_branch_split() {
    // A sink reached via two sibling paths should render as FLOW Na / Nb,
    // not two separate numeric flows.
    if require_binary_built().is_none() {
        return;
    }
    let Some(bin) = require_binary_built() else {
        return;
    };
    let td = tempdir_for_test("bonsai_flow_label_test");
    let src = "import os\n\
def sink(cmd):\n    os.system(cmd)\n\
def left(cmd):\n    sink(cmd)\n\
def right(cmd):\n    sink(cmd)\n\
def handle_request(cmd, path):\n    if path == '/l':\n        left(cmd)\n    else:\n        right(cmd)\n";
    std::fs::write(td.join("a.py"), src).unwrap();
    let out = Command::new(bin)
        .args(["inspect", td.to_str().unwrap(), "sink", "--no-color"])
        .output()
        .expect("run bonsai-ninja");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // At least one label should include a letter suffix (e.g. 1a / 1b).
    let has_letter_label = stdout
        .lines()
        .any(|l| l.contains("FLOW 1a") || l.contains("FLOW 2a"));
    assert!(
        has_letter_label,
        "expected letter-suffix flow label for sibling chain, got:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&td);
}
