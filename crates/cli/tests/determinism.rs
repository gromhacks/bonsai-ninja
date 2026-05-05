//! Determinism guarantees across Rayon thread counts.
//!
//! Every parallelized command must produce **byte-identical output**
//! regardless of `RAYON_NUM_THREADS`, host CPU count, or worker
//! completion order. This file exercises that contract end-to-end:
//! it spawns the release binary twice — once with `RAYON_NUM_THREADS=1`,
//! once with `RAYON_NUM_THREADS=8` — and asserts the stdout streams
//! are identical.
//!
//! These tests are integration-level (they shell out to the binary)
//! because the only way to genuinely simulate "what users see on
//! different machines" is to drive the full CLI process the way a
//! user would, with the threading config that varies per machine.
//!
//! Tests are skipped when:
//! - the release binary doesn't exist (rare in CI; expected before
//!   the first `cargo build --release`),
//! - the test fixture workspace doesn't exist (the per-language
//!   conformance fixtures under `crates/workspace/tests/` ship with
//!   the repo, so this is rare).

use std::path::{Path, PathBuf};
use std::process::Command;

fn release_bin() -> Option<PathBuf> {
    // Walk up from CARGO_MANIFEST_DIR (= crates/cli) to the workspace
    // root, then look for target/release/bonsai-ninja.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent()?.parent()?;
    let bin = workspace_root.join("target/release/bonsai-ninja");
    if bin.exists() {
        Some(bin)
    } else {
        None
    }
}

fn fixture_workspace() -> Option<PathBuf> {
    // Use a checked-in multi-file Python fixture. Keep this small:
    // determinism is about byte-stable ordering, not stress-testing
    // a large real-world repository. Real-world command coverage is
    // exercised separately by the benchmark/audit scripts.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent()?.parent()?;
    let candidates = [
        workspace_root.join("examples/python/complex"),
        workspace_root.join("examples/python/micro"),
        workspace_root.join("examples/realworld/requests/src/requests"),
        workspace_root.join("crates/workspace/tests/fixtures/python"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn run_with_threads(bin: &Path, ws: &Path, args: &[&str], threads: usize) -> Vec<u8> {
    let mut cmd = Command::new(bin);
    cmd.env("RAYON_NUM_THREADS", threads.to_string())
        .env("NO_COLOR", "1") // strip ANSI so the diff isn't fooled by color resets
        .arg(args[0])
        .arg(ws)
        .args(&args[1..]);
    let out = cmd.output().expect("CLI process spawn failed");
    assert!(
        out.status.success() || out.status.code() == Some(2),
        "CLI exited with {:?} for args {:?}\nstderr:\n{}",
        out.status,
        args,
        String::from_utf8_lossy(&out.stderr),
    );
    out.stdout
}

fn assert_deterministic(args: &[&str]) {
    let Some(bin) = release_bin() else {
        eprintln!(
            "skipping {:?}: release binary not built (run `cargo build --release` first)",
            args
        );
        return;
    };
    let Some(ws) = fixture_workspace() else {
        eprintln!("skipping {:?}: no fixture workspace found", args);
        return;
    };
    let out_t1 = run_with_threads(&bin, &ws, args, 1);
    let out_t8 = run_with_threads(&bin, &ws, args, 8);
    assert_eq!(
        out_t1.len(),
        out_t8.len(),
        "stdout length differs across thread counts for {:?} (t1={} bytes, t8={} bytes)",
        args,
        out_t1.len(),
        out_t8.len(),
    );
    assert!(
        out_t1 == out_t8,
        "stdout content differs across thread counts for {:?}",
        args,
    );
}

// ---------------------------------------------------------------------------
// Browse commands — every parallelized one
// ---------------------------------------------------------------------------

#[test]
fn defs_deterministic_across_threads() {
    assert_deterministic(&["defs", "--format", "json"]);
}

#[test]
fn calls_deterministic_across_threads() {
    assert_deterministic(&["calls", "--format", "json"]);
}

#[test]
fn imports_deterministic_across_threads() {
    assert_deterministic(&["imports", "--format", "json"]);
}

#[test]
fn vars_deterministic_across_threads() {
    assert_deterministic(&["vars", "--format", "json"]);
}

#[test]
fn strings_deterministic_across_threads() {
    assert_deterministic(&["strings", "--format", "json"]);
}

#[test]
fn args_deterministic_across_threads() {
    assert_deterministic(&["args", "--format", "json"]);
}

#[test]
fn classes_deterministic_across_threads() {
    assert_deterministic(&["classes", "--format", "json"]);
}

#[test]
fn refs_deterministic_across_threads() {
    assert_deterministic(&["refs", "Session", "--format", "json"]);
}

#[test]
fn search_deterministic_across_threads() {
    assert_deterministic(&["search", "Session", "--format", "json"]);
}

// ---------------------------------------------------------------------------
// Dump commands — every parallelized one
// ---------------------------------------------------------------------------

#[test]
fn dump_callgraph_deterministic_across_threads() {
    assert_deterministic(&["dump-callgraph"]);
}

#[test]
fn dump_edges_deterministic_across_threads() {
    assert_deterministic(&["dump-edges", "--compact"]);
}

#[test]
fn dump_ast_deterministic_across_threads() {
    assert_deterministic(&["dump-ast", "--function", "get", "--compact"]);
}

// ---------------------------------------------------------------------------
// Flow analysis — the headline parallel command
// ---------------------------------------------------------------------------

#[test]
fn inspect_compact_deterministic_across_threads() {
    assert_deterministic(&["inspect", "--query", "request", "--compact"]);
}

#[test]
fn inspect_with_filters_deterministic_across_threads() {
    assert_deterministic(&["inspect", "--query", "request", "--from", "session", "--compact"]);
}

#[test]
fn inspect_grouped_view_deterministic_across_threads() {
    assert_deterministic(&["inspect", "--query", "request", "--view", "grouped", "--compact"]);
}
