//! Drift guard: name resolution is coherent across CLI surfaces.
//!
//! `docs/contributing/specification.mdx`: symbol resolution (`find_by_name` over `GlobalIndex`)
//! is the canonical mechanism. Every command that resolves a name —
//! `defs --name X`, `inspect --query X`, etc. — must agree on the
//! `(file, line)` set for that name. A drift here means a future
//! refactor lets one command see a function that another command
//! doesn't, which silently breaks cross-command workflows.
//!
//! The test runs over every language's `micro` fixture: lists
//! every function the adapter emits via `defs`, then for the first
//! function name asserts `inspect --query <name>` reports a
//! `decl_hits` entry at the same `(file, line)`.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const LANGS: &[&str] = &[
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
];

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    let p = repo_root().join("target/release/bonsai-ninja");
    p.exists().then_some(p)
}

fn run_json(args: &[&str]) -> Option<Value> {
    let bin = bin_path()?;
    let out = Command::new(&bin)
        .args(args)
        .args(["--no-color", "--no-progress"])
        .current_dir(repo_root())
        .output()
        .expect("spawn bonsai-ninja");
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    serde_json::from_str(&text).ok()
}

fn first_function(defs_rows: &[Value]) -> Option<(String, String, u64)> {
    for row in defs_rows {
        let kind = row.get("kind").and_then(Value::as_str)?;
        if !matches!(kind, "function" | "method") {
            continue;
        }
        let name = row.get("name").and_then(Value::as_str)?;
        let file = row.get("file").and_then(Value::as_str)?;
        let line = row.get("line").and_then(Value::as_u64)?;
        // Skip lambdas / generated names — `<lambda@…>` etc.
        // Inspect's --query intentionally won't find these by
        // synthetic name.
        if name.starts_with('<') {
            continue;
        }
        return Some((name.to_string(), file.to_string(), line));
    }
    None
}

#[test]
fn defs_and_inspect_agree_on_function_locations() {
    let Some(_) = bin_path() else {
        eprintln!("skipping name resolution drift test: release binary missing");
        return;
    };
    let mut langs_checked = 0;
    for lang in LANGS {
        let ws = repo_root().join("examples").join(lang).join("micro");
        if !ws.exists() {
            continue;
        }
        let ws_str = ws.to_str().unwrap();

        let Some(defs_json) = run_json(&["defs", ws_str, "--format", "json"]) else {
            continue;
        };
        let defs_rows = defs_json.as_array().cloned().unwrap_or_default();
        let Some((name, expected_file, expected_line)) = first_function(&defs_rows) else {
            // Adapter emits no plain functions in micro fixture
            // (rare; e.g. Solidity micro is method-only) — skip.
            continue;
        };

        let Some(inspect_json) = run_json(&["inspect", ws_str, "--query", &name, "--format", "json"]) else {
            panic!("[{lang}] inspect --query {name} returned non-zero exit / non-JSON output");
        };
        let decl_hits = inspect_json
            .get("decl_hits")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        // The exact (file, line) reported by `defs` must be in
        // `inspect`'s decl_hits for the same name. We don't
        // require set equality — inspect may surface additional
        // hits via subcalls / refs — but the canonical decl
        // location must be present.
        let matched = decl_hits.iter().any(|hit| {
            let file = hit.get("file").and_then(Value::as_str).unwrap_or("");
            let line = hit.get("line").and_then(Value::as_u64).unwrap_or(0);
            file == expected_file && line == expected_line
        });
        assert!(
            matched,
            "[{lang}] name `{name}` resolves to {expected_file}:{expected_line} via `defs` \
             but `inspect --query {name}` returned no decl_hit at that location.\n\
             decl_hits: {}",
            serde_json::to_string_pretty(&decl_hits).unwrap_or_default()
        );
        langs_checked += 1;
    }
    assert!(
        langs_checked >= 15,
        "expected to check ≥15 languages, only checked {langs_checked} — \
         either fixtures are missing or `defs` is broken across the board"
    );
}
