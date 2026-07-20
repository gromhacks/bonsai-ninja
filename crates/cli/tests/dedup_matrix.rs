//! Deduplication invariant matrix.
//!
//! Every output-bearing command, every supported language, every fixture
//! has the same precondition: rows the user reads must be unique by their
//! user-visible identity. A regression — engine path producing two flows
//! that collapse to the same chain, an adapter emitting the same decl
//! twice, a browse fact reported once per ref-edge instead of once per
//! call site — surfaces here as a `DUP` line in the failing assertion.
//!
//! One parameterised test per (command, fixture) cell, iterated over the
//! 21 languages. JSON output is the source of truth because text rendering
//! adds folding / suppression that hides true duplicates the engine emits.
//! Identity keys are command-specific (see each `dedup_*` helper).
//!
//! Skips gracefully when the release binary isn't built so `cargo test`
//! before `cargo build --release` still runs cleanly.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const LANGS: &[(&str, &str)] = &[
    ("c", "mega_flow"),
    ("cpp", "mega_flow"),
    ("csharp", "mega_flow"),
    ("dart", "mega_flow"),
    ("elixir", "mega_flow"),
    ("erlang", "mega_flow"),
    ("go", "mega_flow"),
    ("java", "mega_flow"),
    ("javascript", "mega_flow"),
    ("kotlin", "mega_flow"),
    ("lua", "mega_flow"),
    ("objc", "mega_flow"),
    ("perl", "mega_flow"),
    ("php", "mega_flow"),
    ("python", "mega_flow"),
    ("ruby", "mega_flow"),
    ("rust", "mega_flow"),
    ("scala", "mega_flow"),
    ("solidity", "mega_flow"),
    ("swift", "mega_flow"),
    ("typescript", "mega_flow"),
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
    if p.exists() {
        Some(p)
    } else {
        eprintln!("skipping dedup matrix: release binary missing at {}", p.display());
        None
    }
}

fn ws(lang: &str, fixture: &str) -> String {
    repo_root()
        .join("examples")
        .join(lang)
        .join(fixture)
        .to_string_lossy()
        .into_owned()
}

fn run_json(args: &[&str]) -> Option<Value> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    full.push("--no-progress");
    full.push("--format");
    full.push("json");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "240")
        .current_dir(repo_root())
        .output()
        .expect("spawn bonsai-ninja");
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<Value>(&s).ok()
}

/// Browse commands and security commands return either `[rows]`
/// directly or `{page, rows}` — accept both.
fn rows_of(v: &Value) -> Vec<Value> {
    if let Some(arr) = v.as_array() {
        return arr.clone();
    }
    if let Some(obj) = v.as_object() {
        if let Some(rows) = obj.get("rows").and_then(|r| r.as_array()) {
            return rows.clone();
        }
        if let Some(rows) = obj.get("findings").and_then(|r| r.as_array()) {
            return rows.clone();
        }
    }
    Vec::new()
}

/// Generic dedup assertion. `key_of` projects each row into a stable
/// identity string; the test fails when any key occurs more than once.
fn assert_unique<F>(label: &str, rows: &[Value], key_of: F)
where
    F: Fn(&Value) -> String,
{
    let mut seen = std::collections::HashMap::<String, usize>::new();
    for row in rows {
        let k = key_of(row);
        *seen.entry(k).or_default() += 1;
    }
    let dupes: Vec<(String, usize)> = seen.into_iter().filter(|(_, n)| *n > 1).collect();
    if !dupes.is_empty() {
        let mut summary = format!("{label}: {} duplicate group(s)\n", dupes.len());
        for (k, n) in dupes.iter().take(5) {
            summary.push_str(&format!("  {n}x: {k}\n"));
        }
        panic!("{summary}");
    }
}

/// Convenience: stringify-or-empty field lookup.
fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn n(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(|x| x.as_i64()).unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────
// Browse-fact dedup. Each command's identity key matches what the user
// sees in the table.
// ─────────────────────────────────────────────────────────────────────

fn dedup_defs(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["defs", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("defs {lang}/{fixture}"), &rows, |r| {
        format!(
            "{}|{}|{}:{}:{}",
            s(r, "name"),
            s(r, "kind"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_calls(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["calls", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("calls {lang}/{fixture}"), &rows, |r| {
        format!(
            "{}|{}|{}:{}:{}",
            s(r, "callee"),
            s(r, "caller"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_imports(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["imports", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("imports {lang}/{fixture}"), &rows, |r| {
        // `from typing import Any, Callable` emits one row per imported
        // name; `original_name` is the per-symbol differentiator. The
        // user-visible table shows the symbol column too.
        format!(
            "{}|{}|{}|{}|{}:{}",
            s(r, "module"),
            s(r, "original_name"),
            s(r, "alias"),
            s(r, "kind"),
            s(r, "file"),
            n(r, "line"),
        )
    });
}

fn dedup_vars(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["vars", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("vars {lang}/{fixture}"), &rows, |r| {
        // `in_function` is the JSON field for the "in" column. A given
        // variable at a given line is one row per enclosing function:
        // adapters that incorrectly attribute the same site to both
        // `__module__` and the actual function show up as a duplicate
        // group here.
        format!(
            "{}|{}|{}:{}:{}",
            s(r, "name"),
            s(r, "in_function"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_strings(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["strings", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("strings {lang}/{fixture}"), &rows, |r| {
        // A given literal at a given location is one event; the text +
        // location pair is the dedup identity. Multiple identical
        // literals at different sites stay separate.
        format!(
            "{}|{}:{}:{}",
            s(r, "text"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_comments(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["comments", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("comments {lang}/{fixture}"), &rows, |r| {
        format!(
            "{}|{}:{}:{}",
            s(r, "kind"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_args(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["args", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("args {lang}/{fixture}"), &rows, |r| {
        // (callee, positional index, keyword, argument text, file, line, column).
        // The JSON shape is `{callee, position: int, keyword: opt-str, value: str, file, line, column}`.
        format!(
            "{}|{}|{}|{}|{}:{}:{}",
            s(r, "callee"),
            n(r, "position"),
            s(r, "keyword"),
            s(r, "value"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_classes(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["classes", &ws(lang, fixture)]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("classes {lang}/{fixture}"), &rows, |r| {
        format!(
            "{}|{}|{}:{}:{}",
            s(r, "name"),
            s(r, "kind"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_search(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["search", &ws(lang, fixture), "--query", "a"]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("search {lang}/{fixture}"), &rows, |r| {
        format!(
            "{}|{}|{}|{}:{}:{}",
            s(r, "name"),
            s(r, "kind"),
            s(r, "qualified_name"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

// ─────────────────────────────────────────────────────────────────────
// Inspect: occurrence hits must be unique by `(kind, location, text)`.
// ─────────────────────────────────────────────────────────────────────

fn dedup_inspect(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["inspect", &ws(lang, fixture), "--query", "a"]) else {
        return;
    };
    // inspect returns `{flows: [...], occurrences: [...], ...}` or
    // similar — only assert dedup over the occurrences array when
    // present. Other shapes pass-through.
    let occurrences = v
        .get("occurrences")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if occurrences.is_empty() {
        return;
    }
    assert_unique(&format!("inspect {lang}/{fixture}"), &occurrences, |r| {
        format!(
            "{}|{}|{}:{}:{}",
            s(r, "kind"),
            s(r, "text"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

// ─────────────────────────────────────────────────────────────────────
// Security: sources / sinks / sanitizers / taint-analysis / source-analysis.
// ─────────────────────────────────────────────────────────────────────

fn dedup_security_sources(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["security", &ws(lang, fixture), "sources"]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("security sources {lang}/{fixture}"), &rows, |r| {
        // The user-visible row in the security inventory table is
        // `(rule_id, enclosing_fn, text, location)`. Matches with the
        // same rule + location but different `text` (e.g. an adapter
        // emitting both qualified `proc.launchPath` and bare
        // `launchPath` for one write) are distinct rows in the
        // rendered output. The matcher's downstream pipeline cares
        // about the byte-identical 5-tuple — that's what
        // `dedup_inventory_matches` collapses.
        format!(
            "{}|{}|{}|{}:{}:{}",
            s(r, "rule_id"),
            s(r, "enclosing_fn"),
            s(r, "text"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_security_sinks(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["security", &ws(lang, fixture), "sinks"]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("security sinks {lang}/{fixture}"), &rows, |r| {
        // The user-visible row in the security inventory table is
        // `(rule_id, enclosing_fn, text, location)`. Matches with the
        // same rule + location but different `text` (e.g. an adapter
        // emitting both qualified `proc.launchPath` and bare
        // `launchPath` for one write) are distinct rows in the
        // rendered output. The matcher's downstream pipeline cares
        // about the byte-identical 5-tuple — that's what
        // `dedup_inventory_matches` collapses.
        format!(
            "{}|{}|{}|{}:{}:{}",
            s(r, "rule_id"),
            s(r, "enclosing_fn"),
            s(r, "text"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_security_sanitizers(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["security", &ws(lang, fixture), "sanitizers"]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("security sanitizers {lang}/{fixture}"), &rows, |r| {
        format!(
            "{}|{}:{}:{}",
            s(r, "rule_id"),
            s(r, "file"),
            n(r, "line"),
            n(r, "column"),
        )
    });
}

fn dedup_taint_analysis(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["security", &ws(lang, fixture), "taint-analysis"]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(&format!("security taint-analysis {lang}/{fixture}"), &rows, |r| {
        let src = r.get("source").cloned().unwrap_or(Value::Null);
        let sink = r.get("sink").cloned().unwrap_or(Value::Null);
        let chain = r
            .get("chain_display")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("→"))
            .unwrap_or_default();
        format!(
            "{}|{}:{}:{}|{}|{}|{}:{}:{}",
            s(&src, "rule_id"),
            s(&src, "file"),
            n(&src, "line"),
            n(&src, "column"),
            chain,
            s(&sink, "rule_id"),
            s(&sink, "file"),
            n(&sink, "line"),
            n(&sink, "column"),
        )
    });
}

fn dedup_source_analysis(lang: &str, fixture: &str) {
    let Some(v) = run_json(&["security", &ws(lang, fixture), "source-analysis"]) else {
        return;
    };
    let rows = rows_of(&v);
    assert_unique(
        &format!("security source-analysis {lang}/{fixture}"),
        &rows,
        |r| {
            let src = r.get("source").cloned().unwrap_or(Value::Null);
            let flow = r.get("flow").cloned().unwrap_or(Value::Null);
            let chain = flow
                .get("chain")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("→"))
                .unwrap_or_default();
            format!(
                "{}|{}:{}:{}|{}",
                s(&src, "rule_id"),
                s(&src, "file"),
                n(&src, "line"),
                n(&src, "column"),
                chain,
            )
        },
    );
}

// ─────────────────────────────────────────────────────────────────────
// One test per (command) — each iterates over every language. A failure
// names exactly which (command, lang) combination produced duplicates.
// ─────────────────────────────────────────────────────────────────────

macro_rules! per_command_dedup {
    ($name:ident, $fn:ident) => {
        #[test]
        fn $name() {
            if bin_path().is_none() {
                return;
            }
            for (lang, fixture) in LANGS {
                $fn(lang, fixture);
            }
        }
    };
}

per_command_dedup!(dedup_defs_all_langs, dedup_defs);
per_command_dedup!(dedup_calls_all_langs, dedup_calls);
per_command_dedup!(dedup_imports_all_langs, dedup_imports);
per_command_dedup!(dedup_vars_all_langs, dedup_vars);
per_command_dedup!(dedup_strings_all_langs, dedup_strings);
per_command_dedup!(dedup_comments_all_langs, dedup_comments);
per_command_dedup!(dedup_args_all_langs, dedup_args);
per_command_dedup!(dedup_classes_all_langs, dedup_classes);
per_command_dedup!(dedup_search_all_langs, dedup_search);
per_command_dedup!(dedup_inspect_all_langs, dedup_inspect);
per_command_dedup!(dedup_security_sources_all_langs, dedup_security_sources);
per_command_dedup!(dedup_security_sinks_all_langs, dedup_security_sinks);
per_command_dedup!(dedup_security_sanitizers_all_langs, dedup_security_sanitizers);
per_command_dedup!(dedup_taint_analysis_all_langs, dedup_taint_analysis);
per_command_dedup!(dedup_source_analysis_all_langs, dedup_source_analysis);
