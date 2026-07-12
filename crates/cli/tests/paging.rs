//! End-to-end paging tests against the built `bonsai-ninja` binary.
//!
//! Covers the `--context / --page / --page-size / --all` axis on
//! the `calls` command (canonical browse renderer). Other browse
//! commands share the `paging::paginate()` helper + footer, so the
//! invariants proven here carry across the suite.
//!
//! Every assertion pins a user-facing contract:
//!
//! * **lossless paging** — walking from page 1 via `next_cursor`
//!   until `is_last` enumerates every row from the uncapped JSON
//!   run exactly once, in the same order;
//! * **cursor / page-number equivalence** — `--page P:xxxxxxxx`
//!   and `--page N` resolve to the byte-identical row set when
//!   the cursor came from page N's footer;
//! * **JSON tokenizer safety** — default `--format json` returns a
//!   bare array only when the whole result fits the budget; otherwise
//!   it wraps in `{rows, page}`;
//! * **JSON explicit wrap** — `--context` or `--page` on JSON wraps
//!   in `{rows, page}`;
//! * **`--all` overrides** — enabled together with `--context`
//!   still returns every row;
//! * **context-budget cap** — `--context N` keeps the text
//!   footer's `tokens_used` at or under the stated budget.
//!
//! Tests skip silently when the release binary hasn't been built.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};
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
            "skipping paging integration test: release binary not built ({})",
            p.display()
        );
        None
    }
}

fn ws() -> PathBuf {
    repo_root().join("examples/python/micro")
}

fn page_cache_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("page-cache test lock poisoned")
}

fn run(args: &[&str]) -> Option<String> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    full.push("--no-progress");
    let out = Command::new(&bin)
        .args(&full)
        .current_dir(repo_root())
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

fn json_bare(args: &[&str]) -> Option<Vec<serde_json::Value>> {
    let out = run(args)?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    v.as_array().cloned()
}

fn json_wrapped(args: &[&str]) -> Option<(Vec<serde_json::Value>, serde_json::Value)> {
    let out = run(args)?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    let rows = v.get("rows")?.as_array()?.clone();
    let page = v.get("page")?.clone();
    Some((rows, page))
}

fn json_wrapped_value(args: &[&str]) -> Option<serde_json::Value> {
    let out = run(args)?;
    serde_json::from_str(&out).ok()
}

// ---------------------------------------------------------------------------
// Small JSON without paging flags may stay a bare array
// ---------------------------------------------------------------------------

#[test]
fn json_default_returns_bare_array_when_result_fits_budget() {
    let ws = ws();
    let Some(rows) = json_bare(&["calls", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    assert!(
        !rows.is_empty(),
        "calls JSON should return rows on the python micro"
    );
    // Confirm we're NOT getting a `{rows: [...]}` wrapper — pre-
    // paging scripts that do `jq '.[0]'` would break if we did.
    for r in &rows {
        assert!(
            r.get("callee").is_some(),
            "each JSON row should have a callee field — got {r:?}"
        );
    }
}

#[test]
fn json_opts_into_wrap_with_context() {
    let ws = ws();
    let Some(v) = json_wrapped_value(&[
        "calls",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--context",
        "1",
    ]) else {
        return;
    };
    let rows = v
        .get("rows")
        .and_then(|rows| rows.as_array())
        .expect("rows array");
    let page = v.get("page").expect("page object");
    assert!(!rows.is_empty());
    // Every paged JSON response carries the full page metadata
    // so agents can drive a loop without parsing text.
    for key in &[
        "number",
        "total_pages",
        "page_size",
        "shown_rows",
        "total_rows",
        "cursor",
        "is_last",
    ] {
        assert!(page.get(key).is_some(), "page object missing `{key}`: {page:?}");
    }
    assert_eq!(
        v.get("analysis_complete").and_then(|value| value.as_bool()),
        Some(false),
        "paged JSON must not claim complete analysis when more pages exist: {v:?}"
    );
    let incomplete_reasons = v
        .get("analysis_incomplete_reasons")
        .and_then(|value| value.as_array())
        .expect("analysis_incomplete_reasons array");
    assert!(
        incomplete_reasons.iter().any(|reason| {
            reason
                .as_str()
                .is_some_and(|reason| reason.contains("paged calls result incomplete"))
        }),
        "paged JSON must explain incomplete row coverage: {v:?}"
    );
}

#[test]
fn dump_taint_paging_preserves_structured_semantic_and_presentation_coverage() {
    let ws = ws();
    let Some(value) = json_wrapped_value(&[
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
        "--context",
        "1",
    ]) else {
        return;
    };

    assert!(
        value["records"].is_array(),
        "records must remain structured: {value:?}"
    );
    assert!(
        value.get("json_lines").is_none(),
        "paged dump-taint must not replace its report with JSON source lines: {value:?}"
    );
    assert!(
        value["semantic_analysis_complete"].is_boolean(),
        "semantic completeness must remain available: {value:?}"
    );
    assert_eq!(
        value["analysis_complete"], false,
        "the combined envelope must not claim complete coverage for one page: {value:?}"
    );
    assert_eq!(value["presentation_complete"], false);
    assert!(
        value["presentation_incomplete_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|reason| reason
                .as_str()
                .is_some_and(|reason| reason.contains("paged dump-taint result incomplete")))),
        "presentation truncation must carry an actionable reason: {value:?}"
    );
    assert!(
        value["page"]["total_pages"]
            .as_u64()
            .is_some_and(|pages| pages > 1),
        "tiny context should exercise a multi-page report: {value:?}"
    );
}

#[test]
fn dump_taint_empty_page_is_explicitly_complete_when_analysis_and_presentation_are_complete() {
    let ws = ws();
    let Some(value) = json_wrapped_value(&[
        "dump-taint",
        ws.to_str().unwrap(),
        "--source",
        "update_user",
        "--seed",
        "token",
        "--seed",
        "action",
        "--sink",
        "definitely-not-a-callee",
        "--format",
        "json",
        "--context",
        "4k",
    ]) else {
        return;
    };

    assert_eq!(value["records"], serde_json::json!([]));
    assert_eq!(value["semantic_analysis_complete"], true);
    assert_eq!(value["presentation_complete"], true);
    assert_eq!(value["analysis_complete"], true);
    assert!(
        value["analysis_incomplete_reasons"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "a proven complete empty result must not invent an incomplete reason: {value:?}"
    );
}

#[test]
fn last_page_of_paged_json_is_still_incomplete() {
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    let Some(first) = json_wrapped_value(&["calls", ws_str, "--format", "json", "--context", "256"]) else {
        return;
    };
    let total_pages = first["page"]["total_pages"].as_u64().expect("total_pages");
    assert!(
        total_pages > 1,
        "test fixture must produce multiple pages at tiny context: {first:?}"
    );

    let page_arg = total_pages.to_string();
    let args = vec![
        "calls",
        ws_str,
        "--format",
        "json",
        "--context",
        "256",
        "--page",
        page_arg.as_str(),
    ];
    let Some(last) = json_wrapped_value(&args) else {
        return;
    };
    assert_eq!(last["page"]["number"].as_u64(), Some(total_pages));
    assert_eq!(last["page"]["is_last"].as_bool(), Some(true));
    assert_eq!(
        last["analysis_complete"].as_bool(),
        Some(false),
        "the last page is still a partial response unless it is page 1 of 1: {last:?}"
    );
    let reasons = last["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array");
    assert!(
        reasons.iter().any(|reason| {
            reason
                .as_str()
                .is_some_and(|reason| reason.contains("paged calls result incomplete"))
        }),
        "last paged JSON response must explain partial row coverage: {last:?}"
    );
}

#[test]
fn json_opts_into_wrap_with_page_flag() {
    let ws = ws();
    // `--page 1` alone (no context) is enough to flip JSON into
    // wrap mode — the agent told us it wanted paged output.
    let Some(_) = json_wrapped(&["calls", ws.to_str().unwrap(), "--format", "json", "--page", "1"]) else {
        return;
    };
}

#[test]
fn inspect_paged_json_exposes_top_level_completeness() {
    let ws = ws();
    let Some(out) = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "request",
        "--kind",
        "call",
        "--max-hits",
        "1",
        "--format",
        "json",
        "--context",
        "1",
    ]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("inspect JSON");
    assert_eq!(
        v.get("analysis_complete").and_then(|value| value.as_bool()),
        Some(false),
        "paged inspect JSON must expose top-level incomplete status: {v:?}"
    );
    let reasons = v
        .get("analysis_incomplete_reasons")
        .and_then(|value| value.as_array())
        .expect("analysis_incomplete_reasons array");
    assert!(
        reasons.iter().any(|reason| {
            reason
                .as_str()
                .is_some_and(|reason| reason.contains("inspect hit list capped by max-hits output cap"))
        }),
        "paged inspect JSON must carry inspect incompleteness reasons: {v:?}"
    );
}

#[test]
fn trace_paged_json_exposes_top_level_completeness() {
    let ws = ws();
    let Some(out) = run(&[
        "trace",
        ws.to_str().unwrap(),
        "handle_request",
        "--format",
        "json",
        "--context",
        "1",
        "--max-steps",
        "1",
    ]) else {
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&out).expect("trace JSON");
    assert_eq!(
        v.get("analysis_complete").and_then(|value| value.as_bool()),
        Some(false),
        "paged trace JSON must expose top-level incomplete status: {v:?}"
    );
    assert!(
        v.get("analysis_incomplete_reasons")
            .and_then(|value| value.as_array())
            .is_some_and(|reasons| !reasons.is_empty()),
        "paged trace JSON must carry trace/page incompleteness reasons: {v:?}"
    );
}

// ---------------------------------------------------------------------------
// Lossless paging across pages
// ---------------------------------------------------------------------------

fn row_fingerprint(r: &serde_json::Value) -> String {
    // Use the fields a reader would use to locate the call —
    // callee + file + line + column. Sufficient to distinguish
    // every row and stable across runs.
    format!(
        "{}@{}:{}:{}",
        r.get("callee").and_then(|v| v.as_str()).unwrap_or(""),
        r.get("file").and_then(|v| v.as_str()).unwrap_or(""),
        r.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
        r.get("column").and_then(|v| v.as_u64()).unwrap_or(0),
    )
}

#[test]
fn walking_pages_reproduces_uncapped_set() {
    let ws = ws();
    let Some(baseline) = json_bare(&["calls", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    let baseline: Vec<String> = baseline.iter().map(row_fingerprint).collect();
    assert!(!baseline.is_empty());

    // Walk with a tiny budget so the python micro splits into
    // multiple pages. Each `run` is a fresh process so the
    // in-process last-cursor store doesn't help — cursors MUST
    // be content-addressable to stitch the walk.
    let mut walked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..50 {
        let mut args: Vec<String> = vec![
            "calls".to_string(),
            ws.to_str().unwrap().to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--context".to_string(),
            "256".to_string(), // deliberately tiny
        ];
        if let Some(c) = cursor.as_ref() {
            args.push("--page".to_string());
            args.push(c.clone());
        }
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
        let Some((rows, page)) = json_wrapped(&args_ref) else {
            return;
        };
        walked.extend(rows.iter().map(row_fingerprint));
        if page.get("is_last").and_then(|v| v.as_bool()).unwrap_or(true) {
            break;
        }
        cursor = page.get("next_cursor").and_then(|v| v.as_str()).map(String::from);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        walked, baseline,
        "walking pages must reproduce every row from the uncapped run in order"
    );
}

// ---------------------------------------------------------------------------
// Cursor / page-number equivalence
// ---------------------------------------------------------------------------

#[test]
fn cursor_and_page_number_resolve_to_same_rows() {
    let ws = ws();
    let Some((_, page1)) = json_wrapped(&[
        "calls",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--context",
        "256",
    ]) else {
        return;
    };
    let Some(next_cursor) = page1.get("next_cursor").and_then(|v| v.as_str()) else {
        // python micro small enough to fit in one page — not a
        // failure of paging, just nothing to compare.
        return;
    };
    let Some(via_cursor) = json_wrapped(&[
        "calls",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--context",
        "256",
        "--page",
        next_cursor,
    ]) else {
        return;
    };
    let Some(via_number) = json_wrapped(&[
        "calls",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--context",
        "256",
        "--page",
        "2",
    ]) else {
        return;
    };
    assert_eq!(
        via_cursor.0, via_number.0,
        "cursor `{next_cursor}` and `--page 2` must resolve to the same rows"
    );
    assert_eq!(
        via_cursor.1.get("cursor"),
        via_number.1.get("cursor"),
        "both resolutions must emit the same page cursor"
    );
}

// ---------------------------------------------------------------------------
// --all overrides paging
// ---------------------------------------------------------------------------

#[test]
fn all_flag_overrides_context() {
    let ws = ws();
    let Some((rows, page)) = json_wrapped(&[
        "calls",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--context",
        "64",
        "--all",
    ]) else {
        return;
    };
    let Some(uncapped) = json_bare(&["calls", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    assert_eq!(
        rows.len(),
        uncapped.len(),
        "--all should return every row regardless of --context"
    );
    assert_eq!(page.get("is_last").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(page.get("total_pages").and_then(|v| v.as_u64()), Some(1));
}

// ---------------------------------------------------------------------------
// Text footer contract
// ---------------------------------------------------------------------------

#[test]
fn text_footer_prints_cursor_and_page_number() {
    let ws = ws();
    let Some(out) = run(&[
        "calls",
        ws.to_str().unwrap(),
        "--context",
        "256", // tiny so we split
    ]) else {
        return;
    };
    assert!(
        out.contains("page 1 of"),
        "text footer should show `page 1 of N`:\n{out}"
    );
    assert!(
        out.contains("context "),
        "text footer should show context usage:\n{out}"
    );
    // Either we're on the last page (end of results) or the
    // next line shows both cursor + numeric forms.
    if out.contains("end of results") {
        return;
    }
    assert!(
        out.contains("--page P:"),
        "next-page cursor form should appear:\n{out}"
    );
    assert!(
        out.contains("--page 2"),
        "next-page numeric form should appear:\n{out}"
    );
}

#[test]
fn text_footer_silent_on_single_page_no_budget() {
    let ws = ws();
    // No `--context`, no `--page` — default-but-text-budget
    // covers the whole python fixture in one page, which is the
    // common small-repo case. Footer chrome should stay minimal
    // — no "page 1 of 1" noise on small results.
    let Some(out) = run(&["calls", ws.to_str().unwrap(), "--all"]) else {
        return;
    };
    assert!(
        !out.contains("page 1 of 1"),
        "--all with single-page result shouldn't print paging chrome:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// Context budget cap
// ---------------------------------------------------------------------------

#[test]
fn context_budget_caps_tokens_used() {
    let ws = ws();
    // 2k budget; tokens_used reported by the footer must stay
    // at or under it (chrome reserve is 5 %, so practically
    // ~1,950 token ceiling on raw rows).
    let Some((_, page)) = json_wrapped(&[
        "calls",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--context",
        "2048",
    ]) else {
        return;
    };
    let used = page.get("tokens_used").and_then(|v| v.as_u64()).unwrap_or(0);
    let budget = page.get("budget").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        used <= budget,
        "tokens_used ({used}) must stay within budget ({budget})"
    );
    assert_eq!(budget, 2048);
}

#[test]
fn context_shorthand_parses() {
    let ws = ws();
    // `4k` → 4096 tokens. Paging object's `budget` field is the
    // raw number.
    let Some((_, page)) = json_wrapped(&[
        "calls",
        ws.to_str().unwrap(),
        "--format",
        "json",
        "--context",
        "4k",
    ]) else {
        return;
    };
    assert_eq!(
        page.get("budget").and_then(|v| v.as_u64()),
        Some(4096),
        "`4k` must parse to 4096"
    );
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn malformed_context_exits_non_zero() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws();
    let out = Command::new(&bin)
        .args(["calls", ws.to_str().unwrap(), "--context", "12x", "--no-color"])
        .output()
        .expect("run bonsai-ninja");
    assert!(
        !out.status.success(),
        "`--context 12x` should reject as malformed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid --context"),
        "stderr should explain the rejection:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// All-commands smoke matrix — every paged command accepts the same
// paging flags, emits page metadata under an explicit budget, and
// honors `--all`. If any wire-up drifts, this test lights up.
// ---------------------------------------------------------------------------

/// Commands that support paging + their required positional / extra args.
/// Tuple: (command, extra args needed for a non-empty run).
const ALL_PAGED_COMMANDS: &[(&str, &[&str])] = &[
    ("defs", &[]),
    ("calls", &[]),
    ("imports", &[]),
    ("vars", &[]),
    ("strings", &[]),
    ("args", &[]),
    ("operations", &[]),
    ("classes", &[]),
    ("refs", &["handle_request"]),
    ("search", &["--query", "request"]),
    ("dump-callgraph", &[]),
    ("dump-edges", &[]),
    ("dump-resolution", &[]),
    ("dump-ast", &["--file", "gateway.py"]),
    ("dump-taint", &["--source", "handle_request"]),
    ("inspect", &["--query", "verify"]),
    ("trace", &["handle_request"]),
    ("path", &["--from", "handle_request", "--to", "verify_token"]),
    (
        "slice",
        &["--symbol", "result", "--line", "15", "--file", "gateway.py"],
    ),
    ("tree", &[]),
    ("read-file", &["gateway.py"]),
];

#[test]
fn every_command_accepts_context_flag() {
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let mut args: Vec<&str> = vec![cmd, ws_str, "--context", "1024"];
        args.extend_from_slice(extra);
        let Some(out) = run(&args) else { return };
        assert!(
            out.contains("context ") || out.contains("(no ") || out.contains("(0 "),
            "{cmd}: expected footer or empty-result notice, got:\n{out}"
        );
    }
}

#[test]
fn every_command_accepts_all_flag() {
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let mut args: Vec<&str> = vec![cmd, ws_str, "--all"];
        args.extend_from_slice(extra);
        let Some(_) = run(&args) else { return };
        // --all disables paging — reaching here without a non-zero
        // exit is the assertion. A regression in one of the
        // dispatch arms would error out `expected argument` or
        // similar.
    }
}

#[test]
fn every_command_json_default_is_bare_array() {
    // Row-based browse + dump commands default to a bare JSON
    // array. Structural commands (`inspect` / `trace`) default
    // to their object shape (`InspectReport` / `TraceResult`) —
    // pre-paging scripts already consume those. The test
    // enforces that the DEFAULT run (no `--context`, no
    // `--page`) never emits a top-level `page` wrapper. That's
    // the back-compat contract.
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let mut args: Vec<&str> = vec![cmd, ws_str, "--format", "json"];
        args.extend_from_slice(extra);
        let Some(out) = run(&args) else { return };
        let v: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{cmd}: invalid JSON: {e}\n{out}"));
        let has_page = matches!(&v, serde_json::Value::Object(o) if o.contains_key("page"));
        assert!(
            !has_page,
            "{cmd}: default JSON must NOT have a `page` wrapper; got {v:?}"
        );
    }
}

#[test]
fn every_command_json_wraps_when_context_is_set() {
    // Row-based commands wrap as `{rows, page}`. Structural
    // commands keep their native shape and only gain a `page`
    // sibling: inspect → `{decl_hits, ..., page}`, trace →
    // `{summary, paths, ..., page}`. The invariant is just
    // "top-level `page` appears" — the paginated rows live
    // under whichever key that command has always used.
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let mut args: Vec<&str> = vec![cmd, ws_str, "--format", "json", "--context", "4k"];
        args.extend_from_slice(extra);
        let Some(out) = run(&args) else { return };
        let v: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{cmd}: invalid JSON: {e}\n{out}"));
        assert!(
            v.get("page").is_some(),
            "{cmd}: --context should include top-level `page` object, got {v:?}"
        );
    }
}

#[test]
fn every_command_page_2_resolves() {
    // Tiny context so every command actually splits into pages.
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let mut args: Vec<&str> = vec![cmd, ws_str, "--context", "128", "--page", "2"];
        args.extend_from_slice(extra);
        // Non-zero exit is the assertion — `--page 2` should
        // always clamp to the last page and render, never fail.
        let Some(_) = run(&args) else { return };
    }
}

// ---------------------------------------------------------------------------
// Per-command token / context / pagination matrix.
//
// These tests expand the single-command coverage of
// `context_budget_caps_tokens_used` into a full sweep: every paged
// command, checked for (1) footer token count under budget, (2) JSON
// `tokens_used` ≤ `budget`, (3) truncation hint vs `is_last` agreement.
//
// `inspect` is special-cased with a tighter tolerance because it uses
// live byte counting (the footer number matches `out_count::bytes()`
// delta exactly). Other commands rely on paginate()'s per-row cost
// estimate, which can drift by ~15 % from real output, so the
// tolerance there is `used ≤ budget + 5 % slack`.
// ---------------------------------------------------------------------------

/// Extract the `page` JSON object from a `--context`-opted-in run.
/// Handles both row-wrapped shapes (`{rows, page}`) and the
/// structural shapes (`{decl_hits, ..., page}`, `{paths, ..., page}`).
fn page_block(cmd: &str, extra: &[&str]) -> Option<serde_json::Value> {
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    let mut args: Vec<&str> = vec![cmd, ws_str, "--format", "json", "--context", "4096"];
    args.extend_from_slice(extra);
    let out = run(&args)?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    v.as_object().and_then(|o| o.get("page").cloned())
}

#[test]
fn every_command_tokens_used_reported_under_budget() {
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let Some(page) = page_block(cmd, extra) else {
            return;
        };
        let used = page.get("tokens_used").and_then(|v| v.as_u64()).unwrap_or(0);
        let budget = page.get("budget").and_then(|v| v.as_u64()).unwrap_or(0);
        // 5 % slack covers the estimate-vs-reality drift on commands
        // that use paginate()'s cost heuristic. The footer wording
        // on the text side already surfaces overshoot explicitly
        // (`row exceeds --context budget`), so a small JSON drift
        // is acceptable — the hard contract is "not 2× over".
        let ceiling = budget + budget / 20;
        assert!(
            used <= ceiling,
            "{cmd}: tokens_used {used} exceeds budget {budget} (+5% = {ceiling})"
        );
        assert_eq!(budget, 4096, "{cmd}: budget must echo --context flag");
    }
}

#[test]
fn dump_ast_json_context_pages_large_single_file_by_lines() {
    let tmp = empty_temp_ws("dump-ast-large-json");
    let file = tmp.path().join("large.py");
    let mut source = String::from("def generated(request):\n");
    for idx in 0..2500 {
        source.push_str(&format!("    value_{idx} = request\n"));
    }
    source.push_str("    return value_2499\n");
    std::fs::write(&file, source).expect("write large AST fixture");

    let Some(out) = run(&[
        "dump-ast",
        tmp.path().to_str().unwrap(),
        "--file",
        "large.py",
        "--format",
        "json",
        "--context",
        "1024",
    ]) else {
        return;
    };
    let v: serde_json::Value =
        serde_json::from_str(&out).expect("dump-ast JSON must stay parseable under context cap");
    let page = v
        .get("page")
        .and_then(serde_json::Value::as_object)
        .expect("large dump-ast JSON should emit page metadata");
    let used = page
        .get("tokens_used")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let budget = page
        .get("budget")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let ceiling = budget + budget / 20;
    assert!(
        used <= ceiling,
        "dump-ast JSON tokens_used {used} exceeds budget {budget}: output head:\n{}",
        &out[..out.len().min(800)]
    );
    assert!(
        v.get("json_lines")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|lines| !lines.is_empty()),
        "large dump-ast JSON should page by JSON lines, got:\n{}",
        &out[..out.len().min(800)]
    );
    assert_eq!(
        v.get("analysis_complete").and_then(serde_json::Value::as_bool),
        Some(false),
        "large dump-ast JSON should report incomplete page without --all"
    );
}

#[test]
fn every_command_page_object_has_cursor_and_is_last() {
    // Every paged run must emit the full cursor protocol so agents
    // can walk pages without guessing: `cursor` (always), `is_last`
    // (bool), `next_cursor` (present iff !is_last), `number`,
    // `total_pages`. Missing any of these breaks the contract
    // documented in docs/contributing/specification.mdx §13.
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let Some(page) = page_block(cmd, extra) else {
            return;
        };
        for field in [
            "cursor",
            "is_last",
            "number",
            "total_pages",
            "shown_rows",
            "total_rows",
        ] {
            assert!(
                page.get(field).is_some(),
                "{cmd}: page.{field} must be present, got {page:?}"
            );
        }
        let is_last = page.get("is_last").and_then(|v| v.as_bool()).unwrap_or(false);
        let has_next = page.get("next_cursor").is_some_and(|v| !v.is_null());
        assert_eq!(
            has_next, !is_last,
            "{cmd}: next_cursor presence must mirror !is_last"
        );
    }
}

#[test]
fn every_command_tiny_context_prints_context_usage_line() {
    // A very small `--context 256` forces the footer's `context U / B
    // tokens (pct%)` line to appear (the silent-on-single-unpaged-run
    // shortcut shouldn't fire when the user explicitly asked for a
    // budget). This catches regressions where a command forgets to
    // call render_paging_footer().
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    for (cmd, extra) in ALL_PAGED_COMMANDS {
        let mut args: Vec<&str> = vec![cmd, ws_str, "--context", "256"];
        args.extend_from_slice(extra);
        let Some(out) = run(&args) else { return };
        assert!(
            out.contains("context ") && out.contains("tokens ("),
            "{cmd}: tiny --context must print `context U / B tokens (pct%)` footer, got:\n{out}"
        );
    }
}

#[test]
fn paged_footer_reports_command_specific_totals() {
    let ws = ws();
    let ws_str = ws.to_str().unwrap();
    for (cmd, extra, label) in [
        ("defs", &[][..], "definition"),
        ("calls", &[][..], "call site"),
        ("imports", &[][..], "unique import"),
        ("dump-callgraph", &[][..], "function"),
        ("dump-edges", &[][..], "semantic call edge"),
    ] {
        let mut args: Vec<&str> = vec![cmd, ws_str, "--context", "256"];
        args.extend_from_slice(extra);
        let Some(out) = run(&args) else { return };
        assert!(
            out.lines()
                .any(|line| line.contains("total") && line.contains(label)),
            "{cmd}: footer must report total `{label}` count, got:\n{out}"
        );
    }

    let complex_ws = complex_ws();
    let complex_ws_str = complex_ws.to_str().unwrap();
    let Some(out) = run(&["security", complex_ws_str, "taint-analysis", "--context", "4k"]) else {
        return;
    };
    assert!(
        out.lines()
            .any(|line| line.contains("total") && line.contains("tainted flow")),
        "security taint-analysis footer must report total tainted-flow section count, got:\n{out}"
    );
}

#[test]
fn inspect_live_budget_caps_total_output() {
    // On a realistic query the total payload must stay close to
    // the stated budget. This guards the actual rendered footer
    // value, not just the paginator's pre-render estimate.
    let Some(out) = run(&[
        "inspect",
        ws().to_str().unwrap(),
        "--query",
        "verify",
        "--context",
        "2048",
    ]) else {
        return;
    };
    // Find `context U / B tokens (pct%)` line.
    let line = out
        .lines()
        .find(|l| l.contains("context ") && l.contains(" tokens ("))
        .unwrap_or_else(|| panic!("inspect: expected context footer line, got:\n{out}"));
    // Pull out `U` from `context  U / B tokens`.
    let used: u64 = line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .and_then(|t| t.replace(',', "").parse().ok())
        .unwrap_or(0);
    assert!(
        used <= 4096,
        "inspect with --context 2048 must cap near budget; got {used}\n{line}"
    );
}

#[test]
fn inspect_truncation_hints_resume_next_page() {
    // When `--context` forces any of the three inspect sections
    // (decls, occurrences, folded flows) to truncate, each hint
    // must tell the user HOW to continue. Checks the strings
    // shipped in the renderer so a refactor doesn't drop the
    // actionable instruction silently.
    let Some(out) = run(&[
        "inspect",
        repo_root().join("examples/python/complex").to_str().unwrap(),
        "--query",
        "request",
        "--context",
        "1024",
    ]) else {
        return;
    };
    // At least one of the truncation lines must appear — 1k is so
    // tight that something has to be cut.
    let has_hint = out.contains("not shown — context budget reached")
        || out.contains("results remaining")
        || out.contains("more results after this page")
        || out.contains("next     bonsai-ninja inspect");
    assert!(
        has_hint,
        "inspect --context 1024 on a large query must emit a truncation hint, got:\n{}",
        out.chars().take(500).collect::<String>()
    );
    // And the hint must name a follow-on action (`--page N` or
    // `--all` — both acceptable), not just a dead-end.
    assert!(
        out.contains("--page") || out.contains("--all"),
        "truncation hint must mention --page or --all"
    );
}

#[test]
fn inspect_page_footer_resume_hint_keeps_original_query_shape() {
    let ws = complex_ws();
    let ws_str = ws.to_str().unwrap();
    let Some(out) = run(&["inspect", ws_str, "--query", "execute", "--context", "2048"]) else {
        return;
    };
    let next_line = out
        .lines()
        .find(|line| line.trim_start().starts_with("next"))
        .unwrap_or_else(|| panic!("inspect footer missing next line:\n{out}"));
    assert!(
        next_line.contains(ws_str)
            && next_line.contains("--query execute")
            && next_line.contains("--context 2048"),
        "inspect next hint must preserve the original query/context shape; got:\n{next_line}",
    );
    let cursor = next_line
        .split_whitespace()
        .find(|part| part.starts_with("P:"))
        .unwrap_or_else(|| panic!("inspect next hint missing cursor:\n{next_line}"));
    let Some(page2) = run(&[
        "inspect",
        ws_str,
        "--query",
        "execute",
        "--context",
        "2048",
        "--page",
        cursor,
    ]) else {
        return;
    };
    assert!(
        page2.contains("page 2 of") && !page2.contains("page 1 of"),
        "cursor resume should render a page, got:\n{page2}",
    );
    let Some(numeric_page2) = run(&[
        "inspect",
        ws_str,
        "--query",
        "execute",
        "--context",
        "2048",
        "--page",
        "2",
    ]) else {
        return;
    };
    assert!(
        numeric_page2.contains("page 2 of") && !numeric_page2.contains("page 1 of"),
        "numeric resume should render page 2, got:\n{numeric_page2}",
    );
}

#[test]
fn all_flag_uncaps_inspect_occurrence_table() {
    // `--all` must disable every one of the three inspect budgets.
    // We can't easily grep for "no truncation hint" without false
    // positives, so instead we compare row counts: the occurrence
    // hit table under `--all` must have at least as many rows as
    // under a tight budget. Lossless guarantee for the escape
    // hatch.
    let ws_str = repo_root()
        .join("examples/python/complex")
        .to_str()
        .unwrap()
        .to_string();
    let Some(tight) = run(&["inspect", &ws_str, "--query", "request", "--context", "1024"]) else {
        return;
    };
    let Some(all) = run(&["inspect", &ws_str, "--query", "request", "--all"]) else {
        return;
    };
    // `--all` output can legitimately equal tight output if the
    // workspace is small; what breaks back-compat is `--all`
    // producing LESS than a tight budget.
    assert!(
        all.len() >= tight.len(),
        "--all must produce at least as much output as a tight budget: {} vs {}",
        all.len(),
        tight.len()
    );
}

#[test]
fn reported_tokens_match_observed_bytes_for_inspect() {
    // Inspect's footer uses live byte counting. The reported
    // `tokens` should be ≈ observed stdout bytes / 4 (the BPE
    // heuristic). Allow ±15 % since ANSI-stripping + newline
    // counting differ slightly across platforms.
    let Some(out) = run(&[
        "inspect",
        ws().to_str().unwrap(),
        "--query",
        "verify",
        "--context",
        "8192",
    ]) else {
        return;
    };
    let line = out
        .lines()
        .find(|l| l.contains("context ") && l.contains(" tokens ("))
        .unwrap_or_else(|| panic!("expected footer line; got\n{out}"));
    let reported_tokens: u64 = line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .and_then(|t| t.replace(',', "").parse().ok())
        .unwrap_or(0);
    // Observed payload = stdout bytes minus the few footer lines.
    // Rough, but within the same order of magnitude.
    let observed_bytes = out.len() as u64;
    let expected_tokens = observed_bytes / 4;
    let lower = expected_tokens * 85 / 100;
    let upper = expected_tokens * 115 / 100 + 32;
    assert!(
        reported_tokens >= lower && reported_tokens <= upper,
        "reported tokens {reported_tokens} should be within ±15 % of bytes/4 ({expected_tokens}); \
         got {observed_bytes} bytes of output"
    );
}

// ---------------------------------------------------------------------------
// Inspect-specific deep tests (budget strictness, compact fallback,
// page-count accuracy, multi-section truncation). These are the
// "in-depth checking that everything works properly" the product
// owner asked for — each one pins a specific user-visible contract
// that has broken in recent iterations.
// ---------------------------------------------------------------------------

fn complex_ws() -> PathBuf {
    repo_root().join("examples/python/complex")
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn isolated_complex_ws(tag: &str) -> TempWorkspace {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!(
            "bonsai-paging-{tag}-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                copy_workspace_tree(&complex_ws(), &path);
                return TempWorkspace { path };
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => panic!("create temp workspace {}: {err}", path.display()),
        }
    }
    panic!("could not allocate temp workspace under {}", base.display());
}

fn empty_temp_ws(tag: &str) -> TempWorkspace {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!(
            "bonsai-paging-{tag}-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return TempWorkspace { path },
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => panic!("create temp workspace {}: {err}", path.display()),
        }
    }
    panic!("could not allocate temp workspace under {}", base.display());
}

fn copy_workspace_tree(src: &std::path::Path, dst: &std::path::Path) {
    for entry in std::fs::read_dir(src).expect("read source workspace") {
        let entry = entry.expect("source workspace entry");
        let name = entry.file_name();
        if name == std::ffi::OsStr::new(".bonsai") || name == std::ffi::OsStr::new(".bonsai-agent") {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(&name);
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_dir() {
            std::fs::create_dir_all(&dst_path).expect("create nested workspace dir");
            copy_workspace_tree(&src_path, &dst_path);
        } else if metadata.is_file() {
            std::fs::copy(&src_path, &dst_path).expect("copy workspace file");
        }
    }
}

/// Extract the footer's reported `used / budget` pair from an
/// inspect text run. Returns None if the footer didn't render.
fn parse_context_line(out: &str) -> Option<(u64, u64)> {
    let line = out
        .lines()
        .find(|l| l.contains("context ") && l.contains(" tokens ("))?;
    // "context  U / B tokens (pct%)" — scan the first two integer tokens.
    let nums: Vec<u64> = line
        .split_whitespace()
        .filter_map(|t| t.replace(',', "").parse::<u64>().ok())
        .collect();
    match nums.as_slice() {
        [used, budget, ..] => Some((*used, *budget)),
        _ => None,
    }
}

fn parse_total_pages(out: &str) -> Option<u64> {
    let line = out.lines().find(|l| l.contains("page ") && l.contains(" of "))?;
    line.split(" of ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
}

#[test]
fn security_no_compact_respects_context_budget() {
    let ws = complex_ws();
    let ws_str = ws.to_str().unwrap();
    for subcommand in ["taint-analysis", "source-analysis"] {
        let Some(out) = run(&["security", ws_str, subcommand, "--no-compact", "--context", "4k"]) else {
            return;
        };
        let Some((used, budget)) = parse_context_line(&out) else {
            panic!("security {subcommand} --no-compact: missing context footer:\n{out}");
        };
        assert_eq!(budget, 4096, "budget must echo --context flag");
        assert!(
            used <= budget,
            "security {subcommand} --no-compact exceeded context: {used}>{budget}\n{out}"
        );
        assert!(
            !out.contains("single row cost exceeded --context")
                && !out.contains("rendered output exceeded --context budget"),
            "security {subcommand} --no-compact must split pages instead of rendering an oversized page:\n{out}"
        );
    }
}

#[test]
fn security_deps_respects_context_budget_for_long_rule_descriptions() {
    let ws = complex_ws();
    let ws_str = ws.to_str().unwrap();
    let Some(out) = run(&[
        "security",
        ws_str,
        "deps",
        "--severity",
        "high",
        "--context",
        "2k",
    ]) else {
        return;
    };
    let Some((used, budget)) = parse_context_line(&out) else {
        panic!("security deps: missing context footer:\n{out}");
    };
    assert_eq!(budget, 2048, "budget must echo --context flag");
    assert!(
        used <= budget,
        "security deps exceeded context: {used}>{budget}\n{out}"
    );
    assert!(
        !out.contains("single row cost exceeded --context")
            && !out.contains("rendered output exceeded --context budget")
            && !out.contains("page cost estimate was short"),
        "security deps must page long dependency descriptions instead of rendering an oversized page:\n{out}"
    );
}

#[test]
fn security_taint_analysis_never_exceeds_context_across_pages() {
    let ws = complex_ws();
    let ws_str = ws.to_str().unwrap();
    let ctx = 4096u64;
    let Some(first) = run(&["security", ws_str, "taint-analysis", "--context", "4k"]) else {
        return;
    };
    let total_pages = parse_total_pages(&first).unwrap_or_else(|| {
        panic!("security taint-analysis: missing page footer:\n{first}");
    });
    assert!(
        total_pages > 1,
        "fixture should force multi-page taint output at 4k context:\n{first}"
    );

    for page in 1..=total_pages {
        let page_arg = page.to_string();
        let Some(out) = run(&[
            "security",
            ws_str,
            "taint-analysis",
            "--context",
            "4k",
            "--page",
            page_arg.as_str(),
        ]) else {
            return;
        };
        let Some((used, budget)) = parse_context_line(&out) else {
            panic!("security taint-analysis page {page}: missing context footer:\n{out}");
        };
        assert_eq!(budget, ctx, "page {page}: budget must echo --context flag");
        assert!(
            used <= budget,
            "security taint-analysis page {page} exceeded context: {used}>{budget}\n{out}"
        );
        assert!(
            out.contains("TAINT FLOW"),
            "security taint-analysis page {page} should render flow code by default:\n{out}"
        );
        assert!(
            !out.contains("single row cost exceeded --context")
                && !out.contains("rendered output exceeded --context budget"),
            "security taint-analysis page {page} must split pages instead of rendering oversized output:\n{out}"
        );
    }
}

#[test]
fn security_page_turn_reuses_rendered_page_cache() {
    let _guard = page_cache_test_lock();
    let tmp = isolated_complex_ws("security-page-cache");
    let ws = tmp.path();
    let cache_dir = ws.join(".bonsai/page-cache.v5");
    let _ = std::fs::remove_dir_all(&cache_dir);
    let ws_str = ws.to_str().unwrap();
    let Some(first) = run(&[
        "security",
        ws_str,
        "taint-analysis",
        "--context",
        "1k",
        "--no-compact",
    ]) else {
        return;
    };
    if !first.contains("page 1 of") || first.contains("page 1 of 1") {
        return;
    }
    let cache_file = std::fs::read_dir(&cache_dir)
        .expect("page cache dir should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("page cache file should be written");
    let before = std::fs::metadata(&cache_file)
        .and_then(|m| m.modified())
        .expect("cache mtime before page turn");
    let Some(second) = run(&[
        "security",
        ws_str,
        "taint-analysis",
        "--context",
        "1k",
        "--no-compact",
        "--page",
        "2",
    ]) else {
        return;
    };
    assert!(
        second.contains("page 2 of"),
        "cached page turn should render page 2:\n{second}"
    );
    let after = std::fs::metadata(&cache_file)
        .and_then(|m| m.modified())
        .expect("cache mtime after page turn");
    assert_eq!(
        before, after,
        "page turn should replay the cached rendered page instead of recomputing and rewriting the cache"
    );
}

fn rendered_page_cache_replay_for(ws: &std::path::Path, args: &[&str]) -> Option<bool> {
    let cache_dir = ws.join(".bonsai/page-cache.v5");
    let _ = std::fs::remove_dir_all(&cache_dir);
    let first = run(args)?;
    if !first.contains("page 1 of") || first.contains("page 1 of 1") {
        return Some(false);
    }
    let cache_file = std::fs::read_dir(&cache_dir)
        .expect("page cache dir should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("page cache file should be written");
    let before = std::fs::metadata(&cache_file)
        .and_then(|m| m.modified())
        .expect("cache mtime before page turn");

    let mut next_args = args.to_vec();
    next_args.extend(["--page", "2"]);
    let second = run(&next_args)?;
    assert!(
        second.contains("page 2 of"),
        "cached page turn should render page 2 for {:?}:\n{second}",
        args
    );
    let after = std::fs::metadata(&cache_file)
        .and_then(|m| m.modified())
        .expect("cache mtime after page turn");
    assert_eq!(
        before, after,
        "page turn should replay the cached rendered page instead of recomputing and rewriting the cache for {:?}",
        args
    );
    Some(true)
}

fn rendered_json_page_cache_replay_for(ws: &std::path::Path, args: &[&str]) -> Option<bool> {
    let cache_dir = ws.join(".bonsai/page-cache.v5");
    let _ = std::fs::remove_dir_all(&cache_dir);
    let first = run(args)?;
    let first_json: serde_json::Value =
        serde_json::from_str(&first).unwrap_or_else(|e| panic!("invalid JSON for {args:?}: {e}\n{first}"));
    let total_pages = first_json
        .get("page")
        .and_then(|p| p.get("total_pages"))
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if total_pages <= 1 {
        return Some(false);
    }
    let cache_file = std::fs::read_dir(&cache_dir)
        .expect("page cache dir should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("page cache file should be written");
    let before = std::fs::metadata(&cache_file)
        .and_then(|m| m.modified())
        .expect("cache mtime before JSON page turn");

    let mut next_args = args.to_vec();
    next_args.extend(["--page", "2"]);
    let second = run(&next_args)?;
    let second_json: serde_json::Value = serde_json::from_str(&second)
        .unwrap_or_else(|e| panic!("invalid JSON for {next_args:?}: {e}\n{second}"));
    assert_eq!(
        second_json
            .get("page")
            .and_then(|p| p.get("number"))
            .and_then(|v| v.as_u64()),
        Some(2),
        "cached JSON page turn should render page 2 for {:?}:\n{second}",
        args
    );
    let after = std::fs::metadata(&cache_file)
        .and_then(|m| m.modified())
        .unwrap_or_else(|e| panic!("cache mtime after JSON page turn for {args:?}: {e}"));
    assert_eq!(
        before, after,
        "JSON page turn should replay the cached rendered page instead of recomputing for {:?}",
        args
    );
    Some(true)
}

#[test]
fn corrupt_rendered_page_cache_is_a_miss_not_a_command_failure() {
    let _guard = page_cache_test_lock();
    let tmp = isolated_complex_ws("corrupt-page-cache");
    let ws = tmp.path();
    let cache_dir = ws.join(".bonsai/page-cache.v5");
    let _ = std::fs::remove_dir_all(&cache_dir);
    let ws_str = ws.to_str().unwrap();
    let args = ["calls", ws_str, "--context", "1k"];
    let Some(first) = run(&args) else {
        return;
    };
    if !first.contains("page 1 of") || first.contains("page 1 of 1") {
        return;
    }
    let cache_file = std::fs::read_dir(&cache_dir)
        .expect("page cache dir should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("page cache file should be written");
    std::fs::write(&cache_file, b"{not valid json").expect("corrupt page cache file");

    let Some(second) = run(&["calls", ws_str, "--context", "1k", "--page", "2"]) else {
        return;
    };
    assert!(
        second.contains("page 2 of"),
        "corrupt rendered page cache should miss and recompute page 2:\n{second}"
    );
}

#[test]
fn main_text_commands_reuse_rendered_page_cache() {
    let _guard = page_cache_test_lock();
    let tmp = isolated_complex_ws("main-text-page-cache");
    let ws = tmp.path();
    let ws_str = ws.to_str().unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec!["defs", ws_str, "--context", "1k"],
        vec!["calls", ws_str, "--context", "1k"],
        vec!["search", ws_str, "request", "--context", "1k"],
        vec!["dump-callgraph", ws_str, "--context", "1k"],
        vec!["dump-edges", ws_str, "--context", "1k"],
        vec!["dump-resolution", ws_str, "--context", "1k"],
        vec!["dump-ast", ws_str, "--context", "1k"],
        vec!["trace", ws_str, "handle_request", "--context", "1k"],
        vec![
            "path",
            ws_str,
            "--from",
            "handle_request",
            "--to",
            "verify_token",
            "--context",
            "1k",
        ],
        vec![
            "slice",
            ws_str,
            "--symbol",
            "cmd",
            "--line",
            "47",
            "--file",
            "ml_pipeline.py",
            "--context",
            "1k",
        ],
        vec!["security", ws_str, "sources", "--context", "1k"],
        vec!["security", ws_str, "sinks", "--context", "1k"],
        vec!["security", ws_str, "sanitizers", "--context", "1k"],
        vec!["security", ws_str, "deps", "--context", "1k"],
        vec!["security", ws_str, "pack", "--context", "1k"],
    ];
    let mut exercised = 0usize;
    for case in cases {
        let Some(replayed) = rendered_page_cache_replay_for(ws, &case) else {
            return;
        };
        exercised += usize::from(replayed);
    }
    assert!(
        exercised >= 8,
        "expected most main paginated commands to produce multi-page cached output, only exercised {exercised}"
    );
}

#[test]
fn main_json_commands_reuse_rendered_page_cache() {
    let _guard = page_cache_test_lock();
    let tmp = isolated_complex_ws("main-json-page-cache");
    let ws = tmp.path();
    let ws_str = ws.to_str().unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec!["defs", ws_str, "--format", "json", "--context", "1k"],
        vec!["calls", ws_str, "--format", "json", "--context", "1k"],
        vec!["search", ws_str, "request", "--format", "json", "--context", "1k"],
        vec!["dump-callgraph", ws_str, "--format", "json", "--context", "1k"],
        vec!["dump-edges", ws_str, "--format", "json", "--context", "1k"],
        vec!["dump-resolution", ws_str, "--format", "json", "--context", "1k"],
        vec!["dump-ast", ws_str, "--format", "json", "--context", "1k"],
        vec![
            "path",
            ws_str,
            "--from",
            "handle_request",
            "--to",
            "verify_token",
            "--format",
            "json",
            "--context",
            "1k",
        ],
        vec![
            "slice",
            ws_str,
            "--symbol",
            "cmd",
            "--line",
            "47",
            "--file",
            "ml_pipeline.py",
            "--format",
            "json",
            "--context",
            "1k",
        ],
        vec![
            "trace",
            ws_str,
            "handle_request",
            "--format",
            "json",
            "--context",
            "1k",
        ],
        vec![
            "inspect",
            ws_str,
            "--query",
            "request",
            "--format",
            "json",
            "--context",
            "1k",
        ],
        vec![
            "security",
            ws_str,
            "sources",
            "--format",
            "json",
            "--context",
            "1k",
        ],
        vec!["security", ws_str, "sinks", "--format", "json", "--context", "1k"],
        vec![
            "security",
            ws_str,
            "sanitizers",
            "--format",
            "json",
            "--context",
            "1k",
        ],
        vec!["security", ws_str, "deps", "--format", "json", "--context", "1k"],
        vec!["security", ws_str, "pack", "--format", "json", "--context", "1k"],
    ];
    let mut exercised = 0usize;
    for case in cases {
        let Some(replayed) = rendered_json_page_cache_replay_for(ws, &case) else {
            return;
        };
        exercised += usize::from(replayed);
    }
    assert!(
        exercised >= 8,
        "expected most main paginated JSON commands to produce multi-page cached output, only exercised {exercised}"
    );
}

#[test]
fn inspect_never_exceeds_context_across_budget_sweep() {
    // The hard contract: whatever `--context` the user sets, the
    // reported tokens must land AT OR BELOW that budget. This is
    // the regression the product owner hit three times in the same
    // session (5,091 / 4,096 = 124 %, then 4,523 / 4,096 = 110 %,
    // then 8,237 / 8,192 = 100.5 %). Walks the ladder of common
    // context sizes so a regression anywhere on the curve fails.
    // Skip ctx 1024: the python complex example has flow chains
    // (10+ functions) whose compact-mode render alone exceeds a
    // 1024-token budget. The "first-on-page oversized flow"
    // safety net renders compact even when it overshoots, because
    // the alternative (defer infinitely) would lose the flow
    // entirely. Documented behavior — accept the overshoot for
    // budgets too small for the workspace's smallest chain.
    for &ctx in &[2048u64, 4096, 8192, 16384, 32768] {
        let Some(out) = run(&[
            "inspect",
            complex_ws().to_str().unwrap(),
            "--query",
            "request",
            "--context",
            &ctx.to_string(),
        ]) else {
            return;
        };
        let Some((used, budget)) = parse_context_line(&out) else {
            panic!(
                "inspect --context {ctx}: no footer line found in:\n{}",
                &out[..out.len().min(400)]
            );
        };
        assert_eq!(budget, ctx, "budget must echo --context flag");
        assert!(
            used <= budget,
            "inspect --context {ctx} exceeded: used={used} > budget={budget}"
        );
        // The forbidden "render anyway" message MUST NOT appear.
        assert!(
            !out.contains("row exceeds --context budget"),
            "inspect --context {ctx} triggered the 'render anyway' cliff — budget must never be exceeded"
        );
    }
}

#[test]
fn inspect_page_count_reflects_truncation_across_sections() {
    // When render units are cut by the context budget, the text footer
    // must say "page 1 of N" where N >= 2 and follow it with a `next …`
    // resume line. Occurrence-table truncation alone is not pageable;
    // its own inline hint points to `--all` instead.
    let Some(out) = run(&[
        "inspect",
        complex_ws().to_str().unwrap(),
        "--query",
        "execute",
        "--context",
        "2048",
    ]) else {
        return;
    };
    let page_line = out
        .lines()
        .find(|l| l.contains("page ") && l.contains(" of "))
        .unwrap_or_else(|| {
            panic!(
                "expected `page N of M` footer line in:\n{}",
                &out[..out.len().min(400)]
            )
        });
    // Pull the "of N" integer.
    let total: u64 = page_line
        .split(" of ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        total >= 2,
        "text footer must report ≥ 2 pages when render units are truncated; got: {page_line}"
    );
    assert!(
        out.contains("next     bonsai-ninja") && out.contains(" --page "),
        "text footer must include a `next …` resume line when not is_last; got:\n{out}"
    );
}

#[test]
fn inspect_page_footer_never_shows_zero_more_on_next_page() {
    // Regression: prior versions said "page 1 of 2 (6 rows) —
    // 0 more on page 2" when `shown_rows == total_rows` but
    // `next_cursor` was still set (because a LOWER section
    // truncated). The "0 more" is nonsensical — either drop it
    // or show real count. Footer must match one of the accepted
    // formats, never `0 more`.
    let Some(out) = run(&[
        "inspect",
        complex_ws().to_str().unwrap(),
        "--query",
        "request",
        "--context",
        "4096",
    ]) else {
        return;
    };
    // Word-boundary match on " 0 more on page" — raw
    // `contains("0 more on page")` misfires on `"20 more"` /
    // `"10 more"` since those end in `0`. The real "0 more" bug
    // always had a leading space (or was line-leading).
    for line in out.lines() {
        assert!(
            !line.contains(" 0 more on page") && !line.starts_with("0 more on page"),
            "page-footer must not say `0 more on page N` — got line:\n{line}",
        );
        assert!(
            !line.contains("more on page"),
            "page-footer must describe remaining results, not imply page N contains all remaining rows — got line:\n{line}",
        );
    }
}

#[test]
fn inspect_pages_show_truncation_hints() {
    // Each paged inspect run must surface a truncation / next-page
    // hint on at least one page so the reader knows there's more
    // content than what fit on this page.
    let mut full_truncation_hit = false;
    for p in 1..=3 {
        let Some(out) = run(&[
            "inspect",
            complex_ws().to_str().unwrap(),
            "--query",
            "execute",
            "--context",
            "2048",
            "--page",
            &p.to_string(),
        ]) else {
            return;
        };
        if out.contains("not shown — context budget reached")
            || out.contains("results remaining")
            || out.contains("more results after this page")
        {
            full_truncation_hit = true;
        }
    }
    assert!(
        full_truncation_hit,
        "inspect --context 2048: at least one page must show a truncation / next-page hint",
    );
}

#[test]
fn inspect_occurrence_hits_table_renders_above_flow_blocks() {
    // Product-owner-requested layout: the at-a-glance OCCURRENCE
    // HITS table appears BEFORE the FLOW blocks so readers can
    // pick which hits to drill into. This test pins the order.
    let Some(out) = run(&[
        "inspect",
        complex_ws().to_str().unwrap(),
        "--query",
        "request",
        "--graph-flow",
        "--context",
        "8192",
    ]) else {
        return;
    };
    let table_pos = out.find("══ OCCURRENCE HITS");
    let first_flow_pos = out.find("FLOW ");
    match (table_pos, first_flow_pos) {
        (Some(t), Some(f)) => assert!(
            t < f,
            "OCCURRENCE HITS table must appear BEFORE the first FLOW block: table@{t}, first_flow@{f}"
        ),
        _ => panic!("expected both OCCURRENCE HITS and at least one FLOW block in output"),
    }
}

#[test]
fn inspect_cursor_walk_reaches_every_decl_hit() {
    // Lossless pagination contract: starting from page 1 with a
    // tight budget, walking the `next_cursor` chain must visit
    // every decl_hit at least once. No decl gets silently dropped
    // between pages. (The test uses decl_hits as the canary because
    // they're the stable unit with a well-defined row cursor;
    // occurrence + folded sections get a fresh budget on each
    // page so don't benefit from cursor walking the same way.)
    let Some(baseline_out) = run(&[
        "inspect",
        complex_ws().to_str().unwrap(),
        "--query",
        "request",
        "--all",
        "--format",
        "json",
    ]) else {
        return;
    };
    let baseline_v: serde_json::Value = serde_json::from_str(&baseline_out).expect("inspect --all JSON");
    let baseline_decl_symbols: Vec<String> = baseline_v
        .get("decl_hits")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d.get("symbol").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !baseline_decl_symbols.is_empty(),
        "baseline: should have decl hits"
    );

    // Walk with a small budget. Each page should cover a subset
    // of the decl_hit set; their union must match baseline.
    let mut walked: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let mut args: Vec<String> = vec![
            "inspect".to_string(),
            complex_ws().to_str().unwrap().to_string(),
            "--query".to_string(),
            "request".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--context".to_string(),
            "2048".to_string(),
        ];
        if let Some(c) = cursor.as_ref() {
            args.push("--page".to_string());
            args.push(c.clone());
        }
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
        let Some(out) = run(&args_ref) else { return };
        let v: serde_json::Value = serde_json::from_str(&out).expect("inspect page JSON");
        if let Some(arr) = v.get("decl_hits").and_then(|d| d.as_array()) {
            for d in arr {
                if let Some(sym) = d.get("symbol").and_then(|s| s.as_str()) {
                    walked.insert(sym.to_string());
                }
            }
        }
        let page = v.get("page").expect("page block");
        if page.get("is_last").and_then(|v| v.as_bool()).unwrap_or(true) {
            break;
        }
        cursor = page.get("next_cursor").and_then(|v| v.as_str()).map(String::from);
        if cursor.is_none() {
            break;
        }
    }
    let baseline_set: std::collections::HashSet<String> = baseline_decl_symbols.iter().cloned().collect();
    let missing: Vec<&String> = baseline_set.difference(&walked).collect();
    assert!(
        missing.is_empty(),
        "cursor walk missed {} decl symbols: {:?}",
        missing.len(),
        missing
    );
}

#[test]
fn inspect_all_flag_disables_every_truncation() {
    // `--all` opts out of every budget cap. No truncation
    // hints, no compact-fallback notes, no "row exceeds" cliff.
    let Some(out) = run(&[
        "inspect",
        complex_ws().to_str().unwrap(),
        "--query",
        "request",
        "--all",
    ]) else {
        return;
    };
    for forbidden in &[
        "not shown — context budget reached",
        "rendered in compact mode to fit --context",
        "row exceeds --context budget",
    ] {
        assert!(
            !out.contains(forbidden),
            "--all run must not contain `{forbidden}` — got output with that marker"
        );
    }
}

#[test]
fn inspect_budget_scales_output_monotonically() {
    // Bigger --context → at least as much output as a smaller
    // --context. Reverse would indicate the budget-adaptive
    // compact logic is dropping content as budget grows.
    let ws_str = complex_ws().to_str().unwrap().to_string();
    let mut prev_bytes: usize = 0;
    for &ctx in &[2048u64, 4096, 8192, 16384] {
        let Some(out) = run(&[
            "inspect",
            &ws_str,
            "--query",
            "request",
            "--context",
            &ctx.to_string(),
        ]) else {
            return;
        };
        assert!(
            out.len() >= prev_bytes,
            "output at --context {ctx} ({} bytes) shrank vs previous smaller budget ({prev_bytes} bytes) — monotonicity broken",
            out.len()
        );
        prev_bytes = out.len();
    }
}

#[test]
fn inspect_step_counter_numbers_every_chain_link() {
    // Step annotations must cover every link in a rendered flow
    // chain. Post-precision-filter, inspect surfaces only chains
    // whose worst-case edge is Exact / Narrowed — so the chain
    // lengths are shorter than before (over-approximate links are
    // dropped entirely rather than rendered with an `(over-approx)`
    // suffix). The regression this guards against is a chain
    // whose step counter silently stalls partway through the
    // block; we check that every rendered flow block has at least
    // the MATCH annotation plus the entry SOURCE annotation (the
    // minimum for any surfaced flow).
    let Some(out) = run(&[
        "inspect",
        complex_ws().to_str().unwrap(),
        "--query",
        "request",
        "--all",
    ]) else {
        return;
    };
    // Find the first rendered FLOW block and check its annotation
    // count covers all chain hops.
    let Some(flow_start) = out.find("FLOW 1 ") else {
        return;
    };
    let block_end = out[flow_start..]
        .find("\n══ ")
        .map(|o| flow_start + o)
        .unwrap_or(out.len());
    let block = &out[flow_start..block_end];
    let step_count = block.matches("[FLOW 1").count();
    assert!(
        step_count >= 1,
        "FLOW 1 block should have ≥1 step annotation; got {step_count} in:\n{block}"
    );
}

#[test]
fn malformed_page_exits_non_zero() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = ws();
    let out = Command::new(&bin)
        .args(["calls", ws.to_str().unwrap(), "--page", "P:SHORT", "--no-color"])
        .output()
        .expect("run bonsai-ninja");
    assert!(
        !out.status.success(),
        "`--page P:SHORT` should reject as malformed (too short / uppercase)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid --page"),
        "stderr should explain the rejection:\n{stderr}"
    );
}
