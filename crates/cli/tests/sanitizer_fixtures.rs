//! Per-language `sanitizer_test` fixture integration tests.
//!
//! Every `examples/<lang>/sanitizer_test/` directory pairs
//! `<name>_raw` / `<name>_safe` handlers: the raw form reaches the
//! sink directly (finding expected), the safe form routes taint
//! through a sanitizer before the sink (finding expected with
//! sanitizer evidence).
//!
//! This file runs `security taint-analysis` against every fixture and
//! asserts the engine's sanitizer semantics hold.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    for path in [
        repo_root().join("target/debug/bonsai-ninja"),
        repo_root().join("target/release/bonsai-ninja"),
    ] {
        if path.exists() {
            return Some(path);
        }
    }
    eprintln!("skipping sanitizer_fixtures: bonsai-ninja binary missing");
    None
}

fn run(args: &[&str]) -> Option<(String, String, i32)> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    full.push("--no-progress");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "240")
        .current_dir(repo_root())
        .output()
        .expect("spawn bonsai-ninja");
    Some((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    ))
}

fn rows_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(a) = v.as_array() {
        return a.clone();
    }
    if let Some(o) = v.as_object() {
        if let Some(r) = o.get("rows").and_then(|r| r.as_array()) {
            return r.clone();
        }
    }
    Vec::new()
}

fn fixture_ws(lang: &str) -> String {
    repo_root()
        .join("examples")
        .join(lang)
        .join("sanitizer_test")
        .to_string_lossy()
        .into_owned()
}

/// Languages whose sanitizer_test fixture produces both a raw (no
/// sanitizer) AND a safe (sanitizer-attached) finding on at least
/// one sink family.
const LANGS_WITH_SANITIZER_EVIDENCE: &[&str] =
    &["c", "dart", "elixir", "erlang", "go", "javascript", "solidity"];

/// Languages whose fixture produces at least one raw-form finding.
const LANGS_WITH_RAW_FINDING: &[&str] = &[
    "c",
    "cpp",
    "csharp",
    "dart",
    "elixir",
    "erlang",
    "go",
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

#[test]
fn every_sanitizer_fixture_produces_a_raw_finding() {
    let Some(_) = bin_path() else { return };
    for lang in LANGS_WITH_RAW_FINDING {
        let w = fixture_ws(lang);
        let Some((out, _, code)) = run(&[
            "security",
            &w,
            "taint-analysis",
            "--inferred-sources",
            "--format",
            "json",
        ]) else {
            return;
        };
        assert_eq!(code, 0, "[{lang}] sanitizer_test flows ec={code}");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let rows = rows_of(&parsed);
        // Raw == not credit-cleared. After T101 the engine's
        // authoritative answer is `status != "sanitized"` —
        // unsanitized AND wrong-context both count as raw because
        // wrong-context means the sanitizer fired but doesn't cover
        // the sink class.
        let raw_count = rows
            .iter()
            .filter(|r| {
                r.get("status")
                    .and_then(|s| s.as_str())
                    .map(|s| s != "sanitized")
                    .unwrap_or(true)
            })
            .count();
        assert!(
            raw_count > 0,
            "[{lang}] sanitizer_test: no raw (unsanitized / wrong-context) finding — rulepack or adapter may have silently suppressed the unsafe handler"
        );
    }
}

#[test]
fn sanitized_paths_attach_sanitizer_evidence() {
    let Some(_) = bin_path() else { return };
    for lang in LANGS_WITH_SANITIZER_EVIDENCE {
        let w = fixture_ws(lang);
        let Some((out, _, code)) = run(&[
            "security",
            &w,
            "taint-analysis",
            "--inferred-sources",
            "--format",
            "json",
        ]) else {
            return;
        };
        assert_eq!(code, 0, "[{lang}] sanitizer_test flows ec={code}");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let rows = rows_of(&parsed);
        let sanitized = rows
            .iter()
            .filter(|r| {
                r.get("sanitizers_seen")
                    .and_then(|s| s.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .count();
        assert!(
            sanitized > 0,
            "[{lang}] sanitizer_test: no finding carries `sanitizers_seen` — engine didn't pick up the safe-path sanitizer"
        );
    }
}

#[test]
fn show_sanitized_is_compatibility_noop() {
    let Some(_) = bin_path() else { return };
    let w = fixture_ws("python");
    let Some((default_out, _, default_code)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--inferred-sources",
        "--format",
        "json",
    ]) else {
        return;
    };
    assert_eq!(default_code, 0, "python sanitizer_test default ec={default_code}");
    let Some((shown_out, _, shown_code)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--inferred-sources",
        "--show-sanitized",
        "--format",
        "json",
    ]) else {
        return;
    };
    assert_eq!(
        shown_code, 0,
        "python sanitizer_test --show-sanitized ec={shown_code}"
    );

    let default_rows = rows_of(&serde_json::from_str(&default_out).unwrap());
    let shown_rows = rows_of(&serde_json::from_str(&shown_out).unwrap());
    let default_sanitized = default_rows
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("sanitized"))
        .count();
    let shown_sanitized = shown_rows
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("sanitized"))
        .count();

    assert!(
        default_sanitized > 0,
        "default taint-analysis should include credit-cleared sanitizer paths"
    );
    assert_eq!(
        shown_sanitized, default_sanitized,
        "--show-sanitized is a compatibility flag and should not change sanitizer visibility"
    );
}

/// Every sanitizer attached to a finding must carry a well-formed
/// `rule_id`, `file`, and `line` — the evidence block a reviewer
/// will see in the `security taint-analysis` text rendering.
#[test]
fn sanitizer_evidence_has_complete_shape() {
    let Some(_) = bin_path() else { return };
    for lang in LANGS_WITH_SANITIZER_EVIDENCE {
        let w = fixture_ws(lang);
        let Some((out, _, _)) = run(&[
            "security",
            &w,
            "taint-analysis",
            "--inferred-sources",
            "--format",
            "json",
        ]) else {
            return;
        };
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let rows = rows_of(&parsed);
        for r in rows {
            let sanitizers = r
                .get("sanitizers_seen")
                .and_then(|s| s.as_array())
                .cloned()
                .unwrap_or_default();
            for s in sanitizers {
                let rule_id = s.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");
                let file = s.get("file").and_then(|v| v.as_str()).unwrap_or("");
                let line = s.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
                assert!(
                    rule_id.contains(".sanitizer."),
                    "[{lang}] sanitizer evidence has non-sanitizer rule_id: {rule_id}"
                );
                assert!(!file.is_empty(), "[{lang}] sanitizer evidence missing file");
                assert!(line > 0, "[{lang}] sanitizer evidence line=0: {s}");
            }
        }
    }
}

/// For the Python fixture we can be precise: raw and sanitized
/// branches both remain visible, with sanitizer evidence attached
/// to the safe branches.
#[test]
fn python_sanitizer_fixture_expected_counts() {
    let Some(_) = bin_path() else { return };
    let w = fixture_ws("python");
    let Some((out, _, code)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--inferred-sources",
        "--format",
        "json",
    ]) else {
        return;
    };
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let rows = rows_of(&parsed);
    let raw: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.get("sanitizers_seen")
                .and_then(|s| s.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(true)
        })
        .collect();
    let safe: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.get("sanitizers_seen")
                .and_then(|s| s.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        raw.len(),
        2,
        "python sanitizer fixture: raw findings = {}, want exactly 2",
        raw.len()
    );
    assert_eq!(
        safe.len(),
        2,
        "python sanitizer fixture: sanitized findings = {}, want exactly 2",
        safe.len()
    );
}
