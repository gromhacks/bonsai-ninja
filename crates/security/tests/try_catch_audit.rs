//! Try / catch precision audit — verifies taint propagates through
//! try-body call sites and survives into the sink even when the
//! try-region might raise.
//!
//! Each fixture under `examples/<lang>/try_catch/`:
//!
//!   `tainted_through_try()`: source -> assign in try block -> sink
//!     after try. POSITIVE: taint must flow through.
//!
//! Per `docs/contributing/taint-engine-spec.mdx § Semantic Model`: "The graph
//! tracks values through ... exceptions, finally/defer/ensure-style
//! cleanup, and throws."

use rayon::prelude::*;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("try_catch");
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
fn try_catch_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .par_iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== try-catch audit ===");
    eprintln!("{:<11} {:>9}  {:<22}  status", "lang", "findings", "expected");
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass",
        };
        let status: &str = if r.skipped.is_some() {
            "fixture missing"
        } else {
            match (expected, r.findings) {
                (Expected::Pass, n) if n >= 1 => "ok",
                (Expected::Pass, _) => "REGRESSION: try-body flow not propagated",
            }
        };
        eprintln!("{:<11} {:>9}  {:<22}  {status}", r.lang, r.findings, exp);
    }

    let regressions: Vec<String> = results
        .par_iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pass => {
                if r.skipped.is_some() {
                    Some(format!("{}: fixture missing", r.lang))
                } else if r.findings == 0 {
                    Some(format!("{}: try-body flow not propagated", r.lang))
                } else {
                    None
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("try-catch audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}
