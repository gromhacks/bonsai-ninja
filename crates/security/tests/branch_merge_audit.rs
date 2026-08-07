//! Branch-merge precision audit — per-language stress test that
//! taint state propagates correctly through branch joins.
//!
//! Each fixture under `examples/<lang>/branch_merge/` has:
//!
//!   `taint_one_leg(cond)`:
//!     if cond { x = source(); } else { x = "constant"; }
//!     sink(x)            // POSITIVE: tainted-leg flow reaches sink
//!
//!   `taint_overwritten(cond)`:
//!     x = source();
//!     if cond { x = "clean"; } else { x = "clean"; }
//!     sink(x)            // NEGATIVE: both legs overwrite — taint
//!                        //           must not survive the merge
//!
//! Per `docs/contributing/taint-engine-spec.mdx`: "The graph rejects false paths
//! through clean overwrite after taint." This audit pins both
//! sides of branch-merge precision.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("branch_merge");
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
    /// Engine reports exactly 1 finding (the one-leg taint case),
    /// AND no finding from the overwritten case.
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
    overwritten_fired: bool,
}

fn audit_one(lang: &'static str) -> Result_ {
    let report = match run_taint_for(lang) {
        Ok(r) => r,
        Err(reason) => {
            return Result_ {
                lang,
                skipped: Some(reason),
                findings: 0,
                overwritten_fired: false,
            }
        }
    };
    // The "overwritten" case must NOT fire — detect by chain
    // containing the function name with `overwritten` substring.
    let overwritten_fired = report.findings.iter().any(|f| {
        f.finding
            .chain_display
            .iter()
            .any(|hop| hop.to_ascii_lowercase().contains("overwritten"))
    });
    Result_ {
        lang,
        skipped: None,
        findings: report.findings.len(),
        overwritten_fired,
    }
}

#[test]
fn branch_merge_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== branch-merge audit ===");
    eprintln!(
        "{:<11} {:>9} {:>10}  {:<22}  status",
        "lang", "findings", "overwr?", "expected"
    );
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass",
        };
        let status: &str = if r.skipped.is_some() {
            "fixture missing"
        } else {
            match (expected, r.findings, r.overwritten_fired) {
                (Expected::Pass, n, false) if n >= 1 => "ok",
                (Expected::Pass, _, true) => "REGRESSION: overwritten leg fired",
                (Expected::Pass, 0, _) => "REGRESSION: tainted leg missing",
                (Expected::Pass, _, _) => "ok",
            }
        };
        eprintln!(
            "{:<11} {:>9} {:>10}  {:<22}  {status}",
            r.lang,
            r.findings,
            if r.overwritten_fired { "yes" } else { "no" },
            exp,
        );
    }

    let regressions: Vec<String> = results
        .iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pass => {
                if let Some(reason) = r.skipped.as_deref() {
                    Some(format!("{}: fixture missing ({reason})", r.lang))
                } else if r.findings == 0 {
                    Some(format!("{}: expected ≥1 finding (tainted leg)", r.lang))
                } else if r.overwritten_fired {
                    Some(format!(
                        "{}: overwritten-leg fired — clean-overwrite precision broken",
                        r.lang
                    ))
                } else {
                    None
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("branch-merge audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}
