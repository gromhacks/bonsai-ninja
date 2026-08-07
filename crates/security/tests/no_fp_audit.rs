//! False-positive audit — per-language stress test that the engine
//! does NOT report findings when source and sink coexist in the
//! same function but there is no dataflow between them.
//!
//! Each fixture under `examples/<lang>/no_fp/` has:
//!   - a function `decoy` that reads a tainted source into one
//!     variable, then runs a sink with a constant — no flow
//!     between them.
//!   - a function `unrelated_chain` that does several unrelated
//!     calls in sequence — no source, no sink, just routine code.
//!
//! Per `docs/contributing/taint-engine-spec.mdx § Semantic Model`: "The graph
//! rejects false paths through ... clean overwrite after taint /
//! sanitized value flowing beside raw value." This audit exercises
//! the simplest form: parallel data flows that share NO assignment
//! relationship.
//!
//! Each fixture must produce **0 findings**. The lock-in is
//! per-lang `Expected::Pass` (no findings is the success
//! condition).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("no_fp");
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
    /// No findings expected. The fixture has source + sink with no
    /// dataflow between them.
    Pass,
    /// Adapter currently produces a known false positive — locked
    /// in here so the day the engine improves precision, the
    /// audit forces the table to be updated.
    #[allow(dead_code)]
    KnownFP(&'static str),
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
struct LangAuditResult {
    lang: &'static str,
    skipped: Option<String>,
    findings: usize,
}

fn audit_one(lang: &'static str) -> LangAuditResult {
    let report = match run_taint_for(lang) {
        Ok(r) => r,
        Err(reason) => {
            return LangAuditResult {
                lang,
                skipped: Some(reason),
                findings: 0,
            }
        }
    };
    LangAuditResult {
        lang,
        skipped: None,
        findings: report.findings.len(),
    }
}

#[test]
fn no_false_positives_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== no-false-positive audit ===");
    eprintln!("{:<11} {:>9}  {:<22}  status", "lang", "findings", "expected");
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass",
            Expected::KnownFP(_) => "KnownFP",
        };
        let status: &str = if r.skipped.is_some() {
            "fixture missing"
        } else {
            match (expected, r.findings) {
                (Expected::Pass, 0) => "ok",
                (Expected::Pass, _) => "REGRESSION: false positive emitted",
                (Expected::KnownFP(_), 0) => "FP CLEARED — flip to Pass",
                (Expected::KnownFP(_), _) => "still false-positive (locked-in)",
            }
        };
        eprintln!("{:<11} {:>9}  {:<22}  {status}", r.lang, r.findings, exp);
    }

    let regressions: Vec<String> = results
        .iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pass => {
                if let Some(reason) = r.skipped.as_deref() {
                    Some(format!("{}: fixture missing ({reason})", r.lang))
                } else if r.findings > 0 {
                    Some(format!(
                        "{}: expected 0 findings (no FP), got {}",
                        r.lang, r.findings
                    ))
                } else {
                    None
                }
            }
            Expected::KnownFP(why) => {
                if let Some(reason) = r.skipped.as_deref() {
                    Some(format!("{}: KnownFP but fixture missing ({reason})", r.lang))
                } else if r.findings == 0 {
                    Some(format!(
                        "{}: KnownFP cleared (engine got more precise) — flip to Pass. \
                         (gap was: {why})",
                        r.lang
                    ))
                } else {
                    None
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("no-fp audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}
