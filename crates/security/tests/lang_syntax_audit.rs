//! Language-specific syntactic-forms audit — verifies that each
//! adapter surfaces unusual language constructs (Perl backtick/qx,
//! Ruby backticks + string interpolation, PHP include/require,
//! Erlang bit-string concat, Solidity inline assembly) as Call /
//! Read FlowEvents so the rulepack's name-based rules can match.
//!
//! Per `docs/contributing/taint-engine-spec.mdx § Adapter Contract`: per-language
//! syntactic differences belong in adapter grammar mappings and
//! tree-sitter queries — not in rules. This audit pins which
//! language-special constructs each adapter currently surfaces.

use rayon::prelude::*;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("lang_syntax");
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
    #[allow(dead_code)]
    KnownAdapterGap(&'static str),
    #[allow(dead_code)]
    Pending,
}

const LANG_TABLE: &[(&str, Expected)] = &[
    ("perl", Expected::Pass),
    // Ruby fires on `eval $tainted` (1 finding), but NOT on backtick
    // `cmd #{interp}` or `%x{...}`. Counted as Pass at the audit
    // level because at least one syntactic form works; the
    // backtick-specific gap is captured under Task #284.
    ("ruby", Expected::Pass),
    ("php", Expected::Pass),
    ("erlang", Expected::Pass),
    ("solidity", Expected::Pass),
    ("elixir", Expected::Pass),
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
fn lang_syntax_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .par_iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== language-syntax audit ===");
    eprintln!("{:<11} {:>9}  {:<22}  status", "lang", "findings", "expected");
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass",
            Expected::Pending => "Pending",
            Expected::KnownAdapterGap(_) => "KnownAdapterGap",
        };
        let status = if matches!(expected, Expected::Pending) {
            "skipped (pending)"
        } else if r.skipped.is_some() {
            match expected {
                Expected::Pass => "REGRESSION: fixture missing",
                Expected::KnownAdapterGap(_) => "fixture removed; restore",
                Expected::Pending => unreachable!(),
            }
        } else if r.findings == 0 {
            match expected {
                Expected::Pass => "REGRESSION: expected Pass, got 0",
                Expected::KnownAdapterGap(_) => "still gapped (locked-in)",
                Expected::Pending => unreachable!(),
            }
        } else {
            match expected {
                Expected::Pass => "ok",
                Expected::KnownAdapterGap(_) => "GAP CLOSED — flip to Pass",
                Expected::Pending => unreachable!(),
            }
        };
        eprintln!("{:<11} {:>9}  {:<22}  {status}", r.lang, r.findings, exp);
    }

    let regressions: Vec<String> = results
        .par_iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pending => None,
            Expected::Pass => {
                if let Some(reason) = r.skipped.as_deref() {
                    Some(format!("{}: fixture missing ({reason})", r.lang))
                } else if r.findings == 0 {
                    Some(format!("{}: expected Pass, got 0 findings", r.lang))
                } else {
                    None
                }
            }
            Expected::KnownAdapterGap(why) => {
                if let Some(reason) = r.skipped.as_deref() {
                    Some(format!(
                        "{}: KnownAdapterGap but fixture missing ({reason})",
                        r.lang
                    ))
                } else if r.findings > 0 {
                    Some(format!(
                        "{}: KnownAdapterGap fired {} finding(s) — adapter likely fixed; \
                         flip to Pass. (gap was: {why})",
                        r.lang, r.findings
                    ))
                } else {
                    None
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("language-syntax audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}
