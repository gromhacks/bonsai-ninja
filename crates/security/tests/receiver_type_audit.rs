//! Receiver-type resolution audit — per-language stress test that
//! every adapter resolves an instance variable's type so rules
//! shaped as `attribute: [<ClassName>, <method>]` fire on
//! instance-method calls (`var.method(...)`).
//!
//! Each fixture under `examples/<lang>/receiver_type/` constructs
//! an instance of a class whose method is a known sink, then calls
//! that method with a tainted argument. The shipped rule for that
//! sink uses the `[<ClassName>, <method>]` shape — so the rule only
//! fires if the engine resolved the receiver's type.
//!
//! Per `docs/contributing/taint-engine-spec.mdx § Adapter Contract`: receiver
//! type resolution belongs in the adapter / resolver / callgraph
//! layers. Rules cannot patch around missing receiver-type facts
//! (and shouldn't try). This audit pins which adapters have the
//! capability today and locks the gap-list in for follow-up.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("receiver_type");
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
fn receiver_type_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== receiver-type audit ===");
    eprintln!("{:<11} {:>9}  {:<22}  status", "lang", "findings", "expected");
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass",
            Expected::KnownAdapterGap(_) => "KnownAdapterGap",
        };
        let status: &str = if r.skipped.is_some() {
            match expected {
                Expected::Pass => "REGRESSION: fixture missing",
                Expected::KnownAdapterGap(_) => "fixture removed; restore",
            }
        } else if r.findings == 0 {
            match expected {
                Expected::Pass => "REGRESSION: expected Pass, got 0",
                Expected::KnownAdapterGap(_) => "still gapped (locked-in)",
            }
        } else {
            match expected {
                Expected::Pass => "ok",
                Expected::KnownAdapterGap(_) => "GAP CLOSED — flip to Pass",
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
        let mut msg = String::from("receiver-type audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}
