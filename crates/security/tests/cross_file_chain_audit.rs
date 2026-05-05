//! Cross-file argument-flow audit — per-language stress test that
//! every adapter propagates taint across multiple module boundaries.
//!
//! The fixtures under `examples/<lang>/cross_file_chain/` follow this
//! shape:
//!
//!     app.<ext>         reads a tainted value, calls into pipeline
//!     pipeline.<ext>    wraps and forwards to transformer
//!     transformer.<ext> identity-ish transform, calls executor
//!     executor.<ext>    consumes the value at the cmdi sink
//!
//! A passing adapter resolves the call chain across all three
//! file boundaries AND propagates taint through the parameter
//! binding at each cross-file call site, producing one or more
//! findings whose `chain_display` includes the executor function.
//!
//! Per `docs/contributing/taint-engine-spec.mdx § Adapter Contract`: cross-module
//! call resolution and parameter-binding taint propagation belong in
//! the adapter / resolver / callgraph layers — not in rules. This
//! test gives each adapter a deterministic, locked-in audit row.

use rayon::prelude::*;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("cross_file_chain");
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
struct LangAuditResult {
    lang: &'static str,
    skipped: Option<String>,
    findings: usize,
    sink_in_executor: bool,
}

fn audit_one(lang: &'static str) -> LangAuditResult {
    let report = match run_taint_for(lang) {
        Ok(r) => r,
        Err(reason) => {
            return LangAuditResult {
                lang,
                skipped: Some(reason),
                findings: 0,
                sink_in_executor: false,
            }
        }
    };
    // Cross-file pass criterion: at least one finding's sink site is
    // declared in `executor.<ext>` — meaning the engine traced the
    // tainted value through pipeline -> transformer -> executor.
    // Case-insensitive: Java/C# fixtures use `Executor.java` /
    // `Executor.cs`; Lua/Erlang/etc use `executor.lua`.
    let sink_in_executor = report
        .findings
        .par_iter()
        .any(|f| f.finding.sink.file.to_ascii_lowercase().contains("executor"));
    LangAuditResult {
        lang,
        skipped: None,
        findings: report.findings.len(),
        sink_in_executor,
    }
}

#[test]
fn cross_file_chain_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .par_iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== cross-file-chain audit ===");
    eprintln!(
        "{:<11} {:>9} {:>10}  {:<22}  status",
        "lang", "findings", "exec-sink?", "expected"
    );
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass".to_string(),
            Expected::Pending => "Pending".to_string(),
            Expected::KnownAdapterGap(_) => "KnownAdapterGap".to_string(),
        };
        let status = match (expected, r.skipped.as_deref(), r.sink_in_executor) {
            (Expected::Pending, _, _) => "skipped (pending)",
            (Expected::Pass, None, true) => "ok",
            (Expected::Pass, None, false) => "REGRESSION: no executor-sink finding",
            (Expected::Pass, Some(_), _) => "REGRESSION: fixture missing",
            (Expected::KnownAdapterGap(_), None, false) => "still gapped (locked-in)",
            (Expected::KnownAdapterGap(_), None, true) => "GAP CLOSED — flip to Pass",
            (Expected::KnownAdapterGap(_), Some(_), _) => "fixture removed; restore",
        };
        eprintln!(
            "{:<11} {:>9} {:>10}  {:<22}  {status}",
            r.lang,
            r.findings,
            if r.sink_in_executor { "yes" } else { "no" },
            exp
        );
    }

    let regressions: Vec<String> = results
        .par_iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pending => None,
            Expected::Pass => {
                if let Some(reason) = r.skipped.as_deref() {
                    Some(format!("{}: fixture missing ({reason})", r.lang))
                } else if !r.sink_in_executor {
                    Some(format!(
                        "{}: expected Pass, no finding sinks in executor file (findings={})",
                        r.lang, r.findings
                    ))
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
                } else if r.sink_in_executor {
                    Some(format!(
                        "{}: KnownAdapterGap fired executor-sink finding — adapter likely fixed; \
                         flip to Pass. (gap was: {why})",
                        r.lang
                    ))
                } else {
                    None
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("cross-file-chain audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}
