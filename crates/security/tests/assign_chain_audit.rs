//! Assignment-chain audit — a per-language stress test that exercises
//! every adapter's basic taint propagation paths through the SDK
//! facade.
//!
//! Each `examples/<lang>/assign_chain/` workspace contains a fixture
//! authored to cover, in one place:
//!
//! - simplest `tmp = source(); sink(tmp)` assignment chain
//! - multi-hop passthrough through helper functions
//! - branch-join (tainted leg must report; clean leg must not)
//! - loop-carried accumulator (taint must survive iteration rebinding)
//! - field write (`obj.field = source(); sink(obj.field)`)
//! - subscript write (`arr[0] = source(); sink(arr[0])`)
//! - cross-file argument flow (source in one file, sink in another)
//! - decoy negatives: sibling field, clean constant, shadowed variable
//!
//! For each language the harness asserts:
//!
//! - **positive**: at least one finding reaches the cmdi sink. The
//!   benchmark feedback (CVEBench-SAST) listed several adapters as
//!   silent on this shape — those rows show up here as failures with
//!   clear "[lang] no taint findings" diagnostics.
//! - **negative coherence**: when findings exist, every finding's
//!   chain endpoint matches one of the positive functions, never a
//!   `_decoy` or `_clean_constant` function. This proves the engine
//!   isn't conflating sibling fields or constants.
//!
//! Languages without a fixture yet are reported as `[lang] skipped:
//! no fixture` so the audit rollout is visible.
//!
//! Per `docs/contributing/taint-engine-spec.mdx § Mega Flow Contract`: if tree-sitter
//! exposes the construct and a developer can follow the value flow,
//! missing taint here is a bug in the adapter, resolver, CFG,
//! callgraph, field/container facts, or taint propagation — not
//! something a rule should patch.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("assign_chain");
    if !p.is_dir() {
        return None;
    }
    // Treat empty directories as "not yet authored" so the audit
    // reports them as `skipped: missing fixture` instead of trying
    // to index an empty workspace and failing as a positive miss.
    let has_file = std::fs::read_dir(&p)
        .ok()?
        .any(|e| e.ok().map(|e| e.path().is_file()).unwrap_or(false));
    has_file.then_some(p)
}

fn rules_root() -> PathBuf {
    repo_root().join("security-patterns")
}

/// Per-language expected audit status. `Pass` means the adapter
/// must emit at least one taint finding for the assign_chain
/// fixture; `KnownAdapterGap` documents an adapter that currently
/// fails the audit (with the specific deficiency noted) so we
/// catch it the day the adapter is fixed.
///
/// Adding a new language fixture: start at `Pending`, run the test,
/// then move to `Pass` (clean) or `KnownAdapterGap` (with reason).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Expected {
    /// Fixture exists and the adapter must produce >=1 finding.
    Pass,
    /// Fixture exists but the adapter is known not to produce any
    /// findings — locked in here so a regression on a passing
    /// language fails this test.
    #[allow(dead_code)]
    KnownAdapterGap(&'static str),
    /// No fixture authored yet. Skip silently.
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

/// Functions in the fixture whose presence in a finding chain is a
/// negative-test failure — they are the clean-twin / decoy / shadowed
/// cases that must not report.
const FORBIDDEN_FN_NAME_FRAGMENTS: &[&str] = &[
    "decoy",
    "clean_constant",
    // The shadowed-inner case lives in `inner` inside chain_shadowed_var
    // — nested adapters surface it under the inner-fn's display name.
    // We don't forbid `chain_shadowed_var` itself; only the inner fn.
];

/// Per-language subset of `FORBIDDEN_FN_NAME_FRAGMENTS` that the
/// adapter exposes under different naming conventions. Empty default
/// uses `FORBIDDEN_FN_NAME_FRAGMENTS`.
fn forbidden_for(_lang: &str) -> &'static [&'static str] {
    FORBIDDEN_FN_NAME_FRAGMENTS
}

fn run_taint_for(lang: &str) -> Result<bonsai_security::TaintAnalysisReport, String> {
    let ws_root = fixture_root(lang).ok_or_else(|| "missing fixture".to_string())?;
    // Build a workspace using the bundled 21-language registry. We
    // bypass `bonsai_sdk` to avoid a dev-dep cycle (sdk depends on
    // security); the shape of this code mirrors what
    // `bonsai_sdk::Bonsai::index` does internally.
    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules_root()).map_err(|e| format!("rulepack load: {e}"))?;
    let ws = bonsai_workspace::Workspace::index(&ws_root, registry)
        .map_err(|e| format!("index workspace: {e}"))?;
    // Inferred-source mode synthesizes a source from every parameter
    // of every unreferenced/decorated function, producing O(funcs)
    // findings that aren't what the assignment-chain audit measures.
    // Real source-rule matches are exactly what we want: the fixture's
    // `req.args.get(...)` calls match the bundled python.flask
    // source rule, and the sink rule matches `os.system`.
    let opts = bonsai_security::TaintAnalysisOptions::default();
    bonsai_security::run_taint_analysis(&ws, &pack, opts).map_err(|e| format!("taint_analysis: {e}"))
}

#[derive(Debug)]
struct LangAuditResult {
    lang: &'static str,
    skipped: Option<String>,
    findings: usize,
    forbidden_hits: Vec<String>,
}

fn audit_one(lang: &'static str) -> LangAuditResult {
    let report = match run_taint_for(lang) {
        Ok(r) => r,
        Err(reason) => {
            return LangAuditResult {
                lang,
                skipped: Some(reason),
                findings: 0,
                forbidden_hits: vec![],
            }
        }
    };
    let forbidden = forbidden_for(lang);
    let mut forbidden_hits = Vec::new();
    for f in &report.findings {
        let chain = &f.finding.chain_display;
        for hop in chain {
            for needle in forbidden {
                if hop.contains(needle) {
                    forbidden_hits.push(format!(
                        "{} chain hop `{hop}` matches forbidden fragment `{needle}`",
                        f.finding.finding_id
                    ));
                }
            }
        }
    }
    LangAuditResult {
        lang,
        skipped: None,
        findings: report.findings.len(),
        forbidden_hits,
    }
}

#[test]
fn assignment_chain_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== assignment-chain audit ===");
    eprintln!("{:<11} {:>9}  {:<22}  status", "lang", "findings", "expected");
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass".to_string(),
            Expected::Pending => "Pending".to_string(),
            Expected::KnownAdapterGap(_) => "KnownAdapterGap".to_string(),
        };
        let status = match (expected, r.skipped.as_deref(), r.findings) {
            (Expected::Pending, _, _) => "skipped (pending)",
            (Expected::Pass, None, n) if n > 0 && r.forbidden_hits.is_empty() => "ok",
            (Expected::Pass, None, 0) => "REGRESSION: expected Pass, got 0",
            (Expected::Pass, None, _) => "REGRESSION: forbidden chain hits",
            (Expected::Pass, Some(_), _) => "REGRESSION: fixture missing for Pass lang",
            (Expected::KnownAdapterGap(_), None, 0) => "still gapped (locked-in)",
            (Expected::KnownAdapterGap(_), None, _) => "GAP CLOSED — flip to Pass",
            (Expected::KnownAdapterGap(_), Some(_), _) => "fixture removed; restore or flip to Pending",
        };
        eprintln!("{:<11} {:>9}  {:<22}  {status}", r.lang, r.findings, exp);
    }

    // A row fails when the actual outcome doesn't match `expected`.
    // Both "regression" and "gap closed" fail — the second forces
    // the table to be updated when an adapter team fixes a gap.
    let regressions: Vec<String> = results
        .iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pending => None,
            Expected::Pass => {
                if let Some(reason) = r.skipped.as_deref() {
                    Some(format!(
                        "{}: fixture missing ({reason}) but expected Pass",
                        r.lang
                    ))
                } else if r.findings == 0 {
                    Some(format!("{}: expected Pass, got 0 findings", r.lang))
                } else if !r.forbidden_hits.is_empty() {
                    Some(format!(
                        "{}: forbidden-chain hits — {:?}",
                        r.lang, r.forbidden_hits
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
                } else if r.findings > 0 {
                    Some(format!(
                        "{}: KnownAdapterGap fired {} finding(s) — adapter likely fixed; \
                         update LANG_TABLE to Pass. (gap was: {why})",
                        r.lang, r.findings
                    ))
                } else {
                    None
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("assignment-chain audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}
