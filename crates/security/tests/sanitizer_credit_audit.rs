//! Sanitizer-credit audit — verifies that taint passing through
//! a recognized sanitizer call is still reported with `status:
//! sanitized`, not silently dropped from the graph.
//!
//! Each fixture under `examples/<lang>/sanitizer_credit/` has:
//!
//!   `unsanitized()` — source -> sink directly. Engine MUST report
//!                     with unsanitized status.
//!   `sanitized()`   — source -> sanitizer() -> sink. Engine MAY
//!                     report, but if it does the status MUST be
//!                     sanitized when the sanitizer credits the sink.
//!
//! Per `docs/contributing/taint-engine-spec.mdx`, sanitizers are reporting
//! evidence, not propagation blockers. This audit exercises the
//! reporting credit on a per-language sample.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut starts = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))];
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    for start in starts {
        for dir in start.ancestors() {
            if dir.join("examples").is_dir() && dir.join("security-patterns").is_dir() {
                return dir.to_path_buf();
            }
        }
    }
    panic!("repo root")
}

fn fixture_root(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join("examples").join(lang).join("sanitizer_credit");
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
    WrongContext,
    #[allow(dead_code)]
    Pending,
}

const LANG_TABLE: &[(&str, Expected)] = &[
    ("c", Expected::Pass),
    ("cpp", Expected::Pass),
    ("csharp", Expected::WrongContext),
    ("dart", Expected::Pass),
    ("elixir", Expected::Pass),
    ("erlang", Expected::Pass),
    ("go", Expected::Pass),
    ("java", Expected::WrongContext),
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
    bonsai_security::run_taint_analysis(
        &ws,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            show_sanitized: true,
            ..Default::default()
        },
    )
    .map_err(|e| format!("taint_analysis: {e}"))
}

#[derive(Debug)]
struct Result_ {
    lang: &'static str,
    skipped: Option<String>,
    findings: usize,
    unsanitized_fired: bool,
    sanitized_statuses: Vec<bonsai_security::FindingStatus>,
}

fn audit_one(lang: &'static str) -> Result_ {
    let report = match run_taint_for(lang) {
        Ok(r) => r,
        Err(reason) => {
            return Result_ {
                lang,
                skipped: Some(reason),
                findings: 0,
                unsanitized_fired: false,
                sanitized_statuses: Vec::new(),
            }
        }
    };
    let unsanitized_fired = report.findings.iter().any(|f| {
        f.finding
            .chain_display
            .iter()
            .any(|hop| hop.to_ascii_lowercase().contains("unsanitized"))
    });
    // Detect the sanitized leg by chain entry name containing
    // "sanitized" but not "unsanitized".
    let sanitized_statuses = report
        .findings
        .iter()
        .filter_map(|f| {
            let is_sanitized_leg = f.finding.chain_display.iter().any(|hop| {
                let lower = hop.to_ascii_lowercase();
                lower.contains("sanitized") && !lower.contains("unsanitized")
            });
            is_sanitized_leg.then_some(f.finding.status)
        })
        .collect();
    Result_ {
        lang,
        skipped: None,
        findings: report.findings.len(),
        unsanitized_fired,
        sanitized_statuses,
    }
}

#[test]
fn sanitizer_credit_audit_per_language() {
    let results: Vec<_> = LANG_TABLE
        .iter()
        .copied()
        .map(|(lang, expected)| (audit_one(lang), expected))
        .collect();

    eprintln!("\n=== sanitizer-credit audit ===");
    eprintln!(
        "{:<11} {:>9} {:>10} {:>10}  {:<22}  status",
        "lang", "findings", "raw?", "san?", "expected"
    );
    for (r, expected) in &results {
        let exp = match expected {
            Expected::Pass => "Pass",
            Expected::WrongContext => "WrongContext",
            Expected::Pending => "Pending",
        };
        let status = if matches!(expected, Expected::Pending) {
            "skipped (pending)"
        } else if r.skipped.is_some() {
            "fixture missing"
        } else {
            let sanitized_has_bad_status = r
                .sanitized_statuses
                .iter()
                .any(|status| *status != bonsai_security::FindingStatus::Sanitized);
            match (expected, r.unsanitized_fired, sanitized_has_bad_status) {
                (Expected::Pass, true, false) => "ok",
                (Expected::Pass, false, _) => "REGRESSION: unsanitized leg missing",
                (Expected::Pass, _, true) => "REGRESSION: sanitized leg wrong status",
                (Expected::WrongContext, false, _) => "REGRESSION: unsanitized leg missing",
                (Expected::WrongContext, true, _) if r.sanitized_statuses.is_empty() => {
                    "REGRESSION: wrong-context leg missing"
                }
                (Expected::WrongContext, true, _) => {
                    let all_wrong_context = r
                        .sanitized_statuses
                        .iter()
                        .all(|status| *status == bonsai_security::FindingStatus::WrongContext);
                    if all_wrong_context {
                        "ok"
                    } else {
                        "REGRESSION: wrong-context leg credited"
                    }
                }
                (Expected::Pending, _, _) => unreachable!(),
            }
        };
        eprintln!(
            "{:<11} {:>9} {:>10} {:>10}  {:<22}  {status}",
            r.lang,
            r.findings,
            if r.unsanitized_fired { "yes" } else { "no" },
            if r.sanitized_statuses.is_empty() {
                "no"
            } else {
                "yes"
            },
            exp
        );
    }

    let regressions: Vec<String> = results
        .iter()
        .filter_map(|(r, expected)| match expected {
            Expected::Pending => None,
            Expected::Pass => {
                if r.skipped.is_some() {
                    Some(format!("{}: fixture missing", r.lang))
                } else if !r.unsanitized_fired {
                    Some(format!("{}: unsanitized leg missing", r.lang))
                } else {
                    r.sanitized_statuses
                        .iter()
                        .find(|status| **status != bonsai_security::FindingStatus::Sanitized)
                        .map(|status| {
                            format!(
                                "{}: sanitized leg reported with {} status",
                                r.lang,
                                status.as_str()
                            )
                        })
                }
            }
            Expected::WrongContext => {
                if r.skipped.is_some() {
                    Some(format!("{}: fixture missing", r.lang))
                } else if !r.unsanitized_fired {
                    Some(format!("{}: unsanitized leg missing", r.lang))
                } else if r.sanitized_statuses.is_empty() {
                    Some(format!("{}: wrong-context sanitizer leg missing", r.lang))
                } else {
                    r.sanitized_statuses
                        .iter()
                        .find(|status| **status != bonsai_security::FindingStatus::WrongContext)
                        .map(|status| {
                            format!(
                                "{}: wrong-context sanitizer leg reported with {} status",
                                r.lang,
                                status.as_str()
                            )
                        })
                }
            }
        })
        .collect();

    if !regressions.is_empty() {
        let mut msg = String::from("sanitizer-credit audit drift:\n");
        for r in &regressions {
            msg.push_str("  ");
            msg.push_str(r);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

#[test]
fn java_and_csharp_html_encoders_credit_xss_sinks() {
    for lang in ["java", "csharp"] {
        let report = run_taint_for(lang).unwrap_or_else(|err| panic!("{lang}: {err}"));
        let encoded_statuses: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| {
                finding
                    .finding
                    .chain_display
                    .iter()
                    .any(|hop| hop.to_ascii_lowercase().replace('_', "").contains("encodedxss"))
            })
            .map(|finding| {
                (
                    finding.finding.status,
                    finding
                        .finding
                        .sanitizers_seen
                        .iter()
                        .map(|sanitizer| sanitizer.rule_id.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        assert!(
            !encoded_statuses.is_empty(),
            "{lang}: expected encoded XSS fixture to produce a sanitizer-credit finding"
        );
        assert!(
            encoded_statuses
                .iter()
                .all(|(status, _)| *status == bonsai_security::FindingStatus::Sanitized),
            "{lang}: encoded XSS fixture should be sanitized, got {encoded_statuses:?}"
        );
        assert!(
            encoded_statuses
                .iter()
                .all(|(_, sanitizers)| !sanitizers.is_empty()),
            "{lang}: encoded XSS fixture should carry sanitizer evidence, got {encoded_statuses:?}"
        );
    }
}
