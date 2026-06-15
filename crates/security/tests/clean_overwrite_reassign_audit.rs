//! Regression audit for the same-function clean-overwrite filter.
//!
//! `same_function_clean_overwrite_kills_sink_arg` suppresses a sink
//! finding when the tainted argument was cleanly overwritten between
//! the source and the sink — the canonical
//! `x = source(); x = "const"; sink(x)` false positive.
//!
//! That suppression must only fire when the clean overwrite is the
//! LAST write to the variable before the sink. A clean overwrite that
//! is itself superseded by a later (re-tainting) write of the same
//! variable does NOT kill the flow — the IDG closure already proved
//! the live value reaches the sink. Two shapes regressed before the
//! fix and are pinned here:
//!
//!   * clean-before-taint:   `cmd = ""; cmd = user; sink(cmd)`
//!   * conditional re-taint: `cmd = ""; if c { cmd = user }; sink(cmd)`
//!
//! while the legitimate clean-after-taint suppression is preserved.

use bonsai_lang_api::LanguageRegistry;
use bonsai_security::{load_rulepack, run_taint_analysis, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::PathBuf;
use std::sync::Arc;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn python_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn os_system_findings(source: &str) -> usize {
    let pack = load_rulepack(&repo_root().join("security-patterns")).expect("rulepack loads");
    let ws = python_ws(source);
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    report
        .findings
        .iter()
        .filter(|f| f.finding.sink.text.contains("os.system") || f.finding.sink.rule_id.contains("cmdi"))
        .count()
}

#[test]
fn clean_literal_then_retaint_still_reaches_sink() {
    // `cmd = "echo"` is a clean string-literal overwrite, but the very
    // next statement re-taints `cmd` from the request-derived param,
    // so the os.system sink is genuinely tainted.
    let findings = os_system_findings(
        r#"
import os
def handler(name):
    cmd = "echo"
    cmd = name
    os.system(cmd)
"#,
    );
    assert!(
        findings >= 1,
        "clean-literal-then-retaint must reach the sink (clean overwrite is superseded), got {findings}"
    );
}

#[test]
fn conditional_retaint_after_clean_init_reaches_sink() {
    // `cmd = ""` initialises clean, then a conditional re-taints it.
    // The taint is live on the then-branch, so the sink is reachable.
    let findings = os_system_findings(
        r#"
import os
def handler(name, flag):
    cmd = ""
    if flag:
        cmd = name
    os.system(cmd)
"#,
    );
    assert!(
        findings >= 1,
        "conditional re-taint after a clean init must reach the sink, got {findings}"
    );
}

#[test]
fn clean_overwrite_after_taint_is_still_suppressed() {
    // The canonical false positive: taint is overwritten by a clean
    // constant before the sink. The clean overwrite IS the last write,
    // so the suppression must still fire.
    let findings = os_system_findings(
        r#"
import os
def handler(name):
    cmd = name
    cmd = "safe"
    os.system(cmd)
"#,
    );
    assert_eq!(
        findings, 0,
        "clean overwrite after taint (last write is clean) must remain suppressed, got {findings}"
    );
}

#[test]
fn all_clean_chain_stays_suppressed() {
    // A chain of clean overwrites never taints the variable; the last
    // write is clean so the sink must not fire.
    let findings = os_system_findings(
        r#"
import os
def handler(name):
    cmd = 0
    cmd = "1"
    os.system(cmd)
"#,
    );
    assert_eq!(
        findings, 0,
        "all-clean overwrite chain must not fire, got {findings}"
    );
}
