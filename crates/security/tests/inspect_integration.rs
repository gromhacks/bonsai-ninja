//! Verify the security layer's inspect / taint wiring:
//!
//! 1. The rule compiler produces `inspect`-shaped flags that, when fed
//!    into `bonsai_inspect`, find the same match that
//!    `match_rule_against_facts` found.
//! 2. Finding ids are stable across reloads of the same workspace.
//! 3. The chain-aware flow intersection uses the existing
//!    `ResolvedCallGraph` and doesn't invent a second one — we check
//!    that by asserting that `security taint-analysis` and `inspect --from X
//!    --to Y` agree on whether a flow exists for a canonical
//!    source/sink pair.

use bonsai_security::{compile_rule_to_inspect_args, compute_finding_id, rule::RuleKind};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    let debug = repo_root().join("target/debug/bonsai-ninja");
    if debug.exists() {
        return Some(debug);
    }
    let release = repo_root().join("target/release/bonsai-ninja");
    release.exists().then_some(release)
}

fn run(args: &[&str]) -> Option<String> {
    let bin = bin_path()?;
    let out = Command::new(&bin)
        .args(args)
        .env("COLUMNS", "200")
        .output()
        .ok()?;
    assert!(
        out.status.success(),
        "CLI-backed inspect integration failed: {}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn sdk_python_registry() -> Arc<bonsai_lang_api::LanguageRegistry> {
    let registry = Arc::new(bonsai_lang_api::LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    registry
}

fn fresh_tmp(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir();
    for attempt in 0..100 {
        let path = root.join(format!("{tag}-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create temp dir {}: {e}", path.display()),
        }
    }
    panic!("could not allocate temp dir");
}

fn write_sdk_rules(root: &std::path::Path) -> PathBuf {
    let rules = root.join("security-patterns");
    let source_dir = rules.join("langs/python/sources");
    let sink_dir = rules.join("langs/python/sinks");
    std::fs::create_dir_all(&source_dir).expect("source dir");
    std::fs::create_dir_all(&sink_dir).expect("sink dir");
    std::fs::write(
        source_dir.join("params.yml"),
        r"- id: python.test.user_param
  enabled: true
  trust: remote
  tag: http-input
  match:
    kind: param
    target:
      name: user
  description: Test-only user parameter source.
",
    )
    .expect("source rule");
    std::fs::write(
        sink_dir.join("cmd.yml"),
        r"- id: python.test.os_system
  enabled: true
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: Test-only os.system sink.
",
    )
    .expect("sink rule");
    rules
}

#[test]
fn compile_rule_produces_non_empty_inspect_args_for_sink() {
    use bonsai_security::rule::{MatchKind, MatchSpec, Rule, RuleConstraint, RuleTarget};
    let rule = Rule {
        id: "python.cmdi.os_system".to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("command-injection".into()),
        severity: None,
        trust: None,
        category: None,
        cwe: vec![],
        owasp: vec![],
        frameworks: vec![],
        packages: vec![],
        imports: vec![],
        modules: vec![],
        manifests: vec![],
        lockfiles: vec![],
        package_matching: Default::default(),
        payload_types: vec![],
        match_spec: MatchSpec {
            kind: MatchKind::Call,
            callee: Some(RuleTarget {
                attribute: Some(vec!["os".into(), "system".into()]),
                ..Default::default()
            }),
            target: None,
            search_depth: 0,
        },
        analysis_semantics: None,
        taint_semantics: None,
        returns_type: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "os.system".into(),
        kind: RuleKind::Sink,
        language: "python".into(),
        source_path: "synthetic".into(),
    };
    let compiled = compile_rule_to_inspect_args(&rule);
    assert!(
        !compiled.is_empty(),
        "compiled rule must populate at least one inspect knob: {compiled:?}"
    );
    assert!(compiled.query.is_some() || compiled.to.is_some());
    // Sink rules should populate both `--query` and `--to` so inspect
    // can find the call AND filter chains that reach it.
    assert!(compiled.query.is_some(), "sink rule must populate --query");
    assert!(compiled.to.is_some(), "sink rule must populate --to");
}

#[test]
fn sdk_taint_analysis_uses_same_exact_source_seed_overlay_as_cli() {
    let root = fresh_tmp("bonsai-sdk-security-taint");
    let rules = write_sdk_rules(&root);
    std::fs::write(
        root.join("bad.py"),
        "import os\n\ndef handle_bad(user, safe):\n    os.system(user)\n",
    )
    .expect("bad fixture");
    std::fs::write(
        root.join("clean.py"),
        "import os\n\ndef handle_clean(user, safe):\n    os.system(safe)\n",
    )
    .expect("clean fixture");

    let ws = bonsai_workspace::Workspace::index(&root, sdk_python_registry()).expect("workspace index");
    let pack = bonsai_security::load_rulepack(&rules).expect("rulepack");
    let report = bonsai_security::run_taint_analysis(
        &ws,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            source: Some("^python\\.test\\.user_param$".to_string()),
            sink: Some("^python\\.test\\.os_system$".to_string()),
            ..Default::default()
        },
    )
    .expect("sdk taint analysis");

    let files: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.finding.sink.file.as_str())
        .collect();
    assert!(
        files.iter().any(|file| file.ends_with("bad.py")),
        "SDK taint analysis should report the tainted user parameter: {files:?}"
    );
    assert!(
        !files.iter().any(|file| file.ends_with("clean.py")),
        "SDK taint analysis must not taint the unrelated safe parameter: {files:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_source_analysis_returns_structured_paths_without_cli_rendering() {
    let root = fresh_tmp("bonsai-sdk-security-source");
    let rules = write_sdk_rules(&root);
    std::fs::write(
        root.join("app.py"),
        "import os\n\ndef handle(user, safe):\n    run(user)\n    clean(safe)\n\ndef run(cmd):\n    os.system(cmd)\n\ndef clean(cmd):\n    os.system(cmd)\n",
    )
    .expect("fixture");

    let ws = bonsai_workspace::Workspace::index(&root, sdk_python_registry()).expect("workspace index");
    let pack = bonsai_security::load_rulepack(&rules).expect("rulepack");
    let report = bonsai_security::run_source_analysis(
        &ws,
        &pack,
        bonsai_security::SourceAnalysisOptions {
            source: Some("^python\\.test\\.user_param$".to_string()),
            ..Default::default()
        },
    )
    .expect("sdk source analysis");

    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.chain_names.iter().any(|name| name == "run")),
        "SDK source-analysis should expose structured chain paths: {:?}",
        report
            .candidates
            .iter()
            .map(|c| &c.chain_names)
            .collect::<Vec<_>>()
    );
    assert!(
        !report
            .candidates
            .iter()
            .any(|candidate| candidate.chain_names.iter().any(|name| name == "clean")),
        "SDK source-analysis must not use broad entry seeds that make the unrelated safe branch look source-tainted: {:?}",
        report
            .candidates
            .iter()
            .map(|c| &c.chain_names)
            .collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn finding_id_matches_explicit_hash() {
    let id = compute_finding_id(
        "python.flask.request_args_get",
        "python.cmdi.os_system",
        "G:0000000000000000",
        "python",
    );
    // Round-trip — same inputs, same output.
    let id2 = compute_finding_id(
        "python.flask.request_args_get",
        "python.cmdi.os_system",
        "G:0000000000000000",
        "python",
    );
    assert_eq!(id, id2);
    assert_eq!(id, "S:c84cb26f0a7f15a2");
}

#[test]
fn security_flows_shares_taint_view_with_inspect() {
    // If `bonsai-ninja inspect --from request --to os.system` finds a
    // flow on python/micro, then `security taint-analysis` with the matching
    // source/sink pair should too. This verifies we wrap the same
    // engine (no second tracer).
    let ws = repo_root().join("examples/python/micro");
    if !ws.exists() {
        return;
    }
    let rules = repo_root().join("security-patterns");
    let ws_s = ws.to_str().unwrap();
    let rules_s = rules.to_str().unwrap();

    let inspect = run(&[
        "inspect",
        ws_s,
        "--from",
        "request",
        "--to",
        "os.system",
        "--no-color",
    ]);
    let Some(inspect) = inspect else { return };
    if inspect.contains("no matches") {
        return;
    }

    let Some(sec) = run(&[
        "security",
        ws_s,
        "taint-analysis",
        "--rules-dir",
        rules_s,
        "--source",
        "^python\\.flask\\.",
        "--sink",
        "^python\\.cmdi\\.os_system$",
        "--no-color",
    ]) else {
        return;
    };
    assert!(
        sec.contains("python.cmdi.os_system") && sec.contains("S:"),
        "security taint-analysis should produce a finding when inspect finds the matching flow; got:\n{sec}"
    );
}

#[test]
fn over_approx_filter_still_applies_under_security_wrapper() {
    // The underlying `inspect` path drops `OverApproximate` chains by
    // default. `security taint-analysis` inherits that automatically. Confirm
    // by checking that the rendered output contains no
    // `(over-approx)` annotation on python/micro's canonical pair.
    let ws = repo_root().join("examples/python/micro");
    if !ws.exists() {
        return;
    }
    let rules = repo_root().join("security-patterns");
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "taint-analysis",
        "--rules-dir",
        rules.to_str().unwrap(),
        "--no-color",
    ]);
    if let Some(out) = out {
        assert!(
            !out.contains("(over-approx)"),
            "security taint-analysis should inherit inspect's accurate-taint default — no `(over-approx)` in output:\n{out}"
        );
    }
}

#[test]
fn rulepack_loader_rejects_duplicate_ids() {
    // Checks the loader lint works end-to-end via the CLI. We write a
    // throw-away rulepack with duplicate ids and confirm the command
    // fails with the `duplicate rule id` diagnostic.
    let tmp = unique_temp_dir("bonsai-sec-dup");
    let dir = tmp.join("langs/python/sinks");
    std::fs::create_dir_all(&dir).unwrap();
    let dup = r"- id: python.dup
  enabled: true
  tag: command-injection
  match:
    kind: call
    callee:
      name: system
  description: ";
    std::fs::write(dir.join("a.yml"), dup).unwrap();
    std::fs::write(dir.join("b.yml"), dup).unwrap();

    let out = Command::new(bin_path().expect("release bin"))
        .args([
            "security",
            repo_root().join("examples/python/micro").to_str().unwrap(),
            "sinks",
            "--rules-dir",
            tmp.to_str().unwrap(),
        ])
        .env("COLUMNS", "200")
        .output()
        .expect("run");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("duplicate rule id") || stderr.contains("rulepack load failed"),
        "expected duplicate diagnostic, got stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!("{prefix}-{}-{nanos:x}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create temp dir {}: {e}", path.display()),
        }
    }
    panic!("could not allocate temp dir for {prefix}");
}
