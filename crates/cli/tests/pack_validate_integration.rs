//! CLI-level `security pack --validate` coverage for fixture rulepacks.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    let debug = repo_root().join("target/debug/bonsai-ninja");
    if debug.exists() {
        return Some(debug);
    }
    let release = repo_root().join("target/release/bonsai-ninja");
    if release.exists() {
        return Some(release);
    }
    None
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let base = std::env::temp_dir();
        for attempt in 0..100 {
            let path = base.join(format!(
                "bonsai-pack-validate-{tag}-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create temp dir {}: {err}", path.display()),
            }
        }
        panic!("could not allocate temp dir under {}", base.display());
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_python_sink_pack(root: &Path, yaml: &str) {
    let sinks = root.join("langs/python/sinks");
    std::fs::create_dir_all(&sinks).expect("create sinks dir");
    std::fs::write(sinks.join("fixture.yml"), yaml).expect("write fixture pack");
}

fn run_pack_validate(rules_dir: &Path) -> Option<Output> {
    let bin = bin_path()?;
    let workspace = repo_root().join("examples/python/micro");
    Some(
        Command::new(bin)
            .args([
                "security",
                workspace.to_str().expect("workspace path"),
                "pack",
                "--rules-dir",
                rules_dir.to_str().expect("rules dir path"),
                "--validate",
                "--format",
                "json",
                "--no-color",
            ])
            .env("COLUMNS", "200")
            .output()
            .expect("run bonsai-ninja"),
    )
}

fn parse_stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn pack_validate_json_reports_broken_regex_rulepack() {
    let tmp = TempDir::new("broken-regex");
    write_python_sink_pack(
        tmp.path(),
        r#"
- id: python.sqli.invalid_regex_fixture
  enabled: false
  disabled_reason:
    code: over-broad
  language: python
  tag: sql-injection
  severity: high
  cwe: [CWE-89]
  match:
    kind: call
    callee:
      regex: "^(execute"
  constraints:
    - any_arg_matches_regex: "["
  description: Disabled invalid regex fixture.
"#,
    );

    let Some(output) = run_pack_validate(tmp.path()) else {
        return;
    };
    assert!(
        !output.status.success(),
        "broken rulepack validation should exit non-zero"
    );

    let report = parse_stdout_json(&output);
    assert_eq!(report["valid"], false);
    assert_eq!(report["errors"], 2);
    let issues = report["issues"].as_array().expect("issues array");
    let regex_issues: Vec<_> = issues
        .iter()
        .filter(|issue| issue["code"] == "match-example-regex-invalid")
        .collect();
    assert_eq!(
        regex_issues.len(),
        2,
        "expected target and constraint regex issues, got {issues:#?}"
    );
}

#[test]
fn pack_validate_json_accepts_clean_rulepack() {
    let tmp = TempDir::new("clean");
    write_python_sink_pack(
        tmp.path(),
        r#"
- id: python.cmdi.clean_disabled_fixture
  enabled: false
  disabled_reason:
    code: over-broad
  language: python
  tag: command-injection
  severity: high
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      name: system
  description: Disabled clean fixture.
"#,
    );

    let Some(output) = run_pack_validate(tmp.path()) else {
        return;
    };
    assert!(
        output.status.success(),
        "clean rulepack validation failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_json(&output);
    assert_eq!(report["valid"], true);
    assert_eq!(report["errors"], 0);
    assert!(report["issues"].as_array().expect("issues array").is_empty());
}

#[test]
fn bundled_rulepack_is_the_out_of_directory_default() {
    let Some(bin) = bin_path() else {
        return;
    };
    let tmp = TempDir::new("bundled-default");
    let workspace = tmp.path().join("workspace");
    let unrelated_cwd = tmp.path().join("cwd");
    std::fs::create_dir(&workspace).expect("create workspace");
    std::fs::create_dir(&unrelated_cwd).expect("create unrelated cwd");
    std::fs::write(workspace.join("app.py"), "def main():\n    return 0\n").expect("write source");

    let output = Command::new(&bin)
        .current_dir(&unrelated_cwd)
        .env_remove("BONSAI_RULES_DIR")
        .args([
            "security",
            workspace.to_str().expect("workspace path"),
            "pack",
            "--lang",
            "python",
            "--limit",
            "3",
            "--format",
            "json",
            "--no-color",
            "--no-progress",
        ])
        .output()
        .expect("run with bundled rulepack");
    assert!(
        output.status.success(),
        "bundled rulepack failed outside the source tree\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_json(&output);
    let rows = report["rows"].as_array().expect("pack rows");
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| row["language"] == "python"));
}

#[test]
fn invalid_explicit_rulepack_does_not_fall_back_to_the_bundle() {
    let Some(bin) = bin_path() else {
        return;
    };
    let tmp = TempDir::new("invalid-explicit");
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir(&workspace).expect("create workspace");
    std::fs::write(workspace.join("app.py"), "pass\n").expect("write source");
    let missing = tmp.path().join("missing-rules");

    let output = Command::new(&bin)
        .current_dir(tmp.path())
        .env_remove("BONSAI_RULES_DIR")
        .args([
            "security",
            workspace.to_str().expect("workspace path"),
            "pack",
            "--rules-dir",
            missing.to_str().expect("missing path"),
            "--format",
            "json",
            "--no-color",
            "--no-progress",
        ])
        .output()
        .expect("run with invalid explicit rulepack");
    assert!(!output.status.success(), "invalid explicit path must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rulepack load failed") && stderr.contains("missing-rules"),
        "explicit-path error should identify the failed rulepack:\n{stderr}"
    );
}
