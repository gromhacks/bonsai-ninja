//! End-to-end completion contract for compiler-proven C preprocessor recovery.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("bonsai-c-preprocessor-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent");
    }
    fs::write(path, contents).expect("fixture file");
}

#[test]
fn c_branch_free_preprocessor_recovery_keeps_security_analysis_complete() {
    let workspace = TempDir::new();
    let rules = TempDir::new();
    write(
        workspace.path(),
        "unit.c",
        r#"int process(int required
#if WITH_OPTIONAL_CONTEXT
    , int optional
#endif
) {
    int value = origin();
    if (required && optional) {
        consume(value);
    }
    return value;
}
"#,
    );
    write(rules.path(), "VERSION", "test\n");
    write(rules.path(), "metadata.yml", "profiles: {}\n");
    write(
        rules.path(),
        "langs/c/sources/test.yml",
        r#"- id: c.test.origin
  enabled: true
  language: c
  trust: remote
  tag: test-input
  match:
    kind: call
    callee:
      name: origin
  description: Test-only call-result source.
"#,
    );
    write(
        rules.path(),
        "langs/c/sinks/test.yml",
        r#"- id: c.test.consume
  enabled: true
  language: c
  tag: test-sink
  severity: high
  match:
    kind: call
    callee:
      name: consume
  constraints:
    - arg_tainted:
        index: 0
  description: Test-only tainted-value sink.
"#,
    );

    let cache = TempDir::new();
    let output = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"))
        .arg("--no-progress")
        .arg("security")
        .arg(workspace.path())
        .args([
            "taint-analysis",
            "--rules-dir",
            rules.path().to_str().expect("rules path"),
            "--format",
            "json",
            "--all",
            "--no-color",
        ])
        .env("BONSAI_WORKSPACE_DIR", cache.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run security analysis");
    assert!(
        output.status.success(),
        "security command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("security JSON");
    assert_eq!(value["analysis_complete"].as_bool(), Some(true), "{value:#}");
    assert!(
        value["analysis_incomplete_reasons"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "{value:#}"
    );
    let rendered = serde_json::to_string(&value).expect("render JSON");
    assert!(rendered.contains("c.test.consume"), "{value:#}");
}
