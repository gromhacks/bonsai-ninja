use bonsai_security::{load_rulepack, validate_pack, PackInventoryOptions};
use std::path::{Path, PathBuf};

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn validate(root: &Path) -> bonsai_security::PackValidationReport {
    let pack = load_rulepack(root).expect("rulepack loads");
    validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    )
}

#[test]
fn uncovered_discriminating_constraint_is_rejected() {
    let tmp = TempDir::new("coverage-missing-negative");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.subprocess_shell
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [subprocess, run]
  constraints:
  - keyword_arg_equals:
      name: shell
      value: "True"
  match_examples:
  - name: positive
    code: |
      import subprocess
      def example(user_input):
          return subprocess.run(user_input, shell=True)
  description: subprocess.run shell test rule.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "constraint-not-exercised"),
        "{:#?}",
        report.issues
    );
}

#[test]
fn positive_and_negative_examples_cover_discriminating_constraint() {
    let tmp = TempDir::new("coverage-ok");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.subprocess_shell
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [subprocess, run]
  constraints:
  - keyword_arg_equals:
      name: shell
      value: "True"
  match_examples:
  - name: positive
    code: |
      import subprocess
      def example(user_input):
          return subprocess.run(user_input, shell=True)
  - name: negative
    code: |
      import subprocess
      def example(user_input):
          return subprocess.run(user_input, shell=False)
    expect_no_match: true
  description: subprocess.run shell test rule.
"#,
    );

    let report = validate(tmp.path());
    assert_eq!(report.errors, 0, "{:#?}", report.issues);
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for attempt in 0..100 {
            let path = base.join(format!(
                "bonsai-coverage-{tag}-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            if std::fs::create_dir(&path).is_ok() {
                return Self { path };
            }
        }
        panic!("create temp dir");
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
