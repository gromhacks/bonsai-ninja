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
fn expect_no_match_reports_unexpected_owner_match() {
    let tmp = TempDir::new("negative-unexpected");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [os, system]
  match_examples:
  - name: positive
    code: |
      import os
      def example(user_input):
          return os.system(user_input)
  - name: negative
    code: |
      import os
      def example(user_input):
          return os.system(user_input)
    expect_no_match: true
  description: os.system test rule with a deliberately failing negative.
"#,
    );

    let report = validate(tmp.path());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "match-example-unexpected-match"),
        "{:#?}",
        report.issues
    );
}

#[test]
fn expect_no_match_passes_when_owner_rule_does_not_match() {
    let tmp = TempDir::new("negative-ok");
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r#"- id: python.test.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [os, system]
  match_examples:
  - name: positive
    code: |
      import os
      def example(user_input):
          return os.system(user_input)
  - name: negative
    code: |
      def example(user_input):
          return print(user_input)
    expect_no_match: true
  description: os.system test rule with a passing negative.
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
                "bonsai-validate-{tag}-{}-{nanos}-{attempt}",
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
