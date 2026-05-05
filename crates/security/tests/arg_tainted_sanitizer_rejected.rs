use bonsai_security::{load_rulepack, validate_pack, PackInventoryOptions};
use std::path::{Path, PathBuf};

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn sanitizer_rule_cannot_use_arg_tainted() {
    let tmp = TempDir::new();
    write(
        &tmp.path().join("langs/python/sanitizers/all.yml"),
        r#"- id: python.sanitizer.bad_arg_tainted
  enabled: true
  language: python
  tag: shell-escape
  match:
    kind: call
    callee:
      attribute: [shlex, quote]
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: positive
    code: |
      import shlex
      def example(user_input):
          return shlex.quote(user_input)
  - name: negative
    code: |
      import shlex
      def example():
          return shlex.quote("safe")
    expect_no_match: true
  description: Invalid sanitizer rule using arg_tainted.
"#,
    );

    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let report = validate_pack(
        &pack,
        &PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "arg-tainted-in-sanitizer"),
        "{:#?}",
        report.issues
    );
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bonsai-arg-tainted-sanitizer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
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
