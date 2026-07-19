//! Behavior tests for `validate_pack`'s `taint_replay_examples` mode —
//! the deep example-replay gate that seeds each taint-dependent rule's
//! positive `match_examples` through live taint analysis and reports the
//! ones whose own example no longer fires (`match-example-taint-miss`).
//!
//! The default (fast) validate path deliberately skips taint-dependent
//! examples; these tests pin both the skip and the opt-in replay so a
//! silently-broken taint rule can't ship undetected when the gate runs.

use bonsai_security::{load_rulepack, validate_pack, PackInventoryOptions};
use std::path::{Path, PathBuf};

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn validate(root: &Path, taint_replay: bool) -> bonsai_security::PackValidationReport {
    let pack = load_rulepack(root).expect("rulepack loads");
    validate_pack(
        &pack,
        &PackInventoryOptions {
            taint_replay_examples: taint_replay,
            ..PackInventoryOptions::default()
        },
        bonsai_adapters::all_languages_registry(),
    )
}

fn taint_miss_ids(report: &bonsai_security::PackValidationReport) -> Vec<String> {
    report
        .issues
        .iter()
        .filter(|issue| issue.code == "match-example-taint-miss")
        .filter_map(|issue| issue.rule_id.clone())
        .collect()
}

/// `arg_tainted` rule whose positive example flows a function parameter
/// (an inferred source) into the sink. Both a `--validate` schema pass
/// and the deep taint replay must accept it.
const FIRES: &str = r#"- id: python.test.tainted_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [os, system]
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: positive tainted arg
    code: |
      import os
      def example(user_input):
          os.system(user_input)
  - name: negative literal arg
    code: |
      import os
      def example():
          os.system("ls")
    expect_no_match: true
  description: os.system with a tainted first argument.
"#;

/// Same rule shape, but its positive example passes a string literal —
/// `arg_tainted` can never fire, so the example is silently broken.
const NONFIRING: &str = r#"- id: python.test.tainted_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      attribute: [os, system]
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: positive but untainted
    code: |
      import os
      def example():
          os.system("ls")
  - name: negative literal arg
    code: |
      import os
      def example():
          os.system("rm -rf /")
    expect_no_match: true
  description: os.system whose positive example is not actually tainted.
"#;

/// A field-sensitive object literal passed as one whole external-call
/// argument. The exact field writers are evidence for `arg_tainted`, but the
/// object must not become a scalar bridge that would taint sibling fields in
/// a resolved local callee.
const JAVASCRIPT_AGGREGATE_FIRES: &str = r#"- id: javascript.test.send_mail
  enabled: true
  language: javascript
  tag: smtp-injection
  severity: medium
  packages: [nodemailer]
  imports: [nodemailer]
  cwe: [CWE-93]
  match:
    kind: call
    callee:
      attribute: [transporter, sendMail]
  constraints:
  - arg_tainted:
      index: 0
  match_examples:
  - name: tainted object field
    code: |
      const nodemailer = require("nodemailer");
      function handle(input) {
        const transporter = nodemailer.createTransport({});
        const opts = {from: "a@x", to: input, subject: input};
        return transporter.sendMail(opts);
      }
    expect_match_text: [transporter.sendMail]
  description: external whole-object consumer observes exact tainted fields.
"#;

#[test]
fn taint_replay_accepts_firing_example() {
    let tmp = TempDir::new("replay-fires");
    write(&tmp.path().join("langs/python/sinks/cmdi.yml"), FIRES);
    let report = validate(tmp.path(), true);
    assert!(
        !taint_miss_ids(&report).contains(&"python.test.tainted_system".to_string()),
        "a rule whose example genuinely flows taint must not be reported as a taint-miss: {:#?}",
        report.issues
    );
}

#[test]
fn taint_replay_flags_nonfiring_example() {
    let tmp = TempDir::new("replay-broken");
    write(&tmp.path().join("langs/python/sinks/cmdi.yml"), NONFIRING);
    let report = validate(tmp.path(), true);
    assert!(
        taint_miss_ids(&report).contains(&"python.test.tainted_system".to_string()),
        "a taint-dependent rule whose own positive example cannot fire must be reported \
         as match-example-taint-miss: {:#?}",
        report.issues
    );
}

#[test]
fn taint_replay_accepts_tainted_field_in_whole_external_argument() {
    let tmp = TempDir::new("replay-javascript-aggregate");
    write(
        &tmp.path().join("langs/javascript/sinks/smtp.yml"),
        JAVASCRIPT_AGGREGATE_FIRES,
    );
    let report = validate(tmp.path(), true);
    assert!(
        !taint_miss_ids(&report).contains(&"javascript.test.send_mail".to_string()),
        "an exact tainted field consumed by a whole external argument must satisfy replay: {:#?}",
        report.issues
    );
}

#[test]
fn default_validate_skips_taint_examples() {
    // Without the opt-in, the broken example must NOT surface as a
    // taint-miss — the default path stays fast and static-only.
    let tmp = TempDir::new("replay-off");
    write(&tmp.path().join("langs/python/sinks/cmdi.yml"), NONFIRING);
    let report = validate(tmp.path(), false);
    assert!(
        taint_miss_ids(&report).is_empty(),
        "default validate must not run taint replay: {:#?}",
        report.issues
    );
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
                "bonsai-replay-{tag}-{}-{nanos}-{attempt}",
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
