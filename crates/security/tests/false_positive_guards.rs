//! Negative / false-positive-guard tests for rulepacks.
//!
//! These fixtures verify rulepack-level false-positive guards for broad
//! sink/source names and constrained sink rules.

use bonsai_security::{load_rulepack, ConstraintKind};

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|p| p.join("security-patterns").exists() && p.join("crates").exists())
        .map(std::path::Path::to_path_buf)
        .expect("repo root")
}

fn tempdir() -> TempDir {
    TempDir::new()
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for attempt in 0..100 {
            let path = base.join(format!(
                "bonsai-security-fp-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create temp dir {}: {err}", path.display()),
            }
        }
        panic!("create unique temp dir under {}", base.display());
    }
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn ubiquitous_sink_without_constraint_loads() {
    for name in &[
        "print",
        "println",
        "log",
        "echo",
        "puts",
        "console.log",
        "fmt.Println",
    ] {
        let tmp = tempdir();
        write(
            &tmp.path().join("langs/x/sinks/bad.yml"),
            &format!(
                r"- id: x.broad.{name}
  enabled: true
  tag: xss
  match:
    kind: call
    callee:
      name: {name}
  description: bad",
                name = name.replace('.', "_")
            ),
        );
        // Need the name to match the callee literally; rewrite by splatting
        // the real `name` into the callee position.
        write(
            &tmp.path().join("langs/x/sinks/bad.yml"),
            &format!(
                "- id: x.broad.n
  enabled: true
  tag: xss
  match:
    kind: call
    callee:
      name: \"{name}\"
  description: bad"
            ),
        );
        load_rulepack(tmp.path()).expect("sink constraints are optional");
    }
}

#[test]
fn ubiquitous_name_is_allowed_without_constraint() {
    let tmp = tempdir();
    write(
        &tmp.path().join("langs/x/sinks/narrow.yml"),
        r"- id: x.log.narrow
  enabled: true
  tag: xss
  match:
    kind: call
    callee:
      name: log
  description: log(...) — taint-analysis decides whether a source argument reaches it",
    );
    load_rulepack(tmp.path()).expect("unconstrained sink should load");
}

#[test]
fn ubiquitous_name_allowed_in_source_rule() {
    // Sources don't carry the FP cost — the cost is on the sink side
    // of an intersection — so the loader lint doesn't fire.
    let tmp = tempdir();
    write(
        &tmp.path().join("langs/x/sources/src.yml"),
        r"- id: x.print.source
  enabled: true
  tag: http-input
  trust: remote
  match:
    kind: call
    callee:
      name: print
  description: hypothetical",
    );
    let pack = load_rulepack(tmp.path()).expect("broad SOURCE is ok");
    assert_eq!(pack.packs.len(), 1);
}

#[test]
fn bundled_sink_constraints_are_explicitly_example_guarded() {
    let pack = load_rulepack(&repo_root().join("security-patterns")).expect("shipped pack loads");
    let mut offenders = Vec::new();
    for lang in pack.packs.values() {
        for rule in &lang.sinks {
            if rule.constraints.is_empty() {
                continue;
            }

            let unguarded: Vec<&'static str> = rule
                .constraints
                .iter()
                .filter(|constraint| constraint.is_discriminating())
                .filter(|_| !rule.match_examples.iter().any(|example| example.expect_no_match))
                .map(ConstraintKind::name)
                .collect();

            if !unguarded.is_empty() {
                offenders.push(format!(
                    "{} ({}) missing negative examples for {}",
                    rule.id,
                    rule.source_path,
                    unguarded.join(", ")
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "sink-side discriminating constraints must be covered by negative examples:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn enabled_rules_do_not_describe_themselves_as_disabled() {
    let pack = load_rulepack(&repo_root().join("security-patterns")).expect("shipped pack loads");
    let mut stale = Vec::new();
    for lang in pack.packs.values() {
        for rule in lang.all_rules() {
            if rule.enabled
                && rule
                    .description
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("disabled")
            {
                stale.push(format!("{} ({})", rule.id, rule.source_path));
            }
        }
    }

    assert!(
        stale.is_empty(),
        "enabled rules must not carry stale Disabled descriptions:\n  {}",
        stale.join("\n  ")
    );
}
