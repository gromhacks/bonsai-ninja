use bonsai_security::{load_rulepack, ConstraintKind};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|path| path.join("security-patterns").exists())
        .expect("repo root")
        .to_path_buf()
}

#[test]
fn enabled_rules_with_discriminating_constraints_have_negative_examples() {
    let pack = load_rulepack(&repo_root().join("security-patterns")).expect("rulepack loads");
    let mut missing = Vec::new();
    for rule in pack.all_rules() {
        if !rule.enabled {
            continue;
        }
        let has_discriminating = rule.constraints.iter().any(ConstraintKind::is_discriminating);
        if !has_discriminating {
            continue;
        }
        let has_positive = rule.match_examples.iter().any(|example| !example.expect_no_match);
        let has_negative = rule.match_examples.iter().any(|example| example.expect_no_match);
        if !has_positive || !has_negative {
            missing.push(rule.id.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "enabled discriminating constraints need positive and negative examples:\n{}",
        missing.join("\n")
    );
}
