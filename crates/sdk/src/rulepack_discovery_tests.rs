use super::Bonsai;
use std::fs;
use std::path::PathBuf;

fn fresh_tempdir(prefix: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "bonsai-rulepack-{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&base).unwrap();
    base
}

#[test]
fn env_var_overrides_workspace_local_rulepack() {
    let workspace = fresh_tempdir("ws");
    let workspace_local = workspace.join("security-patterns");
    fs::create_dir_all(&workspace_local).unwrap();

    let env_pack = fresh_tempdir("env");

    let env_path = env_pack.clone();
    let resolved = Bonsai::discover_rulepack_root_with(&workspace, |key| {
        if key == "BONSAI_RULES_DIR" {
            Some(env_path.clone())
        } else {
            None
        }
    })
    .unwrap();
    assert_eq!(
        resolved.canonicalize().unwrap(),
        env_pack.canonicalize().unwrap(),
        "BONSAI_RULES_DIR should win over workspace-local security-patterns/"
    );

    fs::remove_dir_all(&workspace).ok();
    fs::remove_dir_all(&env_pack).ok();
}

#[test]
fn env_var_falls_back_when_path_missing() {
    let workspace = fresh_tempdir("ws-fallback");
    let workspace_local = workspace.join("security-patterns");
    fs::create_dir_all(&workspace_local).unwrap();

    let resolved = Bonsai::discover_rulepack_root_with(&workspace, |key| {
        if key == "BONSAI_RULES_DIR" {
            Some(PathBuf::from("/nonexistent/path/does/not/exist"))
        } else {
            None
        }
    })
    .unwrap();
    assert_eq!(
        resolved.canonicalize().unwrap(),
        workspace_local.canonicalize().unwrap(),
        "missing BONSAI_RULES_DIR path should fall back to workspace-local security-patterns/"
    );

    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn workspace_local_wins_when_env_unset() {
    let workspace = fresh_tempdir("ws-local");
    let workspace_local = workspace.join("security-patterns");
    fs::create_dir_all(&workspace_local).unwrap();

    let resolved = Bonsai::discover_rulepack_root_with(&workspace, |_| None).unwrap();
    assert_eq!(
        resolved.canonicalize().unwrap(),
        workspace_local.canonicalize().unwrap(),
        "workspace-local security-patterns should be picked when no env var is set"
    );

    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn no_env_no_local_doesnt_panic_or_invent_path() {
    let workspace = fresh_tempdir("ws-empty");
    // No security-patterns/ inside the workspace, no env override.
    // Discovery may still hit the cwd-relative `./security-patterns/`
    // candidate when the test runs from a directory that contains
    // one (the bonsai-ninja repo root does). Either outcome is
    // valid — assert the function never invents a non-existent path.
    if let Some(found) = Bonsai::discover_rulepack_root_with(&workspace, |_| None) {
        assert!(
            found.exists(),
            "discover_rulepack_root returned a non-existent path: {}",
            found.display()
        );
    }

    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn executable_sibling_rulepack_is_discovered_from_an_unrelated_cwd() {
    let workspace = fresh_tempdir("ws-packaged");
    let package = fresh_tempdir("package");
    let executable = package.join("bonsai-ninja");
    let packaged_rules = package.join("security-patterns");
    fs::create_dir_all(&packaged_rules).unwrap();

    let resolved =
        Bonsai::discover_rulepack_root_with_executable(&workspace, |_| None, Some(&executable)).unwrap();
    assert_eq!(
        resolved.canonicalize().unwrap(),
        packaged_rules.canonicalize().unwrap(),
        "a relocated distribution must discover its bundled rulepack beside the executable"
    );

    fs::remove_dir_all(&workspace).ok();
    fs::remove_dir_all(&package).ok();
}
