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
fn env_var_selects_an_explicit_custom_rulepack() {
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
        "BONSAI_RULES_DIR should select the explicit rulepack"
    );

    fs::remove_dir_all(&workspace).ok();
    fs::remove_dir_all(&env_pack).ok();
}

#[test]
fn invalid_env_override_fails_instead_of_falling_back() {
    let workspace = fresh_tempdir("ws-fallback");
    let error = Bonsai::default_rulepack_root_with(|key| {
        if key == "BONSAI_RULES_DIR" {
            Some(PathBuf::from("/nonexistent/path/does/not/exist"))
        } else {
            None
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("BONSAI_RULES_DIR"));

    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn workspace_local_base_pack_is_not_trusted_implicitly() {
    let workspace = fresh_tempdir("ws-local");
    let workspace_local = workspace.join("security-patterns");
    fs::create_dir_all(&workspace_local).unwrap();

    let resolved = Bonsai::discover_rulepack_root_with(&workspace, |_| None).unwrap();
    assert_ne!(
        resolved.canonicalize().unwrap(),
        workspace_local.canonicalize().unwrap()
    );
    assert!(resolved.join("metadata.yml").is_file());

    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn no_override_materializes_the_bundled_pack() {
    let workspace = fresh_tempdir("ws-empty");
    let found = Bonsai::discover_rulepack_root_with(&workspace, |_| None).unwrap();
    assert!(found.join("metadata.yml").is_file());
    assert!(found.join("langs").is_dir());

    fs::remove_dir_all(&workspace).ok();
}
