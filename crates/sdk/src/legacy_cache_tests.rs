use std::path::PathBuf;

use super::{legacy_in_tree_cache_dir, WorkspaceCache};

#[cfg(unix)]
#[test]
fn legacy_cleanup_never_follows_a_directory_symlink() {
    let root = tempdir("legacy-symlink");
    let external = root.join("external");
    std::fs::create_dir(&external).expect("external directory");
    std::fs::write(external.join("dataflow.v2.bin"), b"preserve").expect("external file");
    std::os::unix::fs::symlink(&external, root.join(".bonsai")).expect("directory link");
    assert_eq!(legacy_in_tree_cache_dir(&root, &root.join("active")), None);
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn current_rule_overlays_are_never_legacy_cache() {
    let root = tempdir("current-rules");
    let rules = root.join(".bonsai/rules");
    std::fs::create_dir_all(&rules).expect("rules");
    std::fs::write(rules.join("custom.yml"), "id: local.rule\n").expect("rule");
    assert_eq!(legacy_in_tree_cache_dir(&root, &root.join("external")), None);
    assert_eq!(
        std::fs::read_to_string(rules.join("custom.yml")).expect("rule survives"),
        "id: local.rule\n"
    );
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn legacy_clear_preserves_current_rules_and_unrecognized_files() {
    if std::env::var_os("BONSAI_WORKSPACE_DIR").is_some() {
        return;
    }
    let root = tempdir("mixed-cache-rules");
    let legacy = root.join(".bonsai");
    std::fs::create_dir_all(legacy.join("rules")).expect("rules");
    std::fs::write(legacy.join("rules/custom.yml"), "id: local.rule\n").expect("rule");
    std::fs::write(legacy.join("settings.json"), "{}\n").expect("settings");
    std::fs::write(legacy.join("compiler-objects.v11.factstore"), [0_u8; 42]).expect("old artifact");
    let removed = WorkspaceCache::new(&root)
        .clear_legacy_in_tree()
        .expect("clear attributed artifacts");
    assert_eq!(removed.map(|(_, bytes)| bytes), Some(42));
    assert!(legacy.join("rules/custom.yml").is_file());
    assert!(legacy.join("settings.json").is_file());
    assert!(!legacy.join("compiler-objects.v11.factstore").exists());
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

fn tempdir(name: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("bonsai-sdk-{name}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

#[test]
fn legacy_in_tree_dir_is_reported_only_when_it_is_not_the_active_cache() {
    let root = tempdir("legacy-cache");
    assert_eq!(legacy_in_tree_cache_dir(&root, &root.join("elsewhere")), None);
    let legacy = root.join(".bonsai");
    std::fs::create_dir_all(&legacy).expect("legacy dir");
    std::fs::write(legacy.join("dataflow.v2.bin"), [0u8; 16]).expect("old sidecar");
    assert_eq!(
        legacy_in_tree_cache_dir(&root, &root.join("elsewhere")),
        Some(legacy.clone())
    );
    // The active cache directory is never legacy, whichever spelling names it.
    assert_eq!(legacy_in_tree_cache_dir(&root, &legacy), None);
    std::fs::create_dir_all(root.join("sub")).expect("sub dir");
    assert_eq!(
        legacy_in_tree_cache_dir(&root, &root.join("sub").join("..").join(".bonsai")),
        None
    );
    let canonical_root = root.canonicalize().expect("canonical root");
    assert_eq!(
        legacy_in_tree_cache_dir(&canonical_root, &legacy),
        None,
        "canonical root spelling names the same directory"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn clear_legacy_in_tree_removes_the_directory_and_reports_its_size() {
    if std::env::var_os("BONSAI_WORKSPACE_DIR").is_some() {
        // A pinned cache directory may be the in-tree path itself.
        return;
    }
    let root = tempdir("legacy-clear");
    let legacy = root.join(".bonsai");
    std::fs::create_dir_all(&legacy).expect("legacy dir");
    std::fs::write(legacy.join("callgraph.v1.factstore"), [0u8; 10]).expect("callgraph");
    std::fs::write(legacy.join("value_flow.v1.factstore"), [0u8; 32]).expect("value flow");
    // The cache handle persists the canonical root, so compare canonically.
    let cache = WorkspaceCache::new(&root);
    let canonical_legacy = legacy.canonicalize().expect("canonical legacy dir");
    assert_eq!(cache.legacy_in_tree_dir(), Some(canonical_legacy.clone()));
    let stats = cache.stats().expect("stats");
    assert_eq!(stats.legacy_in_tree_dir, Some(canonical_legacy.clone()));
    assert_eq!(stats.legacy_in_tree_bytes, 42);
    let removed = cache.clear_legacy_in_tree().expect("clear");
    assert_eq!(removed, Some((canonical_legacy, 42)));
    assert!(!legacy.exists());
    assert_eq!(cache.clear_legacy_in_tree().expect("second clear"), None);
    let _ = std::fs::remove_dir_all(&root);
}
