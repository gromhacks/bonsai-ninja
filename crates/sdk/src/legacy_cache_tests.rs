use std::path::PathBuf;

use super::{legacy_in_tree_cache_dir, WorkspaceCache};

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
    std::fs::write(legacy.join("old.bin"), [0u8; 16]).expect("old sidecar");
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
    std::fs::create_dir_all(legacy.join("nested")).expect("legacy dir");
    std::fs::write(legacy.join("a.bin"), [0u8; 10]).expect("a");
    std::fs::write(legacy.join("nested").join("b.bin"), [0u8; 32]).expect("b");
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
