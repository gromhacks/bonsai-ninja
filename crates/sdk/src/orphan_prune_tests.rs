use std::path::PathBuf;

use super::{
    clear_workspace_cache_directory, directory_bytes, manifest_workspace_root_head,
    prune_orphaned_workspace_caches_in,
};

#[test]
fn clear_all_never_removes_the_workspace_or_an_unbound_directory() {
    let root = tempdir("clear-unbound");
    let workspace = root.join("workspace");
    let cache = root.join("unrelated");
    std::fs::create_dir(&workspace).expect("workspace");
    std::fs::create_dir(&cache).expect("unrelated data");
    std::fs::write(workspace.join("source.py"), "source").expect("source");
    std::fs::write(cache.join("important.txt"), "preserve").expect("user data");
    assert!(clear_workspace_cache_directory(&workspace, &workspace).is_err());
    assert!(clear_workspace_cache_directory(&workspace, &root).is_err());
    assert!(clear_workspace_cache_directory(&workspace, &cache).is_err());
    assert!(workspace.join("source.py").is_file());
    assert!(cache.join("important.txt").is_file());
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn orphan_pruning_preserves_unattributed_aged_directories() {
    let root = tempdir("orphan-unknown");
    let cache = root.join("unknown");
    std::fs::create_dir(&cache).expect("unattributed directory");
    std::fs::write(cache.join("important.txt"), "preserve").expect("user data");
    #[cfg(unix)]
    std::fs::File::open(&cache)
        .and_then(|file| file.set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH)))
        .expect("age directory");
    let report = prune_orphaned_workspace_caches_in(&root).expect("isolated prune");
    assert_eq!(report.removed, 0);
    assert_eq!(report.unattributed, 1);
    assert!(cache.join("important.txt").is_file());
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

// Use the real workspace marker publisher/codec, never a test-only imitation
// of its Unix/Windows native-path wire format. No shared-root sweep runs here.
fn copy_binding(workspace: &std::path::Path, cache: &std::path::Path) {
    let registry = std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new());
    let project = bonsai_workspace::Workspace::open(workspace, registry).expect("bound workspace");
    drop(project);
    let published = bonsai_common::workspace_bonsai_dir(workspace);
    std::fs::copy(
        published.join(".workspace-root.v1"),
        cache.join(".workspace-root.v1"),
    )
    .expect("copy real binding to isolated cache");
    std::fs::remove_dir_all(published).expect("remove fixture's published cache");
}

#[test]
fn bound_manifestless_cache_survives_until_its_workspace_is_deleted() {
    if std::env::var_os("BONSAI_WORKSPACE_DIR").is_some() {
        return;
    }
    let fixture = tempdir("bound-orphan");
    let root = fixture.join("caches");
    let cache = root.join("bound");
    let workspace = fixture.join("workspace");
    std::fs::create_dir_all(&cache).expect("cache");
    std::fs::create_dir(&workspace).expect("workspace");
    copy_binding(&workspace, &cache);
    std::fs::write(cache.join("dataflow.v2.bin"), [0_u8; 42]).expect("sidecar");
    #[cfg(unix)]
    std::fs::File::open(&cache)
        .and_then(|file| file.set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH)))
        .expect("age cache");
    assert_eq!(
        prune_orphaned_workspace_caches_in(&root)
            .expect("live sweep")
            .removed,
        0
    );
    assert!(cache.is_dir());
    std::fs::remove_dir(&workspace).expect("delete isolated workspace");
    let bytes = directory_bytes(&cache);
    let report = prune_orphaned_workspace_caches_in(&root).expect("orphan sweep");
    assert_eq!(report.removed, 1);
    assert_eq!(report.freed_bytes, bytes);
    assert!(!cache.exists());
    std::fs::remove_dir_all(fixture).expect("fixture cleanup");
}

#[test]
fn clear_all_requires_matching_ownership_and_preserves_project_settings() {
    if std::env::var_os("BONSAI_WORKSPACE_DIR").is_some() {
        return;
    }
    let root = tempdir("clear-bound");
    let workspace = root.join("workspace");
    let other = root.join("other");
    let cache = root.join("cache");
    for dir in [&workspace, &other, &cache] {
        std::fs::create_dir(dir).expect("directory");
    }
    copy_binding(&workspace, &cache);
    std::fs::write(cache.join("dataflow.v2.bin"), [0_u8; 42]).expect("sidecar");
    assert!(clear_workspace_cache_directory(&other, &cache).is_err());
    let settings = cache.join("settings.json");
    std::fs::write(&settings, "preserve").expect("settings");
    assert!(clear_workspace_cache_directory(&workspace, &cache).is_err());
    assert_eq!(
        std::fs::read_to_string(&settings).expect("settings survive"),
        "preserve"
    );
    assert!(
        cache.join("dataflow.v2.bin").exists(),
        "clear must preflight before deleting anything"
    );
    std::fs::remove_file(settings).expect("remove isolated settings");
    clear_workspace_cache_directory(&workspace, &cache).expect("clear owned cache");
    assert!(!cache.exists());
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn orphan_pruning_preserves_corrupt_ownership_even_with_an_orphan_manifest() {
    let root = tempdir("orphan-corrupt-binding");
    let cache = root.join("cache");
    std::fs::create_dir(&cache).expect("cache");
    std::fs::write(cache.join(".workspace-root.v1"), b"broken").expect("broken binding");
    std::fs::write(
        cache.join("manifest.json"),
        serde_json::json!({
            "schema_version": 7, "workspace_root": root.join("deleted"), "cache_dir": cache,
        })
        .to_string(),
    )
    .expect("manifest");
    let report = prune_orphaned_workspace_caches_in(&root).expect("isolated sweep");
    assert_eq!(report.removed, 0);
    assert_eq!(report.unattributed, 1);
    assert!(cache.exists());
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn manifest_root_must_be_a_complete_top_level_identity() {
    let root = tempdir("orphan-manifest-attribution");
    let manifest = root.join("manifest.json");
    for invalid in [
        r#"{"nested":{"workspace_root":"/deleted"}}"#,
        r#"{"workspace_root":"relative"}"#,
        r#"{"workspace_root":"/deleted", broken}"#,
        r#"{"workspace_root":"/deleted","workspace_root":"/present"}"#,
    ] {
        std::fs::write(&manifest, invalid).expect("invalid manifest");
        assert_eq!(
            manifest_workspace_root_head(&manifest).expect("read manifest"),
            None,
            "{invalid}"
        );
    }
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
fn manifest_identity_skips_source_rows_without_materializing_them() {
    let root = tempdir("orphan-head");
    let manifest = root.join("manifest.json");
    // Stream over the large trailing table without constructing source rows.
    let workspace = root.join("with spaces");
    let mut body = format!(
        "{{\"schema_version\":7,\"workspace_root\":{},\"cache_dir\":{},\"workspace_source_files\":[",
        serde_json::to_string(&workspace).expect("root JSON"),
        serde_json::to_string(&root).expect("cache JSON")
    );
    for index in 0..20_000 {
        if index != 0 {
            body.push(',');
        }
        body.push_str(&format!("    {{\"hash\": {index}, \"stamp\": {{\"len\": 1}}}}\n"));
    }
    body.push_str("  ]\n}\n");
    std::fs::write(&manifest, body).expect("write manifest");
    let parsed = manifest_workspace_root_head(&manifest).expect("read head");
    assert_eq!(parsed, Some(workspace));

    // Not one of our manifests: unattributed, never treated as orphaned.
    std::fs::write(&manifest, "{\"unrelated\": true}\n").expect("write other");
    assert_eq!(manifest_workspace_root_head(&manifest).expect("read other"), None);

    // Missing ownership is kept, never treated as an age-based orphan.
    std::fs::remove_file(&manifest).expect("remove");
    let error = manifest_workspace_root_head(&manifest).expect_err("missing");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn directory_bytes_sums_nested_files() {
    let root = tempdir("orphan-bytes");
    std::fs::write(root.join("a.bin"), [0u8; 10]).expect("a");
    std::fs::create_dir_all(root.join("nested")).expect("nested");
    std::fs::write(root.join("nested").join("b.bin"), [0u8; 32]).expect("b");
    assert_eq!(directory_bytes(&root), 42);
    let _ = std::fs::remove_dir_all(&root);
}
