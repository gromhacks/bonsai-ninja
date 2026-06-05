use super::{
    cache_is_fresh, content_tree_fingerprint, dependency_metadata_fingerprint, eager_window,
    rulepack_dir_skipped, workspace_fingerprint, PageCacheFile, RENDER_CACHE_VERSION,
};
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("bonsai-page-cache-{name}-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&path).expect("create temp dir");
    path
}

#[test]
fn eager_window_keeps_page_cache_opportunistic() {
    let window = eager_window(10, 100);
    assert_eq!(
        window.into_iter().collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 10, 11, 12, 13]
    );
}

#[test]
fn workspace_fingerprint_changes_when_indexed_file_changes() {
    let root = tempdir("content-change");
    let file = root.join("app.py");
    std::fs::write(&file, "print('a')\n").expect("write app");
    let before = workspace_fingerprint(&root).expect("fingerprint before");
    std::fs::write(&file, "print('b')\n").expect("rewrite app");
    let after = workspace_fingerprint(&root).expect("fingerprint after");
    std::fs::remove_dir_all(&root).ok();

    assert_ne!(before, after);
}

#[cfg(unix)]
#[test]
fn workspace_fingerprint_skips_symlinked_directories() {
    let root = tempdir("symlink-root");
    let outside = tempdir("symlink-outside");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write root app");
    std::fs::write(outside.join("external.py"), "print('outside')\n").expect("write outside app");
    std::os::unix::fs::symlink(&outside, root.join("linked")).expect("create symlink dir");

    let before = workspace_fingerprint(&root).expect("fingerprint before");
    std::fs::write(outside.join("external.py"), "print('changed')\n").expect("rewrite outside app");
    let after = workspace_fingerprint(&root).expect("fingerprint after");
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&outside).ok();

    assert_eq!(before, after);
}

#[test]
fn dependency_metadata_fingerprint_changes_when_manifest_changes() {
    let root = tempdir("dependency-metadata");
    let manifest = root.join("requirements.txt");
    std::fs::write(&manifest, "flask==3.0.0\n").expect("write deps");
    let before = dependency_metadata_fingerprint(&root).expect("fingerprint before");
    std::fs::write(&manifest, "flask==3.0.0\nrequests==2.32.0\n").expect("rewrite deps");
    let after = dependency_metadata_fingerprint(&root).expect("fingerprint after");
    std::fs::remove_dir_all(&root).ok();

    assert_ne!(before, after);
}

#[test]
fn dependency_metadata_fingerprint_tracks_common_project_manifests() {
    for (label, manifest) in [
        ("go-work", "go.work"),
        ("requirements-dev", "requirements-dev.txt"),
        ("dotnet-project", "Service.csproj"),
    ] {
        let root = tempdir(label);
        let path = root.join(manifest);
        std::fs::write(&path, "before\n").expect("write dependency metadata");
        let before = dependency_metadata_fingerprint(&root).expect("fingerprint before");
        std::fs::write(&path, "after\n").expect("rewrite dependency metadata");
        let after = dependency_metadata_fingerprint(&root).expect("fingerprint after");
        std::fs::remove_dir_all(&root).ok();

        assert_ne!(
            before, after,
            "{manifest} changes must invalidate page cache metadata"
        );
    }
}

#[test]
fn dependency_metadata_fingerprint_tracks_deep_project_manifest() {
    let root = tempdir("dependency-metadata-deep");
    let manifest_dir = root
        .join("a")
        .join("b")
        .join("c")
        .join("d")
        .join("e")
        .join("service");
    std::fs::create_dir_all(&manifest_dir).expect("create deep manifest dir");
    let manifest = manifest_dir.join("pom.xml");
    std::fs::write(&manifest, "<project />\n").expect("write deep dependency metadata");

    let before = dependency_metadata_fingerprint(&root).expect("fingerprint before");
    std::fs::write(&manifest, "<project><dependencies /></project>\n")
        .expect("rewrite deep dependency metadata");
    let after = dependency_metadata_fingerprint(&root).expect("fingerprint after");
    std::fs::remove_dir_all(&root).ok();

    assert_ne!(
        before, after,
        "deep dependency metadata changes must invalidate page cache metadata"
    );
}

#[test]
fn rulepack_fingerprint_changes_when_rule_changes() {
    let root = tempdir("rulepack");
    let rule = root.join("rule.yml");
    std::fs::write(&rule, "id: before\n").expect("write rule");
    let before = content_tree_fingerprint(&root, rulepack_dir_skipped).expect("fingerprint before");
    std::fs::write(&rule, "id: after\n").expect("rewrite rule");
    let after = content_tree_fingerprint(&root, rulepack_dir_skipped).expect("fingerprint after");
    std::fs::remove_dir_all(&root).ok();

    assert_ne!(before, after);
}

fn cache_file_for(workspace: &std::path::Path) -> PageCacheFile {
    PageCacheFile {
        version: RENDER_CACHE_VERSION,
        binary_version: super::binary_cache_fingerprint().to_string(),
        matcher_policy_fingerprint: bonsai_common::MATCHER_POLICY_FINGERPRINT,
        workspace_fingerprint: workspace_fingerprint(workspace).expect("workspace fingerprint"),
        dependency_metadata_fingerprint: dependency_metadata_fingerprint(workspace)
            .expect("dependency fingerprint"),
        rulepack_fingerprint: super::rulepack_fingerprint_for_command(workspace)
            .expect("rulepack fingerprint"),
        normalized_argv_hash: 0,
        pages: Vec::new(),
    }
}

#[test]
fn cache_freshness_rejects_parent_rulepack_content_change() {
    let parent = tempdir("parent-rulepack");
    let workspace = parent.join("ws");
    let rulepack = parent.join("security-patterns");
    std::fs::create_dir(&workspace).expect("create workspace");
    std::fs::create_dir(&rulepack).expect("create rulepack");
    std::fs::write(workspace.join("app.py"), "print('root')\n").expect("write source");
    std::fs::write(rulepack.join("rule.yml"), "id: before\n").expect("write rule");

    let cache = cache_file_for(&workspace);
    assert!(cache_is_fresh(&workspace, &cache).expect("fresh before"));

    std::fs::write(rulepack.join("rule.yml"), "id: after\n").expect("rewrite rule");
    assert!(
        !cache_is_fresh(&workspace, &cache).expect("fresh after"),
        "page cache must not replay when the discovered rulepack changes"
    );
    std::fs::remove_dir_all(&parent).ok();
}

#[test]
fn cache_freshness_rejects_dependency_metadata_content_change() {
    let root = tempdir("cache-dependency");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    std::fs::write(root.join("requirements.txt"), "flask==3.0.0\n").expect("write deps");

    let cache = cache_file_for(&root);
    assert!(cache_is_fresh(&root, &cache).expect("fresh before"));

    std::fs::write(root.join("requirements.txt"), "flask==3.0.0\nrequests==2.32.0\n").expect("rewrite deps");
    assert!(
        !cache_is_fresh(&root, &cache).expect("fresh after"),
        "page cache must not replay when dependency metadata changes"
    );
    std::fs::remove_dir_all(&root).ok();
}
