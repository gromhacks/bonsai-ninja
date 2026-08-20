use super::{
    cache_is_fresh, content_tree_fingerprint, dependency_metadata_fingerprint, page_after_cursor,
    read_json_cache_file, remember_structural_id_hints, requested_page_window, rulepack_dir_skipped,
    serialize_json_bounded, structural_id_hint, workspace_fingerprint, CachedPage, PageCacheFile,
    MAX_PAYLOAD_BYTES, RENDER_CACHE_VERSION,
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
fn page_window_formats_only_the_requested_page() {
    let window = requested_page_window(10, 100);
    assert_eq!(window.into_iter().collect::<Vec<_>>(), vec![10]);
}

#[test]
fn next_page_replay_resolves_from_the_current_cached_cursor() {
    let pages = (1..=3)
        .map(|number| CachedPage {
            number,
            total_pages: 3,
            cursor: format!("P:{number:08x}"),
            text: format!("page {number}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        page_after_cursor(&pages, "P:00000001").map(|page| page.number),
        Some(2)
    );
    assert!(page_after_cursor(&pages, "P:00000003").is_none());
}

#[test]
fn oversized_cache_file_is_rejected_before_deserialization() {
    let root = tempdir("oversized-read");
    let path = root.join("cache.json");
    let file = std::fs::File::create(&path).expect("create sparse cache");
    file.set_len(MAX_PAYLOAD_BYTES as u64 + 1)
        .expect("size sparse cache");

    assert!(read_json_cache_file::<serde_json::Value>(&path).is_none());

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn oversized_cache_value_is_rejected_during_serialization() {
    let value = "x".repeat(256);
    assert!(serialize_json_bounded(&value, 32)
        .expect("bounded serialization")
        .is_none());
}

#[test]
fn requested_page_rendering_preserves_the_displayed_cursor() {
    crate::paging::clear_cursor_history_for_tests();
    let root = tempdir("displayed-cursor");
    let rows: Vec<String> = (0..8).map(|index| format!("row-{index}")).collect();
    let cfg = crate::paging::PagingConfig::new(
        Some(64),
        crate::paging::PageArg::First,
        Some(1),
        false,
        crate::paging::FormatClass::Text,
    );

    super::emit_paged_text(
        &root,
        &rows,
        &cfg,
        "cache-cursor-test",
        17,
        |row| row.len() as u64,
        |_, _, _| Ok(()),
    )
    .expect("render page window");

    let expected_cursor = crate::paging::cursor_id("cache-cursor-test", 17, 0);
    assert_eq!(
        crate::paging::last_cursor("cache-cursor-test", 17).as_deref(),
        Some(expected_cursor.as_str()),
        "rendering the requested page must preserve its displayed cursor"
    );
    let next_cfg = crate::paging::PagingConfig::new(
        Some(64),
        crate::paging::PageArg::Next,
        Some(1),
        false,
        crate::paging::FormatClass::Text,
    );
    let (_, next_info) =
        crate::paging::paginate(&rows, &next_cfg, "cache-cursor-test", 17, |row| row.len() as u64).unwrap();
    assert_eq!(next_info.page_number, 2);

    crate::paging::clear_cursor_history_for_tests();
    std::fs::remove_dir_all(&root).ok();
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
        command: "test".to_string(),
        filters_hash: 0,
        pages: Vec::new(),
    }
}

#[test]
fn cache_freshness_rejects_source_metadata_change() {
    let root = tempdir("cache-source-metadata");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");

    let cache = cache_file_for(&root);
    assert!(cache_is_fresh(&root, &cache).expect("fresh before"));

    std::fs::write(root.join("app.py"), "print('changed root')\n").expect("rewrite source");
    assert!(
        !cache_is_fresh(&root, &cache).expect("fresh after"),
        "page cache must not replay when source metadata changes"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn cache_freshness_ignores_unconfigured_parent_rulepack_change() {
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
        cache_is_fresh(&workspace, &cache).expect("fresh after"),
        "an unconfigured parent rulepack must not affect the embedded rulepack cache identity"
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

#[test]
fn structural_id_hint_round_trips_and_invalidates_with_source() {
    let root = tempdir("structural-id-hint");
    std::fs::write(root.join("app.py"), "def target():\n    return 1\n").expect("write source");
    let cache_root = bonsai_common::workspace_bonsai_dir(&root);
    let id = "F:0123456789abcdef";

    remember_structural_id_hints(
        &root,
        [id],
        super::StructuralIdHint {
            query: "pkg.Target.target".to_string(),
            regex: false,
            kind_filter: vec!["call".to_string()],
            from: Some("entry".to_string()),
            from_kind: Some("decl".to_string()),
            to: Some("target".to_string()),
            to_kind: Some("call".to_string()),
            file: Some("app.py".to_string()),
            in_fn: Some("target".to_string()),
        },
    );
    let hint = structural_id_hint(&root, id)
        .expect("read hint")
        .expect("stored hint");
    assert_eq!(hint.query, "pkg.Target.target");
    assert!(!hint.regex);
    assert_eq!(hint.kind_filter, ["call"]);
    assert_eq!(hint.from.as_deref(), Some("entry"));
    assert_eq!(hint.to.as_deref(), Some("target"));

    std::fs::write(root.join("app.py"), "def target():\n    return 2\n").expect("change source");
    assert!(
        structural_id_hint(&root, id).expect("read stale hint").is_none(),
        "a structural breadcrumb must never survive workspace source changes"
    );

    std::fs::remove_dir_all(&cache_root).ok();
    std::fs::remove_dir_all(&root).ok();
}
