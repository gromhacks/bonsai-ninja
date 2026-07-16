use super::{
    default_export_cache_metadata_path, default_export_cache_path, export_cache_is_fresh_via_fd,
    unique_default_export_tmp_path, workspace_source_fingerprint_from_disk, write_default_export_cache,
    write_default_export_cache_with,
};
use std::path::Path;

#[test]
fn default_export_tmp_paths_are_unique_per_write() {
    let path = Path::new("/tmp/.bonsai/export.default.v9.json");
    let first = unique_default_export_tmp_path(path);
    let second = unique_default_export_tmp_path(path);

    assert_ne!(first, second);
    assert_eq!(first.parent(), path.parent());
    assert!(first
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("export.default.v9.json.tmp.")));
}

fn tempdir(name: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("bonsai-sdk-{name}-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&path).expect("create temp dir");
    path
}

fn write_cache(root: &Path, rulepack_root: Option<&Path>) {
    let cache = default_export_cache_path(root);
    let sources = workspace_source_fingerprint_from_disk(root).expect("source fingerprint");
    write_default_export_cache(&cache, root, rulepack_root, sources, r#"{"ok":true}"#)
        .expect("write export cache");
}

fn cache_is_fresh(root: &Path, rulepack_root: Option<&Path>) -> bool {
    let cache = default_export_cache_path(root);
    let file = std::fs::File::open(cache).expect("open export cache");
    export_cache_is_fresh_via_fd(root, rulepack_root, &file).expect("freshness check")
}

#[test]
fn export_cache_writer_writes_one_valid_json_document() {
    let root = tempdir("export-single-json");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    write_cache(&root, None);

    let cache = default_export_cache_path(&root);
    let bytes = std::fs::read_to_string(&cache).expect("read export cache");
    assert_eq!(
        bytes, "{\"ok\":true}\n",
        "string export cache writer must not duplicate the JSON document"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&bytes).expect("cache should parse as one JSON document");
    assert_eq!(parsed["ok"], true);
    assert!(cache_is_fresh(&root, None));

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn export_cache_writer_removes_abandoned_temp_siblings_under_lock() {
    let root = tempdir("export-stale-temp");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    let cache = default_export_cache_path(&root);
    std::fs::create_dir_all(cache.parent().expect("cache parent")).expect("create cache dir");
    let abandoned = unique_default_export_tmp_path(&cache);
    std::fs::write(&abandoned, b"abandoned").expect("write abandoned temp");

    write_cache(&root, None);

    assert!(
        !abandoned.exists(),
        "exclusive writer should reclaim abandoned temp files"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn streaming_export_error_removes_its_temp_file() {
    let root = tempdir("export-error-temp");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    let cache = default_export_cache_path(&root);
    let sources = workspace_source_fingerprint_from_disk(&root).expect("source fingerprint");

    let error = write_default_export_cache_with(&cache, &root, None, sources, |_writer| {
        anyhow::bail!("synthetic streaming failure")
    })
    .expect_err("writer should fail");

    assert!(error.to_string().contains("synthetic streaming failure"));
    let prefix = format!("{}.tmp.", cache.file_name().unwrap().to_string_lossy());
    let leftovers = std::fs::read_dir(cache.parent().expect("cache parent"))
        .expect("read cache dir")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .count();
    assert_eq!(leftovers, 0, "failed streaming writes must not leak temp files");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn export_cache_requires_metadata_sidecar() {
    let root = tempdir("export-missing-meta");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    let cache = default_export_cache_path(&root);
    std::fs::create_dir_all(cache.parent().expect("cache parent")).expect("create cache dir");
    std::fs::write(&cache, "{}\n").expect("write raw cache");

    let file = std::fs::File::open(&cache).expect("open raw cache");
    assert!(
        !export_cache_is_fresh_via_fd(&root, None, &file).expect("freshness check"),
        "cache without fingerprint metadata must not be replayed"
    );
    assert!(!default_export_cache_metadata_path(&root).exists());

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn export_cache_rejects_source_content_mismatch() {
    let root = tempdir("export-source-content");
    std::fs::write(root.join("app.py"), "print('before')\n").expect("write source");
    write_cache(&root, None);
    assert!(cache_is_fresh(&root, None));

    std::fs::write(root.join("app.py"), "print('after')\n").expect("rewrite source");
    assert!(
        !cache_is_fresh(&root, None),
        "source content changes must invalidate the export cache even when cache bytes still exist"
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn export_cache_rejects_pipeline_version_mismatch() {
    let root = tempdir("export-pipeline-version");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    write_cache(&root, None);
    assert!(cache_is_fresh(&root, None));

    let metadata_path = default_export_cache_metadata_path(&root);
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&metadata_path).expect("read metadata"))
            .expect("parse metadata");
    metadata["pipeline_version"] = serde_json::Value::String("native-export-cache-old".to_string());
    let mut bytes = serde_json::to_vec_pretty(&metadata).expect("serialize metadata");
    bytes.push(b'\n');
    std::fs::write(&metadata_path, bytes).expect("rewrite metadata");

    assert!(
        !cache_is_fresh(&root, None),
        "native export cache pipeline changes must invalidate stale semantic export JSON"
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn export_cache_rejects_dependency_metadata_mismatch() {
    let root = tempdir("export-dependency-content");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    std::fs::write(root.join("requirements.txt"), "flask==3.0.0\n").expect("write deps");
    write_cache(&root, None);
    assert!(cache_is_fresh(&root, None));

    std::fs::write(root.join("requirements.txt"), "flask==3.0.0\nrequests==2.32.0\n").expect("rewrite deps");
    assert!(
        !cache_is_fresh(&root, None),
        "dependency metadata content changes must invalidate the export cache"
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn export_cache_rejects_common_dependency_metadata_shapes() {
    for (label, manifest) in [
        ("go-work", "go.work"),
        ("requirements-dev", "requirements-dev.txt"),
        ("dotnet-project", "Service.csproj"),
    ] {
        let root = tempdir(label);
        std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
        std::fs::write(root.join(manifest), "before\n").expect("write dependency metadata");
        write_cache(&root, None);
        assert!(
            cache_is_fresh(&root, None),
            "{manifest} precondition should be fresh"
        );

        std::fs::write(root.join(manifest), "after\n").expect("rewrite dependency metadata");
        assert!(
            !cache_is_fresh(&root, None),
            "{manifest} changes must invalidate the export cache"
        );

        std::fs::remove_dir_all(&root).ok();
    }
}

#[test]
fn export_cache_rejects_deep_dependency_metadata_mismatch() {
    let root = tempdir("export-deep-dependency-content");
    let manifest_dir = root
        .join("a")
        .join("b")
        .join("c")
        .join("d")
        .join("e")
        .join("service");
    std::fs::create_dir_all(&manifest_dir).expect("create deep manifest dir");
    let manifest = manifest_dir.join("pom.xml");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    std::fs::write(&manifest, "<project />\n").expect("write deep dependency metadata");
    write_cache(&root, None);
    assert!(cache_is_fresh(&root, None));

    std::fs::write(&manifest, "<project><dependencies /></project>\n")
        .expect("rewrite deep dependency metadata");
    assert!(
        !cache_is_fresh(&root, None),
        "deep dependency metadata changes must invalidate the export cache"
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn export_cache_rejects_rulepack_content_mismatch() {
    let root = tempdir("export-rulepack-content");
    let rulepack = tempdir("export-rulepack");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write source");
    std::fs::write(rulepack.join("rule.yml"), "id: before\n").expect("write rule");
    write_cache(&root, Some(&rulepack));
    assert!(cache_is_fresh(&root, Some(&rulepack)));

    std::fs::write(rulepack.join("rule.yml"), "id: after\n").expect("rewrite rule");
    assert!(
        !cache_is_fresh(&root, Some(&rulepack)),
        "rulepack content changes must invalidate the export cache"
    );

    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&rulepack).ok();
}

#[cfg(unix)]
#[test]
fn export_freshness_skips_symlinked_directories() {
    let root = tempdir("export-root");
    let outside = tempdir("export-outside");
    std::fs::write(root.join("app.py"), "print('root')\n").expect("write root app");
    std::fs::write(outside.join("external.py"), "print('outside')\n").expect("write outside app");
    std::os::unix::fs::symlink(&outside, root.join("linked")).expect("create symlink dir");

    let before = workspace_source_fingerprint_from_disk(&root).expect("fingerprint before");
    std::fs::write(outside.join("external.py"), "print('changed')\n").expect("rewrite outside app");
    let after = workspace_source_fingerprint_from_disk(&root).expect("fingerprint after");
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&outside).ok();

    assert_eq!(before, after);
}
