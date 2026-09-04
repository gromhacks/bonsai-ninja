use std::path::PathBuf;

use super::{directory_bytes, manifest_workspace_root_head};

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
fn manifest_head_yields_workspace_root_without_full_decode() {
    let root = tempdir("orphan-head");
    let manifest = root.join("manifest.json");
    // A large trailing source table must not be decoded to answer the query.
    let mut body = String::from(
        "{\n  \"schema_version\": 7,\n  \"engine_version\": \"0.2.13\",\n  \"workspace_root\": \"/tmp/with \\\"quote\\\" and \\\\ slash\",\n  \"cache_dir\": \"/x\",\n  \"workspace_source_files\": [\n",
    );
    for index in 0..20_000 {
        body.push_str(&format!(
            "    {{\"hash\": {index}, \"stamp\": {{\"len\": 1}}}},\n"
        ));
    }
    body.push_str("  ]\n}\n");
    std::fs::write(&manifest, body).expect("write manifest");
    let parsed = manifest_workspace_root_head(&manifest).expect("read head");
    assert_eq!(parsed, Some(PathBuf::from("/tmp/with \"quote\" and \\ slash")));

    // Not one of our manifests: unattributed, never treated as orphaned.
    std::fs::write(&manifest, "{\"unrelated\": true}\n").expect("write other");
    assert_eq!(manifest_workspace_root_head(&manifest).expect("read other"), None);

    // Missing manifest surfaces as NotFound so the caller can apply the
    // manifest-less grace period.
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
