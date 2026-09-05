use std::path::PathBuf;

#[cfg(unix)]
use super::{digest_from_hex, lazy_source_table_from_manifest, CACHE_MANIFEST_SCHEMA_VERSION};
use super::{hex_digest, manifest_source_files, WorkspaceCache};

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
fn digest_hex_round_trips_and_rejects_malformed_text() {
    let digest: [u8; 32] = core::array::from_fn(|index| (index as u8).wrapping_mul(37));
    let hex = hex_digest(&digest);
    assert_eq!(hex.len(), 64);
    assert_eq!(digest_from_hex(&hex), Some(digest));
    assert_eq!(digest_from_hex(&hex[..63]), None);
    assert_eq!(digest_from_hex(&format!("zz{}", &hex[2..])), None);
}

#[test]
#[cfg(unix)]
fn manifest_records_text_digests_only_for_verbatim_utf8_sources() {
    let root = tempdir("lazy-manifest");
    std::fs::write(root.join("plain.py"), "def plain():\n    return 1\n").expect("plain");
    // A grammar-normalised byte inside a comment: the loaded text differs
    // from the bytes on disk, so no identity may be recorded.
    let mut odd = b"# legacy quote: x\ndef odd():\n    return 2\n".to_vec();
    let marker = odd.iter().position(|byte| *byte == b'x').expect("marker");
    odd[marker] = 0x92;
    std::fs::write(root.join("odd.py"), &odd).expect("odd");

    let cache = WorkspaceCache::new(&root);
    let manifest = cache.manifest().expect("manifest");
    assert_eq!(manifest.schema_version, CACHE_MANIFEST_SCHEMA_VERSION);
    let by_name = |name: &str| {
        manifest
            .workspace_source_files
            .iter()
            .find(|file| file.stamp.path.file_name().and_then(|n| n.to_str()) == Some(name))
            .unwrap_or_else(|| panic!("{name} recorded"))
    };
    let plain = by_name("plain.py");
    let registry = bonsai_adapters::all_languages_registry();
    let workspace = bonsai_workspace::Workspace::new_with_open_options(
        registry,
        bonsai_workspace::WorkspaceOpenOptions::lazy_query(),
    );
    let identities = workspace.source_file_identities(&root).expect("identities");
    let expected = identities
        .iter()
        .find(|identity| identity.path.file_name().and_then(|n| n.to_str()) == Some("plain.py"))
        .expect("plain identity");
    assert!(expected.text_exact);
    assert_eq!(plain.hash, expected.hash);
    assert_eq!(
        plain.text_digest.as_deref(),
        Some(hex_digest(&expected.digest).as_str())
    );
    assert_eq!(by_name("odd.py").text_digest, None);

    // The lazy table carries exactly the identified files, keyed by the
    // paths the workspace walk yields.
    let table = lazy_source_table_from_manifest(&root, &manifest, false).expect("table");
    assert_eq!(table.len(), 1);
    // A different compiler-input profile or schema is never trusted.
    assert!(lazy_source_table_from_manifest(&root, &manifest, true).is_none());
    let mut stale = manifest.clone();
    stale.schema_version -= 1;
    assert!(lazy_source_table_from_manifest(&root, &stale, false).is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn manifest_source_files_require_the_stamp_to_describe_the_identified_bytes() {
    let root = tempdir("lazy-stamp");
    let path = root.join("a.py");
    std::fs::write(&path, "x = 1\n").expect("write");
    let registry = bonsai_adapters::all_languages_registry();
    let workspace = bonsai_workspace::Workspace::new_with_open_options(
        registry,
        bonsai_workspace::WorkspaceOpenOptions::lazy_query(),
    );
    let identities = workspace.source_file_identities(&root).expect("identities");
    let mut stamps = workspace.source_file_stamps(&root).expect("stamps");
    assert!(manifest_source_files(&identities, &stamps)[0]
        .text_digest
        .is_some());
    // The file grew between hashing and stamping: the stamp no longer
    // describes the hashed bytes, so the identity is withheld.
    stamps[0].len += 1;
    assert_eq!(manifest_source_files(&identities, &stamps)[0].text_digest, None);
    let _ = std::fs::remove_dir_all(&root);
}
