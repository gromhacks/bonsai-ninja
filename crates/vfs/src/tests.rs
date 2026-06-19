use super::*;

fn tempdir(name: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("bonsai-vfs-{name}-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    path
}

#[test]
fn write_interns_and_versions() {
    let vfs = Vfs::new();
    assert_ne!(vfs.instance_id(), 0);
    assert_eq!(vfs.revision(), 0);
    let a = vfs.write("a.rs", "fn main() {}");
    assert_eq!(vfs.revision(), 1);
    let b = vfs.write("a.rs", "fn main() { 1 }");
    assert_eq!(a, b);
    assert_eq!(vfs.snapshot(a).unwrap().version, 1);
    assert_eq!(vfs.revision(), 2);
    let c = vfs.write("b.rs", "fn other() {}");
    assert_ne!(a, c);
    assert_eq!(vfs.revision(), 3);
}

#[test]
fn new_instances_have_distinct_cache_identity() {
    let a = Vfs::new();
    let b = Vfs::new();

    assert_ne!(a.instance_id(), b.instance_id());
    assert_eq!(a.revision(), b.revision());
}

#[test]
fn remove_tombstones_file_without_reusing_id() {
    let vfs = Vfs::new();
    let a = vfs.write("a.rs", "fn main() {}");
    let before_remove = vfs.revision();
    assert_eq!(vfs.remove(Path::new("a.rs")), Some(a));
    assert_eq!(vfs.revision(), before_remove + 1);
    assert!(vfs.lookup(Path::new("a.rs")).is_none());
    assert!(matches!(vfs.snapshot(a), Err(VfsError::UnknownFile(_))));
    assert!(vfs.all_files().is_empty());
    assert_eq!(vfs.file_count(), 0);

    let b = vfs.write("a.rs", "fn main() { 1 }");
    assert_ne!(a, b, "deleted FileIds must not be reused");
    assert_eq!(vfs.file_count(), 1);
}

#[test]
fn apply_edits_bumps_workspace_revision() {
    let vfs = Vfs::new();
    let a = vfs.write("a.rs", "abc");
    let before = vfs.revision();

    vfs.apply_edits(
        vec![TextEdit {
            file_id: a,
            old_start_byte: 1,
            old_end_byte: 2,
            new_end_byte: 1,
        }],
        "axc",
    )
    .unwrap();

    assert_eq!(vfs.snapshot(a).unwrap().text.as_ref(), "axc");
    assert_eq!(vfs.revision(), before + 1);
}

#[test]
fn apply_edits_rejects_mixed_file_batches_without_mutating() {
    let vfs = Vfs::new();
    let a = vfs.write("a.rs", "a");
    let b = vfs.write("b.rs", "b");

    let err = vfs
        .apply_edits(
            vec![
                TextEdit {
                    file_id: a,
                    old_start_byte: 0,
                    old_end_byte: 1,
                    new_end_byte: 1,
                },
                TextEdit {
                    file_id: b,
                    old_start_byte: 0,
                    old_end_byte: 1,
                    new_end_byte: 1,
                },
            ],
            "changed",
        )
        .unwrap_err();

    assert!(matches!(
        err,
        VfsError::MixedEditFiles {
            expected,
            actual
        } if expected == a && actual == b
    ));
    assert_eq!(vfs.snapshot(a).unwrap().text.as_ref(), "a");
    assert!(vfs.take_edits(a).unwrap().is_empty());
}

#[test]
fn nearest_existing_directory_uses_containing_directory() {
    let root = tempdir("nearest-dir");
    let child = root.join("CHILD");
    std::fs::create_dir(&child).unwrap();
    let missing_file = child.join("missing.rs");

    assert_eq!(nearest_existing_directory(&missing_file), child);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn canonical_path_key_matches_directory_case_behavior() {
    let root = tempdir("case-key");
    let insensitive = probe_case_insensitive_with_temp(&root).expect("tempdir case probe");
    let upper = canonical_path_key(&root.join("CaseProbe.rs"));
    let lower = canonical_path_key(&root.join("caseprobe.rs"));

    if insensitive {
        assert_eq!(upper, lower);
    } else {
        assert_ne!(upper, lower);
    }
    let _ = std::fs::remove_dir_all(root);
}
