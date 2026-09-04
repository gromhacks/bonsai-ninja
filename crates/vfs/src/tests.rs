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
fn compiler_assigned_ids_preserve_sparse_workspace_identity() {
    let vfs = Vfs::new();
    let expected = FileId::new(7);
    let actual = vfs.write_with_id(expected, "scoped.py", "def scoped():\n    pass\n");

    assert_eq!(actual, expected);
    assert_eq!(vfs.lookup(Path::new("scoped.py")), Some(expected));
    assert_eq!(vfs.all_files(), vec![expected]);
    assert_eq!(vfs.file_count(), 1);
    assert_eq!(vfs.snapshot(expected).unwrap().file_id, expected);

    let updated = vfs.write_with_id(expected, "scoped.py", "def scoped():\n    return 1\n");
    assert_eq!(updated, expected);
    assert_eq!(vfs.snapshot(expected).unwrap().version, 1);
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
fn exact_suffix_lookup_is_indexed_unique_and_remove_safe() {
    let vfs = Vfs::new();
    let first = vfs.write("project/include/api/config.h", "#define API\n");
    assert_eq!(
        vfs.unique_file_ending_with(Path::new("api/config.h"))
            .map(|(file, _)| file),
        Some(first)
    );

    let second = vfs.write("vendor/api/config.h", "#define VENDOR_API\n");
    assert!(
        vfs.unique_file_ending_with(Path::new("api/config.h")).is_none(),
        "an ambiguous include suffix must fail closed"
    );
    assert_eq!(vfs.remove(Path::new("vendor/api/config.h")), Some(second));
    assert_eq!(
        vfs.unique_file_ending_with(Path::new("api/config.h"))
            .map(|(file, _)| file),
        Some(first),
        "removing one candidate must update the suffix directory"
    );
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

fn identity_for(text: &str) -> SourceIdentity {
    SourceIdentity {
        len: text.len() as u64,
        hash: text.len() as u64 ^ 0x5eed,
        digest: [7; 32],
    }
}

#[test]
fn lazy_entries_answer_metadata_without_a_loader() {
    let vfs = Vfs::new();
    let text = "print('hello')\n";
    let id = vfs.write_lazy("/lazy/a.py", identity_for(text));
    assert_eq!(vfs.lookup(Path::new("/lazy/a.py")), Some(id));
    assert_eq!(vfs.path(id).unwrap().as_path(), Path::new("/lazy/a.py"));
    assert_eq!(vfs.file_version(id).unwrap(), 0);
    assert_eq!(vfs.text_len(id).unwrap(), text.len() as u64);
    assert_eq!(vfs.lazy_identity(id), Some(identity_for(text)));
    assert_eq!(vfs.lazy_source_counts(), (1, 0));
    assert!(matches!(vfs.snapshot(id), Err(VfsError::MissingLazyLoader(_))));
    // Eager files report no identity and their real length.
    let eager = vfs.write("/lazy/b.py", "x = 1\n");
    assert_eq!(vfs.lazy_identity(eager), None);
    assert_eq!(vfs.text_len(eager).unwrap(), 6);
}

#[test]
fn lazy_snapshot_loads_once_then_behaves_like_an_eager_write() {
    let vfs = Vfs::new();
    let text = "def f():\n    return 1\n";
    let id = vfs.write_lazy("/lazy/a.py", identity_for(text));
    let loads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&loads);
    let expected = identity_for(text);
    vfs.set_lazy_loader(Arc::new(move |path: &Path, identity: &SourceIdentity| {
        assert_eq!(path, Path::new("/lazy/a.py"));
        assert_eq!(*identity, expected);
        counter.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::<str>::from("def f():\n    return 1\n"))
    }));
    let first = vfs.snapshot(id).unwrap();
    assert_eq!(first.text.as_ref(), text);
    assert_eq!(first.version, 0);
    let second = vfs.snapshot(id).unwrap();
    assert_eq!(second.text.as_ref(), text);
    assert_eq!(
        loads.load(Ordering::Relaxed),
        1,
        "the text is pinned after the first load"
    );
    assert_eq!(vfs.lazy_identity(id), None);
    assert_eq!(vfs.text_len(id).unwrap(), text.len() as u64);
    assert_eq!(vfs.lazy_source_counts(), (1, 1));
    // A later write bumps the version exactly like an eager file.
    vfs.write("/lazy/a.py", "changed\n");
    assert_eq!(vfs.file_version(id).unwrap(), 1);
    assert_eq!(vfs.snapshot(id).unwrap().text.as_ref(), "changed\n");
    assert_eq!(loads.load(Ordering::Relaxed), 1);
}

#[test]
fn lazy_loader_errors_surface_and_leave_the_entry_lazy() {
    let vfs = Vfs::new();
    let id = vfs.write_lazy("/lazy/a.py", identity_for("x\n"));
    vfs.set_lazy_loader(Arc::new(|_: &Path, _: &SourceIdentity| {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "changed on disk",
        ))
    }));
    let error = vfs.snapshot(id).unwrap_err();
    assert!(matches!(error, VfsError::LazyLoad { .. }), "{error}");
    assert!(error.to_string().contains("changed on disk"));
    assert_eq!(vfs.lazy_identity(id), Some(identity_for("x\n")));
    assert_eq!(vfs.lazy_source_counts(), (1, 0));
}

#[test]
fn writes_edits_and_removal_clear_lazy_identity() {
    let vfs = Vfs::new();
    let id = vfs.write_lazy("/lazy/a.py", identity_for("abc\n"));
    vfs.set_lazy_loader(Arc::new(|_: &Path, _: &SourceIdentity| {
        Ok(Arc::<str>::from("abc\n"))
    }));
    // Edits address the loaded text, so applying them loads first.
    let edit = TextEdit {
        file_id: id,
        old_start_byte: 0,
        old_end_byte: 1,
        new_end_byte: 1,
    };
    vfs.apply_edits(vec![edit], "Xbc\n").unwrap();
    assert_eq!(vfs.lazy_identity(id), None);
    assert_eq!(vfs.snapshot(id).unwrap().text.as_ref(), "Xbc\n");
    assert_eq!(vfs.file_version(id).unwrap(), 1);

    // A lazy re-intern of the same path replaces the text with the identity.
    let again = vfs.write_lazy("/lazy/a.py", identity_for("zz\n"));
    assert_eq!(again, id);
    assert_eq!(vfs.file_version(id).unwrap(), 2);
    assert_eq!(vfs.text_len(id).unwrap(), 3);
    vfs.write_with_id(id, "/lazy/a.py", "eager\n");
    assert_eq!(vfs.lazy_identity(id), None);
    assert_eq!(vfs.snapshot(id).unwrap().text.as_ref(), "eager\n");

    let lazy_b = vfs.write_lazy("/lazy/b.py", identity_for("b\n"));
    assert_eq!(vfs.remove(Path::new("/lazy/b.py")), Some(lazy_b));
    assert_eq!(vfs.lazy_identity(lazy_b), None);
    assert!(vfs.snapshot(lazy_b).is_err());
}
