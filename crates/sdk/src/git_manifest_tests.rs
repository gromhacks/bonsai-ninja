use super::*;
use std::{
    path::Path,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "bonsai-sdk-{label}-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create test workspace");
    path
}

fn git(root: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .status()
        .is_ok_and(|status| status.success())
}

fn init_git_workspace(label: &str, source: &str) -> Option<PathBuf> {
    let root = tempdir(label);
    if !git(&root, &["init", "-q"]) {
        let _ = std::fs::remove_dir_all(root);
        return None;
    }
    std::fs::write(root.join("app.py"), source).expect("write source");
    assert!(git(&root, &["add", "app.py"]));
    assert!(git(
        &root,
        &[
            "-c",
            "user.name=Bonsai Test",
            "-c",
            "user.email=bonsai@example.invalid",
            "commit",
            "-qm",
            "initial",
        ],
    ));
    Some(root)
}

#[test]
fn workspace_cache_persists_canonical_workspace_identity() {
    let root = tempdir("canonical-cache-root");
    std::fs::create_dir(root.join("nested")).expect("create nested directory");
    std::fs::write(root.join("app.py"), "def run():\n    return 1\n").expect("write source");
    let spelled = root.join("nested").join("..");
    let expected = root.canonicalize().expect("canonical root");

    let cache = WorkspaceCache::new(&spelled);
    assert_eq!(cache.root(), expected);
    let manifest = cache.manifest().expect("build manifest");
    assert_eq!(manifest.workspace_root, expected);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn unchanged_git_snapshot_reuses_manifest_source_hashes() {
    let Some(root) = init_git_workspace("git-manifest-reuse", "def original():\n    return 1\n") else {
        return;
    };
    let cache = WorkspaceCache::new(&root);
    let mut manifest = cache.manifest().expect("build manifest");
    assert!(
        manifest.git_source_state.is_some(),
        "a quiescent Git worktree should record an acceleration proof"
    );
    assert_eq!(manifest.workspace_source_files.len(), 1);

    let sentinel = 0xfeed_beef_dead_cafe;
    manifest.workspace_source_files[0].hash = sentinel;
    let validated = source_file_fingerprints_for_cache_validation(&root, Some(&manifest))
        .expect("validate unchanged Git snapshot");
    assert_eq!(validated.len(), 1);
    assert_eq!(
        validated[0].hash, sentinel,
        "an unchanged exact Git snapshot should reuse the manifest's compiler input table"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn dirty_source_identity_invalidates_git_fast_path() {
    let Some(root) = init_git_workspace("git-manifest-dirty", "def original():\n    return 1\n") else {
        return;
    };
    let cache = WorkspaceCache::new(&root);
    let mut manifest = cache.manifest().expect("build manifest");
    let recorded_hash = manifest.workspace_source_files[0].hash;
    manifest.workspace_source_files[0].hash = 0xfeed_beef_dead_cafe;

    std::fs::write(root.join("app.py"), "def changed():\n    return 2\n").expect("change tracked source");
    let validated = source_file_fingerprints_for_cache_validation(&root, Some(&manifest))
        .expect("validate changed Git snapshot");
    assert_eq!(validated.len(), 1);
    assert_ne!(validated[0].hash, 0xfeed_beef_dead_cafe);
    assert_ne!(validated[0].hash, recorded_hash);

    // Once a dirty source is recorded, another same-path rewrite must still
    // invalidate via its strong ctime/device/inode stamp even though Git's
    // porcelain status text remains ` M app.py`.
    let dirty_manifest = cache.manifest().expect("record dirty snapshot");
    let dirty_hash = dirty_manifest.workspace_source_files[0].hash;
    std::fs::write(root.join("app.py"), "def changed_again():\n    return 3\n")
        .expect("rewrite already-dirty source");
    let revalidated = source_file_fingerprints_for_cache_validation(&root, Some(&dirty_manifest))
        .expect("validate rewritten dirty source");
    assert_ne!(revalidated[0].hash, dirty_hash);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn head_and_untracked_source_changes_invalidate_git_fast_path() {
    let Some(root) = init_git_workspace("git-manifest-index", "def original():\n    return 1\n") else {
        return;
    };
    let cache = WorkspaceCache::new(&root);
    let manifest = cache.manifest().expect("build manifest");

    std::fs::write(root.join("extra.py"), "def extra():\n    return 2\n").expect("add source");
    let with_untracked = source_file_fingerprints_for_cache_validation(&root, Some(&manifest))
        .expect("validate untracked source");
    assert_eq!(with_untracked.len(), 2);

    assert!(git(&root, &["add", "extra.py"]));
    assert!(git(
        &root,
        &[
            "-c",
            "user.name=Bonsai Test",
            "-c",
            "user.email=bonsai@example.invalid",
            "commit",
            "-qm",
            "add source",
        ],
    ));
    let after_commit = source_file_fingerprints_for_cache_validation(&root, Some(&manifest))
        .expect("validate changed index tree");
    assert_eq!(after_commit.len(), 2);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn bonsai_cache_directories_are_never_compiler_inputs() {
    let Some(root) = init_git_workspace("git-manifest-cache-dir", "def original():\n    return 1\n") else {
        return;
    };
    std::fs::create_dir_all(root.join(".bonsai/nested")).expect("create cache directory");
    std::fs::write(
        root.join(".bonsai/nested/cache_payload.py"),
        "def must_not_be_indexed():\n    return 0\n",
    )
    .expect("write source-shaped cache payload");

    let fingerprints = source_file_fingerprints_from_disk(&root).expect("fingerprint workspace");
    assert_eq!(fingerprints.len(), 1);
    assert!(fingerprints[0].path.ends_with("app.py"));
    let _ = std::fs::remove_dir_all(root);
}
