//! Virtual filesystem for the analyzer.
//!
//! Responsibilities (spec §7):
//!
//! - Intern canonical paths and hand out stable `FileId`s.
//! - Store a versioned snapshot of each file's text.
//! - Accept in-memory overlays (for LSP / test harness / daemon).
//! - Record edits so the parser can do incremental reparsing.
//!
//! The VFS is single-writer, multi-reader; updates go through [`Vfs::write`]
//! which holds an exclusive lock, while reads can proceed concurrently.

use ahash::AHashMap;
use bonsai_common::FileId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

/// A text edit applied between two snapshots of the same file. Byte offsets
/// refer to the *old* snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEdit {
    pub file_id: FileId,
    pub old_start_byte: u32,
    pub old_end_byte: u32,
    pub new_end_byte: u32,
}

/// Immutable snapshot of a file's contents at a particular version.
#[derive(Clone, Debug)]
pub struct FileSnapshot {
    pub file_id: FileId,
    pub path: Arc<PathBuf>,
    pub text: Arc<str>,
    pub version: u64,
}

#[derive(Debug, Error)]
pub enum VfsError {
    #[error("unknown file id {0}")]
    UnknownFile(FileId),
    #[error("unknown path {0}")]
    UnknownPath(PathBuf),
    #[error("edit batch spans multiple files: expected {expected}, got {actual}")]
    MixedEditFiles { expected: FileId, actual: FileId },
}

/// Interned file registry with versioned snapshots.
#[derive(Debug, Default)]
pub struct Vfs {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    by_path: AHashMap<PathBuf, FileId>,
    files: Vec<Option<FileSnapshot>>,
    edits_since: Vec<Vec<TextEdit>>,
}

impl Vfs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a path and set or replace its contents. Returns the existing
    /// `FileId` if the path was seen before, otherwise mints a new one.
    ///
    /// On case-insensitive filesystems (the default on macOS HFS+/APFS,
    /// most Windows volumes) `Foo.py` and `foo.py` denote the same
    /// file. We canonicalise the lookup key by case-folding the path
    /// string so a workspace that resolves the file via two different
    /// casings is interned to a single FileId. The stored `path` field
    /// still carries the first casing the caller used.
    pub fn write(&self, path: impl Into<PathBuf>, text: impl Into<Arc<str>>) -> FileId {
        let path = path.into();
        let text = text.into();
        let lookup_key = canonical_path_key(&path);
        let mut inner = self.inner.write();
        if let Some(&id) = inner.by_path.get(&lookup_key) {
            let old = inner.files[id.raw() as usize]
                .clone()
                .expect("path table pointed at removed file");
            inner.files[id.raw() as usize] = Some(FileSnapshot {
                file_id: id,
                path: old.path,
                text,
                version: old.version + 1,
            });
            return id;
        }
        // INTENTIONAL: panic at the structural u32 boundary. `FileId`
        // is a `u32` newtype (per `crates/common/src/ids.rs`) — the
        // analyzer assumes file IDs fit in 32 bits across the
        // codebase (sidecar serialisation, ahash keys, GraphML
        // export). A workspace with 2^32 files would require a
        // FileId redesign, not a runtime fallback. The panic
        // surfaces that capacity limit cleanly instead of silently
        // wrapping. See docs/contributing/review-checklist.mdx §"no caps" rationale.
        let id = FileId::new(u32::try_from(inner.files.len()).expect("too many files"));
        let snapshot = FileSnapshot {
            file_id: id,
            path: Arc::new(path.clone()),
            text,
            version: 0,
        };
        inner.files.push(Some(snapshot));
        inner.edits_since.push(Vec::new());
        inner.by_path.insert(lookup_key, id);
        id
    }

    /// Remove a file from the intern table. Existing `FileId`s are
    /// tombstoned rather than compacted so stale IDs cannot point at a
    /// different file after a delete/re-add cycle.
    pub fn remove(&self, path: &Path) -> Option<FileId> {
        let lookup_key = canonical_path_key(path);
        let mut inner = self.inner.write();
        let id = inner.by_path.remove(&lookup_key)?;
        let idx = id.raw() as usize;
        if let Some(slot) = inner.files.get_mut(idx) {
            *slot = None;
        }
        if let Some(edits) = inner.edits_since.get_mut(idx) {
            edits.clear();
        }
        Some(id)
    }

    /// Apply an already-computed set of text edits to a file (LSP path).
    pub fn apply_edits(
        &self,
        edits: Vec<TextEdit>,
        new_text: impl Into<Arc<str>>,
    ) -> Result<FileId, VfsError> {
        let mut inner = self.inner.write();
        let Some(file_id) = edits.first().map(|e| e.file_id) else {
            return Err(VfsError::UnknownFile(FileId::INVALID));
        };
        if let Some(edit) = edits.iter().find(|edit| edit.file_id != file_id) {
            return Err(VfsError::MixedEditFiles {
                expected: file_id,
                actual: edit.file_id,
            });
        }
        let idx = file_id.raw() as usize;
        let prev = inner
            .files
            .get(idx)
            .and_then(Option::as_ref)
            .cloned()
            .ok_or(VfsError::UnknownFile(file_id))?;
        // Install the new snapshot first; only then push the edit
        // log. If the two vecs ever diverge in length (a future
        // change might add a fail-able step between snapshot
        // construction and write), this order ensures we never end
        // up with a half-applied state where `edits_since[idx]`
        // contains edits that aren't yet reflected in `files[idx]`.
        inner.files[idx] = Some(FileSnapshot {
            file_id,
            path: prev.path,
            text: new_text.into(),
            version: prev.version + 1,
        });
        inner.edits_since[idx].extend(edits);
        Ok(file_id)
    }

    /// Current snapshot for `file`. Errors when the id is unknown
    /// (typically a stale id after `remove_file` / VFS reset).
    pub fn snapshot(&self, file: FileId) -> Result<FileSnapshot, VfsError> {
        self.inner
            .read()
            .files
            .get(file.raw() as usize)
            .and_then(Option::as_ref)
            .cloned()
            .ok_or(VfsError::UnknownFile(file))
    }

    /// Path the VFS interned this file under.
    pub fn path(&self, file: FileId) -> Result<Arc<PathBuf>, VfsError> {
        self.snapshot(file).map(|snap| snap.path)
    }

    /// `FileId` for `path`, or `None` if the path was never written.
    pub fn lookup(&self, path: &Path) -> Option<FileId> {
        self.inner.read().by_path.get(&canonical_path_key(path)).copied()
    }

    /// Return and clear the queued edits for a file. The parser calls this
    /// when it wants to incrementally reparse.
    pub fn take_edits(&self, file: FileId) -> Result<Vec<TextEdit>, VfsError> {
        let mut inner = self.inner.write();
        let idx = file.raw() as usize;
        if idx >= inner.files.len() || inner.files[idx].is_none() {
            return Err(VfsError::UnknownFile(file));
        }
        Ok(std::mem::take(&mut inner.edits_since[idx]))
    }

    /// Snapshot of every interned `FileId`. Order is allocation
    /// order, which is determined by the workspace's deterministic
    /// ingest sort (see `Workspace::ingest_dir`).
    pub fn all_files(&self) -> Vec<FileId> {
        self.inner
            .read()
            .files
            .iter()
            .filter_map(|snap| snap.as_ref().map(|snap| snap.file_id))
            .collect()
    }

    /// Number of interned files.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.inner
            .read()
            .files
            .iter()
            .filter(|snap| snap.is_some())
            .count()
    }
}

/// Path interning key. We probe the filesystem for case sensitivity
/// instead of trusting the OS default — APFS volumes can be either,
/// and Windows now ships per-directory case-sensitive flags. When
/// the filesystem treats casings as distinct, `Foo.py` and `foo.py`
/// stay separate FileIds; otherwise we fold to lowercase to avoid
/// double-counting facts.
fn canonical_path_key(path: &Path) -> PathBuf {
    if filesystem_is_case_insensitive(path) {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    } else {
        path.to_path_buf()
    }
}

/// Probe whether the directory that will contain `path` is
/// case-insensitive. APFS is volume-scoped, but Windows can opt into
/// case-sensitive lookup per directory, so the probe must happen inside
/// the containing directory rather than by changing that directory's own
/// name in its parent. Cached per canonical directory to keep the cost a
/// one-time hit.
fn filesystem_is_case_insensitive(path: &Path) -> bool {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<std::collections::HashMap<PathBuf, bool>>> = OnceLock::new();
    let dir = nearest_existing_directory(path);
    let cache_key = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    if let Some(hit) = cache.lock().ok().and_then(|m| m.get(&cache_key).copied()) {
        return hit;
    }
    // Fallback: trust the OS default if we can't probe.
    let default = cfg!(any(target_os = "macos", target_os = "windows"));
    let probe = probe_case_insensitive_with_temp(&dir)
        .or_else(|| probe_case_insensitive_from_entries(&dir))
        .unwrap_or(default);
    if let Ok(mut m) = cache.lock() {
        m.insert(cache_key, probe);
    }
    probe
}

fn nearest_existing_directory(path: &Path) -> PathBuf {
    let start = if path.is_dir() {
        path
    } else {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    };
    start
        .ancestors()
        .find(|candidate| candidate.is_dir())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn probe_case_insensitive_with_temp(dir: &Path) -> Option<bool> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let name = format!(".bonsai_case_probe_{}_{}", std::process::id(), nanos);
    let probe = dir.join(&name);
    let alternate = dir.join(name.to_uppercase());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .ok()?;
    drop(file);

    let result = match (std::fs::canonicalize(&probe), std::fs::canonicalize(&alternate)) {
        (Ok(original), Ok(alt)) => Some(original == alt),
        (Ok(_), Err(err)) if err.kind() == std::io::ErrorKind::NotFound => Some(false),
        _ => None,
    };
    let _ = std::fs::remove_file(&probe);
    result
}

fn probe_case_insensitive_from_entries(dir: &Path) -> Option<bool> {
    for entry in std::fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let mut alternate_name = name.to_uppercase();
        if alternate_name == name {
            alternate_name = name.to_lowercase();
        }
        if alternate_name == name {
            continue;
        }
        let alternate = dir.join(alternate_name);
        let Ok(original) = std::fs::canonicalize(entry.path()) else {
            continue;
        };
        match std::fs::canonicalize(&alternate) {
            Ok(alt) => return Some(alt == original),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Some(false),
            Err(_) => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
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
        let a = vfs.write("a.rs", "fn main() {}");
        let b = vfs.write("a.rs", "fn main() { 1 }");
        assert_eq!(a, b);
        assert_eq!(vfs.snapshot(a).unwrap().version, 1);
        let c = vfs.write("b.rs", "fn other() {}");
        assert_ne!(a, c);
    }

    #[test]
    fn remove_tombstones_file_without_reusing_id() {
        let vfs = Vfs::new();
        let a = vfs.write("a.rs", "fn main() {}");
        assert_eq!(vfs.remove(Path::new("a.rs")), Some(a));
        assert!(vfs.lookup(Path::new("a.rs")).is_none());
        assert!(matches!(vfs.snapshot(a), Err(VfsError::UnknownFile(_))));
        assert!(vfs.all_files().is_empty());
        assert_eq!(vfs.file_count(), 0);

        let b = vfs.write("a.rs", "fn main() { 1 }");
        assert_ne!(a, b, "deleted FileIds must not be reused");
        assert_eq!(vfs.file_count(), 1);
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
}
