//! Shared freshness fingerprints for persisted workspace analysis caches.
//!
//! These helpers intentionally live below the SDK/CLI layer so
//! analysis sidecars use the same source and dependency-metadata
//! freshness model as rendered/export caches.

use bonsai_common::dependency_metadata::walk_dependency_metadata_files;
use bonsai_common::{workspace_bonsai_dir, write_atomic_bytes};
use bonsai_db::AnalyzerDb;
use bonsai_factstore::FactStoreError;
use bonsai_hash::fnv1a_bytes64;
use fs2::FileExt;
use std::path::{Path, PathBuf};

const WORKSPACE_ROOT_MARKER: &str = ".workspace-root.v1";
const WORKSPACE_ROOT_LOCK: &str = ".workspace-root.lock";
const WORKSPACE_ROOT_MAGIC: &[u8] = b"BONSAI-WORKSPACE-ROOT\0\x01";
// Pre-external-cache sidecars recorded `0` because their source root could
// not be recovered from the cache path. A distinct nonzero value makes an
// unbound directory fail closed during migration instead of accepting those
// stale dependency semantics. Normal production opens register the marker
// before any sidecar access.
const UNBOUND_WORKSPACE_DEPENDENCY_FINGERPRINT: u64 = 0xd541_6f4a_21ce_b783;

pub(crate) fn workspace_content_fingerprint(db: &AnalyzerDb) -> u64 {
    let entries = db.vfs().all_files().into_iter().filter_map(|file| {
        let path = db.vfs().path(file).ok()?.display().to_string();
        let snap = db.vfs().snapshot(file).ok()?;
        Some((path, fnv1a_bytes64(snap.text.as_bytes())))
    });
    workspace_content_fingerprint_from_entries(entries)
}

pub(crate) fn workspace_content_fingerprint_from_paths<I, P>(fingerprints: I) -> u64
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    workspace_content_fingerprint_from_entries(
        fingerprints
            .into_iter()
            .map(|(path, hash)| (path.as_ref().display().to_string(), hash)),
    )
}

fn workspace_content_fingerprint_from_entries<I>(entries: I) -> u64
where
    I: IntoIterator<Item = (String, u64)>,
{
    let mut entries: Vec<(String, u64)> = entries.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = bonsai_hash::Hasher::new();
    for (path, content) in &entries {
        h.absorb(path.as_bytes());
        h.absorb_separator();
        h.absorb(&content.to_le_bytes());
        h.absorb_separator();
    }
    h.finish()
}

pub(crate) fn dependency_metadata_fingerprint(root: &Path) -> u64 {
    let mut entries = Vec::new();
    let _ = walk_dependency_metadata_files(root, |path, rel| {
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(());
        };
        entries.push((rel.to_string(), fnv1a_bytes64(&bytes)));
        Ok(())
    });
    fingerprint_entries(entries)
}

pub(crate) fn dependency_metadata_fingerprint_for_sidecar(sidecar: &Path) -> u64 {
    workspace_root_for_sidecar(sidecar)
        .as_deref()
        .map(dependency_metadata_fingerprint)
        .unwrap_or(UNBOUND_WORKSPACE_DEPENDENCY_FINGERPRINT)
}

/// Bind the external cache directory to one canonical workspace root.
///
/// Sidecars are intentionally stored outside the inspected repository. Their
/// paths therefore no longer reveal which dependency manifests belong to the
/// source generation. Persist this small native-path marker before any
/// sidecar is read or written so every cache family shares the same freshness
/// root. A lock prevents an explicit absolute `BONSAI_WORKSPACE_DIR` from
/// being raced between two different workspaces.
pub(crate) fn register_workspace_cache_root(workspace_root: &Path) -> std::io::Result<PathBuf> {
    let root = canonical_workspace_root(workspace_root);
    let cache_dir = workspace_bonsai_dir(&root);
    std::fs::create_dir_all(&cache_dir)?;

    let lock_path = cache_dir.join(WORKSPACE_ROOT_LOCK);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    lock.lock_exclusive()?;

    let marker_path = cache_dir.join(WORKSPACE_ROOT_MARKER);
    let encoded = encode_workspace_root(&root);
    match std::fs::read(&marker_path) {
        Ok(existing) if existing == encoded => {}
        Ok(existing) => {
            if let Some(other) = decode_workspace_root(&existing) {
                if std::env::var_os("BONSAI_WORKSPACE_DIR").is_some_and(|value| !value.is_empty()) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "workspace cache {} is already bound to {}; use a distinct BONSAI_WORKSPACE_DIR for {}",
                            cache_dir.display(),
                            other.display(),
                            root.display()
                        ),
                    ));
                }
                // The default directory is derived from the canonical root,
                // so a different valid marker can only be a manually copied
                // cache (or an astronomically unlikely hash collision).
                // Rebind it: every semantic sidecar also validates exact
                // source paths/content and the manifest validates this root.
                write_atomic_bytes(&marker_path, &encoded)?;
                drop(lock);
                return Ok(cache_dir);
            }
            // A corrupt/torn marker cannot safely identify any old sidecar.
            // Atomic replacement binds the directory; the resulting nonzero
            // dependency fingerprint rejects artifacts written without it.
            write_atomic_bytes(&marker_path, &encoded)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_atomic_bytes(&marker_path, &encoded)?;
        }
        Err(error) => return Err(error),
    }
    drop(lock);
    Ok(cache_dir)
}

fn workspace_root_for_sidecar(sidecar: &Path) -> Option<PathBuf> {
    let parent = sidecar.parent()?;
    if parent.file_name().and_then(|name| name.to_str()) == Some(".bonsai") {
        return parent.parent().map(canonical_workspace_root);
    }
    decode_workspace_root(&std::fs::read(parent.join(WORKSPACE_ROOT_MARKER)).ok()?)
}

fn canonical_workspace_root(root: &Path) -> PathBuf {
    root.canonicalize()
        .ok()
        .or_else(|| {
            if root.is_absolute() {
                Some(root.to_path_buf())
            } else {
                std::env::current_dir().ok().map(|cwd| cwd.join(root))
            }
        })
        .unwrap_or_else(|| root.to_path_buf())
}

#[cfg(unix)]
fn encode_workspace_root(root: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = Vec::with_capacity(WORKSPACE_ROOT_MAGIC.len() + root.as_os_str().as_bytes().len());
    bytes.extend_from_slice(WORKSPACE_ROOT_MAGIC);
    bytes.extend_from_slice(root.as_os_str().as_bytes());
    bytes
}

#[cfg(unix)]
fn decode_workspace_root(bytes: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let raw = bytes.strip_prefix(WORKSPACE_ROOT_MAGIC)?;
    (!raw.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
}

#[cfg(windows)]
fn encode_workspace_root(root: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(WORKSPACE_ROOT_MAGIC);
    for unit in root.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

#[cfg(windows)]
fn decode_workspace_root(bytes: &[u8]) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let raw = bytes.strip_prefix(WORKSPACE_ROOT_MAGIC)?;
    if raw.is_empty() || raw.len() % 2 != 0 {
        return None;
    }
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    Some(PathBuf::from(std::ffi::OsString::from_wide(&units)))
}

#[cfg(not(any(unix, windows)))]
fn encode_workspace_root(root: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(WORKSPACE_ROOT_MAGIC);
    bytes.extend_from_slice(root.to_string_lossy().as_bytes());
    bytes
}

#[cfg(not(any(unix, windows)))]
fn decode_workspace_root(bytes: &[u8]) -> Option<PathBuf> {
    let raw = bytes.strip_prefix(WORKSPACE_ROOT_MAGIC)?;
    (!raw.is_empty()).then(|| PathBuf::from(String::from_utf8_lossy(raw).into_owned()))
}

pub(crate) fn discard_stale_factstore_sidecar(path: &Path, err: &FactStoreError) {
    if factstore_sidecar_error_is_discardable(err) {
        let _ = std::fs::remove_file(path);
    }
}

pub(crate) fn factstore_sidecar_error_is_discardable(err: &FactStoreError) -> bool {
    matches!(
        err,
        FactStoreError::BadMagic
            | FactStoreError::Truncated { .. }
            | FactStoreError::VersionMismatch { .. }
            | FactStoreError::PipelineMismatch { .. }
            | FactStoreError::WrongTable { .. }
            | FactStoreError::BadStringPool(_)
            | FactStoreError::BadIndexEntry { .. }
            | FactStoreError::UnsortedIndex
            | FactStoreError::DuplicateKey(_)
    )
}

fn fingerprint_entries(mut entries: Vec<(String, u64)>) -> u64 {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = bonsai_hash::Hasher::new();
    for (path, digest) in entries {
        h.absorb(path.as_bytes());
        h.absorb_separator();
        h.absorb(&digest.to_le_bytes());
        h.absorb_separator();
    }
    h.finish()
}

#[cfg(test)]
#[path = "cache_fingerprint_tests.rs"]
mod tests;
