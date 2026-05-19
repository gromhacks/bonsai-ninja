//! Shared freshness fingerprints for persisted workspace analysis caches.
//!
//! These helpers intentionally live below the SDK/CLI layer so
//! analysis sidecars use the same source and dependency-metadata
//! freshness model as rendered/export caches.

use bonsai_common::dependency_metadata::walk_dependency_metadata_files;
use bonsai_db::AnalyzerDb;
use bonsai_factstore::FactStoreError;
use bonsai_hash::fnv1a_bytes64;
use std::path::Path;

pub(crate) fn workspace_content_fingerprint(db: &AnalyzerDb) -> u64 {
    let mut entries: Vec<(String, u64)> = db
        .vfs()
        .all_files()
        .into_iter()
        .filter_map(|file| {
            let path = db.vfs().path(file).ok()?.display().to_string();
            let snap = db.vfs().snapshot(file).ok()?;
            Some((path, fnv1a_bytes64(snap.text.as_bytes())))
        })
        .collect();
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
    sidecar
        .parent()
        .filter(|parent| parent.file_name().and_then(|name| name.to_str()) == Some(".bonsai"))
        .and_then(Path::parent)
        .map(dependency_metadata_fingerprint)
        .unwrap_or(0)
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
