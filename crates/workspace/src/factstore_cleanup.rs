//! Lock-proven cleanup for FactStore staging files.
//!
//! [`bonsai_factstore::FactStoreWriter`] publishes through a unique
//! `<target>.tmp.<pid>.<counter>` file. Normal `Drop` removes that file, but
//! the operating system cannot run `Drop` after a hard kill. Callers must hold
//! the target's advisory writer lock before using these helpers; the filename
//! alone is not proof that a writer is dead.

use ahash::AHashSet;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use fs2::FileExt;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::fs::File;
use std::path::Path;

/// Convert storage-layer failures into the workspace facade's I/O error
/// contract without making callers depend on FactStore internals.
pub(crate) fn map_factstore_io(error: bonsai_factstore::FactStoreError) -> std::io::Error {
    match error {
        bonsai_factstore::FactStoreError::Io(error) => error,
        other => std::io::Error::other(other),
    }
}

/// Copy entries not replaced by the current compiler pass from an older
/// immutable FactStore generation into its successor.
pub(crate) fn forward_port_unwritten_entries(
    existing: Option<&FactStoreReader>,
    writer: &FactStoreWriter,
    written_keys: &Mutex<AHashSet<u64>>,
) -> std::io::Result<()> {
    let Some(existing) = existing else {
        return Ok(());
    };
    let mut written_keys = written_keys.lock();
    for item in existing.iter() {
        let (key, hit) = item.map_err(map_factstore_io)?;
        if written_keys.contains(&key) {
            continue;
        }
        writer
            .add(key, hit.body_hash, &hit.payload)
            .map_err(map_factstore_io)?;
        written_keys.insert(key);
    }
    Ok(())
}

pub(crate) fn cleanup_valid_sidecar_temp_files(path: &Path) -> std::io::Result<usize> {
    let Some(parent) = path.parent() else {
        return Ok(0);
    };
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(0);
    };
    let prefix = format!("{file_name}.tmp.");
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0usize;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(writer_suffix) = name.to_str().and_then(|name| name.strip_prefix(&prefix)) else {
            continue;
        };
        if !factstore_writer_suffix_is_valid(writer_suffix) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(removed)
}

pub(crate) fn factstore_writer_suffix_is_valid(suffix: &str) -> bool {
    let mut parts = suffix.split('.');
    parts.next().is_some_and(|pid| pid.parse::<u32>().is_ok())
        && parts.next().is_some_and(|counter| counter.parse::<u64>().is_ok())
        && parts.next().is_none()
}

/// Remove older members of one versioned sidecar family while respecting
/// each target's writer lock. A busy target is skipped because another
/// process may still own that immutable generation.
pub(crate) fn prune_obsolete_versioned_sidecars(
    current_path: &Path,
    version_of: impl Fn(&str) -> Option<u32>,
    acquire_lock: impl Fn(&Path) -> std::io::Result<File>,
    family_label: &str,
) -> std::io::Result<usize> {
    let Some(parent) = current_path.parent() else {
        return Ok(0);
    };
    let Some(current_version) = current_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(&version_of)
    else {
        return Ok(0);
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut obsolete = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if version_of(name).is_some_and(|version| version < current_version) {
            obsolete.insert(entry.path());
        }
    }

    let mut removed = 0usize;
    for target in obsolete {
        let lock_file = match acquire_lock(&target) {
            Ok(lock_file) => lock_file,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    family = family_label,
                    "skipping superseded sidecar cleanup"
                );
                continue;
            }
        };
        match std::fs::remove_file(&target) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    family = family_label,
                    "superseded sidecar cleanup failed"
                );
            }
        }
        if let Err(error) = FileExt::unlock(&lock_file) {
            tracing::warn!(
                path = %target.display(),
                error = %error,
                family = family_label,
                "superseded sidecar cleanup lock release failed"
            );
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_removes_only_exact_writer_temps() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("idg.factstore");
        let valid = dir.path().join("idg.factstore.tmp.1234.5");
        let malformed = dir.path().join("idg.factstore.tmp.not-a-pid.5");
        let extra = dir.path().join("idg.factstore.tmp.1234.5.extra");
        let unrelated = dir.path().join("other.factstore.tmp.1234.5");
        let directory = dir.path().join("idg.factstore.tmp.1234.6");
        for path in [&valid, &malformed, &extra, &unrelated] {
            std::fs::write(path, b"partial").expect("write fixture");
        }
        std::fs::create_dir(&directory).expect("create directory fixture");

        assert_eq!(cleanup_valid_sidecar_temp_files(&target).expect("cleanup"), 1);
        assert!(!valid.exists());
        assert!(malformed.exists());
        assert!(extra.exists());
        assert!(unrelated.exists());
        assert!(directory.exists());
    }
}
