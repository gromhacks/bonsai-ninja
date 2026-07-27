//! Lock-proven cleanup for FactStore staging files.
//!
//! [`bonsai_factstore::FactStoreWriter`] publishes through a unique
//! `<target>.tmp.<pid>.<counter>` file. Normal `Drop` removes that file, but
//! the operating system cannot run `Drop` after a hard kill. Callers must hold
//! the target's advisory writer lock before using these helpers; the filename
//! alone is not proof that a writer is dead.

use std::path::Path;

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
