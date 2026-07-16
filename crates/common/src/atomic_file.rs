//! Durable atomic replacement for small cache and metadata files.
//!
//! Large streaming analysis artifacts use the factstore writer directly.
//! JSON manifests, page-cache payloads, and whole-object compatibility
//! sidecars share this helper so temp naming, cleanup, file synchronization,
//! and parent-directory synchronization cannot drift between crates.

use std::io::{self, Write};
use std::path::Path;

/// Write all `bytes` to a temporary file beside `path`, synchronize the
/// file, atomically replace `path`, then synchronize the parent directory.
///
/// The temporary file is removed automatically if writing, syncing, or
/// persistence fails. Keeping it in the destination directory preserves
/// same-filesystem rename semantics.
pub fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
    }
    let temp_parent = parent.unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".bonsai-atomic-")
        .tempfile_in(temp_parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    if let Some(parent) = parent {
        if let Ok(directory) = std::fs::File::open(parent) {
            directory.sync_all()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_atomic_bytes;

    #[test]
    fn atomically_replaces_existing_payload() {
        let directory = tempfile::tempdir().expect("tempdir");
        let target = directory.path().join("manifest.json");
        std::fs::write(&target, b"old").expect("seed target");

        write_atomic_bytes(&target, b"new payload").expect("replace target");

        assert_eq!(std::fs::read(&target).expect("read target"), b"new payload");
        let leftovers = std::fs::read_dir(directory.path())
            .expect("read tempdir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".bonsai-atomic-"))
            .count();
        assert_eq!(leftovers, 0, "successful writes must not leave temp files");
    }
}
