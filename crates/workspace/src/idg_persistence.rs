//! Cross-process ownership for workspace IDG sidecar generations.
//!
//! IDG persistence can stage many large FactStore payloads beside one target.
//! Unique temp names prevent collisions, but they do not serialize publication
//! or prove that a leftover temp is abandoned. The guard below owns a
//! target-specific advisory lock for the entire compiler build and removes
//! only well-formed staging files after ownership is established.

use crate::factstore_cleanup::{
    cleanup_valid_sidecar_temp_files, factstore_writer_suffix_is_valid, prune_obsolete_versioned_sidecars,
};
use fs2::FileExt;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct IdgSidecarWriteGuard {
    lock_file: File,
    target: PathBuf,
}

impl IdgSidecarWriteGuard {
    pub(crate) fn acquire(target: &Path) -> std::io::Result<Self> {
        let lock_file = open_lock_file(target)?;
        lock_file.lock_exclusive()?;
        Self::finish_acquire(lock_file, target)
    }

    pub(crate) fn try_acquire(target: &Path) -> std::io::Result<Self> {
        let lock_file = open_lock_file(target)?;
        lock_file.try_lock_exclusive()?;
        Self::finish_acquire(lock_file, target)
    }

    fn finish_acquire(lock_file: File, target: &Path) -> std::io::Result<Self> {
        let removed = cleanup_abandoned_idg_sidecar_temp_files(target)?;
        if removed != 0 {
            tracing::debug!(
                path = %target.display(),
                removed,
                "removed abandoned IDG FactStore staging files"
            );
        }
        let guard = Self {
            lock_file,
            target: target.to_path_buf(),
        };
        let obsolete = guard.prune_obsolete_versions()?;
        if obsolete != 0 {
            tracing::debug!(
                path = %target.display(),
                removed = obsolete,
                "removed superseded IDG FactStore generations"
            );
        }
        Ok(guard)
    }

    /// Remove finalized sidecars from older IDG schemas.
    ///
    /// The current target lock is already held. Each obsolete target gets its
    /// own non-blocking lock before removal, so a concurrent older binary can
    /// finish publishing without having its target unlinked. Newer schemas are
    /// never touched.
    fn prune_obsolete_versions(&self) -> std::io::Result<usize> {
        prune_obsolete_idg_sidecars(&self.target)
    }
}

impl Drop for IdgSidecarWriteGuard {
    fn drop(&mut self) {
        if let Err(error) = FileExt::unlock(&self.lock_file) {
            tracing::warn!(
                path = %self.target.display(),
                error = %error,
                "IDG sidecar writer lock release failed"
            );
        }
    }
}

fn open_lock_file(target: &Path) -> std::io::Result<File> {
    let lock_path = lock_path(target);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
}

/// Remove abandoned staging files for every recognized IDG target in the
/// cache directory. The caller already owns `owned_target`; every other
/// target is cleaned only after a non-blocking target-lock acquisition
/// succeeds.
fn cleanup_abandoned_idg_sidecar_temp_files(owned_target: &Path) -> std::io::Result<usize> {
    let Some(parent) = owned_target.parent() else {
        return Ok(0);
    };
    let Some(owned_name) = owned_target.file_name().and_then(|name| name.to_str()) else {
        return cleanup_valid_sidecar_temp_files(owned_target);
    };
    let Some(current_version) = idg_sidecar_version(owned_name) else {
        return cleanup_valid_sidecar_temp_files(owned_target);
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut targets = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((target_name, writer_suffix)) = name.rsplit_once(".tmp.") else {
            continue;
        };
        if factstore_writer_suffix_is_valid(writer_suffix)
            && idg_sidecar_version(target_name).is_some_and(|version| version <= current_version)
        {
            targets.insert(parent.join(target_name));
        }
    }

    let mut removed = cleanup_valid_sidecar_temp_files(owned_target)?;
    for target in targets {
        if target == owned_target {
            continue;
        }
        let lock_file = match open_lock_file(&target).and_then(|file| {
            file.try_lock_exclusive()?;
            Ok(file)
        }) {
            Ok(lock_file) => lock_file,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    "skipping abandoned IDG staging cleanup"
                );
                continue;
            }
        };
        match cleanup_valid_sidecar_temp_files(&target) {
            Ok(count) => removed = removed.saturating_add(count),
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    "abandoned IDG staging cleanup failed"
                );
            }
        }
        if let Err(error) = FileExt::unlock(&lock_file) {
            tracing::warn!(
                path = %target.display(),
                error = %error,
                "abandoned IDG staging cleanup lock release failed"
            );
        }
    }
    Ok(removed)
}

/// Best-effort maintenance after a current sidecar was opened successfully.
///
/// Read paths call this only after they have validated and opened the current
/// immutable generation. Failure to acquire the writer lock means another
/// process is publishing; that is normal and maintenance is skipped.
pub(crate) fn maintain_current_idg_sidecar(target: &Path) {
    match maintain_idg_sidecar_cache(target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => {
            tracing::debug!(
                path = %target.display(),
                error = %error,
                "IDG sidecar maintenance skipped"
            );
        }
    }
}

pub(crate) fn maintain_idg_sidecar_cache(target: &Path) -> std::io::Result<()> {
    let _guard = IdgSidecarWriteGuard::try_acquire(target)?;
    Ok(())
}

fn prune_obsolete_idg_sidecars(current_target: &Path) -> std::io::Result<usize> {
    prune_obsolete_versioned_sidecars(
        current_target,
        idg_sidecar_version,
        |target| {
            let file = open_lock_file(target)?;
            file.try_lock_exclusive()?;
            Ok(file)
        },
        "IDG",
    )
}

/// Return the versioned IDG family prefix for a final sidecar target.
///
/// Both `idg.vN.factstore` and `idg.vN.transfer.<hash>.factstore` belong to
/// `idg.vN`. Deriving the family from the owned target avoids duplicating the
/// IDG schema version in the workspace layer.
pub(crate) fn idg_sidecar_family(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".factstore")?;
    let family = match stem.split_once(".transfer.") {
        Some((family, transfer_hash))
            if transfer_hash.len() == 16 && transfer_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            family
        }
        Some(_) => return None,
        None => stem,
    };
    let version = family.strip_prefix("idg.v")?;
    (!version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())).then_some(family)
}

fn idg_sidecar_version(name: &str) -> Option<u32> {
    idg_sidecar_family(name)?.strip_prefix("idg.v")?.parse().ok()
}

fn lock_path(target: &Path) -> PathBuf {
    let mut path = target.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_cleans_unlocked_family_targets_and_excludes_peer_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("idg.v13.factstore");
        let stale = dir.path().join("idg.v13.factstore.tmp.1234.5");
        let other_target = dir.path().join("idg.v13.transfer.aaaaaaaaaaaaaaaa.factstore");
        let other_stale = PathBuf::from(format!("{}.tmp.2345.6", other_target.display()));
        let active_target = dir.path().join("idg.v13.transfer.bbbbbbbbbbbbbbbb.factstore");
        let active_temp = dir
            .path()
            .join("idg.v13.transfer.bbbbbbbbbbbbbbbb.factstore.tmp.3456.7");
        let old_version = dir.path().join("idg.v12.factstore.tmp.4567.8");
        let unrelated = dir.path().join("other.factstore.tmp.1234.5");
        for path in [&stale, &other_stale, &active_temp, &old_version, &unrelated] {
            std::fs::write(path, b"partial").expect("write stale temp");
        }
        let active_lock = open_lock_file(&active_target).expect("open active lock");
        active_lock.try_lock_exclusive().expect("acquire active writer");

        let guard = IdgSidecarWriteGuard::acquire(&target).expect("acquire owner");
        assert!(!stale.exists());
        assert!(!other_stale.exists());
        assert!(active_temp.exists());
        assert!(!old_version.exists());
        assert!(unrelated.exists());

        let peer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path(&target))
            .expect("open peer lock handle");
        let peer_error = peer.try_lock_exclusive().expect_err("owner excludes peer");
        assert_eq!(peer_error.kind(), std::io::ErrorKind::WouldBlock);
        let guard_error =
            IdgSidecarWriteGuard::try_acquire(&target).expect_err("non-blocking owner excludes peer");
        assert_eq!(guard_error.kind(), std::io::ErrorKind::WouldBlock);

        drop(guard);
        peer.try_lock_exclusive().expect("lock released on drop");
        FileExt::unlock(&peer).expect("release peer lock");
        FileExt::unlock(&active_lock).expect("release active writer");
    }

    #[test]
    fn family_parser_rejects_malformed_or_non_idg_targets() {
        assert_eq!(idg_sidecar_family("idg.v13.factstore"), Some("idg.v13"));
        assert_eq!(idg_sidecar_family("idg.v13.transfer.abcd.factstore"), None);
        assert_eq!(
            idg_sidecar_family("idg.v13.transfer.0123456789abcdef.factstore"),
            Some("idg.v13")
        );
        assert_eq!(idg_sidecar_family("idg.v13.transfer..factstore"), None);
        assert_eq!(idg_sidecar_family("idg.v.factstore"), None);
        assert_eq!(idg_sidecar_family("other.v12.factstore"), None);
        assert_eq!(idg_sidecar_family("idg.v13.bin"), None);
    }

    #[test]
    fn current_owner_prunes_only_unowned_older_generations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let current = dir.path().join("idg.v13.factstore");
        let current_transfer = dir.path().join("idg.v13.transfer.0123456789abcdef.factstore");
        let newer = dir.path().join("idg.v14.factstore");
        let old = dir.path().join("idg.v12.factstore");
        let active_old = dir.path().join("idg.v11.transfer.fedcba9876543210.factstore");
        for path in [&current, &current_transfer, &newer, &old, &active_old] {
            std::fs::write(path, b"sidecar").expect("write sidecar");
        }
        let active_lock = open_lock_file(&active_old).expect("open active old lock");
        active_lock
            .try_lock_exclusive()
            .expect("acquire active old writer");

        let guard = IdgSidecarWriteGuard::acquire(&current).expect("acquire current owner");
        assert!(current.exists());
        assert!(current_transfer.exists());
        assert!(newer.exists());
        assert!(!old.exists());
        assert!(active_old.exists());

        drop(guard);
        FileExt::unlock(&active_lock).expect("release active old writer");
        let _guard = IdgSidecarWriteGuard::acquire(&current).expect("reacquire current owner");
        assert!(!active_old.exists());
    }
}
