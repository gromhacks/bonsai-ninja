//! Immutable rulepack resource compiled into the release binary.
//!
//! The production loader deliberately remains filesystem-backed: validation,
//! project overlays, source locations, and cache fingerprints all share that
//! one path. This module materializes the embedded, content-addressed archive
//! once in the OS cache instead of introducing a second parser or lowering
//! pipeline for bundled rules.

use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

/// SHA-256 identity of every path and byte in the source-controlled bundled
/// rulepack. The materialized directory is immutable and keyed by this value.
pub(crate) const BUNDLED_RULEPACK_ID: &str = bonsai_rulepack::IDENTITY;

/// Return a filesystem root containing the exact rulepack compiled into this
/// build. The first call publishes it atomically in the OS cache; later calls
/// reuse the content-addressed generation from any current working directory.
pub fn bundled_rulepack_root() -> Result<PathBuf> {
    let cache_root = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("bonsai-ninja")
        .join("rulepacks");
    materialize_bundled_rulepack_at(&cache_root)
}

fn materialize_bundled_rulepack_at(cache_root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(cache_root)
        .with_context(|| format!("creating bundled rulepack cache `{}`", cache_root.display()))?;
    let lock_path = cache_root.join(".publish.lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening bundled rulepack lock `{}`", lock_path.display()))?;
    lock.lock_exclusive()
        .with_context(|| format!("locking bundled rulepack cache `{}`", cache_root.display()))?;

    let result = materialize_bundled_rulepack_locked(cache_root);
    FileExt::unlock(&lock)
        .with_context(|| format!("unlocking bundled rulepack cache `{}`", cache_root.display()))?;
    result
}

fn materialize_bundled_rulepack_locked(cache_root: &Path) -> Result<PathBuf> {
    let generation = cache_root.join(BUNDLED_RULEPACK_ID);
    let destination = generation.join("security-patterns");
    let marker = generation.join(".bundled-rulepack-id");
    if fs::read_to_string(&marker)
        .ok()
        .is_some_and(|value| value.trim() == BUNDLED_RULEPACK_ID)
        && destination.join("metadata.yml").is_file()
        && destination.join("langs").is_dir()
    {
        return Ok(destination);
    }

    if generation.exists() {
        fs::remove_dir_all(&generation).with_context(|| {
            format!(
                "removing incomplete bundled rulepack generation `{}`",
                generation.display()
            )
        })?;
    }

    let staging = cache_root.join(format!(".{}.tmp-{}", BUNDLED_RULEPACK_ID, std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging).with_context(|| {
            format!(
                "removing stale bundled rulepack staging directory `{}`",
                staging.display()
            )
        })?;
    }
    fs::create_dir(&staging).with_context(|| {
        format!(
            "creating bundled rulepack staging directory `{}`",
            staging.display()
        )
    })?;

    let publish_result = (|| -> Result<()> {
        let staging_root = staging.join("security-patterns");
        fs::create_dir(&staging_root)?;
        let decoded = zstd::stream::decode_all(bonsai_rulepack::ARCHIVE)
            .context("decoding bundled rulepack archive")?;
        let mut cursor = Cursor::new(decoded.as_slice());
        let mut magic = [0_u8; 8];
        cursor.read_exact(&mut magic)?;
        if &magic != bonsai_rulepack::ARCHIVE_MAGIC {
            return Err(anyhow!("bundled rulepack archive has an invalid header"));
        }
        let file_count = read_u32(&mut cursor)?;
        for _ in 0..file_count {
            let path_len = usize::try_from(read_u32(&mut cursor)?)?;
            let content_len = usize::try_from(read_u64(&mut cursor)?)?;
            let mut path_bytes = vec![0_u8; path_len];
            cursor.read_exact(&mut path_bytes)?;
            let relative = std::str::from_utf8(&path_bytes)
                .context("bundled rulepack archive contains a non-UTF-8 path")?;
            let relative = validated_relative_path(relative)?;
            let mut content = vec![0_u8; content_len];
            cursor.read_exact(&mut content)?;
            let output = staging_root.join(relative);
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, content)
                .with_context(|| format!("writing bundled rule `{}`", output.display()))?;
        }
        if cursor.position() != u64::try_from(decoded.len())? {
            return Err(anyhow!("bundled rulepack archive contains trailing bytes"));
        }
        fs::write(staging.join(".bundled-rulepack-id"), BUNDLED_RULEPACK_ID)?;
        fs::rename(&staging, &generation).with_context(|| {
            format!(
                "publishing bundled rulepack generation `{}`",
                generation.display()
            )
        })?;
        Ok(())
    })();

    if publish_result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    publish_result?;
    Ok(destination)
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    cursor.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    cursor.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn validated_relative_path(raw: &str) -> Result<&Path> {
    let path = Path::new(raw);
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!("invalid path in bundled rulepack archive: `{raw}`"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_pack_materializes_and_loads_from_an_arbitrary_directory() {
        let temp = tempfile::tempdir().expect("temporary cache root");
        let first = materialize_bundled_rulepack_at(temp.path()).expect("materialize bundled pack");
        let second = materialize_bundled_rulepack_at(temp.path()).expect("reuse bundled pack");
        assert_eq!(first, second);
        assert_eq!(
            fs::read_to_string(first.join("VERSION")).expect("bundled VERSION"),
            fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../security-patterns/VERSION"
            ))
            .expect("source VERSION")
        );
        let embedded = crate::loader::load_rulepack(&first).expect("materialized pack loads");
        let source = crate::loader::load_rulepack(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../security-patterns"
        )))
        .expect("source pack loads");
        assert_eq!(embedded.metadata, source.metadata);
        assert_eq!(semantic_rule_rows(&embedded), semantic_rule_rows(&source));
    }

    #[test]
    fn archive_paths_cannot_escape_the_materialization_root() {
        assert!(validated_relative_path("langs/python/sources/web.yml").is_ok());
        for invalid in [
            "",
            "/tmp/rule.yml",
            "../rule.yml",
            "langs/../rule.yml",
            "./rule.yml",
        ] {
            assert!(validated_relative_path(invalid).is_err(), "accepted `{invalid}`");
        }
    }

    fn semantic_rule_rows(pack: &crate::loader::Rulepack) -> Vec<(String, String, String, String)> {
        let mut rows = pack
            .all_rules()
            .into_iter()
            .map(|rule| {
                (
                    rule.language.clone(),
                    format!("{:?}", rule.kind),
                    rule.id.clone(),
                    serde_json::to_string(rule).expect("serialize rule semantics"),
                )
            })
            .collect::<Vec<_>>();
        rows.sort_unstable();
        rows
    }
}
