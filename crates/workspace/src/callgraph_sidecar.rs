//! Versioned resolved-callgraph sidecar.
//!
//! Metadata and graph facts are separate factstore entries. Warm-up and cache
//! inspection can therefore prove source/build/dependency freshness without
//! decoding or allocating the graph. Query consumers read the graph entry and
//! validate its MessagePack payload before use.

use crate::cache_fingerprint::dependency_metadata_fingerprint_for_sidecar;
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{wire, workspace_bonsai_dir, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_hash::fnv1a_bytes64;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// v17 (2026-07-25): graph payloads retain exact unresolved workspace call
// sites so completeness diagnostics distinguish resolver gaps from external
// calls.
// v16 (2026-07-20): graph payloads retain compiler-resolved local callable
// bindings so the IDG does not keep assignment bodies resident.
// v15 (2026-07-20): graph payloads include a deterministic compact endpoint
// name table so later phases can release whole-file declaration bodies.
// v14 (2026-07-20): graph payloads stream directly and contain only compact
// typed edges; numeric adjacency indexes are rebuilt after decode.
// v13 (2026-07-18): metadata and graph payloads are independent factstore
// entries, so freshness checks do not recursively decode millions of edges.
// v12 (2026-07-16): MessagePack replaced the retired binary codec.
pub const CALLGRAPH_CACHE_VERSION: u32 = 17;

const CALLGRAPH_TABLE_ID: u32 = 102;
const METADATA_KEY: u64 = 0;
const GRAPH_KEY: u64 = 1;
const ENTRY_COUNT: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CallgraphMetadata {
    version: u32,
    matcher_policy_fingerprint: u128,
    /// Sorted `(workspace path, content hash)` pairs for every indexed file.
    files: Vec<(String, u64)>,
    dependency_metadata_fingerprint: u64,
    /// Producer identity retained for diagnostics and artifact integrity.
    /// Freshness is governed by the callgraph semantic ABI plus exact input
    /// fingerprints, not by unrelated changes elsewhere in the binary.
    build_fingerprint: u64,
}

#[must_use]
pub fn callgraph_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.factstore"))
}

pub(crate) fn save_callgraph_sidecar(
    path: &Path,
    db: &AnalyzerDb,
    graph: Arc<ResolvedCallGraph>,
) -> std::io::Result<()> {
    let metadata = CallgraphMetadata {
        version: CALLGRAPH_CACHE_VERSION,
        matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
        files: current_source_fingerprints(db),
        dependency_metadata_fingerprint: dependency_metadata_fingerprint_for_sidecar(path),
        build_fingerprint: crate::build_fingerprint_hash(),
    };
    let pipeline_hash = metadata_pipeline_hash(&metadata);
    let writer =
        FactStoreWriter::create_with_capacity(path, CALLGRAPH_TABLE_ID, pipeline_hash, ENTRY_COUNT, 0, 0)
            .map_err(factstore_io)?;
    let metadata_bytes = wire::encode(&metadata).map_err(invalid_wire)?;
    writer
        .add_owned(METADATA_KEY, CALLGRAPH_CACHE_VERSION as u64, metadata_bytes)
        .map_err(factstore_io)?;
    writer
        .add_streamed(GRAPH_KEY, CALLGRAPH_CACHE_VERSION as u64, move |output| {
            wire::encode_to_writer(output, graph.as_ref()).map_err(invalid_wire)
        })
        .map_err(factstore_io)?;
    writer.finish().map_err(factstore_io)?;
    // The current artifact is durable before cleanup starts. Cache migration
    // is best-effort: an inability to remove an obsolete file must not turn a
    // successfully persisted compiler graph into an analysis failure.
    let _ = prune_obsolete_callgraph_sidecars(path);
    Ok(())
}

fn prune_obsolete_callgraph_sidecars(current_path: &Path) -> std::io::Result<()> {
    let Some(cache_dir) = current_path.parent() else {
        return Ok(());
    };
    for entry in std::fs::read_dir(cache_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path() == current_path {
            continue;
        }
        let Some(version) = callgraph_sidecar_version(&entry.file_name()) else {
            continue;
        };
        if version < CALLGRAPH_CACHE_VERSION {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn callgraph_sidecar_version(file_name: &std::ffi::OsStr) -> Option<u32> {
    let file_name = file_name.to_str()?;
    let version_and_extension = file_name.strip_prefix("callgraph.v")?;
    let (version, extension) = version_and_extension.split_once('.')?;
    (!extension.is_empty()).then_some(())?;
    version.parse().ok()
}

/// Load and validate the exact current graph while preserving the concrete
/// miss/decode error for compiler warm-up orchestration.
pub(crate) fn load_callgraph_sidecar_checked(
    path: &Path,
    db: &AnalyzerDb,
) -> std::io::Result<ResolvedCallGraph> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    if current_source_fingerprints(db) != metadata.files {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar source fingerprint mismatch",
        ));
    }
    decode_graph(&reader)
}

/// Validate exact workspace freshness without reading the graph payload.
pub(crate) fn validate_callgraph_sidecar_for_db(path: &Path, db: &AnalyzerDb) -> std::io::Result<()> {
    let (_reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    if current_source_fingerprints(db) != metadata.files {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar source fingerprint mismatch",
        ));
    }
    Ok(())
}

/// Validate that a callgraph sidecar is structurally readable and was
/// produced by the current callgraph/matcher pipeline. This exhaustive
/// validator decodes the graph payload; warm-up uses the metadata-only exact
/// workspace validator above.
pub fn validate_callgraph_sidecar_file(path: &Path) -> std::io::Result<usize> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    let graph = decode_graph(&reader)?;
    Ok(graph.inner().edges.len())
}

/// Exhaustively validate a callgraph sidecar against an explicit source set.
pub fn validate_callgraph_sidecar_file_with_source_fingerprints<I, P>(
    path: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    let mut current: Vec<(String, u64)> = fingerprints
        .into_iter()
        .map(|(path, hash)| (path.as_ref().display().to_string(), hash))
        .collect();
    current.sort();
    if current != metadata.files {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar source fingerprint mismatch",
        ));
    }
    let graph = decode_graph(&reader)?;
    Ok(graph.inner().edges.len())
}

fn open_sidecar(path: &Path) -> std::io::Result<(FactStoreReader, CallgraphMetadata)> {
    let reader = FactStoreReader::open_relaxed(path).map_err(factstore_io)?;
    if reader.header().table_id != CALLGRAPH_TABLE_ID {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar factstore table mismatch",
        ));
    }
    if reader.len() != ENTRY_COUNT || !reader.contains_key(METADATA_KEY) || !reader.contains_key(GRAPH_KEY) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar entry layout mismatch",
        ));
    }
    let hit = reader.get(METADATA_KEY).map_err(factstore_io)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar metadata is missing",
        )
    })?;
    if hit.body_hash != CALLGRAPH_CACHE_VERSION as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar metadata body version mismatch",
        ));
    }
    let metadata: CallgraphMetadata = wire::decode(&hit.payload).map_err(invalid_wire)?;
    if reader.header().pipeline_hash != metadata_pipeline_hash(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar pipeline fingerprint mismatch",
        ));
    }
    Ok((reader, metadata))
}

fn decode_graph(reader: &FactStoreReader) -> std::io::Result<ResolvedCallGraph> {
    let mut payload = reader
        .payload_reader(GRAPH_KEY)
        .map_err(factstore_io)?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "callgraph sidecar graph payload is missing",
            )
        })?;
    if payload.body_hash != CALLGRAPH_CACHE_VERSION as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar graph body version mismatch",
        ));
    }
    let graph = wire::decode_from_reader(&mut payload).map_err(invalid_wire)?;
    let mut trailing = [0u8; 1];
    if payload.read(&mut trailing)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar graph payload has trailing bytes",
        ));
    }
    Ok(graph)
}

fn validate_metadata(path: &Path, metadata: &CallgraphMetadata) -> std::io::Result<()> {
    if metadata.version != CALLGRAPH_CACHE_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "callgraph sidecar version mismatch: file={} expected={}",
                metadata.version, CALLGRAPH_CACHE_VERSION
            ),
        ));
    }
    if metadata.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar matcher policy fingerprint mismatch",
        ));
    }
    if metadata.dependency_metadata_fingerprint != dependency_metadata_fingerprint_for_sidecar(path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar dependency metadata fingerprint mismatch",
        ));
    }
    Ok(())
}

fn metadata_pipeline_hash(metadata: &CallgraphMetadata) -> u64 {
    let mut hasher = bonsai_hash::Hasher::new();
    hasher.absorb(b"bonsai-callgraph-sidecar-v17");
    hasher.absorb_separator();
    hasher.absorb(&metadata.version.to_le_bytes());
    hasher.absorb(&metadata.matcher_policy_fingerprint.to_le_bytes());
    hasher.absorb(&metadata.dependency_metadata_fingerprint.to_le_bytes());
    // Bind the header to the recorded producer so metadata tampering cannot
    // preserve the artifact hash. This is an integrity/provenance field, not
    // a comparison against the currently running binary.
    hasher.absorb(&metadata.build_fingerprint.to_le_bytes());
    for (path, content_hash) in &metadata.files {
        hasher.absorb(path.as_bytes());
        hasher.absorb_separator();
        hasher.absorb(&content_hash.to_le_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

fn current_source_fingerprints(db: &AnalyzerDb) -> Vec<(String, u64)> {
    let mut files = Vec::new();
    for file in db.vfs().all_files() {
        let Ok(snapshot) = db.vfs().snapshot(file) else {
            continue;
        };
        let Ok(path) = db.vfs().path(file) else {
            continue;
        };
        files.push((
            path.to_string_lossy().into_owned(),
            fnv1a_bytes64(snapshot.text.as_bytes()),
        ));
    }
    files.sort();
    files
}

fn invalid_wire(error: impl std::error::Error + Send + Sync + 'static) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

fn factstore_io(error: bonsai_factstore::FactStoreError) -> std::io::Error {
    match error {
        bonsai_factstore::FactStoreError::Io(error) => error,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_schema_migration_prunes_only_older_callgraph_sidecars() {
        let root = tempfile::tempdir().expect("tempdir");
        let cache_dir = root.path().join(".bonsai");
        std::fs::create_dir(&cache_dir).expect("create cache dir");
        let current = cache_dir.join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.factstore"));
        let older_factstore = cache_dir.join(format!("callgraph.v{}.factstore", CALLGRAPH_CACHE_VERSION - 1));
        let older_wire = cache_dir.join(format!("callgraph.v{}.msgpack", CALLGRAPH_CACHE_VERSION - 2));
        let newer = cache_dir.join(format!("callgraph.v{}.factstore", CALLGRAPH_CACHE_VERSION + 1));
        let unrelated = cache_dir.join("idg.v11.factstore");
        for path in [&current, &older_factstore, &older_wire, &newer, &unrelated] {
            std::fs::write(path, b"fixture").expect("write fixture");
        }

        prune_obsolete_callgraph_sidecars(&current).expect("prune obsolete sidecars");

        assert!(current.is_file());
        assert!(!older_factstore.exists());
        assert!(!older_wire.exists());
        assert!(newer.is_file(), "a newer binary may still need its artifact");
        assert!(unrelated.is_file());
    }

    #[test]
    fn sidecar_version_parser_rejects_unversioned_and_extensionless_names() {
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("callgraph.v12.msgpack")),
            Some(12)
        );
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("callgraph.msgpack")),
            None
        );
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("callgraph.v12")),
            None
        );
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("idg.v12.factstore")),
            None
        );
    }

    #[test]
    fn producer_identity_is_provenance_not_semantic_freshness() {
        let root = tempfile::tempdir().expect("tempdir");
        let cache_dir = root.path().join(".bonsai");
        std::fs::create_dir(&cache_dir).expect("create cache dir");
        let path = cache_dir.join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.factstore"));
        let metadata = CallgraphMetadata {
            version: CALLGRAPH_CACHE_VERSION,
            matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
            files: Vec::new(),
            dependency_metadata_fingerprint: dependency_metadata_fingerprint_for_sidecar(&path),
            build_fingerprint: crate::build_fingerprint_hash() ^ 1,
        };

        validate_metadata(&path, &metadata)
            .expect("an unrelated producer build must not invalidate exact compiler inputs");
    }
}
