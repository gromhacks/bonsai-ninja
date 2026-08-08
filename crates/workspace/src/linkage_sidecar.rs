//! Versioned compiler-linkage sidecar.
//!
//! The semantic frontend lowers every Tree-sitter input into stable
//! declaration/type headers plus the compact call/return facts required by
//! IDG stitching. Persisting that phase artifact lets the subsequent IDG
//! worker start in a fresh process: parser and allocator arenas die with the
//! frontend process instead of becoming additive with the graph compiler.
//!
//! This is not a substitute for syntax. IDG transfer streams each exact file
//! body from the content-addressed Tree-sitter compiler-object generation at
//! its segment boundary. The sidecar is
//! the compiler's symbol/linkage table, analogous to a module interface or
//! object-file symbol table.

use crate::cache_fingerprint::dependency_metadata_fingerprint_for_sidecar;
use bonsai_common::{wire, workspace_bonsai_dir, FileId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::{AnalyzerDb, COMPILER_OBJECT_CACHE_VERSION};
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_hash::fnv1a_bytes64;
use bonsai_index::{GlobalIndex, ReceiverAncestry};
use bonsai_lang_api::DeclIndex;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Current compiler-linkage schema and semantic ABI.
///
/// Version 8 stores per-file declaration headers as named-field MessagePack.
/// Version 7 used positional encoding for structs with omitted default
/// grammar fields, which shifted later fields and made non-empty partitions
/// undecodable.
///
/// Version 7 binds the header partitions to the current declaration-index
/// wire schema. Version 6 artifacts predate the adapter-owned grammar
/// taxonomy fields and cannot be decoded safely by the current compiler.
///
/// Version 9 retains complete nested lexical identities from compiler-object
/// ABI v13.
///
/// Version 10 retains standalone lambda/local-callable lexical parents and
/// Perl package/static-call identity from compiler-object ABI v15.
///
/// Version 11 binds every linkage generation to the exact compiler frontend
/// ABI. Adapter lowering changes can no longer leave a source-current symbol
/// header reusable beside newly lowered compiler-object bodies.
///
/// Version 6 stores declaration headers as independently decodable per-file
/// partitions. Scoped compiler worklists no longer allocate every workspace
/// header merely to replay a handful of exact bodies.
///
/// Version 5 carries exact class-like declaration kinds and anonymous-body
/// ownership from compiler-object ABI v11.
///
/// Version 4 adds independently decodable receiver ancestry beside the
/// declaration/type header and call-linkage payloads. File-local inventory
/// scans can preserve cross-file receiver constraints without hydrating the
/// complete global symbol table.
pub const LINKAGE_CACHE_VERSION: u32 = 11;

const LINKAGE_TABLE_ID: u32 = 103;
const METADATA_KEY: u64 = 0;
const LINKAGE_KEY: u64 = 1;
const RECEIVER_ANCESTRY_KEY: u64 = 3;
const HEADER_PARTITION_KEY_BASE: u64 = 0x2000_0000_0000_0000;
const FIXED_ENTRY_COUNT: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LinkageMetadata {
    version: u32,
    compiler_frontend_abi: u32,
    matcher_policy_fingerprint: u128,
    /// Exact VFS identity/order used to assign stable FileId/SymbolId values.
    files: Vec<(u32, String, u64)>,
    dependency_metadata_fingerprint: u64,
    declaration_count: u64,
    /// Sorted full-workspace FileIds with independently decodable declaration
    /// header partitions.
    header_files: Vec<u32>,
    /// Producer provenance. Compatibility is governed by the explicit
    /// semantic ABI above, so storage-only binary changes retain this cache.
    build_fingerprint: u64,
}

/// Conventional linkage artifact path in the external workspace cache.
#[must_use]
pub fn linkage_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!("linkage.v{LINKAGE_CACHE_VERSION}.factstore"))
}

pub(crate) fn save_linkage_sidecar(
    path: &Path,
    db: &AnalyzerDb,
    index: Arc<GlobalIndex>,
) -> std::io::Result<()> {
    let header_files = index.all_files().map(FileId::raw).collect::<Vec<_>>();
    let metadata = LinkageMetadata {
        version: LINKAGE_CACHE_VERSION,
        compiler_frontend_abi: COMPILER_OBJECT_CACHE_VERSION,
        matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
        files: current_source_inputs(db),
        dependency_metadata_fingerprint: dependency_metadata_fingerprint_for_sidecar(path),
        declaration_count: index.len() as u64,
        build_fingerprint: crate::build_fingerprint_hash(),
        header_files: header_files.clone(),
    };
    let writer = FactStoreWriter::create_with_capacity(
        path,
        LINKAGE_TABLE_ID,
        metadata_pipeline_hash(&metadata),
        FIXED_ENTRY_COUNT.saturating_add(header_files.len()),
        0,
        0,
    )
    .map_err(factstore_io)?;
    writer
        .add_owned(
            METADATA_KEY,
            LINKAGE_CACHE_VERSION as u64,
            wire::encode(&metadata).map_err(invalid_wire)?,
        )
        .map_err(factstore_io)?;
    let linkage = Arc::clone(&index);
    writer
        .add_streamed(LINKAGE_KEY, LINKAGE_CACHE_VERSION as u64, move |output| {
            wire::encode_struct_map_to_writer(output, linkage.as_ref()).map_err(invalid_wire)
        })
        .map_err(factstore_io)?;
    let receiver_ancestry = index.receiver_ancestry();
    writer
        .add_owned(
            RECEIVER_ANCESTRY_KEY,
            LINKAGE_CACHE_VERSION as u64,
            wire::encode_struct_map(&receiver_ancestry).map_err(invalid_wire)?,
        )
        .map_err(factstore_io)?;
    for file in header_files {
        let header = index.file_index(FileId::new(file)).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing header partition")
        })?;
        writer
            .add_streamed(
                header_partition_key(file),
                header_partition_body_hash(file),
                move |output| wire::encode_struct_map_to_writer(output, &header).map_err(invalid_wire),
            )
            .map_err(factstore_io)?;
    }
    writer.finish().map_err(factstore_io)?;
    let _ = prune_obsolete_linkage_sidecars(path);
    Ok(())
}

pub(crate) fn load_linkage_sidecar_checked(path: &Path, db: &AnalyzerDb) -> std::io::Result<GlobalIndex> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, db, &metadata)?;
    decode_index_payload(&reader, &metadata, LINKAGE_KEY, "linkage")
}

/// Load only the complete declaration/type symbol table from the exact
/// compiler-linkage artifact.
///
/// This payload contains no call-linkage summaries and no function bodies.
/// Syntax lookup must use it instead of decoding every per-file compiler
/// object merely to discard its flow events.
pub(crate) fn load_header_sidecar_checked(path: &Path, db: &AnalyzerDb) -> std::io::Result<GlobalIndex> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, db, &metadata)?;
    decode_header_partitions(&reader, &metadata, &metadata.header_files)
}

/// Load the complete declaration/type header table after a scoped compiler
/// session has independently fingerprinted the whole workspace.
pub(crate) fn load_header_sidecar_checked_with_source_inputs(
    path: &Path,
    inputs: &[(u32, String, u64)],
) -> std::io::Result<GlobalIndex> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata_base(path, &metadata)?;
    if metadata.files != inputs {
        return Err(invalid_data(
            "linkage sidecar source/VFS identity mismatch for scoped compiler session",
        ));
    }
    decode_header_partitions(&reader, &metadata, &metadata.header_files)
}

/// Load only declaration headers for the exact files admitted by a compiler
/// worklist while preserving their workspace-global symbol identities.
pub(crate) fn load_header_partitions_checked(
    path: &Path,
    db: &AnalyzerDb,
    files: &[FileId],
) -> std::io::Result<GlobalIndex> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, db, &metadata)?;
    decode_requested_header_partitions(&reader, &metadata, files)
}

/// Load selected declaration headers after a scoped compiler session has
/// independently fingerprinted the complete workspace.
///
/// `inputs` retains the canonical full-workspace FileId ordering, so both
/// source freshness and SymbolId identity are checked without keeping every
/// source string resident.
pub(crate) fn load_header_partitions_checked_with_source_inputs(
    path: &Path,
    inputs: &[(u32, String, u64)],
    files: &[FileId],
) -> std::io::Result<GlobalIndex> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata_base(path, &metadata)?;
    if metadata.files != inputs {
        return Err(invalid_data(
            "linkage sidecar source/VFS identity mismatch for scoped compiler session",
        ));
    }
    decode_requested_header_partitions(&reader, &metadata, files)
}

fn decode_requested_header_partitions(
    reader: &FactStoreReader,
    metadata: &LinkageMetadata,
    files: &[FileId],
) -> std::io::Result<GlobalIndex> {
    let mut requested = files.iter().map(|file| file.raw()).collect::<Vec<_>>();
    requested.sort_unstable();
    requested.dedup();
    if requested
        .iter()
        .any(|file| metadata.header_files.binary_search(file).is_err())
    {
        return Err(invalid_data(
            "linkage sidecar does not contain every requested header file",
        ));
    }
    decode_header_partitions(reader, metadata, &requested)
}

/// Load only finalized cross-file receiver inheritance facts.
pub(crate) fn load_receiver_ancestry_sidecar_checked(
    path: &Path,
    db: &AnalyzerDb,
) -> std::io::Result<ReceiverAncestry> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, db, &metadata)?;
    decode_receiver_ancestry_payload(&reader)
}

/// Exhaustively validate a linkage artifact against explicit source hashes.
///
/// Root-only cache inspection has no live VFS, so it validates the canonical
/// `(path, content hash)` projection. Actual compiler loads additionally bind
/// the persisted FileId ordering through the private
/// `load_linkage_sidecar_checked` loader.
pub fn validate_linkage_sidecar_file_with_source_fingerprints<I, P>(
    path: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    validate_linkage_sidecar_metadata_with_source_fingerprints(path, fingerprints)?;
    let (reader, metadata) = open_sidecar(path)?;
    let index = decode_index_payload(&reader, &metadata, LINKAGE_KEY, "linkage")?;
    let headers = decode_header_partitions(&reader, &metadata, &metadata.header_files)?;
    decode_receiver_ancestry_payload(&reader)?;
    if headers.len() != index.len() {
        return Err(invalid_data(
            "linkage sidecar header/linkage declaration count mismatch",
        ));
    }
    Ok(index.len())
}

fn decode_header_partitions(
    reader: &FactStoreReader,
    metadata: &LinkageMetadata,
    files: &[u32],
) -> std::io::Result<GlobalIndex> {
    let ancestry = decode_receiver_ancestry_payload(reader)?;
    let mut headers = Vec::with_capacity(files.len());
    for file in files {
        let hit = reader
            .get(header_partition_key(*file))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("linkage sidecar header partition is missing"))?;
        if hit.body_hash != header_partition_body_hash(*file) {
            return Err(invalid_data("linkage sidecar header partition version mismatch"));
        }
        let header: DeclIndex = wire::decode(&hit.payload).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decoding linkage header partition {file}: {error}"),
            )
        })?;
        if header.file.raw() != *file {
            return Err(invalid_data(
                "linkage sidecar header partition key/payload mismatch",
            ));
        }
        headers.push(header);
    }
    let index = GlobalIndex::from_persisted_header_files(headers, ancestry)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if files.len() == metadata.header_files.len() && index.len() as u64 != metadata.declaration_count {
        return Err(invalid_data("linkage sidecar header declaration count mismatch"));
    }
    Ok(index)
}

fn decode_receiver_ancestry_payload(reader: &FactStoreReader) -> std::io::Result<ReceiverAncestry> {
    let hit = reader
        .get(RECEIVER_ANCESTRY_KEY)
        .map_err(factstore_io)?
        .ok_or_else(|| invalid_data("linkage sidecar receiver ancestry is missing"))?;
    if hit.body_hash != LINKAGE_CACHE_VERSION as u64 {
        return Err(invalid_data("linkage sidecar receiver ancestry version mismatch"));
    }
    wire::decode(&hit.payload).map_err(invalid_wire)
}

/// Validate linkage schema, compiler inputs, and source identity without
/// allocating the persisted global symbol table.
pub fn validate_linkage_sidecar_metadata_with_source_fingerprints<I, P>(
    path: &Path,
    fingerprints: I,
) -> std::io::Result<()>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata_base(path, &metadata)?;
    let mut current = fingerprints
        .into_iter()
        .map(|(path, hash)| (path.as_ref().display().to_string(), hash))
        .collect::<Vec<_>>();
    current.sort();
    let mut recorded = metadata
        .files
        .iter()
        .map(|(_, path, hash)| (path.clone(), *hash))
        .collect::<Vec<_>>();
    recorded.sort();
    if current != recorded {
        return Err(invalid_data("linkage sidecar source fingerprint mismatch"));
    }
    drop(reader);
    Ok(())
}

fn decode_index_payload(
    reader: &FactStoreReader,
    metadata: &LinkageMetadata,
    key: u64,
    label: &'static str,
) -> std::io::Result<GlobalIndex> {
    let mut payload = reader
        .payload_reader(key)
        .map_err(factstore_io)?
        .ok_or_else(|| invalid_data("linkage sidecar index payload is missing"))?;
    if payload.body_hash != LINKAGE_CACHE_VERSION as u64 {
        return Err(invalid_data("linkage sidecar index payload version mismatch"));
    }
    let index: GlobalIndex = wire::decode_from_reader(&mut payload).map_err(invalid_wire)?;
    let mut trailing = [0_u8; 1];
    if payload.read(&mut trailing)? != 0 {
        return Err(invalid_data("linkage sidecar index payload has trailing bytes"));
    }
    if index.len() as u64 != metadata.declaration_count {
        return Err(invalid_data(match label {
            "header" => "linkage sidecar header declaration count mismatch",
            _ => "linkage sidecar declaration count mismatch",
        }));
    }
    Ok(index)
}

pub(crate) fn validate_linkage_sidecar_for_db(path: &Path, db: &AnalyzerDb) -> std::io::Result<()> {
    let (_reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, db, &metadata)
}

fn open_sidecar(path: &Path) -> std::io::Result<(FactStoreReader, LinkageMetadata)> {
    let reader = FactStoreReader::open_relaxed(path).map_err(factstore_io)?;
    if reader.header().table_id != LINKAGE_TABLE_ID {
        return Err(invalid_data("linkage sidecar factstore table mismatch"));
    }
    if reader.len() < FIXED_ENTRY_COUNT
        || !reader.contains_key(METADATA_KEY)
        || !reader.contains_key(LINKAGE_KEY)
        || !reader.contains_key(RECEIVER_ANCESTRY_KEY)
    {
        return Err(invalid_data("linkage sidecar entry layout mismatch"));
    }
    let hit = reader
        .get(METADATA_KEY)
        .map_err(factstore_io)?
        .ok_or_else(|| invalid_data("linkage sidecar metadata is missing"))?;
    if hit.body_hash != LINKAGE_CACHE_VERSION as u64 {
        return Err(invalid_data("linkage sidecar metadata version mismatch"));
    }
    let metadata: LinkageMetadata = wire::decode(&hit.payload).map_err(invalid_wire)?;
    let expected_entries = FIXED_ENTRY_COUNT.saturating_add(metadata.header_files.len());
    if reader.len() != expected_entries
        || metadata
            .header_files
            .iter()
            .any(|file| !reader.contains_key(header_partition_key(*file)))
    {
        return Err(invalid_data("linkage sidecar header partition layout mismatch"));
    }
    if reader.header().pipeline_hash != metadata_pipeline_hash(&metadata) {
        return Err(invalid_data("linkage sidecar pipeline fingerprint mismatch"));
    }
    Ok((reader, metadata))
}

fn validate_metadata(path: &Path, db: &AnalyzerDb, metadata: &LinkageMetadata) -> std::io::Result<()> {
    validate_metadata_base(path, metadata)?;
    let current = current_source_inputs(db);
    if metadata.files != current {
        let first_mismatch = metadata
            .files
            .iter()
            .zip(current.iter())
            .position(|(recorded, actual)| recorded != actual);
        let mismatch_detail = first_mismatch
            .and_then(|index| metadata.files.get(index).zip(current.get(index)))
            .map_or_else(
                || "length differs".to_string(),
                |(recorded, actual)| format!("recorded={recorded:?} current={actual:?}"),
            );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "linkage sidecar source/VFS identity mismatch: recorded={} current={} first_mismatch={} ({})",
                metadata.files.len(),
                current.len(),
                first_mismatch
                    .map(|index| index.to_string())
                    .unwrap_or_else(|| "length".to_string()),
                mismatch_detail
            ),
        ));
    }
    Ok(())
}

fn validate_metadata_base(path: &Path, metadata: &LinkageMetadata) -> std::io::Result<()> {
    if metadata.version != LINKAGE_CACHE_VERSION {
        return Err(invalid_data("linkage sidecar schema version mismatch"));
    }
    if metadata.compiler_frontend_abi != COMPILER_OBJECT_CACHE_VERSION {
        return Err(invalid_data("linkage sidecar compiler frontend ABI mismatch"));
    }
    if metadata.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
        return Err(invalid_data("linkage sidecar matcher-policy mismatch"));
    }
    if metadata.dependency_metadata_fingerprint != dependency_metadata_fingerprint_for_sidecar(path) {
        return Err(invalid_data("linkage sidecar dependency metadata mismatch"));
    }
    if metadata.header_files.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_data(
            "linkage sidecar header file table is not strictly sorted",
        ));
    }
    Ok(())
}

fn metadata_pipeline_hash(metadata: &LinkageMetadata) -> u64 {
    let mut hasher = bonsai_hash::Hasher::new();
    hasher.absorb(b"bonsai-linkage-sidecar-v1");
    hasher.absorb_separator();
    hasher.absorb(&metadata.version.to_le_bytes());
    hasher.absorb(&metadata.compiler_frontend_abi.to_le_bytes());
    hasher.absorb(&metadata.matcher_policy_fingerprint.to_le_bytes());
    hasher.absorb(&metadata.dependency_metadata_fingerprint.to_le_bytes());
    hasher.absorb(&metadata.declaration_count.to_le_bytes());
    hasher.absorb(&metadata.build_fingerprint.to_le_bytes());
    for (file, path, content_hash) in &metadata.files {
        hasher.absorb(&file.to_le_bytes());
        hasher.absorb(path.as_bytes());
        hasher.absorb_separator();
        hasher.absorb(&content_hash.to_le_bytes());
        hasher.absorb_separator();
    }
    for file in &metadata.header_files {
        hasher.absorb(&file.to_le_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

fn header_partition_key(file: u32) -> u64 {
    HEADER_PARTITION_KEY_BASE | u64::from(file)
}

fn header_partition_body_hash(file: u32) -> u64 {
    (u64::from(LINKAGE_CACHE_VERSION) << 32) | u64::from(file)
}

fn current_source_inputs(db: &AnalyzerDb) -> Vec<(u32, String, u64)> {
    let mut files = db
        .vfs()
        .all_files()
        .into_iter()
        .filter_map(|file| {
            let snapshot = db.vfs().snapshot(file).ok()?;
            let path = db.vfs().path(file).ok()?;
            Some((
                file.raw(),
                path.to_string_lossy().into_owned(),
                fnv1a_bytes64(snapshot.text.as_bytes()),
            ))
        })
        .collect::<Vec<_>>();
    files.sort_unstable_by_key(|(file, _, _)| *file);
    files
}

fn prune_obsolete_linkage_sidecars(current_path: &Path) -> std::io::Result<()> {
    let Some(cache_dir) = current_path.parent() else {
        return Ok(());
    };
    for entry in std::fs::read_dir(cache_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path() == current_path {
            continue;
        }
        let Some(version) = linkage_sidecar_version(&entry.file_name()) else {
            continue;
        };
        if version < LINKAGE_CACHE_VERSION {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn linkage_sidecar_version(file_name: &std::ffi::OsStr) -> Option<u32> {
    let file_name = file_name.to_str()?;
    let version_and_extension = file_name.strip_prefix("linkage.v")?;
    let (version, extension) = version_and_extension.split_once('.')?;
    (!extension.is_empty()).then_some(version.parse().ok()?)
}

fn invalid_wire(error: impl std::error::Error + Send + Sync + 'static) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
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
    use bonsai_common::{Span, SymbolId};
    use bonsai_lang_api::{Decl, DeclKind, LanguageRegistry, ModulePath, Visibility};
    use bonsai_vfs::Vfs;

    fn callable_header(file: FileId) -> Decl {
        let span = Span::new(file, 0, 4);
        Decl {
            symbol: SymbolId::new(0),
            kind: DeclKind::Function,
            name: "main".to_string(),
            qualified_name: None,
            module_path: ModulePath::default(),
            span,
            name_span: span,
            visibility: Visibility::Private,
            parent: None,
            body_span: Some(span),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        }
    }

    #[test]
    fn parser_accepts_only_versioned_linkage_artifacts() {
        assert_eq!(
            linkage_sidecar_version(std::ffi::OsStr::new("linkage.v1.factstore")),
            Some(1)
        );
        assert_eq!(
            linkage_sidecar_version(std::ffi::OsStr::new("linkage.factstore")),
            None
        );
        assert_eq!(
            linkage_sidecar_version(std::ffi::OsStr::new("callgraph.v1.factstore")),
            None
        );
    }

    #[test]
    fn sidecar_round_trip_is_bound_to_exact_vfs_inputs() {
        let root = tempfile::tempdir().expect("tempdir");
        let vfs = Arc::new(Vfs::new());
        vfs.write("src/input.fixture".to_string(), Arc::<str>::from("first"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        let path = linkage_sidecar_path(root.path());
        let mut index = GlobalIndex::new();
        index.insert(DeclIndex {
            file: FileId::new(0),
            defs: vec![callable_header(FileId::new(0))],
            ..DeclIndex::default()
        });

        save_linkage_sidecar(&path, &db, Arc::new(index)).expect("save linkage");
        assert!(validate_linkage_sidecar_for_db(&path, &db).is_ok());
        let restored = load_linkage_sidecar_checked(&path, &db).expect("load linkage");
        assert_eq!(restored.len(), 1);
        let headers = load_header_sidecar_checked(&path, &db).expect("load headers");
        assert_eq!(headers.len(), 1);
        let scoped_headers = load_header_partitions_checked_with_source_inputs(
            &path,
            &[(0, "src/input.fixture".to_string(), fnv1a_bytes64(b"first"))],
            &[FileId::new(0)],
        )
        .expect("load scoped headers against complete source identity");
        assert_eq!(scoped_headers.len(), 1);
        let ancestry = load_receiver_ancestry_sidecar_checked(&path, &db).expect("load receiver ancestry");
        assert!(ancestry.is_empty());

        vfs.write("src/input.fixture".to_string(), Arc::<str>::from("second"));
        assert!(
            validate_linkage_sidecar_for_db(&path, &db).is_err(),
            "content drift must reject the exact compiler phase artifact"
        );
    }
}
