//! Immutable, content-addressed compiler objects.
//!
//! Tree-sitter remains the syntax authority. This module persists the exact
//! language-adapter IR produced from one immutable source snapshot so later
//! compiler phases can stream that typed object instead of reparsing the same
//! file. Objects are accepted only when their strong source digest,
//! workspace-relative path/module context, selected language, and explicit
//! frontend semantic ABI all match.

use crate::AnalyzerDb;
use bonsai_common::{wire, workspace_bonsai_dir, FileId, Span, MATCHER_POLICY_FINGERPRINT};
use bonsai_diagnostics::{Diagnostic, DiagnosticSink, Severity};
use bonsai_factstore::{
    FactStoreError, FactStoreReader, FactStoreWriter, PreparedFactStoreEntry, PreparedFactStorePayload,
};
use bonsai_lang_api::{DeclIndex, ImportIndex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Current per-file compiler-object wire and semantic ABI.
///
/// Bump this whenever adapter lowering, [`DeclIndex`], [`ImportIndex`], or the
/// object validation contract changes in a way that can alter compiler facts.
pub const COMPILER_OBJECT_CACHE_VERSION: u32 = 6;

const COMPILER_OBJECT_TABLE_ID: u32 = 104;
const METADATA_KEY: u64 = 0;
const COMPILER_OBJECT_COMPRESSION_LEVEL: i32 = 1;

/// Exact typed compiler output for one source file.
///
/// This is the persistent equivalent of a relocatable compiler object: all
/// syntax interpretation remains in the language adapter, while workspace
/// symbol identities are assigned later by the linker/global index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledFileObject {
    /// Stable file id within the immutable workspace generation.
    pub file: FileId,
    /// Workspace-relative path used by adapters for module identity.
    pub path: String,
    /// Language adapter selected for this exact snapshot.
    pub language: Option<String>,
    /// SHA-256 of the complete source bytes.
    pub source_digest: [u8; 32],
    /// Adapter-lowered declarations, references, flow events, and browse
    /// facts. `None` only when no registered adapter owns the file.
    pub declarations: Option<DeclIndex>,
    /// Adapter-lowered imports for the same syntax tree.
    pub imports: Option<ImportIndex>,
    /// Parser/adapter diagnostics emitted while lowering this exact file.
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceDescriptor {
    file: FileId,
    path: String,
    language: Option<String>,
    source_digest: [u8; 32],
    source_bytes: u64,
    version: u64,
}

struct PreparedCompilerObject {
    compressed: Vec<u8>,
    payload_digest: [u8; 32],
    payload_len: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompilerObjectMetadata {
    version: u32,
    semantic_fingerprint: u64,
    generation_digest: [u8; 32],
    files: Vec<CompilerObjectFileMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompilerObjectFileMetadata {
    file: u32,
    path: String,
    language: Option<String>,
    source_digest: [u8; 32],
    payload_digest: [u8; 32],
    payload_len: u32,
}

/// Read-only compiler-object generation. A generation may be globally stale
/// after one edit while still supplying exact content-addressed objects for
/// every unchanged file.
pub(crate) struct CompilerObjectStore {
    reader: FactStoreReader,
    metadata: CompilerObjectMetadata,
    /// Keeps a scoped compiler session's directory alive until the last
    /// reader is dropped. Persistent workspace sidecars leave this empty.
    _temporary_root: Option<Arc<tempfile::TempDir>>,
}

impl CompilerObjectStore {
    pub(crate) fn open_reusable(workspace_root: &Path) -> std::io::Result<Self> {
        let path = compiler_object_sidecar_path(workspace_root);
        Self::open_at(&path, None)
    }

    fn open_at(path: &Path, temporary_root: Option<Arc<tempfile::TempDir>>) -> std::io::Result<Self> {
        let reader = FactStoreReader::open_relaxed(path).map_err(factstore_io)?;
        if reader.header().table_id != COMPILER_OBJECT_TABLE_ID {
            return Err(invalid_data("compiler-object factstore table mismatch"));
        }
        let hit = reader
            .get(METADATA_KEY)
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object metadata is missing"))?;
        if hit.body_hash != u64::from(COMPILER_OBJECT_CACHE_VERSION) {
            return Err(invalid_data("compiler-object metadata version mismatch"));
        }
        let metadata: CompilerObjectMetadata = wire::decode(&hit.payload).map_err(invalid_wire)?;
        if metadata.version != COMPILER_OBJECT_CACHE_VERSION
            || metadata.semantic_fingerprint != compiler_frontend_semantic_fingerprint()
        {
            return Err(invalid_data("compiler-object semantic ABI mismatch"));
        }
        if reader.header().pipeline_hash != metadata_pipeline_hash(&metadata) {
            return Err(invalid_data("compiler-object pipeline fingerprint mismatch"));
        }
        Ok(Self {
            reader,
            metadata,
            _temporary_root: temporary_root,
        })
    }

    fn covers(&self, descriptors: &[SourceDescriptor]) -> bool {
        descriptors
            .iter()
            .all(|descriptor| self.metadata_for(descriptor).is_some())
    }

    fn metadata_for(&self, descriptor: &SourceDescriptor) -> Option<&CompilerObjectFileMetadata> {
        let metadata = self
            .metadata
            .files
            .binary_search_by_key(&descriptor.file.raw(), |file| file.file)
            .ok()
            .map(|index| &self.metadata.files[index])?;
        (metadata.path == descriptor.path
            && metadata.language == descriptor.language
            && metadata.source_digest == descriptor.source_digest)
            .then_some(metadata)
    }

    fn load(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompiledFileObject>> {
        let Some(prepared) = self.compressed_payload(descriptor)? else {
            return Ok(None);
        };
        let decoded = zstd::stream::decode_all(Cursor::new(prepared.compressed))?;
        let object: CompiledFileObject = wire::decode(&decoded).map_err(invalid_wire)?;
        validate_object(&object, descriptor)?;
        Ok(Some(object))
    }

    fn compressed_payload(
        &self,
        descriptor: &SourceDescriptor,
    ) -> std::io::Result<Option<PreparedCompilerObject>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let hit = self
            .reader
            .get(object_key(descriptor.file))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object payload is missing"))?;
        if hit.body_hash != object_body_hash(descriptor) {
            return Err(invalid_data("compiler-object body fingerprint mismatch"));
        }
        if digest_bytes(&hit.payload) != metadata.payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.payload_len)
        {
            return Err(invalid_data("compiler-object payload digest mismatch"));
        }
        Ok(Some(PreparedCompilerObject {
            compressed: hit.payload,
            payload_digest: metadata.payload_digest,
            payload_len: metadata.payload_len,
        }))
    }

    fn validate_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<()> {
        let mut payload = self
            .reader
            .payload_reader(u64::from(metadata.file) + 1)
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object payload is missing"))?;
        if payload.body_hash != object_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data("compiler-object body fingerprint mismatch"));
        }
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = payload.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            total = total.saturating_add(read as u64);
        }
        if total != u64::from(metadata.payload_len)
            || <[u8; 32]>::from(hasher.finalize()) != metadata.payload_digest
        {
            return Err(invalid_data("compiler-object payload digest mismatch"));
        }
        Ok(())
    }
}

impl AnalyzerDb {
    /// Load one exact compiler object from the current content-addressed
    /// generation, or compile it from Tree-sitter when no valid object exists.
    /// The result is not retained in the database: broad phases stream one
    /// object at a time so resident memory follows active work, not project
    /// size.
    #[must_use]
    pub fn compiler_file_object_uncached(&self, file: FileId) -> Option<CompiledFileObject> {
        let descriptor = source_descriptor(self, file)?;
        let mut loaded = None;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load(&descriptor) {
                Ok(Some(object)) => loaded = Some(object),
                Ok(None) => {}
                Err(error) => {
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler object miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        let object = loaded.unwrap_or_else(|| self.compile_fresh_file_object(descriptor));
        self.publish_compiler_diagnostics(&object);
        Some(object)
    }

    /// Visit exact compiler objects for a deterministic file sequence using
    /// memory-aware parallel batches.
    ///
    /// `visit` is called in `files` order exactly once per requested file.
    /// Each completed batch is projected and dropped before the next batch is
    /// compiled, so retained memory follows the scheduler's batch width
    /// rather than workspace size. Batches use the current/shared Rayon
    /// scheduler instead of creating nested private pools, preventing
    /// oversubscription when several exact analyses run concurrently. Memory
    /// availability changes only how many independent Tree-sitter units are
    /// present in a batch; it never changes the file set or compiler facts.
    pub fn visit_compiler_file_objects_uncached(
        &self,
        files: &[FileId],
        mut visit: impl FnMut(FileId, Option<CompiledFileObject>),
    ) {
        let source_bytes = files
            .iter()
            .map(|file| {
                self.inner
                    .vfs
                    .snapshot(*file)
                    .ok()
                    .and_then(|snapshot| u64::try_from(snapshot.text.len()).ok())
                    .unwrap_or(0)
            })
            .collect::<Vec<_>>();
        let batches = bonsai_common::compiler_weighted_batches(&source_bytes, compiler_object_cpu_workers());
        let mut visited = 0usize;
        for range in batches {
            use rayon::prelude::*;
            let batch = files[range]
                .par_iter()
                .map(|file| (*file, self.compiler_file_object_uncached(*file)))
                .collect::<Vec<_>>();
            for (file, object) in batch {
                visit(file, object);
                visited = visited.saturating_add(1);
            }
        }
        debug_assert_eq!(visited, files.len());
    }

    /// Persist a complete immutable compiler-object generation. Existing
    /// objects are validated and reused entry-by-entry without decoding;
    /// stale, corrupt, or missing entries are recompiled from the registered
    /// language adapter.
    pub fn save_compiler_object_sidecar(&self, workspace_root: &Path) -> std::io::Result<usize> {
        let _generation_guard = self.inner.compiler_object_generation_build.lock();
        let path = compiler_object_sidecar_path(workspace_root);
        let descriptors = self
            .inner
            .vfs
            .all_files()
            .into_iter()
            .filter_map(|file| source_descriptor(self, file))
            .collect::<Vec<_>>();
        self.write_compiler_object_generation(&path, descriptors, None)
    }

    /// Ensure that exact compiler objects for `files` are reusable for the
    /// lifetime of this database without publishing a partial generation
    /// under the analyzed workspace.
    ///
    /// The first caller lowers missing Tree-sitter units into a scoped
    /// disk-backed factstore. Later compiler phases stream validated objects
    /// from that immutable session, so declarations never accumulate in RAM
    /// and the same source is not reparsed for package, matcher, and taint
    /// phases. Existing persistent or scoped objects are copied as compressed
    /// payloads; only genuinely missing or changed files are lowered.
    pub fn ensure_compiler_object_session(&self, files: &[FileId]) -> std::io::Result<usize> {
        if files.is_empty() {
            return Ok(0);
        }
        let _generation_guard = self.inner.compiler_object_generation_build.lock();
        let mut descriptors = files
            .iter()
            .copied()
            .filter_map(|file| source_descriptor(self, file))
            .collect::<Vec<_>>();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        descriptors.dedup_by_key(|descriptor| descriptor.file.raw());
        if self
            .inner
            .compiler_object_store
            .read()
            .as_ref()
            .is_some_and(|store| store.covers(&descriptors))
        {
            return Ok(0);
        }

        // Preserve every still-exact object from a previous scoped session.
        // This makes successive rule-language batches monotonic without
        // widening the first pass to files that no active rule can consume.
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            for metadata in &store.metadata.files {
                let Some(descriptor) = source_descriptor(self, FileId::new(metadata.file)) else {
                    continue;
                };
                if store.metadata_for(&descriptor).is_some() {
                    descriptors.push(descriptor);
                }
            }
            descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
            descriptors.dedup_by_key(|descriptor| descriptor.file.raw());
        }

        let temporary_root = Arc::new(
            tempfile::Builder::new()
                .prefix("bonsai-compiler-session-")
                .tempdir()?,
        );
        let path = temporary_root.path().join("compiler-objects.factstore");
        self.write_compiler_object_generation(&path, descriptors, Some(temporary_root))
    }

    fn write_compiler_object_generation(
        &self,
        path: &Path,
        mut descriptors: Vec<SourceDescriptor>,
        temporary_root: Option<Arc<tempfile::TempDir>>,
    ) -> std::io::Result<usize> {
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        descriptors.dedup_by_key(|descriptor| descriptor.file.raw());
        let generation_digest = generation_digest(&descriptors);
        let mut prepared = PreparedFactStorePayload::create_near(path).map_err(factstore_io)?;
        let mut prepared_entries = Vec::with_capacity(descriptors.len());
        let mut files = Vec::with_capacity(descriptors.len());
        let cpu_workers = compiler_object_cpu_workers();
        let source_bytes = descriptors
            .iter()
            .map(|descriptor| descriptor.source_bytes)
            .collect::<Vec<_>>();
        let batches = bonsai_common::compiler_weighted_batches(&source_bytes, cpu_workers);
        let parallel_width = batches.iter().map(std::ops::Range::len).max().unwrap_or(1);
        let pool = (parallel_width > 1)
            .then(|| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(parallel_width)
                    .build()
                    .ok()
            })
            .flatten();
        for range in batches {
            let compile = || {
                use rayon::prelude::*;
                descriptors[range.clone()]
                    .par_iter()
                    .map(|descriptor| prepare_compiler_object(self, descriptor))
                    .collect::<Vec<_>>()
            };
            let encoded = if let Some(pool) = &pool {
                pool.install(compile)
            } else {
                compile()
            };
            for (descriptor, encoded) in descriptors[range].iter().zip(encoded) {
                let encoded = encoded?;
                let (payload_offset, persisted_len) =
                    prepared.append(&encoded.compressed).map_err(factstore_io)?;
                debug_assert_eq!(encoded.payload_len, persisted_len);
                prepared_entries.push(PreparedFactStoreEntry {
                    key: object_key(descriptor.file),
                    body_hash: object_body_hash(descriptor),
                    payload_offset,
                    payload_len: encoded.payload_len,
                });
                files.push(CompilerObjectFileMetadata {
                    file: descriptor.file.raw(),
                    path: descriptor.path.clone(),
                    language: descriptor.language.clone(),
                    source_digest: descriptor.source_digest,
                    payload_digest: encoded.payload_digest,
                    payload_len: encoded.payload_len,
                });
            }
        }
        let metadata = CompilerObjectMetadata {
            version: COMPILER_OBJECT_CACHE_VERSION,
            semantic_fingerprint: compiler_frontend_semantic_fingerprint(),
            generation_digest,
            files,
        };
        let writer = FactStoreWriter::create_from_prepared(
            path,
            COMPILER_OBJECT_TABLE_ID,
            metadata_pipeline_hash(&metadata),
            prepared,
            prepared_entries,
        )
        .map_err(factstore_io)?;
        writer
            .add_owned(
                METADATA_KEY,
                u64::from(COMPILER_OBJECT_CACHE_VERSION),
                wire::encode_struct_map(&metadata).map_err(invalid_wire)?,
            )
            .map_err(factstore_io)?;
        let entries = writer.finish().map_err(factstore_io)?;
        let store = CompilerObjectStore::open_at(path, temporary_root)?;
        *self.inner.compiler_object_store.write() = Some(Arc::new(store));
        Ok(entries.saturating_sub(1))
    }

    /// Validate that the complete compiler-object generation matches the
    /// current immutable VFS snapshot without decoding every object payload.
    #[must_use]
    pub fn compiler_object_sidecar_is_current(&self, workspace_root: &Path) -> bool {
        let Ok(store) = CompilerObjectStore::open_reusable(workspace_root) else {
            return false;
        };
        let mut descriptors = self
            .inner
            .vfs
            .all_files()
            .into_iter()
            .filter_map(|file| source_descriptor(self, file))
            .collect::<Vec<_>>();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        if store.metadata.generation_digest != generation_digest(&descriptors)
            || store.metadata.files.len() != descriptors.len()
            || store.reader.len() != descriptors.len().saturating_add(1)
        {
            return false;
        }
        descriptors
            .iter()
            .zip(&store.metadata.files)
            .all(|(descriptor, metadata)| {
                metadata.file == descriptor.file.raw()
                    && metadata.path == descriptor.path
                    && metadata.language == descriptor.language
                    && metadata.source_digest == descriptor.source_digest
                    && store.validate_payload(metadata).is_ok()
            })
    }

    fn compile_fresh_file_object(&self, descriptor: SourceDescriptor) -> CompiledFileObject {
        if descriptor.language.is_none() {
            return CompiledFileObject {
                file: descriptor.file,
                path: descriptor.path,
                language: None,
                source_digest: descriptor.source_digest,
                declarations: None,
                imports: None,
                diagnostics: Vec::new(),
            };
        }
        let mut parser_diagnostics = match self.parse(descriptor.file) {
            Ok(parsed) => parsed.diagnostics.clone(),
            Err(error) => vec![Diagnostic::new(
                Span::new(descriptor.file, 0, descriptor.source_bytes),
                Severity::Error,
                format!("source parsing failed: {error}"),
            )
            .with_code("parse-failed")],
        };
        let diagnostics = parking_lot::RwLock::new(DiagnosticSink::new());
        let declarations = self.build_decl_index_with_diagnostics(descriptor.file, &diagnostics);
        let imports = self.build_import_index_with_diagnostics(descriptor.file, &diagnostics);
        self.release_syntax(descriptor.file);
        parser_diagnostics.extend(diagnostics.read().snapshot());
        CompiledFileObject {
            file: descriptor.file,
            path: descriptor.path,
            language: descriptor.language,
            source_digest: descriptor.source_digest,
            declarations,
            imports,
            diagnostics: parser_diagnostics,
        }
    }

    fn publish_compiler_diagnostics(&self, object: &CompiledFileObject) {
        let key = (object.file, object.source_digest);
        if object.diagnostics.is_empty() {
            return;
        }
        let _gate = self.inner.compiler_diagnostics_gate.lock();
        if !self.inner.compiler_diagnostics_published.write().insert(key) {
            return;
        }
        self.inner
            .diagnostics
            .write()
            .extend(object.diagnostics.iter().cloned());
    }
}

/// Conventional compiler-object generation path under `<workspace>/.bonsai`.
#[must_use]
pub fn compiler_object_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!(
        "compiler-objects.v{COMPILER_OBJECT_CACHE_VERSION}.factstore"
    ))
}

/// Validate the compiler-object container and semantic ABI without opening a
/// workspace or decoding every file payload. Exact source identity is checked
/// separately by [`AnalyzerDb::compiler_object_sidecar_is_current`] whenever a
/// workspace is available.
pub fn validate_compiler_object_sidecar_layout(workspace_root: &Path) -> std::io::Result<usize> {
    let store = CompilerObjectStore::open_reusable(workspace_root)?;
    if store.reader.len() != store.metadata.files.len().saturating_add(1) {
        return Err(invalid_data("compiler-object entry count mismatch"));
    }
    let mut previous_file = None;
    for file in &store.metadata.files {
        if previous_file.is_some_and(|previous| previous >= file.file) {
            return Err(invalid_data("compiler-object metadata is not uniquely sorted"));
        }
        store.validate_payload(file)?;
        previous_file = Some(file.file);
    }
    Ok(store.metadata.files.len())
}

fn source_descriptor(db: &AnalyzerDb, file: FileId) -> Option<SourceDescriptor> {
    let snapshot = db.inner.vfs.snapshot(file).ok()?;
    let path = db.inner.vfs.path(file).ok()?;
    let root = db.workspace_root();
    let relative = root
        .as_deref()
        .and_then(|root| path.strip_prefix(root).ok())
        .unwrap_or(path.as_path());
    let path = relative.to_string_lossy().replace('\\', "/");
    let language = db
        .adapter_for(file)
        .map(|adapter| adapter.language_id().as_str().to_string());
    Some(SourceDescriptor {
        file,
        path,
        language,
        source_digest: digest_bytes(snapshot.text.as_bytes()),
        source_bytes: u64::try_from(snapshot.text.len()).unwrap_or(u64::MAX),
        version: snapshot.version,
    })
}

fn prepare_compiler_object(
    db: &AnalyzerDb,
    descriptor: &SourceDescriptor,
) -> std::io::Result<PreparedCompilerObject> {
    ensure_source_version(db, descriptor)?;
    if let Some(store) = db.inner.compiler_object_store.read().as_ref().cloned() {
        match store.compressed_payload(descriptor) {
            Ok(Some(prepared)) => {
                ensure_source_version(db, descriptor)?;
                return Ok(prepared);
            }
            Ok(None) => {}
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "compiler object rebuild for {}: {}",
                    descriptor.path,
                    error
                );
            }
        }
    }
    let object = db.compile_fresh_file_object(descriptor.clone());
    ensure_source_version(db, descriptor)?;
    validate_object(&object, descriptor)?;
    let encoded = wire::encode_struct_map(&object).map_err(invalid_wire)?;
    let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
    let payload_digest = digest_bytes(&compressed);
    let payload_len =
        u32::try_from(compressed.len()).map_err(|_| invalid_data("compiler-object payload exceeds 4 GiB"))?;
    Ok(PreparedCompilerObject {
        compressed,
        payload_digest,
        payload_len,
    })
}

fn ensure_source_version(db: &AnalyzerDb, descriptor: &SourceDescriptor) -> std::io::Result<()> {
    let snapshot = db
        .inner
        .vfs
        .snapshot(descriptor.file)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Interrupted, error))?;
    if snapshot.version != descriptor.version
        || u64::try_from(snapshot.text.len()).unwrap_or(u64::MAX) != descriptor.source_bytes
        || digest_bytes(snapshot.text.as_bytes()) != descriptor.source_digest
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!(
                "source changed while compiling immutable object `{}`",
                descriptor.path
            ),
        ));
    }
    Ok(())
}

fn compiler_object_cpu_workers() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    std::env::var("BONSAI_COMPILER_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(available)
        .clamp(1, available)
}

fn validate_object(object: &CompiledFileObject, descriptor: &SourceDescriptor) -> std::io::Result<()> {
    if object.file != descriptor.file
        || object.path != descriptor.path
        || object.language != descriptor.language
        || object.source_digest != descriptor.source_digest
        || object
            .declarations
            .as_ref()
            .is_some_and(|index| index.file != descriptor.file)
        || object
            .imports
            .as_ref()
            .is_some_and(|index| index.file != descriptor.file)
        || object
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.span.file != descriptor.file)
    {
        return Err(invalid_data("compiler-object identity mismatch"));
    }
    Ok(())
}

fn generation_digest(descriptors: &[SourceDescriptor]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bonsai-compiler-generation-v1\0");
    hasher.update(compiler_frontend_semantic_fingerprint().to_le_bytes());
    for descriptor in descriptors {
        hasher.update(descriptor.file.raw().to_le_bytes());
        hasher.update(descriptor.path.as_bytes());
        hasher.update([0]);
        if let Some(language) = &descriptor.language {
            hasher.update(language.as_bytes());
        }
        hasher.update([0]);
        hasher.update(descriptor.source_digest);
    }
    hasher.finalize().into()
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn compiler_frontend_semantic_fingerprint() -> u64 {
    let policy = MATCHER_POLICY_FINGERPRINT;
    (policy as u64)
        ^ ((policy >> 64) as u64)
        ^ u64::from(COMPILER_OBJECT_CACHE_VERSION)
        ^ 0x434F_4D50_494C_4552
}

fn metadata_pipeline_hash(metadata: &CompilerObjectMetadata) -> u64 {
    u64::from_le_bytes(
        metadata.generation_digest[..8]
            .try_into()
            .expect("fixed SHA-256 prefix"),
    ) ^ metadata.semantic_fingerprint
        ^ u64::from(metadata.version)
}

fn object_key(file: FileId) -> u64 {
    u64::from(file.raw()) + 1
}

fn object_body_hash(descriptor: &SourceDescriptor) -> u64 {
    object_body_hash_from_digest(descriptor.source_digest)
}

fn object_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    u64::from_le_bytes(source_digest[..8].try_into().expect("fixed SHA-256 prefix"))
        ^ compiler_frontend_semantic_fingerprint()
}

fn invalid_wire(error: impl std::error::Error + Send + Sync + 'static) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn factstore_io(error: FactStoreError) -> std::io::Error {
    match error {
        FactStoreError::Io(error) => error,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_factstore::{Header, IndexEntry, HEADER_SIZE, INDEX_ENTRY_SIZE};
    use bonsai_lang_api::LanguageRegistry;
    use bonsai_vfs::Vfs;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn compiler_object_generation_round_trips_and_rejects_changed_source() {
        let root = tempfile::tempdir().expect("tempdir");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write("src/input.fixture".to_string(), Arc::<str>::from("first"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());

        assert_eq!(
            db.save_compiler_object_sidecar(root.path())
                .expect("save objects"),
            1
        );
        assert!(db.compiler_object_sidecar_is_current(root.path()));
        let object = db.compiler_file_object_uncached(file).expect("load object");
        assert_eq!(object.source_digest, digest_bytes(b"first"));
        assert!(object.diagnostics.is_empty());

        vfs.write("src/input.fixture".to_string(), Arc::<str>::from("second"));
        assert!(!db.compiler_object_sidecar_is_current(root.path()));
        let object = db.compiler_file_object_uncached(file).expect("recompile object");
        assert_eq!(object.source_digest, digest_bytes(b"second"));
    }

    #[test]
    fn compiler_object_identity_is_workspace_relative() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.fixture");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(source.to_string_lossy().into_owned(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());

        let object = db.compiler_file_object_uncached(file).expect("compile object");
        assert_eq!(object.path, "src/input.fixture");
    }

    #[test]
    fn bulk_compiler_objects_preserve_requested_order_and_complete_coverage() {
        let vfs = Arc::new(Vfs::new());
        let first = vfs.write("src/first.fixture".to_string(), Arc::<str>::from("first"));
        let second = vfs.write("src/second.fixture".to_string(), Arc::<str>::from("second"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));

        let requested = [second, first, second];
        let mut objects = Vec::new();
        db.visit_compiler_file_objects_uncached(&requested, |file, object| {
            objects.push((file, object));
        });

        assert_eq!(
            objects.iter().map(|(file, _)| *file).collect::<Vec<_>>(),
            requested,
            "memory-aware scheduling must not reorder or omit compiler units"
        );
        assert_eq!(
            objects
                .iter()
                .map(|(_, object)| object.as_ref().map(|object| object.source_digest))
                .collect::<Vec<_>>(),
            vec![
                Some(digest_bytes(b"second")),
                Some(digest_bytes(b"first")),
                Some(digest_bytes(b"second")),
            ]
        );
    }

    #[test]
    fn compiler_object_validation_rejects_same_size_payload_corruption() {
        let root = tempfile::tempdir().expect("tempdir");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write("src/input.fixture".to_string(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects");

        let path = compiler_object_sidecar_path(root.path());
        let mut sidecar = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open compiler-object sidecar");
        let mut header_bytes = [0_u8; HEADER_SIZE];
        sidecar.read_exact(&mut header_bytes).expect("read header");
        let header = Header::from_bytes(&header_bytes).expect("valid factstore header");
        sidecar
            .seek(SeekFrom::Start(header.index_offset))
            .expect("seek index");
        let mut object_entry = None;
        for _ in 0..header.index_count {
            let mut entry_bytes = [0_u8; INDEX_ENTRY_SIZE];
            sidecar.read_exact(&mut entry_bytes).expect("read index entry");
            let entry = IndexEntry::from_bytes(&entry_bytes).expect("valid index entry");
            if entry.key == object_key(file) {
                object_entry = Some(entry);
                break;
            }
        }
        let entry = object_entry.expect("compiler-object entry");
        sidecar
            .seek(SeekFrom::Start(entry.payload_offset))
            .expect("seek object payload");
        let mut byte = [0_u8; 1];
        sidecar.read_exact(&mut byte).expect("read object payload");
        byte[0] ^= 0xff;
        sidecar
            .seek(SeekFrom::Start(entry.payload_offset))
            .expect("rewind object payload");
        sidecar.write_all(&byte).expect("corrupt object payload");
        sidecar.sync_all().expect("flush object corruption");

        assert!(validate_compiler_object_sidecar_layout(root.path()).is_err());
        assert!(!db.compiler_object_sidecar_is_current(root.path()));
    }
}
