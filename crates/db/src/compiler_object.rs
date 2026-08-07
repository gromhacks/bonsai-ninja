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
use bonsai_hash::fnv1a_bytes64;
use bonsai_lang_api::{
    CompilerAttribution, CompilerBrowseHeader, CompilerFunctionAttribution, CompilerSyntaxHeader, DeclIndex,
    ImportIndex,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Current per-file compiler-object wire and semantic ABI.
///
/// Bump this whenever adapter lowering, [`DeclIndex`], [`ImportIndex`],
/// [`CompilerSyntaxHeader`], [`CompilerBrowseHeader`], [`CompilerAttribution`],
/// or the object validation contract changes in a way that can alter compiler
/// facts.
// v62: call-argument facts retain adapter-lowered inline callback parameter
// bindings. Configured source-callback delivery can therefore enter an
// inlined callback body without parsing rendered lambda text or inventing a
// synthetic callable declaration.
// v61: Java compilation units without a package declaration use the unnamed
// package rather than a filename-derived namespace; Perl, Ruby, and Rust
// structured control facts track their current Tree-sitter grammar nodes.
// v60: Go interpreted strings assemble exact byte/octal escapes before UTF-8
// conversion, retaining valid multi-byte static scalar values while invalid
// byte strings still fail closed.
// v59: Python finite-map and character-substitution binding checks resolve
// lexical owners, nested closures, and global/nonlocal directives instead of
// treating same-spelled names across a file as one binding.
// v58: configured Go transformer bindings are keyed by callable ownership, so
// same-spelled locals in independent functions cannot suppress or inherit one
// another's facts. Cached v57 objects used file-wide textual write counts.
// v57: exact aggregate fields survive unrelated dynamic leaves; configured
// Go character transforms retain decoded substitution maps and lexical binding
// ownership; Go qualified composite receivers, Java constructor-local scope,
// nested receiver-call operands, and Python finite-map membership use their
// corrected adapter IR. Cached v55/v56 objects cannot represent or reliably
// reproduce all of those facts.
// v55: synthesized Swift computed-property declarations retain the same
// AST-derived receiver-state sources as ordinary callable lowering.
// v54: Ruby ERB/RHTML compiler objects retain Tree-sitter-proven instance
// variables as implicit inputs of the synthetic template module. Cached v53
// bodies cannot prove template-context values reaching a sink.
// v53: C++ direct initialization (`Type value(args)`) retains the
// Tree-sitter `init_declarator` as a constructor call. Cached v52 bodies omit
// that call boundary and cannot preserve constructor state/return flow;
// constructor field dependencies also use exact expression-operand facts.
// v52: C# expression-bodied property getters retain exact receiver-field
// return projections. Cached v51 bodies may expose only the scalar return and
// cannot satisfy a field-specific IDG target demand.
// v51: direct-call assignment lowering follows only the immediate operand of
// adapter-declared transparent CST wrappers. Cached v50 bodies may otherwise
// retain an unrelated nested helper call as the value-producing RHS.
// v50: PHP callable literals are classified by the PHP adapter, Go nested
// aggregate call arguments retain exact field dependencies, and file-derived
// semantic identities use canonical dotted compiler IR. Cached v49 bodies
// must not replay the former shared text interpretation or qualified names.
// v49: Java non-static field initializer targets use the adapter's canonical
// implicit-receiver place, matching later field receiver calls without a
// shared-language alias rule.
// v48: Ruby class/module and singleton-method ownership is lowered directly
// from the adapter's declared Tree-sitter grammar contexts. Cached declarations
// must not replay the earlier function taxonomy for class-owned methods.
// v47: PHP's adapter types sigiled implicit receivers from their enclosing
// class/base declarations so streamed bodies and persisted compiler objects
// resolve `$this` calls from the same syntax facts.
// v46: Perl conditional and postfix-conditional expression nodes lower to
// explicit branch IR instead of being flattened into unconditional events.
// v45: JavaScript `super(...)` retains constructor dispatch kind.
// v44: Java bare call receivers proven by lexical binding to be current-class
// instance fields are qualified to the adapter's current receiver place;
// shadowing locals and static fields remain unqualified.
// v43: Elixir map/struct results nested beneath control expressions merge
// exact field dependencies across result branches, including map-update
// syntax, without treating call target names as value sources.
// v42: Elixir `try` assignment results lower from the body and each
// rescue/catch/else clause's final expression; `after` remains side-effect
// only and cannot become the expression result.
// v41: Elixir `cond` assignment results lower from each clause body's final
// expression rather than surviving as an unresolved macro call result.
// v40: assignment/value lowering now carries exact adapter-owned generator,
// aggregate, receiver projection, constructor-delegation, and Elixir
// value-field facts introduced by the unified IDG compiler pipeline. Cached
// v39 bodies must not replay the former pseudo-call/phantom-assignment IR.
// v38: runtime type-guard operator/call spellings are adapter declarations;
// compiler objects no longer inherit a cross-language builtin/operator union.
// v37: provider-bound character/same-origin facts and compiler-guard evidence
// carry exact adapter syntax identity for rule-selected interpretation;
// typed branch conditions also preserve runtime-truth operands.
// v36: Go final-pass call arguments include adapter-added if-init/range/index
// calls plus adapter-decoded static values, and exact adapter guard facts
// include proven relative-path boundary helpers.
// v20: imported namespace/type qualifiers are classified in receiver facts,
// preventing call resolution syntax from becoming a runtime data receiver.
// v19: exact browse/search candidate terms became an independently decodable
// projection. Candidate-index construction no longer inflates declaration and
// flow bodies for every file.
// v17: compiler attribution is stored as independently compressed function
// frames behind a small span index. A function-scoped query never decodes the
// attribution for every sibling method in a large source file.
// v16: exact call/write attribution became an independently decodable per-file
// projection beside the full declaration/flow body.
// v15: standalone lambdas and named local callables retain their nearest
// Tree-sitter lexical callable parent; Perl package modules own their
// declarations and `Package::sub(...)` lowers as a static function call.
// v13: nested class-like declarations retain their exact lexical parent, so
// member qualified identities include every enclosing AST owner.
// v14: receiver-less constructor events inherit the enclosing declaration
// type only when the language adapter declares that exact constructor syntax.
// v12: independently decodable imports/syntax projections live in one
// per-file factstore entry instead of the generation metadata. Opening a
// 30k-file generation now retains only compact path/digest descriptors;
// candidate queries hydrate headers and bodies for selected FileIds lazily.
pub const COMPILER_OBJECT_CACHE_VERSION: u32 = 62;
const LEGACY_COMPILER_OBJECT_CACHE_VERSION: u32 = 11;

const COMPILER_OBJECT_TABLE_ID: u32 = 104;
const METADATA_KEY: u64 = 0;
const COMPILER_OBJECT_COMPRESSION_LEVEL: i32 = 1;
const ATTRIBUTION_PAYLOAD_MAGIC: [u8; 8] = *b"BNSATTR1";
const ATTRIBUTION_PAYLOAD_PREFIX_BYTES: usize = 8 + 4 + 32;

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
    source_hash: u64,
    source_bytes: u64,
    version: u64,
}

struct PreparedCompilerObject {
    compressed: Vec<u8>,
    payload_digest: [u8; 32],
    payload_len: u32,
    header_compressed: Vec<u8>,
    header_payload_digest: [u8; 32],
    header_payload_len: u32,
    attribution_compressed: Vec<u8>,
    attribution_payload_digest: [u8; 32],
    attribution_payload_len: u32,
    browse_compressed: Vec<u8>,
    browse_payload_digest: [u8; 32],
    browse_payload_len: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompilerObjectHeader {
    imports: Option<ImportIndex>,
    imports_digest: [u8; 32],
    syntax: Option<CompilerSyntaxHeader>,
    syntax_digest: [u8; 32],
}

/// Independently decoded directory for the function frames in one compiler
/// attribution payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompilerAttributionIndex {
    pub file: FileId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    frames: Vec<CompilerAttributionFrame>,
    /// Absolute offset of the frame blob relative to the fact-store payload.
    /// This is container metadata reconstructed from the fixed prefix and is
    /// intentionally not serialized inside the semantic index.
    #[serde(skip)]
    frames_payload_offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CompilerAttributionFrame {
    declaration_span: Span,
    relative_offset: u64,
    compressed_len: u32,
    compressed_digest: [u8; 32],
}

impl CompilerAttributionIndex {
    fn frame_at_span(&self, span: Span) -> Option<&CompilerAttributionFrame> {
        let key = |value: Span| (value.file.raw(), value.start, value.end);
        let wanted = key(span);
        let index = self
            .frames
            .binary_search_by_key(&wanted, |frame| key(frame.declaration_span))
            .ok()?;
        self.frames.get(index)
    }
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
    source_hash: u64,
    payload_digest: [u8; 32],
    payload_len: u32,
    /// Digest/length of the independently decodable imports/syntax projection.
    /// The projection itself is keyed by FileId in the factstore so opening a
    /// generation is O(number of compact descriptors), not O(all header AST
    /// facts).
    header_payload_digest: [u8; 32],
    header_payload_len: u32,
    /// Digest/length of exact adapter-lowered call/write attribution. This
    /// payload is separate from both the broad syntax header and full body so
    /// a path query decodes only the facts it consumes.
    attribution_payload_digest: [u8; 32],
    attribution_payload_len: u32,
    /// Digest/length of exact file-local browse candidate terms. Kept apart
    /// from syntax targets and bodies so either consumer decodes only its own
    /// compiler projection.
    browse_payload_digest: [u8; 32],
    browse_payload_len: u32,
}

/// v11 stored every per-file import/syntax projection inside one monolithic
/// metadata record. Retain only the decoder needed for an exact, one-time
/// migration into v12's lazy per-file layout.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyCompilerObjectMetadataV11 {
    version: u32,
    semantic_fingerprint: u64,
    generation_digest: [u8; 32],
    files: Vec<LegacyCompilerObjectFileMetadataV11>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyCompilerObjectFileMetadataV11 {
    file: u32,
    path: String,
    language: Option<String>,
    source_digest: [u8; 32],
    source_hash: u64,
    payload_digest: [u8; 32],
    payload_len: u32,
    imports: Option<ImportIndex>,
    imports_digest: [u8; 32],
    syntax: Option<CompilerSyntaxHeader>,
    syntax_digest: [u8; 32],
}

/// Read-only compiler-object generation. A generation may be globally stale
/// after one edit while still supplying exact content-addressed objects for
/// every unchanged file.
pub(crate) struct CompilerObjectStore {
    reader: FactStoreReader,
    metadata: CompilerObjectMetadata,
    attribution_indexes: parking_lot::Mutex<CompilerAttributionIndexCache>,
    attribution_index_budget_bytes: u64,
    /// Keeps a scoped compiler session's directory alive until the last
    /// reader is dropped. Persistent workspace sidecars leave this empty.
    _temporary_root: Option<Arc<tempfile::TempDir>>,
}

#[derive(Debug)]
struct CachedCompilerAttributionIndex {
    index: Arc<CompilerAttributionIndex>,
    estimated_bytes: u64,
}

#[derive(Debug)]
struct CompilerAttributionIndexCache {
    entries: lru::LruCache<FileId, CachedCompilerAttributionIndex>,
    estimated_bytes: u64,
}

impl Default for CompilerAttributionIndexCache {
    fn default() -> Self {
        Self {
            entries: lru::LruCache::unbounded(),
            estimated_bytes: 0,
        }
    }
}

fn compiler_attribution_index_cache_budget_bytes() -> u64 {
    const DEFAULT_BYTES: u64 = 16 * 1024 * 1024;
    const MIN_BYTES: u64 = 1024 * 1024;
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    bonsai_common::effective_memory_limit_bytes()
        .map(|limit| (limit / 256).clamp(MIN_BYTES, MAX_BYTES))
        .unwrap_or(DEFAULT_BYTES)
}

fn estimated_compiler_attribution_index_bytes(index: &CompilerAttributionIndex) -> u64 {
    u64::try_from(std::mem::size_of::<CompilerAttributionIndex>())
        .unwrap_or(u64::MAX)
        .saturating_add(
            u64::try_from(index.frames.capacity())
                .unwrap_or(u64::MAX)
                .saturating_mul(
                    u64::try_from(std::mem::size_of::<CompilerAttributionFrame>()).unwrap_or(u64::MAX),
                ),
        )
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
            attribution_indexes: parking_lot::Mutex::new(CompilerAttributionIndexCache::default()),
            attribution_index_budget_bytes: compiler_attribution_index_cache_budget_bytes(),
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
            && metadata.source_digest == descriptor.source_digest
            && metadata.source_hash == descriptor.source_hash)
            .then_some(metadata)
    }

    fn load(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompiledFileObject>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_object_payload(descriptor, metadata)?;
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
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
        let compressed = self.compressed_object_payload(descriptor, metadata)?;
        Ok(Some(PreparedCompilerObject {
            compressed,
            payload_digest: metadata.payload_digest,
            payload_len: metadata.payload_len,
            header_compressed: self.compressed_header_payload(metadata)?,
            header_payload_digest: metadata.header_payload_digest,
            header_payload_len: metadata.header_payload_len,
            attribution_compressed: self.compressed_attribution_payload(metadata)?,
            attribution_payload_digest: metadata.attribution_payload_digest,
            attribution_payload_len: metadata.attribution_payload_len,
            browse_compressed: self.compressed_browse_payload(metadata)?,
            browse_payload_digest: metadata.browse_payload_digest,
            browse_payload_len: metadata.browse_payload_len,
        }))
    }

    fn compressed_object_payload(
        &self,
        descriptor: &SourceDescriptor,
        metadata: &CompilerObjectFileMetadata,
    ) -> std::io::Result<Vec<u8>> {
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
        Ok(hit.payload)
    }

    fn compressed_header_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(header_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object header payload is missing"))?;
        if hit.body_hash != header_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data("compiler-object header body fingerprint mismatch"));
        }
        if digest_bytes(&hit.payload) != metadata.header_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.header_payload_len)
        {
            return Err(invalid_data("compiler-object header payload digest mismatch"));
        }
        Ok(hit.payload)
    }

    fn compressed_attribution_payload(
        &self,
        metadata: &CompilerObjectFileMetadata,
    ) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(attribution_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object attribution payload is missing"))?;
        if hit.body_hash != attribution_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data(
                "compiler-object attribution body fingerprint mismatch",
            ));
        }
        if digest_bytes(&hit.payload) != metadata.attribution_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.attribution_payload_len)
        {
            return Err(invalid_data(
                "compiler-object attribution payload digest mismatch",
            ));
        }
        Ok(hit.payload)
    }

    fn compressed_browse_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(browse_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object browse payload is missing"))?;
        if hit.body_hash != browse_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data("compiler-object browse body fingerprint mismatch"));
        }
        if digest_bytes(&hit.payload) != metadata.browse_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.browse_payload_len)
        {
            return Err(invalid_data("compiler-object browse payload digest mismatch"));
        }
        Ok(hit.payload)
    }

    fn load_header(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompilerObjectHeader>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_header_payload(metadata)?;
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let header: CompilerObjectHeader = wire::decode(&decoded).map_err(invalid_wire)?;
        if import_index_digest(header.imports.as_ref()) != header.imports_digest
            || compiler_syntax_header_digest(header.syntax.as_ref()) != header.syntax_digest
        {
            return Err(invalid_data("compiler-object independent-header digest mismatch"));
        }
        Ok(Some(header))
    }

    fn load_imports(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<ImportIndex>> {
        Ok(self.load_header(descriptor)?.and_then(|header| header.imports))
    }

    fn load_syntax(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompilerSyntaxHeader>> {
        Ok(self.load_header(descriptor)?.and_then(|header| header.syntax))
    }

    fn load_browse(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompilerBrowseHeader>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_browse_payload(metadata)?;
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let browse: CompilerBrowseHeader = wire::decode(&decoded).map_err(invalid_wire)?;
        Ok(Some(browse))
    }

    fn attribution_payload_range(
        &self,
        metadata: &CompilerObjectFileMetadata,
        relative_offset: u64,
        length: u64,
    ) -> std::io::Result<Vec<u8>> {
        let mut reader = self
            .reader
            .payload_range_reader(
                attribution_key(FileId::new(metadata.file)),
                relative_offset,
                length,
            )
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object attribution payload is missing"))?;
        if reader.body_hash != attribution_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data(
                "compiler-object attribution body fingerprint mismatch",
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
        reader.read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).ok() != Some(length) {
            return Err(invalid_data("compiler-object attribution range is truncated"));
        }
        Ok(bytes)
    }

    fn load_attribution_index(
        &self,
        descriptor: &SourceDescriptor,
    ) -> std::io::Result<Option<Arc<CompilerAttributionIndex>>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        if let Some(index) = self
            .attribution_indexes
            .lock()
            .entries
            .get(&descriptor.file)
            .map(|entry| Arc::clone(&entry.index))
        {
            return Ok(Some(index));
        }
        if metadata.attribution_payload_len < ATTRIBUTION_PAYLOAD_PREFIX_BYTES as u32 {
            return Err(invalid_data("compiler-object attribution payload is truncated"));
        }
        let prefix = self.attribution_payload_range(metadata, 0, ATTRIBUTION_PAYLOAD_PREFIX_BYTES as u64)?;
        if prefix[..8] != ATTRIBUTION_PAYLOAD_MAGIC {
            return Err(invalid_data("compiler-object attribution payload magic mismatch"));
        }
        let index_len = u32::from_le_bytes(prefix[8..12].try_into().expect("fixed attribution index length"));
        let frames_payload_offset = u64::try_from(ATTRIBUTION_PAYLOAD_PREFIX_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(index_len));
        if frames_payload_offset > u64::from(metadata.attribution_payload_len) {
            return Err(invalid_data("compiler-object attribution index exceeds payload"));
        }
        let index_bytes = self.attribution_payload_range(
            metadata,
            ATTRIBUTION_PAYLOAD_PREFIX_BYTES as u64,
            u64::from(index_len),
        )?;
        if digest_bytes(&index_bytes) != prefix[12..44] {
            return Err(invalid_data("compiler-object attribution index digest mismatch"));
        }
        let mut index: CompilerAttributionIndex = wire::decode(&index_bytes).map_err(invalid_wire)?;
        index.frames_payload_offset = frames_payload_offset;
        validate_compiler_attribution_index(&index, metadata)?;
        let index = Arc::new(index);
        let estimated_bytes = estimated_compiler_attribution_index_bytes(&index);
        if self.attribution_index_budget_bytes != 0 && estimated_bytes <= self.attribution_index_budget_bytes
        {
            let mut cache = self.attribution_indexes.lock();
            if let Some(existing) = cache.entries.get(&descriptor.file) {
                return Ok(Some(Arc::clone(&existing.index)));
            }
            cache.estimated_bytes = cache.estimated_bytes.saturating_add(estimated_bytes);
            if let Some((_file, replaced)) = cache.entries.push(
                descriptor.file,
                CachedCompilerAttributionIndex {
                    index: Arc::clone(&index),
                    estimated_bytes,
                },
            ) {
                cache.estimated_bytes = cache.estimated_bytes.saturating_sub(replaced.estimated_bytes);
            }
            while cache.estimated_bytes > self.attribution_index_budget_bytes {
                let Some((_file, evicted)) = cache.entries.pop_lru() else {
                    break;
                };
                cache.estimated_bytes = cache.estimated_bytes.saturating_sub(evicted.estimated_bytes);
            }
        }
        Ok(Some(index))
    }

    fn load_function_attribution(
        &self,
        descriptor: &SourceDescriptor,
        index: &CompilerAttributionIndex,
        declaration_span: Span,
    ) -> std::io::Result<Option<CompilerFunctionAttribution>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        if index.file != descriptor.file {
            return Err(invalid_data(
                "compiler-object attribution index identity mismatch",
            ));
        }
        let Some(frame) = index.frame_at_span(declaration_span) else {
            return Ok(None);
        };
        let relative_offset = index
            .frames_payload_offset
            .checked_add(frame.relative_offset)
            .ok_or_else(|| invalid_data("compiler-object attribution frame offset overflow"))?;
        let compressed =
            self.attribution_payload_range(metadata, relative_offset, u64::from(frame.compressed_len))?;
        if digest_bytes(&compressed) != frame.compressed_digest {
            return Err(invalid_data("compiler-object attribution frame digest mismatch"));
        }
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let attribution: CompilerFunctionAttribution = wire::decode(&decoded).map_err(invalid_wire)?;
        if attribution.declaration_span != declaration_span {
            return Err(invalid_data(
                "compiler-object attribution frame identity mismatch",
            ));
        }
        Ok(Some(attribution))
    }

    fn load_attribution(
        &self,
        descriptor: &SourceDescriptor,
    ) -> std::io::Result<Option<CompilerAttribution>> {
        let Some(index) = self.load_attribution_index(descriptor)? else {
            return Ok(None);
        };
        let mut functions = Vec::with_capacity(index.frames.len());
        for frame in &index.frames {
            functions.push(
                self.load_function_attribution(descriptor, &index, frame.declaration_span)?
                    .ok_or_else(|| invalid_data("compiler-object attribution frame is missing"))?,
            );
        }
        Ok(Some(CompilerAttribution {
            file: descriptor.file,
            functions,
        }))
    }

    fn validate_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<()> {
        validate_streamed_payload(
            &self.reader,
            object_key(FileId::new(metadata.file)),
            object_body_hash_from_digest(metadata.source_digest),
            metadata.payload_len,
            metadata.payload_digest,
            "compiler-object",
        )?;
        validate_streamed_payload(
            &self.reader,
            header_key(FileId::new(metadata.file)),
            header_body_hash_from_digest(metadata.source_digest),
            metadata.header_payload_len,
            metadata.header_payload_digest,
            "compiler-object header",
        )?;
        validate_streamed_payload(
            &self.reader,
            attribution_key(FileId::new(metadata.file)),
            attribution_body_hash_from_digest(metadata.source_digest),
            metadata.attribution_payload_len,
            metadata.attribution_payload_digest,
            "compiler-object attribution",
        )?;
        validate_streamed_payload(
            &self.reader,
            browse_key(FileId::new(metadata.file)),
            browse_body_hash_from_digest(metadata.source_digest),
            metadata.browse_payload_len,
            metadata.browse_payload_digest,
            "compiler-object browse projection",
        )?;
        Ok(())
    }
}

impl AnalyzerDb {
    /// Attach a complete immutable compiler-object generation to a scoped
    /// query after the caller has validated the full source fingerprint set.
    ///
    /// Scoped workspaces normally compile their selected files directly
    /// because renumbered local [`FileId`] values cannot address a
    /// whole-workspace generation safely. Exact-worklist queries preserve the
    /// original ids and pass every workspace source hash here, allowing lazy
    /// per-file object reuse without loading unrelated payloads.
    pub fn load_compiler_object_store_for_source_fingerprints<I, P>(
        &self,
        workspace_root: &Path,
        fingerprints: I,
    ) -> std::io::Result<usize>
    where
        I: IntoIterator<Item = (P, u64)>,
        P: AsRef<Path>,
    {
        let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
        let files = store.metadata.files.len();
        *self.inner.compiler_object_store.write() = Some(Arc::new(store));
        self.inner
            .compiler_object_store_requires_repair
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(files)
    }

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
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
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

    /// Return whether this exact source snapshot has already completed the
    /// canonical compiler-object diagnostic pass in the current process.
    ///
    /// The marker includes successful files with zero diagnostics. Broad
    /// completion audits use it to avoid recompiling syntax headers that an
    /// earlier command phase already lowered. File invalidation removes the
    /// marker together with that file's published diagnostics.
    #[must_use]
    pub fn compiler_diagnostics_are_current(&self, file: FileId) -> bool {
        let Some(descriptor) = source_descriptor(self, file) else {
            return false;
        };
        self.inner
            .compiler_diagnostics_published
            .read()
            .contains(&(file, descriptor.source_digest))
    }

    /// Parse one exact source snapshot and retain only its syntax diagnostics.
    ///
    /// This deliberately does not build a declaration index, import index, or
    /// flow body. Broad analyses use it for their final completeness audit so
    /// files rejected by exact rule planning still receive Tree-sitter parser
    /// coverage without materializing unrelated semantic IR.
    #[must_use]
    pub fn parser_diagnostics_uncached(&self, file: FileId) -> Option<Arc<[Diagnostic]>> {
        let snapshot = self.inner.vfs.snapshot(file).ok()?;
        let key = (file, snapshot.version);
        if let Some(diagnostics) = self.inner.parser_diagnostics.read().get(&key).cloned() {
            return Some(diagnostics);
        }

        let diagnostics = if self.adapter_for(file).is_none() {
            Vec::new()
        } else {
            match self.parse(file) {
                Ok(parsed) => parsed.diagnostics.clone(),
                Err(error) => vec![Diagnostic::new(
                    Span::new(file, 0, u64::try_from(snapshot.text.len()).unwrap_or(u64::MAX)),
                    Severity::Error,
                    format!("source parsing failed: {error}"),
                )
                .with_code("parse-failed")],
            }
        };
        self.release_syntax(file);
        let diagnostics: Arc<[Diagnostic]> = diagnostics.into();
        let mut cached = self.inner.parser_diagnostics.write();
        Some(
            cached
                .entry(key)
                .or_insert_with(|| Arc::clone(&diagnostics))
                .clone(),
        )
    }

    /// Visit parser diagnostics for a deterministic file sequence in
    /// memory-aware parallel batches. Parsing is exact and exhaustive; batch
    /// width changes storage pressure only, never the audited file set.
    pub fn visit_parser_diagnostics_uncached(
        &self,
        files: &[FileId],
        mut visit: impl FnMut(FileId, Option<Arc<[Diagnostic]>>),
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
                .map(|file| (*file, self.parser_diagnostics_uncached(*file)))
                .collect::<Vec<_>>();
            for (file, diagnostics) in batch {
                visit(file, diagnostics);
                visited = visited.saturating_add(1);
            }
        }
        debug_assert_eq!(visited, files.len());
    }

    /// Load the independently decodable import header for one exact source
    /// snapshot. A valid compiler-object generation answers without
    /// decompressing declaration bodies or flow events; a cache miss falls
    /// back to the canonical Tree-sitter compiler object.
    #[must_use]
    pub fn compiler_import_index_uncached(&self, file: FileId) -> Option<ImportIndex> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_imports(&descriptor) {
                Ok(Some(imports)) => return Some(imports),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler import header miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        // Import-only callers do not require declarations or flow bodies.
        // On a sidecar miss, run the owning adapter's exact import pass over
        // the canonical Tree-sitter tree instead of compiling a complete
        // object. This preserves the language frontend contract and keeps
        // package-gated planning lightweight on a cold workspace.
        self.build_import_index_with_diagnostics(file, &self.inner.diagnostics)
    }

    /// Load the independently decodable syntax-target header for one exact
    /// source snapshot. The header is an adapter-IR projection and therefore
    /// cannot introduce matches: it only avoids inflating a body when every
    /// requested target is structurally impossible.
    #[must_use]
    pub fn compiler_syntax_header_uncached(&self, file: FileId) -> Option<CompilerSyntaxHeader> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_syntax(&descriptor) {
                Ok(Some(syntax)) => return Some(syntax),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler syntax header miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        self.compiler_file_object_uncached(file)?
            .declarations
            .as_ref()
            .map(CompilerSyntaxHeader::from_decl_index)
    }

    /// Load exact normalized browse candidates without decompressing the
    /// declaration/flow body or unrelated syntax-target header.
    ///
    /// A missing or damaged persisted projection falls back to the canonical
    /// Tree-sitter object and derives the identical terms. This changes only
    /// storage and scheduling; it cannot admit a candidate that the owning
    /// adapter did not lower.
    #[must_use]
    pub fn compiler_browse_header_uncached(&self, file: FileId) -> Option<CompilerBrowseHeader> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_browse(&descriptor) {
                Ok(Some(browse)) => return Some(browse),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler browse projection miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        let object = self.compiler_file_object_uncached(file)?;
        Some(CompilerBrowseHeader::from_indexes(
            object.declarations.as_ref(),
            object.imports.as_ref(),
        ))
    }

    /// Load exact adapter-lowered call/write attribution for one source file
    /// without decompressing its declaration and flow body.
    ///
    /// The content-addressed payload is a projection of the same compiler IR,
    /// not a heuristic index. A missing or invalid sidecar falls back to one
    /// canonical Tree-sitter lowering and derives the identical projection.
    #[must_use]
    pub fn compiler_attribution_uncached(&self, file: FileId) -> Option<CompilerAttribution> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_attribution(&descriptor) {
                Ok(Some(attribution)) => return Some(attribution),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler attribution miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        self.compiler_file_object_uncached(file)?
            .declarations
            .as_ref()
            .map(CompilerAttribution::from_decl_index)
    }

    /// Load one exact function's adapter attribution frame.
    ///
    /// The persisted path reads a small span directory and one independently
    /// compressed function frame. It never decodes sibling functions or the
    /// full compiler body. Cache damage falls back to the canonical
    /// Tree-sitter object and therefore affects speed only.
    #[must_use]
    pub fn compiler_function_attribution_uncached(
        &self,
        file: FileId,
        declaration_span: Span,
    ) -> Option<CompilerFunctionAttribution> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_attribution_index(&descriptor) {
                Ok(Some(index)) => {
                    match store.load_function_attribution(&descriptor, &index, declaration_span) {
                        Ok(attribution) => return attribution,
                        Err(error) => {
                            self.inner
                                .compiler_object_store_requires_repair
                                .store(true, std::sync::atomic::Ordering::Release);
                            bonsai_diagnostics::debug_log!(
                                "compiler-object",
                                "compiler function attribution miss for {}: {}",
                                descriptor.path,
                                error
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler function attribution miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        self.compiler_file_object_uncached(file)?
            .declarations
            .as_ref()
            .map(CompilerAttribution::from_decl_index)?
            .function_at_span(declaration_span)
            .cloned()
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

        // Scoped query workspaces intentionally do not open the complete
        // compiler-object metadata during their lightweight syntax phase.
        // Once a semantic consumer requests exact bodies, try that immutable
        // generation before compiling a temporary session. `covers` binds
        // every selected stable FileId to its adapter, path, and strong source
        // digest, so a dense/local scoped id or changed file cannot become a
        // false cache hit. This keeps path-filtered security scans on the
        // already-published Tree-sitter IR without making syntax-only commands
        // pay to hydrate unrelated compiler metadata.
        if let Some(root) = self.workspace_root() {
            if let Ok(store) = CompilerObjectStore::open_reusable(&root) {
                if store.covers(&descriptors) {
                    *self.inner.compiler_object_store.write() = Some(Arc::new(store));
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(false, std::sync::atomic::Ordering::Release);
                    return Ok(0);
                }
            }
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
        let mut prepared_entries = Vec::with_capacity(descriptors.len().saturating_mul(4));
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
                let (header_payload_offset, header_persisted_len) = prepared
                    .append(&encoded.header_compressed)
                    .map_err(factstore_io)?;
                debug_assert_eq!(encoded.header_payload_len, header_persisted_len);
                prepared_entries.push(PreparedFactStoreEntry {
                    key: header_key(descriptor.file),
                    body_hash: header_body_hash(descriptor),
                    payload_offset: header_payload_offset,
                    payload_len: encoded.header_payload_len,
                });
                let (attribution_payload_offset, attribution_persisted_len) = prepared
                    .append(&encoded.attribution_compressed)
                    .map_err(factstore_io)?;
                debug_assert_eq!(encoded.attribution_payload_len, attribution_persisted_len);
                prepared_entries.push(PreparedFactStoreEntry {
                    key: attribution_key(descriptor.file),
                    body_hash: attribution_body_hash(descriptor),
                    payload_offset: attribution_payload_offset,
                    payload_len: encoded.attribution_payload_len,
                });
                let (browse_payload_offset, browse_persisted_len) = prepared
                    .append(&encoded.browse_compressed)
                    .map_err(factstore_io)?;
                debug_assert_eq!(encoded.browse_payload_len, browse_persisted_len);
                prepared_entries.push(PreparedFactStoreEntry {
                    key: browse_key(descriptor.file),
                    body_hash: browse_body_hash(descriptor),
                    payload_offset: browse_payload_offset,
                    payload_len: encoded.browse_payload_len,
                });
                files.push(CompilerObjectFileMetadata {
                    file: descriptor.file.raw(),
                    path: descriptor.path.clone(),
                    language: descriptor.language.clone(),
                    source_digest: descriptor.source_digest,
                    source_hash: descriptor.source_hash,
                    payload_digest: encoded.payload_digest,
                    payload_len: encoded.payload_len,
                    header_payload_digest: encoded.header_payload_digest,
                    header_payload_len: encoded.header_payload_len,
                    attribution_payload_digest: encoded.attribution_payload_digest,
                    attribution_payload_len: encoded.attribution_payload_len,
                    browse_payload_digest: encoded.browse_payload_digest,
                    browse_payload_len: encoded.browse_payload_len,
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
        let _entries = writer.finish().map_err(factstore_io)?;
        let file_count = metadata.files.len();
        let store = CompilerObjectStore::open_at(path, temporary_root)?;
        *self.inner.compiler_object_store.write() = Some(Arc::new(store));
        self.inner
            .compiler_object_store_requires_repair
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(file_count)
    }

    /// Cheap exact-generation check used before a complete compiler phase.
    ///
    /// This compares the immutable generation header with the current VFS
    /// snapshot but deliberately does not hash every compressed payload.
    /// Individual object reads still verify their payload digest; a corrupt
    /// hit marks the store for repair and the orchestrator republishes it
    /// after the exact fallback compile completes.
    #[must_use]
    pub fn compiler_object_generation_matches_current_snapshot(&self) -> bool {
        if self
            .inner
            .compiler_object_store_requires_repair
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() else {
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
        store.metadata.generation_digest == generation_digest(&descriptors)
            && store.metadata.files.len() == descriptors.len()
            && store.reader.len() == compiler_object_entry_count(descriptors.len())
            && store.covers(&descriptors)
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
            || store.reader.len() != compiler_object_entry_count(descriptors.len())
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
                    && metadata.source_hash == descriptor.source_hash
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
        let mut declarations = self.build_decl_index_with_diagnostics(descriptor.file, &diagnostics);
        let imports = self.build_import_index_with_diagnostics(descriptor.file, &diagnostics);
        if let (Some(declarations), Some(imports)) = (&mut declarations, &imports) {
            bonsai_lang_api::mark_namespace_call_receivers(declarations, imports);
        }
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
        let _gate = self.inner.compiler_diagnostics_gate.lock();
        if !self.inner.compiler_diagnostics_published.write().insert(key) {
            return;
        }
        if !object.diagnostics.is_empty() {
            self.inner
                .diagnostics
                .write()
                .extend(object.diagnostics.iter().cloned());
        }
    }
}

/// Conventional compiler-object generation path in the external workspace cache.
#[must_use]
pub fn compiler_object_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!(
        "compiler-objects.v{COMPILER_OBJECT_CACHE_VERSION}.factstore"
    ))
}

/// Migrate the last monolithic-header compiler-object generation into the
/// current lazy per-file layout without reparsing source files.
///
/// `fingerprints` must describe the complete current compiler input set.
/// Missing/stale/corrupt legacy data returns an error and callers fall back to
/// the canonical Tree-sitter rebuild. The destination is published atomically
/// by `FactStoreWriter`; a failed migration cannot replace a valid generation.
pub fn migrate_legacy_compiler_object_sidecar_v11_with_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<Option<usize>>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let destination = compiler_object_sidecar_path(workspace_root);
    if destination.exists() {
        return Ok(None);
    }
    let legacy_path = workspace_bonsai_dir(workspace_root).join(format!(
        "compiler-objects.v{LEGACY_COMPILER_OBJECT_CACHE_VERSION}.factstore"
    ));
    if !legacy_path.exists() {
        return Ok(None);
    }
    let reader = FactStoreReader::open_relaxed(&legacy_path).map_err(factstore_io)?;
    if reader.header().table_id != COMPILER_OBJECT_TABLE_ID {
        return Err(invalid_data("legacy compiler-object factstore table mismatch"));
    }
    let hit = reader
        .get(METADATA_KEY)
        .map_err(factstore_io)?
        .ok_or_else(|| invalid_data("legacy compiler-object metadata is missing"))?;
    if hit.body_hash != u64::from(LEGACY_COMPILER_OBJECT_CACHE_VERSION) {
        return Err(invalid_data("legacy compiler-object metadata version mismatch"));
    }
    let legacy: LegacyCompilerObjectMetadataV11 = wire::decode(&hit.payload).map_err(invalid_wire)?;
    if legacy.version != LEGACY_COMPILER_OBJECT_CACHE_VERSION
        || legacy.semantic_fingerprint != legacy_compiler_frontend_semantic_fingerprint_v11()
        || reader.header().pipeline_hash != legacy_metadata_pipeline_hash_v11(&legacy)
        || reader.len() != legacy.files.len().saturating_add(1)
    {
        return Err(invalid_data("legacy compiler-object generation mismatch"));
    }

    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let mut current = fingerprints
        .into_iter()
        .map(|(path, hash)| {
            let path = path.as_ref();
            let relative = path
                .strip_prefix(&canonical_root)
                .or_else(|_| path.strip_prefix(workspace_root))
                .unwrap_or(path);
            (relative.to_string_lossy().replace('\\', "/"), hash)
        })
        .collect::<Vec<_>>();
    current.sort();
    let mut recorded = legacy
        .files
        .iter()
        .map(|file| (file.path.clone(), file.source_hash))
        .collect::<Vec<_>>();
    recorded.sort();
    if current != recorded {
        return Err(invalid_data("legacy compiler-object source fingerprint mismatch"));
    }

    let legacy_generation_digest = legacy.generation_digest;
    let file_count = legacy.files.len();
    let mut prepared = PreparedFactStorePayload::create_near(&destination).map_err(factstore_io)?;
    let mut prepared_entries = Vec::with_capacity(file_count.saturating_mul(4));
    let mut files = Vec::with_capacity(file_count);
    let mut previous_file = None;
    let mut descriptors = Vec::with_capacity(file_count);
    for legacy_file in legacy.files {
        if previous_file.is_some_and(|previous| previous >= legacy_file.file)
            || import_index_digest(legacy_file.imports.as_ref()) != legacy_file.imports_digest
            || compiler_syntax_header_digest(legacy_file.syntax.as_ref()) != legacy_file.syntax_digest
        {
            return Err(invalid_data("legacy compiler-object metadata is not canonical"));
        }
        previous_file = Some(legacy_file.file);
        let file = FileId::new(legacy_file.file);
        let legacy_payload = reader
            .get(legacy_object_key_v11(file))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("legacy compiler-object payload is missing"))?;
        if legacy_payload.body_hash != legacy_object_body_hash_from_digest_v11(legacy_file.source_digest)
            || digest_bytes(&legacy_payload.payload) != legacy_file.payload_digest
            || u32::try_from(legacy_payload.payload.len()).ok() != Some(legacy_file.payload_len)
        {
            return Err(invalid_data("legacy compiler-object payload mismatch"));
        }
        let legacy_decoded = zstd::stream::decode_all(Cursor::new(&legacy_payload.payload))?;
        let legacy_object: CompiledFileObject = wire::decode(&legacy_decoded).map_err(invalid_wire)?;
        if legacy_object.file != file || legacy_object.source_digest != legacy_file.source_digest {
            return Err(invalid_data("legacy compiler-object identity mismatch"));
        }
        let attribution = legacy_object
            .declarations
            .as_ref()
            .map(CompilerAttribution::from_decl_index)
            .unwrap_or_else(|| CompilerAttribution {
                file,
                functions: Vec::new(),
            });
        let browse = CompilerBrowseHeader::from_indexes(
            legacy_object.declarations.as_ref(),
            legacy_object.imports.as_ref(),
        );
        let (payload_offset, payload_len) = prepared.append(&legacy_payload.payload).map_err(factstore_io)?;
        prepared_entries.push(PreparedFactStoreEntry {
            key: object_key(file),
            body_hash: object_body_hash_from_digest(legacy_file.source_digest),
            payload_offset,
            payload_len,
        });

        let header = CompilerObjectHeader {
            imports: legacy_file.imports,
            imports_digest: legacy_file.imports_digest,
            syntax: legacy_file.syntax,
            syntax_digest: legacy_file.syntax_digest,
        };
        let header_encoded = wire::encode_struct_map(&header).map_err(invalid_wire)?;
        let header_compressed =
            zstd::stream::encode_all(Cursor::new(header_encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
        let header_payload_digest = digest_bytes(&header_compressed);
        let header_payload_len = u32::try_from(header_compressed.len())
            .map_err(|_| invalid_data("compiler-object header payload exceeds 4 GiB"))?;
        let (header_payload_offset, persisted_header_len) =
            prepared.append(&header_compressed).map_err(factstore_io)?;
        debug_assert_eq!(header_payload_len, persisted_header_len);
        prepared_entries.push(PreparedFactStoreEntry {
            key: header_key(file),
            body_hash: header_body_hash_from_digest(legacy_file.source_digest),
            payload_offset: header_payload_offset,
            payload_len: header_payload_len,
        });
        let attribution_compressed = encode_compiler_attribution_payload(&attribution)?;
        let attribution_payload_digest = digest_bytes(&attribution_compressed);
        let attribution_payload_len = u32::try_from(attribution_compressed.len())
            .map_err(|_| invalid_data("compiler-object attribution payload exceeds 4 GiB"))?;
        let (attribution_payload_offset, persisted_attribution_len) =
            prepared.append(&attribution_compressed).map_err(factstore_io)?;
        debug_assert_eq!(attribution_payload_len, persisted_attribution_len);
        prepared_entries.push(PreparedFactStoreEntry {
            key: attribution_key(file),
            body_hash: attribution_body_hash_from_digest(legacy_file.source_digest),
            payload_offset: attribution_payload_offset,
            payload_len: attribution_payload_len,
        });
        let browse_encoded = wire::encode_struct_map(&browse).map_err(invalid_wire)?;
        let browse_compressed =
            zstd::stream::encode_all(Cursor::new(browse_encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
        let browse_payload_digest = digest_bytes(&browse_compressed);
        let browse_payload_len = u32::try_from(browse_compressed.len())
            .map_err(|_| invalid_data("compiler-object browse payload exceeds 4 GiB"))?;
        let (browse_payload_offset, persisted_browse_len) =
            prepared.append(&browse_compressed).map_err(factstore_io)?;
        debug_assert_eq!(browse_payload_len, persisted_browse_len);
        prepared_entries.push(PreparedFactStoreEntry {
            key: browse_key(file),
            body_hash: browse_body_hash_from_digest(legacy_file.source_digest),
            payload_offset: browse_payload_offset,
            payload_len: browse_payload_len,
        });
        descriptors.push(SourceDescriptor {
            file,
            path: legacy_file.path.clone(),
            language: legacy_file.language.clone(),
            source_digest: legacy_file.source_digest,
            source_hash: legacy_file.source_hash,
            source_bytes: 0,
            version: 0,
        });
        files.push(CompilerObjectFileMetadata {
            file: legacy_file.file,
            path: legacy_file.path,
            language: legacy_file.language,
            source_digest: legacy_file.source_digest,
            source_hash: legacy_file.source_hash,
            payload_digest: legacy_file.payload_digest,
            payload_len: legacy_file.payload_len,
            header_payload_digest,
            header_payload_len,
            attribution_payload_digest,
            attribution_payload_len,
            browse_payload_digest,
            browse_payload_len,
        });
    }
    if legacy_generation_digest_v11(&descriptors) != legacy_generation_digest {
        return Err(invalid_data("legacy compiler-object generation digest mismatch"));
    }
    let metadata = CompilerObjectMetadata {
        version: COMPILER_OBJECT_CACHE_VERSION,
        semantic_fingerprint: compiler_frontend_semantic_fingerprint(),
        generation_digest: generation_digest(&descriptors),
        files,
    };
    let writer = FactStoreWriter::create_from_prepared(
        &destination,
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
    if entries != compiler_object_entry_count(file_count) {
        return Err(invalid_data("migrated compiler-object entry count mismatch"));
    }
    let migrated = CompilerObjectStore::open_reusable(workspace_root)?;
    if migrated.metadata.files.len() != file_count
        || migrated.reader.len() != compiler_object_entry_count(file_count)
    {
        return Err(invalid_data("migrated compiler-object generation mismatch"));
    }
    Ok(Some(file_count))
}

/// Validate the compiler-object container and semantic ABI without opening a
/// workspace or decoding every file payload. Exact source identity is checked
/// separately by [`AnalyzerDb::compiler_object_sidecar_is_current`] whenever a
/// workspace is available.
pub fn validate_compiler_object_sidecar_layout(workspace_root: &Path) -> std::io::Result<usize> {
    let store = CompilerObjectStore::open_reusable(workspace_root)?;
    if store.reader.len() != compiler_object_entry_count(store.metadata.files.len()) {
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

/// Exhaustively validate a compiler-object generation against the current
/// supported source set without opening a compiler workspace.
///
/// The supplied hashes are the same streaming content fingerprints used by
/// callgraph/linkage cache inspection. Object payloads remain bound to the
/// stronger SHA-256 digest recorded in each immutable object; this projection
/// lets cache orchestration prove that the generation covers exactly the
/// current paths before advertising it as reusable.
pub fn validate_compiler_object_sidecar_file_with_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
    for file in &store.metadata.files {
        store.validate_payload(file)?;
    }
    Ok(store.metadata.files.len())
}

/// Validate compiler-object schema and exact source coverage without hashing
/// every compressed object payload.
///
/// This is the cache-planning contract. Every object payload is still bound
/// to SHA-256 metadata and verified on read; the exhaustive validator above
/// remains available for an explicit integrity audit.
pub fn validate_compiler_object_sidecar_metadata_with_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
    Ok(store.metadata.files.len())
}

/// Return the exact adapter languages recorded by a validated compiler-object
/// generation without decoding any per-file header or declaration body.
///
/// Root-only cache validation uses this compact compiler metadata to recreate
/// capability-dependent semantic fingerprints. It must not guess languages
/// from extensions: ambiguous compiler extensions are resolved from the
/// Tree-sitter parse when the object generation is built.
pub fn compiler_object_languages_with_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<Vec<String>>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
    let mut languages = store
        .metadata
        .files
        .iter()
        .filter_map(|file| file.language.clone())
        .collect::<Vec<_>>();
    languages.sort();
    languages.dedup();
    Ok(languages)
}

fn compiler_object_store_for_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<CompilerObjectStore>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = CompilerObjectStore::open_reusable(workspace_root)?;
    if store.reader.len() != compiler_object_entry_count(store.metadata.files.len()) {
        return Err(invalid_data("compiler-object entry count mismatch"));
    }
    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let mut current = fingerprints
        .into_iter()
        .map(|(path, hash)| {
            let path = path.as_ref();
            let relative = path
                .strip_prefix(&canonical_root)
                .or_else(|_| path.strip_prefix(workspace_root))
                .unwrap_or(path);
            (relative.to_string_lossy().replace('\\', "/"), hash)
        })
        .collect::<Vec<_>>();
    current.sort();
    let mut recorded = store
        .metadata
        .files
        .iter()
        .map(|file| (file.path.clone(), file.source_hash))
        .collect::<Vec<_>>();
    recorded.sort();
    if current != recorded {
        return Err(invalid_data(
            "compiler-object sidecar source fingerprint mismatch",
        ));
    }
    Ok(store)
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
        source_hash: fnv1a_bytes64(snapshot.text.as_bytes()),
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
    let imports = object.imports.clone();
    let imports_digest = import_index_digest(imports.as_ref());
    let syntax = object
        .declarations
        .as_ref()
        .map(CompilerSyntaxHeader::from_decl_index);
    let attribution = object
        .declarations
        .as_ref()
        .map(CompilerAttribution::from_decl_index)
        .unwrap_or_else(|| CompilerAttribution {
            file: descriptor.file,
            functions: Vec::new(),
        });
    let browse = CompilerBrowseHeader::from_indexes(object.declarations.as_ref(), object.imports.as_ref());
    let syntax_digest = compiler_syntax_header_digest(syntax.as_ref());
    let header = CompilerObjectHeader {
        imports,
        imports_digest,
        syntax,
        syntax_digest,
    };
    let encoded = wire::encode_struct_map(&object).map_err(invalid_wire)?;
    let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
    let payload_digest = digest_bytes(&compressed);
    let payload_len =
        u32::try_from(compressed.len()).map_err(|_| invalid_data("compiler-object payload exceeds 4 GiB"))?;
    let header_encoded = wire::encode_struct_map(&header).map_err(invalid_wire)?;
    let header_compressed =
        zstd::stream::encode_all(Cursor::new(header_encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
    let header_payload_digest = digest_bytes(&header_compressed);
    let header_payload_len = u32::try_from(header_compressed.len())
        .map_err(|_| invalid_data("compiler-object header payload exceeds 4 GiB"))?;
    let attribution_compressed = encode_compiler_attribution_payload(&attribution)?;
    let attribution_payload_digest = digest_bytes(&attribution_compressed);
    let attribution_payload_len = u32::try_from(attribution_compressed.len())
        .map_err(|_| invalid_data("compiler-object attribution payload exceeds 4 GiB"))?;
    let browse_encoded = wire::encode_struct_map(&browse).map_err(invalid_wire)?;
    let browse_compressed =
        zstd::stream::encode_all(Cursor::new(browse_encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
    let browse_payload_digest = digest_bytes(&browse_compressed);
    let browse_payload_len = u32::try_from(browse_compressed.len())
        .map_err(|_| invalid_data("compiler-object browse payload exceeds 4 GiB"))?;
    Ok(PreparedCompilerObject {
        compressed,
        payload_digest,
        payload_len,
        header_compressed,
        header_payload_digest,
        header_payload_len,
        attribution_compressed,
        attribution_payload_digest,
        attribution_payload_len,
        browse_compressed,
        browse_payload_digest,
        browse_payload_len,
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
    generation_digest_with_semantic_fingerprint(descriptors, compiler_frontend_semantic_fingerprint())
}

fn legacy_generation_digest_v11(descriptors: &[SourceDescriptor]) -> [u8; 32] {
    generation_digest_with_semantic_fingerprint(
        descriptors,
        legacy_compiler_frontend_semantic_fingerprint_v11(),
    )
}

fn generation_digest_with_semantic_fingerprint(
    descriptors: &[SourceDescriptor],
    semantic_fingerprint: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bonsai-compiler-generation-v1\0");
    hasher.update(semantic_fingerprint.to_le_bytes());
    for descriptor in descriptors {
        hasher.update(descriptor.file.raw().to_le_bytes());
        hasher.update(descriptor.path.as_bytes());
        hasher.update([0]);
        if let Some(language) = &descriptor.language {
            hasher.update(language.as_bytes());
        }
        hasher.update([0]);
        hasher.update(descriptor.source_digest);
        hasher.update(descriptor.source_hash.to_le_bytes());
    }
    hasher.finalize().into()
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn import_index_digest(imports: Option<&ImportIndex>) -> [u8; 32] {
    let encoded = wire::encode_struct_map(&imports).expect("ImportIndex wire encoding is infallible");
    digest_bytes(&encoded)
}

fn compiler_syntax_header_digest(syntax: Option<&CompilerSyntaxHeader>) -> [u8; 32] {
    let encoded = wire::encode_struct_map(&syntax).expect("CompilerSyntaxHeader wire encoding is infallible");
    digest_bytes(&encoded)
}

fn encode_compiler_attribution_payload(attribution: &CompilerAttribution) -> std::io::Result<Vec<u8>> {
    let mut frames = Vec::with_capacity(attribution.functions.len());
    let mut frame_bytes = Vec::new();
    for function in &attribution.functions {
        let encoded = wire::encode_struct_map(function).map_err(invalid_wire)?;
        let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
        let compressed_len = u32::try_from(compressed.len())
            .map_err(|_| invalid_data("compiler-object attribution frame exceeds 4 GiB"))?;
        frames.push(CompilerAttributionFrame {
            declaration_span: function.declaration_span,
            relative_offset: u64::try_from(frame_bytes.len()).unwrap_or(u64::MAX),
            compressed_len,
            compressed_digest: digest_bytes(&compressed),
        });
        frame_bytes.extend_from_slice(&compressed);
    }
    let index = CompilerAttributionIndex {
        file: attribution.file,
        frames,
        frames_payload_offset: 0,
    };
    let index_bytes = wire::encode_struct_map(&index).map_err(invalid_wire)?;
    let index_len = u32::try_from(index_bytes.len())
        .map_err(|_| invalid_data("compiler-object attribution index exceeds 4 GiB"))?;
    let total_len = ATTRIBUTION_PAYLOAD_PREFIX_BYTES
        .checked_add(index_bytes.len())
        .and_then(|len| len.checked_add(frame_bytes.len()))
        .ok_or_else(|| invalid_data("compiler-object attribution payload length overflow"))?;
    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(&ATTRIBUTION_PAYLOAD_MAGIC);
    payload.extend_from_slice(&index_len.to_le_bytes());
    payload.extend_from_slice(&digest_bytes(&index_bytes));
    payload.extend_from_slice(&index_bytes);
    payload.extend_from_slice(&frame_bytes);
    Ok(payload)
}

fn validate_compiler_attribution_index(
    index: &CompilerAttributionIndex,
    metadata: &CompilerObjectFileMetadata,
) -> std::io::Result<()> {
    if index.file.raw() != metadata.file {
        return Err(invalid_data(
            "compiler-object attribution index identity mismatch",
        ));
    }
    let frames_bytes = u64::from(metadata.attribution_payload_len)
        .checked_sub(index.frames_payload_offset)
        .ok_or_else(|| invalid_data("compiler-object attribution frame directory exceeds payload"))?;
    let mut previous_span = None;
    let mut expected_offset = 0_u64;
    for frame in &index.frames {
        let span_key = (
            frame.declaration_span.file.raw(),
            frame.declaration_span.start,
            frame.declaration_span.end,
        );
        if frame.declaration_span.file != index.file
            || previous_span.is_some_and(|previous| previous >= span_key)
            || frame.relative_offset != expected_offset
        {
            return Err(invalid_data("compiler-object attribution index is not canonical"));
        }
        expected_offset = expected_offset
            .checked_add(u64::from(frame.compressed_len))
            .ok_or_else(|| invalid_data("compiler-object attribution frame range overflow"))?;
        if expected_offset > frames_bytes {
            return Err(invalid_data("compiler-object attribution frame exceeds payload"));
        }
        previous_span = Some(span_key);
    }
    if expected_offset != frames_bytes {
        return Err(invalid_data(
            "compiler-object attribution payload has unindexed bytes",
        ));
    }
    Ok(())
}

fn compiler_frontend_semantic_fingerprint() -> u64 {
    let policy = MATCHER_POLICY_FINGERPRINT;
    (policy as u64)
        ^ ((policy >> 64) as u64)
        ^ u64::from(COMPILER_OBJECT_CACHE_VERSION)
        ^ 0x434F_4D50_494C_4552
}

fn legacy_compiler_frontend_semantic_fingerprint_v11() -> u64 {
    let policy = MATCHER_POLICY_FINGERPRINT;
    (policy as u64)
        ^ ((policy >> 64) as u64)
        ^ u64::from(LEGACY_COMPILER_OBJECT_CACHE_VERSION)
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

fn legacy_metadata_pipeline_hash_v11(metadata: &LegacyCompilerObjectMetadataV11) -> u64 {
    u64::from_le_bytes(
        metadata.generation_digest[..8]
            .try_into()
            .expect("fixed SHA-256 prefix"),
    ) ^ metadata.semantic_fingerprint
        ^ u64::from(metadata.version)
}

fn object_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(4).saturating_add(1)
}

fn legacy_object_key_v11(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_add(1)
}

fn header_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(4).saturating_add(2)
}

fn attribution_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(4).saturating_add(3)
}

fn browse_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(4).saturating_add(4)
}

fn compiler_object_entry_count(files: usize) -> usize {
    files.saturating_mul(4).saturating_add(1)
}

fn object_body_hash(descriptor: &SourceDescriptor) -> u64 {
    object_body_hash_from_digest(descriptor.source_digest)
}

fn object_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    u64::from_le_bytes(source_digest[..8].try_into().expect("fixed SHA-256 prefix"))
        ^ compiler_frontend_semantic_fingerprint()
}

fn legacy_object_body_hash_from_digest_v11(source_digest: [u8; 32]) -> u64 {
    u64::from_le_bytes(source_digest[..8].try_into().expect("fixed SHA-256 prefix"))
        ^ legacy_compiler_frontend_semantic_fingerprint_v11()
}

fn header_body_hash(descriptor: &SourceDescriptor) -> u64 {
    header_body_hash_from_digest(descriptor.source_digest)
}

fn header_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4845_4144_4552_5f31
}

fn attribution_body_hash(descriptor: &SourceDescriptor) -> u64 {
    attribution_body_hash_from_digest(descriptor.source_digest)
}

fn attribution_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4154_5452_4942_5f31
}

fn browse_body_hash(descriptor: &SourceDescriptor) -> u64 {
    browse_body_hash_from_digest(descriptor.source_digest)
}

fn browse_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4252_4f57_5345_5f31
}

fn validate_streamed_payload(
    reader: &FactStoreReader,
    key: u64,
    body_hash: u64,
    expected_len: u32,
    expected_digest: [u8; 32],
    label: &'static str,
) -> std::io::Result<()> {
    let mut payload = reader
        .payload_reader(key)
        .map_err(factstore_io)?
        .ok_or_else(|| invalid_data("compiler-object payload is missing"))?;
    if payload.body_hash != body_hash {
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
    if total != u64::from(expected_len) || <[u8; 32]>::from(hasher.finalize()) != expected_digest {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} payload digest mismatch"),
        ));
    }
    Ok(())
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
    fn root_validator_binds_generation_to_exact_source_paths_and_hashes() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.fixture");
        let vfs = Arc::new(Vfs::new());
        vfs.write(source.to_string_lossy().into_owned(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects");

        assert_eq!(
            validate_compiler_object_sidecar_file_with_source_fingerprints(
                root.path(),
                [(&source, fnv1a_bytes64(b"source"))],
            )
            .expect("exact source generation"),
            1
        );
        assert!(
            validate_compiler_object_sidecar_file_with_source_fingerprints(
                root.path(),
                [(&source, fnv1a_bytes64(b"changed"))],
            )
            .is_err(),
            "same path with changed content must reject the generation"
        );
        assert!(
            validate_compiler_object_sidecar_file_with_source_fingerprints(
                root.path(),
                [(root.path().join("src/other.fixture"), fnv1a_bytes64(b"source"))],
            )
            .is_err(),
            "same content under a different module path must reject the generation"
        );
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

    #[test]
    fn compiler_attribution_decodes_without_opening_corrupt_full_body() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.py");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(
            source.to_string_lossy().into_owned(),
            Arc::<str>::from("def route(payload):\n    repo.send(payload)\n    return payload\n"),
        );
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let db = AnalyzerDb::new(Arc::clone(&vfs), registry);
        db.set_workspace_root(root.path().to_path_buf());
        let descriptor = source_descriptor(&db, file).expect("source descriptor");
        let object = db.compile_fresh_file_object(descriptor.clone());
        let expected = object
            .declarations
            .as_ref()
            .map(CompilerAttribution::from_decl_index)
            .expect("python attribution");
        assert_eq!(expected.functions.len(), 1);
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
        let mut body_entry = None;
        for _ in 0..header.index_count {
            let mut entry_bytes = [0_u8; INDEX_ENTRY_SIZE];
            sidecar.read_exact(&mut entry_bytes).expect("read index entry");
            let entry = IndexEntry::from_bytes(&entry_bytes).expect("valid index entry");
            if entry.key == object_key(file) {
                body_entry = Some(entry);
                break;
            }
        }
        let body_entry = body_entry.expect("compiler body entry");
        sidecar
            .seek(SeekFrom::Start(body_entry.payload_offset))
            .expect("seek body payload");
        let mut byte = [0_u8; 1];
        sidecar.read_exact(&mut byte).expect("read body payload");
        byte[0] ^= 0xff;
        sidecar
            .seek(SeekFrom::Start(body_entry.payload_offset))
            .expect("rewind body payload");
        sidecar.write_all(&byte).expect("corrupt body payload");
        sidecar.sync_all().expect("flush corruption");

        let store = CompilerObjectStore::open_reusable(root.path()).expect("open generation metadata");
        assert_eq!(
            store
                .load_attribution(&descriptor)
                .expect("independent attribution payload"),
            Some(expected),
            "attribution lookup must not touch the unrelated full-body payload"
        );
        assert!(
            store.load(&descriptor).is_err(),
            "test must corrupt only the full body"
        );
    }

    #[test]
    fn function_attribution_range_does_not_decode_corrupt_sibling_frame() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.py");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(
            source.to_string_lossy().into_owned(),
            Arc::<str>::from(
                "def first(payload):\n    sink(payload)\n\ndef second(other):\n    sink(other)\n",
            ),
        );
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let db = AnalyzerDb::new(Arc::clone(&vfs), registry);
        db.set_workspace_root(root.path().to_path_buf());
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects");
        let descriptor = source_descriptor(&db, file).expect("source descriptor");
        let original = CompilerObjectStore::open_reusable(root.path()).expect("open store");
        let index = original
            .load_attribution_index(&descriptor)
            .expect("load frame index")
            .expect("frame index");
        let reused_index = original
            .load_attribution_index(&descriptor)
            .expect("reuse frame index")
            .expect("cached frame index");
        assert!(
            Arc::ptr_eq(&index, &reused_index),
            "immutable frame directories should decode once per live compiler generation"
        );
        assert_eq!(index.frames.len(), 2);
        let first_span = index.frames[0].declaration_span;
        let second_span = index.frames[1].declaration_span;

        let path = compiler_object_sidecar_path(root.path());
        let mut sidecar = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open sidecar");
        let mut header_bytes = [0_u8; HEADER_SIZE];
        sidecar.read_exact(&mut header_bytes).expect("read header");
        let header = Header::from_bytes(&header_bytes).expect("valid header");
        sidecar
            .seek(SeekFrom::Start(header.index_offset))
            .expect("seek index");
        let mut attribution_entry = None;
        for _ in 0..header.index_count {
            let mut entry_bytes = [0_u8; INDEX_ENTRY_SIZE];
            sidecar.read_exact(&mut entry_bytes).expect("read index entry");
            let entry = IndexEntry::from_bytes(&entry_bytes).expect("valid index entry");
            if entry.key == attribution_key(file) {
                attribution_entry = Some(entry);
                break;
            }
        }
        let attribution_entry = attribution_entry.expect("attribution entry");
        let corrupt_offset = attribution_entry
            .payload_offset
            .saturating_add(index.frames_payload_offset)
            .saturating_add(index.frames[1].relative_offset);
        sidecar
            .seek(SeekFrom::Start(corrupt_offset))
            .expect("seek second frame");
        let mut byte = [0_u8; 1];
        sidecar.read_exact(&mut byte).expect("read second frame");
        byte[0] ^= 0xff;
        sidecar
            .seek(SeekFrom::Start(corrupt_offset))
            .expect("rewind second frame");
        sidecar.write_all(&byte).expect("corrupt second frame");
        sidecar.sync_all().expect("flush corruption");

        let store = CompilerObjectStore::open_reusable(root.path()).expect("reopen store");
        let index = store
            .load_attribution_index(&descriptor)
            .expect("uncorrupted index")
            .expect("index");
        assert!(store
            .load_function_attribution(&descriptor, &index, first_span)
            .expect("first frame remains independently readable")
            .is_some());
        assert!(
            store
                .load_function_attribution(&descriptor, &index, second_span)
                .is_err(),
            "the selected corrupt sibling must still fail integrity validation"
        );
        assert!(validate_compiler_object_sidecar_layout(root.path()).is_err());
    }

    #[test]
    fn legacy_v11_generation_migrates_without_reparsing() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.fixture");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "source").expect("source file");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(source.to_string_lossy().into_owned(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());
        let descriptor = source_descriptor(&db, file).expect("source descriptor");
        let object = db.compile_fresh_file_object(descriptor.clone());
        let encoded = wire::encode_struct_map(&object).expect("encode legacy object");
        let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)
            .expect("compress legacy object");
        let payload_digest = digest_bytes(&compressed);
        let payload_len = u32::try_from(compressed.len()).expect("legacy payload length");
        let imports = object.imports.clone();
        let syntax = object
            .declarations
            .as_ref()
            .map(CompilerSyntaxHeader::from_decl_index);
        let legacy_metadata = LegacyCompilerObjectMetadataV11 {
            version: LEGACY_COMPILER_OBJECT_CACHE_VERSION,
            semantic_fingerprint: legacy_compiler_frontend_semantic_fingerprint_v11(),
            generation_digest: legacy_generation_digest_v11(std::slice::from_ref(&descriptor)),
            files: vec![LegacyCompilerObjectFileMetadataV11 {
                file: file.raw(),
                path: descriptor.path.clone(),
                language: descriptor.language.clone(),
                source_digest: descriptor.source_digest,
                source_hash: descriptor.source_hash,
                payload_digest,
                payload_len,
                imports: imports.clone(),
                imports_digest: import_index_digest(imports.as_ref()),
                syntax: syntax.clone(),
                syntax_digest: compiler_syntax_header_digest(syntax.as_ref()),
            }],
        };
        let legacy_path = workspace_bonsai_dir(root.path()).join(format!(
            "compiler-objects.v{LEGACY_COMPILER_OBJECT_CACHE_VERSION}.factstore"
        ));
        let mut prepared =
            PreparedFactStorePayload::create_near(&legacy_path).expect("prepare legacy payload");
        let (payload_offset, persisted_len) = prepared.append(&compressed).expect("append legacy object");
        assert_eq!(persisted_len, payload_len);
        let writer = FactStoreWriter::create_from_prepared(
            &legacy_path,
            COMPILER_OBJECT_TABLE_ID,
            legacy_metadata_pipeline_hash_v11(&legacy_metadata),
            prepared,
            vec![PreparedFactStoreEntry {
                key: legacy_object_key_v11(file),
                body_hash: legacy_object_body_hash_from_digest_v11(descriptor.source_digest),
                payload_offset,
                payload_len,
            }],
        )
        .expect("legacy writer");
        writer
            .add_owned(
                METADATA_KEY,
                u64::from(LEGACY_COMPILER_OBJECT_CACHE_VERSION),
                wire::encode_struct_map(&legacy_metadata).expect("encode legacy metadata"),
            )
            .expect("legacy metadata");
        assert_eq!(writer.finish().expect("finish legacy sidecar"), 2);

        assert_eq!(
            migrate_legacy_compiler_object_sidecar_v11_with_source_fingerprints(
                root.path(),
                [(&source, descriptor.source_hash)],
            )
            .expect("migrate legacy generation"),
            Some(1)
        );
        assert_eq!(
            validate_compiler_object_sidecar_file_with_source_fingerprints(
                root.path(),
                [(&source, descriptor.source_hash)],
            )
            .expect("validate migrated generation"),
            1
        );
        let migrated = CompilerObjectStore::open_reusable(root.path()).expect("open migrated store");
        assert_eq!(migrated.reader.len(), 5);
        let replayed = migrated
            .load(&descriptor)
            .expect("load migrated object")
            .expect("migrated object exists");
        assert_eq!(replayed, object);
        assert_eq!(
            migrated.load_imports(&descriptor).expect("load migrated imports"),
            imports
        );
        assert_eq!(
            migrated.load_syntax(&descriptor).expect("load migrated syntax"),
            syntax
        );
        assert_eq!(
            migrated
                .load_browse(&descriptor)
                .expect("load migrated browse projection"),
            Some(CompilerBrowseHeader::from_indexes(
                object.declarations.as_ref(),
                object.imports.as_ref(),
            ))
        );
        assert_eq!(
            migrated
                .load_attribution(&descriptor)
                .expect("load migrated attribution"),
            Some(
                object
                    .declarations
                    .as_ref()
                    .map(CompilerAttribution::from_decl_index)
                    .unwrap_or_else(|| CompilerAttribution {
                        file,
                        functions: Vec::new(),
                    })
            )
        );
    }
}
