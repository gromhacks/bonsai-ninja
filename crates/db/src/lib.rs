//! Incremental query database (spec §18).
//!
//! This is a hand-rolled memoization layer keyed by `(FileId, version)` or
//! `(FuncId, version)` where appropriate. When a file changes, dependent
//! queries drop their cached values. Heavyweight enough to be useful for a
//! single workspace, light enough to avoid pulling in a full query-db
//! framework like `salsa` (which we can swap in later without changing the
//! public API of this crate).

use ahash::{AHashMap, AHashSet};
use bonsai_abstract_interp::{run_entry, RawTrace, TraceLimits};
use bonsai_cfg::{build_cfg_from_flow, Cfg};
use bonsai_common::{FileId, FuncId, SymbolId};
use bonsai_diagnostics::{Diagnostic, DiagnosticSink};
use bonsai_idg::IdgQueryService;
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{AdapterContext, DeclIndex, DynAdapter, ImportIndex, ImportSpec, LanguageRegistry};
use bonsai_parser::{ParseError, ParsedFile, ParserCache, ParserOptions};
use bonsai_trace::{finalize, TraceResult};
use bonsai_vfs::Vfs;
use parking_lot::{Mutex, RwLock};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

mod compiler_object;

pub use compiler_object::{
    compiler_object_languages_with_source_fingerprints, compiler_object_sidecar_path,
    migrate_legacy_compiler_object_sidecar_v11_with_source_fingerprints,
    validate_compiler_object_sidecar_file_with_source_fingerprints, validate_compiler_object_sidecar_layout,
    validate_compiler_object_sidecar_metadata_with_source_fingerprints, CompiledFileObject,
    COMPILER_OBJECT_CACHE_VERSION,
};

type ParserDiagnosticCache = AHashMap<(FileId, u64), Arc<[Diagnostic]>>;

/// Immutable handle shared across threads. Cheap to clone.
#[derive(Clone)]
pub struct AnalyzerDb {
    inner: Arc<DbInner>,
}

impl std::fmt::Debug for AnalyzerDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalyzerDb").finish()
    }
}

impl bonsai_lang_api::TreeProvider for AnalyzerDb {
    fn tree_for_snapshot(
        &self,
        pack_name: &str,
        snapshot: &bonsai_vfs::FileSnapshot,
    ) -> Option<Arc<bonsai_lang_api::SyntaxTree>> {
        let adapter = self.adapter_for(snapshot.file_id)?;
        let path = self.inner.vfs.path(snapshot.file_id).ok()?;
        if adapter.grammar_name_for_path(&path) != pack_name {
            return None;
        }
        self.inner
            .parser
            .parse_snapshot(snapshot, &adapter, &self.inner.vfs)
            .ok()
            .map(|parsed| Arc::clone(&parsed.tree))
    }
}

struct DbInner {
    pub vfs: Arc<Vfs>,
    pub registry: Arc<LanguageRegistry>,
    pub diagnostics: RwLock<DiagnosticSink>,
    parser: ParserCache,
    cache: RwLock<Caches>,
    /// Single-flight guard for the workspace-global syntax index. Rule
    /// matching asks for global facts from parallel file workers; without a
    /// dedicated build guard every racing caller can lower the entire
    /// workspace before the cache's final compare-and-install step.
    global_index_build: Mutex<()>,
    /// Workspace root path. Set by the workspace at open/index time
    /// via `set_workspace_root`. Adapters use this through
    /// `AdapterContext.workspace_root` to derive workspace-relative
    /// module paths (semantic-identity contract).
    workspace_root: RwLock<Option<std::path::PathBuf>>,
    /// Reusable immutable per-file compiler objects from the most recent
    /// compatible workspace generation. Individual entries are validated by
    /// strong content digest, path/module context, language, and frontend ABI
    /// before use; a changed file simply falls through to exact Tree-sitter
    /// lowering while unchanged objects remain reusable.
    compiler_object_store: RwLock<Option<Arc<compiler_object::CompilerObjectStore>>>,
    /// Set when an object in an otherwise current generation fails payload
    /// validation. The active compiler falls back to exact Tree-sitter
    /// lowering; complete workspace orchestration then republishes the
    /// repaired generation instead of paying that fallback forever.
    compiler_object_store_requires_repair: AtomicBool,
    /// Serializes persistent or ephemeral compiler-object generation. File
    /// lowering inside one generation remains memory-aware and parallel; only
    /// publication of the immutable generation is single-flight.
    compiler_object_generation_build: Mutex<()>,
    /// Exact parser diagnostics cached by the current VFS snapshot. Parser
    /// completeness is a syntax concern: it must not force declaration and
    /// flow lowering for every file after a narrowly planned analysis.
    parser_diagnostics: RwLock<ParserDiagnosticCache>,
    /// Snapshots whose exact compiler diagnostics have already been checked
    /// and, when non-empty, published into the process sink. Successful files
    /// with zero diagnostics remain in this coverage set so a completion audit
    /// does not recompile work already performed by a syntax-header phase.
    compiler_diagnostics_published: RwLock<AHashSet<(FileId, [u8; 32])>>,
    /// Serializes the published-version set with replacement of its diagnostic
    /// rows. Without this gate, an edit racing a warm object load could remove
    /// a new diagnostic while leaving its version marked as published.
    compiler_diagnostics_gate: Mutex<()>,
    /// Workspace-wide IDG query service. Seeded by the workspace at
    /// open/index time via [`AnalyzerDb::set_idg_service`]. Consumers
    /// (value-flow, security analysis, browse, dump, export, inspect)
    /// fetch the service via [`AnalyzerDb::idg_service`] and run their
    /// dataflow queries against it. Cleared on file edit because cross-file
    /// edges may have shifted.
    idg_service: RwLock<Option<Arc<IdgQueryService>>>,
    /// Configured IDGs keyed by the canonical transfer-option fingerprint.
    /// Each key owns a `OnceLock`, making graph construction single-flight
    /// without serializing independent semantic configurations behind one
    /// database-wide build lock. Keeping these separate from `idg_service`
    /// prevents query order from reusing a graph built with different edges.
    idg_services_by_semantics: RwLock<AHashMap<u64, Arc<OnceLock<Arc<IdgQueryService>>>>>,
}

#[derive(Default)]
struct Caches {
    /// Grammar selected for an extension-ambiguous source snapshot. The value
    /// is a language id rather than an adapter Arc so registry ownership stays
    /// centralized and cache serialization is never implied.
    adapter_languages: AHashMap<(FileId, u64), bonsai_lang_api::LanguageId>,
    decl_index: AHashMap<(FileId, u64), Arc<DeclIndex>>,
    import_index: AHashMap<(FileId, u64), Arc<ImportIndex>>,
    /// CFGs are keyed on `(FuncId, file_version)` so an in-place edit
    /// to the file owning the function evicts the cached CFG even if
    /// `invalidate_file` was not explicitly called. The version comes
    /// from `vfs.snapshot(decl.span.file).version`; if the file is
    /// missing the CFG is keyed at version 0 (parity with the parser
    /// cache's missing-snapshot behavior).
    cfgs: AHashMap<(FuncId, u64), Arc<Cfg>>,
    /// `func → latest version cached in `cfgs`` so eviction of the
    /// prior `(func, prev_version)` entry on insert is O(1) instead
    /// of an O(total cached CFGs) `retain`.
    cfg_versions: AHashMap<FuncId, u64>,
    global_index: Option<Arc<GlobalIndex>>,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AnalyzerDbOptions {
    /// Optional per-file tree-sitter parse timeout in milliseconds.
    /// `None` uses `BONSAI_PARSE_TIMEOUT_MS`, then the uncapped default;
    /// `Some(0)` explicitly selects uncapped parsing.
    pub parse_timeout_ms: Option<u64>,
}

impl AnalyzerDb {
    /// Build a database wired to `vfs` and `registry` with default options.
    #[must_use]
    pub fn new(vfs: Arc<Vfs>, registry: Arc<LanguageRegistry>) -> Self {
        Self::with_options(vfs, registry, AnalyzerDbOptions::default())
    }

    /// Build a database with explicit options (parse timeout, etc).
    #[must_use]
    pub fn with_options(vfs: Arc<Vfs>, registry: Arc<LanguageRegistry>, options: AnalyzerDbOptions) -> Self {
        Self::with_parser_options(vfs, registry, parser_options_from_db_options(options))
    }

    #[must_use]
    fn with_parser_options(
        vfs: Arc<Vfs>,
        registry: Arc<LanguageRegistry>,
        parser_options: ParserOptions,
    ) -> Self {
        Self {
            inner: Arc::new(DbInner {
                vfs,
                registry,
                diagnostics: RwLock::new(DiagnosticSink::new()),
                parser: ParserCache::with_options(parser_options),
                cache: RwLock::new(Caches::default()),
                global_index_build: Mutex::new(()),
                workspace_root: RwLock::new(None),
                compiler_object_store: RwLock::new(None),
                compiler_object_store_requires_repair: AtomicBool::new(false),
                compiler_object_generation_build: Mutex::new(()),
                parser_diagnostics: RwLock::new(AHashMap::new()),
                compiler_diagnostics_published: RwLock::new(AHashSet::new()),
                compiler_diagnostics_gate: Mutex::new(()),
                idg_service: RwLock::new(None),
                idg_services_by_semantics: RwLock::new(AHashMap::new()),
            }),
        }
    }

    /// Set the workspace root path so adapters can compute
    /// workspace-relative module paths. Called by `Workspace` at
    /// open/index time. No-op when called twice with the same value.
    pub fn set_workspace_root(&self, root: std::path::PathBuf) {
        let store = compiler_object::CompilerObjectStore::open_reusable(&root)
            .ok()
            .map(Arc::new);
        *self.inner.workspace_root.write() = Some(root);
        *self.inner.compiler_object_store.write() = store;
        self.inner
            .compiler_object_store_requires_repair
            .store(false, Ordering::Release);
    }

    /// Set adapter/module context for an intentionally partial query without
    /// opening the complete workspace compiler-object generation.
    ///
    /// A one-file or retrieval-narrowed workspace has its own VFS universe.
    /// Loading the full generation would both allocate metadata for every
    /// unrelated file and risk interpreting its stable full-workspace
    /// `FileId`s inside the scoped universe. Scoped commands lower their
    /// already-selected source files directly through Tree-sitter instead.
    pub fn set_scoped_workspace_root(&self, root: std::path::PathBuf) {
        *self.inner.workspace_root.write() = Some(root);
        *self.inner.compiler_object_store.write() = None;
        self.inner
            .compiler_object_store_requires_repair
            .store(false, Ordering::Release);
    }

    /// Returns the workspace root path if set, or `None` for
    /// workspaces opened without a root (adapter unit tests).
    pub fn workspace_root(&self) -> Option<std::path::PathBuf> {
        self.inner.workspace_root.read().clone()
    }

    /// Seed the workspace-wide IDG query service. Called by
    /// `bonsai_workspace::Workspace` at open / index time once the
    /// global index and resolved call graph are in place. Consumers
    /// then fetch the service via [`Self::idg_service`].
    pub fn set_idg_service(&self, service: Arc<IdgQueryService>) {
        *self.inner.idg_service.write() = Some(service);
    }

    /// Workspace-wide default IDG query service, if seeded. Consumers with
    /// transfer options use the fingerprint-keyed service cache instead;
    /// there is no alternate interprocedural engine.
    pub fn idg_service(&self) -> Option<Arc<IdgQueryService>> {
        self.inner.idg_service.read().clone()
    }

    /// Configured IDG matching one exact transfer-option fingerprint.
    pub fn idg_service_for_semantics(&self, fingerprint: u64) -> Option<Arc<IdgQueryService>> {
        self.inner
            .idg_services_by_semantics
            .read()
            .get(&fingerprint)
            .and_then(|slot| slot.get())
            .cloned()
    }

    /// Return the configured IDG for `fingerprint`, initializing it exactly
    /// once when absent.
    ///
    /// Concurrent callers for the same semantic fingerprint wait for and
    /// share one build. Different fingerprints initialize independently. The
    /// initializer must not recursively request the same fingerprint.
    pub fn get_or_init_idg_service_for_semantics<F>(
        &self,
        fingerprint: u64,
        initialize: F,
    ) -> Arc<IdgQueryService>
    where
        F: FnOnce() -> Arc<IdgQueryService>,
    {
        let slot = self.idg_service_slot(fingerprint);
        slot.get_or_init(initialize).clone()
    }

    /// Cache a configured IDG without replacing the workspace's default
    /// service slot. Returns the established service when another thread won
    /// the race to seed the same semantics.
    pub fn set_idg_service_for_semantics(
        &self,
        fingerprint: u64,
        service: Arc<IdgQueryService>,
    ) -> Arc<IdgQueryService> {
        let slot = self.idg_service_slot(fingerprint);
        slot.get_or_init(|| service).clone()
    }

    fn idg_service_slot(&self, fingerprint: u64) -> Arc<OnceLock<Arc<IdgQueryService>>> {
        self.inner
            .idg_services_by_semantics
            .write()
            .entry(fingerprint)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone()
    }

    /// Drop the cached IDG service. Called by the workspace on file
    /// edit so a stale service cannot poison subsequent queries.
    pub fn invalidate_idg_service(&self) {
        *self.inner.idg_service.write() = None;
        self.inner.idg_services_by_semantics.write().clear();
    }

    /// Underlying VFS handle. Use this when extracting raw file
    /// contents; cached query helpers above the VFS belong on `self`.
    pub fn vfs(&self) -> &Vfs {
        &self.inner.vfs
    }

    /// Bundled language registry — adapters are looked up by file
    /// extension via [`Self::adapter_for`].
    pub fn registry(&self) -> &LanguageRegistry {
        &self.inner.registry
    }

    /// Snapshot of every diagnostic the db has collected so far.
    pub fn diagnostics(&self) -> Vec<bonsai_diagnostics::Diagnostic> {
        self.inner.diagnostics.read().snapshot()
    }

    /// Adapter responsible for `file`.
    ///
    /// Most extensions have one grammar and take the constant-time registry
    /// path. Ambiguous compiler extensions retain every candidate; each grammar
    /// parses the exact snapshot and the tree with the least syntax damage
    /// wins, with registration order as the deterministic tie-breaker. The
    /// result is cached by `(FileId, version)` and invalidated with the file.
    pub fn adapter_for(&self, file: FileId) -> Option<DynAdapter> {
        let snapshot = self.inner.vfs.snapshot(file).ok()?;
        let path = &snapshot.path;
        let ext = path.extension()?.to_str()?;
        let candidates = self.inner.registry.adapters_for_extension(ext);
        match candidates.as_slice() {
            [] => None,
            [only] => Some(only.clone()),
            _ => {
                let key = (file, snapshot.version);
                if let Some(language) = self.inner.cache.read().adapter_languages.get(&key).copied() {
                    return self.inner.registry.adapter(language);
                }

                let mut selected_index = 0usize;
                let mut selected_score = (usize::MAX, usize::MAX);
                for (index, adapter) in candidates.iter().enumerate() {
                    let score = self
                        .inner
                        .parser
                        .parse_snapshot(&snapshot, adapter, &self.inner.vfs)
                        .map_or((usize::MAX, usize::MAX), |parsed| {
                            bonsai_lang_api::syntax_damage_score(&parsed.tree)
                        });
                    if score < selected_score {
                        selected_index = index;
                        selected_score = score;
                    }
                }
                let selected = candidates[selected_index].clone();
                let language = {
                    let mut cache = self.inner.cache.write();
                    *cache
                        .adapter_languages
                        .entry(key)
                        .or_insert_with(|| selected.language_id())
                };
                let selected = self.inner.registry.adapter(language)?;
                for candidate in candidates {
                    if candidate.language_id() != language {
                        self.inner.parser.release(file, &candidate, &self.inner.vfs);
                    }
                }
                Some(selected)
            }
        }
    }

    /// Adapter language ids whose tree-sitter lowering emits every field
    /// projection as a concrete compiler place.
    ///
    /// The IDG uses this capability set to select its compact symbolic
    /// access-path representation. Keeping the inventory on the database
    /// prevents export, security, and taint facades from independently
    /// rebuilding or hard-coding language lists.
    pub fn complete_field_place_languages(&self) -> Vec<String> {
        // This is a frontend capability query, not a declaration query. Using
        // `global_index()` here forced a full Tree-sitter lowering pass merely
        // to validate an IDG sidecar fingerprint and omitted languages whose
        // files happened to contain no declarations.
        let mut languages: Vec<String> = self
            .inner
            .vfs
            .all_files()
            .into_iter()
            .filter_map(|file| self.adapter_for(file))
            .filter(|adapter| adapter.capabilities().field_places_complete)
            .map(|adapter| adapter.language_id().as_str().to_string())
            .collect();
        languages.sort();
        languages.dedup();
        languages
    }

    /// Build an [`AdapterContext`] without a workspace-root binding.
    /// Cheap to call but loses the workspace-relative module-path
    /// resolution; use [`Self::adapter_context_with`] when adapters
    /// need that path.
    pub fn adapter_context(&self) -> AdapterContext<'_> {
        AdapterContext {
            vfs: &self.inner.vfs,
            diagnostics: &self.inner.diagnostics,
            tree_provider: Some(self),
            workspace_root: None,
        }
    }

    /// Build an AdapterContext that includes the workspace root, if
    /// known. Adapters that compute workspace-relative module paths
    /// should consume this via the standard `&AdapterContext` path
    /// (workspace_root is `Some` whenever set_workspace_root was
    /// called).
    pub fn adapter_context_with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&AdapterContext<'_>) -> R,
    {
        let root_guard = self.inner.workspace_root.read();
        let ctx = AdapterContext {
            vfs: &self.inner.vfs,
            diagnostics: &self.inner.diagnostics,
            tree_provider: Some(self),
            workspace_root: root_guard.as_deref(),
        };
        f(&ctx)
    }

    fn adapter_context_with_diagnostics<F, R>(&self, diagnostics: &RwLock<DiagnosticSink>, f: F) -> R
    where
        F: FnOnce(&AdapterContext<'_>) -> R,
    {
        let root_guard = self.inner.workspace_root.read();
        let ctx = AdapterContext {
            vfs: &self.inner.vfs,
            diagnostics,
            tree_provider: Some(self),
            workspace_root: root_guard.as_deref(),
        };
        f(&ctx)
    }

    /// Parse `file` (cached by VFS, file, language, and version inside the
    /// parser cache). Errors when no adapter handles the extension.
    pub fn parse(&self, file: FileId) -> Result<Arc<ParsedFile>, ParseError> {
        let adapter = self.adapter_for(file).ok_or(ParseError::NoAdapter(file))?;
        let snapshot = self.inner.vfs.snapshot(file)?;
        self.inner
            .parser
            .parse_snapshot(&snapshot, &adapter, &self.inner.vfs)
    }

    /// Release the cached Tree-sitter CST for `file` after a compiler phase
    /// has lowered every fact it needs into durable IR.
    ///
    /// This is cache eviction, not an analysis limit: a later syntax query
    /// reparses the exact VFS snapshot. Broad workspace passes use it to keep
    /// resident memory proportional to concurrently lowered files instead of
    /// retaining one concrete syntax tree for the lifetime of the database.
    pub fn release_syntax(&self, file: FileId) {
        if let Some(adapter) = self.adapter_for(file) {
            self.inner.parser.release(file, &adapter, &self.inner.vfs);
        } else {
            // A formerly supported file can lose its adapter after a registry
            // change. Preserve broad invalidation for that exceptional path.
            self.inner.parser.invalidate(file);
        }
    }

    /// Declaration index for `file`, computed once per `(file,
    /// version)` pair. `None` when no adapter handles the file.
    pub fn decl_index(&self, file: FileId) -> Option<Arc<DeclIndex>> {
        let snap = self.inner.vfs.snapshot(file).ok()?;
        let key = (file, snap.version);
        // Drop the read guard's temporary before any subsequent
        // `cache.write()` further down. parking_lot RwLock is
        // non-reentrant; this is the same hazard B1 hit.
        let cached = self.inner.cache.read().decl_index.get(&key).cloned();
        if let Some(v) = cached {
            return Some(v);
        }
        let value = Arc::new(self.build_decl_index_uncached(file)?);
        let mut cache = self.inner.cache.write();
        // Re-check inside the write lock — a concurrent caller may
        // have inserted between our read and the upgrade. Use
        // `Entry::Vacant` so we only nuke `global_index` when WE
        // were the inserter; otherwise a racing peer that just
        // finished building `global_index` over the cached set
        // would have its result silently discarded.
        let stored = cache
            .decl_index
            .entry(key)
            .or_insert_with(|| value.clone())
            .clone();
        // Installing a per-file cache entry for the current VFS
        // version is not a semantic change. `global_index()` may
        // intentionally consume these local entries on large
        // workspaces to reduce peak RSS; a later caller rebuilding
        // one local `DeclIndex` for CFG/debug use must not invalidate
        // the already-correct workspace-global index. Real edits flow
        // through `invalidate_file`, which drops both local and global
        // derived facts for the changed file.
        Some(stored)
    }

    fn build_decl_index_uncached(&self, file: FileId) -> Option<DeclIndex> {
        self.compiler_decl_index_from_store(file)
            .or_else(|| self.build_decl_index_with_diagnostics(file, &self.inner.diagnostics))
    }

    fn build_decl_index_with_diagnostics(
        &self,
        file: FileId,
        diagnostics: &RwLock<DiagnosticSink>,
    ) -> Option<DeclIndex> {
        let adapter = self.adapter_for(file)?;
        Some(self.adapter_context_with_diagnostics(diagnostics, |ctx| {
            let mut index = adapter.extract_declarations(file, ctx);
            let capabilities = adapter.capabilities();
            // Materialize the adapter's language-syntax receiver tokens on
            // each implicit-receiver declaration. Downstream compiler passes
            // consume `Decl::implicit_receiver_names`; they must not carry a
            // separate cross-language spelling inventory. Explicit receiver
            // parameters remain governed solely by `receiver_param_index`.
            for decl in &mut index.defs {
                if !matches!(
                    decl.kind,
                    bonsai_lang_api::DeclKind::Method | bonsai_lang_api::DeclKind::Constructor
                ) {
                    continue;
                }
                let implicit_receivers = if decl.receiver_param_index.is_none() {
                    capabilities.effective_implicit_receiver_tokens()
                } else {
                    &[]
                };
                for receiver in implicit_receivers
                    .iter()
                    .chain(capabilities.effective_super_receiver_tokens().iter())
                {
                    let receiver = receiver.trim();
                    if receiver.is_empty()
                        || receiver.starts_with('<')
                        || decl
                            .implicit_receiver_names
                            .iter()
                            .any(|existing| existing.trim() == receiver)
                    {
                        continue;
                    }
                    decl.implicit_receiver_names.push(receiver.to_string());
                }
            }
            bonsai_lang_api::apply_local_closure_captures(&mut index);
            bonsai_lang_api::apply_constructor_result_type_aliases(&mut index);
            bonsai_lang_api::apply_assign_value_kind(&mut index);
            bonsai_lang_api::apply_assign_call_result_types(&mut index);
            bonsai_lang_api::apply_call_receiver_types_with_language_syntax(
                &mut index,
                capabilities.effective_super_receiver_tokens(),
                capabilities.effective_implicit_receiver_tokens(),
                capabilities.effective_constructor_method_names(),
                capabilities.receiver_type_syntax,
            );
            index.compact_storage();
            index
        }))
    }

    /// Build a declaration index for `file` without storing it in the
    /// process cache. Broad syntax/rule scans use this streaming path
    /// when they only need file-local facts and would otherwise retain
    /// one `DeclIndex` per workspace file.
    pub fn decl_index_uncached(&self, file: FileId) -> Option<DeclIndex> {
        self.compiler_file_object_uncached(file)?.declarations
    }

    /// Populate/reuse the cached declaration IR, then release its phase-local
    /// Tree-sitter CST. Eager compiler frontends use this rather than keeping
    /// both representations resident for every workspace file.
    pub fn decl_index_releasing_syntax(&self, file: FileId) -> Option<Arc<DeclIndex>> {
        let index = self.decl_index(file);
        self.release_syntax(file);
        index
    }

    /// Build and retain both file-local syntax indexes from one canonical
    /// Tree-sitter CST, then release that phase-local CST.
    pub fn syntax_indexes_releasing_cst(
        &self,
        file: FileId,
    ) -> (Option<Arc<DeclIndex>>, Option<Arc<ImportIndex>>) {
        let declarations = self.decl_index(file);
        let imports = self.import_index(file);
        self.release_syntax(file);
        (declarations, imports)
    }

    /// Build declaration and import IR from one canonical Tree-sitter CST
    /// without retaining either index. One-shot workspace compiler passes use
    /// this streaming lifecycle so resident memory tracks active workers, not
    /// project file count.
    pub fn syntax_indexes_uncached(&self, file: FileId) -> (Option<DeclIndex>, Option<ImportIndex>) {
        let Some(object) = self.compiler_file_object_uncached(file) else {
            return (None, None);
        };
        (object.declarations, object.imports)
    }

    /// Import index for `file`, computed once per `(file, version)`.
    /// Most callers should use [`Self::imports_for`] instead. Both surfaces
    /// preserve the adapter's authoritative result, including an empty index.
    pub fn import_index(&self, file: FileId) -> Option<Arc<ImportIndex>> {
        let snap = self.inner.vfs.snapshot(file).ok()?;
        let key = (file, snap.version);
        let cached = self.inner.cache.read().import_index.get(&key).cloned();
        if let Some(v) = cached {
            return Some(v);
        }
        // The compiler-object import header is the adapter's exact
        // Tree-sitter-lowered `ImportIndex`, stored independently from the
        // declaration/flow body. Reuse it here as well as in streaming
        // passes; reparsing source for the cached interactive facade made a
        // warm large-repository query pay a second frontend pass per file.
        let value = Arc::new(self.compiler_import_index_uncached(file)?);
        let mut cache = self.inner.cache.write();
        let stored = cache
            .import_index
            .entry(key)
            .or_insert_with(|| value.clone())
            .clone();
        Some(stored)
    }

    fn build_import_index_with_diagnostics(
        &self,
        file: FileId,
        diagnostics: &RwLock<DiagnosticSink>,
    ) -> Option<ImportIndex> {
        let adapter = self.adapter_for(file)?;
        Some(self.adapter_context_with_diagnostics(diagnostics, |ctx| adapter.extract_imports(file, ctx)))
    }

    /// Build an import index for `file` without storing it in the process
    /// cache. Broad rule scans use this streaming path when import aliases
    /// are only needed while scanning the current file. Reuse the validated
    /// compiler object when available: its imports are the exact output of
    /// the same adapter/Tree-sitter snapshot. Compiler-object generations
    /// expose imports as an independently decodable header, so this path does
    /// not inflate declaration bodies or flow events.
    pub fn import_index_uncached(&self, file: FileId) -> Option<ImportIndex> {
        self.compiler_import_index_uncached(file)
    }

    /// Single source of truth for "the imports of `file`". Reads the
    /// adapter's grammar-aware [`ImportIndex`] (cached on
    /// `(FileId, version)`) when the registered adapter provides one.
    /// An empty adapter index is authoritative: it means the adapter ran
    /// and found no imports. There is intentionally no shared syntax
    /// fallback: import grammar and lowering belong to the concrete adapter.
    ///
    /// Every consumer that needs a file's imports — alias resolution,
    /// browse-imports rendering, taint reachability — should call this
    /// instead of re-implementing the dual-source pattern. Routing
    /// through one method guarantees that adapter-encoded shape (e.g.
    /// kotlin's `import x.y.z as Z` → `module="x.y", original_name="z",
    /// alias="Z"`) is what every downstream pass sees.
    #[must_use]
    pub fn imports_for(&self, file: FileId) -> Vec<ImportSpec> {
        if let Some(idx) = self.import_index(file) {
            let imports = idx.imports.clone();
            drop(idx);
            self.release_syntax(file);
            return imports;
        }
        Vec::new()
    }

    /// Grammar-aware imports for one streaming compiler pass without retaining
    /// a workspace-sized import-index cache. Semantics are identical to
    /// [`Self::imports_for`], including adapter ownership of empty results.
    #[must_use]
    pub fn imports_for_uncached(&self, file: FileId) -> Vec<ImportSpec> {
        if let Some(idx) = self.import_index_uncached(file) {
            let imports = idx.imports;
            return imports;
        }
        Vec::new()
    }

    /// Workspace-wide global declaration index. Built lazily on first
    /// access; invalidated when any per-file decl index is replaced.
    pub fn global_index(&self) -> Arc<GlobalIndex> {
        let cached = self.inner.cache.read().global_index.clone();
        if let Some(v) = cached {
            return v;
        }
        let _build = self.inner.global_index_build.lock();
        let cached = self.inner.cache.read().global_index.clone();
        if let Some(v) = cached {
            return v;
        }
        // A global-index request can originate inside a caller-owned Rayon
        // pool (the security matcher is the canonical example). Building a
        // second pool with `install` from that worker lets Rayon execute more
        // caller-pool jobs while it waits; those jobs then re-enter this
        // single-flight lock and deadlock the owning worker. Isolate the
        // compiler pass on a plain OS thread whenever the caller is already a
        // Rayon worker. The build still uses host-parallel lowering internally.
        let arc = if rayon::current_thread_index().is_some() {
            let db = self.clone();
            match std::thread::spawn(move || db.build_global_index_uncached()).join() {
                Ok(index) => index,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        } else {
            self.build_global_index_uncached()
        };
        let mut cache = self.inner.cache.write();
        cache.global_index = Some(arc.clone());
        arc
    }

    /// Evict the workspace-global lowered declaration cache at a completed
    /// compiler phase boundary.
    ///
    /// This never changes semantic state: existing [`Arc`] readers remain
    /// valid and a later query reconstructs the exact index from the current
    /// VFS snapshots. Semantic prewarm uses this after persisting callgraph /
    /// IDG artifacts so a subsequent per-file phase does not add its working
    /// set to every lowered body in the project.
    pub fn release_global_index(&self) {
        self.inner.cache.write().global_index = None;
    }

    /// Build the compact workspace declaration header table used by
    /// compiler-scale semantic passes.
    ///
    /// The returned index owns stable global symbols and cross-file
    /// declaration/type metadata, but no function flow bodies or browse-only
    /// facts. Callgraph and IDG builders stream exact file bodies through
    /// [`Self::decl_index_remapped_to_headers`] and release them at the next
    /// file/segment boundary; a fresh body comes from Tree-sitter or the exact
    /// content-addressed compiler-object generation.
    #[must_use]
    pub fn build_global_header_index(&self) -> Arc<GlobalIndex> {
        self.build_streaming_global_index(GlobalIndex::insert_header_preprocessed)
    }

    /// Build declaration headers plus compact AST-derived linkage facts used
    /// by streamed IDG stitching. Complete transfer bodies and control trees
    /// are still lowered one file at a time and never accumulated here.
    #[must_use]
    pub fn build_global_linkage_index(&self) -> Arc<GlobalIndex> {
        self.build_streaming_global_index(GlobalIndex::insert_linkage_header_preprocessed)
    }

    fn build_streaming_global_index(&self, insert: fn(&mut GlobalIndex, DeclIndex)) -> Arc<GlobalIndex> {
        let files = self.inner.vfs.all_files();
        let mut global = GlobalIndex::new();
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
        let batches = bonsai_common::compiler_weighted_batches(&source_bytes, global_index_cpu_workers());
        let parallel_width = batches.iter().map(std::ops::Range::len).max().unwrap_or(1);
        if parallel_width <= 1 || files.len() <= 1 {
            for file in files {
                if let Some(index) = self.decl_index_uncached(file) {
                    insert(&mut global, index);
                }
            }
        } else {
            match rayon::ThreadPoolBuilder::new()
                .num_threads(parallel_width)
                .stack_size(global_index_worker_stack_bytes())
                .build()
            {
                Ok(pool) => {
                    for range in batches {
                        let indexes = pool.install(|| {
                            use rayon::prelude::*;
                            files[range]
                                .par_iter()
                                .map(|&file| self.decl_index_uncached(file))
                                .collect::<Vec<_>>()
                        });
                        for index in indexes.into_iter().flatten() {
                            insert(&mut global, index);
                        }
                    }
                }
                Err(_) => {
                    for file in files {
                        if let Some(index) = self.decl_index_uncached(file) {
                            insert(&mut global, index);
                        }
                    }
                }
            }
        }
        global.finalize_semantic_facts();
        Arc::new(global)
    }

    /// Re-lower one file and bind its local symbols to an immutable global
    /// header index. Returns `None` only when no language adapter owns the
    /// file; declaration drift inside one VFS snapshot is a hard invariant
    /// failure enforced by [`GlobalIndex::remap_file_to_existing_symbols`].
    #[must_use]
    pub fn decl_index_remapped_to_headers(&self, headers: &GlobalIndex, file: FileId) -> Option<DeclIndex> {
        self.decl_index_uncached(file)
            .map(|index| self.remap_decl_index_to_headers(headers, index))
    }

    /// Bind an already-lowered file declaration index to immutable global
    /// header symbols without reparsing its source.
    ///
    /// Compiler phases that consume a [`CompiledFileObject`] use this form so
    /// the object's declaration and import IR can serve the complete file
    /// pass. The same declaration-drift invariant as
    /// [`Self::decl_index_remapped_to_headers`] applies.
    #[must_use]
    pub fn remap_decl_index_to_headers(&self, headers: &GlobalIndex, index: DeclIndex) -> DeclIndex {
        headers.remap_file_to_existing_symbols(index)
    }

    fn build_global_index_uncached(&self) -> Arc<GlobalIndex> {
        let files = self.inner.vfs.all_files();
        let consume_decl_index_cache = should_consume_decl_index_cache_for_global();
        let mut gi = GlobalIndex::new();
        if consume_decl_index_cache {
            self.populate_global_index_consuming(&mut gi, &files);
        } else {
            for file in files {
                if let Some(idx) = self.decl_index(file) {
                    gi.insert_preprocessed((*idx).clone());
                }
            }
        }
        gi.finalize_semantic_facts();
        Arc::new(gi)
    }

    fn populate_global_index_consuming(&self, gi: &mut GlobalIndex, files: &[FileId]) {
        let workers = global_index_worker_count();
        self.populate_global_index_consuming_with_workers(gi, files, workers);
    }

    fn populate_global_index_consuming_with_workers(
        &self,
        gi: &mut GlobalIndex,
        files: &[FileId],
        workers: usize,
    ) {
        if workers <= 1 || files.len() <= 1 {
            for &file in files {
                if let Some(idx) = self.take_decl_index_for_global(file) {
                    gi.insert_preprocessed(idx);
                }
            }
            return;
        }
        let chunk_size = (workers * 8).max(16);
        match rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .stack_size(global_index_worker_stack_bytes())
            .build()
        {
            Ok(pool) => {
                for chunk in files.chunks(chunk_size) {
                    let indexes = pool.install(|| {
                        use rayon::prelude::*;
                        chunk
                            .par_iter()
                            .map(|&file| self.take_decl_index_for_global(file))
                            .collect::<Vec<_>>()
                    });
                    for idx in indexes.into_iter().flatten() {
                        gi.insert_preprocessed(idx);
                    }
                }
            }
            Err(_) => {
                for &file in files {
                    if let Some(idx) = self.take_decl_index_for_global(file) {
                        gi.insert_preprocessed(idx);
                    }
                }
            }
        }
    }

    fn take_decl_index_for_global(&self, file: FileId) -> Option<DeclIndex> {
        let snap = self.inner.vfs.snapshot(file).ok()?;
        let key = (file, snap.version);
        // Bind the removed entry before branching. A write guard created in
        // an `if let` scrutinee lives through the entire expression, which
        // would put the expensive parse/lower `else` branch under this
        // exclusive cache lock and serialize the compiler frontend.
        let cached = self.inner.cache.write().decl_index.remove(&key);
        let index = if let Some(cached) = cached {
            Some(unwrap_or_clone_decl_index(cached))
        } else {
            self.build_decl_index_uncached(file)
        };
        self.release_syntax(file);
        index
    }

    /// Build the CFG of a function from its extracted flow events.
    ///
    /// Flow events (`Call` / `Branch` / `Loop` / `Assign` / `Try` / …)
    /// are the working IR for the current engine; [`bonsai_cfg`] derives
    /// a structured basic-block CFG from that tree. An empty CFG is
    /// returned when the function isn't in the global index (e.g. the
    /// caller passed a stale [`FuncId`]) — this is rare and safe:
    /// downstream consumers that walk the CFG will see no blocks and
    /// report unknown precision.
    pub fn cfg(&self, func: FuncId) -> Arc<Cfg> {
        let decl = self.decl_for_func(func);
        let version = decl
            .as_ref()
            .and_then(|d| self.inner.vfs.snapshot(d.span.file).ok())
            .map_or(0, |snap| snap.version);
        let key = (func, version);
        let cached = self.inner.cache.read().cfgs.get(&key).cloned();
        if let Some(v) = cached {
            return v;
        }
        let cfg = decl
            .map(|d| build_cfg_from_flow(&d.name, &d.flow_events))
            .unwrap_or_default();
        let arc = Arc::new(cfg);
        let mut cache = self.inner.cache.write();
        // Monotonic eviction: only displace the cached `(func, *)`
        // when our `version` is strictly newer than the recorded
        // peer version. A slower thread that re-entered for an
        // OLDER snapshot must NOT evict a peer's freshly-installed
        // newer Arc, and must NOT install its own stale Arc on top.
        let recorded = cache.cfg_versions.get(&func).copied();
        match recorded {
            Some(prev) if prev > version => {
                // Slower thread arrived late. Don't insert; return
                // the cached newer entry if present, else our own
                // computed Arc as a fallback (caller sees a
                // version-correct CFG either way because the cache
                // is keyed on `(func, version)`).
                if let Some(existing) = cache.cfgs.get(&(func, prev)).cloned() {
                    return existing;
                }
                return arc;
            }
            Some(prev) if prev < version => {
                cache.cfg_versions.insert(func, version);
                cache.cfgs.remove(&(func, prev));
            }
            Some(_) => {
                // Same version — don't bump the index, just
                // reuse / install at this key below.
            }
            None => {
                cache.cfg_versions.insert(func, version);
            }
        }
        let stored = cache.cfgs.entry(key).or_insert_with(|| arc.clone()).clone();
        stored
    }

    /// Look up the decl for a function. Returns `None` when the
    /// [`FuncId`] doesn't resolve to a decl in the current global
    /// index — typically only happens when callers pass a stale id
    /// after workspace invalidation.
    fn decl_for_func(&self, func: FuncId) -> Option<bonsai_lang_api::Decl> {
        let global = self.global_index();
        let symbol = SymbolId::new(func.raw());
        global.decl_of(symbol).cloned()
    }

    /// Trace a function from its entry using the intraprocedural
    /// interpreter. The workspace façade exposes a richer cross-module
    /// tracer on top of this; this method remains available for tests
    /// and for adapters that just want raw CFG-level traces.
    pub fn trace_function(&self, func: FuncId, limits: TraceLimits) -> TraceResult {
        let cfg = self.cfg(func);
        let raw: RawTrace = run_entry(func, &cfg, limits);
        let name_of: &dyn Fn(FuncId) -> Option<String> = &|_| None;
        let module_of: &dyn Fn(FuncId) -> Option<String> = &|_| None;
        finalize(
            raw,
            bonsai_trace::FinalizeCtx {
                trace_id: String::new(),
                query: bonsai_trace::TraceQuery {
                    kind: bonsai_trace::TraceQueryKind::FunctionEntry,
                    target_symbol: None,
                    entry_symbol: None,
                    sink_symbol: None,
                    file_filter: None,
                    max_depth: u32::from(limits.max_call_depth),
                    max_paths: limits.max_branches,
                    follow_calls: true,
                },
                language: "",
                workspace_root: "",
                entry_symbol: None,
                entry_funcs: vec![(func, String::new())],
                func_name: name_of,
                func_module: module_of,
                limits,
            },
            &self.inner.vfs,
        )
    }

    /// Invalidate everything that depends on a given file. Coarse-grained
    /// but correct; refine as needed.
    pub fn invalidate_file(&self, file: FileId) {
        // Serialize invalidation with the global-index builder. A file edit
        // that lands during construction must invalidate the completed
        // snapshot instead of allowing that snapshot to publish afterward.
        let _build = self.inner.global_index_build.lock();
        self.inner.parser.invalidate(file);
        // Snapshot the GLOBAL FuncIds for `file` from the current
        // `global_index` BEFORE we wipe it. The per-file
        // `decl_index` cache holds LOCAL SymbolIds (0, 1, … per
        // file), and only `GlobalIndex::insert` remaps them to
        // workspace-flat FuncIds. The CFG cache is keyed on the
        // GLOBAL FuncIds, so trimming via local ids would miss
        // entries (or accidentally evict CFGs of a func with the
        // same local index in a different file).
        //
        // Compute the snapshot under the write lock so a peer can't
        // insert a fresh `decl_index(file)` between snapshot and
        // trim and leak that peer's CFGs.
        let mut cache = self.inner.cache.write();
        let funcs_in_file: ahash::AHashSet<FuncId> = cache
            .global_index
            .as_deref()
            .map(|gi| {
                gi.decls_in(file)
                    .iter()
                    .map(|d| FuncId::new(d.symbol.raw()))
                    .collect()
            })
            .unwrap_or_default();
        cache.decl_index.retain(|(f, _), _| *f != file);
        cache.import_index.retain(|(f, _), _| *f != file);
        cache.adapter_languages.retain(|(f, _), _| *f != file);
        self.inner
            .parser_diagnostics
            .write()
            .retain(|(diagnostic_file, _), _| *diagnostic_file != file);
        let _diagnostics_gate = self.inner.compiler_diagnostics_gate.lock();
        self.inner
            .compiler_diagnostics_published
            .write()
            .retain(|(published_file, _)| *published_file != file);
        let mut diagnostics = self.inner.diagnostics.write();
        let retained_diagnostics = diagnostics
            .snapshot()
            .into_iter()
            .filter(|diagnostic| diagnostic.span.file != file);
        *diagnostics = DiagnosticSink::new();
        diagnostics.extend(retained_diagnostics);
        cache.global_index = None;
        // CFGs are keyed on `(FuncId, file_version)` (see `cfg`).
        // For a file EDIT the version naturally bumps and the next
        // `cfg(func)` call misses the stale entry — no global wipe.
        // For a file REMOVAL the version never bumps and the
        // entries would leak; trim only entries for funcs we know
        // belonged to `file`.
        if !funcs_in_file.is_empty() {
            cache.cfgs.retain(|(func, _), _| !funcs_in_file.contains(func));
            cache.cfg_versions.retain(|func, _| !funcs_in_file.contains(func));
        }
    }

    /// Snapshot of cache occupancy. Useful for the SDK / CLI's
    /// `diagnostics` and `stats` commands.
    pub fn stats(&self) -> DbStats {
        let cache = self.inner.cache.read();
        DbStats {
            files: self.inner.vfs.file_count(),
            cached_decl_indexes: cache.decl_index.len(),
            cached_cfgs: cache.cfgs.len(),
        }
    }
}

fn should_consume_decl_index_cache_for_global() -> bool {
    if let Some(keep_cache) = std::env::var("BONSAI_KEEP_DECL_INDEX_CACHE")
        .ok()
        .and_then(|raw| parse_env_bool(&raw))
    {
        return !keep_cache;
    }
    true
}

fn global_index_worker_count() -> usize {
    bonsai_common::compiler_worker_count(global_index_cpu_workers())
}

fn global_index_cpu_workers() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    std::env::var("BONSAI_GLOBAL_INDEX_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .or_else(|| {
            std::env::var("RAYON_NUM_THREADS")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .unwrap_or(available)
        .max(1)
        .min(available)
}

fn global_index_worker_stack_bytes() -> usize {
    std::env::var("BONSAI_GLOBAL_INDEX_STACK_BYTES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|bytes| *bytes >= 1024 * 1024)
        .unwrap_or(64 * 1024 * 1024)
}

fn unwrap_or_clone_decl_index(index: Arc<DeclIndex>) -> DeclIndex {
    Arc::try_unwrap(index).unwrap_or_else(|shared| (*shared).clone())
}

fn parse_env_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parser_options_from_db_options(options: AnalyzerDbOptions) -> ParserOptions {
    match options.parse_timeout_ms {
        Some(0) => ParserOptions::with_parse_timeout(None),
        Some(ms) => ParserOptions::with_parse_timeout(Some(std::time::Duration::from_millis(ms))),
        None => ParserOptions::default(),
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DbStats {
    pub files: usize,
    pub cached_decl_indexes: usize,
    pub cached_cfgs: usize,
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
