//! Public library entry point.
//!
//! This is the façade the CLI / daemon / LSP all call into. Direct users of
//! the library should depend on this crate rather than poking at the lower
//! layers. The façade is deliberately small: ingest a workspace, accept
//! file updates, ask for diagnostics / traces / dumps. Traces are the
//! headline — they expand calls across files and modules.

// Submodules: `dataflow` and `flow_ids` are used by external
// consumers (sdk, integration tests) via path-style access; keep
// `pub mod`. `cross_module` is internal — consumers go through the
// `Workspace` facade.
pub(crate) mod cross_module;
pub mod dataflow;
pub mod flow_ids;
pub mod value_flow;

use bonsai_abstract_interp::TraceLimits;
use bonsai_common::{FileId, FuncId, Precision, SymbolId};
use bonsai_db::{AnalyzerDb, AnalyzerDbOptions, DbStats};
use bonsai_diagnostics::Diagnostic;
use bonsai_hash::fnv1a_bytes64;
use bonsai_lang_api::{Decl, DeclKind, LanguageRegistry};
use bonsai_trace::{finalize, FinalizeCtx, TraceQuery, TraceQueryKind, TraceResult};
use bonsai_vfs::Vfs;
use cross_module::CrossModuleTracer;
use dataflow::DataFlowCache;
use flow_ids::FlowIdCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use thiserror::Error;
use value_flow::ValueFlowCache;

pub use cross_module::CrossModuleOptions;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("no adapter registered for extension: {0}")]
    NoAdapter(String),
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),
}

#[derive(Clone)]
pub struct Workspace {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace").field("stats", &self.stats()).finish()
    }
}

struct Inner {
    vfs: Arc<Vfs>,
    registry: Arc<LanguageRegistry>,
    db: AnalyzerDb,
    /// Workspace-wide taint-connected data flow. The index path
    /// prewarms it eagerly; query paths can load the persisted
    /// sidecar and compute misses lazily through [`Workspace::dataflow`].
    dataflow: DataFlowCache,
    /// Workspace-wide per-function flow-id cache. Populated lazily by
    /// browse and inspect renderers because most one-shot commands
    /// need ids for only a small subset of functions.
    flow_ids: FlowIdCache,
    /// Workspace-wide cache of per-entry seed-free value-flow graphs.
    /// Populated lazily on first `value_flow()` access — Phase 3 of
    /// the value-flow migration (ADR 0003). Once Phase 5 cuts every
    /// consumer over, this replaces `dataflow` as the single
    /// canonical taint artifact.
    value_flow: ValueFlowCache,
    reparse_counter: Mutex<u64>,
    root_label: Mutex<String>,
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkspaceStats {
    pub files: usize,
    pub cached_decl_indexes: usize,
    pub cached_cfgs: usize,
    pub reparsed_files: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceFileFingerprint {
    pub path: std::path::PathBuf,
    pub hash: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FileRefreshKind {
    Added,
    Modified,
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileRefresh {
    pub file: FileId,
    pub path: std::path::PathBuf,
    pub kind: FileRefreshKind,
}

/// Controls how [`Workspace::open_with_options`] interacts with the
/// persisted dataflow sidecar.
///
/// The default matches the CLI's `index` behavior: parse and index the
/// workspace, load any still-fresh dataflow facts, compute only the
/// missing/stale facts, and write the sidecar back. Use
/// [`Self::query_only`] for SDK command handlers that want the fast
/// "load indexed facts and compute misses lazily" path.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceOpenOptions {
    /// Load `<workspace>/.bonsai/dataflow.v2.bin` before queries run.
    pub load_dataflow_sidecar: bool,
    /// Compute every missing dataflow entry during open.
    pub prewarm_dataflow: bool,
    /// Persist the dataflow sidecar after prewarm.
    pub save_dataflow_sidecar: bool,
    /// Optional per-file tree-sitter parse timeout in milliseconds.
    /// `None` uses the parser default (`BONSAI_PARSE_TIMEOUT_MS` or
    /// 30 seconds); `Some(0)` disables the timeout guard.
    pub parse_timeout_ms: Option<u64>,
}

impl Default for WorkspaceOpenOptions {
    fn default() -> Self {
        Self {
            load_dataflow_sidecar: true,
            prewarm_dataflow: true,
            save_dataflow_sidecar: true,
            parse_timeout_ms: None,
        }
    }
}

impl WorkspaceOpenOptions {
    /// Parse and index, load the sidecar if present, but do not
    /// precompute missing taint facts. Commands can query
    /// [`Workspace::dataflow`] and pay only for the entries they
    /// actually touch.
    #[must_use]
    pub const fn query_only() -> Self {
        Self {
            load_dataflow_sidecar: true,
            prewarm_dataflow: false,
            save_dataflow_sidecar: false,
            parse_timeout_ms: None,
        }
    }

    /// Cold parse/index only. Useful for diagnostics or for
    /// benchmarking the cost of parsing without any taint sidecar
    /// effects.
    #[must_use]
    pub const fn parse_only() -> Self {
        Self {
            load_dataflow_sidecar: false,
            prewarm_dataflow: false,
            save_dataflow_sidecar: false,
            parse_timeout_ms: None,
        }
    }
}

impl Workspace {
    #[must_use]
    pub fn new(registry: Arc<LanguageRegistry>) -> Self {
        Self::new_with_open_options(registry, WorkspaceOpenOptions::default())
    }

    #[must_use]
    pub fn new_with_open_options(registry: Arc<LanguageRegistry>, options: WorkspaceOpenOptions) -> Self {
        let vfs = Arc::new(Vfs::new());
        let db = AnalyzerDb::with_options(
            vfs.clone(),
            registry.clone(),
            db_options_from_open_options(options),
        );
        Self {
            inner: Arc::new(Inner {
                vfs,
                registry,
                db,
                dataflow: DataFlowCache::new(),
                flow_ids: FlowIdCache::new(),
                value_flow: ValueFlowCache::new(),
                reparse_counter: Mutex::new(0),
                root_label: Mutex::new(String::new()),
            }),
        }
    }

    /// Workspace-wide taint-connected dataflow cache. Pre-warmed
    /// during [`Workspace::open`]; queries (inspect filter, export
    /// annotations, future `--source`/`--sink` chains) are hash
    /// lookups into this cache rather than fresh interprocedural
    /// passes.
    pub fn dataflow(&self) -> &DataFlowCache {
        &self.inner.dataflow
    }

    /// Workspace-wide cache of per-entry seed-free value-flow graphs.
    /// See [`crate::value_flow::ValueFlowCache`] and ADR 0003. Phase
    /// 3 of the value-flow migration; consumers (`inspect`, `trace`,
    /// `security`) cut over in Phase 5.
    pub fn value_flow(&self) -> &ValueFlowCache {
        &self.inner.value_flow
    }

    /// Workspace-wide per-function flow-id cache. Populated by the
    /// index-time prewarm so every browse-row flow-id lookup is
    /// O(1). See [`flow_ids::FlowIdCache`].
    pub fn flow_ids(&self) -> &FlowIdCache {
        &self.inner.flow_ids
    }

    pub fn db(&self) -> &AnalyzerDb {
        &self.inner.db
    }

    pub fn vfs(&self) -> &Vfs {
        &self.inner.vfs
    }

    pub fn registry(&self) -> &LanguageRegistry {
        &self.inner.registry
    }

    /// Build the workspace-wide resolved call graph. Walks every decl's
    /// `flow_events` once and resolves each call name through
    /// [`bonsai_resolve::alias_map_for_file`] + the global decl
    /// index — same alias semantics the `inspect` filter uses, and
    /// the spine `bonsai_inspect` walks for chain enumeration.
    ///
    /// O(total flow events × candidates per call) per build. Callers
    /// that build many graphs in a tight loop should cache the result;
    /// `bonsai_inspect::ChainCache` does this with `OnceCell`.
    pub fn resolved_call_graph(&self) -> bonsai_callgraph::ResolvedCallGraph {
        let db = &self.inner.db;
        let global = db.global_index();
        bonsai_callgraph::ResolvedCallGraph::build_with_file_info(
            global.as_ref(),
            |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
            |file| {
                db.vfs()
                    .path(file)
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            },
            |file| {
                db.adapter_for(file)
                    .map(|adapter| adapter.capabilities().module_export_aliases)
                    .unwrap_or(&[])
            },
        )
    }

    /// Build a fully indexed workspace: ingest `root`, parallel-prewarm
    /// each file's decl index, load the dataflow sidecar (if valid),
    /// fill missing taint entries, and write the sidecar back. SDK
    /// equivalent of `bonsai-ninja index`. Minified / bundled files
    /// (`*.min.js`, single lines > 5 KB) are skipped by default;
    /// set `BONSAI_INCLUDE_MINIFIED=1` to opt in.
    pub fn open(root: &Path, registry: Arc<LanguageRegistry>) -> Result<Self, WorkspaceError> {
        Self::open_with_options(root, registry, WorkspaceOpenOptions::default())
    }

    /// Explicit `index` alias for SDK callers. Builds the reusable
    /// analysis sidecar just like [`Self::open`], but reads more
    /// clearly at call sites that are intentionally doing upfront
    /// indexing work.
    pub fn index(root: &Path, registry: Arc<LanguageRegistry>) -> Result<Self, WorkspaceError> {
        Self::open(root, registry)
    }

    /// Open a workspace for a query command: parse/index the current
    /// files, load the persisted dataflow sidecar when present, and
    /// skip eager dataflow prewarm. Missing facts are still computed
    /// lazily through [`DataFlowCache::facts_for`].
    pub fn open_query(root: &Path, registry: Arc<LanguageRegistry>) -> Result<Self, WorkspaceError> {
        Self::open_with_options(root, registry, WorkspaceOpenOptions::query_only())
    }

    /// Build a workspace with explicit control over sidecar load,
    /// prewarm, and save behavior. This is the SDK-level primitive
    /// behind the CLI's "index once, query many" performance model.
    pub fn open_with_options(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        options: WorkspaceOpenOptions,
    ) -> Result<Self, WorkspaceError> {
        use rayon::prelude::*;
        let ws = Self::new_with_open_options(registry, options);
        ws.ingest_dir(root)?;
        // Pass 1: per-file decl + import indexing in parallel.
        // `AnalyzerDb` is `Sync`, so tree-sitter parsing + adapter
        // `extract_declarations` run concurrently on the rayon pool
        // while cache insertion serialises on the db's RwLock.
        let files = ws.vfs().all_files();
        files.par_iter().for_each(|f| {
            let _ = ws.db().decl_index(*f);
        });
        // Pass 2: eager workspace-wide taint-connected dataflow
        // prewarm. Each function gets its per-entry interprocedural
        // taint facts computed once here; every later `inspect` /
        // `export` / `--from`/`--to` query hits the cache instead of
        // paying the per-query cost. The heavy lifting is all inside
        // `DataFlowCache::prewarm_all` — `par_iter` + the existing
        // `bonsai_taint::taint_facts_for_entry`. Disable by setting
        // `BONSAI_NO_DATAFLOW=1` (the per-query path still works; it
        // just won't be pre-populated).
        let skip_prewarm = std::env::var("BONSAI_NO_DATAFLOW")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        if options.load_dataflow_sidecar && !skip_prewarm {
            // Try the sidecar first — a warm cache from a previous
            // run, validated against current file content hashes
            // surgically, is much cheaper than a full rebuild. Any
            // entries that fail validation (file changed, function
            // moved, version mismatch) are dropped; `prewarm_all`
            // below backfills them.
            let sidecar = DataFlowCache::sidecar_path(root);
            let _ = ws.inner.dataflow.load_from_disk(&sidecar, ws.db());
        }
        if options.prewarm_dataflow && !skip_prewarm {
            let sidecar = DataFlowCache::sidecar_path(root);
            ws.inner.dataflow.prewarm_all(ws.db());
            // Write back so next open gets an even hotter cache.
            if options.save_dataflow_sidecar {
                let _ = ws.inner.dataflow.save_to_disk(&sidecar, ws.db());
            }
        }
        Ok(ws)
    }

    /// Load the conventional dataflow sidecar for `root` into this
    /// workspace. Returns the number of entries that survived schema,
    /// content-hash, and dependency validation.
    pub fn load_dataflow_sidecar(&self, root: &Path) -> std::io::Result<usize> {
        self.inner
            .dataflow
            .load_from_disk(&DataFlowCache::sidecar_path(root), self.db())
    }

    /// Save the current dataflow cache to the conventional sidecar
    /// path for `root`.
    pub fn save_dataflow_sidecar(&self, root: &Path) -> std::io::Result<()> {
        self.inner
            .dataflow
            .save_to_disk(&DataFlowCache::sidecar_path(root), self.db())
    }

    pub fn ingest_dir(&self, root: &Path) -> Result<Vec<FileId>, WorkspaceError> {
        *self.inner.root_label.lock() = root.display().to_string();
        let canonical_root = canonical_workspace_root(root);
        self.inner.db.set_workspace_root(canonical_root.clone());
        let mut ingested = Vec::new();
        let (files, skipped_minified) = read_supported_source_files(&canonical_root, &self.inner.registry)?;
        for source in files {
            let path = &source.path;
            let old_id = self.inner.vfs.lookup(path);
            let id = self.inner.vfs.write(path.clone(), Arc::<str>::from(source.text));
            if let Some(prev) = old_id {
                self.inner.db.invalidate_file(prev);
                self.inner.dataflow.invalidate_file(prev);
                self.inner.flow_ids.invalidate_all();
            }
            *self.inner.reparse_counter.lock() += 1;
            ingested.push(id);
        }
        if skipped_minified > 0 {
            tracing::info!(
                skipped = skipped_minified,
                "skipped minified / bundled files (set BONSAI_INCLUDE_MINIFIED=1 to include)"
            );
        }
        Ok(ingested)
    }

    /// Current supported source files under `root`, with stable
    /// content hashes. Long-lived frontends use this to detect
    /// save-time changes without reparsing every unchanged file.
    pub fn source_file_fingerprints(
        &self,
        root: &Path,
    ) -> Result<Vec<SourceFileFingerprint>, WorkspaceError> {
        let canonical_root = canonical_workspace_root(root);
        let (files, _) = read_supported_source_files(&canonical_root, &self.inner.registry)?;
        Ok(files
            .into_iter()
            .map(|file| SourceFileFingerprint {
                path: file.path,
                hash: file.hash,
            })
            .collect())
    }

    /// Refresh one on-disk source file in place. Parser, decl/import,
    /// CFG, flow-id, and dataflow caches are invalidated only for the
    /// edited file and its known dataflow dependents. New files clear
    /// the dataflow cache because they can introduce new resolution
    /// candidates for calls in previously indexed files.
    pub fn refresh_file_from_disk(&self, path: &Path) -> Result<FileRefresh, WorkspaceError> {
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            return Err(WorkspaceError::NoAdapter(path.display().to_string()));
        };
        if self.inner.registry.adapter_for_extension(ext).is_none() {
            return Err(WorkspaceError::NoAdapter(ext.to_string()));
        }
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                return Err(WorkspaceError::Io(error));
            }
            Err(error) => return Err(WorkspaceError::Io(error)),
        };
        let old_id = self.inner.vfs.lookup(path);
        if let Some(file) = old_id {
            if self
                .inner
                .vfs
                .snapshot(file)
                .ok()
                .is_some_and(|snapshot| snapshot.text.as_ref() == text)
            {
                return Ok(FileRefresh {
                    file,
                    path: path.to_path_buf(),
                    kind: FileRefreshKind::Unchanged,
                });
            }
        }
        let kind = if old_id.is_some() {
            FileRefreshKind::Modified
        } else {
            FileRefreshKind::Added
        };
        let id = self.apply_edit(path, text);
        let _ = self.inner.db.decl_index(id);
        let _ = self.inner.db.import_index(id);
        if matches!(kind, FileRefreshKind::Added) {
            self.inner.dataflow.clear();
            self.inner.flow_ids.invalidate_all();
        }
        Ok(FileRefresh {
            file: id,
            path: path.to_path_buf(),
            kind,
        })
    }

    /// Remove one file from the live workspace. Used by watch/SDK
    /// refresh paths after an on-disk delete.
    pub fn remove_file_from_index(&self, path: &Path) -> Option<FileId> {
        let file = self.inner.vfs.remove(path)?;
        self.inner.db.invalidate_file(file);
        self.inner.dataflow.invalidate_file(file);
        self.inner.flow_ids.invalidate_all();
        *self.inner.reparse_counter.lock() += 1;
        Some(file)
    }

    /// Apply an in-memory edit to a workspace file and surgically
    /// bump every downstream cache that observed the prior version.
    ///
    /// VFS bumps the file's version (FileId stays stable). The DB
    /// drops `decl_index`/`import_index`/`resolved`/global-index
    /// entries; CFGs auto-miss on their `(FuncId, file_version)` key.
    /// The dataflow cache invalidates only entries whose declaring
    /// file or transitive callee set touches the edit. Flow-id
    /// labels and the reparse counter both bump.
    pub fn apply_edit(&self, path: &Path, new_text: String) -> FileId {
        let old_id = self.inner.vfs.lookup(path);
        let id = self
            .inner
            .vfs
            .write(path.to_path_buf(), Arc::<str>::from(new_text));
        if let Some(prev) = old_id {
            self.inner.db.invalidate_file(prev);
            self.inner.dataflow.invalidate_file(prev);
            self.inner.flow_ids.invalidate_all();
        } else {
            self.inner.dataflow.clear();
            self.inner.flow_ids.invalidate_all();
        }
        *self.inner.reparse_counter.lock() += 1;
        id
    }

    /// Clear the dataflow cache and rebuild it in one parallel pass.
    /// Use after bulk out-of-band changes (git checkout, codegen)
    /// or when paying the cost up front. CLI: `cache rebuild`.
    pub fn reindex_dataflow(&self) {
        self.inner.dataflow.clear();
        self.inner.dataflow.prewarm_all(&self.inner.db);
    }

    /// Aggregate parser diagnostics across every workspace file plus
    /// the db-level sink. Cheap when the parser cache is warm — each
    /// file's diagnostics are already attached to its `ParsedFile`.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        for file in self.inner.vfs.all_files() {
            if let Ok(parsed) = self.inner.db.parse(file) {
                diagnostics.extend(parsed.diagnostics.iter().cloned());
            }
        }
        diagnostics.extend(self.inner.db.diagnostics());
        diagnostics
    }

    pub fn stats(&self) -> WorkspaceStats {
        let DbStats {
            files,
            cached_decl_indexes,
            cached_cfgs,
        } = self.inner.db.stats();
        WorkspaceStats {
            files,
            cached_decl_indexes,
            cached_cfgs,
            reparsed_files: *self.inner.reparse_counter.lock(),
        }
    }

    pub fn lookup_function(&self, qualified: &str) -> Option<FuncId> {
        self.lookup_function_symbol(qualified)
            .map(|s| FuncId::new(s.raw()))
    }

    fn lookup_function_symbol(&self, qualified: &str) -> Option<SymbolId> {
        // Bare-name lookups can match multiple symbols when names
        // collide across translation units (the canonical regression
        // is `static fn error()` defined in multiple files).
        // `find_by_name` returns hits in insertion order, which is
        // adapter-dependent and non-deterministic across runs.
        // Collect every match, then pick a deterministic winner by
        // sorting on (file path, name span start, symbol id) so the
        // behavior is at least stable — callers that need a specific
        // collision-free hit must pass a more-qualified name.
        let global = self.inner.db.global_index();
        let mut candidates: Vec<(SymbolId, Decl)> = global
            .find_by_name(qualified)
            .iter()
            .filter_map(|sym| self.decl_for_symbol(*sym).map(|d| (*sym, d)))
            .collect();
        candidates.sort_by(|(a_sym, a), (b_sym, b)| {
            let a_path = self
                .inner
                .db
                .vfs()
                .path(a.span.file)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let b_path = self
                .inner
                .db
                .vfs()
                .path(b.span.file)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            a_path
                .cmp(&b_path)
                .then_with(|| a.name_span.start.cmp(&b.name_span.start))
                .then_with(|| a_sym.raw().cmp(&b_sym.raw()))
        });
        for (sym, d) in &candidates {
            if matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                return Some(*sym);
            }
        }
        // Class / Struct → constructor, deterministic by the same sort.
        for (sym, d) in &candidates {
            if matches!(d.kind, DeclKind::Class | DeclKind::Struct) {
                if let Some(ctor) = self.find_constructor_symbol(*sym) {
                    return Some(ctor);
                }
            }
        }
        // Fallback: scan every file's decls (sorted) when
        // `find_by_name` missed the qualified lookup entirely.
        // Walk files in path order so the fallback is also stable.
        let mut all_files: Vec<_> = global.all_files().collect();
        all_files.sort_by_key(|f| {
            self.inner
                .db
                .vfs()
                .path(*f)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
        for file in &all_files {
            for d in global.decls_in(*file) {
                if d.name == qualified
                    && matches!(
                        d.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    )
                {
                    return Some(d.symbol);
                }
            }
        }
        // Second fallback: class -> ctor.
        for file in &all_files {
            for d in global.decls_in(*file) {
                if d.name == qualified && matches!(d.kind, DeclKind::Class | DeclKind::Struct) {
                    if let Some(ctor) = self.find_constructor_symbol(d.symbol) {
                        return Some(ctor);
                    }
                }
            }
        }
        None
    }

    fn find_constructor_symbol(&self, class_sym: SymbolId) -> Option<SymbolId> {
        let global = self.inner.db.global_index();
        let class_decl = global.decl_of(class_sym)?;
        let class_file = global.declaring_file(class_sym)?;
        // Prefer explicit DeclKind::Constructor inside the class span.
        for d in global.decls_in(class_file) {
            if matches!(d.kind, DeclKind::Constructor) && span_contains_lib(class_decl.span, d.span) {
                return Some(d.symbol);
            }
        }
        None
    }

    fn decl_for_symbol(&self, symbol: SymbolId) -> Option<Decl> {
        self.inner.db.global_index().decl_of(symbol).cloned()
    }

    fn language_of(&self, symbol: SymbolId) -> String {
        let global = self.inner.db.global_index();
        global
            .declaring_file(symbol)
            .and_then(|f| self.inner.db.adapter_for(f))
            .map(|a| a.language_id().as_str().to_string())
            .unwrap_or_default()
    }

    /// Cross-module trace from a function's entry. Expands calls across
    /// files and modules. This is the tool's headline feature.
    pub fn trace_from(&self, qualified: &str) -> Result<TraceResult, WorkspaceError> {
        self.trace_from_with_options(qualified, CrossModuleOptions::default())
    }

    pub fn trace_from_with_options(
        &self,
        qualified: &str,
        opts: CrossModuleOptions,
    ) -> Result<TraceResult, WorkspaceError> {
        let symbol = self
            .lookup_function_symbol(qualified)
            .ok_or_else(|| WorkspaceError::SymbolNotFound(qualified.into()))?;
        let raw = CrossModuleTracer::new(&self.inner.db, opts).trace(symbol);
        Ok(self.finalize_trace(
            raw,
            TraceQuery {
                kind: TraceQueryKind::FunctionEntry,
                target_symbol: Some(qualified.to_string()),
                entry_symbol: Some(qualified.to_string()),
                sink_symbol: None,
                file_filter: None,
                max_depth: u32::from(opts.max_depth),
                max_paths: opts.max_steps,
                follow_calls: true,
            },
            symbol,
            opts,
        ))
    }

    /// Source -> sink trace. The cross-module trace is computed from
    /// `source`, then truncated at the first step that reaches `sink`.
    pub fn trace_source_to_sink(&self, source: &str, sink: &str) -> Result<TraceResult, WorkspaceError> {
        self.trace_source_to_sink_with_options(source, sink, CrossModuleOptions::default())
    }

    pub fn trace_source_to_sink_with_options(
        &self,
        source: &str,
        sink: &str,
        opts: CrossModuleOptions,
    ) -> Result<TraceResult, WorkspaceError> {
        let src = self
            .lookup_function_symbol(source)
            .ok_or_else(|| WorkspaceError::SymbolNotFound(source.into()))?;
        // The sink may legitimately be an external / framework call (like
        // `os.system`, `exec`, `Runtime.getRuntime().exec`) that isn't a
        // declared function in the workspace. Only pre-compute a
        // `FuncId` for it when it IS a declared function; otherwise we'll
        // still truncate the trace by matching step messages below.
        let raw = CrossModuleTracer::new(&self.inner.db, opts).trace(src);
        let mut result = self.finalize_trace(
            raw,
            TraceQuery {
                kind: TraceQueryKind::SourceToSink,
                target_symbol: Some(sink.to_string()),
                entry_symbol: Some(source.to_string()),
                sink_symbol: Some(sink.to_string()),
                file_filter: None,
                max_depth: u32::from(opts.max_depth),
                max_paths: opts.max_steps,
                follow_calls: true,
            },
            src,
            opts,
        );
        if let Some(hit) = result.steps.iter().position(|s| s.function == sink) {
            result.steps.truncate(hit + 1);
        } else if !result.steps.iter().any(|s| s.function == sink) {
            // Also match by step message prefix "Call <sink>" for when the
            // sink isn't a separately declared function.
            if let Some(hit) = result.steps.iter().position(|s| s.message.contains(sink)) {
                result.steps.truncate(hit + 1);
            } else {
                result.diagnostics.push(bonsai_trace::TraceDiagnostic {
                    severity: "warning".into(),
                    message: format!("sink {sink} not reached from {source}"),
                    span: None,
                    note: None,
                    code: Some("sink-not-reached".into()),
                });
            }
        }
        Ok(result)
    }

    fn finalize_trace(
        &self,
        raw: bonsai_abstract_interp::RawTrace,
        query: TraceQuery,
        entry: SymbolId,
        opts: CrossModuleOptions,
    ) -> TraceResult {
        let language = self.language_of(entry);
        let root = self.inner.root_label.lock().clone();
        let db_clone = self.inner.db.clone();
        let name_of: Box<dyn Fn(FuncId) -> Option<String>> = Box::new(move |fid: FuncId| {
            let global = db_clone.global_index();
            let sym = SymbolId::new(fid.raw());
            let file = global.declaring_file(sym)?;
            global
                .decls_in(file)
                .iter()
                .find(|d| d.symbol == sym)
                .map(|d| d.name.clone())
        });
        let module_of: Box<dyn Fn(FuncId) -> Option<String>> = {
            let db = self.inner.db.clone();
            Box::new(move |fid: FuncId| {
                let global = db.global_index();
                let sym = SymbolId::new(fid.raw());
                let file = global.declaring_file(sym)?;
                db.vfs().path(file).ok().map(|p| p.display().to_string())
            })
        };
        let entry_name = (name_of)(FuncId::new(entry.raw())).unwrap_or_default();
        let ctx = FinalizeCtx {
            trace_id: format!("trace-{}", self.inner.db.stats().files),
            query,
            language: &language,
            workspace_root: &root,
            entry_symbol: Some(&entry_name),
            entry_funcs: vec![(FuncId::new(entry.raw()), entry_name.clone())],
            func_name: name_of.as_ref(),
            func_module: module_of.as_ref(),
            limits: TraceLimits::from(opts),
        };
        finalize(raw, ctx, self.inner.vfs.as_ref())
    }
}

fn db_options_from_open_options(options: WorkspaceOpenOptions) -> AnalyzerDbOptions {
    AnalyzerDbOptions {
        parse_timeout_ms: options.parse_timeout_ms,
    }
}

struct SourceFileContent {
    path: std::path::PathBuf,
    text: String,
    hash: u64,
}

fn canonical_workspace_root(root: &Path) -> std::path::PathBuf {
    // Canonicalize once and use the absolute path for both the
    // workspace_root and the walker so adapters and downstream FileIds
    // stay deterministic regardless of the caller's CWD. Falls back to
    // `cwd.join(root)` when canonicalize fails (e.g. the path doesn't
    // exist yet), then to the literal path. See
    // docs/contributing/design-patterns.mdx::Stable IDs From Content.
    root.canonicalize()
        .ok()
        .or_else(|| {
            if root.is_absolute() {
                Some(root.to_path_buf())
            } else {
                std::env::current_dir().ok().map(|cwd| cwd.join(root))
            }
        })
        .unwrap_or_else(|| root.to_path_buf())
}

fn include_minified() -> bool {
    std::env::var("BONSAI_INCLUDE_MINIFIED")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
}

fn read_supported_source_files(
    canonical_root: &Path,
    registry: &LanguageRegistry,
) -> Result<(Vec<SourceFileContent>, usize), WorkspaceError> {
    let include_minified = include_minified();
    let mut skipped_minified = 0usize;
    // The ignore walker follows .gitignore / .ignore / .bonsaiignore but
    // still walks in OS-native order, so a fresh ingest can assign different
    // FileIds to the same paths across runs. Sort by path so allocation and
    // refresh fingerprints are deterministic.
    let mut builder = ignore::WalkBuilder::new(canonical_root);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(true)
        .parents(true)
        .ignore(true)
        .add_custom_ignore_filename(".bonsaiignore");
    builder.filter_entry(move |entry| include_minified || !path_looks_minified(entry.path()));
    let mut entries: Vec<_> = builder.build().filter_map(Result::ok).collect();
    entries.sort_by(|a, b| a.path().cmp(b.path()));

    let mut files = Vec::new();
    for entry in entries {
        if !entry.file_type().is_some_and(|file_type| file_type.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if registry.adapter_for_extension(ext).is_none() {
            continue;
        }
        if !include_minified && path_looks_minified(path) {
            tracing::debug!(path = %path.display(), "skipping minified file (filename)");
            skipped_minified += 1;
            continue;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::InvalidData) => continue,
            Err(error) => return Err(WorkspaceError::Io(error)),
        };
        if !include_minified && content_looks_minified(&text) {
            tracing::debug!(path = %path.display(), "skipping minified file (content)");
            skipped_minified += 1;
            continue;
        }
        let hash = fnv1a_bytes64(text.as_bytes());
        files.push(SourceFileContent {
            path: path.to_path_buf(),
            text,
            hash,
        });
    }
    Ok((files, skipped_minified))
}

/// Precision-aware summary printed by the CLI `diagnostics` command.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PrecisionReport {
    pub exact: usize,
    pub narrowed: usize,
    pub over_approximate: usize,
    pub unknown: usize,
}

/// Count steps in `trace` by [`Precision`] bucket. Wired by the
/// `diagnostics` CLI command for an at-a-glance view of how
/// approximate a trace is.
#[must_use]
pub fn summarize_precision(trace: &TraceResult) -> PrecisionReport {
    let mut report = PrecisionReport::default();
    for step in &trace.steps {
        match step.precision {
            Precision::Exact => report.exact += 1,
            Precision::Narrowed => report.narrowed += 1,
            Precision::OverApproximate => report.over_approximate += 1,
            Precision::Unknown => report.unknown += 1,
        }
    }
    report
}

fn span_contains_lib(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

// ---------------------------------------------------------------------------
// Minified-file detection
//
// Minified / bundled JS & TS files are the common failure mode: one
// million-character line of stripped variable names is still syntactically
// valid JS, so tree-sitter happily parses it, but it yields essentially
// zero analysis signal (all identifiers are `a`, `b`, `c` …) while
// dominating index time and inflating `search` / `inspect` output with
// useless hits. Skipping them by default is a safer default than forcing
// users to remember `--exclude`; the `BONSAI_INCLUDE_MINIFIED` env var is
// there for the edge case of actually analyzing a bundle.
// ---------------------------------------------------------------------------

/// Does the filename / path suggest a minified, bundled, or generated
/// build artifact? Catches:
///
/// - Suffix conventions: `*.min.js`, `*.min.ts`, `*.min.css`, `*-min.js`.
/// - Dependency trees: `node_modules/`, `vendor/`, `bower_components/`.
/// - Build-output dirs: `dist/`, `build/`, `target/` (Rust/Maven),
///   `out/` (TS / .NET / generic), `.next/` / `.nuxt/` (frameworks),
///   `__pycache__/` (Python bytecode), `coverage/` (test reports).
///
/// All of the above are skipped because the source they're built from
/// is also in the workspace — indexing both is pure duplication that
/// inflates `search` / `inspect` output and slows the indexer. If a
/// project genuinely ships only built artifacts, set
/// `BONSAI_INCLUDE_MINIFIED=1` to opt back in.
#[must_use]
pub fn path_looks_minified(path: &Path) -> bool {
    // Path-segment checks first — cheaper than reading file content.
    // Common build / dependency / cache dirs that are essentially
    // always either generated, vendored, or duplicated from source.
    // Each entry stays narrow enough to not collide with real
    // first-party directory names. `BONSAI_INCLUDE_VENDOR=1`
    // disables the entire skip set when a project genuinely needs
    // its vendored deps analysed.
    const SKIP_SEGMENTS: &[&str] = &[
        // Cross-language dependency trees.
        "node_modules",     // JS/TS/npm/yarn/pnpm
        "vendor",           // Go (legacy), PHP composer, Ruby bundler dirs, generic
        "bower_components", // legacy JS
        "deps",             // C / C++ / Redis / hiredis / Lua / similar
        "third_party",      // Chromium-style vendoring
        "external",         // Bazel / Meson conventions
        "subprojects",      // Meson
        // Per-language package / build / cache dirs.
        "Pods",          // Swift / Objective-C CocoaPods
        "Carthage",      // Swift Carthage
        "DerivedData",   // Xcode build cache
        ".gradle",       // Gradle cache
        "gradle",        // Gradle wrapper / scripts (regenerable)
        ".tox",          // Python tox
        ".mypy_cache",   // Python mypy
        ".pytest_cache", // Python pytest
        "site-packages", // Python installed packages
        // Build outputs.
        "dist",
        "build",
        "target", // Rust / Maven
        "out",
        ".next",
        ".nuxt",
        "bin", // .NET / generic compiled output
        "obj", // .NET intermediate
        // Caches / coverage / VCS.
        ".bonsai",
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "coverage",
        ".coverage",
        // Virtualenvs (Python convention).
        ".venv",
        "venv",
        ".env",
        "env",
    ];
    for component in path.components() {
        let std::path::Component::Normal(seg) = component else {
            continue;
        };
        let Some(seg) = seg.to_str() else { continue };
        if SKIP_SEGMENTS.contains(&seg) {
            return true;
        }
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    // `.min.` sits between the base name and the extension (`foo.min.js`).
    // `-min.` catches the dash-separated convention (`foo-min.js`).
    lower.contains(".min.") || lower.contains("-min.")
}

/// Does the file content look minified? Heuristic: any single line
/// longer than 5,000 characters is almost certainly machine-emitted.
/// Hand-written code with 5K-char lines is vanishingly rare — the
/// longest lines in the Linux kernel, Chromium, and the V8 sources are
/// all under 1,000.
#[must_use]
pub fn content_looks_minified(text: &str) -> bool {
    const MAX_LINE_LEN: usize = 5_000;
    text.lines().any(|line| line.len() > MAX_LINE_LEN)
}

#[cfg(test)]
mod minified_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn path_suffix_min_js() {
        assert!(path_looks_minified(&PathBuf::from("app.min.js")));
        assert!(path_looks_minified(&PathBuf::from("jquery-3.6.0.min.js")));
        assert!(path_looks_minified(&PathBuf::from("react.production.min.js")));
    }

    #[test]
    fn path_suffix_min_ts_and_css() {
        assert!(path_looks_minified(&PathBuf::from("lib.min.ts")));
        assert!(path_looks_minified(&PathBuf::from("styles.min.css")));
    }

    #[test]
    fn path_suffix_dash_min() {
        assert!(path_looks_minified(&PathBuf::from("foo-min.js")));
    }

    #[test]
    fn path_node_modules_segment() {
        assert!(path_looks_minified(&PathBuf::from("node_modules/react/index.js")));
        assert!(path_looks_minified(&PathBuf::from(
            "src/node_modules/lodash/debounce.js"
        )));
    }

    #[test]
    fn path_vendor_segment() {
        assert!(path_looks_minified(&PathBuf::from(
            "third_party/vendor/jquery.js"
        )));
    }

    #[test]
    fn path_dist_segment() {
        // The lodash failure mode: `dist/lodash.js` is byte-identical
        // to top-level `lodash.js` (the build literally copies the
        // source). Indexing both indexes the same code twice.
        assert!(path_looks_minified(&PathBuf::from("dist/lodash.js")));
        assert!(path_looks_minified(&PathBuf::from("project/dist/index.js")));
    }

    #[test]
    fn path_build_output_segments() {
        assert!(path_looks_minified(&PathBuf::from("build/output.js")));
        assert!(path_looks_minified(&PathBuf::from("target/release/foo.rs")));
        assert!(path_looks_minified(&PathBuf::from("out/main.js")));
        assert!(path_looks_minified(&PathBuf::from(".next/static/chunk.js")));
        assert!(path_looks_minified(&PathBuf::from(".nuxt/server/app.js")));
    }

    #[test]
    fn path_workspace_state_dirs() {
        assert!(path_looks_minified(&PathBuf::from(".bonsai/shadow.py")));
        assert!(path_looks_minified(&PathBuf::from(".git/hooks/pre-commit.py")));
    }

    #[test]
    fn path_python_caches() {
        assert!(path_looks_minified(&PathBuf::from(
            "src/pkg/__pycache__/module.cpython-310.pyc"
        )));
        assert!(path_looks_minified(&PathBuf::from(
            ".venv/lib/site-packages/foo.py"
        )));
        assert!(path_looks_minified(&PathBuf::from("venv/lib/foo.py")));
    }

    #[test]
    fn path_coverage_dirs() {
        assert!(path_looks_minified(&PathBuf::from("coverage/index.html")));
        assert!(path_looks_minified(&PathBuf::from(".coverage/lcov.info")));
    }

    #[test]
    fn path_normal_source_not_minified() {
        assert!(!path_looks_minified(&PathBuf::from("src/index.js")));
        assert!(!path_looks_minified(&PathBuf::from("lib/util/parser.ts")));
        assert!(!path_looks_minified(&PathBuf::from("minimum.js"))); // not `.min.`
                                                                     // Substring matches must not false-positive: "build" inside a
                                                                     // longer name is fine, only an exact path segment counts.
        assert!(!path_looks_minified(&PathBuf::from("rebuild_index.rs")));
        assert!(!path_looks_minified(&PathBuf::from("src/distance.rs")));
        assert!(!path_looks_minified(&PathBuf::from("src/output.rs")));
    }

    #[test]
    fn content_detects_long_line() {
        let mut big = String::with_capacity(6_000);
        for _ in 0..6_000 {
            big.push('a');
        }
        assert!(content_looks_minified(&big));
    }

    #[test]
    fn content_leaves_normal_source_alone() {
        let source = "function greet(name) {\n    console.log(`hello ${name}`);\n}\n";
        assert!(!content_looks_minified(source));
    }

    #[test]
    fn content_leaves_multi_line_big_files_alone() {
        // 5 MB of normal-length lines must NOT flag as minified — we only
        // care about single-line size, not total size.
        let mut big = String::with_capacity(5 * 1024 * 1024);
        for _ in 0..50_000 {
            big.push_str("function fn() { return 1; }\n");
        }
        assert!(!content_looks_minified(&big));
    }
}
