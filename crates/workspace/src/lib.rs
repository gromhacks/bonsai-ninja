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
pub(crate) mod cache_fingerprint;
pub mod callgraph_sidecar;
pub mod class_index;
pub(crate) mod cross_module;
pub mod dataflow;
pub mod dataflow_disk;
pub mod decl_name_index;
pub mod decorators;
pub mod enclosing_index;
mod exact_body_cache;
mod factstore_cleanup;
pub mod flow_ids;
pub mod flow_ids_disk;
pub mod flow_query;
mod idg_persistence;
pub mod linkage_sidecar;
pub mod semantic_context;
pub mod taint_index;
pub mod taint_index_disk;
pub mod value_flow;
pub mod value_flow_disk;

use ahash::{AHashMap, AHashSet};
use bonsai_common::{FileId, FuncId, Precision, SymbolId};
use bonsai_db::{AnalyzerDb, AnalyzerDbOptions, DbStats};
use bonsai_diagnostics::Diagnostic;
use bonsai_hash::Hasher as StableHasher;
use bonsai_index::{GlobalIndex, ReceiverAncestry};
use bonsai_lang_api::{Decl, DeclIndex, DeclKind, FlowEvent, LanguageRegistry};
use bonsai_taint::{InterTaintCaches, KindedTokens};
use bonsai_trace::{finalize, FinalizeCtx, TraceQuery, TraceQueryKind, TraceResult};
use bonsai_vfs::Vfs;
use class_index::ClassMemberIndex;
use cross_module::CrossModuleTracer;
use dataflow::DataFlowCache;
use decl_name_index::DeclNameIndex;
use enclosing_index::EnclosingIndex;
use exact_body_cache::{estimated_exact_body_bytes, ExactBodyCache};
use flow_ids::FlowIdCache;
use idg_persistence::IdgSidecarWriteGuard;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use taint_index::TaintGraphIndex;
use thiserror::Error;
use value_flow::ValueFlowCache;

pub use bonsai_db::{
    compiler_object_languages_with_source_fingerprints, compiler_object_sidecar_path,
    migrate_legacy_compiler_object_sidecar_v11_with_source_fingerprints,
    validate_compiler_object_sidecar_file_with_source_fingerprints, validate_compiler_object_sidecar_layout,
    validate_compiler_object_sidecar_metadata_with_source_fingerprints, COMPILER_OBJECT_CACHE_VERSION,
};
pub use cross_module::CrossModuleOptions;
pub use decorators::decl_decorator_names;
pub use semantic_context::{
    WorkspaceContextRoot, WorkspaceContextRootKind, WorkspaceSemanticContext,
    WorkspaceSemanticContextSummary, WorkspaceSourceTransformation, WorkspaceSourceVariant,
    WorkspaceToolchainManifest,
};

#[derive(Clone)]
pub struct SourceReachableCallGraph {
    pub graph: Arc<bonsai_callgraph::ResolvedCallGraph>,
    pub linkage_index: Arc<GlobalIndex>,
    pub files: Vec<FileId>,
    pub funcs: Vec<FuncId>,
    pub reached_targets: usize,
}

/// One exact Tree-sitter-lowered declaration with ownership of its file IR.
///
/// The wrapper keeps the containing [`DeclIndex`] alive while exposing the
/// selected declaration through [`std::ops::Deref`]. Compiler consumers can
/// therefore inspect complete flow events without cloning a function body.
/// The workspace retains only a memory-scheduled hot set of file bodies.
pub struct ExactDecl {
    file_index: Arc<DeclIndex>,
    position: usize,
}

impl std::ops::Deref for ExactDecl {
    type Target = Decl;

    fn deref(&self) -> &Self::Target {
        &self.file_index.defs[self.position]
    }
}

/// Conventional IDG sidecar path in the workspace's external OS cache.
#[must_use]
pub fn idg_sidecar_path(workspace_root: &Path) -> std::path::PathBuf {
    bonsai_idg::workspace::idg_sidecar_path(workspace_root)
}

/// Reclaim lock-proven crash staging files and sidecars from superseded IDG
/// and taint-graph schemas.
///
/// This never removes a current or newer finalized generation and skips any
/// target owned by another writer. It is cache maintenance only: analysis
/// semantics and result coverage are unchanged.
pub fn maintain_persisted_sidecars(workspace_root: &Path) -> std::io::Result<()> {
    let cache_dir = bonsai_common::workspace_bonsai_dir(workspace_root);
    if !cache_dir.is_dir() {
        return Ok(());
    }
    let idg_target = bonsai_idg::workspace::idg_sidecar_path(workspace_root);
    match idg_persistence::maintain_idg_sidecar_cache(&idg_target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }
    match taint_index::maintain_sidecar_cache(workspace_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Validate that an existing workspace IDG sidecar is structurally readable.
pub fn validate_idg_sidecar_file(path: &Path) -> bonsai_idg::IdgResult<usize> {
    bonsai_idg::workspace::IdgWorkspace::validate_sidecar_file(path)
}

/// Validate an IDG's schema and key layout without decoding graph pages.
///
/// This is suitable only after source/dependency/compiler freshness has been
/// established independently.
pub fn validate_idg_sidecar_layout_file(path: &Path) -> bonsai_idg::IdgResult<usize> {
    bonsai_idg::workspace::IdgWorkspace::validate_sidecar_layout_file(path)
}

/// Validate an IDG against exact root-only compiler inputs without parsing or
/// decoding graph pages.
///
/// `complete_field_place_languages` comes from the validated compiler-object
/// language inventory intersected with the active adapter registry's
/// capability declarations. This preserves custom registries and ambiguous
/// extension selection without embedding language names in the graph engine.
pub fn validate_idg_sidecar_layout_with_source_fingerprints<I, P, J, S>(
    path: &Path,
    workspace_root: &Path,
    fingerprints: I,
    complete_field_place_languages: J,
) -> bonsai_idg::IdgResult<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
    J: IntoIterator<Item = S>,
    S: Into<String>,
{
    let content = crate::cache_fingerprint::workspace_content_fingerprint_from_paths(fingerprints);
    let complete_field_place_languages = complete_field_place_languages
        .into_iter()
        .map(Into::into)
        .collect();
    let transfer = bonsai_idg::TransferOptions::compiler_semantics(complete_field_place_languages)
        .semantic_fingerprint();
    let pipeline_hash = idg_pipeline_hash()
        ^ content
        ^ transfer
        ^ u64::from(callgraph_sidecar::CALLGRAPH_CACHE_VERSION).wrapping_mul(0x9E37_79B1_85EB_CA87)
        ^ crate::cache_fingerprint::dependency_metadata_fingerprint(workspace_root);
    bonsai_idg::workspace::IdgWorkspace::validate_sidecar_layout_with_pipeline(path, pipeline_hash)
}

/// Whether the default workspace-wide IDG sidecar is enabled for a workspace
/// with `file_count` supported source files.
///
/// Streaming factstore persistence has no source-file ceiling. The parameter
/// is retained for API compatibility; every complete workspace may reuse its
/// IDG sidecar regardless of scale.
#[must_use]
pub const fn idg_sidecar_enabled_for_file_count(_file_count: usize) -> bool {
    true
}

fn has_summary_output(global: &bonsai_index::GlobalIndex, func: FuncId) -> bool {
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
        return false;
    };
    matches!(decl.kind, DeclKind::Constructor)
        || !decl.receiver_field_writes.is_empty()
        || global
            .linkage_facts(SymbolId::new(func.raw()))
            .is_some_and(|facts| facts.has_summary_output)
        || summary_output_shape(&decl.flow_events)
}

fn target_emission_requires_callee(
    global: &bonsai_index::GlobalIndex,
    scoped_linkage: &AHashMap<SymbolId, bonsai_index::FunctionLinkageFacts>,
    edge: &bonsai_callgraph::CallEdge,
) -> bool {
    let caller = SymbolId::new(edge.from.raw());
    let consumed_or_writeback = scoped_linkage
        .get(&caller)
        .or_else(|| global.linkage_facts(caller))
        .is_some_and(|facts| {
            facts
                .consumed_call_results
                .iter()
                .any(|consumed| spans_overlap(*consumed, edge.span))
                || facts
                    .calls
                    .iter()
                    .any(|call| call.has_writeback_arg && spans_overlap(call.span, edge.span))
        });
    if consumed_or_writeback {
        return true;
    }
    global
        .decl_of(SymbolId::new(edge.to.raw()))
        .is_some_and(|decl| !decl.receiver_field_writes.is_empty())
}

fn summary_output_shape(events: &[FlowEvent]) -> bool {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if value_text
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                    || value_name
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                {
                    return true;
                }
            }
            FlowEvent::Yield { value_text, .. } => {
                if value_text
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if summary_output_shape(then_events) || summary_output_shape(else_events) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if summary_output_shape(body) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if summary_output_shape(body)
                    || summary_output_shape(catch_events)
                    || summary_output_shape(finally_events)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub fn extend_func_set_with_semantic_callback_dispatchers(
    funcs: &mut AHashSet<FuncId>,
    target_funcs: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) {
    extend_func_set_with_semantic_callback_dispatchers_impl(
        funcs,
        target_funcs,
        global,
        max_precision,
        |func| call_graph.callees_of(func).cloned().collect(),
    );
}

fn extend_func_set_with_semantic_callback_dispatchers_in_call_graph(
    funcs: &mut AHashSet<FuncId>,
    target_funcs: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::CallGraph,
    max_precision: Option<Precision>,
) {
    extend_func_set_with_semantic_callback_dispatchers_impl(
        funcs,
        target_funcs,
        global,
        max_precision,
        |func| call_graph.callees(func).cloned().collect(),
    );
}

fn extend_func_set_with_semantic_callback_dispatchers_impl<C>(
    funcs: &mut AHashSet<FuncId>,
    target_funcs: &AHashSet<FuncId>,
    global: &GlobalIndex,
    max_precision: Option<Precision>,
    mut callees_of: C,
) where
    C: FnMut(FuncId) -> Vec<bonsai_callgraph::CallEdge>,
{
    if target_funcs.is_empty() {
        return;
    }
    let mut changed = true;
    while changed {
        changed = false;
        let lineage: Vec<FuncId> = funcs.iter().copied().collect();
        for func in lineage {
            let outgoing = callees_of(func);
            let callback_target_spans: Vec<bonsai_common::Span> = outgoing
                .iter()
                .filter(|edge| {
                    edge.kind == bonsai_callgraph::EdgeKind::Indirect
                        && target_funcs.contains(&edge.to)
                        && max_precision.is_none_or(|max| edge.precision <= max)
                })
                .map(|edge| edge.span)
                .collect();
            if callback_target_spans.is_empty() {
                continue;
            }
            for edge in outgoing {
                if max_precision.is_some_and(|max| edge.precision > max) || funcs.contains(&edge.to) {
                    continue;
                }
                if !call_edge_passes_target_callback(global, edge.from, edge.span, &callback_target_spans) {
                    continue;
                }
                funcs.insert(edge.to);
                changed = true;
            }
        }
    }
}

fn call_edge_passes_target_callback(
    global: &GlobalIndex,
    caller: FuncId,
    call_span: bonsai_common::Span,
    callback_target_spans: &[bonsai_common::Span],
) -> bool {
    let symbol = SymbolId::new(caller.raw());
    if let Some(facts) = global.linkage_facts(symbol) {
        return facts.calls.iter().any(|call| {
            spans_overlap(call.span, call_span)
                && call.arg_spans.iter().any(|arg_span| {
                    callback_target_spans
                        .iter()
                        .any(|target_span| span_contains(*arg_span, *target_span))
                })
        });
    }
    let Some(decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return false;
    };
    call_event_at_span_passes_target_callback(&decl.flow_events, call_span, callback_target_spans)
}

fn call_event_at_span_passes_target_callback(
    events: &[FlowEvent],
    call_span: bonsai_common::Span,
    callback_target_spans: &[bonsai_common::Span],
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if spans_overlap(*span, call_span)
                    && args.iter().any(|arg| {
                        callback_target_spans
                            .iter()
                            .any(|target_span| span_contains(arg.span, *target_span))
                    })
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if call_event_at_span_passes_target_callback(then_events, call_span, callback_target_spans)
                    || call_event_at_span_passes_target_callback(
                        else_events,
                        call_span,
                        callback_target_spans,
                    )
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if call_event_at_span_passes_target_callback(body, call_span, callback_target_spans) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if call_event_at_span_passes_target_callback(body, call_span, callback_target_spans)
                    || call_event_at_span_passes_target_callback(
                        catch_events,
                        call_span,
                        callback_target_spans,
                    )
                    || call_event_at_span_passes_target_callback(
                        finally_events,
                        call_span,
                        callback_target_spans,
                    )
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn spans_overlap(a: bonsai_common::Span, b: bonsai_common::Span) -> bool {
    a.file == b.file && a.start <= b.end && b.start <= a.end
}

fn span_contains(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

pub(crate) fn build_resolved_call_graph_snapshot(db: &AnalyzerDb) -> bonsai_callgraph::ResolvedCallGraph {
    bonsai_taint::build_resolved_call_graph_snapshot(db)
}

pub(crate) fn build_resolved_call_graph_snapshot_for_files(
    db: &AnalyzerDb,
    included_files: &[FileId],
) -> bonsai_callgraph::ResolvedCallGraph {
    bonsai_taint::build_resolved_call_graph_snapshot_for_files(db, included_files)
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("no adapter registered for extension: {0}")]
    NoAdapter(String),
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("symbol is ambiguous: {query} ({count} candidates)")]
    AmbiguousSymbol {
        query: String,
        count: usize,
        candidates: Vec<String>,
    },
    #[error("source path filter is ambiguous: {query} ({count} candidates: {candidates})")]
    AmbiguousSourcePath {
        query: String,
        count: usize,
        candidates: String,
    },
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
    /// Workspace-wide taint-connected data flow. Full-open/prewarm
    /// paths build it eagerly; query paths can load the persisted
    /// sidecar and compute requested semantic facts on demand through
    /// [`Workspace::dataflow`].
    dataflow: DataFlowCache,
    /// Workspace-wide per-function flow-id cache. Populated on demand by
    /// browse and inspect renderers because most one-shot commands
    /// need ids for only a small subset of functions.
    flow_ids: FlowIdCache,
    /// Workspace-wide cache of per-entry seed-free value-flow graphs.
    /// Populated on first `value_flow()` access for SDK/navigation
    /// compatibility. Security and native export query the canonical IDG
    /// directly; this cache is a presentation projection, not another taint
    /// engine or source-seeding path.
    value_flow: ValueFlowCache,
    /// Workspace-wide singleton for reusable taint-support facts (resolver
    /// answers per `(caller_func, call_span)`, alias maps, local bindings, and
    /// compatibility summaries). IDG query surfaces share this instance so
    /// syntax-derived support facts are compiled once per call site. Held in
    /// an `Arc` for the dataflow compatibility cache and cleared on edits via
    /// `InterTaintCaches::clear()`.
    inter_taint: Arc<InterTaintCaches>,
    /// Memoised workspace-wide resolved call graph. The graph is a
    /// pure function of the indexed decls + import maps + adapter
    /// alias rules, so caching it for the lifetime of one CLI
    /// invocation lets `inspect`, `security taint-analysis`, and
    /// `dump callgraph` share the same instance instead of each
    /// rebuilding from scratch. Cleared on file edits.
    resolved_call_graph: parking_lot::RwLock<Option<Arc<bonsai_callgraph::ResolvedCallGraph>>>,
    /// File-partitioned persisted graph reader for scoped semantic queries.
    /// It owns only the compact callable table and mmapped factstore; exact
    /// adjacency partitions are decoded on demand.
    callgraph_query: Mutex<Option<Arc<callgraph_sidecar::CallgraphQueryService>>>,
    /// Complete canonical `(FileId, path, content hash)` input table used to
    /// validate whole-workspace sidecars from a scoped compiler session.
    ///
    /// Full opens derive it from their immutable VFS snapshot. Scoped opens
    /// stream every source hash from disk without retaining unrelated source
    /// text. Callgraph and linkage readers share the resulting compact table
    /// so a command never fingerprints the workspace twice.
    sidecar_source_inputs: Mutex<Option<SidecarSourceInputs>>,
    /// Compact declaration/type/linkage table for the current source snapshot.
    /// This is the compiler's workspace symbol layer: exact file bodies are
    /// lowered beside it and discarded after each consumer finishes. The IDG
    /// owns the same table when present; this slot serves syntax/graph callers
    /// that do not otherwise require an IDG. Cleared on file edits.
    compiler_linkage: parking_lot::RwLock<Option<Arc<GlobalIndex>>>,
    /// Declaration/type-only compiler symbol table used by syntax lookup.
    ///
    /// Targeted semantic sessions take exclusive ownership of this table,
    /// enrich it with demand-projected linkage, and hand that same allocation
    /// to their temporary IDG. This prevents a broad query from retaining one
    /// full linkage index beside a second scoped compiler header.
    compiler_headers: parking_lot::RwLock<Option<Arc<GlobalIndex>>>,
    /// Memory-scheduled hot set of exact lowered file bodies. Broad compiler
    /// phases still stream every file; repeated query/attribution lookups reuse
    /// these immutable bodies until LRU eviction.
    exact_bodies: ExactBodyCache,
    /// Workspace-wide cache of `(source_func, seed_set) →
    /// EntryTaintGraph`. Lifted out of the per-invocation
    /// `build_findings_chain_aware` map so a second
    /// `taint-analysis`/`source-analysis` against the same workspace
    /// (within one CLI process or one SDK session) is a lookup
    /// instead of recomputing the same source-seeded IDG projection.
    taint_index: TaintGraphIndex,
    /// One source/taint scan at a time may own the index's active semantic
    /// configuration and write-through session. The scan's internal IDG work
    /// remains parallel.
    taint_analysis_serial: Mutex<()>,
    /// One workspace IDG compiler build at a time. AnalyzerDb's
    /// fingerprint-keyed OnceLock map deduplicates identical configured
    /// services; this guard also prevents different exact semantic variants
    /// from overlapping their peak allocations on memory-constrained hosts.
    idg_build_serial: Mutex<()>,
    /// Exact compiler-pipeline identity for the current immutable in-memory
    /// source generation and workspace root. Native export deliberately drops
    /// the resident IDG between memory-heavy phases; retaining this small
    /// validation token prevents the reload from rescanning every source and
    /// dependency metadata file. Cleared with all semantic caches on edits.
    idg_pipeline_hash: Mutex<Option<(Option<std::path::PathBuf>, u64)>>,
    /// `(class_sym, method_name) → Vec<FuncId>` and
    /// `class_sym → constructor FuncIds`. Replaces per-resolution
    /// linear scans of `decls_in(class_file)` in resolve.rs and
    /// cross_module.rs.
    class_members: ClassMemberIndex,
    /// Per-file binary-searchable enclosing-decl index. Replaces
    /// per-call linear scans of `decls_in(file)` in inspect/browse
    /// "what decl contains this position?" queries.
    enclosing: EnclosingIndex,
    /// Lowercased decl-name table for `inspect --query <pat>`
    /// `Contains` matches. Built on first inspect query.
    decl_names: DeclNameIndex,
    /// Workspace-wide memo of `name_reachable_through_func_kinded`
    /// per FuncId. browse-export and inspect both walk the same
    /// per-function structural reachability set; without this
    /// cache they recompute it per call.
    reachable_kinded: parking_lot::RwLock<AHashMap<FuncId, Arc<KindedTokens>>>,
    reparse_counter: Mutex<u64>,
    root_label: Mutex<String>,
    /// Workspace root recorded at open time so the on-demand IDG-build
    /// path can persist its versioned sidecar in the external workspace cache
    /// without re-threading the path through every call site.
    /// `None` for tests / synthetic workspaces that open without a
    /// real on-disk root; persistence is skipped silently in that case.
    idg_sidecar_root: Mutex<Option<std::path::PathBuf>>,
    /// True only when this workspace was opened over the complete
    /// supported source set under `workspace_root`. Literal-, path-,
    /// and filter-scoped query workspaces are exact for their scoped
    /// command, but must not publish reusable whole-workspace sidecars
    /// under the shared complete-workspace cache directory.
    complete_workspace_index: Mutex<bool>,
}

type SidecarSourceInputs = Arc<Vec<(u32, String, u64)>>;

#[derive(Copy, Clone, Debug, Default, Serialize)]
pub struct WorkspaceStats {
    pub files: usize,
    pub cached_decl_indexes: usize,
    pub cached_cfgs: usize,
    pub reparsed_files: u64,
    pub semantic_context: WorkspaceSemanticContextSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceFileFingerprint {
    pub path: std::path::PathBuf,
    pub hash: u64,
}

/// Cheap on-disk identity for one supported compiler input.
///
/// Long-lived SDK projects compare these stamps before reading file contents,
/// so an unchanged query pays for directory traversal and metadata only. On
/// Unix, ctime plus device/inode identity also catches same-size rewrites and
/// atomic editor replacements even when a tool preserves mtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceFileStamp {
    pub path: std::path::PathBuf,
    pub len: u64,
    pub modified: Option<std::time::SystemTime>,
    pub change_seconds: i64,
    pub change_nanoseconds: i64,
    pub device: u64,
    pub inode: u64,
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

/// Progress-event surface for `Workspace::open_with_options_and_events`.
/// Callers with a CLI / TUI / IDE attach a callback; pure programmatic
/// consumers pass `|_| {}` and pay nothing.
///
/// This enum is the single source of truth for open-path progress —
/// the SDK re-exports it as `bonsai_sdk::WorkspaceOpenEvent` so its
/// callbacks see the same variants. Earlier the SDK had its own
/// hand-rolled prewarm pipeline that drifted from this one and
/// re-introduced the OWASP single-core cliff every time a new
/// cache landed in `Workspace::open_with_options` but not the SDK.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceOpenEvent {
    IngestStarted,
    IngestFinished {
        files: usize,
    },
    ParseStarted {
        files: usize,
    },
    ParseFileIndexed,
    ParseFinished,
    DataflowPrewarmStarted {
        pending: usize,
    },
    DataflowEntryBuilt,
    DataflowPrewarmFinished,
    ValueFlowPrewarmStarted,
    ValueFlowPrewarmFinished,
    FlowIdsPrewarmStarted,
    FlowIdsPrewarmFinished,
    CacheChecked {
        cache: &'static str,
        status: WorkspaceCacheStatus,
        entries: usize,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceCacheStatus {
    Hit,
    Miss,
    Skipped,
    Error,
}

const fn cache_status_for_entries(entries: usize) -> WorkspaceCacheStatus {
    if entries > 0 {
        WorkspaceCacheStatus::Hit
    } else {
        WorkspaceCacheStatus::Miss
    }
}

/// Controls how [`Workspace::open_with_options`] interacts with the
/// persisted workspace sidecars.
///
/// The workspace-open default is structural query behavior: parse and index the
/// workspace, load still-fresh sidecars, and compute requested semantic
/// facts on demand. High-level `index` commands intentionally use
/// [`Self::parse_only`] unless the caller explicitly requests semantic
/// or dataflow prewarm.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceOpenOptions {
    /// Load the resolved callgraph sidecar before queries run. This is
    /// independent of dataflow: disabling dataflow prewarm must not
    /// accidentally force every query command to rebuild the callgraph.
    #[serde(default = "default_load_callgraph_sidecar")]
    pub load_callgraph_sidecar: bool,
    /// Load the canonical dataflow factstore before queries run.
    pub load_dataflow_sidecar: bool,
    /// Compute every missing dataflow entry during open.
    pub prewarm_dataflow: bool,
    /// Persist the dataflow sidecar after prewarm.
    pub save_dataflow_sidecar: bool,
    /// Load a fresh compatibility value-flow sidecar before queries run.
    pub load_value_flow_sidecar: bool,
    /// Compute every missing compatibility value-flow projection during
    /// open. Semantic security and export queries do not require this cache;
    /// callers must opt in explicitly when they consume the legacy
    /// `ValueFlowGraph` document shape.
    pub prewarm_value_flow: bool,
    /// Persist the value-flow sidecar after prewarm.
    pub save_value_flow_sidecar: bool,
    /// Compute the workspace-wide flow-id cache during open so every
    /// browse-row flow-id lookup is O(1).
    pub prewarm_flow_ids: bool,
    /// Load the workspace-wide IDG factstore during query open when a
    /// fresh sidecar already exists. This is read-only: misses do not
    /// build the IDG unless a later semantic command asks for it.
    #[serde(default = "default_load_idg_sidecar")]
    pub load_idg_sidecar: bool,
    /// Build every per-file declaration index during open. Explicit
    /// index/prewarm commands keep this enabled. Query commands leave
    /// it disabled so large workspaces can ingest file contents and
    /// then build the global syntax graph by consuming each per-file
    /// IR immediately instead of caching all local and global copies.
    pub eager_decl_index: bool,
    /// Retain eager file-local declaration/import IR after the frontend pass.
    /// Long-lived SDK projects keep this enabled. One-shot compiler checks can
    /// stream each completed unit and release it immediately while still
    /// parsing and lowering every supported file.
    #[serde(default = "default_retain_eager_syntax_ir")]
    pub retain_eager_syntax_ir: bool,
    /// Optional per-file tree-sitter parse timeout in milliseconds.
    /// `None` uses `BONSAI_PARSE_TIMEOUT_MS` when set and otherwise
    /// parses to completion; `Some(0)` explicitly selects uncapped parsing.
    pub parse_timeout_ms: Option<u64>,
}

const fn default_load_idg_sidecar() -> bool {
    true
}

const fn default_load_callgraph_sidecar() -> bool {
    true
}

const fn default_retain_eager_syntax_ir() -> bool {
    true
}

impl Default for WorkspaceOpenOptions {
    fn default() -> Self {
        Self::query_only()
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
            load_callgraph_sidecar: true,
            load_dataflow_sidecar: true,
            prewarm_dataflow: false,
            save_dataflow_sidecar: false,
            load_value_flow_sidecar: true,
            prewarm_value_flow: false,
            save_value_flow_sidecar: false,
            prewarm_flow_ids: false,
            load_idg_sidecar: true,
            eager_decl_index: false,
            retain_eager_syntax_ir: false,
            parse_timeout_ms: None,
        }
    }

    /// Ingest the exact workspace snapshot but hydrate no semantic sidecar
    /// until a command asks for that service.
    ///
    /// This is the default lifecycle for one-shot CLI commands. A definitions
    /// query should not mmap an IDG, and a security inventory should not load
    /// the compatibility value-flow cache. Canonical service entrypoints load
    /// or build their independently validated artifact on first use.
    #[must_use]
    pub const fn lazy_query() -> Self {
        Self {
            load_callgraph_sidecar: false,
            load_dataflow_sidecar: false,
            prewarm_dataflow: false,
            save_dataflow_sidecar: false,
            load_value_flow_sidecar: false,
            prewarm_value_flow: false,
            save_value_flow_sidecar: false,
            prewarm_flow_ids: false,
            load_idg_sidecar: false,
            eager_decl_index: false,
            retain_eager_syntax_ir: false,
            parse_timeout_ms: None,
        }
    }

    /// Cold parse/index only. Useful for diagnostics or for
    /// benchmarking the cost of parsing without any taint sidecar
    /// effects.
    #[must_use]
    pub const fn parse_only() -> Self {
        Self {
            load_callgraph_sidecar: false,
            load_dataflow_sidecar: false,
            prewarm_dataflow: false,
            save_dataflow_sidecar: false,
            load_value_flow_sidecar: false,
            prewarm_value_flow: false,
            save_value_flow_sidecar: false,
            prewarm_flow_ids: false,
            load_idg_sidecar: false,
            eager_decl_index: true,
            retain_eager_syntax_ir: true,
            parse_timeout_ms: None,
        }
    }

    /// Parse and lower every supported file, but release each file-local IR
    /// after the compiler has validated it. This is the one-shot `index`
    /// lifecycle: facts are complete, uncapped, and AST-derived, but are not
    /// retained by a process that will only print statistics and exit.
    #[must_use]
    pub const fn streaming_parse_only() -> Self {
        Self {
            retain_eager_syntax_ir: false,
            ..Self::parse_only()
        }
    }

    /// Ingest source snapshots for content-addressed sidecar validation
    /// without parsing or hydrating any semantic artifact. A frontend can use
    /// this cheap probe to decide whether it needs a cold compiler prewarm.
    #[must_use]
    pub const fn sidecar_validation_only() -> Self {
        Self {
            load_callgraph_sidecar: false,
            load_dataflow_sidecar: false,
            prewarm_dataflow: false,
            save_dataflow_sidecar: false,
            load_value_flow_sidecar: false,
            prewarm_value_flow: false,
            save_value_flow_sidecar: false,
            prewarm_flow_ids: false,
            load_idg_sidecar: false,
            eager_decl_index: false,
            retain_eager_syntax_ir: false,
            parse_timeout_ms: None,
        }
    }

    /// Explicit full-prewarm mode. Parses and indexes the workspace,
    /// loads still-fresh sidecars, computes reusable dataflow/flow-id entries,
    /// and persists the canonical workspace IDG.
    ///
    /// The legacy per-entry `ValueFlowGraph` projection is intentionally
    /// on-demand: eagerly projecting every callable performs one IDG closure
    /// per function and is quadratic-scale work on large repositories. The
    /// IDG itself is the reusable semantic artifact used by security/export.
    /// This is intentionally not the generic workspace-open default; high-level
    /// index facades opt into it to implement "index once, query many times".
    #[must_use]
    pub const fn full_prewarm() -> Self {
        Self {
            load_callgraph_sidecar: true,
            load_dataflow_sidecar: true,
            prewarm_dataflow: true,
            save_dataflow_sidecar: true,
            load_value_flow_sidecar: true,
            prewarm_value_flow: false,
            save_value_flow_sidecar: false,
            prewarm_flow_ids: true,
            load_idg_sidecar: true,
            eager_decl_index: true,
            retain_eager_syntax_ir: true,
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
                inter_taint: Arc::new(InterTaintCaches::default()),
                resolved_call_graph: parking_lot::RwLock::new(None),
                callgraph_query: Mutex::new(None),
                sidecar_source_inputs: Mutex::new(None),
                compiler_linkage: parking_lot::RwLock::new(None),
                compiler_headers: parking_lot::RwLock::new(None),
                exact_bodies: ExactBodyCache::default(),
                taint_index: TaintGraphIndex::new(),
                taint_analysis_serial: Mutex::new(()),
                idg_build_serial: Mutex::new(()),
                idg_pipeline_hash: Mutex::new(None),
                class_members: ClassMemberIndex::new(),
                enclosing: EnclosingIndex::new(),
                decl_names: DeclNameIndex::new(),
                reachable_kinded: parking_lot::RwLock::new(AHashMap::new()),
                reparse_counter: Mutex::new(0),
                root_label: Mutex::new(String::new()),
                idg_sidecar_root: Mutex::new(None),
                complete_workspace_index: Mutex::new(false),
            }),
        }
    }

    /// Workspace-wide taint-connected dataflow cache. Explicit
    /// full-prewarm opens populate it up front; scoped queries compute
    /// requested semantic facts on demand and then reuse them through
    /// this cache.
    pub fn dataflow(&self) -> &DataFlowCache {
        &self.inner.dataflow
    }

    /// Workspace-wide cache of per-entry seed-free value-flow graphs.
    /// See [`crate::value_flow::ValueFlowCache`]. This is a compatibility
    /// projection for SDK/navigation consumers; security and native export
    /// query the canonical IDG directly.
    pub fn value_flow(&self) -> &ValueFlowCache {
        &self.inner.value_flow
    }

    /// Workspace-wide per-function flow-id cache. Populated by the
    /// explicit full-open prewarm so every browse-row flow-id lookup
    /// is O(1). See [`flow_ids::FlowIdCache`].
    pub fn flow_ids(&self) -> &FlowIdCache {
        &self.inner.flow_ids
    }

    /// Workspace-wide singleton `InterTaintCaches`. Sharing one
    /// instance across security/value-flow/inspect runs lets the
    /// resolver memo, file alias maps, and function summaries
    /// survive between commands. Each consumer borrows by reference;
    /// the caches are interior-mutable (`parking_lot::RwLock`) and
    /// safe to share across rayon worker threads.
    pub fn inter_taint_caches(&self) -> &InterTaintCaches {
        self.inner.inter_taint.as_ref()
    }

    /// Cloneable `Arc<InterTaintCaches>` for sub-caches that need
    /// sharing ownership (DataFlowCache seeds itself with this so
    /// its prewarm + on-demand paths thread the workspace
    /// singleton through the engine).
    pub fn shared_inter_taint_caches(&self) -> Arc<InterTaintCaches> {
        self.inner.inter_taint.clone()
    }

    /// Workspace-wide cache of source-seeded entry taint graphs
    /// keyed on `(source_func, sorted_seed_key)`. The security
    /// analysis pipeline consults it before requesting a source-seeded IDG
    /// projection, so a second `taint-analysis`/`source-analysis` query
    /// against the same workspace + rulepack reuses the exact result. Cleared
    /// on file edits.
    pub fn taint_index(&self) -> &TaintGraphIndex {
        &self.inner.taint_index
    }

    /// Hold the Workspace's source-seeded graph configuration/session for a
    /// complete security scan. Concurrent SDK scans otherwise could clear or
    /// finish one another's write-through state.
    pub fn lock_taint_analysis(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.inner.taint_analysis_serial.lock()
    }

    /// Workspace-level class/method/constructor index. Replaces
    /// per-resolution linear scans of `decls_in(class_file)` with
    /// `(class_sym, method_name) → FuncId` lookups. Built on first lookup.
    pub fn class_members(&self) -> &ClassMemberIndex {
        &self.inner.class_members
    }

    /// Workspace-level enclosing-decl span index. Replaces
    /// per-call `decls_in(file)` linear scans in inspect/browse
    /// "what decl contains this position?" queries with binary
    /// search.
    pub fn enclosing_index(&self) -> &EnclosingIndex {
        &self.inner.enclosing
    }

    /// Workspace-level decl-name index. `inspect`'s query layer
    /// iterates this cache instead of re-walking `global.decls_in(file)`
    /// per query. `Contains` matches use the precomputed lowercased
    /// names; regex matches use the original names.
    pub fn decl_name_index(&self) -> &DeclNameIndex {
        &self.inner.decl_names
    }

    /// Cached structural-reachability tokens per `FuncId`. Mirrors
    /// `bonsai_taint::name_reachable_through_func_kinded` but
    /// memoised so browse-export and inspect's chain-cache share one
    /// computation per function. Cleared on file edits.
    pub fn name_reachable_kinded_for(&self, func: FuncId) -> Arc<KindedTokens> {
        // Drop the read guard's temporary at the `;` so the
        // subsequent `.write()` doesn't deadlock with our own read.
        let cached = self.inner.reachable_kinded.read().get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        let computed = Arc::new(
            self.exact_decl(SymbolId::new(func.raw()))
                .map_or_else(KindedTokens::default, |decl| {
                    bonsai_taint::name_reachable_through_decl_kinded(&decl, &decl.file_index)
                }),
        );
        let mut map = self.inner.reachable_kinded.write();
        map.entry(func).or_insert(computed).clone()
    }

    pub fn db(&self) -> &AnalyzerDb {
        &self.inner.db
    }

    /// Check whether the immutable compiler-object generation exactly matches
    /// the current workspace snapshot.
    #[must_use]
    pub fn compiler_object_sidecar_is_current(&self, root: &Path) -> bool {
        self.inner.db.compiler_object_sidecar_is_current(root)
    }

    /// Cheap compiler-generation freshness check for orchestration.
    ///
    /// Payload digests are verified when an object is consumed; this method
    /// proves that the current immutable generation covers the exact VFS
    /// snapshot without reading every compressed payload.
    #[must_use]
    pub fn compiler_object_generation_matches_current_snapshot(&self) -> bool {
        self.inner
            .db
            .compiler_object_generation_matches_current_snapshot()
    }

    /// Persist the complete generation of relocatable, adapter-lowered file
    /// objects consumed by later compiler phases.
    pub fn save_compiler_object_sidecar(&self, root: &Path) -> std::io::Result<usize> {
        if !self.is_complete_workspace_index() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "compiler-object sidecars require a complete workspace index",
            ));
        }
        self.inner.db.save_compiler_object_sidecar(root)
    }

    /// Ensure a complete semantic phase consumes one immutable generation of
    /// adapter-lowered compiler objects.
    ///
    /// Query workspaces normally open an existing generation in
    /// [`AnalyzerDb::set_workspace_root`]. On a cold or invalidated cache, the
    /// first whole-workspace semantic consumer publishes the exact current
    /// generation before building linkage or callgraph facts. Those later
    /// phases then stream the same Tree-sitter lowering instead of reparsing
    /// every source independently. Failure to publish is a performance/cache
    /// failure only: callers retain the canonical syntax fallback.
    fn ensure_complete_compiler_object_generation(&self, root: &Path) {
        if self.compiler_object_generation_matches_current_snapshot() {
            return;
        }
        if let Err(error) = self.save_compiler_object_sidecar(root) {
            bonsai_diagnostics::debug_log!(
                "compiler-cache",
                "compiler-object generation publication failed at {}: {}",
                compiler_object_sidecar_path(root).display(),
                error
            );
        }
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
    /// Returns a clone of the workspace-cached graph when the
    /// singleton is populated; otherwise builds, caches, and clones.
    /// Callers that don't need ownership should prefer
    /// [`Self::cached_resolved_call_graph`] which hands back a shared
    /// `Arc` instead of paying the per-call clone.
    pub fn resolved_call_graph(&self) -> bonsai_callgraph::ResolvedCallGraph {
        (*self.cached_resolved_call_graph()).clone()
    }

    /// Lifetime-shared workspace-wide resolved call graph. Built on
    /// first access and reused across every subsequent caller —
    /// security/analysis, inspect, browse-export, and the dump-callgraph
    /// command all share one allocation. Cleared on file edit via
    /// [`Self::ingest_dir`].
    ///
    /// Seed the slot from a sidecar with [`Self::seed_resolved_call_graph`]
    /// at workspace open time to skip the initial build entirely.
    pub fn seed_resolved_call_graph(&self, graph: Arc<bonsai_callgraph::ResolvedCallGraph>) {
        self.inner.dataflow.seed_call_graph(graph.clone());
        self.inner.flow_ids.seed_call_graph(graph.clone());
        *self.inner.resolved_call_graph.write() = Some(graph);
    }

    /// Load the conventional callgraph sidecar for `root` and seed
    /// the workspace's `cached_resolved_call_graph` slot if every
    /// recorded `(path, content_hash)` matches current state.
    /// Returns `true` when the sidecar was a hit.
    pub fn load_callgraph_sidecar(&self, root: &Path) -> bool {
        self.load_callgraph_sidecar_checked(root).is_ok()
    }

    /// Load and seed the conventional callgraph sidecar while preserving the
    /// exact validation/decode error for compiler phase orchestration.
    pub fn load_callgraph_sidecar_checked(&self, root: &Path) -> std::io::Result<()> {
        let path = callgraph_sidecar::callgraph_sidecar_path(root);
        let graph = callgraph_sidecar::load_callgraph_sidecar_checked(&path, &self.inner.db)?;
        self.seed_resolved_call_graph(Arc::new(graph));
        Ok(())
    }

    /// Check whether the conventional callgraph sidecar exactly matches this
    /// workspace without retaining its graph. Used by compiler warm-up paths
    /// that only need to ensure the artifact exists; query paths continue to
    /// call [`Self::load_callgraph_sidecar`] before consuming edges.
    #[must_use]
    pub fn callgraph_sidecar_is_current(&self, root: &Path) -> bool {
        let path = callgraph_sidecar::callgraph_sidecar_path(root);
        callgraph_sidecar::validate_callgraph_sidecar_for_db(&path, &self.inner.db).is_ok()
    }

    /// Persist the current resolved call graph to the conventional
    /// sidecar path for `root`. Builds the graph on-demand if it
    /// hasn't been built yet.
    pub fn save_callgraph_sidecar(&self, root: &Path) -> std::io::Result<()> {
        if !self.is_complete_workspace_index() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "callgraph sidecars require a complete workspace index",
            ));
        }
        let path = callgraph_sidecar::callgraph_sidecar_path(root);
        let graph = self.cached_resolved_call_graph();
        if callgraph_sidecar::validate_callgraph_sidecar_for_db(&path, &self.inner.db).is_ok() {
            return Ok(());
        }
        callgraph_sidecar::save_callgraph_sidecar(&path, &self.inner.db, graph)
    }

    /// Check whether the compiler linkage artifact exactly matches the
    /// current VFS identity and semantic ABI without decoding its payload.
    #[must_use]
    pub fn compiler_linkage_sidecar_is_current(&self, root: &Path) -> bool {
        let path = linkage_sidecar::linkage_sidecar_path(root);
        linkage_sidecar::validate_linkage_sidecar_for_db(&path, &self.inner.db).is_ok()
    }

    /// Load and seed the compact compiler linkage table from its exact
    /// sidecar. The caller receives the concrete validation/decode error so a
    /// compiler orchestration phase can rebuild rather than weakening facts.
    pub fn load_compiler_linkage_sidecar_checked(&self, root: &Path) -> std::io::Result<()> {
        if self.inner.compiler_linkage.read().is_some() {
            return Ok(());
        }
        let path = linkage_sidecar::linkage_sidecar_path(root);
        let index = Arc::new(linkage_sidecar::load_linkage_sidecar_checked(
            &path,
            &self.inner.db,
        )?);
        let mut slot = self.inner.compiler_linkage.write();
        if slot.is_none() {
            *slot = Some(index);
        }
        Ok(())
    }

    /// Persist the complete linkage-header table. Full function bodies are
    /// never part of this artifact; later IDG transfer streams them from exact
    /// adapter-lowered compiler objects one compilation unit at a time.
    pub fn save_compiler_linkage_sidecar(&self, root: &Path) -> std::io::Result<()> {
        if !self.is_complete_workspace_index() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "compiler linkage sidecars require a complete workspace index",
            ));
        }
        let path = linkage_sidecar::linkage_sidecar_path(root);
        let linkage = self.compiler_linkage_index();
        if linkage_sidecar::validate_linkage_sidecar_for_db(&path, &self.inner.db).is_ok() {
            return Ok(());
        }
        linkage_sidecar::save_linkage_sidecar(&path, &self.inner.db, linkage)
    }

    /// Compact workspace-wide compiler linkage used while resolving calls or
    /// building a new IDG. It contains stable declaration/type symbols and
    /// AST-derived linkage summaries, but never retains every function body.
    ///
    /// A loaded IDG needs declaration/type headers only: its call and return
    /// relations are already compiled into the graph. Keeping this resolver
    /// payload separate prevents a warm semantic query from retaining every
    /// AST call-linkage row beside the IDG.
    #[must_use]
    pub fn compiler_linkage_index(&self) -> Arc<GlobalIndex> {
        // Once the canonical IDG is open, it already owns the exact compact
        // linkage generation used to build or validate that graph. Reuse it
        // rather than decoding/building a second workspace symbol table
        // beside the graph.
        if let Some(idg) = self.inner.db.idg_service() {
            return idg.global_linkage_index();
        }
        if let Some(linkage) = self.inner.compiler_linkage.read().clone() {
            return linkage;
        }
        let mut slot = self.inner.compiler_linkage.write();
        if let Some(linkage) = slot.as_ref() {
            return linkage.clone();
        }
        if let Some(root) = self.root_path().filter(|_| self.is_complete_workspace_index()) {
            let path = linkage_sidecar::linkage_sidecar_path(&root);
            if let Ok(linkage) = linkage_sidecar::load_linkage_sidecar_checked(&path, &self.inner.db) {
                let linkage = Arc::new(linkage);
                *slot = Some(linkage.clone());
                return linkage;
            }
            self.ensure_complete_compiler_object_generation(&root);
        }
        let linkage = self.inner.db.build_global_linkage_index();
        *slot = Some(linkage.clone());
        drop(slot);
        if let Some(root) = self.root_path().filter(|_| self.is_complete_workspace_index()) {
            let path = linkage_sidecar::linkage_sidecar_path(&root);
            if let Err(error) = linkage_sidecar::save_linkage_sidecar(&path, &self.inner.db, linkage.clone())
            {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "compiler-linkage publication failed at {}: {}",
                    path.display(),
                    error
                );
            }
        }
        linkage
    }

    /// Complete workspace declaration/type headers without call linkage or
    /// function bodies.
    ///
    /// Syntax-only symbol lookup shares this table. A later targeted semantic
    /// phase can take its allocation exclusively and add only the linkage
    /// proven necessary by its compiler worklist.
    #[must_use]
    pub fn compiler_header_index(&self) -> Arc<GlobalIndex> {
        // A warmed IDG already owns the immutable declaration/type identity
        // generation used to validate the graph. It is a strict superset of
        // this syntax projection, so reusing it avoids decoding and retaining
        // a second workspace-wide symbol table beside the IDG.
        if let Some(idg) = self.inner.db.idg_service() {
            return idg.global_linkage_index();
        }
        if let Some(headers) = self.inner.compiler_headers.read().clone() {
            return headers;
        }
        let mut slot = self.inner.compiler_headers.write();
        if let Some(headers) = slot.as_ref() {
            return headers.clone();
        }
        if let Some(root) = self.root_path().filter(|_| self.is_complete_workspace_index()) {
            let path = linkage_sidecar::linkage_sidecar_path(&root);
            match linkage_sidecar::load_header_sidecar_checked(&path, &self.inner.db) {
                Ok(headers) => {
                    let headers = Arc::new(headers);
                    *slot = Some(headers.clone());
                    return headers;
                }
                Err(error) => {
                    bonsai_diagnostics::debug_log!(
                        "compiler-cache",
                        "header sidecar rejected at {}: {}",
                        path.display(),
                        error
                    );
                }
            }
        }
        let headers = self.inner.db.build_global_header_index();
        *slot = Some(headers.clone());
        headers
    }

    /// Complete workspace declaration/type headers for read-only lookup.
    ///
    /// A scoped compiler session must keep [`Self::compiler_header_index`]
    /// aligned with the files it can compile. Query planners that need global
    /// endpoint names use this separate projection, validated against the
    /// scoped session's independently fingerprinted complete source set.
    #[must_use]
    pub fn complete_compiler_header_index(&self) -> Arc<GlobalIndex> {
        if self.is_complete_workspace_index() {
            return self.compiler_header_index();
        }
        if let Some(root) = self.root_path() {
            let path = linkage_sidecar::linkage_sidecar_path(&root);
            if let Ok(headers) = self.sidecar_source_inputs().and_then(|inputs| {
                linkage_sidecar::load_header_sidecar_checked_with_source_inputs(&path, inputs.as_slice())
            }) {
                return Arc::new(headers);
            }
        }
        self.compiler_header_index()
    }

    /// Load declaration headers only for files admitted by an exact compiler
    /// worklist.
    ///
    /// Stable workspace symbol ids are preserved by the partitioned linkage
    /// sidecar. A missing or stale partition artifact falls back to the
    /// canonical complete header table, so storage layout never changes
    /// analysis semantics.
    pub fn compiler_header_index_for_files(&self, files: &[FileId]) -> Arc<GlobalIndex> {
        self.persisted_compiler_header_index_for_files(files)
            .unwrap_or_else(|| self.compiler_header_index())
    }

    /// Load exact global-symbol header partitions without falling back to a
    /// scoped workspace's locally renumbered declaration table.
    ///
    /// Query planners use the `None` result to choose a complete-workspace
    /// compiler fallback. Treating local symbols from a retrieval workspace
    /// as globally stable can silently target unrelated callgraph nodes.
    fn persisted_compiler_header_index_for_files(&self, files: &[FileId]) -> Option<Arc<GlobalIndex>> {
        let source_inputs = (!self.is_complete_workspace_index())
            .then(|| self.sidecar_source_inputs().ok())
            .flatten();
        let mut files = if let Some(inputs) = source_inputs.as_deref() {
            // Scoped syntax workspaces may use dense local FileIds (the
            // one-file navigation path intentionally does). Convert their
            // canonical VFS paths back to the stable complete-workspace ids
            // before opening linkage partitions. Retrieval workspaces that
            // already carry global ids pass through the same path mapping.
            let ids_by_path = inputs
                .iter()
                .map(|(raw, path, _)| (std::path::PathBuf::from(path), FileId::new(*raw)))
                .collect::<ahash::AHashMap<_, _>>();
            files
                .iter()
                .map(|file| {
                    self.inner
                        .vfs
                        .path(*file)
                        .ok()
                        .and_then(|path| ids_by_path.get(path.as_path()).copied())
                })
                .collect::<Option<Vec<_>>>()?
        } else {
            files.to_vec()
        };
        files.sort_unstable_by_key(|file| file.raw());
        files.dedup();
        if let Some(root) = self.root_path() {
            let path = linkage_sidecar::linkage_sidecar_path(&root);
            let loaded = if self.is_complete_workspace_index() {
                linkage_sidecar::load_header_partitions_checked(&path, &self.inner.db, &files)
            } else {
                source_inputs
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "complete source generation is unavailable for scoped headers",
                        )
                    })
                    .and_then(|inputs| {
                        linkage_sidecar::load_header_partitions_checked_with_source_inputs(
                            &path,
                            inputs.as_slice(),
                            &files,
                        )
                    })
            };
            match loaded {
                Ok(headers) => return Some(Arc::new(headers)),
                Err(error) => {
                    bonsai_diagnostics::debug_log!(
                        "compiler-cache",
                        "scoped header partitions rejected at {}: {}",
                        path.display(),
                        error
                    );
                }
            }
        }
        None
    }

    /// Finalized cross-file receiver ancestry without declaration headers,
    /// call linkage, or function bodies.
    ///
    /// File-local inventory scans apply this compact compiler projection to
    /// preserve inheritance-sensitive receiver constraints without hydrating
    /// the complete workspace symbol table.
    #[must_use]
    pub fn compiler_receiver_ancestry(&self) -> Arc<ReceiverAncestry> {
        if let Some(root) = self.root_path() {
            let path = linkage_sidecar::linkage_sidecar_path(&root);
            if let Ok(ancestry) =
                linkage_sidecar::load_receiver_ancestry_sidecar_checked(&path, &self.inner.db)
            {
                return Arc::new(ancestry);
            }
        }
        Arc::new(self.compiler_header_index().receiver_ancestry())
    }

    fn take_exclusive_compiler_header_index(&self) -> Arc<GlobalIndex> {
        // Ensure a persisted compiler symbol table is loaded before taking its
        // cache allocation. A missing cache falls back to one exact streamed
        // frontend pass; this function must never independently decode all
        // file bodies after the same query already built the header table.
        drop(self.compiler_header_index());
        let mut slot = self.inner.compiler_headers.write();
        if let Some(headers) = slot.take() {
            if Arc::strong_count(&headers) == 1 {
                return headers;
            }
            // Concurrent syntax readers keep their immutable generation. A
            // compact header clone is bounded by declaration/type facts and
            // avoids re-inflating every exact flow-event body.
            *slot = Some(headers.clone());
            return Arc::new((*headers).clone());
        }
        unreachable!("compiler header cache disappeared while exclusively locked")
    }

    /// Release the resident canonical IDG between whole-workspace compiler
    /// phases. This never removes the validated sidecar or changes source
    /// state; the next semantic consumer reloads or rebuilds the same exact
    /// graph on demand.
    ///
    /// Preserve the service's declaration/type headers before dropping graph
    /// readers. A loaded IDG never owns the much larger resolver-linkage
    /// payload: call and return relations are already compiled into the graph.
    pub fn release_idg_service_cache(&self) {
        if self.inner.compiler_headers.read().is_none() {
            if let Some(service) = self.inner.db.idg_service() {
                let headers = service.global_linkage_index();
                let mut slot = self.inner.compiler_headers.write();
                if slot.is_none() {
                    *slot = Some(headers);
                }
            }
        }
        self.inner.db.invalidate_idg_service();
    }

    /// Return the exact IDG pipeline identity for this workspace generation.
    ///
    /// Source snapshots are immutable until [`Self::apply_edit`] (or another
    /// refresh path) advances the generation and clears this token. Keeping
    /// the validated identity lets memory-bounded consumers unload and reload
    /// the same sidecar without rehashing the entire source/dependency tree.
    fn cached_idg_workspace_pipeline_hash(&self, root: Option<&Path>) -> u64 {
        let root_key = root.map(Path::to_path_buf);
        let mut cached = self.inner.idg_pipeline_hash.lock();
        if let Some((cached_root, hash)) = cached.as_ref() {
            if cached_root == &root_key {
                return *hash;
            }
        }
        let hash = idg_workspace_pipeline_hash(&self.inner.db, root);
        *cached = Some((root_key, hash));
        hash
    }

    fn cached_idg_transfer_pipeline_hash(&self, root: Option<&Path>, transfer_hash: u64) -> u64 {
        self.cached_idg_workspace_pipeline_hash(root) ^ transfer_hash ^ 0x71A1_57E7_1D6D_A7A5_u64
    }

    /// Release the resident resolved call graph after a whole-workspace
    /// consumer has finished with linkage edges. This is allocation lifetime
    /// control, not a graph or traversal limit: a later consumer reloads or
    /// rebuilds the complete graph on demand.
    pub fn release_resolved_call_graph_cache(&self) {
        *self.inner.resolved_call_graph.write() = None;
        *self.inner.callgraph_query.lock() = None;
        self.inner.dataflow.release_call_graph();
        self.inner.flow_ids.release_call_graph();
    }

    /// Release the standalone compiler linkage table at a compiler phase
    /// boundary. A loaded IDG owns its canonical linkage table; keeping both
    /// copies resident would duplicate every declaration header on large
    /// workspaces.
    pub fn release_compiler_linkage_cache(&self) {
        *self.inner.compiler_linkage.write() = None;
    }

    /// Release the syntax-only declaration/type header cache.
    ///
    /// This controls allocation lifetime only; the next lookup rebuilds the
    /// same symbols from immutable compiler objects.
    pub fn release_compiler_header_cache(&self) {
        *self.inner.compiler_headers.write() = None;
    }

    /// Release the memory-scheduled hot set of exact file bodies.
    ///
    /// Compiler objects and VFS snapshots remain authoritative, so a later
    /// lookup replays the identical adapter-lowered body. Broad multi-phase
    /// analyses use this after endpoint matching and callgraph scoping to keep
    /// prior file bodies from overlapping a workspace IDG fixed point.
    pub fn release_exact_body_cache(&self) {
        self.inner.exact_bodies.clear();
    }

    /// Release the lowercased declaration-name projection after a syntax
    /// candidate phase.
    ///
    /// Selected declarations and stable symbols remain owned by the caller;
    /// a later syntax query recreates the same projection from compiler
    /// headers.
    pub fn release_decl_name_index_cache(&self) {
        self.inner.decl_names.clear();
    }

    /// Return a shared exact file body, loading it from the memory-scheduled
    /// hot cache or lowering it from the compiler object on a miss.
    ///
    /// Cache eviction controls allocation lifetime only. Every miss replays
    /// the same Tree-sitter adapter IR and binds it to the same workspace
    /// symbols.
    #[must_use]
    pub fn exact_decl_index_shared(&self, file: FileId) -> Option<Arc<DeclIndex>> {
        let snapshot = self.inner.vfs.snapshot(file).ok()?;
        self.inner.exact_bodies.get_or_insert_with(
            (file, snapshot.version),
            estimated_exact_body_bytes(snapshot.text.len()),
            || {
                let headers = self.compiler_index_for_exact_bodies();
                self.inner
                    .db
                    .decl_index_remapped_to_headers(headers.as_ref(), file)
                    .map(Arc::new)
            },
        )
    }

    /// Compatibility wrapper returning an owned exact file body.
    ///
    /// Prefer [`Self::exact_decl_index_shared`] for read-only consumers so
    /// repeated lookups do not clone the complete lowered body.
    #[must_use]
    pub fn exact_decl_index(&self, file: FileId) -> Option<DeclIndex> {
        self.exact_decl_index_shared(file).map(|index| (*index).clone())
    }

    /// Return one exact declaration from the streamed compiler object without
    /// materializing a workspace-wide body index.
    #[must_use]
    pub fn exact_decl(&self, symbol: SymbolId) -> Option<ExactDecl> {
        let headers = self.compiler_index_for_exact_bodies();
        self.exact_decl_with_headers(symbol, headers)
    }

    /// Return one exact adapter-lowered declaration for frontend debugging.
    /// Unlike [`Self::exact_decl`], this preserves file-local HIR and does not
    /// add workspace-global receiver ancestry. It still remaps declaration
    /// symbols against stable headers, so full and scoped opens agree.
    #[must_use]
    pub fn exact_frontend_decl(&self, symbol: SymbolId) -> Option<ExactDecl> {
        let headers = self.compiler_index_for_exact_bodies();
        let file = headers.declaring_file(symbol)?;
        let index = self.inner.db.decl_index_uncached(file)?;
        let index = headers.remap_file_to_existing_symbols_frontend_only(index);
        let position = index.defs.iter().position(|decl| decl.symbol == symbol)?;
        Some(ExactDecl {
            file_index: Arc::new(index),
            position,
        })
    }

    /// Reuse an already-materialized compiler identity table before building
    /// another one solely to replay an exact body.
    ///
    /// Semantic analysis deliberately retains the linkage projection while
    /// releasing the independent header-cache owner. Exact body consumers can
    /// use either table because both carry the same stable symbols. Falling
    /// straight through to `compiler_header_index` in that state duplicated
    /// memory and, inside a Rayon compiler pass, could deadlock when the
    /// header builder stole another exact-body job and recursively requested
    /// its own write-locked cache.
    fn compiler_index_for_exact_bodies(&self) -> Arc<GlobalIndex> {
        if let Some(idg) = self.inner.db.idg_service() {
            return idg.global_linkage_index();
        }
        if let Some(linkage) = self.inner.compiler_linkage.read().clone() {
            return linkage;
        }
        if let Some(headers) = self.inner.compiler_headers.read().clone() {
            return headers;
        }
        self.compiler_header_index()
    }

    /// Return one exact declaration using an already-selected stable header
    /// projection. Scoped graph queries pass their partitioned header table so
    /// exact body replay never triggers a complete workspace header decode.
    #[must_use]
    pub fn exact_decl_with_headers(&self, symbol: SymbolId, headers: Arc<GlobalIndex>) -> Option<ExactDecl> {
        let file = headers.declaring_file(symbol)?;
        let snapshot = self.inner.vfs.snapshot(file).ok()?;
        let file_index = self.inner.exact_bodies.get_or_insert_with(
            (file, snapshot.version),
            estimated_exact_body_bytes(snapshot.text.len()),
            || {
                self.inner
                    .db
                    .decl_index_remapped_to_headers(headers.as_ref(), file)
                    .map(Arc::new)
            },
        )?;
        let position = file_index.defs.iter().position(|decl| decl.symbol == symbol)?;
        Some(ExactDecl { file_index, position })
    }

    /// Load the workspace IDG sidecar for `root` and seed the shared
    /// [`AnalyzerDb`] IDG service when the factstore is fresh. Returns
    /// the loaded segment count. Missing, stale, or version-mismatched
    /// sidecars are reported as `Ok(None)` so query opens can stay
    /// read-only and compute only if a later command explicitly needs
    /// the graph.
    pub fn load_idg_sidecar(&self, root: &Path) -> bonsai_idg::IdgResult<Option<usize>> {
        if let Some(service) = self.inner.db.idg_service() {
            return Ok(Some(service.segment_count()));
        }
        let sidecar = bonsai_idg::workspace::idg_sidecar_path(root);
        if !sidecar.exists() {
            return Ok(None);
        }
        let pipeline_hash = self.cached_idg_workspace_pipeline_hash(Some(root));
        // Reject a stale/corrupt generation before constructing the compiler
        // linkage table it would need if it were reusable. The prior order
        // made a cheap cache miss trigger a complete streamed linkage build,
        // so every fresh CLI process could compile the workspace merely to
        // discover that the graph header did not match.
        if let Err(error) = bonsai_idg::workspace::IdgWorkspace::validate_sidecar_layout_with_pipeline(
            &sidecar,
            pipeline_hash,
        ) {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "workspace IDG sidecar rejected before linkage hydration: {}",
                error
            );
            return Ok(None);
        }
        // A persisted IDG already contains exact call/return relations. Query
        // rendering needs stable declaration/type headers, not the complete
        // AST resolver-linkage payload that built those relations.
        let global = self.compiler_header_index();
        let Some(service) = bonsai_idg::IdgQueryService::load_from_disk(&sidecar, pipeline_hash, global)?
        else {
            return Ok(None);
        };
        let segment_count = service.segment_count();
        let service = Arc::new(service);
        self.inner.db.set_idg_service(service);
        // The current immutable generation is open and usable. Reclaim crash
        // staging files and superseded schema generations under per-target
        // writer locks; query correctness never depends on this maintenance.
        idg_persistence::maintain_current_idg_sidecar(&sidecar);
        Ok(Some(segment_count))
    }

    /// Validate the conventional IDG sidecar's exact compiler pipeline and
    /// complete factstore layout without opening graph pages. Query consumers
    /// use [`Self::load_idg_sidecar`], which validates the complete layout,
    /// scans segment headers once, and decodes exact relation pages on demand.
    pub fn validate_idg_sidecar_layout(&self, root: &Path) -> bonsai_idg::IdgResult<Option<usize>> {
        let sidecar = bonsai_idg::workspace::idg_sidecar_path(root);
        if !sidecar.exists() {
            return Ok(None);
        }
        let pipeline_hash = self.cached_idg_workspace_pipeline_hash(Some(root));
        bonsai_idg::workspace::IdgWorkspace::validate_sidecar_layout_with_pipeline(&sidecar, pipeline_hash)
            .map(Some)
    }

    pub fn cached_resolved_call_graph(&self) -> Arc<bonsai_callgraph::ResolvedCallGraph> {
        // Drop the read guard's temporary at the `;` so the
        // subsequent `.write()` below can't deadlock on a
        // same-thread read→write upgrade. (parking_lot RwLock is
        // non-reentrant; documented hazard B1.)
        let cached = self.inner.resolved_call_graph.read().as_ref().cloned();
        if let Some(hit) = cached {
            return hit;
        }
        let complete_root = self.root_path().filter(|_| self.is_complete_workspace_index());
        if let Some(root) = complete_root.as_deref() {
            if let Ok(graph) = callgraph_sidecar::load_callgraph_sidecar_checked(
                &callgraph_sidecar::callgraph_sidecar_path(root),
                &self.inner.db,
            ) {
                let graph = Arc::new(graph);
                self.seed_resolved_call_graph(graph.clone());
                return graph;
            }
            self.ensure_complete_compiler_object_generation(root);
        }
        let built = self.build_resolved_call_graph();
        let arc = Arc::new(built);
        let mut slot = self.inner.resolved_call_graph.write();
        if let Some(existing) = slot.as_ref().cloned() {
            // Another thread populated the cache while we built —
            // discard our copy and return the established singleton
            // so downstream pointer-equality checks remain stable.
            drop(slot);
            self.inner.dataflow.seed_call_graph(existing.clone());
            self.inner.flow_ids.seed_call_graph(existing.clone());
            return existing;
        }
        // Publish the shared consumers before exposing the workspace slot.
        // A concurrent caller that can observe the canonical graph must never
        // race into rebuilding the same complete graph in DataFlowCache or
        // FlowIdCache.
        self.inner.dataflow.seed_call_graph(arc.clone());
        self.inner.flow_ids.seed_call_graph(arc.clone());
        *slot = Some(arc.clone());
        drop(slot);
        if let Some(root) = complete_root.as_deref() {
            let path = callgraph_sidecar::callgraph_sidecar_path(root);
            if let Err(error) = callgraph_sidecar::save_callgraph_sidecar(&path, &self.inner.db, arc.clone())
            {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "resolved-callgraph publication failed at {}: {}",
                    path.display(),
                    error
                );
            }
        }
        arc
    }

    fn callgraph_query_service(&self) -> Option<Arc<callgraph_sidecar::CallgraphQueryService>> {
        if let Some(service) = self.inner.callgraph_query.lock().as_ref().cloned() {
            return Some(service);
        }
        let root = self.root_path()?;
        let path = callgraph_sidecar::callgraph_sidecar_path(&root);
        let opened = if self.is_complete_workspace_index() {
            callgraph_sidecar::CallgraphQueryService::open_checked(&path, &self.inner.db)
        } else {
            self.sidecar_source_inputs().and_then(|inputs| {
                callgraph_sidecar::CallgraphQueryService::open_checked_with_source_inputs(
                    &path,
                    inputs.as_slice(),
                )
            })
        };
        let service = match opened {
            Ok(service) => Arc::new(service),
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "partitioned callgraph rejected at {}: {}",
                    path.display(),
                    error
                );
                return None;
            }
        };
        let mut slot = self.inner.callgraph_query.lock();
        Some(slot.get_or_insert_with(|| Arc::clone(&service)).clone())
    }

    /// Return the requested callables that have at least one compiler-resolved
    /// in-workspace caller.
    ///
    /// A complete workspace with a current partitioned sidecar reads only the
    /// compact callable table and the incoming partitions for the candidates'
    /// declaration files. This is the exact query needed by `entrypoints`; it
    /// must not allocate the unrelated outgoing graph merely to answer a
    /// boolean caller predicate.
    #[must_use]
    pub fn functions_with_semantic_callers(&self, functions: &[FuncId]) -> AHashSet<FuncId> {
        if functions.is_empty() {
            return AHashSet::new();
        }
        if let Some(graph) = self.inner.resolved_call_graph.read().as_ref().cloned() {
            return functions
                .iter()
                .copied()
                .filter(|function| {
                    graph
                        .callers_of(*function)
                        .any(|edge| edge.precision.is_semantic())
                })
                .collect();
        }
        if let Some(service) = self.callgraph_query_service() {
            if let Ok(called) = service.functions_with_semantic_callers(functions) {
                return called;
            }
        }
        let graph = self.cached_resolved_call_graph();
        functions
            .iter()
            .copied()
            .filter(|function| {
                graph
                    .callers_of(*function)
                    .any(|edge| edge.precision.is_semantic())
            })
            .collect()
    }

    /// Look up exact short or qualified callable names from the persisted
    /// compiler graph without hydrating declaration headers or function
    /// bodies.
    pub fn persisted_callable_nodes_named(
        &self,
        name: &str,
    ) -> Option<std::io::Result<Vec<bonsai_callgraph::CallGraphNode>>> {
        let service = self.callgraph_query_service()?;
        Some(service.callable_nodes_named(name))
    }

    /// Visit the exact persisted resolved-callgraph one file partition at a
    /// time, if a fresh partitioned sidecar is available.
    ///
    /// This is the broad-consumer counterpart to targeted callgraph queries:
    /// it preserves the complete compiler relation while bounding live graph
    /// memory by the largest source-file partition. `None` means no reusable
    /// sidecar exists; callers may then use the canonical in-memory graph.
    pub fn visit_persisted_callgraph_partitions(
        &self,
        visit: impl FnMut(
            FileId,
            &[bonsai_callgraph::CallGraphNode],
            &[bonsai_callgraph::CallEdge],
            &[bonsai_callgraph::CallEdge],
            &[bonsai_callgraph::UnresolvedWorkspaceCallSite],
        ),
    ) -> Option<std::io::Result<()>> {
        let service = self.callgraph_query_service()?;
        Some(service.visit_partitions(visit))
    }

    /// Load one callable node from the validated partitioned callgraph.
    ///
    /// Filtered graph renderers use this to join an edge with its opposite
    /// endpoint without hydrating the complete callable table. `None` means
    /// no reusable sidecar exists; the caller must take its canonical
    /// resident-graph fallback.
    pub fn persisted_callgraph_node(
        &self,
        function: FuncId,
    ) -> Option<std::io::Result<bonsai_callgraph::CallGraphNode>> {
        let service = self.callgraph_query_service()?;
        Some(service.callable_node(function))
    }

    /// Return the exact persisted callgraph slice containing every path from
    /// `starts` to `targets`, if a fresh partitioned sidecar is available.
    ///
    /// This is the target-directed counterpart to whole-workspace graph
    /// hydration. It performs uncapped compiler work while keeping resident
    /// memory proportional to the source/target slice.
    pub fn persisted_resolved_call_graph_between(
        &self,
        starts: &[FuncId],
        targets: &[FuncId],
    ) -> Option<std::io::Result<bonsai_callgraph::ResolvedCallGraph>> {
        let service = self.callgraph_query_service()?;
        Some(service.materialize_between(starts, targets))
    }

    pub fn persisted_resolved_call_graph_between_with_max_precision(
        &self,
        starts: &[FuncId],
        targets: &[FuncId],
        max_precision: Option<Precision>,
    ) -> Option<std::io::Result<bonsai_callgraph::ResolvedCallGraph>> {
        let service = self.callgraph_query_service()?;
        Some(service.materialize_between_with_max_precision(starts, targets, max_precision))
    }

    /// Return every exact persisted direct edge from `starts` to `targets`.
    pub fn persisted_direct_call_graph_between(
        &self,
        starts: &[FuncId],
        targets: &[FuncId],
    ) -> Option<std::io::Result<bonsai_callgraph::ResolvedCallGraph>> {
        let service = self.callgraph_query_service()?;
        Some(service.materialize_direct_between(starts, targets))
    }

    /// Materialize the exact compiler-resolved subgraph reachable from
    /// `starts`.
    ///
    /// The partitioned sidecar makes tracing proportional to the reachable
    /// compiler worklist instead of the total workspace graph. A cache miss
    /// falls back to the canonical whole-workspace graph without weakening
    /// resolution or imposing a depth/edge cap.
    fn resolved_call_graph_reachable_from(
        &self,
        starts: &[FuncId],
    ) -> Arc<bonsai_callgraph::ResolvedCallGraph> {
        if let Some(graph) = self.inner.resolved_call_graph.read().as_ref().cloned() {
            return graph;
        }
        if let Some(service) = self.callgraph_query_service() {
            if let Ok(graph) = service.materialize_reachable(starts) {
                return Arc::new(graph);
            }
        }
        self.cached_resolved_call_graph()
    }

    fn persisted_resolved_call_graph_reachable_from(
        &self,
        starts: &[FuncId],
        max_precision: Option<Precision>,
    ) -> Option<std::io::Result<bonsai_callgraph::ResolvedCallGraph>> {
        let service = self.callgraph_query_service()?;
        Some(service.materialize_reachable_with_max_precision(starts, max_precision))
    }

    fn build_resolved_call_graph(&self) -> bonsai_callgraph::ResolvedCallGraph {
        let headers = self.compiler_header_index();
        bonsai_taint::build_resolved_call_graph_snapshot_with_headers(&self.inner.db, headers.as_ref())
    }

    pub fn source_reachable_resolved_call_graph(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &[FuncId],
        max_precision: Option<Precision>,
    ) -> SourceReachableCallGraph {
        self.source_reachable_resolved_call_graph_with_scope(
            source_funcs,
            target_funcs,
            max_precision,
            false,
            false,
        )
    }

    /// Compile an uncapped source-reachable callgraph from complete compiler
    /// headers while hydrating only reached function bodies.
    ///
    /// Query commands use this when the partitioned callgraph is absent or
    /// stale. It preserves the same resolver semantics as the complete graph
    /// without loading the workspace-wide linkage payload or compiling every
    /// function merely to answer one exact endpoint question.
    pub fn source_reachable_query_call_graph(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &[FuncId],
        max_precision: Option<Precision>,
    ) -> SourceReachableCallGraph {
        self.source_reachable_resolved_call_graph_with_scope(
            source_funcs,
            target_funcs,
            max_precision,
            false,
            true,
        )
    }

    /// Compile the exact callgraph region needed to emit flows inside
    /// `target_funcs`.
    ///
    /// Unlike a source-to-sink security query, syntax-flow inspection emits
    /// rows only from functions that contain the query/filter hits. A
    /// downstream callee body can affect such a row only when the callee is
    /// itself a target or its compiler linkage advertises return, out-param,
    /// receiver, or callback output. Restricting body compilation to those
    /// syntax-derived capabilities avoids exploring unrelated application
    /// behavior while retaining every semantic provider for the requested
    /// target emissions.
    pub fn target_emission_resolved_call_graph(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &[FuncId],
        max_precision: Option<Precision>,
    ) -> SourceReachableCallGraph {
        self.source_reachable_resolved_call_graph_with_scope(
            source_funcs,
            target_funcs,
            max_precision,
            true,
            true,
        )
    }

    fn source_reachable_resolved_call_graph_with_scope(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &[FuncId],
        max_precision: Option<Precision>,
        target_emissions_only: bool,
        function_scoped: bool,
    ) -> SourceReachableCallGraph {
        let mut global = if function_scoped {
            self.take_exclusive_compiler_header_index()
        } else {
            self.compiler_linkage_index()
        };
        let mut scoped_linkage: AHashMap<SymbolId, bonsai_index::FunctionLinkageFacts> = AHashMap::new();
        let target_set: AHashSet<FuncId> = target_funcs.iter().copied().collect();
        let mut reached_funcs: AHashSet<FuncId> = source_funcs.iter().copied().collect();
        let mut reverse_output_funcs: AHashSet<FuncId> = source_funcs
            .iter()
            .copied()
            .filter(|func| has_summary_output(global.as_ref(), *func))
            .collect();
        let mut queued_files: AHashSet<FileId> = AHashSet::new();
        let mut built_files: AHashSet<FileId> = AHashSet::new();
        let mut queued_funcs: AHashSet<FuncId> = AHashSet::new();
        let mut built_funcs: AHashSet<FuncId> = AHashSet::new();
        // Forward propagation starts at sources, while return-value
        // propagation may enter a target caller from one of its callees.
        // Compile both endpoint file sets up front so a target in another
        // file cannot be invisible merely because the forward source walk
        // has not visited its caller yet.
        for func in source_funcs.iter().chain(target_funcs) {
            if function_scoped {
                queued_funcs.insert(*func);
            } else if let Some(file) = global.declaring_file(SymbolId::new(func.raw())) {
                queued_files.insert(file);
            }
        }

        // Store each resolved edge once. Compact outgoing/incoming indexes
        // drive the two monotone facts below:
        //
        // - ordinary source reachability propagates from caller to callee;
        // - summary-output capability propagates from callee to caller.
        //
        // The previous implementation retained edges by file and rescanned
        // the complete accumulated set after every compiler batch. On a
        // highly connected workspace that was quadratic and also overlapped
        // one unbounded batch graph with the complete retained graph.
        let mut known_edges: Vec<bonsai_callgraph::CallEdge> = Vec::new();
        let mut outgoing_edge_ids: AHashMap<FuncId, Vec<usize>> = AHashMap::new();
        let mut incoming_edge_ids: AHashMap<FuncId, Vec<usize>> = AHashMap::new();
        let mut admitted_edge_ids: AHashSet<usize> = AHashSet::new();
        let mut pending_reached: Vec<FuncId> = reached_funcs.iter().copied().collect();
        pending_reached.sort_unstable_by_key(|func| std::cmp::Reverse(func.raw()));
        let mut processed_reached: AHashSet<FuncId> = AHashSet::new();
        let mut pending_reverse_output: Vec<FuncId> = reverse_output_funcs.iter().copied().collect();
        pending_reverse_output.sort_unstable_by_key(|func| std::cmp::Reverse(func.raw()));
        let mut processed_reverse_output: AHashSet<FuncId> = AHashSet::new();
        let callgraph_context = bonsai_callgraph::ResolvedCallGraph::build_context(
            global.as_ref(),
            |file| {
                self.inner
                    .db
                    .vfs()
                    .path(file)
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            },
            |file| {
                self.inner
                    .db
                    .adapter_for(file)
                    .map(|adapter| adapter.language_id().as_str())
            },
            |file| {
                self.inner
                    .db
                    .adapter_for(file)
                    .map(|adapter| adapter.capabilities())
                    .unwrap_or_else(bonsai_lang_api::LanguageCapabilities::unsupported)
            },
        );
        while !queued_files.is_empty()
            || !queued_funcs.is_empty()
            || !pending_reached.is_empty()
            || !pending_reverse_output.is_empty()
        {
            while let Some(func) = pending_reached.pop() {
                if !processed_reached.insert(func) {
                    continue;
                }
                if function_scoped {
                    if !built_funcs.contains(&func) {
                        queued_funcs.insert(func);
                    }
                } else if let Some(file) = global.declaring_file(SymbolId::new(func.raw())) {
                    if !built_files.contains(&file) {
                        queued_files.insert(file);
                    }
                }
                let Some(edge_ids) = outgoing_edge_ids.get(&func) else {
                    continue;
                };
                for &edge_id in edge_ids {
                    let edge = &known_edges[edge_id];
                    admitted_edge_ids.insert(edge_id);
                    let compile_callee = !target_emissions_only
                        || target_set.contains(&edge.to)
                        || target_emission_requires_callee(global.as_ref(), &scoped_linkage, edge);
                    if compile_callee && reached_funcs.insert(edge.to) {
                        pending_reached.push(edge.to);
                    }
                }
            }

            while let Some(callee) = pending_reverse_output.pop() {
                if !processed_reverse_output.insert(callee) {
                    continue;
                }
                let Some(edge_ids) = incoming_edge_ids.get(&callee) else {
                    continue;
                };
                for &edge_id in edge_ids {
                    let edge = &known_edges[edge_id];
                    if !has_summary_output(global.as_ref(), edge.from) {
                        continue;
                    }
                    admitted_edge_ids.insert(edge_id);
                    if reverse_output_funcs.insert(edge.from) {
                        pending_reverse_output.push(edge.from);
                    }
                    if reached_funcs.insert(edge.from) {
                        pending_reached.push(edge.from);
                    }
                }
            }

            if queued_files.is_empty() && queued_funcs.is_empty() {
                continue;
            }
            let mut requested_funcs: Vec<FuncId> = queued_funcs.drain().collect();
            requested_funcs.retain(|func| !built_funcs.contains(func));
            requested_funcs.sort_unstable_by_key(|func| func.raw());
            requested_funcs.dedup();

            let mut batch: Vec<FileId> = if function_scoped {
                requested_funcs
                    .iter()
                    .filter_map(|func| global.declaring_file(SymbolId::new(func.raw())))
                    .collect()
            } else {
                queued_files.drain().collect()
            };
            if !function_scoped {
                batch.retain(|file| !built_files.contains(file));
            }
            batch.sort_unstable_by_key(|file| file.raw());
            batch.dedup();
            if batch.is_empty() || (function_scoped && requested_funcs.is_empty()) {
                continue;
            }

            let source_bytes: Vec<u64> = batch
                .iter()
                .map(|file| {
                    self.inner
                        .db
                        .vfs()
                        .snapshot(*file)
                        .map_or(0, |snapshot| snapshot.text.len() as u64)
                })
                .collect();
            for range in bonsai_common::resources::compiler_weighted_batches(
                &source_bytes,
                rayon::current_num_threads(),
            ) {
                let files = &batch[range];
                let funcs: Vec<FuncId> = if function_scoped {
                    let files: AHashSet<FileId> = files.iter().copied().collect();
                    requested_funcs
                        .iter()
                        .copied()
                        .filter(|func| {
                            global
                                .declaring_file(SymbolId::new(func.raw()))
                                .is_some_and(|file| files.contains(&file))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let aliases_for_file =
                    |file| bonsai_resolve::alias_map_for_file(&self.inner.db.imports_for_uncached(file));
                let alias_targets_for_file = |file| {
                    bonsai_lang_api::alias_map_from_import_specs(&self.inner.db.imports_for_uncached(file))
                        .into_iter()
                        .collect()
                };
                let projected_linkage = parking_lot::Mutex::new(Vec::new());
                let body_for_file = |file| {
                    let index = self
                        .inner
                        .db
                        .decl_index_remapped_to_headers(global.as_ref(), file);
                    if function_scoped {
                        if let Some(index) = index.as_ref() {
                            projected_linkage
                                .lock()
                                .extend(global.project_linkage_from_remapped_file(index));
                        }
                    }
                    index
                };
                let batch_graph = if function_scoped {
                    bonsai_callgraph::ResolvedCallGraph::build_with_file_semantics_for_funcs_streaming_with_context(
                        global.as_ref(),
                        aliases_for_file,
                        alias_targets_for_file,
                        &funcs,
                        &callgraph_context,
                        body_for_file,
                    )
                } else {
                    bonsai_callgraph::ResolvedCallGraph::build_with_file_semantics_for_files_streaming_with_context(
                        global.as_ref(),
                        aliases_for_file,
                        alias_targets_for_file,
                        files,
                        &callgraph_context,
                        body_for_file,
                    )
                };
                scoped_linkage.extend(projected_linkage.into_inner());
                for edge in &batch_graph.inner().edges {
                    if max_precision.is_some_and(|max| edge.precision > max) {
                        continue;
                    }
                    let edge_id = known_edges.len();
                    known_edges.push(edge.clone());
                    outgoing_edge_ids.entry(edge.from).or_default().push(edge_id);
                    incoming_edge_ids.entry(edge.to).or_default().push(edge_id);

                    // A fact whose endpoint was processed before this caller
                    // file existed must consume the new edge immediately.
                    if processed_reached.contains(&edge.from) {
                        admitted_edge_ids.insert(edge_id);
                        let compile_callee = !target_emissions_only
                            || target_set.contains(&edge.to)
                            || target_emission_requires_callee(global.as_ref(), &scoped_linkage, edge);
                        if compile_callee && reached_funcs.insert(edge.to) {
                            pending_reached.push(edge.to);
                        }
                    }
                    if processed_reverse_output.contains(&edge.to)
                        && has_summary_output(global.as_ref(), edge.from)
                    {
                        admitted_edge_ids.insert(edge_id);
                        if reverse_output_funcs.insert(edge.from) {
                            pending_reverse_output.push(edge.from);
                        }
                        if reached_funcs.insert(edge.from) {
                            pending_reached.push(edge.from);
                        }
                    }
                }
                if function_scoped {
                    built_funcs.extend(funcs);
                } else {
                    built_files.extend(files.iter().copied());
                }
            }
        }

        let mut return_corridor_funcs: AHashSet<FuncId> = AHashSet::new();
        if !target_set.is_empty() {
            let mut target_callers_by_callee: AHashMap<FuncId, Vec<usize>> = AHashMap::new();
            for &target in &target_set {
                if let Some(edge_ids) = outgoing_edge_ids.get(&target) {
                    for &edge_id in edge_ids {
                        let edge = &known_edges[edge_id];
                        if max_precision.is_none_or(|max| edge.precision <= max) {
                            target_callers_by_callee.entry(edge.to).or_default().push(edge_id);
                        }
                    }
                }
            }
            for edge_ids in target_callers_by_callee.values_mut() {
                edge_ids.sort_by_key(|edge_id| {
                    let edge = &known_edges[*edge_id];
                    (
                        edge.from.raw(),
                        edge.span.file.raw(),
                        edge.span.start,
                        edge.span.end,
                        edge.precision.rank(),
                    )
                });
            }

            // A target can consume the return of another target, so one
            // unordered pass over candidate edges is neither complete nor
            // deterministic. Compile the exact reverse target-call relation
            // to a least fixed point. This is a finite compiler worklist:
            // every function is processed once and no depth/work cap changes
            // the admitted graph.
            let mut pending: Vec<FuncId> = reached_funcs.iter().copied().collect();
            pending.sort_unstable_by_key(|func| std::cmp::Reverse(func.raw()));
            let mut processed = AHashSet::default();
            while let Some(callee) = pending.pop() {
                if !processed.insert(callee) {
                    continue;
                }
                let Some(edges) = target_callers_by_callee.get(&callee) else {
                    continue;
                };
                for &edge_id in edges {
                    let edge = &known_edges[edge_id];
                    admitted_edge_ids.insert(edge_id);
                    return_corridor_funcs.insert(edge.from);
                    return_corridor_funcs.insert(edge.to);
                    if reached_funcs.insert(edge.from) {
                        pending.push(edge.from);
                    }
                }
            }
        }

        // Compact the compiler relation in place before allocating final
        // adjacency. This moves no edge payload into a duplicate vector and
        // releases the temporary reachability indexes before the resolved
        // graph builds its canonical caller/callee tables.
        let mut edge_id = 0usize;
        known_edges.retain(|_| {
            let admitted = admitted_edge_ids.contains(&edge_id);
            edge_id += 1;
            admitted
        });
        drop(admitted_edge_ids);
        drop(outgoing_edge_ids);
        drop(incoming_edge_ids);
        let merged = bonsai_callgraph::CallGraph::from_unique_edges(known_edges);

        let reached_target_set: AHashSet<FuncId> = target_set
            .iter()
            .copied()
            .filter(|target| reached_funcs.contains(target))
            .collect();
        let relevant_funcs: AHashSet<FuncId> = if target_set.is_empty() || reached_target_set.is_empty() {
            reached_funcs.clone()
        } else {
            let mut can_reach_target = reached_target_set.clone();
            let mut stack: Vec<FuncId> = reached_target_set.iter().copied().collect();
            while let Some(func) = stack.pop() {
                for edge in merged.callers(func) {
                    if !reached_funcs.contains(&edge.from) {
                        continue;
                    }
                    if can_reach_target.insert(edge.from) {
                        stack.push(edge.from);
                    }
                }
            }
            reached_funcs.intersection(&can_reach_target).copied().collect()
        };
        let mut relevant_funcs = relevant_funcs;
        relevant_funcs.extend(return_corridor_funcs);
        let mut edges_by_from: AHashMap<FuncId, Vec<usize>> = AHashMap::new();
        for (edge_id, edge) in merged.edges.iter().enumerate() {
            if reached_funcs.contains(&edge.to) {
                edges_by_from.entry(edge.from).or_default().push(edge_id);
            }
        }
        let mut provider_stack: Vec<FuncId> = relevant_funcs.iter().copied().collect();
        while let Some(func) = provider_stack.pop() {
            let Some(edge_ids) = edges_by_from.get(&func) else {
                continue;
            };
            for &edge_id in edge_ids {
                let edge = &merged.edges[edge_id];
                let callee = edge.to;
                let needs_provider = if target_emissions_only {
                    target_emission_requires_callee(global.as_ref(), &scoped_linkage, edge)
                } else {
                    has_summary_output(global.as_ref(), callee)
                };
                if relevant_funcs.contains(&callee) || !needs_provider {
                    continue;
                }
                relevant_funcs.insert(callee);
                provider_stack.push(callee);
            }
        }
        extend_func_set_with_semantic_callback_dispatchers_in_call_graph(
            &mut relevant_funcs,
            &reached_target_set,
            global.as_ref(),
            &merged,
            max_precision,
        );
        let semantic_funcs = relevant_funcs;

        let mut filtered = bonsai_callgraph::CallGraph::new();
        for edge in &merged.edges {
            if semantic_funcs.contains(&edge.from)
                && (semantic_funcs.contains(&edge.to) || target_emissions_only)
            {
                filtered.add_edge(edge.clone());
            }
        }
        let mut files: Vec<FileId> = semantic_funcs
            .iter()
            .filter_map(|func| global.declaring_file(SymbolId::new(func.raw())))
            .collect();
        files.sort_by_key(|file| file.raw());
        files.dedup();
        let mut funcs: Vec<FuncId> = semantic_funcs.into_iter().collect();
        funcs.sort_by_key(|func| func.raw());
        funcs.dedup();
        let reached_targets = target_set
            .iter()
            .filter(|target| reached_funcs.contains(target))
            .count();
        if function_scoped {
            let mut header = Arc::try_unwrap(global)
                .unwrap_or_else(|_| panic!("scoped compiler header unexpectedly shared"));
            header.install_projected_linkage(scoped_linkage);
            global = Arc::new(header);
            let mut slot = self.inner.compiler_headers.write();
            if slot.is_none() {
                *slot = Some(global.clone());
            }
        }
        let nodes = funcs
            .iter()
            .filter_map(|func| {
                global
                    .decl_of(SymbolId::new(func.raw()))
                    .map(|decl| bonsai_callgraph::CallGraphNode {
                        func: *func,
                        name: decl.name.clone().into_boxed_str(),
                        qualified_name: decl
                            .qualified_name
                            .as_deref()
                            .map(|name| name.to_string().into_boxed_str()),
                        kind: decl.kind,
                        file: decl.name_span.file,
                        name_span: decl.name_span,
                    })
            })
            .collect();
        SourceReachableCallGraph {
            graph: Arc::new(bonsai_callgraph::ResolvedCallGraph::from_persisted_parts(
                nodes,
                filtered.edges,
                Vec::new(),
                Vec::new(),
            )),
            linkage_index: global,
            files,
            funcs,
            reached_targets,
        }
    }

    /// Build the workspace-wide IDG once and seed it onto
    /// [`AnalyzerDb`] so consumers can fetch it via
    /// [`AnalyzerDb::idg_service`]. Idempotent — calling twice with
    /// the same workspace state is a no-op (the seed is monotonic).
    ///
    /// Built from the cached global index + resolved call graph. The
    /// transfer pass parallelises across functions; the stitching
    /// phase serialises. Returns the populated service handle so
    /// callers can immediately query it without re-fetching from db.
    pub fn build_and_seed_idg_service(&self) -> Arc<bonsai_idg::IdgQueryService> {
        // Avoid recomputing if a peer thread already seeded the slot.
        if let Some(svc) = self.inner.db.idg_service() {
            return svc;
        }
        let _build_guard = self.inner.idg_build_serial.lock();
        // The first caller may have completed while this caller waited.
        if let Some(svc) = self.inner.db.idg_service() {
            return svc;
        }
        let global = self.compiler_linkage_index();
        // The IDG references symbols by their global-index id, which
        // is content-derived: any file content change can renumber
        // ids in the new run. Folding a workspace-wide content
        // fingerprint into the pipeline hash makes the factstore
        // header reject a sidecar whose source tree no longer
        // matches, even when no `refresh_file_from_disk` ran inside
        // bonsai-ninja (e.g. `git checkout` between two CLI calls).
        let root_path = self.root_path();
        let pipeline_hash = self.cached_idg_workspace_pipeline_hash(root_path.as_deref());
        let transfer_options = default_workspace_idg_transfer_options(&self.inner.db);
        // Try to hydrate the workspace IDG from the on-disk sidecar
        // before paying for a fresh build. Cold rebuild on Redis `src/`
        // takes >1 minute and dominates `bonsai-ninja security ...`
        // latency; the sidecar reduces it to a single mmap + decode
        // for subsequent invocations against the same content-hashed
        // workspace.
        let use_idg_sidecar = self.is_complete_workspace_index();
        if use_idg_sidecar {
            if let Some(root) = root_path.as_deref() {
                match self.load_idg_sidecar(root) {
                    Ok(Some(_)) => {
                        if let Some(service) = self.inner.db.idg_service() {
                            return service;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(
                            path = %bonsai_idg::workspace::idg_sidecar_path(root).display(),
                            error = %error,
                            "workspace IDG sidecar load failed; rebuilding exact graph"
                        );
                    }
                }
            }
        } else {
            tracing::debug!(
                complete_workspace = self.is_complete_workspace_index(),
                "skipping workspace IDG sidecar load"
            );
        }
        // Own this target before starting expensive compiler work. A peer
        // process may have published the graph while this process waited, so
        // recheck under the advisory lock before rebuilding.
        let persistence = if use_idg_sidecar {
            root_path.as_deref().and_then(|root| {
                let sidecar = bonsai_idg::workspace::idg_sidecar_path(root);
                match IdgSidecarWriteGuard::acquire(&sidecar) {
                    Ok(guard) => {
                        if self.load_idg_sidecar(root).ok().flatten().is_some() {
                            return None;
                        }
                        Some((sidecar, guard))
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %sidecar.display(),
                            error = %error,
                            "workspace IDG writer lock unavailable; building an exact resident graph"
                        );
                        None
                    }
                }
            })
        } else {
            None
        };
        if let Some(service) = self.inner.db.idg_service() {
            return service;
        }
        let cg = self.cached_resolved_call_graph();
        // Thread per-file alias maps into the IDG resolver so
        // `import { persist as persistEnvelope }` style alias
        // renames still resolve to the underlying callee. The
        // callgraph already used these maps; the IDG layer now
        // reuses them to keep its name filter from rejecting
        // alias-rewritten call sites.
        let db = &self.inner.db;
        let semantics = bonsai_taint::compiler_idg_file_semantics(db);
        let ws = bonsai_idg::workspace_adapter::build_streaming_with_file_semantics_and_options(
            global.as_ref(),
            cg.as_ref(),
            semantics,
            &transfer_options,
            |file| {
                self.inner
                    .db
                    .decl_index_remapped_to_headers(global.as_ref(), file)
            },
        );
        // Persist before constructing the query service so a subsequent
        // open warm-starts. Failures (read-only filesystem, full disk)
        // are tracing-logged but not surfaced — the in-memory IDG is
        // still valid for this run.
        if let Some((sidecar, _guard)) = persistence.as_ref() {
            if let Err(error) = ws.save_to_disk(sidecar, pipeline_hash) {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %error,
                    "workspace IDG save_to_disk failed"
                );
            }
        } else if !use_idg_sidecar {
            tracing::debug!(
                complete_workspace = self.is_complete_workspace_index(),
                "skipping workspace IDG sidecar save"
            );
        }
        // The graph has consumed every resolver-linkage fact. Move the same
        // stable symbol table into header-only form before the query service
        // owns it, rather than keeping millions of call summaries beside the
        // IDG. No syntax or graph fact is changed by this ownership boundary.
        self.release_compiler_linkage_cache();
        // Most callers let the compiler phase own the last linkage handle, so
        // this strips call summaries in place. The API is also callable while
        // an independent syntax consumer still holds an immutable generation;
        // that reader must remain valid, so fall back to one header clone
        // instead of turning a legal concurrent/read-before-build pattern into
        // a process-wide panic.
        let global = Arc::try_unwrap(global)
            .unwrap_or_else(|shared| (*shared).clone())
            .into_header_index();
        let global = Arc::new(global);
        *self.inner.compiler_headers.write() = Some(global.clone());
        let service = Arc::new(bonsai_idg::IdgQueryService::new(Arc::new(ws), global));
        self.inner.db.set_idg_service(service.clone());
        service
    }

    /// Build and seed the workspace IDG when the workspace index is complete,
    /// allowing every workspace size to reuse the streamed sidecar.
    pub fn build_and_seed_persisted_idg_service(&self) -> Option<Arc<bonsai_idg::IdgQueryService>> {
        if !self.is_complete_workspace_index() {
            tracing::debug!("skipping workspace IDG prewarm because the workspace index is scoped");
            return None;
        }
        Some(self.build_and_seed_idg_service())
    }

    /// Build and persist the complete default workspace IDG without retaining
    /// it in the live query-service cache.
    ///
    /// Explicit compiler prewarm only needs a validated sidecar for future
    /// processes. Keeping the multi-gigabyte graph resident while subsequent
    /// callgraph/retrieval artifacts are written makes peak memory additive.
    /// Query paths continue to use [`Self::build_and_seed_persisted_idg_service`]
    /// and load the exact same sidecar when they need an in-process service.
    pub fn build_and_persist_idg_sidecar(&self) -> bonsai_idg::IdgResult<Option<usize>> {
        if !self.is_complete_workspace_index() {
            tracing::debug!("skipping workspace IDG persistence because the workspace index is scoped");
            return Ok(None);
        }
        let Some(root) = self.root_path() else {
            return Ok(None);
        };
        let _build_guard = self.inner.idg_build_serial.lock();
        let pipeline_hash = self.cached_idg_workspace_pipeline_hash(Some(&root));
        let sidecar = bonsai_idg::workspace::idg_sidecar_path(&root);
        let _sidecar_guard = IdgSidecarWriteGuard::acquire(&sidecar)?;
        if let Ok(segment_count) =
            bonsai_idg::workspace::IdgWorkspace::validate_accelerated_sidecar_layout_with_pipeline(
                &sidecar,
                pipeline_hash,
            )
        {
            return Ok(Some(segment_count));
        }
        let call_graph_path = callgraph_sidecar::callgraph_sidecar_path(&root);
        let partitioned_call_graph =
            match callgraph_sidecar::CallgraphQueryService::open_checked(&call_graph_path, &self.inner.db) {
                Ok(service) => Some(service),
                Err(error) => {
                    tracing::warn!(
                        path = %call_graph_path.display(),
                        error = %error,
                        "partitioned IDG callgraph relation unavailable; rebuilding resident exact graph"
                    );
                    None
                }
            };
        let resident_call_graph = partitioned_call_graph
            .is_none()
            .then(|| self.cached_resolved_call_graph());
        let call_graph: &dyn bonsai_idg::workspace_adapter::CallGraphRelation =
            if let Some(service) = partitioned_call_graph.as_ref() {
                service
            } else {
                resident_call_graph
                    .as_deref()
                    .expect("resident callgraph built after partitioned sidecar miss")
            };
        let global = self.compiler_linkage_index();
        let transfer_options = default_workspace_idg_transfer_options(&self.inner.db);
        let semantics = bonsai_taint::compiler_idg_file_semantics(&self.inner.db);
        let workspace =
            bonsai_idg::workspace_adapter::build_for_persistence_streaming_with_callgraph_relation_and_file_semantics_and_options(
                global.as_ref(),
                call_graph,
                semantics,
                &transfer_options,
                &sidecar,
                |file| {
                    self.inner
                        .db
                        .decl_index_remapped_to_headers(global.as_ref(), file)
                },
            )?;
        let segment_count = workspace.segment_count();
        // IDG stitching has consumed every resolver call-linkage row. Retain
        // only stable declaration/type headers while compiling the query
        // accelerator; keeping the resolver payload beside contextual and
        // symbolic fixed-point relations made cold prewarm peak needlessly
        // additive on large workspaces.
        drop(resident_call_graph);
        drop(partitioned_call_graph);
        self.release_compiler_linkage_cache();
        self.release_exact_body_cache();
        self.release_decl_name_index_cache();
        self.inner.db.release_global_index();
        let global = Arc::try_unwrap(global)
            .unwrap_or_else(|shared| (*shared).clone())
            .into_header_index();
        let global = Arc::new(global);
        // Compile the default query representation from the exact graph while
        // its compiler spool is still available, then release every runtime
        // owner before persistence. Warm commands can install this immutable
        // derived fixed point directly instead of decoding every body and
        // rebuilding the same workspace-wide CSR on first use.
        let workspace = Arc::new(workspace);
        let service = bonsai_idg::IdgQueryService::new(Arc::clone(&workspace), global);
        let accelerator = service.compile_default_query_accelerator()?;
        let Ok(mut workspace) = Arc::try_unwrap(workspace) else {
            unreachable!("query-accelerator compiler retained an IDG workspace owner")
        };
        workspace.install_query_accelerator(accelerator);
        workspace.save_into_disk(&sidecar, pipeline_hash)?;
        Ok(Some(segment_count))
    }

    /// Build a workspace IDG with caller-supplied transfer options and cache
    /// it under those exact semantics.
    ///
    /// Configured transfer options use a distinct sidecar keyed by a
    /// stable fingerprint of those options. The default IDG sidecar uses the
    /// canonical adapter-capability compiler semantics, while additional
    /// transfer options can come from an editable security rulepack. A
    /// configured graph never replaces [`AnalyzerDb::idg_service`], whose
    /// invariant is the full-workspace graph with default transfer semantics.
    pub fn build_and_seed_idg_service_with_transfer_options(
        &self,
        transfer_options: &bonsai_idg::TransferOptions,
    ) -> Arc<bonsai_idg::IdgQueryService> {
        let transfer_options = transfer_options.clone().canonicalized();
        if transfer_options.is_empty() {
            return self.build_and_seed_idg_service();
        }
        let transfer_hash = idg_transfer_options_fingerprint(&transfer_options);
        if let Some(service) = self.inner.db.idg_service_for_semantics(transfer_hash) {
            return service;
        }
        let _build_guard = self.inner.idg_build_serial.lock();
        if let Some(service) = self.inner.db.idg_service_for_semantics(transfer_hash) {
            return service;
        }
        let global = self.compiler_linkage_index();
        let root_path = self.root_path();
        let pipeline_hash = self.cached_idg_transfer_pipeline_hash(root_path.as_deref(), transfer_hash);
        let use_idg_sidecar = self.is_complete_workspace_index();
        if use_idg_sidecar {
            if let Some(root) = root_path.as_deref() {
                let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, transfer_hash);
                if let Ok(Some(service)) =
                    bonsai_idg::IdgQueryService::load_from_disk(&sidecar, pipeline_hash, global.clone())
                {
                    let service = Arc::new(service);
                    let service = self
                        .inner
                        .db
                        .set_idg_service_for_semantics(transfer_hash, service);
                    return service;
                }
            }
        } else {
            tracing::debug!(
                complete_workspace = self.is_complete_workspace_index(),
                "skipping workspace transfer IDG sidecar load"
            );
        }
        let persistence = if use_idg_sidecar {
            root_path.as_deref().and_then(|root| {
                let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, transfer_hash);
                match IdgSidecarWriteGuard::acquire(&sidecar) {
                    Ok(guard) => {
                        if let Ok(Some(service)) = bonsai_idg::IdgQueryService::load_from_disk(
                            &sidecar,
                            pipeline_hash,
                            global.clone(),
                        ) {
                            self.inner
                                .db
                                .set_idg_service_for_semantics(transfer_hash, Arc::new(service));
                            return None;
                        }
                        Some((sidecar, guard))
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %sidecar.display(),
                            error = %error,
                            "workspace transfer IDG writer lock unavailable; building an exact resident graph"
                        );
                        None
                    }
                }
            })
        } else {
            None
        };
        if let Some(service) = self.inner.db.idg_service_for_semantics(transfer_hash) {
            return service;
        }
        let cg = self.cached_resolved_call_graph();
        let db = &self.inner.db;
        let semantics = bonsai_taint::compiler_idg_file_semantics(db);
        let ws = bonsai_idg::workspace_adapter::build_streaming_with_file_semantics_and_options(
            global.as_ref(),
            cg.as_ref(),
            semantics,
            &transfer_options,
            |file| {
                self.inner
                    .db
                    .decl_index_remapped_to_headers(global.as_ref(), file)
            },
        );
        if let Some((sidecar, _guard)) = persistence.as_ref() {
            if let Err(error) = ws.save_to_disk(sidecar, pipeline_hash) {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %error,
                    "workspace transfer IDG save_to_disk failed"
                );
            }
        } else if !use_idg_sidecar {
            tracing::debug!(
                complete_workspace = self.is_complete_workspace_index(),
                "skipping workspace transfer IDG sidecar save"
            );
        }
        let service = Arc::new(bonsai_idg::IdgQueryService::new(Arc::new(ws), global));
        self.inner
            .db
            .set_idg_service_for_semantics(transfer_hash, service)
    }

    /// Build a file-scoped workspace IDG with caller-supplied transfer
    /// options and cache it under that exact scope and semantics.
    ///
    /// Security production scans use this to keep excluded files out
    /// of the semantic graph before transfer/stitching. The persisted
    /// sidecar key includes both transfer options and the sorted file
    /// scope, so a scoped graph can never be loaded as the full graph
    /// or as a different scoped graph. The scoped service is deliberately not
    /// installed as [`AnalyzerDb::idg_service`]: later export, inspect, and
    /// taint queries must never mistake a partial graph for the canonical
    /// full-workspace default.
    pub fn build_and_seed_idg_service_with_transfer_options_for_files(
        &self,
        transfer_options: &bonsai_idg::TransferOptions,
        included_files: &[FileId],
    ) -> Arc<bonsai_idg::IdgQueryService> {
        let transfer_options = transfer_options.clone().canonicalized();
        let transfer_hash = idg_transfer_options_fingerprint(&transfer_options);
        let scope_hash = idg_file_scope_fingerprint(included_files);
        let scoped_hash = idg_scoped_semantics_fingerprint(transfer_hash, scope_hash, None, None);
        if let Some(service) = self.inner.db.idg_service_for_semantics(scoped_hash) {
            return service;
        }
        let _build_guard = self.inner.idg_build_serial.lock();
        if let Some(service) = self.inner.db.idg_service_for_semantics(scoped_hash) {
            return service;
        }
        let global = self.compiler_linkage_index();
        let root_path = self.root_path();
        let pipeline_hash = self.cached_idg_transfer_pipeline_hash(root_path.as_deref(), scoped_hash);
        if let Some(root) = root_path.as_deref() {
            let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, scoped_hash);
            if let Ok(Some(service)) =
                bonsai_idg::IdgQueryService::load_from_disk(&sidecar, pipeline_hash, global.clone())
            {
                let service = Arc::new(service);
                let service = self.inner.db.set_idg_service_for_semantics(scoped_hash, service);
                return service;
            }
        }
        let persistence = root_path.as_deref().and_then(|root| {
            let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, scoped_hash);
            match IdgSidecarWriteGuard::acquire(&sidecar) {
                Ok(guard) => {
                    if let Ok(Some(service)) =
                        bonsai_idg::IdgQueryService::load_from_disk(&sidecar, pipeline_hash, global.clone())
                    {
                        self.inner
                            .db
                            .set_idg_service_for_semantics(scoped_hash, Arc::new(service));
                        return None;
                    }
                    Some((sidecar, guard))
                }
                Err(error) => {
                    tracing::warn!(
                        path = %sidecar.display(),
                        error = %error,
                        "workspace scoped transfer IDG writer lock unavailable; building an exact resident graph"
                    );
                    None
                }
            }
        });
        if let Some(service) = self.inner.db.idg_service_for_semantics(scoped_hash) {
            return service;
        }
        let cg = build_resolved_call_graph_snapshot_for_files(&self.inner.db, included_files);
        let db = &self.inner.db;
        let semantics = bonsai_taint::compiler_idg_file_semantics(db);
        let ws = bonsai_idg::workspace_adapter::build_streaming_with_file_semantics_and_options_for_files(
            global.as_ref(),
            &cg,
            semantics,
            &transfer_options,
            included_files,
            |file| {
                self.inner
                    .db
                    .decl_index_remapped_to_headers(global.as_ref(), file)
            },
        );
        if let Some((sidecar, _guard)) = persistence.as_ref() {
            if let Err(error) = ws.save_to_disk(sidecar, pipeline_hash) {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %error,
                    "workspace scoped transfer IDG save_to_disk failed"
                );
            }
        }
        let service = Arc::new(bonsai_idg::IdgQueryService::new(Arc::new(ws), global));
        self.inner.db.set_idg_service_for_semantics(scoped_hash, service)
    }

    /// Build a file-scoped workspace IDG using an already resolved semantic
    /// call graph.
    ///
    /// Source-to-sink security scans compute a source-reachable graph
    /// first. Reusing that graph here avoids rebuilding workspace-wide
    /// call metadata and keeps IDG transfer scoped to the semantic
    /// region that can actually participate in findings. The returned handle
    /// remains query-local and never replaces the canonical workspace-global
    /// default service.
    pub fn build_and_seed_idg_service_with_transfer_options_for_files_and_call_graph(
        &self,
        transfer_options: &bonsai_idg::TransferOptions,
        included_files: &[FileId],
        included_funcs: &[FuncId],
        call_graph: &bonsai_callgraph::ResolvedCallGraph,
    ) -> Arc<bonsai_idg::IdgQueryService> {
        self.build_idg_service_with_transfer_options_for_files_and_call_graph(
            transfer_options,
            included_files,
            included_funcs,
            call_graph,
        )
    }

    /// Build one exact file/function-scoped configured IDG sidecar and open it
    /// through the paged query service.
    ///
    /// Broad security scans can have thousands of overlapping source/sink
    /// corridors. Rebuilding a resident graph for each corridor repeats the
    /// same compiler work and scales with query count rather than program
    /// size. This path lowers each selected Tree-sitter compiler object once,
    /// streams typed stitch records to disk, and reuses the resulting graph
    /// for every closure. The file/function scope and transfer semantics are
    /// all part of the sidecar identity.
    pub fn build_and_seed_persisted_idg_service_with_transfer_options_for_files_and_call_graph(
        &self,
        transfer_options: &bonsai_idg::TransferOptions,
        included_files: &[FileId],
        included_funcs: &[FuncId],
        call_graph: &bonsai_callgraph::ResolvedCallGraph,
    ) -> Arc<bonsai_idg::IdgQueryService> {
        let transfer_options = transfer_options.clone().canonicalized();
        let transfer_hash = idg_transfer_options_fingerprint(&transfer_options);
        let file_scope_hash = idg_file_scope_fingerprint(included_files);
        let func_scope_hash = idg_func_scope_fingerprint(included_funcs);
        let call_graph_hash = idg_call_graph_fingerprint(call_graph);
        let scoped_hash = idg_scoped_semantics_fingerprint(
            transfer_hash,
            file_scope_hash,
            Some(func_scope_hash),
            Some(call_graph_hash),
        );
        if let Some(service) = self.inner.db.idg_service_for_semantics(scoped_hash) {
            return service;
        }

        let _build_guard = self.inner.idg_build_serial.lock();
        if let Some(service) = self.inner.db.idg_service_for_semantics(scoped_hash) {
            return service;
        }

        let global = self.compiler_linkage_index();
        let Some(root) = self.root_path() else {
            let service = self.build_idg_service_with_transfer_options_for_files_and_call_graph(
                &transfer_options,
                included_files,
                included_funcs,
                call_graph,
            );
            return self.inner.db.set_idg_service_for_semantics(scoped_hash, service);
        };
        let pipeline_hash = self.cached_idg_transfer_pipeline_hash(Some(&root), scoped_hash);
        let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(&root, scoped_hash);
        if let Ok(Some(service)) =
            bonsai_idg::IdgQueryService::load_from_disk(&sidecar, pipeline_hash, global.clone())
        {
            return self
                .inner
                .db
                .set_idg_service_for_semantics(scoped_hash, Arc::new(service));
        }
        let _sidecar_guard = match IdgSidecarWriteGuard::acquire(&sidecar) {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %error,
                    "scoped transfer IDG writer lock unavailable; falling back to an exact resident graph"
                );
                let service = self.build_idg_service_with_transfer_options_for_files_and_call_graph(
                    &transfer_options,
                    included_files,
                    included_funcs,
                    call_graph,
                );
                return self.inner.db.set_idg_service_for_semantics(scoped_hash, service);
            }
        };
        // The lock may have blocked behind another analyzer that published the
        // same immutable generation. Reuse it instead of compiling twice.
        if let Ok(Some(service)) =
            bonsai_idg::IdgQueryService::load_from_disk(&sidecar, pipeline_hash, global.clone())
        {
            return self
                .inner
                .db
                .set_idg_service_for_semantics(scoped_hash, Arc::new(service));
        }

        let semantics = bonsai_taint::compiler_idg_file_semantics(&self.inner.db);
        let persisted = bonsai_idg::workspace_adapter::
            build_for_persistence_streaming_with_file_semantics_and_options_for_files_and_funcs(
                global.as_ref(),
                call_graph,
                semantics,
                &transfer_options,
                included_files,
                included_funcs,
                &sidecar,
                |file| {
                    self.inner
                        .db
                        .decl_index_remapped_to_headers(global.as_ref(), file)
                },
            )
            .and_then(|workspace| workspace.save_into_disk(&sidecar, pipeline_hash))
            .and_then(|()| {
                bonsai_idg::IdgQueryService::load_from_disk(
                    &sidecar,
                    pipeline_hash,
                    global.clone(),
                )
            });
        match persisted {
            Ok(Some(service)) => self
                .inner
                .db
                .set_idg_service_for_semantics(scoped_hash, Arc::new(service)),
            Ok(None) => {
                tracing::warn!(
                    path = %sidecar.display(),
                    "scoped transfer IDG sidecar did not reopen; falling back to an exact resident graph"
                );
                let service = self.build_idg_service_with_transfer_options_for_files_and_call_graph(
                    &transfer_options,
                    included_files,
                    included_funcs,
                    call_graph,
                );
                self.inner.db.set_idg_service_for_semantics(scoped_hash, service)
            }
            Err(error) => {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %error,
                    "scoped transfer IDG persistence failed; falling back to an exact resident graph"
                );
                let service = self.build_idg_service_with_transfer_options_for_files_and_call_graph(
                    &transfer_options,
                    included_files,
                    included_funcs,
                    call_graph,
                );
                self.inner.db.set_idg_service_for_semantics(scoped_hash, service)
            }
        }
    }

    /// Build a file/function-scoped workspace IDG using an already
    /// resolved semantic call graph without installing it as the
    /// workspace-global service. Large security scans use this for
    /// short-lived source-corridor batches so peak RSS is bounded by
    /// the active batch, not the whole source-reachable region.
    pub fn build_idg_service_with_transfer_options_for_files_and_call_graph(
        &self,
        transfer_options: &bonsai_idg::TransferOptions,
        included_files: &[FileId],
        included_funcs: &[FuncId],
        call_graph: &bonsai_callgraph::ResolvedCallGraph,
    ) -> Arc<bonsai_idg::IdgQueryService> {
        let transfer_options = transfer_options.clone().canonicalized();
        let global = self.compiler_linkage_index();
        let db = &self.inner.db;
        let semantics = bonsai_taint::compiler_idg_file_semantics(db);
        let ws = bonsai_idg::workspace_adapter::build_streaming_with_file_semantics_and_options_for_files_and_funcs(
            global.as_ref(),
            call_graph,
            semantics,
            &transfer_options,
            included_files,
            included_funcs,
            |file| {
                self.inner
                    .db
                    .decl_index_remapped_to_headers(global.as_ref(), file)
            },
        );
        Arc::new(bonsai_idg::IdgQueryService::new(Arc::new(ws), global))
    }

    /// Return the workspace root path if we have one to serialise
    /// sidecars beside. Synthetic / in-memory workspaces (tests,
    /// SDK ad-hoc opens) have no root; the IDG sidecar path then
    /// resolves to `None` and persistence is skipped silently.
    fn root_path(&self) -> Option<std::path::PathBuf> {
        self.inner.idg_sidecar_root.lock().clone()
    }

    fn sidecar_source_inputs(&self) -> std::io::Result<Arc<Vec<(u32, String, u64)>>> {
        let mut slot = self.inner.sidecar_source_inputs.lock();
        if let Some(inputs) = slot.as_ref() {
            return Ok(Arc::clone(inputs));
        }
        let inputs = if self.is_complete_workspace_index() {
            let mut inputs = self
                .inner
                .vfs
                .all_files()
                .into_iter()
                .map(|file| {
                    let path = self
                        .inner
                        .vfs
                        .path(file)
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let snapshot = self
                        .inner
                        .vfs
                        .snapshot(file)
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    Ok((
                        file.raw(),
                        path.to_string_lossy().into_owned(),
                        bonsai_hash::fnv1a_bytes64(snapshot.text.as_bytes()),
                    ))
                })
                .collect::<std::io::Result<Vec<_>>>()?;
            inputs.sort_unstable_by_key(|(file, _, _)| *file);
            inputs
        } else {
            let root = self.root_path().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "scoped workspace has no root for sidecar validation",
                )
            })?;
            read_supported_source_file_fingerprints(&canonical_workspace_root(&root), &self.inner.registry)
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .into_iter()
                .enumerate()
                .map(|(ordinal, source)| {
                    Ok((
                        u32::try_from(ordinal).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "workspace contains more than u32::MAX supported sources",
                            )
                        })?,
                        source.path.to_string_lossy().into_owned(),
                        source.hash,
                    ))
                })
                .collect::<std::io::Result<Vec<_>>>()?
        };
        let inputs = Arc::new(inputs);
        *slot = Some(Arc::clone(&inputs));
        Ok(inputs)
    }

    /// Content hashes for the complete source generation represented by this
    /// workspace.
    ///
    /// Exact query workspaces contain only the bodies selected for one
    /// compiler worklist, but retain the validated full-workspace source table
    /// used by persisted sidecars. Cache freshness and page replay must use
    /// that complete identity rather than mistaking the scoped body set for a
    /// new 10-file workspace.
    pub fn complete_source_content_hashes(&self) -> std::io::Result<Vec<(std::path::PathBuf, u64)>> {
        Ok(self
            .sidecar_source_inputs()?
            .iter()
            .map(|(_, path, hash)| (std::path::PathBuf::from(path), *hash))
            .collect())
    }

    /// Record the workspace root so [`Self::build_and_seed_idg_service`]
    /// can persist the IDG sidecar next to the other external cache files.
    /// Called by the `open*` family once the root path is known.
    fn set_idg_sidecar_root(&self, root: &std::path::Path) -> std::io::Result<()> {
        let canonical_root = canonical_workspace_root(root);
        cache_fingerprint::register_workspace_cache_root(&canonical_root)?;
        *self.inner.idg_sidecar_root.lock() = Some(canonical_root);
        Ok(())
    }

    /// Whether this workspace contains the complete supported source
    /// set for its recorded root. Scoped query workspaces deliberately
    /// index fewer files and therefore cannot safely write reusable
    /// whole-workspace sidecars.
    #[must_use]
    pub fn is_complete_workspace_index(&self) -> bool {
        *self.inner.complete_workspace_index.lock()
    }

    fn set_complete_workspace_index(&self, complete: bool) {
        *self.inner.complete_workspace_index.lock() = complete;
    }

    /// Drop persisted IDG sidecars after a file edit when no peer compiler
    /// owns them. Header fingerprints already reject stale generations; this
    /// best-effort cleanup only reclaims disk and must never unlink another
    /// process's active publication target.
    fn delete_idg_sidecar(&self) {
        if let Some(root) = self.root_path() {
            let remove_if_unowned = |path: &Path| match IdgSidecarWriteGuard::try_acquire(path) {
                Ok(_guard) => {
                    if let Err(error) = std::fs::remove_file(path) {
                        if error.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(
                                path = %path.display(),
                                error = %error,
                                "stale IDG sidecar cleanup failed"
                            );
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tracing::debug!(
                        path = %path.display(),
                        "skipping IDG sidecar cleanup owned by another compiler"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "could not establish IDG sidecar cleanup ownership"
                    );
                }
            };
            remove_if_unowned(&bonsai_idg::workspace::idg_sidecar_path(&root));
            let bonsai_dir = bonsai_common::workspace_bonsai_dir(&root);
            if let Ok(entries) = std::fs::read_dir(bonsai_dir) {
                for entry in entries.flatten() {
                    let Ok(file_type) = entry.file_type() else {
                        continue;
                    };
                    if !file_type.is_file() {
                        continue;
                    }
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.contains(".transfer.") && idg_persistence::idg_sidecar_family(&name).is_some() {
                        remove_if_unowned(&entry.path());
                    }
                }
            }
        }
    }

    /// Drop every derived cache that can observe stale workspace
    /// structure after a file edit, add, or removal. This is
    /// intentionally centralized so watch/SDK refresh, bulk ingest,
    /// and in-memory edits keep the same correctness contract.
    fn invalidate_after_file_change(&self, file: FileId) {
        let _taint_analysis_guard = self.inner.taint_analysis_serial.lock();
        let _idg_build_guard = self.inner.idg_build_serial.lock();
        self.invalidate_after_file_change_locked(file);
    }

    /// Invalidate derived state while the caller owns both semantic-generation
    /// guards. Mutating VFS contents and invalidating caches must be one
    /// critical section: acquiring the guards only after `Vfs::write` would
    /// let a concurrent compiler build observe a mixture of old indexes and
    /// new source text.
    fn invalidate_after_file_change_locked(&self, file: FileId) {
        self.inner.db.invalidate_file(file);
        // Dataflow tracks per-entry transitive file dependencies, so
        // retain unrelated in-memory facts while evicting entries that
        // actually observed this file. The cache closes any disk
        // sidecar reader internally because persisted stores are tied
        // to the pre-edit workspace fingerprint.
        self.inner.dataflow.invalidate_file(file);
        self.inner.flow_ids.invalidate_all();
        self.inner.value_flow.clear();
        self.inner.db.invalidate_idg_service();
        *self.inner.idg_pipeline_hash.lock() = None;
        self.delete_idg_sidecar();
        self.inner.inter_taint.clear();
        *self.inner.resolved_call_graph.write() = None;
        *self.inner.callgraph_query.lock() = None;
        *self.inner.sidecar_source_inputs.lock() = None;
        *self.inner.compiler_linkage.write() = None;
        *self.inner.compiler_headers.write() = None;
        self.inner.exact_bodies.clear();
        self.inner.taint_index.clear();
        self.inner.class_members.clear();
        self.inner.enclosing.invalidate_file(file);
        self.inner.decl_names.clear();
        self.inner.reachable_kinded.write().clear();
    }

    /// Open a structurally indexed workspace: ingest `root`, prewarm
    /// each file's declaration index, and load reusable sidecars when
    /// present. Missing analysis facts are computed on demand by the
    /// exact query that needs them. Every supported UTF-8 source file
    /// selected by the workspace's ignore rules is ingested; source
    /// spelling, line length, and delimiter text never change semantics.
    pub fn open(root: &Path, registry: Arc<LanguageRegistry>) -> Result<Self, WorkspaceError> {
        Self::open_with_options(root, registry, WorkspaceOpenOptions::default())
    }

    /// Structural index alias for SDK callers. This matches the CLI
    /// `index <workspace>` default: parse/index only, no eager
    /// full-workspace taint/value-flow solve.
    pub fn index(root: &Path, registry: Arc<LanguageRegistry>) -> Result<Self, WorkspaceError> {
        Self::open_with_options(root, registry, WorkspaceOpenOptions::parse_only())
    }

    /// Explicit full-prewarm SDK path for cache rebuilds and benchmark/audit
    /// flows that intentionally compute reusable analysis sidecars up front.
    /// This prewarms the canonical IDG, not the legacy per-entry
    /// `ValueFlowGraph` projection; compatibility callers can opt into that
    /// projection with [`WorkspaceOpenOptions::prewarm_value_flow`].
    pub fn index_full_prewarm(root: &Path, registry: Arc<LanguageRegistry>) -> Result<Self, WorkspaceError> {
        Self::open_with_options(root, registry, WorkspaceOpenOptions::full_prewarm())
    }

    /// Open a workspace for a query command: parse/index the current
    /// files, load the persisted dataflow sidecar when present, and
    /// skip eager dataflow prewarm. Missing facts are still computed
    /// on demand through [`DataFlowCache::facts_for`].
    pub fn open_query(root: &Path, registry: Arc<LanguageRegistry>) -> Result<Self, WorkspaceError> {
        Self::open_with_options(root, registry, WorkspaceOpenOptions::query_only())
    }

    /// Open only source files whose raw text contains `literal`.
    ///
    /// This is a query fast path for very large workspaces. It keeps
    /// syntax-search commands from reparsing tens of thousands of
    /// files when a literal query can first narrow the candidate file
    /// set. It deliberately performs parse/index only; callers that
    /// need whole-workspace semantic graph evidence should use
    /// [`Self::open_query`] or pass an explicit exhaustive flag at the
    /// CLI layer.
    pub fn open_query_matching_literal(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        literal: &str,
    ) -> Result<Self, WorkspaceError> {
        Self::open_query_matching_literal_with_options(
            root,
            registry,
            literal,
            WorkspaceOpenOptions::parse_only(),
        )
    }

    /// Same as [`Self::open_query_matching_literal`] with explicit
    /// open options supplied by the SDK/CLI facade.
    pub fn open_query_matching_literal_with_options(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        literal: &str,
        options: WorkspaceOpenOptions,
    ) -> Result<Self, WorkspaceError> {
        Self::open_query_matching_literal_with_options_and_events(root, registry, literal, options, &|_| {})
    }

    /// Same as [`Self::open_query_matching_literal_with_options`],
    /// emitting workspace lifecycle events while the reduced file set
    /// is selected and indexed.
    pub fn open_query_matching_literal_with_options_and_events<F>(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        literal: &str,
        options: WorkspaceOpenOptions,
        on_event: &F,
    ) -> Result<Self, WorkspaceError>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let ws = Self::new_with_open_options(registry, options);
        ws.set_idg_sidecar_root(root)?;
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_scoped_workspace_root(canonical_root.clone());
        on_event(WorkspaceOpenEvent::IngestStarted);
        let files =
            read_supported_source_files_matching_literal(&canonical_root, &ws.inner.registry, literal)?;
        let file_count = files.len();
        for source in files {
            let SourceFileContent {
                path,
                text,
                full_workspace_file,
            } = source;
            let old_id = ws.inner.vfs.lookup(&path);
            let id = match full_workspace_file {
                Some(file) => ws.inner.vfs.write_with_id(file, path, Arc::<str>::from(text)),
                None => ws.inner.vfs.write(path, Arc::<str>::from(text)),
            };
            if let Some(prev) = old_id {
                ws.invalidate_after_file_change(prev);
            }
            *ws.inner.reparse_counter.lock() += 1;
            let _ = id;
        }
        on_event(WorkspaceOpenEvent::IngestFinished { files: file_count });
        let files = ws.vfs().all_files();
        on_event(WorkspaceOpenEvent::ParseStarted { files: files.len() });
        index_workspace_files_in_parallel(&ws, &files, options.retain_eager_syntax_ir, on_event);
        on_event(WorkspaceOpenEvent::ParseFinished);
        Ok(ws)
    }

    /// Open only source files whose raw text contains at least one requested
    /// literal.
    ///
    /// Multi-endpoint structural queries use this candidate phase before
    /// deciding whether a broader graph slice is necessary. Selection is
    /// lexical only; every rendered fact is still hydrated from the normal
    /// Tree-sitter/compiler APIs in the resulting scoped workspace.
    pub fn open_query_matching_any_literal_with_options_and_events<F>(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        literals: &[&str],
        options: WorkspaceOpenOptions,
        on_event: &F,
    ) -> Result<Self, WorkspaceError>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let ws = Self::new_with_open_options(registry, options);
        ws.set_idg_sidecar_root(root)?;
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_scoped_workspace_root(canonical_root.clone());
        on_event(WorkspaceOpenEvent::IngestStarted);
        let files =
            read_supported_source_files_matching_literals(&canonical_root, &ws.inner.registry, literals)?;
        let file_count = files.len();
        for source in files {
            let SourceFileContent {
                path,
                text,
                full_workspace_file,
            } = source;
            let id = match full_workspace_file {
                Some(file) => ws.inner.vfs.write_with_id(file, path, Arc::<str>::from(text)),
                None => ws.inner.vfs.write(path, Arc::<str>::from(text)),
            };
            *ws.inner.reparse_counter.lock() += 1;
            let _ = id;
        }
        on_event(WorkspaceOpenEvent::IngestFinished { files: file_count });
        let files = ws.vfs().all_files();
        on_event(WorkspaceOpenEvent::ParseStarted { files: files.len() });
        index_workspace_files_in_parallel(&ws, &files, options.retain_eager_syntax_ir, on_event);
        on_event(WorkspaceOpenEvent::ParseFinished);
        Ok(ws)
    }

    /// Open only source files whose paths satisfy the supplied
    /// include/exclude filters. This is the large-repo fast path for
    /// security profiles and explicit path-scoped queries: if the
    /// command has already declared a path scope, do not parse files
    /// that will be discarded by that same scope.
    pub fn open_query_filtered_paths(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        include_filters: &[String],
        exclude_filters: &[String],
    ) -> Result<Self, WorkspaceError> {
        Self::open_query_filtered_paths_with_options(
            root,
            registry,
            include_filters,
            exclude_filters,
            WorkspaceOpenOptions::query_only(),
        )
    }

    /// Same as [`Self::open_query_filtered_paths`] with explicit open
    /// options supplied by the SDK/CLI facade.
    pub fn open_query_filtered_paths_with_options(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        include_filters: &[String],
        exclude_filters: &[String],
        options: WorkspaceOpenOptions,
    ) -> Result<Self, WorkspaceError> {
        Self::open_query_filtered_paths_with_options_and_events(
            root,
            registry,
            include_filters,
            exclude_filters,
            options,
            &|_| {},
        )
    }

    /// Same as [`Self::open_query_filtered_paths_with_options`],
    /// emitting lifecycle events for frontends that want progress
    /// while the scoped file set is selected.
    pub fn open_query_filtered_paths_with_options_and_events<F>(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        include_filters: &[String],
        exclude_filters: &[String],
        options: WorkspaceOpenOptions,
        on_event: &F,
    ) -> Result<Self, WorkspaceError>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let ws = Self::new_with_open_options(registry, options);
        ws.set_idg_sidecar_root(root)?;
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_scoped_workspace_root(canonical_root.clone());
        on_event(WorkspaceOpenEvent::IngestStarted);
        let files = read_supported_source_files_filtered_paths(
            &canonical_root,
            &ws.inner.registry,
            include_filters,
            exclude_filters,
        )?;
        let file_count = files.len();
        for source in files {
            let SourceFileContent {
                path,
                text,
                full_workspace_file,
            } = source;
            let old_id = ws.inner.vfs.lookup(&path);
            let id = match full_workspace_file {
                Some(file) => ws.inner.vfs.write_with_id(file, path, Arc::<str>::from(text)),
                None => ws.inner.vfs.write(path, Arc::<str>::from(text)),
            };
            if let Some(prev) = old_id {
                ws.invalidate_after_file_change(prev);
            }
            *ws.inner.reparse_counter.lock() += 1;
            let _ = id;
        }
        on_event(WorkspaceOpenEvent::IngestFinished { files: file_count });
        if options.eager_decl_index {
            let files = ws.vfs().all_files();
            on_event(WorkspaceOpenEvent::ParseStarted { files: files.len() });
            index_workspace_files_in_parallel(&ws, &files, options.retain_eager_syntax_ir, on_event);
            on_event(WorkspaceOpenEvent::ParseFinished);
        }
        Ok(ws)
    }

    /// Open an exact compiler worklist without walking the workspace again.
    ///
    /// `files` carries the stable full-workspace [`FileId`] for each selected
    /// source. `source_inputs` is the complete, already-validated
    /// `(FileId, path, content-hash)` table used to validate partitioned
    /// semantic sidecars. Retrieval/query planners use this after checking a
    /// strong source manifest, so a warm exact query reads only its candidate
    /// source bodies while preserving whole-workspace symbol identity.
    pub fn open_query_exact_files_with_source_inputs_and_events<F>(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        files: &[(FileId, PathBuf)],
        source_inputs: Vec<(u32, String, u64)>,
        options: WorkspaceOpenOptions,
        on_event: &F,
    ) -> Result<Self, WorkspaceError>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let ws = Self::new_with_open_options(registry, options);
        ws.set_idg_sidecar_root(root)?;
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_scoped_workspace_root(canonical_root.clone());
        if let Err(error) = ws.inner.db.load_compiler_object_store_for_source_fingerprints(
            &canonical_root,
            source_inputs.iter().map(|(_, path, hash)| (path, *hash)),
        ) {
            bonsai_diagnostics::debug_log!(
                "compiler-cache",
                "exact query compiler-object generation rejected at {}: {}",
                canonical_root.display(),
                error
            );
        }
        *ws.inner.sidecar_source_inputs.lock() = Some(Arc::new(source_inputs));

        let mut selected = Vec::with_capacity(files.len());
        let mut seen_files = std::collections::BTreeSet::new();
        let mut seen_paths = std::collections::BTreeSet::new();
        for (file, path) in files {
            if !seen_files.insert(file.raw()) || !seen_paths.insert(path.clone()) {
                return Err(WorkspaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "exact query worklist contains conflicting file identities",
                )));
            }
            selected.push((*file, path.clone()));
        }
        selected.sort_unstable_by_key(|(file, _)| file.raw());

        on_event(WorkspaceOpenEvent::IngestStarted);
        use rayon::prelude::*;
        let sources = selected
            .into_par_iter()
            .map(|(file, path)| {
                if !path.starts_with(&canonical_root) {
                    return Err(WorkspaceError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "exact query source {} is outside workspace {}",
                            path.display(),
                            canonical_root.display()
                        ),
                    )));
                }
                let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
                    return Err(WorkspaceError::NoAdapter(path.display().to_string()));
                };
                if ws.inner.registry.adapter_for_extension(extension).is_none() {
                    return Err(WorkspaceError::NoAdapter(extension.to_string()));
                }
                let text = std::fs::read_to_string(&path).map_err(WorkspaceError::Io)?;
                Ok(SourceFileContent {
                    path,
                    text,
                    full_workspace_file: Some(file),
                })
            })
            .collect::<Result<Vec<_>, WorkspaceError>>()?;
        let file_count = sources.len();
        for source in sources {
            let file = source
                .full_workspace_file
                .expect("exact query source always carries a full-workspace FileId");
            ws.inner
                .vfs
                .write_with_id(file, source.path, Arc::<str>::from(source.text));
            *ws.inner.reparse_counter.lock() += 1;
        }
        on_event(WorkspaceOpenEvent::IngestFinished { files: file_count });
        if options.eager_decl_index {
            let files = ws.vfs().all_files();
            on_event(WorkspaceOpenEvent::ParseStarted { files: files.len() });
            index_workspace_files_in_parallel(&ws, &files, options.retain_eager_syntax_ir, on_event);
            on_event(WorkspaceOpenEvent::ParseFinished);
        }
        Ok(ws)
    }

    /// Open one supported source file under `root`, parse it, and
    /// index only its local syntax facts.
    ///
    /// This is the fast path for file-centric navigation commands.
    /// It deliberately does not ingest the whole workspace or load
    /// whole-workspace graph sidecars; callers that need cross-file
    /// callers, findings, or taint overlays should use
    /// [`Self::open_query`].
    pub fn open_query_matching_path(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        path: &Path,
    ) -> Result<Self, WorkspaceError> {
        Self::open_query_matching_path_with_options(root, registry, path, WorkspaceOpenOptions::parse_only())
    }

    /// Same as [`Self::open_query_matching_path`] with explicit open
    /// options supplied by the SDK/CLI facade.
    pub fn open_query_matching_path_with_options(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        path: &Path,
        options: WorkspaceOpenOptions,
    ) -> Result<Self, WorkspaceError> {
        Self::open_query_matching_path_with_options_and_events(root, registry, path, options, &|_| {})
    }

    /// Same as [`Self::open_query_matching_path_with_options`],
    /// emitting lifecycle events while the single-file workspace is
    /// opened and indexed.
    pub fn open_query_matching_path_with_options_and_events<F>(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        path: &Path,
        options: WorkspaceOpenOptions,
        on_event: &F,
    ) -> Result<Self, WorkspaceError>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let ws = Self::new_with_open_options(registry, options);
        ws.set_idg_sidecar_root(root)?;
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_scoped_workspace_root(canonical_root.clone());
        on_event(WorkspaceOpenEvent::IngestStarted);
        let source = read_supported_source_file_at_path(&canonical_root, &ws.inner.registry, path)?;
        let id = ws
            .inner
            .vfs
            .write(source.path.clone(), Arc::<str>::from(source.text));
        *ws.inner.reparse_counter.lock() += 1;
        on_event(WorkspaceOpenEvent::IngestFinished { files: 1 });
        on_event(WorkspaceOpenEvent::ParseStarted { files: 1 });
        let _ = ws.db().decl_index(id);
        on_event(WorkspaceOpenEvent::ParseFileIndexed);
        on_event(WorkspaceOpenEvent::ParseFinished);
        Ok(ws)
    }

    /// Build a workspace with explicit control over sidecar load,
    /// prewarm, and save behavior. This is the SDK-level primitive
    /// behind the CLI's "index once, query many" performance model.
    pub fn open_with_options(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        options: WorkspaceOpenOptions,
    ) -> Result<Self, WorkspaceError> {
        Self::open_with_options_and_events(root, registry, options, &|_| {})
    }

    /// Same as [`Self::open_with_options`] but fires
    /// [`WorkspaceOpenEvent`]s through `on_event` at each phase
    /// boundary. The SDK's `Bonsai::workspace_with_options_and_progress`
    /// delegates here so a single source of truth drives both
    /// programmatic and CLI/TUI open paths — no more drift between
    /// `Workspace`'s prewarms and what the SDK exposes.
    pub fn open_with_options_and_events<F>(
        root: &Path,
        registry: Arc<LanguageRegistry>,
        options: WorkspaceOpenOptions,
        on_event: &F,
    ) -> Result<Self, WorkspaceError>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let ws = Self::new_with_open_options(registry, options);
        ws.set_idg_sidecar_root(root)?;
        on_event(WorkspaceOpenEvent::IngestStarted);
        ws.ingest_dir(root)?;
        let files = ws.vfs().all_files();
        on_event(WorkspaceOpenEvent::IngestFinished { files: files.len() });
        if options.eager_decl_index {
            // Pass 1: per-file declaration + import indexing. Each syntax
            // tree is independent, so use the host's available parallelism as
            // a compiler frontend would. Repository size must not silently
            // change the scheduler or impose a project-shaped ceiling.
            on_event(WorkspaceOpenEvent::ParseStarted { files: files.len() });
            index_workspace_files_in_parallel(&ws, &files, options.retain_eager_syntax_ir, on_event);
            on_event(WorkspaceOpenEvent::ParseFinished);
        }
        // Optional sidecar load / explicit workspace-wide prewarm.
        // The default structural index path leaves all of these flags
        // off; query commands may load fresh sidecars as performance
        // artifacts, and explicit prewarm/cache flows compute missing
        // per-entry facts up front. Disable even explicit dataflow
        // prewarm with `BONSAI_NO_DATAFLOW=1` (the per-query path
        // still works; it just won't be pre-populated).
        let skip_prewarm = std::env::var("BONSAI_NO_DATAFLOW")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        if options.load_dataflow_sidecar && skip_prewarm {
            on_event(WorkspaceOpenEvent::CacheChecked {
                cache: "dataflow",
                status: WorkspaceCacheStatus::Skipped,
                entries: 0,
            });
        }
        if options.load_dataflow_sidecar && !skip_prewarm {
            // Opening the disk-backed factstore is just an mmap and keeps
            // peak RAM bounded for the rest of the session. Retired eager
            // snapshots are derived caches and intentionally rebuild.
            let factstore_sidecar = DataFlowCache::factstore_sidecar_path(root);
            match ws
                .inner
                .dataflow
                .load_factstore_sidecar(&factstore_sidecar, ws.db())
            {
                Ok(entries) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "dataflow factstore",
                        status: cache_status_for_entries(entries),
                        entries,
                    });
                }
                Err(_) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "dataflow factstore",
                        status: WorkspaceCacheStatus::Error,
                        entries: 0,
                    });
                }
            }
        }
        // Try to load the persisted call graph before any cache
        // that depends on it asks for one. Saves several seconds
        // on every CLI invocation against a workspace with a
        // fresh versioned callgraph sidecar.
        if options.load_callgraph_sidecar {
            let hit = ws.load_callgraph_sidecar(root);
            on_event(WorkspaceOpenEvent::CacheChecked {
                cache: "callgraph",
                status: if hit {
                    WorkspaceCacheStatus::Hit
                } else {
                    WorkspaceCacheStatus::Miss
                },
                entries: usize::from(hit),
            });
        }
        if options.load_idg_sidecar && !skip_prewarm {
            match ws.load_idg_sidecar(root) {
                Ok(Some(entries)) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "IDG factstore",
                        status: WorkspaceCacheStatus::Hit,
                        entries,
                    });
                }
                Ok(None) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "IDG factstore",
                        status: WorkspaceCacheStatus::Miss,
                        entries: 0,
                    });
                }
                Err(error) => {
                    bonsai_diagnostics::debug_log!(
                        "idg-build",
                        "workspace IDG sidecar load failed: path={} error={}",
                        bonsai_idg::workspace::idg_sidecar_path(root).display(),
                        error
                    );
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "IDG factstore",
                        status: WorkspaceCacheStatus::Error,
                        entries: 0,
                    });
                }
            }
        }
        if options.prewarm_dataflow && !skip_prewarm {
            // Build the workspace-cached call graph once, then seed
            // the dataflow + flow-ids caches with it so they don't
            // each rebuild identical content.
            let cg = ws.cached_resolved_call_graph();
            ws.inner.dataflow.seed_call_graph(cg.clone());
            ws.inner.flow_ids.seed_call_graph(cg);
            // Build the complete workspace IDG once the call graph and global
            // index are available. Complete workspaces always persist the
            // exact sidecar regardless of file count; scoped query workspaces
            // deliberately avoid publishing a partial artifact under the
            // full-workspace cache key.
            let _ = ws.build_and_seed_persisted_idg_service();
            // Seed the dataflow cache with the workspace's
            // InterTaintCaches singleton so the engine's resolver
            // memo / alias maps / function summaries built during
            // prewarm survive into security-analysis / value-flow /
            // inspect runs.
            ws.inner
                .dataflow
                .seed_inter_taint_caches(ws.shared_inter_taint_caches());
            let pending = ws.inner.dataflow.pending_count(ws.db());
            on_event(WorkspaceOpenEvent::DataflowPrewarmStarted { pending });
            if options.save_dataflow_sidecar {
                // Streaming prewarm: each computed entry is encoded
                // and appended to the fact-store sidecar immediately,
                // then the file is opened back as the cache's disk
                // store. Peak RAM is bounded by the in-flight rayon
                // chunk — this is the OOM fix for the dataflow cache.
                let factstore_sidecar = DataFlowCache::factstore_sidecar_path(root);
                if let Err(err) = ws
                    .inner
                    .dataflow
                    .prewarm_to_disk(&factstore_sidecar, ws.db(), |_| {
                        on_event(WorkspaceOpenEvent::DataflowEntryBuilt);
                    })
                {
                    tracing::warn!(
                        path = %factstore_sidecar.display(),
                        error = %err,
                        "dataflow prewarm to disk failed; falling back to in-memory prewarm"
                    );
                    ws.inner.dataflow.prewarm_all_with_progress(ws.db(), |_| {
                        on_event(WorkspaceOpenEvent::DataflowEntryBuilt);
                    });
                }
                // Persist the resolved call graph alongside the
                // dataflow sidecar — invalidation rule is identical
                // (content-hash + matcher policy fingerprint), so
                // they always co-evolve.
                let _ = ws.save_callgraph_sidecar(root);
            } else {
                ws.inner.dataflow.prewarm_all_with_progress(ws.db(), |_| {
                    on_event(WorkspaceOpenEvent::DataflowEntryBuilt);
                });
            }
            on_event(WorkspaceOpenEvent::DataflowPrewarmFinished);
        }
        // Pass 3: optional compatibility value-flow projection. Security and
        // native export query the configured IDG directly; only clients of the
        // older per-entry `ValueFlowGraph` document need this sidecar.
        let skip_value_flow = std::env::var("BONSAI_NO_VALUE_FLOW")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        if options.load_value_flow_sidecar && skip_value_flow {
            on_event(WorkspaceOpenEvent::CacheChecked {
                cache: "value-flow",
                status: WorkspaceCacheStatus::Skipped,
                entries: 0,
            });
        }
        if options.load_value_flow_sidecar && !skip_value_flow {
            let sidecar = ValueFlowCache::sidecar_path(root);
            match ws.inner.value_flow.load_from_disk(&sidecar, ws.db()) {
                Ok(entries) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "value-flow",
                        status: cache_status_for_entries(entries),
                        entries,
                    });
                }
                Err(_) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "value-flow",
                        status: WorkspaceCacheStatus::Error,
                        entries: 0,
                    });
                }
            }
        }
        if options.prewarm_value_flow && !skip_value_flow {
            on_event(WorkspaceOpenEvent::ValueFlowPrewarmStarted);
            if options.save_value_flow_sidecar {
                // Streaming prewarm: each computed entry is encoded
                // and appended to the sidecar writer immediately, then
                // the file is opened back as the cache's disk store.
                // Peak RAM is bounded by the in-flight rayon chunk
                // rather than the workspace size — this is the
                // OWASP-class memory fix.
                let sidecar = ValueFlowCache::sidecar_path(root);
                if let Err(err) =
                    ws.inner
                        .value_flow
                        .prewarm_to_disk(&sidecar, ws.db(), &ws.inner.inter_taint)
                {
                    tracing::warn!(
                        path = %sidecar.display(),
                        error = %err,
                        "value-flow prewarm to disk failed; falling back to in-memory prewarm"
                    );
                    ws.inner
                        .value_flow
                        .prewarm_all_with_caches(ws.db(), &ws.inner.inter_taint);
                }
            } else {
                // Caller opted out of persisting the sidecar (e.g.
                // ephemeral SDK consumer). Stay in-memory.
                ws.inner
                    .value_flow
                    .prewarm_all_with_caches(ws.db(), &ws.inner.inter_taint);
            }
            on_event(WorkspaceOpenEvent::ValueFlowPrewarmFinished);
        }
        // Pass 4: flow-id cache. Mirrors the dataflow shape — every
        // browse-row flow-id lookup is O(1) once warmed.
        if options.prewarm_flow_ids && !skip_prewarm {
            on_event(WorkspaceOpenEvent::FlowIdsPrewarmStarted);
            // Streaming prewarm: each computed entry encodes to a
            // fact-store sidecar immediately so peak RAM stays
            // bounded by the in-flight rayon chunk. Falls back to
            // in-memory if disk write fails.
            let sidecar = FlowIdCache::sidecar_path(root);
            // Try to hydrate from any existing sidecar before recomputing.
            match ws.inner.flow_ids.load_from_disk(&sidecar, ws.db()) {
                Ok(entries) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "flow-ids",
                        status: cache_status_for_entries(entries),
                        entries,
                    });
                }
                Err(_) => {
                    on_event(WorkspaceOpenEvent::CacheChecked {
                        cache: "flow-ids",
                        status: WorkspaceCacheStatus::Error,
                        entries: 0,
                    });
                }
            }
            if let Err(err) = ws
                .inner
                .flow_ids
                .prewarm_to_disk(&sidecar, ws.db(), ws.vfs(), |_| {})
            {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %err,
                    "flow-ids prewarm to disk failed; falling back to in-memory prewarm"
                );
                ws.inner.flow_ids.prewarm_all(ws.db(), ws.vfs());
            }
            on_event(WorkspaceOpenEvent::FlowIdsPrewarmFinished);
        }
        Ok(ws)
    }

    /// Load the canonical factstore dataflow sidecar for `root`.
    pub fn load_dataflow_sidecar(&self, root: &Path) -> std::io::Result<usize> {
        let factstore = DataFlowCache::factstore_sidecar_path(root);
        self.inner.dataflow.load_factstore_sidecar(&factstore, self.db())
    }

    /// Persist the complete current dataflow cache to the canonical,
    /// streaming factstore sidecar for `root`.
    pub fn save_dataflow_sidecar(&self, root: &Path) -> std::io::Result<()> {
        self.inner
            .dataflow
            .save_factstore(&DataFlowCache::factstore_sidecar_path(root), self.db())?;
        let legacy = DataFlowCache::sidecar_path(root);
        match std::fs::remove_file(legacy) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Load the conventional value-flow sidecar for `root`. Returns
    /// the number of per-entry graphs the snapshot restored.
    pub fn load_value_flow_sidecar(&self, root: &Path) -> std::io::Result<usize> {
        self.inner
            .value_flow
            .load_from_disk(&ValueFlowCache::sidecar_path(root), self.db())
    }

    /// Save the current value-flow cache to the conventional sidecar
    /// path for `root`.
    pub fn save_value_flow_sidecar(&self, root: &Path) -> std::io::Result<()> {
        self.inner
            .value_flow
            .save_to_disk(&ValueFlowCache::sidecar_path(root), self.db())
    }

    pub fn ingest_dir(&self, root: &Path) -> Result<Vec<FileId>, WorkspaceError> {
        // A whole ingest publishes one coherent source generation. Security
        // analysis and IDG compilation finish their current immutable
        // snapshot before any VFS entry changes.
        let _taint_analysis_guard = self.inner.taint_analysis_serial.lock();
        let _idg_build_guard = self.inner.idg_build_serial.lock();
        *self.inner.root_label.lock() = root.display().to_string();
        self.set_complete_workspace_index(true);
        let canonical_root = canonical_workspace_root(root);
        cache_fingerprint::register_workspace_cache_root(&canonical_root)?;
        self.inner.db.set_workspace_root(canonical_root.clone());
        let mut ingested = Vec::new();
        stream_supported_source_files(&canonical_root, &self.inner.registry, |source| {
            let path = &source.path;
            let old_id = self.inner.vfs.lookup(path);
            let id = self.inner.vfs.write(path.clone(), Arc::<str>::from(source.text));
            if let Some(prev) = old_id {
                self.invalidate_after_file_change_locked(prev);
            }
            *self.inner.reparse_counter.lock() += 1;
            ingested.push(id);
            Ok(())
        })?;
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
        read_supported_source_file_fingerprints(&canonical_root, &self.inner.registry)
    }

    /// Current supported source files under `root`, using metadata-only
    /// change stamps. This does not open or hash unchanged source contents.
    pub fn source_file_stamps(&self, root: &Path) -> Result<Vec<SourceFileStamp>, WorkspaceError> {
        let canonical_root = canonical_workspace_root(root);
        read_supported_source_file_stamps(&canonical_root, &self.inner.registry)
    }

    /// Metadata-only stamp for one supported source path. Returns `None`
    /// when the path has no registered language adapter or was removed.
    /// Workspace frontends use this after a source-control change index has
    /// narrowed the candidate set, avoiding a recursive metadata walk.
    pub fn source_file_stamp(&self, path: &Path) -> Result<Option<SourceFileStamp>, WorkspaceError> {
        let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
            return Ok(None);
        };
        if self.inner.registry.adapter_for_extension(ext).is_none() {
            return Ok(None);
        }
        match source_file_stamp(path) {
            Ok(stamp) => Ok(Some(stamp)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(WorkspaceError::Io(error)),
        }
    }

    /// Metadata stamps for the source files already present in this
    /// workspace snapshot. Used to initialize long-lived refresh state
    /// without walking the workspace a second time during open.
    pub fn indexed_source_file_stamps(&self) -> Result<Vec<SourceFileStamp>, WorkspaceError> {
        let files = self.inner.vfs.all_files();
        let mut stamps = Vec::with_capacity(files.len());
        for file in files {
            let path = self.inner.vfs.path(file).map_err(|error| {
                WorkspaceError::Io(std::io::Error::other(format!(
                    "reading indexed source path: {error}"
                )))
            })?;
            match source_file_stamp(&path) {
                Ok(stamp) => stamps.push(stamp),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(WorkspaceError::Io(error)),
            }
        }
        stamps.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(stamps)
    }

    /// Refresh one on-disk source file in place. Parser, decl/import,
    /// CFG, flow-id, dataflow, value-flow, callgraph, source-taint,
    /// and other derived caches are invalidated through the same
    /// workspace-wide edit path used by watch and SDK hot reload.
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
        Ok(FileRefresh {
            file: id,
            path: path.to_path_buf(),
            kind,
        })
    }

    /// Remove one file from the live workspace. Used by watch/SDK
    /// refresh paths after an on-disk delete.
    pub fn remove_file_from_index(&self, path: &Path) -> Option<FileId> {
        let _taint_analysis_guard = self.inner.taint_analysis_serial.lock();
        let _idg_build_guard = self.inner.idg_build_serial.lock();
        let file = self.inner.vfs.remove(path)?;
        self.invalidate_after_file_change_locked(file);
        *self.inner.reparse_counter.lock() += 1;
        Some(file)
    }

    /// Apply an in-memory edit to a workspace file and invalidate
    /// every derived cache that observed the prior version.
    ///
    /// VFS bumps the file's version (FileId stays stable). The DB
    /// drops `decl_index`/`import_index`/`resolved`/global-index
    /// entries; CFGs auto-miss on their `(FuncId, file_version)` key.
    /// Derived workspace-wide caches are dropped conservatively so
    /// exact command scopes rebuild from the current source tree.
    /// Flow-id labels and the reparse counter both bump.
    pub fn apply_edit(&self, path: &Path, new_text: String) -> FileId {
        // Preserve the same lock order used by security analysis
        // (`taint_analysis_serial` then `idg_build_serial`) so edits wait for
        // the current compiler generation before changing its source snapshot.
        let _taint_analysis_guard = self.inner.taint_analysis_serial.lock();
        let _idg_build_guard = self.inner.idg_build_serial.lock();
        let old_id = self.inner.vfs.lookup(path);
        let id = self
            .inner
            .vfs
            .write(path.to_path_buf(), Arc::<str>::from(new_text));
        if let Some(prev) = old_id {
            self.invalidate_after_file_change_locked(prev);
        } else {
            self.invalidate_after_file_change_locked(id);
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

    /// Aggregate parser/adapter diagnostics across every workspace file.
    /// Compiler objects retain the exact diagnostics for their source
    /// snapshot, so a warm query does not reparse the project merely to report
    /// syntax coverage.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let files = self.inner.vfs.all_files();
        self.inner
            .db
            .visit_compiler_file_objects_uncached(&files, |_, _| {});
        self.inner.db.diagnostics()
    }

    /// Return deterministic parser-coverage reasons for an exact file scope.
    ///
    /// Parsing is a cached syntax query. Exact Tree-sitter diagnostics and the
    /// DB-level compiler diagnostic sink are both inspected, with file sets
    /// preventing duplicate diagnostics from inflating the counts. The syntax
    /// query never lowers declarations or flow bodies merely to prove parser
    /// coverage. A hard parser or VFS failure has no `ParsedFile`, so it is
    /// recorded explicitly instead of allowing a false-complete analysis.
    pub fn parser_incomplete_reasons_for_files(&self, files: &[FileId]) -> Vec<String> {
        let file_set: AHashSet<FileId> = files.iter().copied().collect();
        let mut syntax_error_files = AHashSet::new();
        let mut parse_timeout_files = AHashSet::new();
        let mut parse_failed_files = AHashSet::new();
        let mut missing_object_files = Vec::new();
        let mut record_diagnostic = |diagnostic: &Diagnostic| {
            if file_set.contains(&diagnostic.span.file) {
                match diagnostic.code.as_deref() {
                    Some("parse-failed") => {
                        parse_failed_files.insert(diagnostic.span.file);
                    }
                    Some("parse-timeout") => {
                        parse_timeout_files.insert(diagnostic.span.file);
                    }
                    Some("syntax-error") => {
                        syntax_error_files.insert(diagnostic.span.file);
                    }
                    _ => {}
                }
            }
        };

        let unchecked_files = files
            .iter()
            .copied()
            .filter(|file| !self.inner.db.compiler_diagnostics_are_current(*file))
            .collect::<Vec<_>>();
        self.inner
            .db
            .visit_parser_diagnostics_uncached(&unchecked_files, |file, diagnostics| match diagnostics {
                Some(diagnostics) => {
                    for diagnostic in diagnostics.iter() {
                        record_diagnostic(diagnostic);
                    }
                }
                None => {
                    missing_object_files.push(file);
                }
            });
        for diagnostic in self.inner.db.diagnostics() {
            record_diagnostic(&diagnostic);
        }
        parse_failed_files.extend(missing_object_files);

        let mut reasons = std::collections::BTreeSet::new();
        if !parse_failed_files.is_empty() {
            reasons.insert(format!("parse-failed-files:{}", parse_failed_files.len()));
        }
        if !parse_timeout_files.is_empty() {
            reasons.insert(format!("parse-timeout-files:{}", parse_timeout_files.len()));
        }
        if !syntax_error_files.is_empty() {
            reasons.insert(format!("syntax-error-files:{}", syntax_error_files.len()));
        }
        reasons.into_iter().collect()
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
            semantic_context: self.semantic_context_summary(),
        }
    }

    /// Language-neutral project context derived from indexed syntax
    /// paths plus complete filesystem discovery of roots the ingest
    /// layer intentionally skips (dependencies, generated output,
    /// caches, and VCS metadata). Adapters and frontends use this
    /// shared contract instead of inventing per-language workspace
    /// heuristics.
    #[must_use]
    pub fn semantic_context(&self) -> WorkspaceSemanticContext {
        self.build_semantic_context(true)
    }

    /// Build language-neutral workspace context from metadata-only source
    /// discovery.
    ///
    /// This is the compiler planning form used by `context`: it enumerates
    /// adapter-owned source paths and filesystem roots without reading source
    /// contents into the VFS or invoking Tree-sitter. Commands that need
    /// declarations still use [`Self::semantic_context`] over their immutable
    /// indexed snapshot.
    pub fn semantic_context_for_root(&self, root: &Path) -> Result<WorkspaceSemanticContext, WorkspaceError> {
        let canonical_root = canonical_workspace_root(root);
        let files = read_supported_source_file_stamps(&canonical_root, &self.inner.registry)?
            .into_iter()
            .map(|stamp| stamp.path)
            .collect::<Vec<_>>();
        Ok(semantic_context::build_workspace_semantic_context(
            Some(&canonical_root),
            &files,
            true,
        ))
    }

    /// Same counts as [`Self::semantic_context`], including complete
    /// filesystem discovery of non-indexed roots — `index` stats and
    /// `context` must not disagree about the same workspace.
    #[must_use]
    pub fn semantic_context_summary(&self) -> WorkspaceSemanticContextSummary {
        self.build_semantic_context(true).summary
    }

    fn build_semantic_context(&self, discover_roots: bool) -> WorkspaceSemanticContext {
        let root = self.inner.db.workspace_root();
        let files = self
            .inner
            .vfs
            .all_files()
            .into_iter()
            .filter_map(|file| self.inner.vfs.path(file).ok().map(|path| path.as_ref().clone()))
            .collect::<Vec<_>>();
        semantic_context::build_workspace_semantic_context(root.as_deref(), &files, discover_roots)
    }

    pub fn lookup_function(&self, qualified: &str) -> Option<FuncId> {
        self.resolve_function_symbol(qualified)
            .ok()
            .map(|s| FuncId::new(s.raw()))
    }

    /// Resolve one callable through persisted header partitions for the
    /// supplied candidate files, retaining complete-workspace SymbolIds.
    ///
    /// This is the bridge from retrieval candidate workspaces to exact
    /// semantic worklists. It returns `None` when the partition sidecar is
    /// unavailable, stale, or the name is ambiguous; callers then reopen the
    /// complete compiler workspace instead of guessing an identity.
    pub fn lookup_function_in_persisted_headers(
        &self,
        qualified: &str,
        candidate_files: &[FileId],
    ) -> Option<FuncId> {
        let hits = self.lookup_functions_in_persisted_headers(qualified, candidate_files)?;
        match hits.as_slice() {
            [function] => Some(*function),
            _ => None,
        }
    }

    /// Resolve every exact callable overload through persisted header
    /// partitions for the supplied candidate files.
    ///
    /// A qualified source-level name does not necessarily identify one
    /// callable: Java, C#, C++, Kotlin, and other languages can declare
    /// overload sets. Relational query planners must carry that set into the
    /// compiler graph rather than treating ordinary overloads as a cache miss
    /// and broadening to an unrelated whole-workspace search. `None` means
    /// the persisted compiler generation is unavailable or stale; `Some`
    /// contains every exact match and can be empty when the name is absent.
    pub fn lookup_functions_in_persisted_headers(
        &self,
        qualified: &str,
        candidate_files: &[FileId],
    ) -> Option<Vec<FuncId>> {
        let lookup = split_symbol_lookup_spec(qualified);
        let global = self.persisted_compiler_header_index_for_files(candidate_files)?;
        // CONTEXTLESS_LOOKUP_JUSTIFICATION: integrity-checked partition
        // inventory, constrained below by the complete lookup spec; all
        // overloads survive and no semantic dispatch is guessed by name.
        let mut hits = global
            .find_by_name(lookup.name)
            .iter()
            .copied()
            .filter(|symbol| {
                global.decl_of(*symbol).is_some_and(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    ) && self.decl_matches_lookup_spec(decl, &lookup)
                })
            })
            .collect::<Vec<_>>();
        hits.sort_unstable_by_key(|symbol| symbol.raw());
        hits.dedup();
        Some(hits.into_iter().map(|symbol| FuncId::new(symbol.raw())).collect())
    }

    fn resolve_function_symbol(&self, qualified: &str) -> Result<SymbolId, WorkspaceError> {
        let lookup = split_symbol_lookup_spec(qualified);
        if let Some(resolved) = self.resolve_function_symbol_from_callgraph(qualified, &lookup) {
            return resolved;
        }
        // Bare-name lookups can match multiple symbols when names
        // collide across translation units (the canonical regression
        // is `static fn error()` defined in multiple files).
        // Collect every match in deterministic order, then require a
        // single semantic candidate. The caller must disambiguate
        // instead of letting trace pick a workspace-order winner. A
        // `path:name` or `path:line:name` query narrows that same
        // inventory by declaration location; it never broadens lookup.
        let global = self.compiler_header_index();
        let mut candidates: Vec<(SymbolId, Decl)> = global
            // CLI/user-supplied trace entry lookup only.
            // CONTEXTLESS_LOOKUP_JUSTIFICATION: This is an inventory step that
            // either yields exactly one semantic target or reports
            // ambiguity. The cross-module tracer starts from the
            // resolved symbol and resolves subsequent edges with caller
            // context.
            .find_by_name(lookup.name)
            .iter()
            .filter_map(|sym| self.decl_for_symbol(*sym).map(|d| (*sym, d)))
            .filter(|(_, decl)| self.decl_matches_lookup_spec(decl, &lookup))
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
        let mut callable_hits: Vec<(SymbolId, Decl)> = candidates
            .iter()
            .filter(|(_, d)| {
                matches!(
                    d.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
            })
            .cloned()
            .collect();
        collect_unindexed_named_decls(
            self,
            lookup.name,
            |d| {
                matches!(
                    d.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
            },
            &mut callable_hits,
        );
        callable_hits.retain(|(_, decl)| self.decl_matches_lookup_spec(decl, &lookup));
        sort_symbol_decl_candidates(self, &mut callable_hits);
        dedup_symbol_decl_candidates(&mut callable_hits);
        match callable_hits.as_slice() {
            [(sym, _)] => return Ok(*sym),
            [] => {}
            hits => {
                return Err(WorkspaceError::AmbiguousSymbol {
                    query: qualified.to_string(),
                    count: hits.len(),
                    candidates: hits
                        .iter()
                        .map(|(sym, decl)| self.symbol_candidate_label(*sym, decl))
                        .collect(),
                });
            }
        }
        let mut ctor_hits: Vec<(SymbolId, Decl)> = candidates
            .iter()
            .filter(|(_, d)| matches!(d.kind, DeclKind::Class | DeclKind::Struct))
            .flat_map(|(sym, _)| {
                self.find_constructor_symbols(*sym)
                    .into_iter()
                    .filter_map(|ctor| self.decl_for_symbol(ctor).map(|decl| (ctor, decl)))
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut class_hits = Vec::new();
        collect_unindexed_named_decls(
            self,
            lookup.name,
            |d| matches!(d.kind, DeclKind::Class | DeclKind::Struct),
            &mut class_hits,
        );
        class_hits.retain(|(_, decl)| self.decl_matches_lookup_spec(decl, &lookup));
        ctor_hits.extend(class_hits.into_iter().flat_map(|(class_sym, _)| {
            self.find_constructor_symbols(class_sym)
                .into_iter()
                .filter_map(|ctor| self.decl_for_symbol(ctor).map(|decl| (ctor, decl)))
                .collect::<Vec<_>>()
        }));
        sort_symbol_decl_candidates(self, &mut ctor_hits);
        dedup_symbol_decl_candidates(&mut ctor_hits);
        match ctor_hits.as_slice() {
            [(sym, _)] => Ok(*sym),
            [] => Err(WorkspaceError::SymbolNotFound(qualified.into())),
            hits => Err(WorkspaceError::AmbiguousSymbol {
                query: qualified.to_string(),
                count: hits.len(),
                candidates: hits
                    .iter()
                    .map(|(sym, decl)| self.symbol_candidate_label(*sym, decl))
                    .collect(),
            }),
        }
    }

    fn resolve_function_symbol_from_callgraph(
        &self,
        query: &str,
        lookup: &SymbolLookupSpec<'_>,
    ) -> Option<Result<SymbolId, WorkspaceError>> {
        let service = self.callgraph_query_service()?;
        let mut nodes = match service.callable_nodes_named(lookup.name) {
            Ok(nodes) => nodes,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "callable-name bucket query failed: {}",
                    error
                );
                return None;
            }
        };
        nodes.retain(|node| {
            let file_matches = lookup.file.is_none_or(|qualifier| {
                self.inner
                    .db
                    .vfs()
                    .path(node.file)
                    .is_ok_and(|path| file_matches_qualifier(path.as_ref(), qualifier))
            });
            let line_matches = lookup.line.is_none_or(|wanted| {
                self.inner.db.vfs().snapshot(node.file).is_ok_and(|snapshot| {
                    let map = bonsai_common::cached_span_map_arc(node.file, snapshot.version, &snapshot.text);
                    map.line_col(node.name_span.start).line == wanted
                })
            });
            file_matches && line_matches
        });
        nodes.sort_by(|left, right| {
            let left_path = self
                .inner
                .db
                .vfs()
                .path(left.file)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            let right_path = self
                .inner
                .db
                .vfs()
                .path(right.file)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            left_path
                .cmp(&right_path)
                .then_with(|| left.name_span.start.cmp(&right.name_span.start))
                .then_with(|| left.func.raw().cmp(&right.func.raw()))
        });
        nodes.dedup_by_key(|node| node.func);
        match nodes.as_slice() {
            [] => None,
            [node] => Some(Ok(SymbolId::new(node.func.raw()))),
            nodes => Some(Err(WorkspaceError::AmbiguousSymbol {
                query: query.to_string(),
                count: nodes.len(),
                candidates: nodes
                    .iter()
                    .map(|node| {
                        let path = self
                            .inner
                            .db
                            .vfs()
                            .path(node.file)
                            .map(|path| path.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let line = self
                            .inner
                            .db
                            .vfs()
                            .snapshot(node.file)
                            .ok()
                            .map(|snapshot| {
                                bonsai_common::cached_span_map_arc(
                                    node.file,
                                    snapshot.version,
                                    &snapshot.text,
                                )
                                .line_col(node.name_span.start)
                                .line
                            })
                            .unwrap_or(0);
                        format!("{path}:{line}:{} (FuncId:{})", node.name, node.func.raw())
                    })
                    .collect(),
            })),
        }
    }

    fn decl_matches_lookup_spec(&self, decl: &Decl, spec: &SymbolLookupSpec<'_>) -> bool {
        let file_matches = spec.file.is_none_or(|qualifier| {
            self.inner
                .db
                .vfs()
                .path(decl.span.file)
                .is_ok_and(|path| file_matches_qualifier(path.as_ref(), qualifier))
        });
        let line_matches = spec
            .line
            .is_none_or(|wanted| self.decl_name_line(decl).is_some_and(|line| line == wanted));
        file_matches && line_matches
    }

    fn decl_name_line(&self, decl: &Decl) -> Option<u32> {
        let snapshot = self.inner.db.vfs().snapshot(decl.name_span.file).ok()?;
        let map = bonsai_common::cached_span_map_arc(decl.name_span.file, snapshot.version, &snapshot.text);
        Some(map.line_col(decl.name_span.start).line)
    }

    fn find_constructor_symbols(&self, class_sym: SymbolId) -> Vec<SymbolId> {
        // Workspace class-member index lookup — O(1) instead of the
        // prior linear scan of `decls_in(class_file)`. Constructors
        // must be owned by the class declaration through
        // `Decl.parent`; span containment is intentionally not used
        // here because overlapping spans are a syntactic accident,
        // not semantic ownership.
        //
        // Two-stage lookup so the workspace path returns the most
        // complete answer:
        //   1. Explicit `DeclKind::Constructor` decls (every mature
        //      adapter populates this).
        //   2. Per-adapter constructor-name fallback against the
        //      class's methods (catches adapters that name `__init__`
        //      or `new` but don't tag the kind).
        let global = self.compiler_linkage_index();
        let constructors = self.inner.class_members.constructors_of(&global, class_sym);
        if !constructors.is_empty() {
            return constructors
                .into_iter()
                .map(|func| SymbolId::new(func.raw()))
                .collect();
        }
        let Some(class_file) = global.declaring_file(class_sym) else {
            return Vec::new();
        };
        let names = self
            .inner
            .db
            .adapter_for(class_file)
            .map(|adapter| adapter.capabilities().effective_constructor_method_names())
            .unwrap_or(&[]);
        let mut out = Vec::new();
        for name in names {
            let candidates = self.inner.class_members.methods_of(&global, class_sym, name);
            out.extend(candidates.into_iter().map(|func| SymbolId::new(func.raw())));
        }
        out.sort_by_key(|sym| sym.raw());
        out.dedup();
        out
    }

    fn decl_for_symbol(&self, symbol: SymbolId) -> Option<Decl> {
        self.compiler_header_index().decl_of(symbol).cloned()
    }

    fn symbol_candidate_label(&self, symbol: SymbolId, decl: &Decl) -> String {
        let path = self
            .inner
            .db
            .vfs()
            .path(decl.span.file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let line = self.decl_name_line(decl).unwrap_or(0);
        format!("{path}:{line}:{} (FuncId:{})", decl.name, symbol.raw())
    }

    fn language_of(&self, headers: &GlobalIndex, symbol: SymbolId) -> String {
        headers
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
        let symbol = self.resolve_function_symbol(qualified)?;
        let call_graph = self.resolved_call_graph_reachable_from(&[FuncId::new(symbol.raw())]);
        let header_files = call_graph
            .nodes()
            .iter()
            .map(|node| node.file)
            .collect::<Vec<_>>();
        let headers = self.compiler_header_index_for_files(&header_files);
        let raw = CrossModuleTracer::new(self, Arc::clone(&headers), call_graph.as_ref(), opts).trace(symbol);
        Ok(self.finalize_trace(
            raw,
            TraceQuery {
                kind: TraceQueryKind::FunctionEntry,
                target_symbol: Some(qualified.to_string()),
                entry_symbol: Some(qualified.to_string()),
                sink_symbol: None,
                file_filter: None,
                max_depth: u32::from(opts.max_depth),
                max_paths: u32::from(opts.max_branch_fanout),
                follow_calls: true,
            },
            symbol,
            opts,
            headers,
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
        let src = self.resolve_function_symbol(source)?;
        // The sink may legitimately be an external / framework call (like
        // `os.system`, `exec`, `Runtime.getRuntime().exec`) that isn't a
        // declared function in the workspace. Only pre-compute a
        // `FuncId` for it when it IS a declared function; otherwise we'll
        // still truncate the trace by matching step messages below.
        let call_graph = self.resolved_call_graph_reachable_from(&[FuncId::new(src.raw())]);
        let header_files = call_graph
            .nodes()
            .iter()
            .map(|node| node.file)
            .collect::<Vec<_>>();
        let headers = self.compiler_header_index_for_files(&header_files);
        let raw = CrossModuleTracer::new(self, Arc::clone(&headers), call_graph.as_ref(), opts).trace(src);
        let mut result = self.finalize_trace(
            raw,
            TraceQuery {
                kind: TraceQueryKind::SourceToSink,
                target_symbol: Some(sink.to_string()),
                entry_symbol: Some(source.to_string()),
                sink_symbol: Some(sink.to_string()),
                file_filter: None,
                max_depth: u32::from(opts.max_depth),
                max_paths: u32::from(opts.max_branch_fanout),
                follow_calls: true,
            },
            src,
            opts,
            headers,
        );
        if let Some(hit) = result.steps.iter().position(|s| s.function == sink) {
            bonsai_trace::truncate_after_step(&mut result, hit);
        } else if !result.steps.iter().any(|s| s.function == sink) {
            // External/framework sinks are not workspace declarations, so
            // match the finalized concrete call step. Keep this exact:
            // substring scans can stop at unrelated calls such as
            // `os.system_safe` for a requested sink of `os.system`.
            if let Some(hit) = result.steps.iter().position(|s| trace_step_calls_symbol(s, sink)) {
                bonsai_trace::truncate_after_step(&mut result, hit);
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
        headers: Arc<GlobalIndex>,
    ) -> TraceResult {
        let language = self.language_of(headers.as_ref(), entry);
        let root = self.inner.root_label.lock().clone();
        let name_headers = Arc::clone(&headers);
        let name_of: Box<dyn Fn(FuncId) -> Option<String>> = Box::new(move |fid: FuncId| {
            let sym = SymbolId::new(fid.raw());
            let file = name_headers.declaring_file(sym)?;
            name_headers
                .decls_in(file)
                .iter()
                .find(|d| d.symbol == sym)
                .map(|d| d.name.clone())
        });
        let module_of: Box<dyn Fn(FuncId) -> Option<String>> = {
            let headers = Arc::clone(&headers);
            let db = self.inner.db.clone();
            Box::new(move |fid: FuncId| {
                let sym = SymbolId::new(fid.raw());
                let file = headers.declaring_file(sym)?;
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
            limits: opts.trace_metadata_limits(),
        };
        finalize(raw, ctx, self.inner.vfs.as_ref())
    }
}

fn index_workspace_files_in_parallel<F>(
    ws: &Workspace,
    files: &[FileId],
    retain_syntax_ir: bool,
    on_event: &F,
) where
    F: Fn(WorkspaceOpenEvent) + Sync,
{
    let index_file = |file| {
        if retain_syntax_ir {
            let _ = ws.db().syntax_indexes_releasing_cst(file);
        } else {
            let _ = ws.db().syntax_indexes_uncached(file);
        }
    };
    let workers = workspace_parse_worker_count();
    if workers <= 1 || files.len() <= 1 {
        for &file in files {
            index_file(file);
            on_event(WorkspaceOpenEvent::ParseFileIndexed);
        }
        return;
    }

    match rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .stack_size(workspace_parse_worker_stack_bytes())
        .build()
    {
        Ok(pool) => {
            pool.install(|| {
                use rayon::prelude::*;
                files.par_iter().for_each(|file| {
                    index_file(*file);
                    on_event(WorkspaceOpenEvent::ParseFileIndexed);
                });
            });
        }
        Err(_) => {
            for &file in files {
                index_file(file);
                on_event(WorkspaceOpenEvent::ParseFileIndexed);
            }
        }
    }
}

fn workspace_parse_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    let requested = std::env::var("BONSAI_PARSE_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .or_else(|| {
            std::env::var("RAYON_NUM_THREADS")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .unwrap_or(available)
        .max(1);
    // This is cache scheduling only: every file is still parsed and indexed.
    // The shared compiler profile keeps this earliest Tree-sitter phase from
    // overcommitting memory before downstream exact analyses begin.
    bonsai_common::syntax_worker_count(requested.min(available))
}

fn workspace_parse_worker_stack_bytes() -> usize {
    std::env::var("BONSAI_PARSE_STACK_BYTES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|bytes| *bytes >= 1024 * 1024)
        .unwrap_or(64 * 1024 * 1024)
}

fn trace_step_calls_symbol(step: &bonsai_trace::TraceStep, sink: &str) -> bool {
    if !matches!(
        step.kind,
        bonsai_trace::TraceStepKind::Call | bonsai_trace::TraceStepKind::Diagnostic
    ) {
        return false;
    }
    let Some(callee) = trace_step_callee_label(&step.message) else {
        return false;
    };
    normalized_external_call_label(callee) == normalized_external_call_label(sink)
}

fn trace_step_callee_label(message: &str) -> Option<&str> {
    [
        "Method call ",
        "Indirect call ",
        "Call ",
        "Macro ",
        "New ",
        "Unresolved call ",
        "Ambiguous call ",
    ]
    .iter()
    .find_map(|prefix| message.strip_prefix(prefix))
    .map(str::trim)
    .filter(|callee| !callee.is_empty())
}

fn normalized_external_call_label(label: &str) -> &str {
    label
        .trim()
        .trim_start_matches(bonsai_common::REFERENCE_SIGILS)
        .trim_start_matches('&')
        .trim_start_matches('*')
}

#[derive(Debug, Default)]
struct SymbolLookupSpec<'a> {
    file: Option<&'a str>,
    line: Option<u32>,
    name: &'a str,
}

fn split_symbol_lookup_spec(spec: &str) -> SymbolLookupSpec<'_> {
    let Some(name_idx) = spec.rfind(':') else {
        return SymbolLookupSpec {
            name: spec,
            ..Default::default()
        };
    };
    let (head, name) = (&spec[..name_idx], &spec[name_idx + 1..]);
    if name.is_empty() || head.is_empty() || name.contains(['/', '\\']) {
        return SymbolLookupSpec {
            name: spec,
            ..Default::default()
        };
    }
    let path_like = |value: &str| value.contains(['/', '\\']);
    if let Some((path, maybe_line)) = head.rsplit_once(':') {
        if !path.is_empty() {
            if let Ok(line) = maybe_line.parse::<u32>() {
                return SymbolLookupSpec {
                    file: Some(path),
                    line: Some(line),
                    name,
                };
            }
        }
    }
    if path_like(head) {
        return SymbolLookupSpec {
            file: Some(head),
            line: None,
            name,
        };
    }
    SymbolLookupSpec {
        name: spec,
        ..Default::default()
    }
}

fn file_matches_qualifier(decl_file: &Path, qualifier: &str) -> bool {
    if decl_file == Path::new(qualifier) {
        return true;
    }
    let canonical_qualifier = Path::new(qualifier).canonicalize().ok();
    if decl_file
        .canonicalize()
        .ok()
        .as_deref()
        .zip(canonical_qualifier.as_deref())
        .is_some_and(|(decl, qual)| decl == qual)
    {
        return true;
    }
    let decl_text = decl_file.to_string_lossy();
    if decl_text.ends_with(qualifier)
        && decl_text
            .as_bytes()
            .get(decl_text.len().saturating_sub(qualifier.len()).saturating_sub(1))
            .is_some_and(|b| *b == b'/' || *b == b'\\')
    {
        return true;
    }
    decl_file
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == qualifier)
}

fn collect_unindexed_named_decls<F>(
    ws: &Workspace,
    qualified: &str,
    kind_matches: F,
    out: &mut Vec<(SymbolId, Decl)>,
) where
    F: Fn(&Decl) -> bool,
{
    let global = ws.compiler_header_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == qualified && kind_matches(decl) {
                out.push((decl.symbol, decl.clone()));
            }
        }
    }
}

fn sort_symbol_decl_candidates(ws: &Workspace, candidates: &mut [(SymbolId, Decl)]) {
    candidates.sort_by(|(a_sym, a), (b_sym, b)| {
        let a_path = ws
            .inner
            .db
            .vfs()
            .path(a.span.file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let b_path = ws
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
}

fn dedup_symbol_decl_candidates(candidates: &mut Vec<(SymbolId, Decl)>) {
    let mut seen = ahash::AHashSet::new();
    candidates.retain(|(sym, _)| seen.insert(*sym));
}

fn db_options_from_open_options(options: WorkspaceOpenOptions) -> AnalyzerDbOptions {
    AnalyzerDbOptions {
        parse_timeout_ms: options.parse_timeout_ms,
    }
}

/// Pipeline-hash fingerprint stamped into the IDG sidecar header. The
/// IDG depends on the matcher-policy fingerprint indirectly (via the
/// alias-target resolver), so reusing the same fold as the dataflow
/// sidecar keeps the two artifacts invalidated together on a rule-pack
/// or engine-policy bump. XOR with a constant tag keeps the IDG hash
/// space disjoint from the dataflow / value-flow sidecars'.
fn idg_pipeline_hash() -> u64 {
    // Bump when IDG construction, call-site stitching, resolver
    // semantics, or side-effect propagation changes without an
    // on-disk layout change. This rejects old `idg.v*.factstore`
    // files whose shape can still decode but whose edges/lineage are
    // no longer semantically equivalent.
    // v28 (2026-07-04): `bridge_return_expression_calls` now forwards
    // the return-expression's span node into the scalar `Return` place,
    // restoring interprocedural taint for `return <source-expr>` (e.g.
    // `return os.environ["CMD"]`) that had no call in the return span.
    // v26 (2026-06-05): Constructor-like assignment RHS calls now
    // propagate argument taint into the constructed receiver state
    // for receiver-tainted sink checks.
    // v25 (2026-06-04): Ruby terminal `super` returns now emit a
    // semantic super-call FlowEvent, changing callgraph/IDG edges.
    // v24 (2026-06-04): IDG callback and class/base fallback lookups
    // are scoped by module/directory/file so copied projects with
    // identical helper/class names do not cross-wire semantic edges.
    // v23 (2026-05-27): transfer.rs source-seeding changes
    // (method-receiver-base SemanticSourceFilter exemption +
    // container-input span-containment linkage), service.rs
    // return-position source-seeding fallback, and adapter member
    // synthesis (C# expression-bodied-property getters / record members,
    // Java records, Solidity struct-literal field writes) all change the
    // built IDG without an on-disk layout change.
    let raw = bonsai_common::MATCHER_POLICY_FINGERPRINT;
    let lo = raw as u64;
    let hi = (raw >> 64) as u64;
    lo ^ hi ^ idg_stitching_semantic_fingerprint()
}

/// Semantic-only IDG construction fingerprint shared with caches whose
/// payloads embed IDG-derived reachability. Keep build/content/rule hashes out
/// of this value so callers can combine it without XOR-cancelling their own
/// freshness inputs.
pub(crate) const fn idg_stitching_semantic_fingerprint() -> u64 {
    // v33 (2026-07-10): IDG positional parameter/call-argument identities
    // use u32 end-to-end, so positions above 254 no longer collide with the
    // synthetic receiver/return sentinel.
    // v34 (2026-07-15): projected field state has distinct interprocedural
    // edge provenance, so it cannot be decoded as a scalar call boundary.
    // v35 (2026-07-15): a resolved nested-expression edge is indexed only on
    // the Tree-sitter call event that owns its resolved target.
    // v36 (2026-07-15): implicit higher-order flow requires an indirect
    // callgraph edge inside an explicit argument; name equality is not type
    // evidence that an ordinary value is callable.
    // v37 (2026-07-15): callback-parameter binding likewise requires an
    // indirect callgraph edge inside the exact AST argument span.
    // v38 (2026-07-15): a nested indirect callable-argument edge cannot use
    // the constructor-name exception to replace its enclosing call target.
    // v39 (2026-07-15): lexical parameters/locals shadow same-spelled
    // callable declarations, and Dart's ambiguous bare call syntax is
    // refined against scoped class declarations before IDG stitching.
    // v40 (2026-07-15): demanded symbolic access-path call boundaries retain
    // closure provenance, and resolved projected call arguments are distinct
    // from synthetic allocation-insensitive field-state links.
    // v41 (2026-07-15): symbolic call provenance retains AST argument and
    // formal slots without materializing access-path edges.
    // v42 (2026-07-19): whole-aggregate consumption has explicit edge
    // provenance. Unresolved/external consumers retain scalar argument
    // evidence, while resolved local boundaries render only exact projected
    // field stitching instead of promoting sibling fields.
    // v43 (2026-07-20): persisted symbolic argument transforms carry the
    // exact AST argument and resolved formal slots established while
    // stitching, so query/export facades never need resident function bodies.
    // v44 (2026-07-20): source-reachable planning streams exact bodies from
    // compact headers and retains return/callback scope facts in the compiler
    // linkage projection; cached taint graphs from the incomplete scope are
    // therefore invalid.
    // v45 (2026-07-22): projected field forwarding reaches the finite
    // AST-demanded suffix fixed point without split-view duplicate states,
    // and contextual return composition matches exact structural
    // caller/callee/span boundaries. Rebuild IDG and taint sidecars because
    // recursive field and symbolic return reachability can change.
    // v46 (2026-07-22): exact projected Read/Write nodes participate in
    // synthetic write attribution. Rebuild taint sidecars so cached graphs
    // cannot retain the former bare-local-only evidence surface.
    // v47 (2026-07-22): taint evidence attribution renders reachable storage
    // names directly from numeric IDG places and always hydrates the exact
    // per-file compiler object instead of treating non-empty compact linkage
    // headers as complete function bodies.
    // v48 (2026-07-25): compact linkage records AST-consumed call-result and
    // write-back demand, and target-emission corridors compile only demanded
    // return/mutation providers. Rebuild IDG and linkage sidecars so an older
    // broad provider projection cannot be reused as the compiler contract.
    // v49 (2026-07-27): call-result source pruning canonicalizes adapter-owned
    // identifier sigils before separating argument carriers from independent
    // RHS sources. Rebuild IDG/taint sidecars so warm Perl/PHP workspaces
    // cannot retain the former spurious argument-source edges.
    // v50 (2026-07-28): a whole call-result writer feeds later compiler
    // projections when no exact projected writer exists. Rebuild IDG and
    // taint sidecars so warm workspaces cannot retain the missing def-use
    // edge or a target-relevance proof derived from it.
    // v51 (2026-07-28): restrict that fallback to true root bindings;
    // projected call-result assignments remain governed by the finite AST
    // projection-demand closure. Invalidate the broader v50 sidecars.
    // v52 (2026-07-30): compiler-object v11 corrects class-like taxonomy and
    // anonymous-body ownership. Invalidate stitched graphs whose call/member
    // edges were derived from the former ownership facts.
    // v53 (2026-07-30): nested class-like declarations retain the complete
    // AST lexical-parent chain. Rebuild resolver/IDG/taint facts so nested
    // interface and class members cannot reuse truncated owner identities.
    // v54 (2026-07-31): standalone lambdas/local callables retain their
    // Tree-sitter lexical parent, Perl package calls use static identity, and
    // adapter-declared implicit class receivers resolve inherited
    // constructors. Rebuild linkage, callgraph, IDG, and taint facts whose
    // identities or attribution depend on those compiler semantics.
    const IDG_STITCHING_SEMANTIC_VERSION: u64 = 55;
    0xBEEF_C0DE_DEAD_FACE_u64 ^ IDG_STITCHING_SEMANTIC_VERSION
}

/// Build-time producer fingerprint emitted by `build.rs`.
///
/// Presentation and aggregate metadata retain the release/commit identity for
/// provenance. Semantic compiler sidecars use their own ABI version and exact
/// source, dependency, matcher, rule, and transfer fingerprints; producer
/// identity is never used as a substitute for those compiler inputs.
pub(crate) fn build_fingerprint_hash() -> u64 {
    const FINGERPRINT_HEX: &str = env!(
        "BONSAI_BUILD_FINGERPRINT_HASH",
        "build.rs must emit BONSAI_BUILD_FINGERPRINT_HASH"
    );
    u64::from_str_radix(FINGERPRINT_HEX, 16).unwrap_or(0)
}

/// Analyzer build identity shared by semantic and presentation caches.
///
/// The workspace build script binds this to the release version and Git
/// commit. Cache correctness is governed separately by explicit semantic and
/// source fingerprints.
#[must_use]
pub fn analyzer_build_fingerprint() -> &'static str {
    env!(
        "BONSAI_BUILD_FINGERPRINT",
        "build.rs must emit BONSAI_BUILD_FINGERPRINT"
    )
}

fn idg_workspace_pipeline_hash(db: &AnalyzerDb, root: Option<&Path>) -> u64 {
    let mut pipeline_hash = idg_pipeline_hash()
        ^ crate::cache_fingerprint::workspace_content_fingerprint(db)
        ^ default_workspace_idg_transfer_options(db).semantic_fingerprint()
        ^ u64::from(callgraph_sidecar::CALLGRAPH_CACHE_VERSION).wrapping_mul(0x9E37_79B1_85EB_CA87);
    if let Some(root) = root {
        pipeline_hash ^= crate::cache_fingerprint::dependency_metadata_fingerprint(root);
    }
    pipeline_hash
}

fn default_workspace_idg_transfer_options(db: &AnalyzerDb) -> bonsai_idg::TransferOptions {
    bonsai_idg::TransferOptions::compiler_semantics(db.complete_field_place_languages())
}

fn idg_transfer_options_fingerprint(options: &bonsai_idg::TransferOptions) -> u64 {
    options.semantic_fingerprint()
}

fn idg_file_scope_fingerprint(files: &[FileId]) -> u64 {
    let mut file_ids: Vec<u32> = files.iter().map(|file| file.raw()).collect();
    file_ids.sort_unstable();
    file_ids.dedup();

    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-idg-file-scope-v1");
    hasher.absorb_separator();
    hasher.absorb(&(file_ids.len() as u64).to_le_bytes());
    hasher.absorb_separator();
    for file in file_ids {
        hasher.absorb(&file.to_le_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

fn idg_func_scope_fingerprint(funcs: &[FuncId]) -> u64 {
    let mut func_ids: Vec<u32> = funcs.iter().map(|func| func.raw()).collect();
    func_ids.sort_unstable();
    func_ids.dedup();

    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-idg-func-scope-v1");
    hasher.absorb_separator();
    hasher.absorb(&(func_ids.len() as u64).to_le_bytes());
    hasher.absorb_separator();
    for func in func_ids {
        hasher.absorb(&func.to_le_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

fn idg_call_graph_fingerprint(call_graph: &bonsai_callgraph::ResolvedCallGraph) -> u64 {
    let mut edges: Vec<_> = call_graph
        .inner()
        .edges
        .iter()
        .map(|edge| {
            let kind = match edge.kind {
                bonsai_callgraph::EdgeKind::Direct => 0_u8,
                bonsai_callgraph::EdgeKind::Virtual => 1,
                bonsai_callgraph::EdgeKind::Indirect => 2,
                bonsai_callgraph::EdgeKind::Unknown => 3,
            };
            (
                edge.from.raw(),
                edge.to.raw(),
                edge.span.file.raw(),
                edge.span.start,
                edge.span.end,
                kind,
                edge.precision.rank(),
            )
        })
        .collect();
    edges.sort_unstable();

    let mut bindings: Vec<_> = call_graph.local_callable_bindings().collect();
    bindings.sort_unstable_by(|left, right| {
        (left.0.raw(), left.1, left.2.raw()).cmp(&(right.0.raw(), right.1, right.2.raw()))
    });

    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-idg-call-graph-v1");
    hasher.absorb_separator();
    hasher.absorb(&(edges.len() as u64).to_le_bytes());
    hasher.absorb_separator();
    for (from, to, file, start, end, kind, precision) in edges {
        hasher.absorb(&from.to_le_bytes());
        hasher.absorb(&to.to_le_bytes());
        hasher.absorb(&file.to_le_bytes());
        hasher.absorb(&start.to_le_bytes());
        hasher.absorb(&end.to_le_bytes());
        hasher.absorb(&[kind, precision]);
        hasher.absorb_separator();
    }
    hasher.absorb(&(bindings.len() as u64).to_le_bytes());
    hasher.absorb_separator();
    for (caller, name, target) in bindings {
        hasher.absorb(&caller.raw().to_le_bytes());
        hasher.absorb(&(name.len() as u64).to_le_bytes());
        hasher.absorb(name.as_bytes());
        hasher.absorb(&target.raw().to_le_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

fn idg_scoped_semantics_fingerprint(
    transfer_hash: u64,
    file_scope_hash: u64,
    func_scope_hash: Option<u64>,
    call_graph_hash: Option<u64>,
) -> u64 {
    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-idg-scoped-semantics-v2");
    hasher.absorb_separator();
    hasher.absorb(&transfer_hash.to_le_bytes());
    hasher.absorb(&file_scope_hash.to_le_bytes());
    hasher.absorb(&func_scope_hash.unwrap_or_default().to_le_bytes());
    hasher.absorb(&call_graph_hash.unwrap_or_default().to_le_bytes());
    hasher.absorb(&[
        u8::from(func_scope_hash.is_some()),
        u8::from(call_graph_hash.is_some()),
    ]);
    hasher.finish()
}

#[cfg(test)]
#[path = "idg_pipeline_hash_tests.rs"]
mod idg_pipeline_hash_tests;

struct SourceFileContent {
    path: std::path::PathBuf,
    text: String,
    /// Deterministic ordinal among all supported sources in the complete
    /// workspace. Scoped readers retain it so immutable compiler objects
    /// remain addressable by the same `FileId`.
    full_workspace_file: Option<FileId>,
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

/// Hash every supported source file without retaining its contents.
///
/// Fingerprinting is a freshness check, not a parse pass. Keeping all source
/// strings alive here made a single SDK refresh require memory proportional to
/// the whole repository before it could compare one hash. Each Rayon worker
/// now owns one fixed-size read buffer and the result retains only path/hash
/// pairs, matching a compiler's streaming input-fingerprint phase.
fn read_supported_source_file_fingerprints(
    canonical_root: &Path,
    registry: &LanguageRegistry,
) -> Result<Vec<SourceFileFingerprint>, WorkspaceError> {
    let entries = walk_workspace_entries(canonical_root)?;

    use rayon::prelude::*;
    let outcomes: Vec<Result<Option<SourceFileFingerprint>, std::io::Error>> = entries
        .into_par_iter()
        .map(|entry| {
            if !entry.file_type().is_some_and(|file_type| file_type.is_file()) {
                return Ok(None);
            }
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
                return Ok(None);
            };
            if registry.adapter_for_extension(ext).is_none() {
                return Ok(None);
            }

            let mut file = std::fs::File::open(path)?;
            let mut hasher = StableHasher::new();
            // Keep the bounded per-worker buffer off Rayon worker stacks.
            // Optimised iterator frames can otherwise duplicate a large
            // inline array and overflow the platform's default worker stack.
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.absorb(&buffer[..read]);
            }
            Ok(Some(SourceFileFingerprint {
                path: path.to_path_buf(),
                hash: hasher.finish(),
            }))
        })
        .collect();

    let mut fingerprints = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        match outcome {
            Ok(Some(fingerprint)) => fingerprints.push(fingerprint),
            Ok(None) => {}
            Err(error) => return Err(WorkspaceError::Io(error)),
        }
    }
    fingerprints.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(fingerprints)
}

/// Collect metadata-only stamps for supported source files. Unlike
/// `read_supported_source_file_fingerprints`, this never opens a source file.
fn read_supported_source_file_stamps(
    canonical_root: &Path,
    registry: &LanguageRegistry,
) -> Result<Vec<SourceFileStamp>, WorkspaceError> {
    let entries = walk_workspace_entries(canonical_root)?;
    use rayon::prelude::*;
    let outcomes: Vec<Result<Option<SourceFileStamp>, std::io::Error>> = entries
        .into_par_iter()
        .map(|entry| {
            if !entry.file_type().is_some_and(|file_type| file_type.is_file()) {
                return Ok(None);
            }
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
                return Ok(None);
            };
            if registry.adapter_for_extension(ext).is_none() {
                return Ok(None);
            }
            source_file_stamp(path).map(Some)
        })
        .collect();

    let mut stamps = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        match outcome {
            Ok(Some(stamp)) => stamps.push(stamp),
            Ok(None) => {}
            Err(error) => return Err(WorkspaceError::Io(error)),
        }
    }
    stamps.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(stamps)
}

fn source_file_stamp(path: &Path) -> Result<SourceFileStamp, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    #[cfg(unix)]
    let (change_seconds, change_nanoseconds, device, inode) = {
        use std::os::unix::fs::MetadataExt as _;
        (
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.dev(),
            metadata.ino(),
        )
    };
    #[cfg(not(unix))]
    let (change_seconds, change_nanoseconds, device, inode) = (0, 0, 0, 0);
    Ok(SourceFileStamp {
        path: path.to_path_buf(),
        len: metadata.len(),
        modified: metadata.modified().ok(),
        change_seconds,
        change_nanoseconds,
        device,
        inode,
    })
}

fn walk_workspace_entries(canonical_root: &Path) -> Result<Vec<ignore::DirEntry>, WorkspaceError> {
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
    builder.filter_entry(|entry| entry.file_name() != ".bonsai");
    let mut entries = builder
        .build()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| WorkspaceError::Io(std::io::Error::other(error.to_string())))?;
    entries.sort_by(|left, right| left.path().cmp(right.path()));
    Ok(entries)
}

fn stream_supported_source_files<F>(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    mut on_file: F,
) -> Result<(), WorkspaceError>
where
    F: FnMut(SourceFileContent) -> Result<(), WorkspaceError>,
{
    // Inclusion is structural: explicit ignore rules plus the adapter's
    // supported extension. File names and source text are compiler input,
    // never heuristics for dropping otherwise supported programs.
    let entries = walk_workspace_entries(canonical_root)?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_some_and(|file_type| file_type.is_file())
                && entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| registry.adapter_for_extension(extension).is_some())
        })
        .collect::<Vec<_>>();
    let source_bytes = entries
        .iter()
        .map(|entry| entry.metadata().map_or(0, |metadata| metadata.len()))
        .collect::<Vec<_>>();
    let workers = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);

    // Read independent compiler inputs concurrently, but publish each bounded
    // batch to the VFS in sorted path order. This preserves deterministic
    // FileIds and the exact source snapshot while removing a serialized I/O
    // pass from every cold CLI process. The shared syntax scheduler accounts
    // for current RSS and file size, so constrained machines execute smaller
    // batches instead of retaining a second whole-workspace source copy.
    for range in bonsai_common::source_ingestion_batches(&source_bytes, workers) {
        use rayon::prelude::*;
        let batch = entries[range]
            .par_iter()
            .map(|entry| {
                let path = entry.path();
                std::fs::read_to_string(path).map(|text| SourceFileContent {
                    path: path.to_path_buf(),
                    text,
                    full_workspace_file: None,
                })
            })
            .collect::<Vec<_>>();
        for source in batch {
            on_file(source.map_err(WorkspaceError::Io)?)?;
        }
    }

    Ok(())
}

fn read_supported_source_files_matching_literal(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    literal: &str,
) -> Result<Vec<SourceFileContent>, WorkspaceError> {
    read_supported_source_files_impl(
        canonical_root,
        registry,
        Some(std::slice::from_ref(&literal)),
        None,
    )
}

fn read_supported_source_files_matching_literals(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    literals: &[&str],
) -> Result<Vec<SourceFileContent>, WorkspaceError> {
    read_supported_source_files_impl(canonical_root, registry, Some(literals), None)
}

fn read_supported_source_files_filtered_paths(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    include_filters: &[String],
    exclude_filters: &[String],
) -> Result<Vec<SourceFileContent>, WorkspaceError> {
    read_supported_source_files_impl(
        canonical_root,
        registry,
        None,
        Some(PathFilterSpec {
            include_filters,
            exclude_filters,
        }),
    )
}

fn read_supported_source_file_at_path(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    requested_path: &Path,
) -> Result<SourceFileContent, WorkspaceError> {
    let direct_path = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        canonical_root.join(requested_path)
    };
    let path = if direct_path.is_file() || requested_path.is_absolute() {
        direct_path
    } else {
        resolve_unique_supported_source_path(canonical_root, registry, requested_path)?
    };
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return Err(WorkspaceError::NoAdapter(path.display().to_string()));
    };
    if registry.adapter_for_extension(ext).is_none() {
        return Err(WorkspaceError::NoAdapter(ext.to_string()));
    }

    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => return Err(WorkspaceError::Io(error)),
    };
    Ok(SourceFileContent {
        path,
        text,
        full_workspace_file: None,
    })
}

/// Resolve a user-facing file filter to one supported workspace source.
///
/// CLI file options are documented as workspace-relative path filters, so a
/// unique basename such as `executor.rs` must find `src/executor.rs`. Exact
/// paths stay O(1) in [`read_supported_source_file_at_path`]; this metadata
/// walk is only the fallback for a non-exact filter. Ambiguity fails closed
/// with candidate paths instead of silently selecting whichever directory the
/// filesystem happened to enumerate first.
fn resolve_unique_supported_source_path(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    requested_path: &Path,
) -> Result<PathBuf, WorkspaceError> {
    let query = requested_path.to_string_lossy().replace('\\', "/");
    let query = query.trim_start_matches("./");
    let mut candidates = walk_workspace_entries(canonical_root)?
        .into_iter()
        .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            let path = entry.into_path();
            let ext = path.extension()?.to_str()?;
            registry.adapter_for_extension(ext)?;
            let relative = path.strip_prefix(canonical_root).ok()?;
            let normalized = relative.to_string_lossy().replace('\\', "/");
            normalized.contains(query).then_some((normalized, path))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    match candidates.as_slice() {
        [(_, path)] => Ok(path.clone()),
        [] => Err(WorkspaceError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no supported source path matching `{}` under {}",
                requested_path.display(),
                canonical_root.display()
            ),
        ))),
        _ => Err(WorkspaceError::AmbiguousSourcePath {
            query: requested_path.display().to_string(),
            count: candidates.len(),
            candidates: candidates
                .iter()
                .take(8)
                .map(|(relative, _)| relative.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

fn read_supported_source_files_impl(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    literal_filters: Option<&[&str]>,
    path_filter: Option<PathFilterSpec<'_>>,
) -> Result<Vec<SourceFileContent>, WorkspaceError> {
    // Match the streaming path's compiler contract. Literal/path filters are
    // explicit query scopes; no source-shape heuristic may narrow them.
    // The ignore walker follows .gitignore / .ignore / .bonsaiignore but
    // still walks in OS-native order, so a fresh ingest can assign different
    // FileIds to the same paths across runs. Sort by path so allocation and
    // refresh fingerprints are deterministic.
    let entries = walk_workspace_entries(canonical_root)?;

    // Read files in parallel. The prior sequential `for entry in
    // entries { read_to_string(...) }` loop blocked the downstream
    // parallel decl-index pass on a single core for ~30ms per file
    // — minutes wasted on cold-FS-cache OWASP / Redis opens.
    // Determinism: input `entries` is sorted; we sort `files` by
    // path again after the parallel collect so FileId allocation
    // stays deterministic regardless of read-completion order.
    use rayon::prelude::*;
    enum ReadOutcome {
        Keep(SourceFileContent),
        Skip,
        Err(std::io::Error),
    }
    let literal_lowers = literal_filters.map(|literals| {
        literals
            .iter()
            .map(|literal| literal.to_lowercase())
            .collect::<Vec<_>>()
    });
    // Assign the same ordinal as a complete ingest before applying the query
    // filter. This is the compiler's stable file identity; filtering first
    // would renumber candidates and turn valid persistent objects into cache
    // misses. Walking/extension selection is metadata-only and does not parse
    // or read excluded source bodies.
    let supported_entries = entries
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_some_and(|file_type| file_type.is_file())
                && entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| registry.adapter_for_extension(extension).is_some())
        })
        .enumerate()
        .map(|(ordinal, entry)| {
            (
                FileId::new(u32::try_from(ordinal).expect("too many supported source files")),
                entry,
            )
        })
        .collect::<Vec<_>>();
    let outcomes: Vec<ReadOutcome> = supported_entries
        .into_par_iter()
        .map(|(file, entry)| {
            let path = entry.path();
            if let Some(filter) = path_filter {
                if !source_path_allowed(canonical_root, path, filter) {
                    return ReadOutcome::Skip;
                }
            }
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) => return ReadOutcome::Err(error),
            };
            if let Some(literals) = literal_filters {
                let lowers = literal_lowers.as_deref().unwrap_or_default();
                if !literals
                    .iter()
                    .zip(lowers)
                    .any(|(literal, lower)| text_contains_literal_query(&text, literal, lower))
                {
                    return ReadOutcome::Skip;
                }
            }
            ReadOutcome::Keep(SourceFileContent {
                path: path.to_path_buf(),
                text,
                full_workspace_file: Some(file),
            })
        })
        .collect();
    let mut files = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        match outcome {
            ReadOutcome::Keep(file) => files.push(file),
            ReadOutcome::Skip => {}
            ReadOutcome::Err(error) => return Err(WorkspaceError::Io(error)),
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

#[derive(Clone, Copy)]
struct PathFilterSpec<'a> {
    include_filters: &'a [String],
    exclude_filters: &'a [String],
}

fn source_path_allowed(root: &Path, path: &Path, filter: PathFilterSpec<'_>) -> bool {
    let relative = normalize_path_for_filter(
        &semantic_context::context_relative_path(Some(root), path).to_string_lossy(),
    );
    let absolute = normalize_path_for_filter(&path.to_string_lossy());
    (filter.include_filters.is_empty()
        || filter
            .include_filters
            .iter()
            .any(|include| path_filter_matches_scoped(&relative, &absolute, include)))
        && !filter
            .exclude_filters
            .iter()
            .any(|exclude| path_filter_matches_scoped(&relative, &absolute, exclude))
}

fn path_filter_matches_scoped(relative: &str, absolute: &str, filter: &str) -> bool {
    if path_filter_matches(relative, filter) {
        return true;
    }
    filter_looks_like_absolute_path(filter) && path_filter_matches(absolute, filter)
}

fn filter_looks_like_absolute_path(filter: &str) -> bool {
    let normalized = normalize_path_for_filter(filter);
    if normalized.len() >= 3 && normalized.as_bytes()[1] == b':' && normalized.as_bytes()[2] == b'/' {
        return true;
    }
    Path::new(filter).is_absolute() && normalized.trim_matches('/').contains('/')
}

fn path_filter_matches(path: &str, filter: &str) -> bool {
    let path = normalize_path_for_filter(path);
    let filter = normalize_path_for_filter(filter);
    if filter.is_empty() {
        return false;
    }
    if let Some(root_relative) = filter.strip_prefix('^') {
        let root_relative = root_relative.trim_start_matches('/');
        if root_relative.is_empty() {
            return false;
        }
        let path = path.trim_start_matches('/');
        let root_relative = root_relative.trim_end_matches('/');
        return path == root_relative || path.starts_with(&format!("{root_relative}/"));
    }
    if filter.contains('/') {
        return path_filter_with_separator_matches(&path, &filter);
    }
    path.contains(filter.as_str())
}

fn path_filter_with_separator_matches(path: &str, filter: &str) -> bool {
    let trimmed = filter.trim_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    if filter.starts_with('/') || filter.ends_with('/') {
        // Anchored comparison must strip the path's own leading slash the
        // same way the filter was trimmed, or an explicit absolute filter
        // (`/abs/ws/app.py`) can never equal the absolute path it names.
        let anchored = path.trim_start_matches('/');
        return anchored == trimmed
            || anchored.starts_with(&format!("{trimmed}/"))
            || path.contains(&format!("/{trimmed}/"));
    }
    path.contains(filter)
}

fn normalize_path_for_filter(path: &str) -> String {
    path.replace('\\', "/")
}

fn text_contains_literal_query(text: &str, literal: &str, literal_lower: &str) -> bool {
    text.contains(literal) || text.to_lowercase().contains(literal_lower)
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

#[cfg(test)]
#[path = "ingestion_tests.rs"]
mod ingestion_tests;

#[cfg(test)]
mod symbol_lookup_spec_tests {
    use super::*;

    #[test]
    fn basename_line_name_is_file_qualified_lookup() {
        let spec = split_symbol_lookup_spec("json.lua:189:codepoint_to_utf8");
        assert_eq!(spec.file, Some("json.lua"));
        assert_eq!(spec.line, Some(189));
        assert_eq!(spec.name, "codepoint_to_utf8");
    }

    #[test]
    fn module_style_colon_without_line_stays_bare_name() {
        let spec = split_symbol_lookup_spec("My.Module:run");
        assert_eq!(spec.file, None);
        assert_eq!(spec.line, None);
        assert_eq!(spec.name, "My.Module:run");
    }
}
