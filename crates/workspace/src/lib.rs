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
pub mod flow_ids;
pub mod flow_ids_disk;
pub mod flow_query;
pub mod semantic_context;
pub mod taint_index;
pub mod taint_index_disk;
pub mod transitive_callers;
pub mod value_flow;
pub mod value_flow_disk;

use ahash::{AHashMap, AHashSet};
use bonsai_common::{callable_reference_variants, short_qualified_tail, FileId, FuncId, Precision, SymbolId};
use bonsai_db::{AnalyzerDb, AnalyzerDbOptions, DbStats};
use bonsai_diagnostics::Diagnostic;
use bonsai_hash::Hasher as StableHasher;
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{Decl, DeclKind, FlowEvent, LanguageRegistry};
use bonsai_taint::{InterTaintCaches, KindedTokens};
use bonsai_trace::{finalize, FinalizeCtx, TraceQuery, TraceQueryKind, TraceResult};
use bonsai_vfs::Vfs;
use class_index::ClassMemberIndex;
use cross_module::CrossModuleTracer;
use dataflow::DataFlowCache;
use decl_name_index::DeclNameIndex;
use enclosing_index::EnclosingIndex;
use flow_ids::FlowIdCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path, sync::Arc};
use taint_index::TaintGraphIndex;
use thiserror::Error;
use transitive_callers::TransitiveCallersIndex;
use value_flow::ValueFlowCache;

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
    pub files: Vec<FileId>,
    pub funcs: Vec<FuncId>,
    pub reached_targets: usize,
}

/// Conventional workspace IDG sidecar path under `<workspace>/.bonsai/`.
#[must_use]
pub fn idg_sidecar_path(workspace_root: &Path) -> std::path::PathBuf {
    bonsai_idg::workspace::idg_sidecar_path(workspace_root)
}

/// Validate that an existing workspace IDG sidecar is structurally readable.
pub fn validate_idg_sidecar_file(path: &Path) -> bonsai_idg::IdgResult<usize> {
    bonsai_idg::workspace::IdgWorkspace::validate_sidecar_file(path)
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
        || summary_output_shape(&decl.flow_events)
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
    let target_keys = function_reference_keys(global, target_funcs);
    if target_keys.is_empty() {
        return;
    }
    let mut changed = true;
    while changed {
        changed = false;
        let lineage: Vec<FuncId> = funcs.iter().copied().collect();
        for func in lineage {
            for edge in callees_of(func) {
                if max_precision.is_some_and(|max| edge.precision > max) || funcs.contains(&edge.to) {
                    continue;
                }
                if !call_edge_passes_target_callback(global, edge.from, edge.span, &target_keys) {
                    continue;
                }
                funcs.insert(edge.to);
                changed = true;
            }
        }
    }
}

fn function_reference_keys(global: &GlobalIndex, funcs: &AHashSet<FuncId>) -> AHashSet<String> {
    let mut out = AHashSet::new();
    for func in funcs {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        push_reference_key(&mut out, &decl.name);
    }
    out
}

fn push_reference_key(out: &mut AHashSet<String>, raw: &str) {
    let raw = raw.trim();
    if raw.is_empty() {
        return;
    }
    out.insert(raw.to_string());
    let tail = short_qualified_tail(raw);
    if !tail.is_empty() {
        out.insert(tail.to_string());
    }
    for variant in callable_reference_variants(raw) {
        let variant = variant.trim();
        if !variant.is_empty() {
            out.insert(variant.to_string());
            let tail = short_qualified_tail(variant);
            if !tail.is_empty() {
                out.insert(tail.to_string());
            }
        }
    }
}

fn call_edge_passes_target_callback(
    global: &GlobalIndex,
    caller: FuncId,
    call_span: bonsai_common::Span,
    target_keys: &AHashSet<String>,
) -> bool {
    let Some(decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return false;
    };
    call_event_at_span_passes_target_callback(&decl.flow_events, call_span, target_keys)
}

fn call_event_at_span_passes_target_callback(
    events: &[FlowEvent],
    call_span: bonsai_common::Span,
    target_keys: &AHashSet<String>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if spans_overlap(*span, call_span)
                    && args
                        .iter()
                        .any(|arg| call_arg_references_target(arg, target_keys))
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if call_event_at_span_passes_target_callback(then_events, call_span, target_keys)
                    || call_event_at_span_passes_target_callback(else_events, call_span, target_keys)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if call_event_at_span_passes_target_callback(body, call_span, target_keys) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if call_event_at_span_passes_target_callback(body, call_span, target_keys)
                    || call_event_at_span_passes_target_callback(catch_events, call_span, target_keys)
                    || call_event_at_span_passes_target_callback(finally_events, call_span, target_keys)
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

fn call_arg_references_target(arg: &bonsai_lang_api::CallArg, target_keys: &AHashSet<String>) -> bool {
    if raw_value_references_target(&arg.value_text, target_keys) {
        return true;
    }
    if arg
        .place
        .as_deref()
        .is_some_and(|place| raw_value_references_target(place, target_keys))
    {
        return true;
    }
    arg.source_names
        .iter()
        .any(|name| raw_value_references_target(name, target_keys))
}

fn raw_value_references_target(raw: &str, target_keys: &AHashSet<String>) -> bool {
    if target_keys.contains(raw.trim()) {
        return true;
    }
    callable_reference_variants(raw)
        .into_iter()
        .any(|variant| target_keys.contains(variant.trim()))
}

pub(crate) fn build_resolved_call_graph_snapshot(db: &AnalyzerDb) -> bonsai_callgraph::ResolvedCallGraph {
    let global = db.global_index();
    bonsai_callgraph::ResolvedCallGraph::build_with_file_info_and_super_tokens(
        global.as_ref(),
        bonsai_callgraph::CallGraphFileSemantics::new(
            |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
            |file| {
                bonsai_lang_api::alias_map_from_import_specs(&db.imports_for(file))
                    .into_iter()
                    .collect()
            },
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
            |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
            |file| {
                db.adapter_for(file)
                    .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
                    .unwrap_or(&[])
            },
            |file| {
                db.adapter_for(file)
                    .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax)
            },
        ),
    )
}

pub(crate) fn build_resolved_call_graph_snapshot_for_files(
    db: &AnalyzerDb,
    included_files: &[FileId],
) -> bonsai_callgraph::ResolvedCallGraph {
    let global = db.global_index();
    bonsai_callgraph::ResolvedCallGraph::build_with_file_info_and_super_tokens_for_files(
        global.as_ref(),
        bonsai_callgraph::CallGraphFileSemantics::new(
            |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
            |file| {
                bonsai_lang_api::alias_map_from_import_specs(&db.imports_for(file))
                    .into_iter()
                    .collect()
            },
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
            |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
            |file| {
                db.adapter_for(file)
                    .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
                    .unwrap_or(&[])
            },
            |file| {
                db.adapter_for(file)
                    .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax)
            },
        ),
        included_files,
    )
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
    /// Workspace-wide singleton for the interprocedural taint engine's
    /// internal caches (resolver answers per `(caller_func, call_span)`,
    /// alias maps per file, function summaries, local bindings). Every
    /// per-source / per-query run shares the same instance, so the
    /// resolver memo lands once per call site instead of per
    /// `InterTaintCaches::default()`. Held in an `Arc` so the dataflow
    /// cache can take a sharing reference at workspace open. Cleared
    /// on file edits via `InterTaintCaches::clear()` (interior
    /// mutability through `parking_lot::RwLock`).
    inter_taint: Arc<InterTaintCaches>,
    /// Memoised workspace-wide resolved call graph. The graph is a
    /// pure function of the indexed decls + import maps + adapter
    /// alias rules, so caching it for the lifetime of one CLI
    /// invocation lets `inspect`, `security taint-analysis`, and
    /// `dump callgraph` share the same instance instead of each
    /// rebuilding from scratch. Cleared on file edits.
    resolved_call_graph: parking_lot::RwLock<Option<Arc<bonsai_callgraph::ResolvedCallGraph>>>,
    /// Workspace-wide cache of `(source_func, seed_set) →
    /// EntryTaintGraph`. Lifted out of the per-invocation
    /// `build_findings_chain_aware` map so a second
    /// `taint-analysis`/`source-analysis` against the same workspace
    /// (within one CLI process or one SDK session) is a lookup
    /// instead of a full per-source interprocedural pass.
    taint_index: TaintGraphIndex,
    /// One source/taint scan at a time may own the index's active semantic
    /// configuration and write-through session. The scan's internal IDG work
    /// remains parallel.
    taint_analysis_serial: Mutex<()>,
    /// Single-flight guard for the canonical default workspace IDG. Configured
    /// services use AnalyzerDb's per-fingerprint OnceLock map.
    idg_default_build_serial: Mutex<()>,
    /// Memoised transitive caller closures on the resolved call
    /// graph. The closure is rulepack-independent — selection by
    /// `source_returning_indices` is a post-hoc filter — so a
    /// second `taint-analysis` against a different rulepack still
    /// hits the cache. Cleared on file edit.
    transitive_callers: TransitiveCallersIndex,
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
    /// path can persist its versioned sidecar under `<root>/.bonsai/`
    /// without re-threading the path through every call site.
    /// `None` for tests / synthetic workspaces that open without a
    /// real on-disk root; persistence is skipped silently in that case.
    idg_sidecar_root: Mutex<Option<std::path::PathBuf>>,
    /// True only when this workspace was opened over the complete
    /// supported source set under `workspace_root`. Literal-, path-,
    /// and filter-scoped query workspaces are exact for their scoped
    /// command, but must not publish reusable whole-workspace sidecars
    /// under the shared `.bonsai/` directory.
    complete_workspace_index: Mutex<bool>,
}

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
#[derive(Clone, Debug, Eq, PartialEq)]
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
                taint_index: TaintGraphIndex::new(),
                taint_analysis_serial: Mutex::new(()),
                idg_default_build_serial: Mutex::new(()),
                transitive_callers: TransitiveCallersIndex::new(),
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
    /// analysis pipeline consults it before kicking off the
    /// per-source interprocedural pass, so a second
    /// `taint-analysis`/`source-analysis` query against the same
    /// workspace + rulepack reuses the cached graph instead of
    /// re-running the engine. Cleared on file edits.
    pub fn taint_index(&self) -> &TaintGraphIndex {
        &self.inner.taint_index
    }

    /// Hold the Workspace's source-seeded graph configuration/session for a
    /// complete security scan. Concurrent SDK scans otherwise could clear or
    /// finish one another's write-through state.
    pub fn lock_taint_analysis(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.inner.taint_analysis_serial.lock()
    }

    /// Workspace-cached transitive caller closures on the resolved
    /// call graph. `taint-analysis` consults this when scheduling
    /// caller-frontier expansion for source-returning helpers; the
    /// closure is rulepack-independent so the cache survives
    /// rulepack swaps. Builds on first request, cleared on edit.
    pub fn transitive_callers(&self) -> &TransitiveCallersIndex {
        &self.inner.transitive_callers
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
        let computed = Arc::new(bonsai_taint::name_reachable_through_func_kinded(
            func,
            &self.inner.db,
        ));
        let mut map = self.inner.reachable_kinded.write();
        map.entry(func).or_insert(computed).clone()
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
        *self.inner.resolved_call_graph.write() = Some(graph);
    }

    /// Load the conventional callgraph sidecar for `root` and seed
    /// the workspace's `cached_resolved_call_graph` slot if every
    /// recorded `(path, content_hash)` matches current state.
    /// Returns `true` when the sidecar was a hit.
    pub fn load_callgraph_sidecar(&self, root: &Path) -> bool {
        let path = callgraph_sidecar::callgraph_sidecar_path(root);
        if let Some(graph) = callgraph_sidecar::load_callgraph_sidecar(&path, &self.inner.db) {
            self.seed_resolved_call_graph(Arc::new(graph));
            true
        } else {
            false
        }
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
        callgraph_sidecar::save_callgraph_sidecar(&path, &self.inner.db, &graph)
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
        let pipeline_hash = idg_workspace_pipeline_hash(&self.inner.db, Some(root));
        let Some(loaded) = bonsai_idg::workspace::IdgWorkspace::load_from_disk(&sidecar, pipeline_hash)?
        else {
            return Ok(None);
        };
        let segment_count = loaded.segment_count();
        let global = self.inner.db.global_index();
        let service = Arc::new(bonsai_idg::IdgQueryService::new(Arc::new(loaded), global));
        self.inner.db.set_idg_service(service);
        Ok(Some(segment_count))
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
        let built = self.build_resolved_call_graph();
        let arc = Arc::new(built);
        let mut slot = self.inner.resolved_call_graph.write();
        if let Some(existing) = slot.as_ref().cloned() {
            // Another thread populated the cache while we built —
            // discard our copy and return the established singleton
            // so downstream pointer-equality checks remain stable.
            return existing;
        }
        *slot = Some(arc.clone());
        arc
    }

    fn build_resolved_call_graph(&self) -> bonsai_callgraph::ResolvedCallGraph {
        build_resolved_call_graph_snapshot(&self.inner.db)
    }

    pub fn source_reachable_resolved_call_graph(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &[FuncId],
        max_precision: Option<Precision>,
    ) -> SourceReachableCallGraph {
        let global = self.inner.db.global_index();
        let target_set: AHashSet<FuncId> = target_funcs.iter().copied().collect();
        let mut reached_funcs: AHashSet<FuncId> = source_funcs.iter().copied().collect();
        let mut reverse_output_funcs: AHashSet<FuncId> = source_funcs
            .iter()
            .copied()
            .filter(|func| has_summary_output(global.as_ref(), *func))
            .collect();
        let mut queued_files: AHashSet<FileId> = AHashSet::new();
        let mut built_files: AHashSet<FileId> = AHashSet::new();
        for func in source_funcs {
            if let Some(file) = global.declaring_file(SymbolId::new(func.raw())) {
                queued_files.insert(file);
            }
        }

        let mut known_edges_by_file: AHashMap<FileId, Vec<bonsai_callgraph::CallEdge>> = AHashMap::new();
        let mut merged = bonsai_callgraph::CallGraph::new();
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
                    .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax)
            },
        );
        while !queued_files.is_empty() {
            let mut batch: Vec<FileId> = queued_files.drain().collect();
            batch.retain(|file| !built_files.contains(file));
            if batch.is_empty() {
                break;
            }
            batch.sort_by_key(|file| file.raw());
            batch.dedup();

            let batch_graph =
                bonsai_callgraph::ResolvedCallGraph::build_with_file_info_and_super_tokens_for_files_with_context(
                    global.as_ref(),
                    |file| bonsai_resolve::alias_map_for_file(&self.inner.db.imports_for(file)),
                    |file| {
                        bonsai_lang_api::alias_map_from_import_specs(&self.inner.db.imports_for(file))
                            .into_iter()
                            .collect()
                    },
                    |file| {
                        self.inner
                            .db
                            .adapter_for(file)
                            .map(|adapter| adapter.capabilities().module_export_aliases)
                            .unwrap_or(&[])
                    },
                    |file| {
                        self.inner
                            .db
                            .adapter_for(file)
                            .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
                            .unwrap_or(&[])
                    },
                    &batch,
                    &callgraph_context,
                );
            for edge in &batch_graph.inner().edges {
                let Some(file) = global.declaring_file(SymbolId::new(edge.from.raw())) else {
                    continue;
                };
                known_edges_by_file.entry(file).or_default().push(edge.clone());
            }
            for file in &batch {
                built_files.insert(*file);
            }

            let mut newly_reached = Vec::new();
            let mut changed = true;
            while changed {
                changed = false;
                for edges in known_edges_by_file.values() {
                    for edge in edges {
                        if max_precision.is_some_and(|max| edge.precision > max) {
                            continue;
                        }
                        if !reached_funcs.contains(&edge.from) {
                            if reverse_output_funcs.contains(&edge.to) {
                                merged.add_edge(edge.clone());
                                if has_summary_output(global.as_ref(), edge.from) {
                                    reverse_output_funcs.insert(edge.from);
                                }
                                if reached_funcs.insert(edge.from) {
                                    newly_reached.push(edge.from);
                                    changed = true;
                                }
                            }
                            continue;
                        }
                        merged.add_edge(edge.clone());
                        if reached_funcs.insert(edge.to) {
                            newly_reached.push(edge.to);
                            changed = true;
                        }
                    }
                }
            }

            for func in newly_reached.drain(..) {
                let Some(file) = global.declaring_file(SymbolId::new(func.raw())) else {
                    continue;
                };
                if !built_files.contains(&file) {
                    queued_files.insert(file);
                }
            }
        }

        let mut return_corridor_funcs: AHashSet<FuncId> = AHashSet::new();
        if !target_set.is_empty() {
            for edges in known_edges_by_file.values() {
                for edge in edges {
                    if max_precision.is_some_and(|max| edge.precision > max) {
                        continue;
                    }
                    if target_set.contains(&edge.from) && reached_funcs.contains(&edge.to) {
                        merged.add_edge(edge.clone());
                        reached_funcs.insert(edge.from);
                        return_corridor_funcs.insert(edge.from);
                        return_corridor_funcs.insert(edge.to);
                    }
                }
            }
        }

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
        let mut edges_by_from: AHashMap<FuncId, Vec<FuncId>> = AHashMap::new();
        for edge in &merged.edges {
            if reached_funcs.contains(&edge.to) {
                edges_by_from.entry(edge.from).or_default().push(edge.to);
            }
        }
        let mut provider_stack: Vec<FuncId> = relevant_funcs.iter().copied().collect();
        while let Some(func) = provider_stack.pop() {
            let Some(callees) = edges_by_from.get(&func) else {
                continue;
            };
            for callee in callees {
                if relevant_funcs.contains(callee) || !has_summary_output(global.as_ref(), *callee) {
                    continue;
                }
                relevant_funcs.insert(*callee);
                provider_stack.push(*callee);
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
            if semantic_funcs.contains(&edge.from) && semantic_funcs.contains(&edge.to) {
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
        SourceReachableCallGraph {
            graph: Arc::new(bonsai_callgraph::ResolvedCallGraph::from_call_graph(filtered)),
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
        let _build_guard = self.inner.idg_default_build_serial.lock();
        // The first caller may have completed while this caller waited.
        if let Some(svc) = self.inner.db.idg_service() {
            return svc;
        }
        let global = self.inner.db.global_index();
        // The IDG references symbols by their global-index id, which
        // is content-derived: any file content change can renumber
        // ids in the new run. Folding a workspace-wide content
        // fingerprint into the pipeline hash makes the factstore
        // header reject a sidecar whose source tree no longer
        // matches, even when no `refresh_file_from_disk` ran inside
        // bonsai-ninja (e.g. `git checkout` between two CLI calls).
        let root_path = self.root_path();
        let pipeline_hash = idg_workspace_pipeline_hash(&self.inner.db, root_path.as_deref());
        let transfer_options = default_workspace_idg_transfer_options(&self.inner.db);
        // Try to hydrate the workspace IDG from the on-disk sidecar
        // before paying for a fresh build. Cold rebuild on Redis `src/`
        // takes >1 minute and dominates `bonsai-ninja security ...`
        // latency; the sidecar reduces it to a single mmap + decode
        // for subsequent invocations against the same content-hashed
        // workspace.
        let use_idg_sidecar = self.is_complete_workspace_index();
        if use_idg_sidecar {
            if let Some(root) = self.root_path() {
                if self.load_idg_sidecar(&root).ok().flatten().is_some() {
                    if let Some(service) = self.inner.db.idg_service() {
                        return service;
                    }
                }
            }
        } else {
            tracing::debug!(
                complete_workspace = self.is_complete_workspace_index(),
                "skipping workspace IDG sidecar load"
            );
        }
        let cg = self.cached_resolved_call_graph();
        // Thread per-file alias maps into the IDG resolver so
        // `import { persist as persistEnvelope }` style alias
        // renames still resolve to the underlying callee. The
        // callgraph already used these maps; the IDG layer now
        // reuses them to keep its name filter from rejecting
        // alias-rewritten call sites.
        let db = &self.inner.db;
        let ws = bonsai_idg::workspace_adapter::build_with_file_info_and_options_with_paths(
            global.as_ref(),
            cg.as_ref(),
            |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
            |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
            |file| {
                db.vfs()
                    .path(file)
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            },
            &transfer_options,
        );
        // Persist before constructing the query service so a subsequent
        // open warm-starts. Failures (read-only filesystem, full disk)
        // are tracing-logged but not surfaced — the in-memory IDG is
        // still valid for this run.
        if use_idg_sidecar {
            if let Some(root) = self.root_path() {
                let sidecar = bonsai_idg::workspace::idg_sidecar_path(&root);
                if let Err(err) = ws.save_to_disk(&sidecar, pipeline_hash) {
                    tracing::warn!(
                        path = %sidecar.display(),
                        error = %err,
                        "workspace IDG save_to_disk failed"
                    );
                }
            }
        } else {
            tracing::debug!(
                complete_workspace = self.is_complete_workspace_index(),
                "skipping workspace IDG sidecar save"
            );
        }
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
        let global = self.inner.db.global_index();
        let root_path = self.root_path();
        let transfer_hash = idg_transfer_options_fingerprint(&transfer_options);
        let pipeline_hash = idg_transfer_pipeline_hash(&self.inner.db, root_path.as_deref(), transfer_hash);
        let use_idg_sidecar = self.is_complete_workspace_index();
        if use_idg_sidecar {
            if let Some(root) = root_path.as_deref() {
                let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, transfer_hash);
                if let Ok(Some(loaded)) =
                    bonsai_idg::workspace::IdgWorkspace::load_from_disk(&sidecar, pipeline_hash)
                {
                    let service =
                        Arc::new(bonsai_idg::IdgQueryService::new(Arc::new(loaded), global.clone()));
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
        let cg = self.cached_resolved_call_graph();
        let db = &self.inner.db;
        let ws = bonsai_idg::workspace_adapter::build_with_file_info_and_options_with_paths(
            global.as_ref(),
            cg.as_ref(),
            |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
            |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
            |file| {
                db.vfs()
                    .path(file)
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            },
            &transfer_options,
        );
        if use_idg_sidecar {
            if let Some(root) = root_path.as_deref() {
                let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, transfer_hash);
                if let Err(err) = ws.save_to_disk(&sidecar, pipeline_hash) {
                    tracing::warn!(
                        path = %sidecar.display(),
                        error = %err,
                        "workspace transfer IDG save_to_disk failed"
                    );
                }
            }
        } else {
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
        let global = self.inner.db.global_index();
        let root_path = self.root_path();
        let transfer_hash = idg_transfer_options_fingerprint(&transfer_options);
        let scope_hash = idg_file_scope_fingerprint(included_files);
        let scoped_hash = transfer_hash ^ scope_hash ^ 0x5C0F_ED1D_65C0_9E5D_u64;
        let pipeline_hash = idg_transfer_pipeline_hash(&self.inner.db, root_path.as_deref(), scoped_hash);
        if let Some(root) = root_path.as_deref() {
            let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, scoped_hash);
            if let Ok(Some(loaded)) =
                bonsai_idg::workspace::IdgWorkspace::load_from_disk(&sidecar, pipeline_hash)
            {
                let service = Arc::new(bonsai_idg::IdgQueryService::new(Arc::new(loaded), global.clone()));
                let service = self.inner.db.set_idg_service_for_semantics(scoped_hash, service);
                return service;
            }
        }
        let cg = build_resolved_call_graph_snapshot_for_files(&self.inner.db, included_files);
        let db = &self.inner.db;
        let ws = bonsai_idg::workspace_adapter::build_with_file_info_and_options_for_files_with_paths(
            global.as_ref(),
            &cg,
            |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
            |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
            |file| {
                db.vfs()
                    .path(file)
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            },
            &transfer_options,
            included_files,
        );
        if let Some(root) = root_path.as_deref() {
            let sidecar = bonsai_idg::workspace::idg_transfer_sidecar_path(root, scoped_hash);
            if let Err(err) = ws.save_to_disk(&sidecar, pipeline_hash) {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %err,
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
        let global = self.inner.db.global_index();
        let db = &self.inner.db;
        let ws =
            bonsai_idg::workspace_adapter::build_with_file_info_and_options_for_files_and_funcs_with_paths(
                global.as_ref(),
                call_graph,
                |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
                |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
                |file| {
                    db.vfs()
                        .path(file)
                        .ok()
                        .map(|path| path.to_string_lossy().into_owned())
                },
                &transfer_options,
                included_files,
                included_funcs,
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

    /// Record the workspace root so [`Self::build_and_seed_idg_service`]
    /// can persist the IDG sidecar next to the other `.bonsai/` files.
    /// Called by the `open*` family once the root path is known.
    fn set_idg_sidecar_root(&self, root: &std::path::Path) {
        *self.inner.idg_sidecar_root.lock() = Some(root.to_path_buf());
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

    /// Drop the persisted IDG sidecar (if any) so a stale snapshot
    /// can't survive a file edit. Best-effort: missing file and
    /// permission errors are swallowed since the in-memory invalidation
    /// is the authoritative source of truth.
    fn delete_idg_sidecar(&self) {
        if let Some(root) = self.root_path() {
            let _ = std::fs::remove_file(bonsai_idg::workspace::idg_sidecar_path(&root));
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
                    if name.starts_with("idg.v")
                        && name.contains(".transfer.")
                        && name.ends_with(".factstore")
                    {
                        let _ = std::fs::remove_file(entry.path());
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
        // A security scan owns a coherent source snapshot from match through
        // IDG closure and sidecar commit. Saved-file refresh waits for that
        // snapshot to finish instead of clearing its caches/write session
        // midway through analysis.
        let _taint_analysis_guard = self.inner.taint_analysis_serial.lock();
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
        self.delete_idg_sidecar();
        self.inner.inter_taint.clear();
        *self.inner.resolved_call_graph.write() = None;
        self.inner.taint_index.clear();
        self.inner.transitive_callers.clear();
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
        ws.set_idg_sidecar_root(root);
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_workspace_root(canonical_root.clone());
        on_event(WorkspaceOpenEvent::IngestStarted);
        let files =
            read_supported_source_files_matching_literal(&canonical_root, &ws.inner.registry, literal)?;
        let file_count = files.len();
        for source in files {
            let path = &source.path;
            let old_id = ws.inner.vfs.lookup(path);
            let id = ws.inner.vfs.write(path.clone(), Arc::<str>::from(source.text));
            if let Some(prev) = old_id {
                ws.invalidate_after_file_change(prev);
            }
            *ws.inner.reparse_counter.lock() += 1;
            let _ = id;
        }
        on_event(WorkspaceOpenEvent::IngestFinished { files: file_count });
        let files = ws.vfs().all_files();
        on_event(WorkspaceOpenEvent::ParseStarted { files: files.len() });
        index_workspace_files_in_parallel(&ws, &files, on_event);
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
        ws.set_idg_sidecar_root(root);
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_workspace_root(canonical_root.clone());
        on_event(WorkspaceOpenEvent::IngestStarted);
        let files = read_supported_source_files_filtered_paths(
            &canonical_root,
            &ws.inner.registry,
            include_filters,
            exclude_filters,
        )?;
        let file_count = files.len();
        for source in files {
            let path = &source.path;
            let old_id = ws.inner.vfs.lookup(path);
            let id = ws.inner.vfs.write(path.clone(), Arc::<str>::from(source.text));
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
            index_workspace_files_in_parallel(&ws, &files, on_event);
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
        ws.set_idg_sidecar_root(root);
        ws.set_complete_workspace_index(false);
        let canonical_root = canonical_workspace_root(root);
        *ws.inner.root_label.lock() = root.display().to_string();
        ws.inner.db.set_workspace_root(canonical_root.clone());
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
        ws.set_idg_sidecar_root(root);
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
            index_workspace_files_in_parallel(&ws, &files, on_event);
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
                Err(_) => {
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
            // Build the workspace IDG once the call graph and global
            // index are available, but only when the result can be
            // persisted for later commands. On very large workspaces
            // the sidecar gate intentionally disables the global IDG
            // artifact; eagerly constructing it here would spend
            // minutes materializing a whole-workspace object-field
            // closure that the short-lived index process then drops.
            // Commands that need semantic flow still build their exact
            // requested scope on demand.
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
        *self.inner.root_label.lock() = root.display().to_string();
        self.set_complete_workspace_index(true);
        let canonical_root = canonical_workspace_root(root);
        self.inner.db.set_workspace_root(canonical_root.clone());
        let mut ingested = Vec::new();
        stream_supported_source_files(&canonical_root, &self.inner.registry, |source| {
            let path = &source.path;
            let old_id = self.inner.vfs.lookup(path);
            let id = self.inner.vfs.write(path.clone(), Arc::<str>::from(source.text));
            if let Some(prev) = old_id {
                self.invalidate_after_file_change(prev);
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
        let file = self.inner.vfs.remove(path)?;
        self.invalidate_after_file_change(file);
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
        let old_id = self.inner.vfs.lookup(path);
        let id = self
            .inner
            .vfs
            .write(path.to_path_buf(), Arc::<str>::from(new_text));
        if let Some(prev) = old_id {
            self.invalidate_after_file_change(prev);
        } else {
            self.invalidate_after_file_change(id);
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

    /// Return deterministic parser-coverage reasons for an exact file scope.
    ///
    /// Parsing is a cached compiler query. Parsed-file diagnostics and the
    /// DB-level adapter/index diagnostic sink are both inspected, with file
    /// sets preventing duplicate diagnostics from inflating the counts. A
    /// hard parser, adapter, or VFS failure has no `ParsedFile`, so it is
    /// recorded explicitly instead of allowing a false-complete analysis.
    pub fn parser_incomplete_reasons_for_files(&self, files: &[FileId]) -> Vec<String> {
        let file_set: AHashSet<FileId> = files.iter().copied().collect();
        let mut syntax_error_files = AHashSet::new();
        let mut parse_timeout_files = AHashSet::new();
        let mut parse_failed_files = AHashSet::new();
        let mut record_diagnostic = |diagnostic: &Diagnostic| {
            if file_set.contains(&diagnostic.span.file) {
                match diagnostic.code.as_deref() {
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

        for &file in files {
            match self.inner.db.parse(file) {
                Ok(parsed) => {
                    for diagnostic in &parsed.diagnostics {
                        record_diagnostic(diagnostic);
                    }
                }
                Err(_) => {
                    parse_failed_files.insert(file);
                }
            }
        }
        for diagnostic in self.inner.db.diagnostics() {
            record_diagnostic(&diagnostic);
        }

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

    fn resolve_function_symbol(&self, qualified: &str) -> Result<SymbolId, WorkspaceError> {
        let lookup = split_symbol_lookup_spec(qualified);
        // Bare-name lookups can match multiple symbols when names
        // collide across translation units (the canonical regression
        // is `static fn error()` defined in multiple files).
        // Collect every match in deterministic order, then require a
        // single semantic candidate. The caller must disambiguate
        // instead of letting trace pick a workspace-order winner. A
        // `path:name` or `path:line:name` query narrows that same
        // inventory by declaration location; it never broadens lookup.
        let global = self.inner.db.global_index();
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
        let constructors = self
            .inner
            .class_members
            .constructors_of(&self.inner.db, class_sym);
        if !constructors.is_empty() {
            return constructors
                .into_iter()
                .map(|func| SymbolId::new(func.raw()))
                .collect();
        }
        let global = self.inner.db.global_index();
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
            let candidates = self
                .inner
                .class_members
                .methods_of(&self.inner.db, class_sym, name);
            out.extend(candidates.into_iter().map(|func| SymbolId::new(func.raw())));
        }
        out.sort_by_key(|sym| sym.raw());
        out.dedup();
        out
    }

    fn decl_for_symbol(&self, symbol: SymbolId) -> Option<Decl> {
        self.inner.db.global_index().decl_of(symbol).cloned()
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
        let symbol = self.resolve_function_symbol(qualified)?;
        let call_graph = self.cached_resolved_call_graph();
        let raw = CrossModuleTracer::new(&self.inner.db, call_graph.as_ref(), opts).trace(symbol);
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
        let call_graph = self.cached_resolved_call_graph();
        let raw = CrossModuleTracer::new(&self.inner.db, call_graph.as_ref(), opts).trace(src);
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
            limits: opts.trace_metadata_limits(),
        };
        finalize(raw, ctx, self.inner.vfs.as_ref())
    }
}

fn index_workspace_files_in_parallel<F>(ws: &Workspace, files: &[FileId], on_event: &F)
where
    F: Fn(WorkspaceOpenEvent) + Sync,
{
    let workers = workspace_parse_worker_count();
    if workers <= 1 || files.len() <= 1 {
        for &file in files {
            let _ = ws.db().decl_index(file);
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
                    let _ = ws.db().decl_index(*file);
                    on_event(WorkspaceOpenEvent::ParseFileIndexed);
                });
            });
        }
        Err(_) => {
            for &file in files {
                let _ = ws.db().decl_index(file);
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
    if let Some(requested) = std::env::var("BONSAI_PARSE_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
    {
        return requested.max(1);
    }
    if let Some(requested) = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
    {
        return requested.max(1);
    }
    available
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
    let global = ws.inner.db.global_index();
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
    lo ^ hi ^ idg_stitching_semantic_fingerprint() ^ build_fingerprint_hash()
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
    const IDG_STITCHING_SEMANTIC_VERSION: u64 = 41;
    0xBEEF_C0DE_DEAD_FACE_u64 ^ IDG_STITCHING_SEMANTIC_VERSION
}

/// Build-time fingerprint emitted by `build.rs` — combines
/// `git rev-parse HEAD` with the working-tree dirty hash, folded
/// into a `u64`. Every sidecar's pipeline hash xors this in so an
/// upgraded binary can't reuse caches built by a different analyzer
/// version even if the per-sidecar manual semantic constant wasn't
/// bumped. Falls back to `0` only when the build.rs env var is
/// somehow unset (defense in depth — `build.rs` always emits it).
pub(crate) fn build_fingerprint_hash() -> u64 {
    const FINGERPRINT_HEX: &str = env!(
        "BONSAI_BUILD_FINGERPRINT_HASH",
        "build.rs must emit BONSAI_BUILD_FINGERPRINT_HASH"
    );
    u64::from_str_radix(FINGERPRINT_HEX, 16).unwrap_or(0)
}

/// Analyzer build identity shared by semantic and presentation caches.
///
/// The workspace build script binds this to the git commit plus the actual
/// tracked/untracked dirty payload, so rebuilding after another local source
/// edit cannot reuse artifacts produced by an older analyzer binary.
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
        ^ default_workspace_idg_transfer_options(db).semantic_fingerprint();
    if let Some(root) = root {
        pipeline_hash ^= crate::cache_fingerprint::dependency_metadata_fingerprint(root);
    }
    pipeline_hash
}

fn default_workspace_idg_transfer_options(db: &AnalyzerDb) -> bonsai_idg::TransferOptions {
    bonsai_idg::TransferOptions::compiler_semantics(db.complete_field_place_languages())
}

fn idg_transfer_pipeline_hash(db: &AnalyzerDb, root: Option<&Path>, transfer_hash: u64) -> u64 {
    idg_workspace_pipeline_hash(db, root) ^ transfer_hash ^ 0x71A1_57E7_1D6D_A7A5_u64
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

#[cfg(test)]
#[path = "idg_pipeline_hash_tests.rs"]
mod idg_pipeline_hash_tests;

struct SourceFileContent {
    path: std::path::PathBuf,
    text: String,
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
    let entries = walk_workspace_entries(canonical_root)?;

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
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => return Err(WorkspaceError::Io(error)),
        };
        on_file(SourceFileContent {
            path: path.to_path_buf(),
            text,
        })?;
    }

    Ok(())
}

fn read_supported_source_files_matching_literal(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    literal: &str,
) -> Result<Vec<SourceFileContent>, WorkspaceError> {
    read_supported_source_files_impl(canonical_root, registry, Some(literal), None)
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
    let path = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        canonical_root.join(requested_path)
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
    Ok(SourceFileContent { path, text })
}

fn read_supported_source_files_impl(
    canonical_root: &Path,
    registry: &LanguageRegistry,
    literal_filter: Option<&str>,
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
    let literal_lower = literal_filter.map(str::to_lowercase);
    let outcomes: Vec<ReadOutcome> = entries
        .into_par_iter()
        .map(|entry| {
            if !entry.file_type().is_some_and(|file_type| file_type.is_file()) {
                return ReadOutcome::Skip;
            }
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                return ReadOutcome::Skip;
            };
            if registry.adapter_for_extension(ext).is_none() {
                return ReadOutcome::Skip;
            }
            if let Some(filter) = path_filter {
                if !source_path_allowed(canonical_root, path, filter) {
                    return ReadOutcome::Skip;
                }
            }
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) => return ReadOutcome::Err(error),
            };
            if let Some(literal) = literal_filter {
                if !text_contains_literal_query(&text, literal, literal_lower.as_deref().unwrap_or(literal)) {
                    return ReadOutcome::Skip;
                }
            }
            ReadOutcome::Keep(SourceFileContent {
                path: path.to_path_buf(),
                text,
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
