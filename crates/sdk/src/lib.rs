//! Ergonomic facade SDK for `bonsai-ninja`.
//!
//! Lower-level crates remain public for advanced integrations. This crate
//! gives application code one obvious entry point:
//!
//! ```ignore
//! let bonsai = bonsai_sdk::Bonsai::new().with_rulepack("security-patterns")?;
//! let project = bonsai.index("examples/python/micro")?;
//! let findings = project.security().taint_analysis(Default::default())?;
//! let export = project.export().native_json(Default::default())?;
//! ```
//!
//! The facade owns no independent analysis semantics. Each method delegates to
//! the same SDK/service functions used by the CLI.

use ahash::{AHashMap, AHashSet};
use anyhow::{anyhow, Context, Result};
use bonsai_common::FuncId;
use bonsai_lang_api::{Decl, LanguageRegistry};
use bonsai_workspace::{FileRefreshKind, WorkspaceOpenOptions};
use serde::Serialize;
use std::{
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const DEFAULT_EXPORT_CACHE_FILE: &str = "export.default.v4.json";
static EXPORT_CACHE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub mod read_file;
pub mod tree;

pub use read_file::{
    read_file as build_read_file, FindingDigest, FlowEntryExit, FlowRole, InlinedDecl, LineDeclSpan,
    LineMark, MarkKind, ReadFileFilters, ReadFileOut, ReadFileTruncation, TaintHop,
};
pub use tree::{
    tree as build_tree, CrossEdge, ExternalKind, IndexedStatus, MostSevereFlowSummary, NodeKind,
    SeverityHistogram, TreeFilters, TreeNode, TreeOut, TreeSummary, TreeTruncation,
};

pub use bonsai_browse::{
    ArgOut, ArgsFilters, AstFileDump, AstFilters, AstNode, AstOutcome, CallOut, CallgraphRow, CallsFilters,
    ClassOut, ClassesFilters, CommentOut, CommentsFilters, DefOut, DefsFilters, EdgeRecord, EdgesFilters,
    FlowAnnotator, GraphExportFormat, GraphProjection, HirDump, ImportOut, ImportsFilters, PrecisionClass,
    RefOut, RefsFilters, ResolveFilters, ResolveOutcome, ResolveTrace, SearchFilters, SearchHit, StringOut,
    StringsFilters, TaintFilters, TaintOutcome, TaintReport, VarOut, VarsFilters,
};
pub use bonsai_inspect::{
    chain_matches_filters, chain_to_names, compute_flow_id, compute_flow_labels_from, compute_group_id,
    find_call_span_by_name, find_call_span_to_func_uncached, find_enclosing_func, func_display_name,
    matching_decls, matching_func_ids, name_token_match, CallEdgeResolver, ChainCache, FactKindFilter,
    InspectFilters, Matcher, PrecisionFilter, ResolvedChain,
};
pub use bonsai_security::{
    canonical_sink_audit_applies, drain_runtime_disabled_rules, filter_rules_to_workspace_languages,
    load_rulepack, load_workspace_local_rules, normalise_family, parse_severity, rule_family,
    security_match_rows, select_rules, source_rule_matches_filters, tree_file_rel, workspace_languages,
    AnalysisProgress, CombinedFindingWithChain, CombinedSourceAnalysisCandidate, DependencyInventory,
    DependencyInventoryOptions, DependencyRow, Finding, FindingMatch, FindingStatus, FindingWithChain,
    PackAuditCount, PackAuditFamilyCount, PackAuditLanguage, PackAuditReport, PackInventoryOptions,
    PackRuleRow, PackTreeFile, PackTreeLanguage, PackTreeReport, PackTreeRule, PackValidationIssue,
    PackValidationReport, Rule, RuleKind, RuleMatch, Rulepack, RuntimeDisabledRule, SecurityInventoryOptions,
    SecurityMatchRow, SecurityReport, Severity, SourceAnalysisCandidate, SourceAnalysisOptions,
    SourceAnalysisReport, TaintAnalysisOptions, TaintAnalysisReport, TaintPropagationArg,
    TaintPropagationStep, TrustClass, CANONICAL_SINK_FAMILIES, ECOSYSTEM_SPECIFIC_SINK_AUDIT_LANGS,
    FAMILY_NOT_APPLICABLE,
};
pub use bonsai_trace::{PathSummary, TraceResult, TraceStep, TraceStepKind};
pub use bonsai_workspace::value_flow::{
    ValueFlowCache, ValueFlowEdge, ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind,
};
pub use bonsai_workspace::{
    summarize_precision, CrossModuleOptions, Workspace, WorkspaceError, WorkspaceOpenOptions as OpenOptions,
    WorkspaceStats,
};

pub mod cache {
    pub use bonsai_inspect::cache::{
        CALLEES_CACHE_CAP, CHAINS_CACHE_CAP, DOWNSTREAM_CACHE_CAP, ENCLOSING_CACHE_CAP, REACHABLE_CACHE_CAP,
    };
}

pub mod refs {
    pub use bonsai_browse::refs::read_snippet;
}

pub mod strings {
    pub use bonsai_browse::strings::enclosing_fn_for_file_line;
}

pub mod trace_render {
    pub use bonsai_trace::render::{to_dot, to_json, to_text};
}

/// Progress lifecycle event emitted by [`Bonsai::index_with_progress`]
/// and [`Bonsai::open_with_options_and_progress`].
///
/// The SDK owns workspace opening and indexing; terminal frontends can
/// translate these events into spinners or progress bars without
/// reaching into `bonsai_workspace` internals.
///
/// Re-exported from `bonsai_workspace::WorkspaceOpenEvent` so SDK
/// consumers and the workspace's own `open_with_options_and_events`
/// path see the same variants. Earlier the SDK had a private copy
/// plus a hand-rolled prewarm pipeline; both have been collapsed
/// onto the workspace's canonical implementation.
pub use bonsai_workspace::WorkspaceOpenEvent;

/// SDK configuration and workspace factory.
#[derive(Clone)]
pub struct Bonsai {
    registry: Arc<LanguageRegistry>,
    rulepack_root: Option<PathBuf>,
    rulepack: Option<Arc<Rulepack>>,
    parse_timeout_ms: Option<u64>,
}

impl Default for Bonsai {
    fn default() -> Self {
        Self::new()
    }
}

impl Bonsai {
    /// Create a facade configured with the bundled 21-language registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: bonsai_adapters::all_languages_registry(),
            rulepack_root: None,
            rulepack: None,
            parse_timeout_ms: None,
        }
    }

    /// Replace the language registry. Advanced users can install a custom
    /// registry; most callers should use [`Self::new`].
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<LanguageRegistry>) -> Self {
        self.registry = registry;
        self
    }

    /// Set the per-file tree-sitter parse timeout used while opening
    /// workspaces. A zero duration disables the timeout guard.
    #[must_use]
    pub fn with_parse_timeout(mut self, timeout: Duration) -> Self {
        let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.parse_timeout_ms = Some(millis);
        self
    }

    /// Load and attach a security rulepack. The rulepack classifies
    /// sources, sinks, and sanitizer evidence for security reports; it does
    /// not change the semantic dataflow graph built by [`Self::index`].
    pub fn with_rulepack(mut self, root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let pack = bonsai_security::load_rulepack(&root)
            .map_err(|err| anyhow!("failed to load rulepack `{}`: {err}", root.display()))?;
        self.rulepack_root = Some(root);
        self.rulepack = Some(Arc::new(pack));
        Ok(self)
    }

    /// Parse, index, prewarm dataflow, and save the dataflow sidecar.
    ///
    /// Rulepacks are report classifiers, not propagation inputs: sources,
    /// sinks, and sanitizers are applied by `bonsai_security` after graph
    /// construction. The persisted sidecar therefore has one semantic
    /// propagation profile regardless of the attached rulepack.
    pub fn index(&self, root: impl AsRef<Path>) -> Result<Project> {
        let root = root.as_ref();
        let ws = Workspace::open_with_options(
            root,
            self.registry.clone(),
            self.apply_workspace_options(WorkspaceOpenOptions::default()),
        )?;
        Ok(self.project(root, ws))
    }

    /// Parse, index, prewarm dataflow, and save the dataflow sidecar,
    /// emitting progress events for terminal frontends.
    pub fn index_with_progress<F>(&self, root: impl AsRef<Path>, on_event: F) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        self.open_with_options_and_progress(root, WorkspaceOpenOptions::default(), on_event)
    }

    /// Open a workspace for fast queries: load the dataflow sidecar and compute
    /// misses lazily.
    pub fn open_query(&self, root: impl AsRef<Path>) -> Result<Project> {
        let root = root.as_ref();
        let ws = Workspace::open_with_options(
            root,
            self.registry.clone(),
            self.apply_workspace_options(WorkspaceOpenOptions::query_only()),
        )?;
        Ok(self.project(root, ws))
    }

    /// Open a workspace with explicit sidecar/prewarm behavior.
    pub fn open_with_options(
        &self,
        root: impl AsRef<Path>,
        options: WorkspaceOpenOptions,
    ) -> Result<Project> {
        let root = root.as_ref();
        let ws =
            Workspace::open_with_options(root, self.registry.clone(), self.apply_workspace_options(options))?;
        Ok(self.project(root, ws))
    }

    /// Open a workspace with explicit sidecar/prewarm behavior,
    /// emitting progress events while the SDK owns orchestration.
    pub fn open_with_options_and_progress<F>(
        &self,
        root: impl AsRef<Path>,
        options: WorkspaceOpenOptions,
        on_event: F,
    ) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let root = root.as_ref();
        let ws = self.workspace_with_options_and_progress(root, options, &on_event)?;
        Ok(self.project(root, ws))
    }

    /// Open a root-only cache handle. This does not parse or index the
    /// workspace; it only manages SDK-owned persisted analysis cache files.
    #[must_use]
    pub fn cache(&self, root: impl AsRef<Path>) -> WorkspaceCache {
        WorkspaceCache::new(root)
    }

    /// Return a rulepack facade for rootless pack inspection APIs.
    pub fn security_pack(&self) -> Result<SecurityPack<'_>> {
        let pack = self
            .rulepack
            .as_deref()
            .ok_or_else(|| anyhow!("security pack APIs require Bonsai::with_rulepack(...)"))?;
        Ok(SecurityPack::with_registry(pack, self.registry.clone()))
    }

    /// Find the rulepack directory for a workspace.
    ///
    /// Probes in order: `BONSAI_RULES_DIR`, `<root>/security-patterns`,
    /// `<root>/../security-patterns`, `./security-patterns`. Returns
    /// the first existing path, or `None`. `--rules-dir` overrides.
    #[must_use]
    pub fn discover_rulepack_root(workspace_root: &Path) -> Option<PathBuf> {
        Self::discover_rulepack_root_with(workspace_root, |key| std::env::var_os(key).map(PathBuf::from))
    }

    /// Test variant of [`Self::discover_rulepack_root`] that takes a
    /// custom env-lookup closure (Rust 2024 makes mutating the real
    /// process env unsafe and racy).
    #[must_use]
    pub fn discover_rulepack_root_with<F>(workspace_root: &Path, env_lookup: F) -> Option<PathBuf>
    where
        F: Fn(&str) -> Option<PathBuf>,
    {
        if let Some(env_path) = env_lookup("BONSAI_RULES_DIR") {
            if env_path.exists() {
                return Some(env_path);
            }
        }
        // The parent-less case is silently skipped (root filesystem,
        // single-segment relative path) — fabricating a path would
        // surface as a confusing "no such file" later.
        let mut candidates: Vec<PathBuf> = Vec::with_capacity(3);
        candidates.push(workspace_root.join("security-patterns"));
        if let Some(parent) = workspace_root.parent() {
            candidates.push(parent.join("security-patterns"));
        }
        candidates.push(PathBuf::from("security-patterns"));
        candidates.into_iter().find(|path| path.exists())
    }

    /// Wrap an opened workspace in the [`Project`] facade with the
    /// SDK's current registry and rulepack handles attached.
    fn project(&self, root: &Path, workspace: Workspace) -> Project {
        Project {
            root: root.to_path_buf(),
            workspace,
            registry: self.registry.clone(),
            rulepack: self.rulepack.clone(),
            rulepack_root: self.rulepack_root.clone(),
            fingerprints: Arc::new(Mutex::new(initial_fingerprints(root, &self.registry))),
        }
    }

    /// Layer the SDK-configured parse timeout (if any) over the
    /// caller-supplied open options. SDK-level config wins because
    /// it represents the user's explicit override.
    fn apply_workspace_options(&self, mut options: WorkspaceOpenOptions) -> WorkspaceOpenOptions {
        if let Some(ms) = self.parse_timeout_ms {
            options.parse_timeout_ms = Some(ms);
        }
        options
    }

    fn workspace_with_options_and_progress<F>(
        &self,
        root: &Path,
        options: WorkspaceOpenOptions,
        on_event: &F,
    ) -> Result<Workspace>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        match std::fs::metadata(root) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => anyhow::bail!("workspace path is not a directory: {}", root.display()),
            Err(err) => anyhow::bail!("workspace not accessible: {} ({err})", root.display()),
        }
        // Single source of truth: every prewarm + sidecar pass
        // lives in `Workspace::open_with_options_and_events`. The
        // SDK is now a thin wrapper that forwards events. Earlier
        // this method hand-rolled a parallel implementation that
        // drifted from the workspace's pipeline every time a new
        // cache landed there but not here — the OWASP single-core
        // cliff was reintroduced multiple times before being
        // collapsed onto this delegation.
        let opts = self.apply_workspace_options(options);
        Workspace::open_with_options_and_events(root, self.registry.clone(), opts, on_event)
            .with_context(|| format!("opening workspace at {}", root.display()))
    }
}

/// Opened/indexed project handle.
#[derive(Clone)]
pub struct Project {
    root: PathBuf,
    workspace: Workspace,
    registry: Arc<LanguageRegistry>,
    rulepack: Option<Arc<Rulepack>>,
    rulepack_root: Option<PathBuf>,
    fingerprints: Arc<Mutex<AHashMap<PathBuf, u64>>>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct WorkspaceRefreshReport {
    pub added: usize,
    pub modified: usize,
    pub removed: usize,
    pub dataflow_entries_built: usize,
}

impl WorkspaceRefreshReport {
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.added > 0 || self.modified > 0 || self.removed > 0
    }
}

impl Project {
    /// Wrap an already-open lower-level [`Workspace`] in the ergonomic
    /// facade. This is mainly for frontends that need custom progress or
    /// logging around workspace open but still want grouped SDK APIs.
    #[must_use]
    pub fn from_workspace(root: impl AsRef<Path>, workspace: Workspace) -> Self {
        Self::from_workspace_with_registry(root, workspace, bonsai_adapters::all_languages_registry())
    }

    /// Wrap an already-open lower-level [`Workspace`] with an explicit
    /// registry for SDK APIs that build synthetic examples, such as
    /// rulepack validation.
    #[must_use]
    pub fn from_workspace_with_registry(
        root: impl AsRef<Path>,
        workspace: Workspace,
        registry: Arc<LanguageRegistry>,
    ) -> Self {
        let root = root.as_ref();
        Self {
            root: root.to_path_buf(),
            workspace,
            fingerprints: Arc::new(Mutex::new(initial_fingerprints(root, &registry))),
            registry,
            rulepack: None,
            rulepack_root: None,
        }
    }

    /// Attach a loaded rulepack to an existing project facade.
    #[must_use]
    pub fn with_loaded_rulepack(mut self, root: impl AsRef<Path>, rulepack: Rulepack) -> Self {
        self.rulepack_root = Some(root.as_ref().to_path_buf());
        self.rulepack = Some(Arc::new(rulepack));
        self
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn workspace(&self) -> &Workspace {
        self.refresh_from_disk_best_effort();
        &self.workspace
    }

    #[must_use]
    pub fn registry(&self) -> &LanguageRegistry {
        &self.registry
    }

    #[must_use]
    pub fn rulepack(&self) -> Option<&Rulepack> {
        self.rulepack.as_deref()
    }

    #[must_use]
    pub fn rulepack_root(&self) -> Option<&Path> {
        self.rulepack_root.as_deref()
    }

    #[must_use]
    pub fn stats(&self) -> bonsai_workspace::WorkspaceStats {
        self.refresh_from_disk_best_effort();
        self.workspace.stats()
    }

    #[must_use]
    pub fn diagnostics(&self) -> Vec<bonsai_diagnostics::Diagnostic> {
        self.refresh_from_disk_best_effort();
        self.workspace.diagnostics()
    }

    /// Refresh this long-lived project from the current on-disk source
    /// tree. Modified files are reparsed and reindexed in place; deleted
    /// files are removed from the live VFS/global index; new files are
    /// added and force a conservative dataflow rebuild because they can
    /// introduce new call-resolution targets. When anything changed, the
    /// dataflow sidecar is warmed and written back for the next process.
    pub fn refresh_from_disk(&self) -> Result<WorkspaceRefreshReport> {
        let current = self
            .workspace
            .source_file_fingerprints(&self.root)
            .with_context(|| format!("scanning {}", self.root.display()))?;
        let current_map: AHashMap<PathBuf, u64> =
            current.into_iter().map(|file| (file.path, file.hash)).collect();

        let mut previous = self.fingerprints.lock().expect("fingerprint lock");
        let previous_paths: AHashSet<PathBuf> = previous.keys().cloned().collect();
        let current_paths: AHashSet<PathBuf> = current_map.keys().cloned().collect();

        let mut report = WorkspaceRefreshReport::default();
        for path in previous_paths.difference(&current_paths) {
            if self.workspace.remove_file_from_index(path).is_some() {
                report.removed += 1;
            }
        }

        let mut changed_paths: Vec<PathBuf> = current_map
            .iter()
            .filter_map(|(path, hash)| {
                if previous.get(path).copied() == Some(*hash) {
                    None
                } else {
                    Some(path.clone())
                }
            })
            .collect();
        changed_paths.sort();
        for path in changed_paths {
            let refresh = self
                .workspace
                .refresh_file_from_disk(&path)
                .with_context(|| format!("refreshing {}", path.display()))?;
            match refresh.kind {
                FileRefreshKind::Added => report.added += 1,
                FileRefreshKind::Modified => report.modified += 1,
                FileRefreshKind::Unchanged => {}
            }
        }

        if report.changed() {
            let pending = self.workspace.dataflow().pending_count(self.workspace.db());
            self.workspace.dataflow().prewarm_all(self.workspace.db());
            report.dataflow_entries_built = pending;
            let _ = self.save_dataflow_sidecar();
            *previous = current_map;
        }
        Ok(report)
    }

    fn refresh_from_disk_best_effort(&self) {
        let _ = self.refresh_from_disk();
    }

    /// Rebuild the live dataflow cache using the semantic propagation
    /// profile. Rulepack sanitizers are report evidence and do not mutate
    /// this graph.
    pub fn reindex_dataflow(&self) {
        self.workspace.reindex_dataflow();
    }

    pub fn save_dataflow_sidecar(&self) -> std::io::Result<()> {
        self.workspace.save_dataflow_sidecar(&self.root)
    }

    pub fn load_dataflow_sidecar(&self) -> std::io::Result<usize> {
        self.workspace.load_dataflow_sidecar(&self.root)
    }

    #[must_use]
    pub fn cache(&self) -> Cache<'_> {
        Cache { project: self }
    }

    #[must_use]
    pub fn browse(&self) -> Browse<'_> {
        self.refresh_from_disk_best_effort();
        Browse { project: self }
    }

    #[must_use]
    pub fn dump(&self) -> Dump<'_> {
        self.refresh_from_disk_best_effort();
        Dump { project: self }
    }

    #[must_use]
    pub fn export(&self) -> Export<'_> {
        self.refresh_from_disk_best_effort();
        Export { project: self }
    }

    #[must_use]
    pub fn security(&self) -> Security<'_> {
        self.refresh_from_disk_best_effort();
        Security { project: self }
    }

    #[must_use]
    pub fn trace(&self) -> Trace<'_> {
        self.refresh_from_disk_best_effort();
        Trace { project: self }
    }

    #[must_use]
    pub fn inspect(&self) -> Inspect<'_> {
        self.refresh_from_disk_best_effort();
        Inspect { project: self }
    }
}

fn initial_fingerprints(root: &Path, registry: &Arc<LanguageRegistry>) -> AHashMap<PathBuf, u64> {
    let workspace = Workspace::new(registry.clone());
    workspace
        .source_file_fingerprints(root)
        .unwrap_or_default()
        .into_iter()
        .map(|file| (file.path, file.hash))
        .collect()
}

/// Core cache facade. This manages SDK-owned workspace analysis cache files,
/// not CLI rendered-page cache entries.
pub struct Cache<'a> {
    project: &'a Project,
}

#[derive(Clone, Debug, Serialize)]
pub struct CacheStats {
    pub bonsai_dir: PathBuf,
    pub bonsai_dir_exists: bool,
    pub total_bytes: u64,
    pub dataflow_sidecar: PathBuf,
    pub dataflow_sidecar_exists: bool,
    pub dataflow_sidecar_bytes: u64,
    pub export_sidecar: PathBuf,
    pub export_sidecar_exists: bool,
    pub export_sidecar_bytes: u64,
}

/// Root-only persisted analysis cache facade.
#[derive(Clone, Debug)]
pub struct WorkspaceCache {
    root: PathBuf,
    rulepack_root: Option<PathBuf>,
}

impl WorkspaceCache {
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            rulepack_root: None,
        }
    }

    /// Attach the rulepack root that produced the analysis output
    /// the cache holds. Mutations under this directory invalidate
    /// the cache — without this, an edit to `security-patterns/`
    /// would silently replay stale findings (per
    /// `docs/contributing/design-patterns.mdx::Lossless Caches`).
    #[must_use]
    pub fn with_rulepack_root(mut self, rulepack_root: impl AsRef<Path>) -> Self {
        self.rulepack_root = Some(rulepack_root.as_ref().to_path_buf());
        self
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stats(&self) -> std::io::Result<CacheStats> {
        let bonsai_dir = self.root.join(".bonsai");
        let dataflow_sidecar = bonsai_workspace::dataflow::DataFlowCache::sidecar_path(&self.root);
        let export_sidecar = default_export_cache_path(&self.root);
        let total_bytes = dir_size(&bonsai_dir)?;
        let dataflow_sidecar_bytes = fs::metadata(&dataflow_sidecar).map_or(0, |meta| meta.len());
        let export_sidecar_bytes = fs::metadata(&export_sidecar).map_or(0, |meta| meta.len());
        Ok(CacheStats {
            bonsai_dir_exists: bonsai_dir.is_dir(),
            dataflow_sidecar_exists: dataflow_sidecar.is_file(),
            export_sidecar_exists: export_sidecar.is_file(),
            bonsai_dir,
            total_bytes,
            dataflow_sidecar,
            dataflow_sidecar_bytes,
            export_sidecar,
            export_sidecar_bytes,
        })
    }

    pub fn clear_all(&self) -> std::io::Result<()> {
        let dir = self.root.join(".bonsai");
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn clear_dataflow(&self) -> std::io::Result<()> {
        let sidecar = bonsai_workspace::dataflow::DataFlowCache::sidecar_path(&self.root);
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
        Ok(())
    }

    pub fn clear_dataflow_only(&self) -> std::io::Result<()> {
        self.clear_dataflow()
    }

    #[must_use]
    pub fn default_export_cache_path(&self) -> PathBuf {
        default_export_cache_path(&self.root)
    }

    pub fn default_export_cache_is_fresh(&self) -> Result<bool> {
        let cache = self.default_export_cache_path();
        let Ok(file) = fs::File::open(&cache) else {
            return Ok(false);
        };
        export_cache_is_fresh_via_fd(&self.root, self.rulepack_root.as_deref(), &file)
    }

    pub fn stream_default_export_cache_if_fresh<W: Write>(&self, writer: &mut W) -> Result<bool> {
        let cache = self.default_export_cache_path();
        // Open the cache file FIRST, then validate freshness from
        // the open fd's metadata. A separate `fs::metadata` + later
        // `File::open` would let a concurrent writer swap the file
        // between the check and the read; using the same fd makes
        // the check race-free.
        let mut input = match fs::File::open(&cache) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        if !export_cache_is_fresh_via_fd(&self.root, self.rulepack_root.as_deref(), &input)? {
            return Ok(false);
        }
        io::copy(&mut input, writer)?;
        writer.flush()?;
        Ok(true)
    }
}

impl Cache<'_> {
    fn workspace_cache(&self) -> WorkspaceCache {
        let mut cache = WorkspaceCache::new(&self.project.root);
        if let Some(rulepack_root) = self.project.rulepack_root.as_deref() {
            cache = cache.with_rulepack_root(rulepack_root);
        }
        cache
    }

    pub fn stats(&self) -> std::io::Result<CacheStats> {
        self.workspace_cache().stats()
    }

    pub fn clear_all(&self) -> std::io::Result<()> {
        self.workspace_cache().clear_all()
    }

    pub fn clear_dataflow(&self) -> std::io::Result<()> {
        self.workspace_cache().clear_dataflow()
    }

    pub fn clear_dataflow_only(&self) -> std::io::Result<()> {
        self.workspace_cache().clear_dataflow_only()
    }

    #[must_use]
    pub fn default_export_cache_path(&self) -> PathBuf {
        self.workspace_cache().default_export_cache_path()
    }

    pub fn default_export_cache_is_fresh(&self) -> Result<bool> {
        self.workspace_cache().default_export_cache_is_fresh()
    }

    pub fn stream_default_export_cache_if_fresh<W: Write>(&self, writer: &mut W) -> Result<bool> {
        self.workspace_cache()
            .stream_default_export_cache_if_fresh(writer)
    }

    pub fn rebuild_dataflow(&self) -> std::io::Result<()> {
        self.project.workspace.reindex_dataflow();
        self.project.workspace.save_dataflow_sidecar(&self.project.root)
    }
}

/// Recursive size of every file under `path`. Tolerates entries that
/// vanish mid-walk (concurrent cleaner, log rotation) by skipping
/// `NotFound` errors instead of failing the whole stat.
fn dir_size(path: &Path) -> std::io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let mut total_bytes = 0;
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if meta.is_dir() {
            total_bytes += dir_size(&entry.path())?;
        } else {
            total_bytes += meta.len();
        }
    }
    Ok(total_bytes)
}

fn default_export_cache_path(root: &Path) -> PathBuf {
    root.join(".bonsai").join(DEFAULT_EXPORT_CACHE_FILE)
}

fn unique_default_export_tmp_path(cache: &Path) -> PathBuf {
    let counter = EXPORT_CACHE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = cache
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from(DEFAULT_EXPORT_CACHE_FILE));
    name.push(format!(".tmp.{}.{}", std::process::id(), counter));
    cache.with_file_name(name)
}

fn write_default_export_cache(cache: &Path, out: &str) -> Result<()> {
    if let Some(parent) = cache.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = unique_default_export_tmp_path(cache);
    {
        let file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let mut writer = io::BufWriter::with_capacity(1024 * 1024, file);
        writer.write_all(out.as_bytes())?;
        writeln!(writer)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    if let Err(err) = fs::rename(&tmp, cache) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    if let Some(parent) = cache.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
}

/// Validate the freshness of an already-opened export cache file.
/// Reading metadata from the open `fd` (instead of re-stat'ing the
/// path) closes the TOCTOU window between check and read.
///
/// Inputs that invalidate the cache, in order:
/// 1. Any workspace source file newer than the cache.
/// 2. Any rulepack file newer than the cache (an edit to a
///    `security-patterns/*.yml` rule changes finding shape, so
///    cached export bytes are wrong even when sources didn't move).
/// 3. The bonsai-ninja binary itself being newer than the cache
///    (engine upgrades change finding shape too).
fn export_cache_is_fresh_via_fd(root: &Path, rulepack_root: Option<&Path>, cache: &fs::File) -> Result<bool> {
    let Ok(cache_meta) = cache.metadata() else {
        return Ok(false);
    };
    let Ok(cache_modified) = cache_meta.modified() else {
        return Ok(false);
    };
    let Some(newest_source) = newest_workspace_mtime(root)? else {
        return Ok(false);
    };
    if cache_modified < newest_source {
        return Ok(false);
    }
    if let Some(rulepack) = rulepack_root {
        if let Some(newest_rule) = newest_rulepack_mtime(rulepack)? {
            if cache_modified < newest_rule {
                return Ok(false);
            }
        }
    }
    let Ok(exe) = std::env::current_exe() else {
        return Ok(true);
    };
    let Ok(exe_meta) = fs::metadata(exe) else {
        return Ok(true);
    };
    let Ok(exe_modified) = exe_meta.modified() else {
        return Ok(true);
    };
    Ok(cache_modified >= exe_modified)
}

/// Most recent `mtime` over every file under `root`. Used for export
/// cache freshness — a rulepack edit must invalidate cached findings.
fn newest_rulepack_mtime(root: &Path) -> Result<Option<std::time::SystemTime>> {
    let mut newest: Option<std::time::SystemTime> = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue
            }
            Err(err) => return Err(err.into()),
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if let Ok(modified) = meta.modified() {
                    newest = Some(newest.map_or(modified, |prev| prev.max(modified)));
                }
            }
        }
    }
    Ok(newest)
}

/// Most recent `mtime` over the workspace's source tree, skipping
/// `.bonsai/` (our own cache) and `.git/` (history mtimes shouldn't
/// invalidate analysis).
fn newest_workspace_mtime(root: &Path) -> Result<Option<std::time::SystemTime>> {
    let mut newest: Option<std::time::SystemTime> = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue
            }
            Err(err) => return Err(err.into()),
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            let name = entry.file_name();
            if name == ".bonsai" || name == ".git" {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if let Ok(modified) = meta.modified() {
                    newest = Some(newest.map_or(modified, |prev| prev.max(modified)));
                }
            }
        }
    }
    Ok(newest)
}

/// Browse facts facade.
pub struct Browse<'a> {
    project: &'a Project,
}

impl Browse<'_> {
    pub fn defs(&self, filters: DefsFilters<'_>) -> Result<Vec<bonsai_browse::DefOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::defs(&self.project.workspace, &filters)
    }

    pub fn calls(&self, filters: CallsFilters<'_>) -> Result<Vec<bonsai_browse::CallOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::calls(&self.project.workspace, &filters)
    }

    pub fn imports(
        &self,
        filters: ImportsFilters<'_>,
    ) -> Result<Vec<bonsai_browse::ImportOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::imports(&self.project.workspace, &filters)
    }

    pub fn vars(&self, filters: VarsFilters<'_>) -> Result<Vec<bonsai_browse::VarOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::vars(&self.project.workspace, &filters)
    }

    pub fn strings(
        &self,
        filters: bonsai_browse::StringsFilters<'_>,
    ) -> Result<Vec<bonsai_browse::StringOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::strings(&self.project.workspace, &filters)
    }

    pub fn comments(
        &self,
        filters: CommentsFilters<'_>,
    ) -> Result<Vec<bonsai_browse::CommentOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::comments(&self.project.workspace, &filters)
    }

    pub fn args(&self, filters: ArgsFilters<'_>) -> Result<Vec<bonsai_browse::ArgOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::args(&self.project.workspace, &filters)
    }

    pub fn classes(&self, filters: ClassesFilters<'_>) -> Result<Vec<bonsai_browse::ClassOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::classes(&self.project.workspace, &filters)
    }

    pub fn refs(
        &self,
        symbol: &str,
        filters: RefsFilters<'_>,
    ) -> Result<Vec<bonsai_browse::RefOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::refs(&self.project.workspace, symbol, &filters)
    }

    pub fn search(
        &self,
        query: &str,
        filters: SearchFilters<'_>,
        limit: usize,
    ) -> Result<Vec<bonsai_browse::SearchHit>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::search(&self.project.workspace, query, &filters, limit)
    }

    /// Workspace navigation: hierarchical view with finding /
    /// flow / cross-file edge annotations per file.
    pub fn tree(&self, filters: TreeFilters<'_>) -> Result<TreeOut> {
        self.project.refresh_from_disk_best_effort();
        crate::tree::tree(
            &self.project.workspace,
            self.project.rulepack.as_deref(),
            &filters,
        )
    }

    /// Single-file connected-content view: source plus marks for
    /// findings/flows on its lines, and cross-file caller/callee
    /// inlined bodies.
    pub fn read_file(&self, filters: ReadFileFilters<'_>) -> Result<ReadFileOut> {
        self.project.refresh_from_disk_best_effort();
        crate::read_file::read_file(
            &self.project.workspace,
            self.project.rulepack.as_deref(),
            &filters,
        )
    }
}

/// Debug/dump facade.
pub struct Dump<'a> {
    project: &'a Project,
}

impl Dump<'_> {
    #[must_use]
    pub fn hir(&self, symbol: &str) -> Option<bonsai_browse::HirDump> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_hir(&self.project.workspace, symbol)
    }

    #[must_use]
    pub fn cfg(&self, symbol: &str) -> Option<bonsai_cfg::Cfg> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_cfg(&self.project.workspace, symbol)
    }

    #[must_use]
    pub fn callgraph(&self) -> Vec<bonsai_browse::CallgraphRow> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_callgraph(&self.project.workspace)
    }

    #[must_use]
    pub fn edges(&self, filters: EdgesFilters<'_>) -> Vec<bonsai_browse::EdgeRecord> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_edges(&self.project.workspace, &filters)
    }

    #[must_use]
    pub fn ast(&self, filters: AstFilters<'_>) -> AstOutcome {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_ast(&self.project.workspace, &filters)
    }

    #[must_use]
    pub fn resolve(&self, query: &str, filters: ResolveFilters<'_>) -> ResolveOutcome {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_resolve(&self.project.workspace, query, &filters, |_, _| Vec::new())
    }

    #[must_use]
    pub fn resolve_with_suggestions<F>(
        &self,
        query: &str,
        filters: ResolveFilters<'_>,
        suggestions_for: F,
    ) -> ResolveOutcome
    where
        F: FnOnce(&Workspace, &str) -> Vec<String>,
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_resolve(&self.project.workspace, query, &filters, suggestions_for)
    }

    #[must_use]
    pub fn taint(&self, filters: TaintFilters<'_>) -> TaintOutcome {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_taint(&self.project.workspace, &filters)
    }
}

/// Export facade.
pub struct Export<'a> {
    project: &'a Project,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct NativeExportOptions {
    pub full_propagations: bool,
}

impl Export<'_> {
    pub fn native_json(&self, options: NativeExportOptions) -> serde_json::Result<serde_json::Value> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::native_export_json(
            &self.project.workspace,
            &self.project.root,
            options.full_propagations,
        )
    }

    pub fn native_json_string(&self, options: NativeExportOptions) -> serde_json::Result<String> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::render_native_export_json(
            &self.project.workspace,
            &self.project.root,
            options.full_propagations,
        )
    }

    #[must_use]
    pub fn default_json_cache_path(&self) -> PathBuf {
        default_export_cache_path(&self.project.root)
    }

    fn export_workspace_cache(&self) -> WorkspaceCache {
        let mut cache = WorkspaceCache::new(&self.project.root);
        if let Some(rulepack_root) = self.project.rulepack_root.as_deref() {
            cache = cache.with_rulepack_root(rulepack_root);
        }
        cache
    }

    pub fn default_json_cache_is_fresh(&self) -> Result<bool> {
        self.export_workspace_cache().default_export_cache_is_fresh()
    }

    pub fn stream_default_json_cache_if_fresh<W: Write>(&self, writer: &mut W) -> Result<bool> {
        self.export_workspace_cache()
            .stream_default_export_cache_if_fresh(writer)
    }

    pub fn write_default_json_cache(&self, out: &str) -> Result<()> {
        write_default_export_cache(&self.default_json_cache_path(), out)
    }

    pub fn warm_default_json_cache(&self) -> Result<()> {
        self.project.refresh_from_disk_best_effort();
        if self.default_json_cache_is_fresh()? {
            return Ok(());
        }
        let rendered = self.native_json_string(NativeExportOptions {
            full_propagations: false,
        })?;
        self.write_default_json_cache(&rendered)
    }

    #[must_use]
    pub fn graph_projection(&self) -> GraphProjection {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::graph_projection(&self.project.workspace, &self.project.root)
    }

    pub fn graph(&self, format: GraphExportFormat) -> Result<String> {
        self.project.refresh_from_disk_best_effort();
        Ok(bonsai_browse::render_graph_export(
            &self.project.workspace,
            &self.project.root,
            format,
        )?)
    }

    pub fn networkx_json(&self) -> Result<String> {
        self.graph(GraphExportFormat::Networkx)
    }

    pub fn graphml(&self) -> Result<String> {
        self.graph(GraphExportFormat::Graphml)
    }

    pub fn cypher(&self) -> Result<String> {
        self.graph(GraphExportFormat::Cypher)
    }
}

/// Security facade.
pub struct Security<'a> {
    project: &'a Project,
}

impl Security<'_> {
    fn pack(&self) -> Result<&Rulepack> {
        self.project
            .rulepack()
            .ok_or_else(|| anyhow!("security APIs require Bonsai::with_rulepack(...)"))
    }

    pub fn taint_analysis(
        &self,
        options: TaintAnalysisOptions,
    ) -> Result<bonsai_security::TaintAnalysisReport> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::run_taint_analysis(&self.project.workspace, self.pack()?, options)
    }

    pub fn taint_analysis_with_progress<F>(
        &self,
        options: TaintAnalysisOptions,
        on_rule: F,
    ) -> Result<bonsai_security::TaintAnalysisReport>
    where
        F: FnMut(&'static str),
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::run_taint_analysis_with_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_rule,
        )
    }

    /// Phase-aware progress variant. The callback receives
    /// `PhaseStarted { label, total }` / `PhaseTicked` / `PhaseFinished`
    /// events so a CLI can render a progress bar with a known length
    /// for every long-running phase, including post-matching chain
    /// assembly (which the legacy callback can't describe).
    pub fn taint_analysis_with_phase_progress<F>(
        &self,
        options: TaintAnalysisOptions,
        on_progress: F,
    ) -> Result<bonsai_security::TaintAnalysisReport>
    where
        F: FnMut(bonsai_security::AnalysisProgress),
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::run_taint_analysis_with_phase_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_progress,
        )
    }

    pub fn source_analysis(
        &self,
        options: SourceAnalysisOptions,
    ) -> Result<bonsai_security::SourceAnalysisReport> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::run_source_analysis(&self.project.workspace, self.pack()?, options)
    }

    pub fn source_analysis_with_progress<F>(
        &self,
        options: SourceAnalysisOptions,
        on_rule: F,
    ) -> Result<bonsai_security::SourceAnalysisReport>
    where
        F: FnMut(&'static str),
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::run_source_analysis_with_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_rule,
        )
    }

    /// Phase-aware progress variant of [`Self::source_analysis_with_progress`].
    pub fn source_analysis_with_phase_progress<F>(
        &self,
        options: SourceAnalysisOptions,
        on_progress: F,
    ) -> Result<bonsai_security::SourceAnalysisReport>
    where
        F: FnMut(bonsai_security::AnalysisProgress),
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::run_source_analysis_with_phase_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_progress,
        )
    }

    pub fn sources(&self, options: SecurityInventoryOptions) -> Result<Vec<bonsai_security::RuleMatch>> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::source_inventory(&self.project.workspace, self.pack()?, options)
    }

    pub fn sinks(&self, options: SecurityInventoryOptions) -> Result<Vec<bonsai_security::RuleMatch>> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::sink_inventory(&self.project.workspace, self.pack()?, options)
    }

    pub fn sanitizers(&self, options: SecurityInventoryOptions) -> Result<Vec<bonsai_security::RuleMatch>> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::sanitizer_inventory(&self.project.workspace, self.pack()?, options)
    }

    pub fn source_rows(
        &self,
        options: SecurityInventoryOptions,
    ) -> Result<Vec<bonsai_security::SecurityMatchRow>> {
        let matches = self.sources(options)?;
        Ok(bonsai_security::security_match_rows(self.pack()?, &matches))
    }

    pub fn sink_rows(
        &self,
        options: SecurityInventoryOptions,
    ) -> Result<Vec<bonsai_security::SecurityMatchRow>> {
        let matches = self.sinks(options)?;
        Ok(bonsai_security::security_match_rows(self.pack()?, &matches))
    }

    pub fn sanitizer_rows(
        &self,
        options: SecurityInventoryOptions,
    ) -> Result<Vec<bonsai_security::SecurityMatchRow>> {
        let matches = self.sanitizers(options)?;
        Ok(bonsai_security::security_match_rows(self.pack()?, &matches))
    }

    pub fn deps(&self, options: DependencyInventoryOptions) -> Result<bonsai_security::DependencyInventory> {
        self.project.refresh_from_disk_best_effort();
        Ok(bonsai_security::dependency_inventory(
            &self.project.workspace,
            self.pack()?,
            &self.project.root,
            options,
        ))
    }

    pub fn pack_inventory(&self, options: PackInventoryOptions) -> Result<Vec<bonsai_security::PackRuleRow>> {
        self.pack_facade()?.inventory(options)
    }

    pub fn pack_audit(&self, lang_filter: Option<&str>) -> Result<bonsai_security::PackAuditReport> {
        self.pack_facade()?.audit(lang_filter)
    }

    pub fn pack_tree(&self, options: PackInventoryOptions) -> Result<bonsai_security::PackTreeReport> {
        self.pack_facade()?.tree(options)
    }

    pub fn validate_pack(
        &self,
        options: PackInventoryOptions,
    ) -> Result<bonsai_security::PackValidationReport> {
        self.pack_facade()?.validate(options)
    }

    fn pack_facade(&self) -> Result<SecurityPack<'_>> {
        Ok(SecurityPack::with_registry(
            self.pack()?,
            self.project.registry.clone(),
        ))
    }
}

/// Rootless security rulepack facade.
pub struct SecurityPack<'a> {
    pack: &'a Rulepack,
    registry: Arc<LanguageRegistry>,
}

impl<'a> SecurityPack<'a> {
    #[must_use]
    pub fn new(pack: &'a Rulepack) -> Self {
        Self::with_registry(pack, bonsai_adapters::all_languages_registry())
    }

    #[must_use]
    pub fn with_registry(pack: &'a Rulepack, registry: Arc<LanguageRegistry>) -> Self {
        Self { pack, registry }
    }

    #[must_use]
    pub fn rulepack(&self) -> &'a Rulepack {
        self.pack
    }

    pub fn inventory(&self, options: PackInventoryOptions) -> Result<Vec<bonsai_security::PackRuleRow>> {
        Ok(bonsai_security::pack_inventory(self.pack, options))
    }

    pub fn audit(&self, lang_filter: Option<&str>) -> Result<bonsai_security::PackAuditReport> {
        Ok(bonsai_security::pack_audit(self.pack, lang_filter))
    }

    pub fn tree(&self, options: PackInventoryOptions) -> Result<bonsai_security::PackTreeReport> {
        Ok(bonsai_security::pack_tree(self.pack, options))
    }

    pub fn select_rules(&self, options: &PackInventoryOptions) -> Vec<&'a bonsai_security::Rule> {
        bonsai_security::select_pack_rules(self.pack, options)
    }

    pub fn tree_for_rules(
        &self,
        rules: &[&bonsai_security::Rule],
    ) -> Result<bonsai_security::PackTreeReport> {
        Ok(bonsai_security::pack_tree_for_rules(self.pack, rules))
    }

    pub fn validate(&self, options: PackInventoryOptions) -> Result<bonsai_security::PackValidationReport> {
        Ok(bonsai_security::validate_pack(
            self.pack,
            &options,
            self.registry.clone(),
        ))
    }
}

/// Trace facade.
pub struct Trace<'a> {
    project: &'a Project,
}

impl Trace<'_> {
    pub fn from(
        &self,
        entry: &str,
    ) -> std::result::Result<bonsai_trace::TraceResult, bonsai_workspace::WorkspaceError> {
        self.project.refresh_from_disk_best_effort();
        self.project.workspace.trace_from(entry)
    }

    pub fn from_with_options(
        &self,
        entry: &str,
        options: bonsai_workspace::CrossModuleOptions,
    ) -> std::result::Result<bonsai_trace::TraceResult, bonsai_workspace::WorkspaceError> {
        self.project.refresh_from_disk_best_effort();
        self.project.workspace.trace_from_with_options(entry, options)
    }

    pub fn source_to_sink(
        &self,
        source: &str,
        sink: &str,
    ) -> std::result::Result<bonsai_trace::TraceResult, bonsai_workspace::WorkspaceError> {
        self.project.refresh_from_disk_best_effort();
        self.project.workspace.trace_source_to_sink(source, sink)
    }

    pub fn source_to_sink_with_options(
        &self,
        source: &str,
        sink: &str,
        options: bonsai_workspace::CrossModuleOptions,
    ) -> std::result::Result<bonsai_trace::TraceResult, bonsai_workspace::WorkspaceError> {
        self.project.refresh_from_disk_best_effort();
        self.project
            .workspace
            .trace_source_to_sink_with_options(source, sink, options)
    }

    pub fn to_json(&self, trace: &bonsai_trace::TraceResult) -> serde_json::Result<String> {
        bonsai_trace::render::to_json(trace)
    }

    #[must_use]
    pub fn to_text(&self, trace: &bonsai_trace::TraceResult) -> String {
        bonsai_trace::render::to_text(trace)
    }

    #[must_use]
    pub fn to_dot(&self, trace: &bonsai_trace::TraceResult) -> String {
        bonsai_trace::render::to_dot(trace)
    }
}

/// Inspect/query facade.
pub struct Inspect<'a> {
    project: &'a Project,
}

#[derive(Clone, Debug)]
pub struct InspectQuery<'a> {
    pub pattern: Option<&'a str>,
    pub regex: bool,
    pub max_chains: usize,
    pub max_probes: usize,
}

impl Default for InspectQuery<'_> {
    fn default() -> Self {
        Self {
            pattern: None,
            regex: false,
            max_chains: 64,
            max_probes: 10_000,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectTargetChains {
    pub target_func_id: u32,
    pub target: String,
    pub chains: Vec<InspectChain>,
    pub truncated: bool,
    pub truncation: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectChain {
    pub funcs: Vec<u32>,
    pub names: Vec<String>,
    pub precision: String,
}

impl Inspect<'_> {
    pub fn matcher(
        &self,
        pattern: Option<&str>,
        regex: bool,
    ) -> Result<bonsai_inspect::Matcher, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_inspect::Matcher::build(pattern, regex)
    }

    pub fn matching_decls(&self, pattern: Option<&str>, regex: bool) -> Result<Vec<Decl>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        let matcher = self.matcher(pattern, regex)?;
        Ok(bonsai_inspect::matching_decls(&self.project.workspace, &matcher))
    }

    pub fn matching_func_ids(&self, pattern: Option<&str>, regex: bool) -> Result<Vec<FuncId>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        let matcher = self.matcher(pattern, regex)?;
        Ok(bonsai_inspect::matching_func_ids(
            &self.project.workspace,
            &matcher,
        ))
    }

    pub fn chains(&self, query: InspectQuery<'_>) -> Result<Vec<InspectTargetChains>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        let matcher = self.matcher(query.pattern, query.regex)?;
        let targets = bonsai_inspect::matching_func_ids(&self.project.workspace, &matcher);
        let cache = bonsai_inspect::ChainCache::new(&self.project.workspace);
        let mut out = Vec::new();
        for target in targets {
            let (chains, truncation) = cache.chains_resolved(target, query.max_chains, query.max_probes);
            out.push(InspectTargetChains {
                target_func_id: target.raw(),
                target: bonsai_inspect::func_display_name(&self.project.workspace, target),
                chains: chains
                    .into_iter()
                    .map(|chain| InspectChain {
                        funcs: chain.funcs.iter().map(|func| func.raw()).collect(),
                        names: bonsai_inspect::chain_to_names(&self.project.workspace, &chain.funcs),
                        precision: format!("{:?}", chain.precision),
                    })
                    .collect(),
                truncated: truncation.is_truncated(),
                truncation: truncation.label().map(str::to_string),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod rulepack_discovery_tests {
    use super::Bonsai;
    use std::fs;
    use std::path::PathBuf;

    fn fresh_tempdir(prefix: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "bonsai-rulepack-{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn env_var_overrides_workspace_local_rulepack() {
        let workspace = fresh_tempdir("ws");
        let workspace_local = workspace.join("security-patterns");
        fs::create_dir_all(&workspace_local).unwrap();

        let env_pack = fresh_tempdir("env");

        let env_path = env_pack.clone();
        let resolved = Bonsai::discover_rulepack_root_with(&workspace, |key| {
            if key == "BONSAI_RULES_DIR" {
                Some(env_path.clone())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(
            resolved.canonicalize().unwrap(),
            env_pack.canonicalize().unwrap(),
            "BONSAI_RULES_DIR should win over workspace-local security-patterns/"
        );

        fs::remove_dir_all(&workspace).ok();
        fs::remove_dir_all(&env_pack).ok();
    }

    #[test]
    fn env_var_falls_back_when_path_missing() {
        let workspace = fresh_tempdir("ws-fallback");
        let workspace_local = workspace.join("security-patterns");
        fs::create_dir_all(&workspace_local).unwrap();

        let resolved = Bonsai::discover_rulepack_root_with(&workspace, |key| {
            if key == "BONSAI_RULES_DIR" {
                Some(PathBuf::from("/nonexistent/path/does/not/exist"))
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(
            resolved.canonicalize().unwrap(),
            workspace_local.canonicalize().unwrap(),
            "missing BONSAI_RULES_DIR path should fall back to workspace-local security-patterns/"
        );

        fs::remove_dir_all(&workspace).ok();
    }

    #[test]
    fn workspace_local_wins_when_env_unset() {
        let workspace = fresh_tempdir("ws-local");
        let workspace_local = workspace.join("security-patterns");
        fs::create_dir_all(&workspace_local).unwrap();

        let resolved = Bonsai::discover_rulepack_root_with(&workspace, |_| None).unwrap();
        assert_eq!(
            resolved.canonicalize().unwrap(),
            workspace_local.canonicalize().unwrap(),
            "workspace-local security-patterns should be picked when no env var is set"
        );

        fs::remove_dir_all(&workspace).ok();
    }

    #[test]
    fn no_env_no_local_doesnt_panic_or_invent_path() {
        let workspace = fresh_tempdir("ws-empty");
        // No security-patterns/ inside the workspace, no env override.
        // Discovery may still hit the cwd-relative `./security-patterns/`
        // candidate when the test runs from a directory that contains
        // one (the bonsai-ninja repo root does). Either outcome is
        // valid — assert the function never invents a non-existent path.
        if let Some(found) = Bonsai::discover_rulepack_root_with(&workspace, |_| None) {
            assert!(
                found.exists(),
                "discover_rulepack_root returned a non-existent path: {}",
                found.display()
            );
        }

        fs::remove_dir_all(&workspace).ok();
    }
}

#[cfg(test)]
mod export_cache_tests {
    use super::{newest_workspace_mtime, unique_default_export_tmp_path};
    use std::path::Path;

    #[test]
    fn default_export_tmp_paths_are_unique_per_write() {
        let path = Path::new("/tmp/.bonsai/export.default.v4.json");
        let first = unique_default_export_tmp_path(path);
        let second = unique_default_export_tmp_path(path);

        assert_ne!(first, second);
        assert_eq!(first.parent(), path.parent());
        assert!(first
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("export.default.v4.json.tmp.")));
    }

    fn tempdir(name: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("bonsai-sdk-{name}-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).expect("create temp dir");
        path
    }

    #[cfg(unix)]
    #[test]
    fn export_freshness_skips_symlinked_directories() {
        let root = tempdir("export-root");
        let outside = tempdir("export-outside");
        std::fs::write(root.join("app.py"), "print('root')\n").expect("write root app");
        std::fs::write(outside.join("external.py"), "print('outside')\n").expect("write outside app");
        std::os::unix::fs::symlink(&outside, root.join("linked")).expect("create symlink dir");

        let before = newest_workspace_mtime(&root)
            .expect("mtime before")
            .expect("root file mtime");
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(outside.join("external.py"), "print('changed')\n").expect("rewrite outside app");
        let after = newest_workspace_mtime(&root)
            .expect("mtime after")
            .expect("root file mtime");
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();

        assert_eq!(before, after);
    }
}
