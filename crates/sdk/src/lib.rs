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
use bonsai_common::{
    dependency_metadata::collect_dependency_metadata_fingerprints, FuncId, MATCHER_POLICY_FINGERPRINT,
};
use bonsai_lang_api::{Decl, LanguageRegistry};
use bonsai_workspace::{FileRefreshKind, WorkspaceOpenOptions};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const DEFAULT_EXPORT_CACHE_FILE: &str = "export.default.v11.json";
const DEFAULT_EXPORT_CACHE_METADATA_FILE: &str = "export.default.v11.meta.json";
const DEFAULT_EXPORT_CACHE_METADATA_VERSION: u32 = 1;
const DEFAULT_EXPORT_CACHE_PIPELINE_VERSION: &str = "native-export-cache-v12";
const CACHE_MANIFEST_FILE: &str = "manifest.json";
const CACHE_MANIFEST_SCHEMA_VERSION: u32 = 1;
const RETRIEVAL_NO_CANDIDATES_FILTER: &str = "/__bonsai_no_retrieval_candidates__/__none__";
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
    collect_callee_names, file_path_excluded_by_filters, file_path_matches_filter, ArgOut, ArgsFilters,
    AstFileDump, AstFilters, AstNode, AstOutcome, CallOut, CallgraphRow, CallsFilters, ClassOut,
    ClassesFilters, CommentOut, CommentsFilters, DefOut, DefsFilters, EdgeRecord, EdgesFilters,
    EntryPointOut, EntryPointsFilters, FlowAnnotator, GraphExportFormat, GraphProjection, HirDump, ImportOut,
    ImportsFilters, Locator, OperationOperandOut, OperationOut, OperationsFilters, PathFilters,
    PathFunctionRow, PathOutcome, PathRow, PrecisionClass, RefOut, RefsFilters, ResolutionCoverageDeclRow,
    ResolutionCoverageFileRow, ResolutionCoverageFilters, ResolveFilters, ResolveOutcome, ResolveTrace,
    SearchFilters, SearchHit, SliceFilters, SliceOutcome, SliceRow, SliceStep, StringOut, StringsFilters,
    TaintFilters, TaintOutcome, TaintReport, VarOut, VarsFilters,
};
pub use bonsai_inspect::{
    chain_matches_filters, chain_matches_filters_for_hit, chain_to_names, compute_flow_id,
    compute_flow_labels_from, compute_group_id, compute_taint_flow_id, find_call_span_by_name,
    find_call_span_to_func_uncached, find_enclosing_func, func_display_name, matching_decls,
    matching_func_ids, name_token_match, CallEdgeResolver, CallPathTruncation, ChainCache, FactKindFilter,
    FilterHit, InspectFilters, Matcher, PrecisionFilter, ResolvedChain, TaintFlowIdentityStep,
};
pub use bonsai_security::{
    build_flow_bodies, canonical_sink_audit_applies, drain_runtime_disabled_rules,
    filter_rules_to_workspace_languages, load_rulepack, load_workspace_local_rules, normalise_family,
    parse_severity, rule_family, security_match_rows, select_rules, source_rule_matches_filters,
    tree_file_rel, workspace_languages, AnalysisProgress, CombinedFindingWithChain,
    CombinedSourceAnalysisCandidate, DependencyInventory, DependencyInventoryOptions, DependencyRow, Finding,
    FindingMatch, FindingStatus, FindingWithChain, FlowFunctionBody, FlowRole as SecurityFlowRole,
    FlowSourceLine, PackAuditCount, PackAuditFamilyCount, PackAuditLanguage, PackAuditReport,
    PackInventoryOptions, PackRuleRow, PackTreeFile, PackTreeLanguage, PackTreeReport, PackTreeRule,
    PackValidationIssue, PackValidationReport, Rule, RuleKind, RuleMatch, Rulepack, RuntimeDisabledRule,
    SecurityInventoryOptions, SecurityMatchRow, SecurityReport, Severity, SourceAnalysisCandidate,
    SourceAnalysisOptions, SourceAnalysisReport, SourceLineageLimits, SourceLineageStatus,
    SourceLineageSummary, TaintAnalysisOptions, TaintAnalysisReport, TaintPropagationArg,
    TaintPropagationStep, TrustClass, CANONICAL_SINK_FAMILIES, ECOSYSTEM_SPECIFIC_SINK_AUDIT_LANGS,
    FAMILY_NOT_APPLICABLE,
};
pub use bonsai_trace::{PathSummary, TraceResult, TraceStep, TraceStepKind};
pub use bonsai_workspace::value_flow::{
    ValueFlowCache, ValueFlowEdge, ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind,
};
pub use bonsai_workspace::{
    analyzer_build_fingerprint,
    flow_query::{
        EntryTaintGraph, SyntaxFlowBackend, SyntaxFlowCacheStatus, SyntaxFlowGraph, SyntaxFlowPlan,
        SyntaxFlowQuery, TaintedCall, TaintedCallEdge, TaintedCallKind,
    },
    summarize_precision, CrossModuleOptions, Workspace, WorkspaceContextRoot, WorkspaceContextRootKind,
    WorkspaceError, WorkspaceOpenOptions as OpenOptions, WorkspaceSemanticContext,
    WorkspaceSemanticContextSummary, WorkspaceSourceTransformation, WorkspaceSourceVariant, WorkspaceStats,
    WorkspaceToolchainManifest,
};

pub mod cache {
    pub use bonsai_inspect::cache::{
        CALLEES_CACHE_CAP, CHAINS_CACHE_CAP, DOWNSTREAM_CACHE_CAP, ENCLOSING_CACHE_CAP, REACHABLE_CACHE_CAP,
    };
}

pub mod refs {
    pub use bonsai_browse::refs::read_snippet;
}

pub use bonsai_browse::decl_decorator_names;

pub mod strings {
    pub use bonsai_browse::strings::enclosing_fn_for_file_line;
}

pub mod trace_render {
    pub use bonsai_trace::render::{to_dot, to_json, to_text};
}

/// Full diagnostics report shared by the SDK and CLI.
///
/// `diagnostics` is the traditional adapter/parser warning stream.
/// `adapter_capabilities` is the machine-readable capability declaration
/// for every registered adapter, so diagnostics consumers do not have to
/// cross-reference generated docs by hand.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub diagnostics: Vec<bonsai_diagnostics::Diagnostic>,
    pub workspace_languages: Vec<String>,
    pub adapter_capabilities: Vec<AdapterCapabilityRow>,
}

/// One adapter's declared capability metadata, serialized for diagnostics
/// and SDK consumers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterCapabilityRow {
    pub language: String,
    pub display_name: String,
    pub file_extensions: Vec<String>,
    pub modules: bonsai_lang_api::CapabilityLevel,
    pub generics: bonsai_lang_api::CapabilityLevel,
    pub macros: bonsai_lang_api::CapabilityLevel,
    pub dynamic_dispatch: bonsai_lang_api::CapabilityLevel,
    pub exceptions: bonsai_lang_api::CapabilityLevel,
    pub async_await: bonsai_lang_api::CapabilityLevel,
    pub coroutines: bonsai_lang_api::CapabilityLevel,
    pub reflection: bonsai_lang_api::CapabilityLevel,
    pub ffi: bonsai_lang_api::CapabilityLevel,
    pub pattern_matching: bonsai_lang_api::CapabilityLevel,
    pub receiver_types: bonsai_lang_api::CapabilityLevel,
    pub module_export_aliases: Vec<String>,
    pub constructor_method_names: Vec<String>,
    pub super_receiver_tokens: Vec<String>,
    pub implicit_receiver_tokens: Vec<String>,
}

fn string_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
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
/// path see the same variants. `WorkspaceCacheStatus` describes
/// sidecar/cache checks emitted during open. Earlier the SDK had a
/// private copy plus a hand-rolled prewarm pipeline; both have been
/// collapsed onto the workspace's canonical implementation.
pub use bonsai_workspace::{WorkspaceCacheStatus, WorkspaceOpenEvent};

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
    /// sources, sinks, and sanitizer evidence for security reports, and
    /// contributes declarative transfer semantics such as passthrough
    /// decoders, output-argument sources, and receiver-state flows. The
    /// engine still owns the transfer mechanism; API names and argument
    /// shapes stay in the rulepack.
    pub fn with_rulepack(mut self, root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let pack = bonsai_security::load_rulepack(&root)
            .map_err(|err| anyhow!("failed to load rulepack `{}`: {err}", root.display()))?;
        self.rulepack_root = Some(root);
        self.rulepack = Some(Arc::new(pack));
        Ok(self)
    }

    /// Attach a pre-loaded security rulepack. Use this when the
    /// embedding application already parsed or synthesized the pack
    /// and wants every project opened by this builder to share it.
    #[must_use]
    pub fn with_loaded_rulepack(mut self, root: impl AsRef<Path>, rulepack: Rulepack) -> Self {
        self.rulepack_root = Some(root.as_ref().to_path_buf());
        self.rulepack = Some(Arc::new(rulepack));
        self
    }

    /// Parse and structurally index the workspace. Missing exact analysis
    /// facts are loaded from fresh sidecars or computed by the query that
    /// requests them; use [`Self::index_semantic`] or
    /// [`WorkspaceOpenOptions::full_prewarm`] for an explicit cache prewarm.
    ///
    /// Rulepacks classify sources/sinks/sanitizers and can contribute
    /// declarative transfer semantics. Explicit prewarm sidecars are
    /// deterministic for a given rulepack/configuration; query-time exact
    /// analysis still refreshes any configured transfer profile it needs.
    pub fn index(&self, root: impl AsRef<Path>) -> Result<Project> {
        self.index_structural(root)
    }

    /// Parse and structurally index the workspace without warming persisted
    /// semantic sidecars.
    pub fn index_structural(&self, root: impl AsRef<Path>) -> Result<Project> {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::parse_only());
        let ws = Workspace::open_with_options(root, self.registry.clone(), options)?;
        Ok(self.project(root, ws, options))
    }

    /// Same as [`Self::index`], emitting progress events for terminal or IDE
    /// frontends.
    pub fn index_with_progress<F>(&self, root: impl AsRef<Path>, on_event: F) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        self.index_structural_with_progress(root, on_event)
    }

    /// Same as [`Self::index_structural`], emitting progress events for
    /// terminal or IDE frontends.
    pub fn index_structural_with_progress<F>(&self, root: impl AsRef<Path>, on_event: F) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        self.open_with_options_and_progress(root, WorkspaceOpenOptions::parse_only(), on_event)
    }

    /// Parse/index the workspace and eagerly build the reusable semantic
    /// structural sidecars shared by query commands: callgraph and the
    /// workspace IDG. This deliberately does not materialize the legacy
    /// per-entry value-flow projection; those compatibility documents are
    /// derived from the IDG on demand.
    pub fn index_semantic(&self, root: impl AsRef<Path>) -> Result<Project> {
        let project = self.open_with_options(root, WorkspaceOpenOptions::parse_only())?;
        let _ = project.cache().warm_structural()?;
        Ok(project)
    }

    /// Same as [`Self::index_semantic`], emitting progress events for terminal
    /// or IDE frontends.
    pub fn index_semantic_with_progress<F>(&self, root: impl AsRef<Path>, on_event: F) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let project =
            self.open_with_options_and_progress(root, WorkspaceOpenOptions::parse_only(), on_event)?;
        let _ = project.cache().warm_structural()?;
        Ok(project)
    }

    /// Open a workspace for fast semantic queries: load the dataflow sidecar
    /// and compute requested missing facts on demand.
    pub fn open_query(&self, root: impl AsRef<Path>) -> Result<Project> {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::query_only());
        let ws = Workspace::open_with_options(root, self.registry.clone(), options)?;
        Ok(self.project(root, ws, options))
    }

    /// Return workspace-relative file filters for fact candidates from a
    /// fresh retrieval sidecar.
    ///
    /// Retrieval is candidate lookup only. Callers must open the returned file
    /// scope and hydrate through canonical browse/search/inspect APIs before rendering
    /// public facts. Returns `Ok(None)` when the query shape is unsupported or
    /// the retrieval sidecar is missing/stale for the current source,
    /// dependency, build, or pipeline fingerprint.
    pub fn retrieval_candidate_file_filters(
        &self,
        root: impl AsRef<Path>,
        query: &str,
        filters: SearchFilters<'_>,
    ) -> Result<Option<Vec<String>>> {
        let root = root.as_ref();
        if filters.regex || query.trim().len() < 3 {
            return Ok(None);
        }
        let fingerprint_ws = Workspace::new(self.registry.clone());
        let Ok(fingerprints) = fingerprint_ws.source_file_fingerprints(root) else {
            return Ok(None);
        };
        let root_for_pipeline = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let pipeline = bonsai_retrieval::pipeline_hash_for_source_fingerprints(
            Some(root_for_pipeline.as_path()),
            fingerprints.iter().map(|file| (file.path.as_path(), file.hash)),
        );
        let Ok(index) = bonsai_retrieval::load_sidecar_with_pipeline(root, pipeline) else {
            return Ok(None);
        };
        let candidates = index
            .query(&bonsai_retrieval::RetrievalQuery {
                text: query,
                kind: filters.kind,
                file: filters.file,
                workspace_root: Some(root_for_pipeline.as_path()),
                regex: false,
                limit: 0,
            })
            .map_err(|err| anyhow!("invalid retrieval query `{query}`: {err}"))?;
        let mut include_filters: Vec<String> = candidates
            .into_iter()
            .filter_map(|doc| retrieval_include_filter(root, &doc.file_path))
            .collect();
        include_filters.sort();
        include_filters.dedup();
        Ok(Some(include_filters))
    }

    /// Compatibility spelling for search integrations. Retrieval candidates
    /// are not search-specific; prefer [`Self::retrieval_candidate_file_filters`]
    /// for new SDK integrations that hydrate browse or inspect facts.
    pub fn retrieval_search_candidate_file_filters(
        &self,
        root: impl AsRef<Path>,
        query: &str,
        filters: SearchFilters<'_>,
    ) -> Result<Option<Vec<String>>> {
        self.retrieval_candidate_file_filters(root, query, filters)
    }

    /// Return include filters that are safe to pass to
    /// [`Self::open_query_filtered_paths`] for canonical fact hydration.
    ///
    /// Unlike [`Self::retrieval_candidate_file_filters`], a fresh
    /// sidecar with zero matching facts returns an impossible include filter
    /// rather than `[]`, because an empty include filter means "open every
    /// source file" to path-filtered workspace opens.
    pub fn retrieval_hydration_include_filters(
        &self,
        root: impl AsRef<Path>,
        query: &str,
        filters: SearchFilters<'_>,
    ) -> Result<Option<Vec<String>>> {
        let Some(filters) = self.retrieval_candidate_file_filters(root, query, filters)? else {
            return Ok(None);
        };
        if filters.is_empty() {
            return Ok(Some(vec![RETRIEVAL_NO_CANDIDATES_FILTER.to_string()]));
        }
        Ok(Some(filters))
    }

    /// Compatibility spelling for search integrations. Prefer
    /// [`Self::retrieval_hydration_include_filters`] for new SDK integrations
    /// that hydrate browse or inspect facts.
    pub fn retrieval_search_hydration_include_filters(
        &self,
        root: impl AsRef<Path>,
        query: &str,
        filters: SearchFilters<'_>,
    ) -> Result<Option<Vec<String>>> {
        self.retrieval_hydration_include_filters(root, query, filters)
    }

    /// Open only files whose raw text contains `literal`, then parse
    /// and index that reduced candidate set. Intended for large
    /// syntax-search/inspect queries where whole-workspace graph
    /// evidence is explicitly not requested.
    pub fn open_query_matching_literal(&self, root: impl AsRef<Path>, literal: &str) -> Result<Project> {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::parse_only());
        let ws = Workspace::open_query_matching_literal_with_options(
            root,
            self.registry.clone(),
            literal,
            options,
        )?;
        Ok(self.project(root, ws, options).with_auto_refresh(false))
    }

    /// Same as [`Self::open_query_matching_literal`], emitting
    /// workspace lifecycle events while the reduced file set is opened.
    pub fn open_query_matching_literal_with_progress<F>(
        &self,
        root: impl AsRef<Path>,
        literal: &str,
        on_event: F,
    ) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::parse_only());
        let ws = Workspace::open_query_matching_literal_with_options_and_events(
            root,
            self.registry.clone(),
            literal,
            options,
            &on_event,
        )?;
        Ok(self.project(root, ws, options).with_auto_refresh(false))
    }

    /// Open only files whose paths match the supplied include/exclude
    /// filters. Intended for large security/profile queries where the
    /// path scope is known before semantic analysis starts.
    pub fn open_query_filtered_paths(
        &self,
        root: impl AsRef<Path>,
        include_filters: &[String],
        exclude_filters: &[String],
    ) -> Result<Project> {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::query_only());
        let ws = Workspace::open_query_filtered_paths_with_options(
            root,
            self.registry.clone(),
            include_filters,
            exclude_filters,
            options,
        )?;
        Ok(self.project(root, ws, options).with_auto_refresh(false))
    }

    /// Same as [`Self::open_query_filtered_paths`], emitting
    /// workspace lifecycle events while the scoped file set is opened.
    pub fn open_query_filtered_paths_with_progress<F>(
        &self,
        root: impl AsRef<Path>,
        include_filters: &[String],
        exclude_filters: &[String],
        on_event: F,
    ) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::query_only());
        let ws = Workspace::open_query_filtered_paths_with_options_and_events(
            root,
            self.registry.clone(),
            include_filters,
            exclude_filters,
            options,
            &on_event,
        )?;
        Ok(self.project(root, ws, options).with_auto_refresh(false))
    }

    /// Open and index exactly one supported source file under `root`.
    ///
    /// This is intended for navigation surfaces such as `read-file`
    /// where a direct file view should not pay whole-workspace parse
    /// or graph costs.
    pub fn open_query_matching_path(
        &self,
        root: impl AsRef<Path>,
        path: impl AsRef<Path>,
    ) -> Result<Project> {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::parse_only());
        let ws = Workspace::open_query_matching_path_with_options(
            root,
            self.registry.clone(),
            path.as_ref(),
            options,
        )?;
        Ok(self.project(root, ws, options).with_auto_refresh(false))
    }

    /// Same as [`Self::open_query_matching_path`], emitting workspace
    /// lifecycle events while the single-file workspace is opened.
    pub fn open_query_matching_path_with_progress<F>(
        &self,
        root: impl AsRef<Path>,
        path: impl AsRef<Path>,
        on_event: F,
    ) -> Result<Project>
    where
        F: Fn(WorkspaceOpenEvent) + Sync,
    {
        let root = root.as_ref();
        let options = self.apply_workspace_options(WorkspaceOpenOptions::parse_only());
        let ws = Workspace::open_query_matching_path_with_options_and_events(
            root,
            self.registry.clone(),
            path.as_ref(),
            options,
            &on_event,
        )?;
        Ok(self.project(root, ws, options).with_auto_refresh(false))
    }

    /// Open a workspace with explicit sidecar/prewarm behavior.
    pub fn open_with_options(
        &self,
        root: impl AsRef<Path>,
        options: WorkspaceOpenOptions,
    ) -> Result<Project> {
        let root = root.as_ref();
        let options = self.apply_workspace_options(options);
        let ws = Workspace::open_with_options(root, self.registry.clone(), options)?;
        let project = self.project(root, ws, options);
        persist_manifest_for_explicit_prewarm(&project)?;
        Ok(project)
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
        let options = self.apply_workspace_options(options);
        let ws = self.workspace_with_options_and_progress(root, options, &on_event)?;
        let project = self.project(root, ws, options);
        persist_manifest_for_explicit_prewarm(&project)?;
        Ok(project)
    }

    /// Open a root-only cache handle. This does not parse or index the
    /// workspace; it only manages SDK-owned persisted analysis cache files.
    #[must_use]
    pub fn cache(&self, root: impl AsRef<Path>) -> WorkspaceCache {
        let mut cache = WorkspaceCache::new(root);
        if let Some(rulepack_root) = self.rulepack_root.as_deref() {
            cache = cache.with_rulepack_root(rulepack_root);
        } else {
            cache = cache.with_discovered_rulepack_root();
        }
        cache
    }

    /// Rebuild the same bounded structural sidecars as
    /// `bonsai-ninja cache rebuild`: callgraph and IDG, plus the
    /// default export cache when `warm_export` is true. This does not
    /// run the legacy full-workspace dataflow prewarm.
    pub fn rebuild_structural_cache(&self, root: impl AsRef<Path>, warm_export: bool) -> Result<CacheStats> {
        let project = self.index_structural(root)?;
        project.cache().rebuild_structural_with_export(warm_export)
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
    fn project(&self, root: &Path, workspace: Workspace, open_options: WorkspaceOpenOptions) -> Project {
        let fingerprints = workspace_fingerprints_from_vfs(&workspace);
        Project {
            root: root.to_path_buf(),
            workspace,
            registry: self.registry.clone(),
            rulepack: self.rulepack.clone(),
            rulepack_root: self.rulepack_root.clone(),
            fingerprints: Arc::new(Mutex::new(fingerprints)),
            refresh_gate: Arc::new(Mutex::new(())),
            last_refresh_error: Arc::new(Mutex::new(None)),
            pending_dataflow_sidecar_save: Arc::new(AtomicBool::new(false)),
            refresh_options: open_options,
            auto_refresh: true,
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
        Workspace::open_with_options_and_events(root, self.registry.clone(), options, on_event)
            .with_context(|| format!("opening workspace at {}", root.display()))
    }
}

fn persist_manifest_for_explicit_prewarm(project: &Project) -> Result<()> {
    let options = project.refresh_options;
    let writes_analysis_sidecars = (options.prewarm_dataflow && options.save_dataflow_sidecar)
        || (options.prewarm_value_flow && options.save_value_flow_sidecar)
        || options.prewarm_flow_ids;
    if writes_analysis_sidecars {
        let _ = project.cache().warm_structural()?;
    }
    Ok(())
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
    refresh_gate: Arc<Mutex<()>>,
    last_refresh_error: Arc<Mutex<Option<String>>>,
    pending_dataflow_sidecar_save: Arc<AtomicBool>,
    refresh_options: WorkspaceOpenOptions,
    auto_refresh: bool,
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
        let fingerprints = workspace_fingerprints_from_vfs(&workspace);
        Self {
            root: root.to_path_buf(),
            workspace,
            fingerprints: Arc::new(Mutex::new(fingerprints)),
            registry,
            rulepack: None,
            rulepack_root: None,
            refresh_options: WorkspaceOpenOptions::default(),
            refresh_gate: Arc::new(Mutex::new(())),
            last_refresh_error: Arc::new(Mutex::new(None)),
            pending_dataflow_sidecar_save: Arc::new(AtomicBool::new(false)),
            auto_refresh: true,
        }
    }

    /// Attach a loaded rulepack to an existing project facade.
    #[must_use]
    pub fn with_loaded_rulepack(mut self, root: impl AsRef<Path>, rulepack: Rulepack) -> Self {
        self.rulepack_root = Some(root.as_ref().to_path_buf());
        self.rulepack = Some(Arc::new(rulepack));
        self
    }

    /// Control automatic save-time refreshes performed by SDK facades.
    ///
    /// One-shot CLI commands open a fresh workspace from disk, then keep
    /// analysis/rendering on that stable snapshot. Long-lived SDK clients
    /// keep the default `true` so saved edits are picked up before facade
    /// calls.
    #[must_use]
    pub fn with_auto_refresh(mut self, enabled: bool) -> Self {
        self.auto_refresh = enabled;
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
    pub fn semantic_context(&self) -> bonsai_workspace::WorkspaceSemanticContext {
        self.refresh_from_disk_best_effort();
        self.workspace.semantic_context()
    }

    #[must_use]
    pub fn diagnostics(&self) -> Vec<bonsai_diagnostics::Diagnostic> {
        self.refresh_from_disk_best_effort();
        self.workspace.diagnostics()
    }

    #[must_use]
    pub fn diagnostics_report(&self) -> DiagnosticsReport {
        self.refresh_from_disk_best_effort();
        DiagnosticsReport {
            diagnostics: self.workspace.diagnostics(),
            workspace_languages: self.workspace_languages(),
            adapter_capabilities: self.adapter_capability_rows(),
        }
    }

    fn workspace_languages(&self) -> Vec<String> {
        let mut langs = BTreeSet::new();
        let db = self.workspace.db();
        for file in db.global_index().all_files() {
            if let Some(adapter) = db.adapter_for(file) {
                langs.insert(adapter.language_id().as_str().to_string());
            }
        }
        langs.into_iter().collect()
    }

    fn adapter_capability_rows(&self) -> Vec<AdapterCapabilityRow> {
        let mut rows: Vec<AdapterCapabilityRow> = self
            .registry
            .all()
            .into_iter()
            .map(|adapter| {
                let caps = adapter.capabilities();
                AdapterCapabilityRow {
                    language: adapter.language_id().as_str().to_string(),
                    display_name: adapter.display_name().to_string(),
                    file_extensions: adapter
                        .file_extensions()
                        .iter()
                        .map(|ext| (*ext).to_string())
                        .collect(),
                    modules: caps.modules,
                    generics: caps.generics,
                    macros: caps.macros,
                    dynamic_dispatch: caps.dynamic_dispatch,
                    exceptions: caps.exceptions,
                    async_await: caps.async_await,
                    coroutines: caps.coroutines,
                    reflection: caps.reflection,
                    ffi: caps.ffi,
                    pattern_matching: caps.pattern_matching,
                    receiver_types: caps.receiver_types,
                    module_export_aliases: string_vec(caps.module_export_aliases),
                    constructor_method_names: string_vec(caps.effective_constructor_method_names()),
                    super_receiver_tokens: string_vec(caps.effective_super_receiver_tokens()),
                    implicit_receiver_tokens: string_vec(caps.effective_implicit_receiver_tokens()),
                }
            })
            .collect();
        rows.sort_by(|a, b| a.language.cmp(&b.language));
        rows
    }

    /// Fingerprint of the source files known to this project's current
    /// workspace snapshot. This is O(files) over the SDK's existing
    /// path/hash map and does not re-read files from disk.
    #[must_use]
    pub fn source_content_fingerprint(&self) -> WorkspaceContentFingerprint {
        self.current_source_fingerprint()
    }

    /// Most recent automatic or explicit refresh failure, if any.
    ///
    /// Existing facade methods retain their infallible/typed return contracts,
    /// so automatic refresh cannot always be returned through the method's
    /// error type. Failures are recorded here instead of being silently
    /// discarded. A later successful refresh clears the diagnostic.
    #[must_use]
    pub fn last_refresh_error(&self) -> Option<String> {
        self.last_refresh_error
            .lock()
            .expect("refresh error lock")
            .clone()
    }

    /// Refresh this long-lived project from the current on-disk source
    /// tree. Modified files are reparsed and reindexed in place; deleted
    /// files are removed from the live VFS/global index; new files are
    /// added and force a conservative dataflow rebuild because they can
    /// introduce new call-resolution targets. When anything changed, the
    /// dataflow sidecar is warmed and written back for the next process.
    pub fn refresh_from_disk(&self) -> Result<WorkspaceRefreshReport> {
        let result = self.refresh_from_disk_impl();
        let mut last_error = self.last_refresh_error.lock().expect("refresh error lock");
        match &result {
            Ok(_) => *last_error = None,
            Err(error) => *last_error = Some(format!("{error:#}")),
        }
        result
    }

    fn refresh_from_disk_impl(&self) -> Result<WorkspaceRefreshReport> {
        // A Project is Clone and its facades may be queried concurrently.
        // Serialise refresh transactions without holding the fingerprint-map
        // lock across file IO, parsing, cache invalidation, or sidecar writes.
        let _refresh = self.refresh_gate.lock().expect("refresh gate lock");
        let current = self
            .workspace
            .source_file_fingerprints(&self.root)
            .with_context(|| format!("scanning {}", self.root.display()))?;
        let current_map: AHashMap<PathBuf, u64> =
            current.into_iter().map(|file| (file.path, file.hash)).collect();

        let previous = self.fingerprints.lock().expect("fingerprint lock").clone();
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

        // The live workspace now reflects every source hash in current_map.
        // Publish that compact state before optional prewarm/persistence so a
        // sidecar write failure cannot cause every later query to reparse the
        // same already-applied edits.
        *self.fingerprints.lock().expect("fingerprint lock") = current_map;

        if report.changed() && self.refresh_options.prewarm_dataflow {
            let pending = self.workspace.dataflow().pending_count(self.workspace.db());
            self.workspace.dataflow().prewarm_all(self.workspace.db());
            report.dataflow_entries_built = pending;
            self.pending_dataflow_sidecar_save
                .store(self.refresh_options.save_dataflow_sidecar, Ordering::Release);
        }
        if self.pending_dataflow_sidecar_save.load(Ordering::Acquire) {
            self.save_dataflow_sidecar()
                .with_context(|| format!("saving dataflow sidecar under {}", self.root.display()))?;
            self.pending_dataflow_sidecar_save.store(false, Ordering::Release);
        }
        Ok(report)
    }

    fn refresh_from_disk_best_effort(&self) {
        if !self.auto_refresh {
            return;
        }
        let _ = self.refresh_from_disk();
    }

    /// Rebuild the live structural dataflow cache. Rulepack transfer
    /// semantics are applied by exact security/dump query paths; sanitizer
    /// credit remains report evidence and does not mutate this cache.
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
        Browse { project: self }
    }

    #[must_use]
    pub fn dump(&self) -> Dump<'_> {
        Dump { project: self }
    }

    #[must_use]
    pub fn show(&self) -> Show<'_> {
        Show { project: self }
    }

    #[must_use]
    pub fn export(&self) -> Export<'_> {
        Export { project: self }
    }

    #[must_use]
    pub fn security(&self) -> Security<'_> {
        Security { project: self }
    }

    #[must_use]
    pub fn trace(&self) -> Trace<'_> {
        Trace { project: self }
    }

    #[must_use]
    pub fn inspect(&self) -> Inspect<'_> {
        Inspect { project: self }
    }

    fn current_source_fingerprint(&self) -> ExportCacheContentFingerprint {
        let fingerprints = self.fingerprints.lock().expect("fingerprint lock");
        source_fingerprint_from_pairs(
            &self.root,
            fingerprints.iter().map(|(path, hash)| (path.as_path(), *hash)),
        )
    }
}

fn workspace_fingerprints_from_vfs(workspace: &Workspace) -> AHashMap<PathBuf, u64> {
    workspace
        .db()
        .vfs()
        .all_files()
        .into_iter()
        .filter_map(|file| {
            let path = workspace.db().vfs().path(file).ok()?;
            let snapshot = workspace.db().vfs().snapshot(file).ok()?;
            Some((
                path.to_path_buf(),
                bonsai_hash::fnv1a_bytes64(snapshot.text.as_bytes()),
            ))
        })
        .collect()
}

fn retrieval_include_filter(root: &Path, file_path: &str) -> Option<String> {
    if file_path.is_empty() || file_path == "<unknown>" {
        return None;
    }
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let path = Path::new(file_path);
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let relative = canonical_path
        .strip_prefix(&root)
        .or_else(|_| path.strip_prefix(&root))
        .unwrap_or(path);
    let filter = relative.to_string_lossy().replace('\\', "/");
    (!filter.is_empty()).then_some(filter)
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
    pub manifest: PathBuf,
    pub manifest_exists: bool,
    pub manifest_bytes: u64,
    pub dataflow_sidecar: PathBuf,
    pub dataflow_sidecar_exists: bool,
    pub dataflow_sidecar_bytes: u64,
    pub dataflow_factstore_sidecar: PathBuf,
    pub dataflow_factstore_sidecar_exists: bool,
    pub dataflow_factstore_sidecar_bytes: u64,
    pub value_flow_sidecar: PathBuf,
    pub value_flow_sidecar_exists: bool,
    pub value_flow_sidecar_bytes: u64,
    pub flow_ids_sidecar: PathBuf,
    pub flow_ids_sidecar_exists: bool,
    pub flow_ids_sidecar_bytes: u64,
    pub callgraph_sidecar: PathBuf,
    pub callgraph_sidecar_exists: bool,
    pub callgraph_sidecar_bytes: u64,
    pub idg_sidecar: PathBuf,
    pub idg_sidecar_exists: bool,
    pub idg_sidecar_bytes: u64,
    pub retrieval_sidecar: PathBuf,
    pub retrieval_sidecar_exists: bool,
    pub retrieval_sidecar_bytes: u64,
    pub taint_graph_sidecar: PathBuf,
    pub taint_graph_sidecar_exists: bool,
    pub taint_graph_sidecar_bytes: u64,
    pub export_sidecar: PathBuf,
    pub export_sidecar_exists: bool,
    pub export_sidecar_bytes: u64,
    pub validation: CacheValidationReport,
}

#[derive(Clone, Debug, Serialize)]
pub struct CacheValidationReport {
    pub manifest_status: CacheFreshnessStatus,
    pub structural_ready: bool,
    pub semantic_ready: bool,
    pub legacy_dataflow_ready: bool,
    pub taint_graph_ready: bool,
    pub export_ready: bool,
    pub sidecars: Vec<CacheSidecarValidation>,
    pub stale_reasons: Vec<String>,
}

impl CacheValidationReport {
    fn unvalidated() -> Self {
        Self {
            manifest_status: CacheFreshnessStatus::Unvalidated,
            structural_ready: false,
            semantic_ready: false,
            legacy_dataflow_ready: false,
            taint_graph_ready: false,
            export_ready: false,
            sidecars: Vec::new(),
            stale_reasons: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CacheSidecarValidation {
    pub name: String,
    pub path: PathBuf,
    pub status: CacheFreshnessStatus,
    pub exists: bool,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheFreshnessStatus {
    Fresh,
    Missing,
    Stale,
    Unvalidated,
    NotApplicable,
    Error,
}

impl CacheFreshnessStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::Unvalidated => "unvalidated",
            Self::NotApplicable => "not-applicable",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheManifest {
    pub schema_version: u32,
    pub engine_version: String,
    pub build_fingerprint: String,
    pub matcher_policy_fingerprint: u128,
    pub workspace_root: PathBuf,
    pub cache_dir: PathBuf,
    pub workspace_sources: WorkspaceContentFingerprint,
    pub dependency_metadata: WorkspaceContentFingerprint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rulepack: Option<WorkspaceContentFingerprint>,
    pub coverage: CacheManifestCoverage,
    pub sidecars: Vec<CacheManifestSidecar>,
    pub validation_note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheManifestCoverage {
    pub structural_ready: bool,
    pub semantic_ready: bool,
    pub legacy_dataflow_ready: bool,
    pub taint_graph_ready: bool,
    pub export_ready: bool,
    pub missing_reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheManifestSidecar {
    pub name: String,
    pub path: PathBuf,
    pub purpose: String,
    pub status: CacheManifestSidecarStatus,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheManifestSidecarStatus {
    Present,
    Missing,
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

    /// Attach the rulepack root discovered by the same precedence the
    /// CLI uses (`BONSAI_RULES_DIR`, workspace-local, parent-local,
    /// then cwd-local). Useful for root-only cache reads before a
    /// [`Project`] has been opened.
    #[must_use]
    pub fn with_discovered_rulepack_root(mut self) -> Self {
        if let Some(rulepack_root) = Bonsai::discover_rulepack_root(&self.root) {
            self.rulepack_root = Some(rulepack_root);
        }
        self
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stats(&self) -> std::io::Result<CacheStats> {
        let mut stats = self.raw_stats()?;
        stats.validation = cache_validation_report(&stats, &self.root, self.rulepack_root.as_deref());
        Ok(stats)
    }

    fn raw_stats(&self) -> std::io::Result<CacheStats> {
        let bonsai_dir = self.root.join(".bonsai");
        let manifest = self.manifest_path();
        let dataflow_sidecar = bonsai_workspace::dataflow::DataFlowCache::sidecar_path(&self.root);
        let dataflow_factstore_sidecar =
            bonsai_workspace::dataflow::DataFlowCache::factstore_sidecar_path(&self.root);
        let value_flow_sidecar = bonsai_workspace::value_flow::ValueFlowCache::sidecar_path(&self.root);
        let flow_ids_sidecar = bonsai_workspace::flow_ids::FlowIdCache::sidecar_path(&self.root);
        let callgraph_sidecar = bonsai_workspace::callgraph_sidecar::callgraph_sidecar_path(&self.root);
        let idg_sidecar = bonsai_workspace::idg_sidecar_path(&self.root);
        let retrieval_sidecar = bonsai_retrieval::retrieval_sidecar_path(&self.root);
        let taint_graph_sidecar =
            bonsai_workspace::taint_index::TaintGraphIndex::latest_sidecar_path(&self.root);
        let export_sidecar = default_export_cache_path(&self.root);
        let total_bytes = dir_size(&bonsai_dir)?;
        let manifest_bytes = file_size(&manifest);
        let dataflow_sidecar_bytes = file_size(&dataflow_sidecar);
        let dataflow_factstore_sidecar_bytes = file_size(&dataflow_factstore_sidecar);
        let value_flow_sidecar_bytes = file_size(&value_flow_sidecar);
        let flow_ids_sidecar_bytes = file_size(&flow_ids_sidecar);
        let callgraph_sidecar_bytes = file_size(&callgraph_sidecar);
        let idg_sidecar_bytes = file_size(&idg_sidecar);
        let retrieval_sidecar_bytes = file_size(&retrieval_sidecar);
        let taint_graph_sidecar_bytes = file_size(&taint_graph_sidecar);
        let export_sidecar_bytes = file_size(&export_sidecar);
        Ok(CacheStats {
            bonsai_dir_exists: bonsai_dir.is_dir(),
            dataflow_sidecar_exists: dataflow_sidecar.is_file(),
            dataflow_factstore_sidecar_exists: dataflow_factstore_sidecar.is_file(),
            value_flow_sidecar_exists: value_flow_sidecar.is_file(),
            flow_ids_sidecar_exists: flow_ids_sidecar.is_file(),
            callgraph_sidecar_exists: callgraph_sidecar.is_file(),
            idg_sidecar_exists: idg_sidecar.is_file(),
            retrieval_sidecar_exists: retrieval_sidecar.is_file(),
            taint_graph_sidecar_exists: taint_graph_sidecar.is_file(),
            export_sidecar_exists: export_sidecar.is_file(),
            manifest_exists: manifest.is_file(),
            bonsai_dir,
            total_bytes,
            manifest,
            manifest_bytes,
            dataflow_sidecar,
            dataflow_sidecar_bytes,
            dataflow_factstore_sidecar,
            dataflow_factstore_sidecar_bytes,
            value_flow_sidecar,
            value_flow_sidecar_bytes,
            flow_ids_sidecar,
            flow_ids_sidecar_bytes,
            callgraph_sidecar,
            callgraph_sidecar_bytes,
            idg_sidecar,
            idg_sidecar_bytes,
            retrieval_sidecar,
            retrieval_sidecar_bytes,
            taint_graph_sidecar,
            taint_graph_sidecar_bytes,
            export_sidecar,
            export_sidecar_bytes,
            validation: CacheValidationReport::unvalidated(),
        })
    }

    #[must_use]
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(".bonsai").join(CACHE_MANIFEST_FILE)
    }

    pub fn manifest(&self) -> Result<CacheManifest> {
        let stats = self.raw_stats()?;
        self.manifest_from_stats(&stats)
    }

    pub fn read_manifest(&self) -> Result<Option<CacheManifest>> {
        let path = self.manifest_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub fn write_manifest(&self) -> Result<CacheManifest> {
        let manifest = self.manifest()?;
        let mut bytes = serde_json::to_vec_pretty(&manifest)?;
        bytes.push(b'\n');
        write_atomic_bytes(&self.manifest_path(), &bytes)?;
        Ok(manifest)
    }

    fn manifest_from_stats(&self, stats: &CacheStats) -> Result<CacheManifest> {
        let sidecars = cache_manifest_sidecars(stats);
        let workspace_sources = workspace_source_fingerprint_from_disk(&self.root)?;
        let idg_sidecar_applicable =
            bonsai_workspace::idg_sidecar_enabled_for_file_count(workspace_sources.files);
        let coverage = cache_manifest_coverage(&sidecars, stats, idg_sidecar_applicable);
        Ok(CacheManifest {
            schema_version: CACHE_MANIFEST_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            build_fingerprint: export_cache_build_fingerprint().to_string(),
            matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
            workspace_root: self.root.clone(),
            cache_dir: stats.bonsai_dir.clone(),
            workspace_sources,
            dependency_metadata: dependency_metadata_fingerprint(&self.root)?,
            rulepack: self.rulepack_root.as_deref().map(rulepack_content_fingerprint).transpose()?,
            coverage,
            sidecars,
            validation_note: "Commands validate sidecar headers and pipeline fingerprints before reuse; this manifest records cache coverage and producer fingerprints at write time.".to_string(),
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
        let sidecars = [
            bonsai_workspace::dataflow::DataFlowCache::sidecar_path(&self.root),
            bonsai_workspace::dataflow::DataFlowCache::factstore_sidecar_path(&self.root),
        ];
        for sidecar in sidecars {
            if sidecar.exists() {
                fs::remove_file(sidecar)?;
            }
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

    pub fn stream_default_export_cache_if_fresh<W: Write + ?Sized>(&self, writer: &mut W) -> Result<bool> {
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
        } else {
            cache = cache.with_discovered_rulepack_root();
        }
        cache
    }

    pub fn stats(&self) -> std::io::Result<CacheStats> {
        self.workspace_cache().stats()
    }

    pub fn manifest(&self) -> Result<CacheManifest> {
        self.workspace_cache().manifest()
    }

    pub fn read_manifest(&self) -> Result<Option<CacheManifest>> {
        self.workspace_cache().read_manifest()
    }

    pub fn write_manifest(&self) -> Result<CacheManifest> {
        self.workspace_cache().write_manifest()
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

    /// Rebuild the bounded structural sidecars used by query,
    /// inspect, export, and security commands. This matches CLI
    /// `cache rebuild`: clear the persisted workspace cache, write a
    /// fresh callgraph sidecar, build/write the workspace IDG sidecar,
    /// and optionally warm the default export cache. It deliberately
    /// does not rebuild the legacy eager dataflow sidecar.
    pub fn rebuild_structural(&self) -> Result<CacheStats> {
        self.rebuild_structural_with_export(false)
    }

    /// Warm structural semantic sidecars without clearing unrelated
    /// cache artifacts. This is the SDK counterpart to
    /// `bonsai-ninja index --semantic`: write the resolved callgraph,
    /// build/write the workspace IDG only when its sidecar is enabled
    /// for this workspace size, and refresh the manifest. It does not
    /// run the legacy all-entry dataflow prewarm.
    pub fn warm_structural(&self) -> Result<CacheStats> {
        let cache = self.workspace_cache();
        let workspace = &self.project.workspace;
        if !workspace.load_callgraph_sidecar(&self.project.root) {
            let _ = workspace.cached_resolved_call_graph();
            workspace.save_callgraph_sidecar(&self.project.root)?;
        }
        match workspace.load_idg_sidecar(&self.project.root) {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = workspace.build_and_seed_persisted_idg_service();
            }
        }
        let _ = bonsai_retrieval::ensure_sidecar(workspace, &self.project.root)?;
        let _ = cache.write_manifest()?;
        Ok(cache.stats()?)
    }

    /// Same as [`Self::rebuild_structural`], with optional default
    /// native-export JSON cache warming.
    pub fn rebuild_structural_with_export(&self, warm_export: bool) -> Result<CacheStats> {
        let cache = self.workspace_cache();
        cache.clear_all()?;
        let workspace = &self.project.workspace;
        workspace.db().invalidate_idg_service();
        let _ = workspace.cached_resolved_call_graph();
        workspace.save_callgraph_sidecar(&self.project.root)?;
        let _ = workspace.build_and_seed_persisted_idg_service();
        bonsai_retrieval::save_sidecar(workspace, &self.project.root)?;
        if warm_export {
            self.project.export().warm_default_json_cache()?;
        }
        let _ = cache.write_manifest()?;
        Ok(cache.stats()?)
    }

    pub fn rebuild_dataflow(&self) -> std::io::Result<()> {
        self.project.workspace.reindex_dataflow();
        self.project.workspace.save_dataflow_sidecar(&self.project.root)?;
        let _ = self.workspace_cache().write_manifest();
        Ok(())
    }
}

fn cache_manifest_sidecars(stats: &CacheStats) -> Vec<CacheManifestSidecar> {
    vec![
        cache_manifest_sidecar(
            "callgraph",
            &stats.callgraph_sidecar,
            stats.callgraph_sidecar_exists,
            stats.callgraph_sidecar_bytes,
            "Resolved semantic callgraph shared by inspect, path, trace, export, and security.",
        ),
        cache_manifest_sidecar(
            "idg",
            &stats.idg_sidecar,
            stats.idg_sidecar_exists,
            stats.idg_sidecar_bytes,
            "Interprocedural data graph used by security, taint, inspect flow, path, and slice backends.",
        ),
        cache_manifest_sidecar(
            "retrieval",
            &stats.retrieval_sidecar,
            stats.retrieval_sidecar_exists,
            stats.retrieval_sidecar_bytes,
            "Fact-backed candidate index for search and candidate narrowing. Canonical facts still decide truth.",
        ),
        cache_manifest_sidecar(
            "dataflow_factstore",
            &stats.dataflow_factstore_sidecar,
            stats.dataflow_factstore_sidecar_exists,
            stats.dataflow_factstore_sidecar_bytes,
            "Per-function syntax-flow taint graphs for rulepack-free flow queries.",
        ),
        cache_manifest_sidecar(
            "dataflow_legacy",
            &stats.dataflow_sidecar,
            stats.dataflow_sidecar_exists,
            stats.dataflow_sidecar_bytes,
            "Compatibility dataflow sidecar retained for older warm-reopen paths.",
        ),
        cache_manifest_sidecar(
            "value_flow",
            &stats.value_flow_sidecar,
            stats.value_flow_sidecar_exists,
            stats.value_flow_sidecar_bytes,
            "On-demand seed-free compatibility graphs reused by slice and SDK/navigation clients; canonical security/export flow lives in the IDG.",
        ),
        cache_manifest_sidecar(
            "flow_ids",
            &stats.flow_ids_sidecar,
            stats.flow_ids_sidecar_exists,
            stats.flow_ids_sidecar_bytes,
            "Stable flow labels used by browse, inspect, read-file, and export renderers.",
        ),
        cache_manifest_sidecar(
            "taint_graph",
            &stats.taint_graph_sidecar,
            stats.taint_graph_sidecar_exists,
            stats.taint_graph_sidecar_bytes,
            "Configured source-seeded taint graph cache keyed by source function and seed set.",
        ),
        cache_manifest_sidecar(
            "export_default",
            &stats.export_sidecar,
            stats.export_sidecar_exists,
            stats.export_sidecar_bytes,
            "Default native export JSON for downstream tooling and repeated export commands.",
        ),
    ]
}

fn cache_manifest_sidecar(
    name: &str,
    path: &Path,
    exists: bool,
    bytes: u64,
    purpose: &str,
) -> CacheManifestSidecar {
    CacheManifestSidecar {
        name: name.to_string(),
        path: path.to_path_buf(),
        purpose: purpose.to_string(),
        status: if exists {
            CacheManifestSidecarStatus::Present
        } else {
            CacheManifestSidecarStatus::Missing
        },
        bytes,
        missing_reason: (!exists).then(|| "sidecar has not been produced for this workspace".to_string()),
    }
}

fn cache_manifest_coverage(
    sidecars: &[CacheManifestSidecar],
    stats: &CacheStats,
    idg_sidecar_applicable: bool,
) -> CacheManifestCoverage {
    let idg_ready = stats.idg_sidecar_exists || !idg_sidecar_applicable;
    let structural_ready = stats.callgraph_sidecar_exists && idg_ready && stats.retrieval_sidecar_exists;
    let semantic_ready = structural_ready;
    let mut missing_reasons = Vec::new();
    let required_sidecars: &[&str] = if idg_sidecar_applicable {
        &["callgraph", "idg", "retrieval"]
    } else {
        &["callgraph", "retrieval"]
    };
    for required in required_sidecars {
        if let Some(sidecar) = sidecars.iter().find(|sidecar| {
            sidecar.name == *required && sidecar.status == CacheManifestSidecarStatus::Missing
        }) {
            missing_reasons.push(format!(
                "{} missing: {}",
                sidecar.name,
                sidecar
                    .missing_reason
                    .as_deref()
                    .unwrap_or("sidecar has not been produced")
            ));
        }
    }
    CacheManifestCoverage {
        structural_ready,
        semantic_ready,
        legacy_dataflow_ready: stats.dataflow_factstore_sidecar_exists || stats.dataflow_sidecar_exists,
        taint_graph_ready: stats.taint_graph_sidecar_exists,
        export_ready: stats.export_sidecar_exists,
        missing_reasons,
    }
}

fn cache_validation_report(
    stats: &CacheStats,
    root: &Path,
    rulepack_root: Option<&Path>,
) -> CacheValidationReport {
    let source_files = match source_file_fingerprints_from_disk(root) {
        Ok(fingerprints) => fingerprints,
        Err(err) => {
            return cache_validation_error_report(
                stats,
                format!("workspace source fingerprint failed: {err}"),
            )
        }
    };
    let current_sources = source_fingerprint_from_pairs(
        root,
        source_files.iter().map(|file| (file.path.as_path(), file.hash)),
    );
    let idg_sidecar_applicable = bonsai_workspace::idg_sidecar_enabled_for_file_count(current_sources.files);
    let export_validation = export_sidecar_validation(stats, root, rulepack_root);
    let manifest_state = validate_cache_manifest(stats, root, rulepack_root, current_sources);

    let (manifest_status, sidecars, mut stale_reasons) = match manifest_state {
        ManifestValidationState::Fresh(manifest) => {
            let sidecars = validate_manifest_sidecars(
                stats,
                root,
                manifest.as_ref(),
                idg_sidecar_applicable,
                export_validation,
                &source_files,
            );
            let stale_reasons = sidecars
                .iter()
                .filter(|sidecar| {
                    matches!(
                        sidecar.status,
                        CacheFreshnessStatus::Stale
                            | CacheFreshnessStatus::Unvalidated
                            | CacheFreshnessStatus::Error
                    )
                })
                .filter_map(|sidecar| {
                    sidecar
                        .reason
                        .as_ref()
                        .map(|reason| format!("{}: {reason}", sidecar.name))
                })
                .collect();
            (CacheFreshnessStatus::Fresh, sidecars, stale_reasons)
        }
        ManifestValidationState::Missing => (
            CacheFreshnessStatus::Missing,
            validate_without_manifest(stats, idg_sidecar_applicable, export_validation),
            vec!["cache manifest is missing; sidecars cannot be validated as reusable".to_string()],
        ),
        ManifestValidationState::Stale(reasons) => (
            CacheFreshnessStatus::Stale,
            validate_stale_manifest_sidecars(stats, idg_sidecar_applicable, export_validation),
            reasons,
        ),
        ManifestValidationState::Error(reason) => (
            CacheFreshnessStatus::Error,
            validate_error_sidecars(stats, idg_sidecar_applicable, export_validation, &reason),
            vec![reason],
        ),
    };

    let structural_ready = validation_status(&sidecars, "callgraph") == Some(CacheFreshnessStatus::Fresh)
        && matches!(
            validation_status(&sidecars, "idg"),
            Some(CacheFreshnessStatus::Fresh | CacheFreshnessStatus::NotApplicable)
        )
        && validation_status(&sidecars, "retrieval") == Some(CacheFreshnessStatus::Fresh);
    let legacy_dataflow_ready = matches!(
        validation_status(&sidecars, "dataflow_factstore"),
        Some(CacheFreshnessStatus::Fresh)
    ) || matches!(
        validation_status(&sidecars, "dataflow_legacy"),
        Some(CacheFreshnessStatus::Fresh)
    );
    let taint_graph_ready = validation_status(&sidecars, "taint_graph") == Some(CacheFreshnessStatus::Fresh);
    let export_ready = validation_status(&sidecars, "export_default") == Some(CacheFreshnessStatus::Fresh);

    stale_reasons.sort();
    stale_reasons.dedup();
    CacheValidationReport {
        manifest_status,
        structural_ready,
        semantic_ready: structural_ready,
        legacy_dataflow_ready,
        taint_graph_ready,
        export_ready,
        sidecars,
        stale_reasons,
    }
}

fn cache_validation_error_report(stats: &CacheStats, reason: String) -> CacheValidationReport {
    CacheValidationReport {
        manifest_status: CacheFreshnessStatus::Error,
        structural_ready: false,
        semantic_ready: false,
        legacy_dataflow_ready: false,
        taint_graph_ready: false,
        export_ready: false,
        sidecars: cache_validation_inputs(stats)
            .into_iter()
            .map(|input| CacheSidecarValidation {
                name: input.name.to_string(),
                path: input.path.to_path_buf(),
                status: CacheFreshnessStatus::Error,
                exists: input.exists,
                bytes: input.bytes,
                reason: Some(reason.clone()),
            })
            .collect(),
        stale_reasons: vec![reason],
    }
}

enum ManifestValidationState {
    Fresh(Box<CacheManifest>),
    Missing,
    Stale(Vec<String>),
    Error(String),
}

fn validate_cache_manifest(
    stats: &CacheStats,
    root: &Path,
    rulepack_root: Option<&Path>,
    current_sources: WorkspaceContentFingerprint,
) -> ManifestValidationState {
    if !stats.manifest_exists {
        return ManifestValidationState::Missing;
    }
    let bytes = match fs::read(&stats.manifest) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return ManifestValidationState::Missing,
        Err(err) => {
            return ManifestValidationState::Error(format!(
                "reading cache manifest {} failed: {err}",
                stats.manifest.display()
            ))
        }
    };
    let manifest: CacheManifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            return ManifestValidationState::Error(format!(
                "parsing cache manifest {} failed: {err}",
                stats.manifest.display()
            ))
        }
    };

    let mut reasons = Vec::new();
    if manifest.schema_version != CACHE_MANIFEST_SCHEMA_VERSION {
        reasons.push(format!(
            "manifest schema version {} does not match {}",
            manifest.schema_version, CACHE_MANIFEST_SCHEMA_VERSION
        ));
    }
    if manifest.engine_version != env!("CARGO_PKG_VERSION") {
        reasons.push(format!(
            "manifest engine version {} does not match {}",
            manifest.engine_version,
            env!("CARGO_PKG_VERSION")
        ));
    }
    if manifest.build_fingerprint != export_cache_build_fingerprint() {
        reasons.push("manifest build fingerprint does not match the running binary".to_string());
    }
    if manifest.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
        reasons.push("manifest matcher policy fingerprint does not match the running binary".to_string());
    }
    if manifest.workspace_sources != current_sources {
        reasons.push("workspace source content changed since the cache manifest was written".to_string());
    }
    match dependency_metadata_fingerprint(root) {
        Ok(current) if manifest.dependency_metadata != current => {
            reasons.push("dependency metadata changed since the cache manifest was written".to_string());
        }
        Ok(_) => {}
        Err(err) => reasons.push(format!("dependency metadata fingerprint failed: {err}")),
    }
    match rulepack_root.map(rulepack_content_fingerprint).transpose() {
        Ok(current) if manifest.rulepack != current => {
            reasons.push("rulepack content changed since the cache manifest was written".to_string());
        }
        Ok(_) => {}
        Err(err) => reasons.push(format!("rulepack fingerprint failed: {err}")),
    }
    if reasons.is_empty() {
        ManifestValidationState::Fresh(Box::new(manifest))
    } else {
        ManifestValidationState::Stale(reasons)
    }
}

fn validate_manifest_sidecars(
    stats: &CacheStats,
    root: &Path,
    manifest: &CacheManifest,
    idg_sidecar_applicable: bool,
    export_validation: CacheSidecarValidation,
    source_files: &[bonsai_workspace::SourceFileFingerprint],
) -> Vec<CacheSidecarValidation> {
    cache_validation_inputs(stats)
        .into_iter()
        .map(|input| {
            if input.name == "export_default" {
                return export_validation.clone();
            }
            if input.name == "idg" && !idg_sidecar_applicable {
                return not_applicable_validation(input, "IDG sidecar is disabled for this workspace size");
            }
            let manifest_sidecar = manifest
                .sidecars
                .iter()
                .find(|sidecar| sidecar.name == input.name);
            let Some(manifest_sidecar) = manifest_sidecar else {
                return CacheSidecarValidation {
                    name: input.name.to_string(),
                    path: input.path.to_path_buf(),
                    status: if input.exists {
                        CacheFreshnessStatus::Unvalidated
                    } else {
                        CacheFreshnessStatus::Missing
                    },
                    exists: input.exists,
                    bytes: input.bytes,
                    reason: Some("sidecar is not listed in the cache manifest".to_string()),
                };
            };
            match manifest_sidecar.status {
                CacheManifestSidecarStatus::Missing if input.exists => CacheSidecarValidation {
                    name: input.name.to_string(),
                    path: input.path.to_path_buf(),
                    status: CacheFreshnessStatus::Unvalidated,
                    exists: true,
                    bytes: input.bytes,
                    reason: Some("sidecar was written after the cache manifest".to_string()),
                },
                CacheManifestSidecarStatus::Missing => CacheSidecarValidation {
                    name: input.name.to_string(),
                    path: input.path.to_path_buf(),
                    status: CacheFreshnessStatus::Missing,
                    exists: false,
                    bytes: input.bytes,
                    reason: manifest_sidecar.missing_reason.clone(),
                },
                CacheManifestSidecarStatus::Present if !input.exists => CacheSidecarValidation {
                    name: input.name.to_string(),
                    path: input.path.to_path_buf(),
                    status: CacheFreshnessStatus::Stale,
                    exists: false,
                    bytes: input.bytes,
                    reason: Some("cache manifest lists the sidecar, but the file is missing".to_string()),
                },
                CacheManifestSidecarStatus::Present if manifest_sidecar.bytes != input.bytes => {
                    CacheSidecarValidation {
                        name: input.name.to_string(),
                        path: input.path.to_path_buf(),
                        status: CacheFreshnessStatus::Stale,
                        exists: true,
                        bytes: input.bytes,
                        reason: Some(format!(
                            "sidecar size changed since manifest write: manifest={} actual={}",
                            manifest_sidecar.bytes, input.bytes
                        )),
                    }
                }
                CacheManifestSidecarStatus::Present => {
                    if let Some(reason) = validate_sidecar_payload(input, root, source_files) {
                        CacheSidecarValidation {
                            name: input.name.to_string(),
                            path: input.path.to_path_buf(),
                            status: CacheFreshnessStatus::Stale,
                            exists: true,
                            bytes: input.bytes,
                            reason: Some(reason),
                        }
                    } else {
                        CacheSidecarValidation {
                            name: input.name.to_string(),
                            path: input.path.to_path_buf(),
                            status: CacheFreshnessStatus::Fresh,
                            exists: true,
                            bytes: input.bytes,
                            reason: None,
                        }
                    }
                }
            }
        })
        .collect()
}

fn validate_sidecar_payload(
    input: CacheValidationInput<'_>,
    root: &Path,
    source_files: &[bonsai_workspace::SourceFileFingerprint],
) -> Option<String> {
    match input.name {
        "callgraph" if input.exists => {
            bonsai_workspace::callgraph_sidecar::validate_callgraph_sidecar_file_with_source_fingerprints(
                input.path,
                source_files
                    .iter()
                    .map(|file| (file.path.as_path(), file.hash)),
            )
                .err()
                .map(|err| format!("callgraph sidecar validation failed: {err}"))
        }
        "idg" if input.exists => bonsai_workspace::validate_idg_sidecar_file(input.path)
            .err()
            .map(|err| format!("idg sidecar validation failed: {err}")),
        "retrieval" if input.exists => retrieval_pipeline_hash_from_sources(root, source_files)
            .and_then(|pipeline| {
                bonsai_retrieval::validate_sidecar_file_with_pipeline(input.path, pipeline)
                    .map(|_| ())
                    .map_err(anyhow::Error::from)
            })
            .err()
            .map(|err| format!("retrieval sidecar validation failed: {err}")),
        "dataflow_factstore" if input.exists => {
            bonsai_workspace::dataflow::DataFlowCache::validate_factstore_sidecar_file_with_source_fingerprints(
                input.path,
                source_files
                    .iter()
                    .map(|file| (file.path.as_path(), file.hash)),
            )
                .err()
                .map(|err| format!("dataflow factstore sidecar validation failed: {err}"))
        }
        "value_flow" if input.exists => {
            bonsai_workspace::value_flow::ValueFlowCache::validate_sidecar_file_with_source_fingerprints(
                input.path,
                source_files
                    .iter()
                    .map(|file| (file.path.as_path(), file.hash)),
            )
                .err()
                .map(|err| format!("value-flow sidecar validation failed: {err}"))
        }
        "flow_ids" if input.exists => {
            bonsai_workspace::flow_ids::FlowIdCache::validate_sidecar_file_with_source_fingerprints(
                input.path,
                source_files
                    .iter()
                    .map(|file| (file.path.as_path(), file.hash)),
            )
                .err()
                .map(|err| format!("flow-id sidecar validation failed: {err}"))
        }
        "taint_graph" if input.exists => {
            bonsai_workspace::taint_index::TaintGraphIndex::validate_sidecar_file(input.path)
                .err()
                .map(|err| format!("taint-graph sidecar validation failed: {err}"))
        }
        _ => None,
    }
}

fn validate_without_manifest(
    stats: &CacheStats,
    idg_sidecar_applicable: bool,
    export_validation: CacheSidecarValidation,
) -> Vec<CacheSidecarValidation> {
    cache_validation_inputs(stats)
        .into_iter()
        .map(|input| {
            if input.name == "export_default" {
                return export_validation.clone();
            }
            if input.name == "idg" && !idg_sidecar_applicable {
                return not_applicable_validation(input, "IDG sidecar is disabled for this workspace size");
            }
            CacheSidecarValidation {
                name: input.name.to_string(),
                path: input.path.to_path_buf(),
                status: if input.exists {
                    CacheFreshnessStatus::Unvalidated
                } else {
                    CacheFreshnessStatus::Missing
                },
                exists: input.exists,
                bytes: input.bytes,
                reason: Some("cache manifest is missing".to_string()),
            }
        })
        .collect()
}

fn validate_stale_manifest_sidecars(
    stats: &CacheStats,
    idg_sidecar_applicable: bool,
    export_validation: CacheSidecarValidation,
) -> Vec<CacheSidecarValidation> {
    cache_validation_inputs(stats)
        .into_iter()
        .map(|input| {
            if input.name == "export_default" {
                return export_validation.clone();
            }
            if input.name == "idg" && !idg_sidecar_applicable {
                return not_applicable_validation(input, "IDG sidecar is disabled for this workspace size");
            }
            CacheSidecarValidation {
                name: input.name.to_string(),
                path: input.path.to_path_buf(),
                status: if input.exists {
                    CacheFreshnessStatus::Stale
                } else {
                    CacheFreshnessStatus::Missing
                },
                exists: input.exists,
                bytes: input.bytes,
                reason: Some("cache manifest is stale".to_string()),
            }
        })
        .collect()
}

fn validate_error_sidecars(
    stats: &CacheStats,
    idg_sidecar_applicable: bool,
    export_validation: CacheSidecarValidation,
    reason: &str,
) -> Vec<CacheSidecarValidation> {
    cache_validation_inputs(stats)
        .into_iter()
        .map(|input| {
            if input.name == "export_default" {
                return export_validation.clone();
            }
            if input.name == "idg" && !idg_sidecar_applicable {
                return not_applicable_validation(input, "IDG sidecar is disabled for this workspace size");
            }
            CacheSidecarValidation {
                name: input.name.to_string(),
                path: input.path.to_path_buf(),
                status: CacheFreshnessStatus::Error,
                exists: input.exists,
                bytes: input.bytes,
                reason: Some(reason.to_string()),
            }
        })
        .collect()
}

fn export_sidecar_validation(
    stats: &CacheStats,
    root: &Path,
    rulepack_root: Option<&Path>,
) -> CacheSidecarValidation {
    if !stats.export_sidecar_exists {
        return CacheSidecarValidation {
            name: "export_default".to_string(),
            path: stats.export_sidecar.clone(),
            status: CacheFreshnessStatus::Missing,
            exists: false,
            bytes: stats.export_sidecar_bytes,
            reason: Some("sidecar has not been produced for this workspace".to_string()),
        };
    }
    let file = match fs::File::open(&stats.export_sidecar) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return CacheSidecarValidation {
                name: "export_default".to_string(),
                path: stats.export_sidecar.clone(),
                status: CacheFreshnessStatus::Missing,
                exists: false,
                bytes: 0,
                reason: Some("sidecar disappeared during validation".to_string()),
            }
        }
        Err(err) => {
            return CacheSidecarValidation {
                name: "export_default".to_string(),
                path: stats.export_sidecar.clone(),
                status: CacheFreshnessStatus::Error,
                exists: true,
                bytes: stats.export_sidecar_bytes,
                reason: Some(format!("opening export sidecar failed: {err}")),
            }
        }
    };
    match export_cache_is_fresh_via_fd(root, rulepack_root, &file) {
        Ok(true) => CacheSidecarValidation {
            name: "export_default".to_string(),
            path: stats.export_sidecar.clone(),
            status: CacheFreshnessStatus::Fresh,
            exists: true,
            bytes: stats.export_sidecar_bytes,
            reason: None,
        },
        Ok(false) => CacheSidecarValidation {
            name: "export_default".to_string(),
            path: stats.export_sidecar.clone(),
            status: CacheFreshnessStatus::Stale,
            exists: true,
            bytes: stats.export_sidecar_bytes,
            reason: Some("export metadata does not match the current workspace/build".to_string()),
        },
        Err(err) => CacheSidecarValidation {
            name: "export_default".to_string(),
            path: stats.export_sidecar.clone(),
            status: CacheFreshnessStatus::Error,
            exists: true,
            bytes: stats.export_sidecar_bytes,
            reason: Some(format!("validating export metadata failed: {err}")),
        },
    }
}

fn not_applicable_validation(input: CacheValidationInput<'_>, reason: &str) -> CacheSidecarValidation {
    CacheSidecarValidation {
        name: input.name.to_string(),
        path: input.path.to_path_buf(),
        status: CacheFreshnessStatus::NotApplicable,
        exists: input.exists,
        bytes: input.bytes,
        reason: Some(reason.to_string()),
    }
}

fn validation_status(sidecars: &[CacheSidecarValidation], name: &str) -> Option<CacheFreshnessStatus> {
    sidecars
        .iter()
        .find(|sidecar| sidecar.name == name)
        .map(|sidecar| sidecar.status)
}

#[derive(Clone, Copy)]
struct CacheValidationInput<'a> {
    name: &'static str,
    path: &'a Path,
    exists: bool,
    bytes: u64,
}

fn cache_validation_inputs(stats: &CacheStats) -> Vec<CacheValidationInput<'_>> {
    vec![
        CacheValidationInput {
            name: "callgraph",
            path: &stats.callgraph_sidecar,
            exists: stats.callgraph_sidecar_exists,
            bytes: stats.callgraph_sidecar_bytes,
        },
        CacheValidationInput {
            name: "idg",
            path: &stats.idg_sidecar,
            exists: stats.idg_sidecar_exists,
            bytes: stats.idg_sidecar_bytes,
        },
        CacheValidationInput {
            name: "retrieval",
            path: &stats.retrieval_sidecar,
            exists: stats.retrieval_sidecar_exists,
            bytes: stats.retrieval_sidecar_bytes,
        },
        CacheValidationInput {
            name: "dataflow_factstore",
            path: &stats.dataflow_factstore_sidecar,
            exists: stats.dataflow_factstore_sidecar_exists,
            bytes: stats.dataflow_factstore_sidecar_bytes,
        },
        CacheValidationInput {
            name: "dataflow_legacy",
            path: &stats.dataflow_sidecar,
            exists: stats.dataflow_sidecar_exists,
            bytes: stats.dataflow_sidecar_bytes,
        },
        CacheValidationInput {
            name: "value_flow",
            path: &stats.value_flow_sidecar,
            exists: stats.value_flow_sidecar_exists,
            bytes: stats.value_flow_sidecar_bytes,
        },
        CacheValidationInput {
            name: "flow_ids",
            path: &stats.flow_ids_sidecar,
            exists: stats.flow_ids_sidecar_exists,
            bytes: stats.flow_ids_sidecar_bytes,
        },
        CacheValidationInput {
            name: "taint_graph",
            path: &stats.taint_graph_sidecar,
            exists: stats.taint_graph_sidecar_exists,
            bytes: stats.taint_graph_sidecar_bytes,
        },
        CacheValidationInput {
            name: "export_default",
            path: &stats.export_sidecar,
            exists: stats.export_sidecar_exists,
            bytes: stats.export_sidecar_bytes,
        },
    ]
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |meta| meta.len())
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

fn default_export_cache_metadata_path(root: &Path) -> PathBuf {
    root.join(".bonsai").join(DEFAULT_EXPORT_CACHE_METADATA_FILE)
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

fn default_export_lock_path(cache: &Path) -> PathBuf {
    let mut name = cache
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from(DEFAULT_EXPORT_CACHE_FILE));
    name.push(".lock");
    cache.with_file_name(name)
}

struct ExportCacheWriteLock {
    file: fs::File,
}

impl Drop for ExportCacheWriteLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// Serialize default-export cache replacement with an OS file lock. The lock
/// is released by the kernel when a process is interrupted, so once acquired
/// every matching temp sibling is known to be abandoned by a previous writer
/// and can be removed without racing another current bonsai process.
fn lock_default_export_cache(cache: &Path) -> Result<ExportCacheWriteLock> {
    let lock_path = default_export_lock_path(cache);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    file.lock_exclusive()?;
    cleanup_default_export_temp_files(cache)?;
    Ok(ExportCacheWriteLock { file })
}

fn cleanup_default_export_temp_files(target: &Path) -> Result<usize> {
    let Some(parent) = target.parent() else {
        return Ok(0);
    };
    let Some(file_name) = target.file_name().and_then(|name| name.to_str()) else {
        return Ok(0);
    };
    let prefix = format!("{file_name}.tmp.");
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut removed = 0usize;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        match fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(removed)
}

struct PendingExportTemp {
    path: PathBuf,
    committed: bool,
}

impl PendingExportTemp {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PendingExportTemp {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkspaceContentFingerprint {
    pub files: usize,
    pub digest: u64,
}

type ExportCacheContentFingerprint = WorkspaceContentFingerprint;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ExportCacheMetadata {
    metadata_version: u32,
    cache_file: String,
    cache_bytes: u64,
    engine_version: String,
    build_fingerprint: String,
    pipeline_version: String,
    matcher_policy_fingerprint: u128,
    workspace_sources: ExportCacheContentFingerprint,
    dependency_metadata: ExportCacheContentFingerprint,
    #[serde(skip_serializing_if = "Option::is_none")]
    rulepack: Option<ExportCacheContentFingerprint>,
}

fn write_default_export_cache(
    cache: &Path,
    root: &Path,
    rulepack_root: Option<&Path>,
    workspace_sources: ExportCacheContentFingerprint,
    out: &str,
) -> Result<()> {
    if let Some(parent) = cache.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = lock_default_export_cache(cache)?;
    cleanup_default_export_temp_files(&default_export_cache_metadata_path(root))?;
    let cache_bytes = out
        .len()
        .checked_add(1)
        .context("export cache output too large to write")? as u64;
    let metadata = build_export_cache_metadata(root, rulepack_root, workspace_sources, cache_bytes)?;
    let mut tmp = PendingExportTemp::new(unique_default_export_tmp_path(cache));
    {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp.path)?;
        let mut writer = io::BufWriter::with_capacity(1024 * 1024, file);
        writer.write_all(out.as_bytes())?;
        writeln!(writer)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    fs::rename(&tmp.path, cache)?;
    tmp.commit();
    let mut metadata_bytes = serde_json::to_vec_pretty(&metadata)?;
    metadata_bytes.push(b'\n');
    write_atomic_bytes(&default_export_cache_metadata_path(root), &metadata_bytes)?;
    sync_parent_dir(cache);
    Ok(())
}

fn write_default_export_cache_with<F>(
    cache: &Path,
    root: &Path,
    rulepack_root: Option<&Path>,
    workspace_sources: ExportCacheContentFingerprint,
    write_json: F,
) -> Result<()>
where
    F: FnOnce(&mut dyn Write) -> Result<()>,
{
    if let Some(parent) = cache.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = lock_default_export_cache(cache)?;
    cleanup_default_export_temp_files(&default_export_cache_metadata_path(root))?;
    let mut tmp = PendingExportTemp::new(unique_default_export_tmp_path(cache));
    {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp.path)?;
        let mut writer = io::BufWriter::with_capacity(1024 * 1024, file);
        write_json(&mut writer)?;
        writeln!(writer)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    let cache_bytes = fs::metadata(&tmp.path)?.len();
    let metadata = build_export_cache_metadata(root, rulepack_root, workspace_sources, cache_bytes)?;
    fs::rename(&tmp.path, cache)?;
    tmp.commit();
    let mut metadata_bytes = serde_json::to_vec_pretty(&metadata)?;
    metadata_bytes.push(b'\n');
    write_atomic_bytes(&default_export_cache_metadata_path(root), &metadata_bytes)?;
    sync_parent_dir(cache);
    Ok(())
}

fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = PendingExportTemp::new(unique_default_export_tmp_path(path));
    {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp.path)?;
        let mut writer = io::BufWriter::with_capacity(64 * 1024, file);
        writer.write_all(bytes)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    fs::rename(&tmp.path, path)?;
    tmp.commit();
    sync_parent_dir(path);
    Ok(())
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
}

/// Validate the freshness of an already-opened export cache file. The
/// export bytes are trusted only when the adjacent metadata sidecar
/// matches the current source content, dependency metadata, rulepack
/// content, matcher policy, and cache pipeline version.
fn export_cache_is_fresh_via_fd(root: &Path, rulepack_root: Option<&Path>, cache: &fs::File) -> Result<bool> {
    let Ok(cache_metadata) = cache.metadata() else {
        return Ok(false);
    };
    if !cache_metadata.is_file() || cache_metadata.len() == 0 {
        return Ok(false);
    }
    let Ok(Some(saved)) = read_export_cache_metadata(root) else {
        return Ok(false);
    };
    let workspace_sources = workspace_source_fingerprint_from_disk(root)?;
    let expected = build_export_cache_metadata(root, rulepack_root, workspace_sources, cache_metadata.len())?;
    if saved != expected {
        return Ok(false);
    }
    Ok(!current_exe_is_newer_than_cache(&cache_metadata))
}

fn read_export_cache_metadata(root: &Path) -> Result<Option<ExportCacheMetadata>> {
    let path = default_export_cache_metadata_path(root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn build_export_cache_metadata(
    root: &Path,
    rulepack_root: Option<&Path>,
    workspace_sources: ExportCacheContentFingerprint,
    cache_bytes: u64,
) -> Result<ExportCacheMetadata> {
    Ok(ExportCacheMetadata {
        metadata_version: DEFAULT_EXPORT_CACHE_METADATA_VERSION,
        cache_file: DEFAULT_EXPORT_CACHE_FILE.to_string(),
        cache_bytes,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        build_fingerprint: export_cache_build_fingerprint().to_string(),
        pipeline_version: DEFAULT_EXPORT_CACHE_PIPELINE_VERSION.to_string(),
        matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
        workspace_sources,
        dependency_metadata: dependency_metadata_fingerprint(root)?,
        rulepack: rulepack_root.map(rulepack_content_fingerprint).transpose()?,
    })
}

fn export_cache_build_fingerprint() -> &'static str {
    analyzer_build_fingerprint()
}

fn current_exe_is_newer_than_cache(cache_metadata: &fs::Metadata) -> bool {
    let Ok(cache_modified) = cache_metadata.modified() else {
        return false;
    };
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Ok(exe_meta) = fs::metadata(exe) else {
        return false;
    };
    let Ok(exe_modified) = exe_meta.modified() else {
        return false;
    };
    exe_modified > cache_modified
}

pub fn workspace_source_fingerprint_from_disk(root: &Path) -> Result<WorkspaceContentFingerprint> {
    let fingerprints = source_file_fingerprints_from_disk(root)?;
    Ok(source_fingerprint_from_pairs(
        root,
        fingerprints.iter().map(|file| (file.path.as_path(), file.hash)),
    ))
}

fn source_file_fingerprints_from_disk(root: &Path) -> Result<Vec<bonsai_workspace::SourceFileFingerprint>> {
    let registry = bonsai_adapters::all_languages_registry();
    let workspace = Workspace::new(registry);
    workspace
        .source_file_fingerprints(root)
        .with_context(|| format!("fingerprinting workspace sources under {}", root.display()))
}

fn retrieval_pipeline_hash_from_sources(
    root: &Path,
    fingerprints: &[bonsai_workspace::SourceFileFingerprint],
) -> Result<u64> {
    let root_for_pipeline = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    Ok(bonsai_retrieval::pipeline_hash_for_source_fingerprints(
        Some(root_for_pipeline.as_path()),
        fingerprints.iter().map(|file| (file.path.as_path(), file.hash)),
    ))
}

fn source_fingerprint_from_pairs<'a>(
    root: &Path,
    pairs: impl IntoIterator<Item = (&'a Path, u64)>,
) -> ExportCacheContentFingerprint {
    let stable_root = stable_root_path(root);
    let entries = pairs
        .into_iter()
        .map(|(path, hash)| (stable_relative_path(&stable_root, root, path), hash));
    content_fingerprint_from_entries(entries)
}

fn rulepack_content_fingerprint(root: &Path) -> Result<ExportCacheContentFingerprint> {
    let stable_root = stable_root_path(root);
    let mut entries = Vec::new();
    collect_regular_file_fingerprints(&stable_root, &stable_root, &mut entries, rulepack_dir_skipped)?;
    Ok(content_fingerprint_from_entries(entries))
}

fn dependency_metadata_fingerprint(root: &Path) -> Result<ExportCacheContentFingerprint> {
    let entries = collect_dependency_metadata_fingerprints(root)
        .with_context(|| format!("fingerprinting dependency metadata under {}", root.display()))?;
    Ok(content_fingerprint_from_entries(
        entries
            .into_iter()
            .map(|entry| (entry.relative_path, entry.content_hash)),
    ))
}

fn collect_regular_file_fingerprints(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, u64)>,
    skip_dir: fn(&str) -> bool,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(())
        }
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                if skip_dir(name) {
                    continue;
                }
            }
            collect_regular_file_fingerprints(root, &path, out, skip_dir)?;
        } else if file_type.is_file() {
            let digest = file_content_digest(&path)?;
            out.push((stable_relative_path(root, root, &path), digest));
        }
    }
    Ok(())
}

fn content_fingerprint_from_entries(
    entries: impl IntoIterator<Item = (String, u64)>,
) -> ExportCacheContentFingerprint {
    let mut entries: Vec<(String, u64)> = entries.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = bonsai_hash::Hasher::new();
    for (path, digest) in &entries {
        hasher.absorb(path.as_bytes());
        hasher.absorb_separator();
        hasher.absorb(&digest.to_le_bytes());
        hasher.absorb_separator();
    }
    ExportCacheContentFingerprint {
        files: entries.len(),
        digest: hasher.finish(),
    }
}

fn file_content_digest(path: &Path) -> Result<u64> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(bonsai_hash::fnv1a_bytes64(&bytes))
}

fn stable_root_path(root: &Path) -> PathBuf {
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

fn stable_relative_path(stable_root: &Path, original_root: &Path, path: &Path) -> String {
    path.strip_prefix(stable_root)
        .or_else(|_| path.strip_prefix(original_root))
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn rulepack_dir_skipped(name: &str) -> bool {
    matches!(name, ".git" | ".bonsai" | "target")
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

    pub fn entrypoints(
        &self,
        filters: EntryPointsFilters<'_>,
    ) -> Result<Vec<bonsai_browse::EntryPointOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::entrypoints(&self.project.workspace, &filters)
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

    pub fn operations(
        &self,
        filters: OperationsFilters<'_>,
    ) -> Result<Vec<bonsai_browse::OperationOut>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::operations(&self.project.workspace, &filters)
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

    pub fn paths(&self, filters: PathFilters<'_>) -> Result<bonsai_browse::PathOutcome, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::paths(&self.project.workspace, &filters)
    }

    pub fn slices(&self, filters: SliceFilters<'_>) -> bonsai_browse::SliceOutcome {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::slices(&self.project.workspace, &filters)
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
    pub fn hir(
        &self,
        symbol: &str,
    ) -> std::result::Result<Option<bonsai_browse::HirDump>, bonsai_browse::DumpLookupError> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::dump_hir(&self.project.workspace, symbol)
    }

    pub fn cfg(
        &self,
        symbol: &str,
    ) -> std::result::Result<Option<bonsai_cfg::Cfg>, bonsai_browse::DumpLookupError> {
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
    pub fn resolution_coverage(
        &self,
        filters: ResolutionCoverageFilters<'_>,
    ) -> Vec<bonsai_browse::ResolutionCoverageFileRow> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::resolution_coverage(&self.project.workspace, &filters)
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
    pub fn taint(&self, mut filters: TaintFilters<'_>) -> TaintOutcome {
        self.project.refresh_from_disk_best_effort();
        if let Some(pack) = self.project.rulepack.as_deref() {
            let transfers = bonsai_security::taint_transfers_from_rulepack(pack);
            filters.receiver_state_propagations = transfers.receiver_state_propagations;
            filters.call_result_passthroughs = transfers.call_result_passthroughs;
            filters.output_arg_flows = transfers.output_arg_flows;
        }
        bonsai_browse::dump_taint(&self.project.workspace, &filters)
    }
}

/// Stable-id drilldown facade.
///
/// This is the SDK counterpart to the structured parts of CLI `show`:
/// `E:` call edges, `F:` inspect graph flows or security taint-path
/// flows, `G:` inspect graph-flow groups, `N:` AST nodes, `R:`
/// resolver candidates, source-seeded `T:` dump-taint propagation ids,
/// and `S:` security findings.
pub struct Show<'a> {
    project: &'a Project,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShowOptions<'a> {
    /// Required for `R:` resolver candidate ids.
    pub query: Option<&'a str>,
    /// Optional file-context substring for `R:` resolver candidate ids.
    pub in_file: Option<&'a str>,
    /// Optional file filter for `N:` AST node ids.
    pub ast_file: Option<&'a str>,
    /// Optional function scope for `N:` AST node ids.
    pub ast_function: Option<&'a str>,
    /// Optional AST depth cap for `N:` drilldown.
    pub ast_max_depth: Option<usize>,
    /// Required for structured `T:` dump-taint propagation ids.
    pub taint_source: Option<&'a str>,
    /// Seed identifiers for structured `T:` propagation ids.
    pub taint_seeds: &'a [&'a str],
    /// Sanitizer identifiers for structured `T:` propagation ids.
    pub taint_sanitizers: &'a [&'a str],
    /// Optional sink-name filter when resolving `T:` propagation ids.
    pub taint_sink: Option<&'a str>,
    /// Optional compatibility budget for structured `T:` drilldown.
    pub taint_budget: Option<u32>,
    /// Legacy compatibility knob; structured `T:` drilldown uses uncapped IDG closure.
    pub taint_intra_worklist_cap: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub enum ShowOutcome {
    Edge(EdgeRecord),
    AstNode(AstFileDump),
    ResolverCandidate(Box<ResolveTrace>),
    InspectFlow(InspectFlowShow),
    InspectFlowGroup(InspectFlowGroupShow),
    TaintPropagation(TaintReport),
    SecurityFinding(Box<CombinedFindingWithChain>),
    SecurityFindingGroup(SecurityFindingGroupShow),
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectFlowShow {
    pub flow_id: String,
    pub matches: Vec<InspectFlowDrilldown>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectFlowDrilldown {
    pub target_func_id: u32,
    pub target: String,
    pub chain: InspectChain,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectFlowGroupShow {
    pub group_id: String,
    pub matches: Vec<InspectFlowGroupDrilldown>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectFlowGroupDrilldown {
    pub target_func_id: u32,
    pub target: String,
    pub group: InspectChainGroup,
    pub chains: Vec<InspectChain>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityFindingGroupShow {
    pub group_id: String,
    pub findings: Vec<CombinedFindingWithChain>,
}

impl Show<'_> {
    pub fn by_id(&self, id: &str, options: ShowOptions<'_>) -> Result<ShowOutcome> {
        let id = id.trim();
        let (prefix, body) = stable_id_parts(id)?;
        match prefix {
            "E" => self.edge(id),
            "F" => self.structural_or_security_flow(id),
            "G" => self.structural_or_security_group(id),
            "N" => self.ast_node(id, options),
            "R" => self.resolver_candidate(id, options),
            "T" => self.taint_propagation(id, options),
            "S" => self.security_finding(id),
            unsupported => Err(anyhow!(
                "stable id `{unsupported}:{body}` is not supported by SDK structured show yet; supported prefixes are E:, F:, G:, N:, R:, T:, and S:"
            )),
        }
    }

    pub fn edge(&self, edge_id: &str) -> Result<ShowOutcome> {
        let mut rows = self.project.dump().edges(EdgesFilters {
            edge_id: Some(edge_id),
            ..Default::default()
        });
        match rows.len() {
            1 => Ok(ShowOutcome::Edge(rows.remove(0))),
            0 => Err(anyhow!("edge id `{edge_id}` was not found")),
            _ => Err(anyhow!("edge id `{edge_id}` matched multiple rows")),
        }
    }

    pub fn ast_node(&self, node_id: &str, options: ShowOptions<'_>) -> Result<ShowOutcome> {
        match self.project.dump().ast(AstFilters {
            file: options.ast_file,
            function: options.ast_function,
            max_depth: options.ast_max_depth,
            node_id: Some(node_id),
        }) {
            AstOutcome::Dumps(mut dumps) if dumps.len() == 1 => Ok(ShowOutcome::AstNode(dumps.remove(0))),
            AstOutcome::Dumps(_) | AstOutcome::NodeIdNotFound => {
                Err(anyhow!("AST node id `{node_id}` was not found"))
            }
        }
    }

    pub fn resolver_candidate(&self, candidate_id: &str, options: ShowOptions<'_>) -> Result<ShowOutcome> {
        let Some(query) = options.query else {
            return Err(anyhow!(
                "`show {candidate_id}` needs ShowOptions::query because resolver candidate ids are scoped to the original dump-resolve query"
            ));
        };
        match self.project.dump().resolve(
            query,
            ResolveFilters {
                in_file: options.in_file,
                candidate_id: Some(candidate_id),
            },
        ) {
            ResolveOutcome::Trace(trace) => Ok(ShowOutcome::ResolverCandidate(trace)),
            ResolveOutcome::FileContextNotFound { needle } => Err(anyhow!(
                "resolver file context `{needle}` was not found for candidate id `{candidate_id}`"
            )),
            ResolveOutcome::CandidateNotFound => {
                Err(anyhow!("resolver candidate id `{candidate_id}` was not found"))
            }
        }
    }

    pub fn structural_flow(&self, flow_id: &str) -> Result<ShowOutcome> {
        let mut matches = Vec::new();
        for target in self.inspect_chains_for_show()? {
            for chain in target.chains {
                if chain.flow_id == flow_id {
                    matches.push(InspectFlowDrilldown {
                        target_func_id: target.target_func_id,
                        target: target.target.clone(),
                        chain,
                    });
                }
            }
        }
        if matches.is_empty() {
            Err(anyhow!("structural flow id `{flow_id}` was not found"))
        } else {
            Ok(ShowOutcome::InspectFlow(InspectFlowShow {
                flow_id: flow_id.to_string(),
                matches,
            }))
        }
    }

    pub fn structural_or_security_flow(&self, flow_id: &str) -> Result<ShowOutcome> {
        match self.structural_flow(flow_id) {
            Ok(outcome) => Ok(outcome),
            Err(structural_err) => self.security_flow(flow_id).map_err(|security_err| {
                anyhow!(
                    "flow id `{flow_id}` was not found as a structural inspect flow or security taint flow: {structural_err}; {security_err}"
                )
            }),
        }
    }

    pub fn flow_group(&self, group_id: &str) -> Result<ShowOutcome> {
        let mut matches = Vec::new();
        for target in self.inspect_chains_for_show()? {
            for group in target.groups.iter().filter(|group| group.group_id == group_id) {
                let member_ids: AHashSet<&str> = group.member_flow_ids.iter().map(String::as_str).collect();
                let chains = target
                    .chains
                    .iter()
                    .filter(|chain| member_ids.contains(chain.flow_id.as_str()))
                    .cloned()
                    .collect();
                matches.push(InspectFlowGroupDrilldown {
                    target_func_id: target.target_func_id,
                    target: target.target.clone(),
                    group: group.clone(),
                    chains,
                });
            }
        }
        if matches.is_empty() {
            Err(anyhow!("structural flow group id `{group_id}` was not found"))
        } else {
            Ok(ShowOutcome::InspectFlowGroup(InspectFlowGroupShow {
                group_id: group_id.to_string(),
                matches,
            }))
        }
    }

    pub fn structural_or_security_group(&self, group_id: &str) -> Result<ShowOutcome> {
        match self.flow_group(group_id) {
            Ok(outcome) => Ok(outcome),
            Err(structural_err) => self.security_group(group_id).map_err(|security_err| {
                anyhow!(
                    "group id `{group_id}` was not found as a structural inspect group or security taint group: {structural_err}; {security_err}"
                )
            }),
        }
    }

    pub fn taint_propagation(&self, taint_id: &str, options: ShowOptions<'_>) -> Result<ShowOutcome> {
        let Some(source) = options.taint_source else {
            return Err(anyhow!(
                "`show {taint_id}` needs ShowOptions::taint_source because structured T: propagation ids are source-seeded"
            ));
        };
        match self.project.dump().taint(TaintFilters {
            source,
            seeds: options
                .taint_seeds
                .iter()
                .map(|seed| (*seed).to_string())
                .collect(),
            sanitizers: options
                .taint_sanitizers
                .iter()
                .map(|sanitizer| (*sanitizer).to_string())
                .collect(),
            sink: options.taint_sink,
            budget: options.taint_budget,
            intra_worklist_cap: options.taint_intra_worklist_cap,
            taint_id: Some(taint_id),
            ..Default::default()
        }) {
            TaintOutcome::Report(report) => Ok(ShowOutcome::TaintPropagation(report)),
            TaintOutcome::SourceNotFound => Err(anyhow!("taint source `{source}` was not found")),
            TaintOutcome::SourceAmbiguous { candidates, .. } => Err(anyhow!(
                "taint source `{source}` is ambiguous ({} candidates)",
                candidates.len()
            )),
            TaintOutcome::TaintIdNotFound => Err(anyhow!("taint propagation id `{taint_id}` was not found")),
        }
    }

    pub fn security_finding(&self, finding_id: &str) -> Result<ShowOutcome> {
        let report = self.project.security().taint_analysis(TaintAnalysisOptions {
            include_pattern_only: true,
            show_sanitized: true,
            attach_flow_evidence: true,
            ..Default::default()
        })?;
        let mut matches: Vec<_> = report
            .findings
            .into_iter()
            .filter(|combined| {
                combined.finding.finding_id == finding_id
                    || combined
                        .member_finding_ids
                        .iter()
                        .any(|member_id| member_id == finding_id)
            })
            .collect();
        match matches.len() {
            1 => Ok(ShowOutcome::SecurityFinding(Box::new(matches.remove(0)))),
            0 => Err(anyhow!(
                "security finding id `{finding_id}` was not found in this workspace + rulepack"
            )),
            _ => Err(anyhow!(
                "security finding id `{finding_id}` matched multiple findings in this workspace + rulepack"
            )),
        }
    }

    pub fn security_flow(&self, flow_id: &str) -> Result<ShowOutcome> {
        let report = self.project.security().taint_analysis(TaintAnalysisOptions {
            flow_id: Some(flow_id.to_string()),
            include_pattern_only: true,
            show_sanitized: true,
            attach_flow_evidence: true,
            ..Default::default()
        })?;
        let mut matches = report.findings;
        match matches.len() {
            1 => Ok(ShowOutcome::SecurityFinding(Box::new(matches.remove(0)))),
            0 => Err(anyhow!(
                "security flow id `{flow_id}` was not found in this workspace + rulepack"
            )),
            _ => Err(anyhow!(
                "security flow id `{flow_id}` matched multiple findings in this workspace + rulepack"
            )),
        }
    }

    pub fn security_group(&self, group_id: &str) -> Result<ShowOutcome> {
        let report = self.project.security().taint_analysis(TaintAnalysisOptions {
            include_pattern_only: true,
            show_sanitized: true,
            attach_flow_evidence: true,
            ..Default::default()
        })?;
        let matches: Vec<_> = report
            .findings
            .into_iter()
            .filter(|combined| combined.finding.group_id.as_deref() == Some(group_id))
            .collect();
        if matches.is_empty() {
            Err(anyhow!(
                "security group id `{group_id}` was not found in this workspace + rulepack"
            ))
        } else {
            Ok(ShowOutcome::SecurityFindingGroup(SecurityFindingGroupShow {
                group_id: group_id.to_string(),
                findings: matches,
            }))
        }
    }

    fn inspect_chains_for_show(&self) -> Result<Vec<InspectTargetChains>> {
        Ok(self.project.inspect().chains(InspectQuery {
            pattern: None,
            regex: false,
            max_chains: usize::MAX,
            max_probes: usize::MAX,
        })?)
    }
}

fn stable_id_parts(id: &str) -> Result<(&str, &str)> {
    let Some((prefix, body)) = id.split_once(':') else {
        return Err(anyhow!(
            "stable id `{id}` is missing a prefix; expected E:, F:, G:, N:, R:, T:, or S:"
        ));
    };
    if body.is_empty() {
        return Err(anyhow!("stable id `{id}` is missing its hash body"));
    }
    Ok((prefix, body))
}

/// Export facade.
pub struct Export<'a> {
    project: &'a Project,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct NativeExportOptions {
    /// Materialize exhaustive interprocedural propagation records.
    /// Defaults to false because propagation records can be much
    /// larger than the structural taint graph; omitted exports carry
    /// `analysis_complete=false`, `propagations_complete=false`, and
    /// omission reasons.
    pub full_propagations: bool,
    /// Request complete semantic chain and flow-id-label evidence for
    /// native JSON export. Defaults to false so the warmed default
    /// export cache remains compact and predictable. Even small graphs can
    /// have exponentially many exact paths, so complete mode always uses the
    /// exact `compressed_callgraph` representation instead of materializing
    /// every path row.
    pub complete_chains: bool,
    /// Keep the complete propagation relation in canonical compiler form.
    /// This is the scalable exact mode used by CLI `export --all`.
    pub compiled_propagations: bool,
}

impl Export<'_> {
    pub fn native_json(&self, options: NativeExportOptions) -> serde_json::Result<serde_json::Value> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::native_export_json_with_config(
            &self.project.workspace,
            &self.project.root,
            bonsai_browse::NativeExportConfig {
                full_propagations: options.full_propagations,
                complete_chains: options.complete_chains,
                compiled_propagations: options.compiled_propagations,
            },
        )
    }

    pub fn native_json_string(&self, options: NativeExportOptions) -> serde_json::Result<String> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::render_native_export_json_with_config(
            &self.project.workspace,
            &self.project.root,
            bonsai_browse::NativeExportConfig {
                full_propagations: options.full_propagations,
                complete_chains: options.complete_chains,
                compiled_propagations: options.compiled_propagations,
            },
        )
    }

    pub fn write_native_json<W: Write + ?Sized>(
        &self,
        options: NativeExportOptions,
        writer: &mut W,
    ) -> serde_json::Result<()> {
        self.project.refresh_from_disk_best_effort();
        bonsai_browse::write_native_export_json_with_config(
            &self.project.workspace,
            &self.project.root,
            bonsai_browse::NativeExportConfig {
                full_propagations: options.full_propagations,
                complete_chains: options.complete_chains,
                compiled_propagations: options.compiled_propagations,
            },
            writer,
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
        } else {
            cache = cache.with_discovered_rulepack_root();
        }
        cache
    }

    pub fn default_json_cache_is_fresh(&self) -> Result<bool> {
        self.export_workspace_cache().default_export_cache_is_fresh()
    }

    pub fn stream_default_json_cache_if_fresh<W: Write + ?Sized>(&self, writer: &mut W) -> Result<bool> {
        self.export_workspace_cache()
            .stream_default_export_cache_if_fresh(writer)
    }

    pub fn write_default_json_cache(&self, out: &str) -> Result<()> {
        let rulepack_root = self
            .project
            .rulepack_root
            .clone()
            .or_else(|| Bonsai::discover_rulepack_root(&self.project.root));
        write_default_export_cache(
            &self.default_json_cache_path(),
            &self.project.root,
            rulepack_root.as_deref(),
            self.project.current_source_fingerprint(),
            out,
        )
    }

    pub fn write_default_json_cache_streaming(&self, options: NativeExportOptions) -> Result<()> {
        anyhow::ensure!(
            !options.complete_chains && !options.full_propagations && !options.compiled_propagations,
            "default export cache can only store default native export scope"
        );
        let rulepack_root = self
            .project
            .rulepack_root
            .clone()
            .or_else(|| Bonsai::discover_rulepack_root(&self.project.root));
        write_default_export_cache_with(
            &self.default_json_cache_path(),
            &self.project.root,
            rulepack_root.as_deref(),
            self.project.current_source_fingerprint(),
            |writer| {
                self.write_native_json(options, writer)
                    .map_err(|err| anyhow!("serializing native export JSON: {err}"))
            },
        )
    }

    pub fn warm_default_json_cache(&self) -> Result<()> {
        self.project.refresh_from_disk_best_effort();
        if self.default_json_cache_is_fresh()? {
            return Ok(());
        }
        self.write_default_json_cache_streaming(NativeExportOptions {
            full_propagations: false,
            complete_chains: false,
            compiled_propagations: false,
        })
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
        let report = bonsai_security::run_taint_analysis(&self.project.workspace, self.pack()?, options)?;
        self.refresh_cache_manifest_best_effort();
        Ok(report)
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
        let report = bonsai_security::run_taint_analysis_with_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_rule,
        )?;
        self.refresh_cache_manifest_best_effort();
        Ok(report)
    }

    /// Phase-aware progress variant. The callback receives
    /// `PhaseStarted { label, total }` / `PhaseTicked` / `PhaseFinished`
    /// events so a CLI can render a progress bar with a known length
    /// for every long-running phase, plus `Note` events for scope/cache
    /// observability that the legacy callback can't describe.
    pub fn taint_analysis_with_phase_progress<F>(
        &self,
        options: TaintAnalysisOptions,
        on_progress: F,
    ) -> Result<bonsai_security::TaintAnalysisReport>
    where
        F: FnMut(bonsai_security::AnalysisProgress),
    {
        self.project.refresh_from_disk_best_effort();
        let report = bonsai_security::run_taint_analysis_with_phase_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_progress,
        )?;
        self.refresh_cache_manifest_best_effort();
        Ok(report)
    }

    pub fn source_analysis(
        &self,
        options: SourceAnalysisOptions,
    ) -> Result<bonsai_security::SourceAnalysisReport> {
        self.project.refresh_from_disk_best_effort();
        let report = bonsai_security::run_source_analysis(&self.project.workspace, self.pack()?, options)?;
        self.refresh_cache_manifest_best_effort();
        Ok(report)
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
        let report = bonsai_security::run_source_analysis_with_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_rule,
        )?;
        self.refresh_cache_manifest_best_effort();
        Ok(report)
    }

    /// Phase-aware progress variant of [`Self::source_analysis_with_progress`].
    /// Emits phase progress plus `Note` events for source scope and
    /// taint-graph cache observability.
    pub fn source_analysis_with_phase_progress<F>(
        &self,
        options: SourceAnalysisOptions,
        on_progress: F,
    ) -> Result<bonsai_security::SourceAnalysisReport>
    where
        F: FnMut(bonsai_security::AnalysisProgress),
    {
        self.project.refresh_from_disk_best_effort();
        let report = bonsai_security::run_source_analysis_with_phase_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_progress,
        )?;
        self.refresh_cache_manifest_best_effort();
        Ok(report)
    }

    fn refresh_cache_manifest_best_effort(&self) {
        if !self.project.workspace.is_complete_workspace_index() {
            return;
        }
        let _ = self.project.cache().write_manifest();
    }

    pub fn sources(&self, options: SecurityInventoryOptions) -> Result<Vec<bonsai_security::RuleMatch>> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::source_inventory(&self.project.workspace, self.pack()?, options)
    }

    pub fn sources_with_progress<F>(
        &self,
        options: SecurityInventoryOptions,
        on_progress: F,
    ) -> Result<Vec<bonsai_security::RuleMatch>>
    where
        F: FnMut(bonsai_security::AnalysisProgress),
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::source_inventory_with_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_progress,
        )
    }

    pub fn sinks(&self, options: SecurityInventoryOptions) -> Result<Vec<bonsai_security::RuleMatch>> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::sink_inventory(&self.project.workspace, self.pack()?, options)
    }

    pub fn sinks_with_progress<F>(
        &self,
        options: SecurityInventoryOptions,
        on_progress: F,
    ) -> Result<Vec<bonsai_security::RuleMatch>>
    where
        F: FnMut(bonsai_security::AnalysisProgress),
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::sink_inventory_with_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_progress,
        )
    }

    pub fn sanitizers(&self, options: SecurityInventoryOptions) -> Result<Vec<bonsai_security::RuleMatch>> {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::sanitizer_inventory(&self.project.workspace, self.pack()?, options)
    }

    pub fn sanitizers_with_progress<F>(
        &self,
        options: SecurityInventoryOptions,
        on_progress: F,
    ) -> Result<Vec<bonsai_security::RuleMatch>>
    where
        F: FnMut(bonsai_security::AnalysisProgress),
    {
        self.project.refresh_from_disk_best_effort();
        bonsai_security::sanitizer_inventory_with_progress(
            &self.project.workspace,
            self.pack()?,
            options,
            on_progress,
        )
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
    pub groups: Vec<InspectChainGroup>,
    pub truncated: bool,
    pub truncation: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectChain {
    pub flow_id: String,
    pub funcs: Vec<u32>,
    pub names: Vec<String>,
    pub precision: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectChainGroup {
    pub group_id: String,
    pub member_flow_ids: Vec<String>,
    pub shared_suffix: Vec<String>,
    pub unique_prefixes: Vec<Vec<String>>,
    pub precision: String,
    pub member_count: usize,
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
        let matcher = bonsai_inspect::Matcher::build(pattern, regex)?;
        Ok(bonsai_inspect::matching_decls(&self.project.workspace, &matcher))
    }

    pub fn matching_func_ids(&self, pattern: Option<&str>, regex: bool) -> Result<Vec<FuncId>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        let matcher = bonsai_inspect::Matcher::build(pattern, regex)?;
        Ok(bonsai_inspect::matching_func_ids(
            &self.project.workspace,
            &matcher,
        ))
    }

    pub fn chains(&self, query: InspectQuery<'_>) -> Result<Vec<InspectTargetChains>, regex::Error> {
        self.project.refresh_from_disk_best_effort();
        let matcher = bonsai_inspect::Matcher::build(query.pattern, query.regex)?;
        let targets = bonsai_inspect::matching_func_ids(&self.project.workspace, &matcher);
        let cache = bonsai_inspect::ChainCache::new(&self.project.workspace);
        let mut out = Vec::new();
        for target in targets {
            let (chains, truncation) = cache.chains_resolved(target, query.max_chains, query.max_probes);
            let chains = chains
                .into_iter()
                .map(|chain| {
                    let names = bonsai_inspect::chain_to_names(&self.project.workspace, &chain.funcs);
                    InspectChain {
                        flow_id: bonsai_inspect::compute_flow_id(&names),
                        funcs: chain.funcs.iter().map(|func| func.raw()).collect(),
                        names,
                        precision: format!("{:?}", chain.precision),
                    }
                })
                .collect::<Vec<_>>();
            let groups = group_inspect_chains_by_suffix(&chains);
            out.push(InspectTargetChains {
                target_func_id: target.raw(),
                target: bonsai_inspect::func_display_name(&self.project.workspace, target),
                chains,
                groups,
                truncated: truncation.is_truncated(),
                truncation: truncation.label().map(str::to_string),
            });
        }
        Ok(out)
    }
}

fn group_inspect_chains_by_suffix(chains: &[InspectChain]) -> Vec<InspectChainGroup> {
    if chains.is_empty() {
        return Vec::new();
    }

    let mut bucket_index_by_sink: AHashMap<String, usize> = AHashMap::new();
    let mut buckets: Vec<(String, Vec<&InspectChain>)> = Vec::new();
    for chain in chains {
        let Some(sink_name) = chain.names.last().cloned() else {
            continue;
        };
        let bucket_idx = *bucket_index_by_sink.entry(sink_name.clone()).or_insert_with(|| {
            buckets.push((sink_name.clone(), Vec::new()));
            buckets.len() - 1
        });
        buckets[bucket_idx].1.push(chain);
    }

    let mut groups = Vec::with_capacity(buckets.len());
    for (_sink_name, members) in buckets {
        let shortest_member_chain_len = members.iter().map(|member| member.names.len()).min().unwrap_or(1);
        let mut suffix_len = 1usize;
        while suffix_len < shortest_member_chain_len {
            let candidate_idx_in_first = members[0].names.len() - 1 - suffix_len;
            let candidate_name = &members[0].names[candidate_idx_in_first];
            let every_member_agrees = members.iter().all(|member| {
                let candidate_idx = member.names.len() - 1 - suffix_len;
                &member.names[candidate_idx] == candidate_name
            });
            if every_member_agrees {
                suffix_len += 1;
            } else {
                break;
            }
        }

        let first_member_chain = &members[0].names;
        let shared_suffix = first_member_chain[first_member_chain.len() - suffix_len..].to_vec();
        let mut member_flow_ids = Vec::with_capacity(members.len());
        let mut unique_prefixes = Vec::with_capacity(members.len());
        let mut precision = "Exact".to_string();
        for member in &members {
            member_flow_ids.push(member.flow_id.clone());
            let prefix_end = member.names.len() - suffix_len;
            unique_prefixes.push(member.names[..prefix_end].to_vec());
            precision = worse_precision(&precision, &member.precision).to_string();
        }

        groups.push(InspectChainGroup {
            group_id: bonsai_inspect::compute_group_id(&shared_suffix),
            member_flow_ids,
            shared_suffix,
            unique_prefixes,
            precision,
            member_count: members.len(),
        });
    }
    groups
}

fn worse_precision<'a>(left: &'a str, right: &'a str) -> &'a str {
    if precision_rank(right) > precision_rank(left) {
        right
    } else {
        left
    }
}

fn precision_rank(precision: &str) -> u8 {
    match precision {
        "Exact" => 0,
        "Narrowed" => 1,
        "OverApproximate" => 2,
        _ => 3,
    }
}

#[cfg(test)]
#[path = "rulepack_discovery_tests.rs"]
mod rulepack_discovery_tests;

#[cfg(test)]
#[path = "export_cache_tests.rs"]
mod export_cache_tests;
