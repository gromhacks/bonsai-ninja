//! Canonical workspace entry point for syntax-shaped taint graphs.
//!
//! Commands should ask this module for an entry graph instead of
//! open-coding "try IDG, else dataflow" decisions. The IDG target cut
//! and cached dataflow graph are backend choices for the same semantic
//! query: adapter-lowered `FlowEvent`s, resolver-backed call edges, and
//! the taint crate's canonical propagation rules.

use crate::Workspace;
use ahash::{AHashMap, AHashSet};
use bonsai_common::FuncId;
use std::sync::Arc;

pub use bonsai_taint::{EntryTaintGraph, TaintedCall, TaintedCallEdge, TaintedCallKind};

/// Exact target nodes grouped by syntax owner, plus owners whose spans do not
/// map to a scalar IDG node.
pub type SyntaxFlowTargetsBySource = (AHashMap<FuncId, Vec<bonsai_idg::WsNodeId>>, AHashSet<FuncId>);

/// Backend used to answer a syntax-flow query.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SyntaxFlowBackend {
    /// Answered by the warmed workspace IDG with an optional target cut.
    WarmedIdgTargetCut,
    /// Answered by an exact query-scoped IDG built from the compiler's
    /// source-to-target call-graph corridor.
    ScopedIdgTargetCut,
    /// Answered by the persisted/on-demand canonical dataflow cache.
    CachedDataflow,
}

impl SyntaxFlowBackend {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WarmedIdgTargetCut => "warmed-idg-target-cut",
            Self::ScopedIdgTargetCut => "scoped-idg-target-cut",
            Self::CachedDataflow => "cached-dataflow",
        }
    }
}

/// Exact semantic session for one source batch in an inspect request.
///
/// The session owns a file/function-scoped IDG compiled from the complete
/// source-to-target resolver corridor. It is deliberately not installed as
/// the workspace-global IDG, so a partial query graph can never be reused as
/// a full-workspace graph by security, export, or another command.
#[derive(Clone)]
pub struct SyntaxFlowSession {
    idg: Arc<bonsai_idg::IdgQueryService>,
    _lease: Arc<tempfile::TempDir>,
}

impl SyntaxFlowSession {
    /// Exact query-local IDG compiled for this session.
    ///
    /// The service is deliberately borrowed through the session so the
    /// temporary factstore that pages its graph remains alive for the whole
    /// query.
    #[must_use]
    pub fn idg(&self) -> &bonsai_idg::IdgQueryService {
        self.idg.as_ref()
    }
}

impl std::fmt::Debug for SyntaxFlowSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyntaxFlowSession")
            .finish_non_exhaustive()
    }
}

/// Cache state observed while answering a syntax-flow query.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SyntaxFlowCacheStatus {
    /// The selected backend was already available before this query did
    /// any per-entry work.
    Hit,
    /// The selected backend had to compute the requested entry graph.
    MissComputed,
}

impl SyntaxFlowCacheStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::MissComputed => "miss-computed",
        }
    }
}

/// One entry-function taint graph query.
#[derive(Copy, Clone, Debug)]
pub struct SyntaxFlowQuery<'a> {
    pub entry: FuncId,
    pub target_nodes: Option<&'a [bonsai_idg::WsNodeId]>,
    pub target_funcs: Option<&'a AHashSet<FuncId>>,
    pub lineage_funcs: Option<&'a AHashSet<FuncId>>,
    pub target_relevance: Option<&'a bonsai_idg::IdgTargetRelevance>,
    pub prefer_warmed_idg: bool,
    pub session: Option<&'a SyntaxFlowSession>,
}

impl<'a> SyntaxFlowQuery<'a> {
    #[must_use]
    pub const fn new(entry: FuncId) -> Self {
        Self {
            entry,
            target_nodes: None,
            target_funcs: None,
            lineage_funcs: None,
            target_relevance: None,
            prefer_warmed_idg: false,
            session: None,
        }
    }

    #[must_use]
    pub const fn target_nodes(mut self, target_nodes: Option<&'a [bonsai_idg::WsNodeId]>) -> Self {
        self.target_nodes = target_nodes;
        self
    }

    #[must_use]
    pub const fn target_funcs(mut self, target_funcs: Option<&'a AHashSet<FuncId>>) -> Self {
        self.target_funcs = target_funcs;
        self
    }

    #[must_use]
    pub const fn lineage_funcs(mut self, lineage_funcs: Option<&'a AHashSet<FuncId>>) -> Self {
        self.lineage_funcs = lineage_funcs;
        self
    }

    /// Reuse one conservative backward demand proof across an entry batch.
    /// The exact forward closure still validates every admitted path.
    #[must_use]
    pub const fn target_relevance(
        mut self,
        target_relevance: Option<&'a bonsai_idg::IdgTargetRelevance>,
    ) -> Self {
        self.target_relevance = target_relevance;
        self
    }

    #[must_use]
    pub const fn prefer_warmed_idg(mut self, prefer_warmed_idg: bool) -> Self {
        self.prefer_warmed_idg = prefer_warmed_idg;
        self
    }

    #[must_use]
    pub const fn session(mut self, session: Option<&'a SyntaxFlowSession>) -> Self {
        self.session = session;
        self
    }
}

/// Planner metadata for a syntax-flow query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxFlowPlan {
    pub entry: FuncId,
    pub backend: SyntaxFlowBackend,
    pub cache_status: SyntaxFlowCacheStatus,
    pub prefer_warmed_idg: bool,
    pub idg_available: bool,
    pub target_cut_size: Option<usize>,
    pub fallback_reasons: Vec<String>,
    pub analysis_incomplete_reasons: Vec<String>,
}

/// Result of a syntax-flow query.
#[derive(Clone, Debug)]
pub struct SyntaxFlowGraph {
    pub graph: Arc<EntryTaintGraph>,
    pub backend: SyntaxFlowBackend,
    pub plan: SyntaxFlowPlan,
}

impl Workspace {
    fn reopen_query_workspace_for_graph(
        &self,
        graph: bonsai_callgraph::ResolvedCallGraph,
        diagnostic_label: &str,
    ) -> Option<Workspace> {
        let graph = Arc::new(graph);
        let mut reached_files = graph.nodes().iter().map(|node| node.file).collect::<Vec<_>>();
        // Preserve endpoint candidate files even when the exact relation has
        // no source-to-target path. The resulting empty seeded graph then
        // answers "no path" without falling back to a whole-workspace build.
        if reached_files.is_empty() {
            reached_files.extend(self.vfs().all_files());
        }
        reached_files.sort_unstable_by_key(|file| file.raw());
        reached_files.dedup();
        let root = self.root_path()?;
        let source_inputs = match self.sidecar_source_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "{} source generation unavailable: {}",
                    diagnostic_label,
                    error
                );
                return None;
            }
        };
        let mut files = Vec::with_capacity(reached_files.len());
        for file in reached_files {
            let Ok(position) = source_inputs.binary_search_by_key(&file.raw(), |(raw, _, _)| *raw) else {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "{} file {} is absent from source generation",
                    diagnostic_label,
                    file.raw()
                );
                return None;
            };
            files.push((file, std::path::PathBuf::from(&source_inputs[position].1)));
        }
        match Workspace::open_query_exact_files_with_source_inputs_and_events(
            &root,
            Arc::clone(&self.inner.registry),
            &files,
            source_inputs.as_ref().clone(),
            crate::WorkspaceOpenOptions::lazy_query(),
            &|_| {},
        ) {
            Ok(workspace) => {
                // The reopened VFS contains a subset of full-workspace
                // FileIds. Seed its declaration cache from the partitioned
                // header generation before any exact declaration lookup;
                // rebuilding headers from the subset would renumber SymbolIds
                // and make persisted callgraph endpoints impossible to
                // hydrate.
                let header_files = files.iter().map(|(file, _)| *file).collect::<Vec<_>>();
                let headers = workspace.compiler_header_index_for_files(&header_files);
                *workspace.inner.compiler_headers.write() = Some(headers);
                workspace.seed_resolved_call_graph(graph);
                Some(workspace)
            }
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "{} hydration failed: {}",
                    diagnostic_label,
                    error
                );
                None
            }
        }
    }

    /// Reopen only the exact source files reachable from `source_funcs`.
    ///
    /// Retrieval-scoped CLI workspaces initially contain the source
    /// declaration candidates only. The persisted compiler callgraph carries
    /// stable full-workspace FileIds, so this method can hydrate the complete
    /// uncapped reachable file set without ingesting unrelated source text.
    /// `None` means the current workspace is already complete or a validated
    /// partitioned source generation is unavailable.
    #[must_use]
    pub fn source_reachable_query_workspace(
        &self,
        source_funcs: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> Option<Workspace> {
        if self.is_complete_workspace_index() || source_funcs.is_empty() {
            return None;
        }
        let graph = match self.persisted_resolved_call_graph_reachable_from(source_funcs, max_precision)? {
            Ok(graph) => graph,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "source-flow workspace callgraph partitions rejected: {}",
                    error
                );
                return None;
            }
        };
        self.reopen_query_workspace_for_graph(graph, "source-flow workspace")
    }

    /// Reopen only the exact compiler corridor lying on a source-to-target
    /// path and seed that resolved relation into the scoped workspace.
    ///
    /// Both reverse and forward reachability are finite uncapped worklists
    /// over persisted resolver edges. `None` means no validated partitioned
    /// graph is available; callers must use their canonical full-workspace
    /// fallback rather than treating cache absence as "no path."
    #[must_use]
    pub fn source_target_query_workspace(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> Option<Workspace> {
        if self.is_complete_workspace_index() || source_funcs.is_empty() || target_funcs.is_empty() {
            return None;
        }
        let graph = match self.persisted_resolved_call_graph_between_with_max_precision(
            source_funcs,
            target_funcs,
            max_precision,
        )? {
            Ok(graph) => graph,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "source-target workspace callgraph partitions rejected: {}",
                    error
                );
                return None;
            }
        };
        self.reopen_query_workspace_for_graph(graph, "source-target workspace")
    }

    /// Reopen the exact compiler neighborhood needed to inspect callable
    /// targets: every semantic caller chain plus each target's direct
    /// semantic callees.
    ///
    /// The persisted callgraph traversal is uncapped and partition-backed.
    /// A missing or stale sidecar returns `None`; callers must then use the
    /// canonical complete-workspace fallback instead of treating cache
    /// absence as an empty graph.
    #[must_use]
    pub fn target_inspect_query_workspace(
        &self,
        target_funcs: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> Option<Workspace> {
        if target_funcs.is_empty() {
            return None;
        }
        let service = self.callgraph_query_service()?;
        let graph = match service.materialize_reaching_with_direct_callees(target_funcs, max_precision) {
            Ok(graph) => graph,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "target inspect callgraph partitions rejected: {}",
                    error
                );
                return None;
            }
        };
        self.reopen_query_workspace_for_graph(graph, "target inspect workspace")
    }

    /// Exact compiler function neighborhood for target-oriented inspection.
    ///
    /// The persisted call-linkage partitions contain every semantic caller
    /// chain reaching the targets plus their direct semantic callees. This is
    /// a query scope, not a work limit: failure to open a fresh partition
    /// returns `None` so callers can fall back to the complete workspace.
    #[must_use]
    pub fn target_inspect_lineage_funcs(
        &self,
        target_funcs: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> Option<AHashSet<FuncId>> {
        if target_funcs.is_empty() {
            return None;
        }
        let service = self.callgraph_query_service()?;
        let graph = match service.materialize_reaching_with_direct_callees(target_funcs, max_precision) {
            Ok(graph) => graph,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "target inspect function scope rejected: {}",
                    error
                );
                return None;
            }
        };
        let mut funcs: AHashSet<FuncId> = graph.nodes().iter().map(|node| node.func).collect();
        for edge in &graph.inner().edges {
            funcs.insert(edge.from);
            funcs.insert(edge.to);
        }
        funcs.extend(target_funcs.iter().copied());
        Some(funcs)
    }

    fn persisted_source_flow_corridor(
        &self,
        source_funcs: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> Option<crate::SourceReachableCallGraph> {
        let started = std::time::Instant::now();
        let graph = match self.persisted_resolved_call_graph_reachable_from(source_funcs, max_precision)? {
            Ok(graph) => Arc::new(graph),
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-cache",
                    "source-flow callgraph partitions rejected: {}",
                    error
                );
                return None;
            }
        };
        bonsai_diagnostics::debug_log!(
            "compiler-cache",
            "source-flow reachable graph: funcs={} edges={} elapsed={:.3}s",
            graph.nodes().len(),
            graph.inner().edges.len(),
            started.elapsed().as_secs_f64()
        );
        let mut funcs = graph.nodes().iter().map(|node| node.func).collect::<Vec<_>>();
        funcs.sort_unstable_by_key(|func| func.raw());
        funcs.dedup();
        if funcs.is_empty() {
            return None;
        }
        let mut files = graph.nodes().iter().map(|node| node.file).collect::<Vec<_>>();
        files.sort_unstable_by_key(|file| file.raw());
        files.dedup();

        // Header partitions preserve workspace-global SymbolIds without
        // hydrating unrelated declarations. Project compact call/return
        // linkage from the same exact Tree-sitter bodies the scoped IDG will
        // consume; this retains callback, receiver, out-param, and return
        // semantics without opening the workspace-wide linkage payload.
        let headers = self.compiler_header_index_for_files(&files);
        bonsai_diagnostics::debug_log!(
            "compiler-cache",
            "source-flow header partitions: files={} decls={} elapsed={:.3}s",
            files.len(),
            headers.len(),
            started.elapsed().as_secs_f64()
        );
        let mut projected_linkage = Vec::new();
        for file in &files {
            if let Some(index) = self.db().decl_index_remapped_to_headers(headers.as_ref(), *file) {
                projected_linkage.extend(headers.project_linkage_from_remapped_file(&index));
            }
        }
        bonsai_diagnostics::debug_log!(
            "compiler-cache",
            "source-flow exact bodies projected: files={} linkage={} elapsed={:.3}s",
            files.len(),
            projected_linkage.len(),
            started.elapsed().as_secs_f64()
        );
        let mut headers = Arc::try_unwrap(headers).unwrap_or_else(|headers| headers.as_ref().clone());
        headers.install_projected_linkage(projected_linkage);
        let headers = Arc::new(headers);
        if !self.is_complete_workspace_index() {
            *self.inner.compiler_headers.write() = Some(Arc::clone(&headers));
        }

        Some(crate::SourceReachableCallGraph {
            graph,
            linkage_index: headers,
            files,
            funcs,
            reached_targets: 0,
        })
    }

    fn compile_syntax_flow_session(
        &self,
        corridor: crate::SourceReachableCallGraph,
    ) -> Option<SyntaxFlowSession> {
        if corridor.funcs.is_empty() {
            return None;
        }
        let transfer_options = crate::default_workspace_idg_transfer_options(self.db());
        let lease = match tempfile::Builder::new().prefix("bonsai-syntax-flow-").tempdir() {
            Ok(lease) => Arc::new(lease),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "query-scoped IDG temp directory unavailable; using canonical resident fallback"
                );
                return None;
            }
        };
        let sidecar = lease.path().join("idg.factstore");
        let transfer_hash = crate::idg_transfer_options_fingerprint(&transfer_options);
        let file_scope_hash = crate::idg_file_scope_fingerprint(&corridor.files);
        let func_scope_hash = crate::idg_func_scope_fingerprint(&corridor.funcs);
        let call_graph_hash = crate::idg_call_graph_fingerprint(corridor.graph.as_ref());
        let pipeline_hash = crate::idg_scoped_semantics_fingerprint(
            transfer_hash,
            file_scope_hash,
            Some(func_scope_hash),
            Some(call_graph_hash),
        );
        let global = corridor.linkage_index.clone();
        let semantics = bonsai_taint::compiler_idg_file_semantics(self.db());
        let persisted = bonsai_idg::workspace_adapter::
            build_for_persistence_streaming_with_file_semantics_and_options_for_files_and_funcs(
                global.as_ref(),
                corridor.graph.as_ref(),
                semantics,
                &transfer_options,
                &corridor.files,
                &corridor.funcs,
                &sidecar,
                |file| {
                    self.db()
                        .decl_index_remapped_to_headers(global.as_ref(), file)
                },
            )
            .and_then(|workspace| workspace.save_into_disk(&sidecar, pipeline_hash))
            .and_then(|()| {
                bonsai_idg::IdgQueryService::load_from_disk(
                    &sidecar,
                    pipeline_hash,
                    global,
                )
            });
        match persisted {
            Ok(Some(idg)) => Some(SyntaxFlowSession {
                idg: Arc::new(idg),
                _lease: lease,
            }),
            Ok(None) => {
                tracing::warn!(
                    path = %sidecar.display(),
                    "query-scoped IDG did not reopen; using canonical resident fallback"
                );
                None
            }
            Err(error) => {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %error,
                    "query-scoped IDG persistence failed; using canonical resident fallback"
                );
                None
            }
        }
    }

    /// Compile the complete source-reachable semantic region for an exact
    /// source-seeded flow query.
    ///
    /// Reachability is the compiler call-relation least fixed point. There is
    /// no depth, file-count, edge-count, or time budget that can remove facts.
    /// The resulting IDG is query-local and cannot contaminate whole-workspace
    /// security or export state.
    #[must_use]
    pub fn source_flow_session(
        &self,
        source_funcs: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> Option<SyntaxFlowSession> {
        if self.db().idg_service().is_some() || source_funcs.is_empty() {
            return None;
        }
        let corridor = self
            .persisted_source_flow_corridor(source_funcs, max_precision)
            .unwrap_or_else(|| self.source_reachable_query_call_graph(source_funcs, &[], max_precision));
        self.compile_syntax_flow_session(corridor)
    }

    /// Compile one exact semantic session for a targeted syntax-flow source
    /// batch.
    ///
    /// Resolver reachability is a finite least fixed point over compiler
    /// symbols. The corridor is narrowed only by the request's source and
    /// target functions; no depth, file-count, or work budget changes which
    /// syntax facts are admitted.
    #[must_use]
    pub fn syntax_flow_session(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &AHashSet<FuncId>,
    ) -> Option<SyntaxFlowSession> {
        if self.db().idg_service().is_some() || source_funcs.is_empty() || target_funcs.is_empty() {
            return None;
        }
        let mut targets: Vec<FuncId> = target_funcs.iter().copied().collect();
        targets.sort_unstable_by_key(|func| func.raw());
        let corridor = if source_funcs.iter().all(|func| target_funcs.contains(func)) {
            self.target_emission_resolved_call_graph(source_funcs, &targets, None)
        } else {
            self.source_reachable_resolved_call_graph(source_funcs, &targets, None)
        };
        self.compile_syntax_flow_session(corridor)
    }

    /// Compile one reusable backward demand relation for a warmed-IDG entry
    /// batch. This is an exact compiler optimization: the proof may retain
    /// extra states, but it can never discard a realizable path to a target.
    #[must_use]
    pub fn syntax_flow_target_relevance(
        &self,
        target_nodes: &[bonsai_idg::WsNodeId],
        target_funcs: &AHashSet<FuncId>,
        lineage_funcs: Option<&AHashSet<FuncId>>,
    ) -> Option<bonsai_idg::IdgTargetRelevance> {
        self.syntax_flow_target_relevance_with_session(target_nodes, target_funcs, lineage_funcs, None)
    }

    /// Session-aware form of [`Self::syntax_flow_target_relevance`]. A cold
    /// inspect batch must derive its target demand from the same exact scoped
    /// compiler graph it will query, rather than falling back to function-only
    /// matching merely because no global IDG is installed.
    #[must_use]
    pub fn syntax_flow_target_relevance_with_session(
        &self,
        target_nodes: &[bonsai_idg::WsNodeId],
        target_funcs: &AHashSet<FuncId>,
        lineage_funcs: Option<&AHashSet<FuncId>>,
        session: Option<&SyntaxFlowSession>,
    ) -> Option<bonsai_idg::IdgTargetRelevance> {
        if target_nodes.is_empty() && target_funcs.is_empty() {
            return None;
        }
        let global_idg = self.db().idg_service();
        let idg = global_idg
            .as_deref()
            .or_else(|| session.map(SyntaxFlowSession::idg))?;
        let max_precision = Some(bonsai_common::Precision::Narrowed);
        Some(
            if let Some(lineage_funcs) = lineage_funcs.filter(|funcs| !funcs.is_empty()) {
                idg.target_relevance_within_funcs_with_max_precision(
                    target_nodes,
                    Some(target_funcs),
                    lineage_funcs,
                    max_precision,
                )
            } else {
                idg.target_relevance_with_max_precision(target_nodes, Some(target_funcs), max_precision)
            },
        )
    }

    /// Source-rooted target demand for one syntax owner. This preserves exact
    /// compiler call/return direction, so a broad batch does not let one
    /// owner's target pull unrelated callers into another owner's closure.
    #[must_use]
    pub fn syntax_flow_source_target_relevance_with_session(
        &self,
        source: FuncId,
        target_nodes: &[bonsai_idg::WsNodeId],
        target_funcs: &AHashSet<FuncId>,
        lineage_funcs: &AHashSet<FuncId>,
        session: Option<&SyntaxFlowSession>,
    ) -> Option<bonsai_idg::IdgTargetRelevance> {
        if target_nodes.is_empty() && target_funcs.is_empty() || lineage_funcs.is_empty() {
            return None;
        }
        let global_idg = self.db().idg_service();
        let idg = global_idg
            .as_deref()
            .or_else(|| session.map(SyntaxFlowSession::idg))?;
        Some(idg.target_relevance_from_source_within_funcs_with_max_precision(
            source,
            target_nodes,
            Some(target_funcs),
            lineage_funcs,
            Some(bonsai_common::Precision::Narrowed),
        ))
    }

    /// Filter a multi-entry syntax-flow batch through one already-computed
    /// backward target-demand relation using only compact IDG headers.
    #[must_use]
    pub fn syntax_flow_relevant_sources(
        &self,
        source_funcs: &[FuncId],
        relevance: &bonsai_idg::IdgTargetRelevance,
    ) -> Option<Vec<FuncId>> {
        self.syntax_flow_relevant_sources_with_session(source_funcs, relevance, None)
    }

    /// Session-aware form of [`Self::syntax_flow_relevant_sources`].
    #[must_use]
    pub fn syntax_flow_relevant_sources_with_session(
        &self,
        source_funcs: &[FuncId],
        relevance: &bonsai_idg::IdgTargetRelevance,
        session: Option<&SyntaxFlowSession>,
    ) -> Option<Vec<FuncId>> {
        let global_idg = self.db().idg_service();
        let idg = global_idg
            .as_deref()
            .or_else(|| session.map(SyntaxFlowSession::idg))?;
        Some(idg.funcs_admitted_by_target_relevance(source_funcs, relevance))
    }

    /// Resolve syntax spans to exact IDG endpoints. Spans without an IDG
    /// carrier remain explicit function fallbacks, so attribution gaps may
    /// reduce pruning but can never make the query incomplete.
    #[must_use]
    pub fn syntax_flow_target_nodes(
        &self,
        targets: &[(FuncId, bonsai_common::Span)],
    ) -> Option<(Vec<bonsai_idg::WsNodeId>, AHashSet<FuncId>)> {
        self.syntax_flow_target_nodes_with_session(targets, None)
    }

    /// Session-aware form of [`Self::syntax_flow_target_nodes`].
    #[must_use]
    pub fn syntax_flow_target_nodes_with_session(
        &self,
        targets: &[(FuncId, bonsai_common::Span)],
        session: Option<&SyntaxFlowSession>,
    ) -> Option<(Vec<bonsai_idg::WsNodeId>, AHashSet<FuncId>)> {
        let global_idg = self.db().idg_service();
        let idg = global_idg
            .as_deref()
            .or_else(|| session.map(SyntaxFlowSession::idg))?;
        Some(idg.nodes_and_unresolved_funcs_at_spans(targets))
    }

    /// Session-aware exact target attribution grouped by syntax owner.
    #[must_use]
    pub fn syntax_flow_target_nodes_by_source_with_session(
        &self,
        targets: &[(FuncId, bonsai_common::Span)],
        session: Option<&SyntaxFlowSession>,
    ) -> Option<SyntaxFlowTargetsBySource> {
        let global_idg = self.db().idg_service();
        let idg = global_idg
            .as_deref()
            .or_else(|| session.map(SyntaxFlowSession::idg))?;
        Some(idg.nodes_by_func_and_unresolved_at_spans(targets))
    }

    /// Return the canonical syntax-shaped taint graph for `query`.
    ///
    /// This never builds the IDG. If a caller has already warmed the
    /// workspace IDG, the query can use the target-cut IDG backend;
    /// otherwise it falls back to the canonical dataflow cache, which
    /// computes and persists the same semantic graph on demand.
    #[must_use]
    pub fn syntax_flow_graph(&self, query: SyntaxFlowQuery<'_>) -> SyntaxFlowGraph {
        let idg_available = self.db().idg_service().is_some();
        let target_cut_size = match (query.target_nodes, query.target_funcs) {
            (Some(nodes), Some(funcs)) => Some(nodes.len().saturating_add(funcs.len())),
            (Some(nodes), None) => Some(nodes.len()),
            (None, Some(funcs)) => Some(funcs.len()),
            (None, None) => None,
        };
        if query.prefer_warmed_idg {
            if let Some(idg) = self.db().idg_service() {
                let graph =
                    bonsai_taint::inspect_entry_taint_graph_from_idg_with_target_funcs_and_lineage_with_caches(
                        query.entry,
                        bonsai_taint::IdgTaintTargets {
                            nodes: query.target_nodes,
                            funcs: query.target_funcs,
                            lineage_funcs: query.lineage_funcs,
                            relevance: query.target_relevance,
                        },
                        self.db(),
                        idg.as_ref(),
                        Some(self.inter_taint_caches()),
                    );
                return SyntaxFlowGraph {
                    graph: Arc::new(graph),
                    backend: SyntaxFlowBackend::WarmedIdgTargetCut,
                    plan: SyntaxFlowPlan {
                        entry: query.entry,
                        backend: SyntaxFlowBackend::WarmedIdgTargetCut,
                        cache_status: SyntaxFlowCacheStatus::Hit,
                        prefer_warmed_idg: query.prefer_warmed_idg,
                        idg_available,
                        target_cut_size,
                        fallback_reasons: Vec::new(),
                        analysis_incomplete_reasons: Vec::new(),
                    },
                };
            }
        }

        let dataflow_hit = self.dataflow().has_entry(query.entry);
        if let Some(session) = query.session {
            let graph =
                bonsai_taint::inspect_entry_taint_graph_from_idg_with_target_funcs_and_lineage_with_caches(
                    query.entry,
                    bonsai_taint::IdgTaintTargets {
                        nodes: query.target_nodes,
                        funcs: query.target_funcs,
                        lineage_funcs: query.lineage_funcs,
                        relevance: query.target_relevance,
                    },
                    self.db(),
                    session.idg.as_ref(),
                    Some(self.inter_taint_caches()),
                );
            return SyntaxFlowGraph {
                graph: Arc::new(graph),
                backend: SyntaxFlowBackend::ScopedIdgTargetCut,
                plan: SyntaxFlowPlan {
                    entry: query.entry,
                    backend: SyntaxFlowBackend::ScopedIdgTargetCut,
                    cache_status: SyntaxFlowCacheStatus::Hit,
                    prefer_warmed_idg: query.prefer_warmed_idg,
                    idg_available,
                    target_cut_size,
                    fallback_reasons: if query.prefer_warmed_idg && !idg_available {
                        vec!["warmed IDG unavailable; used exact query-scoped IDG target cut".to_string()]
                    } else {
                        Vec::new()
                    },
                    analysis_incomplete_reasons: Vec::new(),
                },
            };
        }
        let mut fallback_reasons = Vec::new();
        if query.prefer_warmed_idg && !idg_available {
            fallback_reasons.push("warmed IDG unavailable; used cached dataflow backend".to_string());
        }
        SyntaxFlowGraph {
            graph: self.dataflow().graph_for(query.entry, self.db()),
            backend: SyntaxFlowBackend::CachedDataflow,
            plan: SyntaxFlowPlan {
                entry: query.entry,
                backend: SyntaxFlowBackend::CachedDataflow,
                cache_status: if dataflow_hit {
                    SyntaxFlowCacheStatus::Hit
                } else {
                    SyntaxFlowCacheStatus::MissComputed
                },
                prefer_warmed_idg: query.prefer_warmed_idg,
                idg_available,
                target_cut_size,
                fallback_reasons,
                analysis_incomplete_reasons: Vec::new(),
            },
        }
    }
}
