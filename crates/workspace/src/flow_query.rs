//! Canonical workspace entry point for syntax-shaped taint graphs.
//!
//! Commands should ask this module for an entry graph instead of
//! open-coding "try IDG, else dataflow" decisions. The IDG target cut
//! and cached dataflow graph are backend choices for the same semantic
//! query: adapter-lowered `FlowEvent`s, resolver-backed call edges, and
//! the taint crate's canonical propagation rules.

use crate::Workspace;
use ahash::AHashSet;
use bonsai_common::FuncId;
use std::sync::Arc;

pub use bonsai_taint::{EntryTaintGraph, TaintedCall, TaintedCallEdge, TaintedCallKind};

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
    pub target_funcs: Option<&'a AHashSet<FuncId>>,
    pub prefer_warmed_idg: bool,
    pub session: Option<&'a SyntaxFlowSession>,
}

impl<'a> SyntaxFlowQuery<'a> {
    #[must_use]
    pub const fn new(entry: FuncId) -> Self {
        Self {
            entry,
            target_funcs: None,
            prefer_warmed_idg: false,
            session: None,
        }
    }

    #[must_use]
    pub const fn target_funcs(mut self, target_funcs: Option<&'a AHashSet<FuncId>>) -> Self {
        self.target_funcs = target_funcs;
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

    /// Return the canonical syntax-shaped taint graph for `query`.
    ///
    /// This never builds the IDG. If a caller has already warmed the
    /// workspace IDG, the query can use the target-cut IDG backend;
    /// otherwise it falls back to the canonical dataflow cache, which
    /// computes and persists the same semantic graph on demand.
    #[must_use]
    pub fn syntax_flow_graph(&self, query: SyntaxFlowQuery<'_>) -> SyntaxFlowGraph {
        let idg_available = self.db().idg_service().is_some();
        let target_cut_size = query.target_funcs.map(|targets| targets.len());
        if query.prefer_warmed_idg {
            if let Some(idg) = self.db().idg_service() {
                let graph = bonsai_taint::inspect_entry_taint_graph_from_idg_with_target_funcs(
                    query.entry,
                    query.target_funcs,
                    self.db(),
                    idg.as_ref(),
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
            let graph = bonsai_taint::inspect_entry_taint_graph_from_idg_with_target_funcs(
                query.entry,
                query.target_funcs,
                self.db(),
                session.idg.as_ref(),
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
