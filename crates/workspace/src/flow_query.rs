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
    /// Answered by the persisted/on-demand canonical dataflow cache.
    CachedDataflow,
}

impl SyntaxFlowBackend {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WarmedIdgTargetCut => "warmed-idg-target-cut",
            Self::CachedDataflow => "cached-dataflow",
        }
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
}

impl<'a> SyntaxFlowQuery<'a> {
    #[must_use]
    pub const fn new(entry: FuncId) -> Self {
        Self {
            entry,
            target_funcs: None,
            prefer_warmed_idg: false,
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
