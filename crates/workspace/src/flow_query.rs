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
use bonsai_taint::EntryTaintGraph;
use std::sync::Arc;

/// Backend used to answer a syntax-flow query.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SyntaxFlowBackend {
    /// Answered by the warmed workspace IDG with an optional target cut.
    WarmedIdgTargetCut,
    /// Answered by the persisted/on-demand canonical dataflow cache.
    CachedDataflow,
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

/// Result of a syntax-flow query.
#[derive(Clone, Debug)]
pub struct SyntaxFlowGraph {
    pub graph: Arc<EntryTaintGraph>,
    pub backend: SyntaxFlowBackend,
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
                };
            }
        }

        SyntaxFlowGraph {
            graph: self.dataflow().graph_for(query.entry, self.db()),
            backend: SyntaxFlowBackend::CachedDataflow,
        }
    }
}
