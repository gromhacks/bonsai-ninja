//! Typed query descriptors for the canonical IDG-backed taint engine.
//!
//! These types describe compiler queries without performing traversal or
//! allocating graph state. Execution remains in `reachable`, while callers
//! select source semantics, declarative transfers, target scope, precision,
//! and cache reuse through named fields instead of positional API ladders.

use crate::reachable::TokenSet;
use ahash::AHashSet;
use bonsai_common::{FuncId, Precision};
use bonsai_db::AnalyzerDb;

/// Describes how a taint query obtains its initial IDG nodes.
///
/// `RuleMatch` composes nodes from the source rule's AST span and declared
/// output carriers. `Precomposed` uses exactly the nodes supplied by a caller
/// that has already applied another public seeding policy. Keeping these modes
/// distinct prevents an empty precomposed set from silently falling back to a
/// broader name-based rule match.
#[derive(Clone, Copy)]
pub enum IdgTaintSeed<'a> {
    RuleMatch {
        source_anchor: Option<bonsai_common::Span>,
        output_arg_names: &'a [String],
    },
    Precomposed(&'a [bonsai_idg::WsNodeId]),
}

#[derive(Clone, Copy)]
pub struct IdgTaintSource<'a> {
    pub func: FuncId,
    pub tokens: &'a TokenSet,
    pub seed: IdgTaintSeed<'a>,
}

impl<'a> IdgTaintSource<'a> {
    #[must_use]
    pub const fn rule_match(
        func: FuncId,
        tokens: &'a TokenSet,
        source_anchor: Option<bonsai_common::Span>,
        output_arg_names: &'a [String],
    ) -> Self {
        Self {
            func,
            tokens,
            seed: IdgTaintSeed::RuleMatch {
                source_anchor,
                output_arg_names,
            },
        }
    }

    #[must_use]
    pub const fn precomposed(func: FuncId, tokens: &'a TokenSet, nodes: &'a [bonsai_idg::WsNodeId]) -> Self {
        Self {
            func,
            tokens,
            seed: IdgTaintSeed::Precomposed(nodes),
        }
    }
}

#[derive(Clone, Copy)]
pub struct IdgTaintTransfers<'a> {
    pub receiver_state: &'a [crate::inter::ReceiverStatePropagation],
    pub call_result_passthroughs: &'a [crate::inter::CallResultPassthrough],
    pub output_args: &'a [crate::inter::OutputArgFlow],
    pub call_results_materialized: bool,
}

impl IdgTaintTransfers<'_> {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            receiver_state: &[],
            call_result_passthroughs: &[],
            output_args: &[],
            call_results_materialized: false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct IdgTaintTargets<'a> {
    pub nodes: Option<&'a [bonsai_idg::WsNodeId]>,
    pub funcs: Option<&'a AHashSet<FuncId>>,
    pub lineage_funcs: Option<&'a AHashSet<FuncId>>,
}

impl IdgTaintTargets<'_> {
    #[must_use]
    pub const fn all_reachable() -> Self {
        Self {
            nodes: None,
            funcs: None,
            lineage_funcs: None,
        }
    }
}

/// Complete typed request for one IDG-backed taint closure.
///
/// The request is a borrowed compiler-query descriptor: constructing it does
/// not allocate, traverse, or cap the graph.
#[derive(Clone, Copy)]
pub struct IdgTaintQuery<'a> {
    pub source: IdgTaintSource<'a>,
    pub transfers: IdgTaintTransfers<'a>,
    pub targets: IdgTaintTargets<'a>,
    pub max_precision: Option<Precision>,
    pub db: &'a AnalyzerDb,
    pub idg: &'a bonsai_idg::IdgQueryService,
    pub caches: Option<&'a crate::inter::InterTaintCaches>,
}

impl<'a> IdgTaintQuery<'a> {
    #[must_use]
    pub const fn semantic(
        source: IdgTaintSource<'a>,
        db: &'a AnalyzerDb,
        idg: &'a bonsai_idg::IdgQueryService,
    ) -> Self {
        Self {
            source,
            transfers: IdgTaintTransfers::none(),
            targets: IdgTaintTargets::all_reachable(),
            max_precision: Some(Precision::Narrowed),
            db,
            idg,
            caches: None,
        }
    }

    #[must_use]
    pub const fn with_transfers(mut self, transfers: IdgTaintTransfers<'a>) -> Self {
        self.transfers = transfers;
        self
    }

    #[must_use]
    pub const fn with_targets(mut self, targets: IdgTaintTargets<'a>) -> Self {
        self.targets = targets;
        self
    }

    #[must_use]
    pub const fn with_max_precision(mut self, max_precision: Option<Precision>) -> Self {
        self.max_precision = max_precision;
        self
    }

    #[must_use]
    pub const fn with_caches(mut self, caches: &'a crate::inter::InterTaintCaches) -> Self {
        self.caches = Some(caches);
        self
    }
}

#[derive(Clone, Copy)]
pub struct IdgReturnQuery<'a> {
    pub source: IdgTaintSource<'a>,
    pub receiver_state: &'a [crate::inter::ReceiverStatePropagation],
    pub max_precision: Option<Precision>,
    pub db: &'a AnalyzerDb,
    pub idg: &'a bonsai_idg::IdgQueryService,
}

impl<'a> IdgReturnQuery<'a> {
    #[must_use]
    pub const fn semantic(
        source: IdgTaintSource<'a>,
        receiver_state: &'a [crate::inter::ReceiverStatePropagation],
        db: &'a AnalyzerDb,
        idg: &'a bonsai_idg::IdgQueryService,
    ) -> Self {
        Self {
            source,
            receiver_state,
            max_precision: Some(Precision::Narrowed),
            db,
            idg,
        }
    }

    #[must_use]
    pub const fn with_max_precision(mut self, max_precision: Option<Precision>) -> Self {
        self.max_precision = max_precision;
        self
    }
}
