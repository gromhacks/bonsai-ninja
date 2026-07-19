//! IDG edges: directed dataflow relationships between nodes.
//!
//! The IDG is conceptually a directed graph `Node → Node`. An edge
//! represents "the value at `from` flows to the position `to`."
//! Every edge carries:
//!
//! - precision (Exact / Narrowed / OverApprox / Unknown), inherited
//!   from the resolver that built it.
//! - kind (intra-procedural assign, call-arg, return, throw/catch),
//!   so renderers and queries can filter by edge type.
//! - the originating source span (for path rendering).

use bonsai_callgraph::EdgeKind as CallEdgeKind;
use bonsai_common::{Precision, Span};
use bonsai_lang_api::FlowEdgeKind;
use serde::{Deserialize, Serialize};

use crate::node::NodeId;

/// What program-level relationship this edge represents.
///
/// The `IntraAssign` / `IntraRead` / `IntraReturn` family are
/// produced by the per-function transfer-function pass (Phase 2).
/// The `Call*` / `Return*` family come from inter-procedural
/// stitching (Phase 3) — each is paired with a [`CallEdgeKind`]
/// (Direct / Virtual / Indirect / Unknown) imprinted into
/// [`EdgeMeta`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IdgEdgeKind {
    /// A `target = source` style assignment within one function.
    IntraAssign = 0,
    /// A reference to a name within the function body, distinct
    /// from an assignment. Used to surface read-only flows.
    IntraRead = 1,
    /// A `return value` event in the function body, flowing into the
    /// function's `Place::Return`.
    IntraReturn = 2,
    /// A throw event flowing into the function's `Place::Throw(ty)`.
    IntraThrow = 3,
    /// `caller.CallArg(site, i)` → `callee.Param(i)`. The actual
    /// call-edge precision (Direct / Virtual / etc.) lives on
    /// [`EdgeMeta::call_kind`].
    InterCallArg = 4,
    /// `callee.Return` → `caller.CallRet(site)`.
    InterReturn = 5,
    /// `callee.Throw(ty)` → `caller.Catch(ty)` for a matching
    /// surrounding `try` in the caller.
    InterThrow = 6,
    /// `target = obj.field` style read where the source is a field
    /// projection of the caller-side argument. Distinguished so
    /// renderers can show "field-of-X" lineage.
    IntraFieldRead = 7,
    /// `obj.field = source` field write, paired with a
    /// `Place::Write` carrying the field path.
    IntraFieldWrite = 8,
    /// `yield value` → `Place::Yield`. Coroutine flows.
    IntraYield = 9,
    /// `await x` → consumer's place; coroutine flows.
    IntraAwait = 10,
    /// A projected caller field → projected callee parameter field.
    ///
    /// This is heap/object-state propagation associated with a call, not a
    /// scalar `CallArg → Param` boundary. Keeping the provenance explicit
    /// prevents renderers from treating a canonical field node's owning
    /// method as the resolved callee.
    InterFieldCallArg = 11,
    /// A projected callee field → projected caller field.
    ///
    /// Covers constructor results, receiver mutation, and projected return
    /// state. It participates in interprocedural reachability but is not a
    /// scalar `Return → CallRet` boundary.
    InterFieldReturn = 12,
    /// A concrete descendant field is consumed by a call argument that
    /// evaluates the whole aggregate. This is non-traversable call-site
    /// evidence: unresolved/external consumers report it directly, while
    /// resolved local calls propagate exact fields through
    /// [`Self::InterFieldCallArg`].
    IntraAggregateConsume = 13,
}

impl IdgEdgeKind {
    /// Taxonomy classes that this coarse IDG edge kind can carry.
    ///
    /// IDG edge kinds are intentionally compact for storage. Several
    /// language-neutral taxonomy entries share one edge kind; the exact
    /// source construct is still available from the originating FlowEvent,
    /// Operation, place shape, callgraph edge, or rulepack fact.
    #[must_use]
    pub const fn taxonomy(self) -> &'static [FlowEdgeKind] {
        match self {
            Self::IntraAssign => &[
                FlowEdgeKind::LocalAssign,
                FlowEdgeKind::ExprPropagation,
                FlowEdgeKind::DefUse,
                FlowEdgeKind::Alias,
                FlowEdgeKind::ObjectConstruction,
                FlowEdgeKind::Destructuring,
                FlowEdgeKind::GlobalAccess,
                FlowEdgeKind::HeapStore,
                FlowEdgeKind::ContainerStore,
                FlowEdgeKind::Serialize,
                FlowEdgeKind::Deserialize,
            ],
            Self::IntraRead => &[
                FlowEdgeKind::DefUse,
                FlowEdgeKind::ExprPropagation,
                FlowEdgeKind::FieldRead,
                FlowEdgeKind::IndexRead,
                FlowEdgeKind::Dereference,
                FlowEdgeKind::HeapLoad,
                FlowEdgeKind::ContainerLoad,
                FlowEdgeKind::DynamicPropertyAccess,
                FlowEdgeKind::Sink,
            ],
            Self::IntraReturn => &[
                FlowEdgeKind::ExprPropagation,
                FlowEdgeKind::ReturnToCaller,
                FlowEdgeKind::Serialize,
                FlowEdgeKind::Deserialize,
            ],
            Self::IntraThrow => &[FlowEdgeKind::ThrowToCatch],
            Self::InterCallArg => &[
                FlowEdgeKind::ArgToParam,
                FlowEdgeKind::ReceiverToThis,
                FlowEdgeKind::CallbackInvocation,
                FlowEdgeKind::EventDispatch,
                FlowEdgeKind::InterFile,
                FlowEdgeKind::InterPackage,
            ],
            Self::InterReturn => &[
                FlowEdgeKind::ReturnToCaller,
                FlowEdgeKind::AwaitResolution,
                FlowEdgeKind::InterFile,
                FlowEdgeKind::InterPackage,
            ],
            Self::InterThrow => &[
                FlowEdgeKind::ThrowToCatch,
                FlowEdgeKind::InterFile,
                FlowEdgeKind::InterPackage,
            ],
            Self::IntraFieldRead => &[
                FlowEdgeKind::FieldRead,
                FlowEdgeKind::IndexRead,
                FlowEdgeKind::HeapLoad,
                FlowEdgeKind::ContainerLoad,
                FlowEdgeKind::DynamicPropertyAccess,
            ],
            Self::IntraFieldWrite => &[
                FlowEdgeKind::FieldWrite,
                FlowEdgeKind::IndexWrite,
                FlowEdgeKind::HeapStore,
                FlowEdgeKind::ContainerStore,
                FlowEdgeKind::DynamicPropertyAccess,
            ],
            Self::IntraYield => &[
                FlowEdgeKind::Yield,
                FlowEdgeKind::Iteration,
                FlowEdgeKind::CallbackInvocation,
            ],
            Self::IntraAwait => &[FlowEdgeKind::AwaitResolution],
            Self::InterFieldCallArg => &[
                FlowEdgeKind::ArgToParam,
                FlowEdgeKind::HeapLoad,
                FlowEdgeKind::HeapStore,
                FlowEdgeKind::ContainerLoad,
                FlowEdgeKind::ContainerStore,
                FlowEdgeKind::InterFile,
                FlowEdgeKind::InterPackage,
            ],
            Self::InterFieldReturn => &[
                FlowEdgeKind::ReturnToCaller,
                FlowEdgeKind::HeapLoad,
                FlowEdgeKind::HeapStore,
                FlowEdgeKind::ContainerLoad,
                FlowEdgeKind::ContainerStore,
                FlowEdgeKind::InterFile,
                FlowEdgeKind::InterPackage,
            ],
            Self::IntraAggregateConsume => &[
                FlowEdgeKind::ExprPropagation,
                FlowEdgeKind::HeapLoad,
                FlowEdgeKind::ContainerLoad,
                FlowEdgeKind::Sink,
            ],
        }
    }

    /// True iff this kind is an inter-procedural edge built during
    /// Phase 3 stitching. Lets queries filter intra-only flows.
    #[must_use]
    pub const fn is_inter(self) -> bool {
        matches!(
            self,
            Self::InterCallArg
                | Self::InterReturn
                | Self::InterThrow
                | Self::InterFieldCallArg
                | Self::InterFieldReturn
        )
    }

    /// True iff this kind is intra-procedural (one function only).
    #[must_use]
    pub const fn is_intra(self) -> bool {
        !self.is_inter()
    }

    /// Numeric tag used in the on-disk encoding. Stable across
    /// format versions; new variants append.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Reverse of [`Self::tag`]. Returns `None` for unknown tags so
    /// readers can fail-closed on a corrupt encoding rather than
    /// silently misinterpret.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::IntraAssign),
            1 => Some(Self::IntraRead),
            2 => Some(Self::IntraReturn),
            3 => Some(Self::IntraThrow),
            4 => Some(Self::InterCallArg),
            5 => Some(Self::InterReturn),
            6 => Some(Self::InterThrow),
            7 => Some(Self::IntraFieldRead),
            8 => Some(Self::IntraFieldWrite),
            9 => Some(Self::IntraYield),
            10 => Some(Self::IntraAwait),
            11 => Some(Self::InterFieldCallArg),
            12 => Some(Self::InterFieldReturn),
            13 => Some(Self::IntraAggregateConsume),
            _ => None,
        }
    }
}

/// Per-edge metadata. Held adjacent to the `(from, to)` node pair
/// in the on-disk encoding.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeMeta {
    /// Precision floor for this edge. Conservatively computed at
    /// build time — every consumer reads it as-is.
    pub precision: Precision,
    /// Kind of program-level relationship.
    pub kind: IdgEdgeKind,
    /// Sub-classifier for inter-procedural edges. For intra edges
    /// this is [`CallEdgeKind::Direct`] as a sentinel (callers ignore
    /// it on `is_intra` edges).
    pub call_kind: CallEdgeKind,
    /// Source span the edge anchors at. For intra edges this is the
    /// statement / event span; for inter edges it's the call site.
    pub via_span: Span,
}

/// One directed edge in the IDG. `from` and `to` are dictionary
/// indices; `meta` is the per-edge metadata bundle.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdgEdge {
    /// Source node.
    pub from: NodeId,
    /// Destination node.
    pub to: NodeId,
    /// Edge metadata (precision, kind, call sub-kind, source span).
    pub meta: EdgeMeta,
}

impl IdgEdge {
    /// Construct an edge with explicit metadata.
    #[must_use]
    pub const fn new(from: NodeId, to: NodeId, meta: EdgeMeta) -> Self {
        Self { from, to, meta }
    }

    /// Construct an intra-procedural assignment edge with `Exact`
    /// precision.
    #[must_use]
    pub const fn intra_assign(from: NodeId, to: NodeId, span: Span) -> Self {
        Self {
            from,
            to,
            meta: EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraAssign,
                call_kind: CallEdgeKind::Direct,
                via_span: span,
            },
        }
    }

    /// Construct an inter-procedural call-arg edge with the given
    /// precision (typically inherited from the resolver) and call
    /// sub-kind (Direct / Virtual / Indirect / Unknown).
    #[must_use]
    pub const fn inter_call_arg(
        from: NodeId,
        to: NodeId,
        span: Span,
        precision: Precision,
        call_kind: CallEdgeKind,
    ) -> Self {
        Self {
            from,
            to,
            meta: EdgeMeta {
                precision,
                kind: IdgEdgeKind::InterCallArg,
                call_kind,
                via_span: span,
            },
        }
    }

    /// Construct an inter-procedural return edge.
    #[must_use]
    pub const fn inter_return(
        from: NodeId,
        to: NodeId,
        span: Span,
        precision: Precision,
        call_kind: CallEdgeKind,
    ) -> Self {
        Self {
            from,
            to,
            meta: EdgeMeta {
                precision,
                kind: IdgEdgeKind::InterReturn,
                call_kind,
                via_span: span,
            },
        }
    }
}

#[cfg(test)]
#[path = "edge_tests.rs"]
mod tests;
