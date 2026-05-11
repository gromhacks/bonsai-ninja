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
}

impl IdgEdgeKind {
    /// True iff this kind is an inter-procedural edge built during
    /// Phase 3 stitching. Lets queries filter intra-only flows.
    #[must_use]
    pub const fn is_inter(self) -> bool {
        matches!(
            self,
            Self::InterCallArg | Self::InterReturn | Self::InterThrow
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
mod tests {
    use super::*;
    use bonsai_common::FileId;

    fn span() -> Span {
        Span::new(FileId::new(0), 0, 1)
    }

    #[test]
    fn intra_assign_constructor_sets_exact_precision_and_direct() {
        let e = IdgEdge::intra_assign(NodeId(1), NodeId(2), span());
        assert_eq!(e.meta.precision, Precision::Exact);
        assert_eq!(e.meta.kind, IdgEdgeKind::IntraAssign);
        assert_eq!(e.meta.call_kind, CallEdgeKind::Direct);
    }

    #[test]
    fn inter_call_arg_carries_call_kind() {
        let e = IdgEdge::inter_call_arg(
            NodeId(1),
            NodeId(2),
            span(),
            Precision::OverApproximate,
            CallEdgeKind::Virtual,
        );
        assert_eq!(e.meta.precision, Precision::OverApproximate);
        assert_eq!(e.meta.kind, IdgEdgeKind::InterCallArg);
        assert_eq!(e.meta.call_kind, CallEdgeKind::Virtual);
    }

    #[test]
    fn is_inter_only_for_inter_kinds() {
        assert!(IdgEdgeKind::InterCallArg.is_inter());
        assert!(IdgEdgeKind::InterReturn.is_inter());
        assert!(IdgEdgeKind::InterThrow.is_inter());
        assert!(!IdgEdgeKind::IntraAssign.is_inter());
        assert!(!IdgEdgeKind::IntraRead.is_inter());
        assert!(!IdgEdgeKind::IntraReturn.is_inter());
        assert!(!IdgEdgeKind::IntraThrow.is_inter());
    }

    #[test]
    fn is_intra_is_negation_of_is_inter() {
        for tag in 0u8..=10 {
            let kind = IdgEdgeKind::from_tag(tag).expect("known tag");
            assert_ne!(kind.is_intra(), kind.is_inter());
        }
    }

    #[test]
    fn tag_roundtrips_via_from_tag() {
        for tag in 0u8..=10 {
            let kind = IdgEdgeKind::from_tag(tag).expect("known tag");
            assert_eq!(kind.tag(), tag);
        }
    }

    #[test]
    fn from_tag_rejects_unknown_values() {
        assert_eq!(IdgEdgeKind::from_tag(11), None);
        assert_eq!(IdgEdgeKind::from_tag(255), None);
    }

    #[test]
    fn edge_equality_full_componentwise() {
        let a = IdgEdge::intra_assign(NodeId(1), NodeId(2), span());
        let b = IdgEdge::intra_assign(NodeId(1), NodeId(2), span());
        assert_eq!(a, b);
        let c = IdgEdge::intra_assign(NodeId(1), NodeId(3), span());
        assert_ne!(a, c);
    }

    #[test]
    fn edge_kind_tag_values_are_pinned() {
        // The on-disk format depends on these — pin them so a future
        // enum reorder is caught at build time.
        assert_eq!(IdgEdgeKind::IntraAssign.tag(), 0);
        assert_eq!(IdgEdgeKind::IntraRead.tag(), 1);
        assert_eq!(IdgEdgeKind::IntraReturn.tag(), 2);
        assert_eq!(IdgEdgeKind::IntraThrow.tag(), 3);
        assert_eq!(IdgEdgeKind::InterCallArg.tag(), 4);
        assert_eq!(IdgEdgeKind::InterReturn.tag(), 5);
        assert_eq!(IdgEdgeKind::InterThrow.tag(), 6);
        assert_eq!(IdgEdgeKind::IntraFieldRead.tag(), 7);
        assert_eq!(IdgEdgeKind::IntraFieldWrite.tag(), 8);
        assert_eq!(IdgEdgeKind::IntraYield.tag(), 9);
        assert_eq!(IdgEdgeKind::IntraAwait.tag(), 10);
    }
}
