//! Bonsai's workspace-wide Interprocedural Dataflow Graph.
//!
//! This crate is the canonical structural taint / dataflow graph.
//! Consumers that need over-approximate reachability (value-flow,
//! dump-taint, inspect, browse export) read the IDG directly. The
//! security findings pipeline still drives the legacy
//! [`bonsai_taint::inter`] engine for precision parity — see
//! "Hybrid path" below.
//!
//! ## Design
//!
//! Conceptually the IDG is a directed graph:
//!
//! ```text
//! Node = (FuncId, Place)        4 + 4 = 8 bytes
//! Edge = (Node → Node, meta)   12 bytes interned + 6 bytes meta
//! ```
//!
//! Built once at workspace index time, persisted via
//! [`bonsai_factstore`] as one segment per source file plus a
//! workspace-level cross-file edge index. mmap-friendly: opens with
//! a single header read, keeps the place dictionary + adjacency
//! tables resident in memory, pages payload bytes on demand.
//!
//! ## SSA-style CFG narrowing (Phase 8)
//!
//! [`Place::Write`] carries a `span` so each assignment in the
//! program is a distinct IDG node. The transfer pass tracks a
//! per-name `last_writer` set as it walks flow events in CFG
//! order, emitting `Write(name, span_W) → consumer-node` bridges
//! only from the most-recent writer(s). Branches snapshot
//! `last_writer` at entry, walk each arm, and union the post-arm
//! sets at the merge — so a clean overwrite later in the function
//! kills earlier writers' bridges (the engine's classic
//! clean-overwrite kill semantics, structurally encoded).
//!
//! Loops walk the body twice with `last_writer` accumulating
//! across iterations — a fixpoint approximation that handles
//! loop-carried accumulators and zero-iteration cases without
//! converging deeper.
//!
//! ## Hybrid path
//!
//! The IDG forward-closure correctly models clean-overwrite kills
//! and branch joins for most adapter shapes, but full security
//! migration also needs adapter-uniform source-event anchoring
//! (e.g., objc's side-effecting `fgets(buf, ...)`, solidity's
//! `block.timestamp` field-read, perl's specific patterns) that's
//! beyond the IDG's scope today. Until those land, the security
//! findings pipeline keeps using the engine for precision-critical
//! taint analysis. value-flow / dump-taint / inspect / browse
//! consume the IDG directly — see [`IdgQueryService`].
//!
//! ## Why a single graph
//!
//! The IFDS dataflow framework (Reps, Horwitz, Sagiv 1995) reduces
//! interprocedural taint reachability to **graph reachability** on
//! a precomputed exploded supergraph. The bonsai IDG is that
//! supergraph specialised for the language-agnostic FlowEvent
//! contract. Once it's built, every "is X tainted?" / "what flows
//! into Y?" / "show source-to-sink chains" question is a bitvector
//! operation on the graph — never a per-query traversal of the
//! whole workspace.
//!
//! ## Module layout
//!
//! - [`place`] — every position a value can occupy.
//! - [`node`] — nodes (`(FuncId, PlaceId)`) and their u32 handles.
//! - [`edge`] — directed edges with precision + kind metadata.
//! - [`error`] — error types surfaced by the layer.

#![deny(missing_docs)]

pub mod bitset;
pub mod builder;
pub mod csr;
pub mod dict;
pub mod edge;
pub mod error;
pub mod node;
pub mod place;
pub mod query;
pub mod segment;
pub mod service;
pub mod transfer;
pub mod workspace;
pub mod workspace_adapter;

pub use bitset::NodeBitSet;
pub use builder::{stitch_idg, CalleeResolver, FuncToSegment, ResolvedCallee};
pub use csr::EdgeCsr;
pub use query::ReachabilityIndex;
pub use service::{CrossCallEdge, IdgQueryService, PointKind, PointRef, WsNodeId};
pub use transfer::{
    transfer_for_many, transfer_function_for, CallSiteRef, NameInterner, ThrowSite, TransferOutput,
};
pub use workspace::{CrossFileEdge, CrossFileEdges, FieldFlowLink, IdgWorkspace, SegmentId};

pub use edge::{EdgeMeta, IdgEdge, IdgEdgeKind};
pub use error::{IdgError, IdgResult};
pub use node::{IdgNode, NodeId, PlaceId};
pub use place::{CallSiteId, FieldPath, Place, TypeId};
