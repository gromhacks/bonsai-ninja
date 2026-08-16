//! Bonsai's workspace-wide Interprocedural Dataflow Graph.
//!
//! This crate is the canonical structural taint / dataflow graph.
//! Public review, export, dump-taint, inspect, and security callers
//! read it through precision-scoped queries and expose only
//! semantic (`Exact` / `Narrowed`) reachability. Unscoped
//! over-approximate reachability is diagnostic-only.
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
//! Built on semantic demand (or explicitly by `index --semantic`) and
//! persisted via [`bonsai_factstore`] as one segment per source file plus a
//! workspace-level cross-file edge index. Warm queries validate compact
//! function/node directories and the default contextual accelerator without
//! decoding every segment. Canonical segments and fixed-width query
//! relations page from disk on demand.
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
//! Loops emit the body once for may-run flows, then revisit the body
//! with body-end writers live so reads can bind to values from the
//! previous iteration. Duplicate transfer edges are suppressed.
//!
//! ## Evidence boundary
//!
//! The IDG forward closure models clean-overwrite kills and branch joins,
//! and public queries accept evidence through `Precision::Narrowed` while
//! excluding diagnostic-only edges. This is an evidence classification, not
//! a traversal or result cap. Adapters provide syntax/capability facts and
//! the rulepack provides security meaning; source/sink selection and
//! framework policy remain layers above this API-neutral graph.
//!
//! ## Why a single graph
//!
//! The IFDS dataflow framework (Reps, Horwitz, Sagiv 1995) reduces
//! interprocedural taint reachability to graph reachability. Bonsai lowers the
//! language-agnostic `FlowEvent` contract into numeric nodes, CSR value edges,
//! and compact symbolic access-path transforms. Queries reuse those compiler
//! relations and solve only demanded facts to a fixed point; they do not
//! materialize the whole `transform × field` product or search through source
//! spellings.
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
mod external_relation;
mod fact_source_index;
mod function_summary;
pub mod node;
pub mod place;
mod positioned_io;
pub mod query;
mod reverse_scalar_index;
mod reverse_symbolic_index;
pub mod segment;
pub mod service;
mod spill_set;
pub mod symbolic;
pub mod transfer;
pub mod workspace;
pub mod workspace_adapter;

pub use bitset::NodeBitSet;
pub use builder::{stitch_idg, CalleeResolver, FuncToSegment, ResolvedCallee};
pub use csr::EdgeCsr;
pub use query::ReachabilityIndex;
pub use service::{
    expand_bare_seed_names_with_descendants, CallRetAssignmentTarget, CrossCallEdge, CrossCallRelation,
    IdgClosureEvidence, IdgQueryService, IdgTargetRelevance, PointKind, PointRef, WsNodeId,
};
pub use symbolic::{
    SymbolicFieldBase, SymbolicFieldGraph, SymbolicFieldTransform, SymbolicFieldTransformKind,
    NO_SYMBOLIC_STRING,
};
pub use transfer::{
    transfer_for_many, transfer_for_many_with_options, transfer_function_for,
    transfer_function_for_with_options, transfer_function_for_with_options_and_assignment_values,
    transfer_function_for_with_options_and_compiler_facts,
    transfer_function_for_with_options_and_syntax_facts, CallResultPassthroughSpec, CallSiteRef,
    CleanOutputOverwriteSpec, NameInterner, OutputArgFlowSpec, ReceiverStatePropagationSpec,
    SourceCallbackArgSpec, SourceOutputArgSpec, ThrowSite, TransferOptions, TransferOutput,
};
pub use workspace::{CrossFileEdge, CrossFileEdges, FieldFlowLink, IdgWorkspace, SegmentId};

pub use edge::{EdgeMeta, IdgEdge, IdgEdgeKind};
pub use error::{IdgError, IdgResult};
pub use node::{IdgNode, NodeId, PlaceId};
pub use place::{CallSiteId, FieldPath, Place, TypeId};
