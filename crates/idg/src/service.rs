//! High-level query service over an [`IdgWorkspace`].
//!
//! Phase 5 consumers (value-flow, security analysis, dump-taint,
//! inspect, source-analysis, export) all need the same primitives:
//!
//! - "What flows from `entry_func`'s params (or a named seed)?"
//! - "What flows into `sink_func`'s arg N?"
//! - "Does a realizable, call-matched source flow reach a sink target?"
//! - "Translate an IDG node back to a renderable `(func, span, name)`
//!   triple."
//!
//! [`IdgQueryService`] gathers those primitives behind a single
//! handle so consumers don't have to wire up `ReachabilityIndex`,
//! `EdgeCsr`, and the segment-walking themselves.
//!
//! ## Cross-segment reachability
//!
//! [`IdgWorkspace`] stores per-segment edges and a workspace-level
//! `CrossFileEdge` index. The service materialises a unified
//! address-space view (workspace-global node ids that span every
//! segment) for closure queries. The materialisation is computed
//! lazily on first query and cached on the service, so repeated
//! queries amortise the cost.

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::EdgeKind as CallEdgeKind;
use bonsai_common::{current_process_resident_bytes, FileId, FuncId, Precision, Span};
use bonsai_index::GlobalIndex;
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::hash::Hash;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, OnceLock};

use crate::bitset::NodeBitSet;
use crate::edge::{IdgEdge, IdgEdgeKind};
use crate::external_relation::{merge_page_rows, ExternalRecord, ExternalSorter, PersistedExternalRelation};
use crate::fact_source_index::{FactSourceIndex, FactSourceSpool};
use crate::node::NodeId;
use crate::place::Place;
use crate::positioned_io::read_exact_at;
use crate::query::ReachabilityIndex;
use crate::reverse_scalar_index::{ReverseScalarTransformIndex, ReverseScalarTransformSpool};
use crate::reverse_symbolic_index::{ReverseSymbolicTransformIndex, ReverseSymbolicTransformSpool};
use crate::spill_set::{SpillSet, SpillStack};
use crate::symbolic::{structured_storage_parts, SymbolicFieldTransformKind, NO_SYMBOLIC_STRING};
use crate::workspace::{
    CompiledQueryAccelerator, CompiledQueryAcceleratorBlob, CompiledQueryAcceleratorFrame, IdgWorkspace,
    PersistedQueryAcceleratorParts, QueryAcceleratorBlobKind, QueryAcceleratorBlobReader, SegmentId,
};

const SEMANTIC_MAX_PRECISION: Precision = Precision::Narrowed;

/// A renderable program point: the (function, span, place) triple
/// every consumer eventually reports back to its UI / report layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PointRef {
    /// Owning function.
    pub func: FuncId,
    /// Exact source span.
    pub span: Span,
    /// Renderable compiler-place name.
    pub name: String,
    /// Coarse point classification.
    pub kind: PointKind,
}

/// Coarse classification of an IDG compiler point.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PointKind {
    /// Formal parameter.
    Param,
    /// Function return slot.
    Return,
    /// Storage read.
    Read,
    /// Storage write.
    Write,
    /// Call argument slot.
    CallArg,
    /// Call result slot.
    CallRet,
    /// Exceptional or asynchronous flow point.
    Other,
}

/// Assignment target fed by a call site's result slot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallRetAssignmentTarget {
    /// Adapter-normalized target storage.
    pub name: String,
    /// Target write span.
    pub span: Span,
    /// Workspace-global target node.
    pub node: WsNodeId,
}

/// Workspace-global IDG node identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct WsNodeId(pub u32);

/// One resolved cross-call value propagation extracted from the IDG.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CrossCallEdge {
    /// Function containing the call.
    pub caller: FuncId,
    /// Resolved destination function.
    pub callee: FuncId,
    /// Call-site span.
    pub call_span: Span,
    /// Zero-based argument position, or `u32::MAX` when the relation is
    /// carried by a receiver, callback, capture, or outbound state.
    pub arg_idx: u32,
    /// Zero-based formal position, or `u32::MAX` when no scalar formal slot
    /// represents the relation.
    pub param_idx: u32,
    /// Resolver/evidence precision.
    pub precision: Precision,
    /// Resolved call classification.
    pub call_kind: bonsai_callgraph::EdgeKind,
    /// Compiler relation represented by this propagation.
    pub relation: CrossCallRelation,
}

/// One exact forward-closure result together with the symbolic call-boundary
/// transitions that fired while computing it.
///
/// Ordinary scalar call edges remain available through
/// [`IdgQueryService::cross_call_edges_in_reachable_nodes`]. Symbolic
/// transitions are returned here because access-path transforms are composed
/// on demand and therefore do not exist as eagerly materialized graph edges.
#[derive(Clone, Debug, Default)]
pub struct IdgClosureEvidence {
    /// Workspace nodes reached by the compiler fixed point.
    pub nodes: Vec<WsNodeId>,
    /// Exact call-boundary transitions that fired while solving the closure.
    ///
    /// Scalar call/return rows come from the contextual compiler relation;
    /// projected access-path rows come from the symbolic transform algebra.
    /// Retaining both at transition time avoids a second workspace-wide IDG
    /// scan merely to reconstruct evidence for the nodes already reached.
    pub cross_calls: Vec<CrossCallEdge>,
}

/// Run one ownership-transferring compiler phase on a scoped allocator heap.
/// Large summary/CSR builders return only their canonical result; when the
/// thread exits, transient hash tables and endpoint buffers cannot remain in
/// the caller thread's allocator arena and overlap the next phase.
fn run_isolated_compiler_phase<T, F>(phase: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    std::thread::scope(|scope| match scope.spawn(phase).join() {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    })
}

/// Provenance of a cross-function IDG propagation.
///
/// The distinction is semantic, not presentational: projected heap state can
/// connect functions without proving that one calls the other. Consumers may
/// use those links for reachability and lineage, but must not render them as
/// resolved call records.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum CrossCallRelation {
    /// Resolved scalar or projected `CallArg -> Param` boundary.
    Argument,
    /// External/source callback result entering a callback parameter.
    Callback,
    /// Lexically captured value entering a closure body.
    Capture,
    /// Callee return/output state flowing back to its caller.
    Return,
    /// Projected object/container state crossing function ownership.
    FieldState,
}

impl CrossCallRelation {
    /// Whether this relation proves a renderable call-like propagation.
    #[must_use]
    pub const fn is_renderable_call(self) -> bool {
        !matches!(self, Self::FieldState)
    }
}

struct UnifiedAddressSpace {
    segment_bases: Box<[u32]>,
    /// Dense `FuncId.raw() -> SegmentId` directory. A global node already
    /// stores its owning function, so `(segment, local)` is recovered as
    /// `func_segments[func]` plus `global - segment_bases[segment]`; retaining
    /// that pair again for every node would cost eight bytes per IR point.
    func_segments: Box<[u32]>,
    node_funcs: Box<[FuncId]>,
    node_boundaries: Box<[u8]>,
    projected_storage: Box<[u8]>,
    nodes_by_func: NodesByFunc,
    call_args: CallArgIdentityIndex,
    params: ParamIdentityIndex,
    unfiltered_reach: RwLock<Option<Arc<ReachabilityIndex>>>,
    precision_reach: RwLock<AHashMap<Precision, Arc<ReachabilityIndex>>>,
    contextual_summaries: RwLock<AHashMap<Option<Precision>, Arc<ContextualSummaryRuntime>>>,
    cross_calls_by_from: RwLock<Option<Arc<CrossCallsByFrom>>>,
    symbolic_runtime: OnceLock<Arc<SymbolicRuntimeIndex>>,
}

/// Independently decodable compiler indexes stored after the canonical IDG
/// relations. The payload contains only representation state derived from the
/// same immutable graph generation; it never admits or suppresses a semantic
/// edge. Keeping the wire version separate lets us evolve this acceleration
/// layer without conflating it with the canonical workspace IDG ABI.
const IDG_QUERY_ACCELERATOR_VERSION: u32 = 5;
const IDG_QUERY_CORE_MAGIC: [u8; 8] = *b"BNSIQC01";
const IDG_QUERY_CORE_COUNT_FIELDS: usize = 12;
const IDG_QUERY_CORE_HEADER_BYTES: u64 = 8 + 4 + 1 + 3 + 4 + (IDG_QUERY_CORE_COUNT_FIELDS as u64 * 8);

struct PersistedQueryAccelerator {
    version: u32,
    max_precision: Precision,
    segment_count: u32,
    segment_bases: Box<[u32]>,
    func_segments: Box<[u32]>,
    node_funcs: Box<[FuncId]>,
    node_boundaries: Box<[u8]>,
    projected_storage: Box<[u8]>,
    nodes_by_func: NodesByFunc,
    call_args: CallArgIdentityIndex,
    params: ParamIdentityIndex,
}

const NODE_BOUNDARY_PARAM: u8 = 1;
const NODE_BOUNDARY_RETURN: u8 = 2;
const NODE_BOUNDARY_THROW: u8 = 3;
const NODE_BOUNDARY_YIELD: u8 = 4;
const NODE_BOUNDARY_CALL_RET: u8 = 4;

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct NodesByFunc {
    /// Dense `FuncId.raw() -> [start, end)` table. Empty function ids have an
    /// empty range; this costs four bytes per symbol and avoids one hash-map
    /// bucket plus one heap allocation per callable.
    offsets: Box<[u32]>,
    nodes: Box<[NodeId]>,
}

impl NodesByFunc {
    fn get(&self, func: FuncId) -> Option<&[NodeId]> {
        let index = func.raw() as usize;
        let start = *self.offsets.get(index)? as usize;
        let end = *self.offsets.get(index + 1)? as usize;
        Some(&self.nodes[start..end])
    }
}

/// Compact compiler identity for the sparse subset of workspace nodes that
/// represent call arguments. Nodes are appended in workspace-address order
/// while the unified address space is built, so lookups stay logarithmic
/// without reopening the segment that owns the node.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct CallArgIdentityIndex {
    nodes: Box<[WsNodeId]>,
    sites: Box<[Span]>,
    indices: Box<[u32]>,
}

impl CallArgIdentityIndex {
    fn get(&self, node: WsNodeId) -> Option<(Span, u32)> {
        let index = self.nodes.binary_search(&node).ok()?;
        Some((*self.sites.get(index)?, *self.indices.get(index)?))
    }

    fn is_valid_for(&self, node_count: usize) -> bool {
        self.nodes.len() == self.sites.len()
            && self.nodes.len() == self.indices.len()
            && strictly_sorted_ws_nodes(&self.nodes)
            && self.nodes.iter().all(|node| (node.0 as usize) < node_count)
    }
}

/// Compact parameter-slot identity for the sparse subset of workspace nodes
/// that are formal parameters. Cross-file call evidence can therefore be
/// lifted from compiler headers without reopening a complete IDG body.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct ParamIdentityIndex {
    nodes: Box<[WsNodeId]>,
    indices: Box<[u32]>,
}

/// Exact AST-lowered storage base owned by a sparse subset of IDG nodes.
///
/// The rows are ordered by workspace node id while the ordinary symbolic
/// consumer indexes are ordered by storage base. Keeping this compact inverse
/// directory lets backward demand recover a node's canonical storage identity
/// without reopening its complete source-file IDG segment.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct NodeStorageReadIndex {
    nodes: Box<[WsNodeId]>,
    bases: Box<[u32]>,
}

impl NodeStorageReadIndex {
    fn from_sorted_rows(rows: impl IntoIterator<Item = (WsNodeId, u32)>) -> Self {
        let (nodes, bases): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        debug_assert!(strictly_sorted_ws_nodes(&nodes));
        Self {
            nodes: nodes.into_boxed_slice(),
            bases: bases.into_boxed_slice(),
        }
    }

    fn base(&self, node: WsNodeId) -> Option<u32> {
        let index = self.nodes.binary_search(&node).ok()?;
        self.bases.get(index).copied()
    }

    fn is_valid_for(&self, node_count: usize, base_count: usize) -> bool {
        self.nodes.len() == self.bases.len()
            && strictly_sorted_ws_nodes(&self.nodes)
            && self.nodes.iter().all(|node| (node.0 as usize) < node_count)
            && self.bases.iter().all(|base| (*base as usize) < base_count)
    }
}

/// Exact AST-lowered scalar write identity for reverse-return demand.
///
/// Spans are interned in [`SymbolicRuntimeIndex::spans`], so each sparse row
/// remains three words instead of retaining a full [`Span`] beside every
/// write node.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct NodeStorageWriteIndex {
    nodes: Box<[WsNodeId]>,
    bases: Box<[u32]>,
    spans: Box<[u32]>,
}

impl NodeStorageWriteIndex {
    fn from_sorted_rows(rows: impl IntoIterator<Item = (WsNodeId, u32, u32)>) -> Self {
        let mut nodes = Vec::new();
        let mut bases = Vec::new();
        let mut spans = Vec::new();
        for (node, base, span) in rows {
            nodes.push(node);
            bases.push(base);
            spans.push(span);
        }
        debug_assert!(strictly_sorted_ws_nodes(&nodes));
        Self {
            nodes: nodes.into_boxed_slice(),
            bases: bases.into_boxed_slice(),
            spans: spans.into_boxed_slice(),
        }
    }

    fn identity(&self, node: WsNodeId) -> Option<(u32, u32)> {
        let index = self.nodes.binary_search(&node).ok()?;
        Some((*self.bases.get(index)?, *self.spans.get(index)?))
    }

    fn is_valid_for(&self, node_count: usize, base_count: usize, span_count: usize) -> bool {
        self.nodes.len() == self.bases.len()
            && self.nodes.len() == self.spans.len()
            && strictly_sorted_ws_nodes(&self.nodes)
            && self.nodes.iter().all(|node| (node.0 as usize) < node_count)
            && self.bases.iter().all(|base| (*base as usize) < base_count)
            && self.spans.iter().all(|span| (*span as usize) < span_count)
    }
}

impl ParamIdentityIndex {
    fn get(&self, node: WsNodeId) -> Option<u32> {
        let index = self.nodes.binary_search(&node).ok()?;
        self.indices.get(index).copied()
    }

    fn is_valid_for(&self, node_count: usize) -> bool {
        self.nodes.len() == self.indices.len()
            && strictly_sorted_ws_nodes(&self.nodes)
            && self.nodes.iter().all(|node| (node.0 as usize) < node_count)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GroupedNodeIndex<K> {
    keys: Box<[K]>,
    offsets: Box<[u32]>,
    nodes: Box<[WsNodeId]>,
}

impl<K> Default for GroupedNodeIndex<K> {
    fn default() -> Self {
        Self {
            keys: Box::new([]),
            offsets: Box::new([0]),
            nodes: Box::new([]),
        }
    }
}

impl<K: Copy + Ord> GroupedNodeIndex<K> {
    fn from_rows(mut rows: Vec<(K, WsNodeId)>) -> Self {
        rows.sort_unstable_by_key(|(key, node)| (*key, node.0));
        rows.dedup();
        let mut keys = Vec::new();
        let mut offsets = vec![0_u32];
        let mut nodes = Vec::with_capacity(rows.len());
        let mut current = None;
        for (key, node) in rows {
            if current != Some(key) {
                if current.is_some() {
                    offsets.push(u32::try_from(nodes.len()).expect("symbolic node index exceeds u32"));
                }
                keys.push(key);
                current = Some(key);
            }
            nodes.push(node);
        }
        if current.is_some() {
            offsets.push(u32::try_from(nodes.len()).expect("symbolic node index exceeds u32"));
        }
        Self {
            keys: keys.into_boxed_slice(),
            offsets: offsets.into_boxed_slice(),
            nodes: nodes.into_boxed_slice(),
        }
    }

    fn has_valid_layout(&self, node_count: usize) -> bool {
        self.keys.windows(2).all(|pair| pair[0] < pair[1])
            && self.offsets.len() == self.keys.len().saturating_add(1)
            && offsets_are_valid(&self.offsets, self.nodes.len())
            && self.nodes.iter().all(|node| (node.0 as usize) < node_count)
    }

    fn get(&self, key: &K) -> Option<&[WsNodeId]> {
        let index = self.keys.binary_search(key).ok()?;
        let start = self.offsets[index] as usize;
        let end = self.offsets[index + 1] as usize;
        Some(&self.nodes[start..end])
    }
}

fn offsets_are_valid(offsets: &[u32], value_count: usize) -> bool {
    offsets.first().copied() == Some(0)
        && offsets.windows(2).all(|pair| pair[0] <= pair[1])
        && offsets.last().copied().map(|last| last as usize) == Some(value_count)
}

fn strictly_sorted_ws_nodes(nodes: &[WsNodeId]) -> bool {
    nodes.windows(2).all(|pair| pair[0] < pair[1])
}

type CrossCallsByFrom = AHashMap<WsNodeId, Vec<CrossCallEdge>>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct SymbolicNodeFact {
    base: u32,
    field: u32,
    /// Low 31 bits store a one-based [`SymbolicFactSpan`] id; the high bit
    /// records whether this fact crossed a call boundary. Interprocedural
    /// facts deliberately carry no local ordering span because the transfer
    /// predicate never consults one after a call. Canonicalizing that unused
    /// field prevents equivalent facts reached through many call sites from
    /// multiplying in the fixed point.
    provenance: u32,
    context: u32,
}

const SYMBOLIC_FACT_INTERPROCEDURAL: u32 = 1 << 31;
const SYMBOLIC_FACT_SPAN_MASK: u32 = SYMBOLIC_FACT_INTERPROCEDURAL - 1;

impl SymbolicNodeFact {
    fn new(base: u32, field: u32, span: Option<u32>, interprocedural: bool, context: u32) -> Self {
        let encoded_span = if interprocedural {
            0
        } else {
            span.map_or(0, |span| {
                let one_based = span.checked_add(1).expect("symbolic fact span id exceeds u32");
                assert!(
                    one_based <= SYMBOLIC_FACT_SPAN_MASK,
                    "symbolic fact span count exceeds compact representation"
                );
                one_based
            })
        };
        Self {
            base,
            field,
            provenance: encoded_span | (u32::from(interprocedural) * SYMBOLIC_FACT_INTERPROCEDURAL),
            context,
        }
    }

    fn span_id(self) -> Option<u32> {
        (self.provenance & SYMBOLIC_FACT_SPAN_MASK).checked_sub(1)
    }

    fn is_interprocedural(self) -> bool {
        self.provenance & SYMBOLIC_FACT_INTERPROCEDURAL != 0
    }

    fn identity(self) -> SymbolicFactIdentity {
        SymbolicFactIdentity {
            base: self.base,
            field: self.field,
            provenance: self.provenance,
        }
    }

    fn from_identity(identity: SymbolicFactIdentity, context: u32) -> Self {
        Self {
            base: identity.base,
            field: identity.field,
            provenance: identity.provenance,
            context,
        }
    }

    fn state_key(self) -> u128 {
        self.identity().key() | (u128::from(self.context) << 96)
    }

    fn from_state_key(key: u128) -> Self {
        Self::from_identity(SymbolicFactIdentity::from_key(key), (key >> 96) as u32)
    }
}

/// Context-independent identity for one compiler-derived symbolic fact.
///
/// The identity occupies the low 96 bits of an external-memory relation key;
/// the high 32 bits carry its realizable call context.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SymbolicFactIdentity {
    base: u32,
    field: u32,
    provenance: u32,
}

impl SymbolicFactIdentity {
    fn key(self) -> u128 {
        u128::from(self.base) | (u128::from(self.field) << 32) | (u128::from(self.provenance) << 64)
    }

    fn from_key(key: u128) -> Self {
        Self {
            base: key as u32,
            field: (key >> 32) as u32,
            provenance: (key >> 64) as u32,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
struct SymbolicFactSpan {
    file: FileId,
    start: u64,
    end: u64,
}

impl From<Span> for SymbolicFactSpan {
    fn from(span: Span) -> Self {
        Self {
            file: span.file,
            start: span.start,
            end: span.end,
        }
    }
}

impl SymbolicFactSpan {
    fn into_span(self) -> Span {
        Span::new(self.file, self.start, self.end)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SymbolicBaseRebaseKind {
    /// `(nested, field)` becomes `(ancestor, nested_suffix.field)`.
    PrependPrefix,
    /// `(ancestor, nested_suffix.field)` becomes `(nested, field)`.
    StripPrefix,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolicBaseRebase {
    target: u32,
    prefix: u32,
    kind: SymbolicBaseRebaseKind,
}

/// Sparse source-indexed equivalence rows for alternate access-path
/// decompositions. A sorted flat relation avoids one empty allocation per
/// symbolic base and remains cheap to binary-search in the closure hot path.
#[derive(Default)]
struct SymbolicBaseRebaseIndex {
    keys: Box<[u32]>,
    offsets: Box<[u32]>,
    rows: Box<[SymbolicBaseRebase]>,
}

impl SymbolicBaseRebaseIndex {
    fn specs(
        symbolic: &crate::symbolic::SymbolicFieldGraph,
    ) -> Vec<(u32, u32, String, SymbolicBaseRebaseKind)> {
        let mut specs = Vec::new();
        for (nested_id, nested) in symbolic.bases().iter().enumerate() {
            let Some(storage) = symbolic.string(nested.storage) else {
                continue;
            };
            let parts = storage
                .split('.')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            for split in 1..parts.len() {
                let ancestor_text = parts[..split].join(".");
                let prefix = parts[split..].join(".");
                let Some(ancestor_id) = symbolic.base_id(nested.segment, nested.func, &ancestor_text) else {
                    continue;
                };
                let nested_id = u32::try_from(nested_id).expect("symbolic base count exceeds u32");
                specs.push((
                    nested_id,
                    ancestor_id,
                    prefix.clone(),
                    SymbolicBaseRebaseKind::PrependPrefix,
                ));
                specs.push((
                    ancestor_id,
                    nested_id,
                    prefix,
                    SymbolicBaseRebaseKind::StripPrefix,
                ));
            }
        }
        specs.sort_unstable();
        specs.dedup();
        specs
    }

    fn from_specs(
        specs: Vec<(u32, u32, String, SymbolicBaseRebaseKind)>,
        fields: &PackedStringTable,
    ) -> Self {
        let mut compiled = specs
            .into_iter()
            .filter_map(|(source, target, prefix, kind)| {
                Some((
                    source,
                    SymbolicBaseRebase {
                        target,
                        prefix: fields.find(&prefix)?,
                        kind,
                    },
                ))
            })
            .collect::<Vec<_>>();
        compiled.sort_unstable();
        compiled.dedup();
        let mut keys = Vec::new();
        let mut offsets = vec![0_u32];
        let mut rows = Vec::with_capacity(compiled.len());
        let mut current = None;
        for (source, row) in compiled {
            if current != Some(source) {
                if current.is_some() {
                    offsets.push(u32::try_from(rows.len()).expect("symbolic rebase count exceeds u32"));
                }
                keys.push(source);
                current = Some(source);
            }
            rows.push(row);
        }
        if current.is_some() {
            offsets.push(u32::try_from(rows.len()).expect("symbolic rebase count exceeds u32"));
        }
        Self {
            keys: keys.into_boxed_slice(),
            offsets: offsets.into_boxed_slice(),
            rows: rows.into_boxed_slice(),
        }
    }

    fn outgoing(&self, source: u32) -> &[SymbolicBaseRebase] {
        let Ok(index) = self.keys.binary_search(&source) else {
            return &[];
        };
        let start = self.offsets[index] as usize;
        let end = self.offsets[index + 1] as usize;
        &self.rows[start..end]
    }
}

struct SymbolicRuntimeIndex {
    /// Sorted AST-derived suffix paths. The owned dictionary is built only in
    /// the query phase and replaces no compiler fact; numeric ids keep the
    /// hot closure relation compact.
    fields: PackedStringTable,
    /// Sorted unique source positions used by local symbolic ordering.
    spans: Box<[SymbolicFactSpan]>,
    /// Bases whose outgoing transfer relation consults local write order.
    ///
    /// A fact's source span is semantically irrelevant everywhere else. The
    /// closure canonicalizes that unused component to zero so equivalent
    /// field facts reached through many local writes do not multiply in the
    /// exact fixed point.
    ordering_sensitive_bases: Box<[u64]>,
    /// Equivalent decompositions of one canonical compiler access path.
    /// For example, `(self._data, cmd)` and `(self, _data.cmd)` denote the
    /// same field. Rows exist only when both bases occur in the symbolic
    /// transform dictionary, so storage is proportional to real nested
    /// compiler places rather than the Cartesian product of bases and fields.
    base_rebases: SymbolicBaseRebaseIndex,
    exact_reads: GroupedNodeIndex<u64>,
    /// Sorted exact `(base, field)` identities that occur in adapter-lowered
    /// projected storage.  The backward demand compiler starts from this
    /// finite syntax relation, then follows inverse field transforms to admit
    /// carrier bases.  A suffix can therefore cross scalar-looking wrapper
    /// names only when some real projected place downstream demands it.
    projected_fact_keys: Box<[u64]>,
    /// Whole-aggregate AST consumers keyed by their canonical storage base.
    ///
    /// These are narrower than all bare reads: only nodes with an
    /// `IntraAggregateConsume` edge are admitted, and resolver-proven local
    /// call arguments are excluded because their exact field transforms own
    /// interprocedural propagation. This preserves `sink(record)` semantics
    /// without turning scalar carrier reads into invented field consumers.
    aggregate_reads: GroupedNodeIndex<u32>,
    scalar_writes: GroupedNodeIndex<(u32, Span)>,
    storage_reads: NodeStorageReadIndex,
    storage_writes: NodeStorageWriteIndex,
    fact_sources: FactSourceIndex,
    aggregate_inputs: GroupedNodeIndex<NodeId>,
    aggregate_outputs: GroupedNodeIndex<NodeId>,
    resolved_call_args: Box<[WsNodeId]>,
    reverse_transforms: ReverseSymbolicTransformIndex,
    reverse_scalar_transforms: ReverseScalarTransformIndex,
    fact_pages: Mutex<SymbolicFactPager>,
    transforms: Mutex<SymbolicTransformPager>,
    field_demands: Mutex<AHashMap<Option<Precision>, Arc<SymbolicFieldDemand>>>,
}

// Version 5 retains the exact positional argument/parameter slots on
// projected call-boundary rows. Earlier accelerators preserved reachability
// but rendered those proven calls with sentinel slots, breaking diagnostic
// call-chain continuity for aggregate fields.
// Version 4 adds the compiler-proven whole-aggregate consumer relation.
// Older accelerators remain semantically valid as IDG bodies, but must rebuild
// this derived query product before symbolic closure can distinguish a real
// `sink(record)` read from a scalar carrier used by a resolved local call.
const SYMBOLIC_RUNTIME_ACCELERATOR_VERSION: u32 = 5;

#[derive(serde::Serialize)]
struct PersistedSymbolicRuntimeRef<'a> {
    version: u32,
    fields: &'a PackedStringTable,
    spans: &'a [SymbolicFactSpan],
    ordering_sensitive_bases: &'a [u64],
    exact_reads: &'a GroupedNodeIndex<u64>,
    projected_fact_keys: &'a [u64],
    aggregate_reads: &'a GroupedNodeIndex<u32>,
    scalar_writes: &'a GroupedNodeIndex<(u32, Span)>,
    storage_reads: &'a NodeStorageReadIndex,
    storage_writes: &'a NodeStorageWriteIndex,
    fact_sources: PersistedExternalRelation,
    aggregate_inputs: &'a GroupedNodeIndex<NodeId>,
    aggregate_outputs: &'a GroupedNodeIndex<NodeId>,
    resolved_call_args: &'a [WsNodeId],
    reverse_transforms: PersistedExternalRelation,
    reverse_scalar_transforms: PersistedExternalRelation,
    fact_page_entries: &'a [Option<SymbolicFactPageEntry>],
    fact_page_bytes: u64,
    transform_offsets: &'a [u32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSymbolicRuntime {
    version: u32,
    fields: PackedStringTable,
    spans: Box<[SymbolicFactSpan]>,
    ordering_sensitive_bases: Box<[u64]>,
    exact_reads: GroupedNodeIndex<u64>,
    projected_fact_keys: Box<[u64]>,
    aggregate_reads: GroupedNodeIndex<u32>,
    scalar_writes: GroupedNodeIndex<(u32, Span)>,
    storage_reads: NodeStorageReadIndex,
    storage_writes: NodeStorageWriteIndex,
    fact_sources: PersistedExternalRelation,
    aggregate_inputs: GroupedNodeIndex<NodeId>,
    aggregate_outputs: GroupedNodeIndex<NodeId>,
    resolved_call_args: Box<[WsNodeId]>,
    reverse_transforms: PersistedExternalRelation,
    reverse_scalar_transforms: PersistedExternalRelation,
    fact_page_entries: Vec<Option<SymbolicFactPageEntry>>,
    fact_page_bytes: u64,
    transform_offsets: Box<[u32]>,
}

impl Default for SymbolicRuntimeIndex {
    fn default() -> Self {
        Self {
            fields: PackedStringTable::default(),
            spans: Box::new([]),
            ordering_sensitive_bases: Box::new([]),
            base_rebases: SymbolicBaseRebaseIndex::default(),
            exact_reads: GroupedNodeIndex::default(),
            projected_fact_keys: Box::new([]),
            aggregate_reads: GroupedNodeIndex::default(),
            scalar_writes: GroupedNodeIndex::default(),
            storage_reads: NodeStorageReadIndex::default(),
            storage_writes: NodeStorageWriteIndex::default(),
            fact_sources: FactSourceIndex::empty(),
            aggregate_inputs: GroupedNodeIndex::default(),
            aggregate_outputs: GroupedNodeIndex::default(),
            resolved_call_args: Box::new([]),
            reverse_transforms: ReverseSymbolicTransformIndex::empty(),
            reverse_scalar_transforms: ReverseScalarTransformIndex::empty(),
            fact_pages: Mutex::new(SymbolicFactPager::new(0)),
            transforms: Mutex::new(SymbolicTransformPager::empty()),
            field_demands: Mutex::new(AHashMap::default()),
        }
    }
}

impl PersistedSymbolicRuntime {
    fn decode(
        reader: impl std::io::Read,
        mut blobs: AHashMap<QueryAcceleratorBlobKind, QueryAcceleratorBlobReader>,
        workspace: &IdgWorkspace,
        node_count: usize,
    ) -> crate::IdgResult<SymbolicRuntimeIndex> {
        let persisted: Self = bonsai_common::wire::decode_from_reader(reader).map_err(|error| {
            invalid_query_accelerator(format!(
                "workspace IDG symbolic accelerator decode failed: {error}"
            ))
        })?;
        let base_count = workspace.symbolic_field().bases().len();
        let layout_valid = persisted.version == SYMBOLIC_RUNTIME_ACCELERATOR_VERSION
            && persisted.fields.has_valid_layout()
            && persisted.spans.windows(2).all(|pair| pair[0] < pair[1])
            && persisted.ordering_sensitive_bases.len() == base_count.div_ceil(u64::BITS as usize)
            && persisted.exact_reads.has_valid_layout(node_count)
            && persisted
                .projected_fact_keys
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && persisted.projected_fact_keys.iter().all(|key| {
                ((*key >> 32) as usize) < base_count && ((*key as u32) as usize) < persisted.fields.len()
            })
            && persisted.aggregate_reads.has_valid_layout(node_count)
            && persisted.scalar_writes.has_valid_layout(node_count)
            && persisted.storage_reads.is_valid_for(node_count, base_count)
            && persisted
                .storage_writes
                .is_valid_for(node_count, base_count, persisted.spans.len())
            && persisted.aggregate_inputs.has_valid_layout(node_count)
            && persisted.aggregate_outputs.has_valid_layout(node_count)
            && persisted
                .resolved_call_args
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && persisted
                .resolved_call_args
                .iter()
                .all(|node| (node.0 as usize) < node_count)
            && persisted.fact_page_entries.len() == workspace.segment_count()
            && persisted.transform_offsets.len() == base_count.saturating_add(1);
        if !layout_valid {
            return Err(invalid_query_accelerator(
                "workspace IDG symbolic accelerator resident layout mismatch",
            ));
        }
        let mut take_blob = |kind| {
            blobs.remove(&kind).ok_or_else(|| {
                invalid_query_accelerator(format!("workspace IDG symbolic accelerator is missing {kind:?}"))
            })
        };
        let fact_pages = SymbolicFactPager::from_persisted(
            persisted.fact_page_entries,
            persisted.fact_page_bytes,
            take_blob(QueryAcceleratorBlobKind::SymbolicFacts)?,
        )
        .map_err(invalid_query_accelerator)?;
        let transforms = SymbolicTransformPager::from_persisted(
            persisted.transform_offsets,
            take_blob(QueryAcceleratorBlobKind::SymbolicTransforms)?,
        )
        .map_err(invalid_query_accelerator)?;
        let fact_sources = FactSourceIndex::from_persisted(
            persisted.fact_sources,
            take_blob(QueryAcceleratorBlobKind::FactSources)?,
        )
        .map_err(invalid_query_accelerator)?;
        let reverse_transforms = ReverseSymbolicTransformIndex::from_persisted(
            persisted.reverse_transforms,
            take_blob(QueryAcceleratorBlobKind::ReverseSymbolicTransforms)?,
        )
        .map_err(invalid_query_accelerator)?;
        let reverse_scalar_transforms = ReverseScalarTransformIndex::from_persisted(
            persisted.reverse_scalar_transforms,
            take_blob(QueryAcceleratorBlobKind::ReverseScalarTransforms)?,
        )
        .map_err(invalid_query_accelerator)?;
        if !blobs.is_empty() {
            return Err(invalid_query_accelerator(
                "workspace IDG symbolic accelerator has unknown blob relations",
            ));
        }
        let base_rebases = SymbolicBaseRebaseIndex::from_specs(
            SymbolicBaseRebaseIndex::specs(workspace.symbolic_field()),
            &persisted.fields,
        );
        Ok(SymbolicRuntimeIndex {
            fields: persisted.fields,
            spans: persisted.spans,
            ordering_sensitive_bases: persisted.ordering_sensitive_bases,
            base_rebases,
            exact_reads: persisted.exact_reads,
            projected_fact_keys: persisted.projected_fact_keys,
            aggregate_reads: persisted.aggregate_reads,
            scalar_writes: persisted.scalar_writes,
            storage_reads: persisted.storage_reads,
            storage_writes: persisted.storage_writes,
            fact_sources,
            aggregate_inputs: persisted.aggregate_inputs,
            aggregate_outputs: persisted.aggregate_outputs,
            resolved_call_args: persisted.resolved_call_args,
            reverse_transforms,
            reverse_scalar_transforms,
            fact_pages: Mutex::new(fact_pages),
            transforms: Mutex::new(transforms),
            field_demands: Mutex::new(AHashMap::default()),
        })
    }
}

/// Exact field suffixes that can reach some real adapter-lowered projected
/// place through the symbolic transform algebra.
///
/// The relation is compiled backward from the finite syntax fact set.  It is
/// intentionally independent of any source query: callers may carry an
/// aggregate through arbitrarily many wrappers, but a scalar carrier cannot
/// acquire invented descendants merely because the same field spelling exists
/// elsewhere in the workspace.  The sparse set spills exactly when required;
/// representation changes never cap or approximate the fixed point.
struct SymbolicFieldDemand {
    facts: SpillSet,
    wildcard_bases: SpillSet,
}

impl SymbolicFieldDemand {
    fn contains(&self, base: u32, field: u32) -> bool {
        self.wildcard_bases.contains(u128::from(base))
            || self.facts.contains(u128::from(symbolic_fact_key(base, field)))
    }
}

/// Opaque backward relevance proof for one target set.
///
/// The proof is context-insensitive and therefore conservative: it may admit
/// extra states, but it never excludes a realizable contextual path. Exact
/// forward solvers use it only as a demand predicate and still run their
/// admitted relations to fixed point.
pub struct IdgTargetRelevance {
    // Target cuts are commonly tiny even when the persisted workspace IDG is
    // very large. Start with the same sparse, density-promoting set used by
    // forward closures instead of reserving one workspace-sized bitmap per
    // inspect batch. Representation changes never alter membership.
    nodes: RootClosureVisited,
    facts: SpillSet,
    wildcard_bases: SpillSet,
    // `false` means the frontend exposed a projected compiler place without
    // the symbolic access-path fact required to invert it. In that case this
    // relation remains useful for diagnostics, but it is not a proof that an
    // omitted node or fact cannot reach the target. Exact forward closure
    // therefore treats it as non-pruning.
    pruning_complete: bool,
}

impl std::fmt::Debug for IdgTargetRelevance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdgTargetRelevance")
            .field("nodes", &self.nodes.len())
            .field("facts", &self.facts.len())
            .field("wildcard_bases", &self.wildcard_bases.len())
            .field("pruning_complete", &self.pruning_complete)
            .finish()
    }
}

impl IdgTargetRelevance {
    fn contains_node(&self, node: NodeId) -> bool {
        !self.pruning_complete || self.nodes.contains(node)
    }

    fn contains_fact(&self, base: u32, field: u32) -> bool {
        !self.pruning_complete
            || self.wildcard_bases.contains(u128::from(base))
            || self.facts.contains(u128::from(symbolic_fact_key(base, field)))
    }

    /// Whether at least one seed belongs to the conservative backward target
    /// relation. `false` is an exact proof that no contextual target path can
    /// start from these seeds.
    #[must_use]
    pub fn admits_any(&self, seeds: &[WsNodeId]) -> bool {
        seeds.iter().any(|node| self.contains_node(NodeId(node.0)))
    }
}

struct TargetRelevanceWorklist {
    relevance: IdgTargetRelevance,
    pending_nodes: SpillStack,
    pending_facts: SpillStack,
    pending_wildcard_bases: SpillStack,
}

impl TargetRelevanceWorklist {
    fn new(node_count: usize) -> Self {
        Self {
            relevance: IdgTargetRelevance {
                nodes: RootClosureVisited::new(node_count, 0),
                facts: target_relevance_fact_store(),
                wildcard_bases: target_relevance_wildcard_store(),
                pruning_complete: true,
            },
            pending_nodes: target_relevance_frontier_store(),
            pending_facts: target_relevance_frontier_store(),
            pending_wildcard_bases: target_relevance_frontier_store(),
        }
    }

    fn enqueue_node(&mut self, node: NodeId) {
        if self.relevance.nodes.insert(node) {
            self.pending_nodes.push(u128::from(node.0));
        }
    }

    fn enqueue_fact(&mut self, base: u32, field: u32) {
        if self.relevance.wildcard_bases.contains(u128::from(base)) {
            return;
        }
        let key = symbolic_fact_key(base, field);
        if self.relevance.facts.insert(u128::from(key)) {
            self.pending_facts.push(u128::from(key));
        }
    }

    fn enqueue_wildcard_base(&mut self, base: u32) {
        if self.relevance.wildcard_bases.insert(u128::from(base)) {
            self.pending_wildcard_bases.push(u128::from(base));
        }
    }

    fn has_pending(&self) -> bool {
        !self.pending_nodes.is_empty()
            || !self.pending_facts.is_empty()
            || !self.pending_wildcard_bases.is_empty()
    }
}

impl SymbolicRuntimeIndex {
    fn field(&self, id: u32) -> Option<&str> {
        self.fields.get(id)
    }

    fn field_id(&self, field: &str) -> Option<u32> {
        self.fields.find(field)
    }

    fn rebased_field(&self, rebase: SymbolicBaseRebase, field: u32) -> Option<u32> {
        let prefix = self.field(rebase.prefix)?;
        let field = self.field(field)?;
        match rebase.kind {
            SymbolicBaseRebaseKind::PrependPrefix => self.fields.find_joined(prefix, field),
            SymbolicBaseRebaseKind::StripPrefix => field
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_prefix('.'))
                .filter(|rest| !rest.is_empty())
                .and_then(|rest| self.field_id(rest)),
        }
    }

    fn span_id(&self, span: Span) -> Option<u32> {
        self.spans
            .binary_search(&SymbolicFactSpan::from(span))
            .ok()
            .and_then(|index| u32::try_from(index).ok())
    }

    fn span(&self, id: u32) -> Option<SymbolicFactSpan> {
        self.spans.get(id as usize).copied()
    }

    fn retains_local_provenance(&self, base: u32) -> bool {
        let base = base as usize;
        self.ordering_sensitive_bases
            .get(base / u64::BITS as usize)
            .is_some_and(|word| word & (1_u64 << (base % u64::BITS as usize)) != 0)
    }

    fn local_provenance_id(&self, base: u32, span: Span) -> Option<u32> {
        self.retains_local_provenance(base)
            .then(|| self.span_id(span))
            .flatten()
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PackedStringTable {
    bytes: Box<[u8]>,
    offsets: Box<[u32]>,
}

impl PackedStringTable {
    fn from_sorted(strings: Vec<String>) -> Self {
        let total_bytes = strings.iter().map(String::len).sum();
        let mut bytes = Vec::with_capacity(total_bytes);
        let mut offsets = Vec::with_capacity(strings.len().saturating_add(1));
        offsets.push(0);
        for string in strings {
            bytes.extend_from_slice(string.as_bytes());
            offsets.push(u32::try_from(bytes.len()).expect("symbolic field text exceeds u32"));
        }
        Self {
            bytes: bytes.into_boxed_slice(),
            offsets: offsets.into_boxed_slice(),
        }
    }

    fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    fn has_valid_layout(&self) -> bool {
        self.offsets.first().copied() == Some(0)
            && self.offsets.windows(2).all(|pair| pair[0] <= pair[1])
            && self.offsets.last().copied() == u32::try_from(self.bytes.len()).ok()
            && std::str::from_utf8(&self.bytes).is_ok()
            && (0..self.len().saturating_sub(1)).all(|index| {
                self.get_bytes(index as u32)
                    .zip(self.get_bytes(index as u32 + 1))
                    .is_some_and(|(left, right)| left < right)
            })
    }

    fn get(&self, id: u32) -> Option<&str> {
        std::str::from_utf8(self.get_bytes(id)?).ok()
    }

    fn get_bytes(&self, id: u32) -> Option<&[u8]> {
        let index = id as usize;
        let start = *self.offsets.get(index)? as usize;
        let end = *self.offsets.get(index + 1)? as usize;
        Some(&self.bytes[start..end])
    }

    fn find(&self, value: &str) -> Option<u32> {
        let mut low = 0usize;
        let mut high = self.len();
        while low < high {
            let middle = low + (high - low) / 2;
            match self.get_bytes(u32::try_from(middle).ok()?)?.cmp(value.as_bytes()) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return u32::try_from(middle).ok(),
            }
        }
        None
    }

    /// Find `prefix + "." + suffix` without allocating the joined field in
    /// the fixed-point hot path. The table is byte-sorted, so comparing the
    /// candidate against the chained byte iterators preserves binary search.
    fn find_joined(&self, prefix: &str, suffix: &str) -> Option<u32> {
        if prefix.is_empty() || suffix.is_empty() {
            return None;
        }
        let mut low = 0usize;
        let mut high = self.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let candidate = self.get_bytes(u32::try_from(middle).ok()?)?;
            let ordering = candidate.iter().cmp(
                prefix
                    .as_bytes()
                    .iter()
                    .chain(std::iter::once(&b'.'))
                    .chain(suffix.as_bytes()),
            );
            match ordering {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return u32::try_from(middle).ok(),
            }
        }
        None
    }
}

#[derive(Copy, Clone)]
struct SymbolicFactTemplate {
    base: u32,
    field: u32,
    span: u32,
}

struct SymbolicFactPage {
    offsets: Box<[u32]>,
    facts: Box<[SymbolicFactTemplate]>,
}

impl SymbolicFactPage {
    fn get(&self, node: NodeId) -> &[SymbolicFactTemplate] {
        let index = node.0 as usize;
        let Some(&start) = self.offsets.get(index) else {
            return &[];
        };
        let Some(&end) = self.offsets.get(index + 1) else {
            return &[];
        };
        &self.facts[start as usize..end as usize]
    }
}

#[derive(Copy, Clone, serde::Serialize, serde::Deserialize)]
struct SymbolicFactPageEntry {
    offset: u64,
    node_count: u32,
    fact_count: u32,
}

const NO_SYMBOLIC_FACT_SPAN: u32 = u32::MAX;
const SYMBOLIC_FACT_BYTES: usize = 12;

enum SymbolicBlobStorage {
    File(std::fs::File),
    Persisted(QueryAcceleratorBlobReader),
}

impl SymbolicBlobStorage {
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> std::io::Result<()> {
        match self {
            Self::File(file) => read_exact_at(file, offset, output),
            Self::Persisted(blob) => blob
                .read_exact_at(offset, output)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        }
    }

    fn snapshot_file(&self, bytes: u64) -> std::io::Result<Arc<std::fs::File>> {
        let mut file = tempfile::tempfile()?;
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        while offset < bytes {
            let take = usize::try_from((bytes - offset).min(buffer.len() as u64))
                .expect("symbolic blob page fits usize");
            self.read_exact_at(offset, &mut buffer[..take])?;
            file.write_all(&buffer[..take])?;
            offset = offset.saturating_add(take as u64);
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(Arc::new(file))
    }
}

struct SymbolicFactPager {
    storage: SymbolicBlobStorage,
    entries: Vec<Option<SymbolicFactPageEntry>>,
    write_offset: u64,
    pages: AHashMap<SegmentId, Arc<SymbolicFactPage>>,
    order: VecDeque<SegmentId>,
    capacity: usize,
}

impl SymbolicFactPager {
    fn new(segment_count: usize) -> Self {
        let workers = bonsai_common::compiler_worker_count(rayon::current_num_threads());
        Self {
            storage: SymbolicBlobStorage::File(
                tempfile::tempfile().expect("create symbolic fact page spool"),
            ),
            entries: vec![None; segment_count],
            write_offset: 0,
            pages: AHashMap::default(),
            order: VecDeque::new(),
            capacity: workers.saturating_mul(2).max(2),
        }
    }

    fn snapshot_file(&self) -> std::io::Result<Arc<std::fs::File>> {
        self.storage.snapshot_file(self.write_offset)
    }

    fn from_persisted(
        entries: Vec<Option<SymbolicFactPageEntry>>,
        bytes: u64,
        storage: QueryAcceleratorBlobReader,
    ) -> Result<Self, &'static str> {
        if storage.len() != bytes
            || entries.iter().flatten().any(|entry| {
                let offsets = u64::from(entry.node_count).saturating_add(1).saturating_mul(4);
                let facts = u64::from(entry.fact_count).saturating_mul(SYMBOLIC_FACT_BYTES as u64);
                entry
                    .offset
                    .checked_add(offsets.saturating_add(facts))
                    .is_none_or(|end| end > bytes)
            })
        {
            return Err("symbolic fact page layout");
        }
        let workers = bonsai_common::compiler_worker_count(rayon::current_num_threads());
        Ok(Self {
            storage: SymbolicBlobStorage::Persisted(storage),
            entries,
            write_offset: bytes,
            pages: AHashMap::default(),
            order: VecDeque::new(),
            capacity: workers.saturating_mul(2).max(2),
        })
    }

    fn write_page(&mut self, segment: SegmentId, page: &SymbolicFactPage) {
        let index = segment.0 as usize;
        if self.entries.len() <= index {
            self.entries.resize(index + 1, None);
        }
        let mut payload = Vec::with_capacity(
            page.offsets
                .len()
                .saturating_mul(std::mem::size_of::<u32>())
                .saturating_add(page.facts.len().saturating_mul(SYMBOLIC_FACT_BYTES)),
        );
        for offset in &page.offsets {
            payload.extend_from_slice(&offset.to_le_bytes());
        }
        for fact in &page.facts {
            payload.extend_from_slice(&fact.base.to_le_bytes());
            payload.extend_from_slice(&fact.field.to_le_bytes());
            payload.extend_from_slice(&fact.span.to_le_bytes());
        }
        let SymbolicBlobStorage::File(file) = &mut self.storage else {
            panic!("persisted symbolic fact pages are immutable");
        };
        file.seek(SeekFrom::Start(self.write_offset))
            .expect("seek symbolic fact page spool");
        file.write_all(&payload).expect("write symbolic fact page spool");
        self.entries[index] = Some(SymbolicFactPageEntry {
            offset: self.write_offset,
            node_count: u32::try_from(page.offsets.len().saturating_sub(1))
                .expect("symbolic fact node count exceeds u32"),
            fact_count: u32::try_from(page.facts.len()).expect("symbolic fact count exceeds u32"),
        });
        self.write_offset = self
            .write_offset
            .saturating_add(u64::try_from(payload.len()).expect("symbolic fact payload exceeds u64"));
    }

    fn page(&mut self, segment: SegmentId) -> Option<Arc<SymbolicFactPage>> {
        if let Some(page) = self.pages.get(&segment) {
            return Some(Arc::clone(page));
        }
        let entry = self.entries.get(segment.0 as usize).copied().flatten()?;
        let offset_count = usize::try_from(entry.node_count).ok()?.saturating_add(1);
        let fact_count = usize::try_from(entry.fact_count).ok()?;
        let payload_len = offset_count
            .checked_mul(std::mem::size_of::<u32>())?
            .checked_add(fact_count.checked_mul(SYMBOLIC_FACT_BYTES)?)?;
        let mut payload = vec![0_u8; payload_len];
        self.storage.read_exact_at(entry.offset, &mut payload).ok()?;
        let mut offsets = Vec::with_capacity(offset_count);
        for bytes in payload[..offset_count * 4].chunks_exact(4) {
            offsets.push(u32::from_le_bytes(bytes.try_into().ok()?));
        }
        let mut facts = Vec::with_capacity(fact_count);
        for record in payload[offset_count * 4..].chunks_exact(SYMBOLIC_FACT_BYTES) {
            let word = |start| u32::from_le_bytes(record[start..start + 4].try_into().expect("fact word"));
            facts.push(SymbolicFactTemplate {
                base: word(0),
                field: word(4),
                span: word(8),
            });
        }
        let page = Arc::new(SymbolicFactPage {
            offsets: offsets.into_boxed_slice(),
            facts: facts.into_boxed_slice(),
        });
        while self.pages.len() >= self.capacity {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            self.pages.remove(&evicted);
        }
        self.order.push_back(segment);
        self.pages.insert(segment, Arc::clone(&page));
        Some(page)
    }
}

const SYMBOLIC_TRANSFORM_BYTES: usize = 60;
const SYMBOLIC_TRANSFORM_RUN_BYTES: usize = 72;
const SYMBOLIC_TRANSFORM_RUN_ROWS: usize = 100_000;
const SYMBOLIC_TRANSFORM_READ_ROWS: usize = 1_024;

#[derive(Copy, Clone)]
struct SymbolicTransformRunEntry {
    offset: u64,
    count: u32,
}

#[derive(Copy, Clone)]
struct SymbolicTransformRunRow {
    source: u32,
    ordinal: u64,
    transform: crate::symbolic::SymbolicFieldTransform,
}

impl PartialEq for SymbolicTransformRunRow {
    fn eq(&self, other: &Self) -> bool {
        (self.source, self.ordinal) == (other.source, other.ordinal)
    }
}

impl Eq for SymbolicTransformRunRow {}

impl PartialOrd for SymbolicTransformRunRow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymbolicTransformRunRow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.source, self.ordinal).cmp(&(other.source, other.ordinal))
    }
}

fn encode_precision(precision: Precision) -> u8 {
    precision.rank()
}

fn decode_precision(value: u8) -> Precision {
    match value {
        0 => Precision::Exact,
        1 => Precision::Narrowed,
        2 => Precision::OverApproximate,
        3 => Precision::Unknown,
        _ => panic!("invalid compact symbolic precision"),
    }
}

fn encode_call_kind(kind: CallEdgeKind) -> u8 {
    match kind {
        CallEdgeKind::Direct => 0,
        CallEdgeKind::Virtual => 1,
        CallEdgeKind::Indirect => 2,
        CallEdgeKind::Unknown => 3,
    }
}

fn decode_call_kind(value: u8) -> CallEdgeKind {
    match value {
        0 => CallEdgeKind::Direct,
        1 => CallEdgeKind::Virtual,
        2 => CallEdgeKind::Indirect,
        3 => CallEdgeKind::Unknown,
        _ => panic!("invalid compact symbolic call kind"),
    }
}

fn encode_transform_kind(kind: SymbolicFieldTransformKind) -> u8 {
    kind as u8
}

fn decode_transform_kind(value: u8) -> SymbolicFieldTransformKind {
    match value {
        0 => SymbolicFieldTransformKind::Argument,
        1 => SymbolicFieldTransformKind::Return,
        2 => SymbolicFieldTransformKind::ScalarReturn,
        3 => SymbolicFieldTransformKind::ConstructorReturn,
        4 => SymbolicFieldTransformKind::ReceiverMutation,
        5 => SymbolicFieldTransformKind::Copy,
        _ => panic!("invalid compact symbolic transform kind"),
    }
}

fn encode_symbolic_transform(out: &mut Vec<u8>, transform: &crate::symbolic::SymbolicFieldTransform) {
    out.extend_from_slice(&transform.target.to_le_bytes());
    out.extend_from_slice(&transform.exact_field.to_le_bytes());
    out.extend_from_slice(&transform.call_span.file.raw().to_le_bytes());
    out.extend_from_slice(&transform.call_span.start.to_le_bytes());
    out.extend_from_slice(&transform.call_span.end.to_le_bytes());
    out.extend_from_slice(&transform.write_span.file.raw().to_le_bytes());
    out.extend_from_slice(&transform.write_span.start.to_le_bytes());
    out.extend_from_slice(&transform.write_span.end.to_le_bytes());
    out.push(encode_precision(transform.precision));
    out.push(encode_call_kind(transform.call_kind));
    out.push(encode_transform_kind(transform.kind));
    out.extend_from_slice(&transform.arg_idx.to_le_bytes());
    out.extend_from_slice(&transform.param_idx.to_le_bytes());
    out.push(u8::from(transform.allow_out_of_order_source));
}

fn decode_symbolic_transform(record: &[u8], source: u32) -> crate::symbolic::SymbolicFieldTransform {
    debug_assert_eq!(record.len(), SYMBOLIC_TRANSFORM_BYTES);
    let word = |start| u32::from_le_bytes(record[start..start + 4].try_into().expect("word bytes"));
    let wide = |start| u64::from_le_bytes(record[start..start + 8].try_into().expect("wide bytes"));
    crate::symbolic::SymbolicFieldTransform {
        source,
        target: word(0),
        exact_field: word(4),
        call_span: Span::new(FileId::new(word(8)), wide(12), wide(20)),
        write_span: Span::new(FileId::new(word(28)), wide(32), wide(40)),
        precision: decode_precision(record[48]),
        call_kind: decode_call_kind(record[49]),
        kind: decode_transform_kind(record[50]),
        arg_idx: word(51),
        param_idx: word(55),
        allow_out_of_order_source: record[59] != 0,
    }
}

/// Bounded external sort for the compiler's symbolic transform relation.
/// The source sidecar is streamed once; no workspace-sized Rust transform
/// vector is retained while the exact source-grouped binary relation is built.
struct SymbolicTransformSpool {
    file: std::fs::File,
    write_offset: u64,
    runs: Vec<SymbolicTransformRunEntry>,
    buffer: Vec<SymbolicTransformRunRow>,
    next_ordinal: u64,
}

impl SymbolicTransformSpool {
    fn new() -> Self {
        Self {
            file: tempfile::tempfile().expect("create symbolic transform run spool"),
            write_offset: 0,
            runs: Vec::new(),
            buffer: Vec::with_capacity(SYMBOLIC_TRANSFORM_RUN_ROWS),
            next_ordinal: 0,
        }
    }

    fn push(&mut self, transform: crate::symbolic::SymbolicFieldTransform) {
        self.buffer.push(SymbolicTransformRunRow {
            source: transform.source,
            ordinal: self.next_ordinal,
            transform,
        });
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .expect("symbolic transform count exceeds u64");
        if self.buffer.len() == SYMBOLIC_TRANSFORM_RUN_ROWS {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        self.buffer.sort_unstable();
        let mut payload = Vec::with_capacity(self.buffer.len().saturating_mul(SYMBOLIC_TRANSFORM_RUN_BYTES));
        for row in &self.buffer {
            payload.extend_from_slice(&row.source.to_le_bytes());
            payload.extend_from_slice(&row.ordinal.to_le_bytes());
            encode_symbolic_transform(&mut payload, &row.transform);
        }
        debug_assert_eq!(payload.len(), self.buffer.len() * SYMBOLIC_TRANSFORM_RUN_BYTES);
        self.file
            .seek(SeekFrom::Start(self.write_offset))
            .expect("seek symbolic transform run spool");
        self.file
            .write_all(&payload)
            .expect("write symbolic transform run spool");
        self.runs.push(SymbolicTransformRunEntry {
            offset: self.write_offset,
            count: u32::try_from(self.buffer.len()).expect("symbolic transform run exceeds u32"),
        });
        self.write_offset = self
            .write_offset
            .saturating_add(u64::try_from(payload.len()).expect("symbolic transform payload exceeds u64"));
        self.buffer.clear();
    }

    fn finish(mut self) -> SymbolicTransformRunMerger {
        self.flush();
        let file = self.file;
        let runs = self.runs;
        SymbolicTransformRunMerger::new(file, &runs)
    }
}

struct SymbolicTransformRunReader {
    file: Arc<std::fs::File>,
    offset: u64,
    remaining: u32,
    buffer: Vec<u8>,
    position: usize,
    page_rows: usize,
}

impl SymbolicTransformRunReader {
    fn refill(&mut self) {
        let records = usize::try_from(self.remaining)
            .expect("symbolic transform run length fits usize")
            .min(self.page_rows);
        self.buffer
            .resize(records.saturating_mul(SYMBOLIC_TRANSFORM_RUN_BYTES), 0);
        read_exact_at(self.file.as_ref(), self.offset, &mut self.buffer)
            .expect("read sorted symbolic transform run page");
        self.offset = self
            .offset
            .saturating_add(u64::try_from(self.buffer.len()).expect("symbolic transform page fits u64"));
        self.position = 0;
    }

    fn next(&mut self) -> Option<SymbolicTransformRunRow> {
        if self.remaining == 0 {
            return None;
        }
        if self.position == self.buffer.len() {
            self.refill();
        }
        let end = self.position.saturating_add(SYMBOLIC_TRANSFORM_RUN_BYTES);
        let record = &self.buffer[self.position..end];
        self.position = end;
        self.remaining -= 1;
        let source = u32::from_le_bytes(record[0..4].try_into().expect("source bytes"));
        let ordinal = u64::from_le_bytes(record[4..12].try_into().expect("ordinal bytes"));
        Some(SymbolicTransformRunRow {
            source,
            ordinal,
            transform: decode_symbolic_transform(&record[12..], source),
        })
    }
}

struct SymbolicTransformRunMerger {
    readers: Vec<SymbolicTransformRunReader>,
    pending: BinaryHeap<Reverse<(SymbolicTransformRunRow, usize)>>,
}

impl SymbolicTransformRunMerger {
    fn new(file: std::fs::File, runs: &[SymbolicTransformRunEntry]) -> Self {
        let file = Arc::new(file);
        let page_rows = merge_page_rows(
            runs.len(),
            SYMBOLIC_TRANSFORM_RUN_BYTES,
            SYMBOLIC_TRANSFORM_READ_ROWS,
        );
        let mut readers = Vec::with_capacity(runs.len());
        for run in runs {
            readers.push(SymbolicTransformRunReader {
                file: Arc::clone(&file),
                offset: run.offset,
                remaining: run.count,
                buffer: Vec::new(),
                position: 0,
                page_rows,
            });
        }
        let mut pending = BinaryHeap::new();
        for (index, reader) in readers.iter_mut().enumerate() {
            if let Some(row) = reader.next() {
                pending.push(Reverse((row, index)));
            }
        }
        Self { readers, pending }
    }
}

impl Iterator for SymbolicTransformRunMerger {
    type Item = SymbolicTransformRunRow;

    fn next(&mut self) -> Option<Self::Item> {
        let Reverse((row, reader_index)) = self.pending.pop()?;
        if let Some(next) = self.readers[reader_index].next() {
            self.pending.push(Reverse((next, reader_index)));
        }
        Some(row)
    }
}

/// Exact source-indexed transform pages used by symbolic closure. The offsets
/// stay resident; fixed-width rows page from an anonymous temporary file, so
/// available memory affects cache locality rather than semantic coverage.
struct SymbolicTransformPager {
    storage: SymbolicBlobStorage,
    offsets: Box<[u32]>,
    pages: AHashMap<u32, Arc<Vec<crate::symbolic::SymbolicFieldTransform>>>,
    order: VecDeque<u32>,
    capacity: usize,
}

impl SymbolicTransformPager {
    fn empty() -> Self {
        Self {
            storage: SymbolicBlobStorage::File(
                tempfile::tempfile().expect("create empty symbolic transform relation"),
            ),
            offsets: Box::new([0]),
            pages: AHashMap::default(),
            order: VecDeque::new(),
            capacity: 2,
        }
    }

    fn snapshot_file(&self) -> std::io::Result<Arc<std::fs::File>> {
        let rows = self.offsets.last().copied().unwrap_or(0);
        self.storage
            .snapshot_file(u64::from(rows).saturating_mul(SYMBOLIC_TRANSFORM_BYTES as u64))
    }

    fn from_persisted(
        offsets: Box<[u32]>,
        storage: QueryAcceleratorBlobReader,
    ) -> Result<Self, &'static str> {
        let rows = offsets.last().copied().unwrap_or(0);
        if offsets.is_empty()
            || offsets.first().copied() != Some(0)
            || offsets.windows(2).any(|pair| pair[0] > pair[1])
            || storage.len() != u64::from(rows).saturating_mul(SYMBOLIC_TRANSFORM_BYTES as u64)
        {
            return Err("symbolic transform page layout");
        }
        let workers = bonsai_common::compiler_worker_count(rayon::current_num_threads());
        Ok(Self {
            storage: SymbolicBlobStorage::Persisted(storage),
            offsets,
            pages: AHashMap::default(),
            order: VecDeque::new(),
            capacity: workers.saturating_mul(2).max(2),
        })
    }

    fn build(
        workspace: &IdgWorkspace,
        base_count: usize,
        fact_spans: &mut AHashSet<SymbolicFactSpan>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> (
        Self,
        ReverseSymbolicTransformIndex,
        ReverseScalarTransformIndex,
        Box<[u64]>,
    ) {
        let mut spool = SymbolicTransformSpool::new();
        let mut reverse = ReverseSymbolicTransformSpool::new();
        let mut reverse_scalar = ReverseScalarTransformSpool::new();
        let mut ordering_sensitive_bases = vec![0_u64; base_count.div_ceil(u64::BITS as usize)];
        let bases = workspace.symbolic_field().bases();
        workspace
            .visit_symbolic_transforms(|transforms| {
                for &transform in transforms {
                    let source = transform.source as usize;
                    assert!(
                        source < base_count,
                        "symbolic transform source exceeds base dictionary"
                    );
                    if allowed_funcs.is_some_and(|allowed| {
                        !bases.get(source).is_some_and(|base| allowed.contains(&base.func))
                            || !bases
                                .get(transform.target as usize)
                                .is_some_and(|base| allowed.contains(&base.func))
                    }) {
                        continue;
                    }
                    if !transform.allow_out_of_order_source {
                        ordering_sensitive_bases[source / u64::BITS as usize] |=
                            1_u64 << (source % u64::BITS as usize);
                    }
                    fact_spans.insert(SymbolicFactSpan::from(transform.write_span));
                    if transform.kind == SymbolicFieldTransformKind::ScalarReturn {
                        reverse_scalar.push(
                            transform.target,
                            transform.write_span,
                            transform.source,
                            transform.exact_field,
                            transform.precision,
                        );
                    } else {
                        assert!(
                            (transform.target as usize) < base_count,
                            "reverse symbolic transform target exceeds base dictionary"
                        );
                        reverse.push(
                            transform.target,
                            transform.source,
                            transform.precision,
                            transform.kind,
                        );
                    }
                    spool.push(transform);
                }
                Ok(())
            })
            .expect("validated IDG symbolic relation remains readable");

        let mut file = tempfile::tempfile().expect("create compact symbolic transform relation");
        let mut offsets = vec![0_u32; base_count.saturating_add(1)];
        let mut next_base = 0usize;
        let mut count = 0_u32;
        let mut payload = Vec::with_capacity(SYMBOLIC_TRANSFORM_READ_ROWS * SYMBOLIC_TRANSFORM_BYTES);
        for row in spool.finish() {
            let source = row.source as usize;
            assert!(
                source < base_count,
                "symbolic transform source exceeds base dictionary"
            );
            while next_base <= source {
                offsets[next_base] = count;
                next_base += 1;
            }
            encode_symbolic_transform(&mut payload, &row.transform);
            count = count
                .checked_add(1)
                .expect("symbolic transform count exceeds u32");
            if payload.len() >= SYMBOLIC_TRANSFORM_READ_ROWS * SYMBOLIC_TRANSFORM_BYTES {
                file.write_all(&payload)
                    .expect("write compact symbolic transforms");
                payload.clear();
            }
        }
        file.write_all(&payload)
            .expect("write final compact symbolic transforms");
        while next_base < offsets.len() {
            offsets[next_base] = count;
            next_base += 1;
        }
        let workers = bonsai_common::compiler_worker_count(rayon::current_num_threads());
        (
            Self {
                storage: SymbolicBlobStorage::File(file),
                offsets: offsets.into_boxed_slice(),
                pages: AHashMap::default(),
                order: VecDeque::new(),
                capacity: workers.saturating_mul(2).max(2),
            },
            reverse.finish(),
            reverse_scalar.finish(),
            ordering_sensitive_bases.into_boxed_slice(),
        )
    }

    fn outgoing(&mut self, source: u32) -> Arc<Vec<crate::symbolic::SymbolicFieldTransform>> {
        if let Some(page) = self.pages.get(&source) {
            return Arc::clone(page);
        }
        let index = source as usize;
        let Some((&start, &end)) = self.offsets.get(index).zip(self.offsets.get(index + 1)) else {
            return Arc::new(Vec::new());
        };
        let count = (end - start) as usize;
        let mut payload = vec![0_u8; count.saturating_mul(SYMBOLIC_TRANSFORM_BYTES)];
        if !payload.is_empty() {
            self.storage
                .read_exact_at(u64::from(start) * SYMBOLIC_TRANSFORM_BYTES as u64, &mut payload)
                .expect("read compact symbolic transforms");
        }
        let mut transforms = Vec::with_capacity(count);
        for record in payload.chunks_exact(SYMBOLIC_TRANSFORM_BYTES) {
            transforms.push(decode_symbolic_transform(record, source));
        }
        let page = Arc::new(transforms);
        self.pages.insert(source, Arc::clone(&page));
        self.order.push_back(source);
        while self.pages.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.pages.remove(&evicted);
            }
        }
        page
    }
}

#[cfg(test)]
mod compact_symbolic_transform_tests {
    use super::*;

    fn transform(
        source: u32,
        target: u32,
        precision: Precision,
        call_kind: CallEdgeKind,
        kind: SymbolicFieldTransformKind,
    ) -> crate::symbolic::SymbolicFieldTransform {
        crate::symbolic::SymbolicFieldTransform {
            source,
            target,
            exact_field: target.wrapping_add(17),
            call_span: Span::new(FileId::new(target.wrapping_add(3)), 19, u64::from(target) + 41),
            write_span: Span::new(FileId::new(target.wrapping_add(5)), 23, u64::from(target) + 47),
            precision,
            call_kind,
            kind,
            arg_idx: target.wrapping_add(7),
            param_idx: target.wrapping_add(11),
            allow_out_of_order_source: target.is_multiple_of(2),
        }
    }

    #[test]
    fn compact_symbolic_transform_round_trips_every_algebraic_variant() {
        let precisions = [
            Precision::Exact,
            Precision::Narrowed,
            Precision::OverApproximate,
            Precision::Unknown,
        ];
        let call_kinds = [
            CallEdgeKind::Direct,
            CallEdgeKind::Virtual,
            CallEdgeKind::Indirect,
            CallEdgeKind::Unknown,
        ];
        let transform_kinds = [
            SymbolicFieldTransformKind::Argument,
            SymbolicFieldTransformKind::Return,
            SymbolicFieldTransformKind::ScalarReturn,
            SymbolicFieldTransformKind::ConstructorReturn,
            SymbolicFieldTransformKind::ReceiverMutation,
            SymbolicFieldTransformKind::Copy,
        ];
        for (index, ((precision, call_kind), kind)) in precisions
            .into_iter()
            .cycle()
            .zip(call_kinds.into_iter().cycle())
            .zip(transform_kinds)
            .enumerate()
        {
            let expected = transform(13, index as u32 + 29, precision, call_kind, kind);
            let mut encoded = Vec::new();
            encode_symbolic_transform(&mut encoded, &expected);
            assert_eq!(encoded.len(), SYMBOLIC_TRANSFORM_BYTES);
            assert_eq!(decode_symbolic_transform(&encoded, expected.source), expected);
        }
    }

    #[test]
    fn symbolic_transform_external_sort_merges_across_run_boundaries() {
        let row_count = SYMBOLIC_TRANSFORM_RUN_ROWS + 37;
        let mut spool = SymbolicTransformSpool::new();
        for index in 0..row_count {
            let source = ((row_count - index) % 97) as u32;
            spool.push(transform(
                source,
                index as u32,
                Precision::Narrowed,
                CallEdgeKind::Direct,
                SymbolicFieldTransformKind::Copy,
            ));
        }
        let rows: Vec<_> = spool.finish().collect();
        assert_eq!(rows.len(), row_count);
        assert!(rows
            .windows(2)
            .all(|pair| { (pair[0].source, pair[0].ordinal) < (pair[1].source, pair[1].ordinal) }));
        assert!(rows.iter().all(|row| row.source == row.transform.source));
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct ContextBoundaryKey {
    caller: FuncId,
    callee: FuncId,
    span: Span,
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ContextBoundaryEdge {
    key: ContextBoundaryKey,
    target: NodeId,
    /// Renderable source-level boundary represented by this transition.
    /// Exception edges intentionally remain `None`: they participate in the
    /// contextual fixed point but are not ordinary call/return trace hops.
    cross_call: Option<CrossCallEdge>,
}

/// Compact exact `(caller, call site) -> callee` boundary relation.
///
/// Millions of call sites must not become one hash bucket plus one heap
/// allocation each. Canonical sorted rows support logarithmic site lookup and
/// contiguous callee iteration while retaining the same structural endpoint
/// facts.
struct StructuralBoundaryIndex {
    rows: Vec<ContextBoundaryKey>,
}

impl StructuralBoundaryIndex {
    fn new(mut rows: Vec<ContextBoundaryKey>) -> Self {
        rows.sort_unstable_by_key(|key| (key.caller.raw(), key.span, key.callee.raw()));
        rows.dedup_by_key(|key| (key.caller, key.span, key.callee));
        Self { rows }
    }

    fn for_site(&self, caller: FuncId, span: Span) -> &[ContextBoundaryKey] {
        let site = (caller.raw(), span);
        let start = self
            .rows
            .partition_point(|key| (key.caller.raw(), key.span) < site);
        let end = self
            .rows
            .partition_point(|key| (key.caller.raw(), key.span) <= site);
        &self.rows[start..end]
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SparseContextEdges {
    /// Boundaries grouped by the parallel source/offset directory. Source ids
    /// are not repeated in every retained edge.
    edges: Vec<ContextBoundaryEdge>,
    /// One entry per distinct source and a terminal offset.
    sources: Vec<NodeId>,
    offsets: Vec<u32>,
}

const CONTEXTUAL_BOUNDARY_RECORD_BYTES: usize = std::mem::size_of::<u32>() + CONTEXTUAL_BOUNDARY_EDGE_BYTES;
const CONTEXTUAL_BOUNDARY_RUN_ROWS: usize = 65_536;

/// One globally sortable contextual boundary row.
///
/// Equality intentionally matches [`SparseContextEdges::from_rows`]: source,
/// compiler boundary identity, and target define one semantic transition.
/// Renderable evidence is payload on that transition, not an additional
/// graph edge.
#[derive(Copy, Clone)]
struct ContextBoundaryRecord {
    source: NodeId,
    edge: ContextBoundaryEdge,
}

impl ContextBoundaryRecord {
    fn cmp_key(&self, other: &Self) -> std::cmp::Ordering {
        self.source
            .0
            .cmp(&other.source.0)
            .then(self.edge.key.caller.raw().cmp(&other.edge.key.caller.raw()))
            .then(self.edge.key.callee.raw().cmp(&other.edge.key.callee.raw()))
            .then(self.edge.key.span.cmp(&other.edge.key.span))
            .then(self.edge.target.0.cmp(&other.edge.target.0))
    }
}

impl PartialEq for ContextBoundaryRecord {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_key(other).is_eq()
    }
}

impl Eq for ContextBoundaryRecord {}

impl PartialOrd for ContextBoundaryRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ContextBoundaryRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cmp_key(other)
    }
}

impl ExternalRecord for ContextBoundaryRecord {
    const BYTES: usize = CONTEXTUAL_BOUNDARY_RECORD_BYTES;

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.source.0.to_le_bytes());
        encode_context_boundary_edge(output, &self.edge);
    }

    fn decode(record: &[u8]) -> Self {
        Self {
            source: NodeId(u32::from_le_bytes(
                record[..4].try_into().expect("boundary source bytes"),
            )),
            edge: decode_context_boundary_edge(&record[4..]),
        }
    }
}

struct ContextBoundarySpool(ExternalSorter<ContextBoundaryRecord>);

impl ContextBoundarySpool {
    fn new() -> Self {
        Self(ExternalSorter::new(CONTEXTUAL_BOUNDARY_RUN_ROWS))
    }

    fn push(&mut self, source: NodeId, edge: ContextBoundaryEdge) {
        self.0.push(ContextBoundaryRecord { source, edge });
    }

    fn finish(self, include_reverse: bool) -> (SparseContextEdges, Vec<(NodeId, WsNodeId)>) {
        let relation = self.0.finish();
        let capacity = usize::try_from(relation.len()).expect("context boundary row count exceeds usize");
        let mut edges = Vec::with_capacity(capacity);
        let mut sources = Vec::new();
        let mut offsets = Vec::new();
        let mut reverse = if include_reverse {
            Vec::with_capacity(capacity)
        } else {
            Vec::new()
        };
        relation.visit_range(0, relation.len(), |record| {
            if sources.last() != Some(&record.source) {
                sources.push(record.source);
                offsets.push(u32::try_from(edges.len()).expect("context boundary row count exceeds u32"));
            }
            if include_reverse {
                reverse.push((record.edge.target, WsNodeId(record.source.0)));
            }
            edges.push(record.edge);
        });
        offsets.push(u32::try_from(edges.len()).expect("context boundary row count exceeds u32"));
        (
            SparseContextEdges {
                edges,
                sources,
                offsets,
            },
            reverse,
        )
    }
}

enum ContextBoundaryRows {
    Resident(Vec<(NodeId, ContextBoundaryEdge)>),
    External {
        rows: ContextBoundarySpool,
        pushed: usize,
    },
}

impl ContextBoundaryRows {
    fn new(external: bool) -> Self {
        if external {
            Self::External {
                rows: ContextBoundarySpool::new(),
                pushed: 0,
            }
        } else {
            Self::Resident(Vec::new())
        }
    }

    fn push(&mut self, row: (NodeId, ContextBoundaryEdge)) {
        match self {
            Self::Resident(rows) => rows.push(row),
            Self::External { rows, pushed } => {
                rows.push(row.0, row.1);
                *pushed = pushed.saturating_add(1);
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Resident(rows) => rows.len(),
            Self::External { pushed, .. } => *pushed,
        }
    }

    fn finish(self, include_reverse: bool) -> (SparseContextEdges, Vec<(NodeId, WsNodeId)>) {
        match self {
            Self::External { rows, .. } => rows.finish(include_reverse),
            Self::Resident(rows) => {
                let reverse = if include_reverse {
                    rows.iter()
                        .map(|(source, edge)| (edge.target, WsNodeId(source.0)))
                        .collect()
                } else {
                    Vec::new()
                };
                (SparseContextEdges::from_rows(rows), reverse)
            }
        }
    }
}

#[derive(Copy, Clone)]
enum BoundaryEvidenceDirection {
    CallerToCallee,
    CalleeToCaller,
}

#[derive(Copy, Clone, serde::Serialize, serde::Deserialize)]
struct HeapBoundaryEdge {
    target: WsNodeId,
    cross_call: Option<CrossCallEdge>,
}

/// Compact projected-heap relation keyed by its workspace source node.
/// Projected call/return boundaries retain their source-level provenance in
/// the same row so evidence collection never needs a second segment scan.
#[derive(serde::Serialize, serde::Deserialize)]
struct SparseHeapEdges {
    edges: Vec<HeapBoundaryEdge>,
    sources: Vec<NodeId>,
    offsets: Vec<u32>,
}

impl SparseHeapEdges {
    fn from_rows(mut rows: Vec<(NodeId, HeapBoundaryEdge)>) -> Self {
        rows.sort_unstable_by_key(|(source, edge)| {
            let call_key = edge.cross_call.map(|call| {
                (
                    call.caller.raw(),
                    call.callee.raw(),
                    call.call_span,
                    call.arg_idx,
                    call.param_idx,
                    call.precision,
                    call.relation,
                )
            });
            (source.0, edge.target.0, call_key)
        });
        rows.dedup_by_key(|(source, edge)| (*source, edge.target, edge.cross_call));
        let mut sources = Vec::new();
        let mut offsets = Vec::new();
        let mut edges = Vec::with_capacity(rows.len());
        for (source, edge) in rows {
            if sources.last() != Some(&source) {
                sources.push(source);
                offsets.push(u32::try_from(edges.len()).expect("heap boundary row count exceeds u32"));
            }
            edges.push(edge);
        }
        offsets.push(u32::try_from(edges.len()).expect("heap boundary row count exceeds u32"));
        Self {
            edges,
            sources,
            offsets,
        }
    }

    fn get(&self, source: NodeId) -> &[HeapBoundaryEdge] {
        let Some(index) = self.sources.binary_search_by_key(&source.0, |node| node.0).ok() else {
            return &[];
        };
        &self.edges[self.offsets[index] as usize..self.offsets[index + 1] as usize]
    }

    fn is_valid_for(&self, node_count: usize, func_segments: &[u32]) -> bool {
        strictly_sorted_node_ids(&self.sources)
            && self.offsets.len() == self.sources.len().saturating_add(1)
            && offsets_are_valid(&self.offsets, self.edges.len())
            && self.sources.iter().all(|node| (node.0 as usize) < node_count)
            && self.edges.iter().all(|edge| {
                (edge.target.0 as usize) < node_count
                    && edge
                        .cross_call
                        .is_none_or(|call| cross_call_is_valid(call, func_segments))
            })
    }
}

impl SparseContextEdges {
    fn from_rows(mut rows: Vec<(NodeId, ContextBoundaryEdge)>) -> Self {
        rows.sort_unstable_by_key(|(source, edge)| {
            (
                source.0,
                edge.key.caller.0,
                edge.key.callee.0,
                edge.key.span,
                edge.target.0,
            )
        });
        rows.dedup_by_key(|(source, edge)| (*source, edge.key, edge.target));
        let mut sources = Vec::new();
        let mut offsets = Vec::new();
        let mut edges = Vec::with_capacity(rows.len());
        for (source, edge) in rows {
            if sources.last() != Some(&source) {
                sources.push(source);
                offsets.push(u32::try_from(edges.len()).expect("context boundary row count exceeds u32"));
            }
            edges.push(edge);
        }
        offsets.push(u32::try_from(edges.len()).expect("context boundary row count exceeds u32"));
        Self {
            edges,
            sources,
            offsets,
        }
    }

    fn get(&self, source: NodeId) -> impl Iterator<Item = &ContextBoundaryEdge> {
        let range = self
            .sources
            .binary_search_by_key(&source.0, |node| node.0)
            .ok()
            .map(|index| self.offsets[index] as usize..self.offsets[index + 1] as usize)
            .unwrap_or(0..0);
        self.edges[range].iter()
    }

    fn is_valid_for(
        &self,
        node_count: usize,
        func_segments: &[u32],
        evidence_direction: BoundaryEvidenceDirection,
    ) -> bool {
        strictly_sorted_node_ids(&self.sources)
            && self.offsets.len() == self.sources.len().saturating_add(1)
            && offsets_are_valid(&self.offsets, self.edges.len())
            && self.sources.iter().all(|node| (node.0 as usize) < node_count)
            && self.edges.iter().all(|edge| {
                let key_valid = func_is_in_workspace(edge.key.caller, func_segments)
                    && func_is_in_workspace(edge.key.callee, func_segments);
                let evidence_valid = edge.cross_call.is_none_or(|call| {
                    let endpoints_match = match evidence_direction {
                        BoundaryEvidenceDirection::CallerToCallee => {
                            call.caller == edge.key.caller && call.callee == edge.key.callee
                        }
                        BoundaryEvidenceDirection::CalleeToCaller => {
                            call.caller == edge.key.callee && call.callee == edge.key.caller
                        }
                    };
                    cross_call_is_valid(call, func_segments)
                        && endpoints_match
                        && call.call_span == edge.key.span
                });
                key_valid && evidence_valid && (edge.target.0 as usize) < node_count
            })
    }
}

struct ContextualSummaryRuntime {
    reach: ContextualReach,
    heap_by_from: ContextualHeapEdges,
    calls_by_from: ContextualBoundaryEdges,
    returns_by_from: ContextualBoundaryEdges,
    reverse_heap: ContextualReverseNodes,
    reverse_calls: ContextualReverseNodes,
    reverse_returns: ContextualReverseNodes,
}

impl ContextualSummaryRuntime {
    fn validate_global_runtime(&self, node_count: usize, func_segments: &[u32]) -> Result<(), &'static str> {
        match &self.reach {
            ContextualReach::Dense(reach) if reach.is_valid_for(node_count) => {}
            ContextualReach::Dense(_) => return Err("dense reachability layout"),
            ContextualReach::Paged { forward, backward }
                if paged_csr_is_valid(forward, node_count) && paged_csr_is_valid(backward, node_count) => {}
            ContextualReach::Paged { .. } => return Err("paged reachability layout"),
            ContextualReach::Sparse { .. } => return Err("global reachability representation"),
        }
        if !self.heap_by_from.is_valid_for(node_count, func_segments) {
            return Err("projected-heap relation");
        }
        if !self.calls_by_from.is_valid_for(
            node_count,
            func_segments,
            BoundaryEvidenceDirection::CallerToCallee,
        ) {
            return Err("call-boundary relation");
        }
        if !self.returns_by_from.is_valid_for(
            node_count,
            func_segments,
            BoundaryEvidenceDirection::CalleeToCaller,
        ) {
            return Err("return-boundary relation");
        }
        if !self.reverse_heap.is_valid_for(node_count)
            || !self.reverse_calls.is_valid_for(node_count)
            || !self.reverse_returns.is_valid_for(node_count)
        {
            return Err("reverse-contextual relation");
        }
        Ok(())
    }
}

fn paged_csr_is_valid(csr: &PagedEdgeCsr, node_count: usize) -> bool {
    csr.offsets.len() == node_count.saturating_add(1)
        && offsets_are_valid(&csr.offsets, csr.offsets.last().copied().unwrap_or(0) as usize)
        && csr.targets.len()
            == u64::from(csr.offsets.last().copied().unwrap_or(0))
                .saturating_mul(std::mem::size_of::<u32>() as u64)
}

const CONTEXTUAL_RUNTIME_ACCELERATOR_VERSION: u32 = 1;
const CONTEXTUAL_HEAP_EDGE_BYTES: usize = 44;
const CONTEXTUAL_BOUNDARY_EDGE_BYTES: usize = 72;

#[derive(serde::Serialize)]
struct PersistedContextualRuntimeRef<'a> {
    version: u32,
    node_count: u32,
    forward_offsets: &'a [u32],
    backward_offsets: &'a [u32],
    heap_sources: &'a [NodeId],
    heap_offsets: &'a [u32],
    call_sources: &'a [NodeId],
    call_offsets: &'a [u32],
    return_sources: &'a [NodeId],
    return_offsets: &'a [u32],
    reverse_heap_keys: &'a [NodeId],
    reverse_heap_offsets: &'a [u32],
    reverse_call_keys: &'a [NodeId],
    reverse_call_offsets: &'a [u32],
    reverse_return_keys: &'a [NodeId],
    reverse_return_offsets: &'a [u32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedContextualRuntime {
    version: u32,
    node_count: u32,
    forward_offsets: Box<[u32]>,
    backward_offsets: Box<[u32]>,
    heap_sources: Box<[NodeId]>,
    heap_offsets: Box<[u32]>,
    call_sources: Box<[NodeId]>,
    call_offsets: Box<[u32]>,
    return_sources: Box<[NodeId]>,
    return_offsets: Box<[u32]>,
    reverse_heap_keys: Box<[NodeId]>,
    reverse_heap_offsets: Box<[u32]>,
    reverse_call_keys: Box<[NodeId]>,
    reverse_call_offsets: Box<[u32]>,
    reverse_return_keys: Box<[NodeId]>,
    reverse_return_offsets: Box<[u32]>,
}

struct PagedEdgeCsr {
    offsets: Box<[u32]>,
    targets: QueryAcceleratorBlobReader,
}

impl PagedEdgeCsr {
    fn visit(&self, node: NodeId, visit: impl FnMut(NodeId)) {
        let index = node.0 as usize;
        let Some((&start, &end)) = self.offsets.get(index).zip(self.offsets.get(index + 1)) else {
            return;
        };
        visit_paged_rows(
            &self.targets,
            start,
            end,
            std::mem::size_of::<u32>(),
            decode_node_row,
            visit,
        );
    }
}

struct PagedHeapEdges {
    sources: Box<[NodeId]>,
    offsets: Box<[u32]>,
    edges: QueryAcceleratorBlobReader,
}

struct PagedBoundaryEdges {
    sources: Box<[NodeId]>,
    offsets: Box<[u32]>,
    edges: QueryAcceleratorBlobReader,
}

struct PagedReverseNodes {
    keys: Box<[NodeId]>,
    offsets: Box<[u32]>,
    nodes: QueryAcceleratorBlobReader,
}

enum ContextualHeapEdges {
    Resident(SparseHeapEdges),
    Paged(PagedHeapEdges),
}

impl ContextualHeapEdges {
    fn visit(&self, source: NodeId, visit: impl FnMut(HeapBoundaryEdge)) {
        match self {
            Self::Resident(edges) => edges.get(source).iter().copied().for_each(visit),
            Self::Paged(edges) => {
                let Some((start, end)) = grouped_range(&edges.sources, &edges.offsets, source) else {
                    return;
                };
                visit_paged_rows(
                    &edges.edges,
                    start,
                    end,
                    CONTEXTUAL_HEAP_EDGE_BYTES,
                    decode_heap_boundary_edge,
                    visit,
                );
            }
        }
    }

    fn is_valid_for(&self, node_count: usize, func_segments: &[u32]) -> bool {
        match self {
            Self::Resident(edges) => edges.is_valid_for(node_count, func_segments),
            Self::Paged(edges) => grouped_paged_layout_is_valid(
                &edges.sources,
                &edges.offsets,
                edges.edges.len(),
                CONTEXTUAL_HEAP_EDGE_BYTES,
                node_count,
            ),
        }
    }
}

enum ContextualBoundaryEdges {
    Resident(SparseContextEdges),
    Paged(PagedBoundaryEdges),
}

impl ContextualBoundaryEdges {
    fn visit(&self, source: NodeId, visit: impl FnMut(ContextBoundaryEdge)) {
        match self {
            Self::Resident(edges) => edges.get(source).copied().for_each(visit),
            Self::Paged(edges) => {
                let Some((start, end)) = grouped_range(&edges.sources, &edges.offsets, source) else {
                    return;
                };
                visit_paged_rows(
                    &edges.edges,
                    start,
                    end,
                    CONTEXTUAL_BOUNDARY_EDGE_BYTES,
                    decode_context_boundary_edge,
                    visit,
                );
            }
        }
    }

    fn is_valid_for(
        &self,
        node_count: usize,
        func_segments: &[u32],
        evidence_direction: BoundaryEvidenceDirection,
    ) -> bool {
        match self {
            Self::Resident(edges) => edges.is_valid_for(node_count, func_segments, evidence_direction),
            Self::Paged(edges) => grouped_paged_layout_is_valid(
                &edges.sources,
                &edges.offsets,
                edges.edges.len(),
                CONTEXTUAL_BOUNDARY_EDGE_BYTES,
                node_count,
            ),
        }
    }
}

enum ContextualReverseNodes {
    Resident(GroupedNodeIndex<NodeId>),
    Paged(PagedReverseNodes),
}

impl ContextualReverseNodes {
    fn visit(&self, source: NodeId, visit: impl FnMut(NodeId)) {
        match self {
            Self::Resident(nodes) => nodes
                .get(&source)
                .into_iter()
                .flatten()
                .map(|node| NodeId(node.0))
                .for_each(visit),
            Self::Paged(nodes) => {
                let Some((start, end)) = grouped_range(&nodes.keys, &nodes.offsets, source) else {
                    return;
                };
                visit_paged_rows(
                    &nodes.nodes,
                    start,
                    end,
                    std::mem::size_of::<u32>(),
                    decode_node_row,
                    visit,
                );
            }
        }
    }

    fn is_valid_for(&self, node_count: usize) -> bool {
        match self {
            Self::Resident(nodes) => {
                nodes.has_valid_layout(node_count)
                    && nodes.keys.iter().all(|node| (node.0 as usize) < node_count)
            }
            Self::Paged(nodes) => grouped_paged_layout_is_valid(
                &nodes.keys,
                &nodes.offsets,
                nodes.nodes.len(),
                std::mem::size_of::<u32>(),
                node_count,
            ),
        }
    }
}

fn grouped_range(keys: &[NodeId], offsets: &[u32], source: NodeId) -> Option<(u32, u32)> {
    let index = keys.binary_search_by_key(&source.0, |node| node.0).ok()?;
    Some((*offsets.get(index)?, *offsets.get(index + 1)?))
}

fn grouped_paged_layout_is_valid(
    keys: &[NodeId],
    offsets: &[u32],
    bytes: u64,
    row_bytes: usize,
    node_count: usize,
) -> bool {
    strictly_sorted_node_ids(keys)
        && offsets.len() == keys.len().saturating_add(1)
        && offsets_are_valid(offsets, offsets.last().copied().unwrap_or(0) as usize)
        && keys.iter().all(|node| (node.0 as usize) < node_count)
        && bytes == u64::from(offsets.last().copied().unwrap_or(0)).saturating_mul(row_bytes as u64)
}

fn visit_paged_rows<T>(
    storage: &QueryAcceleratorBlobReader,
    mut start: u32,
    end: u32,
    row_bytes: usize,
    decode: fn(&[u8]) -> T,
    mut visit: impl FnMut(T),
) {
    const PAGE_BYTES: usize = 8 * 1024;
    let mut page = [0_u8; PAGE_BYTES];
    let page_rows = (PAGE_BYTES / row_bytes).max(1);
    while start < end {
        let rows = usize::try_from(end - start).unwrap_or(usize::MAX).min(page_rows);
        let bytes = rows.saturating_mul(row_bytes);
        storage
            .read_exact_at(
                u64::from(start).saturating_mul(row_bytes as u64),
                &mut page[..bytes],
            )
            .expect("validated contextual accelerator row remains readable");
        for row in page[..bytes].chunks_exact(row_bytes) {
            visit(decode(row));
        }
        start = start.saturating_add(u32::try_from(rows).expect("contextual row page exceeds u32"));
    }
}

fn encode_cross_call(output: &mut Vec<u8>, call: CrossCallEdge) {
    output.extend_from_slice(&call.caller.raw().to_le_bytes());
    output.extend_from_slice(&call.callee.raw().to_le_bytes());
    output.extend_from_slice(&call.call_span.file.raw().to_le_bytes());
    output.extend_from_slice(&call.call_span.start.to_le_bytes());
    output.extend_from_slice(&call.call_span.end.to_le_bytes());
    output.extend_from_slice(&call.arg_idx.to_le_bytes());
    output.extend_from_slice(&call.param_idx.to_le_bytes());
    output.push(encode_precision(call.precision));
    output.push(encode_call_kind(call.call_kind));
    output.push(encode_cross_call_relation(call.relation));
}

fn decode_cross_call(row: &[u8]) -> CrossCallEdge {
    debug_assert_eq!(row.len(), 39);
    let word = |start| u32::from_le_bytes(row[start..start + 4].try_into().expect("word bytes"));
    let wide = |start| u64::from_le_bytes(row[start..start + 8].try_into().expect("wide bytes"));
    CrossCallEdge {
        caller: FuncId::new(word(0)),
        callee: FuncId::new(word(4)),
        call_span: Span::new(FileId::new(word(8)), wide(12), wide(20)),
        arg_idx: word(28),
        param_idx: word(32),
        precision: decode_precision(row[36]),
        call_kind: decode_call_kind(row[37]),
        relation: decode_cross_call_relation(row[38]),
    }
}

fn encode_cross_call_relation(relation: CrossCallRelation) -> u8 {
    match relation {
        CrossCallRelation::Argument => 0,
        CrossCallRelation::Callback => 1,
        CrossCallRelation::Capture => 2,
        CrossCallRelation::Return => 3,
        CrossCallRelation::FieldState => 4,
    }
}

fn decode_cross_call_relation(value: u8) -> CrossCallRelation {
    match value {
        0 => CrossCallRelation::Argument,
        1 => CrossCallRelation::Callback,
        2 => CrossCallRelation::Capture,
        3 => CrossCallRelation::Return,
        4 => CrossCallRelation::FieldState,
        _ => panic!("invalid compact cross-call relation"),
    }
}

fn encode_optional_cross_call(output: &mut Vec<u8>, call: Option<CrossCallEdge>) {
    output.push(u8::from(call.is_some()));
    if let Some(call) = call {
        encode_cross_call(output, call);
    } else {
        output.resize(output.len() + 39, 0);
    }
}

fn decode_optional_cross_call(row: &[u8]) -> Option<CrossCallEdge> {
    (row.first().copied() == Some(1)).then(|| decode_cross_call(&row[1..40]))
}

fn encode_heap_boundary_edge(output: &mut Vec<u8>, edge: &HeapBoundaryEdge) {
    output.extend_from_slice(&edge.target.0.to_le_bytes());
    encode_optional_cross_call(output, edge.cross_call);
}

fn decode_heap_boundary_edge(row: &[u8]) -> HeapBoundaryEdge {
    debug_assert_eq!(row.len(), CONTEXTUAL_HEAP_EDGE_BYTES);
    HeapBoundaryEdge {
        target: WsNodeId(u32::from_le_bytes(row[..4].try_into().expect("node bytes"))),
        cross_call: decode_optional_cross_call(&row[4..44]),
    }
}

fn encode_context_boundary_edge(output: &mut Vec<u8>, edge: &ContextBoundaryEdge) {
    output.extend_from_slice(&edge.key.caller.raw().to_le_bytes());
    output.extend_from_slice(&edge.key.callee.raw().to_le_bytes());
    output.extend_from_slice(&edge.key.span.file.raw().to_le_bytes());
    output.extend_from_slice(&edge.key.span.start.to_le_bytes());
    output.extend_from_slice(&edge.key.span.end.to_le_bytes());
    output.extend_from_slice(&edge.target.0.to_le_bytes());
    encode_optional_cross_call(output, edge.cross_call);
}

fn decode_context_boundary_edge(row: &[u8]) -> ContextBoundaryEdge {
    debug_assert_eq!(row.len(), CONTEXTUAL_BOUNDARY_EDGE_BYTES);
    let word = |start| u32::from_le_bytes(row[start..start + 4].try_into().expect("word bytes"));
    let wide = |start| u64::from_le_bytes(row[start..start + 8].try_into().expect("wide bytes"));
    ContextBoundaryEdge {
        key: ContextBoundaryKey {
            caller: FuncId::new(word(0)),
            callee: FuncId::new(word(4)),
            span: Span::new(FileId::new(word(8)), wide(12), wide(20)),
        },
        target: NodeId(word(28)),
        cross_call: decode_optional_cross_call(&row[32..72]),
    }
}

fn decode_node_row(row: &[u8]) -> NodeId {
    NodeId(u32::from_le_bytes(row[..4].try_into().expect("node bytes")))
}

fn snapshot_fixed_rows<T>(
    rows: &[T],
    row_bytes: usize,
    encode: fn(&mut Vec<u8>, &T),
) -> crate::IdgResult<Arc<std::fs::File>> {
    let file = tempfile::tempfile()?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    let mut row = Vec::with_capacity(row_bytes);
    for value in rows {
        row.clear();
        encode(&mut row, value);
        debug_assert_eq!(row.len(), row_bytes);
        writer.write_all(&row)?;
    }
    writer.flush()?;
    let mut file = writer
        .into_inner()
        .map_err(|error| crate::IdgError::Io(error.into_error()))?;
    file.seek(SeekFrom::Start(0))?;
    Ok(Arc::new(file))
}

fn snapshot_node_rows(rows: &[u32]) -> crate::IdgResult<Arc<std::fs::File>> {
    snapshot_fixed_rows(rows, std::mem::size_of::<u32>(), |output, value| {
        output.extend_from_slice(&value.to_le_bytes());
    })
}

fn snapshot_ws_node_rows(rows: &[WsNodeId]) -> crate::IdgResult<Arc<std::fs::File>> {
    snapshot_fixed_rows(rows, std::mem::size_of::<u32>(), |output, value| {
        output.extend_from_slice(&value.0.to_le_bytes());
    })
}

fn strictly_sorted_node_ids(nodes: &[NodeId]) -> bool {
    nodes.windows(2).all(|pair| pair[0] < pair[1])
}

fn func_is_in_workspace(func: FuncId, func_segments: &[u32]) -> bool {
    func_segments
        .get(func.raw() as usize)
        .is_some_and(|segment| *segment != u32::MAX)
}

fn cross_call_is_valid(call: CrossCallEdge, func_segments: &[u32]) -> bool {
    func_is_in_workspace(call.caller, func_segments) && func_is_in_workspace(call.callee, func_segments)
}

impl PersistedQueryAccelerator {
    fn decode(reader: impl Read, encoded_bytes: u64, workspace: &IdgWorkspace) -> crate::IdgResult<Self> {
        let mut reader = BufReader::with_capacity(1024 * 1024, reader);
        let mut magic = [0_u8; 8];
        reader.read_exact(&mut magic)?;
        if magic != IDG_QUERY_CORE_MAGIC {
            return Err(invalid_query_accelerator(
                "workspace IDG query accelerator core magic mismatch",
            ));
        }
        let version = read_core_u32(&mut reader)?;
        let mut precision = [0_u8; 1];
        reader.read_exact(&mut precision)?;
        let mut reserved = [0_u8; 3];
        reader.read_exact(&mut reserved)?;
        if precision[0] != encode_precision(SEMANTIC_MAX_PRECISION) || reserved != [0; 3] {
            return Err(invalid_query_accelerator(
                "workspace IDG query accelerator precision header mismatch",
            ));
        }
        let segment_count = read_core_u32(&mut reader)?;
        let mut counts = [0_u64; IDG_QUERY_CORE_COUNT_FIELDS];
        for count in &mut counts {
            *count = read_core_u64(&mut reader)?;
        }
        let widths = [4_u64, 4, 4, 1, 1, 4, 4, 4, 20, 4, 4, 4];
        let expected_bytes =
            counts
                .iter()
                .zip(widths)
                .try_fold(IDG_QUERY_CORE_HEADER_BYTES, |total, (count, width)| {
                    count
                        .checked_mul(width)
                        .and_then(|bytes| total.checked_add(bytes))
                        .ok_or_else(|| {
                            invalid_query_accelerator("workspace IDG query accelerator size overflow")
                        })
                })?;
        if expected_bytes != encoded_bytes {
            return Err(invalid_query_accelerator(format!(
                "workspace IDG query accelerator byte length mismatch: expected {expected_bytes}, got {encoded_bytes}",
            )));
        }
        let counts = counts
            .map(|count| {
                usize::try_from(count).map_err(|_| {
                    invalid_query_accelerator("workspace IDG query accelerator row count exceeds usize")
                })
            })
            .into_iter()
            .collect::<crate::IdgResult<Vec<_>>>()?;
        let segment_bases = read_core_u32_values(&mut reader, counts[0], std::convert::identity)?;
        let func_segments = read_core_u32_values(&mut reader, counts[1], std::convert::identity)?;
        let node_funcs = read_core_u32_values(&mut reader, counts[2], FuncId::new)?;
        let node_boundaries = read_core_bytes(&mut reader, counts[3])?;
        let projected_storage = read_core_bytes(&mut reader, counts[4])?;
        let nodes_by_func = NodesByFunc {
            offsets: read_core_u32_values(&mut reader, counts[5], std::convert::identity)?,
            nodes: read_core_u32_values(&mut reader, counts[6], NodeId)?,
        };
        let call_args = CallArgIdentityIndex {
            nodes: read_core_u32_values(&mut reader, counts[7], WsNodeId)?,
            sites: read_core_spans(&mut reader, counts[8])?,
            indices: read_core_u32_values(&mut reader, counts[9], std::convert::identity)?,
        };
        let params = ParamIdentityIndex {
            nodes: read_core_u32_values(&mut reader, counts[10], WsNodeId)?,
            indices: read_core_u32_values(&mut reader, counts[11], std::convert::identity)?,
        };
        let decoded = Self {
            version,
            max_precision: SEMANTIC_MAX_PRECISION,
            segment_count,
            segment_bases,
            func_segments,
            node_funcs,
            node_boundaries,
            projected_storage,
            nodes_by_func,
            call_args,
            params,
        };
        decoded.validate(workspace)?;
        Ok(decoded)
    }

    fn validate(&self, workspace: &IdgWorkspace) -> crate::IdgResult<()> {
        let segment_count = usize::try_from(self.segment_count)
            .map_err(|_| invalid_query_accelerator("query accelerator segment count exceeds usize"))?;
        let node_count = self.segment_bases.last().copied().unwrap_or(0) as usize;
        let segment_layout_valid = self.version == IDG_QUERY_ACCELERATOR_VERSION
            && self.max_precision == SEMANTIC_MAX_PRECISION
            && segment_count == workspace.segment_count()
            && self.segment_bases.len() == segment_count.saturating_add(1)
            && self.segment_bases.first().copied() == Some(0)
            && self.segment_bases.windows(2).all(|pair| pair[0] <= pair[1])
            && self.node_funcs.len() == node_count
            && self.node_boundaries.len() == node_count
            && self.projected_storage.len() == node_count
            && self.func_segments.iter().all(|segment| {
                *segment == u32::MAX || usize::try_from(*segment).is_ok_and(|value| value < segment_count)
            });
        if !segment_layout_valid {
            return Err(invalid_query_accelerator(
                "workspace IDG query accelerator header or dense array layout mismatch",
            ));
        }

        for segment in 0..segment_count {
            let start = self.segment_bases[segment] as usize;
            let end = self.segment_bases[segment + 1] as usize;
            for node in start..end {
                let func = self.node_funcs[node];
                if self.node_boundaries[node] > NODE_BOUNDARY_CALL_RET
                    || self.projected_storage[node] > 1
                    || self.func_segments.get(func.raw() as usize).copied() != Some(segment as u32)
                {
                    return Err(invalid_query_accelerator(
                        "query accelerator node layout or ownership is invalid",
                    ));
                }
            }
        }

        let identity_layout_valid =
            self.nodes_by_func.offsets.len() == self.func_segments.len().saturating_add(1)
                && offsets_are_valid(&self.nodes_by_func.offsets, self.nodes_by_func.nodes.len())
                && self.call_args.is_valid_for(node_count)
                && self.params.is_valid_for(node_count)
                && self.params.nodes.iter().all(|node| {
                    self.node_boundaries.get(node.0 as usize).copied() == Some(NODE_BOUNDARY_PARAM)
                });
        if !identity_layout_valid {
            return Err(invalid_query_accelerator(
                "workspace IDG query accelerator identity directory mismatch",
            ));
        }
        for func_raw in 0..self.func_segments.len() {
            let func = FuncId::new(u32::try_from(func_raw).map_err(|_| {
                invalid_query_accelerator("query accelerator function directory exceeds u32")
            })?);
            if self.nodes_by_func.get(func).is_some_and(|nodes| {
                nodes.iter().any(|node| {
                    self.node_funcs
                        .get(node.0 as usize)
                        .is_none_or(|owner| *owner != func)
                })
            }) {
                return Err(invalid_query_accelerator(
                    "query accelerator function-to-node directory is inconsistent",
                ));
            }
        }
        Ok(())
    }

    fn into_unified_core(self) -> UnifiedAddressSpace {
        UnifiedAddressSpace {
            segment_bases: self.segment_bases,
            func_segments: self.func_segments,
            node_funcs: self.node_funcs,
            node_boundaries: self.node_boundaries,
            projected_storage: self.projected_storage,
            nodes_by_func: self.nodes_by_func,
            call_args: self.call_args,
            params: self.params,
            unfiltered_reach: RwLock::new(None),
            precision_reach: RwLock::new(AHashMap::new()),
            contextual_summaries: RwLock::new(AHashMap::new()),
            cross_calls_by_from: RwLock::new(None),
            symbolic_runtime: OnceLock::new(),
        }
    }
}

fn read_core_u32(reader: &mut impl Read) -> crate::IdgResult<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_core_u64(reader: &mut impl Read) -> crate::IdgResult<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_core_u32_values<T>(
    reader: &mut impl Read,
    count: usize,
    map: impl Fn(u32) -> T,
) -> crate::IdgResult<Box<[T]>> {
    const VALUES_PER_PAGE: usize = 16 * 1024;
    let mut values = Vec::with_capacity(count);
    let mut bytes = vec![0_u8; VALUES_PER_PAGE * 4];
    let mut remaining = count;
    while remaining > 0 {
        let rows = remaining.min(VALUES_PER_PAGE);
        let payload = &mut bytes[..rows * 4];
        reader.read_exact(payload)?;
        values.extend(
            payload
                .chunks_exact(4)
                .map(|row| map(u32::from_le_bytes(row.try_into().expect("core word bytes")))),
        );
        remaining -= rows;
    }
    Ok(values.into_boxed_slice())
}

fn read_core_bytes(reader: &mut impl Read, count: usize) -> crate::IdgResult<Box<[u8]>> {
    let mut values = vec![0_u8; count];
    reader.read_exact(&mut values)?;
    Ok(values.into_boxed_slice())
}

fn read_core_spans(reader: &mut impl Read, count: usize) -> crate::IdgResult<Box<[Span]>> {
    let mut spans = Vec::with_capacity(count);
    for _ in 0..count {
        let file = FileId::new(read_core_u32(reader)?);
        let start = read_core_u64(reader)?;
        let end = read_core_u64(reader)?;
        spans.push(Span::new(file, start, end));
    }
    Ok(spans.into_boxed_slice())
}

fn encode_query_accelerator_core(
    unified: &UnifiedAddressSpace,
    segment_count: u32,
) -> crate::IdgResult<CompiledQueryAcceleratorFrame> {
    let file = tempfile::tempfile()?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    writer.write_all(&IDG_QUERY_CORE_MAGIC)?;
    writer.write_all(&IDG_QUERY_ACCELERATOR_VERSION.to_le_bytes())?;
    writer.write_all(&[encode_precision(SEMANTIC_MAX_PRECISION), 0, 0, 0])?;
    writer.write_all(&segment_count.to_le_bytes())?;
    let counts = [
        unified.segment_bases.len(),
        unified.func_segments.len(),
        unified.node_funcs.len(),
        unified.node_boundaries.len(),
        unified.projected_storage.len(),
        unified.nodes_by_func.offsets.len(),
        unified.nodes_by_func.nodes.len(),
        unified.call_args.nodes.len(),
        unified.call_args.sites.len(),
        unified.call_args.indices.len(),
        unified.params.nodes.len(),
        unified.params.indices.len(),
    ];
    for count in counts {
        writer.write_all(
            &u64::try_from(count)
                .map_err(|_| invalid_query_accelerator("query accelerator row count exceeds u64"))?
                .to_le_bytes(),
        )?;
    }
    write_core_u32_values(&mut writer, unified.segment_bases.iter().copied())?;
    write_core_u32_values(&mut writer, unified.func_segments.iter().copied())?;
    write_core_u32_values(&mut writer, unified.node_funcs.iter().map(|func| func.raw()))?;
    writer.write_all(&unified.node_boundaries)?;
    writer.write_all(&unified.projected_storage)?;
    write_core_u32_values(&mut writer, unified.nodes_by_func.offsets.iter().copied())?;
    write_core_u32_values(&mut writer, unified.nodes_by_func.nodes.iter().map(|node| node.0))?;
    write_core_u32_values(&mut writer, unified.call_args.nodes.iter().map(|node| node.0))?;
    for span in &unified.call_args.sites {
        writer.write_all(&span.file.raw().to_le_bytes())?;
        writer.write_all(&span.start.to_le_bytes())?;
        writer.write_all(&span.end.to_le_bytes())?;
    }
    write_core_u32_values(&mut writer, unified.call_args.indices.iter().copied())?;
    write_core_u32_values(&mut writer, unified.params.nodes.iter().map(|node| node.0))?;
    write_core_u32_values(&mut writer, unified.params.indices.iter().copied())?;
    writer.flush()?;
    let mut file = writer
        .into_inner()
        .map_err(|error| crate::IdgError::Io(error.into_error()))?;
    let bytes = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    Ok(CompiledQueryAcceleratorFrame {
        file: Arc::new(file),
        bytes,
    })
}

fn write_core_u32_values(
    writer: &mut impl Write,
    values: impl IntoIterator<Item = u32>,
) -> crate::IdgResult<()> {
    const VALUES_PER_PAGE: usize = 16 * 1024;
    let mut bytes = Vec::with_capacity(VALUES_PER_PAGE * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
        if bytes.len() == VALUES_PER_PAGE * 4 {
            writer.write_all(&bytes)?;
            bytes.clear();
        }
    }
    if !bytes.is_empty() {
        writer.write_all(&bytes)?;
    }
    Ok(())
}

fn invalid_query_accelerator(message: impl Into<String>) -> crate::IdgError {
    crate::IdgError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn encode_query_accelerator_frame(
    value: &(impl serde::Serialize + ?Sized),
    kind: &'static str,
) -> crate::IdgResult<CompiledQueryAcceleratorFrame> {
    // MessagePack emits many small integer writes. Sending those directly to
    // a `File` turns a large exact compiler relation into millions of
    // syscalls; a bounded buffer preserves identical wire bytes while making
    // serialization proportional to payload size.
    let file = tempfile::tempfile()?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    bonsai_common::wire::encode_to_writer(&mut writer, value).map_err(|error| {
        invalid_query_accelerator(format!("workspace IDG {kind} accelerator encode failed: {error}"))
    })?;
    writer.flush()?;
    let mut file = writer
        .into_inner()
        .map_err(|error| crate::IdgError::Io(error.into_error()))?;
    let bytes = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    Ok(CompiledQueryAcceleratorFrame {
        file: Arc::new(file),
        bytes,
    })
}

fn compiled_query_blob(
    kind: QueryAcceleratorBlobKind,
    file: Arc<std::fs::File>,
) -> crate::IdgResult<CompiledQueryAcceleratorBlob> {
    let bytes = file.metadata()?.len();
    Ok(CompiledQueryAcceleratorBlob { kind, file, bytes })
}

fn compile_contextual_query_accelerator(
    runtime: &ContextualSummaryRuntime,
    node_count: usize,
) -> crate::IdgResult<(CompiledQueryAcceleratorFrame, Vec<CompiledQueryAcceleratorBlob>)> {
    let ContextualReach::Dense(reach) = &runtime.reach else {
        return Err(invalid_query_accelerator(
            "default contextual accelerator requires the complete dense compiler relation",
        ));
    };
    let ContextualHeapEdges::Resident(heap) = &runtime.heap_by_from else {
        return Err(invalid_query_accelerator(
            "cannot republish a paged contextual heap relation",
        ));
    };
    let ContextualBoundaryEdges::Resident(calls) = &runtime.calls_by_from else {
        return Err(invalid_query_accelerator(
            "cannot republish a paged contextual call relation",
        ));
    };
    let ContextualBoundaryEdges::Resident(returns) = &runtime.returns_by_from else {
        return Err(invalid_query_accelerator(
            "cannot republish a paged contextual return relation",
        ));
    };
    let ContextualReverseNodes::Resident(reverse_heap) = &runtime.reverse_heap else {
        return Err(invalid_query_accelerator(
            "cannot republish a paged reverse-heap relation",
        ));
    };
    let ContextualReverseNodes::Resident(reverse_calls) = &runtime.reverse_calls else {
        return Err(invalid_query_accelerator(
            "cannot republish a paged reverse-call relation",
        ));
    };
    let ContextualReverseNodes::Resident(reverse_returns) = &runtime.reverse_returns else {
        return Err(invalid_query_accelerator(
            "cannot republish a paged reverse-return relation",
        ));
    };
    let (forward, backward) = reach.persisted_relations();
    let (forward_offsets, forward_targets) = forward.persisted_parts();
    let (backward_offsets, backward_targets) = backward.persisted_parts();
    let header = encode_query_accelerator_frame(
        &PersistedContextualRuntimeRef {
            version: CONTEXTUAL_RUNTIME_ACCELERATOR_VERSION,
            node_count: u32::try_from(node_count)
                .map_err(|_| invalid_query_accelerator("contextual node count exceeds u32"))?,
            forward_offsets,
            backward_offsets,
            heap_sources: &heap.sources,
            heap_offsets: &heap.offsets,
            call_sources: &calls.sources,
            call_offsets: &calls.offsets,
            return_sources: &returns.sources,
            return_offsets: &returns.offsets,
            reverse_heap_keys: &reverse_heap.keys,
            reverse_heap_offsets: &reverse_heap.offsets,
            reverse_call_keys: &reverse_calls.keys,
            reverse_call_offsets: &reverse_calls.offsets,
            reverse_return_keys: &reverse_returns.keys,
            reverse_return_offsets: &reverse_returns.offsets,
        },
        "contextual header",
    )?;
    let blobs = vec![
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualForwardTargets,
            snapshot_node_rows(forward_targets)?,
        )?,
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualBackwardTargets,
            snapshot_node_rows(backward_targets)?,
        )?,
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualHeapEdges,
            snapshot_fixed_rows(&heap.edges, CONTEXTUAL_HEAP_EDGE_BYTES, encode_heap_boundary_edge)?,
        )?,
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualCallEdges,
            snapshot_fixed_rows(
                &calls.edges,
                CONTEXTUAL_BOUNDARY_EDGE_BYTES,
                encode_context_boundary_edge,
            )?,
        )?,
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualReturnEdges,
            snapshot_fixed_rows(
                &returns.edges,
                CONTEXTUAL_BOUNDARY_EDGE_BYTES,
                encode_context_boundary_edge,
            )?,
        )?,
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualReverseHeapNodes,
            snapshot_ws_node_rows(&reverse_heap.nodes)?,
        )?,
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualReverseCallNodes,
            snapshot_ws_node_rows(&reverse_calls.nodes)?,
        )?,
        compiled_query_blob(
            QueryAcceleratorBlobKind::ContextualReverseReturnNodes,
            snapshot_ws_node_rows(&reverse_returns.nodes)?,
        )?,
    ];
    Ok((header, blobs))
}

fn load_contextual_query_accelerator(
    reader: impl std::io::Read,
    mut blobs: AHashMap<QueryAcceleratorBlobKind, QueryAcceleratorBlobReader>,
    node_count: usize,
    func_segments: &[u32],
) -> crate::IdgResult<ContextualSummaryRuntime> {
    let persisted: PersistedContextualRuntime =
        bonsai_common::wire::decode_from_reader(reader).map_err(|error| {
            invalid_query_accelerator(format!(
                "workspace IDG contextual accelerator decode failed: {error}"
            ))
        })?;
    if persisted.version != CONTEXTUAL_RUNTIME_ACCELERATOR_VERSION
        || persisted.node_count as usize != node_count
    {
        return Err(invalid_query_accelerator(
            "workspace IDG contextual accelerator header mismatch",
        ));
    }
    let mut take = |kind| {
        blobs.remove(&kind).ok_or_else(|| {
            invalid_query_accelerator(format!(
                "workspace IDG contextual accelerator is missing {kind:?}"
            ))
        })
    };
    let runtime = ContextualSummaryRuntime {
        reach: ContextualReach::Paged {
            forward: PagedEdgeCsr {
                offsets: persisted.forward_offsets,
                targets: take(QueryAcceleratorBlobKind::ContextualForwardTargets)?,
            },
            backward: PagedEdgeCsr {
                offsets: persisted.backward_offsets,
                targets: take(QueryAcceleratorBlobKind::ContextualBackwardTargets)?,
            },
        },
        heap_by_from: ContextualHeapEdges::Paged(PagedHeapEdges {
            sources: persisted.heap_sources,
            offsets: persisted.heap_offsets,
            edges: take(QueryAcceleratorBlobKind::ContextualHeapEdges)?,
        }),
        calls_by_from: ContextualBoundaryEdges::Paged(PagedBoundaryEdges {
            sources: persisted.call_sources,
            offsets: persisted.call_offsets,
            edges: take(QueryAcceleratorBlobKind::ContextualCallEdges)?,
        }),
        returns_by_from: ContextualBoundaryEdges::Paged(PagedBoundaryEdges {
            sources: persisted.return_sources,
            offsets: persisted.return_offsets,
            edges: take(QueryAcceleratorBlobKind::ContextualReturnEdges)?,
        }),
        reverse_heap: ContextualReverseNodes::Paged(PagedReverseNodes {
            keys: persisted.reverse_heap_keys,
            offsets: persisted.reverse_heap_offsets,
            nodes: take(QueryAcceleratorBlobKind::ContextualReverseHeapNodes)?,
        }),
        reverse_calls: ContextualReverseNodes::Paged(PagedReverseNodes {
            keys: persisted.reverse_call_keys,
            offsets: persisted.reverse_call_offsets,
            nodes: take(QueryAcceleratorBlobKind::ContextualReverseCallNodes)?,
        }),
        reverse_returns: ContextualReverseNodes::Paged(PagedReverseNodes {
            keys: persisted.reverse_return_keys,
            offsets: persisted.reverse_return_offsets,
            nodes: take(QueryAcceleratorBlobKind::ContextualReverseReturnNodes)?,
        }),
    };
    runtime
        .validate_global_runtime(node_count, func_segments)
        .map_err(invalid_query_accelerator)?;
    Ok(runtime)
}

/// Query-time ordinary relation. Whole-workspace consumers retain the dense
/// compiler CSR; exact function corridors use sparse grouped rows so a narrow
/// query never allocates offsets for every node in the repository.
enum ContextualReach {
    Dense(ReachabilityIndex),
    Paged {
        forward: PagedEdgeCsr,
        backward: PagedEdgeCsr,
    },
    Sparse {
        forward: GroupedNodeIndex<NodeId>,
        backward: GroupedNodeIndex<NodeId>,
    },
}

impl ContextualReach {
    fn visit_forward(&self, node: NodeId, mut visit: impl FnMut(NodeId)) {
        match self {
            Self::Dense(reach) => {
                for target in reach.forward_neighbours(node) {
                    visit(NodeId(*target));
                }
            }
            Self::Paged { forward, .. } => forward.visit(node, visit),
            Self::Sparse { forward, .. } => {
                for target in forward.get(&node).into_iter().flatten() {
                    visit(NodeId(target.0));
                }
            }
        }
    }

    fn visit_backward(&self, node: NodeId, mut visit: impl FnMut(NodeId)) {
        match self {
            Self::Dense(reach) => {
                for predecessor in reach.backward_neighbours(node) {
                    visit(NodeId(*predecessor));
                }
            }
            Self::Paged { backward, .. } => backward.visit(node, visit),
            Self::Sparse { backward, .. } => {
                for predecessor in backward.get(&node).into_iter().flatten() {
                    visit(NodeId(predecessor.0));
                }
            }
        }
    }

    fn forward_closure_nodes(&self, seeds: &[NodeId]) -> Vec<NodeId> {
        match self {
            Self::Dense(reach) => reach.forward_closure_nodes(seeds),
            Self::Paged { .. } | Self::Sparse { .. } => {
                let mut reached = AHashSet::default();
                let mut pending = Vec::new();
                for seed in seeds.iter().copied() {
                    if reached.insert(seed.0) {
                        pending.push(seed);
                    }
                }
                while let Some(node) = pending.pop() {
                    self.visit_forward(node, |target| {
                        if reached.insert(target.0) {
                            pending.push(target);
                        }
                    });
                }
                let mut nodes: Vec<NodeId> = reached.into_iter().map(NodeId).collect();
                nodes.sort_unstable_by_key(|node| node.0);
                nodes
            }
        }
    }
}

#[derive(Copy, Clone)]
struct SymbolicClosurePolicy<'a> {
    max_precision: Option<Precision>,
    /// Exact compiler-derived function scope for a targeted query. `None`
    /// retains the ordinary whole-graph closure. Unlike a work budget, this
    /// is a semantic graph predicate: every admitted function runs to fixed
    /// point, while nodes outside the proven source-to-target corridor are
    /// not part of the query.
    allowed_funcs: Option<&'a AHashSet<FuncId>>,
    target_relevance: Option<&'a IdgTargetRelevance>,
    /// Direct return-relevant call dependencies for batch function-summary
    /// compilation. `None` is the unrestricted interactive-query mode.
    ///
    /// Summary evaluation activates a callee only when an exact structural
    /// or symbolic call boundary is reached. This is the compiler's normal
    /// pushdown transition; precomputing every root's transitive callee set
    /// repeated the same graph walk for thousands of functions.
    summary_callees: Option<&'a AHashMap<FuncId, Vec<FuncId>>>,
    summary_root: Option<FuncId>,
    contextual: Option<&'a ContextualSummaryRuntime>,
    activate_seed_callers: bool,
}

enum RootClosureVisited {
    Dense(NodeBitSet),
    Sparse {
        reached: AHashSet<u32>,
        node_count: usize,
    },
}

impl RootClosureVisited {
    fn new(node_count: usize, seed_count: usize) -> Self {
        let dense_bytes = node_count.div_ceil(u8::BITS as usize);
        let sparse_entry_bytes = std::mem::size_of::<u32>() + std::mem::size_of::<usize>();
        if seed_count.saturating_mul(sparse_entry_bytes) >= dense_bytes {
            Self::Dense(NodeBitSet::zeros(node_count))
        } else {
            Self::Sparse {
                reached: AHashSet::with_capacity(seed_count),
                node_count,
            }
        }
    }

    fn insert(&mut self, node: NodeId) -> bool {
        match self {
            Self::Dense(reached) => reached.insert(node),
            Self::Sparse { reached, node_count } => {
                if node.0 as usize >= *node_count || !reached.insert(node.0) {
                    return false;
                }
                let dense_bytes = node_count.div_ceil(u8::BITS as usize);
                let sparse_entry_bytes = std::mem::size_of::<u32>() + std::mem::size_of::<usize>();
                if reached.len().saturating_mul(sparse_entry_bytes) >= dense_bytes {
                    let mut dense = NodeBitSet::zeros(*node_count);
                    for reached_node in reached.iter().copied() {
                        dense.set(NodeId(reached_node));
                    }
                    *self = Self::Dense(dense);
                }
                true
            }
        }
    }

    fn contains(&self, node: NodeId) -> bool {
        match self {
            Self::Dense(reached) => reached.contains(node),
            Self::Sparse { reached, .. } => reached.contains(&node.0),
        }
    }

    fn admits(&self, node: NodeId) -> bool {
        match self {
            Self::Dense(reached) => (node.0 as usize) < reached.len(),
            Self::Sparse { node_count, .. } => (node.0 as usize) < *node_count,
        }
    }

    #[cfg(test)]
    fn sorted_nodes(&self) -> Vec<NodeId> {
        match self {
            Self::Dense(reached) => reached.iter().collect(),
            Self::Sparse { reached, .. } => {
                let mut nodes: Vec<_> = reached.iter().copied().map(NodeId).collect();
                nodes.sort_unstable_by_key(|node| node.0);
                nodes
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Dense(reached) => reached.popcount(),
            Self::Sparse { reached, .. } => reached.len(),
        }
    }

    fn union_into(&self, nodes: &mut NodeBitSet) {
        match self {
            Self::Dense(reached) => nodes.union_inplace(reached),
            Self::Sparse { reached, .. } => {
                for node in reached.iter().copied() {
                    nodes.set(NodeId(node));
                }
            }
        }
    }
}

struct ClosureVisited {
    root: RootClosureVisited,
    contextual: ContextualClosureVisited,
}

struct ContextualClosureVisited {
    /// Exact `(context, node)` compiler states. The relation can be much
    /// larger than the source graph on highly connected workspaces, so it
    /// uses the same external-memory representation as symbolic facts.
    states: SpillSet,
    /// The public closure result is context-erased. It starts sparse and
    /// promotes to a dense bitset only when reached-node density justifies
    /// workspace-sized storage.
    nodes: RootClosureVisited,
}

impl ContextualClosureVisited {
    fn new(node_count: usize) -> Self {
        Self {
            states: contextual_node_store(),
            nodes: RootClosureVisited::new(node_count, 0),
        }
    }

    fn insert(&mut self, context: u32, node: NodeId) -> bool {
        if !self.nodes.admits(node) {
            return false;
        }
        let key = (u128::from(context) << 32) | u128::from(node.0);
        if !self.states.insert(key) {
            return false;
        }
        self.nodes.insert(node);
        true
    }

    fn len(&self) -> u64 {
        self.states.len()
    }

    #[cfg(test)]
    fn erased_nodes(&self) -> Vec<NodeId> {
        self.nodes.sorted_nodes()
    }
}

impl ClosureVisited {
    fn new(node_count: usize, seed_count: usize) -> Self {
        Self {
            root: RootClosureVisited::new(node_count, seed_count),
            contextual: ContextualClosureVisited::new(node_count),
        }
    }

    fn insert(&mut self, node: NodeId, context: u32) -> bool {
        if context == 0 {
            self.root.insert(node)
        } else {
            self.contextual.insert(context, node)
        }
    }

    fn nodes(&self) -> Vec<NodeId> {
        match (&self.root, &self.contextual.nodes) {
            (
                RootClosureVisited::Sparse { reached: root, .. },
                RootClosureVisited::Sparse {
                    reached: contextual, ..
                },
            ) => {
                let mut nodes = Vec::with_capacity(root.len().saturating_add(contextual.len()));
                nodes.extend(root.iter().copied().map(NodeId));
                nodes.extend(contextual.iter().copied().map(NodeId));
                nodes.sort_unstable_by_key(|node| node.0);
                nodes.dedup();
                nodes
            }
            _ => {
                // Dense closures retain the linear bitset finalisation path;
                // only sparse, function-sized closures avoid allocating a
                // workspace-sized result bitmap.
                let node_count = match &self.root {
                    RootClosureVisited::Dense(nodes) => nodes.len(),
                    RootClosureVisited::Sparse { node_count, .. } => *node_count,
                };
                let mut nodes = NodeBitSet::zeros(node_count);
                self.root.union_into(&mut nodes);
                self.contextual.nodes.union_into(&mut nodes);
                nodes.iter().collect()
            }
        }
    }
}

#[derive(Copy, Clone)]
struct ClosureNodeState {
    node: NodeId,
    context: u32,
}

impl ClosureNodeState {
    fn key(self) -> u128 {
        (u128::from(self.context) << 32) | u128::from(self.node.0)
    }

    fn from_key(key: u128) -> Self {
        Self {
            node: NodeId(key as u32),
            context: (key >> 32) as u32,
        }
    }
}

/// Finite pushdown tabulation for realizable call/return flow.
///
/// A context is one concrete call boundary, not an ever-growing call string.
/// `callers[boundary]` records the contexts in which that call was reached,
/// and completed node/fact returns are replayed when a new caller context is
/// discovered. This is the standard compiler-summary fixed point: recursion
/// and diamonds converge over finite relations instead of enumerating paths.
enum CompactSet<T> {
    Inline(smallvec::SmallVec<[T; 4]>),
    Hashed(AHashSet<T>),
}

impl<T> Default for CompactSet<T> {
    fn default() -> Self {
        Self::Inline(smallvec::SmallVec::new())
    }
}

impl<T: Copy + Eq + Hash> CompactSet<T> {
    fn insert(&mut self, value: T) -> bool {
        match self {
            Self::Inline(values) => {
                if values.contains(&value) {
                    return false;
                }
                if values.len() < values.inline_size() {
                    values.push(value);
                    return true;
                }
                let mut hashed = AHashSet::with_capacity(values.len().saturating_add(1));
                hashed.extend(values.iter().copied());
                let inserted = hashed.insert(value);
                *self = Self::Hashed(hashed);
                inserted
            }
            Self::Hashed(values) => values.insert(value),
        }
    }

    fn copied_values(&self) -> Vec<T> {
        match self {
            Self::Inline(values) => values.to_vec(),
            Self::Hashed(values) => values.iter().copied().collect(),
        }
    }
}

const MIB: u64 = 1024 * 1024;
const CONTEXT_REPLAY_BATCH_ENTRIES: usize = 16_384;

fn bounded_relation_bytes(divisor: u64, maximum_mib: u64, default_mib: u64) -> usize {
    const MINIMUM_ALLOCATION_BYTES: u64 = 64 * 1024;
    let fallback_mib = default_mib.min(maximum_mib);
    let bytes = bonsai_common::effective_memory_limit_bytes().map_or(fallback_mib * MIB, |limit| {
        (limit / divisor).clamp(MINIMUM_ALLOCATION_BYTES, maximum_mib * MIB)
    });
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// Size the exact-positive hot set from the relation's detected-memory
/// allocation. This is cache policy, not semantic scope: a smaller machine
/// evicts sooner and performs more exact run reads, while every fact remains
/// in the external relation.
fn recent_positive_bytes(resident_bytes: usize) -> usize {
    // The resident delta is an open-addressed hash set budgeted at roughly
    // 40 bytes per key. Four resident budgets let the compact 17-byte cache
    // retain about nine flushed deltas without duplicating keys in a map.
    resident_bytes.saturating_mul(4)
}

/// Construct the exact closure relation's external-memory store.
///
/// The byte profile affects only how frequently the resident delta flushes.
/// Every fact remains present in either memory or a sorted temporary run and
/// participates in the same fixed point.
fn closure_fact_store() -> SpillSet {
    let resident_bytes = bounded_relation_bytes(256, 64, 64);
    // One relation-wide Bloom index eliminates nearly all random probes into
    // the external relation. This budget is reclaimable acceleration state
    // only; every possible positive is still checked against an exact sorted
    // run.
    let bloom_bytes = bounded_relation_bytes(32, 96, 64);
    // A hash-table slot plus control/allocation slack costs more than the
    // 16-byte key. The conservative divisor keeps actual resident use below
    // the scheduling allocation.
    SpillSet::new(
        resident_bytes / 40,
        bloom_bytes,
        recent_positive_bytes(resident_bytes),
        false,
    )
}

fn contextual_node_store() -> SpillSet {
    let resident_bytes = bounded_relation_bytes(384, 32, 32);
    let bloom_bytes = bounded_relation_bytes(256, 16, 16);
    SpillSet::new(
        resident_bytes / 40,
        bloom_bytes,
        recent_positive_bytes(resident_bytes),
        false,
    )
}

fn pending_node_store() -> SpillStack {
    let resident_bytes = bounded_relation_bytes(768, 8, 8);
    SpillStack::new(resident_bytes / std::mem::size_of::<u128>())
}

fn pending_fact_store() -> SpillStack {
    let resident_bytes = bounded_relation_bytes(512, 16, 16);
    SpillStack::new(resident_bytes / std::mem::size_of::<u128>())
}

/// Backward target demand is a compiler fixed point in its own right. Keep
/// its symbolic relation external-memory just like the forward closure:
/// target count and access-path fan-out must never determine peak heap use.
fn target_relevance_fact_store() -> SpillSet {
    let resident_bytes = bounded_relation_bytes(256, 32, 32);
    let bloom_bytes = bounded_relation_bytes(64, 64, 32);
    SpillSet::new(
        resident_bytes / 40,
        bloom_bytes,
        recent_positive_bytes(resident_bytes),
        false,
    )
}

fn target_relevance_wildcard_store() -> SpillSet {
    let resident_bytes = bounded_relation_bytes(1024, 8, 8);
    let bloom_bytes = bounded_relation_bytes(512, 8, 8);
    SpillSet::new(
        resident_bytes / 40,
        bloom_bytes,
        recent_positive_bytes(resident_bytes),
        false,
    )
}

fn target_relevance_frontier_store() -> SpillStack {
    let resident_bytes = bounded_relation_bytes(1024, 8, 8);
    SpillStack::new(resident_bytes / std::mem::size_of::<u128>())
}

/// Return summaries need prefix replay as new caller contexts are discovered.
/// They share the same exact spill design with a smaller resident delta.
fn returned_fact_store() -> SpillSet {
    let resident_bytes = bounded_relation_bytes(512, 16, 16);
    let bloom_bytes = bounded_relation_bytes(384, 8, 8);
    SpillSet::new(
        resident_bytes / 56,
        bloom_bytes,
        recent_positive_bytes(resident_bytes),
        true,
    )
}

/// Scalar return summaries can also grow as `(call context, returned node)`.
/// Keep that complete relation external-memory and prefix-addressable so a
/// highly shared recursive boundary cannot turn return replay into an
/// unbounded resident map or one giant temporary vector.
fn returned_node_store() -> SpillSet {
    let resident_bytes = bounded_relation_bytes(1024, 8, 8);
    let bloom_bytes = bounded_relation_bytes(512, 8, 8);
    SpillSet::new(
        resident_bytes / 56,
        bloom_bytes,
        recent_positive_bytes(resident_bytes),
        true,
    )
}

struct CallContexts {
    ids: AHashMap<ContextBoundaryKey, u32>,
    boundaries: Vec<Option<ContextBoundaryKey>>,
    callers: Vec<CompactSet<u32>>,
    returned_nodes: SpillSet,
    returned_facts: SpillSet,
}

impl CallContexts {
    fn new() -> Self {
        Self {
            boundaries: vec![None],
            ids: AHashMap::default(),
            callers: vec![CompactSet::default()],
            returned_nodes: returned_node_store(),
            returned_facts: returned_fact_store(),
        }
    }

    fn context_for(&mut self, boundary: ContextBoundaryKey) -> u32 {
        if let Some(context) = self.ids.get(&boundary).copied() {
            return context;
        }
        let context = u32::try_from(self.boundaries.len()).expect("call-context count exceeds u32");
        self.boundaries.push(Some(boundary));
        self.callers.push(CompactSet::default());
        self.ids.insert(boundary, context);
        context
    }

    fn register_call(&mut self, caller_context: u32, boundary: ContextBoundaryKey) -> (u32, bool) {
        let context = self.context_for(boundary);
        let Some(callers) = self.callers.get_mut(context as usize) else {
            return (context, false);
        };
        if !callers.insert(caller_context) {
            return (context, false);
        }
        (context, true)
    }

    fn returned_node_batch(&mut self, context: u32, after: Option<u128>) -> Vec<NodeId> {
        self.returned_nodes
            .keys_with_prefix_batch(context, after, CONTEXT_REPLAY_BATCH_ENTRIES)
            .into_iter()
            .map(|key| NodeId(key as u32))
            .collect()
    }

    fn returned_fact_batch(&mut self, context: u32, after: Option<u128>) -> Vec<SymbolicFactIdentity> {
        self.returned_facts
            .keys_with_prefix_batch(context, after, CONTEXT_REPLAY_BATCH_ENTRIES)
            .into_iter()
            .map(SymbolicFactIdentity::from_key)
            .collect()
    }

    fn matches(&self, context: u32, boundary: ContextBoundaryKey) -> bool {
        self.boundaries.get(context as usize).and_then(|value| *value) == Some(boundary)
    }

    fn complete_node_return(&mut self, context: u32, node: NodeId) -> Vec<u32> {
        if self.boundaries.get(context as usize).is_none() {
            return Vec::new();
        }
        let key = (u128::from(context) << 96) | u128::from(node.0);
        if !self.returned_nodes.insert(key) {
            return Vec::new();
        }
        self.callers
            .get(context as usize)
            .map(CompactSet::copied_values)
            .unwrap_or_default()
    }

    fn complete_fact_return(&mut self, context: u32, identity: SymbolicFactIdentity) -> Vec<u32> {
        if self.boundaries.get(context as usize).is_none() {
            return Vec::new();
        }
        let key = identity.key() | (u128::from(context) << 96);
        if !self.returned_facts.insert(key) {
            return Vec::new();
        }
        self.callers
            .get(context as usize)
            .map(CompactSet::copied_values)
            .unwrap_or_default()
    }
}

/// Monotone state for one symbolic/contextual closure compilation.
///
/// Nodes and symbolic facts have independent cursors because processing one
/// relation may discover work in the other. Both relations deduplicate on
/// insertion, so recursive call components converge without a depth or
/// iteration cap.
struct SymbolicClosureWorklist<'a> {
    pending_nodes: SpillStack,
    reached: ClosureVisited,
    /// Node/context states whose compiler place has already introduced its
    /// symbolic access-path facts. A field fact that is *consumed* by a
    /// projected read reaches that scalar read, but must not reintroduce the
    /// same field as a spanless source: doing so would erase write ordering
    /// and allow a later write to flow through an earlier aggregate copy.
    fact_source_states: SpillSet,
    /// Exact reached relation packed as the complete 128-bit
    /// `(context, base, field, provenance)` compiler state. Its resident delta
    /// spills to sorted temporary runs; no state is capped or approximated.
    facts: SpillSet,
    pending_facts: SpillStack,
    contexts: CallContexts,
    /// Functions entered through a proven call boundary in summary mode.
    /// Interactive queries are unrestricted and leave this set empty.
    active_summary_funcs: AHashSet<FuncId>,
    summary_restricted: bool,
    allowed_funcs: Option<&'a AHashSet<FuncId>>,
    target_relevance: Option<&'a IdgTargetRelevance>,
    field_demand: &'a SymbolicFieldDemand,
}

impl<'a> SymbolicClosureWorklist<'a> {
    fn new(
        node_count: usize,
        seed_count: usize,
        summary_root: Option<FuncId>,
        allowed_funcs: Option<&'a AHashSet<FuncId>>,
        target_relevance: Option<&'a IdgTargetRelevance>,
        field_demand: &'a SymbolicFieldDemand,
    ) -> Self {
        let mut active_summary_funcs = AHashSet::default();
        if let Some(root) = summary_root {
            active_summary_funcs.insert(root);
        }
        Self {
            pending_nodes: pending_node_store(),
            reached: ClosureVisited::new(node_count, seed_count),
            fact_source_states: contextual_node_store(),
            facts: closure_fact_store(),
            pending_facts: pending_fact_store(),
            contexts: CallContexts::new(),
            active_summary_funcs,
            summary_restricted: summary_root.is_some(),
            allowed_funcs,
            target_relevance,
            field_demand,
        }
    }

    fn func_is_allowed(&self, func: FuncId) -> bool {
        self.allowed_funcs.is_none_or(|allowed| allowed.contains(&func))
    }

    fn activate_summary_func(&mut self, func: FuncId) -> bool {
        if !self.func_is_allowed(func) {
            return false;
        }
        if self.summary_restricted {
            self.active_summary_funcs.insert(func);
        }
        true
    }

    fn summary_func_is_active(&self, func: FuncId) -> bool {
        self.func_is_allowed(func) && (!self.summary_restricted || self.active_summary_funcs.contains(&func))
    }

    fn node_is_relevant(&self, node: NodeId) -> bool {
        self.target_relevance
            .is_none_or(|relevance| relevance.contains_node(node))
    }

    fn enqueue_node(&mut self, node: NodeId, context: u32) {
        if self.reached.insert(node, context) {
            self.pending_nodes.push(ClosureNodeState { node, context }.key());
        }
    }

    fn activate_fact_source(&mut self, node: NodeId, context: u32) -> bool {
        self.fact_source_states
            .insert(ClosureNodeState { node, context }.key())
    }

    fn fact_is_relevant(&self, base: u32, field: u32) -> bool {
        self.field_demand.contains(base, field)
            && self
                .target_relevance
                .is_none_or(|relevance| relevance.contains_fact(base, field))
    }

    fn enqueue_fact_state(&mut self, fact: SymbolicNodeFact) {
        if !self.fact_is_relevant(fact.base, fact.field) {
            return;
        }
        let key = fact.state_key();
        if self.facts.insert(key) {
            self.pending_facts.push(key);
        }
    }

    fn next_node(&mut self) -> Option<ClosureNodeState> {
        self.pending_nodes.pop().map(ClosureNodeState::from_key)
    }

    fn next_fact(&mut self) -> Option<SymbolicNodeFact> {
        self.pending_facts.pop().map(SymbolicNodeFact::from_state_key)
    }

    fn has_pending(&self) -> bool {
        !self.pending_nodes.is_empty() || !self.pending_facts.is_empty()
    }
}

struct SymbolicTransformContexts {
    next: Vec<u32>,
    completed: Option<u32>,
}

fn symbolic_node_allowed(
    unified: &UnifiedAddressSpace,
    worklist: &SymbolicClosureWorklist<'_>,
    node: NodeId,
) -> bool {
    worklist.node_is_relevant(node)
        && IdgQueryService::ws_node_func(unified, node)
            .is_some_and(|func| worklist.summary_func_is_active(func))
}

fn summary_dependency_is_permitted(
    summary_callees: Option<&AHashMap<FuncId, Vec<FuncId>>>,
    caller: FuncId,
    callee: FuncId,
) -> bool {
    summary_callees.is_none_or(|callees| {
        callees.get(&caller).is_some_and(|targets| {
            targets
                .binary_search_by_key(&callee.raw(), |func| func.raw())
                .is_ok()
        })
    })
}

fn activate_summary_call(
    summary_callees: Option<&AHashMap<FuncId, Vec<FuncId>>>,
    boundary: ContextBoundaryKey,
    worklist: &mut SymbolicClosureWorklist<'_>,
) -> bool {
    if !worklist.summary_func_is_active(boundary.caller)
        || !summary_dependency_is_permitted(summary_callees, boundary.caller, boundary.callee)
    {
        return false;
    }
    worklist.activate_summary_func(boundary.callee)
}

fn activate_summary_transition(
    unified: &UnifiedAddressSpace,
    summary_callees: Option<&AHashMap<FuncId, Vec<FuncId>>>,
    source: NodeId,
    target: NodeId,
    worklist: &mut SymbolicClosureWorklist<'_>,
) -> bool {
    if !worklist.node_is_relevant(target) {
        return false;
    }
    let Some(source_func) = IdgQueryService::ws_node_func(unified, source) else {
        return false;
    };
    let Some(target_func) = IdgQueryService::ws_node_func(unified, target) else {
        return false;
    };
    if worklist.summary_func_is_active(target_func) {
        return true;
    }
    if !worklist.summary_func_is_active(source_func)
        || !summary_dependency_is_permitted(summary_callees, source_func, target_func)
    {
        return false;
    }
    worklist.activate_summary_func(target_func)
}

fn symbolic_fact_key(base: u32, field: u32) -> u64 {
    (u64::from(base) << 32) | u64::from(field)
}

fn symbolic_transform_boundary(
    graph: &crate::symbolic::SymbolicFieldGraph,
    transform: &crate::symbolic::SymbolicFieldTransform,
) -> Option<(ContextBoundaryKey, bool)> {
    let source = graph.bases().get(transform.source as usize)?.func;
    let target = graph.bases().get(transform.target as usize)?.func;
    if source == target {
        return None;
    }
    let (caller, callee, enters) = match transform.kind {
        SymbolicFieldTransformKind::Argument => (source, target, true),
        SymbolicFieldTransformKind::Return
        | SymbolicFieldTransformKind::ScalarReturn
        | SymbolicFieldTransformKind::ConstructorReturn
        | SymbolicFieldTransformKind::ReceiverMutation => (target, source, false),
        SymbolicFieldTransformKind::Copy => return None,
    };
    Some((
        ContextBoundaryKey {
            caller,
            callee,
            span: transform.call_span,
        },
        enters,
    ))
}

fn record_symbolic_cross_call(
    graph: &crate::symbolic::SymbolicFieldGraph,
    transform: &crate::symbolic::SymbolicFieldTransform,
    out: Option<&mut AHashSet<CrossCallEdge>>,
) {
    let Some(out) = out else {
        return;
    };
    let Some(source) = graph.bases().get(transform.source as usize) else {
        return;
    };
    let Some(target) = graph.bases().get(transform.target as usize) else {
        return;
    };
    if source.func == target.func {
        return;
    }
    let Some(relation) = symbolic_cross_call_relation(transform.kind) else {
        return;
    };
    let (arg_idx, param_idx) = symbolic_cross_call_slots(transform);
    out.insert(CrossCallEdge {
        caller: source.func,
        callee: target.func,
        call_span: transform.call_span,
        arg_idx,
        param_idx,
        precision: transform.precision,
        call_kind: transform.call_kind,
        relation,
    });
}

fn symbolic_cross_call_relation(kind: SymbolicFieldTransformKind) -> Option<CrossCallRelation> {
    match kind {
        SymbolicFieldTransformKind::Argument => Some(CrossCallRelation::Argument),
        SymbolicFieldTransformKind::Return | SymbolicFieldTransformKind::ScalarReturn => {
            Some(CrossCallRelation::Return)
        }
        SymbolicFieldTransformKind::ConstructorReturn | SymbolicFieldTransformKind::ReceiverMutation => {
            Some(CrossCallRelation::FieldState)
        }
        SymbolicFieldTransformKind::Copy => None,
    }
}

fn symbolic_cross_call_slots(transform: &crate::symbolic::SymbolicFieldTransform) -> (u32, u32) {
    if transform.kind != SymbolicFieldTransformKind::Argument {
        return (u32::MAX, u32::MAX);
    }
    (transform.arg_idx, transform.param_idx)
}

/// Service handle for IDG queries. Wraps an [`IdgWorkspace`] and a
/// reference to the workspace's [`GlobalIndex`] (needed to
/// translate IDG nodes back to source spans).
///
/// The unified address space is built lazily; cheap to construct.
pub struct IdgQueryService {
    workspace: Arc<IdgWorkspace>,
    global: Arc<GlobalIndex>,
    unified: RwLock<Option<Arc<UnifiedAddressSpace>>>,
    /// Independently decodable exact query relations from the immutable
    /// semantic generation. Core compiler identity is opened at service load;
    /// contextual and symbolic products remain cold until an unscoped query
    /// actually requests them. Scoped queries compile only their exact
    /// function corridor from canonical IDG bodies.
    persisted_query_accelerator: Option<PersistedQueryAcceleratorParts>,
    return_summaries: Mutex<AHashMap<Option<Precision>, ReturnSummaryCache>>,
    /// One exact function-summary corridor is retained separately from the
    /// canonical global cache. A scoped negative must never become a global
    /// negative merely because a callee lived outside an earlier query.
    scoped_return_summaries: Mutex<Option<ScopedReturnSummaryCache>>,
    /// One exact scoped runtime is retained. Replacing it is safe because the
    /// runtime is a derived cache; recomputation changes no admitted facts.
    scoped_contextual_summary: Mutex<Option<ScopedContextualSummaryCache>>,
    /// Symbolic access-path facts are likewise compiled for the exact
    /// function corridor used by targeted queries. One evictable entry avoids
    /// retaining multiple body projections beside the canonical IDG.
    scoped_symbolic_runtime: Mutex<Option<ScopedSymbolicRuntimeCache>>,
    /// Renderable cross-call provenance for the same exact compiler scope,
    /// keyed by source node. Broad entry batches reuse this immutable index
    /// instead of rescanning the workspace relation once per source.
    scoped_cross_calls: Mutex<Option<ScopedCrossCallsCache>>,
}

struct ScopedContextualSummaryCache {
    max_precision: Option<Precision>,
    funcs: Box<[FuncId]>,
    runtime: Arc<ContextualSummaryRuntime>,
    batch: Arc<crate::function_summary::ReturnSummaryBatch>,
}

struct ScopedReturnSummaryCache {
    max_precision: Option<Precision>,
    funcs: Box<[FuncId]>,
    values: AHashMap<FuncId, Vec<u32>>,
}

struct ScopedSymbolicRuntimeCache {
    funcs: Box<[FuncId]>,
    runtime: Arc<SymbolicRuntimeIndex>,
}

struct ScopedCrossCallsCache {
    funcs: Box<[FuncId]>,
    rows: Arc<CrossCallsByFrom>,
}

#[derive(Default)]
struct ReturnSummaryCache {
    covered: AHashSet<FuncId>,
    values: AHashMap<FuncId, Vec<u32>>,
}

impl IdgQueryService {
    /// Open the canonical warm-query sidecar behind the query-service API.
    ///
    /// Paged segments and relations are deliberately not exposed as an
    /// [`IdgWorkspace`]: resident build workspaces have borrowing accessors,
    /// while a sidecar query may need to decode and own one segment page.
    /// Keeping that storage distinction private prevents callers from
    /// mistaking an evicted page for an absent compiler fact.
    pub fn load_from_disk(
        path: &std::path::Path,
        pipeline_hash: u64,
        global: Arc<GlobalIndex>,
    ) -> crate::IdgResult<Option<Self>> {
        let Some(workspace) = IdgWorkspace::load_query_from_disk(path, pipeline_hash)? else {
            return Ok(None);
        };
        let accelerator = workspace.query_accelerator_parts()?;
        let unified = accelerator
            .as_ref()
            .map(|parts| {
                bonsai_diagnostics::debug_log!(
                    "idg-query",
                    "accelerator frames core={} contextual={} symbolic_header={} fixed_blobs={}",
                    parts.core.len(),
                    parts.contextual.len(),
                    parts.symbolic_header.len(),
                    parts
                        .blobs
                        .values()
                        .map(QueryAcceleratorBlobReader::len)
                        .sum::<u64>()
                );
                PersistedQueryAccelerator::decode(parts.core.stream(), parts.core.len(), &workspace)
                    .map(PersistedQueryAccelerator::into_unified_core)
                    .map(Arc::new)
            })
            .transpose()?;
        Ok(Some(Self::from_parts(
            Arc::new(workspace),
            global,
            unified,
            accelerator,
        )))
    }

    /// Wrap a workspace + global index. The unified address space
    /// is **not** built here — it's deferred to first query.
    #[must_use]
    pub fn new(workspace: Arc<IdgWorkspace>, global: Arc<GlobalIndex>) -> Self {
        Self::from_parts(workspace, global, None, None)
    }

    fn from_parts(
        workspace: Arc<IdgWorkspace>,
        global: Arc<GlobalIndex>,
        unified: Option<Arc<UnifiedAddressSpace>>,
        persisted_query_accelerator: Option<PersistedQueryAcceleratorParts>,
    ) -> Self {
        Self {
            workspace,
            global,
            unified: RwLock::new(unified),
            persisted_query_accelerator,
            return_summaries: Mutex::new(AHashMap::new()),
            scoped_return_summaries: Mutex::new(None),
            scoped_contextual_summary: Mutex::new(None),
            scoped_symbolic_runtime: Mutex::new(None),
            scoped_cross_calls: Mutex::new(None),
        }
    }

    /// Compile the query-ready narrowed compiler relation that semantic
    /// prewarm persists beside the canonical graph. The payload is a cache of
    /// exact derived representation state: deleting it only makes the first
    /// query rebuild the same fixed point.
    pub fn compile_default_query_accelerator(self) -> crate::IdgResult<CompiledQueryAccelerator> {
        let unified = self.ensure_unified();
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator core-ready rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        let segment_count = u32::try_from(self.workspace.segment_count())
            .map_err(|_| invalid_query_accelerator("workspace IDG segment count exceeds u32"))?;
        let core = encode_query_accelerator_core(&unified, segment_count)?;
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator core-encoded rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );

        // The contextual and symbolic products are independently decodable
        // compiler relations. Serialize the first directly to its anonymous
        // publication spool, then release its live runtime before compiling
        // the second. Available memory changes only phase overlap, never the
        // graph or fixed-point scope.
        let contextual_runtime =
            self.ensure_contextual_summary_runtime(&unified, Some(SEMANTIC_MAX_PRECISION), None);
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator contextual-runtime-ready rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        let (contextual, mut blobs) = compile_contextual_query_accelerator(
            contextual_runtime.as_ref(),
            Self::unified_node_count(&unified),
        )?;
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator contextual-encoded rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        unified
            .contextual_summaries
            .write()
            .remove(&Some(SEMANTIC_MAX_PRECISION));
        drop(contextual_runtime);
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator contextual-released rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );

        // The core and contextual products are now complete anonymous files.
        // Global symbolic compilation only needs the stable segment-base
        // directory to translate segment-local nodes into workspace ids; it
        // does not need the other dense core arrays. Consume the compiler
        // service and release both owners of that core before opening the
        // symbolic relation. This keeps cold semantic prewarm from retaining
        // two independently persisted accelerator products at once.
        let segment_bases = unified.segment_bases.clone();
        let cached_unified = self.unified.write().take();
        drop(unified);
        drop(cached_unified);
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator core-released rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );

        let symbolic = self.build_symbolic_runtime_index_with_layout(&segment_bases, None, None);
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator symbolic-runtime-ready rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );

        let fact_pages = symbolic.fact_pages.lock();
        let transforms = symbolic.transforms.lock();
        let symbolic_header = encode_query_accelerator_frame(
            &PersistedSymbolicRuntimeRef {
                version: SYMBOLIC_RUNTIME_ACCELERATOR_VERSION,
                fields: &symbolic.fields,
                spans: &symbolic.spans,
                ordering_sensitive_bases: &symbolic.ordering_sensitive_bases,
                exact_reads: &symbolic.exact_reads,
                projected_fact_keys: &symbolic.projected_fact_keys,
                aggregate_reads: &symbolic.aggregate_reads,
                scalar_writes: &symbolic.scalar_writes,
                storage_reads: &symbolic.storage_reads,
                storage_writes: &symbolic.storage_writes,
                fact_sources: symbolic.fact_sources.persisted_metadata(),
                aggregate_inputs: &symbolic.aggregate_inputs,
                aggregate_outputs: &symbolic.aggregate_outputs,
                resolved_call_args: &symbolic.resolved_call_args,
                reverse_transforms: symbolic.reverse_transforms.persisted_metadata(),
                reverse_scalar_transforms: symbolic.reverse_scalar_transforms.persisted_metadata(),
                fact_page_entries: &fact_pages.entries,
                fact_page_bytes: fact_pages.write_offset,
                transform_offsets: &transforms.offsets,
            },
            "symbolic",
        )?;
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator symbolic-header-encoded rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );

        let fact_file = fact_pages.snapshot_file()?;
        let transform_file = transforms.snapshot_file()?;
        drop(transforms);
        drop(fact_pages);
        let fact_source_file = symbolic.fact_sources.snapshot_file()?;
        let reverse_transform_file = symbolic.reverse_transforms.snapshot_file()?;
        let reverse_scalar_file = symbolic.reverse_scalar_transforms.snapshot_file()?;
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "compile accelerator symbolic-files-ready rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        blobs.extend([
            compiled_query_blob(QueryAcceleratorBlobKind::SymbolicFacts, fact_file)?,
            compiled_query_blob(QueryAcceleratorBlobKind::SymbolicTransforms, transform_file)?,
            compiled_query_blob(QueryAcceleratorBlobKind::FactSources, fact_source_file)?,
            compiled_query_blob(
                QueryAcceleratorBlobKind::ReverseSymbolicTransforms,
                reverse_transform_file,
            )?,
            compiled_query_blob(
                QueryAcceleratorBlobKind::ReverseScalarTransforms,
                reverse_scalar_file,
            )?,
        ]);
        Ok(CompiledQueryAccelerator {
            core,
            contextual,
            symbolic_header,
            blobs: Arc::from(blobs.into_boxed_slice()),
        })
    }

    /// Number of segments in the underlying workspace.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.workspace.segment_count()
    }

    /// Compact Tree-sitter/resolver linkage retained with this query service.
    ///
    /// Broad compiler consumers can use these stable declaration/type headers
    /// while streaming exact file bodies, instead of materializing a second
    /// workspace-wide body index beside the IDG.
    #[must_use]
    pub fn global_linkage_index(&self) -> Arc<GlobalIndex> {
        Arc::clone(&self.global)
    }

    /// Number of intra-segment edges across all segments.
    #[must_use]
    pub fn intra_edge_count(&self) -> usize {
        self.workspace.intra_edge_count()
    }

    /// Number of cross-file edges in the workspace index.
    #[must_use]
    pub fn cross_file_edge_count(&self) -> usize {
        self.workspace.cross_file_edge_count()
    }

    /// Release derived query indexes while retaining the canonical IDG.
    ///
    /// Batch compiler consumers often need one expensive projection followed
    /// by source-local streaming work. Dropping the unified address space at
    /// that phase boundary prevents CSR, contextual, and symbolic indexes
    /// from remaining live solely because the reusable service is cached.
    /// Any later graph query reconstructs the exact indexes on demand.
    pub fn release_query_indexes(&self) {
        // Match the scoped query lock order (summaries, contextual, symbolic,
        // cross calls, unified) so
        // a concurrent phase release cannot deadlock a query compiling its
        // exact runtimes.
        *self.scoped_return_summaries.lock() = None;
        *self.scoped_contextual_summary.lock() = None;
        *self.scoped_symbolic_runtime.lock() = None;
        *self.scoped_cross_calls.lock() = None;
        *self.unified.write() = None;
    }

    /// Compute parameter-to-return summaries for `funcs` inside the requested
    /// precision scope.
    ///
    /// Each function is compacted to a function-local CSR. Resolved call
    /// inputs and outputs are then composed with a monotone summary worklist,
    /// so recursion reaches a complete least fixed point without allocating a
    /// workspace-sized closure per function or applying an iteration cap.
    pub fn return_taint_param_indices_for_funcs_with_max_precision(
        &self,
        funcs: &[FuncId],
        max_precision: Option<Precision>,
    ) -> AHashMap<FuncId, Vec<u32>> {
        self.ensure_return_taint_summaries(funcs, max_precision);
        let summaries = self.return_summaries.lock();
        let Some(cache) = summaries.get(&max_precision) else {
            return AHashMap::new();
        };
        funcs
            .iter()
            .copied()
            .map(|func| (func, cache.values.get(&func).cloned().unwrap_or_default()))
            .collect()
    }

    /// Compile and retain parameter-to-return summaries for `funcs`.
    ///
    /// Broad semantic consumers call this once for their exact compiler scope.
    /// Later single-function queries reuse the same immutable facts rather
    /// than rebuilding the workspace summary fixed point per source.
    pub fn prewarm_return_taint_param_indices_for_funcs_with_max_precision(
        &self,
        funcs: &[FuncId],
        max_precision: Option<Precision>,
    ) {
        self.ensure_return_taint_summaries(funcs, max_precision);
    }

    /// Compute parameter-to-return summaries inside one exact compiler
    /// function corridor.
    ///
    /// The complete corridor is solved and cached as one immutable entry so
    /// repeated entry-point queries reuse the same least fixed point. Scoped
    /// results are kept separate from global summaries: excluding a function
    /// changes the compiler program being queried, never the amount of work
    /// performed within that program.
    pub fn return_taint_param_indices_for_funcs_within_funcs_with_max_precision(
        &self,
        funcs: &[FuncId],
        allowed_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> AHashMap<FuncId, Vec<u32>> {
        self.ensure_scoped_return_taint_summaries(allowed_funcs, max_precision);
        let cache = self.scoped_return_summaries.lock();
        let Some(cache) = cache.as_ref() else {
            return AHashMap::new();
        };
        funcs
            .iter()
            .copied()
            .map(|func| (func, cache.values.get(&func).cloned().unwrap_or_default()))
            .collect()
    }

    fn ensure_scoped_return_taint_summaries(
        &self,
        allowed_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) {
        let mut funcs: Vec<FuncId> = allowed_funcs.iter().copied().collect();
        funcs.sort_unstable_by_key(|func| func.raw());
        funcs.dedup();
        let mut cache = self.scoped_return_summaries.lock();
        if cache.as_ref().is_some_and(|cache| {
            cache.max_precision == max_precision && cache.funcs.as_ref() == funcs.as_slice()
        }) {
            return;
        }
        let values = self.compile_return_taint_param_indices(&funcs, max_precision, Some(allowed_funcs));
        *cache = Some(ScopedReturnSummaryCache {
            max_precision,
            funcs: funcs.into_boxed_slice(),
            values,
        });
    }

    fn ensure_return_taint_summaries(&self, funcs: &[FuncId], max_precision: Option<Precision>) {
        let mut caches = self.return_summaries.lock();
        let cache = caches.entry(max_precision).or_default();
        let mut missing: Vec<FuncId> = funcs
            .iter()
            .copied()
            .filter(|func| !cache.covered.contains(func))
            .collect();
        missing.sort_unstable_by_key(|func| func.raw());
        missing.dedup();
        if missing.is_empty() {
            return;
        }
        let mut compiled = self.compile_return_taint_param_indices(&missing, max_precision, None);
        for func in missing {
            cache
                .values
                .insert(func, compiled.remove(&func).unwrap_or_default());
            cache.covered.insert(func);
        }
    }

    fn compile_return_taint_param_indices(
        &self,
        funcs: &[FuncId],
        max_precision: Option<Precision>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> AHashMap<FuncId, Vec<u32>> {
        let summary_started = std::time::Instant::now();
        let cached_scoped = allowed_funcs.and_then(|allowed_funcs| {
            let mut scope: Vec<FuncId> = allowed_funcs.iter().copied().collect();
            scope.sort_unstable_by_key(|func| func.raw());
            scope.dedup();
            let cache = self.scoped_contextual_summary.lock();
            cache
                .as_ref()
                .filter(|cache| {
                    cache.max_precision == max_precision && cache.funcs.as_ref() == scope.as_slice()
                })
                .map(|cache| (Arc::clone(&cache.batch), Arc::clone(&cache.runtime)))
        });
        let (mut batch, cached_contextual_runtime) = if let Some((batch, runtime)) = cached_scoped {
            ((*batch).clone(), Some(runtime))
        } else {
            (
                run_isolated_compiler_phase(|| {
                    crate::function_summary::return_taint_param_indices_in_scope(
                        &self.workspace,
                        funcs,
                        allowed_funcs,
                        max_precision,
                    )
                }),
                None,
            )
        };
        bonsai_diagnostics::debug_log!(
            "idg-summary",
            "ordinary compiler summaries funcs={} symbolic_sensitive={} contextual_edges={} cached_scope={} elapsed={:.3}s",
            funcs.len(),
            batch.symbolic_sensitive.len(),
            batch.contextual_edges.len(),
            cached_contextual_runtime.is_some(),
            summary_started.elapsed().as_secs_f64()
        );
        if self.workspace.has_symbolic_transforms() {
            // Return-summary compilation is a forward dataflow pass. Build
            // its exact contextual relation without the reverse CSR and
            // reverse contextual side index used only by later target-cut
            // queries. Interactive consumers reconstruct the bidirectional
            // runtime on demand; export releases query indexes after this
            // phase.
            let contextual_runtime = cached_contextual_runtime.unwrap_or_else(|| {
                run_isolated_compiler_phase(|| {
                    Arc::new(self.build_contextual_summary_runtime_with_reverse(
                        &batch.contextual_edges,
                        max_precision,
                        false,
                        allowed_funcs,
                    ))
                })
            });
            bonsai_diagnostics::debug_log!(
                "idg-summary",
                "contextual compiler runtime elapsed={:.3}s",
                summary_started.elapsed().as_secs_f64()
            );
            let unified = self.ensure_unified();
            run_isolated_compiler_phase(|| {
                self.ensure_symbolic_runtime(&unified, allowed_funcs);
            });
            bonsai_diagnostics::debug_log!(
                "idg-summary",
                "symbolic compiler runtime elapsed={:.3}s",
                summary_started.elapsed().as_secs_f64()
            );
            let symbolic_sensitive = Arc::new(batch.symbolic_sensitive.clone());
            let symbolic_callees = Arc::new(batch.symbolic_callees.clone());
            let mut symbolic_funcs: Vec<FuncId> = funcs
                .iter()
                .copied()
                .filter(|func| symbolic_sensitive.contains(func))
                .collect();
            symbolic_funcs.sort_unstable_by_key(|func| {
                (
                    self.workspace
                        .segment_for_func(*func)
                        .map_or(u32::MAX, |segment| segment.0),
                    func.raw(),
                )
            });
            let completed_funcs = AtomicUsize::new(0);
            let closure_runs = AtomicUsize::new(0);
            let union_negatives = AtomicUsize::new(0);
            let summarize = |func: &FuncId| {
                let func = *func;
                let result = (|| {
                    let return_node = self.return_node_of(func)?;
                    let params = self.param_nodes_of(func);
                    let mut returning = batch.indices.get(&func).cloned().unwrap_or_default();
                    if returning.len() >= params.len() {
                        return Some((func, returning));
                    }
                    let already_returning: AHashSet<u32> = returning.iter().copied().collect();
                    let candidates: Vec<(u32, WsNodeId)> = params
                        .into_iter()
                        .enumerate()
                        .filter_map(|(index, param)| {
                            let index = u32::try_from(index).expect("parameter index exceeds u32");
                            (!already_returning.contains(&index)).then_some((index, param))
                        })
                        .collect();
                    let reaches_return = |seeds: &[WsNodeId]| {
                        closure_runs.fetch_add(1, AtomicOrdering::Relaxed);
                        self.contextual_forward_closure_for_summary_with_max_precision(
                            seeds,
                            func,
                            symbolic_callees.as_ref(),
                            max_precision,
                            contextual_runtime.as_ref(),
                            allowed_funcs,
                        )
                        .contains(&return_node)
                    };
                    // A union seed is an exact negative proof: if no candidate
                    // reaches the return, no per-parameter traversal is needed.
                    // Positive unions are split back into individual compiler
                    // facts so provenance is never merged in the emitted summary.
                    if candidates.len() > 1 {
                        let seeds: Vec<WsNodeId> = candidates.iter().map(|(_, param)| *param).collect();
                        if !reaches_return(&seeds) {
                            union_negatives.fetch_add(1, AtomicOrdering::Relaxed);
                            return Some((func, returning));
                        }
                    }
                    for (index, param) in candidates {
                        if reaches_return(&[param]) {
                            returning.push(index);
                        }
                    }
                    returning.sort_unstable();
                    returning.dedup();
                    Some((func, returning))
                })();
                let completed = completed_funcs.fetch_add(1, AtomicOrdering::Relaxed) + 1;
                if completed.is_multiple_of(10_000) {
                    bonsai_diagnostics::debug_log!(
                        "idg-summary",
                        "symbolic compiler progress funcs={}/{} closures={} union_negatives={} elapsed={:.3}s",
                        completed,
                        symbolic_funcs.len(),
                        closure_runs.load(AtomicOrdering::Relaxed),
                        union_negatives.load(AtomicOrdering::Relaxed),
                        summary_started.elapsed().as_secs_f64()
                    );
                }
                result
            };
            // Memory budgets schedule concurrent compiler closures; they do
            // not cap functions, parameters, paths, or fixed-point work. A
            // constrained host executes the identical symbolic summaries
            // serially while larger hosts use a dedicated bounded pool.
            let workers = bonsai_common::compiler_worker_count(rayon::current_num_threads());
            let updates: Vec<(FuncId, Vec<u32>)> = if workers == 1 {
                symbolic_funcs.iter().filter_map(summarize).collect()
            } else {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .thread_name(|index| format!("bonsai-idg-summary-{index}"))
                    .build()
                    .expect("build memory-bounded IDG summary pool")
                    .install(|| symbolic_funcs.par_iter().filter_map(summarize).collect())
            };
            for (func, returning) in updates {
                batch.indices.insert(func, returning);
            }
            bonsai_diagnostics::debug_log!(
                "idg-summary",
                "symbolic compiler summaries funcs={} elapsed={:.3}s",
                symbolic_funcs.len(),
                summary_started.elapsed().as_secs_f64()
            );
        }
        batch.indices
    }

    fn contextual_forward_closure_for_summary_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        root: FuncId,
        summary_callees: &AHashMap<FuncId, Vec<FuncId>>,
        max_precision: Option<Precision>,
        contextual: &ContextualSummaryRuntime,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        self.symbolic_forward_closure_nodes(
            &unified,
            &contextual.reach,
            &seed_nodes,
            SymbolicClosurePolicy {
                max_precision,
                allowed_funcs,
                target_relevance: None,
                summary_callees: Some(summary_callees),
                summary_root: Some(root),
                contextual: Some(contextual),
                activate_seed_callers: false,
            },
            None,
        )
        .into_iter()
        .map(|node| WsNodeId(node.0))
        .collect()
    }

    /// Compute the function-local read/write storage reached from each formal
    /// parameter in `funcs`.
    ///
    /// The outer vector is indexed by parameter position. Traversal uses a
    /// compact CSR and bitset sized to the owning function, never to the whole
    /// workspace. All retained edges run to closure; `max_precision` filters
    /// evidence strength rather than limiting semantic work.
    pub fn local_storage_taint_by_param_for_funcs_with_max_precision(
        &self,
        funcs: &[FuncId],
        max_precision: Option<Precision>,
    ) -> AHashMap<FuncId, Vec<Vec<String>>> {
        crate::function_summary::local_storage_taint_by_param(&self.workspace, funcs, max_precision)
    }

    /// Stream the same exact function-local summaries as
    /// [`Self::local_storage_taint_by_param_for_funcs_with_max_precision`]
    /// while retaining only one source segment's compact graphs and one
    /// function's rendered result at a time.
    pub fn try_visit_local_storage_taint_by_param_for_funcs_with_max_precision<E>(
        &self,
        funcs: &[FuncId],
        max_precision: Option<Precision>,
        visit: impl FnMut(FuncId, Vec<Vec<String>>) -> Result<(), E>,
    ) -> Result<(), E> {
        crate::function_summary::try_visit_local_storage_taint_by_param(
            &self.workspace,
            funcs,
            max_precision,
            visit,
        )
    }

    /// Resolve a [`PointRef`] back from a [`WsNodeId`].
    pub fn resolve_point(&self, ws_node: WsNodeId) -> Option<PointRef> {
        let unified = self.ensure_unified();
        let (seg_id, local_node) = Self::ws_address(&unified, ws_node)?;
        let segment = self.workspace.segment_view(seg_id)?;
        let idg_node = segment.nodes.get(local_node)?;
        let place = segment.places.get(idg_node.place)?;
        Some(self.build_point_ref(idg_node.func, place))
    }

    /// Return the compiler identity of a call-argument node.
    ///
    /// Unlike [`Self::resolve_point`], this preserves the positional index as
    /// structured data. Target-cut consumers use it to compare exact sink
    /// argument nodes without parsing a rendered place name.
    #[must_use]
    pub fn call_arg_identity(&self, ws_node: WsNodeId) -> Option<(FuncId, Span, u32)> {
        let unified = self.ensure_unified();
        let func = *unified.node_funcs.get(ws_node.0 as usize)?;
        let (site, idx) = unified.call_args.get(ws_node)?;
        Some((func, site, idx))
    }

    /// Owning compiler function for one workspace-global IDG node.
    #[must_use]
    pub fn func_of_node(&self, ws_node: WsNodeId) -> Option<FuncId> {
        self.ensure_unified().node_funcs.get(ws_node.0 as usize).copied()
    }

    /// Semantic forward closure: which nodes are reachable from `seeds`
    /// through exact or narrowed edges?
    ///
    /// This is the default evidence-producing reachability surface.
    /// Diagnostic callers that need to inspect weaker edges must call
    /// [`Self::forward_closure_with_max_precision`] explicitly.
    ///
    /// Returns the set of [`WsNodeId`]s in the closure (always
    /// includes the seeds themselves).
    pub fn forward_closure(&self, seeds: &[WsNodeId]) -> Vec<WsNodeId> {
        self.forward_closure_with_max_precision(seeds, Some(SEMANTIC_MAX_PRECISION))
    }

    fn forward_closure_unfiltered(&self, seeds: &[WsNodeId]) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|w| NodeId(w.0)).collect();
        let contextual = self.ensure_contextual_summary_runtime(&unified, None, None);
        self.symbolic_forward_closure_nodes(
            &unified,
            &contextual.reach,
            &seed_nodes,
            SymbolicClosurePolicy {
                max_precision: None,
                allowed_funcs: None,
                target_relevance: None,
                summary_callees: None,
                summary_root: None,
                contextual: Some(contextual.as_ref()),
                activate_seed_callers: true,
            },
            None,
        )
        .into_iter()
        .map(|n| WsNodeId(n.0))
        .collect()
    }

    /// Forward closure constrained to edges whose precision is at or
    /// below `max_precision`. `None` is an explicit diagnostic
    /// unfiltered closure and must not be used as user-visible
    /// evidence.
    ///
    /// This is still exact for the requested precision scope: every
    /// retained edge is explored to fixpoint, and every excluded edge
    /// is outside the caller's declared precision contract.
    pub fn forward_closure_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        let Some(max_precision) = max_precision else {
            return self.forward_closure_unfiltered(seeds);
        };
        let unified = self.ensure_unified();
        let contextual = self.ensure_contextual_summary_runtime(&unified, Some(max_precision), None);
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|w| NodeId(w.0)).collect();
        self.symbolic_forward_closure_nodes(
            &unified,
            &contextual.reach,
            &seed_nodes,
            SymbolicClosurePolicy {
                max_precision: Some(max_precision),
                allowed_funcs: None,
                target_relevance: None,
                summary_callees: None,
                summary_root: None,
                contextual: Some(contextual.as_ref()),
                activate_seed_callers: true,
            },
            None,
        )
        .into_iter()
        .map(|n| WsNodeId(n.0))
        .collect()
    }

    /// Exact forward closure inside a compiler-proven function set.
    ///
    /// This is a semantic restriction, not a traversal budget: all nodes,
    /// call contexts, heap transitions, and symbolic field facts owned by an
    /// admitted function run to fixed point. Security uses it after deriving
    /// a complete source-to-sink corridor from the resolved call graph.
    pub fn forward_closure_within_funcs_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        allowed_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        self.forward_closure_within_func_scope(seeds, allowed_funcs, None, max_precision)
    }

    /// Exact function-scoped closure additionally restricted by a reusable
    /// target relevance proof.
    pub fn forward_closure_within_funcs_and_relevance_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        allowed_funcs: &AHashSet<FuncId>,
        target_relevance: &IdgTargetRelevance,
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        self.forward_closure_within_func_scope(seeds, allowed_funcs, Some(target_relevance), max_precision)
    }

    fn forward_closure_within_func_scope(
        &self,
        seeds: &[WsNodeId],
        allowed_funcs: &AHashSet<FuncId>,
        target_relevance: Option<&IdgTargetRelevance>,
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        if seeds.is_empty() || allowed_funcs.is_empty() {
            return Vec::new();
        }
        let unified = self.ensure_unified();
        let contextual = self.ensure_contextual_summary_runtime(&unified, max_precision, Some(allowed_funcs));
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        self.symbolic_forward_closure_nodes(
            &unified,
            &contextual.reach,
            &seed_nodes,
            SymbolicClosurePolicy {
                max_precision,
                allowed_funcs: Some(allowed_funcs),
                target_relevance,
                summary_callees: None,
                summary_root: None,
                contextual: Some(contextual.as_ref()),
                activate_seed_callers: true,
            },
            None,
        )
        .into_iter()
        .map(|node| WsNodeId(node.0))
        .collect()
    }

    /// Compute the semantic forward closure and retain the symbolic
    /// cross-function transitions that actually fired while solving it.
    ///
    /// This is the provenance-preserving query used by taint/reporting
    /// consumers. It runs the same finite compiler fixed point as
    /// [`Self::forward_closure_with_max_precision`]; it does not perform a
    /// second graph traversal or infer transitions from identifier text.
    pub fn forward_closure_evidence_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> IdgClosureEvidence {
        self.forward_closure_evidence_in_func_scope(seeds, max_precision, None, None, None)
    }

    /// Provenance-preserving counterpart to
    /// [`Self::forward_closure_within_funcs_with_max_precision`].
    pub fn forward_closure_evidence_within_funcs_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        allowed_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> IdgClosureEvidence {
        if seeds.is_empty() || allowed_funcs.is_empty() {
            return IdgClosureEvidence {
                nodes: Vec::new(),
                cross_calls: Vec::new(),
            };
        }
        self.forward_closure_evidence_in_func_scope(seeds, max_precision, Some(allowed_funcs), None, None)
    }

    /// Provenance-preserving exact closure using both a compiler function
    /// corridor and a reusable target relevance proof.
    pub fn forward_closure_evidence_within_funcs_and_relevance_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        allowed_funcs: &AHashSet<FuncId>,
        target_relevance: &IdgTargetRelevance,
        max_precision: Option<Precision>,
    ) -> IdgClosureEvidence {
        if seeds.is_empty() || allowed_funcs.is_empty() {
            return IdgClosureEvidence {
                nodes: Vec::new(),
                cross_calls: Vec::new(),
            };
        }
        self.forward_closure_evidence_in_func_scope(
            seeds,
            max_precision,
            Some(allowed_funcs),
            Some(target_relevance),
            None,
        )
    }

    /// Provenance-preserving closure whose call stack is rooted at one
    /// compiler entry function.
    ///
    /// Entry-oriented tools seed parameters and local writes of `root`; such
    /// a seed may enter callees through exact call boundaries and return only
    /// through its matching context, but it must not escape into unrelated
    /// callers of `root`. Rule-matched security sources deliberately use the
    /// unrooted APIs because a source discovered in a helper may flow back to
    /// any resolved caller. This distinction is semantic query scope, not a
    /// traversal limit: every state reachable from the rooted call stack runs
    /// to the same fixed point.
    pub fn forward_closure_evidence_rooted_at_func_within_funcs_and_relevance_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        root: FuncId,
        allowed_funcs: &AHashSet<FuncId>,
        target_relevance: Option<&IdgTargetRelevance>,
        max_precision: Option<Precision>,
    ) -> IdgClosureEvidence {
        if seeds.is_empty() || allowed_funcs.is_empty() || !allowed_funcs.contains(&root) {
            return IdgClosureEvidence {
                nodes: Vec::new(),
                cross_calls: Vec::new(),
            };
        }
        self.forward_closure_evidence_in_func_scope(
            seeds,
            max_precision,
            Some(allowed_funcs),
            target_relevance,
            Some(root),
        )
    }

    /// Unscoped compiler-program counterpart to
    /// [`Self::forward_closure_evidence_rooted_at_func_within_funcs_and_relevance_with_max_precision`].
    /// The root still constrains call-stack direction; every function reached
    /// through an exact call boundary remains eligible.
    pub fn forward_closure_evidence_rooted_at_func_and_relevance_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        root: FuncId,
        target_relevance: Option<&IdgTargetRelevance>,
        max_precision: Option<Precision>,
    ) -> IdgClosureEvidence {
        if seeds.is_empty() {
            return IdgClosureEvidence {
                nodes: Vec::new(),
                cross_calls: Vec::new(),
            };
        }
        self.forward_closure_evidence_in_func_scope(seeds, max_precision, None, target_relevance, Some(root))
    }

    /// Prove whether an entry-rooted scalar query can reach one of its exact
    /// owner-local target nodes using the compiler's already-composed
    /// function summaries.
    ///
    /// `Some(false)` is an exact negative proof. `None` means the function
    /// owns projected storage or the targets are not wholly owner-local, so
    /// the caller must run the full symbolic/contextual fixed point. A
    /// positive scalar proof is only a candidate and is likewise confirmed by
    /// the full closure so provenance and cross-call evidence stay complete.
    pub fn rooted_scalar_target_precheck_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        root: FuncId,
        target_nodes: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Option<bool> {
        if seeds.is_empty() || target_nodes.is_empty() {
            return Some(false);
        }
        let unified = self.ensure_unified();
        let root_nodes = unified.nodes_by_func.get(root)?;
        if root_nodes
            .iter()
            .any(|node| unified.projected_storage.get(node.0 as usize).copied() == Some(1))
        {
            return None;
        }
        let targets: AHashSet<u32> = target_nodes
            .iter()
            .map(|node| NodeId(node.0))
            .map(|node| (Self::ws_node_func(&unified, node) == Some(root)).then_some(node.0))
            .collect::<Option<_>>()?;
        let contextual = self.ensure_contextual_summary_runtime(&unified, max_precision, None);
        let runtime = self.ensure_symbolic_runtime(&unified, None);
        let mut reached = AHashSet::with_capacity(seeds.len());
        let mut pending = Vec::with_capacity(seeds.len());
        for seed in seeds.iter().map(|node| NodeId(node.0)) {
            if Self::ws_node_func(&unified, seed) == Some(root) && reached.insert(seed.0) {
                if targets.contains(&seed.0) {
                    return Some(true);
                }
                pending.push(seed);
            }
        }
        while let Some(node) = pending.pop() {
            let mut enqueue = |target: NodeId| {
                if Self::ws_node_func(&unified, target) != Some(root) || !reached.insert(target.0) {
                    return false;
                }
                pending.push(target);
                targets.contains(&target.0)
            };
            let mut matched = false;
            contextual.reach.visit_forward(node, |target| {
                matched |= enqueue(target);
            });
            if matched {
                return Some(true);
            }
            if let Some(outputs) = runtime.aggregate_outputs.get(&node) {
                for output in outputs {
                    if runtime.resolved_call_args.contains(output) {
                        continue;
                    }
                    if enqueue(NodeId(output.0)) {
                        return Some(true);
                    }
                }
            }
        }
        Some(false)
    }

    fn forward_closure_evidence_in_func_scope(
        &self,
        seeds: &[WsNodeId],
        max_precision: Option<Precision>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
        target_relevance: Option<&IdgTargetRelevance>,
        root: Option<FuncId>,
    ) -> IdgClosureEvidence {
        let unified = self.ensure_unified();
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        let contextual = self.ensure_contextual_summary_runtime(&unified, max_precision, allowed_funcs);
        // One transform can fire for every access-path field and caller
        // context. Cross-call evidence is transform identity, not fixed-point
        // multiplicity, so deduplicate at insertion instead of retaining
        // millions of duplicate rows until the closure finishes.
        let mut cross_calls = AHashSet::new();
        let nodes = self
            .symbolic_forward_closure_nodes(
                &unified,
                &contextual.reach,
                &seed_nodes,
                SymbolicClosurePolicy {
                    max_precision,
                    allowed_funcs,
                    target_relevance,
                    summary_callees: None,
                    summary_root: root,
                    contextual: Some(contextual.as_ref()),
                    activate_seed_callers: root.is_none(),
                },
                Some(&mut cross_calls),
            )
            .into_iter()
            .map(|node| WsNodeId(node.0))
            .collect();
        let mut cross_calls: Vec<_> = cross_calls.into_iter().collect();
        cross_calls.sort_unstable_by_key(|edge| {
            (
                edge.caller.raw(),
                edge.callee.raw(),
                edge.call_span,
                edge.arg_idx,
                edge.param_idx,
                edge.precision,
                edge.relation,
            )
        });
        IdgClosureEvidence { nodes, cross_calls }
    }

    /// Exact forward closure restricted to nodes owned by `func`.
    ///
    /// Export and other intraprocedural projections use this instead of a
    /// target-function cut: the latter may legitimately include callees that
    /// flow back into the target, while this API never leaves the function's
    /// compiler-derived node set.
    pub fn forward_closure_within_func_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        func: FuncId,
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        if seeds.is_empty() {
            return Vec::new();
        }
        let unified = self.ensure_unified();
        let Some(func_nodes) = unified.nodes_by_func.get(func) else {
            return Vec::new();
        };
        let allowed = NodeBitSet::from_seed(Self::unified_node_count(&unified), func_nodes);
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        self.forward_closure_nodes_within(&unified, &seed_nodes, &allowed, max_precision)
            .into_iter()
            .map(|node| WsNodeId(node.0))
            .collect()
    }

    /// Context-matched forward closure when at least one requested target
    /// function is reached; otherwise empty.
    ///
    /// Security scopes the service to its source/sink callgraph corridor
    /// before querying, so returning the complete realizable closure retains
    /// symbolic path evidence that a raw backward graph cut cannot see.
    pub fn forward_target_func_cut_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        target_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        if seeds.is_empty() || target_funcs.is_empty() {
            return Vec::new();
        }
        let unified = self.ensure_unified();
        let closure = self.forward_closure_with_max_precision(seeds, max_precision);
        if closure.iter().any(|node| {
            unified
                .node_funcs
                .get(node.0 as usize)
                .is_some_and(|func| target_funcs.contains(func))
        }) {
            closure
        } else {
            Vec::new()
        }
    }

    /// Context-matched forward closure when at least one concrete target IDG
    /// node is reached; otherwise empty.
    pub fn forward_target_nodes_cut_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        target_nodes: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        if seeds.is_empty() || target_nodes.is_empty() {
            return Vec::new();
        }
        let targets: AHashSet<WsNodeId> = target_nodes.iter().copied().collect();
        let closure = self.forward_closure_with_max_precision(seeds, max_precision);
        if self.closure_reaches_target_nodes(&closure, &targets) {
            closure
        } else {
            Vec::new()
        }
    }

    /// Exact target-presence query inside a compiler-proven function set.
    ///
    /// The returned closure is complete for `allowed_funcs`; an empty result
    /// means no requested scalar or aggregate-consumption target was reached.
    pub fn forward_target_nodes_cut_within_funcs_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        target_nodes: &[WsNodeId],
        allowed_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        if seeds.is_empty() || target_nodes.is_empty() || allowed_funcs.is_empty() {
            return Vec::new();
        }
        let targets: AHashSet<WsNodeId> = target_nodes.iter().copied().collect();
        let closure =
            self.forward_closure_within_funcs_with_max_precision(seeds, allowed_funcs, max_precision);
        if self.closure_reaches_target_nodes(&closure, &targets) {
            closure
        } else {
            Vec::new()
        }
    }

    /// Compile one reusable backward demand relation for target nodes and
    /// fallback target functions.
    ///
    /// The relation follows ordinary IDG edges in reverse and composes the
    /// reverse of the symbolic access-path algebra. Call contexts and source
    /// ordering are intentionally ignored, making this a conservative
    /// superset suitable for pruning exact forward closures. No language
    /// names, API inventories, depth limits, or result caps participate.
    pub fn target_relevance_with_max_precision(
        &self,
        target_nodes: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
        max_precision: Option<Precision>,
    ) -> IdgTargetRelevance {
        self.target_relevance_in_func_scope(target_nodes, target_funcs, None, None, max_precision)
    }

    /// Compile a backward demand relation inside an exact compiler function
    /// corridor.
    ///
    /// This is the demand-analysis counterpart to
    /// [`Self::forward_closure_within_funcs_and_relevance_with_max_precision`].
    /// It is useful when one workspace graph serves many independent source
    /// queries: each query receives only the target facts in its proven
    /// callgraph corridor instead of inheriting demand from unrelated sinks.
    /// The function set is a semantic graph slice, not a work budget; every
    /// admitted node and symbolic fact runs to the same least fixed point.
    pub fn target_relevance_within_funcs_with_max_precision(
        &self,
        target_nodes: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
        allowed_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> IdgTargetRelevance {
        self.target_relevance_in_func_scope(
            target_nodes,
            target_funcs,
            Some(allowed_funcs),
            None,
            max_precision,
        )
    }

    /// Compile a source-rooted backward demand proof for one syntax owner.
    ///
    /// The backward solver activates callees only through exact return/heap
    /// compiler relations and permits argument edges back only into an
    /// already-active caller. This is the reverse pushdown counterpart of the
    /// context-matched forward closure: unrelated callers of a shared helper
    /// never enter the proof, while every provider reachable from `source`
    /// remains admitted to the same uncapped fixed point.
    pub fn target_relevance_from_source_within_funcs_with_max_precision(
        &self,
        source: FuncId,
        target_nodes: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
        allowed_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> IdgTargetRelevance {
        self.target_relevance_in_func_scope(
            target_nodes,
            target_funcs,
            Some(allowed_funcs),
            Some(source),
            max_precision,
        )
    }

    /// Keep only source functions that own at least one node in an exact
    /// backward target-demand relation.
    ///
    /// This is a compiler-header prefilter for multi-entry queries. A function
    /// with no relevant node cannot contribute any possible seed to a target;
    /// omitting it avoids opening its body and running an immediately empty
    /// forward closure. Input order is preserved and no path-bearing source is
    /// removed because the relevance relation is conservative.
    #[must_use]
    pub fn funcs_admitted_by_target_relevance(
        &self,
        funcs: &[FuncId],
        relevance: &IdgTargetRelevance,
    ) -> Vec<FuncId> {
        let unified = self.ensure_unified();
        funcs
            .iter()
            .copied()
            .filter(|func| {
                unified
                    .nodes_by_func
                    .get(*func)
                    .is_some_and(|nodes| nodes.iter().any(|node| relevance.contains_node(*node)))
            })
            .collect()
    }

    fn target_relevance_in_func_scope(
        &self,
        target_nodes: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
        source_root: Option<FuncId>,
        max_precision: Option<Precision>,
    ) -> IdgTargetRelevance {
        let unified = self.ensure_unified();
        let contextual = self.ensure_contextual_summary_runtime(&unified, max_precision, allowed_funcs);
        let runtime = self.ensure_symbolic_runtime(&unified, allowed_funcs);
        let symbolic = self.workspace.symbolic_field();
        let mut worklist = TargetRelevanceWorklist::new(Self::unified_node_count(&unified));
        let mut active_funcs = source_root.map(|source| AHashSet::from([source]));
        let func_is_allowed = |func: FuncId, active: Option<&AHashSet<FuncId>>| {
            allowed_funcs.is_none_or(|allowed| allowed.contains(&func))
                && active.is_none_or(|active| active.contains(&func))
        };
        let node_is_allowed = |node: NodeId, active: Option<&AHashSet<FuncId>>| {
            Self::ws_node_func(&unified, node).is_some_and(|func| func_is_allowed(func, active))
        };
        for target in target_nodes {
            let target = NodeId(target.0);
            if node_is_allowed(target, active_funcs.as_ref()) {
                worklist.enqueue_node(target);
            }
        }
        for func in target_funcs.into_iter().flatten() {
            if !func_is_allowed(*func, active_funcs.as_ref()) {
                continue;
            }
            if let Some(nodes) = unified.nodes_by_func.get(*func) {
                for node in nodes {
                    worklist.enqueue_node(*node);
                }
            }
        }

        while worklist.has_pending() {
            if let Some(node) = worklist.pending_nodes.pop() {
                let node = NodeId(node as u32);
                contextual.reach.visit_backward(node, |predecessor| {
                    if node_is_allowed(predecessor, active_funcs.as_ref()) {
                        worklist.enqueue_node(predecessor);
                    }
                });
                contextual.reverse_heap.visit(node, |predecessor| {
                    let Some(func) = Self::ws_node_func(&unified, predecessor) else {
                        return;
                    };
                    if allowed_funcs.is_some_and(|allowed| !allowed.contains(&func)) {
                        return;
                    }
                    if let Some(active) = &mut active_funcs {
                        active.insert(func);
                    }
                    worklist.enqueue_node(predecessor);
                });
                contextual.reverse_calls.visit(node, |predecessor| {
                    if node_is_allowed(predecessor, active_funcs.as_ref()) {
                        worklist.enqueue_node(predecessor);
                    }
                });
                contextual.reverse_returns.visit(node, |predecessor| {
                    let Some(func) = Self::ws_node_func(&unified, predecessor) else {
                        return;
                    };
                    if allowed_funcs.is_some_and(|allowed| !allowed.contains(&func)) {
                        return;
                    }
                    if let Some(active) = &mut active_funcs {
                        active.insert(func);
                    }
                    worklist.enqueue_node(predecessor);
                });
                if let Some(inputs) = runtime.aggregate_inputs.get(&node) {
                    for input in inputs {
                        let input = NodeId(input.0);
                        if node_is_allowed(input, active_funcs.as_ref()) {
                            worklist.enqueue_node(input);
                        }
                    }
                }

                // Reverse every exact access-path fact introduced when this
                // node is reached by the forward algebra. Projected reads do
                // not appear in `storage_reads` (that compact inverse is for
                // bare-base wildcard consumers), so nesting this loop under
                // the bare lookup incorrectly pruned `arg.field` targets.
                let symbolic_facts = Self::symbolic_facts_for_node(&unified, &runtime, node);
                let has_symbolic_fact = !symbolic_facts.is_empty();
                for fact in symbolic_facts {
                    worklist.enqueue_fact(fact.base, fact.field);
                }
                // A projected place with no symbolic fact comes from a
                // frontend that has not supplied the access-path fact needed
                // to invert this construct. The backward relation is a
                // pruning proof, so a partial inverse must become non-pruning:
                // forward compilation can still relate a scalar
                // receiver/carrier to that projection through exact call and
                // return summaries. The exact forward fixed point still
                // decides whether a real path exists.
                if !has_symbolic_fact && unified.projected_storage.get(node.0 as usize).copied() == Some(1) {
                    worklist.relevance.pruning_complete = false;
                }
                if let Some(base) = runtime.storage_reads.base(WsNodeId(node.0)) {
                    worklist.enqueue_wildcard_base(base);
                }
                if let Some((target, write_span)) = runtime.storage_writes.identity(WsNodeId(node.0)) {
                    if let Some(write_span) = runtime.span(write_span).map(SymbolicFactSpan::into_span) {
                        runtime
                            .reverse_scalar_transforms
                            .visit_incoming(target, write_span, |row| {
                                if max_precision.is_some_and(|max| row.precision > max) {
                                    return;
                                }
                                let Some(field) = symbolic
                                    .string(row.exact_field)
                                    .and_then(|field| runtime.field_id(field))
                                else {
                                    return;
                                };
                                let source_func =
                                    symbolic.bases().get(row.source as usize).map(|base| base.func);
                                if let Some(source_func) = source_func {
                                    if allowed_funcs.is_none_or(|allowed| allowed.contains(&source_func)) {
                                        if let Some(active) = &mut active_funcs {
                                            active.insert(source_func);
                                        }
                                        worklist.enqueue_fact(row.source, field);
                                    }
                                }
                            });
                    }
                }
            }

            // The relevance relation is only an optional pruning proof. Once
            // one projected compiler place lacks the symbolic inverse needed
            // to make that proof complete, `contains_node`/`contains_fact`
            // deliberately admit every forward state. Finishing the backward
            // fixed point would therefore be dead work and cannot change the
            // exact forward closure or its result.
            if !worklist.relevance.pruning_complete {
                break;
            }

            if let Some(key) = worklist.pending_facts.pop() {
                let key = key as u64;
                let base = (key >> 32) as u32;
                let field = key as u32;
                for &rebase in runtime.base_rebases.outgoing(base) {
                    if let Some(field) = runtime.rebased_field(rebase, field) {
                        worklist.enqueue_fact(rebase.target, field);
                    }
                }
                runtime.fact_sources.visit_key(key, |source| {
                    let source = NodeId(source);
                    if node_is_allowed(source, active_funcs.as_ref()) {
                        worklist.enqueue_node(source);
                    }
                });
                runtime.reverse_transforms.visit_incoming(base, |row| {
                    if max_precision.is_some_and(|max| row.precision > max) {
                        return;
                    }
                    let activates_provider = matches!(
                        row.kind,
                        SymbolicFieldTransformKind::Return
                            | SymbolicFieldTransformKind::ConstructorReturn
                            | SymbolicFieldTransformKind::ReceiverMutation
                    );
                    let source_func = symbolic.bases().get(row.source as usize).map(|base| base.func);
                    let source_allowed = source_func.is_some_and(|func| {
                        allowed_funcs.is_none_or(|allowed| allowed.contains(&func))
                            && (activates_provider
                                || active_funcs.as_ref().is_none_or(|active| active.contains(&func)))
                    });
                    if source_allowed {
                        if activates_provider {
                            if let (Some(active), Some(func)) = (&mut active_funcs, source_func) {
                                active.insert(func);
                            }
                        }
                        worklist.enqueue_fact(row.source, field);
                    }
                });
            }

            if let Some(base) = worklist.pending_wildcard_bases.pop() {
                let base = base as u32;
                // Backward wildcard demand is a conservative pruning proof.
                // Either decomposition can denote fields below the other, so
                // admitting both bases cannot create forward facts and avoids
                // pruning a realizable nested receiver path.
                for rebase in runtime.base_rebases.outgoing(base) {
                    worklist.enqueue_wildcard_base(rebase.target);
                }
                runtime.fact_sources.visit_base(base, |source| {
                    let source = NodeId(source);
                    if node_is_allowed(source, active_funcs.as_ref()) {
                        worklist.enqueue_node(source);
                    }
                });
                runtime.reverse_transforms.visit_incoming(base, |row| {
                    if max_precision.is_some_and(|max| row.precision > max) {
                        return;
                    }
                    let activates_provider = matches!(
                        row.kind,
                        SymbolicFieldTransformKind::Return
                            | SymbolicFieldTransformKind::ConstructorReturn
                            | SymbolicFieldTransformKind::ReceiverMutation
                    );
                    let source_func = symbolic.bases().get(row.source as usize).map(|base| base.func);
                    let source_allowed = source_func.is_some_and(|func| {
                        allowed_funcs.is_none_or(|allowed| allowed.contains(&func))
                            && (activates_provider
                                || active_funcs.as_ref().is_none_or(|active| active.contains(&func)))
                    });
                    if source_allowed {
                        if activates_provider {
                            if let (Some(active), Some(func)) = (&mut active_funcs, source_func) {
                                active.insert(func);
                            }
                        }
                        worklist.enqueue_wildcard_base(row.source);
                    }
                });
            }
        }

        bonsai_diagnostics::debug_log!(
            "idg-target",
            "backward relevance targets={} fallback_funcs={} allowed_funcs={} source_root={} active_funcs={} nodes={} facts={} wildcard_bases={} pruning_complete={}",
            target_nodes.len(),
            target_funcs.map_or(0, |funcs| funcs.len()),
            allowed_funcs.map_or(0, |funcs| funcs.len()),
            source_root.map_or(u32::MAX, FuncId::raw),
            active_funcs.as_ref().map_or(0, |funcs| funcs.len()),
            worklist.relevance.nodes.len(),
            worklist.relevance.facts.len(),
            worklist.relevance.wildcard_bases.len(),
            worklist.relevance.pruning_complete
        );
        worklist.relevance
    }

    /// Context-matched forward closure when a concrete target node or fallback
    /// target function is reached; otherwise empty.
    pub fn forward_target_nodes_and_funcs_cut_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        target_nodes: &[WsNodeId],
        target_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        if seeds.is_empty() || (target_nodes.is_empty() && target_funcs.is_empty()) {
            return Vec::new();
        }
        let unified = self.ensure_unified();
        let targets: AHashSet<WsNodeId> = target_nodes.iter().copied().collect();
        let closure = self.forward_closure_with_max_precision(seeds, max_precision);
        let reaches_target = closure.iter().any(|node| {
            unified
                .node_funcs
                .get(node.0 as usize)
                .is_some_and(|func| target_funcs.contains(func))
        }) || self.closure_reaches_target_nodes(&closure, &targets);
        if reaches_target {
            closure
        } else {
            Vec::new()
        }
    }

    /// Whether a closure reaches a requested scalar node or supplies exact
    /// aggregate-consumption evidence for a requested call-argument node.
    ///
    /// `IntraAggregateConsume` is intentionally not a traversable scalar
    /// edge: making it one would widen a tainted field into its siblings when
    /// a local callee reads a different field. An unresolved/external call
    /// still observes the complete argument value, however, so its exact
    /// call-argument identity satisfies a target cut without inserting that
    /// argument into the scalar closure.
    fn closure_reaches_target_nodes(&self, closure: &[WsNodeId], targets: &AHashSet<WsNodeId>) -> bool {
        if closure.iter().any(|node| targets.contains(node)) {
            return true;
        }
        let target_args: AHashSet<(FuncId, Span, u32)> = targets
            .iter()
            .filter_map(|node| self.call_arg_identity(*node))
            .collect();
        if target_args.is_empty() {
            return false;
        }
        self.tainted_call_args_in_reachable_nodes(closure)
            .into_iter()
            .any(|identity| target_args.contains(&identity))
    }

    /// Backward closure: which nodes flow *into* `targets`?
    pub fn backward_closure(&self, targets: &[WsNodeId]) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let target_nodes: Vec<NodeId> = targets.iter().map(|w| NodeId(w.0)).collect();
        let bits = self
            .ensure_unfiltered_reach(&unified)
            .backward_closure(&target_nodes);
        bits.iter().map(|n| WsNodeId(n.0)).collect()
    }

    /// Does any path lead from `from` to `to`?
    #[must_use]
    pub fn reaches(&self, from: WsNodeId, to: WsNodeId) -> bool {
        self.forward_closure_unfiltered(&[from]).contains(&to)
    }

    /// Find every IDG node in `func` whose place is a `Place::Read`
    /// or `Place::Write` matching one of `seed_names`.
    ///
    /// Bare seeds (`x`) match only bare reads/writes of `x`.
    /// Wildcard descendant seeds (`x.*`) match only projected
    /// reads/writes such as `x.y`, and exact projected seeds
    /// (`x.y`) match that specific path. This keeps source rules
    /// that intentionally mark a container's fields tainted from
    /// promoting the whole container, while still letting a source
    /// parameter like GraphQL `args` reach `args.q`.
    /// Lets consumers translate "user-provided seed names" into the
    /// IDG nodes those names address — used by browse-taint /
    /// security-analysis when the caller supplies explicit seeds.
    ///
    /// Callers seeding a CONTAINER source (a bare name that stands
    /// for the whole value, like GraphQL `args`) should pass the
    /// names through [`expand_bare_seed_names_with_descendants`]
    /// first so projections (`args.q`) seed too.
    ///
    /// Names are looked up via the segment's persisted string pool
    /// (populated at merge time from each function's transfer
    /// output's name pool). Empty pool → empty result.
    pub fn read_or_write_nodes_for_names(&self, func: FuncId, seed_names: &[String]) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut bare_strids: ahash::AHashSet<bonsai_factstore::StrId> = AHashSet::new();
        let mut descendant_strids: ahash::AHashSet<bonsai_factstore::StrId> = AHashSet::new();
        let mut descendant_bases: AHashSet<String> = AHashSet::new();
        let mut descendant_path_prefixes: Vec<(bonsai_factstore::StrId, Vec<bonsai_factstore::StrId>)> =
            Vec::new();
        let mut exact_flat_paths: AHashSet<String> = AHashSet::new();
        let mut exact_paths: Vec<(bonsai_factstore::StrId, Vec<bonsai_factstore::StrId>)> = Vec::new();
        for seed in seed_names {
            let seed = seed.trim();
            if seed.is_empty() {
                continue;
            }
            if let Some(base) = seed.strip_suffix(".*") {
                let base = base.trim();
                if let Some((root, path)) = split_projected_seed(base) {
                    if let Some(root_strid) = segment.strings.lookup(root) {
                        if let Some(path_strids) = path
                            .iter()
                            .map(|part| segment.strings.lookup(part))
                            .collect::<Option<Vec<_>>>()
                        {
                            descendant_path_prefixes.push((root_strid, path_strids));
                        }
                    }
                }
                if let Some(strid) = segment.strings.lookup(base) {
                    descendant_strids.insert(strid);
                }
                if !base.is_empty() {
                    descendant_bases.insert(base.to_string());
                }
                continue;
            }
            if let Some((base, path)) = split_projected_seed(seed) {
                exact_flat_paths.insert(format!("{base}.{}", path.join(".")));
                let Some(base_strid) = segment.strings.lookup(base) else {
                    continue;
                };
                let Some(path_strids) = path
                    .iter()
                    .map(|part| segment.strings.lookup(part))
                    .collect::<Option<Vec<_>>>()
                else {
                    continue;
                };
                exact_paths.push((base_strid, path_strids));
                continue;
            }
            if let Some(strid) = segment.strings.lookup(seed) {
                bare_strids.insert(strid);
            }
        }
        if bare_strids.is_empty()
            && descendant_strids.is_empty()
            && descendant_bases.is_empty()
            && descendant_path_prefixes.is_empty()
            && exact_paths.is_empty()
            && exact_flat_paths.is_empty()
        {
            return out;
        }
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let matches = match place {
                Place::Read { name, path } if path.is_empty() => {
                    bare_strids.contains(name)
                        || flat_place_matches_projected_seed(
                            segment.strings.get(*name),
                            &descendant_bases,
                            &exact_flat_paths,
                        )
                }
                Place::Write { name, path, .. } if path.is_empty() => {
                    bare_strids.contains(name)
                        || flat_place_matches_projected_seed(
                            segment.strings.get(*name),
                            &descendant_bases,
                            &exact_flat_paths,
                        )
                }
                Place::Read { name, path } | Place::Write { name, path, .. } => {
                    (!path.is_empty() && descendant_strids.contains(name))
                        || descendant_path_prefixes
                            .iter()
                            .any(|(base, prefix)| base == name && path.starts_with(prefix.as_slice()))
                        || exact_paths.iter().any(|(base, exact_path)| {
                            base == name && exact_path.as_slice() == path.as_slice()
                        })
                }
                _ => false,
            };
            if !matches {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) {
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                    out.push(ws_node);
                }
            }
        }
        out
    }

    /// Render every exact Read/Write place in `func` that belongs to an
    /// already-computed reachability closure. Projected places retain their
    /// complete access path, so `response.headers.Location` never promotes
    /// the bare container or a sibling field.
    ///
    /// Taint attribution scans the compiler's numeric place dictionary once
    /// instead of reconstructing a candidate-name list from compact linkage
    /// headers or repeatedly performing name-to-node lookups.
    pub fn read_or_write_names_in_reachable_nodes(
        &self,
        func: FuncId,
        closure: &AHashSet<WsNodeId>,
    ) -> AHashSet<String> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return AHashSet::default();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return AHashSet::default();
        };
        let mut out = AHashSet::default();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let (name, path) = match place {
                Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
                _ => continue,
            };
            let pid = crate::node::PlaceId(pid_idx as u32);
            let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) else {
                continue;
            };
            let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) else {
                continue;
            };
            if !closure.contains(&ws_node) {
                continue;
            }
            let Some(base) = segment.strings.get(name) else {
                continue;
            };
            let mut rendered = base.to_string();
            for part in path {
                let Some(part) = segment.strings.get(*part) else {
                    rendered.clear();
                    break;
                };
                rendered.push('.');
                rendered.push_str(part);
            }
            if !rendered.is_empty() {
                out.insert(rendered);
            }
        }
        out
    }

    /// Render every exact Read/Write place owned by one function.
    ///
    /// This is the compiler-graph counterpart of walking a declaration's
    /// `FlowEvent` carriers. Broad rulepack-free inspect uses it to compose
    /// its intentionally wide entry seed without reopening the full compiler
    /// body. Projected places retain their complete access path; no token or
    /// language-name inference occurs here.
    pub fn read_or_write_names_of_func(&self, func: FuncId) -> AHashSet<String> {
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return AHashSet::default();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return AHashSet::default();
        };
        let mut out = AHashSet::default();
        let mut projected_bases = AHashSet::default();
        let mut bare_reads = AHashSet::default();
        let mut bare_writes = AHashSet::default();
        let parameter_binding_writes: AHashSet<NodeId> = segment
            .edges
            .iter()
            .filter_map(|edge| {
                (edge.meta.kind == IdgEdgeKind::IntraAssign
                    && matches!(
                        segment
                            .nodes
                            .get(edge.from)
                            .and_then(|node| segment.places.get(node.place)),
                        Some(Place::Param { .. })
                    ))
                .then_some(edge.to)
            })
            .collect();
        let mut parameter_carriers = AHashSet::default();
        for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
            if node.func != func {
                continue;
            }
            let Some(place) = segment.places.get(node.place) else {
                continue;
            };
            let (name, path) = match place {
                Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
                _ => continue,
            };
            let Some(base) = segment.strings.get(name) else {
                continue;
            };
            if path.is_empty() {
                match place {
                    Place::Read { .. } => {
                        bare_reads.insert(base.to_string());
                    }
                    Place::Write { .. } => {
                        let node_id = NodeId(
                            u32::try_from(node_index).expect("segment-local IDG node count exceeds u32"),
                        );
                        if parameter_binding_writes.contains(&node_id) {
                            parameter_carriers.insert(base.to_string());
                        } else {
                            bare_writes.insert(base.to_string());
                        }
                    }
                    _ => {}
                }
                continue;
            }
            projected_bases.insert(base.to_string());
            let mut rendered = base.to_string();
            for part in path {
                let Some(part) = segment.strings.get(*part) else {
                    rendered.clear();
                    break;
                };
                rendered.push('.');
                rendered.push_str(part);
            }
            if !rendered.is_empty() {
                out.insert(rendered);
            }
        }
        // Parameter binding is represented as `Param -> Write(name)` at the
        // declaration span. For a parameter used only through projections,
        // that write is a carrier rather than a source-level whole-object
        // access; exposing it as an inventory seed would promote sibling
        // fields. Independent bare writes remain meaningful even when the
        // same base also has projected accesses.
        out.extend(bare_writes.iter().cloned());
        out.extend(
            parameter_carriers
                .into_iter()
                .filter(|base| !projected_bases.contains(base)),
        );
        out.extend(
            bare_reads
                .into_iter()
                .filter(|base| bare_writes.contains(base) || !projected_bases.contains(base)),
        );
        out
    }

    /// Find every IDG node tagged as the entry's `Place::Param(idx)`
    /// for a given function. Returns the workspace-global ids so
    /// callers can immediately feed them to [`Self::forward_closure`].
    /// Resolve the workspace IDG nodes for `func`'s params whose
    /// declared name appears in `names`. Returns an empty Vec when
    /// none match. Differs from [`Self::param_nodes_of`] in that it does
    /// NOT include unrelated params — kind-param seed builders use
    /// it so a rule that only matches `user` doesn't seed the sibling
    /// `safe` param and over-paint the closure with unrelated flows.
    pub fn param_nodes_for_names(
        &self,
        func: FuncId,
        names: &[String],
        global: &bonsai_index::GlobalIndex,
    ) -> Vec<WsNodeId> {
        if names.is_empty() {
            return Vec::new();
        }
        let unified = self.ensure_unified();
        let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
            return Vec::new();
        };
        let want: ahash::AHashSet<&str> = names.iter().map(|n| n.as_str()).collect();
        let wanted_slots = decl
            .params
            .iter()
            .enumerate()
            .filter_map(|(idx, name)| {
                want.contains(name.as_str())
                    .then(|| u32::try_from(idx).ok())
                    .flatten()
            })
            .collect::<AHashSet<_>>();
        unified
            .nodes_by_func
            .get(func)
            .into_iter()
            .flatten()
            .filter_map(|node| {
                let ws_node = WsNodeId(node.0);
                unified
                    .params
                    .get(ws_node)
                    .is_some_and(|idx| wanted_slots.contains(&idx))
                    .then_some(ws_node)
            })
            .collect()
    }

    /// Resolve the workspace IDG nodes for ALL of `func`'s
    /// `Place::Param{idx}` slots. Used by seed builders that have
    /// no narrower signal — the engine's historical default is to
    /// seed every param when the source rule has no name match.
    pub fn param_nodes_of(&self, func: FuncId) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let mut indexed = Vec::new();
        if let Some(nodes) = unified.nodes_by_func.get(func) {
            for node in nodes {
                let ws_node = WsNodeId(node.0);
                if let Some(idx) = unified.params.get(ws_node) {
                    indexed.push((idx, ws_node));
                }
            }
        }
        indexed.sort_unstable_by_key(|(idx, _)| *idx);
        indexed.into_iter().map(|(_, node)| node).collect()
    }

    /// Find every IDG node in `func` anchored at a source-span
    /// matching `match_span`. Used to seed taint propagation from a
    /// *specific* source rule match (e.g. `os.environ()` at line 7
    /// col 4) instead of from every Read/Write of the matched name.
    /// Span-anchored seeding preserves CFG-narrowing kill semantics
    /// when the seed name has multiple writers (clean overwrites).
    ///
    /// Returns nodes whose Place anchors at `match_span`:
    /// - `Place::Write { span: w_span, .. }` when `w_span` overlaps.
    /// - `Place::CallRet { site }` when `site` overlaps.
    /// - `Place::CallArg { site, .. }` when `site` overlaps.
    /// - `Place::Throw`/`Catch` when their event spans overlap.
    pub fn source_seed_nodes_at_span(&self, func: FuncId, match_span: Span) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        // Identify the source rule's own call site by collecting
        // every `Place::CallRet { site }` whose span overlaps
        // `match_span`. A `kind: call` source rule anchors at the
        // matched call's span, so its CallRet IS in the closure;
        // collecting those sites lets us recognise their sibling
        // CallArg places (`call_site.0 == ret_site.0`) and skip
        // them — those args are *inputs* to the source call, not
        // the source's payload (the payload is the CallRet). The
        // semantic check (matched-CallRet site equality) is
        // durable against minor span jitter between the matcher's
        // call-event span and the adapter's call-event span: as
        // long as both ultimately emit a CallRet that overlaps
        // the match anchor, the sibling-CallArg skip fires.
        //
        // For wide anchors (inferred-source function-body spans),
        // many calls' CallRets overlap, but their CallArgs are
        // legitimate carriers of the parameter's taint — we don't
        // skip those because their site equals a CallRet site
        // OTHER than the source's own. The distinction reduces
        // to: "skip a CallArg only when it shares a site with a
        // CallRet AND the match anchor is no wider than that one
        // call". Approximated by also gating the skip on
        // `match_span.start == ret_site.start` so wide anchors
        // (function bodies) don't trip it.
        let mut sibling_arg_sites: ahash::AHashSet<bonsai_common::Span> = ahash::AHashSet::default();
        for place in &segment.places.places {
            if let Place::CallRet { site } = place {
                let ret_span = site.0;
                if spans_overlap(ret_span, match_span) && ret_span.start == match_span.start {
                    sibling_arg_sites.insert(ret_span);
                }
            }
        }
        let mut out = Vec::new();
        let mut local_seeds = Vec::new();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let span = match place {
                Place::Write { span, .. } => *span,
                Place::CallRet { site } => site.0,
                Place::CallArg { site, .. } => {
                    if sibling_arg_sites.contains(&site.0) {
                        continue;
                    }
                    site.0
                }
                _ => continue,
            };
            if !spans_overlap(span, match_span) {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) {
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                    out.push(ws_node);
                    local_seeds.push(local_node);
                }
            }
        }
        // Fallback for sources in NON-assigned position — a source value
        // that is returned directly (`return os.environ["CMD"]`) or
        // nested in a sink argument (`os.system(os.environ["CMD"])`) is
        // bridged through a `Place::Read` → `Place::Return`/`CallArg`
        // edge. `Place::Read` and `Place::Return` are span-less (only
        // `Write` carries a span — see `place.rs`), so the place loop
        // above (which can only seed span-bearing
        // `Write`/`CallRet`/`CallArg`) finds nothing. The edge carrying
        // the value, however, records the statement span in
        // `meta.via_span`. So when no place anchored at the span, seed
        // the `from`-node of every intra edge whose `via_span` overlaps
        // the anchor — that is the read of the source expression, whose
        // forward closure reaches the return / sink argument.
        //
        // The fallback also fires when every span-anchored seed is DEAD
        // (no outgoing intra edge). A method chain on a source receiver
        // in tail position (`def get_input; gets.chomp; end`) anchors
        // the rule on the receiver (`gets`), whose span overlaps only
        // the whole-return `__return__` write-base — a node that is
        // deliberately left without a `-> Return` edge when the return
        // contains a call (see `bridge_return_expression_calls`). A seed
        // set with no outgoing edges can never reach anything, so
        // union-ing in the via-span reads (`Read(gets) -> Return`)
        // restores the source without perturbing anchors that already
        // propagate: the fallback stays OFF whenever any anchored seed
        // has at least one outgoing edge, and it only ever ADDS seeds.
        let anchored_seeds_dead =
            !local_seeds.is_empty() && !segment.edges.iter().any(|edge| local_seeds.contains(&edge.from));
        if out.is_empty() || anchored_seeds_dead {
            for edge in &segment.edges {
                if !spans_overlap(edge.meta.via_span, match_span) {
                    continue;
                }
                if segment.nodes.get(edge.from).is_none_or(|node| node.func != func) {
                    continue;
                }
                // Don't seed a read that feeds the SOURCE call's OWN
                // argument (`os.getenv(y)` — `y` is an INPUT to the
                // source, not its tainted return). The `to` node is the
                // source call's arg slot; `sibling_arg_sites` already
                // marks those. Without this, the fallback re-taints the
                // source's inputs and a later use of `y` (`os.system(y)`)
                // becomes a false positive.
                let feeds_source_own_arg = segment
                    .nodes
                    .get(edge.to)
                    .and_then(|node| segment.places.get(node.place))
                    .is_some_and(|place| match place {
                        Place::CallArg { site, .. } => sibling_arg_sites.contains(&site.0),
                        _ => false,
                    });
                if feeds_source_own_arg {
                    continue;
                }
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, edge.from) {
                    out.push(ws_node);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Find every span-bearing IDG node in `func` anchored at
    /// `match_span`. Unlike [`Self::source_seed_nodes_at_span`], this
    /// keeps call arguments because sink reachability targets are
    /// usually the argument / receiver slots at the sink site.
    pub fn nodes_at_span(&self, func: FuncId, match_span: Span) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let span = match place {
                Place::Write { span, .. } => *span,
                Place::CallRet { site } | Place::CallArg { site, .. } => site.0,
                _ => continue,
            };
            if !spans_overlap(span, match_span) {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) {
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                    out.push(ws_node);
                }
            }
        }
        if out.is_empty() {
            for edge in &segment.edges {
                if !spans_overlap(edge.meta.via_span, match_span) {
                    continue;
                }
                if segment.nodes.get(edge.to).is_none_or(|node| node.func != func) {
                    continue;
                }
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, edge.to) {
                    out.push(ws_node);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Batch form of [`Self::nodes_at_span`] for broad compiler queries.
    ///
    /// Targets are grouped by persisted segment so each segment is decoded
    /// once. The result is the exact union of the scalar lookups plus the set
    /// of functions containing at least one span without an IDG carrier;
    /// callers retain those functions as conservative fallbacks.
    #[must_use]
    pub fn nodes_and_unresolved_funcs_at_spans(
        &self,
        targets: &[(FuncId, Span)],
    ) -> (Vec<WsNodeId>, AHashSet<FuncId>) {
        let (grouped, unresolved) = self.nodes_by_func_and_unresolved_at_spans(targets);
        let mut nodes: Vec<_> = grouped.into_values().flatten().collect();
        nodes.sort_unstable();
        nodes.dedup();
        (nodes, unresolved)
    }

    /// Resolve exact syntax spans while preserving their owning function.
    /// Broad inspect batches use this compiler attribution to build one
    /// source-rooted demand proof per independent syntax owner instead of
    /// mixing unrelated targets into a workspace-wide cut.
    pub fn nodes_by_func_and_unresolved_at_spans(
        &self,
        targets: &[(FuncId, Span)],
    ) -> (AHashMap<FuncId, Vec<WsNodeId>>, AHashSet<FuncId>) {
        let unified = self.ensure_unified();
        let mut unique_targets = targets.to_vec();
        unique_targets.sort_unstable_by_key(|(func, span)| (func.raw(), *span));
        unique_targets.dedup();

        let mut targets_by_segment: AHashMap<SegmentId, AHashMap<FuncId, Vec<Span>>> = AHashMap::new();
        let mut unresolved_funcs = AHashSet::new();
        for (func, span) in &unique_targets {
            let Some(segment) = self.workspace.segment_for_func(*func) else {
                unresolved_funcs.insert(*func);
                continue;
            };
            targets_by_segment
                .entry(segment)
                .or_default()
                .entry(*func)
                .or_default()
                .push(*span);
        }

        let mut nodes: AHashMap<FuncId, Vec<WsNodeId>> = AHashMap::new();
        for (segment_id, targets_by_func) in targets_by_segment {
            let Some(segment) = self.workspace.segment_view(segment_id) else {
                unresolved_funcs.extend(targets_by_func.keys().copied());
                continue;
            };
            let mut resolved: AHashSet<(FuncId, Span)> = AHashSet::new();
            for (local_index, node) in segment.nodes.nodes.iter().enumerate() {
                let func = node.func;
                let Some(match_spans) = targets_by_func.get(&node.func) else {
                    continue;
                };
                let Some(place) = segment.places.get(node.place) else {
                    continue;
                };
                let place_span = match place {
                    Place::Write { span, .. } => *span,
                    Place::CallRet { site } | Place::CallArg { site, .. } => site.0,
                    _ => continue,
                };
                for match_span in match_spans {
                    if spans_overlap(place_span, *match_span) {
                        if let Some(ws_node) = Self::ws_node_for(
                            &unified,
                            segment_id,
                            NodeId(u32::try_from(local_index).expect("IDG segment node exceeds u32")),
                        ) {
                            nodes.entry(func).or_default().push(ws_node);
                            resolved.insert((func, *match_span));
                        }
                    }
                }
            }
            let directly_resolved = resolved.clone();

            // Match the scalar lookup's via-span fallback only for target
            // spans that had no directly anchored place.
            for edge in &segment.edges {
                let Some(target_node) = segment.nodes.get(edge.to) else {
                    continue;
                };
                let Some(match_spans) = targets_by_func.get(&target_node.func) else {
                    continue;
                };
                for match_span in match_spans {
                    let key = (target_node.func, *match_span);
                    if directly_resolved.contains(&key) || !spans_overlap(edge.meta.via_span, *match_span) {
                        continue;
                    }
                    if let Some(node) = Self::ws_node_for(&unified, segment_id, edge.to) {
                        nodes.entry(target_node.func).or_default().push(node);
                        resolved.insert(key);
                    }
                }
            }
            for (func, spans) in targets_by_func {
                if spans.into_iter().any(|span| !resolved.contains(&(func, span))) {
                    unresolved_funcs.insert(func);
                }
            }
        }
        for nodes in nodes.values_mut() {
            nodes.sort_unstable();
            nodes.dedup();
        }
        (nodes, unresolved_funcs)
    }

    /// Enumerate every (caller, call_span, arg_idx) triple where the
    /// `Place::CallArg{site, idx}` node in the caller is reachable
    /// from `seeds`. Includes call sites whose callee did not
    /// resolve (no cross-file edge) — those are exactly the "this
    /// call had a tainted argument" events the legacy engine
    /// captured in `tainted_calls`.
    ///
    /// Result is sorted by `(caller_func, call_span.start, arg_idx)`
    /// for deterministic grouping.
    pub fn tainted_call_args_in_closure(&self, seeds: &[WsNodeId]) -> Vec<(FuncId, Span, u32)> {
        self.tainted_call_args_in_closure_with_max_precision(seeds, Some(SEMANTIC_MAX_PRECISION))
    }

    /// Same as [`Self::tainted_call_args_in_closure`], but computes
    /// the seed closure inside a precision scope.
    pub fn tainted_call_args_in_closure_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Vec<(FuncId, Span, u32)> {
        let closure = self.forward_closure_with_max_precision(seeds, max_precision);
        self.tainted_call_args_in_reachable_nodes(&closure)
    }

    /// Same as [`Self::tainted_call_args_in_closure`], but consumes a
    /// closure the caller already computed. Exact source graph
    /// construction needs several views over the same reachability
    /// set; accepting the closure avoids re-running the bitvector
    /// fixpoint for every view.
    pub fn tainted_call_args_in_reachable_nodes(&self, closure: &[WsNodeId]) -> Vec<(FuncId, Span, u32)> {
        self.tainted_call_args_in_reachable_nodes_for_funcs(closure, None)
    }

    /// Same as [`Self::tainted_call_args_in_reachable_nodes`], but keeps
    /// only call sites owned by `target_funcs` when a filter is supplied.
    pub fn tainted_call_args_in_reachable_nodes_for_funcs(
        &self,
        closure: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
    ) -> Vec<(FuncId, Span, u32)> {
        let unified = self.ensure_unified();
        let runtime = self.symbolic_runtime_for_tainted_calls(&unified, target_funcs);
        let mut out = Vec::new();
        for ws_node in closure {
            let Some(func) = Self::ws_node_func(&unified, NodeId(ws_node.0)) else {
                continue;
            };
            if target_funcs.is_some_and(|targets| !targets.contains(&func)) {
                continue;
            }
            if let Some((site, idx)) = unified.call_args.get(*ws_node) {
                out.push((func, site, idx));
            }

            // Aggregate-consumption markers are deliberately absent from
            // the scalar reachability graph: they record that one reachable
            // field is passed as part of a whole aggregate. An unresolved or
            // external call consumes that aggregate; a resolver-proven call
            // instead uses its exact field-projected call edges. The scoped
            // runtime compiles both relations once, so every source query is
            // a sparse lookup rather than another segment/cross-edge scan.
            let Some(arg_nodes) = runtime.aggregate_outputs.get(&NodeId(ws_node.0)) else {
                continue;
            };
            for &arg_node in arg_nodes {
                if runtime.resolved_call_args.contains(&arg_node) {
                    continue;
                }
                let Some(arg_func) = Self::ws_node_func(&unified, NodeId(arg_node.0)) else {
                    continue;
                };
                if target_funcs.is_some_and(|targets| !targets.contains(&arg_func)) {
                    continue;
                }
                if let Some((site, idx)) = unified.call_args.get(arg_node) {
                    out.push((arg_func, site, idx));
                }
            }
        }
        out.sort_unstable_by_key(|(func, span, idx)| {
            (func.raw(), span.file.raw(), span.start, span.end, *idx)
        });
        out.dedup();
        out
    }

    /// Return read/write storage names in a precomputed closure,
    /// optionally restricted to a function set.
    ///
    /// This is the cheap counterpart to resolving every closure node
    /// into a renderable [`PointRef`]: it checks the underlying
    /// [`Place`] first and only materializes strings for Read/Write
    /// places. Transfer passes use this to detect descendant storage
    /// bases without formatting CallArg/CallRet/Param points they will
    /// immediately discard.
    pub fn read_write_storage_names_in_reachable_nodes_for_funcs(
        &self,
        closure: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
    ) -> Vec<(FuncId, String)> {
        let unified = self.ensure_unified();
        // A warm query owns only a bounded segment-page cache. Reopening a
        // segment once per reachable node turns an otherwise sparse closure
        // projection into cache thrash on large files. Group exact workspace
        // addresses by their compiler segment, then decode each participating
        // body once. This changes only I/O order; every closure node is still
        // inspected and no semantic work is capped.
        let mut addresses = Vec::new();
        for ws_node in closure {
            let Some(func) = Self::ws_node_func(&unified, NodeId(ws_node.0)) else {
                continue;
            };
            if target_funcs.is_some_and(|targets| !targets.contains(&func)) {
                continue;
            }
            let Some((seg_id, local)) = Self::ws_address(&unified, *ws_node) else {
                continue;
            };
            addresses.push((seg_id, local));
        }
        addresses.sort_unstable_by_key(|(segment, local)| (segment.0, local.0));
        addresses.dedup();

        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor < addresses.len() {
            let seg_id = addresses[cursor].0;
            let end = addresses[cursor..].partition_point(|(candidate, _)| *candidate == seg_id) + cursor;
            let Some(segment) = self.workspace.segment_view(seg_id) else {
                cursor = end;
                continue;
            };
            for (_, local) in &addresses[cursor..end] {
                let Some(node) = segment.nodes.get(*local) else {
                    continue;
                };
                let Some(place) = segment.places.get(node.place) else {
                    continue;
                };
                let (name, path) = match place {
                    Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
                    _ => continue,
                };
                let Some(base) = segment.strings.get(name) else {
                    continue;
                };
                let mut storage = base.to_string();
                let mut complete = true;
                for part in path {
                    let Some(part) = segment.strings.get(*part) else {
                        complete = false;
                        break;
                    };
                    storage.push('.');
                    storage.push_str(part);
                }
                if complete && !storage.trim().is_empty() {
                    out.push((node.func, storage));
                }
            }
            cursor = end;
        }
        out.sort_unstable_by(|left, right| (left.0.raw(), &left.1).cmp(&(right.0.raw(), &right.1)));
        out.dedup();
        out
    }

    /// Return every exact `CallRet` identity owned by `funcs`.
    ///
    /// Functions are grouped by source segment so nested-call attribution can
    /// build one ephemeral lookup without repeatedly decoding the same
    /// compiler body. The returned map is a query projection, not a retained
    /// workspace-wide index.
    pub fn call_ret_nodes_for_funcs(&self, funcs: &AHashSet<FuncId>) -> AHashMap<(FuncId, Span), WsNodeId> {
        if funcs.is_empty() {
            return AHashMap::new();
        }
        let unified = self.ensure_unified();
        let mut funcs_by_segment: AHashMap<SegmentId, AHashSet<FuncId>> = AHashMap::new();
        for func in funcs {
            if let Some(segment) = self.workspace.segment_for_func(*func) {
                funcs_by_segment.entry(segment).or_default().insert(*func);
            }
        }
        let mut out = AHashMap::new();
        for (segment_id, segment_funcs) in funcs_by_segment {
            let Some(segment) = self.workspace.segment_view(segment_id) else {
                continue;
            };
            for (local_index, node) in segment.nodes.nodes.iter().enumerate() {
                if !segment_funcs.contains(&node.func) {
                    continue;
                }
                let Some(Place::CallRet { site }) = segment.places.get(node.place) else {
                    continue;
                };
                let local = NodeId(u32::try_from(local_index).expect("segment-local node count exceeds u32"));
                if let Some(ws_node) = Self::ws_node_for(&unified, segment_id, local) {
                    out.entry((node.func, site.0)).or_insert(ws_node);
                }
            }
        }
        out
    }

    /// Return the `CallRet` node for a call site in `func`, if the
    /// transfer pass recorded one. Used by rulepack-declared
    /// call-result passthrough semantics: a tainted `CallArg` at the
    /// same site can seed the return node without hardcoding API
    /// names into the IDG core.
    pub fn call_ret_node_at_site(&self, func: FuncId, call_span: Span) -> Option<WsNodeId> {
        let unified = self.ensure_unified();
        let seg_id = self.workspace.segment_for_func(func)?;
        let segment = self.workspace.segment_view(seg_id)?;
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let Place::CallRet { site } = place else {
                continue;
            };
            if site.0 != call_span {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            let local_node = self.local_node_for(&unified, seg_id, func, pid)?;
            return Self::ws_node_for(&unified, seg_id, local_node);
        }
        None
    }

    /// Return the `Place::Write` nodes in `func` whose span equals
    /// `write_span`. Each assignment interns a distinct span-tagged Write
    /// node, so this addresses one specific assignment (used to seed the
    /// entry-most definition of a token-API seed name without seeding its
    /// later reassignments).
    pub fn write_node_at_span(&self, func: FuncId, write_span: Span) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let Place::Write { span, .. } = place else {
                continue;
            };
            if *span != write_span {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) {
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                    out.push(ws_node);
                }
            }
        }
        out
    }

    /// Return every write target fed directly by the call site's
    /// `CallRet` node. Used by semantic call-result transfer to prove
    /// a concrete assignment target before seeding a constructed
    /// receiver object.
    pub fn call_ret_assignment_targets_at_site(
        &self,
        func: FuncId,
        call_span: Span,
    ) -> Vec<CallRetAssignmentTarget> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let mut ret_node = None;
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let Place::CallRet { site } = place else {
                continue;
            };
            if site.0 != call_span {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            ret_node = self.local_node_for(&unified, seg_id, func, pid);
            break;
        }
        let Some(ret_node) = ret_node else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for edge in &segment.edges {
            if edge.from != ret_node || !edge.meta.kind.is_intra() {
                continue;
            }
            let Some(to_node) = segment.nodes.get(edge.to) else {
                continue;
            };
            if to_node.func != func {
                continue;
            }
            let Some(to_place) = segment.places.get(to_node.place) else {
                continue;
            };
            if !matches!(to_place, Place::Write { .. }) {
                continue;
            }
            let Some(ws_node) = Self::ws_node_for(&unified, seg_id, edge.to) else {
                continue;
            };
            let point = self.build_point_ref(func, to_place);
            if point.name.trim().is_empty() {
                continue;
            }
            out.push(CallRetAssignmentTarget {
                name: point.name,
                span: point.span,
                node: ws_node,
            });
        }
        out.sort_by(|a, b| {
            (a.name.as_str(), a.span.start, a.node.0).cmp(&(b.name.as_str(), b.span.start, b.node.0))
        });
        out.dedup();
        out
    }

    /// Functions whose synthetic `Place::Return` node is in a
    /// caller-provided reachability closure. This is the batched
    /// counterpart to probing `return_node_of(func)` for every
    /// function in the workspace.
    pub fn funcs_with_return_nodes_in_reachable_nodes(&self, closure: &[WsNodeId]) -> Vec<FuncId> {
        let unified = self.ensure_unified();
        let mut out = Vec::new();
        for ws_node in closure {
            if unified.node_boundaries.get(ws_node.0 as usize).copied() != Some(NODE_BOUNDARY_RETURN) {
                continue;
            }
            if let Some(func) = Self::ws_node_func(&unified, NodeId(ws_node.0)) {
                out.push(func);
            }
        }
        out.sort_by_key(|f| f.raw());
        out.dedup();
        out
    }

    /// Returns IDG nodes for `Place::Read{name}` / `Place::Write{name}`
    /// in `func` that lie *after* `cutoff` in source order. `name`
    /// may be a bare storage name (`buf`) or an exact projected
    /// storage path (`env.cmd`). Used by output-argument flow rules
    /// after a tainted input reaches a call that mutates an output
    /// carrier.
    pub fn nodes_for_name_after_span(&self, func: FuncId, name: &str, cutoff: Span) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let bare_strid = segment.strings.lookup(name);
        let projected = projected_storage_path(&segment, name);
        if bare_strid.is_none() && projected.is_none() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let matches = match place {
                // Reads are span-shared in the current model — accept
                // any Read of the name (the over-approximation is
                // harmless when the only relevant flow is post-cutoff
                // because pre-cutoff reads can't reach a seed nobody
                // wrote yet).
                Place::Read { name: n, path } => {
                    bare_strid.is_some_and(|strid| path.is_empty() && *n == strid)
                        || projected.as_ref().is_some_and(|(base, projected_path)| {
                            *n == *base && path.as_slice() == projected_path.as_slice()
                        })
                }
                // Writes are span-distinct — only writes after cutoff.
                Place::Write { name: n, path, span } => {
                    span_after(*span, cutoff)
                        && (bare_strid.is_some_and(|strid| path.is_empty() && *n == strid)
                            || projected.as_ref().is_some_and(|(base, projected_path)| {
                                *n == *base && path.as_slice() == projected_path.as_slice()
                            }))
                }
                _ => false,
            };
            if !matches {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) {
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                    out.push(ws_node);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Enumerate every CallArg / CallRet / receiver-bridge ws_node
    /// in `func`'s segment whose owning call site is anchored after
    /// `cutoff` and references `name`. Used by the receiver-state
    /// propagation post-pass to seed downstream consumers of a
    /// rule-mutated receiver: when `obj.add(x)` (rule-matched)
    /// makes `obj`'s state tainted, every subsequent call that
    /// reads `obj` (positional arg, explicit receiver, implicit
    /// receiver-bridge) needs its CallArg ws_node included so the
    /// next closure round picks it up as tainted-arg for further
    /// rule matching. Walks the workspace IDG's edge index — for
    /// every Write(`name`)→consumer edge in the segment, the
    /// destination consumer is post-`cutoff` if its anchored call
    /// span sorts after `cutoff`.
    pub fn name_consumer_nodes_after_span(&self, func: FuncId, name: &str, cutoff: Span) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let Some(strid) = segment.strings.lookup(name) else {
            return Vec::new();
        };
        // Find every node whose Place is a Write or Read of `name`
        // (path empty) — these are the bridge_read fan-in points.
        let mut name_source_local: ahash::AHashSet<crate::node::NodeId> = ahash::AHashSet::default();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let matches = matches!(place, Place::Read { name: n, path } if path.is_empty() && *n == strid)
                || matches!(place, Place::Write { name: n, path, .. } if path.is_empty() && *n == strid);
            if !matches {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local) = self.local_node_for(&unified, seg_id, func, pid) {
                name_source_local.insert(local);
            }
        }
        if name_source_local.is_empty() {
            return Vec::new();
        }
        // Walk the segment's intra-edge list. For every edge whose
        // `from` is one of those Write/Read nodes, examine the `to`
        // node's Place. If it's a CallArg or CallRet anchored after
        // cutoff, include its ws_node.
        let mut out = Vec::new();
        let mut seen: ahash::AHashSet<WsNodeId> = ahash::AHashSet::default();
        for edge in &segment.edges {
            if !name_source_local.contains(&edge.from) {
                continue;
            }
            let Some(to_node) = segment.nodes.get(edge.to) else {
                continue;
            };
            if to_node.func != func {
                continue;
            }
            let Some(place) = segment.places.places.get(to_node.place.0 as usize) else {
                continue;
            };
            let consumer_span = match place {
                Place::CallArg { site, .. } => site.0,
                Place::CallRet { site } => site.0,
                _ => continue,
            };
            if !span_after(consumer_span, cutoff) {
                continue;
            }
            if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, edge.to) {
                if seen.insert(ws_node) {
                    out.push(ws_node);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Enumerate every function id known to the IDG. Walks
    /// segments and collects each segment's recorded funcs.
    /// Order is sorted by raw FuncId to keep determinism.
    pub fn all_funcs(&self) -> Vec<FuncId> {
        let mut out: Vec<FuncId> = Vec::new();
        for (_, segment) in self.workspace.segment_views() {
            for raw in &segment.funcs {
                out.push(FuncId::new(*raw));
            }
        }
        out.sort_by_key(|f| f.raw());
        out.dedup();
        out
    }

    /// Find the `Place::Return` node of a function (if it exists in
    /// the IDG — every callable should via the Phase 2 transfer
    /// pass's defensive interning).
    pub fn return_node_of(&self, func: FuncId) -> Option<WsNodeId> {
        let unified = self.ensure_unified();
        let seg_id = self.workspace.segment_for_func(func)?;
        let segment = self.workspace.segment_view(seg_id)?;
        let pid = segment.places.lookup(&Place::Return)?;
        let local_node = self.local_node_for(&unified, seg_id, func, pid)?;
        Self::ws_node_for(&unified, seg_id, local_node)
    }

    /// Enumerate every transitive cross-call propagation reachable
    /// from `seeds`. Walks both the per-segment intra edges (for
    /// caller/callee pairs that live in the same source file) and
    /// the workspace cross-file edge index (for cross-file
    /// propagation), keeps only edges whose `from` endpoint is in
    /// the seed's forward closure, and lifts each edge into a
    /// [`CrossCallEdge`] row.
    ///
    /// Used by value-flow / dataflow consumers as the IDG-native
    /// replacement for the legacy engine's `result.call_records`
    /// list.
    pub fn cross_call_edges_in_closure(&self, seeds: &[WsNodeId]) -> Vec<CrossCallEdge> {
        self.cross_call_edges_in_closure_with_max_precision(seeds, Some(SEMANTIC_MAX_PRECISION))
    }

    /// Same as [`Self::cross_call_edges_in_closure`], but computes
    /// the closure itself inside a precision scope. This is the
    /// semantic flow surface used by review/security/export callers:
    /// exact and semantically narrowed edges are walked to fixpoint,
    /// while weaker diagnostic edges are not traversed.
    pub fn cross_call_edges_in_closure_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Vec<CrossCallEdge> {
        let evidence = self.forward_closure_evidence_with_max_precision(seeds, max_precision);
        let mut edges = evidence.cross_calls;
        edges.sort_unstable_by_key(|edge| {
            (
                edge.caller.raw(),
                edge.callee.raw(),
                edge.call_span,
                edge.arg_idx,
                edge.param_idx,
                edge.precision,
                edge.relation,
            )
        });
        edges.dedup();
        edges
    }

    /// Same as [`Self::cross_call_edges_in_closure`], but consumes a
    /// closure the caller already computed.
    pub fn cross_call_edges_in_reachable_nodes(&self, closure: &[WsNodeId]) -> Vec<CrossCallEdge> {
        self.cross_call_edges_in_reachable_nodes_with_max_precision(closure, Some(SEMANTIC_MAX_PRECISION))
    }

    /// Same as [`Self::cross_call_edges_in_reachable_nodes`], but
    /// drops cross-call rows outside the caller's precision scope.
    pub fn cross_call_edges_in_reachable_nodes_with_max_precision(
        &self,
        closure: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Vec<CrossCallEdge> {
        self.cross_call_edges_in_reachable_nodes_filtered_with_max_precision(closure, max_precision, None)
    }

    /// Same as [`Self::cross_call_edges_in_reachable_nodes_with_max_precision`],
    /// but keeps only rows whose caller and callee are both inside
    /// `lineage_funcs` when supplied.
    pub fn cross_call_edges_in_reachable_nodes_filtered_with_max_precision(
        &self,
        closure: &[WsNodeId],
        max_precision: Option<Precision>,
        lineage_funcs: Option<&AHashSet<FuncId>>,
    ) -> Vec<CrossCallEdge> {
        let unified = self.ensure_unified();
        if let Some(lineage_funcs) = lineage_funcs {
            return self.cross_call_edges_in_reachable_nodes_scoped(
                &unified,
                closure,
                max_precision,
                lineage_funcs,
            );
        }
        let cross_calls_by_from = self.ensure_cross_calls_by_from(&unified);
        let mut out = Vec::new();
        for ws_node in closure {
            if let Some(rows) = cross_calls_by_from.get(ws_node) {
                for row in rows {
                    if max_precision.is_some_and(|max| row.precision > max) {
                        continue;
                    }
                    if lineage_funcs
                        .is_some_and(|funcs| !(funcs.contains(&row.caller) && funcs.contains(&row.callee)))
                    {
                        continue;
                    }
                    out.push(*row);
                }
            }
        }
        out
    }

    /// Look up cross-call evidence in the immutable index for an exact
    /// compiler function scope. Building the scope decodes each admitted
    /// relation once; every entry closure then touches only its reached source
    /// nodes.
    fn cross_call_edges_in_reachable_nodes_scoped(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        closure: &[WsNodeId],
        max_precision: Option<Precision>,
        lineage_funcs: &AHashSet<FuncId>,
    ) -> Vec<CrossCallEdge> {
        if closure.is_empty() || lineage_funcs.is_empty() {
            return Vec::new();
        }
        let rows = self.ensure_scoped_cross_calls_by_from(unified, lineage_funcs);
        let mut out = Vec::new();
        for node in closure {
            if let Some(node_rows) = rows.get(node) {
                for row in node_rows {
                    if max_precision.is_none_or(|max| row.precision <= max) {
                        out.push(*row);
                    }
                }
            }
        }
        out.sort_unstable_by_key(|row| {
            (
                row.caller.raw(),
                row.callee.raw(),
                row.call_span.file.raw(),
                row.call_span.start,
                row.call_span.end,
                row.arg_idx,
                row.param_idx,
                row.precision.rank(),
                row.relation,
            )
        });
        out.dedup();
        out
    }

    /// Every semantic function-to-function dataflow edge known to the
    /// IDG, in source-to-sink/dataflow order.
    ///
    /// Unlike the resolved callgraph, this includes callback
    /// bindings, return-to-caller propagation, and cross-method field
    /// links that the IDG stitcher proves. Security source scheduling
    /// uses this as its function-level reachability graph so it can
    /// avoid per-source full dataflow walks without dropping
    /// higher-order flows.
    pub fn semantic_function_edges_with_max_precision(
        &self,
        max_precision: Option<Precision>,
    ) -> Vec<(FuncId, FuncId)> {
        let mut out: Vec<(FuncId, FuncId)> = self
            .semantic_cross_call_edges_with_max_precision(max_precision)
            .into_iter()
            .map(|row| (row.caller, row.callee))
            .collect();
        out.sort_by_key(|(caller, callee)| (caller.raw(), callee.raw()));
        out.dedup();
        out
    }

    /// Exact function corridor between semantic source and target sets.
    ///
    /// The relation is the IDG's numeric compiler dataflow projection, so it
    /// includes arguments, returns, callbacks, captures, and projected field
    /// state in their source-to-sink direction. Both worklists run to a finite
    /// least fixed point; there is no path-depth, iteration, or result cap.
    #[must_use]
    pub fn semantic_function_corridor_with_max_precision(
        &self,
        source_funcs: &[FuncId],
        target_funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> AHashSet<FuncId> {
        if source_funcs.is_empty() || target_funcs.is_empty() {
            return AHashSet::default();
        }
        let mut forward: AHashMap<FuncId, Vec<FuncId>> = AHashMap::default();
        let mut backward: AHashMap<FuncId, Vec<FuncId>> = AHashMap::default();
        for (from, to) in self.semantic_function_edges_with_max_precision(max_precision) {
            forward.entry(from).or_default().push(to);
            backward.entry(to).or_default().push(from);
        }

        let fixed_point = |seeds: &[FuncId], relation: &AHashMap<FuncId, Vec<FuncId>>| {
            let mut reached = AHashSet::default();
            let mut pending = Vec::new();
            for seed in seeds.iter().copied() {
                if reached.insert(seed) {
                    pending.push(seed);
                }
            }
            while let Some(func) = pending.pop() {
                for next in relation.get(&func).into_iter().flatten().copied() {
                    if reached.insert(next) {
                        pending.push(next);
                    }
                }
            }
            reached
        };
        let forward_reached = fixed_point(source_funcs, &forward);
        let mut targets: Vec<FuncId> = target_funcs.iter().copied().collect();
        targets.sort_unstable_by_key(|func| func.raw());
        let backward_reached = fixed_point(&targets, &backward);
        forward_reached.intersection(&backward_reached).copied().collect()
    }

    /// Every semantic cross-call dataflow edge known to the IDG.
    ///
    /// This is the renderable counterpart to
    /// [`Self::semantic_function_edges_with_max_precision`]: callers that
    /// need call-site spans, precision, and edge kind can consume these rows
    /// directly instead of reducing the graph to `(caller, callee)` pairs.
    pub fn semantic_cross_call_edges_with_max_precision(
        &self,
        max_precision: Option<Precision>,
    ) -> Vec<CrossCallEdge> {
        let unified = self.ensure_unified();
        let cross_calls_by_from = self.ensure_cross_calls_by_from(&unified);
        let mut out = Vec::new();
        for rows in cross_calls_by_from.values() {
            for row in rows {
                if max_precision.is_some_and(|precision| row.precision > precision) {
                    continue;
                }
                out.push(*row);
            }
        }
        out.sort_by_key(|row| {
            (
                row.caller.raw(),
                row.callee.raw(),
                row.call_span.file.raw(),
                row.call_span.start,
                row.call_span.end,
                row.arg_idx,
                row.param_idx,
            )
        });
        out.dedup();
        out
    }

    /// Build the unified address space if it isn't cached yet.
    fn ensure_unified(&self) -> Arc<UnifiedAddressSpace> {
        {
            let read = self.unified.read();
            if let Some(u) = read.as_ref() {
                return Arc::clone(u);
            }
        }

        // Only one worker should pay the workspace-wide materialisation
        // cost. Source/security analysis can issue exact IDG queries from
        // multiple Rayon workers; building outside the write lock let each
        // worker race through `build_unified()` and discard all but one
        // result, duplicating CPU and memory for broad scans.
        let mut write = self.unified.write();
        if let Some(u) = write.as_ref() {
            return Arc::clone(u);
        }
        let unified = Arc::new(
            self.persisted_query_accelerator
                .as_ref()
                .and_then(|parts| {
                    PersistedQueryAccelerator::decode(parts.core.stream(), parts.core.len(), &self.workspace)
                        .map(PersistedQueryAccelerator::into_unified_core)
                        .map_err(|error| {
                            bonsai_diagnostics::debug_log!(
                                "idg-query",
                                "persisted core accelerator unavailable; rebuilding exact headers: {error}"
                            );
                            error
                        })
                        .ok()
                })
                .unwrap_or_else(|| self.build_unified()),
        );
        *write = Some(Arc::clone(&unified));
        unified
    }

    /// Compute a flat workspace-global address space. Reachability CSRs are
    /// materialised lazily for the precision actually requested.
    fn build_unified(&self) -> UnifiedAddressSpace {
        let mut node_funcs = Vec::new();
        let mut node_boundaries = Vec::new();
        let mut projected_storage = Vec::new();
        let mut segment_bases = Vec::with_capacity(self.workspace.segment_count() + 1);
        let mut func_segment_pairs = Vec::new();
        let mut call_arg_nodes = Vec::new();
        let mut call_arg_sites = Vec::new();
        let mut call_arg_indices = Vec::new();
        let mut param_nodes = Vec::new();
        let mut param_indices = Vec::new();
        // 1. Allocate a workspace-global id for every segment-local
        // node. Stable order: iterate segments by SegmentId, then
        // local node id ascending. That guarantees deterministic ws
        // node ids for repeated builds (important for snapshot tests).
        for (seg_id, segment) in self.workspace.segment_views() {
            segment_bases.push(u32::try_from(node_funcs.len()).expect("unified IDG node count exceeds u32"));
            func_segment_pairs.extend(segment.funcs.iter().copied().map(|func| (func, seg_id)));
            for node in &segment.nodes.nodes {
                let ws_node =
                    WsNodeId(u32::try_from(node_funcs.len()).expect("unified IDG node count exceeds u32"));
                node_funcs.push(node.func);
                let place = segment.places.get(node.place);
                if let Some(Place::CallArg { site, idx }) = place {
                    call_arg_nodes.push(ws_node);
                    call_arg_sites.push(site.0);
                    call_arg_indices.push(*idx);
                }
                if let Some(Place::Param { idx }) = place {
                    param_nodes.push(ws_node);
                    param_indices.push(*idx);
                }
                node_boundaries.push(match place {
                    Some(Place::Param { .. }) => NODE_BOUNDARY_PARAM,
                    Some(Place::Return) => NODE_BOUNDARY_RETURN,
                    Some(Place::Throw { .. }) => NODE_BOUNDARY_THROW,
                    Some(Place::Yield) => NODE_BOUNDARY_YIELD,
                    Some(Place::CallRet { .. }) => NODE_BOUNDARY_CALL_RET,
                    _ => 0,
                });
                projected_storage.push(u8::from(
                    place
                        .and_then(|place| structured_storage_parts(&segment, place))
                        .is_some_and(|(parts, _, _)| parts.len() > 1),
                ));
            }
        }
        segment_bases.push(u32::try_from(node_funcs.len()).expect("unified IDG node count exceeds u32"));
        let max_func = node_funcs.iter().map(|func| func.raw() as usize).max();
        let mut offsets = vec![0_u32; max_func.map_or(1, |max| max.saturating_add(2))];
        for func in &node_funcs {
            offsets[func.raw() as usize + 1] = offsets[func.raw() as usize + 1].saturating_add(1);
        }
        for index in 1..offsets.len() {
            offsets[index] = offsets[index].saturating_add(offsets[index - 1]);
        }
        let mut func_nodes = vec![NodeId(0); node_funcs.len()];
        let mut write_offsets = offsets[..offsets.len().saturating_sub(1)].to_vec();
        // Revisit each compiler segment and fill its functions' final dense
        // ranges directly. This trades one sequential spool pass for removing
        // a four-byte PlaceId projection per workspace node from peak RSS.
        // Every function belongs to one segment, so its completed slice can be
        // sorted immediately by the canonical `(PlaceId, NodeId)` key before
        // that decoded segment page is released.
        for (seg_id, segment) in self.workspace.segment_views() {
            let base = segment_bases[seg_id.0 as usize];
            for (local_raw, node) in segment.nodes.nodes.iter().enumerate() {
                let cursor = &mut write_offsets[node.func.raw() as usize];
                let local_raw = u32::try_from(local_raw).expect("segment-local IDG node count exceeds u32");
                func_nodes[*cursor as usize] = NodeId(base.saturating_add(local_raw));
                *cursor = cursor.saturating_add(1);
            }
            for &func_raw in &segment.funcs {
                let func_raw = func_raw as usize;
                let Some((&start, &end)) = offsets.get(func_raw).zip(offsets.get(func_raw + 1)) else {
                    continue;
                };
                let start = start as usize;
                let end = end as usize;
                func_nodes[start..end].sort_unstable_by_key(|node| {
                    let local = NodeId(node.0.saturating_sub(base));
                    (
                        segment
                            .nodes
                            .get(local)
                            .map_or(crate::node::PlaceId::SENTINEL, |node| node.place)
                            .0,
                        node.0,
                    )
                });
            }
        }
        drop(write_offsets);
        let mut func_segments = vec![u32::MAX; offsets.len().saturating_sub(1)];
        for (func, segment) in func_segment_pairs {
            if let Some(slot) = func_segments.get_mut(func as usize) {
                *slot = segment.0;
            }
        }
        let nodes_by_func = NodesByFunc {
            offsets: offsets.into_boxed_slice(),
            nodes: func_nodes.into_boxed_slice(),
        };
        UnifiedAddressSpace {
            segment_bases: segment_bases.into_boxed_slice(),
            func_segments: func_segments.into_boxed_slice(),
            node_funcs: node_funcs.into_boxed_slice(),
            node_boundaries: node_boundaries.into_boxed_slice(),
            projected_storage: projected_storage.into_boxed_slice(),
            nodes_by_func,
            call_args: CallArgIdentityIndex {
                nodes: call_arg_nodes.into_boxed_slice(),
                sites: call_arg_sites.into_boxed_slice(),
                indices: call_arg_indices.into_boxed_slice(),
            },
            params: ParamIdentityIndex {
                nodes: param_nodes.into_boxed_slice(),
                indices: param_indices.into_boxed_slice(),
            },
            unfiltered_reach: RwLock::new(None),
            precision_reach: RwLock::new(AHashMap::new()),
            contextual_summaries: RwLock::new(AHashMap::new()),
            cross_calls_by_from: RwLock::new(None),
            symbolic_runtime: OnceLock::new(),
        }
    }

    fn ws_node_for(unified: &UnifiedAddressSpace, seg_id: SegmentId, local_node: NodeId) -> Option<WsNodeId> {
        Self::ws_node_for_segment_bases(&unified.segment_bases, seg_id, local_node)
    }

    fn ws_node_for_segment_bases(
        segment_bases: &[u32],
        seg_id: SegmentId,
        local_node: NodeId,
    ) -> Option<WsNodeId> {
        let seg_idx = seg_id.0 as usize;
        let start = *segment_bases.get(seg_idx)?;
        let end = *segment_bases.get(seg_idx + 1)?;
        (local_node.0 < end.saturating_sub(start)).then(|| WsNodeId(start + local_node.0))
    }

    fn unified_node_count(unified: &UnifiedAddressSpace) -> usize {
        unified.segment_bases.last().copied().unwrap_or(0) as usize
    }

    fn ws_address(unified: &UnifiedAddressSpace, node: WsNodeId) -> Option<(SegmentId, NodeId)> {
        let func = unified.node_funcs.get(node.0 as usize)?;
        let segment = *unified.func_segments.get(func.raw() as usize)?;
        if segment == u32::MAX {
            return None;
        }
        let segment = SegmentId(segment);
        let start = *unified.segment_bases.get(segment.0 as usize)?;
        let end = *unified.segment_bases.get(segment.0 as usize + 1)?;
        (node.0 >= start && node.0 < end).then(|| (segment, NodeId(node.0 - start)))
    }

    /// Resolve one compiler place inside a function without retaining the
    /// build-side `(FuncId, PlaceId) -> NodeId` hash table for every file.
    /// `build_unified` orders the already-required per-function node lists by
    /// `PlaceId`, so warm sidecar queries stay exact and logarithmic while the
    /// canonical node vector remains the single source of truth.
    fn local_node_for(
        &self,
        unified: &UnifiedAddressSpace,
        seg_id: SegmentId,
        func: FuncId,
        place: crate::node::PlaceId,
    ) -> Option<NodeId> {
        let nodes = unified.nodes_by_func.get(func)?;
        let segment = self.workspace.segment_view(seg_id)?;
        let index = nodes
            .binary_search_by_key(&place, |ws_node| {
                let Some((node_segment, local_node)) = Self::ws_address(unified, WsNodeId(ws_node.0)) else {
                    return crate::node::PlaceId::SENTINEL;
                };
                debug_assert_eq!(node_segment, seg_id);
                segment
                    .nodes
                    .get(local_node)
                    .map_or(crate::node::PlaceId::SENTINEL, |node| node.place)
            })
            .ok()?;
        let (node_segment, local_node) = Self::ws_address(unified, WsNodeId(nodes[index].0))?;
        (node_segment == seg_id).then_some(local_node)
    }

    fn ws_node_func(unified: &UnifiedAddressSpace, node: NodeId) -> Option<FuncId> {
        unified.node_funcs.get(node.0 as usize).copied()
    }

    fn node_is_projected_storage(
        unified: &UnifiedAddressSpace,
        segment_id: SegmentId,
        node_id: NodeId,
    ) -> bool {
        Self::ws_node_for(unified, segment_id, node_id)
            .and_then(|node| unified.projected_storage.get(node.0 as usize))
            .copied()
            == Some(1)
    }

    fn forward_closure_nodes_within(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        seeds: &[NodeId],
        allowed: &NodeBitSet,
        max_precision: Option<Precision>,
    ) -> Vec<NodeId> {
        if let Some(precision) = max_precision {
            self.ensure_precision_reach(unified, precision)
                .forward_closure_nodes_within(seeds, allowed)
        } else {
            self.ensure_unfiltered_reach(unified)
                .forward_closure_nodes_within(seeds, allowed)
        }
    }

    fn build_contextual_summary_runtime(
        &self,
        summary_edges: &[crate::function_summary::ContextualSummaryEdge],
        max_precision: Option<Precision>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> ContextualSummaryRuntime {
        self.build_contextual_summary_runtime_with_reverse(summary_edges, max_precision, true, allowed_funcs)
    }

    fn build_contextual_summary_runtime_with_reverse(
        &self,
        summary_edges: &[crate::function_summary::ContextualSummaryEdge],
        max_precision: Option<Precision>,
        include_reverse: bool,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> ContextualSummaryRuntime {
        let unified = self.ensure_unified();
        let node_pair_is_allowed = |from: WsNodeId, to: WsNodeId| {
            allowed_funcs.is_none_or(|allowed| {
                Self::ws_node_func(&unified, NodeId(from.0))
                    .zip(Self::ws_node_func(&unified, NodeId(to.0)))
                    .is_some_and(|(from_func, to_func)| {
                        allowed.contains(&from_func) && allowed.contains(&to_func)
                    })
            })
        };
        let segments: Vec<SegmentId> = match allowed_funcs {
            Some(funcs) => {
                let mut segments: Vec<SegmentId> = funcs
                    .iter()
                    .filter_map(|func| self.workspace.segment_for_func(*func))
                    .collect();
                segments.sort_unstable_by_key(|segment| segment.0);
                segments.dedup();
                segments
            }
            None => (0..self.workspace.segment_count())
                .filter_map(|index| u32::try_from(index).ok().map(SegmentId))
                .collect(),
        };

        // The function-summary compiler already contributes every
        // matched call summary. Canonical function-local relations are read
        // straight from the IDG below, avoiding a workspace-sized duplicate
        // endpoint vector. Preserve non-call relations that intentionally
        // cross function ownership, such as adapter-derived receiver/object-
        // field state flow between methods. Ordinary relations are context-
        // neutral.
        // Projected inter edges from compatibility adapters represent their
        // allocation-insensitive heap places and are kept in `heap_by_from`;
        // scalar InterCallArg / InterReturn / InterThrow edges remain exact
        // stack boundaries.
        let mut heap_rows = Vec::new();
        let mut field_cross_call_index = FieldCrossCallIndex::default();
        // Only compatibility boundaries whose synthetic endpoint is not the
        // canonical formal/return place need same-site structural remapping.
        // Retaining every ordinary call boundary made this sparse repair
        // demand proportional to the whole workspace call relation.
        let mut structural_boundary_demand = AHashSet::default();
        {
            let mut record_non_call_relation =
                |from_segment: SegmentId, to_segment: SegmentId, edge: &IdgEdge| {
                    let projected_heap_relation = edge.meta.kind.is_inter()
                        && (Self::node_is_projected_storage(&unified, from_segment, edge.from)
                            || Self::node_is_projected_storage(&unified, to_segment, edge.to));
                    if max_precision.is_some_and(|max| edge.meta.precision > max) {
                        return;
                    }
                    let Some(from) = Self::ws_node_for(&unified, from_segment, edge.from) else {
                        return;
                    };
                    let Some(to) = Self::ws_node_for(&unified, to_segment, edge.to) else {
                        return;
                    };
                    if !node_pair_is_allowed(from, to) {
                        return;
                    }
                    if edge.meta.kind.is_inter() && !projected_heap_relation {
                        if !Self::contextual_endpoint_is_structural(&unified, edge.meta.kind, from, to) {
                            if let Some((key, _)) =
                                Self::contextual_boundary_identity(&unified, edge, from, to)
                            {
                                structural_boundary_demand.insert((key.caller, key.span));
                            }
                        }
                        return;
                    }
                    if projected_heap_relation {
                        let from_func = Self::ws_node_func(&unified, NodeId(from.0));
                        let to_func = Self::ws_node_func(&unified, NodeId(to.0));
                        let cross_call = match (edge.meta.kind, from_func, to_func) {
                            (IdgEdgeKind::InterFieldCallArg, Some(caller), Some(callee))
                                if caller != callee =>
                            {
                                let (arg_idx, param_idx) = self
                                    .workspace
                                    .segment_view(from_segment)
                                    .zip(self.workspace.segment_view(to_segment))
                                    .and_then(|(from_segment_view, to_segment_view)| {
                                        let from_node = from_segment_view.nodes.get(edge.from)?;
                                        let to_node = to_segment_view.nodes.get(edge.to)?;
                                        let from_place = from_segment_view.places.get(from_node.place)?;
                                        let to_place = to_segment_view.places.get(to_node.place)?;
                                        field_cross_call_arg_and_param_indices(
                                            &mut field_cross_call_index,
                                            from_segment,
                                            &from_segment_view,
                                            to_segment,
                                            &to_segment_view,
                                            caller,
                                            callee,
                                            edge.meta.via_span,
                                            from_place,
                                            to_place,
                                        )
                                    })
                                    .unwrap_or((u32::MAX, u32::MAX));
                                Some(CrossCallEdge {
                                    caller,
                                    callee,
                                    call_span: edge.meta.via_span,
                                    arg_idx,
                                    param_idx,
                                    precision: edge.meta.precision,
                                    call_kind: edge.meta.call_kind,
                                    relation: CrossCallRelation::Argument,
                                })
                            }
                            (IdgEdgeKind::InterFieldReturn, Some(returning), Some(caller))
                                if returning != caller =>
                            {
                                Some(CrossCallEdge {
                                    caller: returning,
                                    callee: caller,
                                    call_span: edge.meta.via_span,
                                    arg_idx: u32::MAX,
                                    param_idx: u32::MAX,
                                    precision: edge.meta.precision,
                                    call_kind: edge.meta.call_kind,
                                    relation: CrossCallRelation::Return,
                                })
                            }
                            _ => None,
                        };
                        heap_rows.push((
                            NodeId(from.0),
                            HeapBoundaryEdge {
                                target: to,
                                cross_call,
                            },
                        ));
                    }
                };
            for &segment_id in &segments {
                let Some(segment) = self.workspace.segment_view(segment_id) else {
                    continue;
                };
                for edge in &segment.edges {
                    record_non_call_relation(segment_id, segment_id, edge);
                }
            }
            self.workspace
                .visit_cross_file_edges(|edges| {
                    for edge in edges {
                        record_non_call_relation(edge.from_segment, edge.to_segment, &edge.edge);
                    }
                })
                .expect("validated IDG cross-file relation remains readable");
        }
        let reverse_heap_rows = if include_reverse {
            heap_rows
                .iter()
                .map(|(source, edge)| (NodeId(edge.target.0), WsNodeId(source.0)))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let heap_by_from = SparseHeapEdges::from_rows(heap_rows);

        // Eager compatibility field edges can point at a canonical type-field
        // node whose owning function differs from the logical callee. Build
        // the authoritative call-site relation from structural formal/return
        // places first, then attribute those synthetic edges to the exact
        // same-span compiler boundary.
        let mut structural_boundaries = Vec::new();
        if !structural_boundary_demand.is_empty() {
            let mut record_structural_boundary =
                |from_segment: SegmentId, to_segment: SegmentId, edge: &IdgEdge| {
                    if max_precision.is_some_and(|max| edge.meta.precision > max) {
                        return;
                    }
                    let Some(from) = Self::ws_node_for(&unified, from_segment, edge.from) else {
                        return;
                    };
                    let Some(to) = Self::ws_node_for(&unified, to_segment, edge.to) else {
                        return;
                    };
                    if !node_pair_is_allowed(from, to) {
                        return;
                    }
                    if !Self::contextual_endpoint_is_structural(&unified, edge.meta.kind, from, to) {
                        return;
                    }
                    if let Some((key, _)) = Self::contextual_boundary_identity(&unified, edge, from, to) {
                        if structural_boundary_demand.contains(&(key.caller, key.span)) {
                            structural_boundaries.push(key);
                        }
                    }
                };
            for &segment_id in &segments {
                let Some(segment) = self.workspace.segment_view(segment_id) else {
                    continue;
                };
                for edge in &segment.edges {
                    record_structural_boundary(segment_id, segment_id, edge);
                }
            }
            self.workspace
                .visit_cross_file_edges(|edges| {
                    for edge in edges {
                        record_structural_boundary(edge.from_segment, edge.to_segment, &edge.edge);
                    }
                })
                .expect("validated IDG cross-file relation remains readable");
        }
        let structural_boundaries = StructuralBoundaryIndex::new(structural_boundaries);

        let external_boundaries = allowed_funcs.is_none();
        let mut call_rows = ContextBoundaryRows::new(external_boundaries);
        let mut return_rows = ContextBoundaryRows::new(external_boundaries);
        {
            let mut record_boundary = |from_segment: SegmentId, to_segment: SegmentId, edge: &IdgEdge| {
                if max_precision.is_some_and(|max| edge.meta.precision > max) {
                    return;
                }
                if edge.meta.kind.is_inter()
                    && (Self::node_is_projected_storage(&unified, from_segment, edge.from)
                        || Self::node_is_projected_storage(&unified, to_segment, edge.to))
                {
                    return;
                }
                let Some(from) = Self::ws_node_for(&unified, from_segment, edge.from) else {
                    return;
                };
                let Some(to) = Self::ws_node_for(&unified, to_segment, edge.to) else {
                    return;
                };
                if !node_pair_is_allowed(from, to) {
                    return;
                }
                let Some((endpoint_key, enters_callee)) =
                    Self::contextual_boundary_identity(&unified, edge, from, to)
                else {
                    return;
                };
                let structural = structural_boundaries.for_site(endpoint_key.caller, endpoint_key.span);
                let endpoint_is_structural = structural.iter().any(|key| key.callee == endpoint_key.callee);
                let mut push_boundary = |key: ContextBoundaryKey| {
                    let cross_call = match edge.meta.kind {
                        IdgEdgeKind::InterCallArg => {
                            let from = WsNodeId(from.0);
                            let to = WsNodeId(to.0);
                            let (relation, arg_idx, param_idx) =
                                if let (Some((_, arg_idx)), Some(param_idx)) =
                                    (unified.call_args.get(from), unified.params.get(to))
                                {
                                    (CrossCallRelation::Argument, arg_idx, param_idx)
                                } else if unified.node_boundaries.get(from.0 as usize).copied()
                                    == Some(NODE_BOUNDARY_CALL_RET)
                                {
                                    (
                                        CrossCallRelation::Callback,
                                        u32::MAX,
                                        unified.params.get(to).unwrap_or(u32::MAX),
                                    )
                                } else {
                                    // Adapter-proven scalar captures and callback
                                    // carriers can cross a call boundary without
                                    // occupying an ordinary positional slot.
                                    (CrossCallRelation::Capture, u32::MAX, u32::MAX)
                                };
                            Some(CrossCallEdge {
                                caller: key.caller,
                                callee: key.callee,
                                call_span: key.span,
                                arg_idx,
                                param_idx,
                                precision: edge.meta.precision,
                                call_kind: edge.meta.call_kind,
                                relation,
                            })
                        }
                        IdgEdgeKind::InterReturn | IdgEdgeKind::InterYield => Some(CrossCallEdge {
                            // Return evidence is oriented in source-to-sink
                            // propagation order: returning callee -> caller.
                            caller: key.callee,
                            callee: key.caller,
                            call_span: key.span,
                            arg_idx: u32::MAX,
                            param_idx: u32::MAX,
                            precision: edge.meta.precision,
                            call_kind: edge.meta.call_kind,
                            relation: CrossCallRelation::Return,
                        }),
                        IdgEdgeKind::InterThrow => None,
                        _ => None,
                    };
                    let boundary = ContextBoundaryEdge {
                        key,
                        target: NodeId(to.0),
                        cross_call,
                    };
                    if enters_callee {
                        call_rows.push((NodeId(from.0), boundary));
                    } else {
                        return_rows.push((NodeId(from.0), boundary));
                    }
                };
                if structural.is_empty() || endpoint_is_structural {
                    push_boundary(endpoint_key);
                } else {
                    for &key in structural {
                        push_boundary(key);
                    }
                }
            };
            for &segment_id in &segments {
                let Some(segment) = self.workspace.segment_view(segment_id) else {
                    continue;
                };
                for edge in &segment.edges {
                    record_boundary(segment_id, segment_id, edge);
                }
            }
            self.workspace
                .visit_cross_file_edges(|edges| {
                    for edge in edges {
                        record_boundary(edge.from_segment, edge.to_segment, &edge.edge);
                    }
                })
                .expect("validated IDG cross-file relation remains readable");
        }
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "contextual boundary demand={} structural={} calls={} returns={} heap={} rss_mib={}",
            structural_boundary_demand.len(),
            structural_boundaries.rows.len(),
            call_rows.len(),
            return_rows.len(),
            heap_by_from.edges.len(),
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024)),
        );
        drop(structural_boundaries);
        drop(structural_boundary_demand);
        let (calls_by_from, reverse_call_rows) = call_rows.finish(include_reverse);
        let (returns_by_from, reverse_return_rows) = return_rows.finish(include_reverse);
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "contextual boundaries grouped calls={} returns={} reverse_calls={} reverse_returns={} rss_mib={}",
            calls_by_from.edges.len(),
            returns_by_from.edges.len(),
            reverse_call_rows.len(),
            reverse_return_rows.len(),
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024)),
        );
        let calls_by_from = ContextualBoundaryEdges::Resident(calls_by_from);
        let returns_by_from = ContextualBoundaryEdges::Resident(returns_by_from);
        let reverse_heap = ContextualReverseNodes::Resident(GroupedNodeIndex::from_rows(reverse_heap_rows));
        let reverse_calls = ContextualReverseNodes::Resident(GroupedNodeIndex::from_rows(reverse_call_rows));
        let reverse_returns =
            ContextualReverseNodes::Resident(GroupedNodeIndex::from_rows(reverse_return_rows));
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "contextual reverse indexes ready rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        let visit_pairs = |visit: &mut dyn FnMut(u32, u32)| {
            for edge in summary_edges {
                let Some(from) = Self::ws_node_for(&unified, edge.segment, edge.from) else {
                    continue;
                };
                let Some(to) = Self::ws_node_for(&unified, edge.segment, edge.to) else {
                    continue;
                };
                if !node_pair_is_allowed(from, to) {
                    continue;
                }
                visit(from.0, to.0);
            }
            for &segment_id in &segments {
                let Some(segment) = self.workspace.segment_view(segment_id) else {
                    continue;
                };
                for edge in &segment.edges {
                    if let Some((from, to)) =
                        Self::contextual_ordinary_pair(&unified, segment_id, segment_id, edge, max_precision)
                    {
                        if node_pair_is_allowed(WsNodeId(from), WsNodeId(to)) {
                            visit(from, to);
                        }
                    }
                }
            }
            self.workspace
                .visit_cross_file_edges(|edges| {
                    for edge in edges {
                        if let Some((from, to)) = Self::contextual_ordinary_pair(
                            &unified,
                            edge.from_segment,
                            edge.to_segment,
                            &edge.edge,
                            max_precision,
                        ) {
                            if node_pair_is_allowed(WsNodeId(from), WsNodeId(to)) {
                                visit(from, to);
                            }
                        }
                    }
                })
                .expect("validated IDG cross-file relation remains readable");
        };
        let reach = if allowed_funcs.is_some() {
            let mut forward_rows = Vec::new();
            visit_pairs(&mut |from, to| forward_rows.push((NodeId(from), WsNodeId(to))));
            let backward_rows = if include_reverse {
                forward_rows
                    .iter()
                    .map(|(from, to)| (NodeId(to.0), WsNodeId(from.0)))
                    .collect()
            } else {
                Vec::new()
            };
            ContextualReach::Sparse {
                forward: GroupedNodeIndex::from_rows(forward_rows),
                backward: GroupedNodeIndex::from_rows(backward_rows),
            }
        } else if include_reverse {
            ContextualReach::Dense(ReachabilityIndex::from_pair_visitor(
                Self::unified_node_count(&unified),
                visit_pairs,
            ))
        } else {
            ContextualReach::Dense(ReachabilityIndex::from_forward_pair_visitor(
                Self::unified_node_count(&unified),
                visit_pairs,
            ))
        };
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "contextual reach ready rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        ContextualSummaryRuntime {
            reach,
            heap_by_from: ContextualHeapEdges::Resident(heap_by_from),
            calls_by_from,
            returns_by_from,
            reverse_heap,
            reverse_calls,
            reverse_returns,
        }
    }

    fn contextual_ordinary_pair(
        unified: &UnifiedAddressSpace,
        from_segment: SegmentId,
        to_segment: SegmentId,
        edge: &IdgEdge,
        max_precision: Option<Precision>,
    ) -> Option<(u32, u32)> {
        if edge.meta.kind.is_inter()
            || edge.meta.kind == IdgEdgeKind::IntraAggregateConsume
            || max_precision.is_some_and(|max| edge.meta.precision > max)
        {
            return None;
        }
        let from = Self::ws_node_for(unified, from_segment, edge.from)?;
        let to = Self::ws_node_for(unified, to_segment, edge.to)?;
        let same_function =
            Self::ws_node_func(unified, NodeId(from.0)) == Self::ws_node_func(unified, NodeId(to.0));
        (!same_function || edge.meta.kind.is_intra()).then_some((from.0, to.0))
    }

    fn contextual_endpoint_is_structural(
        unified: &UnifiedAddressSpace,
        kind: IdgEdgeKind,
        from: WsNodeId,
        to: WsNodeId,
    ) -> bool {
        match kind {
            IdgEdgeKind::InterCallArg => {
                unified.node_boundaries.get(to.0 as usize).copied() == Some(NODE_BOUNDARY_PARAM)
            }
            IdgEdgeKind::InterReturn => {
                unified.node_boundaries.get(from.0 as usize).copied() == Some(NODE_BOUNDARY_RETURN)
            }
            IdgEdgeKind::InterYield => {
                unified.node_boundaries.get(from.0 as usize).copied() == Some(NODE_BOUNDARY_YIELD)
            }
            IdgEdgeKind::InterThrow => {
                unified.node_boundaries.get(from.0 as usize).copied() == Some(NODE_BOUNDARY_THROW)
            }
            _ => false,
        }
    }

    fn contextual_boundary_identity(
        unified: &UnifiedAddressSpace,
        edge: &IdgEdge,
        from: WsNodeId,
        to: WsNodeId,
    ) -> Option<(ContextBoundaryKey, bool)> {
        let (caller, callee, enters_callee) = match edge.meta.kind {
            IdgEdgeKind::InterCallArg => Self::ws_node_func(unified, NodeId(from.0))
                .zip(Self::ws_node_func(unified, NodeId(to.0)))
                .map(|(caller, callee)| (caller, callee, true)),
            IdgEdgeKind::InterReturn | IdgEdgeKind::InterThrow | IdgEdgeKind::InterYield => {
                { Self::ws_node_func(unified, NodeId(to.0)) }
                    .zip(Self::ws_node_func(unified, NodeId(from.0)))
                    .map(|(caller, callee)| (caller, callee, false))
            }
            _ => None,
        }?;
        Some((
            ContextBoundaryKey {
                caller,
                callee,
                span: edge.meta.via_span,
            },
            enters_callee,
        ))
    }

    fn symbolic_forward_closure_nodes(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        reach: &ContextualReach,
        seeds: &[NodeId],
        policy: SymbolicClosurePolicy<'_>,
        mut cross_calls: Option<&mut AHashSet<CrossCallEdge>>,
    ) -> Vec<NodeId> {
        let SymbolicClosurePolicy {
            max_precision,
            allowed_funcs,
            target_relevance,
            summary_callees,
            summary_root,
            contextual,
            activate_seed_callers,
        } = policy;
        let symbolic = self.workspace.symbolic_field();
        if !self.workspace.has_symbolic_transforms()
            && contextual.is_none()
            && allowed_funcs.is_none()
            && target_relevance.is_none()
            && summary_root.is_none()
        {
            return reach.forward_closure_nodes(seeds);
        }
        // The backward demand fixed point is a conservative superset. If it
        // contains none of the concrete compiler seeds, no forward path from
        // this query can reach a requested target. Return before opening the
        // symbolic relation; broad inspect batches commonly contain thousands
        // of independent lexical owners and only a small subset are relevant.
        if target_relevance.is_some_and(|relevance| !seeds.iter().any(|seed| relevance.contains_node(*seed)))
        {
            return Vec::new();
        }
        let runtime = self.ensure_symbolic_runtime(unified, allowed_funcs);
        let field_demand = Self::ensure_symbolic_field_demand(&runtime, max_precision);
        let node_count = Self::unified_node_count(unified);
        let mut worklist = SymbolicClosureWorklist::new(
            node_count,
            seeds.len(),
            summary_root,
            allowed_funcs,
            target_relevance,
            field_demand.as_ref(),
        );
        for seed in seeds.iter().copied() {
            if (seed.0 as usize) < node_count && symbolic_node_allowed(unified, &worklist, seed) {
                Self::enqueue_symbolic_node_source(unified, &runtime, seed, 0, &mut worklist);
            }
        }
        let mut processed_nodes = 0usize;
        let mut processed_facts = 0usize;
        let mut next_progress = 1_000_000usize;
        while worklist.has_pending() {
            if let Some(state) = worklist.next_node() {
                Self::propagate_symbolic_closure_node(
                    unified,
                    reach,
                    &runtime,
                    contextual,
                    summary_callees,
                    activate_seed_callers,
                    state,
                    cross_calls.as_deref_mut(),
                    &mut worklist,
                );
                processed_nodes = processed_nodes.saturating_add(1);
            }
            if let Some(fact) = worklist.next_fact() {
                Self::propagate_symbolic_closure_fact(
                    unified,
                    &runtime,
                    symbolic,
                    max_precision,
                    summary_callees,
                    contextual.is_some(),
                    activate_seed_callers,
                    fact,
                    cross_calls.as_deref_mut(),
                    &mut worklist,
                );
                processed_facts = processed_facts.saturating_add(1);
            }
            let processed = processed_nodes.saturating_add(processed_facts);
            if processed >= next_progress {
                bonsai_diagnostics::debug_log!(
                    "idg-closure",
                    "symbolic closure progress processed_nodes={} processed_facts={} root_context_states={} contextual_states={} facts={} resident_facts={} cached_positive_facts={} fact_runs={} fact_run_bytes={} fact_filter_bytes={} pending_nodes={} pending_facts={} call_contexts={}",
                    processed_nodes,
                    processed_facts,
                    worklist.reached.root.len(),
                    worklist.reached.contextual.len(),
                    worklist.facts.len(),
                    worklist.facts.resident_len(),
                    worklist.facts.recent_positive_len(),
                    worklist.facts.run_count(),
                    worklist.facts.disk_bytes(),
                    worklist.facts.bloom_filter_bytes(),
                    worklist.pending_nodes.len(),
                    worklist.pending_facts.len(),
                    worklist.contexts.ids.len()
                );
                next_progress = next_progress.saturating_add(1_000_000);
            }
        }
        let nodes = worklist.reached.nodes();
        bonsai_diagnostics::debug_log!(
            "idg-closure",
            "symbolic closure seeds={} reached={} facts={}",
            seeds.len(),
            nodes.len(),
            worklist.facts.len()
        );
        nodes
    }

    #[allow(clippy::too_many_arguments)]
    fn propagate_symbolic_closure_node(
        unified: &UnifiedAddressSpace,
        reach: &ContextualReach,
        runtime: &SymbolicRuntimeIndex,
        contextual: Option<&ContextualSummaryRuntime>,
        summary_callees: Option<&AHashMap<FuncId, Vec<FuncId>>>,
        activate_seed_callers: bool,
        state: ClosureNodeState,
        mut cross_calls: Option<&mut AHashSet<CrossCallEdge>>,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) {
        reach.visit_forward(state.node, |target| {
            if activate_summary_transition(unified, summary_callees, state.node, target, worklist) {
                Self::enqueue_symbolic_node_source(unified, runtime, target, state.context, worklist);
            }
        });
        let Some(contextual) = contextual else {
            return;
        };
        contextual.heap_by_from.visit(state.node, |edge| {
            let target = NodeId(edge.target.0);
            if activate_summary_transition(unified, summary_callees, state.node, target, worklist) {
                if let (Some(cross_call), Some(cross_calls)) = (edge.cross_call, cross_calls.as_deref_mut()) {
                    cross_calls.insert(cross_call);
                }
                Self::enqueue_symbolic_node_source(unified, runtime, target, 0, worklist);
            }
        });
        contextual.calls_by_from.visit(state.node, |call| {
            if !worklist.node_is_relevant(call.target)
                || !activate_summary_call(summary_callees, call.key, worklist)
            {
                return;
            }
            let context = Self::register_context_call(unified, runtime, state.context, call.key, worklist);
            if let (Some(cross_call), Some(cross_calls)) = (call.cross_call, cross_calls.as_deref_mut()) {
                cross_calls.insert(cross_call);
            }
            Self::enqueue_symbolic_node_source(unified, runtime, call.target, context, worklist);
        });
        contextual.returns_by_from.visit(state.node, |returned| {
            if !symbolic_node_allowed(unified, worklist, returned.target) {
                return;
            }
            if worklist.contexts.matches(state.context, returned.key) {
                if let (Some(cross_call), Some(cross_calls)) =
                    (returned.cross_call, cross_calls.as_deref_mut())
                {
                    cross_calls.insert(cross_call);
                }
                let caller_contexts = worklist
                    .contexts
                    .complete_node_return(state.context, returned.target);
                for context in caller_contexts {
                    Self::enqueue_symbolic_node_source(unified, runtime, returned.target, context, worklist);
                }
            } else if activate_seed_callers && state.context == 0 {
                if let (Some(cross_call), Some(cross_calls)) =
                    (returned.cross_call, cross_calls.as_deref_mut())
                {
                    cross_calls.insert(cross_call);
                }
                Self::enqueue_symbolic_node_source(unified, runtime, returned.target, 0, worklist);
            }
        });
    }

    /// Reach one scalar compiler node and, when this reach came from an
    /// ordinary value-flow relation, introduce the node's projected storage
    /// facts exactly once for this realizable call context.
    ///
    /// Symbolic fact consumers deliberately call `enqueue_node` directly:
    /// the consumed fact already carries the precise write provenance.
    fn enqueue_symbolic_node_source(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        node: NodeId,
        context: u32,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) {
        if !symbolic_node_allowed(unified, worklist, node) {
            return;
        }
        worklist.enqueue_node(node, context);
        if !worklist.activate_fact_source(node, context) {
            return;
        }
        for mut fact in Self::symbolic_facts_for_node(unified, runtime, node) {
            fact.context = context;
            worklist.enqueue_fact_state(fact);
        }
    }

    /// Derive access-path facts from the canonical segment place when a node
    /// is actually reached. Retaining one expanded fact row for every
    /// projected node duplicated a dominant workspace relation and made broad
    /// export memory proportional to `nodes x access-path-depth`. The segment
    /// place is already the Tree-sitter-derived compiler IR, so demand
    /// derivation preserves the exact same facts while keeping only the small
    /// consumer indexes resident.
    fn build_symbolic_fact_page(
        segment_id: SegmentId,
        segment: &crate::segment::IdgSegment,
        runtime: &SymbolicRuntimeIndex,
        symbolic: &crate::symbolic::SymbolicFieldGraph,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> SymbolicFactPage {
        let mut offsets = Vec::with_capacity(segment.nodes.nodes.len().saturating_add(1));
        let mut facts = Vec::new();
        offsets.push(0);
        for node in &segment.nodes.nodes {
            if allowed_funcs.is_some_and(|allowed| !allowed.contains(&node.func)) {
                offsets.push(u32::try_from(facts.len()).expect("symbolic fact page exceeds u32"));
                continue;
            }
            if let Some(place) = segment.places.get(node.place) {
                if let Some((parts, write_span, _)) = structured_storage_parts(segment, place) {
                    for split in 1..parts.len() {
                        let base_text = parts[..split].join(".");
                        let field_text = parts[split..].join(".");
                        if let (Some(base), Some(field)) = (
                            symbolic.base_id(segment_id, node.func, &base_text),
                            runtime.field_id(&field_text),
                        ) {
                            facts.push(SymbolicFactTemplate {
                                base,
                                field,
                                span: write_span
                                    .and_then(|span| runtime.local_provenance_id(base, span))
                                    .unwrap_or(NO_SYMBOLIC_FACT_SPAN),
                            });
                        }
                    }
                }
            }
            offsets.push(u32::try_from(facts.len()).expect("symbolic fact page exceeds u32"));
        }
        SymbolicFactPage {
            offsets: offsets.into_boxed_slice(),
            facts: facts.into_boxed_slice(),
        }
    }

    fn symbolic_facts_for_node(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        node: NodeId,
    ) -> smallvec::SmallVec<[SymbolicNodeFact; 2]> {
        let mut facts = smallvec::SmallVec::new();
        let Some((segment_id, local_node)) = Self::ws_address(unified, WsNodeId(node.0)) else {
            return facts;
        };
        let Some(page) = runtime.fact_pages.lock().page(segment_id) else {
            return facts;
        };
        for template in page.get(local_node) {
            facts.push(SymbolicNodeFact::new(
                template.base,
                template.field,
                (template.span != NO_SYMBOLIC_FACT_SPAN).then_some(template.span),
                false,
                0,
            ));
        }
        facts
    }

    fn replay_context_outputs(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        caller_context: u32,
        returned_nodes: Vec<NodeId>,
        returned_facts: Vec<SymbolicFactIdentity>,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) {
        for node in returned_nodes {
            Self::enqueue_symbolic_node_source(unified, runtime, node, caller_context, worklist);
        }
        for identity in returned_facts {
            worklist.enqueue_fact_state(SymbolicNodeFact::from_identity(identity, caller_context));
        }
    }

    fn register_context_call(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        caller_context: u32,
        boundary: ContextBoundaryKey,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) -> u32 {
        let (context, newly_registered) = worklist.contexts.register_call(caller_context, boundary);
        if !newly_registered {
            return context;
        }
        let mut after = None;
        loop {
            let returned_nodes = worklist.contexts.returned_node_batch(context, after);
            let Some(last) = returned_nodes.last().copied() else {
                break;
            };
            after = Some((u128::from(context) << 96) | u128::from(last.0));
            Self::replay_context_outputs(
                unified,
                runtime,
                caller_context,
                returned_nodes,
                Vec::new(),
                worklist,
            );
        }

        let mut after = None;
        loop {
            let returned_facts = worklist.contexts.returned_fact_batch(context, after);
            let Some(last) = returned_facts.last().copied() else {
                break;
            };
            after = Some(last.key() | (u128::from(context) << 96));
            Self::replay_context_outputs(
                unified,
                runtime,
                caller_context,
                Vec::new(),
                returned_facts,
                worklist,
            );
        }
        context
    }

    #[allow(clippy::too_many_arguments)]
    fn propagate_symbolic_closure_fact(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        symbolic: &crate::symbolic::SymbolicFieldGraph,
        max_precision: Option<Precision>,
        summary_callees: Option<&AHashMap<FuncId, Vec<FuncId>>>,
        contextual: bool,
        activate_seed_callers: bool,
        fact: SymbolicNodeFact,
        mut symbolic_cross_calls: Option<&mut AHashSet<CrossCallEdge>>,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) {
        for &rebase in runtime.base_rebases.outgoing(fact.base) {
            let Some(field) = runtime.rebased_field(rebase, fact.field) else {
                continue;
            };
            let mut equivalent = fact;
            equivalent.base = rebase.target;
            equivalent.field = field;
            worklist.enqueue_fact_state(equivalent);
        }
        Self::seed_symbolic_fact_consumers(unified, runtime, fact, worklist);
        let transforms = runtime.transforms.lock().outgoing(fact.base);
        for transform in transforms.iter().copied() {
            debug_assert!(
                transform.allow_out_of_order_source || runtime.retains_local_provenance(transform.source)
            );
            if max_precision.is_some_and(|max| transform.precision > max)
                || (!transform.allow_out_of_order_source
                    && !fact.is_interprocedural()
                    && fact
                        .span_id()
                        .and_then(|span| runtime.span(span))
                        .is_some_and(|span| {
                            span.file == transform.call_span.file && span.start > transform.call_span.start
                        }))
            {
                continue;
            }
            if transform.kind != SymbolicFieldTransformKind::ScalarReturn
                && !worklist.fact_is_relevant(transform.target, fact.field)
            {
                continue;
            }
            let Some(contexts) = Self::symbolic_transform_contexts(
                unified,
                runtime,
                symbolic,
                &transform,
                fact,
                summary_callees,
                contextual,
                activate_seed_callers,
                worklist,
            ) else {
                continue;
            };
            if transform.kind == SymbolicFieldTransformKind::ScalarReturn {
                Self::propagate_scalar_symbolic_return(
                    unified,
                    runtime,
                    symbolic,
                    &transform,
                    fact,
                    &contexts,
                    symbolic_cross_calls.as_deref_mut(),
                    worklist,
                );
                continue;
            }
            if symbolic
                .bases()
                .get(transform.target as usize)
                .is_none_or(|base| !worklist.summary_func_is_active(base.func))
            {
                continue;
            }
            record_symbolic_cross_call(symbolic, &transform, symbolic_cross_calls.as_deref_mut());
            let interprocedural = transform.kind != SymbolicFieldTransformKind::Copy;
            let span = (!interprocedural)
                .then(|| runtime.local_provenance_id(transform.target, transform.write_span))
                .flatten();
            debug_assert!(
                interprocedural || !runtime.retains_local_provenance(transform.target) || span.is_some()
            );
            let next = SymbolicNodeFact::new(transform.target, fact.field, span, interprocedural, 0);
            if let Some(context) = contexts.completed {
                let identity = next.identity();
                let caller_contexts = worklist.contexts.complete_fact_return(context, identity);
                for caller_context in caller_contexts {
                    worklist.enqueue_fact_state(SymbolicNodeFact::from_identity(identity, caller_context));
                }
            } else {
                for &context in &contexts.next {
                    let mut next = next;
                    next.context = context;
                    worklist.enqueue_fact_state(next);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn symbolic_transform_contexts(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        symbolic: &crate::symbolic::SymbolicFieldGraph,
        transform: &crate::symbolic::SymbolicFieldTransform,
        fact: SymbolicNodeFact,
        summary_callees: Option<&AHashMap<FuncId, Vec<FuncId>>>,
        contextual: bool,
        activate_seed_callers: bool,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) -> Option<SymbolicTransformContexts> {
        if !contextual {
            return Some(SymbolicTransformContexts {
                next: vec![fact.context],
                completed: None,
            });
        }
        let Some((boundary, enters)) = symbolic_transform_boundary(symbolic, transform) else {
            return Some(SymbolicTransformContexts {
                next: vec![fact.context],
                completed: None,
            });
        };
        if enters {
            if !activate_summary_call(summary_callees, boundary, worklist) {
                return None;
            }
            let context = Self::register_context_call(unified, runtime, fact.context, boundary, worklist);
            Some(SymbolicTransformContexts {
                next: vec![context],
                completed: None,
            })
        } else if worklist.contexts.matches(fact.context, boundary) {
            Some(SymbolicTransformContexts {
                next: Vec::new(),
                completed: Some(fact.context),
            })
        } else if activate_seed_callers && fact.context == 0 {
            Some(SymbolicTransformContexts {
                next: vec![0],
                completed: None,
            })
        } else {
            None
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn propagate_scalar_symbolic_return(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        symbolic: &crate::symbolic::SymbolicFieldGraph,
        transform: &crate::symbolic::SymbolicFieldTransform,
        fact: SymbolicNodeFact,
        contexts: &SymbolicTransformContexts,
        symbolic_cross_calls: Option<&mut AHashSet<CrossCallEdge>>,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) {
        let exact_matches = transform.exact_field != NO_SYMBOLIC_STRING
            && symbolic
                .string(transform.exact_field)
                .zip(runtime.field(fact.field))
                .is_some_and(|(expected, actual)| expected == actual);
        if !exact_matches {
            return;
        }
        let Some(nodes) = runtime
            .scalar_writes
            .get(&(transform.target, transform.write_span))
        else {
            return;
        };
        if !nodes.is_empty() {
            record_symbolic_cross_call(symbolic, transform, symbolic_cross_calls);
        }
        for node in nodes {
            let node = NodeId(node.0);
            if !symbolic_node_allowed(unified, worklist, node) {
                continue;
            }
            if let Some(context) = contexts.completed {
                let caller_contexts = worklist.contexts.complete_node_return(context, node);
                for caller_context in caller_contexts {
                    Self::enqueue_symbolic_node_source(unified, runtime, node, caller_context, worklist);
                }
            } else {
                for &context in &contexts.next {
                    Self::enqueue_symbolic_node_source(unified, runtime, node, context, worklist);
                }
            }
        }
    }

    fn seed_symbolic_fact_consumers(
        unified: &UnifiedAddressSpace,
        runtime: &SymbolicRuntimeIndex,
        fact: SymbolicNodeFact,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) {
        let exact_nodes = runtime.exact_reads.get(&symbolic_fact_key(fact.base, fact.field));
        if let Some(nodes) = exact_nodes {
            for node in nodes {
                let node = NodeId(node.0);
                if symbolic_node_allowed(unified, worklist, node) {
                    worklist.enqueue_node(node, fact.context);
                }
            }
        }
        if let Some(nodes) = runtime.aggregate_reads.get(&fact.base) {
            for node in nodes {
                let node = NodeId(node.0);
                if symbolic_node_allowed(unified, worklist, node) {
                    worklist.enqueue_node(node, fact.context);
                }
            }
        }
    }

    fn build_symbolic_runtime_index(
        &self,
        unified: &UnifiedAddressSpace,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> SymbolicRuntimeIndex {
        self.build_symbolic_runtime_index_with_layout(&unified.segment_bases, Some(unified), allowed_funcs)
    }

    fn build_symbolic_runtime_index_with_layout(
        &self,
        segment_bases: &[u32],
        unified: Option<&UnifiedAddressSpace>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> SymbolicRuntimeIndex {
        debug_assert!(allowed_funcs.is_none() || unified.is_some());
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "symbolic runtime start rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        let symbolic = self.workspace.symbolic_field();
        let mut segments: Vec<SegmentId> = if let Some(allowed) = allowed_funcs {
            allowed
                .iter()
                .filter_map(|func| self.workspace.segment_for_func(*func))
                .collect()
        } else {
            (0..self.workspace.segment_count())
                .map(|segment| SegmentId(u32::try_from(segment).expect("IDG segment count exceeds u32")))
                .collect()
        };
        segments.sort_unstable_by_key(|segment| segment.0);
        segments.dedup();
        let mut field_names = AHashSet::default();
        let mut fact_spans = AHashSet::default();
        let mut bare_read_rows = Vec::new();
        let mut scalar_write_rows = Vec::new();
        // One compiler-object pass collects the dictionaries and compact
        // consumer rows. Older code reopened every body once for each index.
        for &segment_id in &segments {
            let Some(segment) = self.workspace.segment_view(segment_id) else {
                continue;
            };
            for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
                if allowed_funcs.is_some_and(|allowed| !allowed.contains(&node.func)) {
                    continue;
                }
                let Some(place) = segment.places.get(node.place) else {
                    continue;
                };
                let Some((parts, write_span, is_read)) = structured_storage_parts(&segment, place) else {
                    continue;
                };
                for split in 1..parts.len() {
                    field_names.insert(parts[split..].join("."));
                }
                if let Some(span) = write_span {
                    fact_spans.insert(SymbolicFactSpan::from(span));
                }
                let local = NodeId(u32::try_from(node_index).expect("segment-local node count exceeds u32"));
                let Some(ws_node) = Self::ws_node_for_segment_bases(segment_bases, segment_id, local) else {
                    continue;
                };
                let full = parts.join(".");
                let Some(base) = symbolic.base_id(segment_id, node.func, &full) else {
                    continue;
                };
                if is_read {
                    bare_read_rows.push((base, ws_node));
                }
                if let Some(span) = write_span {
                    scalar_write_rows.push(((base, span), ws_node));
                }
            }
        }
        let rebase_specs = SymbolicBaseRebaseIndex::specs(symbolic);
        field_names.extend(rebase_specs.iter().map(|(_, _, prefix, _)| prefix.clone()));
        let mut fields: Vec<String> = field_names.into_iter().collect();
        fields.sort_unstable();
        let (transforms, reverse_transforms, reverse_scalar_transforms, ordering_sensitive_bases) =
            SymbolicTransformPager::build(
                &self.workspace,
                symbolic.bases().len(),
                &mut fact_spans,
                allowed_funcs,
            );
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "symbolic dictionaries ready bare_reads={} scalar_writes={} rss_mib={}",
            bare_read_rows.len(),
            scalar_write_rows.len(),
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024)),
        );
        let mut spans: Vec<SymbolicFactSpan> = fact_spans.into_iter().collect();
        spans.sort_unstable();
        assert!(
            spans.len() < SYMBOLIC_FACT_SPAN_MASK as usize,
            "symbolic fact span count exceeds compact representation"
        );
        let mut out = SymbolicRuntimeIndex {
            fields: PackedStringTable::from_sorted(fields),
            spans: spans.into_boxed_slice(),
            ordering_sensitive_bases,
            ..SymbolicRuntimeIndex::default()
        };
        out.base_rebases = SymbolicBaseRebaseIndex::from_specs(rebase_specs, &out.fields);
        out.transforms = Mutex::new(transforms);
        out.reverse_transforms = reverse_transforms;
        out.reverse_scalar_transforms = reverse_scalar_transforms;

        // Both source vectors were populated in monotonically increasing
        // workspace-node order by the segment scan above. Persist their
        // inverse identities before the forward indexes reorder rows by
        // storage key. This is representation-only compiler metadata: it
        // admits exactly the same AST-lowered reads and writes.
        out.storage_reads =
            NodeStorageReadIndex::from_sorted_rows(bare_read_rows.iter().map(|(base, node)| (*node, *base)));
        out.storage_writes =
            NodeStorageWriteIndex::from_sorted_rows(scalar_write_rows.iter().map(|((base, span), node)| {
                (
                    *node,
                    *base,
                    out.span_id(*span)
                        .expect("scalar write span belongs to symbolic span dictionary"),
                )
            }));

        out.scalar_writes = GroupedNodeIndex::from_rows(scalar_write_rows);
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "symbolic scalar indexes ready rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );

        // Compile each admitted source segment's AST-derived access-path facts
        // once into a fixed-width temporary sidecar. Broad closures admit all
        // segments; targeted closures decode only their exact compiler scope.
        let mut fact_pages = SymbolicFactPager::new(self.workspace.segment_count());
        let mut exact_read_rows = Vec::new();
        let mut fact_sources = FactSourceSpool::new();
        let mut aggregate_input_rows = Vec::new();
        let mut aggregate_output_rows = Vec::new();
        let mut aggregate_read_rows = Vec::new();
        let mut resolved_call_args = AHashSet::default();
        let mut projected_fact_keys = Vec::new();
        let resolved_symbolic_args: AHashSet<(SegmentId, FuncId, Span, u32)> = symbolic
            .transforms()
            .iter()
            .filter(|transform| transform.kind == SymbolicFieldTransformKind::Argument)
            .filter_map(|transform| {
                let source = symbolic.bases().get(transform.source as usize)?;
                Some((
                    source.segment,
                    source.func,
                    transform.call_span,
                    transform.arg_idx,
                ))
            })
            .collect();
        for &segment_id in &segments {
            let Some(segment) = self.workspace.segment_view(segment_id) else {
                continue;
            };
            let page = Self::build_symbolic_fact_page(segment_id, &segment, &out, symbolic, allowed_funcs);
            for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
                if allowed_funcs.is_some_and(|allowed| !allowed.contains(&node.func)) {
                    continue;
                }
                let local = NodeId(u32::try_from(node_index).expect("segment-local node count exceeds u32"));
                let Some(ws_node) = Self::ws_node_for_segment_bases(segment_bases, segment_id, local) else {
                    continue;
                };
                if let Some(Place::CallArg { site, idx }) = segment.places.get(node.place) {
                    if resolved_symbolic_args.contains(&(segment_id, node.func, site.0, *idx)) {
                        resolved_call_args.insert(ws_node);
                    }
                }
                for fact in page.get(local) {
                    let key = symbolic_fact_key(fact.base, fact.field);
                    projected_fact_keys.push(key);
                    fact_sources.push(key, ws_node.0);
                    if matches!(segment.places.get(node.place), Some(Place::Read { .. })) {
                        exact_read_rows.push((key, ws_node));
                    }
                }
            }
            for edge in &segment.edges {
                if edge.meta.kind == IdgEdgeKind::InterCallArg {
                    if let Some(from) = Self::ws_node_for_segment_bases(segment_bases, segment_id, edge.from)
                    {
                        if allowed_funcs.is_none_or(|allowed| {
                            Self::ws_node_func(
                                unified.expect("scoped symbolic build has unified node ownership"),
                                NodeId(from.0),
                            )
                            .is_some_and(|func| allowed.contains(&func))
                        }) {
                            resolved_call_args.insert(from);
                        }
                    }
                    continue;
                }
                if edge.meta.kind != IdgEdgeKind::IntraAggregateConsume {
                    continue;
                }
                let Some(from) = Self::ws_node_for_segment_bases(segment_bases, segment_id, edge.from) else {
                    continue;
                };
                let Some(to) = Self::ws_node_for_segment_bases(segment_bases, segment_id, edge.to) else {
                    continue;
                };
                if let Some(base) = out.storage_reads.base(from) {
                    aggregate_read_rows.push((base, to));
                }
                if allowed_funcs.is_some_and(|allowed| {
                    let unified = unified.expect("scoped symbolic build has unified node ownership");
                    !Self::ws_node_func(unified, NodeId(from.0)).is_some_and(|func| allowed.contains(&func))
                        || !Self::ws_node_func(unified, NodeId(to.0))
                            .is_some_and(|func| allowed.contains(&func))
                }) {
                    continue;
                }
                aggregate_input_rows.push((NodeId(to.0), from));
                aggregate_output_rows.push((NodeId(from.0), to));
            }
            fact_pages.write_page(segment_id, &page);
        }
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "symbolic fact pages ready exact_reads={} aggregate_inputs={} resolved_call_args={} rss_mib={}",
            exact_read_rows.len(),
            aggregate_input_rows.len(),
            resolved_call_args.len(),
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024)),
        );
        let segment_set: AHashSet<SegmentId> = segments.iter().copied().collect();
        self.workspace
            .visit_cross_file_edges(|edges| {
                for edge in edges {
                    if edge.edge.meta.kind != IdgEdgeKind::InterCallArg
                        || !segment_set.contains(&edge.from_segment)
                    {
                        continue;
                    }
                    let Some(from) =
                        Self::ws_node_for_segment_bases(segment_bases, edge.from_segment, edge.edge.from)
                    else {
                        continue;
                    };
                    if allowed_funcs.is_none_or(|allowed| {
                        Self::ws_node_func(
                            unified.expect("scoped symbolic build has unified node ownership"),
                            NodeId(from.0),
                        )
                        .is_some_and(|func| allowed.contains(&func))
                    }) {
                        resolved_call_args.insert(from);
                    }
                }
            })
            .expect("validated IDG cross-file relation remains readable");
        out.fact_pages = Mutex::new(fact_pages);
        out.exact_reads = GroupedNodeIndex::from_rows(exact_read_rows);
        out.fact_sources = fact_sources.finish();
        out.aggregate_reads = GroupedNodeIndex::from_rows(
            aggregate_read_rows
                .into_iter()
                .filter(|(_, node)| !resolved_call_args.contains(node))
                .collect(),
        );
        out.aggregate_inputs = GroupedNodeIndex::from_rows(aggregate_input_rows);
        out.aggregate_outputs = GroupedNodeIndex::from_rows(aggregate_output_rows);
        projected_fact_keys.sort_unstable();
        projected_fact_keys.dedup();
        out.projected_fact_keys = projected_fact_keys.into_boxed_slice();
        let mut resolved_call_args: Vec<_> = resolved_call_args.into_iter().collect();
        resolved_call_args.sort_unstable_by_key(|node| node.0);
        out.resolved_call_args = resolved_call_args.into_boxed_slice();
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "symbolic runtime finished rss_mib={}",
            current_process_resident_bytes().map_or(0, |bytes| bytes / (1024 * 1024))
        );
        out
    }

    fn ensure_unfiltered_reach(&self, unified: &Arc<UnifiedAddressSpace>) -> Arc<ReachabilityIndex> {
        {
            let read = unified.unfiltered_reach.read();
            if let Some(reach) = read.as_ref() {
                return Arc::clone(reach);
            }
        }
        let mut write = unified.unfiltered_reach.write();
        if let Some(reach) = write.as_ref() {
            return Arc::clone(reach);
        }
        let reach = Arc::new(self.build_reach(unified, None));
        *write = Some(Arc::clone(&reach));
        reach
    }

    fn ensure_precision_reach(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        max_precision: Precision,
    ) -> Arc<ReachabilityIndex> {
        {
            let read = unified.precision_reach.read();
            if let Some(reach) = read.get(&max_precision) {
                return Arc::clone(reach);
            }
        }
        let mut write = unified.precision_reach.write();
        if let Some(reach) = write.get(&max_precision) {
            return Arc::clone(reach);
        }
        let reach = Arc::new(self.build_reach(unified, Some(max_precision)));
        write.insert(max_precision, Arc::clone(&reach));
        reach
    }

    fn ensure_symbolic_runtime(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> Arc<SymbolicRuntimeIndex> {
        // If another exact query has already compiled the global symbolic
        // representation, reuse it and let the closure's `allowed_funcs`
        // predicate filter transitions. Rebuilding a second scoped copy beside
        // an existing immutable relation only increases residency; the choice
        // is based on representation availability, never on a semantic work
        // or result threshold.
        if allowed_funcs.is_some()
            && (unified.symbolic_runtime.get().is_some() || self.persisted_query_accelerator.is_some())
        {
            return self.ensure_symbolic_runtime(unified, None);
        }
        let Some(allowed_funcs) = allowed_funcs else {
            return Arc::clone(unified.symbolic_runtime.get_or_init(|| {
                let runtime = self
                    .load_persisted_symbolic_runtime(unified)
                    .unwrap_or_else(|error| {
                        bonsai_diagnostics::debug_log!(
                            "idg-query",
                            "persisted symbolic accelerator unavailable; rebuilding exact runtime: {error}"
                        );
                        self.build_symbolic_runtime_index(unified, None)
                    });
                Arc::new(runtime)
            }));
        };
        let mut funcs: Vec<FuncId> = allowed_funcs.iter().copied().collect();
        funcs.sort_unstable_by_key(|func| func.raw());
        funcs.dedup();
        let mut scoped = self.scoped_symbolic_runtime.lock();
        if let Some(cache) = scoped.as_ref() {
            if cache.funcs.as_ref() == funcs.as_slice() {
                return Arc::clone(&cache.runtime);
            }
        }
        let runtime = Arc::new(self.build_symbolic_runtime_index(unified, Some(allowed_funcs)));
        *scoped = Some(ScopedSymbolicRuntimeCache {
            funcs: funcs.into_boxed_slice(),
            runtime: Arc::clone(&runtime),
        });
        runtime
    }

    /// Compile the least backward fixed point of field identities demanded by
    /// real projected syntax in this runtime's exact function scope.
    ///
    /// This is a semantic relation, not a budget: every inverse transform and
    /// access-path rebase is followed until convergence.  The spill-backed
    /// set starts empty and promotes storage only with actual relation density.
    fn ensure_symbolic_field_demand(
        runtime: &Arc<SymbolicRuntimeIndex>,
        max_precision: Option<Precision>,
    ) -> Arc<SymbolicFieldDemand> {
        if let Some(demand) = runtime.field_demands.lock().get(&max_precision).cloned() {
            return demand;
        }

        // A whole value passed to an unresolved/external consumer demands
        // every concrete suffix that can reach that compiler base. Keep this
        // as a sparse wildcard relation instead of materializing
        // `bases × fields`; inverse transforms propagate it exactly.
        let mut wildcard_bases = closure_fact_store();
        let mut pending_wildcards = pending_fact_store();
        for &base in runtime.aggregate_reads.keys.iter() {
            let base = u128::from(base);
            if wildcard_bases.insert(base) {
                pending_wildcards.push(base);
            }
        }
        while let Some(base) = pending_wildcards.pop() {
            let base = base as u32;
            let mut enqueue = |base: u32| {
                let base = u128::from(base);
                if wildcard_bases.insert(base) {
                    pending_wildcards.push(base);
                }
            };
            for &rebase in runtime.base_rebases.outgoing(base) {
                enqueue(rebase.target);
            }
            runtime.reverse_transforms.visit_incoming(base, |row| {
                if max_precision.is_none_or(|max| row.precision <= max) {
                    enqueue(row.source);
                }
            });
        }

        let mut facts = closure_fact_store();
        let mut pending = pending_fact_store();
        for &key in &runtime.projected_fact_keys {
            let key = u128::from(key);
            if facts.insert(key) {
                pending.push(key);
            }
        }
        while let Some(key) = pending.pop() {
            let key = key as u64;
            let base = (key >> 32) as u32;
            let field = key as u32;
            let mut enqueue = |base: u32, field: u32| {
                let key = u128::from(symbolic_fact_key(base, field));
                if facts.insert(key) {
                    pending.push(key);
                }
            };
            for &rebase in runtime.base_rebases.outgoing(base) {
                if let Some(rebased_field) = runtime.rebased_field(rebase, field) {
                    enqueue(rebase.target, rebased_field);
                }
            }
            runtime.reverse_transforms.visit_incoming(base, |row| {
                if max_precision.is_none_or(|max| row.precision <= max) {
                    enqueue(row.source, field);
                }
            });
        }
        let demand = Arc::new(SymbolicFieldDemand {
            facts,
            wildcard_bases,
        });
        bonsai_diagnostics::debug_log!(
            "idg-query",
            "symbolic field demand ready syntax_facts={} demanded_facts={} wildcard_bases={} precision={:?}",
            runtime.projected_fact_keys.len(),
            demand.facts.len(),
            demand.wildcard_bases.len(),
            max_precision
        );
        let mut cache = runtime.field_demands.lock();
        Arc::clone(cache.entry(max_precision).or_insert_with(|| Arc::clone(&demand)))
    }

    fn load_persisted_symbolic_runtime(
        &self,
        unified: &UnifiedAddressSpace,
    ) -> crate::IdgResult<SymbolicRuntimeIndex> {
        let parts = self
            .persisted_query_accelerator
            .as_ref()
            .ok_or_else(|| invalid_query_accelerator("workspace has no persisted symbolic accelerator"))?;
        let blobs = parts
            .blobs
            .iter()
            .filter(|(kind, _)| {
                matches!(
                    kind,
                    QueryAcceleratorBlobKind::SymbolicFacts
                        | QueryAcceleratorBlobKind::SymbolicTransforms
                        | QueryAcceleratorBlobKind::FactSources
                        | QueryAcceleratorBlobKind::ReverseSymbolicTransforms
                        | QueryAcceleratorBlobKind::ReverseScalarTransforms
                )
            })
            .map(|(kind, blob)| (*kind, blob.clone()))
            .collect();
        PersistedSymbolicRuntime::decode(
            parts.symbolic_header.stream(),
            blobs,
            &self.workspace,
            Self::unified_node_count(unified),
        )
    }

    /// Reuse an already-compiled exact symbolic corridor when it contains
    /// every requested owner. Tainted-call projection is a read-only view of
    /// those facts and does not require compiling a narrower duplicate. If no
    /// covering corridor exists, the canonical global runtime remains the
    /// exact fallback for unscoped callers.
    fn symbolic_runtime_for_tainted_calls(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        target_funcs: Option<&AHashSet<FuncId>>,
    ) -> Arc<SymbolicRuntimeIndex> {
        if let Some(target_funcs) = target_funcs {
            let scoped = self.scoped_symbolic_runtime.lock();
            if let Some(cache) = scoped.as_ref() {
                let covers_targets = target_funcs.iter().all(|target| {
                    cache
                        .funcs
                        .binary_search_by_key(&target.raw(), |func| func.raw())
                        .is_ok()
                });
                if covers_targets {
                    return Arc::clone(&cache.runtime);
                }
            }
        }
        self.ensure_symbolic_runtime(unified, None)
    }

    fn ensure_contextual_summary_runtime(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        max_precision: Option<Precision>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> Arc<ContextualSummaryRuntime> {
        // Reuse a global runtime only if this process has already opened it.
        // A persisted prewarm is independently decodable storage, not a reason
        // for a narrow query to make the whole workspace resident.
        if allowed_funcs.is_some() {
            let read = unified.contextual_summaries.read();
            if let Some(runtime) = read.get(&max_precision) {
                return Arc::clone(runtime);
            }
        }
        if allowed_funcs.is_some()
            && max_precision == Some(SEMANTIC_MAX_PRECISION)
            && self.persisted_query_accelerator.is_some()
        {
            return self.ensure_contextual_summary_runtime(unified, max_precision, None);
        }
        if let Some(allowed_funcs) = allowed_funcs {
            let mut funcs: Vec<FuncId> = allowed_funcs.iter().copied().collect();
            funcs.sort_unstable_by_key(|func| func.raw());
            funcs.dedup();
            let mut scoped = self.scoped_contextual_summary.lock();
            if let Some(cache) = scoped.as_ref() {
                if cache.max_precision == max_precision && cache.funcs.as_ref() == funcs.as_slice() {
                    return Arc::clone(&cache.runtime);
                }
            }
            let batch = Arc::new(crate::function_summary::return_taint_param_indices_in_scope(
                &self.workspace,
                &funcs,
                Some(allowed_funcs),
                max_precision,
            ));
            let runtime = Arc::new(self.build_contextual_summary_runtime(
                &batch.contextual_edges,
                max_precision,
                Some(allowed_funcs),
            ));
            *scoped = Some(ScopedContextualSummaryCache {
                max_precision,
                funcs: funcs.into_boxed_slice(),
                runtime: Arc::clone(&runtime),
                batch,
            });
            return runtime;
        }
        {
            let read = unified.contextual_summaries.read();
            if let Some(runtime) = read.get(&max_precision) {
                return Arc::clone(runtime);
            }
        }
        let mut write = unified.contextual_summaries.write();
        if let Some(runtime) = write.get(&max_precision) {
            return Arc::clone(runtime);
        }
        // An empty requested-function set still compiles every function's
        // local graph and recursive call summaries, but skips materializing
        // any parameter-result rows. This is the canonical compiler graph for
        // arbitrary forward closures.
        let runtime = Arc::new(
            self.load_persisted_contextual_runtime(unified, max_precision)
                .unwrap_or_else(|error| {
                    bonsai_diagnostics::debug_log!(
                        "idg-query",
                        "persisted contextual accelerator unavailable; rebuilding exact runtime: {error}"
                    );
                    let summary_edges = crate::function_summary::return_taint_param_indices(
                        &self.workspace,
                        &[],
                        max_precision,
                    )
                    .contextual_edges;
                    self.build_contextual_summary_runtime(&summary_edges, max_precision, None)
                }),
        );
        write.insert(max_precision, Arc::clone(&runtime));
        runtime
    }

    fn load_persisted_contextual_runtime(
        &self,
        unified: &UnifiedAddressSpace,
        max_precision: Option<Precision>,
    ) -> crate::IdgResult<ContextualSummaryRuntime> {
        if max_precision != Some(SEMANTIC_MAX_PRECISION) {
            return Err(invalid_query_accelerator(
                "persisted contextual precision does not match the requested query",
            ));
        }
        let parts = self
            .persisted_query_accelerator
            .as_ref()
            .ok_or_else(|| invalid_query_accelerator("workspace has no persisted contextual accelerator"))?;
        let blobs = parts
            .blobs
            .iter()
            .filter(|(kind, _)| {
                matches!(
                    kind,
                    QueryAcceleratorBlobKind::ContextualForwardTargets
                        | QueryAcceleratorBlobKind::ContextualBackwardTargets
                        | QueryAcceleratorBlobKind::ContextualHeapEdges
                        | QueryAcceleratorBlobKind::ContextualCallEdges
                        | QueryAcceleratorBlobKind::ContextualReturnEdges
                        | QueryAcceleratorBlobKind::ContextualReverseHeapNodes
                        | QueryAcceleratorBlobKind::ContextualReverseCallNodes
                        | QueryAcceleratorBlobKind::ContextualReverseReturnNodes
                )
            })
            .map(|(kind, blob)| (*kind, blob.clone()))
            .collect();
        load_contextual_query_accelerator(
            parts.contextual.stream(),
            blobs,
            Self::unified_node_count(unified),
            &unified.func_segments,
        )
    }

    fn build_reach(
        &self,
        unified: &UnifiedAddressSpace,
        max_precision: Option<Precision>,
    ) -> ReachabilityIndex {
        ReachabilityIndex::from_pair_visitor(Self::unified_node_count(unified), |visit| {
            for (seg_id, segment) in self.workspace.segment_views() {
                for edge in &segment.edges {
                    if max_precision.is_some_and(|max| edge.meta.precision > max)
                        || edge.meta.kind == IdgEdgeKind::IntraAggregateConsume
                    {
                        continue;
                    }
                    let Some(from) = Self::ws_node_for(unified, seg_id, edge.from) else {
                        continue;
                    };
                    let Some(to) = Self::ws_node_for(unified, seg_id, edge.to) else {
                        continue;
                    };
                    visit(from.0, to.0);
                }
            }
            self.workspace
                .visit_cross_file_edges(|edges| {
                    for cfe in edges {
                        if max_precision.is_some_and(|max| cfe.edge.meta.precision > max) {
                            continue;
                        }
                        let Some(from) = Self::ws_node_for(unified, cfe.from_segment, cfe.edge.from) else {
                            continue;
                        };
                        let Some(to) = Self::ws_node_for(unified, cfe.to_segment, cfe.edge.to) else {
                            continue;
                        };
                        visit(from.0, to.0);
                    }
                })
                .expect("validated IDG cross-file relation remains readable");
        })
    }

    fn ensure_cross_calls_by_from(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
    ) -> Arc<AHashMap<WsNodeId, Vec<CrossCallEdge>>> {
        {
            let read = unified.cross_calls_by_from.read();
            if let Some(rows) = read.as_ref() {
                return Arc::clone(rows);
            }
        }
        let mut write = unified.cross_calls_by_from.write();
        if let Some(rows) = write.as_ref() {
            return Arc::clone(rows);
        }
        let rows = Arc::new(self.build_cross_calls_by_from(unified, None));
        *write = Some(Arc::clone(&rows));
        rows
    }

    fn ensure_scoped_cross_calls_by_from(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        allowed_funcs: &AHashSet<FuncId>,
    ) -> Arc<CrossCallsByFrom> {
        let mut funcs: Vec<FuncId> = allowed_funcs.iter().copied().collect();
        funcs.sort_unstable_by_key(|func| func.raw());
        funcs.dedup();
        let mut scoped = self.scoped_cross_calls.lock();
        if let Some(cache) = scoped.as_ref() {
            if cache.funcs.as_ref() == funcs.as_slice() {
                return Arc::clone(&cache.rows);
            }
        }
        let rows = Arc::new(self.build_cross_calls_by_from(unified, Some(allowed_funcs)));
        *scoped = Some(ScopedCrossCallsCache {
            funcs: funcs.into_boxed_slice(),
            rows: Arc::clone(&rows),
        });
        rows
    }

    fn build_cross_calls_by_from(
        &self,
        unified: &UnifiedAddressSpace,
        allowed_funcs: Option<&AHashSet<FuncId>>,
    ) -> AHashMap<WsNodeId, Vec<CrossCallEdge>> {
        let mut cross_calls_by_from: AHashMap<WsNodeId, Vec<CrossCallEdge>> = AHashMap::new();
        let mut field_index = FieldCrossCallIndex::default();
        let mut segments: Vec<SegmentId> = if let Some(allowed) = allowed_funcs {
            allowed
                .iter()
                .filter_map(|func| self.workspace.segment_for_func(*func))
                .collect()
        } else {
            (0..self.workspace.segment_count())
                .map(|segment| SegmentId(u32::try_from(segment).expect("IDG segment count exceeds u32")))
                .collect()
        };
        segments.sort_unstable_by_key(|segment| segment.0);
        segments.dedup();
        let segment_set: AHashSet<SegmentId> = segments.iter().copied().collect();
        let row_is_allowed = |row: &CrossCallEdge| {
            allowed_funcs.is_none_or(|allowed| allowed.contains(&row.caller) && allowed.contains(&row.callee))
        };
        for &seg_id in &segments {
            let Some(segment) = self.workspace.segment_view(seg_id) else {
                continue;
            };
            for edge in &segment.edges {
                let Some(from_ws) = Self::ws_node_for(unified, seg_id, edge.from) else {
                    continue;
                };
                if let Some(row) =
                    lift_call_arg_edge(seg_id, &segment, seg_id, &segment, edge, &mut field_index)
                {
                    if row_is_allowed(&row) {
                        cross_calls_by_from.entry(from_ws).or_default().push(row);
                    }
                }
            }
        }
        // Synthetic cross-method field-flow edges. Each link records
        // that a writer-method receiver-field write feeds a
        // reader-method receiver-field read. They are not part of the
        // raw segment edge lists, but source/taint lineage consumers
        // need them as cross-call rows when the writer node is in the
        // seed closure.
        for link in self.workspace.field_flow() {
            if allowed_funcs
                .is_some_and(|allowed| !(allowed.contains(&link.writer) && allowed.contains(&link.reader)))
            {
                continue;
            }
            let writer_ws = WsNodeId(link.writer_ws_node);
            cross_calls_by_from
                .entry(writer_ws)
                .or_default()
                .push(CrossCallEdge {
                    caller: link.writer,
                    callee: link.reader,
                    call_span: link.via_span,
                    arg_idx: u32::MAX,
                    param_idx: u32::MAX,
                    precision: link.precision,
                    call_kind: bonsai_callgraph::EdgeKind::Indirect,
                    relation: CrossCallRelation::FieldState,
                });
        }
        let mut projected_by_pair: AHashMap<(SegmentId, SegmentId), Vec<(WsNodeId, IdgEdge)>> =
            AHashMap::new();
        self.workspace
            .visit_cross_file_edges(|edges| {
                for cfe in edges {
                    if !(segment_set.contains(&cfe.from_segment) && segment_set.contains(&cfe.to_segment)) {
                        continue;
                    }
                    let Some(from_ws) = Self::ws_node_for(unified, cfe.from_segment, cfe.edge.from) else {
                        continue;
                    };
                    match lift_cross_call_edge_from_unified(
                        unified,
                        cfe.from_segment,
                        cfe.to_segment,
                        &cfe.edge,
                    ) {
                        CompactCrossCallLift::Complete(Some(row)) => {
                            if row_is_allowed(&row) {
                                cross_calls_by_from.entry(from_ws).or_default().push(row);
                            }
                        }
                        CompactCrossCallLift::NeedsSegmentPlaces => {
                            projected_by_pair
                                .entry((cfe.from_segment, cfe.to_segment))
                                .or_default()
                                .push((from_ws, cfe.edge));
                        }
                        CompactCrossCallLift::Complete(None) => {}
                    }
                }
            })
            .expect("validated IDG cross-file relation remains readable");
        let mut projected_pairs: Vec<_> = projected_by_pair.keys().copied().collect();
        projected_pairs.sort_unstable_by_key(|(from, to)| (from.0, to.0));
        for pair in projected_pairs {
            let Some(from_segment) = self.workspace.segment_view(pair.0) else {
                continue;
            };
            let Some(to_segment) = self.workspace.segment_view(pair.1) else {
                continue;
            };
            let Some(edges) = projected_by_pair.remove(&pair) else {
                continue;
            };
            for (from_ws, edge) in edges {
                if let Some(row) = lift_call_arg_edge(
                    pair.0,
                    &from_segment,
                    pair.1,
                    &to_segment,
                    &edge,
                    &mut field_index,
                ) {
                    if row_is_allowed(&row) {
                        cross_calls_by_from.entry(from_ws).or_default().push(row);
                    }
                }
            }
        }
        for rows in cross_calls_by_from.values_mut() {
            rows.sort_unstable_by_key(|row| {
                (
                    row.caller.raw(),
                    row.callee.raw(),
                    row.call_span,
                    row.arg_idx,
                    row.param_idx,
                    row.precision,
                    row.relation,
                )
            });
            rows.dedup();
        }
        cross_calls_by_from
    }

    /// Translate `(func, place)` to a [`PointRef`] by looking up the
    /// owning decl's name span (used as the default span for places
    /// that don't carry one — Param, Return, Read/Write of a bare
    /// name).
    fn build_point_ref(&self, func: FuncId, place: &Place) -> PointRef {
        let decl = self.global.decl_of(bonsai_common::SymbolId::new(func.raw()));
        let default_span = decl
            .map(|d| d.name_span)
            .unwrap_or_else(|| Span::empty(bonsai_common::FileId::INVALID, 0));
        let place_name = |name: bonsai_factstore::StrId,
                          path: &smallvec::SmallVec<[bonsai_factstore::StrId; 4]>| {
            let Some(segment_id) = self.workspace.segment_for_func(func) else {
                return String::new();
            };
            let Some(segment) = self.workspace.segment_view(segment_id) else {
                return String::new();
            };
            let Some(base) = segment.strings.get(name) else {
                return String::new();
            };
            if path.is_empty() {
                return base.to_string();
            }
            let mut out = base.to_string();
            for part in path {
                if let Some(segment_part) = segment.strings.get(*part) {
                    out.push('.');
                    out.push_str(segment_part);
                }
            }
            out
        };
        let (kind, name, span) = match place {
            Place::Param { idx } => (
                PointKind::Param,
                decl.and_then(|d| d.params.get(*idx as usize).cloned())
                    .unwrap_or_default(),
                default_span,
            ),
            Place::Return => (PointKind::Return, String::new(), default_span),
            Place::Read { name, path } => (PointKind::Read, place_name(*name, path), default_span),
            Place::Write { name, path, span } => (PointKind::Write, place_name(*name, path), *span),
            Place::CallArg { site, idx } => (PointKind::CallArg, format!("arg{idx}"), site.0),
            Place::CallRet { site } => (PointKind::CallRet, String::new(), site.0),
            _ => (PointKind::Other, String::new(), default_span),
        };
        PointRef {
            func,
            span,
            name,
            kind,
        }
    }
}

/// Expand bare container seed names with their descendant wildcard:
/// `args` → `args` + `args.*`. A source rule whose seed names a bare
/// container taints every projection of that container (`args.q`),
/// while projected seeds (`x.y`) pass through unchanged so a tainted
/// field never promotes its container or siblings. Both taint-graph
/// seed builders (security analysis and the taint crate) MUST use
/// this so scheduling cuts and graph construction see identical
/// seeds.
pub fn expand_bare_seed_names_with_descendants<'a, I>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut out = Vec::new();
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
        if !trimmed.contains(['.', '[']) {
            out.push(format!("{trimmed}.*"));
        }
    }
    out
}

fn split_projected_seed(seed: &str) -> Option<(&str, Vec<&str>)> {
    let (base, rest) = seed.split_once('.')?;
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    let path: Vec<&str> = rest
        .split('.')
        .map(str::trim)
        .filter(|part| !part.is_empty() && *part != "*")
        .collect();
    (!path.is_empty()).then_some((base, path))
}

fn projected_storage_path(
    segment: &crate::segment::IdgSegment,
    name: &str,
) -> Option<(bonsai_factstore::StrId, Vec<bonsai_factstore::StrId>)> {
    let normalised = normalise_projected_storage_text(name);
    let (base, path) = split_projected_seed(&normalised)?;
    let base_id = segment.strings.lookup(base)?;
    let path_ids = path
        .iter()
        .map(|part| segment.strings.lookup(part))
        .collect::<Option<Vec<_>>>()?;
    Some((base_id, path_ids))
}

fn normalise_projected_storage_text(name: &str) -> String {
    bonsai_common::normalize_qualified_name(
        name.trim().trim_start_matches(bonsai_common::is_name_punctuation),
    )
}

fn flat_place_matches_projected_seed(
    place: Option<&str>,
    descendant_bases: &AHashSet<String>,
    exact_flat_paths: &AHashSet<String>,
) -> bool {
    let Some(place) = place.map(str::trim).filter(|place| !place.is_empty()) else {
        return false;
    };
    if exact_flat_paths.contains(place) {
        return true;
    }
    descendant_bases.iter().any(|base| {
        place
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
    })
}

/// True iff two source spans overlap (same file, range intersects).
fn spans_overlap(a: Span, b: Span) -> bool {
    a.file == b.file && a.start < b.end && b.start < a.end
}

/// True iff `a` starts at or after `b` in source order (same file,
/// `a.start >= b.start`). Used to filter post-source writes when a
/// source rule has `output_args` semantics — the cutoff is the source
/// call span, and the source's own output-arg write is anchored *at*
/// that span (same start), so the bound is inclusive of `b.start`
/// rather than requiring `a.start >= b.end`.
fn span_after(a: Span, b: Span) -> bool {
    a.file == b.file && a.start >= b.start
}

/// Lift one IDG edge into a [`CrossCallEdge`] row. Returns `None`
/// when the edge isn't a `CallArg{site, idx} → Param{idx}` shape,
/// a return/yield output edge, or any other cross-call propagation
/// edge the lineage layer can report.
enum CompactCrossCallLift {
    /// The compact compiler identity is sufficient. `None` means the edge is
    /// not renderable cross-call evidence.
    Complete(Option<CrossCallEdge>),
    /// Projected storage needs exact place dictionaries from both bodies to
    /// recover its argument/parameter slots.
    NeedsSegmentPlaces,
}

fn lift_cross_call_edge_from_unified(
    unified: &UnifiedAddressSpace,
    from_segment: SegmentId,
    to_segment: SegmentId,
    edge: &IdgEdge,
) -> CompactCrossCallLift {
    let Some(from) = IdgQueryService::ws_node_for(unified, from_segment, edge.from) else {
        return CompactCrossCallLift::Complete(None);
    };
    let Some(to) = IdgQueryService::ws_node_for(unified, to_segment, edge.to) else {
        return CompactCrossCallLift::Complete(None);
    };
    let Some(caller) = unified.node_funcs.get(from.0 as usize).copied() else {
        return CompactCrossCallLift::Complete(None);
    };
    let Some(callee) = unified.node_funcs.get(to.0 as usize).copied() else {
        return CompactCrossCallLift::Complete(None);
    };

    if edge.meta.kind == IdgEdgeKind::InterCallArg {
        if let (Some((call_span, arg_idx)), Some(param_idx)) =
            (unified.call_args.get(from), unified.params.get(to))
        {
            return CompactCrossCallLift::Complete(Some(CrossCallEdge {
                caller,
                callee,
                call_span,
                arg_idx,
                param_idx,
                precision: edge.meta.precision,
                call_kind: edge.meta.call_kind,
                relation: CrossCallRelation::Argument,
            }));
        }
        if unified.node_boundaries.get(from.0 as usize).copied() == Some(NODE_BOUNDARY_CALL_RET) {
            if let Some(param_idx) = unified.params.get(to) {
                return CompactCrossCallLift::Complete(Some(CrossCallEdge {
                    caller,
                    callee,
                    call_span: edge.meta.via_span,
                    arg_idx: u32::MAX,
                    param_idx,
                    precision: edge.meta.precision,
                    call_kind: edge.meta.call_kind,
                    relation: CrossCallRelation::Callback,
                }));
            }
        }
        return if caller != callee {
            CompactCrossCallLift::NeedsSegmentPlaces
        } else {
            CompactCrossCallLift::Complete(None)
        };
    }
    if edge.meta.kind == IdgEdgeKind::InterFieldCallArg {
        return if caller != callee {
            CompactCrossCallLift::NeedsSegmentPlaces
        } else {
            CompactCrossCallLift::Complete(None)
        };
    }
    if matches!(
        edge.meta.kind,
        IdgEdgeKind::InterReturn | IdgEdgeKind::InterFieldReturn | IdgEdgeKind::InterYield
    ) && caller != callee
    {
        return CompactCrossCallLift::Complete(Some(CrossCallEdge {
            caller,
            callee,
            call_span: edge.meta.via_span,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
            precision: edge.meta.precision,
            call_kind: edge.meta.call_kind,
            relation: CrossCallRelation::Return,
        }));
    }
    CompactCrossCallLift::Complete(None)
}

fn lift_call_arg_edge(
    from_seg_id: SegmentId,
    from_seg: &crate::segment::IdgSegment,
    to_seg_id: SegmentId,
    to_seg: &crate::segment::IdgSegment,
    edge: &IdgEdge,
    field_index: &mut FieldCrossCallIndex,
) -> Option<CrossCallEdge> {
    let from_node = from_seg.nodes.get(edge.from)?;
    let to_node = to_seg.nodes.get(edge.to)?;
    let from_place = from_seg.places.get(from_node.place)?;
    let to_place = to_seg.places.get(to_node.place)?;
    // Forward call-arg edge: caller's CallArg → callee's Param.
    if edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg {
        if let Place::CallArg { site, idx } = from_place {
            if let Place::Param { idx: param_idx } = to_place {
                return Some(CrossCallEdge {
                    caller: from_node.func,
                    callee: to_node.func,
                    call_span: site.0,
                    arg_idx: *idx,
                    param_idx: *param_idx,
                    precision: edge.meta.precision,
                    call_kind: edge.meta.call_kind,
                    relation: CrossCallRelation::Argument,
                });
            }
        }
    }
    // Source-callback edge: an external source API's call result is
    // modeled as flowing into a named callback parameter
    // (`fs.readFile(..., onRead)` taints `onRead`'s `data`
    // parameter). There is no caller-side positional argument that
    // carries the taint, so keep `arg_idx` sentinel while preserving
    // the destination `param_idx` for path rendering and attribution.
    if edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg {
        if let Place::CallRet { .. } = from_place {
            if let Place::Param { idx: param_idx } = to_place {
                return Some(CrossCallEdge {
                    caller: from_node.func,
                    callee: to_node.func,
                    call_span: edge.meta.via_span,
                    arg_idx: u32::MAX,
                    param_idx: *param_idx,
                    precision: edge.meta.precision,
                    call_kind: edge.meta.call_kind,
                    relation: CrossCallRelation::Callback,
                });
            }
        }
    }
    // Field-argument edge: caller field writer → callee field read.
    // The builder emits this when `callee(arg)` passes a container
    // and the caller has a precise `arg.field` writer while the
    // callee reads `param.field`. Treat it as a cross-call lineage
    // hop without pretending the whole positional argument/parameter
    // is tainted.
    if matches!(
        edge.meta.kind,
        crate::edge::IdgEdgeKind::InterCallArg | crate::edge::IdgEdgeKind::InterFieldCallArg
    ) && from_node.func != to_node.func
    {
        let (arg_idx, param_idx) = field_cross_call_arg_and_param_indices(
            field_index,
            from_seg_id,
            from_seg,
            to_seg_id,
            to_seg,
            from_node.func,
            to_node.func,
            edge.meta.via_span,
            from_place,
            to_place,
        )
        .unwrap_or((u32::MAX, u32::MAX));
        return Some(CrossCallEdge {
            caller: from_node.func,
            callee: to_node.func,
            call_span: edge.meta.via_span,
            arg_idx,
            param_idx,
            precision: edge.meta.precision,
            call_kind: edge.meta.call_kind,
            // InterFieldCallArg is still anchored to a resolved AST call
            // boundary; only its carried value is projected. It is therefore
            // renderable call evidence, unlike allocation-insensitive
            // cross-method field-state links synthesized below.
            relation: if edge.meta.kind == crate::edge::IdgEdgeKind::InterFieldCallArg {
                CrossCallRelation::Argument
            } else {
                CrossCallRelation::Capture
            },
        });
    }
    // Return/outbound edge: any interprocedural return-family edge flows
    // from the callee back into the caller. Besides the scalar
    // `Return|Yield → CallRet` shape, the stitcher emits the same semantic
    // edge kind for projected constructor results, receiver mutation, and
    // out-parameter write-back (`callee.Write(field) → caller.Write(field)`).
    // These projected edges are equally load-bearing for lineage: omitting
    // them leaves the IDG proof intact but splits its renderable call chain
    // at the callee-return boundary.
    //
    // The lineage walker treats these as legitimate cross-method
    // propagation steps so chain attribution works for call-RHS
    // source patterns
    // (`cmd = mid(); os.system(cmd)` — mid's Return → top's
    // CallRet is the bridge from mid's body taint to top's
    // sink-relevant local). Encode the edge with `caller =
    // returning function` (mid) and `callee = caller-of-the-call`
    // (top) so `chain_funcs_for_lineage` builds the chain
    // mid → top in source-to-sink order; without this orientation
    // `first_inflow[top]` never gets seeded and the sink's
    // `parent_trace_id` lookup returns None. Sentinel
    // `arg_idx = u32::MAX` / `param_idx = u32::MAX` distinguishes
    // the synthetic return row from real positional-arg edges.
    if matches!(
        edge.meta.kind,
        crate::edge::IdgEdgeKind::InterReturn
            | crate::edge::IdgEdgeKind::InterFieldReturn
            | crate::edge::IdgEdgeKind::InterYield
    ) && from_node.func != to_node.func
    {
        return Some(CrossCallEdge {
            caller: from_node.func,
            callee: to_node.func,
            call_span: edge.meta.via_span,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
            precision: edge.meta.precision,
            call_kind: edge.meta.call_kind,
            relation: CrossCallRelation::Return,
        });
    }
    None
}

#[derive(Default)]
struct FieldCrossCallIndex {
    call_arg: AHashMap<(SegmentId, FuncId, Span, String), Option<u32>>,
    param: AHashMap<(SegmentId, FuncId, String), Option<u32>>,
}

impl FieldCrossCallIndex {
    fn call_arg_index(
        &mut self,
        segment_id: SegmentId,
        segment: &crate::segment::IdgSegment,
        caller: FuncId,
        call_span: Span,
        base: &str,
    ) -> Option<u32> {
        let key = (segment_id, caller, call_span, base.to_string());
        if let Some(value) = self.call_arg.get(&key) {
            return *value;
        }
        let value = call_arg_index_for_storage_base(segment, caller, call_span, base);
        self.call_arg.insert(key, value);
        value
    }

    fn param_index(
        &mut self,
        segment_id: SegmentId,
        segment: &crate::segment::IdgSegment,
        callee: FuncId,
        base: &str,
    ) -> Option<u32> {
        let key = (segment_id, callee, base.to_string());
        if let Some(value) = self.param.get(&key) {
            return *value;
        }
        let value = param_index_for_storage_base(segment, callee, base);
        self.param.insert(key, value);
        value
    }
}

#[allow(clippy::too_many_arguments)] // Hot-path lookup keeps segment/call context explicit to avoid temporary structs.
fn field_cross_call_arg_and_param_indices(
    field_index: &mut FieldCrossCallIndex,
    from_seg_id: SegmentId,
    from_seg: &crate::segment::IdgSegment,
    to_seg_id: SegmentId,
    to_seg: &crate::segment::IdgSegment,
    caller: FuncId,
    callee: FuncId,
    call_span: Span,
    from_place: &Place,
    to_place: &Place,
) -> Option<(u32, u32)> {
    let from_base = storage_base_from_place(from_seg, from_place)?;
    let to_base = storage_base_from_place(to_seg, to_place)?;
    let arg_idx = field_index
        .call_arg_index(from_seg_id, from_seg, caller, call_span, &from_base)
        .unwrap_or(u32::MAX);
    let param_idx = field_index
        .param_index(to_seg_id, to_seg, callee, &to_base)
        .unwrap_or(u32::MAX);
    Some((arg_idx, param_idx))
}

fn storage_base_from_place(segment: &crate::segment::IdgSegment, place: &Place) -> Option<String> {
    let (name, _path) = match place {
        Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
        _ => return None,
    };
    let base = segment.strings.get(name)?.trim();
    (!base.is_empty()).then(|| base.to_string())
}

fn call_arg_index_for_storage_base(
    segment: &crate::segment::IdgSegment,
    caller: FuncId,
    call_span: Span,
    base: &str,
) -> Option<u32> {
    let mut best = None;
    for edge in &segment.edges {
        if !edge.meta.kind.is_intra() {
            continue;
        }
        let Some(to_node) = segment.nodes.get(edge.to) else {
            continue;
        };
        if to_node.func != caller {
            continue;
        }
        let Some(Place::CallArg { site, idx }) = segment.places.get(to_node.place) else {
            continue;
        };
        if site.0 != call_span {
            continue;
        }
        let Some(from_node) = segment.nodes.get(edge.from) else {
            continue;
        };
        if from_node.func != caller {
            continue;
        }
        let Some(from_place) = segment.places.get(from_node.place) else {
            continue;
        };
        if storage_base_from_place(segment, from_place).as_deref() == Some(base) {
            best = Some(best.map_or(*idx, |existing: u32| existing.min(*idx)));
        }
    }
    best
}

fn param_index_for_storage_base(
    segment: &crate::segment::IdgSegment,
    callee: FuncId,
    base: &str,
) -> Option<u32> {
    let mut best = None;
    for edge in &segment.edges {
        if !edge.meta.kind.is_intra() {
            continue;
        }
        let Some(from_node) = segment.nodes.get(edge.from) else {
            continue;
        };
        if from_node.func != callee {
            continue;
        }
        let Some(Place::Param { idx }) = segment.places.get(from_node.place) else {
            continue;
        };
        let Some(to_node) = segment.nodes.get(edge.to) else {
            continue;
        };
        if to_node.func != callee {
            continue;
        }
        let Some(to_place) = segment.places.get(to_node.place) else {
            continue;
        };
        if storage_base_from_place(segment, to_place).as_deref() == Some(base) {
            best = Some(best.map_or(*idx, |existing: u32| existing.min(*idx)));
        }
    }
    best
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
