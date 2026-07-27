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
use bonsai_common::{FileId, FuncId, Precision, Span};
use bonsai_index::GlobalIndex;
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::hash::Hash;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, OnceLock};

use crate::bitset::NodeBitSet;
use crate::edge::{IdgEdge, IdgEdgeKind};
use crate::external_relation::merge_page_rows;
use crate::fact_source_index::{FactSourceIndex, FactSourceSpool};
use crate::node::NodeId;
use crate::place::Place;
use crate::positioned_io::read_exact_at;
use crate::query::ReachabilityIndex;
use crate::reverse_scalar_index::{ReverseScalarTransformIndex, ReverseScalarTransformSpool};
use crate::reverse_symbolic_index::{ReverseSymbolicTransformIndex, ReverseSymbolicTransformSpool};
use crate::spill_set::{SpillSet, SpillStack};
use crate::symbolic::{structured_storage_parts, SymbolicFieldTransformKind, NO_SYMBOLIC_STRING};
use crate::workspace::{IdgWorkspace, SegmentId};

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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WsNodeId(pub u32);

/// One resolved cross-call value propagation extracted from the IDG.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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
    /// Cross-function symbolic transforms proven by that same fixed point.
    pub symbolic_cross_calls: Vec<CrossCallEdge>,
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    unfiltered_reach: RwLock<Option<Arc<ReachabilityIndex>>>,
    precision_reach: RwLock<AHashMap<Precision, Arc<ReachabilityIndex>>>,
    contextual_summaries: RwLock<AHashMap<Option<Precision>, Arc<ContextualSummaryRuntime>>>,
    cross_calls_by_from: RwLock<Option<Arc<CrossCallsByFrom>>>,
    symbolic_runtime: OnceLock<Arc<SymbolicRuntimeIndex>>,
}

const NODE_BOUNDARY_PARAM: u8 = 1;
const NODE_BOUNDARY_RETURN: u8 = 2;
const NODE_BOUNDARY_THROW: u8 = 3;

#[derive(Default)]
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
#[derive(Default)]
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
}

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

    fn get(&self, key: &K) -> Option<&[WsNodeId]> {
        let index = self.keys.binary_search(key).ok()?;
        let start = self.offsets[index] as usize;
        let end = self.offsets[index + 1] as usize;
        Some(&self.nodes[start..end])
    }
}

type CrossCallsByFrom = AHashMap<WsNodeId, Vec<CrossCallEdge>>;

#[derive(Default)]
struct SegmentCallArgEvidence {
    resolved: AHashSet<NodeId>,
    aggregate_inputs: AHashMap<NodeId, smallvec::SmallVec<[NodeId; 4]>>,
}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SymbolicFactSpan {
    file: FileId,
    start: u64,
}

impl From<Span> for SymbolicFactSpan {
    fn from(span: Span) -> Self {
        Self {
            file: span.file,
            start: span.start,
        }
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
    exact_reads: GroupedNodeIndex<u64>,
    bare_reads: GroupedNodeIndex<u32>,
    scalar_writes: GroupedNodeIndex<(u32, Span)>,
    fact_sources: FactSourceIndex,
    aggregate_inputs: GroupedNodeIndex<NodeId>,
    reverse_transforms: ReverseSymbolicTransformIndex,
    reverse_scalar_transforms: ReverseScalarTransformIndex,
    fact_pages: Mutex<SymbolicFactPager>,
    transforms: Mutex<SymbolicTransformPager>,
}

impl Default for SymbolicRuntimeIndex {
    fn default() -> Self {
        Self {
            fields: PackedStringTable::default(),
            spans: Box::new([]),
            ordering_sensitive_bases: Box::new([]),
            exact_reads: GroupedNodeIndex::default(),
            bare_reads: GroupedNodeIndex::default(),
            scalar_writes: GroupedNodeIndex::default(),
            fact_sources: FactSourceIndex::empty(),
            aggregate_inputs: GroupedNodeIndex::default(),
            reverse_transforms: ReverseSymbolicTransformIndex::empty(),
            reverse_scalar_transforms: ReverseScalarTransformIndex::empty(),
            fact_pages: Mutex::new(SymbolicFactPager::new(0)),
            transforms: Mutex::new(SymbolicTransformPager::empty()),
        }
    }
}

/// Opaque backward relevance proof for one target set.
///
/// The proof is context-insensitive and therefore conservative: it may admit
/// extra states, but it never excludes a realizable contextual path. Exact
/// forward solvers use it only as a demand predicate and still run their
/// admitted relations to fixed point.
pub struct IdgTargetRelevance {
    nodes: NodeBitSet,
    facts: SpillSet,
    wildcard_bases: SpillSet,
}

impl IdgTargetRelevance {
    fn contains_node(&self, node: NodeId) -> bool {
        self.nodes.contains(node)
    }

    fn contains_fact(&self, base: u32, field: u32) -> bool {
        self.wildcard_bases.contains(u128::from(base))
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
                nodes: NodeBitSet::zeros(node_count),
                facts: target_relevance_fact_store(),
                wildcard_bases: target_relevance_wildcard_store(),
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

#[derive(Default)]
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

#[derive(Copy, Clone)]
struct SymbolicFactPageEntry {
    offset: u64,
    node_count: u32,
    fact_count: u32,
}

const NO_SYMBOLIC_FACT_SPAN: u32 = u32::MAX;
const SYMBOLIC_FACT_BYTES: usize = 12;

struct SymbolicFactPager {
    file: std::fs::File,
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
            file: tempfile::tempfile().expect("create symbolic fact page spool"),
            entries: vec![None; segment_count],
            write_offset: 0,
            pages: AHashMap::default(),
            order: VecDeque::new(),
            capacity: workers.saturating_mul(2).max(2),
        }
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
        self.file
            .seek(SeekFrom::Start(self.write_offset))
            .expect("seek symbolic fact page spool");
        self.file
            .write_all(&payload)
            .expect("write symbolic fact page spool");
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
        self.file.seek(SeekFrom::Start(entry.offset)).ok()?;
        self.file.read_exact(&mut payload).ok()?;
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
    file: std::fs::File,
    offsets: Box<[u32]>,
    pages: AHashMap<u32, Arc<Vec<crate::symbolic::SymbolicFieldTransform>>>,
    order: VecDeque<u32>,
    capacity: usize,
}

impl SymbolicTransformPager {
    fn empty() -> Self {
        Self {
            file: tempfile::tempfile().expect("create empty symbolic transform relation"),
            offsets: Box::new([0]),
            pages: AHashMap::default(),
            order: VecDeque::new(),
            capacity: 2,
        }
    }

    fn build(
        workspace: &IdgWorkspace,
        base_count: usize,
        fact_spans: &mut AHashSet<SymbolicFactSpan>,
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
        workspace
            .visit_symbolic_transforms(|transforms| {
                for &transform in transforms {
                    let source = transform.source as usize;
                    assert!(
                        source < base_count,
                        "symbolic transform source exceeds base dictionary"
                    );
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
                        reverse.push(transform.target, transform.source, transform.precision);
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
                file,
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
            self.file
                .seek(SeekFrom::Start(
                    u64::from(start) * SYMBOLIC_TRANSFORM_BYTES as u64,
                ))
                .expect("seek compact symbolic transforms");
            self.file
                .read_exact(&mut payload)
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct ContextBoundaryKey {
    caller: FuncId,
    callee: FuncId,
    span: Span,
}

#[derive(Copy, Clone)]
struct ContextBoundaryEdge {
    key: ContextBoundaryKey,
    target: NodeId,
}

struct SparseContextEdges {
    /// Boundaries grouped by the parallel source/offset directory. Source ids
    /// are not repeated in every retained edge.
    edges: Vec<ContextBoundaryEdge>,
    /// One entry per distinct source and a terminal offset.
    sources: Vec<NodeId>,
    offsets: Vec<u32>,
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
}

struct ContextualSummaryRuntime {
    reach: ReachabilityIndex,
    heap_by_from: GroupedNodeIndex<NodeId>,
    calls_by_from: SparseContextEdges,
    returns_by_from: SparseContextEdges,
    reverse_contextual: GroupedNodeIndex<NodeId>,
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

    fn len(&self) -> usize {
        match self {
            Self::Dense(reached) => reached.popcount(),
            Self::Sparse { reached, .. } => reached.len(),
        }
    }

    fn append_nodes(&self, nodes: &mut Vec<NodeId>) {
        match self {
            Self::Dense(reached) => nodes.extend(reached.iter()),
            Self::Sparse { reached, .. } => {
                nodes.extend(reached.iter().copied().map(NodeId));
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
    /// The public closure result is context-erased. One dense node bitset
    /// avoids replaying the external relation merely to construct that result.
    nodes: NodeBitSet,
}

impl ContextualClosureVisited {
    fn new(node_count: usize) -> Self {
        Self {
            states: contextual_node_store(),
            nodes: NodeBitSet::zeros(node_count),
        }
    }

    fn insert(&mut self, context: u32, node: NodeId) -> bool {
        if node.0 as usize >= self.nodes.len() {
            return false;
        }
        let key = (u128::from(context) << 32) | u128::from(node.0);
        if !self.states.insert(key) {
            return false;
        }
        self.nodes.set(node);
        true
    }

    fn append_nodes(&self, nodes: &mut Vec<NodeId>) {
        nodes.extend(self.nodes.iter());
    }

    fn len(&self) -> u64 {
        self.states.len()
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
        let mut nodes = Vec::new();
        self.root.append_nodes(&mut nodes);
        self.contextual.append_nodes(&mut nodes);
        nodes.sort_unstable_by_key(|node| node.0);
        nodes.dedup();
        nodes
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

struct CallContexts {
    ids: AHashMap<ContextBoundaryKey, u32>,
    boundaries: Vec<Option<ContextBoundaryKey>>,
    callers: Vec<CompactSet<u32>>,
    /// Most call contexts never complete a distinct return fact. Sparse maps
    /// avoid retaining two empty set headers for every boundary.
    returned_nodes: AHashMap<u32, AHashSet<NodeId>>,
    returned_facts: SpillSet,
}

impl CallContexts {
    fn new() -> Self {
        Self {
            boundaries: vec![None],
            ids: AHashMap::default(),
            callers: vec![CompactSet::default()],
            returned_nodes: AHashMap::default(),
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

    fn returned_nodes_for(&self, context: u32) -> Vec<NodeId> {
        self.returned_nodes
            .get(&context)
            .map(|values| values.iter().copied().collect())
            .unwrap_or_default()
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
        let returned = self.returned_nodes.entry(context).or_default();
        if !returned.insert(node) {
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
}

impl<'a> SymbolicClosureWorklist<'a> {
    fn new(
        node_count: usize,
        seed_count: usize,
        summary_root: Option<FuncId>,
        allowed_funcs: Option<&'a AHashSet<FuncId>>,
        target_relevance: Option<&'a IdgTargetRelevance>,
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

    fn enqueue_fact_state(&mut self, fact: SymbolicNodeFact) {
        if self
            .target_relevance
            .is_some_and(|relevance| !relevance.contains_fact(fact.base, fact.field))
        {
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
    return_summaries: Mutex<AHashMap<Option<Precision>, ReturnSummaryCache>>,
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
        Ok(Some(Self::new(Arc::new(workspace), global)))
    }

    /// Wrap a workspace + global index. The unified address space
    /// is **not** built here — it's deferred to first query.
    #[must_use]
    pub fn new(workspace: Arc<IdgWorkspace>, global: Arc<GlobalIndex>) -> Self {
        Self {
            workspace,
            global,
            unified: RwLock::new(None),
            return_summaries: Mutex::new(AHashMap::new()),
        }
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
        let mut compiled = self.compile_return_taint_param_indices(&missing, max_precision);
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
    ) -> AHashMap<FuncId, Vec<u32>> {
        let summary_started = std::time::Instant::now();
        let mut batch = run_isolated_compiler_phase(|| {
            crate::function_summary::return_taint_param_indices(&self.workspace, funcs, max_precision)
        });
        bonsai_diagnostics::debug_log!(
            "idg-summary",
            "ordinary compiler summaries funcs={} symbolic_sensitive={} contextual_edges={} elapsed={:.3}s",
            funcs.len(),
            batch.symbolic_sensitive.len(),
            batch.contextual_edges.len(),
            summary_started.elapsed().as_secs_f64()
        );
        if self.workspace.has_symbolic_transforms() {
            let contextual_runtime =
                self.cache_contextual_summary_runtime(max_precision, &batch.contextual_edges);
            bonsai_diagnostics::debug_log!(
                "idg-summary",
                "contextual compiler runtime elapsed={:.3}s",
                summary_started.elapsed().as_secs_f64()
            );
            let unified = self.ensure_unified();
            run_isolated_compiler_phase(|| {
                unified
                    .symbolic_runtime
                    .get_or_init(|| Arc::new(self.build_symbolic_runtime_index(&unified)));
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
    ) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        self.symbolic_forward_closure_nodes(
            &unified,
            &contextual.reach,
            &seed_nodes,
            SymbolicClosurePolicy {
                max_precision,
                allowed_funcs: None,
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
        let contextual = self.ensure_contextual_summary_runtime(&unified, None);
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
        let contextual = self.ensure_contextual_summary_runtime(&unified, Some(max_precision));
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
        let contextual = self.ensure_contextual_summary_runtime(&unified, max_precision);
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
        self.forward_closure_evidence_in_func_scope(seeds, max_precision, None, None)
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
                symbolic_cross_calls: Vec::new(),
            };
        }
        self.forward_closure_evidence_in_func_scope(seeds, max_precision, Some(allowed_funcs), None)
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
                symbolic_cross_calls: Vec::new(),
            };
        }
        self.forward_closure_evidence_in_func_scope(
            seeds,
            max_precision,
            Some(allowed_funcs),
            Some(target_relevance),
        )
    }

    fn forward_closure_evidence_in_func_scope(
        &self,
        seeds: &[WsNodeId],
        max_precision: Option<Precision>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
        target_relevance: Option<&IdgTargetRelevance>,
    ) -> IdgClosureEvidence {
        let unified = self.ensure_unified();
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        let contextual = self.ensure_contextual_summary_runtime(&unified, max_precision);
        // One transform can fire for every access-path field and caller
        // context. Cross-call evidence is transform identity, not fixed-point
        // multiplicity, so deduplicate at insertion instead of retaining
        // millions of duplicate rows until the closure finishes.
        let mut symbolic_cross_calls = AHashSet::new();
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
                    summary_root: None,
                    contextual: Some(contextual.as_ref()),
                    activate_seed_callers: true,
                },
                Some(&mut symbolic_cross_calls),
            )
            .into_iter()
            .map(|node| WsNodeId(node.0))
            .collect();
        let mut symbolic_cross_calls: Vec<_> = symbolic_cross_calls.into_iter().collect();
        symbolic_cross_calls.sort_unstable_by_key(|edge| {
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
        IdgClosureEvidence {
            nodes,
            symbolic_cross_calls,
        }
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
        self.target_relevance_in_func_scope(target_nodes, target_funcs, None, max_precision)
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
        self.target_relevance_in_func_scope(target_nodes, target_funcs, Some(allowed_funcs), max_precision)
    }

    fn target_relevance_in_func_scope(
        &self,
        target_nodes: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
        allowed_funcs: Option<&AHashSet<FuncId>>,
        max_precision: Option<Precision>,
    ) -> IdgTargetRelevance {
        let unified = self.ensure_unified();
        let runtime = unified
            .symbolic_runtime
            .get_or_init(|| Arc::new(self.build_symbolic_runtime_index(&unified)));
        let symbolic = self.workspace.symbolic_field();
        let contextual = self.ensure_contextual_summary_runtime(&unified, max_precision);
        let mut worklist = TargetRelevanceWorklist::new(Self::unified_node_count(&unified));
        let node_is_allowed = |node: NodeId| {
            allowed_funcs.is_none_or(|allowed| {
                Self::ws_node_func(&unified, node).is_some_and(|func| allowed.contains(&func))
            })
        };
        let base_is_allowed = |base: u32| {
            allowed_funcs.is_none_or(|allowed| {
                symbolic
                    .bases()
                    .get(base as usize)
                    .is_some_and(|base| allowed.contains(&base.func))
            })
        };
        for target in target_nodes {
            let target = NodeId(target.0);
            if node_is_allowed(target) {
                worklist.enqueue_node(target);
            }
        }
        for func in target_funcs.into_iter().flatten() {
            if allowed_funcs.is_some_and(|allowed| !allowed.contains(func)) {
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
                for predecessor in contextual.reach.backward_neighbours(node) {
                    let predecessor = NodeId(*predecessor);
                    if node_is_allowed(predecessor) {
                        worklist.enqueue_node(predecessor);
                    }
                }
                if let Some(predecessors) = contextual.reverse_contextual.get(&node) {
                    for predecessor in predecessors {
                        let predecessor = NodeId(predecessor.0);
                        if node_is_allowed(predecessor) {
                            worklist.enqueue_node(predecessor);
                        }
                    }
                }
                if let Some(inputs) = runtime.aggregate_inputs.get(&node) {
                    for input in inputs {
                        let input = NodeId(input.0);
                        if node_is_allowed(input) {
                            worklist.enqueue_node(input);
                        }
                    }
                }

                let Some((segment_id, local_node)) = Self::ws_address(&unified, WsNodeId(node.0)) else {
                    continue;
                };
                let Some(segment) = self.workspace.segment_view(segment_id) else {
                    continue;
                };
                let Some(idg_node) = segment.nodes.get(local_node) else {
                    continue;
                };
                let Some(place) = segment.places.get(idg_node.place) else {
                    continue;
                };
                let Some((parts, write_span, is_read)) = structured_storage_parts(&segment, place) else {
                    continue;
                };
                if is_read {
                    for fact in Self::symbolic_facts_for_node(&unified, runtime, node) {
                        worklist.enqueue_fact(fact.base, fact.field);
                    }
                    let full = parts.join(".");
                    if let Some(base) = symbolic.base_id(segment_id, idg_node.func, &full) {
                        worklist.enqueue_wildcard_base(base);
                    }
                }
                if let Some(write_span) = write_span {
                    let full = parts.join(".");
                    if let Some(target) = symbolic.base_id(segment_id, idg_node.func, &full) {
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
                                if base_is_allowed(row.source) {
                                    worklist.enqueue_fact(row.source, field);
                                }
                            });
                    }
                }
            }

            if let Some(key) = worklist.pending_facts.pop() {
                let key = key as u64;
                let base = (key >> 32) as u32;
                let field = key as u32;
                runtime.fact_sources.visit_key(key, |source| {
                    let source = NodeId(source);
                    if node_is_allowed(source) {
                        worklist.enqueue_node(source);
                    }
                });
                runtime.reverse_transforms.visit_incoming(base, |row| {
                    if max_precision.is_none_or(|max| row.precision <= max) && base_is_allowed(row.source) {
                        worklist.enqueue_fact(row.source, field);
                    }
                });
            }

            if let Some(base) = worklist.pending_wildcard_bases.pop() {
                let base = base as u32;
                runtime.fact_sources.visit_base(base, |source| {
                    let source = NodeId(source);
                    if node_is_allowed(source) {
                        worklist.enqueue_node(source);
                    }
                });
                runtime.reverse_transforms.visit_incoming(base, |row| {
                    if max_precision.is_none_or(|max| row.precision <= max) && base_is_allowed(row.source) {
                        worklist.enqueue_wildcard_base(row.source);
                    }
                });
            }
        }

        bonsai_diagnostics::debug_log!(
            "idg-target",
            "backward relevance targets={} fallback_funcs={} allowed_funcs={} nodes={} facts={} wildcard_bases={}",
            target_nodes.len(),
            target_funcs.map_or(0, |funcs| funcs.len()),
            allowed_funcs.map_or(0, |funcs| funcs.len()),
            worklist.relevance.nodes.iter().count(),
            worklist.relevance.facts.len(),
            worklist.relevance.wildcard_bases.len()
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
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
            return Vec::new();
        };
        let want: ahash::AHashSet<&str> = names.iter().map(|n| n.as_str()).collect();
        let mut out = Vec::new();
        for (idx, param_name) in decl.params.iter().enumerate() {
            if !want.contains(param_name.as_str()) {
                continue;
            }
            let Ok(b) = u32::try_from(idx) else { continue };
            let place = Place::Param { idx: b };
            let Some(pid) = segment.places.lookup(&place) else {
                continue;
            };
            let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) else {
                continue;
            };
            if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                out.push(ws_node);
            }
        }
        out
    }

    /// Resolve the workspace IDG nodes for ALL of `func`'s
    /// `Place::Param{idx}` slots. Used by seed builders that have
    /// no narrower signal — the engine's historical default is to
    /// seed every param when the source rule has no name match.
    pub fn param_nodes_of(&self, func: FuncId) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment_view(seg_id) else {
            return Vec::new();
        };
        let mut indexed = Vec::new();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let Place::Param { idx } = place else {
                continue;
            };
            let pid = crate::node::PlaceId(pid_idx as u32);
            let Some(local_node) = self.local_node_for(&unified, seg_id, func, pid) else {
                continue;
            };
            if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                indexed.push((*idx, ws_node));
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
        let mut reachable = NodeBitSet::zeros(Self::unified_node_count(&unified));
        let mut touched_segments = AHashSet::new();
        for ws_node in closure {
            reachable.set(NodeId(ws_node.0));
            if let Some((segment, _)) = Self::ws_address(&unified, *ws_node) {
                touched_segments.insert(segment);
            }
        }
        // Aggregate-consumption markers are deliberately absent from the
        // reachability graph: they describe an unresolved/external call-site
        // observation, not scalar value flow. Index them once per segment
        // touched by the closure so rendering remains O(reachable nodes +
        // touched edges), rather than rescanning edges per call argument.
        let mut evidence_by_segment: AHashMap<SegmentId, SegmentCallArgEvidence> = AHashMap::new();
        for seg_id in touched_segments {
            let Some(segment) = self.workspace.segment_view(seg_id) else {
                continue;
            };
            let mut evidence = SegmentCallArgEvidence::default();
            for edge in &segment.edges {
                if edge.meta.kind == IdgEdgeKind::InterCallArg {
                    evidence.resolved.insert(edge.from);
                } else if edge.meta.kind == IdgEdgeKind::IntraAggregateConsume {
                    evidence
                        .aggregate_inputs
                        .entry(edge.to)
                        .or_default()
                        .push(edge.from);
                }
            }
            evidence_by_segment.insert(seg_id, evidence);
        }
        // Warm sidecars deliberately keep only the canonical cross-edge
        // vector. Scan it once for the complete set of touched segments
        // instead of rebuilding two workspace-wide directional indexes or
        // rescanning the vector independently for every segment.
        self.workspace
            .visit_cross_file_edges(|edges| {
                for cross in edges {
                    if cross.edge.meta.kind != IdgEdgeKind::InterCallArg {
                        continue;
                    }
                    if let Some(evidence) = evidence_by_segment.get_mut(&cross.from_segment) {
                        evidence.resolved.insert(cross.edge.from);
                    }
                }
            })
            .expect("validated IDG cross-file relation remains readable");
        let mut out = Vec::new();
        for ws_node in closure {
            let Some((seg_id, local)) = Self::ws_address(&unified, *ws_node) else {
                continue;
            };
            let Some(segment) = self.workspace.segment_view(seg_id) else {
                continue;
            };
            let Some(node) = segment.nodes.get(local) else {
                continue;
            };
            let Some(place) = segment.places.get(node.place) else {
                continue;
            };
            if let Place::CallArg { site, idx } = place {
                if target_funcs.is_some_and(|targets| !targets.contains(&node.func)) {
                    continue;
                }
                out.push((node.func, site.0, *idx));
            }
        }
        // A whole aggregate passed to an unresolved/external call consumes
        // its currently known fields even though that observation is not a
        // traversable scalar edge. Resolver-proven local calls instead use
        // exact InterFieldCallArg edges, preserving sibling-field precision.
        for (seg_id, evidence) in evidence_by_segment {
            let Some(segment) = self.workspace.segment_view(seg_id) else {
                continue;
            };
            for (arg_node, aggregate_inputs) in evidence.aggregate_inputs {
                if evidence.resolved.contains(&arg_node) {
                    continue;
                }
                let aggregate_reachable = aggregate_inputs.into_iter().any(|from| {
                    Self::ws_node_for(&unified, seg_id, from)
                        .is_some_and(|from_ws| reachable.contains(NodeId(from_ws.0)))
                });
                if !aggregate_reachable {
                    continue;
                }
                let Some(node) = segment.nodes.get(arg_node) else {
                    continue;
                };
                if target_funcs.is_some_and(|targets| !targets.contains(&node.func)) {
                    continue;
                }
                let Some(Place::CallArg { site, idx }) = segment.places.get(node.place) else {
                    continue;
                };
                out.push((node.func, site.0, *idx));
            }
        }
        out.sort_by_key(|(f, span, idx)| (f.raw(), span.start, *idx));
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
        let mut out = Vec::new();
        for ws_node in closure {
            let Some((seg_id, local)) = Self::ws_address(&unified, *ws_node) else {
                continue;
            };
            let Some(segment) = self.workspace.segment_view(seg_id) else {
                continue;
            };
            let Some(node) = segment.nodes.get(local) else {
                continue;
            };
            if target_funcs.is_some_and(|targets| !targets.contains(&node.func)) {
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
            let mut storage = base.to_string();
            for part in path {
                let Some(part) = segment.strings.get(*part) else {
                    continue;
                };
                storage.push('.');
                storage.push_str(part);
            }
            if storage.trim().is_empty() {
                continue;
            }
            out.push((node.func, storage));
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
            let Some((seg_id, local)) = Self::ws_address(&unified, *ws_node) else {
                continue;
            };
            let Some(segment) = self.workspace.segment_view(seg_id) else {
                continue;
            };
            let Some(node) = segment.nodes.get(local) else {
                continue;
            };
            let Some(place) = segment.places.get(node.place) else {
                continue;
            };
            if matches!(place, Place::Return) {
                out.push(node.func);
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
        let mut edges =
            self.cross_call_edges_in_reachable_nodes_with_max_precision(&evidence.nodes, max_precision);
        edges.extend(evidence.symbolic_cross_calls);
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
        let unified = Arc::new(self.build_unified());
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
        let mut func_node_rows = Vec::new();
        let mut call_arg_nodes = Vec::new();
        let mut call_arg_sites = Vec::new();
        let mut call_arg_indices = Vec::new();
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
                func_node_rows.push((node.func, node.place, NodeId(ws_node.0)));
                if let Some(Place::CallArg { site, idx }) = place {
                    call_arg_nodes.push(ws_node);
                    call_arg_sites.push(site.0);
                    call_arg_indices.push(*idx);
                }
                node_boundaries.push(match place {
                    Some(Place::Param { .. }) => NODE_BOUNDARY_PARAM,
                    Some(Place::Return) => NODE_BOUNDARY_RETURN,
                    Some(Place::Throw { .. }) => NODE_BOUNDARY_THROW,
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
        func_node_rows.sort_unstable_by_key(|(func, place, node)| (func.raw(), place.0, node.0));
        let func_nodes = func_node_rows
            .into_iter()
            .map(|(_, _, node)| node)
            .collect::<Vec<_>>();
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
            unfiltered_reach: RwLock::new(None),
            precision_reach: RwLock::new(AHashMap::new()),
            contextual_summaries: RwLock::new(AHashMap::new()),
            cross_calls_by_from: RwLock::new(None),
            symbolic_runtime: OnceLock::new(),
        }
    }

    fn ws_node_for(unified: &UnifiedAddressSpace, seg_id: SegmentId, local_node: NodeId) -> Option<WsNodeId> {
        let seg_idx = seg_id.0 as usize;
        let start = *unified.segment_bases.get(seg_idx)?;
        let end = *unified.segment_bases.get(seg_idx + 1)?;
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
    ) -> ContextualSummaryRuntime {
        let unified = self.ensure_unified();

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
        {
            let mut record_non_call_relation =
                |from_segment: SegmentId, to_segment: SegmentId, edge: &IdgEdge| {
                    let projected_heap_relation = edge.meta.kind.is_inter()
                        && (Self::node_is_projected_storage(&unified, from_segment, edge.from)
                            || Self::node_is_projected_storage(&unified, to_segment, edge.to));
                    if (edge.meta.kind.is_inter() && !projected_heap_relation)
                        || max_precision.is_some_and(|max| edge.meta.precision > max)
                    {
                        return;
                    }
                    let Some(from) = Self::ws_node_for(&unified, from_segment, edge.from) else {
                        return;
                    };
                    let Some(to) = Self::ws_node_for(&unified, to_segment, edge.to) else {
                        return;
                    };
                    if projected_heap_relation {
                        heap_rows.push((NodeId(from.0), to));
                    }
                };
            for (segment_id, segment) in self.workspace.segment_views() {
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
        let mut reverse_contextual_rows = heap_rows
            .iter()
            .map(|(source, target)| (NodeId(target.0), WsNodeId(source.0)))
            .collect::<Vec<_>>();
        let heap_by_from = GroupedNodeIndex::from_rows(heap_rows);

        // Eager compatibility field edges can point at a canonical type-field
        // node whose owning function differs from the logical callee. Build
        // the authoritative call-site relation from structural formal/return
        // places first, then attribute those synthetic edges to the exact
        // same-span compiler boundary.
        let mut structural_boundaries: AHashMap<(FuncId, Span), Vec<ContextBoundaryKey>> =
            AHashMap::default();
        {
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
                    let structural = match edge.meta.kind {
                        IdgEdgeKind::InterCallArg => {
                            unified.node_boundaries.get(to.0 as usize).copied() == Some(NODE_BOUNDARY_PARAM)
                        }
                        IdgEdgeKind::InterReturn => {
                            unified.node_boundaries.get(from.0 as usize).copied()
                                == Some(NODE_BOUNDARY_RETURN)
                        }
                        IdgEdgeKind::InterThrow => {
                            unified.node_boundaries.get(from.0 as usize).copied() == Some(NODE_BOUNDARY_THROW)
                        }
                        _ => false,
                    };
                    if !structural {
                        return;
                    }
                    let key = match edge.meta.kind {
                        IdgEdgeKind::InterCallArg => Self::ws_node_func(&unified, NodeId(from.0))
                            .zip(Self::ws_node_func(&unified, NodeId(to.0)))
                            .map(|(caller, callee)| ContextBoundaryKey {
                                caller,
                                callee,
                                span: edge.meta.via_span,
                            }),
                        IdgEdgeKind::InterReturn | IdgEdgeKind::InterThrow => {
                            Self::ws_node_func(&unified, NodeId(to.0))
                                .zip(Self::ws_node_func(&unified, NodeId(from.0)))
                        }
                        .map(|(caller, callee)| ContextBoundaryKey {
                            caller,
                            callee,
                            span: edge.meta.via_span,
                        }),
                        _ => None,
                    };
                    if let Some(key) = key {
                        structural_boundaries
                            .entry((key.caller, key.span))
                            .or_default()
                            .push(key);
                    }
                };
            for (segment_id, segment) in self.workspace.segment_views() {
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
        for keys in structural_boundaries.values_mut() {
            keys.sort_unstable_by_key(|key| (key.caller.0, key.callee.0, key.span));
            keys.dedup();
        }

        let mut call_rows = Vec::new();
        let mut return_rows = Vec::new();
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
                let Some(caller_callee) = (match edge.meta.kind {
                    IdgEdgeKind::InterCallArg => Self::ws_node_func(&unified, NodeId(from.0))
                        .zip(Self::ws_node_func(&unified, NodeId(to.0)))
                        .map(|(caller, callee)| (caller, callee, true)),
                    IdgEdgeKind::InterReturn | IdgEdgeKind::InterThrow => {
                        Self::ws_node_func(&unified, NodeId(to.0))
                            .zip(Self::ws_node_func(&unified, NodeId(from.0)))
                    }
                    .map(|(caller, callee)| (caller, callee, false)),
                    _ => None,
                }) else {
                    return;
                };
                let endpoint_key = ContextBoundaryKey {
                    caller: caller_callee.0,
                    callee: caller_callee.1,
                    span: edge.meta.via_span,
                };
                let structural = structural_boundaries.get(&(endpoint_key.caller, endpoint_key.span));
                let keys: &[ContextBoundaryKey] = structural
                    .filter(|keys| !keys.contains(&endpoint_key))
                    .map(Vec::as_slice)
                    .unwrap_or(std::slice::from_ref(&endpoint_key));
                for &key in keys {
                    let boundary = ContextBoundaryEdge {
                        key,
                        target: NodeId(to.0),
                    };
                    if caller_callee.2 {
                        call_rows.push((NodeId(from.0), boundary));
                    } else {
                        return_rows.push((NodeId(from.0), boundary));
                    }
                }
            };
            for (segment_id, segment) in self.workspace.segment_views() {
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
        drop(structural_boundaries);
        reverse_contextual_rows.extend(
            call_rows
                .iter()
                .chain(&return_rows)
                .map(|(source, edge)| (edge.target, WsNodeId(source.0))),
        );
        let calls_by_from = SparseContextEdges::from_rows(call_rows);
        let returns_by_from = SparseContextEdges::from_rows(return_rows);
        let reverse_contextual = GroupedNodeIndex::from_rows(reverse_contextual_rows);
        let reach = ReachabilityIndex::from_pair_visitor(Self::unified_node_count(&unified), |visit| {
            for edge in summary_edges {
                let Some(from) = Self::ws_node_for(&unified, edge.segment, edge.from) else {
                    continue;
                };
                let Some(to) = Self::ws_node_for(&unified, edge.segment, edge.to) else {
                    continue;
                };
                visit(from.0, to.0);
            }
            for (segment_id, segment) in self.workspace.segment_views() {
                for edge in &segment.edges {
                    if let Some((from, to)) =
                        Self::contextual_ordinary_pair(&unified, segment_id, segment_id, edge, max_precision)
                    {
                        visit(from, to);
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
                            visit(from, to);
                        }
                    }
                })
                .expect("validated IDG cross-file relation remains readable");
        });
        ContextualSummaryRuntime {
            reach,
            heap_by_from,
            calls_by_from,
            returns_by_from,
            reverse_contextual,
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

    fn symbolic_forward_closure_nodes(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        reach: &ReachabilityIndex,
        seeds: &[NodeId],
        policy: SymbolicClosurePolicy<'_>,
        mut symbolic_cross_calls: Option<&mut AHashSet<CrossCallEdge>>,
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
        let runtime = unified
            .symbolic_runtime
            .get_or_init(|| Arc::new(self.build_symbolic_runtime_index(unified)));
        let node_count = Self::unified_node_count(unified);
        let mut worklist = SymbolicClosureWorklist::new(
            node_count,
            seeds.len(),
            summary_root,
            allowed_funcs,
            target_relevance,
        );
        for seed in seeds.iter().copied() {
            if (seed.0 as usize) < node_count && symbolic_node_allowed(unified, &worklist, seed) {
                Self::enqueue_symbolic_node_source(unified, runtime, seed, 0, &mut worklist);
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
                    runtime,
                    contextual,
                    summary_callees,
                    activate_seed_callers,
                    state,
                    &mut worklist,
                );
                processed_nodes = processed_nodes.saturating_add(1);
            }
            if let Some(fact) = worklist.next_fact() {
                Self::propagate_symbolic_closure_fact(
                    unified,
                    runtime,
                    symbolic,
                    max_precision,
                    summary_callees,
                    contextual.is_some(),
                    activate_seed_callers,
                    fact,
                    symbolic_cross_calls.as_deref_mut(),
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
        reach: &ReachabilityIndex,
        runtime: &SymbolicRuntimeIndex,
        contextual: Option<&ContextualSummaryRuntime>,
        summary_callees: Option<&AHashMap<FuncId, Vec<FuncId>>>,
        activate_seed_callers: bool,
        state: ClosureNodeState,
        worklist: &mut SymbolicClosureWorklist<'_>,
    ) {
        for target in reach.forward_neighbours(state.node) {
            let target = NodeId(*target);
            if activate_summary_transition(unified, summary_callees, state.node, target, worklist) {
                Self::enqueue_symbolic_node_source(unified, runtime, target, state.context, worklist);
            }
        }
        let Some(contextual) = contextual else {
            return;
        };
        if let Some(targets) = contextual.heap_by_from.get(&state.node) {
            for &target in targets {
                let target = NodeId(target.0);
                if activate_summary_transition(unified, summary_callees, state.node, target, worklist) {
                    Self::enqueue_symbolic_node_source(unified, runtime, target, 0, worklist);
                }
            }
        }
        for call in contextual.calls_by_from.get(state.node) {
            if !worklist.node_is_relevant(call.target)
                || !activate_summary_call(summary_callees, call.key, worklist)
            {
                continue;
            }
            let context = Self::register_context_call(unified, runtime, state.context, call.key, worklist);
            Self::enqueue_symbolic_node_source(unified, runtime, call.target, context, worklist);
        }
        for returned in contextual.returns_by_from.get(state.node) {
            if !symbolic_node_allowed(unified, worklist, returned.target) {
                continue;
            }
            if worklist.contexts.matches(state.context, returned.key) {
                let caller_contexts = worklist
                    .contexts
                    .complete_node_return(state.context, returned.target);
                for context in caller_contexts {
                    Self::enqueue_symbolic_node_source(unified, runtime, returned.target, context, worklist);
                }
            } else if activate_seed_callers && state.context == 0 {
                Self::enqueue_symbolic_node_source(unified, runtime, returned.target, 0, worklist);
            }
        }
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
    ) -> SymbolicFactPage {
        let mut offsets = Vec::with_capacity(segment.nodes.nodes.len().saturating_add(1));
        let mut facts = Vec::new();
        offsets.push(0);
        for node in &segment.nodes.nodes {
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
        let returned_nodes = worklist.contexts.returned_nodes_for(context);
        Self::replay_context_outputs(
            unified,
            runtime,
            caller_context,
            returned_nodes,
            Vec::new(),
            worklist,
        );

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
        if let Some(nodes) = runtime.bare_reads.get(&fact.base) {
            for node in nodes {
                let node = NodeId(node.0);
                if symbolic_node_allowed(unified, worklist, node) {
                    worklist.enqueue_node(node, fact.context);
                }
            }
        }
    }

    fn visit_structured_storage_nodes(
        &self,
        unified: &UnifiedAddressSpace,
        mut visit: impl FnMut(SegmentId, FuncId, WsNodeId, &[String], Option<Span>, bool),
    ) {
        for (segment_id, segment) in self.workspace.segment_views() {
            for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
                let Some(place) = segment.places.get(node.place) else {
                    continue;
                };
                let Some((parts, write_span, is_read)) = structured_storage_parts(&segment, place) else {
                    continue;
                };
                let local = NodeId(u32::try_from(node_index).expect("segment-local node count exceeds u32"));
                let Some(ws_node) = Self::ws_node_for(unified, segment_id, local) else {
                    continue;
                };
                visit(segment_id, node.func, ws_node, &parts, write_span, is_read);
            }
        }
    }

    fn build_symbolic_runtime_index(&self, unified: &UnifiedAddressSpace) -> SymbolicRuntimeIndex {
        let symbolic = self.workspace.symbolic_field();
        let mut field_names = AHashSet::default();
        let mut fact_spans = AHashSet::default();
        self.visit_structured_storage_nodes(unified, |_, _, _, parts, write_span, _| {
            for split in 1..parts.len() {
                field_names.insert(parts[split..].join("."));
            }
            if let Some(span) = write_span {
                fact_spans.insert(SymbolicFactSpan::from(span));
            }
        });
        let mut fields: Vec<String> = field_names.into_iter().collect();
        fields.sort_unstable();
        let (transforms, reverse_transforms, reverse_scalar_transforms, ordering_sensitive_bases) =
            SymbolicTransformPager::build(&self.workspace, symbolic.bases().len(), &mut fact_spans);
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
        out.transforms = Mutex::new(transforms);
        out.reverse_transforms = reverse_transforms;
        out.reverse_scalar_transforms = reverse_scalar_transforms;

        // Compile every source segment's AST-derived access-path facts once
        // into a fixed-width temporary sidecar. Broad closures then page this
        // compact numeric relation instead of repeatedly decoding the full
        // MessagePack IDG segment and rebuilding dotted paths.
        let mut fact_pages = SymbolicFactPager::new(self.workspace.segment_count());
        let mut exact_read_rows = Vec::new();
        let mut fact_sources = FactSourceSpool::new();
        let mut aggregate_input_rows = Vec::new();
        for (segment_id, segment) in self.workspace.segment_views() {
            let page = Self::build_symbolic_fact_page(segment_id, &segment, &out, symbolic);
            for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
                let local = NodeId(u32::try_from(node_index).expect("segment-local node count exceeds u32"));
                let Some(ws_node) = Self::ws_node_for(unified, segment_id, local) else {
                    continue;
                };
                for fact in page.get(local) {
                    let key = symbolic_fact_key(fact.base, fact.field);
                    fact_sources.push(key, ws_node.0);
                    if matches!(segment.places.get(node.place), Some(Place::Read { .. })) {
                        exact_read_rows.push((key, ws_node));
                    }
                }
            }
            for edge in &segment.edges {
                if edge.meta.kind != IdgEdgeKind::IntraAggregateConsume {
                    continue;
                }
                let Some(from) = Self::ws_node_for(unified, segment_id, edge.from) else {
                    continue;
                };
                let Some(to) = Self::ws_node_for(unified, segment_id, edge.to) else {
                    continue;
                };
                aggregate_input_rows.push((NodeId(to.0), from));
            }
            fact_pages.write_page(segment_id, &page);
        }
        out.fact_pages = Mutex::new(fact_pages);
        out.exact_reads = GroupedNodeIndex::from_rows(exact_read_rows);
        out.fact_sources = fact_sources.finish();
        out.aggregate_inputs = GroupedNodeIndex::from_rows(aggregate_input_rows);

        let mut bare_read_rows = Vec::new();
        self.visit_structured_storage_nodes(unified, |segment_id, func, ws_node, parts, _, is_read| {
            if !is_read {
                return;
            }
            let full = parts.join(".");
            if let Some(base) = symbolic.base_id(segment_id, func, &full) {
                bare_read_rows.push((base, ws_node));
            }
        });
        out.bare_reads = GroupedNodeIndex::from_rows(bare_read_rows);

        let mut scalar_write_rows = Vec::new();
        self.visit_structured_storage_nodes(unified, |segment_id, func, ws_node, parts, write_span, _| {
            let Some(span) = write_span else {
                return;
            };
            let full = parts.join(".");
            if let Some(base) = symbolic.base_id(segment_id, func, &full) {
                scalar_write_rows.push(((base, span), ws_node));
            }
        });
        out.scalar_writes = GroupedNodeIndex::from_rows(scalar_write_rows);
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

    fn ensure_contextual_summary_runtime(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        max_precision: Option<Precision>,
    ) -> Arc<ContextualSummaryRuntime> {
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
        let batch = crate::function_summary::return_taint_param_indices(&self.workspace, &[], max_precision);
        let runtime = Arc::new(self.build_contextual_summary_runtime(&batch.contextual_edges, max_precision));
        write.insert(max_precision, Arc::clone(&runtime));
        runtime
    }

    fn cache_contextual_summary_runtime(
        &self,
        max_precision: Option<Precision>,
        summary_edges: &[crate::function_summary::ContextualSummaryEdge],
    ) -> Arc<ContextualSummaryRuntime> {
        let unified = self.ensure_unified();
        {
            let read = unified.contextual_summaries.read();
            if let Some(runtime) = read.get(&max_precision) {
                return Arc::clone(runtime);
            }
        }
        let runtime = run_isolated_compiler_phase(|| {
            Arc::new(self.build_contextual_summary_runtime(summary_edges, max_precision))
        });
        let mut write = unified.contextual_summaries.write();
        Arc::clone(write.entry(max_precision).or_insert(runtime))
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
        let rows = Arc::new(self.build_cross_calls_by_from(unified));
        *write = Some(Arc::clone(&rows));
        rows
    }

    fn build_cross_calls_by_from(
        &self,
        unified: &UnifiedAddressSpace,
    ) -> AHashMap<WsNodeId, Vec<CrossCallEdge>> {
        let mut cross_calls_by_from: AHashMap<WsNodeId, Vec<CrossCallEdge>> = AHashMap::new();
        let mut field_index = FieldCrossCallIndex::default();
        for (seg_id, segment) in self.workspace.segment_views() {
            let seg_id = SegmentId(seg_id.0);
            for edge in &segment.edges {
                let Some(from_ws) = Self::ws_node_for(unified, seg_id, edge.from) else {
                    continue;
                };
                if let Some(row) =
                    lift_call_arg_edge(seg_id, &segment, seg_id, &segment, edge, &mut field_index)
                {
                    cross_calls_by_from
                        .entry(from_ws)
                        .or_default()
                        .push(self.normalize_receiver_arg_index(row));
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
        self.workspace
            .visit_cross_file_edges(|edges| {
                for cfe in edges {
                    let Some(from_ws) = Self::ws_node_for(unified, cfe.from_segment, cfe.edge.from) else {
                        continue;
                    };
                    let Some(from_seg) = self.workspace.segment_view(cfe.from_segment) else {
                        continue;
                    };
                    let Some(to_seg) = self.workspace.segment_view(cfe.to_segment) else {
                        continue;
                    };
                    if let Some(row) = lift_call_arg_edge(
                        cfe.from_segment,
                        &from_seg,
                        cfe.to_segment,
                        &to_seg,
                        &cfe.edge,
                        &mut field_index,
                    ) {
                        cross_calls_by_from
                            .entry(from_ws)
                            .or_default()
                            .push(self.normalize_receiver_arg_index(row));
                    }
                }
            })
            .expect("validated IDG cross-file relation remains readable");
        cross_calls_by_from
    }

    /// Canonicalize older adapter receiver slots that were represented as
    /// argument zero. The AST call shape is authoritative: an argument-less
    /// call with an explicit receiver has no positional argument zero, so the
    /// cross-call carrier is the receiver sentinel.
    fn normalize_receiver_arg_index(&self, mut edge: CrossCallEdge) -> CrossCallEdge {
        let caller_symbol = bonsai_common::SymbolId::new(edge.caller.raw());
        if edge.arg_idx == 0
            && matches!(
                edge.relation,
                CrossCallRelation::Argument | CrossCallRelation::Capture
            )
            && self.global.decl_of(caller_symbol).is_some_and(|decl| {
                self.global.linkage_facts(caller_symbol).map_or_else(
                    || call_event_is_argumentless_receiver(&decl.flow_events, edge.call_span),
                    |facts| {
                        facts.calls.iter().any(|call| {
                            call.span == edge.call_span
                                && call
                                    .receiver
                                    .as_deref()
                                    .is_some_and(|receiver| !receiver.trim().is_empty())
                                && call.arg_spans.is_empty()
                        })
                    },
                )
            })
        {
            edge.arg_idx = u32::MAX;
        }
        edge
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

fn call_event_is_argumentless_receiver(events: &[bonsai_lang_api::FlowEvent], span: Span) -> bool {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call {
                span: call_span,
                receiver,
                args,
                ..
            } if *call_span == span => {
                return receiver
                    .as_deref()
                    .is_some_and(|receiver| !receiver.trim().is_empty())
                    && args.is_empty();
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if call_event_is_argumentless_receiver(then_events, span)
                    || call_event_is_argumentless_receiver(else_events, span)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if call_event_is_argumentless_receiver(body, span) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if call_event_is_argumentless_receiver(body, span)
                    || call_event_is_argumentless_receiver(catch_events, span)
                    || call_event_is_argumentless_receiver(finally_events, span)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
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
    name.trim()
        .trim_start_matches('&')
        .trim_start_matches('*')
        .replace("->", ".")
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
        crate::edge::IdgEdgeKind::InterReturn | crate::edge::IdgEdgeKind::InterFieldReturn
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
