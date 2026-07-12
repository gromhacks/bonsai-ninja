//! High-level query service over an [`IdgWorkspace`].
//!
//! Phase 5 consumers (value-flow, security analysis, dump-taint,
//! inspect, source-analysis, export) all need the same primitives:
//!
//! - "What flows from `entry_func`'s params (or a named seed)?"
//! - "What flows into `sink_func`'s arg N?"
//! - "What's the smallest cut that separates a source from a sink?"
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
use bonsai_common::{FuncId, Precision, Span};
use bonsai_index::GlobalIndex;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::bitset::NodeBitSet;
use crate::edge::IdgEdge;
use crate::node::NodeId;
use crate::place::Place;
use crate::query::ReachabilityIndex;
use crate::symbolic::{SymbolicFieldTransformKind, NO_SYMBOLIC_STRING};
use crate::workspace::{IdgWorkspace, SegmentId};

const SEMANTIC_MAX_PRECISION: Precision = Precision::Narrowed;

/// A renderable program point: the (function, span, place) triple
/// every consumer eventually reports back to its UI / report layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PointRef {
    /// The function that owns this point.
    pub func: FuncId,
    /// The exact source span. Defaults to the func's name span when
    /// the IDG node is a logical position (a synthesised `Param`
    /// node, the function's `Return` slot) without an explicit span.
    pub span: Span,
    /// Render-friendly textual handle. Empty for synthesised nodes.
    pub name: String,
    /// Coarse classification — useful for consumers that want to
    /// render param/read/write/call differently.
    pub kind: PointKind,
}

/// Coarse classification of an IDG point. Mirrors [`Place`] but
/// flattens it to a small enum so consumers don't have to match on
/// every variant.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PointKind {
    /// `Place::Param`.
    Param,
    /// `Place::Return`.
    Return,
    /// `Place::Read`.
    Read,
    /// `Place::Write`.
    Write,
    /// `Place::CallArg`.
    CallArg,
    /// `Place::CallRet`.
    CallRet,
    /// Throw / Catch / Yield / Await — render the same way at the
    /// query layer (rare, exceptional flows).
    Other,
}

/// Assignment target written from a call site's synthetic
/// `Place::CallRet`. This is the precise `target = call(...)`
/// binding the transfer pass emitted, not a name lookup heuristic.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallRetAssignmentTarget {
    /// Adapter-normalized storage name written by the call return.
    pub name: String,
    /// Source span of the assignment target write.
    pub span: Span,
    /// Workspace-global node id for the target write.
    pub node: WsNodeId,
}

/// Workspace-global node identifier. Identifies a `(SegmentId,
/// segment_local_node_id)` pair via a flat u32 mapping the service
/// computes on first query.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WsNodeId(pub u32);

/// One transitive cross-call propagation extracted from the IDG.
///
/// Value-flow / dataflow consumers replace the legacy engine's
/// per-source `CallPropagation` records with these — every
/// `(CallArg{site, arg_idx} → callee.Param{param_idx})` cross-file
/// edge whose source endpoint is in the seed's forward closure
/// surfaces as one [`CrossCallEdge`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrossCallEdge {
    /// Function holding the call site.
    pub caller: FuncId,
    /// Function being called (one row per resolved candidate; virtual
    /// dispatch produces one row per receiver-type-narrowed candidate).
    pub callee: FuncId,
    /// Source span of the call site in the caller.
    pub call_span: Span,
    /// 0-based positional index of the argument in the call.
    pub arg_idx: u32,
    /// 0-based positional index of the parameter in the callee.
    pub param_idx: u32,
    /// Per-edge precision recorded by the IDG transfer / stitch pass.
    pub precision: Precision,
    /// Sub-classifier for the call site (Direct / Virtual / Indirect /
    /// Unknown). Lets consumers render edge_kind without a separate
    /// callgraph lookup.
    pub call_kind: bonsai_callgraph::EdgeKind,
}

/// Lazily-computed unified node address space spanning every
/// segment. Built once on first reachability query; reused for
/// subsequent queries.
struct UnifiedAddressSpace {
    /// Contiguous workspace-node base for each segment plus one trailing
    /// sentinel. Since segment ids and local node ids are dense, translating
    /// `(segment, local)` is arithmetic rather than one hash entry per node.
    segment_bases: Box<[u32]>,
    /// `ws_node → (seg, local_node)`. Vec-indexed by ws node raw.
    reverse: Vec<(SegmentId, NodeId)>,
    /// Nodes grouped by owning function. Target-function cuts use this
    /// compiler-derived index instead of rescanning a file segment once per
    /// method in the target set.
    nodes_by_func: AHashMap<FuncId, Box<[NodeId]>>,
    /// Unfiltered diagnostic reachability is built only if requested. Normal
    /// semantic consumers request a precision-scoped index, so eagerly
    /// retaining both CSR pairs doubles large-workspace memory needlessly.
    unfiltered_reach: RwLock<Option<Arc<ReachabilityIndex>>>,
    /// Precision-scoped reachability indexes. Each entry contains
    /// only edges whose precision is at or below the key. Building
    /// this once per requested precision lets exact/security/export
    /// callers reuse the normal CSR closure kernel without checking
    /// every edge's precision on every source query.
    precision_reach: RwLock<AHashMap<Precision, Arc<ReachabilityIndex>>>,
    /// Cross-call rows keyed by the workspace-global `from` node
    /// that makes the row reachable. `cross_call_edges_in_closure`
    /// is called once per exact source seed; pre-indexing here keeps
    /// those queries proportional to the seed closure instead of
    /// rescanning every segment edge and every cross-file edge.
    cross_calls_by_from: RwLock<Option<Arc<CrossCallsByFrom>>>,
    /// Numeric runtime indexes for the compact access-path algebra. Built
    /// only when a workspace actually carries symbolic transforms.
    symbolic_runtime: OnceLock<Arc<SymbolicRuntimeIndex>>,
    /// Recently used backward closures from sink target function or node
    /// sets. Every closure is a full-workspace bitset, so retaining one per
    /// source group would make memory grow as `groups * nodes`. The shared
    /// LRU retains at most one closure per available analysis worker; an
    /// evicted closure is recomputed exactly when requested again.
    target_backward: RwLock<TargetCutCache>,
    #[cfg(test)]
    target_cut_computations: AtomicU64,
}

type CrossCallsByFrom = AHashMap<WsNodeId, Vec<CrossCallEdge>>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct SymbolicNodeFact {
    base: u32,
    field: u32,
    span: Option<Span>,
    interprocedural: bool,
}

#[derive(Default)]
struct SymbolicRuntimeIndex {
    field_ids: AHashMap<String, u32>,
    fields: Vec<String>,
    facts_by_node: AHashMap<WsNodeId, Vec<SymbolicNodeFact>>,
    exact_reads: AHashMap<u64, Vec<WsNodeId>>,
    bare_reads: AHashMap<u32, Vec<WsNodeId>>,
    scalar_writes: AHashMap<(u32, Span), Vec<WsNodeId>>,
}

impl SymbolicRuntimeIndex {
    fn intern_field(&mut self, field: &str) -> u32 {
        if let Some(id) = self.field_ids.get(field).copied() {
            return id;
        }
        let id = u32::try_from(self.fields.len()).expect("symbolic runtime field count exceeds u32");
        self.fields.push(field.to_string());
        self.field_ids.insert(field.to_string(), id);
        id
    }

    fn field(&self, id: u32) -> Option<&str> {
        self.fields.get(id as usize).map(String::as_str)
    }
}

fn symbolic_fact_key(base: u32, field: u32) -> u64 {
    (u64::from(base) << 32) | u64::from(field)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TargetFuncCutKey {
    max_precision: Option<Precision>,
    funcs: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TargetNodeCutKey {
    max_precision: Option<Precision>,
    nodes: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum TargetCutKey {
    Funcs(TargetFuncCutKey),
    Nodes(TargetNodeCutKey),
}

struct CachedTargetCut {
    closure: Arc<OnceLock<Arc<NodeBitSet>>>,
    last_used: AtomicU64,
}

/// Exact backward target cuts retained under a strict memory bound.
///
/// Cache eviction changes only whether a later query recomputes its reverse
/// fixed point. It never truncates that fixed point or the returned cut.
struct TargetCutCache {
    entries: AHashMap<TargetCutKey, CachedTargetCut>,
    capacity: usize,
    access_clock: AtomicU64,
}

impl TargetCutCache {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            entries: AHashMap::with_capacity(capacity),
            capacity,
            access_clock: AtomicU64::new(1),
        }
    }

    fn next_access(&self) -> u64 {
        self.access_clock.fetch_add(1, Ordering::Relaxed)
    }

    fn get_cell(&self, key: &TargetCutKey) -> Option<Arc<OnceLock<Arc<NodeBitSet>>>> {
        let entry = self.entries.get(key)?;
        entry.last_used.store(self.next_access(), Ordering::Relaxed);
        Some(Arc::clone(&entry.closure))
    }

    fn get_or_insert_cell(&mut self, key: TargetCutKey) -> Arc<OnceLock<Arc<NodeBitSet>>> {
        let access = self.next_access();
        if let Some(existing) = self.entries.get(&key) {
            existing.last_used.store(access, Ordering::Relaxed);
            return Arc::clone(&existing.closure);
        }

        if self.entries.len() >= self.capacity {
            let least_recent = self
                .entries
                .iter()
                // Never evict an in-flight cell: doing so would let a later
                // same-key caller create a second whole-workspace closure.
                .filter(|(_, entry)| entry.closure.get().is_some())
                .min_by_key(|(_, entry)| entry.last_used.load(Ordering::Relaxed))
                .map(|(key, _)| key.clone());
            if let Some(least_recent) = least_recent {
                self.entries.remove(&least_recent);
            }
        }

        let closure = Arc::new(OnceLock::new());
        self.entries.insert(
            key,
            CachedTargetCut {
                closure: Arc::clone(&closure),
                last_used: AtomicU64::new(access),
            },
        );
        closure
    }

    fn trim_completed(&mut self) {
        while self.entries.len() > self.capacity {
            let least_recent = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.closure.get().is_some())
                .min_by_key(|(_, entry)| entry.last_used.load(Ordering::Relaxed))
                .map(|(key, _)| key.clone());
            let Some(least_recent) = least_recent else {
                break;
            };
            self.entries.remove(&least_recent);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn contains(&self, key: &TargetCutKey) -> bool {
        self.entries.contains_key(key)
    }
}

fn default_target_cut_cache_capacity() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

impl TargetFuncCutKey {
    fn new(max_precision: Option<Precision>, funcs: &AHashSet<FuncId>) -> Self {
        let mut funcs: Vec<u32> = funcs.iter().map(|func| func.raw()).collect();
        funcs.sort_unstable();
        funcs.dedup();
        Self { max_precision, funcs }
    }
}

impl TargetNodeCutKey {
    fn new(max_precision: Option<Precision>, nodes: &[WsNodeId]) -> Self {
        let mut nodes: Vec<u32> = nodes.iter().map(|node| node.0).collect();
        nodes.sort_unstable();
        nodes.dedup();
        Self { max_precision, nodes }
    }
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
    target_cut_cache_capacity: usize,
}

impl IdgQueryService {
    /// Wrap a workspace + global index. The unified address space
    /// is **not** built here — it's deferred to first query.
    #[must_use]
    pub fn new(workspace: Arc<IdgWorkspace>, global: Arc<GlobalIndex>) -> Self {
        Self::with_target_cut_cache_capacity(workspace, global, default_target_cut_cache_capacity())
    }

    fn with_target_cut_cache_capacity(
        workspace: Arc<IdgWorkspace>,
        global: Arc<GlobalIndex>,
        target_cut_cache_capacity: usize,
    ) -> Self {
        Self {
            workspace,
            global,
            unified: RwLock::new(None),
            target_cut_cache_capacity: target_cut_cache_capacity.max(1),
        }
    }

    /// Number of segments in the underlying workspace.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.workspace.segment_count()
    }

    /// Number of intra-segment edges across all segments.
    #[must_use]
    pub fn intra_edge_count(&self) -> usize {
        self.workspace.intra_edge_count()
    }

    /// Number of cross-file edges in the workspace index.
    #[must_use]
    pub fn cross_file_edge_count(&self) -> usize {
        self.workspace.cross_file().len()
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
        if !self.workspace.symbolic_field().transforms().is_empty() {
            let mut out = AHashMap::with_capacity(funcs.len());
            for func in funcs.iter().copied() {
                let Some(return_node) = self.return_node_of(func) else {
                    out.insert(func, Vec::new());
                    continue;
                };
                let mut returning = Vec::new();
                for (index, param) in self.param_nodes_of(func).into_iter().enumerate() {
                    let reaches_return = self
                        .forward_closure_with_max_precision(&[param], max_precision)
                        .contains(&return_node);
                    bonsai_diagnostics::debug_log!(
                        "idg-closure",
                        "symbolic return summary func={} param={} reaches_return={}",
                        func.raw(),
                        index,
                        reaches_return
                    );
                    if reaches_return {
                        returning.push(u32::try_from(index).expect("parameter index exceeds u32"));
                    }
                }
                out.insert(func, returning);
            }
            return out;
        }
        crate::function_summary::return_taint_param_indices(&self.workspace, funcs, max_precision)
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

    /// Resolve a [`PointRef`] back from a [`WsNodeId`].
    pub fn resolve_point(&self, ws_node: WsNodeId) -> Option<PointRef> {
        let unified = self.ensure_unified();
        let &(seg_id, local_node) = unified.reverse.get(ws_node.0 as usize)?;
        let segment = self.workspace.segment(seg_id)?;
        let idg_node = segment.nodes.get(local_node)?;
        let place = segment.places.get(idg_node.place)?;
        Some(self.build_point_ref(idg_node.func, place))
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
        let reach = self.ensure_unfiltered_reach(&unified);
        self.symbolic_forward_closure_nodes(&unified, &reach, &seed_nodes, None)
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
        let reach = self.ensure_precision_reach(&unified, max_precision);
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|w| NodeId(w.0)).collect();
        self.symbolic_forward_closure_nodes(&unified, &reach, &seed_nodes, Some(max_precision))
            .into_iter()
            .map(|n| WsNodeId(n.0))
            .collect()
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
        let Some(func_nodes) = unified.nodes_by_func.get(&func) else {
            return Vec::new();
        };
        let allowed = NodeBitSet::from_seed(unified.reverse.len(), func_nodes);
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        self.forward_closure_nodes_within(&unified, &seed_nodes, &allowed, max_precision)
            .into_iter()
            .map(|node| WsNodeId(node.0))
            .collect()
    }

    /// Source-to-target cut: every node on at least one path from
    /// `seeds` to any node owned by `target_funcs`, within the
    /// requested precision scope.
    ///
    /// Security taint analysis uses this instead of a plain forward
    /// closure once it has already narrowed candidate sink functions
    /// with the resolved callgraph. This keeps per-source work
    /// proportional to the source-to-sink corridor rather than every
    /// value reachable from the source in a large workspace.
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
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|w| NodeId(w.0)).collect();
        let backward = self.target_func_backward_closure(&unified, target_funcs, max_precision);
        if backward.is_zero() {
            return Vec::new();
        }
        self.forward_closure_nodes_within(&unified, &seed_nodes, &backward, max_precision)
            .into_iter()
            .map(|node| WsNodeId(node.0))
            .collect()
    }

    /// Source-to-target cut where targets are concrete IDG nodes,
    /// usually sink call arguments / receiver slots / returns.
    pub fn forward_target_nodes_cut_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        target_nodes: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Vec<WsNodeId> {
        if seeds.is_empty() || target_nodes.is_empty() {
            return Vec::new();
        }
        let unified = self.ensure_unified();
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|w| NodeId(w.0)).collect();
        let backward = self.target_nodes_backward_closure(&unified, target_nodes, max_precision);
        if backward.is_zero() {
            return Vec::new();
        }
        self.forward_closure_nodes_within(&unified, &seed_nodes, &backward, max_precision)
            .into_iter()
            .map(|node| WsNodeId(node.0))
            .collect()
    }

    /// Source-to-target cut for a mixture of concrete target nodes and
    /// fallback target functions. The backward slices are unioned first so
    /// one restricted forward traversal covers both target classes.
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
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|node| NodeId(node.0)).collect();
        let mut backward = if target_nodes.is_empty() {
            NodeBitSet::zeros(unified.reverse.len())
        } else {
            (*self.target_nodes_backward_closure(&unified, target_nodes, max_precision)).clone()
        };
        if !target_funcs.is_empty() {
            let function_backward = self.target_func_backward_closure(&unified, target_funcs, max_precision);
            backward.union_inplace(&function_backward);
        }
        if backward.is_zero() {
            return Vec::new();
        }
        self.forward_closure_nodes_within(&unified, &seed_nodes, &backward, max_precision)
            .into_iter()
            .map(|node| WsNodeId(node.0))
            .collect()
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
        let unified = self.ensure_unified();
        self.ensure_unfiltered_reach(&unified)
            .reaches(NodeId(from.0), NodeId(to.0))
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
        let Some(segment) = self.workspace.segment(seg_id) else {
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
            if let Some(local_node) = segment.nodes.lookup(func, pid) {
                if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                    out.push(ws_node);
                }
            }
        }
        out
    }

    /// Return the subset of `names` whose bare Read/Write node in
    /// `func` is present in an already-computed reachability closure.
    ///
    /// This is the batched counterpart to repeatedly calling
    /// [`Self::read_or_write_nodes_for_names`] for each local name.
    /// Taint graph construction asks this for every receiver-bearing
    /// call in a closure; scanning the segment's place dictionary
    /// once per caller avoids an allocation-heavy name-by-name loop.
    pub fn read_or_write_names_in_reachable_nodes(
        &self,
        func: FuncId,
        names: &[String],
        closure: &AHashSet<WsNodeId>,
    ) -> AHashSet<String> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return AHashSet::default();
        };
        let Some(segment) = self.workspace.segment(seg_id) else {
            return AHashSet::default();
        };
        let mut target_by_strid: AHashMap<bonsai_factstore::StrId, String> = AHashMap::new();
        for name in names {
            if let Some(strid) = segment.strings.lookup(name) {
                target_by_strid.entry(strid).or_insert_with(|| name.clone());
            }
        }
        if target_by_strid.is_empty() {
            return AHashSet::default();
        }

        let mut out = AHashSet::default();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let strid = match place {
                Place::Read { name, path } if path.is_empty() => *name,
                Place::Write { name, path, .. } if path.is_empty() => *name,
                _ => continue,
            };
            let Some(source_name) = target_by_strid.get(&strid) else {
                continue;
            };
            let pid = crate::node::PlaceId(pid_idx as u32);
            let Some(local_node) = segment.nodes.lookup(func, pid) else {
                continue;
            };
            let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) else {
                continue;
            };
            if closure.contains(&ws_node) {
                out.insert(source_name.clone());
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
        let Some(segment) = self.workspace.segment(seg_id) else {
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
            let Some(local_node) = segment.nodes.lookup(func, pid) else {
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
        let Some(segment) = self.workspace.segment(seg_id) else {
            return Vec::new();
        };
        let mut indexed = Vec::new();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let Place::Param { idx } = place else {
                continue;
            };
            let pid = crate::node::PlaceId(pid_idx as u32);
            let Some(local_node) = segment.nodes.lookup(func, pid) else {
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
        let Some(segment) = self.workspace.segment(seg_id) else {
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
            if let Some(local_node) = segment.nodes.lookup(func, pid) {
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
        let Some(segment) = self.workspace.segment(seg_id) else {
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
            if let Some(local_node) = segment.nodes.lookup(func, pid) {
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
        let mut out = Vec::new();
        for ws_node in closure {
            let Some(&(seg_id, local)) = unified.reverse.get(ws_node.0 as usize) else {
                continue;
            };
            let Some(segment) = self.workspace.segment(seg_id) else {
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
            let Some(&(seg_id, local)) = unified.reverse.get(ws_node.0 as usize) else {
                continue;
            };
            let Some(segment) = self.workspace.segment(seg_id) else {
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
        let segment = self.workspace.segment(seg_id)?;
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let Place::CallRet { site } = place else {
                continue;
            };
            if site.0 != call_span {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            let local_node = segment.nodes.lookup(func, pid)?;
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
        let Some(segment) = self.workspace.segment(seg_id) else {
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
            if let Some(local_node) = segment.nodes.lookup(func, pid) {
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
        let Some(segment) = self.workspace.segment(seg_id) else {
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
            ret_node = segment.nodes.lookup(func, pid);
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
            let Some(&(seg_id, local)) = unified.reverse.get(ws_node.0 as usize) else {
                continue;
            };
            let Some(segment) = self.workspace.segment(seg_id) else {
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
        let Some(segment) = self.workspace.segment(seg_id) else {
            return Vec::new();
        };
        let bare_strid = segment.strings.lookup(name);
        let projected = projected_storage_path(segment, name);
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
            if let Some(local_node) = segment.nodes.lookup(func, pid) {
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
        let Some(segment) = self.workspace.segment(seg_id) else {
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
            if let Some(local) = segment.nodes.lookup(func, pid) {
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
        for (_, segment) in self.workspace.segments() {
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
        let segment = self.workspace.segment(seg_id)?;
        let pid = segment.places.lookup(&Place::Return)?;
        let local_node = segment.nodes.lookup(func, pid)?;
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
        let closure = self.forward_closure_with_max_precision(seeds, max_precision);
        self.cross_call_edges_in_reachable_nodes_with_max_precision(&closure, max_precision)
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
        let mut reverse = Vec::new();
        let mut segment_bases = Vec::with_capacity(self.workspace.segment_count() + 1);
        let mut nodes_by_func: AHashMap<FuncId, Vec<NodeId>> = AHashMap::new();
        // 1. Allocate a workspace-global id for every segment-local
        // node. Stable order: iterate segments by SegmentId, then
        // local node id ascending. That guarantees deterministic ws
        // node ids for repeated builds (important for snapshot tests).
        for (seg_id, segment) in self.workspace.segments() {
            segment_bases.push(u32::try_from(reverse.len()).expect("unified IDG node count exceeds u32"));
            for (local_idx, node) in segment.nodes.nodes.iter().enumerate() {
                let local_node = NodeId(local_idx as u32);
                let ws_node =
                    NodeId(u32::try_from(reverse.len()).expect("unified IDG node count exceeds u32"));
                reverse.push((seg_id, local_node));
                nodes_by_func.entry(node.func).or_default().push(ws_node);
            }
        }
        segment_bases.push(u32::try_from(reverse.len()).expect("unified IDG node count exceeds u32"));
        let nodes_by_func = nodes_by_func
            .into_iter()
            .map(|(func, nodes)| (func, nodes.into_boxed_slice()))
            .collect();
        UnifiedAddressSpace {
            segment_bases: segment_bases.into_boxed_slice(),
            reverse,
            nodes_by_func,
            unfiltered_reach: RwLock::new(None),
            precision_reach: RwLock::new(AHashMap::new()),
            cross_calls_by_from: RwLock::new(None),
            symbolic_runtime: OnceLock::new(),
            target_backward: RwLock::new(TargetCutCache::new(self.target_cut_cache_capacity)),
            #[cfg(test)]
            target_cut_computations: AtomicU64::new(0),
        }
    }

    fn ws_node_for(unified: &UnifiedAddressSpace, seg_id: SegmentId, local_node: NodeId) -> Option<WsNodeId> {
        let seg_idx = seg_id.0 as usize;
        let start = *unified.segment_bases.get(seg_idx)?;
        let end = *unified.segment_bases.get(seg_idx + 1)?;
        (local_node.0 < end.saturating_sub(start)).then(|| WsNodeId(start + local_node.0))
    }

    fn ws_nodes_for_funcs(&self, unified: &UnifiedAddressSpace, funcs: &AHashSet<FuncId>) -> Vec<NodeId> {
        let mut out = Vec::new();
        for func in funcs {
            if let Some(nodes) = unified.nodes_by_func.get(func) {
                out.extend_from_slice(nodes);
            }
        }
        out.sort_by_key(|node| node.0);
        out.dedup();
        out
    }

    fn target_func_backward_closure(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        funcs: &AHashSet<FuncId>,
        max_precision: Option<Precision>,
    ) -> Arc<NodeBitSet> {
        let key = TargetCutKey::Funcs(TargetFuncCutKey::new(max_precision, funcs));
        let cached = unified.target_backward.read().get_cell(&key);
        let cell = if let Some(hit) = cached {
            hit
        } else {
            unified.target_backward.write().get_or_insert_cell(key)
        };
        let closure = Arc::clone(cell.get_or_init(|| {
            #[cfg(test)]
            unified.target_cut_computations.fetch_add(1, Ordering::Relaxed);
            let target_nodes = self.ws_nodes_for_funcs(unified, funcs);
            Arc::new(if target_nodes.is_empty() {
                NodeBitSet::zeros(unified.reverse.len())
            } else if let Some(precision) = max_precision {
                self.ensure_precision_reach(unified, precision)
                    .backward_closure(&target_nodes)
            } else {
                self.ensure_unfiltered_reach(unified)
                    .backward_closure(&target_nodes)
            })
        }));
        unified.target_backward.write().trim_completed();
        closure
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

    fn target_nodes_backward_closure(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        nodes: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Arc<NodeBitSet> {
        let key = TargetCutKey::Nodes(TargetNodeCutKey::new(max_precision, nodes));
        let cached = unified.target_backward.read().get_cell(&key);
        let cell = if let Some(hit) = cached {
            hit
        } else {
            unified.target_backward.write().get_or_insert_cell(key)
        };
        let closure = Arc::clone(cell.get_or_init(|| {
            #[cfg(test)]
            unified.target_cut_computations.fetch_add(1, Ordering::Relaxed);
            let mut target_nodes: Vec<NodeId> = nodes.iter().map(|node| NodeId(node.0)).collect();
            target_nodes.sort_by_key(|node| node.0);
            target_nodes.dedup();
            Arc::new(if target_nodes.is_empty() {
                NodeBitSet::zeros(unified.reverse.len())
            } else if let Some(precision) = max_precision {
                self.ensure_precision_reach(unified, precision)
                    .backward_closure(&target_nodes)
            } else {
                self.ensure_unfiltered_reach(unified)
                    .backward_closure(&target_nodes)
            })
        }));
        unified.target_backward.write().trim_completed();
        closure
    }

    fn symbolic_forward_closure_nodes(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        reach: &ReachabilityIndex,
        seeds: &[NodeId],
        max_precision: Option<Precision>,
    ) -> Vec<NodeId> {
        let symbolic = self.workspace.symbolic_field();
        if symbolic.transforms().is_empty() {
            return reach.forward_closure_nodes(seeds);
        }
        let runtime = unified
            .symbolic_runtime
            .get_or_init(|| Arc::new(self.build_symbolic_runtime_index(unified)));
        let mut ordinary = Vec::with_capacity(seeds.len());
        let mut ordinary_set = AHashSet::with_capacity(seeds.len());
        for seed in seeds.iter().copied() {
            if ordinary_set.insert(seed.0) {
                ordinary.push(seed);
            }
        }
        let mut processed_nodes = NodeBitSet::zeros(unified.reverse.len());
        let mut facts = AHashSet::default();
        let mut pending_facts = Vec::new();

        loop {
            let reached = reach.forward_closure_nodes(&ordinary);
            for node in reached.iter().copied() {
                if processed_nodes.contains(node) {
                    continue;
                }
                processed_nodes.set(node);
                if let Some(node_facts) = runtime.facts_by_node.get(&WsNodeId(node.0)) {
                    for fact in node_facts.iter().copied() {
                        if facts.insert(fact) {
                            pending_facts.push(fact);
                        }
                    }
                }
            }

            let ordinary_len_before = ordinary.len();
            let mut fact_cursor = 0usize;
            while fact_cursor < pending_facts.len() {
                let fact = pending_facts[fact_cursor];
                fact_cursor += 1;
                self.seed_symbolic_fact_consumers(runtime, fact, &mut ordinary, &mut ordinary_set);
                let outgoing = symbolic.outgoing_transform_indices(fact.base);
                for transform_index in outgoing {
                    let Some(transform) = symbolic.transforms().get(*transform_index as usize) else {
                        continue;
                    };
                    if max_precision.is_some_and(|max| transform.precision > max) {
                        continue;
                    }
                    if !transform.allow_out_of_order_source
                        && !fact.interprocedural
                        && fact.span.is_some_and(|span| {
                            span.file == transform.call_span.file && span.start > transform.call_span.start
                        })
                    {
                        continue;
                    }
                    if transform.kind == SymbolicFieldTransformKind::ScalarReturn {
                        let exact_matches = transform.exact_field != NO_SYMBOLIC_STRING
                            && symbolic
                                .string(transform.exact_field)
                                .zip(runtime.field(fact.field))
                                .is_some_and(|(expected, actual)| expected == actual);
                        if exact_matches {
                            if let Some(nodes) = runtime
                                .scalar_writes
                                .get(&(transform.target, transform.write_span))
                            {
                                for node in nodes {
                                    if ordinary_set.insert(node.0) {
                                        ordinary.push(NodeId(node.0));
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    let next = SymbolicNodeFact {
                        base: transform.target,
                        field: fact.field,
                        span: Some(transform.write_span),
                        interprocedural: transform.kind != SymbolicFieldTransformKind::Copy,
                    };
                    if facts.insert(next) {
                        pending_facts.push(next);
                    }
                }
            }
            pending_facts.clear();
            if ordinary.len() == ordinary_len_before {
                bonsai_diagnostics::debug_log!(
                    "idg-closure",
                    "symbolic closure seeds={} reached={} facts={}",
                    seeds.len(),
                    reached.len(),
                    facts.len()
                );
                return reached;
            }
        }
    }

    fn seed_symbolic_fact_consumers(
        &self,
        runtime: &SymbolicRuntimeIndex,
        fact: SymbolicNodeFact,
        ordinary: &mut Vec<NodeId>,
        ordinary_set: &mut AHashSet<u32>,
    ) {
        let exact_nodes = runtime.exact_reads.get(&symbolic_fact_key(fact.base, fact.field));
        if let Some(nodes) = exact_nodes {
            for node in nodes {
                if ordinary_set.insert(node.0) {
                    ordinary.push(NodeId(node.0));
                }
            }
        }
        if let Some(nodes) = runtime.bare_reads.get(&fact.base) {
            for node in nodes {
                if ordinary_set.insert(node.0) {
                    ordinary.push(NodeId(node.0));
                }
            }
        }
    }

    fn build_symbolic_runtime_index(&self, unified: &UnifiedAddressSpace) -> SymbolicRuntimeIndex {
        let symbolic = self.workspace.symbolic_field();
        let mut out = SymbolicRuntimeIndex::default();
        for (segment_id, segment) in self.workspace.segments() {
            for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
                let Some(place) = segment.places.get(node.place) else {
                    continue;
                };
                let Some((parts, write_span, is_read)) = structured_storage_parts(segment, place) else {
                    continue;
                };
                let local = NodeId(u32::try_from(node_index).expect("segment-local node count exceeds u32"));
                let Some(ws_node) = Self::ws_node_for(unified, segment_id, local) else {
                    continue;
                };
                let full = parts.join(".");
                if let Some(base) = symbolic.base_id(segment_id, node.func, &full) {
                    if is_read {
                        out.bare_reads.entry(base).or_default().push(ws_node);
                    }
                    if let Some(span) = write_span {
                        out.scalar_writes.entry((base, span)).or_default().push(ws_node);
                    }
                }
                for split in 1..parts.len() {
                    let base_text = parts[..split].join(".");
                    let Some(base) = symbolic.base_id(segment_id, node.func, &base_text) else {
                        bonsai_diagnostics::debug_log!(
                            "idg-closure-detail",
                            "symbolic runtime misses base segment={} func={} base={} full={}",
                            segment_id.0,
                            node.func.raw(),
                            base_text,
                            full
                        );
                        continue;
                    };
                    let field_text = parts[split..].join(".");
                    let field = out.intern_field(&field_text);
                    let fact = SymbolicNodeFact {
                        base,
                        field,
                        span: write_span,
                        interprocedural: false,
                    };
                    out.facts_by_node.entry(ws_node).or_default().push(fact);
                    if is_read {
                        out.exact_reads
                            .entry(symbolic_fact_key(base, field))
                            .or_default()
                            .push(ws_node);
                    }
                }
            }
        }
        for nodes in out
            .exact_reads
            .values_mut()
            .chain(out.bare_reads.values_mut())
            .chain(out.scalar_writes.values_mut())
        {
            nodes.sort_unstable_by_key(|node| node.0);
            nodes.dedup();
        }
        for facts in out.facts_by_node.values_mut() {
            facts.sort_unstable_by_key(|fact| (fact.base, fact.field, fact.span, fact.interprocedural));
            facts.dedup();
        }
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

    fn build_reach(
        &self,
        unified: &UnifiedAddressSpace,
        max_precision: Option<Precision>,
    ) -> ReachabilityIndex {
        let mut edges: Vec<(u32, u32)> = Vec::with_capacity(self.workspace.total_edge_count());
        for (seg_id, segment) in self.workspace.segments() {
            let seg_id = SegmentId(seg_id.0);
            for edge in &segment.edges {
                if max_precision.is_some_and(|max| edge.meta.precision > max) {
                    continue;
                }
                let Some(from_ws) = Self::ws_node_for(unified, seg_id, edge.from) else {
                    continue;
                };
                let Some(to_ws) = Self::ws_node_for(unified, seg_id, edge.to) else {
                    continue;
                };
                edges.push((from_ws.0, to_ws.0));
            }
        }
        for cfe in &self.workspace.cross_file().edges {
            if max_precision.is_some_and(|max| cfe.edge.meta.precision > max) {
                continue;
            }
            let Some(from_ws) = Self::ws_node_for(unified, cfe.from_segment, cfe.edge.from) else {
                continue;
            };
            let Some(to_ws) = Self::ws_node_for(unified, cfe.to_segment, cfe.edge.to) else {
                continue;
            };
            edges.push((from_ws.0, to_ws.0));
        }
        ReachabilityIndex::from_pairs(unified.reverse.len(), &edges)
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
        for (seg_id, segment) in self.workspace.segments() {
            let seg_id = SegmentId(seg_id.0);
            for edge in &segment.edges {
                let Some(from_ws) = Self::ws_node_for(unified, seg_id, edge.from) else {
                    continue;
                };
                if let Some(row) =
                    lift_call_arg_edge(seg_id, segment, seg_id, segment, edge, &mut field_index)
                {
                    cross_calls_by_from.entry(from_ws).or_default().push(row);
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
                });
        }
        for cfe in &self.workspace.cross_file().edges {
            let Some(from_ws) = Self::ws_node_for(unified, cfe.from_segment, cfe.edge.from) else {
                continue;
            };
            let Some(from_seg) = self.workspace.segment(cfe.from_segment) else {
                continue;
            };
            let Some(to_seg) = self.workspace.segment(cfe.to_segment) else {
                continue;
            };
            if let Some(row) = lift_call_arg_edge(
                cfe.from_segment,
                from_seg,
                cfe.to_segment,
                to_seg,
                &cfe.edge,
                &mut field_index,
            ) {
                cross_calls_by_from.entry(from_ws).or_default().push(row);
            }
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
            let Some(base) = self
                .workspace
                .segment_for_func(func)
                .and_then(|seg_id| self.workspace.segment(seg_id))
                .and_then(|segment| segment.strings.get(name))
            else {
                return String::new();
            };
            if path.is_empty() {
                return base.to_string();
            }
            let mut out = base.to_string();
            if let Some(segment) = self
                .workspace
                .segment_for_func(func)
                .and_then(|seg_id| self.workspace.segment(seg_id))
            {
                for part in path {
                    if let Some(segment_part) = segment.strings.get(*part) {
                        out.push('.');
                        out.push_str(segment_part);
                    }
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
            });
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
    if edge.meta.kind == crate::edge::IdgEdgeKind::InterCallArg && from_node.func != to_node.func {
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
    if edge.meta.kind == crate::edge::IdgEdgeKind::InterReturn && from_node.func != to_node.func {
        return Some(CrossCallEdge {
            caller: from_node.func,
            callee: to_node.func,
            call_span: edge.meta.via_span,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
            precision: edge.meta.precision,
            call_kind: edge.meta.call_kind,
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

fn structured_storage_parts(
    segment: &crate::segment::IdgSegment,
    place: &Place,
) -> Option<(Vec<String>, Option<Span>, bool)> {
    let (name, path, write_span, is_read) = match place {
        Place::Read { name, path } => (*name, path, None, true),
        Place::Write { name, path, span } => (*name, path, Some(*span), false),
        _ => return None,
    };
    let mut parts = Vec::with_capacity(path.len() + 1);
    // Some older transfer paths intern an adapter-normalized dotted place in
    // the `name` slot while newer paths use `Place::path`. Both are compiler
    // dictionary forms (never raw source text), so canonicalize them here.
    parts.extend(
        segment
            .strings
            .get(name)?
            .split('.')
            .filter(|part| !part.is_empty())
            .map(ToString::to_string),
    );
    for part in path {
        parts.push(segment.strings.get(*part)?.to_string());
    }
    Some((parts, write_span, is_read))
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
