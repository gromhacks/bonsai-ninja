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
use std::sync::Arc;

use crate::bitset::NodeBitSet;
use crate::edge::IdgEdge;
use crate::node::NodeId;
use crate::place::Place;
use crate::query::ReachabilityIndex;
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
    pub arg_idx: u8,
    /// 0-based positional index of the parameter in the callee.
    pub param_idx: u8,
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
    /// `(seg, local_node) → ws_node`.
    forward: AHashMap<(SegmentId, NodeId), WsNodeId>,
    /// `ws_node → (seg, local_node)`. Vec-indexed by ws node raw.
    reverse: Vec<(SegmentId, NodeId)>,
    /// Reachability index over the unified edge set.
    reach: ReachabilityIndex,
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
    /// Backward closures from sink target function sets. Large Java
    /// scans often have many controllers feeding the same sink-bearing
    /// helper; caching the sink side keeps each source query from
    /// walking the same reverse graph again.
    target_func_backward: RwLock<AHashMap<TargetFuncCutKey, Arc<NodeBitSet>>>,
    /// Backward closures from concrete sink target node sets. This is
    /// stricter than `target_func_backward` for same-function or
    /// module-pseudo-function scans where many source calls share an
    /// enclosing function but only a few can reach a real sink site.
    target_node_backward: RwLock<AHashMap<TargetNodeCutKey, Arc<NodeBitSet>>>,
}

type CrossCallsByFrom = AHashMap<WsNodeId, Vec<CrossCallEdge>>;

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
}

impl IdgQueryService {
    /// Wrap a workspace + global index. The unified address space
    /// is **not** built here — it's deferred to first query.
    #[must_use]
    pub fn new(workspace: Arc<IdgWorkspace>, global: Arc<GlobalIndex>) -> Self {
        Self {
            workspace,
            global,
            unified: RwLock::new(None),
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
        let bits = unified.reach.forward_closure(&seed_nodes);
        bits.iter().map(|n| WsNodeId(n.0)).collect()
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
        reach
            .forward_closure_nodes(&seed_nodes)
            .into_iter()
            .map(|n| WsNodeId(n.0))
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
        let mut cut = if let Some(precision) = max_precision {
            self.ensure_precision_reach(&unified, precision)
                .forward_closure(&seed_nodes)
        } else {
            unified.reach.forward_closure(&seed_nodes)
        };
        cut.intersect_inplace(&backward);
        cut.iter().map(|node| WsNodeId(node.0)).collect()
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
        let mut cut = if let Some(precision) = max_precision {
            self.ensure_precision_reach(&unified, precision)
                .forward_closure(&seed_nodes)
        } else {
            unified.reach.forward_closure(&seed_nodes)
        };
        cut.intersect_inplace(&backward);
        cut.iter().map(|node| WsNodeId(node.0)).collect()
    }

    /// Backward closure: which nodes flow *into* `targets`?
    pub fn backward_closure(&self, targets: &[WsNodeId]) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let target_nodes: Vec<NodeId> = targets.iter().map(|w| NodeId(w.0)).collect();
        let bits = unified.reach.backward_closure(&target_nodes);
        bits.iter().map(|n| WsNodeId(n.0)).collect()
    }

    /// Does any path lead from `from` to `to`?
    #[must_use]
    pub fn reaches(&self, from: WsNodeId, to: WsNodeId) -> bool {
        let unified = self.ensure_unified();
        unified.reach.reaches(NodeId(from.0), NodeId(to.0))
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
        let mut exact_flat_paths: AHashSet<String> = AHashSet::new();
        let mut exact_paths: Vec<(bonsai_factstore::StrId, Vec<bonsai_factstore::StrId>)> = Vec::new();
        for seed in seed_names {
            let seed = seed.trim();
            if seed.is_empty() {
                continue;
            }
            if let Some(base) = seed.strip_suffix(".*") {
                let base = base.trim();
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
            let Ok(b) = u8::try_from(idx) else { continue };
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
        let mut out = Vec::new();
        // Inclusive of 255: `Place::Param { idx: 255 }` is a legitimate
        // (256th) param slot. The break-on-miss below still terminates early
        // for the normal case of a handful of params.
        for idx in 0..=u8::MAX {
            let place = Place::Param { idx };
            let Some(pid) = segment.places.lookup(&place) else {
                if idx == 0 {
                    // No params at all.
                    return out;
                }
                break;
            };
            let Some(local_node) = segment.nodes.lookup(func, pid) else {
                break;
            };
            if let Some(ws_node) = Self::ws_node_for(&unified, seg_id, local_node) {
                out.push(ws_node);
            }
        }
        out
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
        // forward closure reaches the return / sink argument. Purely
        // additive (only runs when the span loop produced no seed), so
        // it cannot perturb sources that already anchor on a span node.
        if out.is_empty() {
            for edge in &segment.edges {
                if !spans_overlap(edge.meta.via_span, match_span) {
                    continue;
                }
                if segment.nodes.get(edge.from).is_none_or(|node| node.func != func) {
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
    pub fn tainted_call_args_in_closure(&self, seeds: &[WsNodeId]) -> Vec<(FuncId, Span, u8)> {
        self.tainted_call_args_in_closure_with_max_precision(seeds, Some(SEMANTIC_MAX_PRECISION))
    }

    /// Same as [`Self::tainted_call_args_in_closure`], but computes
    /// the seed closure inside a precision scope.
    pub fn tainted_call_args_in_closure_with_max_precision(
        &self,
        seeds: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Vec<(FuncId, Span, u8)> {
        let closure = self.forward_closure_with_max_precision(seeds, max_precision);
        self.tainted_call_args_in_reachable_nodes(&closure)
    }

    /// Same as [`Self::tainted_call_args_in_closure`], but consumes a
    /// closure the caller already computed. Exact source graph
    /// construction needs several views over the same reachability
    /// set; accepting the closure avoids re-running the bitvector
    /// fixpoint for every view.
    pub fn tainted_call_args_in_reachable_nodes(&self, closure: &[WsNodeId]) -> Vec<(FuncId, Span, u8)> {
        self.tainted_call_args_in_reachable_nodes_for_funcs(closure, None)
    }

    /// Same as [`Self::tainted_call_args_in_reachable_nodes`], but keeps
    /// only call sites owned by `target_funcs` when a filter is supplied.
    pub fn tainted_call_args_in_reachable_nodes_for_funcs(
        &self,
        closure: &[WsNodeId],
        target_funcs: Option<&AHashSet<FuncId>>,
    ) -> Vec<(FuncId, Span, u8)> {
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
        let unified = self.ensure_unified();
        let cross_calls_by_from = self.ensure_cross_calls_by_from(&unified);
        let mut out = Vec::new();
        for rows in cross_calls_by_from.values() {
            for row in rows {
                if max_precision.is_some_and(|precision| row.precision > precision) {
                    continue;
                }
                out.push((row.caller, row.callee));
            }
        }
        out.sort_by_key(|(caller, callee)| (caller.raw(), callee.raw()));
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

    /// Compute a flat workspace-global address space + reachability
    /// index. Performed once per service lifetime (cached).
    fn build_unified(&self) -> UnifiedAddressSpace {
        let mut forward = AHashMap::new();
        let mut reverse = Vec::new();
        let mut edges: Vec<(u32, u32)> = Vec::with_capacity(self.workspace.total_edge_count());
        // 1. Allocate a workspace-global id for every segment-local
        // node. Stable order: iterate segments by SegmentId, then
        // local node id ascending. That guarantees deterministic ws
        // node ids for repeated builds (important for snapshot tests).
        for (seg_id, segment) in self.workspace.segments() {
            let seg_idx = seg_id.0 as usize;
            let seg_id = SegmentId(seg_idx as u32);
            for local_idx in 0..segment.nodes.len() {
                let local_node = NodeId(local_idx as u32);
                let ws_id = WsNodeId(reverse.len() as u32);
                forward.insert((seg_id, local_node), ws_id);
                reverse.push((seg_id, local_node));
            }
        }
        // 2. Translate every intra-segment edge to ws coords.
        for (seg_id, segment) in self.workspace.segments() {
            let seg_idx = seg_id.0 as usize;
            let seg_id = SegmentId(seg_idx as u32);
            for edge in &segment.edges {
                let Some(&from_ws) = forward.get(&(seg_id, edge.from)) else {
                    continue;
                };
                let Some(&to_ws) = forward.get(&(seg_id, edge.to)) else {
                    continue;
                };
                edges.push((from_ws.0, to_ws.0));
            }
        }
        // 3. Translate cross-file edges. The CrossFileEdge stores
        // segment ids on each endpoint, so we look up the local
        // node id within each segment.
        for cfe in &self.workspace.cross_file().edges {
            let Some(&from_ws) = forward.get(&(cfe.from_segment, cfe.edge.from)) else {
                continue;
            };
            let Some(&to_ws) = forward.get(&(cfe.to_segment, cfe.edge.to)) else {
                continue;
            };
            edges.push((from_ws.0, to_ws.0));
        }
        // 4. Build the reachability index over the unified edges.
        let n_nodes = reverse.len();
        let reach = ReachabilityIndex::from_pairs(n_nodes, &edges);
        UnifiedAddressSpace {
            forward,
            reverse,
            reach,
            precision_reach: RwLock::new(AHashMap::new()),
            cross_calls_by_from: RwLock::new(None),
            target_func_backward: RwLock::new(AHashMap::new()),
            target_node_backward: RwLock::new(AHashMap::new()),
        }
    }

    fn ws_node_for(unified: &UnifiedAddressSpace, seg_id: SegmentId, local_node: NodeId) -> Option<WsNodeId> {
        unified.forward.get(&(seg_id, local_node)).copied()
    }

    fn ws_nodes_for_funcs(&self, unified: &UnifiedAddressSpace, funcs: &AHashSet<FuncId>) -> Vec<NodeId> {
        let mut out = Vec::new();
        for func in funcs {
            let Some(seg_id) = self.workspace.segment_for_func(*func) else {
                continue;
            };
            let Some(segment) = self.workspace.segment(seg_id) else {
                continue;
            };
            for (idx, node) in segment.nodes.nodes.iter().enumerate() {
                if node.func != *func {
                    continue;
                }
                let local = NodeId(idx as u32);
                if let Some(ws_node) = Self::ws_node_for(unified, seg_id, local) {
                    out.push(NodeId(ws_node.0));
                }
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
        let key = TargetFuncCutKey::new(max_precision, funcs);
        if let Some(hit) = unified.target_func_backward.read().get(&key).cloned() {
            return hit;
        }
        let target_nodes = self.ws_nodes_for_funcs(unified, funcs);
        let computed = if target_nodes.is_empty() {
            NodeBitSet::zeros(unified.reverse.len())
        } else if let Some(precision) = max_precision {
            self.ensure_precision_reach(unified, precision)
                .backward_closure(&target_nodes)
        } else {
            unified.reach.backward_closure(&target_nodes)
        };
        let computed = Arc::new(computed);
        let mut write = unified.target_func_backward.write();
        write.entry(key).or_insert(computed).clone()
    }

    fn target_nodes_backward_closure(
        &self,
        unified: &Arc<UnifiedAddressSpace>,
        nodes: &[WsNodeId],
        max_precision: Option<Precision>,
    ) -> Arc<NodeBitSet> {
        let key = TargetNodeCutKey::new(max_precision, nodes);
        if let Some(hit) = unified.target_node_backward.read().get(&key).cloned() {
            return hit;
        }
        let mut target_nodes: Vec<NodeId> = nodes.iter().map(|node| NodeId(node.0)).collect();
        target_nodes.sort_by_key(|node| node.0);
        target_nodes.dedup();
        let computed = if target_nodes.is_empty() {
            NodeBitSet::zeros(unified.reverse.len())
        } else if let Some(precision) = max_precision {
            self.ensure_precision_reach(unified, precision)
                .backward_closure(&target_nodes)
        } else {
            unified.reach.backward_closure(&target_nodes)
        };
        let computed = Arc::new(computed);
        let mut write = unified.target_node_backward.write();
        write.entry(key).or_insert(computed).clone()
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
        let reach = Arc::new(self.build_precision_reach(unified, max_precision));
        write.insert(max_precision, Arc::clone(&reach));
        reach
    }

    fn build_precision_reach(
        &self,
        unified: &UnifiedAddressSpace,
        max_precision: Precision,
    ) -> ReachabilityIndex {
        let mut edges: Vec<(u32, u32)> = Vec::with_capacity(self.workspace.total_edge_count());
        for (seg_id, segment) in self.workspace.segments() {
            let seg_id = SegmentId(seg_id.0);
            for edge in &segment.edges {
                if edge.meta.precision > max_precision {
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
            if cfe.edge.meta.precision > max_precision {
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
                    arg_idx: u8::MAX,
                    param_idx: u8::MAX,
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
        .unwrap_or((u8::MAX, u8::MAX));
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
    // Return-value edge: callee's `Place::Return` or generator
    // `Place::Yield` flowing back to the caller's `Place::CallRet`.
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
    // `arg_idx = u8::MAX` / `param_idx = u8::MAX` distinguishes
    // the synthetic return row from real positional-arg edges.
    if matches!(from_place, Place::Return | Place::Yield) {
        if let Place::CallRet { site } = to_place {
            return Some(CrossCallEdge {
                caller: from_node.func,
                callee: to_node.func,
                call_span: site.0,
                arg_idx: u8::MAX,
                param_idx: u8::MAX,
                precision: edge.meta.precision,
                call_kind: edge.meta.call_kind,
            });
        }
    }
    None
}

#[derive(Default)]
struct FieldCrossCallIndex {
    call_arg: AHashMap<(SegmentId, FuncId, Span, String), Option<u8>>,
    param: AHashMap<(SegmentId, FuncId, String), Option<u8>>,
}

impl FieldCrossCallIndex {
    fn call_arg_index(
        &mut self,
        segment_id: SegmentId,
        segment: &crate::segment::IdgSegment,
        caller: FuncId,
        call_span: Span,
        base: &str,
    ) -> Option<u8> {
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
    ) -> Option<u8> {
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
) -> Option<(u8, u8)> {
    let from_base = storage_base_from_place(from_seg, from_place)?;
    let to_base = storage_base_from_place(to_seg, to_place)?;
    let arg_idx = field_index
        .call_arg_index(from_seg_id, from_seg, caller, call_span, &from_base)
        .unwrap_or(u8::MAX);
    let param_idx = field_index
        .param_index(to_seg_id, to_seg, callee, &to_base)
        .unwrap_or(u8::MAX);
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
) -> Option<u8> {
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
            best = Some(best.map_or(*idx, |existing: u8| existing.min(*idx)));
        }
    }
    best
}

fn param_index_for_storage_base(
    segment: &crate::segment::IdgSegment,
    callee: FuncId,
    base: &str,
) -> Option<u8> {
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
            best = Some(best.map_or(*idx, |existing: u8| existing.min(*idx)));
        }
    }
    best
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
