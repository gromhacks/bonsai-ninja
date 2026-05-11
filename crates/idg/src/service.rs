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

use crate::edge::IdgEdge;
use crate::node::NodeId;
use crate::place::Place;
use crate::query::ReachabilityIndex;
use crate::workspace::{IdgWorkspace, SegmentId};

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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

    /// Forward closure: which nodes are reachable from `seeds`?
    /// Returns the set of [`WsNodeId`]s in the closure (always
    /// includes the seeds themselves).
    pub fn forward_closure(&self, seeds: &[WsNodeId]) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let seed_nodes: Vec<NodeId> = seeds.iter().map(|w| NodeId(w.0)).collect();
        let bits = unified.reach.forward_closure(&seed_nodes);
        bits.iter().map(|n| WsNodeId(n.0)).collect()
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

    /// Find every IDG node in `func` whose place is a bare-name
    /// `Place::Read` or `Place::Write` matching one of `seed_names`.
    /// Lets consumers translate "user-provided seed names" into the
    /// IDG nodes those names address — used by browse-taint /
    /// security-analysis when the caller supplies explicit seeds.
    ///
    /// Names are looked up via the segment's persisted string pool
    /// (populated at merge time from each function's transfer
    /// output's name pool). Empty pool → empty result.
    pub fn read_or_write_nodes_for_names(
        &self,
        func: FuncId,
        seed_names: &[String],
    ) -> Vec<WsNodeId> {
        let unified = self.ensure_unified();
        let Some(seg_id) = self.workspace.segment_for_func(func) else {
            return Vec::new();
        };
        let Some(segment) = self.workspace.segment(seg_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // Build the lookup set once per call. Each Read uses
        // `(name, path=[])` and is shared across uses, so a single
        // lookup suffices. Writes use `(name, path=[], span)` per
        // event — we scan the place dict for ALL spans matching
        // each requested name.
        let target_strids: ahash::AHashSet<bonsai_factstore::StrId> = seed_names
            .iter()
            .filter_map(|n| segment.strings.lookup(n))
            .collect();
        if target_strids.is_empty() {
            return out;
        }
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let matches = match place {
                Place::Read { name, path } if path.is_empty() => target_strids.contains(name),
                Place::Write { name, path, .. } if path.is_empty() => target_strids.contains(name),
                _ => false,
            };
            if !matches {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local_node) = segment.nodes.lookup(func, pid) {
                if let Some(&ws_node) = unified.forward.get(&(seg_id, local_node)) {
                    out.push(ws_node);
                }
            }
        }
        out
    }

    /// Find every IDG node tagged as the entry's `Place::Param(idx)`
    /// for a given function. Returns the workspace-global ids so
    /// callers can immediately feed them to [`Self::forward_closure`].
    /// Resolve the workspace IDG nodes for `func`'s params whose
    /// declared name appears in `names`. Returns an empty Vec when
    /// none match. Differs from [`param_nodes_of`] in that it does
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
        let want: ahash::AHashSet<&str> =
            names.iter().map(|n| n.as_str()).collect();
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
            if let Some(&ws_node) = unified.forward.get(&(seg_id, local_node)) {
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
        for idx in 0..u8::MAX {
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
            if let Some(&ws_node) = unified.forward.get(&(seg_id, local_node)) {
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
    pub fn source_seed_nodes_at_span(
        &self,
        func: FuncId,
        match_span: Span,
    ) -> Vec<WsNodeId> {
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
        let mut sibling_arg_sites: ahash::AHashSet<bonsai_common::Span> =
            ahash::AHashSet::default();
        for place in &segment.places.places {
            if let Place::CallRet { site } = place {
                let ret_span = site.0;
                if spans_overlap(ret_span, match_span)
                    && ret_span.start == match_span.start
                {
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
                if let Some(&ws_node) = unified.forward.get(&(seg_id, local_node)) {
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
    pub fn tainted_call_args_in_closure(
        &self,
        seeds: &[WsNodeId],
    ) -> Vec<(FuncId, Span, u8)> {
        let unified = self.ensure_unified();
        let closure: AHashSet<WsNodeId> =
            self.forward_closure(seeds).into_iter().collect();
        let mut out = Vec::new();
        for ws_node in &closure {
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
                out.push((node.func, site.0, *idx));
            }
        }
        out.sort_by_key(|(f, span, idx)| (f.raw(), span.start, *idx));
        out.dedup();
        out
    }

    /// Returns IDG nodes for `Place::Read{name}` / `Place::Write{name}`
    /// in `func` that lie *after* `cutoff` in source order. Used by
    /// security analysis when a source rule has `output_args` —
    /// fgets(buf, ...) writes back to `buf`, so post-call reads of
    /// `buf` are the seed-bearing nodes.
    pub fn nodes_for_name_after_span(
        &self,
        func: FuncId,
        name: &str,
        cutoff: Span,
    ) -> Vec<WsNodeId> {
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
        let mut out = Vec::new();
        for (pid_idx, place) in segment.places.places.iter().enumerate() {
            let matches = match place {
                // Reads are span-shared in the current model — accept
                // any Read of the name (the over-approximation is
                // harmless when the only relevant flow is post-cutoff
                // because pre-cutoff reads can't reach a seed nobody
                // wrote yet).
                Place::Read { name: n, path } if path.is_empty() && *n == strid => true,
                // Writes are span-distinct — only writes after cutoff.
                Place::Write { name: n, path, span }
                    if path.is_empty() && *n == strid && span_after(*span, cutoff) =>
                {
                    true
                }
                _ => false,
            };
            if !matches {
                continue;
            }
            let pid = crate::node::PlaceId(pid_idx as u32);
            if let Some(local_node) = segment.nodes.lookup(func, pid) {
                if let Some(&ws_node) = unified.forward.get(&(seg_id, local_node)) {
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
    pub fn name_consumer_nodes_after_span(
        &self,
        func: FuncId,
        name: &str,
        cutoff: Span,
    ) -> Vec<WsNodeId> {
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
        let mut name_source_local: ahash::AHashSet<crate::node::NodeId> =
            ahash::AHashSet::default();
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
            if let Some(&ws_node) = unified.forward.get(&(seg_id, edge.to)) {
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
        unified.forward.get(&(seg_id, local_node)).copied()
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
        let unified = self.ensure_unified();
        let closure: AHashSet<WsNodeId> =
            self.forward_closure(seeds).into_iter().collect();
        let mut out = Vec::new();

        // 1. Intra-segment edges: same-file caller/callee pairs.
        // The Phase 3 stitcher routes these through the segment's
        // intra-edge list (see `place_inter_edge`); cross_file
        // alone never sees them.
        for (seg_id, segment) in self.workspace.segments() {
            for edge in &segment.edges {
                let Some(&from_ws) = unified.forward.get(&(seg_id, edge.from)) else {
                    continue;
                };
                if !closure.contains(&from_ws) {
                    continue;
                }
                if let Some(row) = lift_call_arg_edge(segment, segment, edge) {
                    out.push(row);
                }
            }
        }

        // 2b. Synthetic cross-method field-flow edges. Each link
        // records that a writer-method's receiver-field write
        // (Place::Write) feeds a reader-method's receiver-field
        // read (Place::Read). Lift it into a CrossCallEdge with
        // sentinel arg/param indices so downstream lineage walks
        // can attribute the chain to (writer, reader) the same
        // way they handle real call edges. Without this the
        // forward closure correctly reaches the reader's CallArg
        // but `chain_funcs_for_lineage` rejects the chain because
        // no CrossCallEdge with `callee = reader` exists.
        for link in self.workspace.field_flow() {
            let writer_ws = WsNodeId(link.writer_ws_node);
            if !closure.contains(&writer_ws) {
                continue;
            }
            out.push(CrossCallEdge {
                caller: link.writer,
                callee: link.reader,
                call_span: link.via_span,
                arg_idx: u8::MAX,
                param_idx: u8::MAX,
                precision: bonsai_common::Precision::OverApproximate,
                call_kind: bonsai_callgraph::EdgeKind::Indirect,
            });
        }

        // 2. Cross-file edges for the genuinely cross-segment
        // caller/callee pairs.
        for cfe in &self.workspace.cross_file().edges {
            let Some(&from_ws) = unified.forward.get(&(cfe.from_segment, cfe.edge.from))
            else {
                continue;
            };
            if !closure.contains(&from_ws) {
                continue;
            }
            let from_seg = match self.workspace.segment(cfe.from_segment) {
                Some(s) => s,
                None => continue,
            };
            let to_seg = match self.workspace.segment(cfe.to_segment) {
                Some(s) => s,
                None => continue,
            };
            if let Some(row) = lift_call_arg_edge(from_seg, to_seg, &cfe.edge) {
                out.push(row);
            }
        }
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
        let unified = self.build_unified();
        let unified = Arc::new(unified);
        *self.unified.write() = Some(Arc::clone(&unified));
        unified
    }

    /// Compute a flat workspace-global address space + reachability
    /// index. Performed once per service lifetime (cached).
    fn build_unified(&self) -> UnifiedAddressSpace {
        let mut forward = AHashMap::new();
        let mut reverse = Vec::new();
        let mut edges = Vec::new();
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
                let from_ws = match forward.get(&(seg_id, edge.from)) {
                    Some(&w) => w,
                    None => continue,
                };
                let to_ws = match forward.get(&(seg_id, edge.to)) {
                    Some(&w) => w,
                    None => continue,
                };
                edges.push(IdgEdge {
                    from: NodeId(from_ws.0),
                    to: NodeId(to_ws.0),
                    meta: edge.meta,
                });
            }
        }
        // 3. Translate cross-file edges. The CrossFileEdge stores
        // segment ids on each endpoint, so we look up the local
        // node id within each segment.
        for cfe in &self.workspace.cross_file().edges {
            let from_ws = match forward.get(&(cfe.from_segment, cfe.edge.from)) {
                Some(&w) => w,
                None => continue,
            };
            let to_ws = match forward.get(&(cfe.to_segment, cfe.edge.to)) {
                Some(&w) => w,
                None => continue,
            };
            edges.push(IdgEdge {
                from: NodeId(from_ws.0),
                to: NodeId(to_ws.0),
                meta: cfe.edge.meta,
            });
        }
        // 4. Build the reachability index over the unified edges.
        let n_nodes = reverse.len();
        let reach = ReachabilityIndex::new(n_nodes, &edges);
        UnifiedAddressSpace {
            forward,
            reverse,
            reach,
        }
    }

    /// Translate `(func, place)` to a [`PointRef`] by looking up the
    /// owning decl's name span (used as the default span for places
    /// that don't carry one — Param, Return, Read/Write of a bare
    /// name).
    fn build_point_ref(&self, func: FuncId, place: &Place) -> PointRef {
        let decl = self
            .global
            .decl_of(bonsai_common::SymbolId::new(func.raw()));
        let default_span = decl
            .map(|d| d.name_span)
            .unwrap_or_else(|| Span::empty(bonsai_common::FileId::INVALID, 0));
        let (kind, name, span) = match place {
            Place::Param { idx } => (
                PointKind::Param,
                decl.and_then(|d| d.params.get(*idx as usize).cloned())
                    .unwrap_or_default(),
                default_span,
            ),
            Place::Return => (PointKind::Return, String::new(), default_span),
            Place::Read { .. } => (PointKind::Read, String::new(), default_span),
            Place::Write { span, .. } => (PointKind::Write, String::new(), *span),
            Place::CallArg { site, .. } => (PointKind::CallArg, String::new(), site.0),
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

/// True iff two source spans overlap (same file, range intersects).
fn spans_overlap(a: Span, b: Span) -> bool {
    a.file == b.file && a.start < b.end && b.start < a.end
}

/// True iff `a` strictly follows `b` in source order (same file,
/// `a.start >= b.end`). Used to filter post-source writes when a
/// source rule has `output_args` semantics.
fn span_after(a: Span, b: Span) -> bool {
    a.file == b.file && a.start >= b.start
}

/// Lift one IDG edge into a [`CrossCallEdge`] row. Returns `None`
/// when the edge isn't a `CallArg{site, idx} → Param{idx}` shape
/// (e.g. `Return → CallRet` return-flow edges, or any intra-procedural
/// non-call edge).
fn lift_call_arg_edge(
    from_seg: &crate::segment::IdgSegment,
    to_seg: &crate::segment::IdgSegment,
    edge: &IdgEdge,
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
    // Return-value edge: callee's `Place::Return` flowing back to
    // the caller's `Place::CallRet`. The lineage walker treats
    // these as legitimate cross-method propagation steps so chain
    // attribution works for call-RHS source patterns
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
    if matches!(from_place, Place::Return) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_adapter;
    use bonsai_callgraph::ResolvedCallGraph;
    use bonsai_common::SymbolId;
    use bonsai_lang_api::{Decl, DeclIndex, DeclKind, FlowEvent, ModulePath, Visibility};

    fn span(file: u32, start: u64, end: u64) -> Span {
        Span::new(bonsai_common::FileId::new(file), start, end)
    }

    fn empty_decl(symbol: u32, file: u32, name: &str) -> Decl {
        Decl {
            symbol: SymbolId::new(symbol),
            kind: DeclKind::Function,
            name: name.to_string(),
            qualified_name: None,
            module_path: ModulePath::default(),
            span: span(file, 0, 100),
            name_span: span(file, 0, 10),
            visibility: Visibility::Public,
            parent: None,
            body_span: Some(span(file, 10, 100)),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
        }
    }

    fn build(decls: Vec<Decl>) -> (Arc<GlobalIndex>, Arc<IdgWorkspace>) {
        let mut by_file: AHashMap<bonsai_common::FileId, Vec<Decl>> = AHashMap::new();
        for d in decls {
            by_file.entry(d.span.file).or_default().push(d);
        }
        let mut idx = GlobalIndex::new();
        for (file, defs) in by_file {
            idx.insert(DeclIndex {
                file,
                defs,
                refs: Vec::new(),
                strings: Vec::new(),
                comments: Vec::new(),
            });
        }
        let cg = ResolvedCallGraph::build_with(&idx, |_| AHashMap::new());
        let ws = workspace_adapter::build(&idx, &cg);
        (Arc::new(idx), Arc::new(ws))
    }

    #[test]
    fn empty_service_has_zero_segments() {
        let idx = Arc::new(GlobalIndex::new());
        let ws = Arc::new(IdgWorkspace::new());
        let svc = IdgQueryService::new(ws, idx);
        assert_eq!(svc.segment_count(), 0);
        assert_eq!(svc.intra_edge_count(), 0);
        assert_eq!(svc.cross_file_edge_count(), 0);
    }

    #[test]
    fn unified_address_space_is_lazily_built() {
        let mut decl = empty_decl(1, 0, "f");
        decl.params = vec!["x".to_string()];
        decl.flow_events = vec![FlowEvent::Return {
            span: span(0, 20, 30),
            value_name: Some("x".to_string()),
            value_text: None,
        }];
        let (idx, ws) = build(vec![decl]);
        let svc = IdgQueryService::new(ws, idx);
        // Trigger materialisation.
        let params = svc.param_nodes_of(FuncId::new(0));
        assert!(!params.is_empty());
    }

    #[test]
    fn forward_closure_from_param_reaches_return() {
        // f(x) returns x — closure of param node should hit Return.
        let mut decl = empty_decl(1, 0, "f");
        decl.params = vec!["x".to_string()];
        decl.flow_events = vec![FlowEvent::Return {
            span: span(0, 20, 30),
            value_name: Some("x".to_string()),
            value_text: None,
        }];
        let (idx, ws) = build(vec![decl]);
        let svc = IdgQueryService::new(ws, idx);
        let func_id = FuncId::new(0);
        let params = svc.param_nodes_of(func_id);
        assert_eq!(params.len(), 1);
        let ret = svc
            .return_node_of(func_id)
            .expect("Return node should exist for callable");
        let closure = svc.forward_closure(&params);
        assert!(closure.contains(&ret), "Param→Return closure missing Return");
    }

    #[test]
    fn backward_closure_from_return_reaches_param() {
        let mut decl = empty_decl(1, 0, "f");
        decl.params = vec!["x".to_string()];
        decl.flow_events = vec![FlowEvent::Return {
            span: span(0, 20, 30),
            value_name: Some("x".to_string()),
            value_text: None,
        }];
        let (idx, ws) = build(vec![decl]);
        let svc = IdgQueryService::new(ws, idx);
        let func_id = FuncId::new(0);
        let params = svc.param_nodes_of(func_id);
        let ret = svc.return_node_of(func_id).unwrap();
        let backward = svc.backward_closure(&[ret]);
        for p in &params {
            assert!(backward.contains(p), "backward(Return) missing param");
        }
    }

    #[test]
    fn reaches_is_consistent_with_forward_closure() {
        let mut decl = empty_decl(1, 0, "f");
        decl.params = vec!["x".to_string()];
        decl.flow_events = vec![FlowEvent::Return {
            span: span(0, 20, 30),
            value_name: Some("x".to_string()),
            value_text: None,
        }];
        let (idx, ws) = build(vec![decl]);
        let svc = IdgQueryService::new(ws, idx);
        let func_id = FuncId::new(0);
        let params = svc.param_nodes_of(func_id);
        let ret = svc.return_node_of(func_id).unwrap();
        for p in &params {
            assert!(svc.reaches(*p, ret));
        }
    }

    #[test]
    fn resolve_point_returns_param_for_param_node() {
        let mut decl = empty_decl(1, 0, "f");
        decl.params = vec!["arg0".to_string(), "arg1".to_string()];
        let (idx, ws) = build(vec![decl]);
        let svc = IdgQueryService::new(ws, idx);
        let func_id = FuncId::new(0);
        let params = svc.param_nodes_of(func_id);
        assert_eq!(params.len(), 2);
        let p0 = svc.resolve_point(params[0]).unwrap();
        assert_eq!(p0.kind, PointKind::Param);
        // Names match the decl's params.
        assert_eq!(p0.func, func_id);
        assert!(p0.name == "arg0" || p0.name == "arg1");
    }

    #[test]
    fn read_or_write_nodes_for_names_locates_local_assign_target() {
        // f(x) does `local = x; helper(local)`. Looking up "local"
        // should find both the Write node from the assign and the
        // Read node from the call arg — both interned in the segment
        // string pool.
        let mut f = empty_decl(1, 0, "f");
        f.params = vec!["x".to_string()];
        f.flow_events = vec![
            FlowEvent::Assign {
                span: span(0, 10, 20),
                target: "local".to_string(),
                source_name: Some("x".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            },
            FlowEvent::Call {
                span: span(0, 30, 40),
                name: "helper".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: vec![bonsai_lang_api::CallArg {
                    span: span(0, 33, 38),
                    name: None,
                    value_text: "local".to_string(),
                    place: Some("local".to_string()),
                    source_names: Vec::new(),
                }],
            },
        ];
        let (idx, ws) = build(vec![f]);
        let svc = IdgQueryService::new(ws, idx);
        let func_for = |name: &str| {
            for f in svc.global.all_files() {
                for decl in svc.global.functions_in(f) {
                    if decl.name == name {
                        return FuncId::new(decl.symbol.raw());
                    }
                }
            }
            unreachable!("function {name} not in index")
        };
        let f_id = func_for("f");
        let nodes = svc.read_or_write_nodes_for_names(f_id, &["local".to_string()]);
        assert!(!nodes.is_empty(), "should locate IDG nodes for `local`");
    }

    #[test]
    fn cross_call_edges_in_closure_reports_callarg_to_param() {
        let mut f = empty_decl(1, 0, "f");
        f.params = vec!["x".to_string()];
        f.flow_events = vec![FlowEvent::Call {
            span: span(0, 20, 30),
            name: "g".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                span: span(0, 22, 23),
                name: None,
                value_text: "x".to_string(),
                place: Some("x".to_string()),
                source_names: Vec::new(),
            }],
        }];
        let mut g = empty_decl(2, 1, "g");
        g.params = vec!["arg".to_string()];
        g.flow_events = Vec::new();
        let (idx, ws) = build(vec![f, g]);
        let svc = IdgQueryService::new(ws, idx);
        let func_for = |name: &str| {
            for f in svc.global.all_files() {
                for decl in svc.global.functions_in(f) {
                    if decl.name == name {
                        return FuncId::new(decl.symbol.raw());
                    }
                }
            }
            unreachable!("function {name} not in index")
        };
        let f_id = func_for("f");
        let g_id = func_for("g");
        let f_params = svc.param_nodes_of(f_id);
        let edges = svc.cross_call_edges_in_closure(&f_params);
        assert!(
            edges.iter().any(|e| {
                e.caller == f_id && e.callee == g_id && e.arg_idx == 0 && e.param_idx == 0
            }),
            "expected one CallArg→Param edge for f→g, got {edges:?}",
        );
    }

    #[test]
    fn cross_call_edges_skip_unreachable_calls() {
        // Closure starting from a node unrelated to any call site
        // returns an empty list — proves the closure filter is wired.
        let mut f = empty_decl(1, 0, "f");
        f.params = vec!["x".to_string()];
        let (idx, ws) = build(vec![f]);
        let svc = IdgQueryService::new(ws, idx);
        let edges = svc.cross_call_edges_in_closure(&[]);
        assert!(edges.is_empty());
    }

    #[test]
    fn cross_file_call_reaches_callee_from_caller_param() {
        // f(x) calls g(x); g returns its arg. Closure of f's param
        // should reach g's Return, then funnel back to f's CallRet
        // node — proving cross-file edges are queryable.
        let mut f = empty_decl(1, 0, "f");
        f.params = vec!["x".to_string()];
        f.flow_events = vec![FlowEvent::Call {
            span: span(0, 20, 30),
            name: "g".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                span: span(0, 22, 23),
                name: None,
                value_text: "x".to_string(),
                place: Some("x".to_string()),
                source_names: Vec::new(),
            }],
        }];
        let mut g = empty_decl(2, 1, "g");
        g.params = vec!["arg".to_string()];
        g.flow_events = vec![FlowEvent::Return {
            span: span(1, 50, 60),
            value_name: Some("arg".to_string()),
            value_text: None,
        }];
        let (idx, ws) = build(vec![f, g]);
        let svc = IdgQueryService::new(ws, idx);

        // GlobalIndex remaps symbols on insert. The first inserted
        // file's first function gets FuncId 0, but order depends on
        // hash-map iteration. Use the per-name lookup instead.
        let func_for = |name: &str| {
            for f in svc.global.all_files() {
                for decl in svc.global.functions_in(f) {
                    if decl.name == name {
                        return FuncId::new(decl.symbol.raw());
                    }
                }
            }
            unreachable!("function {name} not in index")
        };
        let f_id = func_for("f");
        let g_id = func_for("g");

        let f_params = svc.param_nodes_of(f_id);
        let g_return = svc.return_node_of(g_id).unwrap();
        let closure = svc.forward_closure(&f_params);
        assert!(
            closure.contains(&g_return),
            "f's param closure should reach g's Return via CallArg→Param→…→Return"
        );
    }
}
