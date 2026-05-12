//! Phase 3: stitch per-function transfer outputs into a workspace
//! IDG, resolving call sites against a [`CalleeResolver`].
//!
//! The builder is decoupled from the actual `ResolvedCallGraph` via
//! the [`CalleeResolver`] trait so this crate is testable without
//! the workspace heavy machinery. The workspace adapter (the
//! `bonsai_workspace` crate) implements the trait against its
//! `ResolvedCallGraph`; tests here use simple mock resolvers.
//!
//! ## Stitching algorithm
//!
//! For each function's [`TransferOutput`]:
//!
//! 1. **Append intra-edges** to the segment that owns this
//!    function's source file.
//! 2. **Stitch each call site**: for every callee resolved at the
//!    site, emit
//!    - `caller.CallArg(site, i) → callee.Param(i)` per arg index
//!      `i ∈ [0, args_count)`
//!    - `callee.Return → caller.CallRet(site)`
//!
//!    Same-segment edges go in the segment's intra list; different-
//!    segment edges go in the workspace cross-file index.
//! 3. **Stitch each throw site**: for every callee whose recorded
//!    throw type matches a `Try::catch_types` in any caller (we
//!    don't have caller-context here — that's a Phase 3 extension
//!    when the workspace builder feeds calling-context throws), add
//!    `callee.Throw(ty) → caller.Catch(ty)`. The current builder
//!    handles intra-function throw/catch (already done in Phase 2);
//!    cross-function throw/catch is left for the workspace layer
//!    where Try regions in callers can be matched against callee
//!    Throw types.

use ahash::AHashMap;
use bonsai_callgraph::EdgeKind as CallEdgeKind;
use bonsai_common::{FuncId, Precision, Span};

use crate::edge::IdgEdge;
use crate::node::NodeId;
use crate::place::{CallSiteId, Place};
use crate::segment::IdgSegment;
use crate::transfer::{CallSiteRef, TransferOutput};
use crate::workspace::{CrossFileEdge, IdgWorkspace, SegmentId};

/// One resolved callee at a call site. The workspace adapter or a
/// test mock produces this from `ResolvedCallGraph` queries plus
/// receiver-type narrowing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResolvedCallee {
    /// FuncId the call resolves to.
    pub func: FuncId,
    /// Resolver-determined edge sub-kind (Direct / Virtual /
    /// Indirect / Unknown).
    pub edge_kind: CallEdgeKind,
    /// Precision floor for this resolution. The workspace propagates
    /// `Precision::Exact` for direct + narrowed dispatch and
    /// `Precision::OverApproximate` when virtual dispatch widens
    /// to many candidates.
    pub precision: Precision,
}

/// Trait the workspace implements to resolve a call site to its
/// candidate callees. The IDG builder is generic over this so
/// tests can use a tiny in-memory implementation.
pub trait CalleeResolver {
    /// Resolve `(caller, site_span, callee_name)` to the list of
    /// candidate callees. The order and number of callees defines
    /// the precision: one direct candidate → `Precision::Exact`,
    /// many virtual candidates → `Precision::OverApproximate`.
    /// The implementation is responsible for inheriting precision
    /// onto each [`ResolvedCallee`].
    fn resolve(
        &self,
        caller: FuncId,
        site: Span,
        callee_name: &str,
        receiver: Option<&str>,
        receiver_types: &[String],
    ) -> Vec<ResolvedCallee>;

    /// Resolve callback bindings: enumerate every function ever
    /// passed as `param_idx`-th argument to `host` across the
    /// workspace. Used by the IDG builder to stitch callback flows
    /// — when a function `host(callback, value)` has a callee
    /// expression `callback(value)` whose name matches its `param_idx`
    /// parameter, the IDG emits cross-call edges from the
    /// callback's `CallArg(idx)` into each bound function's
    /// `Param(idx)`.
    ///
    /// Default implementation returns empty (no callback support);
    /// the workspace adapter overrides with callgraph-driven
    /// binding analysis.
    fn callback_bindings(&self, _host: FuncId, _param_idx: u8) -> Vec<ResolvedCallee> {
        Vec::new()
    }
}

/// Mapping from `(caller_func, [callee_func]) → SegmentId` lookup
/// the builder uses to decide whether a stitched call edge is
/// intra-segment (same source file) or cross-file. The workspace
/// adapter populates this from its `FuncId → file` index.
pub trait FuncToSegment {
    /// Segment that owns `func`. `None` for unknown FuncIds.
    fn segment_for(&self, func: FuncId) -> Option<SegmentId>;
}

/// Group transfer outputs by their owning segment id. Used by the
/// workspace builder to decide which segment receives each
/// function's edges.
pub fn group_by_segment(
    outputs: Vec<TransferOutput>,
    f2s: &dyn FuncToSegment,
) -> AHashMap<SegmentId, Vec<TransferOutput>> {
    let mut grouped: AHashMap<SegmentId, Vec<TransferOutput>> = AHashMap::new();
    for out in outputs {
        if let Some(seg) = f2s.segment_for(out.func) {
            grouped.entry(seg).or_default().push(out);
        }
    }
    grouped
}

/// Stitch per-function `TransferOutput`s into a workspace IDG.
///
/// `outputs` is the union of every function's `TransferOutput`.
/// `resolver` resolves each call site to candidate callees.
/// `f2s` maps a `FuncId` to the segment that owns it.
///
/// Returns a populated [`IdgWorkspace`].
pub fn stitch_idg(
    outputs: Vec<TransferOutput>,
    resolver: &dyn CalleeResolver,
    f2s: &dyn FuncToSegment,
) -> IdgWorkspace {
    let mut ws = IdgWorkspace::new();
    // Build a `FuncId → TransferOutput` index so we can resolve a
    // callee's Place::Param / Place::Return nodes during stitching.
    // The transfer output already interned those places; we just
    // need to read them back when stitching cross-function edges.
    let by_func: AHashMap<FuncId, TransferOutput> = outputs.into_iter().map(|o| (o.func, o)).collect();

    // Group by segment so each segment gets a single `IdgSegment`
    // built from its functions' transfer outputs.
    let mut by_seg: AHashMap<SegmentId, Vec<FuncId>> = AHashMap::new();
    for func in by_func.keys() {
        if let Some(seg) = f2s.segment_for(*func) {
            by_seg.entry(seg).or_default().push(*func);
        }
    }

    // Phase 3a: build each segment from its functions' transfers.
    // Track per-segment `(FuncId, local_node_id) → workspace_node_id`
    // remappings so cross-file edges can resolve their endpoints.
    // For this builder we keep edges keyed on their owning segment's
    // node ids; Phase 5 query layer translates between segments via
    // the `IdgWorkspace`'s segment lookup.
    let mut seg_remaps: AHashMap<FuncId, (SegmentId, NodeRemap)> = AHashMap::new();
    let mut segment_ids: Vec<(SegmentId, IdgSegment)> = Vec::new();
    // Iterate placeholders in deterministic order — `AHashMap`
    // iteration order is randomised per process, so registering
    // segments in iteration order would assign different
    // workspace `SegmentId`s on every run. That cascades into
    // different ws_node ids, different `cross_call_edges_in_closure`
    // ordering, different trace_ids, and ultimately different
    // `F:`/`G:` ids on findings. Sort placeholders by their raw u32
    // (placeholders are 1:1 with FileId, which is a stable workspace
    // identifier) so segment registration is run-stable.
    let mut sorted_by_seg: Vec<(SegmentId, &Vec<FuncId>)> = by_seg.iter().map(|(s, f)| (*s, f)).collect();
    sorted_by_seg.sort_by_key(|(s, _)| s.0);
    for (seg_id_placeholder, funcs) in sorted_by_seg {
        let mut segment = IdgSegment::new();
        // Register funcs in stable order too; per-segment node
        // intern order depends on this and feeds into ws_node ids.
        let mut sorted_funcs = funcs.clone();
        sorted_funcs.sort_by_key(|f| f.raw());
        for func in &sorted_funcs {
            let out = by_func.get(func).expect("by_func index built from same set");
            let remap = merge_transfer_into_segment(&mut segment, out);
            seg_remaps.insert(*func, (seg_id_placeholder, remap));
            segment.record_func(*func);
        }
        segment_ids.push((seg_id_placeholder, segment));
    }
    // Register all segments. Note: `seg_id_placeholder` keys are the
    // FuncToSegment's view of segment ids; the IdgWorkspace assigns
    // its own ids as it registers. We translate from placeholder to
    // workspace id via the order we register in.
    let mut placeholder_to_workspace: AHashMap<SegmentId, SegmentId> = AHashMap::new();
    for (placeholder, segment) in segment_ids {
        let ws_id = ws.register_segment(segment);
        placeholder_to_workspace.insert(placeholder, ws_id);
    }
    // Translate seg_remaps to use workspace segment ids.
    let seg_remaps: AHashMap<FuncId, (SegmentId, NodeRemap)> = seg_remaps
        .into_iter()
        .filter_map(|(f, (placeholder, remap))| {
            placeholder_to_workspace
                .get(&placeholder)
                .copied()
                .map(|ws_id| (f, (ws_id, remap)))
        })
        .collect();

    // Phase 3b: stitch cross-function edges. `by_func` is an
    // AHashMap whose iteration order is randomised per process —
    // the cross-file edge index this loop appends to is read
    // back in insertion order by `cross_call_edges_in_closure`,
    // and the trace_ids that downstream lineage / `F:` ids hash
    // off depend on edge ordering. Iterate by sorted FuncId so
    // the cross-file edge list, the resulting trace_ids, and
    // every downstream content-hash are stable across runs.
    let mut callers_sorted: Vec<FuncId> = by_func.keys().copied().collect();
    callers_sorted.sort_by_key(|f| f.raw());
    for caller in callers_sorted {
        let out = by_func.get(&caller).expect("just collected from by_func");
        let Some((caller_seg, caller_remap)) = seg_remaps.get(&caller) else {
            continue;
        };
        for site in &out.call_sites {
            stitch_call_site(
                caller,
                *caller_seg,
                caller_remap,
                site,
                &out.params,
                resolver,
                &seg_remaps,
                &mut ws,
            );
        }
    }

    ws
}

/// Per-function remap from `TransferOutput`-local NodeIds to
/// segment-global NodeIds. Built during [`merge_transfer_into_segment`].
#[derive(Default, Debug, Clone)]
struct NodeRemap {
    /// `local_node_id → segment_node_id`. Indexed by local id.
    map: Vec<NodeId>,
}

impl NodeRemap {
    /// Allocate a remap of `n` slots, each initialised to the
    /// sentinel. Callers fill via [`Self::set`].
    fn with_capacity(n: usize) -> Self {
        Self {
            map: vec![NodeId::SENTINEL; n],
        }
    }

    /// Record that `local` in the transfer-output's node dict
    /// resolves to `global` in the segment's node dict.
    fn set(&mut self, local: NodeId, global: NodeId) {
        let i = local.0 as usize;
        if i < self.map.len() {
            self.map[i] = global;
        } else {
            // Grow on demand if the transfer added nodes after the
            // remap was sized.
            self.map
                .extend(std::iter::repeat_n(NodeId::SENTINEL, i + 1 - self.map.len()));
            self.map[i] = global;
        }
    }

    /// Resolve `local`. Returns `NodeId::SENTINEL` if unmapped.
    #[must_use]
    fn get(&self, local: NodeId) -> NodeId {
        self.map
            .get(local.0 as usize)
            .copied()
            .unwrap_or(NodeId::SENTINEL)
    }
}

/// Merge one function's `TransferOutput` into a segment, allocating
/// segment-global ids for each local place + node and remapping
/// every edge endpoint. Returns the local→global node remap so
/// cross-function stitching can use it.
///
/// String fields inside [`Place::Read`] / [`Place::Write`] /
/// [`Place::Throw`] / [`Place::Catch`] / field paths reference
/// `StrId`s scoped to the per-function `out.names` pool. The merge
/// re-interns each name into the segment's pool, producing fresh
/// `StrId`s in the segment's pool's id space, and rewrites the
/// Place values accordingly.
fn merge_transfer_into_segment(segment: &mut IdgSegment, out: &TransferOutput) -> NodeRemap {
    let mut remap = NodeRemap::with_capacity(out.nodes.len());
    // Build per-function StrId remap by walking every interned
    // string in the source pool and re-interning it in the segment
    // pool.
    let strid_remap = build_strid_remap(&out.names, &mut segment.strings);
    // 1. Re-intern places + nodes in segment dictionaries.
    let mut place_id_remap: Vec<crate::node::PlaceId> = Vec::with_capacity(out.places.places.len());
    for place in &out.places.places {
        let remapped = remap_place_strids(place, &strid_remap);
        let pid = segment.intern_place(remapped);
        place_id_remap.push(pid);
    }
    for (local_nid_idx, node) in out.nodes.nodes.iter().enumerate() {
        let local_pid = node.place.0 as usize;
        let pid = place_id_remap.get(local_pid).copied().unwrap_or_else(|| {
            // Fallback for any place not in the index; preserves
            // previous behaviour rather than panicking.
            let p = out.places.places[local_pid].clone();
            segment.intern_place(remap_place_strids(&p, &strid_remap))
        });
        let global_nid = segment.intern_node(node.func, pid);
        remap.set(NodeId(local_nid_idx as u32), global_nid);
    }
    // 2. Append remapped edges.
    for edge in &out.edges {
        segment.add_edge(IdgEdge {
            from: remap.get(edge.from),
            to: remap.get(edge.to),
            meta: edge.meta,
        });
    }
    remap
}

/// Build a per-function-pool → segment-pool [`bonsai_factstore::StrId`]
/// remap by iterating every entry in `from_pool`, looking up its
/// string, and re-interning into `to_pool`. Indexed by the local
/// StrId so callers can do `remap[local_strid as usize]` to get the
/// segment-pool StrId.
fn build_strid_remap(
    from_pool: &bonsai_factstore::StringPoolBuilder,
    to_pool: &mut bonsai_factstore::StringPoolBuilder,
) -> Vec<bonsai_factstore::StrId> {
    let mut remap = Vec::with_capacity(from_pool.len());
    for i in 0..from_pool.len() {
        let local_id: bonsai_factstore::StrId = i as bonsai_factstore::StrId;
        let s = from_pool.get(local_id).unwrap_or("");
        let new_id = to_pool.intern(s);
        remap.push(new_id);
    }
    remap
}

/// Rewrite a [`Place`] so its embedded `StrId`s reference the
/// segment-pool address space instead of the per-function pool.
fn remap_place_strids(place: &Place, strid_remap: &[bonsai_factstore::StrId]) -> Place {
    use crate::place::{FieldPath, TypeId};
    let map_one = |sid: bonsai_factstore::StrId| -> bonsai_factstore::StrId {
        strid_remap.get(sid as usize).copied().unwrap_or(sid)
    };
    let map_path = |path: &FieldPath| -> FieldPath { path.iter().map(|s| map_one(*s)).collect() };
    match place {
        Place::Read { name, path } => Place::Read {
            name: map_one(*name),
            path: map_path(path),
        },
        Place::Write { name, path, span } => Place::Write {
            name: map_one(*name),
            path: map_path(path),
            span: *span,
        },
        Place::Throw { ty } => Place::Throw {
            ty: TypeId(map_one(ty.0)),
        },
        Place::Catch { ty } => Place::Catch {
            ty: TypeId(map_one(ty.0)),
        },
        // The remaining variants don't carry StrIds.
        Place::Param { idx } => Place::Param { idx: *idx },
        Place::Return => Place::Return,
        Place::CallArg { site, idx } => Place::CallArg {
            site: *site,
            idx: *idx,
        },
        Place::CallRet { site } => Place::CallRet { site: *site },
        Place::Yield => Place::Yield,
        Place::Await => Place::Await,
    }
}

/// Stitch cross-function `CallArg → Param` and `Return → CallRet`
/// edges for one call site. Inserts intra-segment edges directly
/// into the caller's segment; routes cross-segment edges through
/// the workspace's cross-file index.
fn stitch_call_site(
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &NodeRemap,
    site: &CallSiteRef,
    caller_params: &[String],
    resolver: &dyn CalleeResolver,
    seg_remaps: &AHashMap<FuncId, (SegmentId, NodeRemap)>,
    ws: &mut IdgWorkspace,
) {
    let mut candidates = resolver.resolve(
        caller,
        site.site.0,
        &site.callee_name,
        site.receiver.as_deref(),
        &site.receiver_types,
    );
    // Callback-binding resolution: indirect calls through a
    // function-typed parameter take two syntactic forms:
    //   1. `callback(args)` — callee-name matches a param name.
    //   2. `callback.invoke(args)` / `callback.call(args)` /
    //      `callback.accept(args)` — receiver matches a param.
    // Both should resolve to whatever functions were ever bound to
    // that parameter across the callgraph. Merge in the
    // `callback_bindings` results so `run(executor, t)` /
    // `callback(value)` and `run(callback, t)` / `callback.call(value)`
    // both surface the cross-call edge to executor.
    let callback_param_idx: Option<u8> =
        if let Some(recv) = site.receiver.as_deref().filter(|r| !r.is_empty()) {
            // Receiver-form callback. The receiver text might be the
            // param name directly (`cb.accept(...)` → receiver "cb")
            // or a sigil'd form (`$cb` in perl). Strip leading `$`/`@`
            // sigils before matching.
            let stripped = recv.trim_start_matches(['$', '@', '%', '&']);
            caller_params
                .iter()
                .position(|p| p == recv || p == stripped)
                .and_then(|i| u8::try_from(i).ok())
        } else {
            // Free-call form: callee name itself is the param.
            // Some adapters keep an explicit invocation marker on the
            // name even without a receiver — elixir emits `cb.(value)`
            // as `name="cb."` with no receiver. Strip a single trailing
            // `.` / `()` punct before the match.
            let bare_name = site.callee_name.trim_end_matches('.').trim_end_matches("()");
            caller_params
                .iter()
                .position(|p| p == &site.callee_name || p == bare_name)
                .and_then(|i| u8::try_from(i).ok())
        };
    if let Some(param_idx) = callback_param_idx {
        for cand in resolver.callback_bindings(caller, param_idx) {
            if !candidates.iter().any(|c| c.func == cand.func) {
                candidates.push(cand);
            }
        }
    }
    // Track whether any candidate was successfully wired into a known
    // segment. If none was — typical of stdlib / external / FFI calls
    // we have no IR for — fall through to the unknown-callee
    // passthrough below so taint can still flow CallArg → CallRet
    // (e.g. `target = ext_func(arg)` keeps `arg`'s taint reaching
    // the assignment target). Without this, every external call is a
    // sink hole that breaks downstream cross-file chains.
    let mut wired_any = false;
    for cand in &candidates {
        let Some((callee_seg, _callee_remap)) = seg_remaps.get(&cand.func) else {
            // Callee not in any segment we know about — likely an
            // unresolved external call. Skip.
            continue;
        };
        wired_any = true;
        // Find callee's local Place::Param(i) and Place::Return
        // nodes by looking them up in its segment.
        let Some(callee_segment) = ws.segment(*callee_seg) else {
            continue;
        };
        let callee_param_nodes = (0..site.args_count)
            .map(|i| {
                let place = Place::Param { idx: i };
                callee_segment
                    .places
                    .lookup(&place)
                    .and_then(|pid| callee_segment.nodes.lookup(cand.func, pid))
            })
            .collect::<Vec<_>>();
        let callee_return_node = callee_segment
            .places
            .lookup(&Place::Return)
            .and_then(|pid| callee_segment.nodes.lookup(cand.func, pid));

        // For each arg index, emit `caller.CallArg(site, i) →
        // callee.Param(i)`.
        for (i, callee_param) in callee_param_nodes.iter().enumerate() {
            let Some(callee_param_node) = callee_param else {
                continue;
            };
            let caller_call_arg =
                caller_remap.get(site.call_arg_nodes.get(i).copied().unwrap_or(NodeId::SENTINEL));
            if caller_call_arg.is_sentinel() {
                continue;
            }
            let edge = IdgEdge::inter_call_arg(
                caller_call_arg,
                *callee_param_node,
                site.site.0,
                cand.precision,
                cand.edge_kind,
            );
            place_inter_edge(caller_seg, *callee_seg, edge, ws);
        }
        // Emit `callee.Return → caller.CallRet(site)`.
        if let Some(callee_return) = callee_return_node {
            let caller_call_ret = caller_remap.get(site.call_ret_node);
            if !caller_call_ret.is_sentinel() {
                let edge = IdgEdge::inter_return(
                    callee_return,
                    caller_call_ret,
                    site.site.0,
                    cand.precision,
                    cand.edge_kind,
                );
                place_inter_edge(*callee_seg, caller_seg, edge, ws);
            }
        }
    }
    // Unknown-callee passthrough: when no candidate could be wired
    // (no resolution from the callgraph, no segment for any candidate),
    // emit intra-segment `CallArg(i) → CallRet` edges so the IDG
    // closure can still flow taint through `target = ext(arg)` /
    // pipeline calls into stdlib helpers (`strings.ToUpper`,
    // `os.Getenv`'s pure-fn cousins, etc.). This mirrors the engine's
    // "external calls pass-through unless sanitized" assumption —
    // sanitizer rules separately gate the propagation; the IDG just
    // ensures connectivity.
    if !wired_any && site.is_assign_rhs {
        let caller_call_ret = caller_remap.get(site.call_ret_node);
        if !caller_call_ret.is_sentinel() {
            for arg_local in &site.call_arg_nodes {
                let caller_call_arg = caller_remap.get(*arg_local);
                if caller_call_arg.is_sentinel() {
                    continue;
                }
                let edge = IdgEdge::inter_call_arg(
                    caller_call_arg,
                    caller_call_ret,
                    site.site.0,
                    bonsai_common::Precision::OverApproximate,
                    bonsai_callgraph::EdgeKind::Indirect,
                );
                if let Some(seg) = ws.segment_mut(caller_seg) {
                    seg.add_edge(edge);
                }
            }
        }
    }
    // Drop unused: candidates iterator is consumed.
    drop(candidates);
}

/// Place an inter-procedural edge in the right bucket: same-segment
/// edges go in the segment's intra-edge list (so closures don't
/// need to walk the cross-file index for purely-local flows),
/// cross-segment edges go in the workspace cross-file index.
fn place_inter_edge(from_seg: SegmentId, to_seg: SegmentId, edge: IdgEdge, ws: &mut IdgWorkspace) {
    if from_seg == to_seg {
        if let Some(seg) = ws.segment_mut(from_seg) {
            seg.add_edge(edge);
        }
    } else {
        ws.cross_file_mut().push(CrossFileEdge {
            from_segment: from_seg,
            to_segment: to_seg,
            edge,
        });
    }
}

/// `CallSiteId` constructor for use sites that already have a Span.
#[must_use]
pub fn call_site_id(span: Span) -> CallSiteId {
    CallSiteId(span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::IdgEdgeKind;
    use crate::transfer::transfer_function_for;
    use bonsai_common::{FileId, SymbolId};
    use bonsai_lang_api::{Decl, DeclKind, FlowEvent, ModulePath, Visibility};

    fn span(start: u64, end: u64) -> Span {
        Span::new(FileId::new(0), start, end)
    }

    fn empty_decl(sym: u32, name: &str) -> Decl {
        Decl {
            symbol: SymbolId::new(sym),
            kind: DeclKind::Function,
            name: name.to_string(),
            qualified_name: None,
            module_path: ModulePath::default(),
            span: span(0, 100),
            name_span: span(0, 10),
            visibility: Visibility::Public,
            parent: None,
            body_span: Some(span(10, 100)),
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

    /// Mock resolver: a fixed map from (caller_func, callee_name)
    /// to candidate FuncIds. All resolved as Direct + Exact.
    struct MockResolver {
        table: AHashMap<(FuncId, String), Vec<FuncId>>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                table: AHashMap::new(),
            }
        }

        fn add(&mut self, caller: FuncId, name: &str, callees: Vec<FuncId>) {
            self.table.insert((caller, name.to_string()), callees);
        }
    }

    impl CalleeResolver for MockResolver {
        fn resolve(
            &self,
            caller: FuncId,
            _site: Span,
            callee_name: &str,
            _receiver: Option<&str>,
            _receiver_types: &[String],
        ) -> Vec<ResolvedCallee> {
            self.table
                .get(&(caller, callee_name.to_string()))
                .into_iter()
                .flatten()
                .map(|f| ResolvedCallee {
                    func: *f,
                    edge_kind: CallEdgeKind::Direct,
                    precision: Precision::Exact,
                })
                .collect()
        }
    }

    /// FuncToSegment that maps each FuncId via a precomputed map.
    struct StaticF2S(AHashMap<FuncId, SegmentId>);

    impl FuncToSegment for StaticF2S {
        fn segment_for(&self, func: FuncId) -> Option<SegmentId> {
            self.0.get(&func).copied()
        }
    }

    #[test]
    fn empty_outputs_produce_empty_workspace() {
        let resolver = MockResolver::new();
        let f2s = StaticF2S(AHashMap::new());
        let ws = stitch_idg(Vec::new(), &resolver, &f2s);
        assert_eq!(ws.segment_count(), 0);
        assert_eq!(ws.total_edge_count(), 0);
    }

    #[test]
    fn single_function_no_calls_creates_one_segment() {
        let mut decl = empty_decl(1, "f");
        decl.params = vec!["x".to_string()];
        decl.flow_events = vec![FlowEvent::Return {
            span: span(20, 30),
            value_name: Some("x".to_string()),
            value_text: None,
        }];
        let out = transfer_function_for(&decl);

        let mut f2s_map = AHashMap::new();
        f2s_map.insert(FuncId::new(1), SegmentId(0));
        let f2s = StaticF2S(f2s_map);
        let resolver = MockResolver::new();
        let ws = stitch_idg(vec![out], &resolver, &f2s);

        assert_eq!(ws.segment_count(), 1);
        assert!(ws.segment_for_func(FuncId::new(1)).is_some());
        // Two intra edges: Param→Read(x) bridge + Read(x)→Return.
        assert_eq!(ws.intra_edge_count(), 2);
    }

    #[test]
    fn two_funcs_in_same_segment_call_each_other_no_cross_file_edge() {
        // f calls g; both in segment 0.
        let mut f = empty_decl(1, "f");
        f.flow_events = vec![FlowEvent::Call {
            span: span(20, 30),
            name: "g".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                span: span(22, 23),
                name: None,
                value_text: "x".to_string(),
                place: Some("x".to_string()),
                source_names: Vec::new(),
            }],
        }];
        let mut g = empty_decl(2, "g");
        g.params = vec!["arg".to_string()];

        let out_f = transfer_function_for(&f);
        let out_g = transfer_function_for(&g);

        let mut f2s_map = AHashMap::new();
        f2s_map.insert(FuncId::new(1), SegmentId(0));
        f2s_map.insert(FuncId::new(2), SegmentId(0));
        let f2s = StaticF2S(f2s_map);

        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "g", vec![FuncId::new(2)]);

        let ws = stitch_idg(vec![out_f, out_g], &resolver, &f2s);

        assert_eq!(ws.segment_count(), 1);
        // Cross-file index should be empty — both funcs same segment.
        assert!(ws.cross_file().is_empty());
    }

    #[test]
    fn two_funcs_in_different_segments_call_creates_cross_file_edges() {
        let mut f = empty_decl(1, "f");
        f.flow_events = vec![FlowEvent::Call {
            span: span(20, 30),
            name: "g".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                span: span(22, 23),
                name: None,
                value_text: "x".to_string(),
                place: Some("x".to_string()),
                source_names: Vec::new(),
            }],
        }];
        let mut g = empty_decl(2, "g");
        g.params = vec!["arg".to_string()];
        g.flow_events = vec![FlowEvent::Return {
            span: span(50, 60),
            value_name: Some("arg".to_string()),
            value_text: None,
        }];

        let out_f = transfer_function_for(&f);
        let out_g = transfer_function_for(&g);

        let mut f2s_map = AHashMap::new();
        f2s_map.insert(FuncId::new(1), SegmentId(0));
        f2s_map.insert(FuncId::new(2), SegmentId(1));
        let f2s = StaticF2S(f2s_map);

        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "g", vec![FuncId::new(2)]);

        let ws = stitch_idg(vec![out_f, out_g], &resolver, &f2s);

        // Two segments registered.
        assert_eq!(ws.segment_count(), 2);
        // Cross-file edges expected:
        //   f.CallArg(site, 0) → g.Param(0)  (1 edge)
        //   g.Return → f.CallRet(site)        (1 edge)
        assert_eq!(ws.cross_file().len(), 2);
        // One InterCallArg + one InterReturn.
        let kinds: Vec<IdgEdgeKind> = ws.cross_file().edges.iter().map(|e| e.edge.meta.kind).collect();
        assert!(kinds.contains(&IdgEdgeKind::InterCallArg));
        assert!(kinds.contains(&IdgEdgeKind::InterReturn));
    }

    #[test]
    fn unresolved_call_emits_no_inter_edge() {
        let mut f = empty_decl(1, "f");
        f.flow_events = vec![FlowEvent::Call {
            span: span(20, 30),
            name: "missing".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: Vec::new(),
        }];

        let out_f = transfer_function_for(&f);

        let mut f2s_map = AHashMap::new();
        f2s_map.insert(FuncId::new(1), SegmentId(0));
        let f2s = StaticF2S(f2s_map);
        let resolver = MockResolver::new(); // empty — `missing` unresolved.

        let ws = stitch_idg(vec![out_f], &resolver, &f2s);
        assert!(ws.cross_file().is_empty());
    }

    #[test]
    fn virtual_dispatch_emits_one_edge_per_candidate() {
        // f calls "method"; resolver returns two candidates (g, h).
        let mut f = empty_decl(1, "f");
        f.flow_events = vec![FlowEvent::Call {
            span: span(20, 30),
            name: "method".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: vec!["Iface".to_string()],
            call_kind: bonsai_lang_api::CallKind::Method,
            args: Vec::new(),
        }];
        let g = empty_decl(2, "g");
        let h = empty_decl(3, "h");

        let outs = vec![
            transfer_function_for(&f),
            transfer_function_for(&g),
            transfer_function_for(&h),
        ];

        let mut f2s_map = AHashMap::new();
        f2s_map.insert(FuncId::new(1), SegmentId(0));
        f2s_map.insert(FuncId::new(2), SegmentId(1));
        f2s_map.insert(FuncId::new(3), SegmentId(2));
        let f2s = StaticF2S(f2s_map);
        let mut resolver = MockResolver::new();
        resolver.add(FuncId::new(1), "method", vec![FuncId::new(2), FuncId::new(3)]);

        let ws = stitch_idg(outs, &resolver, &f2s);
        // Two candidates × at least 1 edge per candidate
        // (the InterReturn). Args count is 0 so no CallArg edges.
        // → at least 2 cross-file edges (two InterReturns).
        assert!(ws.cross_file().len() >= 2);
    }
}
