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
//!    - `caller.CallArg(site, i) → callee.Param(j)` per explicit
//!      arg, where `j` skips any declared receiver parameter
//!    - `caller.CallArg(site, u8::MAX) → callee.Param(receiver)`
//!      when the callee exposes a receiver parameter
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

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::EdgeKind as CallEdgeKind;
use bonsai_common::{FuncId, Precision, Span};
use bonsai_factstore::StrId;
use bonsai_lang_api::CallKind;
use smallvec::SmallVec;
use std::time::Instant;

use crate::edge::IdgEdge;
use crate::node::NodeId;
use crate::place::{CallSiteId, Place};
use crate::segment::IdgSegment;
use crate::transfer::{CallSiteRef, TransferOutput};
use crate::workspace::{CrossFileEdge, IdgWorkspace, SegmentId};

#[derive(Debug, Clone)]
struct CalleeEndpoints {
    segment: SegmentId,
    params: Vec<NodeId>,
    param_names: Vec<String>,
    receiver_param_index: Option<usize>,
    return_node: Option<NodeId>,
}

#[derive(Debug)]
struct FunctionStitchData {
    params: Vec<String>,
    call_sites: Vec<CallSiteRef>,
    param_count: usize,
    receiver_param_index: Option<usize>,
}

#[derive(Clone, Debug)]
struct FieldArgStitch {
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    actual_arg_node: Option<NodeId>,
    actual_arg: String,
    param_name: String,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
}

#[derive(Clone, Debug)]
struct ConstructorReturnStitch {
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    target_base: String,
    receiver_param_name: String,
    call_span: Span,
    write_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
}

#[derive(Clone, Debug)]
struct ReturnFieldStitch {
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    source_base: String,
    target_base: String,
    call_span: Span,
    write_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
}

#[derive(Clone, Debug)]
struct ReceiverMutationStitch {
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    target_base: String,
    callee_receiver_param_name: String,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
}

#[derive(Default, Debug)]
struct StitchStats {
    sites: usize,
    resolved_candidates: usize,
    callback_lookups: usize,
    callback_candidates: usize,
    wired_candidates: usize,
    inter_edges: usize,
    passthrough_edges: usize,
    resolve_nanos: u128,
    callback_nanos: u128,
}

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
    /// Precision floor for this resolution. Semantic resolver paths
    /// return `Exact`/`Narrowed`; ambiguous broad dispatch should
    /// return no candidate instead of a guessed fan-out.
    pub precision: Precision,
}

/// Trait the workspace implements to resolve a call site to its
/// candidate callees. The IDG builder is generic over this so
/// tests can use a tiny in-memory implementation.
pub trait CalleeResolver {
    /// Resolve `(caller, site_span, callee_name)` to semantically
    /// proven candidate callees. Ambiguous broad matches should be
    /// omitted; the implementation is responsible for inheriting
    /// precision onto each [`ResolvedCallee`].
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

    /// Static receiver type that owns `func`, when known. The IDG
    /// uses this to project embedded receiver fields precisely:
    /// `repo.Run()` resolved to `Repository.Run` forwards
    /// `repo.Repository.data` into receiver param `r.data` without
    /// promoting the whole `repo` object.
    fn receiver_type_for(&self, _func: FuncId) -> Option<String> {
        None
    }

    /// True when `func` is the body that initializes a newly
    /// constructed receiver object. The builder uses this to project
    /// constructor receiver fields back onto the caller's assignment
    /// target (`repo = Repository(data)` → `repo._data.*`) without
    /// assuming ordinary method returns alias their receiver.
    fn is_constructor_func(&self, _func: FuncId) -> bool {
        false
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
    let stitch_started = Instant::now();
    // Group by segment so each segment gets a single `IdgSegment`
    // built from its functions' transfer outputs. During the merge we
    // reduce each heavy `TransferOutput` to only the metadata needed
    // for call stitching, so places/nodes/edges/name pools can be
    // dropped before the full workspace IDG is stitched.
    let mut by_seg = group_by_segment(outputs, f2s);
    let function_count: usize = by_seg.values().map(Vec::len).sum();

    // Phase 3a: build each segment from its functions' transfers.
    // Track per-segment `(FuncId, local_node_id) → workspace_node_id`
    // remappings so cross-file edges can resolve their endpoints.
    // For this builder we keep edges keyed on their owning segment's
    // node ids; Phase 5 query layer translates between segments via
    // the `IdgWorkspace`'s segment lookup.
    let mut seg_remaps: AHashMap<FuncId, (SegmentId, NodeRemap)> = AHashMap::with_capacity(function_count);
    let mut stitch_data: AHashMap<FuncId, FunctionStitchData> = AHashMap::with_capacity(function_count);
    // Iterate placeholders in deterministic order — `AHashMap`
    // iteration order is randomised per process, so registering
    // segments in iteration order would assign different
    // workspace `SegmentId`s on every run. That cascades into
    // different ws_node ids, different `cross_call_edges_in_closure`
    // ordering, different trace_ids, and ultimately different
    // `F:`/`G:` ids on findings. Sort placeholders by their raw u32
    // (placeholders are 1:1 with FileId, which is a stable workspace
    // identifier) so segment registration is run-stable.
    let mut sorted_by_seg: Vec<SegmentId> = by_seg.keys().copied().collect();
    sorted_by_seg.sort_by_key(|s| s.0);
    for seg_id_placeholder in sorted_by_seg {
        // Register funcs in stable order too; per-segment node
        // intern order depends on this and feeds into ws_node ids.
        let mut sorted_outputs = by_seg
            .remove(&seg_id_placeholder)
            .expect("segment key collected from grouped outputs");
        sorted_outputs.sort_by_key(|out| out.func.raw());
        let mut place_capacity = 0usize;
        let mut node_capacity = 0usize;
        let mut edge_capacity = 0usize;
        for out in &sorted_outputs {
            place_capacity = place_capacity.saturating_add(out.places.len());
            node_capacity = node_capacity.saturating_add(out.nodes.len());
            edge_capacity = edge_capacity.saturating_add(out.edges.len());
        }
        let mut segment = IdgSegment::with_capacity(place_capacity, node_capacity, edge_capacity);
        let mut local_remaps = Vec::with_capacity(sorted_outputs.len());
        for out in sorted_outputs {
            let remap = merge_transfer_into_segment(&mut segment, &out);
            let TransferOutput {
                func,
                params,
                receiver_param_index,
                call_sites,
                ..
            } = out;
            let param_count = params.len().min(u8::MAX as usize);
            stitch_data.insert(
                func,
                FunctionStitchData {
                    params,
                    call_sites,
                    param_count,
                    receiver_param_index,
                },
            );
            local_remaps.push((func, remap));
            segment.record_func(func);
        }
        let ws_id = ws.register_segment(segment);
        for (func, remap) in local_remaps {
            seg_remaps.insert(func, (ws_id, remap));
        }
    }
    stitch_debug_log(format_args!(
        "stitch merge-segments: {:.3}s segments={} funcs={}",
        stitch_started.elapsed().as_secs_f64(),
        ws.segment_count(),
        stitch_data.len()
    ));
    let register_started = Instant::now();
    stitch_debug_log(format_args!(
        "stitch register-segments: {:.3}s segments={} funcs={}",
        register_started.elapsed().as_secs_f64(),
        ws.segment_count(),
        seg_remaps.len()
    ));

    let endpoint_started = Instant::now();
    let callee_endpoints = build_callee_endpoints(&stitch_data, &seg_remaps, &ws);
    stitch_debug_log(format_args!(
        "stitch endpoint-index: {:.3}s funcs={}",
        endpoint_started.elapsed().as_secs_f64(),
        callee_endpoints.len()
    ));

    let call_started = Instant::now();
    let collect_stats = stitch_debug_enabled();
    let mut stats = StitchStats::default();
    let mut field_arg_sites: Vec<FieldArgStitch> = Vec::new();
    let mut return_field_sites: Vec<ReturnFieldStitch> = Vec::new();
    let mut constructor_return_sites: Vec<ConstructorReturnStitch> = Vec::new();
    let mut receiver_mutation_sites: Vec<ReceiverMutationStitch> = Vec::new();
    // Phase 3b: stitch cross-function edges. `stitch_data` is an
    // AHashMap whose iteration order is randomised per process —
    // the cross-file edge index this loop appends to is read
    // back in insertion order by `cross_call_edges_in_closure`,
    // and the trace_ids that downstream lineage / `F:` ids hash
    // off depend on edge ordering. Iterate by sorted FuncId so
    // the cross-file edge list, the resulting trace_ids, and
    // every downstream content-hash are stable across runs.
    let mut callers_sorted: Vec<FuncId> = stitch_data.keys().copied().collect();
    callers_sorted.sort_by_key(|f| f.raw());
    for caller in callers_sorted {
        let data = stitch_data.get(&caller).expect("just collected from stitch_data");
        let Some((caller_seg, caller_remap)) = seg_remaps.get(&caller) else {
            continue;
        };
        for site in &data.call_sites {
            stitch_call_site(
                caller,
                *caller_seg,
                caller_remap,
                site,
                &data.params,
                data.receiver_param_index,
                resolver,
                &callee_endpoints,
                &mut ws,
                &mut field_arg_sites,
                &mut return_field_sites,
                &mut constructor_return_sites,
                &mut receiver_mutation_sites,
                if collect_stats { Some(&mut stats) } else { None },
            );
        }
    }
    stitch_debug_log(format_args!(
        "stitch call-sites-wired: {:.3}s field_arg_sites={} return_field_sites={} constructor_return_sites={} receiver_mutation_sites={}",
        call_started.elapsed().as_secs_f64(),
        field_arg_sites.len(),
        return_field_sites.len(),
        constructor_return_sites.len(),
        receiver_mutation_sites.len()
    ));
    stitch_field_argument_forwarding(
        &field_arg_sites,
        &return_field_sites,
        &constructor_return_sites,
        &receiver_mutation_sites,
        &mut ws,
    );
    stitch_debug_log(format_args!(
        "stitch calls: {:.3}s sites={} candidates={} callback_lookups={} callback_candidates={} wired_candidates={} inter_edges={} passthrough_edges={} field_arg_sites={} return_field_sites={} constructor_return_sites={} receiver_mutation_sites={} resolve={:.3}s callback={:.3}s",
        call_started.elapsed().as_secs_f64(),
        stats.sites,
        stats.resolved_candidates,
        stats.callback_lookups,
        stats.callback_candidates,
        stats.wired_candidates,
        stats.inter_edges,
        stats.passthrough_edges,
        field_arg_sites.len(),
        return_field_sites.len(),
        constructor_return_sites.len(),
        receiver_mutation_sites.len(),
        stats.resolve_nanos as f64 / 1_000_000_000.0,
        stats.callback_nanos as f64 / 1_000_000_000.0
    ));

    ws
}

fn build_callee_endpoints(
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
    seg_remaps: &AHashMap<FuncId, (SegmentId, NodeRemap)>,
    ws: &IdgWorkspace,
) -> AHashMap<FuncId, CalleeEndpoints> {
    let mut out = AHashMap::with_capacity(stitch_data.len());
    let mut yielded_nodes_by_segment: AHashMap<SegmentId, AHashSet<NodeId>> = AHashMap::new();
    let mut funcs: Vec<FuncId> = stitch_data.keys().copied().collect();
    funcs.sort_by_key(|f| f.raw());
    for func in funcs {
        let Some((segment_id, _)) = seg_remaps.get(&func) else {
            continue;
        };
        let segment_id = *segment_id;
        let Some(segment) = ws.segment(segment_id) else {
            continue;
        };
        let param_count = stitch_data.get(&func).map(|data| data.param_count).unwrap_or(0);
        let mut params = Vec::with_capacity(param_count);
        for idx in 0..param_count {
            let Ok(idx) = u8::try_from(idx) else { break };
            let node = segment
                .places
                .lookup(&Place::Param { idx })
                .and_then(|pid| segment.nodes.lookup(func, pid))
                .unwrap_or(NodeId::SENTINEL);
            params.push(node);
        }
        let plain_return_node = segment
            .places
            .lookup(&Place::Return)
            .and_then(|pid| segment.nodes.lookup(func, pid));
        let yield_node = segment
            .places
            .lookup(&Place::Yield)
            .and_then(|pid| segment.nodes.lookup(func, pid));
        let yielded_nodes = yielded_nodes_by_segment
            .entry(segment_id)
            .or_insert_with(|| collect_yield_value_nodes(segment));
        let return_node = yield_node
            .filter(|node| yielded_nodes.contains(node))
            .or(plain_return_node);
        out.insert(
            func,
            CalleeEndpoints {
                segment: segment_id,
                params,
                param_names: stitch_data
                    .get(&func)
                    .map(|data| data.params.clone())
                    .unwrap_or_default(),
                receiver_param_index: stitch_data.get(&func).and_then(|data| data.receiver_param_index),
                return_node,
            },
        );
    }
    out
}

fn collect_yield_value_nodes(segment: &IdgSegment) -> AHashSet<NodeId> {
    let mut out = AHashSet::new();
    for edge in &segment.edges {
        let Some(to_node) = segment.nodes.get(edge.to) else {
            continue;
        };
        let Some(to_place) = segment.places.get(to_node.place) else {
            continue;
        };
        if matches!(to_place, Place::Yield) {
            out.insert(edge.to);
        }
    }
    out
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
#[allow(clippy::too_many_arguments)] // Hot-path stitch state is passed explicitly to avoid heap context objects.
fn stitch_call_site(
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &NodeRemap,
    site: &CallSiteRef,
    caller_params: &[String],
    caller_receiver_param_index: Option<usize>,
    resolver: &dyn CalleeResolver,
    callee_endpoints: &AHashMap<FuncId, CalleeEndpoints>,
    ws: &mut IdgWorkspace,
    field_arg_sites: &mut Vec<FieldArgStitch>,
    return_field_sites: &mut Vec<ReturnFieldStitch>,
    constructor_return_sites: &mut Vec<ConstructorReturnStitch>,
    receiver_mutation_sites: &mut Vec<ReceiverMutationStitch>,
    mut stats: Option<&mut StitchStats>,
) {
    if let Some(stats) = &mut stats {
        stats.sites = stats.sites.saturating_add(1);
    }
    let resolve_started = stats.is_some().then(Instant::now);
    let mut candidates = resolver.resolve(
        caller,
        site.site.0,
        &site.callee_name,
        site.receiver.as_deref(),
        &site.receiver_types,
    );
    if let Some(stats) = &mut stats {
        stats.resolved_candidates = stats.resolved_candidates.saturating_add(candidates.len());
        if let Some(started) = resolve_started {
            stats.resolve_nanos = stats.resolve_nanos.saturating_add(started.elapsed().as_nanos());
        }
    }
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
        if let Some(stats) = &mut stats {
            stats.callback_lookups = stats.callback_lookups.saturating_add(1);
        }
        let callback_started = stats.is_some().then(Instant::now);
        for cand in resolver.callback_bindings(caller, param_idx) {
            if let Some(stats) = &mut stats {
                stats.callback_candidates = stats.callback_candidates.saturating_add(1);
            }
            if !candidates.iter().any(|c| c.func == cand.func) {
                candidates.push(cand);
            }
        }
        if let Some(stats) = &mut stats {
            if let Some(started) = callback_started {
                stats.callback_nanos = stats.callback_nanos.saturating_add(started.elapsed().as_nanos());
            }
        }
    }
    // Wire only candidates that resolved to a known segment. External
    // calls require explicit summaries/models; unresolved assignment
    // calls do not get a generic passthrough edge.
    for cand in &candidates {
        let Some(endpoints) = callee_endpoints.get(&cand.func) else {
            // Callee not in any segment we know about — likely an
            // unresolved external call. Skip.
            continue;
        };
        if let Some(stats) = &mut stats {
            stats.wired_candidates = stats.wired_candidates.saturating_add(1);
        }
        // For method receivers, emit the synthetic receiver slot to
        // the callee's adapter-declared receiver parameter. This is
        // separate from positional args so explicit arguments keep
        // their source-language order.
        if matches!(site.call_kind, CallKind::Method) {
            if let (Some(receiver_arg_node), Some(receiver_idx)) =
                (site.receiver_arg_node, endpoints.receiver_param_index)
            {
                if let Some(&callee_param_node) = endpoints.params.get(receiver_idx) {
                    if !callee_param_node.is_sentinel() {
                        let caller_call_arg = caller_remap.get(receiver_arg_node);
                        if !caller_call_arg.is_sentinel() {
                            let edge = IdgEdge::inter_call_arg(
                                caller_call_arg,
                                callee_param_node,
                                site.site.0,
                                cand.precision,
                                cand.edge_kind,
                            );
                            place_inter_edge(caller_seg, endpoints.segment, edge, ws);
                            if let Some(stats) = &mut stats {
                                stats.inter_edges = stats.inter_edges.saturating_add(1);
                            }
                        }
                    }
                }
                if let (Some(receiver), Some(param_name)) = (
                    site.receiver
                        .as_deref()
                        .map(str::trim)
                        .filter(|receiver| !receiver.is_empty()),
                    endpoints.param_names.get(receiver_idx).map(String::as_str),
                ) {
                    push_receiver_field_arg_site(
                        field_arg_sites,
                        caller,
                        caller_seg,
                        cand.func,
                        endpoints.segment,
                        receiver,
                        param_name,
                        site.site.0,
                        cand.precision,
                        cand.edge_kind,
                        None,
                    );
                    if let Some(receiver_type) = resolver.receiver_type_for(cand.func) {
                        push_receiver_field_arg_site(
                            field_arg_sites,
                            caller,
                            caller_seg,
                            cand.func,
                            endpoints.segment,
                            receiver,
                            param_name,
                            site.site.0,
                            cand.precision,
                            cand.edge_kind,
                            Some(receiver_type.as_str()),
                        );
                    }
                }
            }
        }
        // For each explicit arg index, emit
        // `caller.CallArg(site, i) → callee.Param(j)`. When the
        // callee has a declared receiver parameter, `j` skips that
        // formal slot instead of treating the receiver as arg zero.
        for i in 0..site.args_count as usize {
            let callee_param_idx = explicit_arg_param_index(i, endpoints.receiver_param_index);
            let Some(&callee_param_node) = endpoints.params.get(callee_param_idx) else {
                continue;
            };
            if callee_param_node.is_sentinel() {
                continue;
            }
            let caller_call_arg =
                caller_remap.get(site.call_arg_nodes.get(i).copied().unwrap_or(NodeId::SENTINEL));
            if caller_call_arg.is_sentinel() {
                continue;
            }
            let edge = IdgEdge::inter_call_arg(
                caller_call_arg,
                callee_param_node,
                site.site.0,
                cand.precision,
                cand.edge_kind,
            );
            place_inter_edge(caller_seg, endpoints.segment, edge, ws);
            if let (Some(actual_arg), Some(param_name)) = (
                site.call_arg_places.get(i).map(String::as_str),
                endpoints.param_names.get(callee_param_idx).map(String::as_str),
            ) {
                if !actual_arg.trim().is_empty() && !param_name.trim().is_empty() {
                    field_arg_sites.push(FieldArgStitch {
                        caller,
                        caller_seg,
                        callee: cand.func,
                        callee_seg: endpoints.segment,
                        actual_arg_node: Some(caller_call_arg),
                        actual_arg: actual_arg.trim().to_string(),
                        param_name: param_name.trim().to_string(),
                        call_span: site.site.0,
                        precision: cand.precision,
                        call_kind: cand.edge_kind,
                    });
                }
            }
            if let Some(stats) = &mut stats {
                stats.inter_edges = stats.inter_edges.saturating_add(1);
            }
        }
        // Emit `callee.Return → caller.CallRet(site)`.
        let caller_call_ret = caller_remap.get(site.call_ret_node);
        if let Some(callee_return) = endpoints.return_node {
            if !caller_call_ret.is_sentinel() {
                let edge = IdgEdge::inter_return(
                    callee_return,
                    caller_call_ret,
                    site.site.0,
                    cand.precision,
                    cand.edge_kind,
                );
                place_inter_edge(endpoints.segment, caller_seg, edge, ws);
                if let Some(stats) = &mut stats {
                    stats.inter_edges = stats.inter_edges.saturating_add(1);
                }
            }
        }
        if !caller_call_ret.is_sentinel() {
            let assignment_targets = call_ret_assignment_targets(ws, caller_seg, caller, caller_call_ret);
            if !assignment_targets.is_empty() {
                for source_base in [
                    crate::transfer::RETURN_FIELD_BASE,
                    crate::transfer::YIELD_FIELD_BASE,
                ] {
                    for (target_base, write_span) in &assignment_targets {
                        return_field_sites.push(ReturnFieldStitch {
                            caller,
                            caller_seg,
                            callee: cand.func,
                            callee_seg: endpoints.segment,
                            source_base: source_base.to_string(),
                            target_base: target_base.clone(),
                            call_span: site.site.0,
                            write_span: *write_span,
                            precision: cand.precision,
                            call_kind: cand.edge_kind,
                        });
                    }
                }
            }
        }
        if matches!(site.call_kind, CallKind::Method) && resolver.is_constructor_func(cand.func) {
            if let (Some(receiver_idx), Some(receiver)) = (
                endpoints.receiver_param_index,
                site.receiver
                    .as_deref()
                    .map(str::trim)
                    .filter(|receiver| !receiver.is_empty()),
            ) {
                if let Some(callee_receiver_param_name) =
                    endpoints.param_names.get(receiver_idx).map(String::as_str)
                {
                    let target_base = constructor_receiver_target_base(
                        receiver,
                        caller_params,
                        caller_receiver_param_index,
                    );
                    if !target_base.is_empty() {
                        receiver_mutation_sites.push(ReceiverMutationStitch {
                            caller,
                            caller_seg,
                            callee: cand.func,
                            callee_seg: endpoints.segment,
                            target_base,
                            callee_receiver_param_name: callee_receiver_param_name.to_string(),
                            call_span: site.site.0,
                            precision: cand.precision,
                            call_kind: cand.edge_kind,
                        });
                    }
                }
            }
        }
        if resolver.is_constructor_func(cand.func) {
            let caller_call_ret = caller_remap.get(site.call_ret_node);
            if !caller_call_ret.is_sentinel() {
                if let Some(receiver_idx) = endpoints.receiver_param_index {
                    if let Some(receiver_param_name) =
                        endpoints.param_names.get(receiver_idx).map(String::as_str)
                    {
                        for (target_base, write_span) in
                            call_ret_assignment_targets(ws, caller_seg, caller, caller_call_ret)
                        {
                            constructor_return_sites.push(ConstructorReturnStitch {
                                caller,
                                caller_seg,
                                callee: cand.func,
                                callee_seg: endpoints.segment,
                                target_base,
                                receiver_param_name: receiver_param_name.to_string(),
                                call_span: site.site.0,
                                write_span,
                                precision: cand.precision,
                                call_kind: cand.edge_kind,
                            });
                        }
                    }
                }
            }
        }
    }
    // Ambiguous or unknown callees do not create IDG flow. Library
    // pass-through needs an explicit semantic summary/model; a
    // generic `CallArg -> CallRet` edge would invent dataflow.
    // Drop unused: candidates iterator is consumed.
    drop(candidates);
}

fn constructor_receiver_target_base(
    receiver: &str,
    caller_params: &[String],
    caller_receiver_param_index: Option<usize>,
) -> String {
    let trimmed = receiver.trim();
    if is_super_receiver(trimmed) {
        return caller_receiver_param_index
            .and_then(|idx| caller_params.get(idx))
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| trimmed.to_string());
    }
    trimmed.to_string()
}

fn is_super_receiver(receiver: &str) -> bool {
    matches!(receiver.trim(), "super" | "super()" | "base")
}

#[allow(clippy::too_many_arguments)] // Mirrors the explicit FieldArgStitch metadata.
fn push_receiver_field_arg_site(
    sites: &mut Vec<FieldArgStitch>,
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    receiver: &str,
    param_name: &str,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    receiver_type: Option<&str>,
) {
    if param_name.trim().is_empty() {
        return;
    }
    let actual_arg = match receiver_type.map(str::trim).filter(|ty| !ty.is_empty()) {
        Some(ty) if receiver_projection_needed(receiver, ty) => format!("{receiver}.{ty}"),
        Some(_) | None => receiver.to_string(),
    };
    if actual_arg.trim().is_empty() {
        return;
    }
    sites.push(FieldArgStitch {
        caller,
        caller_seg,
        callee,
        callee_seg,
        actual_arg_node: None,
        actual_arg,
        param_name: param_name.trim().to_string(),
        call_span,
        precision,
        call_kind,
    });
}

fn receiver_projection_needed(receiver: &str, receiver_type: &str) -> bool {
    storage_segments(receiver)
        .last()
        .is_none_or(|tail| tail != receiver_type)
}

fn explicit_arg_param_index(arg_idx: usize, receiver_param_index: Option<usize>) -> usize {
    match receiver_param_index {
        Some(receiver_idx) if arg_idx >= receiver_idx => arg_idx.saturating_add(1),
        _ => arg_idx,
    }
}

fn stitch_field_argument_forwarding(
    sites: &[FieldArgStitch],
    return_field_sites: &[ReturnFieldStitch],
    constructor_return_sites: &[ConstructorReturnStitch],
    receiver_mutation_sites: &[ReceiverMutationStitch],
    ws: &mut IdgWorkspace,
) {
    if sites.is_empty()
        && return_field_sites.is_empty()
        && constructor_return_sites.is_empty()
        && receiver_mutation_sites.is_empty()
    {
        return;
    }
    let mut known_edges = collect_existing_edges(ws);
    const MAX_FIELD_FORWARDING_ROUNDS: usize = 64;
    for round in 0..MAX_FIELD_FORWARDING_ROUNDS {
        let round_started = Instant::now();
        let mut changed = false;
        for site in sites {
            changed |= stitch_field_argument_site(site, ws, &mut known_edges);
        }
        changed |= stitch_intra_field_copies(ws, &mut known_edges);
        for site in return_field_sites {
            changed |= stitch_return_field_site(site, ws, &mut known_edges);
        }
        for site in receiver_mutation_sites {
            changed |= stitch_receiver_mutation_site(site, ws, &mut known_edges);
        }
        for site in constructor_return_sites {
            changed |= stitch_constructor_return_site(site, ws, &mut known_edges);
        }
        stitch_debug_log(format_args!(
            "field-forward round={} changed={} elapsed={:.3}s total_edges={}",
            round,
            changed,
            round_started.elapsed().as_secs_f64(),
            ws.total_edge_count()
        ));
        if !changed {
            break;
        }
    }
}

fn stitch_field_argument_site(
    site: &FieldArgStitch,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) -> bool {
    let writers = collect_field_writes_for_base_before_call(
        ws,
        site.caller_seg,
        site.caller,
        &site.actual_arg,
        site.call_span,
    );
    let has_precise_actual_field_writers = !writers.is_empty();
    let mut changed = false;
    for (field, writer) in writers {
        if !is_forwardable_field(&field) {
            continue;
        }
        let Some(param_field_write) = ensure_field_write_node(
            ws,
            site.callee_seg,
            site.callee,
            &site.param_name,
            &field,
            site.call_span,
        ) else {
            continue;
        };
        changed |= place_inter_edge_if_absent(
            site.caller_seg,
            site.callee_seg,
            IdgEdge {
                from: writer,
                to: param_field_write,
                meta: crate::edge::EdgeMeta {
                    precision: site.precision,
                    kind: crate::edge::IdgEdgeKind::InterCallArg,
                    call_kind: site.call_kind,
                    via_span: site.call_span,
                },
            },
            ws,
            known_edges,
        );
        changed |= connect_field_write_to_reads(
            site.callee_seg,
            site.callee,
            &site.param_name,
            &field,
            param_field_write,
            site.call_span,
            site.precision,
            site.call_kind,
            ws,
            known_edges,
        );
    }
    if let Some(actual_arg_node) = site.actual_arg_node.filter(|_| !has_precise_actual_field_writers) {
        let readers = collect_field_reads_for_base(ws, site.callee_seg, site.callee, &site.param_name);
        for (field, reader) in readers {
            if !is_forwardable_field(&field) {
                continue;
            }
            changed |= place_inter_edge_if_absent(
                site.caller_seg,
                site.callee_seg,
                IdgEdge {
                    from: actual_arg_node,
                    to: reader,
                    meta: crate::edge::EdgeMeta {
                        precision: site.precision,
                        kind: crate::edge::IdgEdgeKind::InterCallArg,
                        call_kind: site.call_kind,
                        via_span: site.call_span,
                    },
                },
                ws,
                known_edges,
            );
        }
    }
    changed
}

fn stitch_return_field_site(
    site: &ReturnFieldStitch,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) -> bool {
    let writers = collect_field_writes_for_base(ws, site.callee_seg, site.callee, &site.source_base);
    if writers.is_empty() {
        return false;
    }
    let mut changed = false;
    for (field, writer) in writers {
        if !is_forwardable_field(&field) {
            continue;
        }
        let Some(target_field_write) = ensure_field_write_node(
            ws,
            site.caller_seg,
            site.caller,
            &site.target_base,
            &field,
            site.write_span,
        ) else {
            continue;
        };
        changed |= place_inter_edge_if_absent(
            site.callee_seg,
            site.caller_seg,
            IdgEdge {
                from: writer,
                to: target_field_write,
                meta: crate::edge::EdgeMeta {
                    precision: site.precision,
                    kind: crate::edge::IdgEdgeKind::InterReturn,
                    call_kind: site.call_kind,
                    via_span: site.call_span,
                },
            },
            ws,
            known_edges,
        );
        changed |= connect_field_write_to_reads(
            site.caller_seg,
            site.caller,
            &site.target_base,
            &field,
            target_field_write,
            site.write_span,
            site.precision,
            site.call_kind,
            ws,
            known_edges,
        );
    }
    changed
}

fn stitch_receiver_mutation_site(
    site: &ReceiverMutationStitch,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) -> bool {
    let writers =
        collect_field_writes_for_base(ws, site.callee_seg, site.callee, &site.callee_receiver_param_name);
    if writers.is_empty() {
        return false;
    }
    let mut changed = false;
    for (field, writer) in writers {
        if !is_forwardable_field(&field) {
            continue;
        }
        let Some(target_field_write) = ensure_field_write_node(
            ws,
            site.caller_seg,
            site.caller,
            &site.target_base,
            &field,
            site.call_span,
        ) else {
            continue;
        };
        changed |= place_inter_edge_if_absent(
            site.callee_seg,
            site.caller_seg,
            IdgEdge {
                from: writer,
                to: target_field_write,
                meta: crate::edge::EdgeMeta {
                    precision: site.precision,
                    kind: crate::edge::IdgEdgeKind::InterReturn,
                    call_kind: site.call_kind,
                    via_span: site.call_span,
                },
            },
            ws,
            known_edges,
        );
        changed |= connect_field_write_to_reads(
            site.caller_seg,
            site.caller,
            &site.target_base,
            &field,
            target_field_write,
            site.call_span,
            site.precision,
            site.call_kind,
            ws,
            known_edges,
        );
    }
    changed
}

fn stitch_constructor_return_site(
    site: &ConstructorReturnStitch,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) -> bool {
    let writers = collect_field_writes_for_base(ws, site.callee_seg, site.callee, &site.receiver_param_name);
    if writers.is_empty() {
        return false;
    }
    let mut changed = false;
    for (field, writer) in writers {
        if !is_forwardable_field(&field) {
            continue;
        }
        let Some(target_field_write) = ensure_field_write_node(
            ws,
            site.caller_seg,
            site.caller,
            &site.target_base,
            &field,
            site.write_span,
        ) else {
            continue;
        };
        changed |= place_inter_edge_if_absent(
            site.callee_seg,
            site.caller_seg,
            IdgEdge {
                from: writer,
                to: target_field_write,
                meta: crate::edge::EdgeMeta {
                    precision: site.precision,
                    kind: crate::edge::IdgEdgeKind::InterReturn,
                    call_kind: site.call_kind,
                    via_span: site.call_span,
                },
            },
            ws,
            known_edges,
        );
        changed |= connect_field_write_to_reads(
            site.caller_seg,
            site.caller,
            &site.target_base,
            &field,
            target_field_write,
            site.write_span,
            site.precision,
            site.call_kind,
            ws,
            known_edges,
        );
    }
    changed
}

#[derive(Clone, Debug)]
struct FieldCopySite {
    seg_id: SegmentId,
    func: FuncId,
    source_base: String,
    target_base: String,
    write_span: Span,
    via_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
}

fn call_ret_assignment_targets(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    call_ret_node: NodeId,
) -> Vec<(String, Span)> {
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for edge in &segment.edges {
        if edge.from != call_ret_node || !edge.meta.kind.is_intra() {
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
        let Some((target_base, write_span)) = write_place_storage_and_span(segment, to_place) else {
            continue;
        };
        if target_base.trim().is_empty() || target_base.contains('.') {
            continue;
        }
        out.push((target_base, write_span));
    }
    out.sort_by(|a, b| (a.0.as_str(), a.1.start).cmp(&(b.0.as_str(), b.1.start)));
    out.dedup();
    out
}

fn stitch_intra_field_copies(
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) -> bool {
    let copy_sites = collect_field_copy_sites(ws);
    let mut changed = false;
    for site in copy_sites {
        let source_writers = collect_field_writes_for_base(ws, site.seg_id, site.func, &site.source_base);
        if source_writers.is_empty() {
            continue;
        }
        for (field, source_writer) in source_writers {
            if !is_forwardable_field(&field) {
                continue;
            }
            let Some(target_field_write) = ensure_field_write_node(
                ws,
                site.seg_id,
                site.func,
                &site.target_base,
                &field,
                site.write_span,
            ) else {
                continue;
            };
            if source_writer == target_field_write {
                continue;
            }
            changed |= place_inter_edge_if_absent(
                site.seg_id,
                site.seg_id,
                IdgEdge {
                    from: source_writer,
                    to: target_field_write,
                    meta: crate::edge::EdgeMeta {
                        precision: site.precision,
                        kind: crate::edge::IdgEdgeKind::IntraAssign,
                        call_kind: site.call_kind,
                        via_span: site.via_span,
                    },
                },
                ws,
                known_edges,
            );
            changed |= connect_field_write_to_reads(
                site.seg_id,
                site.func,
                &site.target_base,
                &field,
                target_field_write,
                site.write_span,
                site.precision,
                site.call_kind,
                ws,
                known_edges,
            );
        }
    }
    changed
}

fn is_forwardable_field(field: &str) -> bool {
    let parts = storage_segments(field);
    !parts.is_empty() && parts.len() <= 2
}

fn collect_field_copy_sites(ws: &IdgWorkspace) -> Vec<FieldCopySite> {
    let mut out = Vec::new();
    for (seg_id, segment) in ws.segments() {
        for edge in &segment.edges {
            if !edge.meta.kind.is_intra() {
                continue;
            }
            let Some(from_node) = segment.nodes.get(edge.from) else {
                continue;
            };
            let Some(to_node) = segment.nodes.get(edge.to) else {
                continue;
            };
            if from_node.func != to_node.func {
                continue;
            }
            let Some(from_place) = segment.places.get(from_node.place) else {
                continue;
            };
            let Some(to_place) = segment.places.get(to_node.place) else {
                continue;
            };
            if !is_unprojected_storage_place(segment, from_place) {
                continue;
            }
            let Some(source_base) = place_storage_name(segment, from_place) else {
                continue;
            };
            let Some((target_base, write_span)) = write_place_storage_and_span(segment, to_place) else {
                continue;
            };
            if source_base.is_empty()
                || target_base.is_empty()
                || source_base == target_base
                || !is_container_copy_target(&target_base)
            {
                continue;
            }
            out.push(FieldCopySite {
                seg_id,
                func: from_node.func,
                source_base,
                target_base,
                write_span,
                via_span: edge.meta.via_span,
                precision: edge.meta.precision,
                call_kind: edge.meta.call_kind,
            });
        }
    }
    out.sort_by(|a, b| {
        (
            a.seg_id.0,
            a.func.raw(),
            a.source_base.as_str(),
            a.target_base.as_str(),
            a.write_span.start,
        )
            .cmp(&(
                b.seg_id.0,
                b.func.raw(),
                b.source_base.as_str(),
                b.target_base.as_str(),
                b.write_span.start,
            ))
    });
    out.dedup_by(|a, b| {
        a.seg_id == b.seg_id
            && a.func == b.func
            && a.source_base == b.source_base
            && a.target_base == b.target_base
            && a.write_span == b.write_span
            && a.via_span == b.via_span
    });
    out
}

fn is_container_copy_target(target: &str) -> bool {
    let parts = storage_segments(target);
    match parts.as_slice() {
        [_bare] => true,
        [receiver, _field] => is_implicit_receiver_name(receiver),
        [base, ..] => base
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch == '$' || ch.is_ascii_lowercase()),
        _ => false,
    }
}

fn storage_segments(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    push_storage_segments(text, &mut parts);
    parts
}

fn is_implicit_receiver_name(name: &str) -> bool {
    matches!(name.trim(), "self" | "this" | "$this" | "Self")
}

fn is_unprojected_storage_place(segment: &crate::segment::IdgSegment, place: &Place) -> bool {
    let (name, path) = match place {
        Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
        _ => return false,
    };
    if !path.is_empty() {
        return false;
    }
    let Some(name) = segment.strings.get(name) else {
        return false;
    };
    let name = name.trim();
    !name.is_empty() && !name.contains('.') && !name.contains('[') && !name.contains(']')
}

#[allow(clippy::too_many_arguments)] // Keeps call-site/copy-site metadata explicit at edge construction.
fn connect_field_write_to_reads(
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
    field: &str,
    writer: NodeId,
    via_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) -> bool {
    let readers = collect_field_reads_for_base(ws, seg_id, func, base);
    let mut changed = false;
    for (reader_field, reader) in readers {
        if reader_field != field || reader == writer {
            continue;
        }
        changed |= place_inter_edge_if_absent(
            seg_id,
            seg_id,
            IdgEdge {
                from: writer,
                to: reader,
                meta: crate::edge::EdgeMeta {
                    precision,
                    kind: crate::edge::IdgEdgeKind::IntraFieldRead,
                    call_kind,
                    via_span,
                },
            },
            ws,
            known_edges,
        );
    }
    changed
}

fn ensure_field_write_node(
    ws: &mut IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
    field: &str,
    span: Span,
) -> Option<NodeId> {
    let (name, path_parts) = storage_path_parts(base, field)?;
    let segment = ws.segment_mut(seg_id)?;
    let name_id = segment.strings.intern(&name);
    let mut path: SmallVec<[StrId; 4]> = SmallVec::new();
    for part in path_parts {
        path.push(segment.strings.intern(&part));
    }
    let pid = segment.intern_place(Place::Write {
        name: name_id,
        path,
        span,
    });
    Some(segment.intern_node(func, pid))
}

fn storage_path_parts(base: &str, field: &str) -> Option<(String, Vec<String>)> {
    let mut parts = Vec::new();
    push_storage_segments(base, &mut parts);
    push_storage_segments(field, &mut parts);
    if parts.is_empty() {
        return None;
    }
    let name = parts.remove(0);
    Some((name, parts))
}

fn push_storage_segments(text: &str, out: &mut Vec<String>) {
    let normalized = normalize_static_subscripts(text);
    for part in normalized.split('.') {
        let part = part.trim();
        if !part.is_empty() {
            out.push(part.to_string());
        }
    }
}

fn normalize_static_subscripts(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '[' {
            out.push(ch);
            continue;
        }
        let mut inner = String::new();
        let mut closed = false;
        for inner_ch in chars.by_ref() {
            if inner_ch == ']' {
                closed = true;
                break;
            }
            inner.push(inner_ch);
        }
        if !closed {
            out.push('[');
            out.push_str(&inner);
            break;
        }
        let key = inner
            .trim()
            .trim_start_matches(':')
            .trim_matches('"')
            .trim_matches('\'')
            .trim();
        if !key.is_empty() && key.chars().all(|c| c.is_alphanumeric() || c == '_') {
            out.push('.');
            out.push_str(key);
        }
    }
    out
}

fn collect_field_writes_for_base(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
) -> Vec<(String, NodeId)> {
    collect_field_places_for_base(ws, seg_id, func, base, true)
}

fn collect_field_writes_for_base_before_call(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
    call_span: Span,
) -> Vec<(String, NodeId)> {
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let Some((full_name, write_span)) = write_place_storage_and_span(segment, place) else {
            continue;
        };
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        if write_span.file == call_span.file
            && write_span.start > call_span.start
            && !has_inter_call_arg_entry_edge(ws, seg_id, func, local)
        {
            continue;
        }
        let Some(field) = relative_field_name(&full_name, base) else {
            continue;
        };
        out.push((field.to_string(), local));
    }
    out.sort_by(|a, b| (a.0.as_str(), a.1 .0).cmp(&(b.0.as_str(), b.1 .0)));
    out.dedup();
    out
}

fn has_inter_call_arg_entry_edge(ws: &IdgWorkspace, seg_id: SegmentId, func: FuncId, local: NodeId) -> bool {
    let Some(segment) = ws.segment(seg_id) else {
        return false;
    };
    for edge in &segment.edges {
        if edge.to != local || edge.meta.kind != crate::edge::IdgEdgeKind::InterCallArg {
            continue;
        }
        let Some(to_node) = segment.nodes.get(edge.to) else {
            continue;
        };
        if to_node.func == func {
            return true;
        }
    }
    ws.cross_file().edges.iter().any(|cross| {
        if cross.to_segment != seg_id
            || cross.edge.to != local
            || cross.edge.meta.kind != crate::edge::IdgEdgeKind::InterCallArg
        {
            return false;
        }
        ws.segment(cross.to_segment)
            .and_then(|segment| segment.nodes.get(cross.edge.to))
            .is_some_and(|to_node| to_node.func == func)
    })
}

fn collect_field_reads_for_base(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
) -> Vec<(String, NodeId)> {
    collect_field_places_for_base(ws, seg_id, func, base, false)
}

fn collect_field_places_for_base(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
    writes: bool,
) -> Vec<(String, NodeId)> {
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let is_target_kind = matches!(
            (writes, place),
            (true, Place::Write { .. }) | (false, Place::Read { .. })
        );
        if !is_target_kind {
            continue;
        }
        let Some(full_name) = place_storage_name(segment, place) else {
            continue;
        };
        let Some(field) = relative_field_name(&full_name, base) else {
            continue;
        };
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        out.push((field.to_string(), local));
    }
    out.sort_by(|a, b| (a.0.as_str(), a.1 .0).cmp(&(b.0.as_str(), b.1 .0)));
    out.dedup();
    out
}

fn place_storage_name(segment: &crate::segment::IdgSegment, place: &Place) -> Option<String> {
    let (name, path) = match place {
        Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
        _ => return None,
    };
    let base = segment.strings.get(name)?;
    if path.is_empty() {
        return Some(base.to_string());
    }
    let mut out = base.to_string();
    for part in path {
        out.push('.');
        out.push_str(segment.strings.get(*part)?);
    }
    Some(out)
}

fn write_place_storage_and_span(
    segment: &crate::segment::IdgSegment,
    place: &Place,
) -> Option<(String, Span)> {
    let Place::Write { span, .. } = place else {
        return None;
    };
    place_storage_name(segment, place).map(|name| (name, *span))
}

fn relative_field_name<'a>(full_name: &'a str, base: &str) -> Option<&'a str> {
    let base = base.trim();
    if base.is_empty() || full_name == base {
        return None;
    }
    let rest = full_name.strip_prefix(base)?;
    rest.strip_prefix('.').filter(|field| !field.is_empty())
}

fn stitch_debug_enabled() -> bool {
    bonsai_diagnostics::debug::is_enabled("idg-build")
}

fn stitch_debug_log(args: std::fmt::Arguments<'_>) {
    if stitch_debug_enabled() {
        eprintln!("[idg-build] {args}");
    }
}

fn collect_existing_edges(ws: &IdgWorkspace) -> AHashSet<(SegmentId, SegmentId, IdgEdge)> {
    let mut out = AHashSet::default();
    for (seg_id, segment) in ws.segments() {
        for edge in &segment.edges {
            out.insert((seg_id, seg_id, *edge));
        }
    }
    for edge in &ws.cross_file().edges {
        out.insert((edge.from_segment, edge.to_segment, edge.edge));
    }
    out
}

fn place_inter_edge_if_absent(
    from_seg: SegmentId,
    to_seg: SegmentId,
    edge: IdgEdge,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) -> bool {
    if !known_edges.insert((from_seg, to_seg, edge)) {
        return false;
    }
    place_inter_edge(from_seg, to_seg, edge, ws);
    true
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
#[path = "builder_tests.rs"]
mod tests;
