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
//!    - `caller.CallArg(site, u32::MAX) → callee.Param(receiver)`
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
use std::collections::VecDeque;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use crate::edge::IdgEdge;
use crate::node::NodeId;
use crate::place::{CallSiteId, Place};
use crate::segment::IdgSegment;
use crate::transfer::{
    inline_call_result_receiver_base, inline_constructor_receiver_base, receiver_name_matches,
    receiver_tokens_equal, CallSiteRef, DescendantCopy, FlowControlFacts, ReturnFieldProjection,
    TransferOutput,
};
use crate::workspace::{CrossFileEdge, IdgWorkspace, SegmentId};

#[derive(Debug, Clone)]
struct CalleeEndpoints {
    segment: SegmentId,
    params: Vec<NodeId>,
    param_names: Vec<String>,
    /// Non-entry binding writes to each formal parameter. A write is
    /// only stitched back to the caller when the corresponding actual
    /// argument is explicitly passed by mutable reference/address.
    param_write_nodes: Vec<Vec<NodeId>>,
    /// Bare reads with no local writer in the callee. For a
    /// resolver-proven local callable these are lexical captures;
    /// ordinary functions do not receive capture stitching.
    capture_read_nodes: Vec<(String, NodeId)>,
    receiver_param_index: Option<usize>,
    receiver_consumer_nodes: Vec<NodeId>,
    receiver_field_bases: Vec<String>,
    implicit_receiver_bases: Vec<String>,
    receiver_names: Vec<String>,
    return_field_projections: Vec<ReturnFieldProjection>,
    return_passthrough_param_indices: Vec<usize>,
    return_node: Option<NodeId>,
}

#[derive(Debug)]
struct FunctionStitchData {
    params: Vec<String>,
    call_sites: Vec<CallSiteRef>,
    param_count: usize,
    is_constructor: bool,
    has_return_event: bool,
    receiver_param_index: Option<usize>,
    receiver_field_bases: Vec<String>,
    implicit_receiver_bases: Vec<String>,
    receiver_names: Vec<String>,
    return_field_projections: Vec<ReturnFieldProjection>,
    return_passthrough_param_indices: Vec<usize>,
    descendant_copies: Vec<DescendantCopy>,
    flow_control: FlowControlFacts,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    allow_out_of_order_source: bool,
}

const STORAGE_SEGMENTS_CACHE_CAP: usize = 131_072;
static STORAGE_SEGMENTS_CACHE: LazyLock<parking_lot::RwLock<AHashMap<String, Arc<[String]>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));
static NORMALIZED_STORAGE_CACHE: LazyLock<parking_lot::RwLock<AHashMap<String, Arc<str>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

#[derive(Default, Debug)]
struct FieldArgSiteQueue {
    sites: Vec<Arc<FieldArgStitch>>,
    seen: AHashSet<Arc<FieldArgStitch>>,
}

impl FieldArgSiteQueue {
    fn push(&mut self, site: FieldArgStitch) {
        if !field_forwarding_base_allowed(&site.actual_arg)
            || !field_forwarding_base_allowed(&site.param_name)
        {
            return;
        }
        if normalize_storage_base_cached(&site.actual_arg).is_empty() {
            return;
        }
        let site = Arc::new(site);
        if self.seen.insert(Arc::clone(&site)) {
            self.sites.push(site);
        }
    }

    fn into_sites(self) -> Vec<Arc<FieldArgStitch>> {
        self.sites
    }

    fn len(&self) -> usize {
        self.sites.len()
    }
}

#[derive(Default, Debug)]
struct ReturnFieldSiteQueue {
    sites: Vec<Arc<ReturnFieldStitch>>,
    seen: AHashSet<Arc<ReturnFieldStitch>>,
}

#[derive(Default, Debug)]
struct ScalarReturnSiteQueue {
    sites: Vec<Arc<ScalarReturnStitch>>,
    seen: AHashSet<Arc<ScalarReturnStitch>>,
}

impl ScalarReturnSiteQueue {
    fn push(&mut self, site: ScalarReturnStitch) {
        if !field_forwarding_base_allowed(&site.source_base)
            || !field_forwarding_base_allowed(&site.target_base)
        {
            return;
        }
        if normalize_storage_base_cached(&site.source_base).is_empty() {
            return;
        }
        let site = Arc::new(site);
        if self.seen.insert(Arc::clone(&site)) {
            self.sites.push(site);
        }
    }

    fn into_sites(self) -> Vec<Arc<ScalarReturnStitch>> {
        self.sites
    }

    fn len(&self) -> usize {
        self.sites.len()
    }
}

impl ReturnFieldSiteQueue {
    fn push(&mut self, site: ReturnFieldStitch) {
        if !field_forwarding_base_allowed(&site.target_base) {
            return;
        }
        if normalize_storage_base_cached(&site.source_base).is_empty() {
            return;
        }
        let site = Arc::new(site);
        if self.seen.insert(Arc::clone(&site)) {
            self.sites.push(site);
        }
    }

    fn into_sites(self) -> Vec<Arc<ReturnFieldStitch>> {
        self.sites
    }

    fn len(&self) -> usize {
        self.sites.len()
    }
}

#[derive(Default, Debug)]
struct ConstructorReturnSiteQueue {
    sites: Vec<Arc<ConstructorReturnStitch>>,
    seen: AHashSet<Arc<ConstructorReturnStitch>>,
}

impl ConstructorReturnSiteQueue {
    fn push(&mut self, site: ConstructorReturnStitch) {
        if !field_forwarding_base_allowed(&site.target_base)
            || !field_forwarding_base_allowed(&site.receiver_param_name)
        {
            return;
        }
        if normalize_storage_base_cached(&site.receiver_param_name).is_empty() {
            return;
        }
        let site = Arc::new(site);
        if self.seen.insert(Arc::clone(&site)) {
            self.sites.push(site);
        }
    }

    fn into_sites(self) -> Vec<Arc<ConstructorReturnStitch>> {
        self.sites
    }

    fn len(&self) -> usize {
        self.sites.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ScalarReturnStitch {
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    source_base: String,
    source_field: String,
    target_base: String,
    call_span: Span,
    write_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FieldPlaceHit {
    field: String,
    node: NodeId,
    span: Option<Span>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FieldPlaceKey {
    seg_id: SegmentId,
    func: FuncId,
    base: String,
    writes: bool,
}

#[derive(Default, Debug)]
struct FieldPlaceIndex {
    by_base: AHashMap<FieldPlaceKey, Vec<FieldPlaceHit>>,
    /// Exact storage names read by the AST. A bare read of a transform
    /// target (for example `sink(obj)`) is a wildcard demand for every
    /// concrete field that can reach that object; projected reads continue
    /// to use the precise `(base, suffix)` index above.
    read_storages: AHashSet<(SegmentId, FuncId, String)>,
    /// AST read nodes with at least one use other than carrying a value into
    /// a `CallArg`. Carrier-only reads stay indexed for propagation but are
    /// not liveness roots unless the call site is an explicit terminal.
    observable_read_nodes: AHashSet<(SegmentId, FuncId, NodeId)>,
}

#[derive(Default, Debug)]
struct FieldDemandIndex {
    key_ids: AHashMap<FieldPlaceKey, usize>,
    field_ids: AHashMap<String, u32>,
    fields_by_key: Vec<Vec<u32>>,
    all_fields_by_key: Vec<bool>,
}

impl FieldDemandIndex {
    fn contains_all(&self, key: &FieldPlaceKey) -> bool {
        let Some(key_id) = self.key_ids.get(key).copied() else {
            return false;
        };
        self.all_fields_by_key.get(key_id).copied().unwrap_or(false)
    }

    fn contains_exact(&self, key: &FieldPlaceKey, field: &str) -> bool {
        let Some(key_id) = self.key_ids.get(key).copied() else {
            return false;
        };
        let Some(field_id) = self.field_ids.get(field).copied() else {
            return false;
        };
        self.fields_by_key
            .get(key_id)
            .is_some_and(|fields| fields.binary_search(&field_id).is_ok())
    }

    fn contains(&self, key: &FieldPlaceKey, field: &str) -> bool {
        self.contains_all(key) || self.contains_exact(key, field)
    }
}

/// Finite access-path demand derived from the adapter-produced IDG before
/// synthetic interprocedural writes are added. This is the compiler-style
/// termination boundary for recursive base substitution: arbitrary syntactic
/// depth is supported, but the closure does not invent field suffixes absent
/// from the program's AST facts.
#[derive(Default, Debug)]
struct SyntacticFieldUniverse {
    suffixes: AHashSet<String>,
}

impl SyntacticFieldUniverse {
    fn contains(&self, field: &str) -> bool {
        self.suffixes.contains(field)
    }
}

#[derive(Default, Debug)]
struct InterCallArgEntryIndex {
    entries: AHashSet<(SegmentId, FuncId, NodeId)>,
}

#[derive(Default, Debug)]
struct SyntheticFieldWriteCache {
    /// Node ids are segment-local and append-only. A node at or beyond the
    /// segment's pre-closure length was synthesized by field forwarding, so
    /// compiler dictionary identity replaces a hash entry per generated node.
    initial_node_counts: Vec<u32>,
    /// Interprocedural parameters are phi-like compiler places: one callee
    /// field node receives edges from every resolved caller. Call provenance
    /// remains on each edge, so duplicating the destination by call span adds
    /// no information and explodes on widely called methods.
    parameter_nodes: AHashMap<(SegmentId, FuncId, String, String), (NodeId, Span)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PendingFieldWrite {
    seg_id: SegmentId,
    func: FuncId,
    node: NodeId,
}

#[derive(Clone, Debug)]
enum FieldWriteTransform {
    Argument(Arc<FieldArgStitch>),
    Return(Arc<ReturnFieldStitch>),
    ScalarReturn(Arc<ScalarReturnStitch>),
    ConstructorReturn(Arc<ConstructorReturnStitch>),
    ReceiverMutation(Arc<ReceiverMutationStitch>),
    Copy(FieldCopySite),
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
        call_kind: CallKind,
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
    fn callback_bindings(&self, _host: FuncId, _param_idx: u32) -> Vec<ResolvedCallee> {
        Vec::new()
    }

    /// Resolve a callable value passed as an argument at `caller`.
    /// Rulepack-declared source-callback APIs use this to model
    /// external/library calls that invoke a callback with source data.
    fn callable_arg(&self, _caller: FuncId, _arg_text: &str) -> Vec<ResolvedCallee> {
        Vec::new()
    }

    /// Resolve callable values proven by indirect callgraph edges whose
    /// source span is contained by this argument expression. This covers
    /// nested callable-producing syntax without parsing its text or naming
    /// a library helper in the IDG engine.
    fn callable_args_in_span(&self, _caller: FuncId, _arg_span: Span) -> Vec<ResolvedCallee> {
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

    /// True when `callee` belongs to a declared ancestor of the receiver
    /// class that owns `caller`. Workspace implementations derive this from
    /// resolved declaration/callgraph identity; the IDG never guesses from a
    /// receiver spelling such as `super` or `base`.
    fn is_ancestor_dispatch(&self, _caller: FuncId, _callee: FuncId) -> bool {
        false
    }

    /// True when `callee` is the function value assigned to a local
    /// callable binding in `caller` (for example `let f = { ... }`).
    /// This is the precision boundary for lexical capture stitching.
    fn is_local_callable_binding(&self, _caller: FuncId, _callee: FuncId) -> bool {
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
    stitch_idg_with_field_argument_forwarding(outputs, resolver, f2s, true)
}

/// Stitch per-function `TransferOutput`s with optional eager
/// interprocedural object-field forwarding.
pub fn stitch_idg_with_field_argument_forwarding(
    outputs: Vec<TransferOutput>,
    resolver: &dyn CalleeResolver,
    f2s: &dyn FuncToSegment,
    include_field_argument_forwarding: bool,
) -> IdgWorkspace {
    stitch_idg_with_field_forwarding_mode(outputs, resolver, f2s, include_field_argument_forwarding, false)
}

/// Stitch with an optional sparse, read-demanded field closure. The sparse
/// mode changes only which unobserved synthetic writes are materialized; all
/// paths ending at an AST field read or scalar projection remain complete.
pub fn stitch_idg_with_field_forwarding_mode(
    outputs: Vec<TransferOutput>,
    resolver: &dyn CalleeResolver,
    f2s: &dyn FuncToSegment,
    include_field_argument_forwarding: bool,
    demand_driven_field_forwarding: bool,
) -> IdgWorkspace {
    stitch_idg_with_selective_field_forwarding_mode(
        outputs,
        resolver,
        f2s,
        include_field_argument_forwarding,
        demand_driven_field_forwarding,
        None,
        None,
    )
}

/// Stitch with demand-driven field forwarding limited to adapter functions
/// whose AST field-place emission is complete. `None` preserves the public
/// all-functions sparse mode used by focused IDG tests and direct callers.
pub fn stitch_idg_with_selective_field_forwarding_mode(
    outputs: Vec<TransferOutput>,
    resolver: &dyn CalleeResolver,
    f2s: &dyn FuncToSegment,
    include_field_argument_forwarding: bool,
    demand_driven_field_forwarding: bool,
    demand_driven_funcs: Option<&AHashSet<FuncId>>,
    field_demand_terminal_sites: Option<&AHashSet<(FuncId, Span)>>,
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
                receiver_field_bases,
                implicit_receiver_bases,
                receiver_names,
                return_field_projections,
                return_passthrough_param_indices,
                descendant_copies,
                flow_control,
                call_sites,
                is_constructor,
                has_return_event,
                ..
            } = out;
            let param_count = params.len();
            stitch_data.insert(
                func,
                FunctionStitchData {
                    params,
                    call_sites,
                    param_count,
                    is_constructor,
                    has_return_event,
                    receiver_param_index,
                    receiver_field_bases,
                    implicit_receiver_bases,
                    receiver_names,
                    return_field_projections,
                    return_passthrough_param_indices,
                    descendant_copies,
                    flow_control,
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
    let mut field_arg_sites = FieldArgSiteQueue::default();
    let mut return_field_sites = ReturnFieldSiteQueue::default();
    let mut scalar_return_sites = ScalarReturnSiteQueue::default();
    let mut constructor_return_sites = ConstructorReturnSiteQueue::default();
    let mut receiver_mutation_sites: Vec<Arc<ReceiverMutationStitch>> = Vec::new();
    let mut passthrough_field_copy_sites: Vec<FieldCopySite> = Vec::new();
    for (&func, data) in &stitch_data {
        let Some((seg_id, _)) = seg_remaps.get(&func) else {
            continue;
        };
        passthrough_field_copy_sites.extend(data.descendant_copies.iter().map(|copy| FieldCopySite {
            seg_id: *seg_id,
            func,
            source_base: copy.source_base.clone(),
            target_base: copy.target_base.clone(),
            write_span: copy.span,
            via_span: copy.span,
            precision: Precision::Exact,
            call_kind: CallEdgeKind::Direct,
        }));
    }
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
                data.is_constructor,
                data.receiver_param_index,
                &data.implicit_receiver_bases,
                &data.receiver_names,
                resolver,
                &callee_endpoints,
                &mut ws,
                &mut field_arg_sites,
                &mut return_field_sites,
                &mut scalar_return_sites,
                &mut constructor_return_sites,
                &mut receiver_mutation_sites,
                &mut passthrough_field_copy_sites,
                if collect_stats { Some(&mut stats) } else { None },
            );
        }
    }
    dedup_receiver_mutation_sites(&mut receiver_mutation_sites);
    let field_arg_site_count = field_arg_sites.len();
    let return_field_site_count = return_field_sites.len();
    let scalar_return_site_count = scalar_return_sites.len();
    let constructor_return_site_count = constructor_return_sites.len();
    let receiver_mutation_site_count = receiver_mutation_sites.len();
    stitch_debug_log(format_args!(
        "stitch call-sites-wired: {:.3}s field_arg_sites={} return_field_sites={} scalar_return_sites={} constructor_return_sites={} receiver_mutation_sites={}",
        call_started.elapsed().as_secs_f64(),
        field_arg_site_count,
        return_field_site_count,
        scalar_return_site_count,
        constructor_return_site_count,
        receiver_mutation_site_count
    ));
    // Drop the large hash-table dedup indexes before materializing field
    // transforms. The vectors and transform table share each site record via
    // `Arc`, so strings remain single-owner throughout the closure build.
    let field_arg_sites = field_arg_sites.into_sites();
    let return_field_sites = return_field_sites.into_sites();
    let scalar_return_sites = scalar_return_sites.into_sites();
    let constructor_return_sites = constructor_return_sites.into_sites();
    if include_field_argument_forwarding {
        stitch_field_argument_forwarding(
            &field_arg_sites,
            &return_field_sites,
            &scalar_return_sites,
            &constructor_return_sites,
            &receiver_mutation_sites,
            &passthrough_field_copy_sites,
            &stitch_data,
            &mut ws,
            demand_driven_field_forwarding,
            demand_driven_funcs,
            field_demand_terminal_sites,
        );
    } else {
        stitch_debug_log(format_args!(
            "field-forward worklist: skipped eager closure field_arg_sites={} return_field_sites={} scalar_return_sites={} constructor_return_sites={} receiver_mutation_sites={}",
            field_arg_site_count,
            return_field_site_count,
            scalar_return_site_count,
            constructor_return_site_count,
            receiver_mutation_site_count
        ));
    }
    stitch_debug_log(format_args!(
        "stitch calls: {:.3}s sites={} candidates={} callback_lookups={} callback_candidates={} wired_candidates={} inter_edges={} passthrough_edges={} field_arg_sites={} return_field_sites={} scalar_return_sites={} constructor_return_sites={} receiver_mutation_sites={} resolve={:.3}s callback={:.3}s",
        call_started.elapsed().as_secs_f64(),
        stats.sites,
        stats.resolved_candidates,
        stats.callback_lookups,
        stats.callback_candidates,
        stats.wired_candidates,
        stats.inter_edges,
        stats.passthrough_edges,
        field_arg_site_count,
        return_field_site_count,
        scalar_return_site_count,
        constructor_return_site_count,
        receiver_mutation_site_count,
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
    let mut returned_nodes_by_segment: AHashMap<SegmentId, AHashSet<NodeId>> = AHashMap::new();
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
            let Ok(idx) = u32::try_from(idx) else { break };
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
        let returned_nodes = returned_nodes_by_segment
            .entry(segment_id)
            .or_insert_with(|| collect_return_value_nodes(segment));
        // A function that both yields and returns (notably Ruby methods
        // invoking a block) still assigns its explicit return value at the
        // call site. Treat Yield as the result endpoint only for generator-
        // shaped declarations with no explicit Return node.
        let has_return_event = stitch_data.get(&func).is_some_and(|data| data.has_return_event);
        let return_node = if has_return_event {
            // A literal or void return deliberately has no inbound dataflow,
            // but it is still the function's result endpoint. Never replace
            // it with Yield merely because the returned value is clean.
            plain_return_node
        } else {
            plain_return_node
                .filter(|node| returned_nodes.contains(node))
                .or_else(|| yield_node.filter(|node| yielded_nodes.contains(node)))
                .or(plain_return_node)
        };
        let param_names = stitch_data
            .get(&func)
            .map(|data| data.params.clone())
            .unwrap_or_default();
        let param_write_nodes = collect_non_entry_param_write_nodes(segment, func, &param_names, &params);
        let capture_read_nodes = collect_unrooted_scalar_reads(segment, func);
        out.insert(
            func,
            CalleeEndpoints {
                segment: segment_id,
                params,
                param_names,
                param_write_nodes,
                capture_read_nodes,
                receiver_param_index: stitch_data.get(&func).and_then(|data| data.receiver_param_index),
                receiver_consumer_nodes: stitch_data
                    .get(&func)
                    .map(|data| collect_receiver_consumer_nodes(segment, func, data))
                    .unwrap_or_default(),
                receiver_field_bases: stitch_data
                    .get(&func)
                    .map(|data| data.receiver_field_bases.clone())
                    .unwrap_or_default(),
                implicit_receiver_bases: stitch_data
                    .get(&func)
                    .map(|data| data.implicit_receiver_bases.clone())
                    .unwrap_or_default(),
                receiver_names: stitch_data
                    .get(&func)
                    .map(|data| data.receiver_names.clone())
                    .unwrap_or_default(),
                return_field_projections: stitch_data
                    .get(&func)
                    .map(|data| data.return_field_projections.clone())
                    .unwrap_or_default(),
                return_passthrough_param_indices: stitch_data
                    .get(&func)
                    .map(|data| data.return_passthrough_param_indices.clone())
                    .unwrap_or_default(),
                return_node,
            },
        );
    }
    out
}

fn collect_unrooted_scalar_reads(segment: &IdgSegment, func: FuncId) -> Vec<(String, NodeId)> {
    let mut out = Vec::new();
    for (node_idx, node) in segment.nodes.nodes.iter().enumerate() {
        if node.func != func {
            continue;
        }
        let Some(Place::Read { name, path }) = segment.places.get(node.place) else {
            continue;
        };
        if !path.is_empty() {
            continue;
        }
        let Some(name) = segment.strings.get(*name) else {
            continue;
        };
        if !name.trim().is_empty() {
            out.push((name.to_string(), NodeId(node_idx as u32)));
        }
    }
    out
}

fn collect_non_entry_param_write_nodes(
    segment: &IdgSegment,
    func: FuncId,
    param_names: &[String],
    params: &[NodeId],
) -> Vec<Vec<NodeId>> {
    let mut out = vec![Vec::new(); param_names.len()];
    for (node_idx, node) in segment.nodes.nodes.iter().enumerate() {
        if node.func != func {
            continue;
        }
        let Some(Place::Write { name, path, .. }) = segment.places.get(node.place) else {
            continue;
        };
        if !path.is_empty() {
            continue;
        }
        let Some(write_name) = segment.strings.get(*name) else {
            continue;
        };
        let Some(param_idx) = param_names
            .iter()
            .position(|param| param.trim() == write_name.trim())
        else {
            continue;
        };
        let write_node = NodeId(node_idx as u32);
        let is_entry_binding = params.get(param_idx).is_some_and(|param_node| {
            !param_node.is_sentinel()
                && segment
                    .edges
                    .iter()
                    .any(|edge| edge.from == *param_node && edge.to == write_node)
        });
        if !is_entry_binding {
            out[param_idx].push(write_node);
        }
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

fn collect_return_value_nodes(segment: &IdgSegment) -> AHashSet<NodeId> {
    let mut out = AHashSet::new();
    for edge in &segment.edges {
        let Some(to_node) = segment.nodes.get(edge.to) else {
            continue;
        };
        let Some(to_place) = segment.places.get(to_node.place) else {
            continue;
        };
        if matches!(to_place, Place::Return) {
            out.insert(edge.to);
        }
    }
    out
}

fn collect_receiver_consumer_nodes(
    segment: &IdgSegment,
    func: FuncId,
    data: &FunctionStitchData,
) -> Vec<NodeId> {
    let mut out = Vec::new();
    for site in &data.call_sites {
        if matches!(site.call_kind, CallKind::Method) {
            let receiver_is_implicit = site
                .receiver
                .as_deref()
                .map(str::trim)
                .is_some_and(|receiver| receiver_name_matches(receiver, &data.receiver_names));
            if receiver_is_implicit {
                push_call_arg_node(segment, func, site.site, u32::MAX, &mut out);
            }
        }
        if site.explicit_args_count == 0 && site.receiver.is_none() && !site.receiver_types.is_empty() {
            push_call_arg_node(segment, func, site.site, 0, &mut out);
        }
    }
    // A callee that consumes its implicit receiver as a VALUE — passes
    // `this`/`self` as a call argument (`sink(this)`), returns it, or
    // reads it into an assignment — surfaces as a bare `Read` place on
    // the implicit-receiver name. Languages with an explicit receiver
    // parameter (Python `self`) route this through `receiver_param_index`
    // instead; for implicit-`this` languages (Java/Kotlin/JS/C#/…) these
    // Read nodes are the only endpoint that lets a tainted caller
    // receiver (`args.method()`) flow into the method body.
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let Place::Read { name, path } = place else {
            continue;
        };
        if !path.is_empty() {
            continue;
        }
        let Some(name_text) = segment.strings.get(*name) else {
            continue;
        };
        if !receiver_name_matches(name_text, &data.receiver_names) {
            continue;
        }
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(node) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        if !node.is_sentinel() {
            out.push(node);
        }
    }
    out.sort_by_key(|node| node.0);
    out.dedup();
    out
}

fn push_call_arg_node(segment: &IdgSegment, func: FuncId, site: CallSiteId, idx: u32, out: &mut Vec<NodeId>) {
    let place = Place::CallArg { site, idx };
    let Some(pid) = segment.places.lookup(&place) else {
        return;
    };
    let Some(node) = segment.nodes.lookup(func, pid) else {
        return;
    };
    if !node.is_sentinel() {
        out.push(node);
    }
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
    caller_is_constructor: bool,
    caller_receiver_param_index: Option<usize>,
    caller_implicit_receiver_bases: &[String],
    caller_receiver_names: &[String],
    resolver: &dyn CalleeResolver,
    callee_endpoints: &AHashMap<FuncId, CalleeEndpoints>,
    ws: &mut IdgWorkspace,
    field_arg_sites: &mut FieldArgSiteQueue,
    return_field_sites: &mut ReturnFieldSiteQueue,
    scalar_return_sites: &mut ScalarReturnSiteQueue,
    constructor_return_sites: &mut ConstructorReturnSiteQueue,
    receiver_mutation_sites: &mut Vec<Arc<ReceiverMutationStitch>>,
    passthrough_field_copy_sites: &mut Vec<FieldCopySite>,
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
        site.call_kind,
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
    let callback_param_idx: Option<u32> =
        if let Some(recv) = site.receiver.as_deref().filter(|r| !r.is_empty()) {
            // Receiver-form callback. The receiver text might be the
            // param name directly (`cb.accept(...)` → receiver "cb")
            // or a sigil'd form (`$cb` in perl). Strip leading `$`/`@`
            // sigils before matching.
            let stripped = recv.trim_start_matches(['$', '@', '%', '&']);
            caller_params
                .iter()
                .position(|p| p == recv || p == stripped)
                .and_then(|i| u32::try_from(i).ok())
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
                .and_then(|i| u32::try_from(i).ok())
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
    // Compatibility-only unresolved-call summary. The security graph keeps
    // this disabled and supplies explicit rulepack passthrough shapes. The
    // token-level legacy API enables it so an external value constructor such
    // as `path = os.path.join(base, name)` and nested transforms such as
    // `map(..., cmd.split(" "))` retain the old conservative argument/receiver
    // → result contract without weakening resolved callees whose explicit
    // Return semantics are known.
    let has_stitchable_candidate = candidates
        .iter()
        .any(|candidate| callee_endpoints.contains_key(&candidate.func));
    // Constructor syntax itself proves that the returned object incorporates
    // its arguments even when the constructor body lives outside the indexed
    // workspace. This exception is keyed only by adapter-emitted CallKind,
    // never by a class/API name heuristic.
    let unmodeled_constructor = !has_stitchable_candidate && call_site_is_constructor(site);
    if !has_stitchable_candidate
        && (site.unresolved_result_passthrough
            || site.unresolved_receiver_result_passthrough
            || unmodeled_constructor)
    {
        let caller_call_ret = caller_remap.get(site.call_ret_node);
        if !caller_call_ret.is_sentinel() {
            let mut passthrough_inputs = site
                .call_arg_nodes
                .iter()
                // Only source-level arguments are generic result inputs.
                // `walk_call` may append a synthetic arg for flattened
                // zero-arg method expressions; treating that receiver token
                // as an ordinary argument would make `client.capacity`
                // inherit taint from the whole `client` object.
                .take(if site.unresolved_result_passthrough || unmodeled_constructor {
                    site.explicit_args_count as usize
                } else {
                    0
                })
                .copied()
                .chain(
                    site.receiver_arg_node
                        .filter(|_| site.unresolved_receiver_result_passthrough),
                )
                .map(|node| caller_remap.get(node))
                .filter(|node| !node.is_sentinel())
                .collect::<Vec<_>>();
            passthrough_inputs.sort_unstable();
            passthrough_inputs.dedup();
            for input in passthrough_inputs {
                place_inter_edge(
                    caller_seg,
                    caller_seg,
                    IdgEdge {
                        from: input,
                        to: caller_call_ret,
                        meta: crate::edge::EdgeMeta {
                            precision: bonsai_common::Precision::Narrowed,
                            kind: crate::edge::IdgEdgeKind::IntraAssign,
                            call_kind: bonsai_callgraph::EdgeKind::Indirect,
                            via_span: site.site.0,
                        },
                    },
                    ws,
                );
                if let Some(stats) = &mut stats {
                    stats.passthrough_edges = stats.passthrough_edges.saturating_add(1);
                    stats.inter_edges = stats.inter_edges.saturating_add(1);
                }
            }
        }
    }
    let higher_order_edges = stitch_indirect_callback_inputs(
        caller,
        caller_seg,
        caller_remap,
        site,
        resolver,
        callee_endpoints,
        ws,
    );
    if higher_order_edges > 0 {
        if let Some(stats) = &mut stats {
            stats.inter_edges = stats.inter_edges.saturating_add(higher_order_edges);
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
        let is_ancestor_dispatch = resolver.is_ancestor_dispatch(caller, cand.func);
        // For method receivers, emit the synthetic receiver slot to
        // the callee's adapter-declared receiver parameter. This is
        // separate from positional args so explicit arguments keep
        // their source-language order.
        if matches!(site.call_kind, CallKind::Method) {
            let receiver_call_arg = site
                .receiver_arg_node
                .map(|node| caller_remap.get(node))
                .filter(|node| !node.is_sentinel());
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
                    let actual_receiver = receiver_field_forwarding_base(
                        site,
                        receiver,
                        caller_params,
                        caller_receiver_param_index,
                        caller_implicit_receiver_bases,
                        caller_receiver_names,
                        is_ancestor_dispatch,
                        false,
                    );
                    push_receiver_field_arg_site(
                        field_arg_sites,
                        caller,
                        caller_seg,
                        cand.func,
                        endpoints.segment,
                        &actual_receiver,
                        param_name,
                        site.site.0,
                        cand.precision,
                        cand.edge_kind,
                        receiver_call_arg,
                        None,
                    );
                    push_nested_receiver_field_arg_sites(
                        field_arg_sites,
                        caller,
                        caller_seg,
                        cand.func,
                        endpoints.segment,
                        &actual_receiver,
                        param_name,
                        endpoints,
                        site.site.0,
                        cand.precision,
                        cand.edge_kind,
                        receiver_call_arg,
                    );
                    if let Some(receiver_type) = resolver.receiver_type_for(cand.func) {
                        push_receiver_field_arg_site(
                            field_arg_sites,
                            caller,
                            caller_seg,
                            cand.func,
                            endpoints.segment,
                            &actual_receiver,
                            param_name,
                            site.site.0,
                            cand.precision,
                            cand.edge_kind,
                            receiver_call_arg,
                            Some(receiver_type.as_str()),
                        );
                    }
                }
            }
            if endpoints.receiver_param_index.is_none() && !endpoints.receiver_consumer_nodes.is_empty() {
                if let Some(receiver_arg_node) = site.receiver_arg_node {
                    let caller_call_arg = caller_remap.get(receiver_arg_node);
                    if !caller_call_arg.is_sentinel() {
                        for &callee_receiver_consumer in &endpoints.receiver_consumer_nodes {
                            if callee_receiver_consumer.is_sentinel() {
                                continue;
                            }
                            let edge = IdgEdge::inter_call_arg(
                                caller_call_arg,
                                callee_receiver_consumer,
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
            }
            if endpoints.receiver_param_index.is_none()
                && (!endpoints.implicit_receiver_bases.is_empty()
                    || !endpoints.receiver_field_bases.is_empty()
                    || !endpoints.return_field_projections.is_empty())
            {
                if let Some(receiver) = site
                    .receiver
                    .as_deref()
                    .map(str::trim)
                    .filter(|receiver| !receiver.is_empty())
                {
                    let actual_receiver = receiver_field_forwarding_base(
                        site,
                        receiver,
                        caller_params,
                        caller_receiver_param_index,
                        caller_implicit_receiver_bases,
                        caller_receiver_names,
                        is_ancestor_dispatch,
                        true,
                    );
                    let projection_bases = return_projection_bases(endpoints);
                    for param_name in endpoints
                        .implicit_receiver_bases
                        .iter()
                        .chain(endpoints.receiver_field_bases.iter())
                        .chain(projection_bases.iter())
                    {
                        push_receiver_field_arg_site(
                            field_arg_sites,
                            caller,
                            caller_seg,
                            cand.func,
                            endpoints.segment,
                            &actual_receiver,
                            param_name,
                            site.site.0,
                            cand.precision,
                            cand.edge_kind,
                            receiver_call_arg,
                            None,
                        );
                    }
                }
            }
        }
        if site.receiver.is_none()
            && endpoints.receiver_param_index.is_none()
            && (!endpoints.implicit_receiver_bases.is_empty()
                || !endpoints.receiver_field_bases.is_empty()
                || !endpoints.return_field_projections.is_empty())
        {
            push_bare_implicit_member_field_arg_sites(
                field_arg_sites,
                caller,
                caller_seg,
                cand.func,
                endpoints.segment,
                endpoints,
                caller_implicit_receiver_bases,
                caller_receiver_names,
                site.site.0,
                cand.precision,
                cand.edge_kind,
            );
        }
        // For each explicit arg index, emit
        // `caller.CallArg(site, i) → callee.Param(j)`. When the
        // callee has a declared receiver parameter, `j` skips that
        // formal slot instead of treating the receiver as arg zero.
        // Named / labelled arguments bind by adapter-supplied formal
        // name first, then fall back to positional order.
        for i in 0..site.args_count as usize {
            let callee_param_idx = site
                .call_arg_names
                .get(i)
                .and_then(|name| {
                    name.as_deref().and_then(|name| {
                        named_arg_param_index(name, &endpoints.param_names, endpoints.receiver_param_index)
                    })
                })
                .unwrap_or_else(|| explicit_arg_param_index(i, endpoints.receiver_param_index));
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
                        allow_out_of_order_source: false,
                    });
                }
            }
            if let Some(target_base) = site.call_arg_writeback_targets.get(i).and_then(Option::as_deref) {
                let added = stitch_out_parameter_write_back(
                    caller,
                    caller_seg,
                    cand.func,
                    endpoints.segment,
                    endpoints
                        .param_write_nodes
                        .get(callee_param_idx)
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                    target_base,
                    site.site.0,
                    cand.precision,
                    cand.edge_kind,
                    ws,
                );
                if let Some(stats) = &mut stats {
                    stats.inter_edges = stats.inter_edges.saturating_add(added);
                }
            }
            if let Some(stats) = &mut stats {
                stats.inter_edges = stats.inter_edges.saturating_add(1);
            }
        }
        if resolver.is_local_callable_binding(caller, cand.func) {
            let added = stitch_lexical_capture_reads(
                caller,
                caller_seg,
                endpoints.segment,
                &endpoints.capture_read_nodes,
                site.site.0,
                cand.precision,
                cand.edge_kind,
                ws,
            );
            if let Some(stats) = &mut stats {
                stats.inter_edges = stats.inter_edges.saturating_add(added);
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
                // Preserve field/descendant identity through wrappers such
                // as `return param`. This is intentionally separate from
                // scalar return flow: a bare tainted object remains scalar,
                // while an explicit `param.*` seed or exact field write can
                // flow to the corresponding field on the assigned result.
                for &param_idx in &endpoints.return_passthrough_param_indices {
                    let explicit_arg_idx = match endpoints.receiver_param_index {
                        Some(receiver_idx) if param_idx == receiver_idx => None,
                        Some(receiver_idx) if param_idx > receiver_idx => Some(param_idx - 1),
                        _ => Some(param_idx),
                    };
                    let Some(actual_arg) = explicit_arg_idx
                        .and_then(|idx| site.call_arg_places.get(idx))
                        .map(String::as_str)
                        .map(str::trim)
                        .filter(|arg| !arg.is_empty())
                    else {
                        continue;
                    };
                    for (target_base, write_span, result_field) in &assignment_targets {
                        if result_field.is_some() {
                            continue;
                        }
                        passthrough_field_copy_sites.push(FieldCopySite {
                            seg_id: caller_seg,
                            func: caller,
                            source_base: actual_arg.to_string(),
                            target_base: target_base.clone(),
                            write_span: *write_span,
                            via_span: site.site.0,
                            precision: cand.precision,
                            call_kind: cand.edge_kind,
                        });
                    }
                }
                for source_base in [
                    crate::transfer::RETURN_FIELD_BASE,
                    crate::transfer::YIELD_FIELD_BASE,
                ] {
                    for (target_base, write_span, result_field) in &assignment_targets {
                        if result_field.is_some() {
                            continue;
                        }
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
                for (target_base, write_span, result_field) in &assignment_targets {
                    if let Some(result_field) = result_field {
                        scalar_return_sites.push(ScalarReturnStitch {
                            caller,
                            caller_seg,
                            callee: cand.func,
                            callee_seg: endpoints.segment,
                            source_base: crate::transfer::RETURN_FIELD_BASE.to_string(),
                            source_field: result_field.clone(),
                            target_base: target_base.clone(),
                            call_span: site.site.0,
                            write_span: *write_span,
                            precision: cand.precision,
                            call_kind: cand.edge_kind,
                        });
                        continue;
                    }
                    for projection in &endpoints.return_field_projections {
                        scalar_return_sites.push(ScalarReturnStitch {
                            caller,
                            caller_seg,
                            callee: cand.func,
                            callee_seg: endpoints.segment,
                            source_base: projection.base.clone(),
                            source_field: projection.field.clone(),
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
        if matches!(site.call_kind, CallKind::Method | CallKind::Constructor)
            && resolver.is_constructor_func(cand.func)
        {
            let explicit_receiver = site
                .receiver
                .as_deref()
                .map(str::trim)
                .filter(|receiver| !receiver.is_empty());
            let target_base = explicit_receiver
                .map(|receiver| {
                    constructor_receiver_target_base(
                        receiver,
                        caller_params,
                        caller_is_constructor,
                        caller_receiver_param_index,
                        caller_implicit_receiver_bases,
                        caller_receiver_names,
                        is_ancestor_dispatch,
                    )
                })
                .or_else(|| {
                    // A synthesized primary constructor represents a class-
                    // header delegation call with no expression receiver.
                    // Resolved ancestor identity proves that the call mutates
                    // the current object; use the adapter's canonical receiver
                    // token rather than a language spelling in the IDG.
                    (matches!(site.call_kind, CallKind::Constructor)
                        && caller_is_constructor
                        && is_ancestor_dispatch)
                        .then(|| caller_receiver_names.first().cloned())
                        .flatten()
                })
                .unwrap_or_default();
            if !target_base.is_empty() {
                for callee_receiver_param_name in constructor_receiver_bases(endpoints) {
                    receiver_mutation_sites.push(Arc::new(ReceiverMutationStitch {
                        caller,
                        caller_seg,
                        callee: cand.func,
                        callee_seg: endpoints.segment,
                        target_base: target_base.clone(),
                        callee_receiver_param_name,
                        call_span: site.site.0,
                        precision: cand.precision,
                        call_kind: cand.edge_kind,
                    }));
                }
            }
        }
        if resolver.is_constructor_func(cand.func) {
            let caller_call_ret = caller_remap.get(site.call_ret_node);
            if !caller_call_ret.is_sentinel() {
                let receiver_bases = constructor_receiver_bases(endpoints);
                let assignment_targets = call_ret_assignment_targets(ws, caller_seg, caller, caller_call_ret);
                if !receiver_bases.is_empty() {
                    for (target_base, write_span, result_field) in assignment_targets {
                        if result_field.is_some() {
                            continue;
                        }
                        for receiver_param_name in &receiver_bases {
                            let target_base =
                                projected_receiver_target_base(&target_base, receiver_param_name);
                            constructor_return_sites.push(ConstructorReturnStitch {
                                caller,
                                caller_seg,
                                callee: cand.func,
                                callee_seg: endpoints.segment,
                                target_base,
                                receiver_param_name: receiver_param_name.clone(),
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
    let source_callback_edges = stitch_source_callback_args(
        caller,
        caller_seg,
        caller_remap,
        site,
        resolver,
        callee_endpoints,
        ws,
    );
    if source_callback_edges > 0 {
        if let Some(stats) = &mut stats {
            stats.inter_edges = stats.inter_edges.saturating_add(source_callback_edges);
        }
    }
    // Ambiguous or unknown callees do not create IDG flow. Library
    // pass-through needs an explicit semantic summary/model; a
    // generic `CallArg -> CallRet` edge would invent dataflow.
    // Drop unused: candidates iterator is consumed.
    drop(candidates);
}

fn call_site_is_constructor(site: &crate::transfer::CallSiteRef) -> bool {
    matches!(site.call_kind, CallKind::Constructor)
}

#[allow(clippy::too_many_arguments)] // Capture edges retain the resolved call's full precision metadata.
fn stitch_lexical_capture_reads(
    caller: FuncId,
    caller_seg: SegmentId,
    callee_seg: SegmentId,
    capture_reads: &[(String, NodeId)],
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    ws: &mut IdgWorkspace,
) -> usize {
    let mut added = 0usize;
    for (capture_name, capture_read) in capture_reads {
        for source in scalar_producers_live_at_span(ws, caller_seg, caller, capture_name, call_span) {
            place_inter_edge(
                caller_seg,
                callee_seg,
                IdgEdge {
                    from: source,
                    to: *capture_read,
                    meta: crate::edge::EdgeMeta {
                        precision,
                        kind: crate::edge::IdgEdgeKind::InterCallArg,
                        call_kind,
                        via_span: call_span,
                    },
                },
                ws,
            );
            added = added.saturating_add(1);
        }
    }
    added
}

fn scalar_producers_live_at_span(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    name: &str,
    at_span: Span,
) -> Vec<NodeId> {
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut writes = Vec::new();
    let mut reads = Vec::new();
    for (node_idx, node) in segment.nodes.nodes.iter().enumerate() {
        if node.func != func {
            continue;
        }
        let Some(place) = segment.places.get(node.place) else {
            continue;
        };
        if place_storage_name(segment, place).as_deref() != Some(name) {
            continue;
        }
        let node_id = NodeId(node_idx as u32);
        match place {
            Place::Write { path, span, .. }
                if path.is_empty() && (span.file != at_span.file || span.start <= at_span.start) =>
            {
                writes.push((span.start, node_id));
            }
            Place::Read { path, .. } if path.is_empty() => reads.push(node_id),
            _ => {}
        }
    }
    if let Some(latest_start) = writes.iter().map(|(start, _)| *start).max() {
        let mut out = writes
            .into_iter()
            .filter_map(|(start, node)| (start == latest_start).then_some(node))
            .collect::<Vec<_>>();
        out.sort_by_key(|node| node.0);
        out.dedup();
        return out;
    }
    reads.sort_by_key(|node| node.0);
    reads.dedup();
    reads
}

#[allow(clippy::too_many_arguments)] // The stitch carries both call endpoints and edge metadata explicitly.
fn stitch_out_parameter_write_back(
    caller: FuncId,
    caller_seg: SegmentId,
    _callee: FuncId,
    callee_seg: SegmentId,
    callee_param_writes: &[NodeId],
    target_base: &str,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    ws: &mut IdgWorkspace,
) -> usize {
    if callee_param_writes.is_empty() {
        return 0;
    }
    let consumer_edges = scalar_post_call_consumer_edges(ws, caller_seg, caller, target_base, call_span);
    if consumer_edges.is_empty() {
        return 0;
    }
    let Some(target_write) = ensure_scalar_write_node(ws, caller_seg, caller, target_base, call_span) else {
        return 0;
    };

    let mut added = 0usize;
    for &source_write in callee_param_writes {
        place_inter_edge(
            callee_seg,
            caller_seg,
            IdgEdge {
                from: source_write,
                to: target_write,
                meta: crate::edge::EdgeMeta {
                    precision,
                    kind: crate::edge::IdgEdgeKind::InterReturn,
                    call_kind,
                    via_span: call_span,
                },
            },
            ws,
        );
        added = added.saturating_add(1);
    }
    for consumer in consumer_edges {
        place_inter_edge(
            caller_seg,
            caller_seg,
            IdgEdge {
                from: target_write,
                to: consumer.to,
                meta: consumer.meta,
            },
            ws,
        );
        added = added.saturating_add(1);
    }
    added
}

fn scalar_post_call_consumer_edges(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    target_base: &str,
    call_span: Span,
) -> Vec<IdgEdge> {
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut live_producers = AHashSet::default();
    for (node_idx, node) in segment.nodes.nodes.iter().enumerate() {
        if node.func != func {
            continue;
        }
        let Some(place) = segment.places.get(node.place) else {
            continue;
        };
        let matches_target = place_storage_name(segment, place)
            .as_deref()
            .is_some_and(|name| name == target_base);
        if !matches_target {
            continue;
        }
        let was_live_at_call = match place {
            Place::Read { path, .. } => path.is_empty(),
            Place::Write { path, span, .. } => {
                path.is_empty() && (span.file != call_span.file || span.start <= call_span.start)
            }
            _ => false,
        };
        if was_live_at_call {
            live_producers.insert(NodeId(node_idx as u32));
        }
    }

    let mut seen = AHashSet::default();
    segment
        .edges
        .iter()
        .filter(|edge| live_producers.contains(&edge.from))
        .filter(|edge| {
            edge.meta.via_span.file != call_span.file || edge.meta.via_span.start > call_span.start
        })
        .filter(|edge| seen.insert((edge.to, edge.meta)))
        .copied()
        .collect()
}

fn stitch_source_callback_args(
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &NodeRemap,
    site: &CallSiteRef,
    resolver: &dyn CalleeResolver,
    callee_endpoints: &AHashMap<FuncId, CalleeEndpoints>,
    ws: &mut IdgWorkspace,
) -> usize {
    if site.source_callback_args.is_empty() {
        return 0;
    }
    let caller_call_ret = caller_remap.get(site.call_ret_node);
    if caller_call_ret.is_sentinel() {
        return 0;
    }
    let mut emitted = 0usize;
    for shape in &site.source_callback_args {
        let Some(callback_text) = site.call_arg_places.get(shape.callback_arg_index) else {
            continue;
        };
        let callback_text = callback_text.trim();
        if callback_text.is_empty() {
            continue;
        }
        for cand in resolver.callable_arg(caller, callback_text) {
            let Some(endpoints) = callee_endpoints.get(&cand.func) else {
                continue;
            };
            for &source_param_index in &shape.source_param_indices {
                let callee_param_idx =
                    explicit_arg_param_index(source_param_index, endpoints.receiver_param_index);
                let Some(&callee_param_node) = endpoints.params.get(callee_param_idx) else {
                    continue;
                };
                if callee_param_node.is_sentinel() {
                    continue;
                }
                let edge = IdgEdge::inter_call_arg(
                    caller_call_ret,
                    callee_param_node,
                    site.site.0,
                    cand.precision,
                    cand.edge_kind,
                );
                place_inter_edge(caller_seg, endpoints.segment, edge, ws);
                emitted = emitted.saturating_add(1);
            }
        }
    }
    emitted
}

/// Route the data operands of an AST-proven indirect callback invocation to
/// its first parameter. The callable argument is identified by resolver
/// evidence, not by a table of library method names. For a method call the
/// receiver is also a data operand; for a free call every non-callback
/// source-level argument is a candidate input.
#[allow(clippy::too_many_arguments)]
fn stitch_indirect_callback_inputs(
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &NodeRemap,
    site: &CallSiteRef,
    resolver: &dyn CalleeResolver,
    callee_endpoints: &AHashMap<FuncId, CalleeEndpoints>,
    ws: &mut IdgWorkspace,
) -> usize {
    let mut callback_arg_indices = AHashSet::new();
    let mut callback_candidates = Vec::new();
    let mut seen_candidates = AHashSet::new();
    for (idx, value) in site.call_arg_values.iter().enumerate() {
        let mut resolved = resolver.callable_arg(caller, value);
        if let Some(&arg_span) = site.call_arg_spans.get(idx) {
            resolved.extend(resolver.callable_args_in_span(caller, arg_span));
        }
        if resolved.is_empty() {
            continue;
        }
        callback_arg_indices.insert(idx);
        for cand in resolved {
            if cand.edge_kind == bonsai_callgraph::EdgeKind::Indirect
                && callee_endpoints.contains_key(&cand.func)
                && seen_candidates.insert(cand.func)
            {
                callback_candidates.push(cand);
            }
        }
    }
    if callback_arg_indices.is_empty() {
        return 0;
    }

    let mut input_nodes = Vec::new();
    if matches!(site.call_kind, CallKind::Method) {
        if let Some(receiver_arg_node) = site.receiver_arg_node {
            input_nodes.push(receiver_arg_node);
        }
    }
    input_nodes.extend(
        site.call_arg_nodes
            .iter()
            .take(site.explicit_args_count as usize)
            .enumerate()
            .filter_map(|(idx, node)| (!callback_arg_indices.contains(&idx)).then_some(*node)),
    );
    if input_nodes.is_empty() {
        return 0;
    }

    let mut emitted = 0usize;
    for cand in callback_candidates {
        let Some(endpoints) = callee_endpoints.get(&cand.func) else {
            continue;
        };
        let callback_param_idx = explicit_arg_param_index(0, endpoints.receiver_param_index);
        let Some(&callee_param_node) = endpoints.params.get(callback_param_idx) else {
            continue;
        };
        if callee_param_node.is_sentinel() {
            continue;
        }
        for &input_node in &input_nodes {
            let caller_call_arg = caller_remap.get(input_node);
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
            emitted = emitted.saturating_add(1);
        }
    }
    emitted
}

fn constructor_receiver_target_base(
    receiver: &str,
    caller_params: &[String],
    caller_is_constructor: bool,
    caller_receiver_param_index: Option<usize>,
    caller_implicit_receiver_bases: &[String],
    caller_receiver_names: &[String],
    is_ancestor_dispatch: bool,
) -> String {
    let trimmed = receiver.trim();
    if receiver_name_matches(trimmed, caller_receiver_names) {
        if let Some(param) = caller_receiver_param_index
            .and_then(|idx| caller_params.get(idx))
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
        {
            return param;
        }
        if caller_is_constructor {
            if let Some(base) = constructor_implicit_receiver_base(
                trimmed,
                caller_implicit_receiver_bases,
                caller_receiver_names,
                is_ancestor_dispatch,
            ) {
                return base;
            }
        }
    }
    trimmed.to_string()
}

fn constructor_receiver_bases(endpoints: &CalleeEndpoints) -> Vec<String> {
    let mut out: Vec<String> = endpoints
        .receiver_param_index
        .and_then(|idx| endpoints.param_names.get(idx).cloned())
        .into_iter()
        .collect();
    for base in endpoints
        .receiver_field_bases
        .iter()
        .chain(endpoints.implicit_receiver_bases.iter())
    {
        let base = base.trim();
        if !base.is_empty() && !out.iter().any(|existing| existing == base) {
            out.push(base.to_string());
        }
    }
    // Constructors with an implicit receiver still own object state even
    // when their body only delegates to an ancestor and declares no fields.
    // The adapter orders `receiver_names` with the canonical current-object
    // token first; retaining it lets descendant state flow through each
    // constructor in the hierarchy without spelling any language receiver in
    // the IDG.
    if endpoints.receiver_param_index.is_none() {
        if let Some(receiver) = endpoints
            .receiver_names
            .first()
            .map(String::as_str)
            .map(str::trim)
            .filter(|receiver| !receiver.is_empty())
        {
            if !out.iter().any(|existing| existing == receiver) {
                out.push(receiver.to_string());
            }
        }
    }
    out
}

fn constructor_implicit_receiver_base(
    receiver: &str,
    caller_implicit_receiver_bases: &[String],
    caller_receiver_names: &[String],
    is_ancestor_dispatch: bool,
) -> Option<String> {
    let matches_requested_receiver = |base: &&String| {
        receiver_root_if_declared(base, caller_receiver_names)
            .is_some_and(|root| receiver_tokens_equal(root, receiver))
    };
    let declared_bases = caller_implicit_receiver_bases
        .iter()
        .filter(|base| receiver_root_if_declared(base, caller_receiver_names).is_some());
    if is_ancestor_dispatch {
        declared_bases
            .clone()
            .find(|base| !matches_requested_receiver(base))
            .or_else(|| declared_bases.clone().next())
            .map(|base| base.trim().to_string())
            .or_else(|| {
                caller_receiver_names
                    .iter()
                    .find(|name| !receiver_tokens_equal(name, receiver))
                    .or_else(|| caller_receiver_names.first())
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty())
            })
    } else {
        declared_bases
            .clone()
            .find(matches_requested_receiver)
            .or_else(|| declared_bases.clone().next())
            .map(|base| base.trim().to_string())
            .or_else(|| {
                caller_receiver_names
                    .iter()
                    .find(|name| receiver_tokens_equal(name, receiver))
                    .or_else(|| caller_receiver_names.first())
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty())
            })
    }
}

fn receiver_field_forwarding_base(
    site: &CallSiteRef,
    receiver: &str,
    caller_params: &[String],
    caller_receiver_param_index: Option<usize>,
    caller_implicit_receiver_bases: &[String],
    caller_receiver_names: &[String],
    is_ancestor_dispatch: bool,
    allow_implicit_receiver_rewrite: bool,
) -> String {
    if let Some(base) = inline_constructor_receiver_base(receiver, site.site.0) {
        return base;
    }
    if let Some(base) = inline_call_result_receiver_base(receiver, site.site.0) {
        return base;
    }
    if allow_implicit_receiver_rewrite {
        return implicit_receiver_actual_base(
            receiver,
            caller_params,
            caller_receiver_param_index,
            caller_implicit_receiver_bases,
            caller_receiver_names,
            is_ancestor_dispatch,
        );
    }
    receiver.trim().to_string()
}

fn implicit_receiver_actual_base(
    receiver: &str,
    caller_params: &[String],
    caller_receiver_param_index: Option<usize>,
    caller_implicit_receiver_bases: &[String],
    caller_receiver_names: &[String],
    is_ancestor_dispatch: bool,
) -> String {
    let trimmed = receiver.trim();
    if receiver_name_matches(trimmed, caller_receiver_names) {
        if let Some(param) = caller_receiver_param_index
            .and_then(|idx| caller_params.get(idx))
            .map(String::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            return param.to_string();
        }
        if let Some(base) = constructor_implicit_receiver_base(
            trimmed,
            caller_implicit_receiver_bases,
            caller_receiver_names,
            is_ancestor_dispatch,
        ) {
            return base;
        }
    }
    trimmed.to_string()
}

#[allow(clippy::too_many_arguments)] // Mirrors the explicit FieldArgStitch metadata.
fn push_receiver_field_arg_site(
    sites: &mut FieldArgSiteQueue,
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    receiver: &str,
    param_name: &str,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    actual_arg_node: Option<NodeId>,
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
        actual_arg_node,
        actual_arg,
        param_name: param_name.trim().to_string(),
        call_span,
        precision,
        call_kind,
        allow_out_of_order_source: false,
    });
}

#[allow(clippy::too_many_arguments)] // Mirrors receiver forwarding metadata.
fn push_nested_receiver_field_arg_sites(
    sites: &mut FieldArgSiteQueue,
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    actual_receiver: &str,
    receiver_param_name: &str,
    endpoints: &CalleeEndpoints,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    actual_arg_node: Option<NodeId>,
) {
    let projection_bases = return_projection_bases(endpoints);
    let nested_bases = endpoints
        .receiver_field_bases
        .iter()
        .chain(endpoints.implicit_receiver_bases.iter())
        .chain(projection_bases.iter());
    let mut seen = AHashSet::new();
    for nested_param_base in nested_bases {
        let nested_param_base = nested_param_base.trim();
        let Some(actual_nested_base) =
            project_receiver_base(actual_receiver, receiver_param_name, nested_param_base)
        else {
            continue;
        };
        if actual_nested_base == actual_receiver
            || !seen.insert((actual_nested_base.clone(), nested_param_base.to_string()))
        {
            continue;
        }
        sites.push(FieldArgStitch {
            caller,
            caller_seg,
            callee,
            callee_seg,
            actual_arg_node,
            actual_arg: actual_nested_base,
            param_name: nested_param_base.to_string(),
            call_span,
            precision,
            call_kind,
            allow_out_of_order_source: false,
        });
    }
}

#[allow(clippy::too_many_arguments)] // Mirrors receiver forwarding metadata for implicit member calls.
fn push_bare_implicit_member_field_arg_sites(
    sites: &mut FieldArgSiteQueue,
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    endpoints: &CalleeEndpoints,
    caller_implicit_receiver_bases: &[String],
    caller_receiver_names: &[String],
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
) {
    let roots = implicit_member_actual_roots(caller_implicit_receiver_bases, caller_receiver_names);
    if roots.is_empty() {
        return;
    }
    let projection_bases = return_projection_bases(endpoints);
    let nested_bases = endpoints
        .receiver_field_bases
        .iter()
        .chain(endpoints.implicit_receiver_bases.iter())
        .chain(projection_bases.iter());
    let mut seen = AHashSet::new();
    for nested_param_base in nested_bases {
        let nested_param_base = nested_param_base.trim();
        if nested_param_base.is_empty() {
            continue;
        }
        for root in &roots {
            let actual_arg = implicit_member_actual_base(root, nested_param_base, &endpoints.receiver_names);
            if !seen.insert((actual_arg.clone(), nested_param_base.to_string())) {
                continue;
            }
            if actual_arg == nested_param_base && caller == callee {
                continue;
            }
            sites.push(FieldArgStitch {
                caller,
                caller_seg,
                callee,
                callee_seg,
                actual_arg,
                actual_arg_node: None,
                param_name: nested_param_base.to_string(),
                call_span,
                precision,
                call_kind,
                allow_out_of_order_source: true,
            });
        }
    }
}

fn return_projection_bases(endpoints: &CalleeEndpoints) -> Vec<String> {
    let mut out = Vec::new();
    for projection in &endpoints.return_field_projections {
        let base = projection.base.trim();
        if !base.is_empty() && !out.iter().any(|existing| existing == base) {
            out.push(base.to_string());
        }
    }
    out
}

fn implicit_member_actual_roots(
    caller_implicit_receiver_bases: &[String],
    caller_receiver_names: &[String],
) -> Vec<String> {
    let mut roots = Vec::new();
    for base in caller_implicit_receiver_bases {
        let Some(root) = receiver_root_if_declared(base, caller_receiver_names) else {
            continue;
        };
        if !roots.iter().any(|existing| existing == root) {
            roots.push(root.to_string());
        }
    }
    for receiver in caller_receiver_names {
        let receiver = receiver.trim();
        if !receiver.is_empty()
            && !roots
                .iter()
                .any(|existing| receiver_tokens_equal(existing, receiver))
        {
            roots.push(receiver.to_string());
        }
    }
    roots
}

fn implicit_member_actual_base(root: &str, nested_param_base: &str, receiver_names: &[String]) -> String {
    if receiver_root_if_declared(nested_param_base, receiver_names).is_some() {
        nested_param_base.trim().to_string()
    } else {
        format!("{}.{}", root.trim(), nested_param_base.trim())
    }
}

fn projected_receiver_target_base(target_base: &str, receiver_base: &str) -> String {
    let receiver_segments = storage_segments_cached(receiver_base);
    let receiver_root = receiver_segments.first().map(String::as_str).unwrap_or("");
    project_receiver_base(target_base, receiver_root, receiver_base)
        .unwrap_or_else(|| target_base.trim().to_string())
}

fn project_receiver_base(actual_base: &str, receiver_root: &str, receiver_base: &str) -> Option<String> {
    let actual_base = actual_base.trim();
    let receiver_root = receiver_root.trim();
    let receiver_base = receiver_base.trim();
    if actual_base.is_empty() || receiver_root.is_empty() || receiver_base.is_empty() {
        return None;
    }
    if receiver_base == receiver_root {
        return Some(actual_base.to_string());
    }
    let suffix = receiver_base
        .strip_prefix(receiver_root)
        .and_then(|rest| rest.strip_prefix('.'))?;
    if suffix.is_empty() {
        return Some(actual_base.to_string());
    }
    Some(format!("{actual_base}.{suffix}"))
}

fn receiver_root_if_declared<'a>(receiver_base: &'a str, receiver_names: &[String]) -> Option<&'a str> {
    let root = receiver_base
        .trim()
        .split('.')
        .find(|part| !part.trim().is_empty())?
        .trim();
    receiver_name_matches(root, receiver_names).then_some(root)
}

fn receiver_projection_needed(receiver: &str, receiver_type: &str) -> bool {
    storage_segments_cached(receiver)
        .last()
        .is_none_or(|tail| tail != receiver_type)
}

fn explicit_arg_param_index(arg_idx: usize, receiver_param_index: Option<usize>) -> usize {
    match receiver_param_index {
        Some(receiver_idx) if arg_idx >= receiver_idx => arg_idx.saturating_add(1),
        _ => arg_idx,
    }
}

fn named_arg_param_index(
    arg_name: &str,
    param_names: &[String],
    receiver_param_index: Option<usize>,
) -> Option<usize> {
    let arg_name = arg_name.trim();
    if arg_name.is_empty() {
        return None;
    }
    param_names
        .iter()
        .enumerate()
        .find(|(idx, param)| Some(*idx) != receiver_param_index && param.trim() == arg_name)
        .map(|(idx, _)| idx)
}

fn stitch_field_argument_forwarding(
    sites: &[Arc<FieldArgStitch>],
    return_field_sites: &[Arc<ReturnFieldStitch>],
    scalar_return_sites: &[Arc<ScalarReturnStitch>],
    constructor_return_sites: &[Arc<ConstructorReturnStitch>],
    receiver_mutation_sites: &[Arc<ReceiverMutationStitch>],
    passthrough_field_copy_sites: &[FieldCopySite],
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
    ws: &mut IdgWorkspace,
    demand_driven: bool,
    demand_driven_funcs: Option<&AHashSet<FuncId>>,
    field_demand_terminal_sites: Option<&AHashSet<(FuncId, Span)>>,
) {
    let mut copy_sites = collect_field_copy_sites(ws, stitch_data);
    copy_sites.extend_from_slice(passthrough_field_copy_sites);
    copy_sites.sort_by(|a, b| {
        (
            a.seg_id.0,
            a.func.raw(),
            a.source_base.as_str(),
            a.target_base.as_str(),
            a.write_span.start,
            a.via_span.start,
        )
            .cmp(&(
                b.seg_id.0,
                b.func.raw(),
                b.source_base.as_str(),
                b.target_base.as_str(),
                b.write_span.start,
                b.via_span.start,
            ))
    });
    copy_sites.dedup_by(|a, b| {
        a.seg_id == b.seg_id
            && a.func == b.func
            && a.source_base == b.source_base
            && a.target_base == b.target_base
            && a.write_span == b.write_span
            && a.via_span == b.via_span
    });
    if sites.is_empty()
        && return_field_sites.is_empty()
        && scalar_return_sites.is_empty()
        && constructor_return_sites.is_empty()
        && receiver_mutation_sites.is_empty()
        && copy_sites.is_empty()
    {
        return;
    }
    // Field forwarding creates edges to synthetic field nodes. Track only
    // edges produced by this phase instead of duplicating every pre-existing
    // workspace edge (millions on large projects) in a second hash table.
    let mut known_edges = AHashSet::default();
    let mut field_index = FieldPlaceIndex::from_workspace(ws);
    let syntactic_fields = field_index.syntactic_field_universe();
    let mut inter_call_arg_entries = InterCallArgEntryIndex::from_workspace(ws);
    let mut synthetic_field_writes = SyntheticFieldWriteCache::from_workspace(ws);
    let transforms = build_field_write_transforms(
        sites,
        return_field_sites,
        scalar_return_sites,
        constructor_return_sites,
        receiver_mutation_sites,
        &copy_sites,
    );
    let demands = demand_driven.then(|| {
        build_field_demands(
            &field_index,
            &transforms,
            stitch_data,
            field_demand_terminal_sites,
        )
    });
    if let Some(demands) = &demands {
        let field_count = demands.fields_by_key.iter().map(Vec::len).sum::<usize>();
        let exact_base_count = demands
            .fields_by_key
            .iter()
            .filter(|fields| !fields.is_empty())
            .count();
        let wildcard_base_count = demands.all_fields_by_key.iter().filter(|all| **all).count();
        stitch_debug_log(format_args!(
            "field-forward demands: exact_bases={} wildcard_bases={} fields={}",
            exact_base_count, wildcard_base_count, field_count
        ));
        if field_count <= 128 && wildcard_base_count <= 128 {
            let fields_by_id: AHashMap<u32, &str> = demands
                .field_ids
                .iter()
                .map(|(field, id)| (*id, field.as_str()))
                .collect();
            let mut rendered = Vec::new();
            for (key, key_id) in &demands.key_ids {
                if demands.all_fields_by_key.get(*key_id).copied().unwrap_or(false) {
                    rendered.push(format!("{}:{}:{}.*", key.seg_id.0, key.func.raw(), key.base));
                }
                for field_id in demands.fields_by_key.get(*key_id).into_iter().flatten() {
                    if let Some(field) = fields_by_id.get(field_id) {
                        rendered.push(format!(
                            "{}:{}:{}.{field}",
                            key.seg_id.0,
                            key.func.raw(),
                            key.base
                        ));
                    }
                }
            }
            rendered.sort();
            stitch_debug_log(format_args!(
                "field-forward demand facts: {}",
                rendered.join(", ")
            ));
        }
    }
    let transform_count = transforms.values().map(Vec::len).sum::<usize>();
    let mut applicable_transform_cache: AHashMap<(usize, u32), SmallVec<[u32; 2]>> = AHashMap::default();
    let mut pending = VecDeque::new();
    let mut enqueued = AHashSet::default();
    seed_field_write_worklist(
        &field_index,
        &transforms,
        demands.as_ref(),
        demand_driven,
        demand_driven_funcs,
        &mut pending,
        &mut enqueued,
    );

    let phase_started = Instant::now();
    let before_edges = ws.total_edge_count();
    let mut fallback_edges =
        stitch_field_argument_fallbacks(sites, ws, &mut known_edges, &field_index, &inter_call_arg_entries);
    fallback_edges += stitch_field_copy_fallbacks(
        &copy_sites,
        ws,
        &mut known_edges,
        &mut field_index,
        &mut inter_call_arg_entries,
        &mut synthetic_field_writes,
        &transforms,
        &mut pending,
        &mut enqueued,
        stitch_data,
    );
    let mut processed = 0usize;
    let mut processed_transforms = 0usize;
    while let Some(write) = pending.pop_front() {
        processed += 1;
        let Some((storage, write_span)) = ws.segment(write.seg_id).and_then(|segment| {
            let node = segment.nodes.get(write.node)?;
            if node.func != write.func {
                return None;
            }
            let place = segment.places.get(node.place)?;
            write_place_storage_and_span(segment, place)
        }) else {
            continue;
        };
        let cached_parts = storage_segments_cached(&storage);
        let parts = cached_parts.iter().map(String::as_str).collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        // A concrete IDG write is queued once. Its canonical storage path is
        // projected onto every transform-bearing base here, so no semantic
        // fanout is lost even though duplicate prefix/suffix queue states are
        // gone.
        for split in 1..parts.len() {
            let field = join_storage_part_refs(&parts[split..]);
            if !syntactic_fields.contains(&field) {
                continue;
            }
            let key = FieldPlaceKey {
                seg_id: write.seg_id,
                func: write.func,
                base: join_storage_part_refs(&parts[..split]),
                writes: true,
            };
            let Some(sites) = transforms.get(&key) else {
                continue;
            };
            let source = FieldPlaceHit {
                field,
                node: write.node,
                span: Some(write_span),
            };
            let applicable = demands.as_ref().and_then(|demands| {
                let key_id = demands.key_ids.get(&key).copied()?;
                let field_id = demands.field_ids.get(&source.field).copied().unwrap_or(u32::MAX);
                Some(
                    applicable_transform_cache
                        .entry((key_id, field_id))
                        .or_insert_with(|| {
                            sites
                                .iter()
                                .enumerate()
                                .filter(|(_, transform)| {
                                    field_transform_may_apply(
                                        transform,
                                        &source.field,
                                        demands,
                                        demand_driven,
                                        demand_driven_funcs,
                                    )
                                })
                                .map(|(index, _)| {
                                    u32::try_from(index).expect("field transform fanout exceeds u32")
                                })
                                .collect()
                        })
                        .as_slice(),
                )
            });
            let mut apply_site = |site: &FieldWriteTransform| {
                if !field_transform_source_may_apply(
                    site,
                    &source,
                    &inter_call_arg_entries,
                    &synthetic_field_writes,
                    stitch_data,
                ) {
                    return;
                }
                processed_transforms += 1;
                apply_field_write_transform(
                    site,
                    &source,
                    demands.as_ref(),
                    demand_driven,
                    demand_driven_funcs,
                    &mut inter_call_arg_entries,
                    &mut synthetic_field_writes,
                    ws,
                    &mut known_edges,
                    &mut field_index,
                    &transforms,
                    &mut pending,
                    &mut enqueued,
                    stitch_data,
                );
            };
            if let Some(indices) = applicable {
                for site_index in indices.iter().copied() {
                    apply_site(&sites[site_index as usize]);
                }
            } else {
                for site in sites {
                    apply_site(site);
                }
            }
        }
    }
    let added_edges = ws.total_edge_count().saturating_sub(before_edges);
    stitch_debug_log(format_args!(
        "field-forward worklist: {:.3}s processed={} transform_apps={} transforms={} transform_field_views={} fallback_edges={} added_edges={} total_edges={} pending_remaining={}",
        phase_started.elapsed().as_secs_f64(),
        processed,
        processed_transforms,
        transform_count,
        applicable_transform_cache.len(),
        fallback_edges,
        added_edges,
        ws.total_edge_count(),
        pending.len(),
    ));
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

fn build_field_write_transforms(
    sites: &[Arc<FieldArgStitch>],
    return_field_sites: &[Arc<ReturnFieldStitch>],
    scalar_return_sites: &[Arc<ScalarReturnStitch>],
    constructor_return_sites: &[Arc<ConstructorReturnStitch>],
    receiver_mutation_sites: &[Arc<ReceiverMutationStitch>],
    copy_sites: &[FieldCopySite],
) -> AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>> {
    let mut out: AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>> = AHashMap::default();
    for site in sites {
        push_field_write_transform(
            &mut out,
            field_write_key(site.caller_seg, site.caller, &site.actual_arg),
            FieldWriteTransform::Argument(Arc::clone(site)),
        );
    }
    for site in return_field_sites {
        push_field_write_transform(
            &mut out,
            field_write_key(site.callee_seg, site.callee, &site.source_base),
            FieldWriteTransform::Return(Arc::clone(site)),
        );
    }
    for site in scalar_return_sites {
        push_field_write_transform(
            &mut out,
            field_write_key(site.callee_seg, site.callee, &site.source_base),
            FieldWriteTransform::ScalarReturn(Arc::clone(site)),
        );
    }
    for site in constructor_return_sites {
        push_field_write_transform(
            &mut out,
            field_write_key(site.callee_seg, site.callee, &site.receiver_param_name),
            FieldWriteTransform::ConstructorReturn(Arc::clone(site)),
        );
    }
    for site in receiver_mutation_sites {
        push_field_write_transform(
            &mut out,
            field_write_key(site.callee_seg, site.callee, &site.callee_receiver_param_name),
            FieldWriteTransform::ReceiverMutation(Arc::clone(site)),
        );
    }
    for site in copy_sites {
        let key = field_write_key(site.seg_id, site.func, &site.source_base);
        push_field_write_transform(&mut out, key, FieldWriteTransform::Copy(site.clone()));
    }
    out
}

fn field_transform_target_key(transform: &FieldWriteTransform) -> Option<FieldPlaceKey> {
    match transform {
        FieldWriteTransform::Argument(site) => {
            Some(field_write_key(site.callee_seg, site.callee, &site.param_name))
        }
        FieldWriteTransform::Return(site) => {
            Some(field_write_key(site.caller_seg, site.caller, &site.target_base))
        }
        FieldWriteTransform::ScalarReturn(_) => None,
        FieldWriteTransform::ConstructorReturn(site) => {
            Some(field_write_key(site.caller_seg, site.caller, &site.target_base))
        }
        FieldWriteTransform::ReceiverMutation(site) => {
            Some(field_write_key(site.caller_seg, site.caller, &site.target_base))
        }
        FieldWriteTransform::Copy(site) => Some(field_write_key(site.seg_id, site.func, &site.target_base)),
    }
}

fn build_field_demands(
    field_index: &FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
    terminal_sites: Option<&AHashSet<(FuncId, Span)>>,
) -> FieldDemandIndex {
    let mut demands = FieldDemandIndex::default();
    let mut reverse: Vec<Vec<usize>> = Vec::new();
    for (source_key, source_transforms) in transforms {
        let source_id = intern_field_demand_key(&mut demands, &mut reverse, source_key.clone());
        for transform in source_transforms {
            let Some(target_key) = field_transform_target_key(transform) else {
                continue;
            };
            let target_id = intern_field_demand_key(&mut demands, &mut reverse, target_key);
            reverse[target_id].push(source_id);
        }
    }
    for sources in &mut reverse {
        sources.sort_unstable();
        sources.dedup();
    }

    let mut roots_by_field: Vec<Vec<usize>> = Vec::new();
    for (key, hits) in &field_index.by_base {
        if key.writes {
            continue;
        }
        let write_key = FieldPlaceKey {
            seg_id: key.seg_id,
            func: key.func,
            base: key.base.clone(),
            writes: true,
        };
        for hit in hits {
            if !field_index.is_observable_read(key, hit.node) {
                continue;
            }
            seed_exact_field_demand(
                &mut demands,
                &mut reverse,
                &mut roots_by_field,
                write_key.clone(),
                &hit.field,
            );
        }
    }
    for (source_key, source_transforms) in transforms {
        for transform in source_transforms {
            let FieldWriteTransform::ScalarReturn(site) = transform else {
                continue;
            };
            seed_exact_field_demand(
                &mut demands,
                &mut reverse,
                &mut roots_by_field,
                source_key.clone(),
                &site.source_field,
            );
        }
    }
    let mut segment_by_func = AHashMap::default();
    for key in field_index.by_base.keys().chain(demands.key_ids.keys()) {
        segment_by_func.entry(key.func).or_insert(key.seg_id);
    }
    let mut resolved_call_sites = AHashSet::default();
    for source_transforms in transforms.values() {
        for transform in source_transforms {
            let caller_and_span = match transform {
                FieldWriteTransform::Argument(site) => Some((site.caller, site.call_span)),
                FieldWriteTransform::Return(site) => Some((site.caller, site.call_span)),
                FieldWriteTransform::ScalarReturn(site) => Some((site.caller, site.call_span)),
                FieldWriteTransform::ConstructorReturn(site) => Some((site.caller, site.call_span)),
                FieldWriteTransform::ReceiverMutation(site) => Some((site.caller, site.call_span)),
                FieldWriteTransform::Copy(_) => None,
            };
            if let Some(caller_and_span) = caller_and_span {
                resolved_call_sites.insert(caller_and_span);
            }
        }
    }
    let mut whole_demand_key_ids = AHashSet::default();
    // Some grammars represent a zero-argument field/property access as a
    // call-shaped AST node (`envelope.cmd`, `obj.size`). Treat its receiver
    // and member spelling as a demanded access path. This is syntax-derived
    // and only broadens sparse materialization toward the complete IDG.
    for (func, data) in stitch_data {
        let Some(seg_id) = segment_by_func.get(func).copied() else {
            continue;
        };
        for site in &data.call_sites {
            let call_is_resolved = resolved_call_sites.contains(&(*func, site.site.0));
            let whole_object_is_demanded =
                whole_object_call_is_demanded(terminal_sites, call_is_resolved, *func, site.site.0);
            if whole_object_is_demanded {
                let argument_count = site.call_arg_places.len().max(site.call_arg_values.len());
                for index in 0..argument_count {
                    let place = site
                        .call_arg_places
                        .get(index)
                        .map(String::as_str)
                        .filter(|place| !place.trim().is_empty())
                        .or_else(|| site.call_arg_values.get(index).map(String::as_str))
                        .unwrap_or_default()
                        .trim();
                    if place.is_empty() {
                        continue;
                    }
                    seed_terminal_projection_demands(
                        &mut demands,
                        &mut reverse,
                        &mut roots_by_field,
                        seg_id,
                        *func,
                        place,
                    );
                    let key = field_write_key(seg_id, *func, place);
                    let key_id = intern_field_demand_key(&mut demands, &mut reverse, key);
                    whole_demand_key_ids.insert(key_id);
                }
                if site.call_kind == CallKind::Method {
                    if let Some(receiver) = site
                        .receiver
                        .as_deref()
                        .map(str::trim)
                        .filter(|receiver| !receiver.is_empty())
                    {
                        seed_terminal_projection_demands(
                            &mut demands,
                            &mut reverse,
                            &mut roots_by_field,
                            seg_id,
                            *func,
                            receiver,
                        );
                        let key = field_write_key(seg_id, *func, receiver);
                        let key_id = intern_field_demand_key(&mut demands, &mut reverse, key);
                        whole_demand_key_ids.insert(key_id);
                    }
                }
            }
            if site.explicit_args_count != 0 {
                continue;
            }
            let projection = if let Some(receiver) = site
                .receiver
                .as_deref()
                .map(str::trim)
                .filter(|receiver| !receiver.is_empty())
            {
                let field = site.callee_name.rsplit('.').next().unwrap_or_default().trim();
                (!field.is_empty()).then(|| (receiver.to_string(), field.to_string()))
            } else {
                site.callee_name.rsplit_once('.').and_then(|(base, field)| {
                    let base = base.trim();
                    let field = field.trim();
                    (!base.is_empty() && !field.is_empty()).then(|| (base.to_string(), field.to_string()))
                })
            };
            let Some((base, field)) = projection else {
                continue;
            };
            let key = field_write_key(seg_id, *func, &base);
            seed_exact_field_demand(&mut demands, &mut reverse, &mut roots_by_field, key, &field);
        }
    }

    let mut pending_all = VecDeque::new();
    for (key, key_id) in &demands.key_ids {
        if (field_index.has_whole_read(key) || whole_demand_key_ids.contains(key_id))
            && !demands.all_fields_by_key[*key_id]
        {
            demands.all_fields_by_key[*key_id] = true;
            pending_all.push_back(*key_id);
        }
    }
    while let Some(target_id) = pending_all.pop_front() {
        for source_id in reverse.get(target_id).into_iter().flatten().copied() {
            if !demands.all_fields_by_key[source_id] {
                demands.all_fields_by_key[source_id] = true;
                pending_all.push_back(source_id);
            }
        }
    }

    // A wildcard is the lattice top for its base: transforms materialize all
    // concrete syntactic suffixes directly, so duplicating those suffix ids
    // in the demand relation adds no information. Exact facts propagate only
    // through non-wildcard keys, using a generation-mark array for O(1)
    // deduplication and no semantic work cap.
    let exact_started = Instant::now();
    let mut seen_generation = vec![0u32; demands.fields_by_key.len()];
    let mut pending = VecDeque::new();
    for (field_index, roots) in roots_by_field.into_iter().enumerate() {
        let field_id = u32::try_from(field_index).expect("field demand id exceeds u32");
        let generation = field_id.saturating_add(1);
        for root in roots {
            if demands.all_fields_by_key[root] || seen_generation[root] == generation {
                continue;
            }
            seen_generation[root] = generation;
            pending.push_back(root);
        }
        while let Some(target_id) = pending.pop_front() {
            demands.fields_by_key[target_id].push(field_id);
            for source_id in reverse.get(target_id).into_iter().flatten().copied() {
                if demands.all_fields_by_key[source_id] || seen_generation[source_id] == generation {
                    continue;
                }
                seen_generation[source_id] = generation;
                pending.push_back(source_id);
            }
        }
    }
    stitch_debug_log(format_args!(
        "exact field-demand closure: {:.3}s facts={}",
        exact_started.elapsed().as_secs_f64(),
        demands.fields_by_key.iter().map(Vec::len).sum::<usize>()
    ));
    demands
}

fn whole_object_call_is_demanded(
    terminal_sites: Option<&AHashSet<(FuncId, Span)>>,
    call_is_resolved: bool,
    caller: FuncId,
    site: Span,
) -> bool {
    terminal_sites
        .map(|terminals| terminals.contains(&(caller, site)))
        .unwrap_or(!call_is_resolved)
}

fn seed_terminal_projection_demands(
    demands: &mut FieldDemandIndex,
    reverse: &mut Vec<Vec<usize>>,
    roots_by_field: &mut Vec<Vec<usize>>,
    seg_id: SegmentId,
    func: FuncId,
    place: &str,
) {
    let parts = storage_segments_cached(place);
    for split in 1..parts.len() {
        let base = join_storage_parts(&parts[..split]);
        let field = join_storage_parts(&parts[split..]);
        seed_exact_field_demand(
            demands,
            reverse,
            roots_by_field,
            field_write_key(seg_id, func, &base),
            &field,
        );
    }
}

fn intern_field_demand_key(
    demands: &mut FieldDemandIndex,
    reverse: &mut Vec<Vec<usize>>,
    key: FieldPlaceKey,
) -> usize {
    if let Some(id) = demands.key_ids.get(&key).copied() {
        return id;
    }
    let id = demands.fields_by_key.len();
    demands.key_ids.insert(key, id);
    demands.fields_by_key.push(Vec::new());
    demands.all_fields_by_key.push(false);
    reverse.push(Vec::new());
    id
}

fn seed_exact_field_demand(
    demands: &mut FieldDemandIndex,
    reverse: &mut Vec<Vec<usize>>,
    roots_by_field: &mut Vec<Vec<usize>>,
    key: FieldPlaceKey,
    field: &str,
) {
    let key_id = intern_field_demand_key(demands, reverse, key);
    let field_id = if let Some(id) = demands.field_ids.get(field).copied() {
        id
    } else {
        let id = u32::try_from(demands.field_ids.len()).expect("field demand id exceeds u32");
        demands.field_ids.insert(field.to_string(), id);
        roots_by_field.push(Vec::new());
        id
    };
    roots_by_field[field_id as usize].push(key_id);
}

fn push_field_write_transform(
    transforms: &mut AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    key: FieldPlaceKey,
    transform: FieldWriteTransform,
) {
    if key.base.is_empty() {
        return;
    }
    transforms.entry(key).or_default().push(transform);
}

fn field_write_key(seg_id: SegmentId, func: FuncId, base: &str) -> FieldPlaceKey {
    FieldPlaceKey {
        seg_id,
        func,
        base: normalize_storage_base(base),
        writes: true,
    }
}

fn seed_field_write_worklist(
    field_index: &FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    demands: Option<&FieldDemandIndex>,
    demand_driven: bool,
    demand_driven_funcs: Option<&AHashSet<FuncId>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    let mut keys: Vec<FieldPlaceKey> = transforms.keys().cloned().collect();
    sort_field_keys(&mut keys);
    for key in keys {
        let Some(hits) = field_index.by_base.get(&key) else {
            continue;
        };
        for hit in hits {
            if field_demand_applies(demand_driven, demand_driven_funcs, key.func)
                && demands.is_some_and(|demands| !demands.contains(&key, &hit.field))
            {
                continue;
            }
            enqueue_field_write(&key, hit, pending, enqueued);
        }
    }
}

fn sort_field_keys(keys: &mut [FieldPlaceKey]) {
    keys.sort_by(|a, b| {
        (a.seg_id.0, a.func.raw(), a.base.as_str(), a.writes).cmp(&(
            b.seg_id.0,
            b.func.raw(),
            b.base.as_str(),
            b.writes,
        ))
    });
}

fn enqueue_field_write(
    key: &FieldPlaceKey,
    hit: &FieldPlaceHit,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    let write = PendingFieldWrite {
        seg_id: key.seg_id,
        func: key.func,
        node: hit.node,
    };
    if enqueued.insert(write) {
        pending.push_back(write);
    }
}

fn enqueue_recorded_field_writes(
    writes: Vec<(FieldPlaceKey, FieldPlaceHit)>,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    for (key, hit) in writes {
        if transforms.contains_key(&key) {
            enqueue_field_write(&key, &hit, pending, enqueued);
        }
    }
}

fn dedup_receiver_mutation_sites(sites: &mut Vec<Arc<ReceiverMutationStitch>>) {
    let mut seen = AHashSet::default();
    sites.retain(|site| seen.insert(Arc::clone(site)));
}

#[allow(clippy::too_many_arguments)] // Worklist state is explicit to keep the field propagation side effects auditable.
fn apply_field_write_transform(
    transform: &FieldWriteTransform,
    source: &FieldPlaceHit,
    demands: Option<&FieldDemandIndex>,
    demand_driven: bool,
    demand_driven_funcs: Option<&AHashSet<FuncId>>,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
) {
    if let (Some(demands), Some(target_key)) = (demands, field_transform_target_key(transform)) {
        if field_demand_applies(demand_driven, demand_driven_funcs, target_key.func) {
            let aggregate_demand = demands.contains_all(&target_key);
            let exact_demand = demands.contains_exact(&target_key, &source.field);
            if aggregate_demand {
                if let FieldWriteTransform::Argument(site) = transform {
                    apply_field_argument_aggregate(site, source, inter_call_arg_entries, ws, known_edges);
                }
            }
            if !aggregate_demand && !exact_demand {
                return;
            }
        }
    }
    match transform {
        FieldWriteTransform::Argument(site) => {
            apply_field_argument_write(
                site,
                source,
                inter_call_arg_entries,
                synthetic_field_writes,
                ws,
                known_edges,
                field_index,
                transforms,
                pending,
                enqueued,
            );
        }
        FieldWriteTransform::Return(site) => {
            apply_return_field_write(
                site,
                source,
                inter_call_arg_entries,
                synthetic_field_writes,
                ws,
                known_edges,
                field_index,
                transforms,
                pending,
                enqueued,
            );
        }
        FieldWriteTransform::ScalarReturn(site) => {
            apply_scalar_return_field_write(site, source, ws, known_edges);
        }
        FieldWriteTransform::ConstructorReturn(site) => {
            apply_constructor_return_field_write(
                site,
                source,
                inter_call_arg_entries,
                synthetic_field_writes,
                ws,
                known_edges,
                field_index,
                transforms,
                pending,
                enqueued,
            );
        }
        FieldWriteTransform::ReceiverMutation(site) => {
            apply_receiver_mutation_field_write(
                site,
                source,
                inter_call_arg_entries,
                synthetic_field_writes,
                ws,
                known_edges,
                field_index,
                transforms,
                pending,
                enqueued,
            );
        }
        FieldWriteTransform::Copy(site) => {
            apply_intra_field_copy_write(
                site,
                source,
                inter_call_arg_entries,
                synthetic_field_writes,
                ws,
                known_edges,
                field_index,
                transforms,
                pending,
                enqueued,
                stitch_data.get(&site.func).map(|data| &data.flow_control),
            );
        }
    }
}

fn field_transform_may_apply(
    transform: &FieldWriteTransform,
    field: &str,
    demands: &FieldDemandIndex,
    demand_driven: bool,
    demand_driven_funcs: Option<&AHashSet<FuncId>>,
) -> bool {
    let Some(target_key) = field_transform_target_key(transform) else {
        return true;
    };
    !field_demand_applies(demand_driven, demand_driven_funcs, target_key.func)
        || demands.contains_all(&target_key)
        || demands.contains_exact(&target_key, field)
}

fn field_transform_source_may_apply(
    transform: &FieldWriteTransform,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &InterCallArgEntryIndex,
    synthetic_field_writes: &SyntheticFieldWriteCache,
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
) -> bool {
    if !is_forwardable_field(&source.field) {
        return false;
    }
    match transform {
        FieldWriteTransform::Argument(site) => {
            site.allow_out_of_order_source
                || source_write_can_reach_call(
                    source,
                    site.call_span,
                    inter_call_arg_entries,
                    site.caller_seg,
                    site.caller,
                )
        }
        FieldWriteTransform::ScalarReturn(site) => source.field == site.source_field,
        FieldWriteTransform::Copy(site) => source_can_reach_field_copy(
            source,
            site,
            synthetic_field_writes,
            inter_call_arg_entries,
            stitch_data.get(&site.func).map(|data| &data.flow_control),
        ),
        FieldWriteTransform::Return(_)
        | FieldWriteTransform::ConstructorReturn(_)
        | FieldWriteTransform::ReceiverMutation(_) => true,
    }
}

fn apply_field_argument_aggregate(
    site: &FieldArgStitch,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &InterCallArgEntryIndex,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) {
    if (!site.allow_out_of_order_source
        && !source_write_can_reach_call(
            source,
            site.call_span,
            inter_call_arg_entries,
            site.caller_seg,
            site.caller,
        ))
        || !is_forwardable_field(&source.field)
    {
        return;
    }
    let Some(actual_arg_node) = site.actual_arg_node else {
        return;
    };
    let _ = place_inter_edge_if_absent(
        site.caller_seg,
        site.caller_seg,
        IdgEdge {
            from: source.node,
            to: actual_arg_node,
            meta: crate::edge::EdgeMeta {
                precision: site.precision,
                kind: crate::edge::IdgEdgeKind::IntraRead,
                call_kind: site.call_kind,
                via_span: site.call_span,
            },
        },
        ws,
        known_edges,
    );
}

fn field_demand_applies(
    demand_driven: bool,
    demand_driven_funcs: Option<&AHashSet<FuncId>>,
    func: FuncId,
) -> bool {
    demand_driven && demand_driven_funcs.is_none_or(|funcs| funcs.contains(&func))
}

#[allow(clippy::too_many_arguments)] // Call-site field forwarding carries source, destination, and worklist state.
fn apply_field_argument_write(
    site: &FieldArgStitch,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    if (!site.allow_out_of_order_source
        && !source_write_can_reach_call(
            source,
            site.call_span,
            inter_call_arg_entries,
            site.caller_seg,
            site.caller,
        ))
        || !is_forwardable_field(&source.field)
    {
        return;
    }
    let Some((param_field_write, param_field_span, is_new_field_write)) = synthetic_field_writes
        .ensure_parameter(
            ws,
            site.callee_seg,
            site.callee,
            &site.param_name,
            &source.field,
            site.call_span,
        )
    else {
        return;
    };
    let recorded = if is_new_field_write {
        field_index.record_write(
            site.callee_seg,
            site.callee,
            &site.param_name,
            &source.field,
            param_field_span,
            param_field_write,
            transforms,
        )
    } else {
        Vec::new()
    };
    if place_inter_edge_if_absent(
        site.caller_seg,
        site.callee_seg,
        IdgEdge {
            from: source.node,
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
    ) {
        inter_call_arg_entries.insert(site.callee_seg, site.callee, param_field_write);
    }
    // A synthetic node can be interned first through a different prefix view
    // of the same storage place. Its exact inbound edge is new even when the
    // node is not, so always ensure its AST read consumers are connected.
    // `known_edges` keeps this idempotent.
    connect_field_write_to_reads(
        site.callee_seg,
        site.callee,
        &site.param_name,
        &source.field,
        param_field_write,
        site.call_span,
        site.precision,
        site.call_kind,
        ws,
        known_edges,
        field_index,
    );
    enqueue_recorded_field_writes(recorded, transforms, pending, enqueued);
}

#[allow(clippy::too_many_arguments)] // Return field forwarding carries source, destination, and worklist state.
fn apply_return_field_write(
    site: &ReturnFieldStitch,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    apply_outbound_field_write(
        site.callee_seg,
        site.caller_seg,
        site.caller,
        &site.target_base,
        site.write_span,
        site.call_span,
        site.precision,
        site.call_kind,
        source,
        inter_call_arg_entries,
        synthetic_field_writes,
        ws,
        known_edges,
        field_index,
        transforms,
        pending,
        enqueued,
        crate::edge::IdgEdgeKind::InterReturn,
        false,
    );
}

fn apply_scalar_return_field_write(
    site: &ScalarReturnStitch,
    source: &FieldPlaceHit,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
) {
    if source.field != site.source_field {
        return;
    }
    let Some(target_write) = ensure_scalar_write_node(
        ws,
        site.caller_seg,
        site.caller,
        &site.target_base,
        site.write_span,
    ) else {
        return;
    };
    place_inter_edge_if_absent(
        site.callee_seg,
        site.caller_seg,
        IdgEdge {
            from: source.node,
            to: target_write,
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
}

#[allow(clippy::too_many_arguments)] // Constructor return forwarding carries source, destination, and worklist state.
fn apply_constructor_return_field_write(
    site: &ConstructorReturnStitch,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    apply_outbound_field_write(
        site.callee_seg,
        site.caller_seg,
        site.caller,
        &site.target_base,
        site.write_span,
        site.call_span,
        site.precision,
        site.call_kind,
        source,
        inter_call_arg_entries,
        synthetic_field_writes,
        ws,
        known_edges,
        field_index,
        transforms,
        pending,
        enqueued,
        crate::edge::IdgEdgeKind::InterReturn,
        false,
    );
}

#[allow(clippy::too_many_arguments)] // Receiver mutation forwarding carries source, destination, and worklist state.
fn apply_receiver_mutation_field_write(
    site: &ReceiverMutationStitch,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    apply_outbound_field_write(
        site.callee_seg,
        site.caller_seg,
        site.caller,
        &site.target_base,
        site.call_span,
        site.call_span,
        site.precision,
        site.call_kind,
        source,
        inter_call_arg_entries,
        synthetic_field_writes,
        ws,
        known_edges,
        field_index,
        transforms,
        pending,
        enqueued,
        crate::edge::IdgEdgeKind::InterReturn,
        false,
    );
}

#[allow(clippy::too_many_arguments)] // Intra-copy forwarding carries source, destination, and worklist state.
fn apply_intra_field_copy_write(
    site: &FieldCopySite,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
    flow_control: Option<&FlowControlFacts>,
) {
    // Reaching definitions normally follow source order. A lexically later
    // syntax write may feed an earlier copy only when the adapter's structured
    // FlowEvent tree proves a CFG back-edge. A descendant self-alias such as
    // `a.child = identity(a)` is the other semantic cycle: the statement
    // creates a recursive object after the call returns. Its synthetic writes
    // may feed the same copy, but only through suffixes in the immutable
    // AST-derived field universe, so convergence is finite without a cap.
    // Inter-call writes are exempt because their spans are caller anchors, not
    // ordering points in this function.
    if !source_can_reach_field_copy(
        source,
        site,
        synthetic_field_writes,
        inter_call_arg_entries,
        flow_control,
    ) {
        return;
    }
    apply_outbound_field_write(
        site.seg_id,
        site.seg_id,
        site.func,
        &site.target_base,
        site.write_span,
        site.via_span,
        site.precision,
        site.call_kind,
        source,
        inter_call_arg_entries,
        synthetic_field_writes,
        ws,
        known_edges,
        field_index,
        transforms,
        pending,
        enqueued,
        crate::edge::IdgEdgeKind::IntraAssign,
        true,
    );
}

fn source_can_reach_field_copy(
    source: &FieldPlaceHit,
    site: &FieldCopySite,
    synthetic_field_writes: &SyntheticFieldWriteCache,
    inter_call_arg_entries: &InterCallArgEntryIndex,
    flow_control: Option<&FlowControlFacts>,
) -> bool {
    if inter_call_arg_entries.contains(site.seg_id, site.func, source.node) {
        return true;
    }
    let Some(write_span) = source.span else {
        return true;
    };
    if write_span.file != site.via_span.file {
        return false;
    }
    if write_span.start < site.via_span.start {
        return true;
    }
    if synthetic_field_writes.is_generated(site.seg_id, site.func, source.node) {
        let source_parts = storage_segments_cached(&site.source_base);
        let target_parts = storage_segments_cached(&site.target_base);
        return write_span == site.write_span
            && target_parts.len() > source_parts.len()
            && target_parts.starts_with(source_parts.as_ref());
    }
    flow_control.is_some_and(|facts| facts.spans_share_loop_back_edge(write_span, site.via_span))
}

#[allow(clippy::too_many_arguments)] // Shared helper keeps edge construction identical across propagation kinds.
fn apply_outbound_field_write(
    from_seg: SegmentId,
    to_seg: SegmentId,
    to_func: FuncId,
    target_base: &str,
    write_span: Span,
    via_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    source: &FieldPlaceHit,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
    edge_kind: crate::edge::IdgEdgeKind,
    skip_self_edge: bool,
) {
    if !is_forwardable_field(&source.field) {
        return;
    }
    let Some((target_field_write, target_field_span, is_new_field_write)) =
        synthetic_field_writes.ensure(ws, to_seg, to_func, target_base, &source.field, write_span)
    else {
        return;
    };
    let recorded = if is_new_field_write {
        field_index.record_write(
            to_seg,
            to_func,
            target_base,
            &source.field,
            target_field_span,
            target_field_write,
            transforms,
        )
    } else {
        Vec::new()
    };
    if !(skip_self_edge && from_seg == to_seg && source.node == target_field_write) {
        let changed = place_inter_edge_if_absent(
            from_seg,
            to_seg,
            IdgEdge {
                from: source.node,
                to: target_field_write,
                meta: crate::edge::EdgeMeta {
                    precision,
                    kind: edge_kind,
                    call_kind,
                    via_span,
                },
            },
            ws,
            known_edges,
        );
        if changed
            && matches!(
                edge_kind,
                crate::edge::IdgEdgeKind::InterCallArg | crate::edge::IdgEdgeKind::InterReturn
            )
        {
            inter_call_arg_entries.insert(to_seg, to_func, target_field_write);
        }
    }
    connect_field_write_to_reads(
        to_seg,
        to_func,
        target_base,
        &source.field,
        target_field_write,
        target_field_span,
        precision,
        call_kind,
        ws,
        known_edges,
        field_index,
    );
    enqueue_recorded_field_writes(recorded, transforms, pending, enqueued);
}

fn source_write_can_reach_call(
    source: &FieldPlaceHit,
    call_span: Span,
    inter_call_arg_entries: &InterCallArgEntryIndex,
    seg_id: SegmentId,
    func: FuncId,
) -> bool {
    let Some(write_span) = source.span else {
        return true;
    };
    write_span.file != call_span.file
        || write_span.start <= call_span.start
        || inter_call_arg_entries.contains(seg_id, func, source.node)
}

fn stitch_field_argument_fallbacks(
    sites: &[Arc<FieldArgStitch>],
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &FieldPlaceIndex,
    inter_call_arg_entries: &InterCallArgEntryIndex,
) -> usize {
    let mut added = 0usize;
    for site in sites {
        let writers = field_index.field_writes_for_base_before_call(
            inter_call_arg_entries,
            site.caller_seg,
            site.caller,
            &site.actual_arg,
            site.call_span,
        );
        if !writers.is_empty() {
            continue;
        }
        let readers = field_index.field_reads_for_base(site.callee_seg, site.callee, &site.param_name);
        for (field, reader) in readers {
            if !is_forwardable_field(&field) {
                continue;
            }
            // The source must be the matching projected Place. Linking the
            // whole CallArg value here would collapse an object into every
            // field demanded by the callee and taint unrelated siblings.
            let Some(actual_field_read) =
                ensure_field_read_node(ws, site.caller_seg, site.caller, &site.actual_arg, &field)
            else {
                continue;
            };
            let changed = place_inter_edge_if_absent(
                site.caller_seg,
                site.callee_seg,
                IdgEdge {
                    from: actual_field_read,
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
            if changed {
                added += 1;
            }
        }
    }
    added
}

#[allow(clippy::too_many_arguments)]
fn stitch_field_copy_fallbacks(
    sites: &[FieldCopySite],
    ws: &mut IdgWorkspace,
    known_edges: &mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &mut FieldPlaceIndex,
    inter_call_arg_entries: &mut InterCallArgEntryIndex,
    synthetic_field_writes: &mut SyntheticFieldWriteCache,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut VecDeque<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
) -> usize {
    let mut added = 0usize;
    for site in sites {
        let writers = field_index.field_writes_for_base_before_call(
            inter_call_arg_entries,
            site.seg_id,
            site.func,
            &site.source_base,
            site.via_span,
        );
        if !writers.is_empty() {
            continue;
        }
        let mut readers = field_index.field_reads_for_base(site.seg_id, site.func, &site.target_base);
        readers.sort_by(|a, b| (a.0.as_str(), a.1 .0).cmp(&(b.0.as_str(), b.1 .0)));
        readers.dedup();
        for (field, _) in readers {
            if !is_forwardable_field(&field) {
                continue;
            }
            let Some(source_read) =
                ensure_field_read_node(ws, site.seg_id, site.func, &site.source_base, &field)
            else {
                continue;
            };
            let before = known_edges.len();
            apply_intra_field_copy_write(
                site,
                &FieldPlaceHit {
                    field,
                    node: source_read,
                    span: None,
                },
                inter_call_arg_entries,
                synthetic_field_writes,
                ws,
                known_edges,
                field_index,
                transforms,
                pending,
                enqueued,
                stitch_data.get(&site.func).map(|data| &data.flow_control),
            );
            added = added.saturating_add(known_edges.len().saturating_sub(before));
        }
    }
    added
}

fn call_ret_assignment_targets(
    ws: &IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    call_ret_node: NodeId,
) -> Vec<(String, Span, Option<String>)> {
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
        if target_base.trim().is_empty() {
            continue;
        }
        let result_field = tuple_result_storage_field(&target_base).map(str::to_string);
        out.push((target_base, write_span, result_field));
    }
    out.sort_by(|a, b| {
        (a.0.as_str(), a.1.start, a.2.as_deref()).cmp(&(b.0.as_str(), b.1.start, b.2.as_deref()))
    });
    out.dedup();
    out
}

fn tuple_result_storage_field(storage: &str) -> Option<&str> {
    let (_, suffix) = storage.rsplit_once('.')?;
    suffix
        .strip_prefix(bonsai_lang_api::kit::SYNTHETIC_TUPLE_RESULT_PREFIX)
        .filter(|field| !field.is_empty() && field.chars().all(|ch| ch.is_ascii_digit()))
}

fn is_forwardable_field(field: &str) -> bool {
    let parts = storage_segments_cached(field);
    !parts.is_empty()
}

fn field_forwarding_base_allowed(base: &str) -> bool {
    let parts = storage_segments_cached(base);
    !parts.is_empty()
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '$' | '@'))
        })
}

fn collect_field_copy_sites(
    ws: &IdgWorkspace,
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
) -> Vec<FieldCopySite> {
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
                || !is_container_copy_target(
                    &target_base,
                    stitch_data
                        .get(&from_node.func)
                        .map(|data| data.receiver_names.as_slice())
                        .unwrap_or_default(),
                )
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

fn is_container_copy_target(target: &str, receiver_names: &[String]) -> bool {
    let parts = storage_segments_cached(target);
    match parts.as_ref() {
        [_bare] => true,
        [receiver, _field] => receiver_name_matches(receiver, receiver_names),
        [base, ..] => base
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch == '$' || ch.is_lowercase()),
        _ => false,
    }
}

fn storage_segments_cached(text: &str) -> Arc<[String]> {
    let cached = STORAGE_SEGMENTS_CACHE.read().get(text).cloned();
    if let Some(hit) = cached {
        return hit;
    }
    let mut parts = Vec::new();
    push_storage_segments(text, &mut parts);
    let parts: Arc<[String]> = Arc::from(parts.into_boxed_slice());
    let mut write = STORAGE_SEGMENTS_CACHE.write();
    if write.len() >= STORAGE_SEGMENTS_CACHE_CAP {
        write.clear();
    }
    write.entry(text.to_string()).or_insert_with(|| parts.clone());
    parts
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
    field_index: &FieldPlaceIndex,
) -> bool {
    let normalized_base = normalize_storage_base(base);
    let Some(readers) = field_index.field_hits_for_normalized_base(seg_id, func, &normalized_base, false)
    else {
        return false;
    };
    let mut changed = false;
    // Every exact read is indexed under all of its prefix/suffix views. The
    // split used to create this canonical writer is therefore sufficient to
    // find every same-or-descendant read without an O(path_depth^2) scan.
    for reader in readers {
        if !field_matches_or_descends(&reader.field, field) || reader.node == writer {
            continue;
        }
        changed |= place_inter_edge_if_absent(
            seg_id,
            seg_id,
            IdgEdge {
                from: writer,
                to: reader.node,
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

fn field_matches_or_descends(candidate: &str, field: &str) -> bool {
    candidate == field
        || candidate
            .strip_prefix(field)
            .is_some_and(|suffix| suffix.starts_with('.'))
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

fn ensure_field_read_node(
    ws: &mut IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
    field: &str,
) -> Option<NodeId> {
    let (name, path_parts) = storage_path_parts(base, field)?;
    let segment = ws.segment_mut(seg_id)?;
    let name_id = segment.strings.intern(&name);
    let mut path: SmallVec<[StrId; 4]> = SmallVec::new();
    for part in path_parts {
        path.push(segment.strings.intern(&part));
    }
    let pid = segment.intern_place(Place::Read { name: name_id, path });
    Some(segment.intern_node(func, pid))
}

fn ensure_scalar_write_node(
    ws: &mut IdgWorkspace,
    seg_id: SegmentId,
    func: FuncId,
    target_base: &str,
    span: Span,
) -> Option<NodeId> {
    let positional_tuple_binding = tuple_result_storage_field(target_base).is_some();
    let name = if positional_tuple_binding {
        target_base.trim().to_string()
    } else {
        normalize_storage_base(target_base)
    };
    if name.is_empty() || (name.contains('.') && !positional_tuple_binding) {
        return None;
    }
    let segment = ws.segment_mut(seg_id)?;
    let name_id = segment.strings.intern(&name);
    let pid = segment.intern_place(Place::Write {
        name: name_id,
        path: SmallVec::new(),
        span,
    });
    Some(segment.intern_node(func, pid))
}

fn storage_path_parts(base: &str, field: &str) -> Option<(String, Vec<String>)> {
    let base_parts = storage_segments_cached(base);
    let field_parts = storage_segments_cached(field);
    let total = base_parts.len() + field_parts.len();
    if total == 0 {
        return None;
    }
    let mut iter = base_parts.iter().chain(field_parts.iter());
    let name = iter.next()?.clone();
    let mut path = Vec::with_capacity(total.saturating_sub(1));
    path.extend(iter.cloned());
    Some((name, path))
}

fn push_storage_segments(text: &str, out: &mut Vec<String>) {
    let normalized = normalize_static_subscripts(text);
    for part in normalized.split('.') {
        let part = part.trim().trim_start_matches(':');
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

impl FieldPlaceIndex {
    fn from_workspace(ws: &IdgWorkspace) -> Self {
        let mut index = Self::default();
        for (seg_id, segment) in ws.segments() {
            for edge in &segment.edges {
                let Some(from_node) = segment.nodes.get(edge.from) else {
                    continue;
                };
                if !matches!(segment.places.get(from_node.place), Some(Place::Read { .. })) {
                    continue;
                }
                let carrier_only_use = edge.meta.kind == crate::edge::IdgEdgeKind::IntraRead
                    && segment
                        .nodes
                        .get(edge.to)
                        .and_then(|node| segment.places.get(node.place))
                        .is_some_and(|place| matches!(place, Place::CallArg { .. }));
                if !carrier_only_use {
                    index
                        .observable_read_nodes
                        .insert((seg_id, from_node.func, edge.from));
                }
            }
        }
        for (seg_id, segment) in ws.segments() {
            for (node_idx, node) in segment.nodes.nodes.iter().enumerate() {
                let Some(place) = segment.places.get(node.place) else {
                    continue;
                };
                let (writes, span, full_name) = match place {
                    Place::Read { .. } => {
                        let Some(full_name) = place_storage_name(segment, place) else {
                            continue;
                        };
                        (false, None, full_name)
                    }
                    Place::Write { span, .. } => {
                        let Some(full_name) = place_storage_name(segment, place) else {
                            continue;
                        };
                        (true, Some(*span), full_name)
                    }
                    _ => continue,
                };
                let node_id = NodeId(node_idx as u32);
                if !writes
                    && index
                        .observable_read_nodes
                        .contains(&(seg_id, node.func, node_id))
                {
                    index
                        .read_storages
                        .insert((seg_id, node.func, normalize_storage_base(&full_name)));
                }
                let _ = index.record_full_storage_place(seg_id, node.func, &full_name, writes, span, node_id);
            }
        }
        index.sort_and_dedup();
        index
    }

    fn has_whole_read(&self, write_key: &FieldPlaceKey) -> bool {
        self.read_storages
            .contains(&(write_key.seg_id, write_key.func, write_key.base.clone()))
    }

    fn is_observable_read(&self, key: &FieldPlaceKey, node: NodeId) -> bool {
        self.observable_read_nodes.contains(&(key.seg_id, key.func, node))
    }

    fn syntactic_field_universe(&self) -> SyntacticFieldUniverse {
        // This snapshot is intentionally taken before synthetic writes are
        // recorded. Reads and writes emitted by every language adapter use the
        // same Place representation, so numeric map/tuple keys and arbitrarily
        // deep exact paths participate without language-specific constants.
        let suffixes = self
            .by_base
            .values()
            .flat_map(|hits| hits.iter().map(|hit| hit.field.clone()))
            .collect();
        SyntacticFieldUniverse { suffixes }
    }

    fn field_writes_for_base_before_call(
        &self,
        inter_call_arg_entries: &InterCallArgEntryIndex,
        seg_id: SegmentId,
        func: FuncId,
        base: &str,
        call_span: Span,
    ) -> Vec<(String, NodeId)> {
        self.field_hits_for_base(seg_id, func, base, true)
            .into_iter()
            .flatten()
            .filter_map(|hit| {
                let write_span = hit.span?;
                if write_span.file == call_span.file
                    && write_span.start > call_span.start
                    && !inter_call_arg_entries.contains(seg_id, func, hit.node)
                {
                    return None;
                }
                Some((hit.field, hit.node))
            })
            .collect()
    }

    fn field_reads_for_base(&self, seg_id: SegmentId, func: FuncId, base: &str) -> Vec<(String, NodeId)> {
        self.field_hits_for_base(seg_id, func, base, false)
            .into_iter()
            .flatten()
            .map(|hit| (hit.field, hit.node))
            .collect()
    }

    fn has_field_read_for_normalized_base_field(
        &self,
        seg_id: SegmentId,
        func: FuncId,
        base: &str,
        field: &str,
    ) -> bool {
        let key = FieldPlaceKey {
            seg_id,
            func,
            base: base.to_string(),
            writes: false,
        };
        self.by_base
            .get(&key)
            .is_some_and(|hits| hits.iter().any(|hit| hit.field == field))
    }

    fn field_hits_for_base(
        &self,
        seg_id: SegmentId,
        func: FuncId,
        base: &str,
        writes: bool,
    ) -> Option<Vec<FieldPlaceHit>> {
        let base = normalize_storage_base(base);
        self.field_hits_for_normalized_base(seg_id, func, &base, writes)
            .map(|hits| hits.to_vec())
    }

    fn field_hits_for_normalized_base(
        &self,
        seg_id: SegmentId,
        func: FuncId,
        base: &str,
        writes: bool,
    ) -> Option<&[FieldPlaceHit]> {
        let key = FieldPlaceKey {
            seg_id,
            func,
            base: base.to_string(),
            writes,
        };
        self.by_base.get(&key).map(Vec::as_slice)
    }

    #[allow(clippy::too_many_arguments)] // Field write recording carries segment, function, span, node, and transform state.
    fn record_write(
        &mut self,
        seg_id: SegmentId,
        func: FuncId,
        base: &str,
        field: &str,
        span: Span,
        node: NodeId,
        transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    ) -> Vec<(FieldPlaceKey, FieldPlaceHit)> {
        let base_parts = storage_segments_cached(base);
        let field_parts = storage_segments_cached(field);
        let mut parts = Vec::with_capacity(base_parts.len() + field_parts.len());
        parts.extend(base_parts.iter().map(String::as_str));
        parts.extend(field_parts.iter().map(String::as_str));
        if parts.len() < 2 {
            return Vec::new();
        }
        let mut added = Vec::new();
        for split in 1..parts.len() {
            let field_parts = &parts[split..];
            let base = join_storage_part_refs(&parts[..split]);
            let field = join_storage_part_refs(field_parts);
            if base.is_empty() || field.is_empty() {
                continue;
            }
            let key = FieldPlaceKey {
                seg_id,
                func,
                base: base.clone(),
                writes: true,
            };
            if !transforms.contains_key(&key)
                && !self.has_field_read_for_normalized_base_field(seg_id, func, &base, &field)
            {
                continue;
            }
            added.extend(self.record_storage_hit(seg_id, func, base, field, true, Some(span), node));
        }
        added
    }

    fn record_full_storage_place(
        &mut self,
        seg_id: SegmentId,
        func: FuncId,
        full_name: &str,
        writes: bool,
        span: Option<Span>,
        node: NodeId,
    ) -> Vec<(FieldPlaceKey, FieldPlaceHit)> {
        let mut added = Vec::new();
        let cached_parts = storage_segments_cached(full_name);
        let parts = cached_parts.iter().map(String::as_str).collect::<Vec<_>>();
        if parts.len() < 2 {
            return added;
        }
        for split in 1..parts.len() {
            let field_parts = &parts[split..];
            let base = join_storage_part_refs(&parts[..split]);
            let field = join_storage_part_refs(field_parts);
            if base.is_empty() || field.is_empty() {
                continue;
            }
            added.extend(self.record_storage_hit(seg_id, func, base, field, writes, span, node));
        }
        added
    }

    #[allow(clippy::too_many_arguments)] // Keeps the field-place key and hit metadata explicit at the write site.
    fn record_storage_hit(
        &mut self,
        seg_id: SegmentId,
        func: FuncId,
        base: String,
        field: String,
        writes: bool,
        span: Option<Span>,
        node: NodeId,
    ) -> Vec<(FieldPlaceKey, FieldPlaceHit)> {
        let key = FieldPlaceKey {
            seg_id,
            func,
            base,
            writes,
        };
        let hit = FieldPlaceHit { field, node, span };
        self.by_base.entry(key.clone()).or_default().push(hit.clone());
        vec![(key, hit)]
    }

    fn sort_and_dedup(&mut self) {
        for hits in self.by_base.values_mut() {
            sort_field_hits(hits);
        }
    }
}

fn normalize_storage_base(base: &str) -> String {
    normalize_storage_base_cached(base).as_ref().to_string()
}

fn normalize_storage_base_cached(base: &str) -> Arc<str> {
    let cached = NORMALIZED_STORAGE_CACHE.read().get(base).cloned();
    if let Some(hit) = cached {
        return hit;
    }
    let parts = storage_segments_cached(base);
    let normalized: Arc<str> = Arc::from(join_storage_parts(parts.as_ref()));
    let mut write = NORMALIZED_STORAGE_CACHE.write();
    if write.len() >= STORAGE_SEGMENTS_CACHE_CAP {
        write.clear();
    }
    write
        .entry(base.to_string())
        .or_insert_with(|| normalized.clone());
    normalized
}

fn join_storage_parts(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        _ => {
            let len = parts.iter().map(String::len).sum::<usize>() + parts.len().saturating_sub(1);
            let mut out = String::with_capacity(len);
            for (idx, part) in parts.iter().enumerate() {
                if idx > 0 {
                    out.push('.');
                }
                out.push_str(part);
            }
            out
        }
    }
}

fn join_storage_part_refs(parts: &[&str]) -> String {
    match parts {
        [] => String::new(),
        [one] => (*one).to_string(),
        _ => {
            let len = parts.iter().map(|part| part.len()).sum::<usize>() + parts.len().saturating_sub(1);
            let mut out = String::with_capacity(len);
            for (idx, part) in parts.iter().enumerate() {
                if idx > 0 {
                    out.push('.');
                }
                out.push_str(part);
            }
            out
        }
    }
}

fn sort_field_hits(hits: &mut Vec<FieldPlaceHit>) {
    hits.sort_by(|a, b| {
        (a.field.as_str(), a.node.0, a.span.map(|span| span.start)).cmp(&(
            b.field.as_str(),
            b.node.0,
            b.span.map(|span| span.start),
        ))
    });
    hits.dedup();
}

impl InterCallArgEntryIndex {
    fn from_workspace(ws: &IdgWorkspace) -> Self {
        let mut index = Self::default();
        for (seg_id, segment) in ws.segments() {
            for edge in &segment.edges {
                if edge.meta.kind != crate::edge::IdgEdgeKind::InterCallArg {
                    continue;
                }
                if let Some(to_node) = segment.nodes.get(edge.to) {
                    index.entries.insert((seg_id, to_node.func, edge.to));
                }
            }
        }
        for cross in &ws.cross_file().edges {
            if cross.edge.meta.kind != crate::edge::IdgEdgeKind::InterCallArg {
                continue;
            }
            if let Some(to_node) = ws
                .segment(cross.to_segment)
                .and_then(|segment| segment.nodes.get(cross.edge.to))
            {
                index
                    .entries
                    .insert((cross.to_segment, to_node.func, cross.edge.to));
            }
        }
        index
    }

    fn contains(&self, seg_id: SegmentId, func: FuncId, local: NodeId) -> bool {
        self.entries.contains(&(seg_id, func, local))
    }

    fn insert(&mut self, seg_id: SegmentId, func: FuncId, local: NodeId) {
        self.entries.insert((seg_id, func, local));
    }
}

impl SyntheticFieldWriteCache {
    fn from_workspace(ws: &IdgWorkspace) -> Self {
        let mut initial_node_counts = vec![0; ws.segment_count()];
        for (seg_id, segment) in ws.segments() {
            initial_node_counts[seg_id.0 as usize] =
                u32::try_from(segment.nodes.len()).expect("segment node count exceeds u32");
        }
        Self {
            initial_node_counts,
            parameter_nodes: AHashMap::default(),
        }
    }

    fn is_generated(&self, seg_id: SegmentId, _func: FuncId, node: NodeId) -> bool {
        self.initial_node_counts
            .get(seg_id.0 as usize)
            .is_some_and(|initial| node.0 >= *initial)
    }

    fn ensure(
        &mut self,
        ws: &mut IdgWorkspace,
        seg_id: SegmentId,
        func: FuncId,
        base: &str,
        field: &str,
        fallback_span: Span,
    ) -> Option<(NodeId, Span, bool)> {
        // The segment's compiler dictionaries already intern the complete
        // `Place::Write { path, span }` and `(func, place)` node identity.
        // Reusing that identity avoids a second string-heavy cache while still
        // canonicalising alternate `(base, field)` splits of the same place.
        let before = ws.segment(seg_id)?.nodes.len();
        let node = ensure_field_write_node(ws, seg_id, func, base, field, fallback_span)?;
        let is_new = ws.segment(seg_id)?.nodes.len() != before;
        Some((node, fallback_span, is_new))
    }

    fn ensure_parameter(
        &mut self,
        ws: &mut IdgWorkspace,
        seg_id: SegmentId,
        func: FuncId,
        base: &str,
        field: &str,
        fallback_span: Span,
    ) -> Option<(NodeId, Span, bool)> {
        let key = (
            seg_id,
            func,
            normalize_storage_base(base),
            normalize_storage_base(field),
        );
        if let Some((node, span)) = self.parameter_nodes.get(&key).copied() {
            return Some((node, span, false));
        }
        let created = self.ensure(ws, seg_id, func, &key.2, &key.3, fallback_span)?;
        self.parameter_nodes.insert(key, (created.0, created.1));
        Some(created)
    }
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

fn stitch_debug_enabled() -> bool {
    bonsai_diagnostics::debug::is_enabled("idg-build")
}

fn stitch_debug_log(args: std::fmt::Arguments<'_>) {
    if stitch_debug_enabled() {
        let message = bonsai_diagnostics::debug::render_message(&args.to_string());
        eprintln!("[idg-build] {message}");
    }
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
