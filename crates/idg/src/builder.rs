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
use bonsai_factstore::{StrId, StringPoolBuilder};
use bonsai_lang_api::CallKind;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use crate::edge::IdgEdge;
use crate::node::NodeId;
use crate::place::{CallSiteId, Place};
use crate::segment::IdgSegment;
use crate::symbolic::{SymbolicFieldTransform, SymbolicFieldTransformKind, NO_SYMBOLIC_STRING};
use crate::transfer::{
    receiver_name_matches, receiver_tokens_equal, CallSiteRef, DescendantCopy, FlowControlFacts,
    ReturnFieldProjection, TransferOutput, YieldResultRef,
};
use crate::workspace::{
    CrossFileEdge, IdgWorkspace, SegmentId, SymbolicFieldCompilerStorage, WireChunkSpool,
};

#[derive(Debug)]
struct CalleeEndpointInput {
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
    yield_node: Option<NodeId>,
}

#[derive(Debug)]
struct CalleeEndpoints {
    segment: SegmentId,
    params_end: u32,
    param_names_end: u32,
    param_write_nodes_end: u32,
    capture_read_nodes_end: u32,
    receiver_param_index: u32,
    receiver_consumer_nodes_end: u32,
    receiver_field_bases_end: u32,
    implicit_receiver_bases_end: u32,
    receiver_names_end: u32,
    return_field_projections_end: u32,
    return_passthrough_param_indices_end: u32,
    return_node: NodeId,
    yield_node: NodeId,
}

#[derive(Copy, Clone, Debug)]
struct PackedRange {
    start: u32,
    len: u32,
}

impl PackedRange {
    fn append<T>(pool: &mut Vec<T>, values: impl IntoIterator<Item = T>) -> Self {
        let start = pool.len();
        pool.extend(values);
        let len = pool.len().saturating_sub(start);
        Self {
            start: u32::try_from(start).expect("callee endpoint arena exceeds u32"),
            len: u32::try_from(len).expect("callee endpoint slice exceeds u32"),
        }
    }

    fn slice<T>(self, pool: &[T]) -> &[T] {
        let start = self.start as usize;
        let end = start.saturating_add(self.len as usize);
        pool.get(start..end)
            .expect("callee endpoint range belongs to its canonical arena")
    }
}

#[derive(Copy, Clone, Debug)]
struct PackedReturnFieldProjection {
    base: StrId,
    field: StrId,
}

#[derive(Copy, Clone)]
struct ReturnFieldProjectionView<'a> {
    base: &'a str,
    field: &'a str,
}

#[derive(Copy, Clone)]
struct CalleeEndpointView<'a> {
    row_index: usize,
    row: &'a CalleeEndpoints,
    index: &'a CalleeEndpointIndex,
}

impl std::ops::Deref for CalleeEndpointView<'_> {
    type Target = CalleeEndpoints;

    fn deref(&self) -> &Self::Target {
        self.row
    }
}

impl<'a> CalleeEndpointView<'a> {
    fn previous(self) -> Option<&'a CalleeEndpoints> {
        self.row_index
            .checked_sub(1)
            .and_then(|index| self.index.rows.get(index))
    }

    fn row_slice<T>(
        self,
        pool: &'a [T],
        end: u32,
        previous_end: impl Fn(&CalleeEndpoints) -> u32,
    ) -> &'a [T] {
        let start = self.previous().map_or(0, previous_end) as usize;
        pool.get(start..end as usize)
            .expect("callee endpoint row boundary belongs to its canonical arena")
    }

    fn receiver_param_index(self) -> Option<usize> {
        (self.row.receiver_param_index != u32::MAX).then_some(self.row.receiver_param_index as usize)
    }

    fn return_node(self) -> Option<NodeId> {
        (!self.row.return_node.is_sentinel()).then_some(self.row.return_node)
    }

    fn yield_node(self) -> Option<NodeId> {
        (!self.row.yield_node.is_sentinel()).then_some(self.row.yield_node)
    }

    fn params(self) -> &'a [NodeId] {
        self.row_slice(&self.index.params, self.row.params_end, |row| row.params_end)
    }

    fn param_name(self, index: usize) -> Option<&'a str> {
        self.row_slice(&self.index.param_names, self.row.param_names_end, |row| {
            row.param_names_end
        })
        .get(index)
        .and_then(|id| self.index.strings.get(*id))
    }

    fn param_names(self) -> impl Iterator<Item = &'a str> + 'a {
        self.row_slice(&self.index.param_names, self.row.param_names_end, |row| {
            row.param_names_end
        })
        .iter()
        .filter_map(|id| self.index.strings.get(*id))
    }

    fn param_write_nodes(self, index: usize) -> &'a [NodeId] {
        self.row_slice(
            &self.index.param_write_nodes,
            self.row.param_write_nodes_end,
            |row| row.param_write_nodes_end,
        )
        .get(index)
        .copied()
        .map_or(&[], |range| range.slice(&self.index.param_write_node_values))
    }

    fn receiver_consumer_nodes(self) -> &'a [NodeId] {
        self.row_slice(
            &self.index.receiver_consumer_nodes,
            self.row.receiver_consumer_nodes_end,
            |row| row.receiver_consumer_nodes_end,
        )
    }

    fn receiver_field_bases(self) -> impl Iterator<Item = &'a str> + 'a {
        self.row_slice(
            &self.index.receiver_field_bases,
            self.row.receiver_field_bases_end,
            |row| row.receiver_field_bases_end,
        )
        .iter()
        .filter_map(|id| self.index.strings.get(*id))
    }

    fn implicit_receiver_bases(self) -> impl Iterator<Item = &'a str> + 'a {
        self.row_slice(
            &self.index.implicit_receiver_bases,
            self.row.implicit_receiver_bases_end,
            |row| row.implicit_receiver_bases_end,
        )
        .iter()
        .filter_map(|id| self.index.strings.get(*id))
    }

    fn receiver_names(self) -> impl Iterator<Item = &'a str> + 'a {
        self.row_slice(&self.index.receiver_names, self.row.receiver_names_end, |row| {
            row.receiver_names_end
        })
        .iter()
        .filter_map(|id| self.index.strings.get(*id))
    }

    fn return_field_projections(self) -> impl Iterator<Item = ReturnFieldProjectionView<'a>> + 'a {
        self.row_slice(
            &self.index.return_field_projections,
            self.row.return_field_projections_end,
            |row| row.return_field_projections_end,
        )
        .iter()
        .filter_map(|projection| {
            Some(ReturnFieldProjectionView {
                base: self.index.strings.get(projection.base)?,
                field: self.index.strings.get(projection.field)?,
            })
        })
    }

    fn capture_reads(self) -> impl Iterator<Item = (&'a str, NodeId)> + 'a {
        self.row_slice(
            &self.index.capture_read_nodes,
            self.row.capture_read_nodes_end,
            |row| row.capture_read_nodes_end,
        )
        .iter()
        .filter_map(|(name, node)| self.index.strings.get(*name).map(|name| (name, *node)))
    }

    fn return_passthrough_param_indices(self) -> impl Iterator<Item = usize> + 'a {
        self.row_slice(
            &self.index.param_indices,
            self.row.return_passthrough_param_indices_end,
            |row| row.return_passthrough_param_indices_end,
        )
        .iter()
        .map(|index| *index as usize)
    }
}

/// Packed endpoint records with a dense compiler-id indirection.
///
/// `CalleeEndpoints` is intentionally rich and therefore large. Storing it
/// inline in an over-capacity hash table wastes one full record-sized bucket
/// for every spare slot on broad workspaces. Function ids are stable `u32`
/// compiler ids, so a compact `FuncId -> row` vector provides O(1) lookup
/// while the endpoint rows remain tightly packed.
struct CalleeEndpointIndex {
    rows: Vec<CalleeEndpoints>,
    row_by_func: Vec<u32>,
    strings: StringPoolBuilder,
    params: Vec<NodeId>,
    param_names: Vec<StrId>,
    param_write_nodes: Vec<PackedRange>,
    param_write_node_values: Vec<NodeId>,
    capture_read_nodes: Vec<(StrId, NodeId)>,
    receiver_consumer_nodes: Vec<NodeId>,
    receiver_field_bases: Vec<StrId>,
    implicit_receiver_bases: Vec<StrId>,
    receiver_names: Vec<StrId>,
    return_field_projections: Vec<PackedReturnFieldProjection>,
    param_indices: Vec<u32>,
}

impl CalleeEndpointIndex {
    const MISSING: u32 = u32::MAX;

    fn with_capacity(function_count: usize) -> Self {
        Self {
            rows: Vec::with_capacity(function_count),
            row_by_func: Vec::new(),
            strings: StringPoolBuilder::new(),
            params: Vec::new(),
            param_names: Vec::new(),
            param_write_nodes: Vec::new(),
            param_write_node_values: Vec::new(),
            capture_read_nodes: Vec::new(),
            receiver_consumer_nodes: Vec::new(),
            receiver_field_bases: Vec::new(),
            implicit_receiver_bases: Vec::new(),
            receiver_names: Vec::new(),
            return_field_projections: Vec::new(),
            param_indices: Vec::new(),
        }
    }

    fn insert(&mut self, func: FuncId, endpoints: CalleeEndpointInput) {
        let func_index = func.raw() as usize;
        if self.row_by_func.len() <= func_index {
            self.row_by_func.resize(func_index + 1, Self::MISSING);
        }
        assert_eq!(
            self.row_by_func[func_index],
            Self::MISSING,
            "callee endpoint inserted twice for function {}",
            func.raw()
        );
        let row = u32::try_from(self.rows.len()).expect("callee endpoint row overflow");
        let CalleeEndpointInput {
            segment,
            params,
            param_names,
            param_write_nodes,
            capture_read_nodes,
            receiver_param_index,
            receiver_consumer_nodes,
            receiver_field_bases,
            implicit_receiver_bases,
            receiver_names,
            return_field_projections,
            return_passthrough_param_indices,
            return_node,
            yield_node,
        } = endpoints;
        let params_end = Self::append_end(&mut self.params, params);
        let param_names_end = Self::pack_strings(&mut self.strings, &mut self.param_names, param_names);
        for nodes in param_write_nodes {
            self.param_write_nodes
                .push(PackedRange::append(&mut self.param_write_node_values, nodes));
        }
        let param_write_nodes_end =
            u32::try_from(self.param_write_nodes.len()).expect("callee parameter range arena exceeds u32");
        let capture_read_nodes = capture_read_nodes
            .into_iter()
            .map(|(name, node)| (self.strings.intern(&name), node));
        let capture_read_nodes_end = Self::append_end(&mut self.capture_read_nodes, capture_read_nodes);
        let receiver_consumer_nodes_end =
            Self::append_end(&mut self.receiver_consumer_nodes, receiver_consumer_nodes);
        let receiver_field_bases_end = Self::pack_strings(
            &mut self.strings,
            &mut self.receiver_field_bases,
            receiver_field_bases,
        );
        let implicit_receiver_bases_end = Self::pack_strings(
            &mut self.strings,
            &mut self.implicit_receiver_bases,
            implicit_receiver_bases,
        );
        let receiver_names_end =
            Self::pack_strings(&mut self.strings, &mut self.receiver_names, receiver_names);
        let return_field_projections =
            return_field_projections
                .into_iter()
                .map(|projection| PackedReturnFieldProjection {
                    base: self.strings.intern(&projection.base),
                    field: self.strings.intern(&projection.field),
                });
        let return_field_projections_end =
            Self::append_end(&mut self.return_field_projections, return_field_projections);
        let return_passthrough_param_indices_end = Self::append_end(
            &mut self.param_indices,
            return_passthrough_param_indices
                .into_iter()
                .map(|index| u32::try_from(index).expect("callee parameter index exceeds u32")),
        );
        self.rows.push(CalleeEndpoints {
            segment,
            params_end,
            param_names_end,
            param_write_nodes_end,
            capture_read_nodes_end,
            receiver_param_index: receiver_param_index
                .map(|index| u32::try_from(index).expect("receiver parameter index exceeds u32"))
                .unwrap_or(u32::MAX),
            receiver_consumer_nodes_end,
            receiver_field_bases_end,
            implicit_receiver_bases_end,
            receiver_names_end,
            return_field_projections_end,
            return_passthrough_param_indices_end,
            return_node: return_node.unwrap_or(NodeId::SENTINEL),
            yield_node: yield_node.unwrap_or(NodeId::SENTINEL),
        });
        self.row_by_func[func_index] = row;
    }

    fn append_end<T>(pool: &mut Vec<T>, values: impl IntoIterator<Item = T>) -> u32 {
        pool.extend(values);
        u32::try_from(pool.len()).expect("callee endpoint arena exceeds u32")
    }

    fn pack_strings(strings: &mut StringPoolBuilder, pool: &mut Vec<StrId>, values: Vec<String>) -> u32 {
        pool.extend(values.into_iter().map(|value| strings.intern(&value)));
        u32::try_from(pool.len()).expect("callee endpoint string arena exceeds u32")
    }

    fn finish_build(&mut self) {
        self.strings.release_lookup();
    }

    fn get(&self, func: FuncId) -> Option<CalleeEndpointView<'_>> {
        let row = *self.row_by_func.get(func.raw() as usize)?;
        if row == Self::MISSING {
            return None;
        }
        let row_index = row as usize;
        self.rows.get(row_index).map(|row| CalleeEndpointView {
            row_index,
            row,
            index: self,
        })
    }

    fn contains_key(&self, func: FuncId) -> bool {
        self.get(func).is_some()
    }

    fn len(&self) -> usize {
        self.rows.len()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FunctionStitchData {
    params: Vec<String>,
    call_sites: Vec<CallSiteRef>,
    yield_results: Vec<YieldResultRef>,
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

fn take_function_stitch_data(out: TransferOutput) -> (FuncId, FunctionStitchData) {
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
        yield_results,
        is_constructor,
        has_return_event,
        ..
    } = out;
    let param_count = params.len();
    (
        func,
        FunctionStitchData {
            params,
            call_sites,
            yield_results,
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
    )
}

/// Minimal function facts retained after its call sites have been stitched.
/// The complete [`FunctionStitchData`] owns every call-site string and node
/// list; keeping all of it until field propagation made transient compiler IR
/// overlap the fully materialized cross-file graph on large workspaces.
struct FunctionFieldContext {
    receiver_names: Vec<String>,
    flow_control: FlowControlFacts,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FieldArgStitch {
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    actual_arg: String,
    param_name: String,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    arg_idx: u32,
    param_idx: u32,
    allow_out_of_order_source: bool,
}

const MAX_STORAGE_NORMALIZATION_CACHE_ENTRIES: usize = 131_072;
const MIN_STORAGE_NORMALIZATION_CACHE_ENTRIES: usize = 4_096;
// One logical path owns a hash key plus either a normalized string or an Arc
// slice whose elements own separate strings. Include allocator/hash control
// overhead as well as the visible payload; treating this as a 512-byte scalar
// record made the two recomputable memos retain ~180 MiB on Elasticsearch.
const ESTIMATED_STORAGE_NORMALIZATION_ENTRY_BYTES: u64 = 2 * 1024;
static STORAGE_SEGMENTS_CACHE: LazyLock<parking_lot::RwLock<AHashMap<String, Arc<[String]>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));
static NORMALIZED_STORAGE_CACHE: LazyLock<parking_lot::RwLock<AHashMap<String, Arc<str>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

fn storage_normalization_cache_capacity() -> usize {
    storage_normalization_cache_capacity_for_limit(bonsai_common::effective_memory_limit_bytes())
}

fn storage_normalization_cache_capacity_for_limit(limit: Option<u64>) -> usize {
    // This is a recomputable build-phase memo. Give the two normalization
    // caches a small fraction of detected memory so compiler dictionaries,
    // edge spools, and query accelerators remain the dominant residents.
    // Capacity affects cache hits only; every storage path is normalized with
    // the same AST-derived algorithm after eviction.
    let cache_bytes = limit.map(|limit| limit / 128).unwrap_or(
        MAX_STORAGE_NORMALIZATION_CACHE_ENTRIES as u64 * ESTIMATED_STORAGE_NORMALIZATION_ENTRY_BYTES,
    );
    usize::try_from(cache_bytes / ESTIMATED_STORAGE_NORMALIZATION_ENTRY_BYTES)
        .unwrap_or(MAX_STORAGE_NORMALIZATION_CACHE_ENTRIES)
        .clamp(
            MIN_STORAGE_NORMALIZATION_CACHE_ENTRIES,
            MAX_STORAGE_NORMALIZATION_CACHE_ENTRIES,
        )
}

#[derive(Default, Debug)]
struct FieldArgSiteQueue {
    sites: Vec<FieldArgStitch>,
    deferred: Vec<Arc<FieldArgStitch>>,
    current_caller: Option<FuncId>,
    accepted: usize,
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
        begin_site_caller(
            site.caller,
            &mut self.current_caller,
            &mut self.sites,
            &mut self.deferred,
            &mut self.accepted,
        );
        self.sites.push(site);
    }

    fn take_current_sites(&mut self) -> Vec<FieldArgStitch> {
        self.current_caller = None;
        take_unique_site_batch(&mut self.sites, &mut self.accepted)
    }

    fn defer(&mut self, site: FieldArgStitch) {
        self.deferred.push(Arc::new(site));
    }

    fn into_sites(mut self) -> Vec<Arc<FieldArgStitch>> {
        seal_site_batch(&mut self.sites, &mut self.deferred, &mut self.accepted);
        self.deferred
    }

    fn len(&self) -> usize {
        self.accepted
    }
}

#[derive(Default, Debug)]
struct ReturnFieldSiteQueue {
    sites: Vec<ReturnFieldStitch>,
    deferred: Vec<Arc<ReturnFieldStitch>>,
    current_caller: Option<FuncId>,
    accepted: usize,
}

#[derive(Default, Debug)]
struct ScalarReturnSiteQueue {
    sites: Vec<ScalarReturnStitch>,
    deferred: Vec<Arc<ScalarReturnStitch>>,
    current_caller: Option<FuncId>,
    accepted: usize,
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
        begin_site_caller(
            site.caller,
            &mut self.current_caller,
            &mut self.sites,
            &mut self.deferred,
            &mut self.accepted,
        );
        self.sites.push(site);
    }

    fn take_current_sites(&mut self) -> Vec<ScalarReturnStitch> {
        self.current_caller = None;
        take_unique_site_batch(&mut self.sites, &mut self.accepted)
    }

    fn defer(&mut self, site: ScalarReturnStitch) {
        self.deferred.push(Arc::new(site));
    }

    fn into_sites(mut self) -> Vec<Arc<ScalarReturnStitch>> {
        seal_site_batch(&mut self.sites, &mut self.deferred, &mut self.accepted);
        self.deferred
    }

    fn len(&self) -> usize {
        self.accepted
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
        begin_site_caller(
            site.caller,
            &mut self.current_caller,
            &mut self.sites,
            &mut self.deferred,
            &mut self.accepted,
        );
        self.sites.push(site);
    }

    fn take_current_sites(&mut self) -> Vec<ReturnFieldStitch> {
        self.current_caller = None;
        take_unique_site_batch(&mut self.sites, &mut self.accepted)
    }

    fn defer(&mut self, site: ReturnFieldStitch) {
        self.deferred.push(Arc::new(site));
    }

    fn into_sites(mut self) -> Vec<Arc<ReturnFieldStitch>> {
        seal_site_batch(&mut self.sites, &mut self.deferred, &mut self.accepted);
        self.deferred
    }

    fn len(&self) -> usize {
        self.accepted
    }
}

#[derive(Default, Debug)]
struct ConstructorReturnSiteQueue {
    sites: Vec<ConstructorReturnStitch>,
    deferred: Vec<Arc<ConstructorReturnStitch>>,
    current_caller: Option<FuncId>,
    accepted: usize,
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
        begin_site_caller(
            site.caller,
            &mut self.current_caller,
            &mut self.sites,
            &mut self.deferred,
            &mut self.accepted,
        );
        self.sites.push(site);
    }

    fn take_current_sites(&mut self) -> Vec<ConstructorReturnStitch> {
        self.current_caller = None;
        take_unique_site_batch(&mut self.sites, &mut self.accepted)
    }

    fn defer(&mut self, site: ConstructorReturnStitch) {
        self.deferred.push(Arc::new(site));
    }

    fn into_sites(mut self) -> Vec<Arc<ConstructorReturnStitch>> {
        seal_site_batch(&mut self.sites, &mut self.deferred, &mut self.accepted);
        self.deferred
    }

    fn len(&self) -> usize {
        self.accepted
    }
}

fn begin_site_caller<T>(
    caller: FuncId,
    current_caller: &mut Option<FuncId>,
    sites: &mut Vec<T>,
    retained: &mut Vec<Arc<T>>,
    accepted: &mut usize,
) where
    T: Eq + std::hash::Hash,
{
    if *current_caller == Some(caller) {
        return;
    }
    debug_assert!(
        current_caller.is_none_or(|previous| previous.raw() < caller.raw()),
        "field stitch sites must be emitted in caller order"
    );
    seal_site_batch(sites, retained, accepted);
    *current_caller = Some(caller);
}

fn take_unique_site_batch<T>(sites: &mut Vec<T>, accepted: &mut usize) -> Vec<T>
where
    T: Eq + std::hash::Hash,
{
    let sites = dedup_site_batch(std::mem::take(sites));
    *accepted = accepted.saturating_add(sites.len());
    sites
}

fn seal_site_batch<T>(sites: &mut Vec<T>, retained: &mut Vec<Arc<T>>, accepted: &mut usize)
where
    T: Eq + std::hash::Hash,
{
    retained.extend(take_unique_site_batch(sites, accepted).into_iter().map(Arc::new));
}

/// Deduplicate one caller's compiler facts without cloning their strings or
/// allocating one reference-counted object per candidate. The numeric hash
/// table resolves collisions against the canonical vector, preserving both
/// exact equality and adapter emission order.
fn dedup_site_batch<T>(sites: Vec<T>) -> Vec<T>
where
    T: Eq + std::hash::Hash,
{
    if sites.len() < 2 {
        return sites;
    }
    let hash_builder = ahash::RandomState::new();
    let mut seen = hashbrown::HashTable::<u32>::with_capacity(sites.len());
    let mut unique = Vec::with_capacity(sites.len());
    for site in sites {
        let hash = hash_builder.hash_one(&site);
        if seen
            .find(hash, |index| unique.get(*index as usize) == Some(&site))
            .is_some()
        {
            continue;
        }
        let index = u32::try_from(unique.len()).expect("field stitch site count exceeds u32");
        unique.push(site);
        seen.insert_unique(hash, index, |stored| {
            hash_builder.hash_one(
                unique
                    .get(*stored as usize)
                    .expect("field stitch dedup index belongs to its canonical batch"),
            )
        });
    }
    unique
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
    /// Exact suffixes observed in adapter-lowered places. This remains
    /// independent of `by_base` filtering: a synthetic interprocedural write
    /// may compose two AST-proven path fragments and later need a suffix whose
    /// original base was not itself a requested transform key.
    syntactic_fields: SyntacticFieldUniverse,
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

    fn record_full_storage_place(&mut self, full_name: &str) {
        let cached_parts = storage_segments_cached(full_name);
        let parts = cached_parts.iter().map(String::as_str).collect::<Vec<_>>();
        for split in 1..parts.len() {
            let suffix = join_storage_part_refs(&parts[split..]);
            if !suffix.is_empty() {
                self.suffixes.insert(suffix);
            }
        }
    }

    fn record_argument_projection_demands(
        &mut self,
        field_index: &FieldPlaceIndex,
        sites: &[Arc<FieldArgStitch>],
    ) {
        // Tree-sitter grammars commonly lower a member access as a receiver
        // place plus a selector call. The individual compiler facts prove
        // both halves, but neither necessarily contains their composed access
        // path. Preserve that exact demand so an upstream object hop can carry
        // `container.value.field` through a later `value.field` accessor.
        // This is a finite projection of resolver-backed call sites and
        // adapter-lowered reads; it never admits a token absent from the IR.
        for site in sites {
            let normalized_param = normalize_storage_base_cached(&site.param_name);
            let Some(reads) = field_index.field_hits_for_normalized_base(
                site.callee_seg,
                site.callee,
                normalized_param.as_ref(),
                false,
            ) else {
                continue;
            };
            for read in reads {
                let full_name = if site.actual_arg.trim().is_empty() {
                    read.field.clone()
                } else {
                    format!("{}.{}", site.actual_arg.trim(), read.field)
                };
                self.record_full_storage_place(&full_name);
            }
        }
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

/// Stitch with an optional symbolic access-path relation. Complete adapter
/// field places remain queryable without materializing base × suffix edges.
pub fn stitch_idg_with_field_forwarding_mode(
    outputs: Vec<TransferOutput>,
    resolver: &dyn CalleeResolver,
    f2s: &dyn FuncToSegment,
    include_field_argument_forwarding: bool,
    symbolic_field_forwarding: bool,
) -> IdgWorkspace {
    stitch_idg_with_selective_field_forwarding_mode(
        outputs,
        resolver,
        f2s,
        include_field_argument_forwarding,
        symbolic_field_forwarding,
        None,
    )
}

/// Stitch with symbolic field forwarding limited to adapter functions whose
/// AST field-place emission is complete. `None` preserves the public
/// all-functions symbolic mode used by focused IDG tests and direct callers.
pub fn stitch_idg_with_selective_field_forwarding_mode(
    outputs: Vec<TransferOutput>,
    resolver: &dyn CalleeResolver,
    f2s: &dyn FuncToSegment,
    include_field_argument_forwarding: bool,
    symbolic_field_forwarding: bool,
    symbolic_funcs: Option<&AHashSet<FuncId>>,
) -> IdgWorkspace {
    let mut by_seg = group_by_segment(outputs, f2s);
    let function_count: usize = by_seg.values().map(Vec::len).sum();
    let mut sorted_by_seg: Vec<SegmentId> = by_seg.keys().copied().collect();
    sorted_by_seg.sort_by_key(|segment| segment.0);
    let grouped = sorted_by_seg.into_iter().map(|segment| {
        let outputs = by_seg
            .remove(&segment)
            .expect("segment key collected from grouped outputs");
        (segment, outputs)
    });
    stitch_idg_from_segment_batches(
        std::iter::once(grouped),
        function_count,
        resolver,
        include_field_argument_forwarding,
        symbolic_field_forwarding,
        symbolic_funcs,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReverseLookupRetention {
    Queryable,
    SidecarOnly,
}

struct WorkspaceStitchState {
    call_started: Instant,
    collect_stats: bool,
    stats: StitchStats,
    field_arg_sites: FieldArgSiteQueue,
    return_field_sites: ReturnFieldSiteQueue,
    scalar_return_sites: ScalarReturnSiteQueue,
    constructor_return_sites: ConstructorReturnSiteQueue,
    symbolic_field_graph: SymbolicFieldCompilerStorage,
    receiver_mutation_sites: Vec<Arc<ReceiverMutationStitch>>,
    pending_field_copy_sites: Vec<FieldCopySite>,
    symbolic_field_copy_spool: Option<WireChunkSpool<FieldCopySite>>,
    passthrough_field_copy_sites: Vec<FieldCopySite>,
    field_contexts: AHashMap<FuncId, FunctionFieldContext>,
    field_copy_sites_collected_by_segment: bool,
}

struct WorkspaceCallerStitch<'a> {
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &'a NodeRemap,
    data: FunctionStitchData,
    resolver: &'a dyn CalleeResolver,
    callee_endpoints: &'a CalleeEndpointIndex,
    symbolic_field_forwarding: bool,
    symbolic_funcs: Option<&'a AHashSet<FuncId>>,
}

impl WorkspaceStitchState {
    fn new(function_count: usize) -> Self {
        Self::with_symbolic_storage(
            function_count,
            false,
            SymbolicFieldCompilerStorage::resident(),
            None,
        )
    }

    fn for_spooled_persistence(spool_path: &std::path::Path) -> crate::IdgResult<Self> {
        Ok(Self::with_symbolic_storage(
            0,
            true,
            SymbolicFieldCompilerStorage::spooled(spool_path)?,
            Some(WireChunkSpool::new(
                spool_path,
                FIELD_COPY_SPOOL_CHUNK_LEN,
                "symbolic field copy",
            )?),
        ))
    }

    fn with_symbolic_storage(
        field_context_capacity: usize,
        field_copy_sites_collected_by_segment: bool,
        symbolic_field_graph: SymbolicFieldCompilerStorage,
        symbolic_field_copy_spool: Option<WireChunkSpool<FieldCopySite>>,
    ) -> Self {
        Self {
            call_started: Instant::now(),
            collect_stats: stitch_debug_enabled(),
            stats: StitchStats::default(),
            field_arg_sites: FieldArgSiteQueue::default(),
            return_field_sites: ReturnFieldSiteQueue::default(),
            scalar_return_sites: ScalarReturnSiteQueue::default(),
            constructor_return_sites: ConstructorReturnSiteQueue::default(),
            symbolic_field_graph,
            receiver_mutation_sites: Vec::new(),
            pending_field_copy_sites: Vec::new(),
            symbolic_field_copy_spool,
            passthrough_field_copy_sites: Vec::new(),
            // A spooled build consumes and removes contexts with each file
            // segment, so reserving for every workspace function would leave
            // a mostly empty workspace-sized table resident throughout typed
            // replay. Resident builds pass their full function count because
            // they intentionally defer the same exact facts to the final
            // compatibility phase.
            field_contexts: AHashMap::with_capacity(field_context_capacity),
            field_copy_sites_collected_by_segment,
        }
    }

    fn check_symbolic_spool(&self) -> crate::IdgResult<()> {
        self.symbolic_field_graph.check_spool()?;
        self.symbolic_field_copy_spool
            .as_ref()
            .map_or(Ok(()), WireChunkSpool::check_error)
    }

    fn collect_active_segment_field_copy_sites(
        &mut self,
        seg_id: SegmentId,
        ws: &IdgWorkspace,
        symbolic_field_forwarding: bool,
        symbolic_funcs: Option<&AHashSet<FuncId>>,
    ) {
        let Some(segment) = ws.segment(seg_id) else {
            return;
        };
        let mut sites = std::mem::take(&mut self.pending_field_copy_sites);
        sites.extend(collect_field_copy_sites_from_segment(
            seg_id,
            segment,
            &self.field_contexts,
        ));
        sort_and_dedup_field_copy_sites(&mut sites);
        for site in sites {
            if symbolic_field_forwarding && symbolic_pair_supported(site.func, site.func, symbolic_funcs) {
                if let Some(spool) = &mut self.symbolic_field_copy_spool {
                    spool.push(site);
                } else {
                    push_symbolic_field_copy(&mut self.symbolic_field_graph, &site);
                }
            } else {
                self.passthrough_field_copy_sites.push(site);
            }
        }
        if symbolic_field_forwarding {
            for func_raw in &segment.funcs {
                let func = FuncId::new(*func_raw);
                if symbolic_pair_supported(func, func, symbolic_funcs) {
                    self.field_contexts.remove(&func);
                }
            }
        }
    }

    fn collect_resident_field_copy_sites(
        &mut self,
        ws: &IdgWorkspace,
        symbolic_field_forwarding: bool,
        symbolic_funcs: Option<&AHashSet<FuncId>>,
    ) {
        let mut sites = std::mem::take(&mut self.pending_field_copy_sites);
        sites.extend(collect_field_copy_sites(ws, &self.field_contexts));
        sort_and_dedup_field_copy_sites(&mut sites);
        for site in sites {
            if symbolic_field_forwarding && symbolic_pair_supported(site.func, site.func, symbolic_funcs) {
                push_symbolic_field_copy(&mut self.symbolic_field_graph, &site);
            } else {
                self.passthrough_field_copy_sites.push(site);
            }
        }
        if symbolic_field_forwarding {
            self.field_contexts
                .retain(|func, _| !symbolic_pair_supported(*func, *func, symbolic_funcs));
        }
    }

    fn flush_symbolic_field_copy_spool(&mut self) -> crate::IdgResult<()> {
        let (spool, graph) = (
            self.symbolic_field_copy_spool.as_ref(),
            &mut self.symbolic_field_graph,
        );
        if let Some(spool) = spool {
            spool.visit(|sites| {
                for site in sites {
                    push_symbolic_field_copy(graph, site);
                }
                Ok(())
            })?;
        }
        graph.check_spool()
    }

    fn stitch_caller(&mut self, ws: &mut IdgWorkspace, request: WorkspaceCallerStitch<'_>) {
        let WorkspaceCallerStitch {
            caller,
            caller_seg,
            caller_remap,
            data,
            resolver,
            callee_endpoints,
            symbolic_field_forwarding,
            symbolic_funcs,
        } = request;
        let receiver_mutation_start = self.receiver_mutation_sites.len();
        self.pending_field_copy_sites
            .extend(data.descendant_copies.iter().map(|copy| FieldCopySite {
                seg_id: caller_seg,
                func: caller,
                source_base: copy.source_base.clone(),
                target_base: copy.target_base.clone(),
                write_span: copy.span,
                via_span: copy.span,
                precision: Precision::Exact,
                call_kind: CallEdgeKind::Direct,
            }));
        let mut yield_cursor = 0usize;
        for site in &data.call_sites {
            let site_key = (site.site.0.file.raw(), site.site.0.start, site.site.0.end);
            while data.yield_results.get(yield_cursor).is_some_and(|binding| {
                (
                    binding.site.0.file.raw(),
                    binding.site.0.start,
                    binding.site.0.end,
                ) < site_key
            }) {
                yield_cursor = yield_cursor.saturating_add(1);
            }
            let yield_start = yield_cursor;
            while data.yield_results.get(yield_cursor).is_some_and(|binding| {
                (
                    binding.site.0.file.raw(),
                    binding.site.0.start,
                    binding.site.0.end,
                ) == site_key
            }) {
                yield_cursor = yield_cursor.saturating_add(1);
            }
            stitch_call_site(
                CallStitchRequest {
                    caller,
                    caller_seg,
                    caller_remap,
                    site,
                    yield_results: &data.yield_results[yield_start..yield_cursor],
                    caller_params: &data.params,
                    caller_is_constructor: data.is_constructor,
                    caller_receiver_param_index: data.receiver_param_index,
                    caller_implicit_receiver_bases: &data.implicit_receiver_bases,
                    caller_receiver_names: &data.receiver_names,
                    resolver,
                    callee_endpoints,
                },
                CallStitchOutputs {
                    ws,
                    field_arg_sites: &mut self.field_arg_sites,
                    return_field_sites: &mut self.return_field_sites,
                    scalar_return_sites: &mut self.scalar_return_sites,
                    constructor_return_sites: &mut self.constructor_return_sites,
                    receiver_mutation_sites: &mut self.receiver_mutation_sites,
                    passthrough_field_copy_sites: &mut self.pending_field_copy_sites,
                    stats: self.collect_stats.then_some(&mut self.stats),
                },
            );
        }
        if symbolic_field_forwarding {
            flush_symbolic_site_queues(
                &mut self.field_arg_sites,
                &mut self.return_field_sites,
                &mut self.scalar_return_sites,
                &mut self.constructor_return_sites,
                &mut self.symbolic_field_graph,
                symbolic_funcs,
            );
            let mut current_receiver_mutations =
                self.receiver_mutation_sites.split_off(receiver_mutation_start);
            dedup_receiver_mutation_sites(&mut current_receiver_mutations);
            for site in current_receiver_mutations {
                if symbolic_pair_supported(site.callee, site.caller, symbolic_funcs) {
                    push_symbolic_receiver_mutation(&mut self.symbolic_field_graph, &site);
                } else {
                    self.receiver_mutation_sites.push(site);
                }
            }
        }
        self.field_contexts.insert(
            caller,
            FunctionFieldContext {
                receiver_names: data.receiver_names,
                flow_control: data.flow_control,
            },
        );
    }

    fn finish(
        mut self,
        mut ws: IdgWorkspace,
        include_field_argument_forwarding: bool,
        symbolic_field_forwarding: bool,
        symbolic_funcs: Option<&AHashSet<FuncId>>,
    ) -> crate::IdgResult<IdgWorkspace> {
        if !self.field_copy_sites_collected_by_segment {
            self.collect_resident_field_copy_sites(&ws, symbolic_field_forwarding, symbolic_funcs);
        }
        self.flush_symbolic_field_copy_spool()?;
        // Every symbolic transform is interned incrementally while its caller
        // (or field-copy spool chunk) is active. No later phase mutates the
        // canonical dictionaries, so release their hash-consing tables before
        // eager compatibility forwarding opens its own field indexes.
        self.symbolic_field_graph.release_indexes();
        // Spooled symbolic functions were removed segment by segment. Compact
        // the remaining incomplete-adapter contexts before opening the eager
        // field indexes; hash-table capacity is a storage choice, not part of
        // the compiler relation.
        self.field_contexts.shrink_to_fit();
        // Symbolic call-site and copy lowering was the last consumer of the
        // call-stitch normalization memo. Release its owned strings before
        // sealing compatibility queues so this recomputable cache cannot
        // overlap the completed cross-file graph. The field fixed point below
        // lazily rebuilds only the exact paths it actually visits.
        release_storage_normalization_caches();
        self.passthrough_field_copy_sites
            .append(&mut self.pending_field_copy_sites);
        dedup_receiver_mutation_sites(&mut self.receiver_mutation_sites);
        let field_arg_site_count = self.field_arg_sites.len();
        let return_field_site_count = self.return_field_sites.len();
        let scalar_return_site_count = self.scalar_return_sites.len();
        let constructor_return_site_count = self.constructor_return_sites.len();
        let receiver_mutation_site_count = self.receiver_mutation_sites.len();
        let field_arg_sites = std::mem::take(&mut self.field_arg_sites).into_sites();
        let return_field_sites = std::mem::take(&mut self.return_field_sites).into_sites();
        let scalar_return_sites = std::mem::take(&mut self.scalar_return_sites).into_sites();
        let constructor_return_sites = std::mem::take(&mut self.constructor_return_sites).into_sites();
        stitch_debug_log(format_args!(
            "stitch call-sites-wired: {:.3}s field_arg_sites={} return_field_sites={} scalar_return_sites={} constructor_return_sites={} compatibility_field_args={} compatibility_return_fields={} compatibility_scalar_returns={} compatibility_constructor_returns={} receiver_mutation_sites={} symbolic_transforms={} symbolic_bases={} deferred_field_copies={} field_contexts={}",
            self.call_started.elapsed().as_secs_f64(),
            field_arg_site_count,
            return_field_site_count,
            scalar_return_site_count,
            constructor_return_site_count,
            field_arg_sites.len(),
            return_field_sites.len(),
            scalar_return_sites.len(),
            constructor_return_sites.len(),
            receiver_mutation_site_count,
            self.symbolic_field_graph.transform_count(),
            self.symbolic_field_graph.bases().len(),
            self.passthrough_field_copy_sites.len(),
            self.field_contexts.len(),
        ));
        if include_field_argument_forwarding {
            stitch_field_argument_forwarding(
                FieldForwardingSites {
                    field_args: &field_arg_sites,
                    return_fields: &return_field_sites,
                    scalar_returns: &scalar_return_sites,
                    constructor_returns: &constructor_return_sites,
                    receiver_mutations: &self.receiver_mutation_sites,
                    passthrough_copies: &self.passthrough_field_copy_sites,
                },
                &self.field_contexts,
                &mut ws,
                symbolic_field_forwarding,
                symbolic_funcs,
                self.symbolic_field_graph,
            )?;
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
            self.call_started.elapsed().as_secs_f64(),
            self.stats.sites,
            self.stats.resolved_candidates,
            self.stats.callback_lookups,
            self.stats.callback_candidates,
            self.stats.wired_candidates,
            self.stats.inter_edges,
            self.stats.passthrough_edges,
            field_arg_site_count,
            return_field_site_count,
            scalar_return_site_count,
            constructor_return_site_count,
            receiver_mutation_site_count,
            self.stats.resolve_nanos as f64 / 1_000_000_000.0,
            self.stats.callback_nanos as f64 / 1_000_000_000.0
        ));
        release_storage_normalization_caches();
        Ok(ws)
    }
}

/// Stitch lazily lowered segment batches for an in-process query graph.
/// Persistence builds use [`stitch_idg_from_spooled_segment_batches`] so
/// caller IR never accumulates across source-file segments.
pub(crate) fn stitch_idg_from_segment_batches<B, I>(
    batches: B,
    function_count: usize,
    resolver: &dyn CalleeResolver,
    include_field_argument_forwarding: bool,
    symbolic_field_forwarding: bool,
    symbolic_funcs: Option<&AHashSet<FuncId>>,
) -> IdgWorkspace
where
    B: IntoIterator<Item = I>,
    I: IntoIterator<Item = (SegmentId, Vec<TransferOutput>)>,
{
    let mut ws = IdgWorkspace::new();
    let stitch_started = Instant::now();
    // Phase 3a: build each segment from its functions' transfers.
    // Track per-segment `(FuncId, local_node_id) → workspace_node_id`
    // remappings so cross-file edges can resolve their endpoints.
    // For this builder we keep edges keyed on their owning segment's
    // node ids; Phase 5 query layer translates between segments via
    // the `IdgWorkspace`'s segment lookup.
    let mut seg_remaps: AHashMap<FuncId, (SegmentId, NodeRemap)> = AHashMap::with_capacity(function_count);
    let mut stitch_data: AHashMap<FuncId, FunctionStitchData> = AHashMap::with_capacity(function_count);
    let mut callee_endpoints = CalleeEndpointIndex::with_capacity(function_count);
    // Callers emit placeholder segments in ascending order. This preserves
    // stable workspace node ids while allowing each completed compiler batch
    // to be consumed before the next batch is lowered.
    let mut previous_placeholder = None;
    for batch in batches {
        for (seg_id_placeholder, mut sorted_outputs) in batch {
            debug_assert!(
                previous_placeholder.is_none_or(|previous| previous < seg_id_placeholder),
                "segment transfer batches must be strictly ordered"
            );
            previous_placeholder = Some(seg_id_placeholder);
            // Register funcs in stable order too; per-segment node
            // intern order depends on this and feeds into ws_node ids.
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
                let (func, data) = take_function_stitch_data(out);
                stitch_data.insert(func, data);
                local_remaps.push((func, remap));
                segment.record_func(func);
            }
            let ws_id = ws.register_segment(segment);
            let mut segment_funcs = Vec::with_capacity(local_remaps.len());
            for (func, remap) in local_remaps {
                segment_funcs.push(func);
                seg_remaps.insert(func, (ws_id, remap));
            }
            extend_callee_endpoints_for_segment(
                ws_id,
                &segment_funcs,
                &stitch_data,
                &ws,
                &mut callee_endpoints,
                None,
            );
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

    stitch_debug_log(format_args!(
        "stitch endpoint-index: streamed funcs={}",
        callee_endpoints.len()
    ));
    callee_endpoints.finish_build();

    let mut state = WorkspaceStitchState::new(stitch_data.len());
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
        let data = stitch_data
            .remove(&caller)
            .expect("just collected from stitch_data");
        let Some((caller_seg, caller_remap)) = seg_remaps.get(&caller) else {
            continue;
        };
        state.stitch_caller(
            &mut ws,
            WorkspaceCallerStitch {
                caller,
                caller_seg: *caller_seg,
                caller_remap,
                data,
                resolver,
                callee_endpoints: &callee_endpoints,
                symbolic_field_forwarding,
                symbolic_funcs,
            },
        );
        // This caller's transfer-local node ids cannot be referenced after
        // its call sites are stitched. Release the remap while the canonical
        // edge graph is still growing instead of at function return.
        seg_remaps.remove(&caller);
    }
    state
        .finish(
            ws,
            include_field_argument_forwarding,
            symbolic_field_forwarding,
            symbolic_funcs,
        )
        .expect("resident IDG stitching does not perform fallible spill I/O")
}

/// Persistence options for one-pass lowering followed by exact typed replay.
pub(crate) struct SpooledStitchOptions<'a> {
    pub spool_path: &'a std::path::Path,
    pub include_field_argument_forwarding: bool,
    pub symbolic_field_forwarding: bool,
    pub symbolic_funcs: Option<&'a AHashSet<FuncId>>,
    /// Resolver-proven local callable targets that can consume lexical
    /// captures. `None` preserves the general resident-builder contract;
    /// persistence callers provide the exact callgraph-derived target set so
    /// ordinary functions do not retain duplicate bare-read strings.
    pub capture_funcs: Option<&'a AHashSet<FuncId>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StitchFunctionRecord {
    caller: FuncId,
    remap: NodeRemap,
    data: FunctionStitchData,
}

#[derive(Debug, Serialize, Deserialize)]
struct StitchSegmentRecord {
    scheduled_segment: SegmentId,
    functions: Vec<StitchFunctionRecord>,
}

/// Build a persistence graph from one deterministic lowering pass.
///
/// Each file segment is lowered exactly once. The canonical segment is spilled
/// immediately, while its much smaller typed call-stitch object and stable
/// local-to-segment node map are written to a temporary spool. The replay phase
/// hydrates one canonical segment and consumes those facts directly; it never
/// reparses source or reruns transfer lowering. This is a memory-lifetime
/// boundary, not a semantic budget: every scheduled function and closure fact
/// is still processed.
pub(crate) fn stitch_idg_from_spooled_segment_batches<B, I>(
    canonical_batches: B,
    function_count: usize,
    resolver: &dyn CalleeResolver,
    options: SpooledStitchOptions<'_>,
) -> crate::IdgResult<IdgWorkspace>
where
    B: IntoIterator<Item = I>,
    I: IntoIterator<Item = (SegmentId, Vec<TransferOutput>)>,
{
    let SpooledStitchOptions {
        spool_path,
        include_field_argument_forwarding,
        symbolic_field_forwarding,
        symbolic_funcs,
        capture_funcs,
    } = options;
    let started = Instant::now();
    let mut ws = IdgWorkspace::new();
    ws.enable_segment_spool(spool_path)?;
    ws.disable_cross_file_indexes();
    let mut callee_endpoints = CalleeEndpointIndex::with_capacity(function_count);
    let mut schedule_to_workspace: AHashMap<SegmentId, SegmentId> = AHashMap::new();
    let mut stitch_spool = WireChunkSpool::new(spool_path, 1, "IDG stitch object")?;
    let mut previous_placeholder: Option<SegmentId> = None;
    let mut canonical_function_count = 0usize;

    for batch in canonical_batches {
        for (placeholder, mut outputs) in batch {
            if let Some(previous) = previous_placeholder {
                if previous == placeholder {
                    return Err(crate::IdgError::Invariant(format!(
                        "canonical segment schedule repeated segment {}",
                        placeholder.0
                    )));
                }
                if previous > placeholder {
                    return Err(crate::IdgError::Invariant(format!(
                        "canonical segment schedule is not strictly ordered: segment {} followed segment {}",
                        placeholder.0, previous.0
                    )));
                }
            }
            previous_placeholder = Some(placeholder);
            outputs.sort_by_key(|out| out.func.raw());
            let place_capacity = outputs.iter().map(|out| out.places.len()).sum();
            let node_capacity = outputs.iter().map(|out| out.nodes.len()).sum();
            let edge_capacity = outputs.iter().map(|out| out.edges.len()).sum();
            let mut segment = IdgSegment::with_capacity(place_capacity, node_capacity, edge_capacity);
            let mut data_by_func = AHashMap::with_capacity(outputs.len());
            let mut remap_by_func = AHashMap::with_capacity(outputs.len());
            let mut segment_funcs = Vec::with_capacity(outputs.len());
            for out in outputs {
                let remap = merge_transfer_into_segment(&mut segment, &out);
                let (func, data) = take_function_stitch_data(out);
                segment.record_func(func);
                segment_funcs.push(func);
                data_by_func.insert(func, data);
                remap_by_func.insert(func, remap);
            }
            canonical_function_count = canonical_function_count.saturating_add(segment_funcs.len());
            let segment_id = ws.register_segment(segment);
            if schedule_to_workspace.insert(placeholder, segment_id).is_some() {
                return Err(crate::IdgError::Invariant(format!(
                    "canonical segment schedule repeated segment {}",
                    placeholder.0
                )));
            }
            extend_callee_endpoints_for_segment(
                segment_id,
                &segment_funcs,
                &data_by_func,
                &ws,
                &mut callee_endpoints,
                capture_funcs,
            );
            let functions = segment_funcs
                .iter()
                .copied()
                .map(|caller| {
                    let remap = remap_by_func.remove(&caller).ok_or_else(|| {
                        crate::IdgError::Invariant(format!(
                            "canonical function {} is missing its node remap",
                            caller.raw()
                        ))
                    })?;
                    let data = data_by_func.remove(&caller).ok_or_else(|| {
                        crate::IdgError::Invariant(format!(
                            "canonical function {} is missing its stitch data",
                            caller.raw()
                        ))
                    })?;
                    Ok(StitchFunctionRecord { caller, remap, data })
                })
                .collect::<crate::IdgResult<Vec<_>>>()?;
            stitch_spool.push(StitchSegmentRecord {
                scheduled_segment: placeholder,
                functions,
            });
            if let Some(segment) = ws.segment_mut(segment_id) {
                segment.release_build_lookups();
            }
            ws.spill_segment(segment_id)?;
        }
    }
    if canonical_function_count != function_count {
        return Err(crate::IdgError::Invariant(format!(
            "canonical lowering covered {canonical_function_count} functions, expected {function_count}"
        )));
    }
    stitch_spool.check_error()?;
    callee_endpoints.finish_build();
    stitch_debug_log(format_args!(
        "stitch canonical-pass: {:.3}s segments={} funcs={} endpoints={}",
        started.elapsed().as_secs_f64(),
        ws.segment_count(),
        canonical_function_count,
        callee_endpoints.len()
    ));

    let stitch_started = Instant::now();
    let mut state = WorkspaceStitchState::for_spooled_persistence(spool_path)?;
    let mut stitched_function_count = 0usize;
    let mut previous_placeholder = None;
    ws.begin_spool_generation()?;
    stitch_spool.into_visit(|batches| {
        for batch in batches {
            let scheduled_segment = batch.scheduled_segment;
            debug_assert!(
                previous_placeholder.is_none_or(|previous| previous < scheduled_segment),
                "stitch object segments must be strictly ordered"
            );
            previous_placeholder = Some(scheduled_segment);
            let segment_id = schedule_to_workspace
                .get(&scheduled_segment)
                .copied()
                .ok_or_else(|| {
                    crate::IdgError::Invariant(format!(
                        "stitch pass referenced unscheduled segment {}",
                        scheduled_segment.0
                    ))
                })?;
            ws.hydrate_segment(segment_id)?;
            let Some(segment) = ws.segment_mut(segment_id) else {
                return Err(crate::IdgError::Invariant(format!(
                    "stitch object referenced missing segment {}",
                    segment_id.0
                )));
            };
            segment.rebuild_build_lookups();
            for record in batch.functions {
                let StitchFunctionRecord { caller, remap, data } = record;
                if ws.segment_for_func(caller) != Some(segment_id) {
                    return Err(crate::IdgError::Invariant(format!(
                        "stitch caller {} moved outside canonical segment {}",
                        caller.raw(),
                        segment_id.0
                    )));
                }
                state.stitch_caller(
                    &mut ws,
                    WorkspaceCallerStitch {
                        caller,
                        caller_seg: segment_id,
                        caller_remap: &remap,
                        data,
                        resolver,
                        callee_endpoints: &callee_endpoints,
                        symbolic_field_forwarding,
                        symbolic_funcs,
                    },
                );
                stitched_function_count = stitched_function_count.saturating_add(1);
            }
            if let Some(segment) = ws.segment_mut(segment_id) {
                segment.release_build_lookups();
            }
            state.collect_active_segment_field_copy_sites(
                segment_id,
                &ws,
                symbolic_field_forwarding,
                symbolic_funcs,
            );
            ws.spill_segment(segment_id)?;
            ws.check_cross_file_spool()?;
            state.check_symbolic_spool()?;
        }
        Ok(())
    })?;
    if stitched_function_count != function_count {
        return Err(crate::IdgError::Invariant(format!(
            "stitch replay covered {stitched_function_count} functions, expected {function_count}"
        )));
    }
    ws.finish_spool_generation()?;
    // Call stitching is complete. Endpoint vectors include parameter names,
    // capture nodes, returns, throws, and receiver writes for every function;
    // field closure consumes only the already-emitted relations. Release this
    // compiler phase before streaming those relations so the two workspace-
    // scale lifetimes never overlap.
    drop(callee_endpoints);
    drop(schedule_to_workspace);
    stitch_debug_log(format_args!(
        "stitch typed-replay: {:.3}s segments={} funcs={}",
        stitch_started.elapsed().as_secs_f64(),
        ws.segment_count(),
        stitched_function_count
    ));
    state.finish(
        ws,
        include_field_argument_forwarding,
        symbolic_field_forwarding,
        symbolic_funcs,
    )
}

fn extend_callee_endpoints_for_segment(
    segment_id: SegmentId,
    funcs: &[FuncId],
    stitch_data: &AHashMap<FuncId, FunctionStitchData>,
    ws: &IdgWorkspace,
    out: &mut CalleeEndpointIndex,
    capture_funcs: Option<&AHashSet<FuncId>>,
) {
    let Some(segment) = ws.segment(segment_id) else {
        return;
    };
    let yielded_nodes = collect_yield_value_nodes(segment);
    let returned_nodes = collect_return_value_nodes(segment);
    for &func in funcs {
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
        let capture_read_nodes = if capture_funcs.is_none_or(|targets| targets.contains(&func)) {
            collect_unrooted_scalar_reads(segment, func)
        } else {
            Vec::new()
        };
        out.insert(
            func,
            CalleeEndpointInput {
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
                yield_node,
            },
        );
    }
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
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
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
    let remap = remap_transfer_into_segment(segment, out);
    // Append remapped intra-procedural edges on the canonical lowering pass.
    // Persistence builds spool the returned remap with typed call-site IR and
    // replay it directly, so these edges are never produced twice.
    for edge in &out.edges {
        segment.add_edge(IdgEdge {
            from: remap.get(edge.from),
            to: remap.get(edge.to),
            meta: edge.meta,
        });
    }
    remap
}

/// Map a function-local transfer into a segment dictionary. The returned map
/// is stable for the canonical segment and can be replayed without lowering
/// the function again.
fn remap_transfer_into_segment(segment: &mut IdgSegment, out: &TransferOutput) -> NodeRemap {
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
struct CallStitchRequest<'a> {
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &'a NodeRemap,
    site: &'a CallSiteRef,
    yield_results: &'a [YieldResultRef],
    caller_params: &'a [String],
    caller_is_constructor: bool,
    caller_receiver_param_index: Option<usize>,
    caller_implicit_receiver_bases: &'a [String],
    caller_receiver_names: &'a [String],
    resolver: &'a dyn CalleeResolver,
    callee_endpoints: &'a CalleeEndpointIndex,
}

struct CallStitchOutputs<'a> {
    ws: &'a mut IdgWorkspace,
    field_arg_sites: &'a mut FieldArgSiteQueue,
    return_field_sites: &'a mut ReturnFieldSiteQueue,
    scalar_return_sites: &'a mut ScalarReturnSiteQueue,
    constructor_return_sites: &'a mut ConstructorReturnSiteQueue,
    receiver_mutation_sites: &'a mut Vec<Arc<ReceiverMutationStitch>>,
    passthrough_field_copy_sites: &'a mut Vec<FieldCopySite>,
    stats: Option<&'a mut StitchStats>,
}

fn stitch_call_site(request: CallStitchRequest<'_>, outputs: CallStitchOutputs<'_>) {
    let CallStitchRequest {
        caller,
        caller_seg,
        caller_remap,
        site,
        yield_results,
        caller_params,
        caller_is_constructor,
        caller_receiver_param_index,
        caller_implicit_receiver_bases,
        caller_receiver_names,
        resolver,
        callee_endpoints,
    } = request;
    let CallStitchOutputs {
        ws,
        field_arg_sites,
        return_field_sites,
        scalar_return_sites,
        constructor_return_sites,
        receiver_mutation_sites,
        passthrough_field_copy_sites,
        mut stats,
    } = outputs;
    let caller_receiver = CallerReceiverContext {
        params: caller_params,
        receiver_param_index: caller_receiver_param_index,
        implicit_receiver_bases: caller_implicit_receiver_bases,
        receiver_names: caller_receiver_names,
    };
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
    // Callback-binding resolution consumes the adapter-emitted call
    // identity directly. A free invocation names the bound parameter as its
    // callee; a receiver-form invocation carries that parameter in
    // `receiver`. Language syntax such as sigils or invocation punctuation
    // must be represented consistently by the owning Tree-sitter adapter,
    // never reinterpreted here.
    // Merge the callgraph's proven parameter bindings into the ordinary
    // candidate set so both forms surface the cross-call edge.
    let callback_param_idx: Option<u32> =
        if let Some(recv) = site.receiver.as_deref().filter(|r| !r.is_empty()) {
            caller_params
                .iter()
                .position(|param| param == recv)
                .and_then(|i| u32::try_from(i).ok())
        } else {
            caller_params
                .iter()
                .position(|param| param == &site.callee_name)
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
        .any(|candidate| callee_endpoints.contains_key(candidate.func));
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
    // The adapter may prove that an inline closure parameter receives this
    // call's yielded value even when the callee is external. In that case the
    // only compiler-proven inputs available to the yield are the explicit
    // arguments and method receiver. Preserve those inputs at narrowed
    // precision instead of silently dropping the adapter's `YieldResult`
    // fact. This is deliberately independent of language and API spelling;
    // adapters decide which syntax establishes a yield binding.
    if !has_stitchable_candidate && !yield_results.is_empty() {
        let mut yield_inputs = site
            .call_arg_nodes
            .iter()
            .take(site.explicit_args_count as usize)
            .copied()
            .chain(site.receiver_arg_node)
            .map(|node| caller_remap.get(node))
            .filter(|node| !node.is_sentinel())
            .collect::<Vec<_>>();
        yield_inputs.sort_unstable();
        yield_inputs.dedup();

        for binding in yield_results {
            let target = caller_remap.get(binding.target_node);
            if target.is_sentinel() {
                continue;
            }
            for &input in &yield_inputs {
                place_inter_edge(
                    caller_seg,
                    caller_seg,
                    IdgEdge {
                        from: input,
                        to: target,
                        meta: crate::edge::EdgeMeta {
                            precision: bonsai_common::Precision::Narrowed,
                            kind: crate::edge::IdgEdgeKind::IntraYield,
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
    for candidate in &candidates {
        let Some(endpoints) = callee_endpoints.get(candidate.func) else {
            continue;
        };
        stitch_resolved_candidate(
            ResolvedCandidateStitch {
                caller,
                caller_seg,
                caller_remap,
                site,
                yield_results,
                caller_params,
                caller_is_constructor,
                caller_receiver_param_index,
                caller_implicit_receiver_bases,
                caller_receiver_names,
                caller_receiver: &caller_receiver,
                resolver,
                candidate,
                endpoints,
            },
            ResolvedCandidateOutputs {
                ws: &mut *ws,
                field_arg_sites: &mut *field_arg_sites,
                return_field_sites: &mut *return_field_sites,
                scalar_return_sites: &mut *scalar_return_sites,
                constructor_return_sites: &mut *constructor_return_sites,
                receiver_mutation_sites: &mut *receiver_mutation_sites,
                passthrough_field_copy_sites: &mut *passthrough_field_copy_sites,
                stats: stats.as_deref_mut(),
            },
        );
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

#[derive(Clone, Copy)]
struct ResolvedCandidateStitch<'a> {
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &'a NodeRemap,
    site: &'a CallSiteRef,
    yield_results: &'a [YieldResultRef],
    caller_params: &'a [String],
    caller_is_constructor: bool,
    caller_receiver_param_index: Option<usize>,
    caller_implicit_receiver_bases: &'a [String],
    caller_receiver_names: &'a [String],
    caller_receiver: &'a CallerReceiverContext<'a>,
    resolver: &'a dyn CalleeResolver,
    candidate: &'a ResolvedCallee,
    endpoints: CalleeEndpointView<'a>,
}

struct ResolvedCandidateOutputs<'a> {
    ws: &'a mut IdgWorkspace,
    field_arg_sites: &'a mut FieldArgSiteQueue,
    return_field_sites: &'a mut ReturnFieldSiteQueue,
    scalar_return_sites: &'a mut ScalarReturnSiteQueue,
    constructor_return_sites: &'a mut ConstructorReturnSiteQueue,
    receiver_mutation_sites: &'a mut Vec<Arc<ReceiverMutationStitch>>,
    passthrough_field_copy_sites: &'a mut Vec<FieldCopySite>,
    stats: Option<&'a mut StitchStats>,
}

fn stitch_resolved_candidate(request: ResolvedCandidateStitch<'_>, outputs: ResolvedCandidateOutputs<'_>) {
    let ResolvedCandidateStitch {
        caller,
        resolver,
        candidate: cand,
        ..
    } = request;
    let ResolvedCandidateOutputs {
        ws,
        field_arg_sites,
        return_field_sites,
        scalar_return_sites,
        constructor_return_sites,
        receiver_mutation_sites,
        passthrough_field_copy_sites,
        mut stats,
    } = outputs;
    if let Some(stats) = &mut stats {
        stats.wired_candidates = stats.wired_candidates.saturating_add(1);
    }
    let is_ancestor_dispatch = resolver.is_ancestor_dispatch(caller, cand.func);
    stitch_candidate_receiver_inputs(request, is_ancestor_dispatch, ws, field_arg_sites, &mut stats);
    stitch_candidate_explicit_arguments(request, ws, field_arg_sites, &mut stats);
    stitch_candidate_capture_inputs(request, ws, &mut stats);
    stitch_candidate_return_outputs(
        request,
        ws,
        return_field_sites,
        scalar_return_sites,
        passthrough_field_copy_sites,
        &mut stats,
    );
    stitch_candidate_constructor_receiver_effects(request, is_ancestor_dispatch, receiver_mutation_sites);
    stitch_candidate_constructor_result(request, ws, constructor_return_sites);
}

fn stitch_candidate_receiver_inputs(
    request: ResolvedCandidateStitch<'_>,
    is_ancestor_dispatch: bool,
    ws: &mut IdgWorkspace,
    field_arg_sites: &mut FieldArgSiteQueue,
    stats: &mut Option<&mut StitchStats>,
) {
    let ResolvedCandidateStitch {
        caller,
        caller_seg,
        caller_remap,
        site,
        caller_implicit_receiver_bases,
        caller_receiver_names,
        caller_receiver,
        resolver,
        candidate: cand,
        endpoints,
        ..
    } = request;
    // For method receivers, emit the synthetic receiver slot to
    // the callee's adapter-declared receiver parameter. This is
    // separate from positional args so explicit arguments keep
    // their source-language order.
    if matches!(site.call_kind, CallKind::Method) {
        if let (Some(receiver_arg_node), Some(receiver_idx)) =
            (site.receiver_arg_node, endpoints.receiver_param_index())
        {
            if let Some(&callee_param_node) = endpoints.params().get(receiver_idx) {
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
                        if let Some(stats) = stats.as_deref_mut() {
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
                endpoints.param_name(receiver_idx),
            ) {
                let actual_receiver = receiver_field_forwarding_base(
                    site,
                    receiver,
                    caller_receiver,
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
                        Some(receiver_type.as_str()),
                    );
                }
            }
        }
        if endpoints.receiver_param_index().is_none() && !endpoints.receiver_consumer_nodes().is_empty() {
            if let Some(receiver_arg_node) = site.receiver_arg_node {
                let caller_call_arg = caller_remap.get(receiver_arg_node);
                if !caller_call_arg.is_sentinel() {
                    for &callee_receiver_consumer in endpoints.receiver_consumer_nodes() {
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
                        if let Some(stats) = stats.as_deref_mut() {
                            stats.inter_edges = stats.inter_edges.saturating_add(1);
                        }
                    }
                }
            }
        }
        if endpoints.receiver_param_index().is_none()
            && (endpoints.implicit_receiver_bases().next().is_some()
                || endpoints.receiver_field_bases().next().is_some()
                || endpoints.return_field_projections().next().is_some())
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
                    caller_receiver,
                    is_ancestor_dispatch,
                    true,
                );
                let projection_bases = return_projection_bases(endpoints);
                let mut seen = AHashSet::new();
                for param_name in endpoints
                    .implicit_receiver_bases()
                    .chain(endpoints.receiver_field_bases())
                    .chain(projection_bases.iter().map(String::as_str))
                {
                    let param_name = param_name.trim();
                    if param_name.is_empty() {
                        continue;
                    }
                    if let Some(receiver_root) =
                        receiver_root_if_declared_names(param_name, endpoints.receiver_names())
                    {
                        // Parameter-less methods and synthesized property
                        // accessors still consume an object receiver. Map the
                        // caller's exact receiver root onto the adapter's
                        // declared receiver root, then let ordinary field
                        // forwarding preserve the remaining access path. For
                        // `value.cmd -> self.cmd`, using `value.cmd` itself as
                        // the source base would incorrectly ask for a deeper
                        // suffix and strand the scalar field.
                        if seen.insert((actual_receiver.clone(), receiver_root.to_string())) {
                            push_receiver_field_arg_site(
                                field_arg_sites,
                                caller,
                                caller_seg,
                                cand.func,
                                endpoints.segment,
                                &actual_receiver,
                                receiver_root,
                                site.site.0,
                                cand.precision,
                                cand.edge_kind,
                                None,
                            );
                            push_nested_receiver_field_arg_sites(
                                field_arg_sites,
                                caller,
                                caller_seg,
                                cand.func,
                                endpoints.segment,
                                &actual_receiver,
                                receiver_root,
                                endpoints,
                                site.site.0,
                                cand.precision,
                                cand.edge_kind,
                            );
                        }
                        continue;
                    }
                    let actual_base = format!("{}.{}", actual_receiver.trim(), param_name);
                    if !seen.insert((actual_base.clone(), param_name.to_string())) {
                        continue;
                    }
                    push_receiver_field_arg_site(
                        field_arg_sites,
                        caller,
                        caller_seg,
                        cand.func,
                        endpoints.segment,
                        &actual_base,
                        param_name,
                        site.site.0,
                        cand.precision,
                        cand.edge_kind,
                        None,
                    );
                }
            }
        }
    }
    if site.receiver.is_none()
        && endpoints.receiver_param_index().is_none()
        && (endpoints.implicit_receiver_bases().next().is_some()
            || endpoints.receiver_field_bases().next().is_some()
            || endpoints.return_field_projections().next().is_some())
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
}

fn stitch_candidate_explicit_arguments(
    request: ResolvedCandidateStitch<'_>,
    ws: &mut IdgWorkspace,
    field_arg_sites: &mut FieldArgSiteQueue,
    stats: &mut Option<&mut StitchStats>,
) {
    let ResolvedCandidateStitch {
        caller,
        caller_seg,
        caller_remap,
        site,
        candidate: cand,
        endpoints,
        ..
    } = request;
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
                name.as_deref()
                    .and_then(|name| named_arg_param_index(name, endpoints, endpoints.receiver_param_index()))
            })
            .unwrap_or_else(|| explicit_arg_param_index(i, endpoints.receiver_param_index()));
        let Some(&callee_param_node) = endpoints.params().get(callee_param_idx) else {
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
            endpoints.param_name(callee_param_idx),
        ) {
            if !actual_arg.trim().is_empty() && !param_name.trim().is_empty() {
                field_arg_sites.push(FieldArgStitch {
                    caller,
                    caller_seg,
                    callee: cand.func,
                    callee_seg: endpoints.segment,
                    actual_arg: actual_arg.trim().to_string(),
                    param_name: param_name.trim().to_string(),
                    call_span: site.site.0,
                    precision: cand.precision,
                    call_kind: cand.edge_kind,
                    arg_idx: u32::try_from(i).expect("call argument index exceeds u32"),
                    param_idx: u32::try_from(callee_param_idx).expect("callee parameter index exceeds u32"),
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
                endpoints.param_write_nodes(callee_param_idx),
                target_base,
                site.site.0,
                cand.precision,
                cand.edge_kind,
                ws,
            );
            if let Some(stats) = stats.as_deref_mut() {
                stats.inter_edges = stats.inter_edges.saturating_add(added);
            }
        }
        if let Some(stats) = stats.as_deref_mut() {
            stats.inter_edges = stats.inter_edges.saturating_add(1);
        }
    }
}

fn stitch_candidate_capture_inputs(
    request: ResolvedCandidateStitch<'_>,
    ws: &mut IdgWorkspace,
    stats: &mut Option<&mut StitchStats>,
) {
    let ResolvedCandidateStitch {
        caller,
        caller_seg,
        site,
        resolver,
        candidate: cand,
        endpoints,
        ..
    } = request;
    if resolver.is_local_callable_binding(caller, cand.func) {
        let added = stitch_lexical_capture_reads(
            caller,
            caller_seg,
            endpoints.segment,
            endpoints,
            site.site.0,
            cand.precision,
            cand.edge_kind,
            ws,
        );
        if let Some(stats) = stats.as_deref_mut() {
            stats.inter_edges = stats.inter_edges.saturating_add(added);
        }
    }
}

fn stitch_candidate_return_outputs(
    request: ResolvedCandidateStitch<'_>,
    ws: &mut IdgWorkspace,
    return_field_sites: &mut ReturnFieldSiteQueue,
    scalar_return_sites: &mut ScalarReturnSiteQueue,
    passthrough_field_copy_sites: &mut Vec<FieldCopySite>,
    stats: &mut Option<&mut StitchStats>,
) {
    let ResolvedCandidateStitch {
        caller,
        caller_seg,
        caller_remap,
        site,
        yield_results,
        candidate: cand,
        endpoints,
        ..
    } = request;
    // A call may expose both a normal return and yielded values (Ruby block
    // calls are the canonical example). Keep the endpoints independent:
    // only the callee's AST-lowered Yield place can populate block/generator
    // bindings recorded at this call site.
    if let Some(callee_yield) = endpoints.yield_node() {
        for binding in yield_results {
            let target = caller_remap.get(binding.target_node);
            if target.is_sentinel() {
                continue;
            }
            place_inter_edge(
                endpoints.segment,
                caller_seg,
                IdgEdge::inter_yield(callee_yield, target, site.site.0, cand.precision, cand.edge_kind),
                ws,
            );
            return_field_sites.push(ReturnFieldStitch {
                caller,
                caller_seg,
                callee: cand.func,
                callee_seg: endpoints.segment,
                source_base: crate::transfer::YIELD_FIELD_BASE.to_string(),
                target_base: binding.target_base.clone(),
                call_span: site.site.0,
                write_span: binding.write_span,
                precision: cand.precision,
                call_kind: cand.edge_kind,
            });
            if let Some(stats) = stats.as_deref_mut() {
                stats.inter_edges = stats.inter_edges.saturating_add(1);
            }
        }
    }
    // Emit `callee.Return → caller.CallRet(site)`.
    let caller_call_ret = caller_remap.get(site.call_ret_node);
    if let Some(callee_return) = endpoints.return_node() {
        if !caller_call_ret.is_sentinel() {
            let edge = IdgEdge::inter_return(
                callee_return,
                caller_call_ret,
                site.site.0,
                cand.precision,
                cand.edge_kind,
            );
            place_inter_edge(endpoints.segment, caller_seg, edge, ws);
            if let Some(stats) = stats.as_deref_mut() {
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
            for param_idx in endpoints.return_passthrough_param_indices() {
                let explicit_arg_idx = match endpoints.receiver_param_index() {
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
                for projection in endpoints.return_field_projections() {
                    scalar_return_sites.push(ScalarReturnStitch {
                        caller,
                        caller_seg,
                        callee: cand.func,
                        callee_seg: endpoints.segment,
                        source_base: projection.base.to_string(),
                        source_field: projection.field.to_string(),
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
}

fn stitch_candidate_constructor_receiver_effects(
    request: ResolvedCandidateStitch<'_>,
    is_ancestor_dispatch: bool,
    receiver_mutation_sites: &mut Vec<Arc<ReceiverMutationStitch>>,
) {
    let ResolvedCandidateStitch {
        caller,
        caller_seg,
        site,
        caller_params,
        caller_is_constructor,
        caller_receiver_param_index,
        caller_implicit_receiver_bases,
        caller_receiver_names,
        resolver,
        candidate: cand,
        endpoints,
        ..
    } = request;
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
                let projected_target_base =
                    projected_receiver_target_base(&target_base, &callee_receiver_param_name);
                receiver_mutation_sites.push(Arc::new(ReceiverMutationStitch {
                    caller,
                    caller_seg,
                    callee: cand.func,
                    callee_seg: endpoints.segment,
                    target_base: projected_target_base,
                    callee_receiver_param_name,
                    call_span: site.site.0,
                    precision: cand.precision,
                    call_kind: cand.edge_kind,
                }));
            }
        }
    }
}

fn stitch_candidate_constructor_result(
    request: ResolvedCandidateStitch<'_>,
    ws: &mut IdgWorkspace,
    constructor_return_sites: &mut ConstructorReturnSiteQueue,
) {
    let ResolvedCandidateStitch {
        caller,
        caller_seg,
        caller_remap,
        site,
        resolver,
        candidate: cand,
        endpoints,
        ..
    } = request;
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
                        let target_base = projected_receiver_target_base(&target_base, receiver_param_name);
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

fn call_site_is_constructor(site: &crate::transfer::CallSiteRef) -> bool {
    matches!(site.call_kind, CallKind::Constructor)
}

#[allow(clippy::too_many_arguments)] // Capture edges retain the resolved call's full precision metadata.
fn stitch_lexical_capture_reads(
    caller: FuncId,
    caller_seg: SegmentId,
    callee_seg: SegmentId,
    endpoints: CalleeEndpointView<'_>,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    ws: &mut IdgWorkspace,
) -> usize {
    let mut added = 0usize;
    for (capture_name, capture_read) in endpoints.capture_reads() {
        for source in scalar_producers_live_at_span(ws, caller_seg, caller, capture_name, call_span) {
            place_inter_edge(
                caller_seg,
                callee_seg,
                IdgEdge {
                    from: source,
                    to: capture_read,
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
        // Aggregate markers carry field-demand intent only. They are
        // deliberately non-traversable and cannot prove a scalar post-call
        // consumer for mutable write-back stitching.
        .filter(|edge| edge.meta.kind != crate::edge::IdgEdgeKind::IntraAggregateConsume)
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
    callee_endpoints: &CalleeEndpointIndex,
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
            let Some(endpoints) = callee_endpoints.get(cand.func) else {
                continue;
            };
            for &source_param_index in &shape.source_param_indices {
                let callee_param_idx =
                    explicit_arg_param_index(source_param_index, endpoints.receiver_param_index());
                let Some(&callee_param_node) = endpoints.params().get(callee_param_idx) else {
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
/// its first parameter. Only indirect callgraph evidence contained by an
/// explicit source argument proves that the argument is callable. Textual
/// name lookup is reserved for rulepack-declared callback positions; using it
/// here would reinterpret an ordinary value such as `text` as any same-named
/// method in the workspace. For a method call the receiver is also a data
/// operand; for a free call every non-callback source-level argument is a
/// candidate input.
#[allow(clippy::too_many_arguments)]
fn stitch_indirect_callback_inputs(
    caller: FuncId,
    caller_seg: SegmentId,
    caller_remap: &NodeRemap,
    site: &CallSiteRef,
    resolver: &dyn CalleeResolver,
    callee_endpoints: &CalleeEndpointIndex,
    ws: &mut IdgWorkspace,
) -> usize {
    let mut callback_arg_indices = AHashSet::new();
    let mut callback_candidates = Vec::new();
    let mut seen_candidates = AHashSet::new();
    for idx in 0..site.explicit_args_count as usize {
        let resolved = site
            .call_arg_spans
            .get(idx)
            .into_iter()
            .flat_map(|arg_span| resolver.callable_args_in_span(caller, *arg_span))
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            continue;
        }
        callback_arg_indices.insert(idx);
        for cand in resolved {
            if cand.edge_kind == bonsai_callgraph::EdgeKind::Indirect
                && callee_endpoints.contains_key(cand.func)
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
        let Some(endpoints) = callee_endpoints.get(cand.func) else {
            continue;
        };
        let callback_param_idx = explicit_arg_param_index(0, endpoints.receiver_param_index());
        let Some(&callee_param_node) = endpoints.params().get(callback_param_idx) else {
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

fn constructor_receiver_bases(endpoints: CalleeEndpointView<'_>) -> Vec<String> {
    let mut out: Vec<String> = endpoints
        .receiver_param_index()
        .and_then(|idx| endpoints.param_name(idx).map(str::to_string))
        .into_iter()
        .collect();
    for base in endpoints
        .receiver_field_bases()
        .chain(endpoints.implicit_receiver_bases())
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
    if endpoints.receiver_param_index().is_none() {
        if let Some(receiver) = endpoints
            .receiver_names()
            .next()
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
    // Ancestor dispatch changes method lookup, not object identity. Both an
    // explicit ancestor qualifier and an inherited method reached through the
    // current receiver operate on the same current object. Canonicalize to the
    // adapter-declared primary receiver before selecting storage; otherwise a
    // call such as `current.inherited_method()` can move state onto the
    // ancestor token and strand exact fields that remain on `current`.
    let receiver = if is_ancestor_dispatch {
        caller_receiver_names
            .first()
            .map(String::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(receiver)
    } else {
        receiver
    };
    let matches_requested_receiver = |base: &&String| {
        receiver_root_if_declared(base, caller_receiver_names)
            .is_some_and(|root| receiver_tokens_equal(root, receiver))
    };
    let declared_bases = caller_implicit_receiver_bases
        .iter()
        .filter(|base| receiver_root_if_declared(base, caller_receiver_names).is_some());
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

fn receiver_field_forwarding_base(
    site: &CallSiteRef,
    receiver: &str,
    caller: &CallerReceiverContext<'_>,
    is_ancestor_dispatch: bool,
    allow_implicit_receiver_rewrite: bool,
) -> String {
    if let Some(base) = site.receiver_storage_base.as_deref() {
        return base.to_string();
    }
    if allow_implicit_receiver_rewrite {
        return implicit_receiver_actual_base(receiver, caller, is_ancestor_dispatch);
    }
    receiver.trim().to_string()
}

fn implicit_receiver_actual_base(
    receiver: &str,
    caller: &CallerReceiverContext<'_>,
    is_ancestor_dispatch: bool,
) -> String {
    let trimmed = receiver.trim();
    if receiver_name_matches(trimmed, caller.receiver_names) {
        if let Some(param) = caller
            .receiver_param_index
            .and_then(|idx| caller.params.get(idx))
            .map(String::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            return param.to_string();
        }
        if let Some(base) = constructor_implicit_receiver_base(
            trimmed,
            caller.implicit_receiver_bases,
            caller.receiver_names,
            is_ancestor_dispatch,
        ) {
            return base;
        }
    }
    trimmed.to_string()
}

struct CallerReceiverContext<'a> {
    params: &'a [String],
    receiver_param_index: Option<usize>,
    implicit_receiver_bases: &'a [String],
    receiver_names: &'a [String],
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
        actual_arg,
        param_name: param_name.trim().to_string(),
        call_span,
        precision,
        call_kind,
        arg_idx: u32::MAX,
        param_idx: u32::MAX,
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
    endpoints: CalleeEndpointView<'_>,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
) {
    let projection_bases = return_projection_bases(endpoints);
    let nested_bases = endpoints
        .receiver_field_bases()
        .chain(endpoints.implicit_receiver_bases())
        .chain(projection_bases.iter().map(String::as_str));
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
            actual_arg: actual_nested_base,
            param_name: nested_param_base.to_string(),
            call_span,
            precision,
            call_kind,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
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
    endpoints: CalleeEndpointView<'_>,
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
        .receiver_field_bases()
        .chain(endpoints.implicit_receiver_bases())
        .chain(projection_bases.iter().map(String::as_str));
    let mut seen = AHashSet::new();
    for nested_param_base in nested_bases {
        let nested_param_base = nested_param_base.trim();
        if nested_param_base.is_empty() {
            continue;
        }
        for root in &roots {
            let actual_arg = implicit_member_actual_base(root, nested_param_base, endpoints.receiver_names());
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
                param_name: nested_param_base.to_string(),
                call_span,
                precision,
                call_kind,
                arg_idx: u32::MAX,
                param_idx: u32::MAX,
                allow_out_of_order_source: true,
            });
        }
    }
}

fn return_projection_bases(endpoints: CalleeEndpointView<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for projection in endpoints.return_field_projections() {
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

fn implicit_member_actual_base<'a>(
    root: &str,
    nested_param_base: &str,
    receiver_names: impl IntoIterator<Item = &'a str>,
) -> String {
    if receiver_root_if_declared_names(nested_param_base, receiver_names).is_some() {
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
    receiver_root_if_declared_names(receiver_base, receiver_names.iter().map(String::as_str))
}

fn receiver_root_if_declared_names<'a, 'b>(
    receiver_base: &'a str,
    receiver_names: impl IntoIterator<Item = &'b str>,
) -> Option<&'a str> {
    let root = receiver_base
        .trim()
        .split('.')
        .find(|part| !part.trim().is_empty())?
        .trim();
    receiver_names
        .into_iter()
        .any(|name| receiver_tokens_equal(root, name))
        .then_some(root)
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
    endpoints: CalleeEndpointView<'_>,
    receiver_param_index: Option<usize>,
) -> Option<usize> {
    let arg_name = arg_name.trim();
    if arg_name.is_empty() {
        return None;
    }
    endpoints
        .param_names()
        .enumerate()
        .find(|(idx, param)| Some(*idx) != receiver_param_index && param.trim() == arg_name)
        .map(|(idx, _)| idx)
}

fn symbolic_pair_supported(
    source: FuncId,
    target: FuncId,
    symbolic_funcs: Option<&AHashSet<FuncId>>,
) -> bool {
    symbolic_funcs.is_none_or(|funcs| funcs.contains(&source) && funcs.contains(&target))
}

fn flush_symbolic_site_queues(
    field_args: &mut FieldArgSiteQueue,
    return_fields: &mut ReturnFieldSiteQueue,
    scalar_returns: &mut ScalarReturnSiteQueue,
    constructor_returns: &mut ConstructorReturnSiteQueue,
    graph: &mut SymbolicFieldCompilerStorage,
    symbolic_funcs: Option<&AHashSet<FuncId>>,
) {
    for site in field_args.take_current_sites() {
        if !symbolic_pair_supported(site.caller, site.callee, symbolic_funcs) {
            field_args.defer(site);
            continue;
        }
        let source_base = normalize_storage_base(&site.actual_arg);
        let source = graph.intern_base(site.caller_seg, site.caller, &source_base);
        let target = graph.intern_base(site.callee_seg, site.callee, &site.param_name);
        graph.push_transform(SymbolicFieldTransform {
            source,
            target,
            exact_field: NO_SYMBOLIC_STRING,
            call_span: site.call_span,
            write_span: site.call_span,
            precision: site.precision,
            call_kind: site.call_kind,
            kind: SymbolicFieldTransformKind::Argument,
            arg_idx: site.arg_idx,
            param_idx: site.param_idx,
            allow_out_of_order_source: site.allow_out_of_order_source,
        });
    }
    for site in return_fields.take_current_sites() {
        if !symbolic_pair_supported(site.callee, site.caller, symbolic_funcs) {
            return_fields.defer(site);
            continue;
        }
        let source_base = normalize_storage_base(&site.source_base);
        let source = graph.intern_base(site.callee_seg, site.callee, &source_base);
        let target = graph.intern_base(site.caller_seg, site.caller, &site.target_base);
        graph.push_transform(SymbolicFieldTransform {
            source,
            target,
            exact_field: NO_SYMBOLIC_STRING,
            call_span: site.call_span,
            write_span: site.write_span,
            precision: site.precision,
            call_kind: site.call_kind,
            kind: SymbolicFieldTransformKind::Return,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
            allow_out_of_order_source: true,
        });
    }
    for site in scalar_returns.take_current_sites() {
        if !symbolic_pair_supported(site.callee, site.caller, symbolic_funcs) {
            scalar_returns.defer(site);
            continue;
        }
        let source_base = normalize_storage_base(&site.source_base);
        let source = graph.intern_base(site.callee_seg, site.callee, &source_base);
        let target = graph.intern_base(site.caller_seg, site.caller, &site.target_base);
        let exact_field = graph.intern_string(&site.source_field);
        graph.push_transform(SymbolicFieldTransform {
            source,
            target,
            exact_field,
            call_span: site.call_span,
            write_span: site.write_span,
            precision: site.precision,
            call_kind: site.call_kind,
            kind: SymbolicFieldTransformKind::ScalarReturn,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
            allow_out_of_order_source: true,
        });
    }
    for site in constructor_returns.take_current_sites() {
        if !symbolic_pair_supported(site.callee, site.caller, symbolic_funcs) {
            constructor_returns.defer(site);
            continue;
        }
        let source_base = normalize_storage_base(&site.receiver_param_name);
        let source = graph.intern_base(site.callee_seg, site.callee, &source_base);
        let target = graph.intern_base(site.caller_seg, site.caller, &site.target_base);
        graph.push_transform(SymbolicFieldTransform {
            source,
            target,
            exact_field: NO_SYMBOLIC_STRING,
            call_span: site.call_span,
            write_span: site.write_span,
            precision: site.precision,
            call_kind: site.call_kind,
            kind: SymbolicFieldTransformKind::ConstructorReturn,
            arg_idx: u32::MAX,
            param_idx: u32::MAX,
            allow_out_of_order_source: true,
        });
    }
}

struct FieldForwardingSites<'a> {
    field_args: &'a [Arc<FieldArgStitch>],
    return_fields: &'a [Arc<ReturnFieldStitch>],
    scalar_returns: &'a [Arc<ScalarReturnStitch>],
    constructor_returns: &'a [Arc<ConstructorReturnStitch>],
    receiver_mutations: &'a [Arc<ReceiverMutationStitch>],
    passthrough_copies: &'a [FieldCopySite],
}

struct FieldPropagationInputs<'a> {
    transforms: &'a AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    field_contexts: &'a AHashMap<FuncId, FunctionFieldContext>,
}

struct FieldPropagationState<'a> {
    inter_call_arg_entries: &'a mut InterCallArgEntryIndex,
    synthetic_field_writes: &'a mut SyntheticFieldWriteCache,
    ws: &'a mut IdgWorkspace,
    known_edges: &'a mut AHashSet<(SegmentId, SegmentId, IdgEdge)>,
    field_index: &'a mut FieldPlaceIndex,
    pending: &'a mut Vec<PendingFieldWrite>,
    enqueued: &'a mut AHashSet<PendingFieldWrite>,
}

#[derive(Clone, Copy)]
struct OutboundFieldWrite<'a> {
    from_seg: SegmentId,
    to_seg: SegmentId,
    to_func: FuncId,
    target_base: &'a str,
    write_span: Span,
    via_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    edge_kind: crate::edge::IdgEdgeKind,
    skip_self_edge: bool,
}

fn stitch_field_argument_forwarding(
    sites: FieldForwardingSites<'_>,
    field_contexts: &AHashMap<FuncId, FunctionFieldContext>,
    ws: &mut IdgWorkspace,
    symbolic: bool,
    symbolic_funcs: Option<&AHashSet<FuncId>>,
    symbolic_field_graph: SymbolicFieldCompilerStorage,
) -> crate::IdgResult<()> {
    let FieldForwardingSites {
        field_args: sites,
        return_fields: return_field_sites,
        scalar_returns: scalar_return_sites,
        constructor_returns: constructor_return_sites,
        receiver_mutations: receiver_mutation_sites,
        passthrough_copies: passthrough_field_copy_sites,
    } = sites;
    let mut copy_sites = passthrough_field_copy_sites.to_vec();
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
        && symbolic_field_graph.is_empty()
    {
        return Ok(());
    }
    let mut transforms = build_field_write_transforms(
        sites,
        return_field_sites,
        scalar_return_sites,
        constructor_return_sites,
        receiver_mutation_sites,
        &copy_sites,
    );
    if symbolic {
        // Keep complete adapter AST places as a compact symbolic relation.
        // In a mixed-language workspace, transforms that cross an adapter
        // without complete field places remain on the eager compatibility
        // path.  This partition is capability-derived per function: a
        // single complete adapter must never disable field forwarding for a
        // peer adapter that cannot consume symbolic facts precisely.
        // Symbolic entries were already compiled per caller before the
        // dictionary indexes were released at the phase boundary. The rows
        // retained here are exactly the deferred mixed/incomplete-adapter
        // compatibility partition and must stay on the eager path.
        transforms.retain(|source, entries| {
            entries.retain(|transform| !field_transform_is_symbolic(source, transform, symbolic_funcs));
            !entries.is_empty()
        });
    }
    // Eager compatibility mode alone needs the concrete field universe and
    // synthetic-node indexes. Building them before the symbolic return made
    // demand-mode peak memory scale with the representation it deliberately
    // avoids.
    let spooled = ws.has_segment_spool();
    let eager_copy_sites = copy_sites
        .iter()
        .filter(|site| !symbolic || !symbolic_pair_supported(site.func, site.func, symbolic_funcs))
        .cloned()
        .collect::<Vec<_>>();
    // Complete adapters already express every argument/copy fallback in the
    // symbolic relation consumed by the query fixed point. Re-indexing those
    // same millions of transforms as concrete field places duplicates one
    // exact compiler product beside another and was the cold-build memory
    // high-water mark on large workspaces. The eager index is therefore only
    // the mixed/incomplete-adapter compatibility partition plus the finite
    // copy sites that this concrete worklist can actually visit.
    let requested_field_places = field_place_keys_for_propagation(&transforms, sites, &eager_copy_sites);
    let mut requested_segments = requested_field_places
        .iter()
        .map(|key| key.seg_id)
        .collect::<Vec<_>>();
    requested_segments.sort_by_key(|segment| segment.0);
    requested_segments.dedup();
    let mut field_index = FieldPlaceIndex::from_workspace_for_keys_streaming(ws, &requested_field_places)?;
    let mut syntactic_fields = field_index.take_syntactic_field_universe();
    syntactic_fields.record_argument_projection_demands(&field_index, sites);
    let mut inter_call_arg_entries =
        InterCallArgEntryIndex::from_workspace_for_segments_streaming(ws, &requested_segments)?;
    let mut synthetic_field_writes = SyntheticFieldWriteCache::from_workspace(ws);
    // Field forwarding creates edges to synthetic field nodes. Track only
    // edges produced by this phase instead of duplicating every pre-existing
    // workspace edge (millions on large projects) in a second hash table.
    let mut known_edges = AHashSet::default();
    // Every transform left after the symbolic partition touches at least one
    // adapter with incomplete field places, so it is materialized eagerly.
    let transform_count = transforms.values().map(Vec::len).sum::<usize>();
    let mut pending = Vec::new();
    let mut enqueued = AHashSet::default();
    seed_field_write_worklist(&field_index, &transforms, &mut pending, &mut enqueued);
    let inputs = FieldPropagationInputs {
        transforms: &transforms,
        field_contexts,
    };
    let mut state = FieldPropagationState {
        inter_call_arg_entries: &mut inter_call_arg_entries,
        synthetic_field_writes: &mut synthetic_field_writes,
        ws,
        known_edges: &mut known_edges,
        field_index: &mut field_index,
        pending: &mut pending,
        enqueued: &mut enqueued,
    };

    let phase_started = Instant::now();
    let before_edges = state.ws.total_edge_count();
    let mut fallback_edges = if spooled {
        stitch_field_argument_fallbacks_spooled(sites, &mut state)?
    } else {
        stitch_field_argument_fallbacks(sites, &mut state)
    };
    fallback_edges += if spooled {
        stitch_field_copy_fallbacks_spooled(&copy_sites, &inputs, &mut state)?
    } else {
        stitch_field_copy_fallbacks(&copy_sites, &inputs, &mut state)
    };
    if spooled {
        state.ws.spill_resident_segments()?;
        let mut eager_segments = requested_field_places
            .iter()
            .map(|key| key.seg_id)
            .collect::<Vec<_>>();
        eager_segments.sort_by_key(|segment| segment.0);
        eager_segments.dedup();
        state.ws.hydrate_segments(eager_segments.iter().copied())?;
        // Canonical lowering deliberately releases the transient reverse
        // dictionaries before it spools each segment. Field compatibility
        // closure is a later compiler mutation pass, so restore those O(1)
        // interning indexes only for the exact demanded segments. Without
        // this step every synthetic string/place/node insertion performs a
        // linear scan of the canonical vectors; dense generated JavaScript
        // can turn an otherwise sparse exact fixed point into quadratic work.
        // The indexes are storage only and are dropped again with the
        // resident segment below.
        for segment_id in eager_segments {
            if let Some(segment) = state.ws.segment_mut(segment_id) {
                segment.rebuild_build_lookups();
            }
        }
    }
    let mut processed = 0usize;
    let mut processed_transforms = 0usize;
    while let Some(write) = state.pending.pop() {
        processed += 1;
        let Some((storage, write_span)) = state.ws.segment(write.seg_id).and_then(|segment| {
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
            let Some(sites) = inputs.transforms.get(&key) else {
                continue;
            };
            let source = FieldPlaceHit {
                field,
                node: write.node,
                span: Some(write_span),
            };
            let mut apply_site = |site: &FieldWriteTransform| {
                if !field_transform_source_may_apply(site, &source, &inputs, &state) {
                    return;
                }
                processed_transforms += 1;
                apply_field_write_transform(site, &source, &inputs, &mut state);
            };
            for site in sites {
                apply_site(site);
            }
        }
    }
    let added_edges = state.ws.total_edge_count().saturating_sub(before_edges);
    stitch_debug_log(format_args!(
        "field-forward worklist: {:.3}s processed={} transform_apps={} transforms={} fallback_edges={} added_edges={} total_edges={} pending_remaining={}",
        phase_started.elapsed().as_secs_f64(),
        processed,
        processed_transforms,
        transform_count,
        fallback_edges,
        added_edges,
        state.ws.total_edge_count(),
        state.pending.len(),
    ));
    if symbolic {
        ws.install_symbolic_compiler_storage(symbolic_field_graph);
    }
    ws.spill_resident_segments()?;
    Ok(())
}

/// Exact field-place keys that the forwarding phase can query.
///
/// Every key comes from an adapter-lowered place or a resolver-backed
/// transform. Indexing only this demand set avoids duplicating unrelated
/// workspace field strings while preserving the same arbitrary-depth AST
/// paths and fixed point as a whole-workspace index.
fn field_place_keys_for_propagation(
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    fallback_argument_sites: &[Arc<FieldArgStitch>],
    copy_sites: &[FieldCopySite],
) -> AHashSet<FieldPlaceKey> {
    let mut keys = AHashSet::default();
    for (source, entries) in transforms {
        keys.insert(source.clone());
        for transform in entries {
            let (segment, func, target_base) = match transform {
                FieldWriteTransform::Argument(site) => (site.callee_seg, site.callee, &site.param_name),
                FieldWriteTransform::Return(site) => (site.caller_seg, site.caller, &site.target_base),
                FieldWriteTransform::ScalarReturn(site) => (site.caller_seg, site.caller, &site.target_base),
                FieldWriteTransform::ConstructorReturn(site) => {
                    (site.caller_seg, site.caller, &site.target_base)
                }
                FieldWriteTransform::ReceiverMutation(site) => {
                    (site.caller_seg, site.caller, &site.target_base)
                }
                FieldWriteTransform::Copy(site) => (site.seg_id, site.func, &site.target_base),
            };
            insert_field_place_key(&mut keys, segment, func, target_base, false);
        }
    }
    for site in fallback_argument_sites {
        insert_field_place_key(&mut keys, site.caller_seg, site.caller, &site.actual_arg, true);
        insert_field_place_key(&mut keys, site.callee_seg, site.callee, &site.param_name, false);
    }
    for site in copy_sites {
        insert_field_place_key(&mut keys, site.seg_id, site.func, &site.source_base, true);
        insert_field_place_key(&mut keys, site.seg_id, site.func, &site.target_base, false);
    }
    keys
}

fn insert_field_place_key(
    keys: &mut AHashSet<FieldPlaceKey>,
    seg_id: SegmentId,
    func: FuncId,
    base: &str,
    writes: bool,
) {
    let base = normalize_storage_base(base);
    if !base.is_empty() {
        keys.insert(FieldPlaceKey {
            seg_id,
            func,
            base,
            writes,
        });
    }
}

#[cfg(not(test))]
const FIELD_COPY_SPOOL_CHUNK_LEN: usize = 100_000;
#[cfg(test)]
const FIELD_COPY_SPOOL_CHUNK_LEN: usize = 2;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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

fn push_symbolic_field_copy(graph: &mut SymbolicFieldCompilerStorage, site: &FieldCopySite) {
    let source = graph.intern_base(site.seg_id, site.func, &site.source_base);
    let target = graph.intern_base(site.seg_id, site.func, &site.target_base);
    graph.push_transform(SymbolicFieldTransform {
        source,
        target,
        exact_field: NO_SYMBOLIC_STRING,
        call_span: site.via_span,
        write_span: site.write_span,
        precision: site.precision,
        call_kind: site.call_kind,
        kind: SymbolicFieldTransformKind::Copy,
        arg_idx: u32::MAX,
        param_idx: u32::MAX,
        allow_out_of_order_source: false,
    });
}

fn push_symbolic_receiver_mutation(graph: &mut SymbolicFieldCompilerStorage, site: &ReceiverMutationStitch) {
    let source = graph.intern_base(site.callee_seg, site.callee, &site.callee_receiver_param_name);
    let target = graph.intern_base(site.caller_seg, site.caller, &site.target_base);
    graph.push_transform(SymbolicFieldTransform {
        source,
        target,
        exact_field: NO_SYMBOLIC_STRING,
        call_span: site.call_span,
        write_span: site.call_span,
        precision: site.precision,
        call_kind: site.call_kind,
        kind: SymbolicFieldTransformKind::ReceiverMutation,
        arg_idx: u32::MAX,
        param_idx: u32::MAX,
        allow_out_of_order_source: true,
    });
}

fn field_transform_is_symbolic(
    source: &FieldPlaceKey,
    transform: &FieldWriteTransform,
    symbolic_funcs: Option<&AHashSet<FuncId>>,
) -> bool {
    symbolic_funcs.is_none_or(|funcs| {
        funcs.contains(&source.func)
            && field_transform_target_func(transform).is_some_and(|target| funcs.contains(&target))
    })
}

fn field_transform_target_func(transform: &FieldWriteTransform) -> Option<FuncId> {
    match transform {
        FieldWriteTransform::Argument(site) => Some(site.callee),
        FieldWriteTransform::Return(site) => Some(site.caller),
        FieldWriteTransform::ScalarReturn(site) => Some(site.caller),
        FieldWriteTransform::ConstructorReturn(site) => Some(site.caller),
        FieldWriteTransform::ReceiverMutation(site) => Some(site.caller),
        FieldWriteTransform::Copy(site) => Some(site.func),
    }
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
    pending: &mut Vec<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    let mut keys: Vec<FieldPlaceKey> = transforms.keys().cloned().collect();
    sort_field_keys(&mut keys);
    for key in keys {
        let Some(hits) = field_index.by_base.get(&key) else {
            continue;
        };
        for hit in hits {
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
    pending: &mut Vec<PendingFieldWrite>,
    enqueued: &mut AHashSet<PendingFieldWrite>,
) {
    let write = PendingFieldWrite {
        seg_id: key.seg_id,
        func: key.func,
        node: hit.node,
    };
    if enqueued.insert(write) {
        pending.push(write);
    }
}

fn enqueue_recorded_field_writes(
    writes: Vec<(FieldPlaceKey, FieldPlaceHit)>,
    transforms: &AHashMap<FieldPlaceKey, Vec<FieldWriteTransform>>,
    pending: &mut Vec<PendingFieldWrite>,
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

fn apply_field_write_transform(
    transform: &FieldWriteTransform,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) {
    match transform {
        FieldWriteTransform::Argument(site) => {
            apply_field_argument_write(site, source, inputs, state);
        }
        FieldWriteTransform::Return(site) => {
            apply_return_field_write(site, source, inputs, state);
        }
        FieldWriteTransform::ScalarReturn(site) => {
            apply_scalar_return_field_write(site, source, state);
        }
        FieldWriteTransform::ConstructorReturn(site) => {
            apply_constructor_return_field_write(site, source, inputs, state);
        }
        FieldWriteTransform::ReceiverMutation(site) => {
            apply_receiver_mutation_field_write(site, source, inputs, state);
        }
        FieldWriteTransform::Copy(site) => {
            apply_intra_field_copy_write(site, source, inputs, state);
        }
    }
}

fn field_transform_source_may_apply(
    transform: &FieldWriteTransform,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &FieldPropagationState<'_>,
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
                    state.inter_call_arg_entries,
                    site.caller_seg,
                    site.caller,
                )
        }
        FieldWriteTransform::ScalarReturn(site) => source.field == site.source_field,
        FieldWriteTransform::Copy(site) => source_can_reach_field_copy(
            source,
            site,
            state.synthetic_field_writes,
            state.inter_call_arg_entries,
            inputs
                .field_contexts
                .get(&site.func)
                .map(|data| &data.flow_control),
        ),
        FieldWriteTransform::Return(_)
        | FieldWriteTransform::ConstructorReturn(_)
        | FieldWriteTransform::ReceiverMutation(_) => true,
    }
}

fn apply_field_argument_write(
    site: &FieldArgStitch,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) {
    if (!site.allow_out_of_order_source
        && !source_write_can_reach_call(
            source,
            site.call_span,
            state.inter_call_arg_entries,
            site.caller_seg,
            site.caller,
        ))
        || !is_forwardable_field(&source.field)
    {
        return;
    }
    let Some((param_field_write, param_field_span, is_new_field_write)) =
        state.synthetic_field_writes.ensure_parameter(
            state.ws,
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
        state.field_index.record_write(
            site.callee_seg,
            site.callee,
            &site.param_name,
            &source.field,
            param_field_span,
            param_field_write,
            inputs.transforms,
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
                kind: crate::edge::IdgEdgeKind::InterFieldCallArg,
                call_kind: site.call_kind,
                via_span: site.call_span,
            },
        },
        state.ws,
        state.known_edges,
    ) {
        state
            .inter_call_arg_entries
            .insert(site.callee_seg, site.callee, param_field_write);
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
        state.ws,
        state.known_edges,
        state.field_index,
    );
    enqueue_recorded_field_writes(recorded, inputs.transforms, state.pending, state.enqueued);
}

fn apply_return_field_write(
    site: &ReturnFieldStitch,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) {
    apply_outbound_field_write(
        OutboundFieldWrite {
            from_seg: site.callee_seg,
            to_seg: site.caller_seg,
            to_func: site.caller,
            target_base: &site.target_base,
            write_span: site.write_span,
            via_span: site.call_span,
            precision: site.precision,
            call_kind: site.call_kind,
            edge_kind: crate::edge::IdgEdgeKind::InterFieldReturn,
            skip_self_edge: false,
        },
        source,
        inputs,
        state,
    );
}

fn apply_scalar_return_field_write(
    site: &ScalarReturnStitch,
    source: &FieldPlaceHit,
    state: &mut FieldPropagationState<'_>,
) {
    if source.field != site.source_field {
        return;
    }
    let Some(target_write) = ensure_scalar_write_node(
        state.ws,
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
                kind: crate::edge::IdgEdgeKind::InterFieldReturn,
                call_kind: site.call_kind,
                via_span: site.call_span,
            },
        },
        state.ws,
        state.known_edges,
    );
}

fn apply_constructor_return_field_write(
    site: &ConstructorReturnStitch,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) {
    apply_outbound_field_write(
        OutboundFieldWrite {
            from_seg: site.callee_seg,
            to_seg: site.caller_seg,
            to_func: site.caller,
            target_base: &site.target_base,
            write_span: site.write_span,
            via_span: site.call_span,
            precision: site.precision,
            call_kind: site.call_kind,
            edge_kind: crate::edge::IdgEdgeKind::InterFieldReturn,
            skip_self_edge: false,
        },
        source,
        inputs,
        state,
    );
}

fn apply_receiver_mutation_field_write(
    site: &ReceiverMutationStitch,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) {
    apply_outbound_field_write(
        OutboundFieldWrite {
            from_seg: site.callee_seg,
            to_seg: site.caller_seg,
            to_func: site.caller,
            target_base: &site.target_base,
            write_span: site.call_span,
            via_span: site.call_span,
            precision: site.precision,
            call_kind: site.call_kind,
            edge_kind: crate::edge::IdgEdgeKind::InterFieldReturn,
            skip_self_edge: false,
        },
        source,
        inputs,
        state,
    );
}

fn apply_intra_field_copy_write(
    site: &FieldCopySite,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
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
        state.synthetic_field_writes,
        state.inter_call_arg_entries,
        inputs
            .field_contexts
            .get(&site.func)
            .map(|data| &data.flow_control),
    ) {
        return;
    }
    apply_outbound_field_write(
        OutboundFieldWrite {
            from_seg: site.seg_id,
            to_seg: site.seg_id,
            to_func: site.func,
            target_base: &site.target_base,
            write_span: site.write_span,
            via_span: site.via_span,
            precision: site.precision,
            call_kind: site.call_kind,
            edge_kind: crate::edge::IdgEdgeKind::IntraAssign,
            skip_self_edge: true,
        },
        source,
        inputs,
        state,
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

fn apply_outbound_field_write(
    target: OutboundFieldWrite<'_>,
    source: &FieldPlaceHit,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) {
    if !is_forwardable_field(&source.field) {
        return;
    }
    let Some((target_field_write, target_field_span, is_new_field_write)) = SyntheticFieldWriteCache::ensure(
        state.ws,
        target.to_seg,
        target.to_func,
        target.target_base,
        &source.field,
        target.write_span,
    ) else {
        return;
    };
    let recorded = if is_new_field_write {
        state.field_index.record_write(
            target.to_seg,
            target.to_func,
            target.target_base,
            &source.field,
            target_field_span,
            target_field_write,
            inputs.transforms,
        )
    } else {
        Vec::new()
    };
    if !(target.skip_self_edge && target.from_seg == target.to_seg && source.node == target_field_write) {
        let changed = place_inter_edge_if_absent(
            target.from_seg,
            target.to_seg,
            IdgEdge {
                from: source.node,
                to: target_field_write,
                meta: crate::edge::EdgeMeta {
                    precision: target.precision,
                    kind: target.edge_kind,
                    call_kind: target.call_kind,
                    via_span: target.via_span,
                },
            },
            state.ws,
            state.known_edges,
        );
        if changed
            && matches!(
                target.edge_kind,
                crate::edge::IdgEdgeKind::InterCallArg
                    | crate::edge::IdgEdgeKind::InterReturn
                    | crate::edge::IdgEdgeKind::InterFieldCallArg
                    | crate::edge::IdgEdgeKind::InterFieldReturn
            )
        {
            state
                .inter_call_arg_entries
                .insert(target.to_seg, target.to_func, target_field_write);
        }
    }
    connect_field_write_to_reads(
        target.to_seg,
        target.to_func,
        target.target_base,
        &source.field,
        target_field_write,
        target_field_span,
        target.precision,
        target.call_kind,
        state.ws,
        state.known_edges,
        state.field_index,
    );
    enqueue_recorded_field_writes(recorded, inputs.transforms, state.pending, state.enqueued);
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
    state: &mut FieldPropagationState<'_>,
) -> usize {
    let mut added = 0usize;
    for site in sites {
        added += stitch_one_field_argument_fallback(
            site.caller,
            site.caller_seg,
            site.callee,
            site.callee_seg,
            &site.actual_arg,
            &site.param_name,
            site.call_span,
            site.precision,
            site.call_kind,
            state,
        );
    }
    added
}

fn stitch_field_argument_fallbacks_spooled(
    sites: &[Arc<FieldArgStitch>],
    state: &mut FieldPropagationState<'_>,
) -> crate::IdgResult<usize> {
    let mut added = 0usize;
    let mut active_segment = None;
    for site in sites {
        activate_fallback_segment(state.ws, &mut active_segment, site.caller_seg)?;
        added += stitch_one_field_argument_fallback(
            site.caller,
            site.caller_seg,
            site.callee,
            site.callee_seg,
            &site.actual_arg,
            &site.param_name,
            site.call_span,
            site.precision,
            site.call_kind,
            state,
        );
    }
    state.ws.spill_resident_segments()?;
    Ok(added)
}

fn activate_fallback_segment(
    ws: &mut IdgWorkspace,
    active_segment: &mut Option<SegmentId>,
    requested: SegmentId,
) -> crate::IdgResult<()> {
    if active_segment.is_some_and(|active| active != requested) {
        ws.spill_resident_segments()?;
    }
    ws.hydrate_segment(requested)?;
    if let Some(segment) = ws.segment_mut(requested) {
        // Spool payloads contain canonical vectors, not the transient reverse
        // maps. Fallback lowering may intern compiler nodes, so it must never
        // run against the exact-but-linear lookup representation.
        segment.rebuild_build_lookups();
    }
    *active_segment = Some(requested);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn stitch_one_field_argument_fallback(
    caller: FuncId,
    caller_seg: SegmentId,
    callee: FuncId,
    callee_seg: SegmentId,
    actual_arg: &str,
    param_name: &str,
    call_span: Span,
    precision: Precision,
    call_kind: CallEdgeKind,
    state: &mut FieldPropagationState<'_>,
) -> usize {
    let writers = state.field_index.field_writes_for_base_before_call(
        state.inter_call_arg_entries,
        caller_seg,
        caller,
        actual_arg,
        call_span,
    );
    if !writers.is_empty() {
        return 0;
    }
    let readers = state
        .field_index
        .field_reads_for_base(callee_seg, callee, param_name);
    let mut added = 0_usize;
    for (field, reader) in readers {
        if !is_forwardable_field(&field) {
            continue;
        }
        // The source must be the matching projected Place. Linking the whole
        // CallArg value here would collapse an object into every field demanded
        // by the callee and taint unrelated siblings.
        let Some(actual_field_read) =
            ensure_field_read_node(state.ws, caller_seg, caller, actual_arg, &field)
        else {
            continue;
        };
        let changed = place_inter_edge_if_absent(
            caller_seg,
            callee_seg,
            IdgEdge {
                from: actual_field_read,
                to: reader,
                meta: crate::edge::EdgeMeta {
                    precision,
                    kind: crate::edge::IdgEdgeKind::InterFieldCallArg,
                    call_kind,
                    via_span: call_span,
                },
            },
            state.ws,
            state.known_edges,
        );
        if changed {
            added += 1;
        }
    }
    added
}

fn stitch_field_copy_fallbacks(
    sites: &[FieldCopySite],
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) -> usize {
    let mut added = 0usize;
    for site in sites {
        added = added.saturating_add(stitch_one_field_copy_fallback(site, inputs, state));
    }
    added
}

fn stitch_field_copy_fallbacks_spooled(
    sites: &[FieldCopySite],
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) -> crate::IdgResult<usize> {
    let mut added = 0usize;
    let mut active_segment = None;
    for site in sites {
        activate_fallback_segment(state.ws, &mut active_segment, site.seg_id)?;
        added = added.saturating_add(stitch_one_field_copy_fallback(site, inputs, state));
    }
    state.ws.spill_resident_segments()?;
    Ok(added)
}

fn stitch_one_field_copy_fallback(
    site: &FieldCopySite,
    inputs: &FieldPropagationInputs<'_>,
    state: &mut FieldPropagationState<'_>,
) -> usize {
    let writers = state.field_index.field_writes_for_base_before_call(
        state.inter_call_arg_entries,
        site.seg_id,
        site.func,
        &site.source_base,
        site.via_span,
    );
    if !writers.is_empty() {
        return 0;
    }
    let mut readers = state
        .field_index
        .field_reads_for_base(site.seg_id, site.func, &site.target_base);
    readers.sort_by(|a, b| (a.0.as_str(), a.1 .0).cmp(&(b.0.as_str(), b.1 .0)));
    readers.dedup();
    let mut added = 0usize;
    for (field, _) in readers {
        if !is_forwardable_field(&field) {
            continue;
        }
        let Some(source_read) =
            ensure_field_read_node(state.ws, site.seg_id, site.func, &site.source_base, &field)
        else {
            continue;
        };
        let before = state.known_edges.len();
        apply_intra_field_copy_write(
            site,
            &FieldPlaceHit {
                field,
                node: source_read,
                span: None,
            },
            inputs,
            state,
        );
        added = added.saturating_add(state.known_edges.len().saturating_sub(before));
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
    field_contexts: &AHashMap<FuncId, FunctionFieldContext>,
) -> Vec<FieldCopySite> {
    let mut out = Vec::new();
    for (seg_id, segment) in ws.segments() {
        out.extend(collect_field_copy_sites_from_segment(
            seg_id,
            segment,
            field_contexts,
        ));
    }
    sort_and_dedup_field_copy_sites(&mut out);
    out
}

fn collect_field_copy_sites_from_segment(
    seg_id: SegmentId,
    segment: &IdgSegment,
    field_contexts: &AHashMap<FuncId, FunctionFieldContext>,
) -> Vec<FieldCopySite> {
    let mut out = Vec::new();
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
                field_contexts
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
    sort_and_dedup_field_copy_sites(&mut out);
    out
}

fn sort_and_dedup_field_copy_sites(out: &mut Vec<FieldCopySite>) {
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
    if write.len() >= storage_normalization_cache_capacity() {
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
    #[cfg(test)]
    fn from_workspace(ws: &IdgWorkspace) -> Self {
        Self::from_workspace_with_filter(ws, None)
    }

    fn from_workspace_for_keys(ws: &IdgWorkspace, requested: &AHashSet<FieldPlaceKey>) -> Self {
        Self::from_workspace_with_filter(ws, Some(requested))
    }

    fn from_workspace_for_keys_streaming(
        ws: &mut IdgWorkspace,
        requested: &AHashSet<FieldPlaceKey>,
    ) -> crate::IdgResult<Self> {
        if !ws.has_segment_spool() {
            return Ok(Self::from_workspace_for_keys(ws, requested));
        }
        let mut segment_ids = requested.iter().map(|key| key.seg_id).collect::<Vec<_>>();
        segment_ids.sort_by_key(|segment| segment.0);
        segment_ids.dedup();
        let mut index = Self::default();
        for seg_id in segment_ids {
            ws.visit_segment(seg_id, |segment| {
                index.extend_segment_with_filter(seg_id, segment, Some(requested));
            })?;
        }
        index.sort_and_dedup();
        Ok(index)
    }

    fn from_workspace_with_filter(ws: &IdgWorkspace, requested: Option<&AHashSet<FieldPlaceKey>>) -> Self {
        let mut index = Self::default();
        for (seg_id, segment) in ws.segments() {
            index.extend_segment_with_filter(seg_id, segment, requested);
        }
        index.sort_and_dedup();
        index
    }

    fn extend_segment_with_filter(
        &mut self,
        seg_id: SegmentId,
        segment: &IdgSegment,
        requested: Option<&AHashSet<FieldPlaceKey>>,
    ) {
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
            self.syntactic_fields.record_full_storage_place(&full_name);
            let node_id = NodeId(node_idx as u32);
            let _ = self.record_full_storage_place_filtered(
                seg_id, node.func, &full_name, writes, span, node_id, requested,
            );
        }
    }

    fn take_syntactic_field_universe(&mut self) -> SyntacticFieldUniverse {
        // This snapshot is intentionally taken before synthetic writes are
        // recorded. Reads and writes emitted by every language adapter use the
        // same Place representation, so numeric map/tuple keys and arbitrarily
        // deep exact paths participate without language-specific constants.
        std::mem::take(&mut self.syntactic_fields)
    }

    #[cfg(test)]
    fn syntactic_field_universe(&self) -> &SyntacticFieldUniverse {
        &self.syntactic_fields
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

    #[allow(clippy::too_many_arguments)]
    fn record_full_storage_place_filtered(
        &mut self,
        seg_id: SegmentId,
        func: FuncId,
        full_name: &str,
        writes: bool,
        span: Option<Span>,
        node: NodeId,
        requested: Option<&AHashSet<FieldPlaceKey>>,
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
            if requested.is_some_and(|requested| {
                !requested.contains(&FieldPlaceKey {
                    seg_id,
                    func,
                    base: base.clone(),
                    writes,
                })
            }) {
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
    if write.len() >= storage_normalization_cache_capacity() {
        write.clear();
    }
    write
        .entry(base.to_string())
        .or_insert_with(|| normalized.clone());
    normalized
}

/// Storage normalization is a build-phase memo, not part of the compiler IR.
/// Release its owned strings before persistence/query materialization so
/// repeated analyses in one process do not retain a previous build's memory
/// high-water mark. Clearing is semantics-neutral; a concurrent or later build
/// simply recomputes the same AST-derived normalization.
fn release_storage_normalization_caches() {
    let (segment_entries, segment_capacity) = {
        let mut cache = STORAGE_SEGMENTS_CACHE.write();
        let stats = (cache.len(), cache.capacity());
        *cache = AHashMap::new();
        stats
    };
    let (normalized_entries, normalized_capacity) = {
        let mut cache = NORMALIZED_STORAGE_CACHE.write();
        let stats = (cache.len(), cache.capacity());
        *cache = AHashMap::new();
        stats
    };
    stitch_debug_log(format_args!(
        "stitch normalization-cache-release: segment_entries={} segment_capacity={} normalized_entries={} normalized_capacity={}",
        segment_entries, segment_capacity, normalized_entries, normalized_capacity
    ));
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
                if !matches!(
                    edge.meta.kind,
                    crate::edge::IdgEdgeKind::InterCallArg
                        | crate::edge::IdgEdgeKind::InterFieldCallArg
                        | crate::edge::IdgEdgeKind::InterFieldReturn
                ) {
                    continue;
                }
                if let Some(to_node) = segment.nodes.get(edge.to) {
                    index.entries.insert((seg_id, to_node.func, edge.to));
                }
            }
        }
        for cross in &ws.cross_file().edges {
            if !matches!(
                cross.edge.meta.kind,
                crate::edge::IdgEdgeKind::InterCallArg
                    | crate::edge::IdgEdgeKind::InterFieldCallArg
                    | crate::edge::IdgEdgeKind::InterFieldReturn
            ) {
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

    fn from_workspace_for_segments_streaming(
        ws: &mut IdgWorkspace,
        segment_ids: &[SegmentId],
    ) -> crate::IdgResult<Self> {
        if !ws.has_segment_spool() {
            return Ok(Self::from_workspace(ws));
        }
        let requested = segment_ids.iter().copied().collect::<AHashSet<_>>();
        let mut cross_entries: AHashMap<SegmentId, Vec<NodeId>> = AHashMap::new();
        ws.visit_cross_file_edges(|edges| {
            for cross in edges {
                if requested.contains(&cross.to_segment)
                    && matches!(
                        cross.edge.meta.kind,
                        crate::edge::IdgEdgeKind::InterCallArg
                            | crate::edge::IdgEdgeKind::InterFieldCallArg
                            | crate::edge::IdgEdgeKind::InterFieldReturn
                    )
                {
                    cross_entries
                        .entry(cross.to_segment)
                        .or_default()
                        .push(cross.edge.to);
                }
            }
        })?;
        let mut index = Self::default();
        for &seg_id in segment_ids {
            ws.visit_segment(seg_id, |segment| {
                for edge in &segment.edges {
                    if !matches!(
                        edge.meta.kind,
                        crate::edge::IdgEdgeKind::InterCallArg
                            | crate::edge::IdgEdgeKind::InterFieldCallArg
                            | crate::edge::IdgEdgeKind::InterFieldReturn
                    ) {
                        continue;
                    }
                    if let Some(to_node) = segment.nodes.get(edge.to) {
                        index.entries.insert((seg_id, to_node.func, edge.to));
                    }
                }
                for &node in cross_entries.get(&seg_id).into_iter().flatten() {
                    if let Some(to_node) = segment.nodes.get(node) {
                        index.entries.insert((seg_id, to_node.func, node));
                    }
                }
            })?;
        }
        Ok(index)
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
        for (index, count) in initial_node_counts.iter_mut().enumerate() {
            *count = ws.segment_node_count(SegmentId(index as u32));
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
        let created = Self::ensure(ws, seg_id, func, &key.2, &key.3, fallback_span)?;
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
        ws.push_cross_file_edge(CrossFileEdge {
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
