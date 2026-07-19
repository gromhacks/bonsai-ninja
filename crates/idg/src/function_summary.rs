//! Function-local compiler summaries over the workspace IDG.
//!
//! Export consumers need two projections that should not require one
//! workspace-sized closure per function or parameter:
//!
//! - formal parameters that can reach a function's return value; and
//! - local storage reached from each formal parameter.
//!
//! This module compacts every function to its own node address space and CSR.
//! Return summaries compose resolved call inputs and outputs with a monotone
//! worklist.  Recursive and mutually recursive call components therefore run
//! to their least fixed point without an iteration or graph-size cap.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{FuncId, Precision, Span};
use std::collections::BTreeSet;

use crate::edge::{IdgEdge, IdgEdgeKind};
use crate::node::{NodeId, PlaceId};
use crate::place::Place;
use crate::query::ReachabilityIndex;
use crate::symbolic::{structured_storage_parts, SymbolicFieldTransformKind};
use crate::workspace::{IdgWorkspace, SegmentId};

#[derive(Copy, Clone)]
struct LocalNodeAddress {
    func: FuncId,
    compact: u32,
    is_param: bool,
    is_return: bool,
    is_throw: bool,
}

struct LocalFunctionGraph {
    segment: SegmentId,
    local_nodes: Vec<NodeId>,
    params: Vec<(u32, u32)>,
    return_node: Option<u32>,
    edges: Vec<(u32, u32)>,
    base_edge_count: usize,
    summary_edge_set: AHashSet<u64>,
    base_finalized: bool,
}

impl LocalFunctionGraph {
    fn new(segment: SegmentId) -> Self {
        Self {
            segment,
            local_nodes: Vec::new(),
            params: Vec::new(),
            return_node: None,
            edges: Vec::new(),
            base_edge_count: 0,
            summary_edge_set: AHashSet::default(),
            base_finalized: false,
        }
    }

    fn add_node(&mut self, local_node: NodeId, place: Option<&Place>) -> u32 {
        let compact =
            u32::try_from(self.local_nodes.len()).expect("function-local IDG node count exceeds u32");
        self.local_nodes.push(local_node);
        match place {
            Some(Place::Param { idx }) => self.params.push((*idx, compact)),
            Some(Place::Return) => self.return_node = Some(compact),
            _ => {}
        }
        compact
    }

    fn add_base_edge(&mut self, from: u32, to: u32) {
        debug_assert!(!self.base_finalized);
        self.edges.push((from, to));
    }

    fn finalize_base_edges(&mut self) {
        if self.base_finalized {
            return;
        }
        self.edges.sort_unstable();
        self.edges.dedup();
        self.base_edge_count = self.edges.len();
        self.base_finalized = true;
    }

    fn add_summary_edge(&mut self, from: u32, to: u32) -> bool {
        self.finalize_base_edges();
        if self.edges[..self.base_edge_count]
            .binary_search(&(from, to))
            .is_ok()
        {
            return false;
        }
        let key = (u64::from(from) << 32) | u64::from(to);
        if !self.summary_edge_set.insert(key) {
            return false;
        }
        self.edges.push((from, to));
        true
    }

    fn reachability(&mut self) -> ReachabilityIndex {
        self.finalize_base_edges();
        ReachabilityIndex::from_pairs(self.local_nodes.len(), &self.edges)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct CallBoundaryKey {
    caller: FuncId,
    callee: FuncId,
    span: Span,
}

struct CallBoundary {
    key: CallBoundaryKey,
    /// `(caller source, callee input)` pairs.
    inputs: Vec<(u32, u32)>,
    /// `(callee output, caller continuation)` pairs.
    outputs: Vec<(u32, u32)>,
}

fn edge_is_within_precision(edge: &IdgEdge, max_precision: Option<Precision>) -> bool {
    max_precision.is_none_or(|max| edge.meta.precision <= max)
}

fn build_layout(
    workspace: &IdgWorkspace,
) -> (AHashMap<FuncId, LocalFunctionGraph>, Vec<Vec<LocalNodeAddress>>) {
    let mut graphs = AHashMap::default();
    let mut addresses = Vec::with_capacity(workspace.segment_count());
    for (segment_id, segment) in workspace.segments() {
        let mut segment_addresses = Vec::with_capacity(segment.nodes.nodes.len());
        for (node_idx, node) in segment.nodes.nodes.iter().enumerate() {
            let local_node =
                NodeId(u32::try_from(node_idx).expect("segment-local IDG node count exceeds u32"));
            let graph = graphs
                .entry(node.func)
                .or_insert_with(|| LocalFunctionGraph::new(segment_id));
            debug_assert_eq!(graph.segment, segment_id);
            let place = segment.places.get(node.place);
            let compact = graph.add_node(local_node, place);
            segment_addresses.push(LocalNodeAddress {
                func: node.func,
                compact,
                is_param: matches!(place, Some(Place::Param { .. })),
                is_return: matches!(place, Some(Place::Return)),
                is_throw: matches!(place, Some(Place::Throw { .. })),
            });
        }
        addresses.push(segment_addresses);
    }
    for graph in graphs.values_mut() {
        graph.params.sort_unstable_by_key(|(idx, _)| *idx);
        graph.params.dedup();
    }
    (graphs, addresses)
}

fn address_of(
    addresses: &[Vec<LocalNodeAddress>],
    segment: SegmentId,
    node: NodeId,
) -> Option<LocalNodeAddress> {
    addresses.get(segment.0 as usize)?.get(node.0 as usize).copied()
}

fn record_summary_edge(
    graphs: &mut AHashMap<FuncId, LocalFunctionGraph>,
    boundaries: &mut AHashMap<CallBoundaryKey, CallBoundary>,
    addresses: &[Vec<LocalNodeAddress>],
    from_segment: SegmentId,
    to_segment: SegmentId,
    edge: &IdgEdge,
    max_precision: Option<Precision>,
) {
    if !edge_is_within_precision(edge, max_precision) {
        return;
    }
    // Whole-aggregate consumption is call-site evidence for unresolved or
    // external callees. It must not participate in scalar function summaries;
    // resolved calls carry projected state through InterFieldCallArg edges.
    if edge.meta.kind == IdgEdgeKind::IntraAggregateConsume {
        return;
    }
    let Some(from) = address_of(addresses, from_segment, edge.from) else {
        return;
    };
    let Some(to) = address_of(addresses, to_segment, edge.to) else {
        return;
    };

    if from.func == to.func && edge.meta.kind.is_intra() {
        if let Some(graph) = graphs.get_mut(&from.func) {
            graph.add_base_edge(from.compact, to.compact);
        }
        return;
    }

    // Only structural formal/return places define compiler call-summary
    // boundaries. Eager field compatibility edges reuse the InterCallArg /
    // InterReturn tags but can be owned by canonical type-field functions;
    // the contextual runtime normalizes those against these structural
    // boundaries instead of allowing endpoint ownership to invent a callee.
    let structural_boundary = match edge.meta.kind {
        IdgEdgeKind::InterCallArg => to.is_param,
        IdgEdgeKind::InterReturn => from.is_return,
        IdgEdgeKind::InterThrow => from.is_throw,
        _ => false,
    };
    if !structural_boundary {
        return;
    }

    let (key, input, output) = match edge.meta.kind {
        IdgEdgeKind::InterCallArg => (
            CallBoundaryKey {
                caller: from.func,
                callee: to.func,
                span: edge.meta.via_span,
            },
            Some((from.compact, to.compact)),
            None,
        ),
        IdgEdgeKind::InterReturn | IdgEdgeKind::InterThrow => (
            CallBoundaryKey {
                caller: to.func,
                callee: from.func,
                span: edge.meta.via_span,
            },
            None,
            Some((from.compact, to.compact)),
        ),
        _ => return,
    };
    let boundary = boundaries.entry(key.clone()).or_insert_with(|| CallBoundary {
        key,
        inputs: Vec::new(),
        outputs: Vec::new(),
    });
    if let Some(input) = input {
        boundary.inputs.push(input);
    }
    if let Some(output) = output {
        boundary.outputs.push(output);
    }
}

fn add_summary_edges_to_fixed_point(
    graphs: &mut AHashMap<FuncId, LocalFunctionGraph>,
    mut boundaries: Vec<CallBoundary>,
) {
    for graph in graphs.values_mut() {
        graph.finalize_base_edges();
    }
    boundaries.retain(|boundary| !boundary.inputs.is_empty() && !boundary.outputs.is_empty());
    for boundary in &mut boundaries {
        boundary.inputs.sort_unstable();
        boundary.inputs.dedup();
        boundary.outputs.sort_unstable();
        boundary.outputs.dedup();
    }
    boundaries.sort_by(|left, right| left.key.cmp(&right.key));

    let mut by_callee: AHashMap<FuncId, Vec<usize>> = AHashMap::default();
    for (idx, boundary) in boundaries.iter().enumerate() {
        by_callee.entry(boundary.key.callee).or_default().push(idx);
    }

    let mut initial: Vec<FuncId> = by_callee.keys().copied().collect();
    initial.sort_unstable_by_key(|func| func.raw());
    let mut pending = initial.clone();
    let mut queued: AHashSet<FuncId> = initial.into_iter().collect();

    while let Some(callee) = pending.pop() {
        queued.remove(&callee);
        let Some(boundary_indices) = by_callee.get(&callee) else {
            continue;
        };

        let mut boundaries_by_output: AHashMap<u32, Vec<(usize, u32)>> = AHashMap::default();
        for &boundary_idx in boundary_indices {
            for &(callee_output, caller_continuation) in &boundaries[boundary_idx].outputs {
                boundaries_by_output
                    .entry(callee_output)
                    .or_default()
                    .push((boundary_idx, caller_continuation));
            }
        }
        let mut output_nodes: Vec<u32> = boundaries_by_output.keys().copied().collect();
        output_nodes.sort_unstable();

        let Some(callee_graph) = graphs.get_mut(&callee) else {
            continue;
        };
        let reachability = callee_graph.reachability();
        let mut effects: Vec<(FuncId, u32, u32)> = Vec::new();
        for output in output_nodes {
            let backward = reachability.backward_closure(&[NodeId(output)]);
            let Some(continuations) = boundaries_by_output.get(&output) else {
                continue;
            };
            for &(boundary_idx, caller_continuation) in continuations {
                let boundary = &boundaries[boundary_idx];
                for &(caller_input, callee_input) in &boundary.inputs {
                    if backward.contains(NodeId(callee_input)) {
                        effects.push((boundary.key.caller, caller_input, caller_continuation));
                    }
                }
            }
        }
        effects.sort_unstable_by_key(|(caller, from, to)| (caller.raw(), *from, *to));
        effects.dedup();

        let mut changed_callers = Vec::new();
        for (caller, from, to) in effects {
            if graphs
                .get_mut(&caller)
                .is_some_and(|graph| graph.add_summary_edge(from, to))
            {
                changed_callers.push(caller);
            }
        }
        changed_callers.sort_unstable_by_key(|func| func.raw());
        changed_callers.dedup();
        for caller in changed_callers {
            if by_callee.contains_key(&caller) && queued.insert(caller) {
                pending.push(caller);
            }
        }
    }
}

/// Batched ordinary summaries plus the functions whose result can depend on
/// the symbolic access-path relation.
pub(crate) struct ReturnSummaryBatch {
    pub(crate) indices: AHashMap<FuncId, Vec<u32>>,
    pub(crate) symbolic_sensitive: AHashSet<FuncId>,
    pub(crate) symbolic_callees: AHashMap<FuncId, Vec<FuncId>>,
    pub(crate) contextual_edges: Vec<ContextualSummaryEdge>,
}

/// One function-local or call-summary edge addressed in the workspace's
/// segmented node space. Raw interprocedural edges are deliberately absent:
/// query evaluation enters callees and returns only through matched call
/// boundaries.
#[derive(Copy, Clone)]
pub(crate) struct ContextualSummaryEdge {
    pub(crate) segment: SegmentId,
    pub(crate) from: NodeId,
    pub(crate) to: NodeId,
}

fn contextual_summary_edges(graphs: &mut AHashMap<FuncId, LocalFunctionGraph>) -> Vec<ContextualSummaryEdge> {
    let mut edges = Vec::new();
    for graph in graphs.values_mut() {
        graph.finalize_base_edges();
        for &(from, to) in &graph.edges {
            let Some(from) = graph.local_nodes.get(from as usize).copied() else {
                continue;
            };
            let Some(to) = graph.local_nodes.get(to as usize).copied() else {
                continue;
            };
            edges.push(ContextualSummaryEdge {
                segment: graph.segment,
                from,
                to,
            });
        }
    }
    edges.sort_unstable_by_key(|edge| (edge.segment.0, edge.from.0, edge.to.0));
    edges.dedup_by_key(|edge| (edge.segment.0, edge.from.0, edge.to.0));
    edges
}

pub(crate) fn return_taint_param_indices(
    workspace: &IdgWorkspace,
    funcs: &[FuncId],
    max_precision: Option<Precision>,
) -> ReturnSummaryBatch {
    let (mut graphs, addresses) = build_layout(workspace);
    let mut boundaries: AHashMap<CallBoundaryKey, CallBoundary> = AHashMap::default();
    for (segment_id, segment) in workspace.segments() {
        for edge in &segment.edges {
            record_summary_edge(
                &mut graphs,
                &mut boundaries,
                &addresses,
                segment_id,
                segment_id,
                edge,
                max_precision,
            );
        }
    }
    for edge in &workspace.cross_file().edges {
        record_summary_edge(
            &mut graphs,
            &mut boundaries,
            &addresses,
            edge.from_segment,
            edge.to_segment,
            &edge.edge,
            max_precision,
        );
    }
    let mut return_continuations_by_caller: AHashMap<FuncId, Vec<(FuncId, u32)>> = AHashMap::default();
    for boundary in boundaries.values() {
        for &(_, continuation) in &boundary.outputs {
            return_continuations_by_caller
                .entry(boundary.key.caller)
                .or_default()
                .push((boundary.key.callee, continuation));
        }
    }
    for continuations in return_continuations_by_caller.values_mut() {
        continuations.sort_unstable_by_key(|(callee, continuation)| (callee.raw(), *continuation));
        continuations.dedup();
    }
    add_summary_edges_to_fixed_point(&mut graphs, boundaries.into_values().collect());
    if funcs.is_empty() {
        return ReturnSummaryBatch {
            indices: AHashMap::default(),
            symbolic_sensitive: AHashSet::default(),
            symbolic_callees: AHashMap::default(),
            contextual_edges: contextual_summary_edges(&mut graphs),
        };
    }

    let mut requested: Vec<FuncId> = funcs.to_vec();
    requested.sort_unstable_by_key(|func| func.raw());
    requested.dedup();
    let requested_set: AHashSet<FuncId> = requested.iter().copied().collect();
    let mut summaries: AHashMap<FuncId, Vec<u32>> =
        requested.iter().copied().map(|func| (func, Vec::new())).collect();
    let symbolic_consumers = symbolic_consumer_nodes(workspace, &addresses, max_precision);
    let mut directly_sensitive = AHashSet::default();
    let mut return_callers_by_callee: AHashMap<FuncId, Vec<FuncId>> = AHashMap::default();
    let mut graph_funcs: Vec<FuncId> = graphs.keys().copied().collect();
    graph_funcs.sort_unstable_by_key(|func| func.raw());
    for func in graph_funcs {
        let Some(graph) = graphs.get_mut(&func) else {
            continue;
        };
        let Some(return_node) = graph.return_node else {
            continue;
        };
        let params = graph.params.clone();
        let backward = graph.reachability().backward_closure(&[NodeId(return_node)]);
        if symbolic_consumers
            .get(&func)
            .is_some_and(|nodes| nodes.iter().any(|node| backward.contains(NodeId(*node))))
        {
            directly_sensitive.insert(func);
        }
        if let Some(continuations) = return_continuations_by_caller.get(&func) {
            for &(callee, continuation) in continuations {
                if backward.contains(NodeId(continuation)) {
                    return_callers_by_callee.entry(callee).or_default().push(func);
                }
            }
        }
        if requested_set.contains(&func) {
            let indices = params
                .into_iter()
                .filter_map(|(idx, node)| backward.contains(NodeId(node)).then_some(idx))
                .collect();
            summaries.insert(func, indices);
        }
    }

    for callers in return_callers_by_callee.values_mut() {
        callers.sort_unstable_by_key(|func| func.raw());
        callers.dedup();
    }

    // Context-matched function dependencies for symbolic return queries.
    // A callee is a predecessor only when its concrete return continuation
    let contextual_edges = contextual_summary_edges(&mut graphs);

    // A symbolic dependency in a callee can change a caller summary only when
    // that exact call's returned continuation reaches the caller's Return.
    // Propagating over these compiler call/return boundaries is substantially
    // narrower than marking every transitive caller in the resolved callgraph.
    let mut symbolic_sensitive = directly_sensitive.clone();
    let mut pending: Vec<FuncId> = directly_sensitive.into_iter().collect();
    while let Some(callee) = pending.pop() {
        let Some(callers) = return_callers_by_callee.get(&callee) else {
            continue;
        };
        for caller in callers {
            if symbolic_sensitive.insert(*caller) {
                pending.push(*caller);
            }
        }
    }

    let mut symbolic_callees: AHashMap<FuncId, Vec<FuncId>> = AHashMap::default();
    for (callee, callers) in &return_callers_by_callee {
        if !symbolic_sensitive.contains(callee) {
            continue;
        }
        for caller in callers {
            if symbolic_sensitive.contains(caller) {
                symbolic_callees.entry(*caller).or_default().push(*callee);
            }
        }
    }
    for callees in symbolic_callees.values_mut() {
        callees.sort_unstable_by_key(|func| func.raw());
        callees.dedup();
    }

    ReturnSummaryBatch {
        indices: summaries,
        symbolic_sensitive,
        symbolic_callees,
        contextual_edges,
    }
}

fn symbolic_consumer_nodes(
    workspace: &IdgWorkspace,
    addresses: &[Vec<LocalNodeAddress>],
    max_precision: Option<Precision>,
) -> AHashMap<FuncId, AHashSet<u32>> {
    let symbolic = workspace.symbolic_field();
    if symbolic.transforms().is_empty() {
        return AHashMap::default();
    }
    let scalar_targets: AHashSet<(u32, Span)> = symbolic
        .transforms()
        .iter()
        .filter(|transform| transform.kind == SymbolicFieldTransformKind::ScalarReturn)
        .filter(|transform| max_precision.is_none_or(|max| transform.precision <= max))
        .map(|transform| (transform.target, transform.write_span))
        .collect();
    let mut consumers: AHashMap<FuncId, AHashSet<u32>> = AHashMap::default();
    for (segment_id, segment) in workspace.segments() {
        for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
            let Some(place) = segment.places.get(node.place) else {
                continue;
            };
            let Some((parts, write_span, is_read)) = structured_storage_parts(segment, place) else {
                continue;
            };
            let full = parts.join(".");
            let full_base = symbolic.base_id(segment_id, node.func, &full);
            let bare_consumer = is_read && full_base.is_some();
            let exact_consumer = is_read
                && (1..parts.len()).any(|split| {
                    let base = parts[..split].join(".");
                    symbolic.base_id(segment_id, node.func, &base).is_some()
                });
            let scalar_consumer = write_span
                .zip(full_base)
                .is_some_and(|(span, base)| scalar_targets.contains(&(base, span)));
            let local = NodeId(u32::try_from(node_index).expect("segment-local IDG node count exceeds u32"));
            let Some(address) = address_of(addresses, segment_id, local) else {
                continue;
            };
            if bare_consumer || exact_consumer || scalar_consumer {
                consumers.entry(address.func).or_default().insert(address.compact);
            }
        }
    }
    consumers
}

fn record_function_local_edge(
    graphs: &mut AHashMap<FuncId, LocalFunctionGraph>,
    addresses: &[Vec<LocalNodeAddress>],
    from_segment: SegmentId,
    to_segment: SegmentId,
    edge: &IdgEdge,
    max_precision: Option<Precision>,
) {
    if !edge_is_within_precision(edge, max_precision) {
        return;
    }
    let Some(from) = address_of(addresses, from_segment, edge.from) else {
        return;
    };
    let Some(to) = address_of(addresses, to_segment, edge.to) else {
        return;
    };
    if from.func != to.func {
        return;
    }
    if let Some(graph) = graphs.get_mut(&from.func) {
        graph.add_base_edge(from.compact, to.compact);
    }
}

fn storage_name(workspace: &IdgWorkspace, segment_id: SegmentId, place_id: PlaceId) -> Option<String> {
    let segment = workspace.segment(segment_id)?;
    let (name, path) = match segment.places.get(place_id)? {
        Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
        _ => return None,
    };
    let mut storage = segment.strings.get(name)?.to_string();
    for part in path {
        storage.push('.');
        storage.push_str(segment.strings.get(*part)?);
    }
    (!storage.trim().is_empty()).then_some(storage)
}

pub(crate) fn local_storage_taint_by_param(
    workspace: &IdgWorkspace,
    funcs: &[FuncId],
    max_precision: Option<Precision>,
) -> AHashMap<FuncId, Vec<Vec<String>>> {
    let (mut graphs, addresses) = build_layout(workspace);
    for (segment_id, segment) in workspace.segments() {
        for edge in &segment.edges {
            record_function_local_edge(
                &mut graphs,
                &addresses,
                segment_id,
                segment_id,
                edge,
                max_precision,
            );
        }
    }
    for edge in &workspace.cross_file().edges {
        record_function_local_edge(
            &mut graphs,
            &addresses,
            edge.from_segment,
            edge.to_segment,
            &edge.edge,
            max_precision,
        );
    }

    let mut requested: Vec<FuncId> = funcs.to_vec();
    requested.sort_unstable_by_key(|func| func.raw());
    requested.dedup();
    let mut all_flows = AHashMap::with_capacity(requested.len());
    for func in requested {
        let Some(graph) = graphs.get_mut(&func) else {
            all_flows.insert(func, Vec::new());
            continue;
        };
        let param_slots = graph
            .params
            .iter()
            .map(|(idx, _)| *idx as usize + 1)
            .max()
            .unwrap_or(0);
        let mut per_param: Vec<BTreeSet<String>> = (0..param_slots).map(|_| BTreeSet::new()).collect();
        let params = graph.params.clone();
        let segment_id = graph.segment;
        let reachability = graph.reachability();
        for (param_idx, param_node) in params {
            let Some(names) = per_param.get_mut(param_idx as usize) else {
                continue;
            };
            let closure = reachability.forward_closure(&[NodeId(param_node)]);
            for reached in closure.iter() {
                let Some(local_node) = graph.local_nodes.get(reached.0 as usize) else {
                    continue;
                };
                let Some(segment) = workspace.segment(segment_id) else {
                    continue;
                };
                let Some(node) = segment.nodes.get(*local_node) else {
                    continue;
                };
                if let Some(name) = storage_name(workspace, segment_id, node.place) {
                    names.insert(name);
                }
            }
        }
        all_flows.insert(
            func,
            per_param
                .into_iter()
                .map(|names| names.into_iter().collect())
                .collect(),
        );
    }
    all_flows
}
