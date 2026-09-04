//! Source-independent sink lineage from function-local summaries.
//!
//! Every admitted function is analysed once per entering value: one exact
//! IDG closure confined to that function per parameter, one per storage read
//! the projected heap feeds from another summary's tainted write, and one
//! over all places of an entry point. Callee returns compose through the
//! IDG's contextual return summaries inside those closures, so no closure
//! ever re-explores a callee body. The summaries form a graph whose nodes
//! are `(function, entering value)` and whose edges are tainted call
//! arguments and projected-heap write→read relations; an upstream route is
//! a path in that graph from an entry point to a sink hit, materialised on
//! demand and rendered with the same call records and taint-path steps as a
//! single-origin closure.
//!
//! The work is proportional to the program (functions × entering values),
//! never to entry points × sinks.

use super::{
    chain_names_for_path, flow_id_for_taint_path, sink_flow_origin, sink_rule_match_key,
    source_analysis_worker_count, taint_path_for_lineage, tainted_call_matches_sink, AnalysisProgress,
    InterTaintCaches, SinkAnalysisFlow, SinkEndpointKey,
};
use crate::RuleMatch;
use ahash::{AHashMap, AHashSet};
use bonsai_common::{FuncId, Span, SymbolId};
use bonsai_idg::{PointKind, WsNodeId};
use bonsai_index::GlobalIndex;
use bonsai_taint::{
    compose_idg_seed_nodes, IdgSeedRequest, IdgTaintQuery, IdgTaintSource, IdgTaintTargets,
    IdgTaintTransfers, TaintedArg, TaintedCall, TaintedCallEdge, TaintedCallKind, TokenSet,
};
use bonsai_workspace::Workspace;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::time::Instant;

/// Everything a function-local summary query needs from the enclosing
/// sink-analysis scope.
pub(super) struct SinkLineageContext<'a> {
    pub ws: &'a Workspace,
    pub global: &'a GlobalIndex,
    pub idg: &'a bonsai_idg::IdgQueryService,
    pub call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    pub transfers: IdgTaintTransfers<'a>,
    pub relevance: &'a bonsai_idg::IdgTargetRelevance,
    pub caches: &'a InterTaintCaches,
    pub sink_matches: &'a [RuleMatch],
    pub sink_indices_by_func: &'a AHashMap<FuncId, Vec<usize>>,
}

/// One entering value of a function.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum LineageEntry {
    /// Every place the function owns: the seed of an entry point.
    Origin,
    /// One formal parameter, by position.
    Param(u32),
    /// The reads of one place that the projected heap feeds from another
    /// function's tainted write.
    Read(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LineageKey {
    func: FuncId,
    entry: LineageEntry,
}

impl LineageKey {
    fn order(&self) -> (u32, &LineageEntry) {
        (self.func.raw(), &self.entry)
    }
}

/// How taint leaves one entering value for another function's entering
/// value.
#[derive(Clone, Debug)]
enum EdgeEvidence {
    /// A tainted argument at a resolved call site.
    Call { call: TaintedCall, arg_index: usize },
    /// A tainted write the projected heap joins to a read elsewhere.
    Heap { storage: String, read_span: Span },
}

/// The exact facts one function-local closure produced.
#[derive(Default)]
struct LineageSummary {
    /// `(callee, argument index, call)` for every tainted argument at a call
    /// the call graph resolves to an admitted callee.
    calls: Vec<(FuncId, usize, TaintedCall)>,
    /// Sink matches inside the function that the closure reached.
    sinks: Vec<(usize, TaintedCall)>,
    /// Read nodes in other admitted functions that the projected heap feeds
    /// from a write the closure tainted.
    heap_targets: Vec<WsNodeId>,
}

/// The parameter nodes of one function, by declared position.
fn param_nodes(context: &SinkLineageContext<'_>, func: FuncId) -> Vec<(String, Vec<WsNodeId>)> {
    let mut params: Vec<(String, Vec<WsNodeId>)> = context
        .global
        .decl_of(SymbolId::new(func.raw()))
        .map(|decl| {
            decl.params
                .iter()
                .filter(|param| !param.is_empty())
                .map(|param| (param.clone(), Vec::new()))
                .collect()
        })
        .unwrap_or_default();
    if params.is_empty() {
        return params;
    }
    for node in context.idg.nodes_of_func(func) {
        let Some(point) = context.idg.resolve_point(node) else {
            continue;
        };
        if point.func != func || point.kind != PointKind::Param {
            continue;
        }
        if let Some((_, nodes)) = params.iter_mut().find(|(name, _)| *name == point.name) {
            nodes.push(node);
        }
    }
    params
}

/// Run one function-local closure and read its exact boundary facts.
fn summarize_entry(
    context: &SinkLineageContext<'_>,
    func: FuncId,
    tokens: &TokenSet,
    seed_nodes: &[WsNodeId],
    callees_by_span: &AHashMap<Span, Vec<FuncId>>,
    admitted: &AHashSet<FuncId>,
) -> LineageSummary {
    let mut summary = LineageSummary::default();
    if seed_nodes.is_empty() {
        return summary;
    }
    let corridor: AHashSet<FuncId> = AHashSet::from([func]);
    let targets = IdgTaintTargets {
        nodes: None,
        funcs: None,
        lineage_funcs: Some(&corridor),
        relevance: Some(context.relevance),
    };
    let (graph, closure_nodes) = bonsai_taint::entry_taint_graph_with_closure_from_idg_query(
        IdgTaintQuery::semantic(
            IdgTaintSource::precomposed(func, tokens, seed_nodes),
            context.ws.db(),
            context.idg,
        )
        .with_global_index(context.global)
        .with_transfers(context.transfers)
        .with_targets(targets)
        .with_caches(context.caches),
    );
    let sink_indices = context.sink_indices_by_func.get(&func);
    for call in &graph.tainted_calls {
        if call.caller != func || call.kind != TaintedCallKind::Call {
            continue;
        }
        if let Some(sink_indices) = sink_indices {
            for &sink_index in sink_indices {
                if tainted_call_matches_sink(call, &context.sink_matches[sink_index]) {
                    summary.sinks.push((sink_index, call.clone()));
                }
            }
        }
        let Some(callees) = callees_by_span.get(&call.call_span) else {
            continue;
        };
        for callee in callees {
            if !admitted.contains(callee) {
                continue;
            }
            for arg in &call.tainted_args {
                summary.calls.push((*callee, arg.index, call.clone()));
            }
        }
    }
    for node in closure_nodes {
        let Some(point) = context.idg.resolve_point(node) else {
            continue;
        };
        if point.func != func || point.kind != PointKind::Write {
            continue;
        }
        for target in context.idg.projected_heap_targets(node) {
            let Some(target_point) = context.idg.resolve_point(target) else {
                continue;
            };
            if target_point.func != func && admitted.contains(&target_point.func) {
                summary.heap_targets.push(target);
            }
        }
    }
    summary.heap_targets.sort_unstable();
    summary.heap_targets.dedup();
    summary
}

fn callees_by_span(
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    func: FuncId,
) -> AHashMap<Span, Vec<FuncId>> {
    let mut by_span: AHashMap<Span, Vec<FuncId>> = AHashMap::new();
    for edge in call_graph.callees_of(func) {
        let callees = by_span.entry(edge.span).or_default();
        if !callees.contains(&edge.to) {
            callees.push(edge.to);
        }
    }
    for callees in by_span.values_mut() {
        callees.sort_unstable_by_key(|callee| callee.raw());
    }
    by_span
}

/// The entry points of the admitted lineage call graph: admitted functions
/// with no admitted caller, plus every member of a call cycle no such entry
/// point reaches.
pub(super) fn sink_lineage_roots(
    admitted_funcs: &[FuncId],
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
) -> Vec<FuncId> {
    let admitted: AHashSet<FuncId> = admitted_funcs.iter().copied().collect();
    let mut roots: Vec<FuncId> = admitted_funcs
        .iter()
        .copied()
        .filter(|func| {
            !call_graph
                .callers_of(*func)
                .any(|edge| edge.from != *func && admitted.contains(&edge.from))
        })
        .collect();
    let mut reached: AHashSet<FuncId> = roots.iter().copied().collect();
    let mut pending: Vec<FuncId> = roots.clone();
    while let Some(func) = pending.pop() {
        for edge in call_graph.callees_of(func) {
            if admitted.contains(&edge.to) && reached.insert(edge.to) {
                pending.push(edge.to);
            }
        }
    }
    roots.extend(
        admitted_funcs
            .iter()
            .copied()
            .filter(|func| !reached.contains(func)),
    );
    roots.sort_unstable_by_key(|func| func.raw());
    roots.dedup();
    roots
}

struct SummaryGraph {
    keys: Vec<LineageKey>,
    index: AHashMap<LineageKey, u32>,
    /// `(source node, evidence)` per target node, in source order.
    incoming: Vec<Vec<(u32, EdgeEvidence)>>,
    /// `(node, terminal call)` per sink index.
    sinks: BTreeMap<usize, Vec<(u32, TaintedCall)>>,
}

impl SummaryGraph {
    fn node(&mut self, key: LineageKey) -> u32 {
        if let Some(&id) = self.index.get(&key) {
            return id;
        }
        let id = u32::try_from(self.keys.len()).expect("summary graph node count fits u32");
        self.keys.push(key.clone());
        self.index.insert(key, id);
        self.incoming.push(Vec::new());
        id
    }
}

/// Run `work` on the bounded lineage pool when one exists.
fn with_pool<T: Send>(pool: Option<&rayon::ThreadPool>, work: impl FnOnce() -> T + Send) -> T {
    match pool {
        Some(pool) => pool.install(work),
        None => work(),
    }
}

/// Group heap-fed read nodes by the reading function and place name: each
/// group is one `Read` entry, seeded by exactly those nodes.
fn queue_heap_targets(
    context: &SinkLineageContext<'_>,
    targets: &[WsNodeId],
    pending_reads: &mut AHashMap<LineageKey, Vec<WsNodeId>>,
    read_spans: &mut AHashMap<LineageKey, Span>,
) {
    for target in targets {
        let Some(point) = context.idg.resolve_point(*target) else {
            continue;
        };
        let key = LineageKey {
            func: point.func,
            entry: LineageEntry::Read(point.name),
        };
        let span = read_spans.entry(key.clone()).or_insert(point.span);
        if point.span.start < span.start {
            *span = point.span;
        }
        pending_reads.entry(key).or_default().push(*target);
    }
}

/// Compile every summary, compose the graph, and materialise one route per
/// sink endpoint and direct feeder.
pub(super) fn compile_sink_routes<F>(
    context: &SinkLineageContext<'_>,
    admitted_funcs: &[FuncId],
    on_progress: &mut F,
) -> Vec<(SinkEndpointKey, SinkAnalysisFlow)>
where
    F: FnMut(AnalysisProgress),
{
    let started = Instant::now();
    let admitted: AHashSet<FuncId> = admitted_funcs.iter().copied().collect();
    let roots: AHashSet<FuncId> = sink_lineage_roots(admitted_funcs, context.call_graph)
        .into_iter()
        .collect();
    let worker_count = source_analysis_worker_count();
    let pool = (worker_count > 1)
        .then(|| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(worker_count)
                .thread_name(|index| format!("bonsai-sink-lineage-{index}"))
                .stack_size(bonsai_common::compiler_worker_stack_bytes())
                .build()
                .ok()
        })
        .flatten();
    let batch = (worker_count * 16).max(1);
    let mut summaries: Vec<(LineageKey, LineageSummary)> = Vec::new();
    let mut pending_reads: AHashMap<LineageKey, Vec<WsNodeId>> = AHashMap::new();
    let mut read_done: AHashSet<LineageKey> = AHashSet::new();
    let mut read_spans: AHashMap<LineageKey, Span> = AHashMap::new();

    // Pass 1: every parameter of every admitted function, plus every place of
    // an entry point.
    on_progress(AnalysisProgress::PhaseStarted {
        label: "compiling sink lineage summaries",
        total: admitted_funcs.len() as u64,
    });
    for chunk in admitted_funcs.chunks(batch) {
        let results = with_pool(pool.as_ref(), || {
            chunk
                .par_iter()
                .map(|&func| {
                    let params = param_nodes(context, func);
                    let callees = callees_by_span(context.call_graph, func);
                    let mut entries: Vec<(LineageEntry, LineageSummary)> = Vec::new();
                    for (index, (name, nodes)) in params.iter().enumerate() {
                        let tokens: TokenSet = [name.clone()].into_iter().collect();
                        let summary = summarize_entry(context, func, &tokens, nodes, &callees, &admitted);
                        if !summary.calls.is_empty()
                            || !summary.sinks.is_empty()
                            || !summary.heap_targets.is_empty()
                        {
                            entries.push((LineageEntry::Param(index as u32), summary));
                        }
                    }
                    if roots.contains(&func) {
                        let mut tokens: TokenSet = context
                            .idg
                            .read_or_write_names_of_func(func)
                            .into_iter()
                            .collect();
                        tokens.extend(params.iter().map(|(name, _)| name.clone()));
                        let seeds = compose_idg_seed_nodes(
                            IdgSeedRequest::rule_match(func, &tokens, None, &[]),
                            context.global,
                            context.idg,
                        );
                        let summary = summarize_entry(context, func, &tokens, &seeds, &callees, &admitted);
                        entries.push((LineageEntry::Origin, summary));
                    }
                    (func, entries)
                })
                .collect::<Vec<_>>()
        });
        for (func, entries) in results {
            for (entry, summary) in entries {
                queue_heap_targets(
                    context,
                    &summary.heap_targets,
                    &mut pending_reads,
                    &mut read_spans,
                );
                summaries.push((LineageKey { func, entry }, summary));
            }
            on_progress(AnalysisProgress::PhaseTicked);
        }
    }
    on_progress(AnalysisProgress::PhaseFinished);

    // Pass 2: heap-fed reads, to a fixed point over the reads each new
    // summary's tainted writes reach.
    loop {
        let mut work: Vec<(LineageKey, Vec<WsNodeId>)> = pending_reads
            .drain()
            .filter(|(key, _)| !read_done.contains(key))
            .collect();
        if work.is_empty() {
            break;
        }
        work.sort_by(|(left, _), (right, _)| left.order().cmp(&right.order()));
        for (key, nodes) in &mut work {
            nodes.sort_unstable();
            nodes.dedup();
            read_done.insert(key.clone());
        }
        on_progress(AnalysisProgress::PhaseStarted {
            label: "tracing heap-fed sink lineage reads",
            total: work.len() as u64,
        });
        for chunk in work.chunks(batch) {
            let results = with_pool(pool.as_ref(), || {
                chunk
                    .par_iter()
                    .map(|(key, nodes)| {
                        let callees = callees_by_span(context.call_graph, key.func);
                        let LineageEntry::Read(name) = &key.entry else {
                            unreachable!("heap-fed entries are reads");
                        };
                        let tokens: TokenSet = [name.clone()].into_iter().collect();
                        let summary = summarize_entry(context, key.func, &tokens, nodes, &callees, &admitted);
                        (key.clone(), summary)
                    })
                    .collect::<Vec<_>>()
            });
            for (key, summary) in results {
                queue_heap_targets(
                    context,
                    &summary.heap_targets,
                    &mut pending_reads,
                    &mut read_spans,
                );
                summaries.push((key, summary));
                on_progress(AnalysisProgress::PhaseTicked);
            }
        }
        on_progress(AnalysisProgress::PhaseFinished);
    }

    // Compose the graph.
    let mut graph = SummaryGraph {
        keys: Vec::new(),
        index: AHashMap::new(),
        incoming: Vec::new(),
        sinks: BTreeMap::new(),
    };
    summaries.sort_by(|(left, _), (right, _)| left.order().cmp(&right.order()));
    for (key, _) in &summaries {
        graph.node(key.clone());
    }
    for (key, summary) in summaries {
        let source = graph.index[&key];
        for (callee, arg_index, call) in summary.calls {
            let target_key = LineageKey {
                func: callee,
                entry: LineageEntry::Param(arg_index as u32),
            };
            let Some(&target) = graph.index.get(&target_key) else {
                continue;
            };
            graph.incoming[target as usize].push((source, EdgeEvidence::Call { call, arg_index }));
        }
        let mut heap_keys: Vec<LineageKey> = summary
            .heap_targets
            .iter()
            .filter_map(|target| {
                let point = context.idg.resolve_point(*target)?;
                Some(LineageKey {
                    func: point.func,
                    entry: LineageEntry::Read(point.name),
                })
            })
            .collect();
        heap_keys.sort_by(|left, right| left.order().cmp(&right.order()));
        heap_keys.dedup();
        for target_key in heap_keys {
            let Some(&target) = graph.index.get(&target_key) else {
                continue;
            };
            let LineageEntry::Read(storage) = &target_key.entry else {
                continue;
            };
            let Some(read_span) = read_spans.get(&target_key).copied() else {
                continue;
            };
            graph.incoming[target as usize].push((
                source,
                EdgeEvidence::Heap {
                    storage: storage.clone(),
                    read_span,
                },
            ));
        }
        for (sink_index, call) in summary.sinks {
            graph.sinks.entry(sink_index).or_default().push((source, call));
        }
    }
    for edges in &mut graph.incoming {
        edges.sort_by_key(|(source, _)| *source);
    }
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "sink lineage summaries: admitted={} roots={} nodes={} edges={} sink_hits={} elapsed={:.3}s",
        admitted_funcs.len(),
        roots.len(),
        graph.keys.len(),
        graph.incoming.iter().map(Vec::len).sum::<usize>(),
        graph.sinks.values().map(Vec::len).sum::<usize>(),
        started.elapsed().as_secs_f64()
    );

    // Materialise one route per sink endpoint and direct feeder.
    on_progress(AnalysisProgress::PhaseStarted {
        label: "tracing upstream sink routes",
        total: graph.sinks.len() as u64,
    });
    let route_started = Instant::now();
    let mut flows: Vec<(SinkEndpointKey, SinkAnalysisFlow)> = Vec::new();
    let mut origin_sites: AHashMap<FuncId, (String, String, u32)> = AHashMap::new();
    for (sink_index, hits) in &graph.sinks {
        let sink = &context.sink_matches[*sink_index];
        let sink_key = sink_rule_match_key(sink);
        let mut routes_by_feeder: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for (hit, _) in hits {
            let hit_key = &graph.keys[*hit as usize];
            if hit_key.entry == LineageEntry::Origin {
                routes_by_feeder
                    .entry(hit_key.func.raw())
                    .or_insert_with(|| vec![*hit]);
            }
            for (feeder, _) in &graph.incoming[*hit as usize] {
                let feeder_func = graph.keys[*feeder as usize].func.raw();
                if routes_by_feeder.contains_key(&feeder_func) {
                    continue;
                }
                if let Some(mut path) = route_to_origin(&graph, *feeder) {
                    path.push(*hit);
                    routes_by_feeder.insert(feeder_func, path);
                }
            }
        }
        for (_, path) in routes_by_feeder {
            let hit = *path.last().expect("route ends at the sink hit");
            let terminal = hits
                .iter()
                .find(|(node, _)| *node == hit)
                .map(|(_, call)| call)
                .expect("sink hit call");
            let Some(flow) = render_route(context, &graph, &path, terminal, &mut origin_sites) else {
                continue;
            };
            flows.push((sink_key.clone(), flow));
        }
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "sink lineage routes: sinks_reached={} routes={} elapsed={:.3}s",
        graph.sinks.len(),
        flows.len(),
        route_started.elapsed().as_secs_f64()
    );
    flows
}

/// Walk backward from `start` to an entry-point origin, always taking the
/// smallest admissible predecessor. Returns the path origin-first.
fn route_to_origin(graph: &SummaryGraph, start: u32) -> Option<Vec<u32>> {
    let mut path: Vec<u32> = vec![start];
    let mut on_path: AHashSet<u32> = AHashSet::from([start]);
    let mut current = start;
    loop {
        if graph.keys[current as usize].entry == LineageEntry::Origin {
            path.reverse();
            return Some(path);
        }
        let next = graph.incoming[current as usize]
            .iter()
            .map(|(source, _)| *source)
            .find(|source| !on_path.contains(source))?;
        on_path.insert(next);
        path.push(next);
        current = next;
    }
}

fn evidence_between(graph: &SummaryGraph, source: u32, target: u32) -> Option<&EdgeEvidence> {
    graph.incoming[target as usize]
        .iter()
        .find(|(from, _)| *from == source)
        .map(|(_, evidence)| evidence)
}

fn render_route(
    context: &SinkLineageContext<'_>,
    graph: &SummaryGraph,
    path: &[u32],
    terminal: &TaintedCall,
    origin_sites: &mut AHashMap<FuncId, (String, String, u32)>,
) -> Option<SinkAnalysisFlow> {
    let ws = context.ws;
    let global = context.global;
    let mut chain_funcs: Vec<FuncId> = Vec::with_capacity(path.len());
    for node in path {
        let func = graph.keys[*node as usize].func;
        if chain_funcs.last() != Some(&func) {
            chain_funcs.push(func);
        }
    }
    let mut records: Vec<TaintedCallEdge> = Vec::new();
    for pair in path.windows(2) {
        let (source, target) = (pair[0], pair[1]);
        let caller = graph.keys[source as usize].func;
        let callee = graph.keys[target as usize].func;
        let Some(evidence) = evidence_between(graph, source, target) else {
            continue;
        };
        let trace_id = records.len() as u64 + 1;
        let parent_trace_id = records.last().map(|record| record.trace_id);
        let record = match evidence {
            EdgeEvidence::Call { call, arg_index } => {
                let param_name = global
                    .decl_of(SymbolId::new(callee.raw()))
                    .and_then(|decl| decl.params.get(*arg_index).cloned())
                    .unwrap_or_default();
                let arg = call.tainted_args.iter().find(|arg| arg.index == *arg_index);
                TaintedCallEdge {
                    trace_id,
                    parent_trace_id,
                    caller,
                    callee,
                    call_span: call.call_span,
                    tainted_args: vec![TaintedArg {
                        index: *arg_index,
                        value_text: arg.map(|arg| arg.value_text.clone()).unwrap_or_default(),
                        param_name,
                        place: arg.and_then(|arg| arg.place.clone()),
                        source_names: arg.map(|arg| arg.source_names.clone()).unwrap_or_default(),
                    }],
                    edge_kind: bonsai_callgraph::EdgeKind::Direct,
                }
            }
            EdgeEvidence::Heap { storage, read_span } => TaintedCallEdge {
                trace_id,
                parent_trace_id,
                caller,
                callee,
                call_span: *read_span,
                tainted_args: vec![TaintedArg {
                    index: 0,
                    value_text: storage.clone(),
                    param_name: storage.clone(),
                    place: Some(storage.clone()),
                    source_names: vec![storage.clone()],
                }],
                edge_kind: bonsai_callgraph::EdgeKind::Direct,
            },
        };
        records.push(record);
    }
    let chain_names = chain_names_for_path(ws, global, &chain_funcs)?;
    let record_refs: Vec<&TaintedCallEdge> = records.iter().collect();
    let taint_path = taint_path_for_lineage(ws, global, &record_refs, Some(terminal));
    let origin = chain_funcs.first().copied()?;
    let (origin_function, origin_file, origin_line) = origin_sites
        .entry(origin)
        .or_insert_with(|| sink_flow_origin(ws, global, origin))
        .clone();
    Some(SinkAnalysisFlow {
        flow_id: flow_id_for_taint_path(&chain_names, &taint_path),
        origin_function,
        origin_file,
        origin_line,
        chain_names,
        chain_funcs,
        taint_path,
        endpoint_only: false,
    })
}
