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
    source_analysis_worker_count, tainted_call_matches_sink, AnalysisProgress, InterTaintCaches,
    SinkAnalysisFlow, SinkEndpointKey,
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
    /// One exact read point fed by a projected-heap write. Different reads of
    /// the same spelling can occur on opposite sides of an overwrite; they
    /// are not interchangeable entering values.
    Read { node: WsNodeId, name: String },
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
    Call { record: TaintedCallEdge },
    /// A tainted write the projected heap joins to a read elsewhere.
    Heap { storage: String, read_span: Span },
}

/// The exact facts one function-local closure produced.
#[derive(Default)]
struct LineageSummary {
    /// `(callee, argument index, call)` for every tainted argument at a call
    /// the call graph resolves to an admitted callee.
    calls: Vec<(u32, TaintedCallEdge)>,
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
    calls: &AHashMap<Span, bonsai_lang_api::CompilerCallAttribution>,
    boundaries: &bonsai_idg::IdgCrossCallLookup,
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
    }
    // The IDG stitch owns actual-to-formal binding, including receivers and
    // named arguments. A callgraph edge plus an argument ordinal is not a
    // parameter binding and must never be used to compose these summaries.
    let mut seen = AHashSet::new();
    for edge in boundaries.edges_for_reachable_nodes(&closure_nodes) {
        if edge.caller != func
            || !admitted.contains(&edge.callee)
            || edge.relation != bonsai_idg::CrossCallRelation::Argument
            || edge.param_idx == u32::MAX
            || !seen.insert(*edge)
        {
            continue;
        }
        let Some(call) = calls.get(&edge.call_span) else {
            continue;
        };
        let Some(callee) = context.global.decl_of(SymbolId::new(edge.callee.raw())) else {
            continue;
        };
        let Some(param_name) = callee.params.get(edge.param_idx as usize) else {
            continue;
        };
        let argument_index = if edge.arg_idx != u32::MAX {
            Some(edge.arg_idx as usize)
        } else if callee.receiver_param_index == Some(edge.param_idx as usize) {
            Some(usize::MAX)
        } else {
            call.args.iter().enumerate().find_map(|(index, argument)| {
                let mapped = argument
                    .name
                    .as_deref()
                    .and_then(|name| {
                        bonsai_lang_api::named_argument_parameter_index(
                            name,
                            callee.params.iter().map(String::as_str),
                            callee.receiver_param_index,
                        )
                    })
                    .unwrap_or_else(|| {
                        bonsai_lang_api::explicit_argument_parameter_index(index, callee.receiver_param_index)
                    });
                (mapped == edge.param_idx as usize).then_some(index)
            })
        };
        let Some(index) = argument_index else {
            continue;
        };
        let arg = if index == usize::MAX {
            let Some(receiver) = call.receiver.as_ref() else {
                continue;
            };
            TaintedArg {
                index,
                value_text: receiver.clone(),
                param_name: param_name.clone(),
                place: Some(receiver.clone()),
                source_names: call.receiver_source_names.clone(),
            }
        } else {
            let Some(argument) = call.args.get(index) else {
                continue;
            };
            TaintedArg {
                index,
                value_text: argument.value_text.clone(),
                param_name: param_name.clone(),
                place: argument.place.clone(),
                source_names: argument.source_names.clone(),
            }
        };
        summary.calls.push((
            edge.param_idx,
            TaintedCallEdge {
                trace_id: 0,
                parent_trace_id: None,
                caller: func,
                callee: edge.callee,
                call_span: edge.call_span,
                tainted_args: vec![arg],
                edge_kind: edge.call_kind,
            },
        ));
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

fn calls_by_span(
    context: &SinkLineageContext<'_>,
    func: FuncId,
) -> AHashMap<Span, bonsai_lang_api::CompilerCallAttribution> {
    let Some(decl) = context.global.decl_of(SymbolId::new(func.raw())) else {
        return AHashMap::new();
    };
    context
        .ws
        .db()
        .compiler_function_attributions_uncached(decl.span.file, &[decl.span])
        .into_iter()
        .flatten()
        .flat_map(|function| function.calls)
        .map(|call| (call.span, call))
        .collect()
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

/// Queue each exact heap-fed read point. A later summary can discover another
/// read of the same place without that point being lost to a name-level done set.
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
            entry: LineageEntry::Read {
                node: *target,
                name: point.name,
            },
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
    context.idg.warm_contextual_query_runtime();
    let admitted: AHashSet<FuncId> = admitted_funcs.iter().copied().collect();
    let boundaries = context.idg.cross_call_lookup_for_funcs(&admitted);
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
                    let calls = calls_by_span(context, func);
                    let mut entries: Vec<(LineageEntry, LineageSummary)> = Vec::new();
                    for (index, (name, nodes)) in params.iter().enumerate() {
                        let tokens: TokenSet = [name.clone()].into_iter().collect();
                        let summary =
                            summarize_entry(context, func, &tokens, nodes, &calls, &boundaries, &admitted);
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
                        let summary =
                            summarize_entry(context, func, &tokens, &seeds, &calls, &boundaries, &admitted);
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
                        let calls = calls_by_span(context, key.func);
                        let LineageEntry::Read { name, .. } = &key.entry else {
                            unreachable!("heap-fed entries are reads");
                        };
                        let tokens: TokenSet = [name.clone()].into_iter().collect();
                        let summary = summarize_entry(
                            context,
                            key.func,
                            &tokens,
                            nodes,
                            &calls,
                            &boundaries,
                            &admitted,
                        );
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
        for (param_index, record) in summary.calls {
            let target_key = LineageKey {
                func: record.callee,
                entry: LineageEntry::Param(param_index),
            };
            let Some(&target) = graph.index.get(&target_key) else {
                continue;
            };
            graph.incoming[target as usize].push((source, EdgeEvidence::Call { record }));
        }
        let mut heap_keys: Vec<LineageKey> = summary
            .heap_targets
            .iter()
            .filter_map(|target| {
                let point = context.idg.resolve_point(*target)?;
                Some(LineageKey {
                    func: point.func,
                    entry: LineageEntry::Read {
                        node: *target,
                        name: point.name,
                    },
                })
            })
            .collect();
        heap_keys.sort_by(|left, right| left.order().cmp(&right.order()));
        heap_keys.dedup();
        for target_key in heap_keys {
            let Some(&target) = graph.index.get(&target_key) else {
                continue;
            };
            let LineageEntry::Read { name: storage, .. } = &target_key.entry else {
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
    let witnesses = origin_witnesses(&graph);
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
                if let Some(mut path) = route_to_origin(&witnesses, *feeder) {
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

/// Propagate origin witnesses through the already compiled summary graph.
/// This is a finite compiler graph fixed point, not path enumeration or name
/// search. Each admitted node receives one rooted, acyclic proof. A dead-end
/// or cyclic predecessor must not mask a different origin-reaching edge.
fn origin_witnesses(graph: &SummaryGraph) -> Vec<Option<u32>> {
    let mut outgoing = vec![Vec::new(); graph.keys.len()];
    for (target, incoming) in graph.incoming.iter().enumerate() {
        for (source, _) in incoming {
            outgoing[*source as usize].push(target as u32);
        }
    }
    let mut witnesses = vec![None; graph.keys.len()];
    let mut pending = Vec::new();
    for (node, key) in graph.keys.iter().enumerate().rev() {
        if key.entry == LineageEntry::Origin {
            witnesses[node] = Some(node as u32);
            pending.push(node as u32);
        }
    }
    while let Some(source) = pending.pop() {
        for &target in outgoing[source as usize].iter().rev() {
            if witnesses[target as usize].is_none() {
                witnesses[target as usize] = Some(source);
                pending.push(target);
            }
        }
    }
    witnesses
}

fn route_to_origin(witnesses: &[Option<u32>], start: u32) -> Option<Vec<u32>> {
    let mut path = vec![start];
    let mut current = start;
    loop {
        let previous = witnesses[current as usize]?;
        if previous == current {
            path.reverse();
            return Some(path);
        }
        path.push(previous);
        current = previous;
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
    let chain_names = chain_names_for_path(ws, global, &chain_funcs)?;
    let names = chain_funcs
        .iter()
        .copied()
        .zip(chain_names.iter().cloned())
        .collect();
    let mut taint_path = Vec::new();
    for pair in path.windows(2) {
        let (source, target) = (pair[0], pair[1]);
        let evidence = evidence_between(graph, source, target)?;
        match evidence {
            EdgeEvidence::Call { record } => {
                if let Some(step) = super::propagation_step_for_edge(ws, global, record, &names) {
                    taint_path.push(step);
                }
            }
            EdgeEvidence::Heap { storage, read_span } => {
                let (file, line, column) = super::resolve_span_location(ws, *read_span);
                taint_path.push(super::TaintPropagationStep {
                    caller: super::path_display_name(global, &names, graph.keys[source as usize].func),
                    callee: super::path_display_name(global, &names, graph.keys[target as usize].func),
                    file,
                    line,
                    column,
                    storage_transfer: Some(storage.clone()),
                    tainted_args: Vec::new(),
                });
            }
        }
    }
    taint_path.push(super::propagation_step_for_terminal_call(
        ws, global, terminal, &names,
    ));
    let taint_path = super::normalize_taint_path(taint_path);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_proof_survives_dead_end_and_cyclic_predecessors() {
        let mut graph = SummaryGraph {
            keys: Vec::new(),
            index: AHashMap::new(),
            incoming: Vec::new(),
            sinks: BTreeMap::new(),
        };
        for (func, entry) in [
            (0, LineageEntry::Param(0)),
            (1, LineageEntry::Param(0)),
            (2, LineageEntry::Origin),
            (3, LineageEntry::Param(0)),
            (4, LineageEntry::Param(0)),
        ] {
            graph.node(LineageKey {
                func: FuncId::new(func),
                entry,
            });
        }
        let evidence = || EdgeEvidence::Heap {
            storage: "value".into(),
            read_span: Span::new(bonsai_common::FileId::new(0), 0, 1),
        };
        graph.incoming[0] = vec![(1, evidence()), (3, evidence())];
        graph.incoming[3] = vec![(0, evidence()), (2, evidence())];
        graph.incoming[4] = vec![(4, evidence())];
        let witnesses = origin_witnesses(&graph);
        assert_eq!(route_to_origin(&witnesses, 0), Some(vec![2, 3, 0]));
        assert_eq!(route_to_origin(&witnesses, 1), None);
        assert_eq!(route_to_origin(&witnesses, 4), None);
    }

    #[test]
    fn separate_heap_reads_of_one_spelling_are_distinct_entering_values() {
        let first = LineageKey {
            func: FuncId::new(0),
            entry: LineageEntry::Read {
                node: WsNodeId(1),
                name: "object.value".into(),
            },
        };
        let later = LineageKey {
            func: FuncId::new(0),
            entry: LineageEntry::Read {
                node: WsNodeId(2),
                name: "object.value".into(),
            },
        };
        assert_ne!(first, later);
        assert!(!AHashSet::from([first]).contains(&later));
    }
}
