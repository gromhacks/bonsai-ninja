//! Exact source-to-sink semantic graph planning and execution.

use super::{
    apply_configured_transfer_fixpoint, build_idg_service_for_rulepack_for_files,
    call_result_passthroughs_from_rulepack_for_languages,
    clean_output_overwrites_from_rulepack_for_languages, compose_idg_seed_nodes, find_call_event_at,
    finish_taint_cache_write_through, func_id_for_match, idg_call_result_passthrough_specs,
    idg_transfer_options_from_rulepack_shapes, mpsc, output_arg_flows_from_rulepack_for_languages,
    output_arg_names_for_match, receiver_state_propagations_from_rulepack_for_languages,
    rule_match_kind_is_param, seed_idg_service_for_rulepack_for_files, source_anchor_for_rule_match,
    source_callback_args_from_rulepack_for_languages, source_output_args_from_rulepack_for_languages,
    source_seed_set, span_contains, spans_overlap, spans_share_enclosing_loop, symbolic_field_languages,
    symbolic_field_source_funcs, taint_cache, AHashMap, AHashSet, AnalysisProgress, Arc, BTreeMap,
    CleanOverwritePolicy, DeclKind, Duration, FileId, FindingWithChain, FlowEvent, FuncId, GlobalIndex,
    IdgSeedRequest, InterTaintCaches, InterTaintConfig, MatchKind, MatchOrigin, OnceLock, Precision,
    ResolutionCoverage, RuleMatch, Rulepack, SourceMatchDedupeKey, SourceMatchDedupeValue, Span, SymbolId,
    TokenSet, Workspace, WorkspaceCallableCache,
};

/// Build chain-aware findings: source rule matches → propagated taint
/// → sink rule matches → assembled findings with stable IDs.
///
/// ## Pipeline phases
///
/// 1. **Resolve matcher hits to FuncIds by span** — per-FuncId
///    sanitizer and sink attribution avoids cross-bridging same-named
///    functions or methods in the same file.
/// 2. **Group sanitizers + sinks by enclosing FuncId** — one
///    `Vec<RuleMatch>` per function, ready for chain-hop attribution.
/// 3. **Per-source seeding** (`source_work` building) — select exact
///    source targets from adapter-emitted AST flow events via
///    `source_seed_set` + `collect_source_seed_targets`, then map them
///    through the one canonical IDG seed composer.
///    `security_text_matches_source_strict` prevents receiver
///    substrings from tainting sibling members.
/// 4. **Declarative transfer shapes** — source output arguments,
///    callbacks, clean overwrites, and external summaries come from the
///    rulepack and are folded into the configured IDG fingerprint.
/// 5. **Run interprocedural taint per source** — `exact_source_seed_graph`
///    composes AST/resolver-derived IDG seeds and computes the complete
///    target-restricted graph closure.
/// 6. **Sink matching** — iterate `tainted_calls`, prefer
///    span-equality match for multi-sink-in-same-fn attribution,
///    apply sink-rule constraints with single-call `InterTaintView`.
/// 7. **Chain assembly** — use propagation lineage IDs recorded by
///    the taint engine. If lineage evidence is missing, skip the
///    finding rather than fabricating a call-graph-only path. Precision
///    is met across the chosen edges, then `flow_id` / `group_id`
///    include concrete call sites. Sanitizer attachment by chain hop
///    with data-flow gate
///    (`sanitizer_call_overlaps_tainted_call` or a sanitizer nested
///    directly inside a tainted sink argument).
/// 8. **Trust-aware severity** — `local`/`inferred` source tier
///    demotes severity one level (Critical → High, etc.).
///
/// `combine_findings_by_source_flow` is the post-pipeline that groups
/// by `(language, group_id, flow_id, chain_display, sink_rule_id)`,
/// merges severity/tag/CWE/sanitizers/status, and recomputes
/// `finding_id` over the combined source/sink token sets.
#[derive(Default)]
pub(super) struct ChainBuildResult {
    pub(super) findings: Vec<FindingWithChain>,
    pub(super) resolution: Option<ResolutionCoverage>,
}

pub(super) struct ChainAnalysisRequest<'a, F> {
    pub(super) ws: &'a Workspace,
    pub(super) source_hits: &'a [RuleMatch],
    pub(super) sinks: &'a [RuleMatch],
    pub(super) sanitizers: &'a [RuleMatch],
    pub(super) pack: &'a Rulepack,
    pub(super) max_precision: Option<Precision>,
    pub(super) taint_graph_resident_cache_entries: Option<usize>,
    pub(super) factory_returns: &'a crate::matcher::FactoryReturns,
    pub(super) on_progress: &'a mut F,
}

struct ResolvedMatchSites<'a> {
    sanitizers_by_func: AHashMap<FuncId, Vec<&'a RuleMatch>>,
    sinks_by_func: AHashMap<FuncId, Vec<&'a RuleMatch>>,
}

impl<'a> ResolvedMatchSites<'a> {
    fn resolve(ws: &Workspace, sanitizers: &'a [RuleMatch], sinks: &'a [RuleMatch]) -> Self {
        let mut sanitizers_by_func = AHashMap::new();
        for sanitizer in sanitizers {
            if let Some(func) = func_id_for_match(ws, sanitizer) {
                sanitizers_by_func
                    .entry(func)
                    .or_insert_with(Vec::new)
                    .push(sanitizer);
            }
        }
        let mut sinks_by_func = AHashMap::new();
        for sink in sinks {
            if let Some(func) = func_id_for_match(ws, sink) {
                sinks_by_func.entry(func).or_insert_with(Vec::new).push(sink);
            }
        }
        Self {
            sanitizers_by_func,
            sinks_by_func,
        }
    }
}

pub(super) struct SourceWorkItem<'a> {
    pub(super) source: &'a RuleMatch,
    pub(super) source_func: FuncId,
    pub(super) seeds: TokenSet,
}

struct SourceWorkPlan<'a> {
    items: Vec<SourceWorkItem<'a>>,
    groups: AHashMap<FuncId, Vec<usize>>,
}

pub(super) struct ScheduledSourceGroup {
    pub(super) src_func_id: FuncId,
    pub(super) indices: Arc<Vec<usize>>,
    pub(super) corridor: Arc<SourceSinkCorridor>,
}

fn plan_source_work<'a>(
    ws: &Workspace,
    global: &GlobalIndex,
    pack: &Rulepack,
    source_hits: &'a [RuleMatch],
) -> SourceWorkPlan<'a> {
    struct SourceForFunction<'a> {
        index: usize,
        source: &'a RuleMatch,
    }

    let mut best_sources: AHashMap<SourceMatchDedupeKey, SourceMatchDedupeValue<'_>> = AHashMap::new();
    for (index, source) in source_hits.iter().enumerate() {
        let Some(source_func) = func_id_for_match(ws, source) else {
            continue;
        };
        let specificity = global
            .decl_of(SymbolId::new(source_func.raw()))
            .map(|decl| decl.span.len())
            .unwrap_or(u64::MAX);
        let key = (
            source.rule_id.clone(),
            source.file.clone(),
            source.span.start,
            source.span.end,
            source.match_text.clone(),
        );
        match best_sources.get_mut(&key) {
            Some(existing)
                if specificity < existing.3 || (specificity == existing.3 && index < existing.0) =>
            {
                *existing = (index, source, source_func, specificity);
            }
            Some(_) => {}
            None => {
                best_sources.insert(key, (index, source, source_func, specificity));
            }
        }
    }

    let mut sources_by_func: AHashMap<FuncId, Vec<SourceForFunction<'_>>> = AHashMap::new();
    for (_, (index, source, source_func, _)) in best_sources {
        sources_by_func
            .entry(source_func)
            .or_default()
            .push(SourceForFunction { index, source });
    }
    let mut ordered_groups: Vec<_> = sources_by_func.into_iter().collect();
    ordered_groups.sort_by_key(|(func, sources)| {
        (
            global
                .declaring_file(SymbolId::new(func.raw()))
                .map_or(u32::MAX, FileId::raw),
            sources
                .iter()
                .map(|source| source.index)
                .min()
                .unwrap_or(usize::MAX),
        )
    });

    let mut indexed_items = Vec::new();
    let mut active_file = None;
    let mut active_index = None;
    for (source_func, sources) in ordered_groups {
        let Some(file) = global.declaring_file(SymbolId::new(source_func.raw())) else {
            continue;
        };
        if active_file != Some(file) {
            active_index = ws.exact_decl_index(file);
            active_file = Some(file);
        }
        let Some(source_decl) = active_index.as_ref().and_then(|index| {
            index
                .defs
                .iter()
                .find(|decl| decl.symbol.raw() == source_func.raw())
        }) else {
            continue;
        };
        for source in sources {
            let seeds = source_seed_set(pack, source.source, source_decl);
            let anchor = source_anchor_for_rule_match(pack, source.source);
            if seeds.is_empty() && anchor.is_none() {
                continue;
            }
            indexed_items.push((
                source.index,
                SourceWorkItem {
                    source: source.source,
                    source_func,
                    seeds,
                },
            ));
        }
    }
    indexed_items.sort_by_key(|(index, _)| *index);

    let mut items = Vec::with_capacity(indexed_items.len());
    let mut groups: AHashMap<FuncId, Vec<usize>> = AHashMap::new();
    for (_, item) in indexed_items {
        let index = items.len();
        groups.entry(item.source_func).or_default().push(index);
        items.push(item);
    }
    SourceWorkPlan { items, groups }
}

struct TransferPlan {
    languages: AHashSet<String>,
    config: InterTaintConfig,
}

struct SemanticScopeRequest<'a> {
    ws: &'a Workspace,
    global: &'a GlobalIndex,
    source_funcs: &'a [FuncId],
    sink_funcs: &'a AHashSet<FuncId>,
    callback_targets: &'a AHashMap<FuncId, AHashSet<FuncId>>,
    call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    fallback_files: &'a [FileId],
    fallback_funcs: &'a [FuncId],
    max_precision: Option<Precision>,
    prefilter_enabled: bool,
}

struct SemanticScopePlan {
    callback_corridors: AHashMap<FuncId, Arc<SourceSinkCorridor>>,
    shared_corridors: SharedSourceSinkCorridors,
    files: Vec<FileId>,
    funcs: Vec<FuncId>,
}

enum SemanticGraphExecution {
    Partitioned,
    Shared(Arc<bonsai_idg::IdgQueryService>),
}

impl SemanticGraphExecution {
    fn is_partitioned(&self) -> bool {
        matches!(self, Self::Partitioned)
    }

    fn shared(&self) -> Option<&Arc<bonsai_idg::IdgQueryService>> {
        match self {
            Self::Partitioned => None,
            Self::Shared(service) => Some(service),
        }
    }
}

struct SemanticGraphCompilationRequest<'a> {
    ws: &'a Workspace,
    pack: &'a Rulepack,
    transfer_languages: &'a AHashSet<String>,
    config: &'a InterTaintConfig,
    files: &'a [FileId],
    funcs: &'a [FuncId],
    call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
    partitioned: bool,
    source_group_count: usize,
    source_unit_count: usize,
}

struct CompiledSemanticGraph {
    execution: SemanticGraphExecution,
    cache_persist_started: bool,
}

fn compile_taint_semantic_graph<F>(
    request: SemanticGraphCompilationRequest<'_>,
    on_progress: &mut F,
) -> CompiledSemanticGraph
where
    F: FnMut(AnalysisProgress),
{
    let mut fingerprint_options = idg_transfer_options_from_rulepack_shapes(
        &request.config.clean_output_overwrites,
        &request.config.source_output_args,
        &request.config.source_callback_args,
        &request.config.output_arg_flows,
        &request.config.receiver_state_propagations,
    );
    fingerprint_options.symbolic_field_languages = symbolic_field_languages(request.ws, request.files);
    fingerprint_options.call_result_passthroughs =
        idg_call_result_passthrough_specs(&request.config.call_result_passthroughs);
    fingerprint_options.symbolic_field_forwarding = !fingerprint_options.symbolic_field_languages.is_empty();
    let taint_graph_fingerprint = taint_cache::scoped_config_fingerprint(
        request.pack,
        "taint-analysis",
        request.max_precision,
        request.files,
        request.funcs,
        fingerprint_options.semantic_fingerprint(),
    );
    let cache_report =
        taint_cache::prepare_workspace_cache(request.ws, "taint-analysis", taint_graph_fingerprint);
    on_progress(AnalysisProgress::Note {
        label: "taint-cache",
        detail: cache_report.detail(),
    });

    let execution = if request.partitioned {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "planning scoped semantic graph batches",
            total: 0,
        });
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "semantic graph source-unit streaming enabled funcs={} files={} source_groups={} units={}",
            request.funcs.len(),
            request.files.len(),
            request.source_group_count,
            request.source_unit_count
        );
        on_progress(AnalysisProgress::PhaseFinished);
        SemanticGraphExecution::Partitioned
    } else {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "building scoped semantic graph",
            total: 0,
        });
        let service = seed_idg_service_for_rulepack_for_files(
            request.ws,
            request.pack,
            request.transfer_languages,
            request.files,
            request.funcs,
            request.call_graph,
        );
        on_progress(AnalysisProgress::PhaseFinished);
        SemanticGraphExecution::Shared(service)
    };
    CompiledSemanticGraph {
        execution,
        cache_persist_started: cache_report.persist_started,
    }
}

struct ReachableTaintScopeRequest<'a, 'source> {
    ws: &'a Workspace,
    global: &'a Arc<GlobalIndex>,
    pack: &'a Rulepack,
    source_work: &'a [SourceWorkItem<'source>],
    source_groups: &'a AHashMap<FuncId, Vec<usize>>,
    sink_by_func: &'a AHashMap<FuncId, Vec<&'source RuleMatch>>,
    max_precision: Option<Precision>,
}

struct ReachableTaintScope {
    source_funcs: Vec<FuncId>,
    sink_funcs: AHashSet<FuncId>,
    callback_targets: AHashMap<FuncId, AHashSet<FuncId>>,
    source_groups: Vec<(FuncId, Vec<usize>)>,
    scheduling_total: u64,
    call_graph: bonsai_workspace::SourceReachableCallGraph,
    resolution: ResolutionCoverage,
}

fn compile_reachable_taint_scope<F>(
    request: ReachableTaintScopeRequest<'_, '_>,
    on_progress: &mut F,
) -> ReachableTaintScope
where
    F: FnMut(AnalysisProgress),
{
    let mut source_funcs: Vec<FuncId> = request.source_groups.keys().copied().collect();
    source_funcs.sort_by_key(|func| func.raw());
    let resolved_call_graph = request.ws.cached_resolved_call_graph();
    let callback_targets = configured_source_callback_targets_by_source(
        request.ws,
        request.source_work,
        request.pack,
        resolved_call_graph.as_ref(),
    );
    let mut graph_source_funcs = source_funcs.clone();
    graph_source_funcs.extend(
        callback_targets
            .values()
            .flat_map(|targets| targets.iter().copied()),
    );
    graph_source_funcs.sort_by_key(|func| func.raw());
    graph_source_funcs.dedup();
    let mut sink_func_list: Vec<FuncId> = request.sink_by_func.keys().copied().collect();
    sink_func_list.sort_by_key(|func| func.raw());

    on_progress(AnalysisProgress::PhaseStarted {
        label: "building source-reachable callgraph",
        total: 0,
    });
    let call_graph = request.ws.source_reachable_resolved_call_graph(
        &graph_source_funcs,
        &sink_func_list,
        request.max_precision,
    );
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph scope source_funcs={} sink_funcs={} reached_sinks={} funcs={} files={}",
        source_funcs.len(),
        sink_func_list.len(),
        call_graph.reached_targets,
        call_graph.funcs.len(),
        call_graph.files.len()
    );
    if call_graph.funcs.len() <= 64 {
        let names: Vec<String> = call_graph
            .funcs
            .iter()
            .filter_map(|func| {
                request
                    .global
                    .decl_of(SymbolId::new(func.raw()))
                    .map(|decl| format!("{}:{:?}", decl.name, decl.kind))
            })
            .collect();
        bonsai_diagnostics::debug_log!("security-phase", "semantic graph funcs={}", names.join(", "));
    }
    on_progress(AnalysisProgress::PhaseFinished);

    let resolution =
        ResolutionCoverage::from_graph(call_graph.graph.as_ref(), call_graph.funcs.iter().copied());
    let sink_funcs = request.sink_by_func.keys().copied().collect();
    let mut source_groups: Vec<(FuncId, Vec<usize>)> = request
        .source_groups
        .iter()
        .map(|(func, indices)| (*func, indices.clone()))
        .collect();
    source_groups.sort_by_key(|(func, _)| func.raw());
    let scheduling_total = source_groups
        .iter()
        .map(|(_, indices)| indices.len() as u64)
        .sum();
    ReachableTaintScope {
        source_funcs,
        sink_funcs,
        callback_targets,
        source_groups,
        scheduling_total,
        call_graph,
        resolution,
    }
}

struct SourceScheduleRequest<'a> {
    source_groups: Vec<(FuncId, Vec<usize>)>,
    callback_corridors: &'a AHashMap<FuncId, Arc<SourceSinkCorridor>>,
    shared_corridors: &'a SharedSourceSinkCorridors,
    use_coarse_schedule: bool,
    prefilter_enabled: bool,
    partitioned_idg: bool,
    idg: Option<&'a Arc<bonsai_idg::IdgQueryService>>,
    target_nodes_for_schedule: Option<&'a [bonsai_idg::WsNodeId]>,
    source_work: &'a [SourceWorkItem<'a>],
    pack: &'a Rulepack,
    config: &'a InterTaintConfig,
    global: &'a Arc<GlobalIndex>,
    sink_target_nodes: Option<&'a SinkTargetNodes>,
    call_graph: &'a Arc<bonsai_callgraph::ResolvedCallGraph>,
    debug_taint_phase: bool,
}

struct SourceSchedulePlan {
    groups: Vec<ScheduledSourceGroup>,
    partitioned_source_indices: AHashMap<FuncId, Arc<Vec<usize>>>,
}

struct SinkScheduleRequest<'a, 'matches> {
    pack: &'a Rulepack,
    sinks_by_func: &'a AHashMap<FuncId, Vec<&'matches RuleMatch>>,
    sink_funcs: &'a AHashSet<FuncId>,
    semantic_funcs: &'a [FuncId],
    semantic_graph: &'a SemanticGraphExecution,
    prefilter_enabled: bool,
    source_work_count: usize,
}

struct SinkSchedulePlan {
    targets: Option<SinkTargetNodes>,
    use_coarse_schedule: bool,
}

fn plan_sink_schedule(request: SinkScheduleRequest<'_, '_>) -> SinkSchedulePlan {
    let semantic_func_set: AHashSet<FuncId> = request.semantic_funcs.iter().copied().collect();
    let semantic_sink_func_set: AHashSet<FuncId> = request
        .sink_funcs
        .intersection(&semantic_func_set)
        .copied()
        .collect();
    let targets = if request.prefilter_enabled {
        request.semantic_graph.shared().map(|service| {
            sink_target_nodes_for_funcs(
                service.as_ref(),
                request.pack,
                request.sinks_by_func,
                &semantic_sink_func_set,
            )
        })
    } else {
        None
    };
    let sink_match_count: usize = if request.prefilter_enabled {
        semantic_sink_func_set
            .iter()
            .filter_map(|func| request.sinks_by_func.get(func))
            .map(Vec::len)
            .sum()
    } else {
        request.sinks_by_func.values().map(Vec::len).sum()
    };
    let schedule_node_cut_enabled = targets
        .as_ref()
        .is_some_and(|targets| targets.complete && !targets.nodes.is_empty());
    let graph_node_cut_enabled = targets.as_ref().is_some_and(|targets| !targets.nodes.is_empty());

    // Choose from semantic work shape rather than a project-size or language
    // constant. The coarse corridor is a conservative superset, so this only
    // changes scheduling cost; the final IDG closure remains identical.
    let scheduler_parallelism = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    let exact_schedule_pair_work = request
        .source_work_count
        .saturating_mul(targets.as_ref().map_or(0, |targets| targets.nodes.len()));
    let graph_parallel_work = request
        .semantic_funcs
        .len()
        .max(1)
        .saturating_mul(scheduler_parallelism);
    let use_coarse_schedule =
        request.semantic_graph.is_partitioned() || exact_schedule_pair_work > graph_parallel_work;
    if let Some(targets) = targets.as_ref() {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "sink target nodes nodes={} sink_matches={} complete={} unresolved_funcs={} schedule_node_cut={} graph_node_cut={}",
            targets.nodes.len(),
            sink_match_count,
            targets.complete,
            targets.unresolved_funcs.len(),
            schedule_node_cut_enabled,
            graph_node_cut_enabled
        );
    }
    SinkSchedulePlan {
        targets,
        use_coarse_schedule,
    }
}

fn schedule_source_groups<F>(request: SourceScheduleRequest<'_>, on_progress: &mut F) -> SourceSchedulePlan
where
    F: FnMut(AnalysisProgress),
{
    let mut groups = Vec::new();
    let mut partitioned_source_indices = AHashMap::new();
    for (source_func, indices) in request.source_groups {
        let coarse_corridors =
            coarse_corridor_for_source(request.callback_corridors, request.shared_corridors, source_func);
        if request.use_coarse_schedule {
            if request.prefilter_enabled {
                for _ in &indices {
                    on_progress(AnalysisProgress::PhaseTicked);
                }
            }
            if request.partitioned_idg && !request.callback_corridors.contains_key(&source_func) {
                if !coarse_corridors.is_empty() {
                    partitioned_source_indices.insert(source_func, Arc::new(indices));
                }
                continue;
            }
            let indices = Arc::new(indices);
            for corridor in coarse_corridors {
                groups.push(ScheduledSourceGroup {
                    src_func_id: source_func,
                    indices: Arc::clone(&indices),
                    corridor: Arc::clone(corridor),
                });
            }
            continue;
        }

        let coarse_corridor = coarse_corridors.first().copied();
        let mut filtered_indices = Vec::with_capacity(indices.len());
        let mut group_corridor = SourceSinkCorridor::default();
        for index in indices.iter().copied() {
            let corridor = if let (Some(service), Some(target_nodes)) =
                (request.idg, request.target_nodes_for_schedule)
            {
                source_index_sink_corridor(
                    index,
                    request.source_work,
                    request.pack,
                    request.config,
                    request.global.as_ref(),
                    service.as_ref(),
                    target_nodes,
                    request.sink_target_nodes.is_none_or(|targets| targets.complete),
                    coarse_corridor.map(Arc::as_ref),
                )
            } else {
                coarse_corridor.map(|corridor| corridor.as_ref().clone())
            };
            if let Some(corridor) = corridor {
                filtered_indices.push(index);
                group_corridor.extend(corridor);
            }
            if request.prefilter_enabled {
                on_progress(AnalysisProgress::PhaseTicked);
            }
        }
        if filtered_indices.is_empty() {
            if request.debug_taint_phase {
                let name = request
                    .global
                    .decl_of(SymbolId::new(source_func.raw()))
                    .map(|decl| decl.name.clone())
                    .unwrap_or_default();
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "group func={}({}) sources={} skipped=no_source_to_sink_node_cut",
                    name,
                    source_func.raw(),
                    indices.len()
                );
            }
            continue;
        }
        if let Some(coarse_corridor) = coarse_corridor {
            group_corridor.extend(coarse_corridor.as_ref().clone());
        }
        group_corridor.lineage_funcs.insert(source_func);
        extend_corridor_with_summary_dependency_support(
            &mut group_corridor,
            request.global.as_ref(),
            request.call_graph.as_ref(),
            request.config.max_edge_precision,
        );
        groups.push(ScheduledSourceGroup {
            src_func_id: source_func,
            indices: Arc::new(filtered_indices),
            corridor: Arc::new(group_corridor),
        });
    }
    if request.prefilter_enabled {
        on_progress(AnalysisProgress::PhaseFinished);
    }
    SourceSchedulePlan {
        groups,
        partitioned_source_indices,
    }
}

fn plan_semantic_scope(request: SemanticScopeRequest<'_>) -> SemanticScopePlan {
    let mut scope_funcs = AHashSet::new();
    let mut callback_corridors = AHashMap::new();
    let mut shared_corridors = SharedSourceSinkCorridors::default();
    if request.prefilter_enabled {
        let symbolic_sources = symbolic_field_source_funcs(request.ws, request.global, request.source_funcs);
        if let Some(corridor) = callgraph_sources_sink_corridor(
            request.source_funcs,
            request.sink_funcs,
            request.global,
            request.call_graph,
            request.max_precision,
        ) {
            shared_corridors = partition_source_sink_corridor(
                corridor,
                request.source_funcs,
                &symbolic_sources,
                request.global,
                request.call_graph,
                request.max_precision,
            );
            scope_funcs.extend(
                shared_corridors
                    .corridors
                    .iter()
                    .flat_map(|corridor| corridor.lineage_funcs.iter().copied()),
            );
        }
        scope_funcs.extend(merge_configured_source_callback_corridors(
            &mut callback_corridors,
            request.callback_targets,
            request.sink_funcs,
            request.global,
            request.call_graph,
            request.max_precision,
        ));
    }
    let callback_corridors = callback_corridors
        .into_iter()
        .map(|(func, corridor)| (func, Arc::new(corridor)))
        .collect();
    let (files, funcs) = if scope_funcs.is_empty() {
        (request.fallback_files.to_vec(), request.fallback_funcs.to_vec())
    } else {
        let mut funcs: Vec<FuncId> = scope_funcs.into_iter().collect();
        funcs.sort_by_key(|func| func.raw());
        funcs.dedup();
        let mut files: Vec<FileId> = funcs
            .iter()
            .filter_map(|func| request.global.declaring_file(SymbolId::new(func.raw())))
            .collect();
        files.sort_by_key(|file| file.raw());
        files.dedup();
        (files, funcs)
    };
    SemanticScopePlan {
        callback_corridors,
        shared_corridors,
        files,
        funcs,
    }
}

fn build_transfer_plan(
    pack: &Rulepack,
    source_hits: &[RuleMatch],
    sinks: &[RuleMatch],
    sanitizers: &[RuleMatch],
    max_precision: Option<Precision>,
) -> TransferPlan {
    let languages: AHashSet<String> = source_hits
        .iter()
        .chain(sinks)
        .chain(sanitizers)
        .map(|rule_match| rule_match.language.clone())
        .collect();
    let config = InterTaintConfig {
        clean_output_overwrites: clean_output_overwrites_from_rulepack_for_languages(pack, &languages),
        source_output_args: source_output_args_from_rulepack_for_languages(pack, &languages),
        source_callback_args: source_callback_args_from_rulepack_for_languages(pack, &languages),
        call_result_passthroughs: call_result_passthroughs_from_rulepack_for_languages(pack, &languages),
        output_arg_flows: output_arg_flows_from_rulepack_for_languages(pack, &languages),
        receiver_state_propagations: receiver_state_propagations_from_rulepack_for_languages(
            pack, &languages,
        ),
        max_edge_precision: max_precision,
    };
    TransferPlan { languages, config }
}

pub(super) struct SourceGroupExecutor<'a> {
    pub(super) ws: &'a Workspace,
    pub(super) global: &'a Arc<GlobalIndex>,
    pub(super) source_work: &'a [SourceWorkItem<'a>],
    pub(super) pack: &'a Rulepack,
    pub(super) config: &'a InterTaintConfig,
    pub(super) chain_call_graph: &'a Arc<bonsai_callgraph::ResolvedCallGraph>,
    pub(super) use_partitioned_scoped_idg: bool,
    pub(super) workspace_taint_index: &'a bonsai_workspace::taint_index::TaintGraphIndex,
    pub(super) taint_caches: &'a InterTaintCaches,
    pub(super) sink_by_func: &'a AHashMap<FuncId, Vec<&'a RuleMatch>>,
    pub(super) san_by_func: &'a AHashMap<FuncId, Vec<&'a RuleMatch>>,
    pub(super) clean_overwrite_policy: CleanOverwritePolicy<'a>,
    pub(super) factory_returns: &'a crate::matcher::FactoryReturns,
    pub(super) receiver_base_map_cell: &'a OnceLock<AHashMap<String, Vec<String>>>,
    pub(super) sink_target_nodes: Option<&'a SinkTargetNodes>,
    pub(super) sink_target_nodes_for_graph: Option<&'a [bonsai_idg::WsNodeId]>,
    pub(super) workspace_callable_cache: &'a WorkspaceCallableCache,
    pub(super) debug_taint_phase: bool,
}

fn execute_source_groups<F>(
    executor: &SourceGroupExecutor<'_>,
    pool: Option<&rayon::ThreadPool>,
    source_groups: &[ScheduledSourceGroup],
    idg_service: &bonsai_idg::IdgQueryService,
    on_progress: &mut F,
) -> Vec<Vec<FindingWithChain>>
where
    F: FnMut(AnalysisProgress),
{
    use rayon::prelude::*;

    if let Some(pool) = pool.filter(|_| source_groups.len() > 1) {
        let expected_groups = source_groups.len();
        let (tx, rx) = mpsc::channel();
        let mut groups = None;
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                pool.install(|| {
                    source_groups
                        .par_iter()
                        .map(|group| {
                            let out = executor.execute(group, idg_service);
                            let _ = tx.send(());
                            out
                        })
                        .collect::<Vec<_>>()
                })
            });
            let mut completed = 0usize;
            while completed < expected_groups {
                match rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(()) => {
                        completed += 1;
                        on_progress(AnalysisProgress::PhaseTicked);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if worker.is_finished() {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            groups = Some(match worker.join() {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            });
            while completed < expected_groups {
                on_progress(AnalysisProgress::PhaseTicked);
                completed += 1;
            }
        });
        return groups.unwrap_or_default();
    }

    let mut groups = Vec::with_capacity(source_groups.len());
    for group in source_groups {
        groups.push(executor.execute(group, idg_service));
        on_progress(AnalysisProgress::PhaseTicked);
    }
    groups
}

#[derive(Clone, Copy)]
struct PartitionedExecutionContext<'a> {
    executor: &'a SourceGroupExecutor<'a>,
    pool: Option<&'a rayon::ThreadPool>,
    global: &'a GlobalIndex,
    ws: &'a Workspace,
    pack: &'a Rulepack,
    transfer_languages: &'a AHashSet<String>,
    call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
}

struct PartitionedExecutionRequest<'a> {
    context: PartitionedExecutionContext<'a>,
    source_groups: Vec<ScheduledSourceGroup>,
    shared_corridors: &'a SharedSourceSinkCorridors,
    partitioned_source_indices: &'a AHashMap<FuncId, Arc<Vec<usize>>>,
}

fn execute_partitioned_source_groups<F>(
    request: PartitionedExecutionRequest<'_>,
    on_progress: &mut F,
) -> Vec<FindingWithChain>
where
    F: FnMut(AnalysisProgress),
{
    let mut out = Vec::new();
    let mut callback_batches: AHashMap<usize, (Arc<SourceSinkCorridor>, Vec<ScheduledSourceGroup>)> =
        AHashMap::default();
    for group in request.source_groups {
        let key = Arc::as_ptr(&group.corridor) as usize;
        callback_batches
            .entry(key)
            .or_insert_with(|| (Arc::clone(&group.corridor), Vec::new()))
            .1
            .push(group);
    }
    let shared_batch_count = request
        .shared_corridors
        .source_units
        .iter()
        .filter(|unit| {
            unit.sources
                .iter()
                .any(|source| request.partitioned_source_indices.contains_key(source))
        })
        .count();
    let total_batches = shared_batch_count.saturating_add(callback_batches.len());
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph source units planned batches={}",
        total_batches
    );
    let mut batch_number = 0usize;
    for unit in &request.shared_corridors.source_units {
        let active_sources: Vec<FuncId> = unit
            .sources
            .iter()
            .copied()
            .filter(|source| request.partitioned_source_indices.contains_key(source))
            .collect();
        if active_sources.is_empty() {
            continue;
        }
        let corridor = Arc::clone(&unit.corridor);
        let batch_groups: Vec<ScheduledSourceGroup> = active_sources
            .iter()
            .filter_map(|source| {
                request
                    .partitioned_source_indices
                    .get(source)
                    .map(|indices| ScheduledSourceGroup {
                        src_func_id: *source,
                        indices: Arc::clone(indices),
                        corridor: Arc::clone(&corridor),
                    })
            })
            .collect();
        batch_number += 1;
        out.extend(execute_partitioned_corridor_batch(
            &request.context,
            &corridor,
            &batch_groups,
            batch_number,
            total_batches,
            "scoped",
            on_progress,
        ));
    }

    let mut callback_batches: Vec<_> = callback_batches.into_values().collect();
    callback_batches.sort_by_key(|(corridor, _)| {
        corridor
            .lineage_funcs
            .iter()
            .map(|func| func.raw())
            .min()
            .unwrap_or_default()
    });
    for (corridor, batch_groups) in callback_batches {
        batch_number += 1;
        out.extend(execute_partitioned_corridor_batch(
            &request.context,
            &corridor,
            &batch_groups,
            batch_number,
            total_batches,
            "callback",
            on_progress,
        ));
    }
    out
}

fn execute_partitioned_corridor_batch<F>(
    context: &PartitionedExecutionContext<'_>,
    corridor: &SourceSinkCorridor,
    groups: &[ScheduledSourceGroup],
    batch_number: usize,
    total_batches: usize,
    batch_kind: &str,
    on_progress: &mut F,
) -> Vec<FindingWithChain>
where
    F: FnMut(AnalysisProgress),
{
    let mut funcs: Vec<FuncId> = corridor.lineage_funcs.iter().copied().collect();
    funcs.sort_by_key(|func| func.raw());
    funcs.dedup();
    let mut files: Vec<FileId> = funcs
        .iter()
        .filter_map(|func| context.global.declaring_file(SymbolId::new(func.raw())))
        .collect();
    files.sort_by_key(|file| file.raw());
    files.dedup();
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "building {} semantic graph batch {}/{} groups={} funcs={} files={}",
        batch_kind,
        batch_number,
        total_batches,
        groups.len(),
        funcs.len(),
        files.len()
    );
    let idg = build_idg_service_for_rulepack_for_files(
        context.ws,
        context.pack,
        context.transfer_languages,
        &files,
        &funcs,
        context.call_graph,
    );
    execute_source_groups(context.executor, context.pool, groups, idg.as_ref(), on_progress)
        .into_iter()
        .flatten()
        .collect()
}

struct ScheduledTaintExecutionRequest<'a, 'analysis> {
    executor: &'a SourceGroupExecutor<'analysis>,
    global: &'a GlobalIndex,
    ws: &'a Workspace,
    pack: &'a Rulepack,
    transfer_languages: &'a AHashSet<String>,
    call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    semantic_graph: &'a SemanticGraphExecution,
    source_groups: Vec<ScheduledSourceGroup>,
    shared_corridors: &'a SharedSourceSinkCorridors,
    partitioned_source_indices: &'a AHashMap<FuncId, Arc<Vec<usize>>>,
    source_group_count: usize,
    prefilter_enabled: bool,
}

fn execute_scheduled_taint_groups<F>(
    request: ScheduledTaintExecutionRequest<'_, '_>,
    on_progress: &mut F,
) -> Vec<FindingWithChain>
where
    F: FnMut(AnalysisProgress),
{
    let ScheduledTaintExecutionRequest {
        executor,
        global,
        ws,
        pack,
        transfer_languages,
        call_graph,
        semantic_graph,
        source_groups,
        shared_corridors,
        partitioned_source_indices,
        source_group_count,
        prefilter_enabled,
    } = request;
    let mut scheduled_corridors = AHashSet::default();
    let mut scheduled_reachable_funcs = AHashSet::default();
    if semantic_graph.is_partitioned() {
        for (corridor, sources) in shared_corridors
            .corridors
            .iter()
            .zip(&shared_corridors.sources_by_corridor)
        {
            if sources
                .iter()
                .any(|source| partitioned_source_indices.contains_key(source))
            {
                scheduled_corridors.insert(Arc::as_ptr(corridor) as usize);
                scheduled_reachable_funcs.extend(corridor.lineage_funcs.iter().copied());
            }
        }
    }
    for group in &source_groups {
        let corridor_key = Arc::as_ptr(&group.corridor) as usize;
        if scheduled_corridors.insert(corridor_key) {
            scheduled_reachable_funcs.extend(group.corridor.lineage_funcs.iter().copied());
        }
    }
    let streamed_group_count = shared_corridors
        .sources_by_corridor
        .iter()
        .flat_map(|sources| sources.iter())
        .filter(|source| partitioned_source_indices.contains_key(source))
        .count();
    let total_groups = source_groups.len().saturating_add(streamed_group_count);
    let reachable_funcs = scheduled_reachable_funcs.len();
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "source groups scheduled total={} filtered={} prefilter_enabled={} reachable_funcs={} distinct_slices={}",
        source_group_count,
        total_groups,
        prefilter_enabled,
        reachable_funcs,
        scheduled_corridors.len()
    );
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "taint-analysis source_groups={} scheduled_groups={} reachable_funcs={} source_sink_prefilter={}",
            source_group_count, total_groups, reachable_funcs, prefilter_enabled
        ),
    });
    on_progress(AnalysisProgress::PhaseStarted {
        label: "building taint chains",
        total: total_groups as u64,
    });

    let worker_count = security_taint_worker_count();
    let rayon_pool = if worker_count > 1 && total_groups > 1 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build()
            .ok()
    } else {
        None
    };
    match semantic_graph {
        SemanticGraphExecution::Partitioned => {
            // Source groups are streamed directly from each parsed source
            // file; each file gets its exact cross-file source→all-sinks
            // corridor and is released before the next compilation unit.
            execute_partitioned_source_groups(
                PartitionedExecutionRequest {
                    context: PartitionedExecutionContext {
                        executor,
                        pool: rayon_pool.as_ref(),
                        global,
                        ws,
                        pack,
                        transfer_languages,
                        call_graph,
                    },
                    source_groups,
                    shared_corridors,
                    partitioned_source_indices,
                },
                on_progress,
            )
        }
        SemanticGraphExecution::Shared(global_idg) => execute_source_groups(
            executor,
            rayon_pool.as_ref(),
            &source_groups,
            global_idg.as_ref(),
            on_progress,
        )
        .into_iter()
        .flatten()
        .collect(),
    }
}

pub(super) fn build_findings_chain_aware<F>(request: ChainAnalysisRequest<'_, F>) -> ChainBuildResult
where
    F: FnMut(AnalysisProgress),
{
    let ChainAnalysisRequest {
        ws,
        source_hits,
        sinks,
        sanitizers,
        pack,
        max_precision,
        taint_graph_resident_cache_entries,
        factory_returns,
        on_progress,
    } = request;
    // ---- Phase 1: resolve rule matches to enclosing FuncIds ----
    let global = ws.compiler_linkage_index();
    // Run-scoped memo for the workspace-wide receiver→base-type map. Sink
    // constraint re-checks (`rule_match_passes_constraints_with_taint_view`)
    // run once per candidate; without this the whole-workspace scan that
    // feeds `receiver_type_in` constraints would be rebuilt per candidate.
    // `OnceLock` is `Sync`, so the parallel source-group workers below share
    // one lazily-built map. Only populated if some sink rule needs it.
    let receiver_base_map_cell: OnceLock<AHashMap<String, Vec<String>>> = OnceLock::new();
    // Use the concrete source span to resolve each matcher hit to the
    // declaration that contains it. Name-only keys (`file + get`) can
    // conflate unrelated methods such as `Handler.get` and
    // `Helper.get`, then attach a source in one class to a sink in the
    // other.
    let ResolvedMatchSites {
        sanitizers_by_func: san_by_func,
        sinks_by_func: sink_by_func,
    } = ResolvedMatchSites::resolve(ws, sanitizers, sinks);
    // Workspace-wide source-seeded graph index. The resident cache is
    // bounded and guarded by a rule/config fingerprint, so reuse
    // cannot keep stale graphs alive across rulepack or precision
    // changes and cannot grow without limit on large scans. Disk
    // persistence is best-effort and default-on so repeated CLI runs
    // can hydrate exact graphs from the sidecar instead of replaying
    // the same taint solve. Set `BONSAI_TAINT_GRAPH_PERSIST=0` to
    // disable the performance artifact for disk-constrained runs.
    //
    let workspace_taint_index = ws.taint_index();
    if let Some(resident_cap) = taint_graph_resident_cache_entries {
        workspace_taint_index.set_resident_capacity(resident_cap);
    }
    if source_hits.is_empty() || sink_by_func.is_empty() {
        // No semantic IDG scope exists for this invocation. Still prepare and
        // immediately finish the empty namespace so SDK progress reports the
        // cache decision and no write-through temp file can dangle.
        let taint_graph_fingerprint = taint_cache::config_fingerprint(pack, "taint-analysis", max_precision);
        let cache_report =
            taint_cache::prepare_workspace_cache(ws, "taint-analysis", taint_graph_fingerprint);
        on_progress(AnalysisProgress::Note {
            label: "taint-cache",
            detail: cache_report.detail(),
        });
        // No source/sink work will run, but `prepare_workspace_cache`
        // may have opened the sidecar write-through — close it so the
        // temp file never dangles.
        finish_taint_cache_write_through(ws, cache_report.persist_started, on_progress);
        return ChainBuildResult::default();
    }
    let SourceWorkPlan {
        items: source_work,
        groups: source_groups,
    } = plan_source_work(ws, global.as_ref(), pack, source_hits);
    let TransferPlan {
        languages: transfer_languages,
        config,
    } = build_transfer_plan(pack, source_hits, sinks, sanitizers, max_precision);
    // IDG closures already follow `callee.Return -> caller.CallRet`
    // edges and then continue through caller-side flow. The legacy
    // engine needed a separate "source reaches return" prepass to
    // schedule callers with synthetic empty seeds; doing that in the
    // IDG path is both redundant and imprecise because empty seeds
    // fall back to all caller params. Keep the phase boundary for
    // progress/API stability, but make it a no-op.
    on_progress(AnalysisProgress::PhaseStarted {
        label: "checking source returns",
        total: 0,
    });
    on_progress(AnalysisProgress::PhaseFinished);

    let clean_overwrite_policy = CleanOverwritePolicy::new(ws, &config.clean_output_overwrites);
    let ReachableTaintScope {
        source_funcs: source_func_ids,
        sink_funcs: sink_func_set,
        callback_targets: source_callback_targets,
        source_groups: source_groups_sorted,
        scheduling_total,
        call_graph: reachable_call_graph,
        resolution,
    } = compile_reachable_taint_scope(
        ReachableTaintScopeRequest {
            ws,
            global: &global,
            pack,
            source_work: &source_work,
            source_groups: &source_groups,
            sink_by_func: &sink_by_func,
            max_precision: config.max_edge_precision,
        },
        on_progress,
    );
    let chain_call_graph = reachable_call_graph.graph.clone();
    // Preserve the exact graph scope already built for this scan so the
    // completeness pass can identify unresolved internal calls without
    // rebuilding a whole-workspace call graph after a scoped analysis.
    let resolution = Some(resolution);
    let source_sink_prefilter_enabled = !source_work.is_empty() && !sink_func_set.is_empty();

    let SemanticScopePlan {
        callback_corridors: coarse_corridors_by_func,
        shared_corridors: shared_coarse_corridors,
        files: semantic_files,
        funcs: semantic_funcs,
    } = plan_semantic_scope(SemanticScopeRequest {
        ws,
        global: global.as_ref(),
        source_funcs: &source_func_ids,
        sink_funcs: &sink_func_set,
        callback_targets: &source_callback_targets,
        call_graph: chain_call_graph.as_ref(),
        fallback_files: &reachable_call_graph.files,
        fallback_funcs: &reachable_call_graph.funcs,
        max_precision: config.max_edge_precision,
        prefilter_enabled: source_sink_prefilter_enabled,
    });
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph idg scope funcs={} files={} full_funcs={} full_files={} source_units={} callback_corridors={}",
        semantic_funcs.len(),
        semantic_files.len(),
        reachable_call_graph.funcs.len(),
        reachable_call_graph.files.len(),
        shared_coarse_corridors.source_units.len(),
        coarse_corridors_by_func.len()
    );

    // Disconnected callgraph components have no possible interprocedural IDG
    // edge between them. Build and release them independently instead of
    // choosing a whole-workspace strategy from a project-size threshold.
    let partition_semantic_graph = source_sink_prefilter_enabled
        && (shared_coarse_corridors.source_units.len() > 1 || !coarse_corridors_by_func.is_empty());
    let CompiledSemanticGraph {
        execution: semantic_graph,
        cache_persist_started,
    } = compile_taint_semantic_graph(
        SemanticGraphCompilationRequest {
            ws,
            pack,
            transfer_languages: &transfer_languages,
            config: &config,
            files: &semantic_files,
            funcs: &semantic_funcs,
            call_graph: chain_call_graph.as_ref(),
            max_precision,
            partitioned: partition_semantic_graph,
            source_group_count: source_groups.len(),
            source_unit_count: shared_coarse_corridors.source_units.len(),
        },
        on_progress,
    );
    let use_partitioned_scoped_idg = semantic_graph.is_partitioned();
    let SinkSchedulePlan {
        targets: sink_target_nodes,
        use_coarse_schedule: use_coarse_source_sink_schedule,
    } = plan_sink_schedule(SinkScheduleRequest {
        pack,
        sinks_by_func: &sink_by_func,
        sink_funcs: &sink_func_set,
        semantic_funcs: &semantic_funcs,
        semantic_graph: &semantic_graph,
        prefilter_enabled: source_sink_prefilter_enabled,
        source_work_count: source_work.len(),
    });
    let sink_target_nodes_for_schedule = sink_target_nodes
        .as_ref()
        .filter(|targets| targets.complete && !targets.nodes.is_empty())
        .map(|targets| targets.nodes.as_slice());
    let sink_target_nodes_for_graph = sink_target_nodes
        .as_ref()
        .filter(|targets| !targets.nodes.is_empty())
        .map(|targets| targets.nodes.as_slice());
    let taint_caches = ws.inter_taint_caches();
    taint_caches.seed_resolved_call_graph(chain_call_graph.as_ref());
    // (Workspace taint-graph index + sidecar prepare happen at the top
    // of this function, before the no-work early return.)
    if source_sink_prefilter_enabled {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "building source-sink reachability",
            total: scheduling_total,
        });
    }

    let debug_taint_phase = bonsai_diagnostics::debug::is_enabled("security-taint");
    let SourceSchedulePlan {
        groups: scheduled_source_groups,
        partitioned_source_indices,
    } = schedule_source_groups(
        SourceScheduleRequest {
            source_groups: source_groups_sorted,
            callback_corridors: &coarse_corridors_by_func,
            shared_corridors: &shared_coarse_corridors,
            use_coarse_schedule: use_coarse_source_sink_schedule,
            prefilter_enabled: source_sink_prefilter_enabled,
            partitioned_idg: use_partitioned_scoped_idg,
            idg: semantic_graph.shared(),
            target_nodes_for_schedule: sink_target_nodes_for_schedule,
            source_work: &source_work,
            pack,
            config: &config,
            global: &global,
            sink_target_nodes: sink_target_nodes.as_ref(),
            call_graph: &chain_call_graph,
            debug_taint_phase,
        },
        on_progress,
    );

    on_progress(AnalysisProgress::PhaseStarted {
        label: "scheduling taint sources",
        total: scheduling_total,
    });
    for _ in 0..scheduling_total {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);

    let workspace_callable_cache = WorkspaceCallableCache::default();
    let source_group_executor = SourceGroupExecutor {
        ws,
        global: &global,
        source_work: &source_work,
        pack,
        config: &config,
        chain_call_graph: &chain_call_graph,
        use_partitioned_scoped_idg,
        workspace_taint_index,
        taint_caches,
        sink_by_func: &sink_by_func,
        san_by_func: &san_by_func,
        clean_overwrite_policy,
        factory_returns,
        receiver_base_map_cell: &receiver_base_map_cell,
        sink_target_nodes: sink_target_nodes.as_ref(),
        sink_target_nodes_for_graph,
        workspace_callable_cache: &workspace_callable_cache,
        debug_taint_phase,
    };
    let findings = execute_scheduled_taint_groups(
        ScheduledTaintExecutionRequest {
            executor: &source_group_executor,
            global: global.as_ref(),
            ws,
            pack,
            transfer_languages: &transfer_languages,
            call_graph: chain_call_graph.as_ref(),
            semantic_graph: &semantic_graph,
            source_groups: scheduled_source_groups,
            shared_corridors: &shared_coarse_corridors,
            partitioned_source_indices: &partitioned_source_indices,
            source_group_count: source_groups.len(),
            prefilter_enabled: source_sink_prefilter_enabled,
        },
        on_progress,
    );
    on_progress(AnalysisProgress::PhaseFinished);
    finish_taint_cache_write_through(ws, cache_persist_started, on_progress);
    ChainBuildResult { findings, resolution }
}

fn sorted_seed_key(seeds: &TokenSet) -> Vec<String> {
    let mut sorted: Vec<String> = seeds.iter().cloned().collect();
    sorted.sort();
    sorted
}

#[derive(Clone, Default)]
pub(super) struct SourceSinkCorridor {
    pub(super) terminal_sinks: AHashSet<FuncId>,
    pub(super) lineage_funcs: AHashSet<FuncId>,
    pub(super) target_nodes: Vec<bonsai_idg::WsNodeId>,
}

#[derive(Default)]
struct SharedSourceSinkCorridors {
    corridors: Vec<Arc<SourceSinkCorridor>>,
    source_corridors: AHashMap<FuncId, Vec<usize>>,
    sources_by_corridor: Vec<Vec<FuncId>>,
    source_units: Vec<SourceUnitPlan>,
}

struct SourceUnitPlan {
    sources: Vec<FuncId>,
    corridor: Arc<SourceSinkCorridor>,
}

impl SharedSourceSinkCorridors {
    fn corridors_for_source(&self, source_func: FuncId) -> Vec<&Arc<SourceSinkCorridor>> {
        self.source_corridors
            .get(&source_func)
            .into_iter()
            .flatten()
            .filter_map(|corridor| self.corridors.get(*corridor))
            .collect()
    }
}

impl SourceSinkCorridor {
    fn extend(&mut self, other: SourceSinkCorridor) {
        self.terminal_sinks.extend(other.terminal_sinks);
        self.lineage_funcs.extend(other.lineage_funcs);
        self.target_nodes.extend(other.target_nodes);
        self.target_nodes.sort();
        self.target_nodes.dedup();
    }
}

fn coarse_corridor_for_source<'a>(
    callback_corridors: &'a AHashMap<FuncId, Arc<SourceSinkCorridor>>,
    shared_corridors: &'a SharedSourceSinkCorridors,
    source_func: FuncId,
) -> Vec<&'a Arc<SourceSinkCorridor>> {
    callback_corridors.get(&source_func).map_or_else(
        || shared_corridors.corridors_for_source(source_func),
        |corridor| vec![corridor],
    )
}

fn configured_source_callback_targets_by_source(
    ws: &Workspace,
    source_work: &[SourceWorkItem<'_>],
    pack: &Rulepack,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
) -> AHashMap<FuncId, AHashSet<FuncId>> {
    if source_work.is_empty() {
        return AHashMap::new();
    }
    let mut out: AHashMap<FuncId, AHashSet<FuncId>> = AHashMap::new();
    for item in source_work {
        let src = item.source;
        let src_func_id = item.source_func;
        let Some(src_decl) = ws.exact_decl(SymbolId::new(src_func_id.raw())) else {
            continue;
        };
        let Some(rule) = pack.find_rule_by_id(&src.rule_id) else {
            continue;
        };
        let Some(semantics) = rule.taint_semantics.as_ref() else {
            continue;
        };
        if semantics.source_callback_args.is_empty() {
            continue;
        }
        let Some(FlowEvent::Call { args, .. }) = find_call_event_at(&src_decl.flow_events, src.span) else {
            continue;
        };
        for shape in &semantics.source_callback_args {
            let Some(arg) = args.get(shape.callback_arg_index) else {
                continue;
            };
            // The callgraph already resolves callable literals/references
            // from the parsed argument node. Containment by the exact
            // argument span is the compiler proof that this indirect edge is
            // the configured callback, so no callback spelling is parsed.
            for edge in call_graph.callees_of(src_func_id) {
                if edge.kind != bonsai_callgraph::EdgeKind::Indirect
                    || !edge.precision.is_semantic()
                    || edge.span.file != arg.span.file
                    || edge.span.start < arg.span.start
                    || edge.span.end > arg.span.end
                    || edge.to == src_func_id
                {
                    continue;
                }
                out.entry(src_func_id).or_default().insert(edge.to);
            }
        }
    }
    out
}

fn merge_configured_source_callback_corridors(
    coarse_corridors_by_func: &mut AHashMap<FuncId, SourceSinkCorridor>,
    source_callback_targets: &AHashMap<FuncId, AHashSet<FuncId>>,
    sink_func_set: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) -> AHashSet<FuncId> {
    let mut added_scope = AHashSet::default();
    let mut sorted_sources: Vec<FuncId> = source_callback_targets.keys().copied().collect();
    sorted_sources.sort_by_key(|func| func.raw());
    for source_func in sorted_sources {
        let Some(targets) = source_callback_targets.get(&source_func) else {
            continue;
        };
        let mut sorted_targets: Vec<FuncId> = targets.iter().copied().collect();
        sorted_targets.sort_by_key(|func| func.raw());
        let mut source_corridor = SourceSinkCorridor::default();
        for callback_func in sorted_targets {
            let Some(mut callback_corridor) = callgraph_source_sink_corridor(
                callback_func,
                sink_func_set,
                global,
                call_graph,
                max_precision,
            ) else {
                continue;
            };
            callback_corridor.lineage_funcs.insert(source_func);
            callback_corridor.lineage_funcs.insert(callback_func);
            source_corridor.extend(callback_corridor);
        }
        if source_corridor.terminal_sinks.is_empty() {
            continue;
        }
        extend_corridor_with_summary_dependency_support(
            &mut source_corridor,
            global,
            call_graph,
            max_precision,
        );
        added_scope.extend(source_corridor.lineage_funcs.iter().copied());
        coarse_corridors_by_func
            .entry(source_func)
            .or_default()
            .extend(source_corridor);
    }
    added_scope
}

fn extend_corridor_with_summary_dependency_support(
    corridor: &mut SourceSinkCorridor,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) {
    let mut pending: Vec<FuncId> = corridor.lineage_funcs.iter().copied().collect();
    while let Some(func) = pending.pop() {
        for edge in call_graph.callees_of(func) {
            if max_precision.is_some_and(|max| edge.precision > max) {
                continue;
            }
            if !summary_dependency_provider(global, edge.to) {
                continue;
            }
            if corridor.lineage_funcs.insert(edge.to) {
                pending.push(edge.to);
            }
        }
    }
    bonsai_workspace::extend_func_set_with_semantic_callback_dispatchers(
        &mut corridor.lineage_funcs,
        &corridor.terminal_sinks,
        global,
        call_graph,
        max_precision,
    );
}

pub(super) fn source_analysis_lineage_func_scope(
    source_func: FuncId,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) -> AHashSet<FuncId> {
    // Source-analysis has no sink set to cut against, so compute the complete
    // semantic callgraph fixed point from the source. Rendering may later keep
    // only representative paths, but its hop/path limits must never change the
    // graph that is analyzed. Summary-output providers can climb back to
    // callers, then continue forward through resolved edges.
    let mut scope = AHashSet::default();
    scope.insert(source_func);

    let mut reverse_output_funcs = AHashSet::default();
    if summary_dependency_provider(global, source_func) {
        reverse_output_funcs.insert(source_func);
    }
    let mut processed_reverse_funcs = AHashSet::default();
    let mut stack = vec![source_func];

    while let Some(func) = stack.pop() {
        let mut next: Vec<FuncId> = call_graph
            .callees_of(func)
            .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
            .map(|edge| edge.to)
            .collect();
        if reverse_output_funcs.contains(&func) && processed_reverse_funcs.insert(func) {
            next.extend(
                call_graph
                    .callers_of(func)
                    .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
                    .map(|edge| edge.from),
            );
        }

        next.sort_by_key(|next_func| next_func.raw());
        next.dedup();
        for next_func in next.into_iter().rev() {
            if !scope.insert(next_func) {
                continue;
            }
            if summary_dependency_provider(global, next_func) {
                reverse_output_funcs.insert(next_func);
            }
            stack.push(next_func);
        }
    }

    let callback_targets = scope.clone();
    bonsai_workspace::extend_func_set_with_semantic_callback_dispatchers(
        &mut scope,
        &callback_targets,
        global,
        call_graph,
        max_precision,
    );
    scope
}

fn summary_dependency_provider(global: &GlobalIndex, func: FuncId) -> bool {
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
        return false;
    };
    matches!(decl.kind, DeclKind::Constructor)
        || !decl.receiver_field_writes.is_empty()
        || global
            .linkage_facts(SymbolId::new(func.raw()))
            .is_some_and(|facts| facts.has_summary_output)
}

pub(super) struct SinkTargetNodes {
    pub(super) nodes: Vec<bonsai_idg::WsNodeId>,
    pub(super) complete: bool,
    pub(super) unresolved_funcs: AHashSet<FuncId>,
}

fn sink_target_nodes_for_funcs(
    idg: &bonsai_idg::IdgQueryService,
    pack: &Rulepack,
    sink_by_func: &AHashMap<FuncId, Vec<&RuleMatch>>,
    sink_funcs: &AHashSet<FuncId>,
) -> SinkTargetNodes {
    let mut sorted_sink_funcs: Vec<FuncId> = sink_funcs.iter().copied().collect();
    sorted_sink_funcs.sort_by_key(|func| func.raw());
    let mut out = Vec::new();
    let mut complete = true;
    let mut unresolved_funcs = AHashSet::new();
    let mut unresolved_rules: AHashMap<String, usize> = AHashMap::new();
    let mut unresolved_samples: Vec<String> = Vec::new();
    for sink_func in sorted_sink_funcs {
        let Some(sinks) = sink_by_func.get(&sink_func) else {
            continue;
        };
        for sink in sinks {
            let mut nodes = idg.nodes_at_span(sink_func, sink.span);
            if pack
                .find_rule_by_id(&sink.rule_id)
                .is_some_and(|rule| rule.match_spec.kind == MatchKind::Return)
            {
                if let Some(return_node) = idg.return_node_of(sink_func) {
                    nodes.push(return_node);
                }
            }
            if nodes.is_empty() {
                complete = false;
                unresolved_funcs.insert(sink_func);
                *unresolved_rules.entry(sink.rule_id.clone()).or_default() += 1;
                if unresolved_samples.len() < 12 {
                    unresolved_samples.push(format!(
                        "{} func={} {}:{}:{} text={}",
                        sink.rule_id,
                        sink_func.raw(),
                        sink.file,
                        sink.line,
                        sink.column,
                        sink.match_text
                    ));
                }
            }
            out.append(&mut nodes);
        }
    }
    out.sort();
    out.dedup();
    if !unresolved_rules.is_empty() {
        let mut top_rules: Vec<(String, usize)> = unresolved_rules.into_iter().collect();
        top_rules.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_rules.truncate(12);
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "sink target unresolved top_rules={:?} samples={:?}",
            top_rules,
            unresolved_samples
        );
    }
    SinkTargetNodes {
        nodes: out,
        complete,
        unresolved_funcs,
    }
}

#[allow(clippy::too_many_arguments)] // Source scheduling needs rule, seed, transfer, and IDG context.
fn source_index_sink_corridor(
    index: usize,
    source_work: &[SourceWorkItem<'_>],
    pack: &Rulepack,
    config: &InterTaintConfig,
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    sink_target_nodes: &[bonsai_idg::WsNodeId],
    sink_target_nodes_complete: bool,
    coarse_corridor: Option<&SourceSinkCorridor>,
) -> Option<SourceSinkCorridor> {
    let source_item = source_work.get(index)?;
    let src = source_item.source;
    let source_func = source_item.source_func;
    let seeds = &source_item.seeds;
    let coarse_corridor = coarse_corridor?;
    if sink_target_nodes.is_empty() {
        return Some(coarse_corridor.clone());
    }
    let output_arg_names = global
        .decl_of(SymbolId::new(source_func.raw()))
        .map(|decl| output_arg_names_for_match(pack, src, decl))
        .unwrap_or_default();
    let anchor = if rule_match_kind_is_param(pack, &src.rule_id) || src.origin != MatchOrigin::Rulepack {
        None
    } else {
        Some(src.span)
    };
    let mut seed_nodes = compose_idg_seed_nodes(
        IdgSeedRequest::rule_match(source_func, seeds, anchor, &output_arg_names),
        global,
        idg,
    );
    if seed_nodes.is_empty() {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "empty source seed rule={} func={} names={:?} anchor={:?} output_args={:?}",
            src.rule_id,
            source_func.raw(),
            seeds.iter().collect::<Vec<_>>(),
            anchor.map(|span| (span.start, span.end)),
            output_arg_names
        );
        return None;
    }
    apply_configured_transfer_fixpoint(
        &mut seed_nodes,
        &config.receiver_state_propagations,
        &[],
        &config.output_arg_flows,
        global,
        idg,
        config.max_edge_precision,
        Some(&coarse_corridor.lineage_funcs),
    );
    let cut = idg.forward_target_nodes_cut_with_max_precision(
        &seed_nodes,
        sink_target_nodes,
        config.max_edge_precision,
    );
    if cut.is_empty() {
        if bonsai_diagnostics::debug::is_enabled("security-taint") {
            let describe = |nodes: &[bonsai_idg::WsNodeId]| {
                nodes
                    .iter()
                    .map(|n| {
                        idg.resolve_point(*n)
                            .map(|p| format!("{n:?}@func{}:{:?}", p.func.raw(), p.kind))
                            .unwrap_or_else(|| format!("{n:?}:unresolved"))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let unscoped =
                idg.forward_target_nodes_cut_with_max_precision(&seed_nodes, sink_target_nodes, None);
            let closure = idg.forward_closure_with_max_precision(&seed_nodes, config.max_edge_precision);
            let mut reached_by_func: AHashMap<FuncId, Vec<String>> = AHashMap::new();
            for node in &closure {
                if let Some(point) = idg.resolve_point(*node) {
                    let label = format!("{:?}:{}", point.kind, point.name);
                    let labels = reached_by_func.entry(point.func).or_default();
                    if !labels.contains(&label) {
                        labels.push(label);
                    }
                }
            }
            let mut reached: Vec<String> = reached_by_func
                .into_iter()
                .map(|(func, mut labels)| {
                    labels.sort();
                    let name = global
                        .decl_of(SymbolId::new(func.raw()))
                        .map(|decl| decl.name.as_str())
                        .unwrap_or("?");
                    format!("{name}({}):{}", func.raw(), labels.join("|"))
                })
                .collect();
            reached.sort();
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "empty cut rule={} seed_names={:?} anchor={:?} seeds=[{}] targets=[{}] unscoped_cut={} closure=[{}]",
                src.rule_id,
                seeds.iter().collect::<Vec<_>>(),
                anchor,
                describe(&seed_nodes),
                describe(sink_target_nodes),
                unscoped.len(),
                reached.join(", ")
            );
        }
        return (!sink_target_nodes_complete).then(|| coarse_corridor.clone());
    }
    let mut corridor = SourceSinkCorridor::default();
    for node in &cut {
        let Some(point) = idg.resolve_point(*node) else {
            continue;
        };
        if sink_target_nodes.binary_search(node).is_ok() {
            corridor.target_nodes.push(*node);
        }
        corridor.lineage_funcs.insert(point.func);
        if coarse_corridor.terminal_sinks.contains(&point.func) {
            corridor.terminal_sinks.insert(point.func);
        }
    }
    if corridor.terminal_sinks.is_empty() {
        return None;
    }
    corridor.lineage_funcs.insert(source_func);
    corridor
        .lineage_funcs
        .extend(corridor.terminal_sinks.iter().copied());
    corridor.target_nodes.sort();
    corridor.target_nodes.dedup();
    Some(corridor)
}

fn callgraph_source_sink_corridor(
    source_func: FuncId,
    sink_func_set: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) -> Option<SourceSinkCorridor> {
    callgraph_sources_sink_corridor(&[source_func], sink_func_set, global, call_graph, max_precision)
}

/// Plan exact source compilation units over one union corridor.
///
/// Sources whose adapters expose complete AST field places share one semantic
/// compilation group: the IDG can apply exact sparse demand to that group
/// without a size threshold. Remaining sources are streamed per parsed file
/// under complete forwarding. Each unit recomputes the complete
/// source→all-sinks corridor, so paths remain cross-file and interprocedural.
fn partition_source_sink_corridor(
    mut corridor: SourceSinkCorridor,
    source_funcs: &[FuncId],
    symbolic_field_source_funcs: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) -> SharedSourceSinkCorridors {
    if corridor.lineage_funcs.is_empty() {
        return SharedSourceSinkCorridors::default();
    }
    extend_corridor_with_summary_dependency_support(&mut corridor, global, call_graph, max_precision);
    let mut sparse_sources = Vec::new();
    let mut sources_by_file: BTreeMap<FileId, Vec<FuncId>> = BTreeMap::new();
    for source in source_funcs.iter().copied() {
        if !corridor.lineage_funcs.contains(&source) {
            continue;
        }
        if symbolic_field_source_funcs.contains(&source) {
            sparse_sources.push(source);
            continue;
        }
        let Some(file) = global.declaring_file(SymbolId::new(source.raw())) else {
            continue;
        };
        sources_by_file.entry(file).or_default().push(source);
    }
    let mut source_batches: Vec<Vec<FuncId>> = sources_by_file.into_values().collect();
    if !sparse_sources.is_empty() {
        source_batches.push(sparse_sources);
    }
    for sources in &mut source_batches {
        sources.sort_by_key(|func| func.raw());
        sources.dedup();
    }
    let sink_func_set = corridor.terminal_sinks.clone();
    let mut units_by_shape: BTreeMap<(Vec<FuncId>, Vec<FuncId>), Vec<FuncId>> = BTreeMap::new();
    for sources in source_batches {
        let Some(unit_corridor) =
            callgraph_sources_sink_corridor(&sources, &sink_func_set, global, call_graph, max_precision)
        else {
            continue;
        };
        let mut lineage: Vec<FuncId> = unit_corridor.lineage_funcs.iter().copied().collect();
        lineage.sort_by_key(|func| func.raw());
        let mut sinks: Vec<FuncId> = unit_corridor.terminal_sinks.iter().copied().collect();
        sinks.sort_by_key(|func| func.raw());
        units_by_shape
            .entry((lineage, sinks))
            .or_default()
            .extend(sources);
    }
    let mut source_units = Vec::with_capacity(units_by_shape.len());
    for ((lineage, sinks), mut sources) in units_by_shape {
        sources.sort_by_key(|func| func.raw());
        sources.dedup();
        let mut unit_corridor = SourceSinkCorridor {
            terminal_sinks: sinks.into_iter().collect(),
            lineage_funcs: lineage.into_iter().collect(),
            target_nodes: Vec::new(),
        };
        extend_corridor_with_summary_dependency_support(
            &mut unit_corridor,
            global,
            call_graph,
            max_precision,
        );
        source_units.push(SourceUnitPlan {
            sources,
            corridor: Arc::new(unit_corridor),
        });
    }
    let mut all_sources: Vec<FuncId> = source_units
        .iter()
        .flat_map(|unit| unit.sources.iter().copied())
        .collect();
    all_sources.sort_by_key(|func| func.raw());
    all_sources.dedup();
    let mut source_corridors: AHashMap<FuncId, Vec<usize>> = AHashMap::default();
    for source in &all_sources {
        source_corridors.insert(*source, vec![0]);
    }
    SharedSourceSinkCorridors {
        corridors: vec![Arc::new(corridor)],
        source_corridors,
        sources_by_corridor: vec![all_sources],
        source_units,
    }
}

/// Compute the union of every source→sink callgraph corridor in one graph
/// traversal. This is exactly the union produced by invoking
/// `callgraph_source_sink_corridor` for each source, but avoids repeating a
/// whole-workspace forward/reverse walk for broad inferred-source scans.
fn callgraph_sources_sink_corridor(
    source_funcs: &[FuncId],
    sink_func_set: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) -> Option<SourceSinkCorridor> {
    if sink_func_set.is_empty() || source_funcs.is_empty() {
        return None;
    }
    let mut sources = source_funcs.to_vec();
    sources.sort_by_key(|func| func.raw());
    sources.dedup();
    let mut seen = AHashSet::default();
    let mut forward: AHashMap<FuncId, Vec<FuncId>> = AHashMap::new();
    let mut reverse_output_funcs = sources
        .iter()
        .copied()
        .filter(|func| summary_dependency_provider(global, *func))
        .collect::<AHashSet<_>>();
    let mut processed_reverse_funcs = AHashSet::default();
    let mut stack = sources.clone();
    stack.reverse();
    seen.extend(sources.iter().copied());
    while let Some(func) = stack.pop() {
        let mut next: Vec<FuncId> = call_graph
            .callees_of(func)
            .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
            .map(|edge| edge.to)
            .collect();
        if reverse_output_funcs.contains(&func) && processed_reverse_funcs.insert(func) {
            let callers: Vec<FuncId> = call_graph
                .callers_of(func)
                .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
                .map(|edge| edge.from)
                .collect();
            for caller in callers {
                if summary_dependency_provider(global, caller) && reverse_output_funcs.insert(caller) {
                    stack.push(caller);
                }
                next.push(caller);
            }
        }
        next.sort_by_key(|callee| callee.raw());
        next.dedup();
        for next_func in &next {
            forward.entry(func).or_default().push(*next_func);
        }
        for next_func in next.into_iter().rev() {
            if seen.insert(next_func) {
                stack.push(next_func);
            }
        }
    }
    let mut terminal_sinks: AHashSet<FuncId> = seen
        .iter()
        .copied()
        .filter(|func| sink_func_set.contains(func))
        .collect();
    let mut return_sinks = AHashSet::default();
    for source_func in &sources {
        for edge in call_graph.callers_of(*source_func) {
            if max_precision.is_some_and(|max| edge.precision > max) {
                continue;
            }
            if sink_func_set.contains(&edge.from) {
                return_sinks.insert(edge.from);
            }
        }
    }
    if terminal_sinks.is_empty() {
        if return_sinks.is_empty() {
            return None;
        }
        let mut lineage_funcs = return_sinks.clone();
        lineage_funcs.extend(sources.iter().copied());
        return Some(SourceSinkCorridor {
            terminal_sinks: return_sinks,
            lineage_funcs,
            target_nodes: Vec::new(),
        });
    }
    terminal_sinks.extend(return_sinks);
    let mut reverse: AHashMap<FuncId, Vec<FuncId>> = AHashMap::new();
    for (caller, callees) in &forward {
        for callee in callees {
            if seen.contains(callee) {
                reverse.entry(*callee).or_default().push(*caller);
            }
        }
    }
    let mut lineage_funcs = terminal_sinks.clone();
    let mut frontier: Vec<FuncId> = terminal_sinks.iter().copied().collect();
    frontier.sort_by_key(|func| func.raw());
    while let Some(func) = frontier.pop() {
        let Some(callers) = reverse.get(&func) else {
            continue;
        };
        let mut sorted_callers = callers.clone();
        sorted_callers.sort_by_key(|caller| caller.raw());
        for caller in sorted_callers.into_iter().rev() {
            if lineage_funcs.insert(caller) {
                frontier.push(caller);
            }
        }
    }
    if sources.iter().all(|source| !lineage_funcs.contains(source)) {
        return None;
    }
    lineage_funcs.extend(terminal_sinks.iter().copied());
    Some(SourceSinkCorridor {
        terminal_sinks,
        lineage_funcs,
        target_nodes: Vec::new(),
    })
}

pub(super) fn append_taint_target_key(
    seed_key: &mut Vec<String>,
    label: &str,
    target_funcs: Option<&AHashSet<FuncId>>,
) {
    let Some(target_funcs) = target_funcs else {
        return;
    };
    let mut targets: Vec<FuncId> = target_funcs.iter().copied().collect();
    targets.sort_by_key(|func| func.raw());
    let encoded = targets
        .into_iter()
        .map(|func| func.raw().to_string())
        .collect::<Vec<_>>()
        .join(",");
    seed_key.push(format!("__{label}@{encoded}"));
}

pub(super) fn append_taint_target_node_key(
    seed_key: &mut Vec<String>,
    label: &str,
    target_nodes: Option<&[bonsai_idg::WsNodeId]>,
) {
    let Some(target_nodes) = target_nodes.filter(|nodes| !nodes.is_empty()) else {
        return;
    };
    let mut nodes: Vec<bonsai_idg::WsNodeId> = target_nodes.to_vec();
    nodes.sort();
    nodes.dedup();
    let encoded = nodes
        .into_iter()
        .map(|node| node.0.to_string())
        .collect::<Vec<_>>()
        .join(",");
    seed_key.push(format!("__{label}@{encoded}"));
}

pub(super) fn source_analysis_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    std::env::var("BONSAI_SOURCE_ANALYSIS_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|requested| requested.max(1))
        .unwrap_or(available)
}

fn security_taint_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    let default = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|requested| requested.max(1))
        .unwrap_or(available);
    std::env::var("BONSAI_TAINT_ANALYSIS_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|requested| requested.max(1))
        .unwrap_or(default)
}

/// Build the cache key for an exact source-seeded graph. When an
/// anchored source match resolves to concrete IDG seed nodes, those
/// nodes are the semantic input to the closure; using them directly
/// deduplicates overlapping rule matches at the same call site
/// without merging distinct anchors that resolve to different nodes.
/// If the anchor cannot be resolved, fall back to the historical
/// name/anchor/output-arg key because the IDG seed builder will do
/// the same fallback internally.
pub(super) fn effective_source_seed_key(
    source_func: FuncId,
    seeds: &TokenSet,
    anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<String> {
    let seed_nodes = compose_idg_seed_nodes(
        IdgSeedRequest::rule_match(source_func, seeds, anchor, output_arg_names),
        global,
        idg,
    );
    if !seed_nodes.is_empty() {
        let node_ids = seed_nodes
            .iter()
            .map(|node| node.0.to_string())
            .collect::<Vec<_>>()
            .join(",");
        return vec![format!("__idg_seed_nodes@{node_ids}")];
    }
    sorted_seed_key_with_anchor(seeds, anchor, output_arg_names)
}

pub(super) fn sorted_seed_key_with_anchor(
    seeds: &TokenSet,
    anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
) -> Vec<String> {
    let mut sorted = sorted_seed_key(seeds);
    if let Some(span) = anchor {
        sorted.push(format!(
            "__anchor@{}:{}..{}",
            span.file.raw(),
            span.start,
            span.end,
        ));
    }
    if !output_arg_names.is_empty() {
        let mut args: Vec<String> = output_arg_names.to_vec();
        args.sort();
        sorted.push(format!("__output_args@{}", args.join(",")));
    }
    sorted
}

/// True when the source could syntactically reach the sink — same-fn
/// flows must have the source statement BEFORE the sink, otherwise
/// the supposed flow runs backwards in time. Cross-fn cases always
/// pass since the call graph models the temporal order separately.
pub(super) fn source_can_precede_sink(
    ws: &Workspace,
    pack: &Rulepack,
    src: &RuleMatch,
    src_func: FuncId,
    snk: &RuleMatch,
    sink_func: FuncId,
) -> bool {
    if src_func != sink_func {
        return true;
    }
    if src.origin != MatchOrigin::Rulepack || rule_match_kind_is_param(pack, &src.rule_id) {
        return true;
    }
    // A call's result (or an output parameter it mutates) becomes
    // available only after that call has consumed its inputs.  When one
    // API is intentionally modeled as both a source and a sink, an exact
    // source/sink span therefore cannot prove that the returned value
    // flowed backwards into the same invocation's arguments.  Nested
    // `sink(source())` remains valid because the two AST call spans are
    // distinct and `source_is_sink_call_argument` handles their ordering.
    if src.span == snk.span {
        return false;
    }
    if src.line < snk.line || (src.line == snk.line && src.column <= snk.column) {
        return true;
    }
    source_is_sink_call_argument(ws, sink_func, src.span, snk.span)
        || spans_share_enclosing_loop(ws, sink_func, src.span, snk.span)
}

pub(super) fn identifier_tokens_outside_strings(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            push_identifier_token(&mut tokens, &mut current);
            quote = Some(ch);
            continue;
        }
        if ch == '_' || ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else {
            push_identifier_token(&mut tokens, &mut current);
        }
    }
    push_identifier_token(&mut tokens, &mut current);
    tokens
}

fn push_identifier_token(tokens: &mut Vec<String>, current: &mut String) {
    if current
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        tokens.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

fn source_is_sink_call_argument(
    ws: &Workspace,
    sink_func: FuncId,
    source_span: Span,
    sink_span: Span,
) -> bool {
    let Some(decl) = ws.exact_decl(SymbolId::new(sink_func.raw())) else {
        return false;
    };
    source_is_sink_call_argument_in_events(&decl.flow_events, source_span, sink_span)
}

fn source_is_sink_call_argument_in_events(
    events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    sink_span: Span,
) -> bool {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if spans_overlap(*span, sink_span)
                    && args.iter().any(|arg| span_contains(arg.span, source_span))
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if source_is_sink_call_argument_in_events(then_events, source_span, sink_span)
                    || source_is_sink_call_argument_in_events(else_events, source_span, sink_span)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if source_is_sink_call_argument_in_events(body, source_span, sink_span) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if source_is_sink_call_argument_in_events(body, source_span, sink_span)
                    || source_is_sink_call_argument_in_events(catch_events, source_span, sink_span)
                    || source_is_sink_call_argument_in_events(finally_events, source_span, sink_span)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}
