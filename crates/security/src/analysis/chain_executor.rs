//! Per-source-group exact taint closure and sink attribution.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Default)]
struct SourceGroupMetrics {
    graph_nanos: u128,
    attribution_nanos: u128,
    graph_builds: usize,
    group_graph_hits: usize,
    workspace_graph_hits: usize,
    empty_graphs: usize,
    tainted_calls_seen: usize,
    sink_candidate_checks: usize,
    sink_matches: usize,
    lineage_misses: usize,
}

struct GroupTaintTargets {
    nodes: Option<Vec<bonsai_idg::WsNodeId>>,
    unresolved_sink_funcs: Option<AHashSet<FuncId>>,
}

impl GroupTaintTargets {
    fn sink_funcs<'a>(&'a self, group: &'a ScheduledSourceGroup) -> Option<&'a AHashSet<FuncId>> {
        if self.nodes.is_some() {
            self.unresolved_sink_funcs.as_ref()
        } else {
            Some(&group.corridor.terminal_sinks)
        }
    }
}

impl SourceGroupExecutor<'_> {
    fn plan_group_targets(
        &self,
        group: &ScheduledSourceGroup,
        idg: &bonsai_idg::IdgQueryService,
    ) -> GroupTaintTargets {
        let nodes = self.sink_target_nodes_for_graph.and_then(|global_targets| {
            if !group.corridor.target_nodes.is_empty() {
                return Some(group.corridor.target_nodes.clone());
            }
            let mut nodes: Vec<_> = global_targets
                .iter()
                .copied()
                .filter(|node| {
                    idg.resolve_point(*node)
                        .is_some_and(|point| group.corridor.terminal_sinks.contains(&point.func))
                })
                .collect();
            nodes.sort();
            nodes.dedup();
            (!nodes.is_empty()).then_some(nodes)
        });
        let unresolved_sink_funcs = nodes.as_ref().and_then(|_| {
            self.sink_target_nodes.and_then(|targets| {
                let funcs: AHashSet<_> = group
                    .corridor
                    .terminal_sinks
                    .intersection(&targets.unresolved_funcs)
                    .copied()
                    .collect();
                (!funcs.is_empty()).then_some(funcs)
            })
        });
        GroupTaintTargets {
            nodes,
            unresolved_sink_funcs,
        }
    }

    fn log_group_lineage(&self, group: &ScheduledSourceGroup) {
        if !self.debug_taint_phase {
            return;
        }
        let mut names: Vec<_> = group
            .corridor
            .lineage_funcs
            .iter()
            .filter_map(|func| {
                self.global
                    .decl_of(SymbolId::new(func.raw()))
                    .map(|decl| format!("{}({})", decl.name, func.raw()))
            })
            .collect();
        names.sort();
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "group func={} lineage_funcs={:?}",
            group.src_func_id.raw(),
            names
        );
    }

    fn compile_source_graph(
        &self,
        group: &ScheduledSourceGroup,
        targets: &GroupTaintTargets,
        source_item: &SourceWorkItem<'_>,
        idg: &bonsai_idg::IdgQueryService,
        group_graphs: &mut AHashMap<Vec<String>, Arc<EntryTaintGraph>>,
        metrics: &mut SourceGroupMetrics,
    ) -> Arc<EntryTaintGraph> {
        let source_func = group.src_func_id;
        let source = source_item.source;
        let output_arg_names = self
            .global
            .decl_of(SymbolId::new(source_func.raw()))
            .map(|decl| output_arg_names_for_match(self.pack, source, decl))
            .unwrap_or_default();
        let anchor = source_anchor_for_rule_match(self.pack, source);
        let mut seed_key = effective_source_seed_key(
            source_func,
            &source_item.seeds,
            anchor,
            &output_arg_names,
            self.global.as_ref(),
            idg,
        );
        let sink_funcs = targets.sink_funcs(group);
        let lineage_funcs = Some(&group.corridor.lineage_funcs);
        append_taint_target_key(&mut seed_key, "target_funcs", sink_funcs);
        append_taint_target_key(&mut seed_key, "lineage_funcs", lineage_funcs);
        append_taint_target_node_key(&mut seed_key, "target_nodes", targets.nodes.as_deref());

        let started = self.debug_taint_phase.then(Instant::now);
        let graph = if let Some(hit) = group_graphs.get(&seed_key) {
            metrics.group_graph_hits = metrics.group_graph_hits.saturating_add(1);
            Arc::clone(hit)
        } else {
            let workspace_hit = if self.use_partitioned_scoped_idg {
                None
            } else {
                self.workspace_taint_index.get(source_func, &seed_key)
            };
            if let Some(hit) = workspace_hit {
                metrics.workspace_graph_hits = metrics.workspace_graph_hits.saturating_add(1);
                group_graphs.insert(seed_key, Arc::clone(&hit));
                hit
            } else {
                metrics.graph_builds = metrics.graph_builds.saturating_add(1);
                let graph = Arc::new(bonsai_taint::entry_taint_graph_from_idg_query(
                    bonsai_taint::IdgTaintQuery::semantic(
                        bonsai_taint::IdgTaintSource::rule_match(
                            source_func,
                            &source_item.seeds,
                            anchor,
                            &output_arg_names,
                        ),
                        self.ws.db(),
                        idg,
                    )
                    .with_global_index(self.global.as_ref())
                    .with_transfers(bonsai_taint::IdgTaintTransfers {
                        call_result_passthroughs: &self.config.call_result_passthroughs,
                        call_results_materialized: true,
                        ..bonsai_taint::IdgTaintTransfers::none()
                    })
                    .with_targets(bonsai_taint::IdgTaintTargets {
                        nodes: targets.nodes.as_deref(),
                        funcs: sink_funcs,
                        lineage_funcs,
                    })
                    .with_max_precision(self.config.max_edge_precision)
                    .with_caches(self.taint_caches),
                ));
                let graph = if self.use_partitioned_scoped_idg {
                    graph
                } else {
                    self.workspace_taint_index
                        .insert_if_absent(source_func, seed_key.clone(), graph)
                };
                group_graphs.insert(seed_key, Arc::clone(&graph));
                graph
            }
        };
        if let Some(started) = started {
            metrics.graph_nanos = metrics.graph_nanos.saturating_add(started.elapsed().as_nanos());
        }
        graph
    }

    fn sink_candidate_is_valid(
        &self,
        source_func: FuncId,
        source: &RuleMatch,
        call: &bonsai_taint::TaintedCall,
        sink: &RuleMatch,
        trace_index: &AHashMap<u64, &TaintedCallEdge>,
        metrics: &mut SourceGroupMetrics,
    ) -> bool {
        if !source_can_precede_sink(self.ws, self.pack, source, source_func, sink, call.caller) {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "sink_match_rejected_order source_rule={} sink_rule={} src_func={} sink_func={} caller={} call={} source_span={:?} sink_span={:?} call_span={:?}",
                source.rule_id,
                sink.rule_id,
                source_func.raw(),
                func_id_for_match(self.ws, sink).map(|func| func.raw()).unwrap_or_default(),
                call.caller.raw(),
                call.name,
                source.span,
                sink.span,
                call.call_span
            );
            return false;
        }
        if same_function_clean_overwrite_kills_sink_arg(
            self.clean_overwrite_policy,
            source_func,
            call.caller,
            source.span,
            sink.span,
            &call.tainted_args,
            call.tainted_receiver.as_deref(),
        ) {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "sink_match_rejected_same_func_clean_overwrite source_rule={} sink_rule={} caller={} call={} span={:?} tainted_args={:?} receiver={:?}",
                source.rule_id,
                sink.rule_id,
                call.caller.raw(),
                call.name,
                call.call_span,
                call.tainted_args,
                call.tainted_receiver
            );
            return false;
        }
        if interprocedural_clean_overwrite_kills_lineage_arg(
            self.clean_overwrite_policy,
            source_func,
            source.span,
            trace_index,
            call,
        ) {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "sink_match_rejected_inter_clean_overwrite source_rule={} sink_rule={} caller={} call={} span={:?} tainted_args={:?} receiver={:?}",
                source.rule_id,
                sink.rule_id,
                call.caller.raw(),
                call.name,
                call.call_span,
                call.tainted_args,
                call.tainted_receiver
            );
            return false;
        }
        metrics.sink_matches = metrics.sink_matches.saturating_add(1);

        let synthetic_evidence = matches!(
            call.kind,
            bonsai_taint::TaintedCallKind::Return | bonsai_taint::TaintedCallKind::Write
        );
        if !synthetic_evidence && call.tainted_args.is_empty() && call.tainted_receiver.is_none() {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "sink_match_dropped_empty_evidence source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?}",
                source.rule_id,
                sink.rule_id,
                call.caller.raw(),
                call.name,
                call.call_span,
                call.kind
            );
            return false;
        }
        let Some(sink_rule) = self.pack.find_rule_by_id(&sink.rule_id) else {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "sink_match_missing_rule source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?}",
                source.rule_id,
                sink.rule_id,
                call.caller.raw(),
                call.name,
                call.call_span,
                call.kind,
                call.tainted_args,
                call.tainted_receiver
            );
            return false;
        };
        if !source_rule_allows_sink_tag(self.pack, &source.rule_id, sink_rule) {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "sink_match_rejected_source_sink_tag source_rule={} sink_rule={} sink_tag={:?}",
                source.rule_id,
                sink.rule_id,
                sink_rule.tag
            );
            return false;
        }
        if prototype_pollution_sink_is_guarded(self.ws, sink_rule, sink) {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "sink_match_guarded source_rule={} sink_rule={} caller={} call={} span={:?}",
                source.rule_id,
                sink.rule_id,
                call.caller.raw(),
                call.name,
                call.call_span
            );
            return false;
        }
        if !sink_rule.constraints.is_empty() {
            let current_call_view = std::slice::from_ref(call);
            let current_call_taint_view = InterTaintView::new(current_call_view);
            if !rule_match_passes_constraints_with_taint_view(
                self.ws,
                sink_rule,
                sink,
                &current_call_taint_view,
                self.factory_returns,
                self.receiver_base_map_cell,
            ) {
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "sink_match_constraint_failed source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?} constraints={:?}",
                    source.rule_id,
                    sink.rule_id,
                    call.caller.raw(),
                    call.name,
                    call.call_span,
                    call.kind,
                    call.tainted_args,
                    call.tainted_receiver,
                    sink_rule.constraints
                );
                return false;
            }
        }
        true
    }

    pub(super) fn execute(
        &self,
        group: &ScheduledSourceGroup,
        idg: &bonsai_idg::IdgQueryService,
    ) -> Vec<FindingWithChain> {
        let ws = self.ws;
        let global = self.global;
        let source_work = self.source_work;
        let pack = self.pack;
        let chain_call_graph = self.chain_call_graph;
        let sink_by_func = self.sink_by_func;
        let san_by_func = self.san_by_func;
        let workspace_callable_cache = self.workspace_callable_cache;
        let debug_taint_phase = self.debug_taint_phase;
        let src_func_id = group.src_func_id;
        let indices = group.indices.as_ref();
        let group_started = debug_taint_phase.then(Instant::now);
        let mut metrics = SourceGroupMetrics::default();
        let mut group_out: Vec<FindingWithChain> = Vec::new();
        let targets = self.plan_group_targets(group, idg);
        self.log_group_lineage(group);
        let mut emitted_for_source_sink_flow: AHashSet<(usize, String, u32, u64, u64, Option<u64>)> =
            AHashSet::new();
        // Bounded L1 for this one source function. Several
        // source-rule matches in the same function can collapse
        // to the same exact seed shape; computing that graph
        // once per group avoids duplicated exact work without
        // retaining every source graph for the whole workspace.
        let mut group_graphs: AHashMap<Vec<String>, Arc<EntryTaintGraph>> = AHashMap::new();
        for &idx in indices {
            let source_item = &source_work[idx];
            let src = source_item.source;
            let graph =
                self.compile_source_graph(group, &targets, source_item, idg, &mut group_graphs, &mut metrics);
            if graph.tainted_calls.is_empty() {
                metrics.empty_graphs = metrics.empty_graphs.saturating_add(1);
                continue;
            }
            metrics.tainted_calls_seen = metrics
                .tainted_calls_seen
                .saturating_add(graph.tainted_calls.len());
            if debug_taint_phase
                && sink_by_func
                    .keys()
                    .all(|func| !graph.tainted_calls.iter().any(|call| call.caller == *func))
            {
                let mut call_sites: Vec<String> = graph
                    .tainted_calls
                    .iter()
                    .take(24)
                    .map(|call| {
                        let caller_name = global
                            .decl_of(SymbolId::new(call.caller.raw()))
                            .map(|decl| decl.name.clone())
                            .unwrap_or_else(|| call.caller.raw().to_string());
                        format!(
                            "{}({})::{}@{}..{} kind={:?} args={:?} recv={:?}",
                            caller_name,
                            call.caller.raw(),
                            call.name,
                            call.call_span.start,
                            call.call_span.end,
                            call.kind,
                            call.tainted_args,
                            call.tainted_receiver
                        )
                    })
                    .collect();
                call_sites.sort();
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "graph_has_no_sink_callers source_rule={} src_func={} tainted_calls={} sample={:?}",
                    src.rule_id,
                    src_func_id.raw(),
                    graph.tainted_calls.len(),
                    call_sites
                );
            }
            // Resolving workspace callability is diagnostic-only and can be
            // expensive on generated/large call sets. Most source graphs do
            // not emit a finding, so build this index only when a finding
            // actually needs incompleteness reasons.
            let mut unresolved_call_index: Option<GraphUnresolvedCallIndex> = None;
            let attribution_started = debug_taint_phase.then(Instant::now);
            // Span set of every recorded tainted call on this
            // source graph — sanitizer credit pass uses it to
            // require data-flow connectivity rather than mere
            // chain co-occurrence.
            let tainted_call_spans: AHashSet<Span> =
                graph.tainted_calls.iter().map(|c| c.call_span).collect();
            let trace_index = trace_record_index(&graph.call_records);
            let canonical_chain_index =
                CanonicalChainIndex::new(&graph.call_records, chain_call_graph.as_ref());
            for call in &graph.tainted_calls {
                let Some(candidate_sinks) = sink_by_func.get(&call.caller) else {
                    continue;
                };
                let mut cached_evidence: Option<Option<CallEvidence>> = None;
                metrics.sink_candidate_checks = metrics
                    .sink_candidate_checks
                    .saturating_add(candidate_sinks.len());
                // Multi-sink attribution: when several sinks live in
                // the same function, prefer span-equality over text
                // overlap. If ANY candidate sink shares a span with
                // this call, attribute to span-matches only — text
                // match is a fallback used when no sink overlaps the
                // call's span (e.g. cross-file references). The
                // Strapi `_.template(layout)` / `fs.readFileSync(path)`
                // case is the canonical motivator: previously the same
                // source attached to BOTH because text-matching is
                // loose enough to bridge unrelated calls.
                let any_exact_span_match = candidate_sinks
                    .iter()
                    .any(|snk| snk.language == src.language && snk.span == call.call_span);
                let any_span_match = candidate_sinks
                    .iter()
                    .any(|snk| snk.language == src.language && spans_overlap(call.call_span, snk.span));
                for snk in candidate_sinks {
                    if snk.language != src.language {
                        continue;
                    }
                    if any_exact_span_match {
                        if snk.span != call.call_span {
                            continue;
                        }
                    } else if any_span_match {
                        if !spans_overlap(call.call_span, snk.span) {
                            continue;
                        }
                    } else if !tainted_call_matches_sink(call, snk) {
                        continue;
                    }
                    if !self.sink_candidate_is_valid(src_func_id, src, call, snk, &trace_index, &mut metrics)
                    {
                        continue;
                    }
                    if !emitted_for_source_sink_flow.insert(source_sink_flow_emission_key(idx, snk, call)) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_duplicate source_rule={} sink_rule={} caller={} call={} span={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span
                        );
                        continue;
                    }
                    let evidence = cached_evidence.get_or_insert_with(|| {
                        build_call_evidence(ws, &trace_index, &canonical_chain_index, src_func_id, call)
                    });
                    let Some(evidence) = evidence.as_ref() else {
                        metrics.lineage_misses = metrics.lineage_misses.saturating_add(1);
                        if debug_taint_phase {
                            let records = graph
                                .call_records
                                .iter()
                                .map(|record| {
                                    format!(
                                        "{}:{}->{} parent={:?}",
                                        record.trace_id,
                                        record.caller.raw(),
                                        record.callee.raw(),
                                        record.parent_trace_id
                                    )
                                })
                                .collect::<Vec<_>>();
                            bonsai_diagnostics::debug_log!(
                                "security-taint",
                                "lineage_missing source_func={} sink_func={} call={} parent={:?} records={:?}",
                                src_func_id.raw(),
                                call.caller.raw(),
                                call.name,
                                call.parent_trace_id,
                                records
                            );
                        }
                        continue;
                    };
                    let taint_path = align_terminal_taint_step_to_sink(evidence.taint_path.clone(), snk);
                    let group_id = group_id_for_taint_path(&evidence.chain_names, &taint_path);
                    let flow_id = flow_id_for_taint_path(&evidence.chain_names, &taint_path);
                    if let Some(f) = make_finding(
                        src,
                        snk,
                        pack,
                        FindingBuildContext {
                            group_id: Some(group_id),
                            flow_id: Some(flow_id),
                            source_func: src_func_id,
                            sink_func: call.caller,
                            sanitizer_candidate_funcs: &evidence.sanitizer_candidate_funcs,
                            chain_names: evidence.chain_names.clone(),
                            san_by_func,
                            ws,
                            tainted_call_spans: &tainted_call_spans,
                            sink_tainted_args: evidence.sink_tainted_args.clone(),
                            taint_path,
                            precision: evidence.chain_precision,
                            analysis_incomplete_reasons: unresolved_call_index
                                .get_or_insert_with(|| {
                                    GraphUnresolvedCallIndex::new(
                                        global.as_ref(),
                                        graph.as_ref(),
                                        workspace_callable_cache,
                                    )
                                })
                                .reasons_for_terminal_call(call),
                        },
                    ) {
                        group_out.push(FindingWithChain {
                            finding: f,
                            chain_funcs: evidence.chain_funcs.clone(),
                        });
                    } else {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_no_finding source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.kind,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                    }
                }
            }
            if let Some(started) = attribution_started {
                metrics.attribution_nanos = metrics
                    .attribution_nanos
                    .saturating_add(started.elapsed().as_nanos());
            }
        }
        if debug_taint_phase {
            let name = global
                .decl_of(SymbolId::new(src_func_id.raw()))
                .map(|decl| decl.name.clone())
                .unwrap_or_default();
            let total_secs = group_started
                .map(|started| started.elapsed().as_secs_f64())
                .unwrap_or_default();
            bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "group func={}({}) sources={} graphs_built={} group_hits={} workspace_hits={} empty_graphs={} tainted_calls={} sink_candidates={} sink_matches={} lineage_misses={} findings={} graph={:.3}s attribution={:.3}s total={:.3}s",
                    name,
                    src_func_id.raw(),
                    indices.len(),
                    metrics.graph_builds,
                    metrics.group_graph_hits,
                    metrics.workspace_graph_hits,
                    metrics.empty_graphs,
                    metrics.tainted_calls_seen,
                    metrics.sink_candidate_checks,
                    metrics.sink_matches,
                    metrics.lineage_misses,
                    group_out.len(),
                    metrics.graph_nanos as f64 / 1_000_000_000.0,
                    metrics.attribution_nanos as f64 / 1_000_000_000.0,
                    total_secs
                );
        }
        group_out
    }
}
