//! Per-source-group exact taint closure and sink attribution.

#[allow(clippy::wildcard_imports)]
use super::*;

impl SourceGroupExecutor<'_> {
    pub(super) fn execute(
        &self,
        group: &ScheduledSourceGroup,
        idg: &bonsai_idg::IdgQueryService,
    ) -> Vec<FindingWithChain> {
        let ws = self.ws;
        let global = self.global;
        let source_work = self.source_work;
        let pack = self.pack;
        let config = self.config;
        let chain_call_graph = self.chain_call_graph;
        let use_partitioned_scoped_idg = self.use_partitioned_scoped_idg;
        let workspace_taint_index = self.workspace_taint_index;
        let taint_caches = self.taint_caches;
        let sink_by_func = self.sink_by_func;
        let san_by_func = self.san_by_func;
        let clean_overwrite_policy = self.clean_overwrite_policy;
        let factory_returns = self.factory_returns;
        let receiver_base_map_cell = self.receiver_base_map_cell;
        let sink_target_nodes = self.sink_target_nodes;
        let sink_target_nodes_for_graph = self.sink_target_nodes_for_graph;
        let workspace_callable_cache = self.workspace_callable_cache;
        let debug_taint_phase = self.debug_taint_phase;
        let src_func_id = group.src_func_id;
        let indices = group.indices.as_ref();
        let group_started = debug_taint_phase.then(Instant::now);
        let mut graph_nanos = 0u128;
        let mut attribution_nanos = 0u128;
        let mut graph_builds = 0usize;
        let mut group_graph_hits = 0usize;
        let mut workspace_graph_hits = 0usize;
        let mut empty_graphs = 0usize;
        let mut tainted_calls_seen = 0usize;
        let mut sink_candidate_checks = 0usize;
        let mut sink_matches = 0usize;
        let mut lineage_misses = 0usize;
        let mut group_out: Vec<FindingWithChain> = Vec::new();
        let group_target_nodes_owned: Option<Vec<bonsai_idg::WsNodeId>> = sink_target_nodes_for_graph
            .and_then(|global_targets| {
                if !group.corridor.target_nodes.is_empty() {
                    return Some(group.corridor.target_nodes.clone());
                }
                let mut nodes: Vec<bonsai_idg::WsNodeId> = global_targets
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
        let group_target_nodes = group_target_nodes_owned.as_deref();
        let unresolved_sink_func_targets: Option<AHashSet<FuncId>> = group_target_nodes.and_then(|_| {
            sink_target_nodes.as_ref().and_then(|targets| {
                let unresolved: AHashSet<FuncId> = group
                    .corridor
                    .terminal_sinks
                    .intersection(&targets.unresolved_funcs)
                    .copied()
                    .collect();
                (!unresolved.is_empty()).then_some(unresolved)
            })
        });
        let group_sink_func_targets = if group_target_nodes.is_some() {
            unresolved_sink_func_targets.as_ref()
        } else {
            Some(&group.corridor.terminal_sinks)
        };
        let group_lineage_func_targets = Some(&group.corridor.lineage_funcs);
        if debug_taint_phase {
            let mut names: Vec<String> = group
                .corridor
                .lineage_funcs
                .iter()
                .filter_map(|func| {
                    global
                        .decl_of(SymbolId::new(func.raw()))
                        .map(|decl| format!("{}({})", decl.name, func.raw()))
                })
                .collect();
            names.sort();
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "group func={} lineage_funcs={:?}",
                src_func_id.raw(),
                names
            );
        }
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
            let seeds = &source_item.seeds;
            let output_arg_names = global
                .decl_of(SymbolId::new(src_func_id.raw()))
                .map(|d| output_arg_names_for_match(pack, src, d))
                .unwrap_or_default();
            let anchor = source_anchor_for_rule_match(pack, src);
            let mut seed_key = effective_source_seed_key(
                src_func_id,
                seeds,
                anchor,
                &output_arg_names,
                global.as_ref(),
                idg,
            );
            append_taint_target_key(&mut seed_key, "target_funcs", group_sink_func_targets);
            append_taint_target_key(&mut seed_key, "lineage_funcs", group_lineage_func_targets);
            append_taint_target_node_key(&mut seed_key, "target_nodes", group_target_nodes);
            let graph_key = (src_func_id, seed_key);
            // Compute the per-`(source_func, seed_shape)` graph
            // exactly. The per-group cache removes duplicate work
            // inside this source function; the workspace cache gives
            // repeat SDK calls bounded reuse across invocations.
            let graph_started = debug_taint_phase.then(Instant::now);
            let graph = if let Some(hit) = group_graphs.get(&graph_key.1) {
                group_graph_hits = group_graph_hits.saturating_add(1);
                hit.clone()
            } else {
                let workspace_hit = if use_partitioned_scoped_idg {
                    None
                } else {
                    workspace_taint_index.get(src_func_id, &graph_key.1)
                };
                if let Some(hit) = workspace_hit {
                    workspace_graph_hits = workspace_graph_hits.saturating_add(1);
                    group_graphs.insert(graph_key.1.clone(), hit.clone());
                    hit
                } else {
                    graph_builds = graph_builds.saturating_add(1);
                    // The shared IDG already contains Tree-sitter-lowered
                    // callback bindings and the rulepack transfer summaries
                    // materialized once per call site. This query only selects
                    // the source seed, semantic target corridor, and caches.
                    let graph = Arc::new(bonsai_taint::entry_taint_graph_from_idg_query(
                        bonsai_taint::IdgTaintQuery::semantic(
                            bonsai_taint::IdgTaintSource::rule_match(
                                src_func_id,
                                seeds,
                                anchor,
                                &output_arg_names,
                            ),
                            ws.db(),
                            idg,
                        )
                        .with_transfers(bonsai_taint::IdgTaintTransfers {
                            call_result_passthroughs: &config.call_result_passthroughs,
                            call_results_materialized: true,
                            ..bonsai_taint::IdgTaintTransfers::none()
                        })
                        .with_targets(bonsai_taint::IdgTaintTargets {
                            nodes: group_target_nodes,
                            funcs: group_sink_func_targets,
                            lineage_funcs: group_lineage_func_targets,
                        })
                        .with_max_precision(config.max_edge_precision)
                        .with_caches(taint_caches),
                    ));
                    let graph = if use_partitioned_scoped_idg {
                        graph
                    } else {
                        workspace_taint_index.insert_if_absent(src_func_id, graph_key.1.clone(), graph)
                    };
                    group_graphs.insert(graph_key.1.clone(), graph.clone());
                    graph
                }
            };
            if let Some(started) = graph_started {
                graph_nanos = graph_nanos.saturating_add(started.elapsed().as_nanos());
            }
            if graph.tainted_calls.is_empty() {
                empty_graphs = empty_graphs.saturating_add(1);
                continue;
            }
            tainted_calls_seen = tainted_calls_seen.saturating_add(graph.tainted_calls.len());
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
                sink_candidate_checks = sink_candidate_checks.saturating_add(candidate_sinks.len());
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
                    if !source_can_precede_sink(ws, pack, src, src_func_id, snk, call.caller) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_rejected_order source_rule={} sink_rule={} src_func={} sink_func={} caller={} call={} source_span={:?} sink_span={:?} call_span={:?}",
                            src.rule_id,
                            snk.rule_id,
                            src_func_id.raw(),
                            func_id_for_match(ws, snk).map(|func| func.raw()).unwrap_or_default(),
                            call.caller.raw(),
                            call.name,
                            src.span,
                            snk.span,
                            call.call_span
                        );
                        continue;
                    }
                    if same_function_clean_overwrite_kills_sink_arg(
                        clean_overwrite_policy,
                        src_func_id,
                        call.caller,
                        src.span,
                        snk.span,
                        &call.tainted_args,
                        call.tainted_receiver.as_deref(),
                    ) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_rejected_same_func_clean_overwrite source_rule={} sink_rule={} caller={} call={} span={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                        continue;
                    }
                    if interprocedural_clean_overwrite_kills_lineage_arg(
                        clean_overwrite_policy,
                        src_func_id,
                        src.span,
                        &trace_index,
                        call,
                    ) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_rejected_inter_clean_overwrite source_rule={} sink_rule={} caller={} call={} span={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                        continue;
                    }
                    sink_matches = sink_matches.saturating_add(1);
                    // Return / Write tainted-call rows are emitted
                    // as evidence that *the function's return slot
                    // / write target* received tainted data — they
                    // don't carry tainted_args because there is no
                    // "argument" to flag, the dataflow happened on
                    // the return expression itself. Skip the
                    // empty-args/receiver guard for those kinds so
                    // a `MatchKind::Return` sink rule (or
                    // `MatchKind::Write`) can still fire on the
                    // span the IDG closure proved tainted.
                    let kind_emits_synthetic_evidence = matches!(
                        call.kind,
                        bonsai_taint::TaintedCallKind::Return | bonsai_taint::TaintedCallKind::Write
                    );
                    if !kind_emits_synthetic_evidence
                        && call.tainted_args.is_empty()
                        && call.tainted_receiver.is_none()
                    {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_dropped_empty_evidence source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.kind
                        );
                        continue;
                    }
                    let Some(sink_rule) = pack.find_rule_by_id(&snk.rule_id) else {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_missing_rule source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.kind,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                        continue;
                    };
                    if !source_rule_allows_sink_tag(pack, &src.rule_id, sink_rule) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_rejected_source_sink_tag source_rule={} sink_rule={} sink_tag={:?}",
                            src.rule_id,
                            snk.rule_id,
                            sink_rule.tag
                        );
                        continue;
                    }
                    if prototype_pollution_sink_is_guarded(ws, sink_rule, snk) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_guarded source_rule={} sink_rule={} caller={} call={} span={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span
                        );
                        continue;
                    }
                    if !sink_rule.constraints.is_empty() {
                        let current_call_view = std::slice::from_ref(call);
                        let current_call_taint_view = InterTaintView::new(current_call_view);
                        if !rule_match_passes_constraints_with_taint_view(
                            ws,
                            sink_rule,
                            snk,
                            &current_call_taint_view,
                            factory_returns,
                            receiver_base_map_cell,
                        ) {
                            bonsai_diagnostics::debug_log!(
                                "security-taint",
                                "sink_match_constraint_failed source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?} constraints={:?}",
                                src.rule_id,
                                snk.rule_id,
                                call.caller.raw(),
                                call.name,
                                call.call_span,
                                call.kind,
                                call.tainted_args,
                                call.tainted_receiver,
                                sink_rule.constraints
                            );
                            continue;
                        }
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
                        lineage_misses = lineage_misses.saturating_add(1);
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
                attribution_nanos = attribution_nanos.saturating_add(started.elapsed().as_nanos());
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
                    graph_builds,
                    group_graph_hits,
                    workspace_graph_hits,
                    empty_graphs,
                    tainted_calls_seen,
                    sink_candidate_checks,
                    sink_matches,
                    lineage_misses,
                    group_out.len(),
                    graph_nanos as f64 / 1_000_000_000.0,
                    attribution_nanos as f64 / 1_000_000_000.0,
                    total_secs
                );
        }
        group_out
    }
}
