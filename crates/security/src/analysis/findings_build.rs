//! Finding construction.
//!
//! `make_finding` assembles a `FindingWithChain` from a source/sink rule
//! match pair plus the engine's chain context — attaching sanitizer
//! credit (data-flow-aware via tainted-call-span overlap), guard-shape
//! sanitizer checks, severity/status computation, and low-signal
//! demotion. Also owns pattern-only (taintless) finding construction.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn build_pattern_only_findings(
    ws: &Workspace,
    sinks: &[RuleMatch],
    pack: &Rulepack,
    taint_sink_sites: &AHashSet<(String, String, u32, u32)>,
) -> Vec<FindingWithChain> {
    let mut emitted: AHashSet<(String, String, u32, u32)> = AHashSet::new();
    let mut out = Vec::new();
    for snk in sinks {
        let site_key = (snk.rule_id.clone(), snk.file.clone(), snk.line, snk.column);
        if taint_sink_sites.contains(&site_key) || !emitted.insert(site_key) {
            continue;
        }
        let chain_funcs: Vec<FuncId> = func_id_for_match(ws, snk).into_iter().collect();
        if let Some(finding) = make_pattern_finding(ws, snk, pack, &chain_funcs) {
            out.push(FindingWithChain { finding, chain_funcs });
        }
    }
    out
}

fn make_pattern_finding(
    ws: &Workspace,
    snk: &RuleMatch,
    pack: &Rulepack,
    _chain_funcs: &[FuncId],
) -> Option<Finding> {
    let sink_rule = pack.find_rule_by_id(&snk.rule_id)?;
    let group_tokens = [
        snk.rule_id.clone(),
        snk.file.clone(),
        snk.line.to_string(),
        snk.column.to_string(),
    ];
    let group_id = format!("G:{:016x}", bonsai_hash::fnv1a_names64(&group_tokens));
    let flow_id = bonsai_inspect::compute_flow_id(&group_tokens);
    let source_rule_id = format!("pattern:{}", sink_rule.id);
    let finding_id = compute_finding_id(&source_rule_id, &sink_rule.id, &group_id, &snk.language);
    let source = FindingMatch {
        origin: MatchOrigin::Pattern,
        rule_id: source_rule_id,
        file: snk.file.clone(),
        line: snk.line,
        column: snk.column,
        text: snk.match_text.clone(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("pattern".to_string()),
        severity: None,
        category: Some("pattern".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    };
    let sink = FindingMatch::from_rule_match(snk, sink_rule);
    let chain_display = snk
        .enclosing_fn
        .as_ref()
        .map(|name| vec![name.clone()])
        .unwrap_or_default();
    // Pattern-only findings are exact local rule matches, not taint/source
    // reachability claims. They carry no propagation path to complete.
    Some(Finding {
        finding_id,
        language: snk.language.clone(),
        source,
        sink,
        sanitizers_seen: Vec::new(),
        group_id: Some(group_id.clone()),
        representative_flow_id: Some(flow_id),
        analysis_complete: true,
        analysis_incomplete_reasons: Vec::new(),
        chain_display,
        taint_path: Vec::new(),
        alternate_flows: Vec::new(),
        hops: Vec::new(),
        tag: sink_rule.tag.clone(),
        severity: sink_rule.severity,
        precision: precision_label(Precision::Exact).to_string(),
        cwe: sink_rule.cwe.clone(),
        owasp: sink_rule.owasp.clone(),
        status: FindingStatus::Unsanitized,
        from_test: path_is_test_file_with_root(ws.db().workspace_root().as_deref(), &snk.file),
    })
}

pub(super) fn rule_is_pattern_only_finding(rule: &Rule) -> bool {
    rule.kind == RuleKind::Sink
        && rule.enabled
        && !rule_has_taint_predicate(rule)
        && (rule.category.as_deref() == Some("source-independent")
            || rule.match_spec.kind == MatchKind::Missing)
}

pub(super) fn rule_is_non_taint_sink(rule: &Rule) -> bool {
    rule_is_pattern_only_finding(rule)
        || (rule.kind == RuleKind::Sink
            && rule.enabled
            && !rule_has_taint_predicate(rule)
            && rule.category.as_deref() == Some("lifecycle-audit"))
}

pub(super) fn rule_has_taint_predicate(rule: &Rule) -> bool {
    rule.constraints.0.iter().any(|constraint| {
        matches!(
            constraint,
            ConstraintKind::ArgTainted { .. }
                | ConstraintKind::AnyArgTainted { .. }
                | ConstraintKind::ReceiverTainted { .. }
                | ConstraintKind::ReceiverOriginCallbackParamReachesCall { .. }
        )
    })
}

pub(super) struct FindingBuildContext<'a> {
    pub(super) group_id: Option<String>,
    pub(super) flow_id: Option<String>,
    pub(super) source_func: FuncId,
    pub(super) sink_func: FuncId,
    pub(super) sanitizer_candidate_funcs: &'a [FuncId],
    pub(super) chain_names: Vec<String>,
    pub(super) san_by_func: &'a AHashMap<FuncId, Vec<&'a RuleMatch>>,
    pub(super) ws: &'a Workspace,
    /// Spans of every call site the engine recorded as carrying
    /// tainted argument flow on this source's graph. A sanitizer
    /// only credits the finding when its match span overlaps one
    /// of these — without this filter, any function that happens
    /// to live on the call path (a `pthread_mutex_lock` somewhere,
    /// a `path_prefix_strncmp` on an unrelated branch) would be
    /// credited as a "sanitizer seen" purely because it shares the
    /// chain with the tainted flow. Sanitizer credit must be
    /// data-flow-aware, not call-graph-aware.
    pub(super) tainted_call_spans: &'a AHashSet<Span>,
    pub(super) sink_tainted_args: Vec<TaintedArgInfo>,
    pub(super) taint_path: Vec<TaintPropagationStep>,
    pub(super) precision: Precision,
    pub(super) analysis_incomplete_reasons: Vec<String>,
}

pub(super) fn make_finding(
    src: &RuleMatch,
    snk: &RuleMatch,
    pack: &Rulepack,
    context: FindingBuildContext<'_>,
) -> Option<Finding> {
    let skr = pack.find_rule_by_id(&snk.rule_id)?;
    let attributed_sink = callback_extension_attribution_match(context.ws, snk, skr);
    let report_sink = attributed_sink.as_ref().unwrap_or(snk);
    let is_inferred = src.origin != MatchOrigin::Rulepack;
    let source_rule = if is_inferred {
        None
    } else {
        Some(pack.find_rule_by_id(&src.rule_id)?)
    };
    let src_match = if let Some(rule) = source_rule {
        FindingMatch::from_rule_match(src, rule)
    } else {
        FindingMatch::from_inferred(src)
    };
    let src_rule_id_for_id = if is_inferred {
        src.rule_id.as_str()
    } else {
        &src_match.rule_id
    };
    let group = context.group_id.unwrap_or_else(|| {
        let tokens = [src.file.clone(), report_sink.file.clone()];
        format!("G:{:016x}", bonsai_hash::fnv1a_names64(&tokens))
    });
    let source_identity = rule_match_identity_token(src_rule_id_for_id, src);
    let sink_identity = rule_match_identity_token(&skr.id, report_sink);
    let finding_id = compute_finding_id(&source_identity, &sink_identity, &group, &src.language);

    let mut sanitizers_seen: Vec<FindingMatch> = Vec::new();
    let mut seen_keys: AHashSet<(String, u32, u32)> = AHashSet::new();
    // Walk the actual `FuncId`s from the taint lineage (not their names) so
    // sanitizers in unrelated same-named functions can't cross-
    // bridge. This intentionally uses the pre-display-rewrite
    // lineage candidates: the rendered chain may collapse helper
    // return frames, but sanitizer attribution still needs to see
    // helper functions that transformed the tainted value. Combined
    // with the data-flow tainted-call-span gate below, this keeps
    // credit semantically precise.
    for &hop_func in context.sanitizer_candidate_funcs {
        let Some(sanitizer_hits) = context.san_by_func.get(&hop_func) else {
            continue;
        };
        for sanitizer_match in sanitizer_hits {
            let sanitizer_rule = pack.find_rule_by_id(&sanitizer_match.rule_id);
            let nested_in_tainted_sink_arg = sanitizer_is_nested_in_tainted_sink_arg(
                context.ws,
                context.sink_func,
                src,
                sanitizer_match,
                snk,
                &context.sink_tainted_args,
            );
            let dataflow_connected =
                sanitizer_call_overlaps_tainted_call(sanitizer_match, context.tainted_call_spans)
                    || sanitizer_char_allowlist_guards_tainted_call(
                        sanitizer_rule,
                        sanitizer_match,
                        context.tainted_call_spans,
                    )
                    || nested_in_tainted_sink_arg
                    || sanitizer_assignment_output_feeds_sink_arg(
                        context.ws,
                        hop_func,
                        sanitizer_match,
                        snk,
                        skr,
                        &context.sink_tainted_args,
                    )
                    || sanitizer_guard_feeds_sink_arg(
                        &SanitizerGuardContext {
                            ws: context.ws,
                            sink_tainted_args: &context.sink_tainted_args,
                        },
                        pack,
                        hop_func,
                        sanitizer_rule,
                        sanitizer_match,
                        sanitizer_hits,
                        snk,
                    )
                    || xxe_factory_hardening_sanitizes_sink(
                        context.ws,
                        context.sink_func,
                        sanitizer_rule,
                        skr,
                        sanitizer_match,
                        snk,
                    );
            let post_sink_path_construction_containment = dataflow_connected
                && post_sink_path_construction_containment_allowed(sanitizer_rule, skr, sanitizer_match, snk);
            if !sanitizer_can_attach(
                src,
                context.source_func,
                sanitizer_match,
                hop_func,
                snk,
                context.sink_func,
                nested_in_tainted_sink_arg,
                dataflow_connected,
                post_sink_path_construction_containment,
            ) {
                continue;
            }
            // Data-flow-aware credit: the sanitizer's call site must
            // itself be a tainted call on this graph. Without this
            // gate any rule firing somewhere on the chain credits the
            // finding even when its argument has nothing to do with
            // the source's tainted value.
            if !dataflow_connected {
                continue;
            }
            let dedup_key = (
                sanitizer_match.file.clone(),
                sanitizer_match.line,
                sanitizer_match.column,
            );
            if seen_keys.insert(dedup_key) {
                if let Some(rule) = sanitizer_rule {
                    sanitizers_seen.push(FindingMatch::from_rule_match(sanitizer_match, rule));
                }
            }
        }
    }
    if let Some(guard) = dev_only_environment_guard_sanitizer(context.ws, src)
        .or_else(|| dev_only_environment_guard_sanitizer(context.ws, snk))
    {
        let dedup_key = (guard.file.clone(), guard.line, guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(guard);
        }
    }
    if let Some(allowlist) =
        finite_literal_map_lookup_allowlist_sanitizer(context.ws, snk, &context.sink_tainted_args)
    {
        let dedup_key = (allowlist.file.clone(), allowlist.line, allowlist.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(allowlist);
        }
    }
    if let Some(selection) = finite_literal_selection_sanitizer(context.ws, snk, &context.sink_tainted_args) {
        let dedup_key = (selection.file.clone(), selection.line, selection.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(selection);
        }
    }
    if let Some(type_guard) = runtime_type_rejection_guard_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (type_guard.file.clone(), type_guard.line, type_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(type_guard);
        }
    }
    if let Some(parameterized_query) =
        parameterized_query_guard_sanitizer(context.ws, context.sink_func, snk, skr)
    {
        let dedup_key = (
            parameterized_query.file.clone(),
            parameterized_query.line,
            parameterized_query.column,
        );
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(parameterized_query);
        }
    }
    if let Some(allowlist) = guarded_char_append_allowlist_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr.tag.as_deref(),
        &context.sink_tainted_args,
    ) {
        let dedup_key = (allowlist.file.clone(), allowlist.line, allowlist.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(allowlist);
        }
    }
    if let Some(path_guard) = path_containment_guard_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (path_guard.file.clone(), path_guard.line, path_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(path_guard);
        }
    }
    if let Some(path_guard) =
        path_consumer_containment_guard_sanitizer(context.ws, context.sink_func, snk, skr)
    {
        let dedup_key = (path_guard.file.clone(), path_guard.line, path_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(path_guard);
        }
    }
    if let Some(factory_guard) = receiver_factory_guard_sanitizer(context.ws, context.sink_func, snk, skr) {
        let dedup_key = (
            factory_guard.file.clone(),
            factory_guard.line,
            factory_guard.column,
        );
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(factory_guard);
        }
    }
    if let Some(escape) = character_escape_sanitizer(context.ws, context.sink_func, snk, skr) {
        let dedup_key = (escape.file.clone(), escape.line, escape.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(escape);
        }
    }
    if let Some(path_guard) = relative_path_containment_guard_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (path_guard.file.clone(), path_guard.line, path_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(path_guard);
        }
    }
    if let Some(regex_guard) = python_compiled_regex_guard_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (regex_guard.file.clone(), regex_guard.line, regex_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(regex_guard);
        }
    }
    if let Some(configured_factory_guard) =
        configured_argument_factory_guard_sanitizer(context.ws, context.sink_func, snk, skr)
    {
        let dedup_key = (
            configured_factory_guard.file.clone(),
            configured_factory_guard.line,
            configured_factory_guard.column,
        );
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(configured_factory_guard);
        }
    }
    if let Some(ssrf_guard) = url_network_guard_sanitizer(context.ws, context.sink_func, snk, skr) {
        let dedup_key = (ssrf_guard.file.clone(), ssrf_guard.line, ssrf_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(ssrf_guard);
        }
    }
    if let Some(jwt_guard) =
        go_jwt_inline_keyfunc_algorithm_guard_sanitizer(context.ws, context.sink_func, snk, skr)
    {
        let dedup_key = (jwt_guard.file.clone(), jwt_guard.line, jwt_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(jwt_guard);
        }
    }
    if let Some(html_helper) = js_ts_local_html_escape_helper_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (html_helper.file.clone(), html_helper.line, html_helper.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(html_helper);
        }
    }
    if let Some(html_helper) = java_local_html_escape_helper_return_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (html_helper.file.clone(), html_helper.line, html_helper.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(html_helper);
        }
    }
    if let Some(xml_guard) = go_xml_decoder_hardening_sanitizer(context.ws, context.sink_func, snk, skr) {
        let dedup_key = (xml_guard.file.clone(), xml_guard.line, xml_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(xml_guard);
        }
    }
    if let Some(eq_guard) = nosql_eq_filter_wrapper_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (eq_guard.file.clone(), eq_guard.line, eq_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(eq_guard);
        }
    }
    if let Some(ldap_guard) = local_ldap_escape_helper_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (ldap_guard.file.clone(), ldap_guard.line, ldap_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(ldap_guard);
        }
    }
    if let Some(redirect_guard) = go_same_origin_redirect_helper_guard_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (
            redirect_guard.file.clone(),
            redirect_guard.line,
            redirect_guard.column,
        );
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(redirect_guard);
        }
    }
    if let Some(ssrf_guard) = python_url_ssrf_guard_sanitizer(
        context.ws,
        context.sink_func,
        snk,
        skr,
        &context.sink_tainted_args,
    ) {
        let dedup_key = (ssrf_guard.file.clone(), ssrf_guard.line, ssrf_guard.column);
        if seen_keys.insert(dedup_key) {
            sanitizers_seen.push(ssrf_guard);
        }
    }

    if source_sink_pair_is_low_signal(&src_match, source_rule, skr) {
        return None;
    }

    let status = compute_status(&sanitizers_seen, skr.tag.as_deref());

    let mut sink_match = FindingMatch::from_rule_match(report_sink, skr);
    sink_match.tainted_args = context.sink_tainted_args;

    // Tag the finding when EITHER endpoint lives in a conventional
    // test path. The CLI / SDK consumer can use `--exclude-tests`
    // to drop these for "production review" reports without
    // rebuilding the analysis.
    let root = context.ws.db().workspace_root();
    let from_test = path_is_test_file_with_root(root.as_deref(), &src.file)
        || path_is_test_file_with_root(root.as_deref(), &report_sink.file)
        || context
            .taint_path
            .iter()
            .any(|step| path_is_test_file_with_root(root.as_deref(), &step.file));

    // Trust-aware severity. Source rules carry a `trust` tag
    // (`remote`, `local`, `inferred`). Local-trust sources are
    // CLI args / env vars / files the local user controls — real
    // attack surface for setuid binaries, but lower priority than
    // network-derived flows in a typical web app review. Demote
    // the rule's declared sink severity by one tier when the
    // source is local-trust so the `severity: high` filter retains
    // signal for genuinely high-priority (network-derived) flows.
    let severity = match (skr.severity, src_match.trust.as_deref()) {
        (Some(sev), Some("local" | "inferred")) => Some(demote_severity_one_tier(sev)),
        (sev, _) => sev,
    };

    Some(Finding {
        finding_id,
        language: src.language.clone(),
        source: src_match,
        sink: sink_match,
        sanitizers_seen,
        group_id: Some(group),
        representative_flow_id: context.flow_id,
        analysis_complete: context.analysis_incomplete_reasons.is_empty(),
        analysis_incomplete_reasons: context.analysis_incomplete_reasons,
        chain_display: context.chain_names,
        taint_path: context.taint_path,
        alternate_flows: Vec::new(),
        hops: Vec::new(),
        tag: skr.tag.clone(),
        severity,
        precision: precision_label(context.precision).to_string(),
        cwe: skr.cwe.clone(),
        owasp: skr.owasp.clone(),
        status,
        from_test,
    })
}
