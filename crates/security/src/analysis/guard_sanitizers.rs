//! Inline guard / helper-shape sanitizer recognizers.
//!
//! `make_finding` consults these to decide whether a tainted flow is
//! neutralized by a recognizable code shape the rulepack cannot express
//! as a sanitizer rule: dev-only environment guards, URL/SSRF host
//! guards, local escape-helper wrappers, hardened XML factories,
//! char-allowlist append loops, literal-map lookups, and the like.
//! Also owns the low-signal source/sink pairing demotion and the
//! template-interpolation scanner these recognizers share.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn source_sink_pair_is_low_signal(
    source: &FindingMatch,
    source_rule: Option<&Rule>,
    sink_rule: &Rule,
) -> bool {
    // Inferred entry parameters are untrusted inputs, not confidential
    // values. A precise flow from such an input to an event/log/response
    // can be useful lineage, but it is not evidence of information
    // exposure. Concrete secret/identity source rules remain eligible.
    if sink_rule.tag.as_deref() == Some("information-exposure") && source.origin != MatchOrigin::Rulepack {
        return true;
    }
    if sink_rule.tag.as_deref() != Some("log-injection") || source.trust.as_deref() != Some("local") {
        return false;
    }
    source_rule.is_some_and(|rule| {
        rule.analysis_semantics
            .as_ref()
            .is_some_and(|semantics| semantics.flow_classes.contains(&FlowClass::EnvironmentInput))
    })
}

/// Return the exact rejecting branch when its compiler-lowered boolean
/// expression proves that `predicate_span` is true on the fallthrough path to
/// `sink_span`. This is deliberately syntax/API neutral: the owning language
/// adapter lowered boolean operators, while the caller establishes what the
/// matched predicate means through a sanitizer rule.
pub(super) fn terminal_rejection_predicate_guard_span(
    ws: &Workspace,
    decl: &bonsai_lang_api::Decl,
    predicate_span: Span,
    sink_span: Span,
) -> Option<Span> {
    if predicate_span.file != sink_span.file {
        return None;
    }
    let file_index = ws.exact_decl_index_shared(sink_span.file)?;
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, sink_span, &mut branches);
    branches.into_iter().rev().find_map(|branch| {
        if !branch_arm_abruptly_exits(branch.then_events) {
            return None;
        }
        let expression = branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)?
            .expression
            .as_ref()?;
        condition_false_implies_atom_true(expression, predicate_span).then_some(branch.span)
    })
}

/// Conservatively reject a guard proof when the guarded place is assigned
/// after the rejecting branch and before the sink. The walk is over the finite
/// structured event tree and has no arbitrary depth or work budget.
pub(super) fn place_is_assigned_between(events: &[FlowEvent], place: &str, after: u64, before: u64) -> bool {
    events.iter().any(|event| {
        let assigned_here = matches!(
            event,
            FlowEvent::Assign { span, target, .. }
                if span.start >= after
                    && span.start < before
                    && clean_overwrite_target_key(target).as_deref() == Some(place)
        );
        assigned_here
            || match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    place_is_assigned_between(then_events, place, after, before)
                        || place_is_assigned_between(else_events, place, after, before)
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => place_is_assigned_between(body, place, after, before),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    place_is_assigned_between(body, place, after, before)
                        || place_is_assigned_between(catch_events, place, after, before)
                        || place_is_assigned_between(finally_events, place, after, before)
                }
                _ => false,
            }
    })
}

fn condition_false_implies_atom_true(expression: &ConditionExpressionFact, atom: Span) -> bool {
    match expression {
        ConditionExpressionFact::Atom { .. } => false,
        ConditionExpressionFact::Not { operand, .. } => condition_true_implies_atom_true(operand, atom),
        // `A || B` is false only when both terms are false. One term whose
        // falsity proves the predicate is therefore sufficient.
        ConditionExpressionFact::Any { operands, .. } => operands
            .iter()
            .any(|operand| condition_false_implies_atom_true(operand, atom)),
        // `A && B` can be false because either term is false. Every possible
        // failing term must prove the predicate.
        ConditionExpressionFact::All { operands, .. } => {
            !operands.is_empty()
                && operands
                    .iter()
                    .all(|operand| condition_false_implies_atom_true(operand, atom))
        }
        ConditionExpressionFact::Equality { .. } | ConditionExpressionFact::Membership { .. } => false,
    }
}

fn condition_true_implies_atom_true(expression: &ConditionExpressionFact, atom: Span) -> bool {
    match expression {
        ConditionExpressionFact::Atom { span } => span_contains(*span, atom),
        ConditionExpressionFact::Not { operand, .. } => condition_false_implies_atom_true(operand, atom),
        // Every conjunct is true, so one conjunct that proves the predicate
        // is sufficient.
        ConditionExpressionFact::All { operands, .. } => operands
            .iter()
            .any(|operand| condition_true_implies_atom_true(operand, atom)),
        // Any disjunct may be the sole true term; all alternatives must prove
        // the predicate.
        ConditionExpressionFact::Any { operands, .. } => {
            !operands.is_empty()
                && operands
                    .iter()
                    .all(|operand| condition_true_implies_atom_true(operand, atom))
        }
        ConditionExpressionFact::Equality { .. } | ConditionExpressionFact::Membership { .. } => false,
    }
}

pub(super) fn dev_only_environment_guard_sanitizer(ws: &Workspace, hit: &RuleMatch) -> Option<FindingMatch> {
    if !matches!(hit.language.as_str(), "javascript" | "typescript" | "python") {
        return None;
    }
    let snapshot = ws.vfs().snapshot(hit.span.file).ok()?;
    let headers = ws.compiler_linkage_index();
    let entry = ws
        .enclosing_index()
        .enclosing_for(headers.as_ref(), hit.span.file, hit.span.start)?;
    let decl = ws.exact_decl(entry.symbol)?;
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, hit.span, &mut branches);
    let guard = branches.into_iter().rev().find(|branch| {
        let condition_matches = if hit.language == "python" {
            python_dev_only_env_guard_condition(branch.condition)
        } else {
            js_dev_only_env_guard_condition(branch.condition)
        };
        condition_matches && branch_arm_abruptly_exits(branch.then_events)
    })?;
    finding_for_guard_span(
        hit,
        snapshot.text.as_ref(),
        guard.span,
        "engine.sanitizer.dev_only_env_guard",
        "dev-only-guard",
        "reachability-guard",
    )
}

fn js_dev_only_env_guard_condition(condition: &str) -> bool {
    let compact = compact_guard_text(condition);
    let lower = compact.to_ascii_lowercase();
    let reads_node_env = lower.contains("process.env.node_env") || lower.contains("node_env");
    if !reads_node_env || !(compact.contains("!==") || compact.contains("!=")) {
        return false;
    }
    let mentions_dev_env = ["dev", "debug", "test", "local", "internal"]
        .iter()
        .any(|marker| lower.contains(marker));
    mentions_dev_env
}

pub(super) fn path_containment_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let semantics = sink_rule.analysis_semantics.as_ref()?;
    if semantics.guard_profile != Some(GuardProfile::PythonPathContainment) {
        return None;
    }
    let guard = semantics.path_containment_guard.as_ref()?;
    let (candidate, base) = path_containment_target_and_base(ws, sink_func, snk, sink_rule, guard)?;
    if sink_tainted_args.iter().any(|arg| {
        arg.place
            .as_deref()
            .and_then(clean_overwrite_target_key)
            .as_deref()
            == Some(base.as_str())
            || arg
                .source_names
                .iter()
                .filter_map(|source| clean_overwrite_target_key(source))
                .any(|source| source == base)
    }) {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut branches = Vec::new();
    collect_following_branches_on_path(&decl.flow_events, snk.span, &mut branches);
    for branch in branches {
        if !path_containment_guard_condition(
            &decl.flow_events,
            &file_index.branch_conditions,
            branch,
            &candidate,
            &base,
            &guard.containment_check,
            &guard.boundary_places,
        ) {
            continue;
        }
        if !branch_arm_abruptly_exits(branch.then_events) {
            continue;
        }
        return finding_for_guard_span(
            snk,
            snapshot.text.as_ref(),
            branch.span,
            "engine.sanitizer.path_containment_guard",
            "path-sanitize",
            "path-containment-guard",
        );
    }
    None
}

pub(super) fn path_consumer_containment_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let semantics = sink_rule.analysis_semantics.as_ref()?;
    if semantics.guard_profile != Some(GuardProfile::PathConsumerContainment) {
        return None;
    }
    let guard = semantics.path_consumer_containment_guard.as_ref()?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let guarded_span = path_consumer_guard_span(ws, &decl, sink.span, guard.sink_path_arg_index, guard, None)
        .or_else(|| {
            let call_graph = ws.cached_resolved_call_graph();
            let guarded = call_graph
                .callers_of(sink_func)
                .filter(|edge| edge.precision.is_semantic())
                .find_map(|edge| {
                    let caller = ws.exact_decl(SymbolId::new(edge.from.raw()))?;
                    path_consumer_guard_span(
                        ws,
                        &caller,
                        edge.span,
                        guard.sink_path_arg_index,
                        guard,
                        Some(&decl.name),
                    )
                });
            guarded
        })?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        guarded_span,
        "engine.sanitizer.path_consumer_containment_guard",
        "path-sanitize",
        "canonical-path-consumer-containment",
    )
}

pub(super) fn receiver_factory_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .receiver_factory_guard
        .as_ref()?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let receiver = calls
        .iter()
        .find(|call| call.span == sink.span || spans_overlap(call.span, sink.span))?
        .receiver
        .and_then(clean_overwrite_target_key)?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let assignment = file_index
        .assignment_values
        .iter()
        .filter(|fact| {
            fact.assignment_span.start < sink.span.start
                && fact
                    .target
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .as_deref()
                    == Some(receiver.as_str())
        })
        .max_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end))?;
    let factory = assignment.direct_call_name.as_deref()?;
    if !guard
        .factories
        .iter()
        .any(|target| rule_target_matches_call(factory, &[], target))
    {
        return None;
    }
    let sink_tag = sink_rule.tag.as_deref()?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        assignment.assignment_span,
        "engine.sanitizer.receiver_factory_guard",
        sink_tag,
        "receiver-factory-guard",
    )
}

pub(super) fn character_escape_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let semantics = sink_rule.analysis_semantics.as_ref()?.character_escape.as_ref()?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let verified_helpers = verified_character_substitution_helpers(&file_index, semantics);
    if verified_helpers.is_empty() {
        return None;
    }
    let mut calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut calls);
    let helper_calls: Vec<_> = calls
        .iter()
        .filter_map(|call| {
            let helper = callee_spelling_tail(call.name);
            verified_helpers
                .iter()
                .find(|candidate| candidate.name == helper)
                .map(|candidate| (*call, *candidate))
        })
        .collect();
    if helper_calls.is_empty() {
        return None;
    }

    let proof = if semantics.value_arg_indices.is_empty() {
        let return_flow = return_value_flow_at_match(&sink_decl.flow_events, sink.span)?;
        character_escape_flow_is_safe(
            return_flow,
            sink.span,
            &file_index,
            &helper_calls,
            &mut AHashSet::new(),
        )
    } else {
        let sink_call = calls
            .iter()
            .find(|call| call.span == sink.span || spans_overlap(call.span, sink.span))?;
        semantics.value_arg_indices.iter().all(|index| {
            let Some(flow) = bonsai_lang_api::call_argument_value_fact(
                &file_index.call_argument_values,
                sink_call.span,
                *index,
            )
            .map(|fact| &fact.value_flow) else {
                return false;
            };
            character_escape_flow_is_safe(flow, sink.span, &file_index, &helper_calls, &mut AHashSet::new())
        })
    };
    if !proof {
        return None;
    }
    let transform_span = helper_calls
        .iter()
        .map(|(_, helper)| helper.transform_span)
        .min_by_key(|span| (span.start, span.end))?;
    let sink_tag = sink_rule.tag.as_deref()?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        transform_span,
        "engine.sanitizer.character_escape",
        sink_tag,
        "compiler-proven-character-substitution",
    )
}

#[derive(Copy, Clone)]
struct VerifiedCharacterHelper<'a> {
    name: &'a str,
    transform_span: Span,
}

fn verified_character_substitution_helpers<'a>(
    file_index: &'a bonsai_lang_api::DeclIndex,
    semantics: &crate::rule::CharacterEscapeSemantics,
) -> Vec<VerifiedCharacterHelper<'a>> {
    let mut helpers = Vec::new();
    for fact in &file_index.character_substitutions {
        let Some(decl) = file_index
            .defs
            .iter()
            .find(|decl| decl.span == fact.function_span)
        else {
            continue;
        };
        if fact.input_param_index >= decl.params.len() {
            continue;
        }
        let Some(map) = file_index
            .static_string_maps
            .iter()
            .filter(|map| map.target == fact.table && map.assignment_span.start < fact.transform_span.start)
            .max_by_key(|map| (map.assignment_span.start, map.assignment_span.end))
        else {
            continue;
        };
        if !semantics.required_mappings.iter().all(|required| {
            map.entries
                .iter()
                .any(|entry| entry.key == required.input && entry.value == required.output)
        }) {
            continue;
        }
        let domain_covers_required = match &fact.domain {
            bonsai_lang_api::CharacterSubstitutionDomain::TableKeysWithIdentityFallback => true,
            bonsai_lang_api::CharacterSubstitutionDomain::ExactCharacters { characters } => semantics
                .required_mappings
                .iter()
                .all(|required| characters.contains(&required.input)),
        };
        if domain_covers_required {
            helpers.push(VerifiedCharacterHelper {
                name: &decl.name,
                transform_span: fact.transform_span,
            });
        }
    }
    helpers.sort_by_key(|helper| (helper.name, helper.transform_span.start));
    helpers.dedup_by_key(|helper| (helper.name, helper.transform_span));
    helpers
}

fn return_value_flow_at_match<'a>(
    events: &'a [FlowEvent],
    matched_span: Span,
) -> Option<&'a bonsai_lang_api::ExpressionFlow> {
    for event in events {
        match event {
            FlowEvent::Return { span, value_flow, .. }
                if spans_overlap(*span, matched_span)
                    || span_contains(*span, matched_span)
                    || span_contains(matched_span, *span) =>
            {
                return Some(value_flow);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(flow) = return_value_flow_at_match(then_events, matched_span)
                    .or_else(|| return_value_flow_at_match(else_events, matched_span))
                {
                    return Some(flow);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(flow) = return_value_flow_at_match(body, matched_span) {
                    return Some(flow);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(flow) = return_value_flow_at_match(body, matched_span)
                    .or_else(|| return_value_flow_at_match(catch_events, matched_span))
                    .or_else(|| return_value_flow_at_match(finally_events, matched_span))
                {
                    return Some(flow);
                }
            }
            _ => {}
        }
    }
    None
}

fn character_escape_flow_is_safe(
    flow: &bonsai_lang_api::ExpressionFlow,
    before: Span,
    file_index: &bonsai_lang_api::DeclIndex,
    helper_calls: &[(StructuredCall<'_>, VerifiedCharacterHelper<'_>)],
    visited_places: &mut AHashSet<String>,
) -> bool {
    if !flow.spreads.is_empty() {
        return false;
    }
    if !flow.call_sites.is_empty() {
        if !flow.source_names.is_empty()
            || flow.place.is_some()
            || flow.projection.is_some()
            || !flow.aggregate_fields.is_empty()
            || !flow.tuple_items.is_empty()
        {
            return false;
        }
        return flow.call_sites.iter().all(|call_site| {
            helper_calls.iter().any(|(call, _)| {
                spans_overlap(call.span, *call_site)
                    || span_contains(*call_site, call.span)
                    || span_contains(call.span, *call_site)
            })
        });
    }
    if let Some(place) = flow.place.as_deref().and_then(clean_overwrite_target_key) {
        if !visited_places.insert(place.clone()) {
            return false;
        }
        let assignment = file_index
            .assignment_values
            .iter()
            .filter(|fact| {
                fact.assignment_span.start < before.start
                    && fact
                        .target
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .as_deref()
                        == Some(place.as_str())
            })
            .max_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end));
        let safe = assignment.is_some_and(|assignment| {
            character_escape_flow_is_safe(
                &assignment.value_flow,
                assignment.assignment_span,
                file_index,
                helper_calls,
                visited_places,
            )
        });
        visited_places.remove(&place);
        return safe;
    }
    if !flow.source_names.is_empty() || flow.projection.is_some() {
        return false;
    }
    flow.aggregate_fields.iter().all(|field| {
        character_escape_flow_is_safe(&field.value, before, file_index, helper_calls, visited_places)
    }) && flow
        .tuple_items
        .iter()
        .all(|item| character_escape_flow_is_safe(item, before, file_index, helper_calls, visited_places))
}

fn path_consumer_guard_span(
    ws: &Workspace,
    decl: &bonsai_lang_api::Decl,
    consumer_span: Span,
    path_arg_index: usize,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
    expected_callee: Option<&str>,
) -> Option<Span> {
    let file_index = ws.exact_decl_index_shared(consumer_span.file)?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let consumer_call = calls
        .iter()
        .filter(|call| call.span == consumer_span || spans_overlap(call.span, consumer_span))
        .find(|call| {
            expected_callee
                .is_none_or(|expected| callee_spelling_tail(call.name) == callee_spelling_tail(expected))
        })?;
    let candidate = consumer_call
        .args
        .get(path_arg_index)?
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)?;

    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, consumer_span, &mut assignments);
    let candidate_assignment = assignments.iter().rev().find(|assignment| {
        clean_overwrite_target_key(assignment.target).as_deref() == Some(candidate.as_str())
            && assignment
                .source_call
                .is_some_and(|call| rule_target_matches_call(call, &[], &guard.canonicalizer))
    })?;
    let path_constructor_calls: Vec<_> = calls
        .iter()
        .filter(|call| {
            span_contains(candidate_assignment.span, call.span)
                && rule_target_matches_call(call.name, &[], &guard.path_constructor)
        })
        .collect();
    if path_constructor_calls.len() != 1 {
        return None;
    }
    let base = path_constructor_calls[0]
        .args
        .get(guard.path_constructor_base_arg_index)?
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)?;

    let exact_file_decls: Vec<_> = file_index
        .defs
        .iter()
        .filter_map(|candidate| ws.exact_decl(candidate.symbol))
        .collect();
    let mut file_assignments = Vec::new();
    for candidate_decl in &exact_file_decls {
        collect_structured_assignments_before(
            &candidate_decl.flow_events,
            candidate_assignment.span,
            &mut file_assignments,
        );
    }
    file_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    file_assignments.dedup_by_key(|assignment| assignment.span);
    if !place_has_static_canonical_provenance(
        &base,
        &file_assignments,
        &file_index.assignment_values,
        guard.base_canonicalizer.as_ref().unwrap_or(&guard.canonicalizer),
        candidate_assignment.span,
    ) {
        return None;
    }

    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, consumer_span, &mut branches);
    let branch = branches.into_iter().rev().find(|branch| {
        branch_arm_abruptly_exits(branch.then_events)
            && path_containment_guard_condition(
                &decl.flow_events,
                &file_index.branch_conditions,
                *branch,
                &candidate,
                &base,
                &guard.containment_check,
                &guard.boundary_places,
            )
    })?;
    Some(branch.span)
}

pub(super) fn relative_path_containment_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let semantics = sink_rule.analysis_semantics.as_ref()?;
    if semantics.guard_profile != Some(GuardProfile::RelativePathContainment) {
        return None;
    }
    let guard = semantics.relative_path_containment_guard.as_ref()?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let sink_call = calls
        .iter()
        .find(|call| call.span == sink.span || spans_overlap(call.span, sink.span))?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, sink.span, &mut assignments);

    let (candidate, candidate_assignment) =
        guarded_relative_path_candidate(sink_call, sink, guard, &assignments)?;
    if !candidate_assignment
        .source_call
        .is_some_and(|call| rule_target_matches_call(call, &[], &guard.candidate_canonicalizer))
    {
        return None;
    }

    let relative_call = calls.iter().find(|call| {
        call.span.start > candidate_assignment.span.start
            && rule_target_matches_call(call.name, &[], &guard.relative_path)
            && call
                .args
                .get(guard.relative_candidate_arg_index)
                .and_then(|argument| argument.place.as_deref())
                .and_then(clean_overwrite_target_key)
                .as_deref()
                == Some(candidate.as_str())
    })?;
    let base = relative_call
        .args
        .get(guard.relative_base_arg_index)?
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)?;
    if sink_tainted_args
        .iter()
        .flat_map(tainted_arg_target_keys)
        .any(|target| target == base)
    {
        return None;
    }

    let exact_file_decls: Vec<_> = file_index
        .defs
        .iter()
        .filter_map(|candidate| ws.exact_decl(candidate.symbol))
        .collect();
    let mut file_assignments = Vec::new();
    for candidate_decl in &exact_file_decls {
        collect_structured_assignments_before(
            &candidate_decl.flow_events,
            relative_call.span,
            &mut file_assignments,
        );
    }
    file_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    if !place_has_static_canonical_provenance(
        &base,
        &file_assignments,
        &file_index.assignment_values,
        &guard.base_canonicalizer,
        relative_call.span,
    ) {
        return None;
    }

    let relative_result = file_assignments.iter().rev().find_map(|assignment| {
        (assignment.span.file == relative_call.span.file
            && span_contains(assignment.span, relative_call.span)
            && assignment
                .source_call
                .is_some_and(|call| rule_target_matches_call(call, &[], &guard.relative_path))
            && bonsai_lang_api::tuple_result_projection_index(assignment.source_names)
                == Some(guard.relative_path_result_index))
        .then(|| clean_overwrite_target_key(assignment.target))
        .flatten()
    })?;

    let mut branches = Vec::new();
    if guard.guarded_path_arg_index.is_some() {
        collect_completed_branches_on_path(&decl.flow_events, sink.span, &mut branches);
    } else {
        collect_following_branches_on_path(&decl.flow_events, sink.span, &mut branches);
    }
    let branch = branches.into_iter().rev().find(|branch| {
        branch.span.start > relative_call.span.start
            && branch_arm_abruptly_exits(branch.then_events)
            && relative_path_rejection_condition(
                &file_index.branch_conditions,
                &decl.flow_events,
                *branch,
                &relative_result,
                guard,
            )
    })?;

    let snapshot = ws.vfs().snapshot(sink.span.file).ok()?;
    finding_for_guard_span(
        sink,
        snapshot.text.as_ref(),
        branch.span,
        "engine.sanitizer.relative_path_containment_guard",
        "path-sanitize",
        "canonical-relative-path-containment",
    )
}

fn guarded_relative_path_candidate<'a>(
    sink_call: &StructuredCall<'_>,
    sink: &RuleMatch,
    guard: &RelativePathContainmentGuardSemantics,
    assignments: &'a [StructuredAssignment<'a>],
) -> Option<(String, &'a StructuredAssignment<'a>)> {
    if let Some(argument_index) = guard.guarded_path_arg_index {
        let candidate = sink_call
            .args
            .get(argument_index)?
            .place
            .as_deref()
            .and_then(clean_overwrite_target_key)?;
        let assignment = assignments.iter().rev().find(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(candidate.as_str())
                && assignment.span.start < sink.span.start
        })?;
        return Some((candidate, assignment));
    }
    let assignment = assignments
        .iter()
        .rev()
        .find(|assignment| span_contains(assignment.span, sink.span))?;
    let candidate = clean_overwrite_target_key(assignment.target)?;
    Some((candidate, assignment))
}

fn relative_path_rejection_condition(
    condition_facts: &[BranchConditionFact],
    events: &[FlowEvent],
    branch: StructuredBranch<'_>,
    relative_result: &str,
    guard: &RelativePathContainmentGuardSemantics,
) -> bool {
    let Some(ConditionExpressionFact::Any { operands, .. }) =
        branch_condition_fact_for_span(condition_facts, branch.span)
            .and_then(|condition| condition.expression.as_ref())
    else {
        return false;
    };
    let exact_rejection = operands.iter().any(|operand| {
        let ConditionExpressionFact::Equality {
            relation: ConditionEquality::Equal,
            left,
            right,
            ..
        } = operand
        else {
            return false;
        };
        condition_place_equals(left, relative_result)
            .then_some(right)
            .or_else(|| condition_place_equals(right, relative_result).then_some(left))
            .and_then(|literal| literal.static_string.as_deref())
            .is_some_and(|literal| {
                guard
                    .rejected_exact_values
                    .iter()
                    .any(|rejected| rejected == literal)
            })
    });
    if !exact_rejection {
        return false;
    }
    operands.iter().any(|operand| {
        let ConditionExpressionFact::Atom { span } = operand else {
            return false;
        };
        let query = RelativeRejectionCallQuery {
            condition_span: *span,
            relative_result,
            guard,
        };
        relative_rejection_call_in_span(events, &query)
    })
}

fn condition_place_equals(operand: &ConditionOperandFact, expected: &str) -> bool {
    operand
        .value_flow
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)
        .as_deref()
        == Some(expected)
}

struct RelativeRejectionCallQuery<'a> {
    condition_span: Span,
    relative_result: &'a str,
    guard: &'a RelativePathContainmentGuardSemantics,
}

fn relative_rejection_call_in_span(events: &[FlowEvent], query: &RelativeRejectionCallQuery<'_>) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver_types,
                args,
                ..
            } if span_contains(query.condition_span, *span)
                && rule_target_matches_call(name, receiver_types, &query.guard.rejection_check) =>
            {
                if args
                    .get(query.guard.rejection_check_arg_index)
                    .and_then(|argument| argument.place.as_deref())
                    .and_then(clean_overwrite_target_key)
                    .as_deref()
                    == Some(query.relative_result)
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if relative_rejection_call_in_span(then_events, query)
                    || relative_rejection_call_in_span(else_events, query)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if relative_rejection_call_in_span(body, query) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if relative_rejection_call_in_span(body, query)
                    || relative_rejection_call_in_span(catch_events, query)
                    || relative_rejection_call_in_span(finally_events, query)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn place_has_static_canonical_provenance(
    place: &str,
    assignments: &[StructuredAssignment<'_>],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    canonicalizer: &RuleTarget,
    before: Span,
) -> bool {
    let mut current = place.to_string();
    let mut visited = AHashSet::new();
    while visited.insert(current.clone()) {
        let Some(assignment) = assignments.iter().rev().find(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(current.as_str())
        }) else {
            return assignment_values.iter().rev().any(|fact| {
                fact.assignment_span.file == before.file
                    && fact.assignment_span.start < before.start
                    && fact.target.as_deref() == Some(current.as_str())
                    && fact.direct_call_name.is_none()
                    && expression_flow_is_literal(&fact.value_flow)
            });
        };
        let Some(value) = assignment_values
            .iter()
            .find(|fact| fact.assignment_span == assignment.span)
        else {
            return false;
        };
        if value.direct_call_name.is_none() && expression_flow_is_literal(&value.value_flow) {
            return true;
        }
        let Some(call) = assignment.source_call else {
            return false;
        };
        if !rule_target_matches_call(call, &[], canonicalizer) {
            return false;
        }
        let Some(next) = assignment
            .source_call_args
            .first()
            .and_then(|argument| clean_overwrite_target_key(argument))
        else {
            return false;
        };
        current = next;
    }
    false
}

pub(super) fn python_compiled_regex_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "python" || sink_rule.tag.as_deref() != Some("path-traversal") {
        return None;
    }
    if !sanitizer_credits_sink_tag(Some("regex-validate"), sink_rule.tag.as_deref()) {
        return None;
    }
    let mut targets: Vec<String> = sink_tainted_args
        .iter()
        .flat_map(tainted_arg_target_keys)
        .filter(|target| !clean_conditional_helper_identifier(target) && !looks_like_clean_constant(target))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return None;
    }
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, snk.span, &mut branches);
    for branch in branches.into_iter().rev() {
        let Some((regex_name, guarded_target)) =
            python_compiled_regex_guard_condition(branch.condition, &targets)
        else {
            continue;
        };
        if !python_compiled_regex_declared_safe_before(
            ws,
            snk.span.file,
            branch.span,
            &regex_name,
            sink_rule.tag.as_deref(),
        ) {
            continue;
        }
        if !branch_arm_abruptly_exits(branch.then_events) {
            continue;
        }
        return finding_for_guard_span(
            snk,
            snapshot.text.as_ref(),
            branch.span,
            "engine.sanitizer.python_compiled_regex_guard",
            "regex-validate",
            &format!("compiled-regex-guard:{guarded_target}"),
        );
    }
    None
}

fn python_compiled_regex_guard_condition(condition: &str, targets: &[String]) -> Option<(String, String)> {
    let compact = compact_guard_text(condition);
    let call_text = compact
        .strip_prefix("not")
        .or_else(|| compact.strip_suffix("isNone"))
        .or_else(|| compact.strip_suffix("==None"))?;
    let (regex_name, arg) = python_compiled_regex_call_parts(call_text)?;
    let target = clean_overwrite_target_key(arg)?;
    targets
        .iter()
        .any(|candidate| candidate == &target)
        .then_some((regex_name, target))
}

fn python_compiled_regex_call_parts(call_text: &str) -> Option<(String, &str)> {
    for marker in [".fullmatch(", ".match("] {
        let Some(marker_idx) = call_text.find(marker) else {
            continue;
        };
        let receiver = call_text[..marker_idx].trim();
        if !python_identifier_path_like(receiver) {
            continue;
        }
        let args_start = marker_idx + marker.len();
        let args = call_text.get(args_start..call_text.rfind(')')?)?;
        let first_arg = args.split(',').next()?.trim();
        if first_arg.is_empty() {
            continue;
        }
        return Some((receiver.to_string(), first_arg));
    }
    None
}

fn python_compiled_regex_declared_safe_before(
    ws: &Workspace,
    file: FileId,
    guard_span: Span,
    regex_name: &str,
    sink_tag: Option<&str>,
) -> bool {
    let Some(file_index) = ws.exact_decl_index_shared(file) else {
        return false;
    };
    let mut assignments = Vec::new();
    for decl in &file_index.defs {
        collect_structured_assignments_before(&decl.flow_events, guard_span, &mut assignments);
    }
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    assignments.dedup_by_key(|assignment| assignment.span);
    for assignment in assignments.into_iter().rev() {
        if clean_overwrite_target_key(assignment.target).as_deref() != Some(regex_name) {
            continue;
        }
        if assignment
            .source_call
            .is_none_or(|call| clean_overwrite_callee_tail(call) != "compile")
        {
            continue;
        }
        let Some(pattern) = assignment
            .source_call_args
            .first()
            .and_then(|argument| python_first_string_literal(argument))
        else {
            return false;
        };
        return python_regex_pattern_safe_for_sink(&pattern, sink_tag);
    }
    false
}

fn python_first_string_literal(args: &str) -> Option<String> {
    let mut s = args.trim_start();
    while let Some(first) = s.chars().next() {
        match first {
            'r' | 'R' | 'u' | 'U' | 'b' | 'B' => s = &s[first.len_utf8()..],
            'f' | 'F' => return None,
            _ => break,
        }
    }
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for ch in s[quote.len_utf8()..].chars() {
        if escaped {
            out.push('\\');
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some(out);
        }
        out.push(ch);
    }
    None
}

fn python_regex_pattern_safe_for_sink(pattern: &str, sink_tag: Option<&str>) -> bool {
    if sink_tag != Some("path-traversal") {
        return false;
    }
    let p = pattern.trim();
    if !p.starts_with('^') || !p.ends_with('$') {
        return false;
    }
    if p.contains("[^")
        || p.contains(".*")
        || p.contains(".+")
        || p.contains("(?")
        || p.contains('/')
        || p.contains("\\\\")
    {
        return false;
    }
    if python_regex_has_unescaped_wildcard_dot(p) {
        return false;
    }
    p.contains('[')
        && p.contains(']')
        && (p.contains("A-Z") || p.contains("a-z") || p.contains("0-9") || p.contains("\\d"))
}

fn python_regex_has_unescaped_wildcard_dot(pattern: &str) -> bool {
    let mut in_class = false;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '.' if !in_class => return true,
            _ => {}
        }
    }
    false
}

fn path_containment_target_and_base(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    guard: &PathContainmentGuardSemantics,
) -> Option<(String, String)> {
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let sink_target = sink_rule.match_spec.callee.as_ref()?;
    let target =
        containing_canonicalized_assignment_target(&decl.flow_events, snk.span, &guard.canonicalizer)?;
    let base = sink_call_base_arg_at(
        &decl.flow_events,
        snk.span,
        sink_target,
        guard.sink_base_arg_index,
    )?;
    Some((target, base))
}

fn containing_canonicalized_assignment_target(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
    canonicalizer: &RuleTarget,
) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                ..
            } if span_contains(*span, sink_span)
                && source_call
                    .as_deref()
                    .is_some_and(|call| rule_target_matches_call(call, &[], canonicalizer)) =>
            {
                return clean_overwrite_target_key(target);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(target) =
                    containing_canonicalized_assignment_target(then_events, sink_span, canonicalizer).or_else(
                        || containing_canonicalized_assignment_target(else_events, sink_span, canonicalizer),
                    )
                {
                    return Some(target);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(target) =
                    containing_canonicalized_assignment_target(body, sink_span, canonicalizer)
                {
                    return Some(target);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(target) =
                    containing_canonicalized_assignment_target(body, sink_span, canonicalizer)
                        .or_else(|| {
                            containing_canonicalized_assignment_target(catch_events, sink_span, canonicalizer)
                        })
                        .or_else(|| {
                            containing_canonicalized_assignment_target(
                                finally_events,
                                sink_span,
                                canonicalizer,
                            )
                        })
                {
                    return Some(target);
                }
            }
            _ => {}
        }
    }
    None
}

fn sink_call_base_arg_at(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
    sink_target: &RuleTarget,
    base_arg_index: usize,
) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver_types,
                args,
                ..
            } if (*span == sink_span || spans_overlap(*span, sink_span))
                && rule_target_matches_call(name, receiver_types, sink_target) =>
            {
                return args.get(base_arg_index).and_then(|arg| {
                    arg.place
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .or_else(|| {
                            let mut sources = arg
                                .source_names
                                .iter()
                                .filter_map(|source| clean_overwrite_target_key(source));
                            let source = sources.next()?;
                            sources.next().is_none().then_some(source)
                        })
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(base) = sink_call_base_arg_at(then_events, sink_span, sink_target, base_arg_index)
                    .or_else(|| sink_call_base_arg_at(else_events, sink_span, sink_target, base_arg_index))
                {
                    return Some(base);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(base) = sink_call_base_arg_at(body, sink_span, sink_target, base_arg_index) {
                    return Some(base);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(base) = sink_call_base_arg_at(body, sink_span, sink_target, base_arg_index)
                    .or_else(|| sink_call_base_arg_at(catch_events, sink_span, sink_target, base_arg_index))
                    .or_else(|| sink_call_base_arg_at(finally_events, sink_span, sink_target, base_arg_index))
                {
                    return Some(base);
                }
            }
            _ => {}
        }
    }
    None
}

fn path_containment_guard_condition(
    events: &[FlowEvent],
    condition_facts: &[BranchConditionFact],
    branch: StructuredBranch<'_>,
    candidate: &str,
    base: &str,
    containment_check: &RuleTarget,
    boundary_places: &[String],
) -> bool {
    let Some(condition) = branch_condition_fact_for_span(condition_facts, branch.span) else {
        return false;
    };
    if condition.polarity != BranchConditionPolarity::Negated {
        return false;
    }
    let query = ContainmentCheckQuery {
        condition_span: condition.condition_span,
        candidate,
        base,
        containment_check,
        boundary_places,
    };
    containment_check_call_before_body(events, &query)
}

#[derive(Copy, Clone)]
struct ContainmentCheckQuery<'a> {
    condition_span: Span,
    candidate: &'a str,
    base: &'a str,
    containment_check: &'a RuleTarget,
    boundary_places: &'a [String],
}

fn containment_check_call_before_body(events: &[FlowEvent], query: &ContainmentCheckQuery<'_>) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                args,
                ..
            } if span_contains(query.condition_span, *span) => {
                let receiver_matches = receiver
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .is_some_and(|receiver| receiver == query.candidate);
                if !receiver_matches
                    || !rule_target_matches_call(name, receiver_types, query.containment_check)
                {
                    continue;
                }
                let Some(argument) = args.first() else {
                    continue;
                };
                let base_is_operand = argument
                    .place
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .is_some_and(|place| place == query.base)
                    || argument
                        .source_names
                        .iter()
                        .filter_map(|source| clean_overwrite_target_key(source))
                        .any(|source| source == query.base);
                if base_is_operand
                    && query
                        .boundary_places
                        .iter()
                        .all(|boundary| argument.source_names.iter().any(|source| source == boundary))
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if containment_check_call_before_body(then_events, query)
                    || containment_check_call_before_body(else_events, query)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if containment_check_call_before_body(body, query) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if [body, catch_events, finally_events]
                    .into_iter()
                    .any(|region| containment_check_call_before_body(region, query))
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub(super) fn configured_argument_factory_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .configured_argument_factory_guard
        .as_ref()?;
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = sink_calls
        .iter()
        .find(|call| call.span == sink.span || spans_overlap(call.span, sink.span))?;
    let guarded_place = sink_call
        .args
        .get(guard.sink_argument_index)?
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)?;

    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let local_assignment = latest_structured_assignment_to(&sink_decl.flow_events, sink.span, &guarded_place);
    let file_decls: Vec<_> = file_index
        .defs
        .iter()
        .filter(|candidate| candidate.symbol != sink_decl.symbol)
        .filter_map(|candidate| ws.exact_decl(candidate.symbol))
        .collect();
    let assignment_span = local_assignment.or_else(|| {
        file_decls
            .iter()
            .filter(|candidate| candidate.name == "__module__")
            .filter_map(|candidate| {
                latest_structured_assignment_to(&candidate.flow_events, sink.span, &guarded_place)
            })
            .max_by_key(|span| (span.start, span.end))
    })?;
    let assignment =
        bonsai_lang_api::assignment_value_fact_for_span(&file_index.assignment_values, assignment_span)?;
    if !assignment
        .direct_call_name
        .as_deref()
        .is_some_and(|callee| rule_target_matches_call(callee, &[], &guard.factory))
    {
        return None;
    }

    let mut file_calls = sink_calls;
    for candidate in &file_decls {
        collect_structured_calls(&candidate.flow_events, &mut file_calls);
    }
    let factory_call = file_calls.iter().find(|call| {
        assignment
            .call_sites
            .iter()
            .any(|call_site| span_contains(*call_site, call.span))
            && rule_target_matches_call(call.name, call.receiver_types, &guard.factory)
    })?;
    let configured = guard.required_named_arguments.iter().all(|required| {
        let Some((argument_index, _)) = factory_call
            .args
            .iter()
            .enumerate()
            .find(|(_, argument)| argument.name.as_deref() == Some(required.name.as_str()))
        else {
            return false;
        };
        bonsai_lang_api::call_argument_value_fact(
            &file_index.call_argument_values,
            factory_call.span,
            argument_index,
        )
        .and_then(|fact| fact.static_value.as_ref())
            == Some(&required.value)
    });
    if !configured {
        return None;
    }

    finding_for_guard_span_in_workspace(
        ws,
        sink,
        assignment.assignment_span,
        "engine.sanitizer.configured_argument_factory_guard",
        sink_rule.tag.as_deref()?,
        "compiler-proven-configured-argument-factory",
    )
}

fn latest_structured_assignment_to(events: &[FlowEvent], before: Span, place: &str) -> Option<Span> {
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, before, &mut assignments);
    assignments
        .into_iter()
        .filter(|assignment| clean_overwrite_target_key(assignment.target).as_deref() == Some(place))
        .map(|assignment| assignment.span)
        .max_by_key(|span| (span.start, span.end))
}

pub(super) fn url_network_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .url_network_guard
        .as_ref()?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let exact_file_decls: Vec<_> = file_index
        .defs
        .iter()
        .filter_map(|candidate| ws.exact_decl(candidate.symbol))
        .collect();
    let mut file_calls = Vec::new();
    for file_decl in &exact_file_decls {
        collect_structured_calls(&file_decl.flow_events, &mut file_calls);
    }
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let sink_call = calls
        .iter()
        .find(|call| call.span == sink.span || spans_overlap(call.span, sink.span))?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(
        &decl.flow_events,
        Span::empty(sink.span.file, decl.span.end),
        &mut assignments,
    );
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let parsed = url_guard_root_place(sink_call, sink.span, guard, &calls, &assignments)?;
    let parser_assignment = assignments.iter().rev().find(|assignment| {
        assignment.span.start <= sink.span.start
            && clean_overwrite_target_key(assignment.target).as_deref() == Some(parsed.as_str())
            && assignment
                .source_call
                .is_some_and(|call| rule_target_matches_call(call, &[], &guard.parser))
    })?;
    let validation_end = if matches!(
        &guard.root,
        crate::rule::UrlGuardRootSemantics::SinkAssignmentTarget
    ) {
        decl.span.end
    } else {
        sink.span.start
    };

    let mut branches = Vec::new();
    collect_all_structured_branches(&decl.flow_events, &mut branches);
    let scheme_guard = branches
        .iter()
        .filter(|branch| {
            parser_assignment.span.start < branch.span.start
                && branch.span.start < validation_end
                && branch_arm_abruptly_exits(branch.then_events)
        })
        .find(|branch| {
            branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
                .and_then(|fact| fact.expression.as_ref())
                .is_some_and(|expression| {
                    url_scheme_rejection_is_exact(expression, &parsed, &guard.scheme, &calls, &file_index)
                })
        })?;
    let host_guard = branches
        .iter()
        .filter(|branch| {
            scheme_guard.span.start <= branch.span.start
                && branch.span.start < validation_end
                && branch_arm_abruptly_exits(branch.then_events)
        })
        .find(|branch| {
            branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
                .and_then(|fact| fact.expression.as_ref())
                .and_then(|expression| {
                    url_rejected_host_collection(expression, &parsed, &guard.host_allowlist, &calls)
                })
                .is_some_and(|collection| {
                    url_collection_is_static(
                        &collection,
                        branch.span,
                        &file_index,
                        &file_calls,
                        &guard.host_allowlist.static_collection_factories,
                    )
                })
        })?;

    let resolver_call = calls.iter().find(|call| {
        host_guard.span.start < call.span.start
            && call.span.start < validation_end
            && rule_target_matches_call(call.name, call.receiver_types, &guard.dns.resolver)
            && call.args.iter().any(|argument| {
                url_span_reads_component(argument.span, &parsed, &guard.host_allowlist.component, &calls)
            })
    })?;
    let resolver_targets: Vec<String> = assignments
        .iter()
        .filter(|assignment| {
            span_contains(assignment.span, resolver_call.span)
                && assignment
                    .source_call
                    .is_some_and(|call| rule_target_matches_call(call, &[], &guard.dns.resolver))
        })
        .filter_map(|assignment| clean_overwrite_target_key(assignment.target))
        .collect();
    if resolver_targets.is_empty() {
        return None;
    }
    let _private_guard = branches
        .iter()
        .filter(|branch| {
            resolver_call.span.start < branch.span.start
                && branch.span.start < validation_end
                && branch_arm_abruptly_exits(branch.then_events)
        })
        .find(|branch| {
            let Some(condition) = branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
            else {
                return false;
            };
            let Some(expression) = condition.expression.as_ref() else {
                return false;
            };
            if !url_condition_is_disjunction(expression) {
                return false;
            }
            let mut predicate_receiver: Option<String> = None;
            for predicate in &guard.dns.private_address_predicates {
                let Some(call) = calls.iter().find(|call| {
                    span_contains(condition.condition_span, call.span)
                        && rule_target_matches_call(call.name, call.receiver_types, predicate)
                }) else {
                    return false;
                };
                let Some(receiver) = call.receiver.and_then(clean_overwrite_target_key) else {
                    return false;
                };
                if predicate_receiver
                    .as_ref()
                    .is_some_and(|existing| existing != &receiver)
                {
                    return false;
                }
                predicate_receiver = Some(receiver);
            }
            predicate_receiver.is_some_and(|receiver| {
                url_place_derives_from_any(
                    &receiver,
                    &resolver_targets,
                    &assignments,
                    branch.span,
                    &mut AHashSet::new(),
                )
            })
        })?;
    if !url_redirect_guard_is_exact(
        &decl.flow_events,
        decl.span,
        sink_call,
        sink.span,
        &parsed,
        guard.redirect.as_ref(),
        &file_index,
    ) {
        return None;
    }
    let sink_tag = sink_rule.tag.as_deref()?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        scheme_guard.span,
        "engine.sanitizer.url_network_guard",
        sink_tag,
        "compiler-proven-url-network-guard",
    )
}

fn url_guard_root_place(
    sink_call: &StructuredCall<'_>,
    sink_span: Span,
    guard: &crate::rule::UrlNetworkGuardSemantics,
    calls: &[StructuredCall<'_>],
    assignments: &[StructuredAssignment<'_>],
) -> Option<String> {
    match &guard.root {
        crate::rule::UrlGuardRootSemantics::SinkReceiver => {
            sink_call.receiver.and_then(clean_overwrite_target_key)
        }
        crate::rule::UrlGuardRootSemantics::SinkAssignmentTarget => assignments
            .iter()
            .rev()
            .find(|assignment| {
                span_contains(assignment.span, sink_span)
                    && assignment
                        .source_call
                        .is_some_and(|call| rule_target_matches_call(call, &[], &guard.parser))
            })
            .and_then(|assignment| clean_overwrite_target_key(assignment.target)),
        crate::rule::UrlGuardRootSemantics::SinkArgumentAccessor {
            argument_index,
            accessor,
        } => {
            let argument = sink_call.args.get(*argument_index)?;
            let mut matching = calls.iter().filter(|call| {
                span_contains(argument.span, call.span)
                    && rule_target_matches_call(call.name, call.receiver_types, accessor)
            });
            let root = matching.next()?.receiver.and_then(clean_overwrite_target_key)?;
            matching.next().is_none().then_some(root)
        }
    }
}

fn url_scheme_rejection_is_exact(
    expression: &ConditionExpressionFact,
    parsed: &str,
    guard: &crate::rule::UrlSchemeGuardSemantics,
    calls: &[StructuredCall<'_>],
    file_index: &bonsai_lang_api::DeclIndex,
) -> bool {
    let terms: &[ConditionExpressionFact] = match expression {
        ConditionExpressionFact::Any { operands, .. } => operands,
        expression => std::slice::from_ref(expression),
    };
    terms.iter().any(|term| match term {
        ConditionExpressionFact::Equality {
            relation: ConditionEquality::NotEqual,
            left,
            right,
            ..
        } => {
            url_scheme_equality_matches(left, right, parsed, guard, calls)
                || url_scheme_equality_matches(right, left, parsed, guard, calls)
        }
        ConditionExpressionFact::Not { operand, .. } => match operand.as_ref() {
            ConditionExpressionFact::Equality {
                relation: ConditionEquality::Equal,
                left,
                right,
                ..
            } => {
                url_scheme_equality_matches(left, right, parsed, guard, calls)
                    || url_scheme_equality_matches(right, left, parsed, guard, calls)
            }
            ConditionExpressionFact::Atom { span } => {
                guard.comparison_predicate.as_ref().is_some_and(|predicate| {
                    url_scheme_predicate_matches(*span, parsed, guard, predicate, calls, file_index)
                })
            }
            _ => false,
        },
        _ => false,
    })
}

fn url_scheme_equality_matches(
    component: &ConditionOperandFact,
    literal: &ConditionOperandFact,
    parsed: &str,
    guard: &crate::rule::UrlSchemeGuardSemantics,
    calls: &[StructuredCall<'_>],
) -> bool {
    url_operand_reads_component(component, parsed, &guard.component, calls)
        && literal
            .static_string
            .as_ref()
            .is_some_and(|value| guard.allowed_values.iter().any(|allowed| allowed == value))
}

fn url_scheme_predicate_matches(
    atom_span: Span,
    parsed: &str,
    guard: &crate::rule::UrlSchemeGuardSemantics,
    predicate: &RuleTarget,
    calls: &[StructuredCall<'_>],
    file_index: &bonsai_lang_api::DeclIndex,
) -> bool {
    calls.iter().any(|call| {
        if !span_contains(atom_span, call.span)
            || !rule_target_matches_call(call.name, call.receiver_types, predicate)
        {
            return false;
        }
        let receiver_fact =
            bonsai_lang_api::call_receiver_fact_for_span(&file_index.call_receivers, call.span);
        let receiver_is_allowed = receiver_fact
            .and_then(|fact| fact.static_value.as_ref())
            .and_then(|value| match value {
                bonsai_lang_api::StaticScalarValue::String(value) => Some(value),
                _ => None,
            })
            .is_some_and(|value| guard.allowed_values.iter().any(|allowed| allowed == value));
        let argument_reads_component = call
            .args
            .iter()
            .any(|argument| url_span_reads_component(argument.span, parsed, &guard.component, calls));
        if receiver_is_allowed && argument_reads_component {
            return true;
        }
        let receiver_reads_component = receiver_fact.is_some_and(|fact| {
            url_span_reads_component(fact.receiver_span, parsed, &guard.component, calls)
        });
        receiver_reads_component
            && call.args.iter().enumerate().any(|(index, _)| {
                bonsai_lang_api::call_argument_value_fact(&file_index.call_argument_values, call.span, index)
                    .and_then(|fact| fact.static_value.as_ref())
                    .and_then(|value| match value {
                        bonsai_lang_api::StaticScalarValue::String(value) => Some(value),
                        _ => None,
                    })
                    .is_some_and(|value| guard.allowed_values.iter().any(|allowed| allowed == value))
            })
    })
}

fn url_operand_reads_component(
    operand: &ConditionOperandFact,
    parsed: &str,
    component: &crate::rule::UrlComponentSemantics,
    calls: &[StructuredCall<'_>],
) -> bool {
    if let Some(field) = component.field.as_deref() {
        return operand.value_flow.projection.as_ref().is_some_and(|projection| {
            projection.base == parsed
                && projection.path.len() == 1
                && projection.path.first().is_some_and(|segment| segment == field)
        });
    }
    url_span_reads_component(operand.span, parsed, component, calls)
}

fn url_span_reads_component(
    span: Span,
    parsed: &str,
    component: &crate::rule::UrlComponentSemantics,
    calls: &[StructuredCall<'_>],
) -> bool {
    component.accessor.as_ref().is_some_and(|accessor| {
        calls.iter().any(|call| {
            span_contains(span, call.span)
                && rule_target_matches_call(call.name, call.receiver_types, accessor)
                && call.receiver.and_then(clean_overwrite_target_key).as_deref() == Some(parsed)
        })
    })
}

fn url_rejected_host_collection(
    expression: &ConditionExpressionFact,
    parsed: &str,
    guard: &crate::rule::UrlHostAllowlistSemantics,
    calls: &[StructuredCall<'_>],
) -> Option<String> {
    let terms: &[ConditionExpressionFact] = match expression {
        ConditionExpressionFact::Any { operands, .. } => operands,
        expression => std::slice::from_ref(expression),
    };
    terms.iter().find_map(|term| match term {
        ConditionExpressionFact::Membership {
            subject,
            collection,
            then_contains: false,
            ..
        } if url_operand_reads_component(subject, parsed, &guard.component, calls) => collection
            .value_flow
            .place
            .as_deref()
            .and_then(clean_overwrite_target_key),
        ConditionExpressionFact::Not { operand, .. } => match operand.as_ref() {
            ConditionExpressionFact::Membership {
                subject,
                collection,
                then_contains: true,
                ..
            } if url_operand_reads_component(subject, parsed, &guard.component, calls) => collection
                .value_flow
                .place
                .as_deref()
                .and_then(clean_overwrite_target_key),
            ConditionExpressionFact::Atom { span } => {
                guard.membership_predicate.as_ref().and_then(|predicate| {
                    calls.iter().find_map(|call| {
                        (span_contains(*span, call.span)
                            && rule_target_matches_call(call.name, call.receiver_types, predicate)
                            && call.args.iter().any(|argument| {
                                url_span_reads_component(argument.span, parsed, &guard.component, calls)
                            }))
                        .then(|| call.receiver.and_then(clean_overwrite_target_key))
                        .flatten()
                    })
                })
            }
            _ => None,
        },
        _ => None,
    })
}

fn url_collection_is_static(
    collection: &str,
    before: Span,
    file_index: &bonsai_lang_api::DeclIndex,
    calls: &[StructuredCall<'_>],
    factories: &[RuleTarget],
) -> bool {
    let Some(assignment) = file_index
        .assignment_values
        .iter()
        .filter(|fact| {
            fact.assignment_span.start < before.start
                && fact
                    .target
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .as_deref()
                    == Some(collection)
        })
        .max_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end))
    else {
        return false;
    };
    if assignment.direct_call_name.is_none() && expression_flow_is_literal(&assignment.value_flow) {
        return true;
    }
    if assignment.direct_call_name.as_deref().is_some_and(|callee| {
        factories
            .iter()
            .any(|target| rule_target_matches_call(callee, &[], target))
    }) && assignment
        .exact_static_call_args
        .as_ref()
        .is_some_and(|arguments| !arguments.is_empty())
    {
        return true;
    }
    let Some(factory) = calls.iter().find(|call| {
        span_contains(assignment.assignment_span, call.span)
            && factories
                .iter()
                .any(|target| rule_target_matches_call(call.name, call.receiver_types, target))
    }) else {
        return false;
    };
    !factory.args.is_empty()
        && factory.args.iter().enumerate().all(|(index, _)| {
            bonsai_lang_api::call_argument_value_fact(&file_index.call_argument_values, factory.span, index)
                .is_some_and(|fact| fact.static_value.is_some())
        })
}

fn url_condition_is_disjunction(expression: &ConditionExpressionFact) -> bool {
    match expression {
        ConditionExpressionFact::Atom { .. } => true,
        ConditionExpressionFact::Any { operands, .. } => operands
            .iter()
            .all(|operand| matches!(operand, ConditionExpressionFact::Atom { .. })),
        _ => false,
    }
}

fn url_place_derives_from_any(
    place: &str,
    roots: &[String],
    assignments: &[StructuredAssignment<'_>],
    before: Span,
    visited: &mut AHashSet<String>,
) -> bool {
    if roots.iter().any(|root| root == place) {
        return true;
    }
    if !visited.insert(place.to_string()) {
        return false;
    }
    let derived = assignments
        .iter()
        .rev()
        .find(|assignment| {
            assignment.span.start < before.start
                && clean_overwrite_target_key(assignment.target).as_deref() == Some(place)
        })
        .is_some_and(|assignment| {
            assignment
                .source_name
                .into_iter()
                .chain(assignment.source_names.iter().map(String::as_str))
                .filter_map(clean_overwrite_target_key)
                .any(|source| {
                    url_place_derives_from_any(&source, roots, assignments, assignment.span, visited)
                })
        });
    visited.remove(place);
    derived
}

fn url_redirect_guard_is_exact(
    events: &[FlowEvent],
    decl_span: Span,
    sink_call: &StructuredCall<'_>,
    sink_span: Span,
    _parsed: &str,
    redirect: Option<&crate::rule::UrlRedirectGuardSemantics>,
    file_index: &bonsai_lang_api::DeclIndex,
) -> bool {
    let Some(redirect) = redirect else {
        return true;
    };
    match redirect {
        crate::rule::UrlRedirectGuardSemantics::ReceiverFieldExactCallback {
            field,
            required_return_place,
        } => {
            let Some(receiver) = sink_call.receiver.and_then(clean_overwrite_target_key) else {
                return false;
            };
            let target = format!("{receiver}.{field}");
            file_index.assignment_values.iter().rev().any(|fact| {
                span_contains(decl_span, fact.assignment_span)
                    && fact.assignment_span.start < sink_span.start
                    && fact.target.as_deref() == Some(target.as_str())
                    && fact
                        .exact_callable_return
                        .as_ref()
                        .and_then(|flow| flow.place.as_deref())
                        == Some(required_return_place.as_str())
            })
        }
        crate::rule::UrlRedirectGuardSemantics::PostSinkCall {
            call,
            argument_index,
            required_value,
        } => {
            let Some(result) = assignment_target_containing_span(events, sink_span) else {
                return false;
            };
            following_direct_call(events, sink_span, |candidate| {
                rule_target_matches_call(candidate.name, candidate.receiver_types, call)
                    && candidate.receiver.and_then(clean_overwrite_target_key).as_deref()
                        == Some(result.as_str())
                    && bonsai_lang_api::call_argument_value_fact(
                        &file_index.call_argument_values,
                        candidate.span,
                        *argument_index,
                    )
                    .and_then(|fact| fact.static_value.as_ref())
                        == Some(required_value)
            })
            .is_some()
        }
    }
}

fn assignment_target_containing_span(events: &[FlowEvent], target: Span) -> Option<String> {
    for event in events {
        match event {
            FlowEvent::Assign {
                span, target: place, ..
            } if span_contains(*span, target) => {
                return clean_overwrite_target_key(place);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(place) = assignment_target_containing_span(then_events, target)
                    .or_else(|| assignment_target_containing_span(else_events, target))
                {
                    return Some(place);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(place) = assignment_target_containing_span(body, target) {
                    return Some(place);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(place) = assignment_target_containing_span(body, target)
                    .or_else(|| assignment_target_containing_span(catch_events, target))
                    .or_else(|| assignment_target_containing_span(finally_events, target))
                {
                    return Some(place);
                }
            }
            _ => {}
        }
    }
    None
}

fn following_direct_call<'a>(
    events: &'a [FlowEvent],
    target: Span,
    predicate: impl Fn(StructuredCall<'a>) -> bool + Copy,
) -> Option<StructuredCall<'a>> {
    let sink_index = events.iter().position(|event| {
        matches!(event, FlowEvent::Call { span, .. } if *span == target || spans_overlap(*span, target))
    });
    if let Some(index) = sink_index {
        for event in &events[index + 1..] {
            match event {
                FlowEvent::Call {
                    span,
                    name,
                    receiver,
                    receiver_types,
                    args,
                    ..
                } => {
                    let call = StructuredCall {
                        span: *span,
                        name,
                        receiver: receiver.as_deref(),
                        receiver_types,
                        args,
                    };
                    if predicate(call) {
                        return Some(call);
                    }
                }
                FlowEvent::Branch { .. }
                | FlowEvent::Loop { .. }
                | FlowEvent::Try { .. }
                | FlowEvent::Defer { .. }
                | FlowEvent::Using { .. } => break,
                _ => {}
            }
        }
        return None;
    }
    for event in events {
        let found = match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => following_direct_call(then_events, target, predicate)
                .or_else(|| following_direct_call(else_events, target, predicate)),
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                following_direct_call(body, target, predicate)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => following_direct_call(body, target, predicate)
                .or_else(|| following_direct_call(catch_events, target, predicate))
                .or_else(|| following_direct_call(finally_events, target, predicate)),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

pub(super) fn go_jwt_inline_keyfunc_algorithm_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    if sink_rule
        .analysis_semantics
        .as_ref()
        .and_then(|semantics| semantics.guard_profile)
        != Some(GuardProfile::GoJwtInlineKeyfuncAlgorithm)
    {
        return None;
    }
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let parse_call = structured_call_at_match(&calls, snk.span, "parse")?;
    let callback_span = parse_call.args.get(1)?.span;
    let mut branches = Vec::new();
    collect_all_structured_branches(&decl.flow_events, &mut branches);
    let guard = branches.into_iter().find(|branch| {
        span_contains(callback_span, branch.span)
            && go_jwt_algorithm_pin_condition(branch.condition)
            && go_jwt_branch_rejects_mismatch(branch.then_events)
    })?;
    if !go_jwt_callback_returns_key(&decl.flow_events, callback_span, guard.span) {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        guard.span,
        "engine.sanitizer.go_jwt_inline_keyfunc_algorithm_guard",
        "jwt-verify",
        "jwt-algorithm-keyfunc-guard",
    )
}

fn go_jwt_algorithm_pin_condition(condition: &str) -> bool {
    let compact = compact_guard_text(condition);
    let lower = compact.to_ascii_lowercase();
    if !compact.contains(".Method.Alg()") || !compact.contains("!=") {
        return false;
    }
    if lower.contains("signingmethodnone")
        || lower.contains("unsafeallownonesignaturetype")
        || lower.contains("\"none\"")
        || lower.contains("'none'")
    {
        return false;
    }
    let Some((_, expected)) = compact.split_once("!=") else {
        return false;
    };
    let expected = expected.trim_matches(|ch| ch == '(' || ch == ')');
    (expected.starts_with('"') && expected.ends_with('"'))
        || (expected.starts_with('\'') && expected.ends_with('\''))
        || expected.contains("SigningMethod")
}

fn go_jwt_branch_rejects_mismatch(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return {
            value_name,
            value_flow,
            ..
        } => {
            value_name.is_none()
                && value_flow.source_names.iter().any(|source| {
                    source.ends_with("ErrSignatureInvalid") || source.ends_with("ErrTokenSignatureInvalid")
                })
        }
        FlowEvent::Call { name, .. } => {
            matches!(clean_overwrite_callee_tail(name).as_str(), "new" | "errorf")
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => go_jwt_branch_rejects_mismatch(then_events) || go_jwt_branch_rejects_mismatch(else_events),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            go_jwt_branch_rejects_mismatch(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            go_jwt_branch_rejects_mismatch(body)
                || go_jwt_branch_rejects_mismatch(catch_events)
                || go_jwt_branch_rejects_mismatch(finally_events)
        }
        _ => false,
    }) && branch_arm_abruptly_exits(events)
}

fn go_jwt_callback_returns_key(events: &[FlowEvent], callback_span: Span, reject_span: Span) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return {
            span,
            value_name,
            value_flow,
            ..
        } => {
            span_contains(callback_span, *span)
                && !span_contains(reject_span, *span)
                && value_name.as_deref().is_some_and(|name| name != "nil")
                && !value_flow.source_names.is_empty()
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            go_jwt_callback_returns_key(then_events, callback_span, reject_span)
                || go_jwt_callback_returns_key(else_events, callback_span, reject_span)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            go_jwt_callback_returns_key(body, callback_span, reject_span)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            go_jwt_callback_returns_key(body, callback_span, reject_span)
                || go_jwt_callback_returns_key(catch_events, callback_span, reject_span)
                || go_jwt_callback_returns_key(finally_events, callback_span, reject_span)
        }
        _ => false,
    })
}

pub(super) fn js_ts_local_html_escape_helper_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if !matches!(snk.language.as_str(), "javascript" | "typescript")
        || sink_rule.tag.as_deref() != Some("xss")
    {
        return None;
    }
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let sink_decl = file_index
        .defs
        .iter()
        .find(|decl| decl.symbol == SymbolId::new(sink_func.raw()))?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = structured_call_at_match(&sink_calls, snk.span, "")?;
    let tainted_places: Vec<String> = sink_tainted_args
        .iter()
        .flat_map(tainted_arg_target_keys)
        .collect();
    let helper_call = sink_calls.iter().find(|call| {
        call.span != sink_call.span
            && sink_call
                .args
                .iter()
                .any(|arg| span_contains(arg.span, call.span))
            && call.args.iter().any(|arg| {
                arg.place
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .is_some_and(|place| tainted_places.iter().any(|target| target == &place))
                    || arg.source_names.iter().any(|source| {
                        clean_overwrite_target_key(source)
                            .is_some_and(|source| tainted_places.iter().any(|target| target == &source))
                    })
            })
    })?;
    let helper = callee_spelling_tail(helper_call.name);
    let helper_lower = helper.to_ascii_lowercase();
    if !(helper_lower.contains("escape")
        || helper_lower.contains("encode")
        || helper_lower.contains("sanitize"))
    {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&file_index.assignment_values);
    let helper_decl = file_index
        .defs
        .iter()
        .find(|candidate| candidate.name == helper)?;
    let sanitizer_span = js_ts_html_escape_helper_span(
        &file_index.defs,
        helper_decl,
        &assignment_values,
        snapshot.text.as_ref(),
    )?;
    let mut finding = finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        sanitizer_span,
        "engine.sanitizer.js_ts_local_html_escape_helper",
        "html-encode",
        "local-html-escape-helper",
    )?;
    finding.enclosing_fn = Some(helper);
    Some(finding)
}

fn js_ts_html_escape_helper_span(
    file_decls: &[bonsai_lang_api::Decl],
    helper_decl: &bonsai_lang_api::Decl,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> Option<Span> {
    let input = helper_decl.params.first()?;
    let mut calls = Vec::new();
    collect_structured_calls(&helper_decl.flow_events, &mut calls);
    let mut returns = Vec::new();
    collect_return_bindings(&helper_decl.flow_events, &mut returns);
    calls.into_iter().find_map(|call| {
        if clean_overwrite_callee_tail(call.name) != "replace"
            || call.args.len() < 2
            || !call.name.strip_suffix(".replace").is_some_and(|receiver| {
                clean_overwrite_target_key(receiver).as_deref() == Some(input.as_str())
            })
            || !returns.iter().any(|(span, _)| span_contains(*span, call.span))
        {
            return None;
        }
        let pattern = compact_guard_text(&call.args[0].value_text);
        let covers_html_metacharacters = ['&', '<', '>', '\'', '"']
            .iter()
            .all(|character| pattern.contains(*character));
        if !covers_html_metacharacters {
            return None;
        }
        js_ts_replacement_has_html_entities(file_decls, &call.args[1], assignment_values, source_text)
            .then_some(call.span)
    })
}

fn js_ts_replacement_has_html_entities(
    file_decls: &[bonsai_lang_api::Decl],
    replacement: &bonsai_lang_api::CallArg,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    if html_entity_set_is_complete(&replacement.value_text) {
        return true;
    }
    let maps: Vec<String> = replacement
        .source_names
        .iter()
        .filter_map(|source| clean_overwrite_target_key(source))
        .map(|source| source.split('.').next().unwrap_or(&source).to_string())
        .collect();
    file_decls.iter().any(|decl| {
        let mut assignments = Vec::new();
        collect_structured_assignments_before(
            &decl.flow_events,
            Span::empty(decl.span.file, decl.span.end),
            &mut assignments,
        );
        assignments.into_iter().any(|assignment| {
            maps.iter()
                .any(|map| clean_overwrite_target_key(assignment.target).as_deref() == Some(map))
                && assignment_values
                    .rendering(assignment.span, source_text)
                    .is_some_and(html_entity_set_is_complete)
        })
    })
}

fn html_entity_set_is_complete(text: &str) -> bool {
    let compact = compact_guard_text(text).to_ascii_lowercase();
    compact.contains("&amp;")
        && compact.contains("&lt;")
        && compact.contains("&gt;")
        && (compact.contains("&quot;") || compact.contains("&#34;") || compact.contains("&#x22;"))
        && (compact.contains("&#39;") || compact.contains("&apos;") || compact.contains("&#x27;"))
}

fn structured_call_at_match<'a>(
    calls: &'a [StructuredCall<'a>],
    matched_span: Span,
    required_tail: &str,
) -> Option<&'a StructuredCall<'a>> {
    calls
        .iter()
        .filter(|call| {
            (required_tail.is_empty() || clean_overwrite_callee_tail(call.name) == required_tail)
                && (spans_overlap(call.span, matched_span)
                    || span_contains(matched_span, call.span)
                    || span_contains(call.span, matched_span))
        })
        .min_by_key(|call| call.span.start.abs_diff(matched_span.start))
}

pub(super) fn java_local_html_escape_helper_return_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "java" || sink_rule.tag.as_deref() != Some("xss") {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let decl = file_index
        .defs
        .iter()
        .find(|decl| decl.symbol == SymbolId::new(sink_func.raw()))?;
    let span_map = bonsai_common::cached_span_map_arc(snk.span.file, snapshot.version, &snapshot.text);
    let targets: Vec<String> = sink_tainted_args
        .iter()
        .filter_map(|arg| clean_overwrite_target_key(&arg.value_text))
        .filter(|target| !target.is_empty())
        .collect();
    for target in targets {
        let Some(helper) = java_helper_assigned_to_target_before_sink(&decl.flow_events, snk.span, &target)
        else {
            continue;
        };
        let Some((helper_decl, sanitizer_span)) = file_index
            .defs
            .iter()
            .filter(|candidate| candidate.name == helper)
            .find_map(|candidate| java_html_sanitizer_return_span(candidate).map(|span| (candidate, span)))
        else {
            continue;
        };
        let location = span_map.line_col(sanitizer_span.start);
        let san_text = snapshot
            .text
            .get(sanitizer_span.start as usize..sanitizer_span.end as usize)?
            .trim()
            .to_string();
        return Some(FindingMatch {
            origin: MatchOrigin::EngineSanitizer,
            rule_id: "engine.sanitizer.java_local_html_escape_helper_return".to_string(),
            file: snk.file.clone(),
            line: location.line,
            column: location.column,
            text: san_text,
            enclosing_fn: Some(helper_decl.name.clone()),
            tag: Some("html-encode".to_string()),
            severity: None,
            category: Some("local-html-escape-helper".to_string()),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
    }
    None
}

fn java_helper_assigned_to_target_before_sink(
    events: &[FlowEvent],
    before: Span,
    target: &str,
) -> Option<String> {
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, before, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    assignments.into_iter().rev().find_map(|assignment| {
        (clean_overwrite_target_key(assignment.target).as_deref() == Some(target))
            .then(|| assignment.source_call.map(callee_spelling_tail))
            .flatten()
    })
}

fn callee_spelling_tail(name: &str) -> String {
    name.rsplit(['.', ':'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or(name)
        .trim()
        .to_string()
}

fn java_html_sanitizer_return_span(decl: &bonsai_lang_api::Decl) -> Option<Span> {
    if decl.params.is_empty() {
        return None;
    }
    let mut assignments = Vec::new();
    collect_structured_assignments_before(
        &decl.flow_events,
        Span::empty(decl.span.file, decl.span.end),
        &mut assignments,
    );
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let mut returns = Vec::new();
    collect_return_bindings(&decl.flow_events, &mut returns);

    for call in calls {
        if !java_html_sanitizer_call_wraps_param(call.name, call.args, &decl.params) {
            continue;
        }
        if returns
            .iter()
            .any(|(return_span, _)| span_contains(*return_span, call.span))
        {
            return Some(call.span);
        }
        for assignment in &assignments {
            if !span_contains(assignment.span, call.span) {
                continue;
            }
            let Some(target) = clean_overwrite_target_key(assignment.target) else {
                continue;
            };
            if returns.iter().any(|(return_span, value_name)| {
                return_span.start > assignment.span.start
                    && value_name.and_then(clean_overwrite_target_key).as_deref() == Some(target.as_str())
            }) {
                return Some(assignment.span);
            }
        }
    }
    None
}

#[derive(Copy, Clone)]
struct StructuredCall<'a> {
    span: Span,
    name: &'a str,
    receiver: Option<&'a str>,
    receiver_types: &'a [String],
    args: &'a [bonsai_lang_api::CallArg],
}

fn collect_structured_calls<'a>(events: &'a [FlowEvent], out: &mut Vec<StructuredCall<'a>>) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                args,
                ..
            } => out.push(StructuredCall {
                span: *span,
                name,
                receiver: receiver.as_deref(),
                receiver_types,
                args,
            }),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_structured_calls(then_events, out);
                collect_structured_calls(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_structured_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_structured_calls(body, out);
                collect_structured_calls(catch_events, out);
                collect_structured_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_return_bindings<'a>(events: &'a [FlowEvent], out: &mut Vec<(Span, Option<&'a str>)>) {
    for event in events {
        match event {
            FlowEvent::Return { span, value_name, .. } => out.push((*span, value_name.as_deref())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_bindings(then_events, out);
                collect_return_bindings(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_bindings(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_bindings(body, out);
                collect_return_bindings(catch_events, out);
                collect_return_bindings(finally_events, out);
            }
            _ => {}
        }
    }
}

fn java_html_sanitizer_call_wraps_param(
    call_name: &str,
    args: &[bonsai_lang_api::CallArg],
    params: &[String],
) -> bool {
    const HTML_SANITIZER_SUFFIXES: &[&str] = &[
        "encodeforhtml",
        "encodeforhtmlattribute",
        "forhtml",
        "forhtmlcontent",
        "forhtmlattribute",
        "escapehtml",
        "htmlescape",
    ];
    let tail = clean_overwrite_callee_tail(call_name);
    HTML_SANITIZER_SUFFIXES.contains(&tail.as_str())
        && args.iter().any(|arg| {
            arg.place
                .as_deref()
                .and_then(clean_overwrite_target_key)
                .is_some_and(|place| params.iter().any(|param| param == &place))
                || arg.source_names.iter().any(|source| {
                    clean_overwrite_target_key(source)
                        .is_some_and(|source| params.iter().any(|param| param == &source))
                })
        })
}

pub(super) fn go_xml_decoder_hardening_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    if sink_rule
        .analysis_semantics
        .as_ref()
        .and_then(|semantics| semantics.guard_profile)
        != Some(GuardProfile::GoXmlDecoderHardening)
    {
        return None;
    }
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let decl = file_index
        .defs
        .iter()
        .find(|decl| decl.symbol == SymbolId::new(sink_func.raw()))?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let decoder_var = assignment_target_for_source_call_at(&decl.flow_events, snk.span, "NewDecoder")?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(
        &decl.flow_events,
        Span::empty(snk.span.file, decl.span.end),
        &mut assignments,
    );
    let strict_target = format!("{decoder_var}.Strict");
    let strict_true = assignments.iter().any(|assignment| {
        assignment.span.start > snk.span.start
            && assignment.target == strict_target
            && assignment.source_name.is_some_and(|source| source == "true")
    });
    let charset_target = format!("{decoder_var}.CharsetReader");
    let charset_assignment = assignments
        .iter()
        .find(|assignment| assignment.span.start > snk.span.start && assignment.target == charset_target)?;
    let callback = file_index.defs.iter().find(|candidate| {
        candidate.span.start >= charset_assignment.span.start
            && candidate.span.end <= charset_assignment.span.end
            && candidate.params.len() >= 2
    })?;
    if !(strict_true && go_charset_reader_callback_is_hardened(callback)) {
        return None;
    }
    finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        charset_assignment.span,
        "engine.sanitizer.go_xml_decoder_hardening",
        "xxe-sanitizer",
        "go-xml-decoder-hardening",
    )
}

fn go_charset_reader_callback_is_hardened(callback: &bonsai_lang_api::Decl) -> bool {
    let charset = callback.params.first().map(String::as_str).unwrap_or_default();
    let input = callback.params.get(1).map(String::as_str).unwrap_or_default();
    if charset.is_empty() || input.is_empty() {
        return false;
    }
    let mut branches = Vec::new();
    collect_all_structured_branches(&callback.flow_events, &mut branches);
    let mut calls = Vec::new();
    collect_structured_calls(&callback.flow_events, &mut calls);
    let rejected = branches.iter().any(|branch| {
        let condition = compact_guard_text(branch.condition);
        let negated_lookup = condition.starts_with('!') && condition.contains(&format!("[{charset}]"));
        let returns_error = branch_arm_abruptly_exits(branch.then_events)
            && calls.iter().any(|call| {
                span_contains(branch.span, call.span)
                    && matches!(clean_overwrite_callee_tail(call.name).as_str(), "new" | "errorf")
            });
        negated_lookup && returns_error
    });
    let mut returns = Vec::new();
    collect_return_bindings(&callback.flow_events, &mut returns);
    let returns_input = returns
        .iter()
        .any(|(_, value_name)| value_name.is_some_and(|value| value == input));
    rejected && returns_input
}

pub(super) fn nosql_eq_filter_wrapper_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink_rule.tag.as_deref() != Some("nosql-injection") || sink_tainted_args.is_empty() {
        return None;
    }
    let semantics = sink_rule.analysis_semantics.as_ref()?.nosql_filter.as_ref()?;
    if !sink_tainted_args
        .iter()
        .any(|arg| arg.index == semantics.filter_arg_index)
    {
        return None;
    }
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let sink_call = calls
        .iter()
        .find(|call| call.span == snk.span || spans_overlap(call.span, snk.span))?;
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let argument = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        sink_call.span,
        semantics.filter_arg_index,
    )?;
    if !nosql_filter_uses_only_literal_value_operators(
        &argument.value_flow,
        &semantics.literal_value_operators,
    ) {
        return None;
    }
    Some(FindingMatch {
        origin: MatchOrigin::EngineSanitizer,
        rule_id: "engine.sanitizer.nosql_literal_operator_filter".to_string(),
        file: snk.file.clone(),
        line: snk.line,
        column: snk.column,
        text: snk.match_text.clone(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("nosql-parameter".to_string()),
        severity: None,
        category: Some("nosql-eq-wrapper".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: vec![u32::try_from(semantics.filter_arg_index).ok()?],
    })
}

fn nosql_filter_uses_only_literal_value_operators(
    filter: &bonsai_lang_api::ExpressionFlow,
    literal_value_operators: &[String],
) -> bool {
    if filter.aggregate_fields.is_empty() || !filter.spreads.is_empty() || !filter.tuple_items.is_empty() {
        return false;
    }
    let mut saw_literal_operator = false;
    for field in &filter.aggregate_fields {
        if field.name.starts_with('$') {
            return false;
        }
        if expression_flow_is_literal(&field.value) {
            continue;
        }
        if field.value.aggregate_fields.len() != 1
            || !field.value.spreads.is_empty()
            || !field.value.tuple_items.is_empty()
            || !literal_value_operators
                .iter()
                .any(|operator| operator == &field.value.aggregate_fields[0].name)
        {
            return false;
        }
        saw_literal_operator = true;
    }
    saw_literal_operator
}

#[derive(Copy, Clone)]
struct StructuredAssignment<'a> {
    span: Span,
    target: &'a str,
    source_name: Option<&'a str>,
    source_names: &'a [String],
    source_call: Option<&'a str>,
    source_call_args: &'a [String],
}

#[derive(Copy, Clone)]
struct StructuredBranch<'a> {
    span: Span,
    condition: &'a str,
    then_events: &'a [FlowEvent],
}

fn collect_completed_branches_on_path<'a>(
    events: &'a [FlowEvent],
    target: Span,
    out: &mut Vec<StructuredBranch<'a>>,
) {
    for event in events {
        let event_span = event.span();
        if span_contains(event_span, target) {
            match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if events_contain_target(then_events, target) {
                        collect_completed_branches_on_path(then_events, target, out);
                    } else if events_contain_target(else_events, target) {
                        collect_completed_branches_on_path(else_events, target, out);
                    }
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_completed_branches_on_path(body, target, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if events_contain_target(body, target) {
                        collect_completed_branches_on_path(body, target, out);
                    } else if events_contain_target(catch_events, target) {
                        collect_completed_branches_on_path(catch_events, target, out);
                    } else if events_contain_target(finally_events, target) {
                        collect_completed_branches_on_path(finally_events, target, out);
                    }
                }
                _ => {}
            }
            return;
        }
        if event_span.file != target.file || event_span.end > target.start {
            continue;
        }
        if let FlowEvent::Branch {
            span,
            condition: Some(condition),
            then_events,
            ..
        } = event
        {
            out.push(StructuredBranch {
                span: *span,
                condition,
                then_events,
            });
        }
    }
}

fn collect_all_structured_branches<'a>(events: &'a [FlowEvent], out: &mut Vec<StructuredBranch<'a>>) {
    for event in events {
        match event {
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                if let Some(condition) = condition.as_deref() {
                    out.push(StructuredBranch {
                        span: *span,
                        condition,
                        then_events,
                    });
                }
                collect_all_structured_branches(then_events, out);
                collect_all_structured_branches(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_all_structured_branches(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_all_structured_branches(body, out);
                collect_all_structured_branches(catch_events, out);
                collect_all_structured_branches(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_following_branches_on_path<'a>(
    events: &'a [FlowEvent],
    target: Span,
    out: &mut Vec<StructuredBranch<'a>>,
) -> bool {
    let mut found_target = false;
    for event in events {
        if !found_target && (event.span() == target || span_contains(event.span(), target)) {
            found_target = match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if events_contain_target(then_events, target) {
                        collect_following_branches_on_path(then_events, target, out)
                    } else if events_contain_target(else_events, target) {
                        collect_following_branches_on_path(else_events, target, out)
                    } else {
                        true
                    }
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_following_branches_on_path(body, target, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if events_contain_target(body, target) {
                        collect_following_branches_on_path(body, target, out)
                    } else if events_contain_target(catch_events, target) {
                        collect_following_branches_on_path(catch_events, target, out)
                    } else if events_contain_target(finally_events, target) {
                        collect_following_branches_on_path(finally_events, target, out)
                    } else {
                        true
                    }
                }
                _ => true,
            };
            continue;
        }
        if !found_target {
            continue;
        }
        if let FlowEvent::Branch {
            span,
            condition: Some(condition),
            then_events,
            ..
        } = event
        {
            out.push(StructuredBranch {
                span: *span,
                condition,
                then_events,
            });
        }
    }
    found_target
}

fn events_contain_target(events: &[FlowEvent], target: Span) -> bool {
    events
        .iter()
        .any(|event| event.span() == target || span_contains(event.span(), target))
}

fn branch_arm_abruptly_exits(events: &[FlowEvent]) -> bool {
    for event in events {
        match event {
            FlowEvent::Return { .. } | FlowEvent::Throw { .. } => return true,
            FlowEvent::Call { name, .. }
                if matches!(
                    clean_overwrite_callee_tail(name).as_str(),
                    "abort" | "sendstatus" | "exit" | "panic"
                ) =>
            {
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if !else_events.is_empty()
                && branch_arm_abruptly_exits(then_events)
                && branch_arm_abruptly_exits(else_events) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn finding_for_guard_span(
    hit: &RuleMatch,
    source_text: &str,
    span: Span,
    rule_id: &str,
    tag: &str,
    category: &str,
) -> Option<FindingMatch> {
    let location = bonsai_common::SpanMap::new(source_text).line_col(span.start);
    let text = source_text
        .get(span.start as usize..span.end as usize)?
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    Some(FindingMatch {
        origin: MatchOrigin::EngineSanitizer,
        rule_id: rule_id.to_string(),
        file: hit.file.clone(),
        line: location.line,
        column: location.column,
        text,
        enclosing_fn: hit.enclosing_fn.clone(),
        tag: Some(tag.to_string()),
        severity: None,
        category: Some(category.to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
}

fn finding_for_guard_span_in_workspace(
    ws: &Workspace,
    hit: &RuleMatch,
    span: Span,
    rule_id: &str,
    tag: &str,
    category: &str,
) -> Option<FindingMatch> {
    let snapshot = ws.vfs().snapshot(span.file).ok()?;
    let (file, line, column) = resolve_span_location(ws, span);
    let text = snapshot
        .text
        .get(span.start as usize..span.end as usize)?
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    Some(FindingMatch {
        origin: MatchOrigin::EngineSanitizer,
        rule_id: rule_id.to_string(),
        file,
        line,
        column,
        text,
        enclosing_fn: hit.enclosing_fn.clone(),
        tag: Some(tag.to_string()),
        severity: None,
        category: Some(category.to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
}

fn collect_structured_assignments_before<'a>(
    events: &'a [FlowEvent],
    before: Span,
    out: &mut Vec<StructuredAssignment<'a>>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_names,
                source_call,
                source_call_args,
                ..
            } => {
                if span.file == before.file && span.start < before.start {
                    out.push(StructuredAssignment {
                        span: *span,
                        target,
                        source_name: source_name.as_deref(),
                        source_names,
                        source_call: source_call.as_deref(),
                        source_call_args,
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_structured_assignments_before(then_events, before, out);
                collect_structured_assignments_before(else_events, before, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_structured_assignments_before(body, before, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_structured_assignments_before(body, before, out);
                collect_structured_assignments_before(catch_events, before, out);
                collect_structured_assignments_before(finally_events, before, out);
            }
            _ => {}
        }
    }
}

pub(super) fn local_ldap_escape_helper_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink_rule.tag.as_deref() != Some("ldap-injection")
        || !matches!(
            snk.language.as_str(),
            "python" | "javascript" | "typescript" | "go"
        )
    {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let decl = file_index
        .defs
        .iter()
        .find(|decl| decl.symbol == SymbolId::new(sink_func.raw()))?;
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&file_index.assignment_values);
    let targets = ldap_tainted_filter_targets(sink_tainted_args);
    if targets.is_empty() {
        return None;
    }
    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, snk.span, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    for target in targets {
        for assignment in assignments.iter().rev() {
            if clean_overwrite_target_key(assignment.target).as_deref() != Some(target.as_str()) {
                continue;
            }
            if ldap_assignment_uses_verified_escape(
                &file_index.defs,
                assignment,
                &assignment_values,
                snapshot.text.as_ref(),
            ) {
                let mut finding = finding_for_guard_span(
                    snk,
                    snapshot.text.as_ref(),
                    assignment.span,
                    "engine.sanitizer.local_ldap_escape_helper",
                    "ldap-escape",
                    "local-rfc4515-escape-helper",
                )?;
                finding.sanitised_arg_indices = sink_tainted_args
                    .iter()
                    .filter_map(|arg| u32::try_from(arg.index).ok())
                    .collect();
                return Some(finding);
            }
        }
    }
    None
}

fn ldap_tainted_filter_targets(sink_tainted_args: &[TaintedArgInfo]) -> Vec<String> {
    let mut targets = Vec::new();
    for arg in sink_tainted_args {
        for key in tainted_arg_target_keys(arg) {
            if !matches!(
                key.as_str(),
                "scope"
                    | "sub"
                    | "err"
                    | "ev"
                    | "resolve"
                    | "reject"
                    | "out"
                    | "dn"
                    | "string"
                    | "String"
                    | "objectClass"
                    | "person"
            ) {
                targets.push(key);
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

fn ldap_assignment_uses_verified_escape(
    file_decls: &[bonsai_lang_api::Decl],
    assignment: &StructuredAssignment<'_>,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    if assignment.source_call.is_some_and(|call| {
        ldap_call_uses_verified_escape(file_decls, call, assignment.span, assignment_values, source_text)
    }) {
        return true;
    }
    file_decls.iter().any(|decl| {
        let mut calls = Vec::new();
        collect_structured_calls(&decl.flow_events, &mut calls);
        calls.into_iter().any(|call| {
            span_contains(assignment.span, call.span)
                && ldap_call_uses_verified_escape(
                    file_decls,
                    call.name,
                    assignment.span,
                    assignment_values,
                    source_text,
                )
        })
    })
}

fn ldap_call_uses_verified_escape(
    file_decls: &[bonsai_lang_api::Decl],
    call: &str,
    call_context: Span,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    let tail = clean_overwrite_callee_tail(call);
    if matches!(tail.as_str(), "escape_filter_chars" | "escapefilter")
        || (tail == "filter" && call.to_ascii_lowercase().contains("ldapescape"))
    {
        return true;
    }
    if tail == "replace" {
        let receiver = call
            .rsplit_once('.')
            .map(|(receiver, _)| receiver)
            .unwrap_or_default();
        if !receiver.is_empty() && ldap_replacer_assignment_is_safe(file_decls, receiver, call_context) {
            return true;
        }
    }
    let helper = callee_spelling_tail(call);
    file_decls
        .iter()
        .find(|decl| decl.name == helper)
        .is_some_and(|decl| local_ldap_helper_is_safe(file_decls, decl, assignment_values, source_text))
}

fn local_ldap_helper_is_safe(
    file_decls: &[bonsai_lang_api::Decl],
    helper: &bonsai_lang_api::Decl,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    let input = helper.params.first().map(String::as_str).unwrap_or_default();
    if input.is_empty() {
        return false;
    }
    let mut calls = Vec::new();
    collect_structured_calls(&helper.flow_events, &mut calls);
    let mut returns = Vec::new();
    collect_return_bindings(&helper.flow_events, &mut returns);
    let map_lookup_is_safe = calls.iter().any(|lookup| {
        if clean_overwrite_callee_tail(lookup.name) != "get" || lookup.args.len() < 2 {
            return false;
        }
        let Some(map) = lookup.name.rsplit_once('.').map(|(receiver, _)| receiver) else {
            return false;
        };
        let key = lookup.args[0].place.as_deref();
        if key.is_none() || lookup.args[1].place.as_deref() != key {
            return false;
        }
        let helper_consumes_input = calls.iter().any(|call| {
            call.args
                .iter()
                .any(|arg| arg.source_names.iter().any(|source| source == input))
        }) || helper.flow_events.iter().any(|event| match event {
            FlowEvent::Assign { source_names, .. } => source_names.iter().any(|source| source == input),
            _ => false,
        });
        helper_consumes_input
            && returns.iter().any(|(span, _)| span_contains(*span, lookup.span))
            && ldap_escape_map_assignment_is_safe(file_decls, map, assignment_values, source_text)
    });
    map_lookup_is_safe
        || calls.iter().any(|call| {
            clean_overwrite_callee_tail(call.name) == "replace"
                && call
                    .args
                    .iter()
                    .any(|arg| arg.source_names.iter().any(|source| source == input))
                && call.name.rsplit_once('.').is_some_and(|(receiver, _)| {
                    ldap_replacer_assignment_is_safe(file_decls, receiver, helper.span)
                })
                && returns.iter().any(|(span, _)| span_contains(*span, call.span))
        })
}

fn ldap_escape_map_assignment_is_safe(
    file_decls: &[bonsai_lang_api::Decl],
    map: &str,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    file_decls.iter().any(|decl| {
        let mut assignments = Vec::new();
        collect_structured_assignments_before(
            &decl.flow_events,
            Span::empty(decl.span.file, decl.span.end),
            &mut assignments,
        );
        assignments.into_iter().any(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(map)
                && assignment_values
                    .rendering(assignment.span, source_text)
                    .is_some_and(ldap_escape_table_literals_present)
        })
    })
}

fn ldap_replacer_assignment_is_safe(
    file_decls: &[bonsai_lang_api::Decl],
    receiver: &str,
    before: Span,
) -> bool {
    file_decls.iter().any(|decl| {
        let mut assignments = Vec::new();
        collect_structured_assignments_before(&decl.flow_events, before, &mut assignments);
        assignments.into_iter().any(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(receiver)
                && assignment
                    .source_call
                    .is_some_and(|call| clean_overwrite_callee_tail(call) == "newreplacer")
                && ldap_escape_table_literals_present(&assignment.source_call_args.join(" "))
        })
    })
}

fn ldap_escape_table_literals_present(text: &str) -> bool {
    ["\\5c", "\\2a", "\\28", "\\29", "\\00"]
        .iter()
        .all(|needle| text.contains(needle))
}

pub(super) fn go_same_origin_redirect_helper_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "go" || sink_rule.tag.as_deref() != Some("open-redirect") {
        return None;
    }
    let mut targets: Vec<String> = sink_tainted_args
        .iter()
        .filter(|arg| arg.index != usize::MAX)
        .flat_map(tainted_arg_target_keys)
        .filter(|target| !looks_like_clean_constant(target))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return None;
    }
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let decl = file_index
        .defs
        .iter()
        .find(|decl| decl.symbol == SymbolId::new(sink_func.raw()))?;
    let guard = find_go_same_origin_helper_guard(&decl.flow_events, snk.span, &targets)?;
    let helper_decl = file_index
        .defs
        .iter()
        .find(|candidate| candidate.name == guard.helper)?;
    if !go_same_origin_helper_is_safe(helper_decl) {
        return None;
    }
    let (file, line, column) = resolve_span_location(ws, guard.span);
    Some(FindingMatch {
        origin: MatchOrigin::EngineSanitizer,
        rule_id: "engine.sanitizer.go_same_origin_redirect_helper_guard".to_string(),
        file,
        line,
        column,
        text: guard.condition,
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("same-origin-path".to_string()),
        severity: None,
        category: Some("same-origin-helper-guard".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: sink_tainted_args
            .iter()
            .filter_map(|arg| u32::try_from(arg.index).ok())
            .collect(),
    })
}

struct GoSameOriginGuard {
    span: Span,
    condition: String,
    helper: String,
}

fn find_go_same_origin_helper_guard(
    events: &[FlowEvent],
    sink_span: Span,
    targets: &[String],
) -> Option<GoSameOriginGuard> {
    for event in events {
        match event {
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } if span.file == sink_span.file && span.start < sink_span.start => {
                if let Some(condition) = condition {
                    if let Some((helper, target)) = negated_single_arg_helper_call(condition) {
                        if targets.iter().any(|candidate| candidate == &target)
                            && branch_assigns_literal_to_target(then_events, &target)
                        {
                            return Some(GoSameOriginGuard {
                                span: *span,
                                condition: condition.clone(),
                                helper: helper.to_string(),
                            });
                        }
                    }
                }
                if let Some(found) = find_go_same_origin_helper_guard(then_events, sink_span, targets)
                    .or_else(|| find_go_same_origin_helper_guard(else_events, sink_span, targets))
                {
                    return Some(found);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(found) = find_go_same_origin_helper_guard(body, sink_span, targets) {
                    return Some(found);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(found) = find_go_same_origin_helper_guard(body, sink_span, targets)
                    .or_else(|| find_go_same_origin_helper_guard(catch_events, sink_span, targets))
                    .or_else(|| find_go_same_origin_helper_guard(finally_events, sink_span, targets))
                {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

fn negated_single_arg_helper_call(condition: &str) -> Option<(String, String)> {
    let compact = compact_guard_text(condition);
    let inner = compact.strip_prefix('!')?;
    let open = inner.find('(')?;
    let close = inner.rfind(')')?;
    if close + 1 != inner.len() {
        return None;
    }
    let helper = &inner[..open];
    let target = &inner[open + 1..close];
    if helper.is_empty()
        || target.is_empty()
        || !helper.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        || !target.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((helper.to_string(), target.to_string()))
}

fn branch_assigns_literal_to_target(events: &[FlowEvent], target: &str) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Assign {
            target: assigned,
            value_kind,
            ..
        } => {
            clean_overwrite_target_key(assigned).as_deref() == Some(target)
                && matches!(value_kind, Some(AssignValueKind::Literal))
        }
        _ => false,
    })
}

fn go_same_origin_helper_is_safe(helper: &bonsai_lang_api::Decl) -> bool {
    let input = helper.params.first().map(String::as_str).unwrap_or_default();
    if input.is_empty() {
        return false;
    }
    helper.flow_events.iter().any(|event| {
        let FlowEvent::Return {
            value_text: Some(value),
            value_flow,
            ..
        } = event
        else {
            return false;
        };
        let first = format!("{input}.0");
        let second = format!("{input}.1");
        if !(value_flow.source_names.iter().any(|source| source == &first)
            && value_flow.source_names.iter().any(|source| source == &second))
        {
            return false;
        }
        let compact = compact_guard_text(value);
        let first_is_slash =
            compact.contains(&format!("{input}[0]=='/'")) || compact.contains(&format!("{input}[0]==\"/\""));
        let second_is_not_slash =
            compact.contains(&format!("{input}[1]!='/'")) || compact.contains(&format!("{input}[1]!=\"/\""));
        let length_checked = compact.contains(&format!("len({input})>0"))
            && (compact.contains(&format!("len({input})==1"))
                || compact.contains(&format!("len({input})>1")));
        first_is_slash && second_is_not_slash && length_checked
    })
}

pub(super) fn python_url_ssrf_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "python" || sink_rule.tag.as_deref() != Some("ssrf") {
        return None;
    }
    let target = sink_tainted_args
        .iter()
        .filter(|arg| arg.index != usize::MAX)
        .find_map(|arg| clean_overwrite_target_key(&arg.value_text))?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let parsed_var = python_urlparse_assignment_var(&decl.flow_events, snk.span, &target)?;
    let mut branches = Vec::new();
    collect_all_structured_branches(&decl.flow_events, &mut branches);
    let relevant_branches: Vec<_> = branches
        .into_iter()
        .filter(|branch| branch.span.start < snk.span.start)
        .collect();
    let scheme_guard = relevant_branches.iter().find(|branch| {
        python_url_scheme_guard_condition(branch.condition, &parsed_var)
            && branch_arm_abruptly_exits(branch.then_events)
    });
    let host_allowlist = relevant_branches.iter().any(|branch| {
        python_url_host_allowlist_condition(branch.condition, &parsed_var)
            && branch_arm_abruptly_exits(branch.then_events)
    });
    let private_ip_reject = relevant_branches.iter().any(|branch| {
        python_private_ip_reject_condition(branch.condition) && branch_arm_abruptly_exits(branch.then_events)
    });
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let hostname_place = format!("{parsed_var}.hostname");
    let dns_lookup = calls.iter().any(|call| {
        call.span.start < snk.span.start
            && clean_overwrite_callee_tail(call.name) == "getaddrinfo"
            && call
                .args
                .first()
                .is_some_and(|arg| arg.place.as_deref() == Some(hostname_place.as_str()))
    });
    let redirects_disabled = calls.iter().any(|call| {
        call.span.start < snk.span.start
            && clean_overwrite_callee_tail(call.name) == "asyncclient"
            && call.args.iter().any(|arg| {
                arg.name.as_deref() == Some("follow_redirects")
                    && arg.value_text.trim().eq_ignore_ascii_case("false")
            })
    });
    if !(scheme_guard.is_some() && host_allowlist && dns_lookup && private_ip_reject && redirects_disabled) {
        return None;
    }
    let mut finding = finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        scheme_guard?.span,
        "engine.sanitizer.python_url_ssrf_guard",
        "ssrf-sanitize",
        "url-scheme-host-private-ip-guard",
    )?;
    finding.sanitised_arg_indices = sink_tainted_args
        .iter()
        .filter_map(|arg| u32::try_from(arg.index).ok())
        .collect();
    Some(finding)
}

fn python_url_scheme_guard_condition(condition: &str, parsed_var: &str) -> bool {
    let compact = compact_guard_text(condition);
    compact.contains(&format!("{parsed_var}.scheme!=\"https\""))
        || compact.contains(&format!("\"https\"!={parsed_var}.scheme"))
}

fn python_url_host_allowlist_condition(condition: &str, parsed_var: &str) -> bool {
    let compact = compact_guard_text(condition).to_ascii_lowercase();
    compact.contains(&format!("{parsed_var}.hostname").to_ascii_lowercase())
        && (compact.contains("notinallowed") || compact.contains("notinallowed_hosts"))
}

fn python_private_ip_reject_condition(condition: &str) -> bool {
    let compact = compact_guard_text(condition);
    compact.contains("is_private") && compact.contains("is_loopback") && compact.contains("is_link_local")
}

fn python_urlparse_assignment_var(events: &[FlowEvent], before: Span, target: &str) -> Option<String> {
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, before, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    assignments.into_iter().rev().find_map(|assignment| {
        let call = assignment.source_call?;
        if clean_overwrite_callee_tail(call) != "urlparse" {
            return None;
        }
        let argument = assignment.source_call_args.first()?;
        (clean_overwrite_target_key(argument).as_deref() == Some(target))
            .then(|| clean_overwrite_target_key(assignment.target))
            .flatten()
    })
}

fn assignment_target_for_source_call_at(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
    call_tail: &str,
) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                ..
            } if span_contains(*span, sink_span)
                && source_call.as_deref().is_some_and(|call| {
                    clean_overwrite_callee_tail(call) == clean_overwrite_callee_tail(call_tail)
                }) =>
            {
                return clean_overwrite_target_key(target);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(target) = assignment_target_for_source_call_at(then_events, sink_span, call_tail)
                    .or_else(|| assignment_target_for_source_call_at(else_events, sink_span, call_tail))
                {
                    return Some(target);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(target) = assignment_target_for_source_call_at(body, sink_span, call_tail) {
                    return Some(target);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(target) = assignment_target_for_source_call_at(body, sink_span, call_tail)
                    .or_else(|| assignment_target_for_source_call_at(catch_events, sink_span, call_tail))
                    .or_else(|| assignment_target_for_source_call_at(finally_events, sink_span, call_tail))
                {
                    return Some(target);
                }
            }
            _ => {}
        }
    }
    None
}

fn python_dev_only_env_guard_condition(condition: &str) -> bool {
    let lower = condition.trim().to_ascii_lowercase();
    let reads_env = lower.contains("os.environ.get")
        || lower.contains("os.getenv")
        || lower.contains("environ.get")
        || lower.contains("getenv(");
    if !reads_env {
        return false;
    }
    let negated = lower.contains("!=") || lower.contains(" not in ");
    if !negated {
        return false;
    }
    const DEV_LITERALS: &[&str] = &[
        "\"dev\"",
        "'dev'",
        "\"development\"",
        "'development'",
        "\"dev-internal\"",
        "'dev-internal'",
        "\"debug\"",
        "'debug'",
        "\"local\"",
        "'local'",
        "\"test\"",
        "'test'",
    ];
    DEV_LITERALS.iter().any(|literal| lower.contains(literal))
}

pub(super) fn finite_literal_map_lookup_allowlist_sanitizer(
    ws: &Workspace,
    sink: &RuleMatch,
    tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink.language != "python" {
        return None;
    }
    let snapshot = ws.vfs().snapshot(sink.span.file).ok()?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&file_index.assignment_values);
    let headers = ws.compiler_linkage_index();
    let enclosing = ws
        .enclosing_index()
        .enclosing_for(headers.as_ref(), sink.span.file, sink.span.start)?;
    let decl = ws.exact_decl(enclosing.symbol)?;
    let mut file_assignments = Vec::new();
    let exact_file_decls: Vec<_> = file_index
        .defs
        .iter()
        .filter_map(|candidate| ws.exact_decl(candidate.symbol))
        .collect();
    for candidate in &exact_file_decls {
        collect_structured_assignments_before(&candidate.flow_events, sink.span, &mut file_assignments);
    }
    file_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    file_assignments.dedup_by_key(|assignment| assignment.span);
    let mut local_assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, sink.span, &mut local_assignments);
    local_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let mut local_calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut local_calls);
    let span_map = bonsai_common::cached_span_map_arc(sink.span.file, snapshot.version, &snapshot.text);
    for arg in tainted_args {
        let target = arg
            .place
            .as_deref()
            .and_then(clean_overwrite_target_key)
            .or_else(|| clean_overwrite_target_key(&arg.value_text));
        if let Some(assignment) = target.as_deref().and_then(|target| {
            python_allowlisted_map_dependency_assignment(
                target,
                sink.span.start,
                &local_assignments,
                &local_calls,
                &file_assignments,
                &file_index.assignment_values,
                &file_index.call_argument_values,
            )
        }) {
            let location = span_map.line_col(assignment.span.start);
            let text = snapshot
                .text
                .get(assignment.span.start as usize..assignment.span.end as usize)?
                .trim()
                .to_string();
            return Some(FindingMatch {
                origin: MatchOrigin::EngineSanitizer,
                rule_id: "engine.sanitizer.literal_map_value_allowlist".to_string(),
                file: sink.file.clone(),
                line: location.line,
                column: location.column,
                text,
                enclosing_fn: sink.enclosing_fn.clone(),
                tag: Some("allowlist-validate".to_string()),
                severity: None,
                category: Some("finite-map-value-allowlist".to_string()),
                trust: None,
                payload_types: Vec::new(),
                tainted_args: Vec::new(),
                sanitised_arg_indices: Vec::new(),
            });
        }
        let Some((map_name, key_name)) = python_index_lookup_parts(&arg.value_text) else {
            continue;
        };
        if !python_literal_mapping_declared_before(
            &file_assignments,
            map_name,
            &assignment_values,
            snapshot.text.as_ref(),
        ) {
            continue;
        }
        for assignment in &local_assignments {
            let location = span_map.line_col(assignment.span.start);
            if location.column > sink.column {
                continue;
            }
            if !python_assignment_narrows_key_to_map(
                assignment,
                key_name,
                map_name,
                &assignment_values,
                snapshot.text.as_ref(),
            ) {
                continue;
            }
            let text = snapshot
                .text
                .get(assignment.span.start as usize..assignment.span.end as usize)?
                .trim()
                .to_string();
            return Some(FindingMatch {
                origin: MatchOrigin::EngineSanitizer,
                rule_id: "engine.sanitizer.literal_map_key_allowlist".to_string(),
                file: sink.file.clone(),
                line: location.line,
                column: location.column,
                text,
                enclosing_fn: sink.enclosing_fn.clone(),
                tag: Some("allowlist-validate".to_string()),
                severity: None,
                category: Some("finite-map-allowlist".to_string()),
                trust: None,
                payload_types: Vec::new(),
                tainted_args: Vec::new(),
                sanitised_arg_indices: Vec::new(),
            });
        }
    }
    None
}

pub(super) fn parameterized_query_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let semantics = sink_rule
        .analysis_semantics
        .as_ref()?
        .parameterized_query
        .as_ref()?;
    if !sanitizer_credits_sink_tag(Some("sql-parameterize"), sink_rule.tag.as_deref()) {
        return None;
    }
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let sink_call = calls
        .iter()
        .find(|call| call.span == sink.span || spans_overlap(call.span, sink.span))?;
    let query_arg = sink_call.args.get(semantics.query_arg_index)?;
    let bindings_arg = sink_call.args.get(semantics.bindings_arg_index)?;
    let query_target = query_arg.place.as_deref().and_then(clean_overwrite_target_key)?;
    let bindings_target = bindings_arg.place.as_deref().and_then(clean_overwrite_target_key);
    if bindings_target.as_deref() == Some(query_target.as_str()) {
        return None;
    }

    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, sink.span, &mut assignments);
    let mut file_assignments = Vec::new();
    let exact_file_decls: Vec<_> = file_index
        .defs
        .iter()
        .filter_map(|candidate| ws.exact_decl(candidate.symbol))
        .collect();
    for candidate in &exact_file_decls {
        collect_structured_assignments_before(&candidate.flow_events, sink.span, &mut file_assignments);
    }
    file_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    file_assignments.dedup_by_key(|assignment| assignment.span);

    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, sink.span, &mut branches);
    let guarded_fragments: AHashMap<String, Span> = branches
        .into_iter()
        .filter(|branch| branch_arm_abruptly_exits(branch.then_events))
        .filter_map(|branch| {
            let membership = branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)?
                .membership
                .as_ref()?;
            if membership.then_contains {
                return None;
            }
            let subject = clean_overwrite_target_key(&membership.subject)?;
            let collection = clean_overwrite_target_key(&membership.collection)?;
            literal_collection_declared_before(&file_assignments, &collection, &file_index.assignment_values)
                .then_some((subject, branch.span))
        })
        .collect();
    if guarded_fragments.is_empty() {
        return None;
    }

    let query_assignments: Vec<_> = assignments
        .iter()
        .filter(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(query_target.as_str())
        })
        .collect();
    if query_assignments.is_empty()
        || !query_assignments.iter().all(|assignment| {
            assignment.source_call.is_none()
                && assignment.source_names.iter().all(|source| {
                    clean_overwrite_target_key(source)
                        .is_some_and(|source| guarded_fragments.contains_key(&source))
                })
        })
        || !query_assignments
            .iter()
            .any(|assignment| !assignment.source_names.is_empty())
    {
        return None;
    }

    let guard_span = guarded_fragments
        .values()
        .copied()
        .min_by_key(|span| (span.start, span.end))?;
    let snapshot = ws.vfs().snapshot(sink.span.file).ok()?;
    let mut finding = finding_for_guard_span(
        sink,
        snapshot.text.as_ref(),
        guard_span,
        "engine.sanitizer.parameterized_query_allowlisted_fragments",
        "sql-parameterize",
        "parameterized-query-allowlisted-fragments",
    )?;
    finding.sanitised_arg_indices = vec![u32::try_from(semantics.query_arg_index).ok()?];
    Some(finding)
}

fn literal_collection_declared_before(
    assignments: &[StructuredAssignment<'_>],
    collection: &str,
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
) -> bool {
    assignments.iter().any(|assignment| {
        if clean_overwrite_target_key(assignment.target).as_deref() != Some(collection) {
            return false;
        }
        assignment_values
            .iter()
            .find(|fact| fact.assignment_span == assignment.span)
            .is_some_and(|fact| {
                let flow = &fact.value_flow;
                (!flow.tuple_items.is_empty() && flow.tuple_items.iter().all(expression_flow_is_literal))
                    || (!flow.aggregate_fields.is_empty()
                        && flow
                            .aggregate_fields
                            .iter()
                            .all(|field| expression_flow_is_literal(&field.value)))
            })
    })
}

fn expression_flow_is_literal(flow: &bonsai_lang_api::ExpressionFlow) -> bool {
    flow.place.is_none()
        && flow.projection.is_none()
        && flow.source_names.is_empty()
        && flow.call_sites.is_empty()
        && flow.spreads.is_empty()
        && flow.tuple_items.iter().all(expression_flow_is_literal)
        && flow
            .aggregate_fields
            .iter()
            .all(|field| expression_flow_is_literal(&field.value))
}

fn python_constant_literal_map_get_assignment(
    assignment: &StructuredAssignment<'_>,
    calls: &[StructuredCall<'_>],
    file_assignments: &[StructuredAssignment<'_>],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
) -> bool {
    let Some(source_call) = assignment.source_call else {
        return false;
    };
    let Some(map_name) = source_call.strip_suffix(".get") else {
        return false;
    };
    if !python_identifier_path_like(map_name) {
        return false;
    }
    let Some(call) = calls.iter().find(|call| {
        span_contains(assignment.span, call.span) && call.name == source_call && call.args.len() >= 2
    }) else {
        return false;
    };
    let default_is_same_map_value =
        call.args
            .get(1)
            .and_then(|arg| arg.place.as_deref())
            .is_some_and(|default_place| {
                default_place
                    .strip_prefix(map_name)
                    .is_some_and(|suffix| suffix.starts_with('.') && suffix.len() > 1)
            });
    let default_is_static_literal =
        bonsai_lang_api::call_argument_value_fact(call_argument_values, call.span, 1)
            .is_some_and(|fact| fact.static_value.is_some() && expression_flow_is_literal(&fact.value_flow));
    (default_is_same_map_value || default_is_static_literal)
        && python_constant_literal_mapping_declared_before(file_assignments, map_name, assignment_values)
}

/// Follow exact local def-use facts backwards from a tainted sink argument to
/// a finite literal-map lookup. This is a compiler slice over adapter-emitted
/// assignments, not a source-text/name search: every hop is the latest
/// dominating definition and the finite assignment table bounds traversal.
fn python_allowlisted_map_dependency_assignment<'a>(
    target: &str,
    before: u64,
    assignments: &[StructuredAssignment<'a>],
    calls: &[StructuredCall<'a>],
    file_assignments: &[StructuredAssignment<'a>],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
) -> Option<StructuredAssignment<'a>> {
    fn visit<'a>(
        target: &str,
        before: u64,
        assignments: &[StructuredAssignment<'a>],
        calls: &[StructuredCall<'a>],
        file_assignments: &[StructuredAssignment<'a>],
        assignment_values: &[bonsai_lang_api::AssignmentValueFact],
        call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
        visited: &mut AHashSet<String>,
    ) -> Option<StructuredAssignment<'a>> {
        if !visited.insert(target.to_string()) {
            return None;
        }
        let assignment = assignments.iter().rev().copied().find(|assignment| {
            assignment.span.start < before
                && clean_overwrite_target_key(assignment.target).as_deref() == Some(target)
        })?;
        if python_constant_literal_map_get_assignment(
            &assignment,
            calls,
            file_assignments,
            assignment_values,
            call_argument_values,
        ) {
            return Some(assignment);
        }
        assignment
            .source_name
            .into_iter()
            .chain(assignment.source_names.iter().map(String::as_str))
            .filter_map(clean_overwrite_target_key)
            .find_map(|source| {
                visit(
                    &source,
                    assignment.span.start,
                    assignments,
                    calls,
                    file_assignments,
                    assignment_values,
                    call_argument_values,
                    visited,
                )
            })
    }

    visit(
        target,
        before,
        assignments,
        calls,
        file_assignments,
        assignment_values,
        call_argument_values,
        &mut AHashSet::new(),
    )
}

fn python_constant_literal_mapping_declared_before(
    assignments: &[StructuredAssignment<'_>],
    map_name: &str,
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
) -> bool {
    assignments.iter().any(|assignment| {
        if clean_overwrite_target_key(assignment.target).as_deref() != Some(map_name) {
            return false;
        }
        let Some(value) = assignment_values
            .iter()
            .find(|fact| fact.assignment_span == assignment.span)
            .map(|fact| &fact.value_flow)
        else {
            return false;
        };
        !value.aggregate_fields.is_empty()
            && value.spreads.is_empty()
            && value.aggregate_fields.iter().all(|field| {
                field.value.place.is_none()
                    && field.value.projection.is_none()
                    && field.value.source_names.is_empty()
                    && field.value.call_sites.is_empty()
                    && field.value.aggregate_fields.is_empty()
                    && field.value.tuple_items.is_empty()
                    && field.value.spreads.is_empty()
            })
    })
}

pub(super) fn guarded_char_append_allowlist_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_tag: Option<&str>,
    tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink.language != "go" || sink_tag != Some("header-injection") {
        return None;
    }
    let mut targets: Vec<String> = tainted_args
        .iter()
        .flat_map(tainted_arg_target_keys)
        .filter(|target| !clean_conditional_helper_identifier(target) && !looks_like_clean_constant(target))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return None;
    }
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    for target in targets {
        let mut scan = GuardedCharAppendScan::default();
        collect_guarded_char_append_writes(&decl.flow_events, sink.span, &target, None, &mut scan);
        if scan.saw_dirty_write {
            continue;
        }
        let Some(span) = scan.sanitizer_span else {
            continue;
        };
        let (file, line, column) = resolve_span_location(ws, span);
        return Some(FindingMatch {
            origin: MatchOrigin::EngineSanitizer,
            rule_id: "engine.sanitizer.go_guarded_char_append_allowlist".to_string(),
            file,
            line,
            column,
            text: "guarded append character allowlist".to_string(),
            enclosing_fn: sink.enclosing_fn.clone(),
            tag: Some("char-allowlist".to_string()),
            severity: None,
            category: Some("guarded-char-allowlist".to_string()),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
    }
    None
}

#[derive(Default)]
struct GuardedCharAppendScan {
    sanitizer_span: Option<Span>,
    saw_dirty_write: bool,
}

fn collect_guarded_char_append_writes(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
    target: &str,
    guard_condition: Option<&str>,
    out: &mut GuardedCharAppendScan,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target: assign_target,
                source_call,
                source_names,
                source_call_args,
                value_kind,
                ..
            } => {
                if span.file != sink_span.file || span.start >= sink_span.start {
                    continue;
                }
                if clean_overwrite_target_key(assign_target).as_deref() != Some(target) {
                    continue;
                }
                if guarded_append_assign_is_char_allowlist(
                    source_call.as_deref(),
                    source_call_args,
                    target,
                    guard_condition,
                ) {
                    out.sanitizer_span.get_or_insert(*span);
                    continue;
                }
                if assignment_initializes_clean_buffer(
                    source_call.as_deref(),
                    source_names,
                    source_call_args,
                    *value_kind,
                ) {
                    continue;
                }
                out.saw_dirty_write = true;
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
                ..
            } => {
                if span.file != sink_span.file || span.start >= sink_span.start {
                    continue;
                }
                collect_guarded_char_append_writes(
                    then_events,
                    sink_span,
                    target,
                    condition.as_deref().or(guard_condition),
                    out,
                );
                collect_guarded_char_append_writes(else_events, sink_span, target, guard_condition, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_guarded_char_append_writes(body, sink_span, target, guard_condition, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_guarded_char_append_writes(body, sink_span, target, guard_condition, out);
                collect_guarded_char_append_writes(catch_events, sink_span, target, guard_condition, out);
                collect_guarded_char_append_writes(finally_events, sink_span, target, guard_condition, out);
            }
            _ => {}
        }
    }
}

fn guarded_append_assign_is_char_allowlist(
    source_call: Option<&str>,
    source_call_args: &[String],
    target: &str,
    guard_condition: Option<&str>,
) -> bool {
    if source_call.map(str::trim) != Some("append") || source_call_args.len() < 2 {
        return false;
    }
    if clean_overwrite_target_key(&source_call_args[0]).as_deref() != Some(target) {
        return false;
    }
    let appended = source_call_args[1].trim();
    !appended.is_empty()
        && guard_condition.is_some_and(|condition| header_char_allowlist_condition(condition, appended))
}

fn assignment_initializes_clean_buffer(
    source_call: Option<&str>,
    source_names: &[String],
    source_call_args: &[String],
    value_kind: Option<AssignValueKind>,
) -> bool {
    source_call.map(str::trim) == Some("make")
        || (source_names.is_empty()
            && source_call_args.is_empty()
            && matches!(
                value_kind,
                Some(AssignValueKind::Literal | AssignValueKind::Unknown)
            ))
}

pub(super) fn header_char_allowlist_condition(condition: &str, variable: &str) -> bool {
    let variable = variable.trim();
    if variable.is_empty() || !text_mentions_token(condition, variable) {
        return false;
    }
    let compact: String = condition.chars().filter(|ch| !ch.is_whitespace()).collect();
    let printable_floor = [
        format!("{variable}>=0x20"),
        format!("{variable}>0x1f"),
        format!("{variable}>=32"),
        format!("{variable}>31"),
        format!("0x20<={variable}"),
        format!("0x1f<{variable}"),
        format!("32<={variable}"),
        format!("31<{variable}"),
    ]
    .into_iter()
    .any(|needle| compact.contains(&needle));
    let crlf_excluded = printable_floor
        || (char_guard_excludes(&compact, variable, "'\\r'")
            && char_guard_excludes(&compact, variable, "'\\n'"))
        || (char_guard_excludes(&compact, variable, "\"\\r\"")
            && char_guard_excludes(&compact, variable, "\"\\n\""));
    let del_excluded = [
        format!("{variable}!=0x7f"),
        format!("{variable}<0x7f"),
        format!("{variable}<=0x7e"),
        format!("0x7f!={variable}"),
        format!("0x7f>{variable}"),
        format!("0x7e>={variable}"),
        format!("{variable}!=127"),
        format!("{variable}<127"),
        format!("{variable}<=126"),
    ]
    .into_iter()
    .any(|needle| compact.contains(&needle));
    crlf_excluded && (del_excluded || !printable_floor)
}

fn char_guard_excludes(compact_condition: &str, variable: &str, literal: &str) -> bool {
    compact_condition.contains(&format!("{variable}!={literal}"))
        || compact_condition.contains(&format!("{literal}!={variable}"))
}

fn python_index_lookup_parts(value: &str) -> Option<(&str, &str)> {
    let trimmed = value.trim();
    let open = trimmed.find('[')?;
    if !trimmed.ends_with(']') {
        return None;
    }
    let map_name = trimmed[..open].trim();
    let key_name = trimmed[open + 1..trimmed.len().saturating_sub(1)].trim();
    if python_identifier_path_like(map_name) && python_identifier_like(key_name) {
        Some((map_name, key_name))
    } else {
        None
    }
}

fn python_literal_mapping_declared_before(
    assignments: &[StructuredAssignment<'_>],
    map_name: &str,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    assignments.iter().any(|assignment| {
        clean_overwrite_target_key(assignment.target).as_deref() == Some(map_name)
            && assignment_values
                .rendering(assignment.span, source_text)
                .is_some_and(|rhs| rhs.starts_with('{'))
    })
}

fn python_assignment_narrows_key_to_map(
    assignment: &StructuredAssignment<'_>,
    key_name: &str,
    map_name: &str,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    if clean_overwrite_target_key(assignment.target).as_deref() != Some(key_name) {
        return false;
    }
    let Some(rhs) = assignment_values.rendering(assignment.span, source_text) else {
        return false;
    };
    if !(rhs.contains(" if ") && rhs.contains(" else ")) {
        return false;
    }
    let membership = format!(" in {map_name}");
    rhs.contains(&membership) && python_conditional_else_is_literal(rhs)
}

fn python_conditional_else_is_literal(rhs: &str) -> bool {
    let Some((_, else_value)) = rhs.rsplit_once(" else ") else {
        return false;
    };
    let else_value = else_value.trim();
    quoted_literal(else_value) || numeric_literal(else_value)
}

fn python_identifier_like(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn python_identifier_path_like(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && python_identifier_like(part))
}

#[cfg(test)]
mod structured_guard_tests {
    use super::*;

    fn span(start: u64, end: u64) -> Span {
        Span::new(FileId::new(0), start, end)
    }

    #[test]
    fn completed_environment_guard_comes_from_branch_facts() {
        let guard_span = span(0, 40);
        let target_span = span(50, 60);
        let events = [
            FlowEvent::Branch {
                span: guard_span,
                condition: Some("process.env.NODE_ENV !== 'development'".to_string()),
                then_events: vec![FlowEvent::Return {
                    span: span(30, 36),
                    value_text: None,
                    value_name: None,
                    value_flow: Default::default(),
                }],
                else_events: Vec::new(),
            },
            FlowEvent::Call {
                span: target_span,
                name: "sink".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: Vec::new(),
            },
        ];
        let mut branches = Vec::new();

        collect_completed_branches_on_path(&events, target_span, &mut branches);

        assert_eq!(branches.len(), 1);
        assert!(js_dev_only_env_guard_condition(branches[0].condition));
        assert!(branch_arm_abruptly_exits(branches[0].then_events));
    }

    #[test]
    fn python_environment_condition_is_ast_rendering_not_if_line() {
        assert!(python_dev_only_env_guard_condition(
            "os.getenv('APP_ENV') != 'dev'"
        ));
        assert!(!python_dev_only_env_guard_condition(
            "os.getenv('APP_ENV') == 'production'"
        ));
    }
}
