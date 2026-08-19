//! Inline guard / helper-shape sanitizer recognizers.
//!
//! `make_finding` consults these to decide whether a tainted flow is
//! neutralized by a recognizable code shape the rulepack cannot express
//! as a sanitizer rule: URL/SSRF host
//! guards, local escape-helper wrappers, hardened XML factories,
//! char-allowlist append loops, literal-map lookups, and the like.
//! Also owns the low-signal source/sink pairing demotion and the
//! template-interpolation scanner these recognizers share.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Exact compiler facts and taint lineage shared by value-shape guard
/// recognizers. Keeping this state together prevents each recognizer from
/// growing a separate, order-sensitive argument list.
pub(super) struct CompilerGuardContext<'a> {
    pub(super) ws: &'a Workspace,
    pub(super) call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    pub(super) source: &'a RuleMatch,
    pub(super) source_func: FuncId,
    pub(super) sink: &'a RuleMatch,
    pub(super) sink_rule: &'a Rule,
    pub(super) candidate_funcs: &'a [FuncId],
    pub(super) tainted_call_spans: &'a AHashSet<Span>,
    pub(super) taint_path: &'a [TaintPropagationStep],
    pub(super) sink_tainted_args: &'a [TaintedArgInfo],
}

pub(super) fn source_sink_pair_is_low_signal(
    source: &FindingMatch,
    source_rule: Option<&Rule>,
    sink_rule: &Rule,
) -> bool {
    // Inferred entry parameters are untrusted inputs, not confidential
    // values. A precise flow from such an input to an event/log/response
    // can be useful lineage, but it is not evidence of information
    // exposure. Concrete secret/identity source rules remain eligible.
    let Some(policy) = sink_rule.analysis_semantics.as_ref() else {
        return false;
    };
    if policy.suppress_inferred_sources == Some(true) && source.origin != MatchOrigin::Rulepack {
        return true;
    }
    if source.trust.as_deref() != Some("local") || policy.suppress_local_source_flow_classes.is_empty() {
        return false;
    }
    source_rule.is_some_and(|rule| {
        rule.analysis_semantics.as_ref().is_some_and(|semantics| {
            semantics
                .flow_classes
                .iter()
                .any(|class| policy.suppress_local_source_flow_classes.contains(class))
        })
    })
}

/// Prove that a sanitized write replaces an implicit context value before a
/// later consumer. A straight-line write is sufficient. A conditional write
/// is sufficient only when the owning frontend proves that the true arm is
/// selected for every non-null value read from the context channel.
pub(super) fn sanitized_context_rewrite_covers_consumer(
    ws: &Workspace,
    rewrite: &RuleMatch,
    consumer: &RuleMatch,
    rewrite_targets: &AHashSet<String>,
) -> bool {
    if rewrite.span.file != consumer.span.file
        || rewrite.span.end > consumer.span.start
        || rewrite_targets.is_empty()
    {
        return false;
    }
    let headers = ws.compiler_header_index();
    let Some(rewrite_owner) =
        ws.enclosing_index()
            .enclosing_for(headers.as_ref(), rewrite.span.file, rewrite.span.start)
    else {
        return false;
    };
    let Some(consumer_owner) =
        ws.enclosing_index()
            .enclosing_for(headers.as_ref(), consumer.span.file, consumer.span.start)
    else {
        return false;
    };
    if rewrite_owner.symbol != consumer_owner.symbol {
        return false;
    }
    let Some(decl) = ws.exact_decl(consumer_owner.symbol) else {
        return false;
    };
    if guaranteed_calls_before(&decl.flow_events, consumer.span)
        .iter()
        .any(|call| call.span == rewrite.span)
    {
        return true;
    }

    let Some(file_index) = ws.exact_decl_index_shared(consumer.span.file) else {
        return false;
    };
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, consumer.span, &mut branches);
    branches.into_iter().rev().any(|branch| {
        let mut branch_calls = Vec::new();
        collect_structured_calls(branch.then_events, &mut branch_calls);
        let rewrite_is_in_true_arm = branch_calls.iter().any(|call| call.span == rewrite.span);
        rewrite_is_in_true_arm
            && branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
                .and_then(|fact| fact.expression.as_ref())
                .is_some_and(|expression| {
                    condition_is_true_for_non_null_targets(expression, rewrite_targets) == GuardTruth::True
                })
    })
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum GuardTruth {
    True,
    False,
    Unknown,
}

fn condition_is_true_for_non_null_targets(
    expression: &ConditionExpressionFact,
    targets: &AHashSet<String>,
) -> GuardTruth {
    match expression {
        ConditionExpressionFact::Not { operand, .. } => {
            match condition_is_true_for_non_null_targets(operand, targets) {
                GuardTruth::True => GuardTruth::False,
                GuardTruth::False => GuardTruth::True,
                GuardTruth::Unknown => GuardTruth::Unknown,
            }
        }
        ConditionExpressionFact::All { operands, .. } => {
            let mut saw_unknown = false;
            for operand in operands {
                match condition_is_true_for_non_null_targets(operand, targets) {
                    GuardTruth::False => return GuardTruth::False,
                    GuardTruth::Unknown => saw_unknown = true,
                    GuardTruth::True => {}
                }
            }
            if saw_unknown {
                GuardTruth::Unknown
            } else {
                GuardTruth::True
            }
        }
        ConditionExpressionFact::Any { operands, .. } => {
            let mut saw_unknown = false;
            for operand in operands {
                match condition_is_true_for_non_null_targets(operand, targets) {
                    GuardTruth::True => return GuardTruth::True,
                    GuardTruth::Unknown => saw_unknown = true,
                    GuardTruth::False => {}
                }
            }
            if saw_unknown {
                GuardTruth::Unknown
            } else {
                GuardTruth::False
            }
        }
        ConditionExpressionFact::Equality {
            relation,
            left,
            right,
            ..
        } => non_null_target_equality(*relation, left, right, targets)
            .or_else(|| non_null_target_equality(*relation, right, left, targets))
            .unwrap_or(GuardTruth::Unknown),
        ConditionExpressionFact::Atom { .. }
        | ConditionExpressionFact::Truthy { .. }
        | ConditionExpressionFact::TypeTest { .. }
        | ConditionExpressionFact::Membership { .. } => GuardTruth::Unknown,
    }
}

fn non_null_target_equality(
    relation: ConditionEquality,
    candidate: &ConditionOperandFact,
    literal: &ConditionOperandFact,
    targets: &AHashSet<String>,
) -> Option<GuardTruth> {
    let candidate = candidate
        .value_flow
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)?;
    if !targets.contains(&candidate)
        || literal.static_value.as_ref() != Some(&bonsai_lang_api::StaticScalarValue::Null)
    {
        return None;
    }
    Some(match relation {
        ConditionEquality::Equal => GuardTruth::False,
        ConditionEquality::NotEqual => GuardTruth::True,
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

pub(super) fn runtime_type_rejection_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
    tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let semantics = sink_rule.analysis_semantics.as_ref()?.nosql_filter.as_ref()?;
    if semantics.safe_scalar_runtime_types.is_empty() {
        return None;
    }
    let sink_targets: AHashSet<String> = tainted_args
        .iter()
        .filter(|arg| arg.index == semantics.filter_arg_index)
        .flat_map(tainted_arg_target_keys)
        .collect();
    if sink_targets.is_empty() {
        return None;
    }

    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, sink.span, &mut branches);
    let mut safe_subjects = AHashMap::<String, Span>::new();
    for branch in branches {
        if !branch_arm_abruptly_exits(branch.then_events) {
            continue;
        }
        let Some(expression) = branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
            .and_then(|fact| fact.expression.as_ref())
        else {
            continue;
        };
        let mut tests = Vec::new();
        collect_runtime_type_tests(expression, &mut tests);
        for (test_span, subject, type_name) in tests {
            if !semantics
                .safe_scalar_runtime_types
                .iter()
                .any(|safe| safe == type_name)
                || !condition_false_implies_atom_true(expression, test_span)
            {
                continue;
            }
            let Some(subject) = subject
                .value_flow
                .place
                .as_deref()
                .and_then(clean_overwrite_target_key)
            else {
                continue;
            };
            if place_is_assigned_between(&decl.flow_events, &subject, branch.span.end, sink.span.start) {
                continue;
            }
            safe_subjects.entry(subject).or_insert(branch.span);
        }
    }
    if safe_subjects.is_empty() {
        return None;
    }

    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, sink.span, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    if !sink_targets.iter().all(|target| {
        target_is_built_only_from_runtime_safe_values(
            target,
            sink.span.start,
            &safe_subjects,
            &assignments,
            &calls,
            &mut AHashSet::new(),
        )
    }) {
        return None;
    }

    let guard_span = safe_subjects
        .values()
        .copied()
        .min_by_key(|span| (span.start, span.end))?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        guard_span,
        "engine.sanitizer.runtime_type_rejection_guard",
        sink_rule.tag.as_deref()?,
        "terminal-runtime-type-guard",
    )
}

pub(super) fn finite_literal_selection_sanitizer(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    sink: &RuleMatch,
    sink_rule: &Rule,
    tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    if file_index.finite_literal_selections.is_empty() {
        return None;
    }
    let enclosing = ws
        .enclosing_index()
        .enclosing_for(global, sink.span.file, sink.span.start)?;
    let decl = ws.exact_decl(enclosing.symbol)?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    if let Some(sink_call) = structured_call_at_match(&calls, sink.span, "") {
        if let Some(selection) = tainted_args.iter().find_map(|argument| {
            file_index.finite_literal_selections.iter().find(|selection| {
                selection.call_span == Some(sink_call.span)
                    && selection.argument_index == Some(argument.index)
            })
        }) {
            return finding_for_guard_span_in_workspace(
                ws,
                sink,
                selection.selection_span,
                "engine.sanitizer.finite_literal_selection",
                sink_rule.tag.as_deref()?,
                "compiler-proven-finite-literal-selection",
            );
        }
    }
    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, sink.span, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));

    let selection = tainted_args.iter().find_map(|arg| {
        tainted_arg_target_keys(arg).into_iter().find_map(|target| {
            finite_literal_selection_dependency(
                &target,
                sink.span.start,
                &assignments,
                &file_index.finite_literal_selections,
                &mut AHashSet::new(),
            )
        })
    })?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        selection.selection_span,
        "engine.sanitizer.finite_literal_selection",
        sink_rule.tag.as_deref()?,
        "compiler-proven-finite-literal-selection",
    )
}

fn finite_literal_selection_dependency<'a>(
    target: &str,
    before: u64,
    assignments: &[StructuredAssignment<'_>],
    selections: &'a [bonsai_lang_api::FiniteLiteralSelectionFact],
    visited: &mut AHashSet<String>,
) -> Option<&'a bonsai_lang_api::FiniteLiteralSelectionFact> {
    if !visited.insert(target.to_string()) {
        return None;
    }
    let assignment = assignments.iter().rev().find(|assignment| {
        assignment.span.start < before
            && clean_overwrite_target_key(assignment.target).as_deref() == Some(target)
    })?;
    if let Some(selection) = selections
        .iter()
        .find(|selection| selection.assignment_span == Some(assignment.span))
    {
        return Some(selection);
    }
    assignment
        .source_name
        .into_iter()
        .chain(assignment.source_names.iter().map(String::as_str))
        .filter_map(clean_overwrite_target_key)
        .find_map(|source| {
            finite_literal_selection_dependency(
                &source,
                assignment.span.start,
                assignments,
                selections,
                visited,
            )
        })
}

fn collect_runtime_type_tests<'a>(
    expression: &'a ConditionExpressionFact,
    out: &mut Vec<(Span, &'a ConditionOperandFact, &'a str)>,
) {
    match expression {
        ConditionExpressionFact::TypeTest {
            span,
            subject,
            type_name,
        } => out.push((*span, subject, type_name)),
        ConditionExpressionFact::Not { operand, .. } => {
            collect_runtime_type_tests(operand, out);
        }
        ConditionExpressionFact::All { operands, .. } | ConditionExpressionFact::Any { operands, .. } => {
            for operand in operands {
                collect_runtime_type_tests(operand, out);
            }
        }
        ConditionExpressionFact::Atom { .. }
        | ConditionExpressionFact::Truthy { .. }
        | ConditionExpressionFact::Equality { .. }
        | ConditionExpressionFact::Membership { .. } => {}
    }
}

fn target_is_built_only_from_runtime_safe_values(
    target: &str,
    before: u64,
    safe_subjects: &AHashMap<String, Span>,
    assignments: &[StructuredAssignment<'_>],
    calls: &[StructuredCall<'_>],
    visited: &mut AHashSet<String>,
) -> bool {
    if safe_subjects.contains_key(target) {
        return true;
    }
    if !visited.insert(target.to_string()) {
        return false;
    }
    let Some(assignment) = assignments.iter().rev().find(|assignment| {
        assignment.span.start < before
            && clean_overwrite_target_key(assignment.target).as_deref() == Some(target)
    }) else {
        return false;
    };

    // Prefer exact addressable call arguments nested in the RHS. This avoids
    // treating fluent API/type/member names as values while retaining every
    // actual dynamic operand (`email`, `password`, etc.).
    let mut dependencies: Vec<String> = calls
        .iter()
        .filter(|call| span_contains(assignment.span, call.span))
        .flat_map(|call| call.args.iter())
        .filter_map(|arg| arg.place.as_deref().and_then(clean_overwrite_target_key))
        .collect();
    if dependencies.is_empty() {
        dependencies.extend(
            assignment
                .source_name
                .into_iter()
                .chain(assignment.source_names.iter().map(String::as_str))
                .filter_map(clean_overwrite_target_key),
        );
    }
    dependencies.sort();
    dependencies.dedup();
    !dependencies.is_empty()
        && dependencies.iter().all(|dependency| {
            target_is_built_only_from_runtime_safe_values(
                dependency,
                assignment.span.start,
                safe_subjects,
                assignments,
                calls,
                visited,
            )
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
        ConditionExpressionFact::Atom { .. } | ConditionExpressionFact::Truthy { .. } => false,
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
        ConditionExpressionFact::Equality { .. }
        | ConditionExpressionFact::TypeTest { .. }
        | ConditionExpressionFact::Membership { .. } => false,
    }
}

fn condition_true_implies_atom_true(expression: &ConditionExpressionFact, atom: Span) -> bool {
    match expression {
        ConditionExpressionFact::Atom { span }
        | ConditionExpressionFact::Truthy { span, .. }
        | ConditionExpressionFact::TypeTest { span, .. } => span_contains(*span, atom),
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

pub(super) fn path_containment_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let semantics = sink_rule.analysis_semantics.as_ref()?;
    if semantics.guard_profile != Some(GuardProfile::CanonicalPathContainment) {
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
            sink_rule.tag.as_deref()?,
            "path-containment-guard",
        );
    }
    None
}

pub(super) fn path_consumer_containment_guard_sanitizer(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
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
    let guarded_span = path_consumer_guard_span(
        ws,
        call_graph,
        &decl,
        sink.span,
        guard.sink_path_arg_index,
        guard,
        None,
    )
    .or_else(|| path_consumer_helper_guard_span(ws, call_graph, sink_func, &decl, sink.span, guard))
    .or_else(|| {
        let guarded = call_graph
            .callers_of(sink_func)
            .filter(|edge| edge.precision.is_semantic())
            .find_map(|edge| {
                let caller = ws.exact_decl(SymbolId::new(edge.from.raw()))?;
                path_consumer_guard_span(
                    ws,
                    call_graph,
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
        sink_rule.tag.as_deref()?,
        "canonical-path-consumer-containment",
    )
}

fn path_consumer_helper_guard_span(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink_func: FuncId,
    sink_decl: &bonsai_lang_api::Decl,
    sink_span: Span,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> Option<Span> {
    let sink_index = ws.exact_decl_index_shared(sink_span.file)?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = sink_calls
        .iter()
        .find(|call| call.span == sink_span || spans_overlap(call.span, sink_span))?;
    let argument_fact = bonsai_lang_api::call_argument_value_fact(
        &sink_index.call_argument_values,
        sink_call.span,
        guard.sink_path_arg_index,
    )?;
    let mut reaching_call_sites = Vec::new();
    if let Some(span) = argument_fact.direct_call_span {
        reaching_call_sites.push(span);
    }
    collect_compiler_call_sites_reaching_value(
        &sink_index,
        &argument_fact.value_flow,
        sink_call.span,
        &mut reaching_call_sites,
        &mut AHashSet::new(),
    );
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_helper_sink sink={} argument={} reaching_calls={:?}",
        sink_decl.name,
        guard.sink_path_arg_index,
        reaching_call_sites
    );
    for helper_call in sink_calls.iter().filter(|call| {
        call.span != sink_call.span
            && reaching_call_sites
                .iter()
                .any(|site| spans_overlap(call.span, *site))
    }) {
        let targets = call_graph
            .callees_of(sink_func)
            .filter(|edge| edge.precision.is_semantic() && spans_overlap(edge.span, helper_call.span))
            .map(|edge| edge.to)
            .collect::<AHashSet<_>>();
        let mut targets = targets.into_iter();
        let Some(helper_func) = targets.next() else {
            continue;
        };
        if targets.next().is_some() {
            continue;
        }
        let Some(helper) = ws.exact_decl(SymbolId::new(helper_func.raw())) else {
            continue;
        };
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_helper_candidate sink={} helper={} call={:?}",
            sink_decl.name,
            helper.name,
            helper_call.span
        );
        if let Some(span) =
            path_guarded_helper_return_span(ws, call_graph, helper_func, &helper, guard, &mut AHashSet::new())
        {
            return Some(span);
        }
    }
    None
}

fn path_guarded_helper_return_span(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    helper_func: FuncId,
    helper: &bonsai_lang_api::Decl,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
    visited: &mut AHashSet<FuncId>,
) -> Option<Span> {
    if !visited.insert(helper_func) {
        return None;
    }
    if let Some(span) = path_guarded_helper_direct_return_span(ws, call_graph, helper, guard) {
        return Some(span);
    }
    let file_index = ws.exact_decl_index_shared(helper.span.file)?;
    let mut returns = Vec::new();
    collect_return_bindings(&helper.flow_events, &mut returns);
    let [(return_span, _)] = returns.as_slice() else {
        return None;
    };
    let flow = return_value_flow_at_match(&helper.flow_events, *return_span)?;
    if flow.call_sites.len() != 1
        || flow.place.is_some()
        || flow.projection.is_some()
        || !flow.source_names.is_empty()
        || !flow.aggregate_fields.is_empty()
        || !flow.tuple_items.is_empty()
        || !flow.spreads.is_empty()
    {
        return None;
    }
    let call_site = flow.call_sites[0];
    let mut calls = Vec::new();
    collect_structured_calls(&helper.flow_events, &mut calls);
    let call = calls.iter().find(|call| spans_overlap(call.span, call_site))?;
    let targets = call_graph
        .callees_of(helper_func)
        .filter(|edge| edge.precision.is_semantic() && spans_overlap(edge.span, call.span))
        .map(|edge| edge.to)
        .collect::<AHashSet<_>>();
    let mut targets = targets.into_iter();
    let target = targets.next()?;
    if targets.next().is_some() {
        return None;
    }
    let target_decl = ws.exact_decl(SymbolId::new(target.raw()))?;
    drop(file_index);
    path_guarded_helper_return_span(ws, call_graph, target, &target_decl, guard, visited)
}

fn path_guarded_helper_direct_return_span(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    helper: &bonsai_lang_api::Decl,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> Option<Span> {
    let file_index = ws.exact_decl_index_shared(helper.span.file)?;
    let mut returns = Vec::new();
    collect_return_bindings(&helper.flow_events, &mut returns);
    let [(return_span, Some(candidate))] = returns.as_slice() else {
        return None;
    };
    let candidate = clean_overwrite_target_key(candidate)?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(&helper.flow_events, *return_span, &mut assignments);
    let candidate_assignment = assignments.iter().rev().find(|assignment| {
        clean_overwrite_target_key(assignment.target).as_deref() == Some(candidate.as_str())
            && assignment
                .source_call
                .is_some_and(|call| rule_target_matches_call(call, &[], &guard.canonicalizer))
    })?;
    let mut calls = Vec::new();
    collect_structured_calls(&helper.flow_events, &mut calls);
    let path_constructor_calls = calls
        .iter()
        .filter(|call| {
            span_contains(candidate_assignment.span, call.span)
                && rule_target_matches_call(call.name, &[], &guard.path_constructor)
        })
        .collect::<Vec<_>>();
    let [path_constructor_call] = path_constructor_calls.as_slice() else {
        return None;
    };
    let base = if guard.path_constructor_base_from_receiver {
        path_constructor_call
            .receiver
            .and_then(clean_overwrite_target_key)?
    } else {
        compiler_call_argument_place(
            &file_index,
            path_constructor_call.span,
            guard.path_constructor_base_arg_index,
        )?
    };
    let base_is_static =
        place_has_static_canonical_provenance_or_static_callers(StaticCanonicalProvenanceContext {
            ws,
            call_graph,
            decl: helper,
            place: &base,
            assignments: &assignments,
            assignment_values: &file_index.assignment_values,
            call_argument_values: &file_index.call_argument_values,
            canonicalizer: guard.base_canonicalizer.as_ref().unwrap_or(&guard.canonicalizer),
            static_base_factories: &guard.static_base_factories,
            before: candidate_assignment.span,
        });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_helper_direct helper={} candidate={} base={} base_static={}",
        helper.name,
        candidate,
        base,
        base_is_static
    );
    if !base_is_static {
        return None;
    }
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&helper.flow_events, *return_span, &mut branches);
    let guarded = branches.into_iter().rev().find_map(|branch| {
        (branch_arm_abruptly_exits(branch.then_events)
            && path_containment_guard_condition(
                &helper.flow_events,
                &file_index.branch_conditions,
                branch,
                &candidate,
                &base,
                &guard.containment_check,
                &guard.boundary_places,
            ))
        .then_some(branch.span)
    });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_helper_result helper={} guarded={:?}",
        helper.name,
        guarded
    );
    guarded
}

fn compiler_call_argument_place(
    file_index: &bonsai_lang_api::DeclIndex,
    call_span: Span,
    argument_index: usize,
) -> Option<String> {
    let fact = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        call_span,
        argument_index,
    )?;
    fact.value_flow
        .projection
        .as_ref()
        .map(bonsai_lang_api::ExpressionProjection::canonical_place)
        .or_else(|| {
            fact.value_flow
                .place
                .as_deref()
                .and_then(clean_overwrite_target_key)
        })
}

fn compiler_call_receiver_place(
    file_index: &bonsai_lang_api::DeclIndex,
    call: &StructuredCall<'_>,
) -> Option<String> {
    bonsai_lang_api::call_receiver_fact_for_span(&file_index.call_receivers, call.span)
        .and_then(|fact| {
            fact.value_flow
                .projection
                .as_ref()
                .map(bonsai_lang_api::ExpressionProjection::canonical_place)
                .or_else(|| {
                    fact.value_flow
                        .place
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                })
        })
        .or_else(|| call.receiver.and_then(clean_overwrite_target_key))
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
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let sink_call =
        structured_call_at_match(&calls, sink.span, &clean_overwrite_callee_tail(&sink.match_text))?;
    let receiver = compiler_call_receiver_place(&file_index, sink_call)?;
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
    if !guard.required_nested_factories.is_empty() {
        let file_decls = file_index
            .defs
            .iter()
            .filter_map(|header| ws.exact_decl(header.symbol))
            .collect::<Vec<_>>();
        let mut file_calls = Vec::new();
        for candidate in &file_decls {
            collect_structured_calls(&candidate.flow_events, &mut file_calls);
        }
        if !guard.required_nested_factories.iter().all(|required| {
            file_calls.iter().any(|call| {
                span_contains(assignment.value_span, call.span)
                    && rule_target_matches_call(call.name, call.receiver_types, required)
            })
        }) {
            return None;
        }
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

pub(super) fn receiver_configuration_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .receiver_configuration_guard
        .as_ref()?;
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = structured_call_at_match(&sink_calls, sink.span, "")?;
    let receiver = compiler_call_receiver_place(&file_index, sink_call)?;

    let local_calls = guaranteed_calls_before(&sink_decl.flow_events, sink.span);
    if let Some(span) =
        receiver_configuration_proof_span(&file_index, &local_calls, &receiver, &guard.required_calls)
    {
        let overwritten_after_proof =
            latest_assignment_to_compiler_place(&file_index.assignment_values, &receiver, sink.span.start)
                .is_some_and(|assignment| assignment.assignment_span.start > span.start);
        if !overwritten_after_proof {
            return finding_for_guard_span_in_workspace(
                ws,
                sink,
                span,
                "engine.sanitizer.receiver_configuration_guard",
                sink_rule.tag.as_deref()?,
                "compiler-proven-receiver-configuration",
            );
        }
    }

    let parent = sink_decl.parent?;
    if !file_index.assignment_values.iter().any(|assignment| {
        assignment.target_is_immutable
            && assignment.target_owner == Some(parent)
            && compiler_assignment_target_place(assignment) == Some(receiver.as_str())
    }) {
        return None;
    }
    let constructors = file_index
        .defs
        .iter()
        .filter(|decl| decl.kind == DeclKind::Constructor && decl.parent == Some(parent))
        .filter_map(|decl| ws.exact_decl(decl.symbol))
        .collect::<Vec<_>>();
    if constructors.is_empty() {
        return None;
    }
    let mut proof_spans = Vec::with_capacity(constructors.len());
    for constructor in &constructors {
        let before_end = Span::empty(constructor.span.file, constructor.span.end);
        let calls = guaranteed_calls_before(&constructor.flow_events, before_end);
        proof_spans.push(receiver_configuration_proof_span(
            &file_index,
            &calls,
            &receiver,
            &guard.required_calls,
        )?);
    }
    let proof = proof_spans
        .into_iter()
        .min_by_key(|span| (span.start, span.end))?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        proof,
        "engine.sanitizer.receiver_configuration_guard",
        sink_rule.tag.as_deref()?,
        "compiler-proven-receiver-configuration",
    )
}

fn latest_assignment_to_compiler_place<'a>(
    assignments: &'a [bonsai_lang_api::AssignmentValueFact],
    place: &str,
    before: u64,
) -> Option<&'a bonsai_lang_api::AssignmentValueFact> {
    assignments
        .iter()
        .filter(|assignment| {
            assignment.assignment_span.start < before
                && compiler_assignment_target_place(assignment) == Some(place)
        })
        .max_by_key(|assignment| (assignment.assignment_span.start, assignment.assignment_span.end))
}

/// Returns the adapter-owned canonical assignment place without reparsing it.
///
/// `AssignmentValueFact::target` is typed compiler IR. Applying the display-text
/// cleaner here rejects valid member places such as `this.client` and creates a
/// second, language-agnostic lowering path in shared security analysis.
fn compiler_assignment_target_place(assignment: &bonsai_lang_api::AssignmentValueFact) -> Option<&str> {
    assignment
        .target
        .as_deref()
        .map(str::trim)
        .filter(|target| !target.is_empty())
}

fn receiver_configuration_proof_span(
    file_index: &bonsai_lang_api::DeclIndex,
    calls: &[StructuredCall<'_>],
    receiver: &str,
    required_calls: &[crate::rule::RequiredReceiverCallSemantics],
) -> Option<Span> {
    let mut proof = None;
    for required in required_calls {
        let call = calls.iter().rev().find(|call| {
            compiler_call_receiver_place(file_index, call).as_deref() == Some(receiver)
                && rule_target_matches_call(call.name, call.receiver_types, &required.call)
                && receiver_configuration_identity_matches(file_index, call.span, required)
        })?;
        if !required
            .required_arguments
            .iter()
            .all(|argument| receiver_configuration_argument_matches(file_index, call.span, argument))
        {
            return None;
        }
        proof = Some(proof.map_or(call.span, |current: Span| {
            if (call.span.start, call.span.end) < (current.start, current.end) {
                call.span
            } else {
                current
            }
        }));
    }
    proof
}

fn receiver_configuration_identity_matches(
    file_index: &bonsai_lang_api::DeclIndex,
    call_span: Span,
    required: &crate::rule::RequiredReceiverCallSemantics,
) -> bool {
    required.identity_argument_indices.iter().all(|identity_index| {
        required
            .required_arguments
            .iter()
            .find(|argument| argument.index == *identity_index)
            .is_some_and(|argument| receiver_configuration_argument_matches(file_index, call_span, argument))
    })
}

fn receiver_configuration_argument_matches(
    file_index: &bonsai_lang_api::DeclIndex,
    call_span: Span,
    argument: &crate::rule::RequiredCallArgumentSemantics,
) -> bool {
    let Some(fact) = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        call_span,
        argument.index,
    ) else {
        return false;
    };
    let place = fact
        .value_flow
        .projection
        .as_ref()
        .map(bonsai_lang_api::ExpressionProjection::canonical_place)
        .or_else(|| {
            fact.value_flow
                .place
                .as_deref()
                .and_then(clean_overwrite_target_key)
        });
    let place_matches = place
        .is_some_and(|place| argument.accepted_places.iter().any(|accepted| accepted == &place))
        || fact
            .value_flow
            .source_names
            .iter()
            .any(|source| argument.accepted_places.iter().any(|accepted| accepted == source));
    let scalar_matches = fact.static_value.as_ref().is_some_and(|value| {
        argument.require_static_value
            || argument
                .accepted_static_values
                .iter()
                .any(|accepted| accepted == value)
    });
    place_matches || scalar_matches
}

fn guaranteed_calls_before<'a>(events: &'a [FlowEvent], target: Span) -> Vec<StructuredCall<'a>> {
    let mut calls = Vec::new();
    collect_guaranteed_calls_before(events, target, &mut calls);
    calls
}

fn collect_guaranteed_calls_before<'a>(
    events: &'a [FlowEvent],
    target: Span,
    out: &mut Vec<StructuredCall<'a>>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                args,
                ..
            } if span.end <= target.start => out.push(StructuredCall {
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
                if events_contain_span(then_events, target) {
                    collect_guaranteed_calls_before(then_events, target, out);
                    return;
                }
                if events_contain_span(else_events, target) {
                    collect_guaranteed_calls_before(else_events, target, out);
                    return;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if events_contain_span(body, target) {
                    collect_guaranteed_calls_before(body, target, out);
                    return;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                for region in [
                    body.as_slice(),
                    catch_events.as_slice(),
                    finally_events.as_slice(),
                ] {
                    if events_contain_span(region, target) {
                        collect_guaranteed_calls_before(region, target, out);
                        return;
                    }
                }
            }
            _ => {}
        }
    }
}

fn events_contain_span(events: &[FlowEvent], target: Span) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Call { span, .. } => *span == target || spans_overlap(*span, target),
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => events_contain_span(then_events, target) || events_contain_span(else_events, target),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            events_contain_span(body, target)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            events_contain_span(body, target)
                || events_contain_span(catch_events, target)
                || events_contain_span(finally_events, target)
        }
        _ => false,
    })
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
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "character_escape sink={} compiler_facts={} compositions={} verified_helpers={}",
        sink.rule_id,
        file_index.character_substitutions.len(),
        file_index.string_compositions.len(),
        verified_helpers.len()
    );
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
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "character_escape sink={} helper_calls={}",
        sink.rule_id,
        helper_calls.len()
    );
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
        let sink_call = structured_call_at_match(&calls, sink.span, "")?;
        semantics.value_arg_indices.iter().all(|index| {
            let Some(argument) = bonsai_lang_api::call_argument_value_fact(
                &file_index.call_argument_values,
                sink_call.span,
                *index,
            ) else {
                return false;
            };
            character_escape_flow_is_safe(
                &argument.value_flow,
                argument.argument_span,
                &file_index,
                &helper_calls,
                &mut AHashSet::new(),
            )
        })
    };
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "character_escape sink={} proof={}",
        sink.rule_id,
        proof
    );
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

pub(super) fn character_constraint_sanitizer(context: &CompilerGuardContext<'_>) -> Option<FindingMatch> {
    let ws = context.ws;
    let source = context.source;
    let source_func = context.source_func;
    let sink = context.sink;
    let sink_rule = context.sink_rule;
    let candidate_funcs = context.candidate_funcs;
    let tainted_call_spans = context.tainted_call_spans;
    let taint_path = context.taint_path;
    let sink_tainted_args = context.sink_tainted_args;
    let semantics = sink_rule
        .analysis_semantics
        .as_ref()?
        .character_constraint
        .as_ref()?;
    for &function in candidate_funcs {
        let Some(decl) = ws.exact_decl(SymbolId::new(function.raw())) else {
            continue;
        };
        let Some(file_index) = ws.exact_decl_index_shared(decl.span.file) else {
            continue;
        };
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "character_constraint_function function={} decl_span={:?} fact_count={}",
            decl.name,
            decl.span,
            file_index.character_constraints.len()
        );
        for fact in file_index
            .character_constraints
            .iter()
            .filter(|fact| fact.function_span == decl.span)
        {
            let domain = character_domain_matches(&fact.domain, semantics);
            let input = character_constraint_input_is_tainted(CharacterConstraintInputContext {
                file_index: &file_index,
                decl: &decl,
                fact,
                source,
                source_func,
                function,
                tainted_call_spans,
                taint_path,
            });
            let output = character_constraint_output_reaches_lineage(
                ws,
                &file_index,
                &decl,
                fact,
                tainted_call_spans,
                taint_path,
                semantics.required_enclosing_literal_delimiter.as_deref(),
            );
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "character_constraint_candidate function={} span={:?} domain={} input={} output={}",
                decl.name,
                fact.transform_span,
                domain,
                input,
                output
            );
            if !domain || !input || !output {
                continue;
            }
            let mut finding = finding_for_guard_span_in_workspace(
                ws,
                sink,
                fact.transform_span,
                "engine.sanitizer.character_constraint",
                sink_rule.tag.as_deref()?,
                "compiler-proven-character-constraint",
            )?;
            finding.sanitised_arg_indices = sink_tainted_args
                .iter()
                .filter_map(|argument| u32::try_from(argument.index).ok())
                .collect();
            return Some(finding);
        }
    }
    if semantics.required_enclosing_literal_delimiter.is_none() {
        for &caller_func in candidate_funcs {
            let Some(caller) = ws.exact_decl(SymbolId::new(caller_func.raw())) else {
                continue;
            };
            if !span_contains(caller.span, sink.span) {
                continue;
            }
            let Some(file_index) = ws.exact_decl_index_shared(caller.span.file) else {
                continue;
            };
            let tainted_targets = sink_tainted_args
                .iter()
                .flat_map(tainted_arg_target_keys)
                .collect::<AHashSet<_>>();
            let tainted_parameters = caller
                .params
                .iter()
                .enumerate()
                .filter_map(|(index, parameter)| {
                    let from_path = taint_path.iter().any(|step| {
                        step.callee == caller.name
                            && step
                                .tainted_args
                                .iter()
                                .any(|argument| argument.param_name == *parameter || argument.index == index)
                    });
                    let from_source = source_func == caller_func
                        && (source_is_exact_parameter(&caller, source, parameter)
                            || place_depends_on_match_span(
                                &file_index,
                                parameter,
                                sink.span,
                                source.span,
                                &mut AHashSet::new(),
                            ));
                    let from_sink_value = sink_tainted_value_depends_on_place(
                        &file_index,
                        &caller,
                        sink.span,
                        sink_tainted_args,
                        parameter,
                    );
                    (from_path || from_source || from_sink_value).then_some(parameter.as_str())
                })
                .collect::<Vec<_>>();
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "character_constraint_caller caller={} tainted_targets={:?} tainted_parameters={:?} compositions={}",
                caller.name,
                tainted_targets,
                tainted_parameters,
                file_index.string_compositions.len()
            );
            if tainted_parameters.is_empty() && source_func != caller_func {
                continue;
            }
            let graph = context.call_graph;
            let mut calls = Vec::new();
            collect_structured_calls(&caller.flow_events, &mut calls);
            let mut helper_call_spans = AHashSet::new();
            if let Some(sink_call) = structured_call_at_match(&calls, sink.span, "") {
                for sink_argument_index in sink_tainted_args.iter().map(|argument| argument.index) {
                    let Some(sink_argument) = bonsai_lang_api::call_argument_value_fact(
                        &file_index.call_argument_values,
                        sink_call.span,
                        sink_argument_index,
                    ) else {
                        continue;
                    };
                    let mut reaching_call_sites = Vec::new();
                    if let Some(span) = sink_argument.direct_call_span {
                        reaching_call_sites.push(span);
                    }
                    collect_compiler_call_sites_reaching_value(
                        &file_index,
                        &sink_argument.value_flow,
                        sink_call.span,
                        &mut reaching_call_sites,
                        &mut AHashSet::new(),
                    );
                    helper_call_spans.extend(reaching_call_sites.into_iter().flat_map(|site| {
                        calls
                            .iter()
                            .filter(move |call| spans_overlap(call.span, site))
                            .map(|call| call.span)
                    }));
                }
            }
            for composition in file_index.string_compositions.iter().filter(|composition| {
                composition.container_span.start < sink.span.start
                    && composition
                        .target
                        .as_ref()
                        .is_some_and(|target| tainted_targets.contains(target))
            }) {
                helper_call_spans.extend(composition.parts.iter().filter_map(|part| match part {
                    bonsai_lang_api::StringCompositionPart::Call { span }
                    | bonsai_lang_api::StringCompositionPart::CallOrLiteral { span, .. } => Some(*span),
                    _ => None,
                }));
            }
            for call_span in helper_call_spans {
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "character_constraint_helper_call caller={} helper_call_span={:?}",
                    caller.name,
                    call_span
                );
                let targets = graph
                    .callees_of(caller_func)
                    .filter(|edge| edge.precision.is_semantic() && spans_overlap(edge.span, call_span))
                    .map(|edge| edge.to)
                    .collect::<AHashSet<_>>();
                let mut targets = targets.into_iter();
                let Some(helper_func) = targets.next() else {
                    continue;
                };
                if targets.next().is_some() {
                    continue;
                }
                let Some(helper) = ws.exact_decl(SymbolId::new(helper_func.raw())) else {
                    continue;
                };
                let Some(helper_index) = ws.exact_decl_index_shared(helper.span.file) else {
                    continue;
                };
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "character_constraint_helper caller={} helper={} facts={}",
                    caller.name,
                    helper.name,
                    helper_index.character_constraints.len()
                );
                for fact in helper_index.character_constraints.iter().filter(|fact| {
                    fact.function_span == helper.span
                        && matches!(fact.output, bonsai_lang_api::CharacterConstraintOutput::Return)
                        && character_domain_matches(&fact.domain, semantics)
                }) {
                    let Some(input_index) = fact.input_param_index else {
                        continue;
                    };
                    let Some(argument) = bonsai_lang_api::call_argument_value_fact(
                        &file_index.call_argument_values,
                        call_span,
                        input_index,
                    ) else {
                        continue;
                    };
                    let from_tainted_parameter = tainted_parameters.iter().any(|parameter| {
                        expression_flow_depends_on_place(
                            &argument.value_flow,
                            parameter,
                            call_span,
                            &file_index,
                            &mut AHashSet::new(),
                        )
                    });
                    let from_local_source = source_func == caller_func
                        && expression_flow_depends_on_match_span(
                            &argument.value_flow,
                            &file_index,
                            call_span,
                            source.span,
                        );
                    let from_tainted_call = tainted_call_spans.iter().any(|tainted| {
                        spans_overlap(*tainted, call_span)
                            || span_contains(*tainted, call_span)
                            || span_contains(call_span, *tainted)
                    });
                    if !from_tainted_parameter && !from_local_source && !from_tainted_call {
                        continue;
                    }
                    let mut finding = finding_for_guard_span_in_workspace(
                        ws,
                        sink,
                        fact.transform_span,
                        "engine.sanitizer.character_constraint",
                        sink_rule.tag.as_deref()?,
                        "compiler-proven-character-constraint",
                    )?;
                    finding.sanitised_arg_indices = sink_tainted_args
                        .iter()
                        .filter_map(|argument| u32::try_from(argument.index).ok())
                        .collect();
                    return Some(finding);
                }
            }
        }
    }
    None
}

pub(super) fn same_origin_path_constraint_sanitizer(
    context: &CompilerGuardContext<'_>,
) -> Option<FindingMatch> {
    let ws = context.ws;
    let source = context.source;
    let source_func = context.source_func;
    let sink = context.sink;
    let sink_rule = context.sink_rule;
    let candidate_funcs = context.candidate_funcs;
    let tainted_call_spans = context.tainted_call_spans;
    let taint_path = context.taint_path;
    let sink_tainted_args = context.sink_tainted_args;
    let required = sink_rule
        .analysis_semantics
        .as_ref()?
        .same_origin_path_constraint
        .as_ref()?;
    if let Some(index) = required.sink_argument_index {
        if !sink_tainted_args.iter().any(|argument| argument.index == index) {
            return None;
        }
    }
    if let Some(context_argument) = required.static_context_argument.as_ref() {
        let rendering = candidate_funcs.iter().find_map(|function| {
            let decl = ws.exact_decl(SymbolId::new(function.raw()))?;
            if !span_contains(decl.span, sink.span) {
                return None;
            }
            let mut calls = Vec::new();
            collect_structured_calls(&decl.flow_events, &mut calls);
            structured_call_at_match(&calls, sink.span, "")
                .and_then(|call| call.args.get(context_argument.index))
                .map(|argument| argument.value_text.trim().to_string())
        });
        if rendering.as_deref().is_none_or(|rendering| {
            !context_argument
                .accepted_renderings
                .iter()
                .any(|accepted| accepted == rendering)
        }) {
            return None;
        }
    }
    for &function in candidate_funcs {
        let decl = ws.exact_decl(SymbolId::new(function.raw()))?;
        let file_index = ws.exact_decl_index_shared(decl.span.file)?;
        for fact in file_index
            .same_origin_path_constraints
            .iter()
            .filter(|fact| fact.function_span == decl.span)
        {
            if !same_origin_provider_is_accepted(fact, required)
                || (required.require_scheme_rejection && !fact.rejects_scheme)
                || (required.require_authority_rejection && !fact.rejects_authority)
                || (required.require_absolute_path && !fact.requires_absolute_path)
                || (required.require_scheme_relative_rejection && !fact.rejects_scheme_relative_path)
            {
                continue;
            }
            let receives_tainted_parameter =
                fact.input_param_index
                    .and_then(|index| decl.params.get(index).map(|parameter| (index, parameter)))
                    .is_some_and(|(index, parameter)| {
                        taint_path.iter().any(|step| {
                            step.callee == decl.name
                                && step.tainted_args.iter().any(|argument| {
                                    argument.param_name == *parameter || argument.index == index
                                })
                        })
                    });
            let guarded_value_reaches_sink = fact.guard_span.end <= sink.span.start
                && sink_tainted_args.iter().any(|argument| {
                    argument
                        .place
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .as_deref()
                        == clean_overwrite_target_key(&fact.input_place).as_deref()
                        || argument.source_names.iter().any(|source| {
                            clean_overwrite_target_key(source).as_deref()
                                == clean_overwrite_target_key(&fact.input_place).as_deref()
                        })
                });
            if !receives_tainted_parameter && !guarded_value_reaches_sink {
                continue;
            }
            let mut finding = finding_for_guard_span_in_workspace(
                ws,
                sink,
                fact.guard_span,
                "engine.sanitizer.same_origin_path_constraint",
                sink_rule.tag.as_deref()?,
                "compiler-proven-same-origin-path-constraint",
            )?;
            finding.sanitised_arg_indices = sink_tainted_args
                .iter()
                .filter_map(|argument| u32::try_from(argument.index).ok())
                .collect();
            return Some(finding);
        }
    }
    for &caller_func in candidate_funcs {
        let Some(caller) = ws.exact_decl(SymbolId::new(caller_func.raw())) else {
            continue;
        };
        if !span_contains(caller.span, sink.span) {
            continue;
        }
        let Some(file_index) = ws.exact_decl_index_shared(caller.span.file) else {
            continue;
        };
        let tainted_parameters = caller
            .params
            .iter()
            .enumerate()
            .filter_map(|(index, parameter)| {
                let from_path = taint_path.iter().any(|step| {
                    step.callee == caller.name
                        && step
                            .tainted_args
                            .iter()
                            .any(|argument| argument.param_name == *parameter || argument.index == index)
                });
                let from_sink_value = sink_tainted_value_depends_on_place(
                    &file_index,
                    &caller,
                    sink.span,
                    sink_tainted_args,
                    parameter,
                );
                let from_source =
                    source_func == caller_func && source_is_exact_parameter(&caller, source, parameter);
                (from_path || from_sink_value || from_source).then_some(parameter.as_str())
            })
            .collect::<Vec<_>>();
        if tainted_parameters.is_empty() && source_func != caller_func {
            continue;
        }
        let mut calls = Vec::new();
        collect_structured_calls(&caller.flow_events, &mut calls);
        let Some(sink_call) = structured_call_at_match(&calls, sink.span, "") else {
            continue;
        };
        for sink_argument_index in sink_tainted_args.iter().map(|argument| argument.index) {
            let Some(sink_argument) = bonsai_lang_api::call_argument_value_fact(
                &file_index.call_argument_values,
                sink_call.span,
                sink_argument_index,
            ) else {
                continue;
            };
            let mut reaching_call_sites = Vec::new();
            if let Some(span) = sink_argument.direct_call_span {
                reaching_call_sites.push(span);
            }
            collect_compiler_call_sites_reaching_value(
                &file_index,
                &sink_argument.value_flow,
                sink_call.span,
                &mut reaching_call_sites,
                &mut AHashSet::new(),
            );
            reaching_call_sites.sort_by_key(|span| (span.start, span.end));
            reaching_call_sites.dedup();
            let helper_call_spans = reaching_call_sites
                .iter()
                .flat_map(|site| {
                    calls
                        .iter()
                        .filter(move |call| spans_overlap(call.span, *site))
                        .map(|call| call.span)
                })
                .collect::<AHashSet<_>>();
            for helper_call_span in helper_call_spans {
                let targets = context
                    .call_graph
                    .callees_of(caller_func)
                    .filter(|edge| edge.precision.is_semantic() && spans_overlap(edge.span, helper_call_span))
                    .map(|edge| edge.to)
                    .collect::<AHashSet<_>>();
                let mut targets = targets.into_iter();
                let Some(helper_func) = targets.next() else {
                    continue;
                };
                if targets.next().is_some() {
                    continue;
                }
                let Some(helper) = ws.exact_decl(SymbolId::new(helper_func.raw())) else {
                    continue;
                };
                let Some(helper_index) = ws.exact_decl_index_shared(helper.span.file) else {
                    continue;
                };
                for fact in helper_index
                    .same_origin_path_constraints
                    .iter()
                    .filter(|fact| fact.function_span == helper.span)
                {
                    if !same_origin_provider_is_accepted(fact, required)
                        || (required.require_scheme_rejection && !fact.rejects_scheme)
                        || (required.require_authority_rejection && !fact.rejects_authority)
                        || (required.require_absolute_path && !fact.requires_absolute_path)
                        || (required.require_scheme_relative_rejection && !fact.rejects_scheme_relative_path)
                    {
                        continue;
                    }
                    let Some(input_param_index) = fact.input_param_index else {
                        continue;
                    };
                    let Some(argument) = bonsai_lang_api::call_argument_value_fact(
                        &file_index.call_argument_values,
                        helper_call_span,
                        input_param_index,
                    ) else {
                        continue;
                    };
                    let from_tainted_parameter = tainted_parameters.iter().any(|parameter| {
                        expression_flow_depends_on_place(
                            &argument.value_flow,
                            parameter,
                            helper_call_span,
                            &file_index,
                            &mut AHashSet::new(),
                        )
                    });
                    let from_local_source = source_func == caller_func
                        && expression_flow_depends_on_match_span(
                            &argument.value_flow,
                            &file_index,
                            helper_call_span,
                            source.span,
                        );
                    let from_tainted_call = tainted_call_spans.iter().any(|tainted| {
                        spans_overlap(*tainted, helper_call_span)
                            || span_contains(*tainted, helper_call_span)
                            || span_contains(helper_call_span, *tainted)
                    });
                    if !from_tainted_parameter && !from_local_source && !from_tainted_call {
                        continue;
                    }
                    let mut finding = finding_for_guard_span_in_workspace(
                        ws,
                        sink,
                        fact.guard_span,
                        "engine.sanitizer.same_origin_path_constraint",
                        sink_rule.tag.as_deref()?,
                        "compiler-proven-same-origin-path-constraint",
                    )?;
                    finding.sanitised_arg_indices = sink_tainted_args
                        .iter()
                        .filter_map(|argument| u32::try_from(argument.index).ok())
                        .collect();
                    return Some(finding);
                }
            }
        }
    }
    None
}

fn same_origin_provider_is_accepted(
    fact: &bonsai_lang_api::SameOriginPathConstraintFact,
    required: &crate::rule::SameOriginPathConstraintSemantics,
) -> bool {
    match fact.provider_call.as_deref() {
        // A provider-bound fact is only security-relevant when the rulepack
        // explicitly assigns semantics to that imported runtime call.
        Some(provider) => required
            .accepted_providers
            .iter()
            .any(|target| rule_target_matches_call(provider, &[], target)),
        // Syntax-only facts are valid only for semantics that do not require
        // a particular runtime provider.
        None => required.accepted_providers.is_empty(),
    }
}

pub(super) fn collect_compiler_call_sites_reaching_value(
    file_index: &bonsai_lang_api::DeclIndex,
    flow: &bonsai_lang_api::ExpressionFlow,
    before: Span,
    out: &mut Vec<Span>,
    seen_places: &mut AHashSet<String>,
) {
    out.extend(flow.call_sites.iter().copied());
    let place = flow.place.clone().or_else(|| {
        let mut assigned_sources = flow
            .source_names
            .iter()
            .filter_map(|source| clean_overwrite_target_key(source))
            .filter(|source| {
                file_index.assignment_values.iter().any(|fact| {
                    fact.target.as_deref() == Some(source.as_str())
                        && fact.assignment_span.file == before.file
                        && fact.assignment_span.end <= before.start
                })
            })
            .collect::<Vec<_>>();
        assigned_sources.sort();
        assigned_sources.dedup();
        (assigned_sources.len() == 1).then(|| assigned_sources.remove(0))
    });
    let Some(place) = place.as_deref() else {
        return;
    };
    if !seen_places.insert(place.to_string()) {
        return;
    }
    let Some(assignment) = file_index
        .assignment_values
        .iter()
        .filter(|fact| {
            fact.target.as_deref() == Some(place)
                && fact.assignment_span.file == before.file
                && fact.assignment_span.end <= before.start
        })
        .max_by_key(|fact| fact.assignment_span.end)
    else {
        return;
    };
    out.extend(assignment.call_sites.iter().copied());
    collect_compiler_call_sites_reaching_value(
        file_index,
        &assignment.value_flow,
        assignment.assignment_span,
        out,
        seen_places,
    );
}

fn sink_tainted_value_depends_on_place(
    file_index: &bonsai_lang_api::DeclIndex,
    decl: &bonsai_lang_api::Decl,
    sink_span: Span,
    sink_tainted_args: &[TaintedArgInfo],
    place: &str,
) -> bool {
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    if let Some(sink_call) = calls
        .iter()
        .find(|call| call.span == sink_span || spans_overlap(call.span, sink_span))
    {
        return sink_tainted_args.iter().any(|tainted| {
            bonsai_lang_api::call_argument_value_fact(
                &file_index.call_argument_values,
                sink_call.span,
                tainted.index,
            )
            .is_some_and(|argument| {
                expression_flow_depends_on_place(
                    &argument.value_flow,
                    place,
                    sink_call.span,
                    file_index,
                    &mut AHashSet::new(),
                )
            })
        });
    }
    return_value_flow_at_match(&decl.flow_events, sink_span).is_some_and(|flow| {
        expression_flow_depends_on_place(flow, place, sink_span, file_index, &mut AHashSet::new())
    })
}

fn character_domain_matches(
    domain: &bonsai_lang_api::CharacterConstraintDomain,
    semantics: &crate::rule::CharacterConstraintSemantics,
) -> bool {
    if let bonsai_lang_api::CharacterConstraintDomain::ProviderBound {
        factory_call,
        operation_call,
        domain,
    } = domain
    {
        return semantics.accepted_providers.iter().any(|provider| {
            rule_target_matches_call(factory_call, &[], &provider.factory)
                && rule_target_matches_call(operation_call, &[], &provider.operation)
        }) && character_domain_satisfies(domain, semantics);
    }
    character_domain_satisfies(domain, semantics)
}

fn character_domain_satisfies(
    domain: &bonsai_lang_api::CharacterConstraintDomain,
    semantics: &crate::rule::CharacterConstraintSemantics,
) -> bool {
    character_domain_excludes(domain, &semantics.required_excluded_characters)
        && character_domain_substitutes(domain, &semantics.required_mappings)
}

fn character_domain_excludes(
    domain: &bonsai_lang_api::CharacterConstraintDomain,
    required: &[String],
) -> bool {
    match domain {
        bonsai_lang_api::CharacterConstraintDomain::ExcludesExact { characters } => {
            required.iter().all(|character| characters.contains(character))
        }
        bonsai_lang_api::CharacterConstraintDomain::AllowOnly {
            classes,
            exact_characters,
        } => required.iter().all(|required| {
            !exact_characters.contains(required)
                && required.chars().next().is_some_and(|character| {
                    !classes.iter().any(|class| match class {
                        bonsai_lang_api::CharacterClass::Alphabetic => character.is_alphabetic(),
                        bonsai_lang_api::CharacterClass::Alphanumeric => character.is_alphanumeric(),
                        bonsai_lang_api::CharacterClass::Digit => character.is_numeric(),
                    })
                })
        }),
        bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact { .. } => required.is_empty(),
        bonsai_lang_api::CharacterConstraintDomain::ProviderBound { domain, .. } => {
            character_domain_excludes(domain, required)
        }
    }
}

fn character_domain_substitutes(
    domain: &bonsai_lang_api::CharacterConstraintDomain,
    required: &[crate::rule::ExactStringMapping],
) -> bool {
    if required.is_empty() {
        return true;
    }
    match domain {
        bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact { mappings } => {
            mappings.len() == required.len()
                && required.iter().all(|required| {
                    let mut matching = mappings.iter().filter(|mapping| mapping.key == required.input);
                    matching
                        .next()
                        .is_some_and(|mapping| mapping.value == required.output)
                        && matching.next().is_none()
                })
        }
        bonsai_lang_api::CharacterConstraintDomain::ProviderBound { domain, .. } => {
            character_domain_substitutes(domain, required)
        }
        bonsai_lang_api::CharacterConstraintDomain::AllowOnly { .. }
        | bonsai_lang_api::CharacterConstraintDomain::ExcludesExact { .. } => false,
    }
}

struct CharacterConstraintInputContext<'a> {
    file_index: &'a bonsai_lang_api::DeclIndex,
    decl: &'a bonsai_lang_api::Decl,
    fact: &'a bonsai_lang_api::CharacterConstraintFact,
    source: &'a RuleMatch,
    source_func: FuncId,
    function: FuncId,
    tainted_call_spans: &'a AHashSet<Span>,
    taint_path: &'a [TaintPropagationStep],
}

fn character_constraint_input_is_tainted(context: CharacterConstraintInputContext<'_>) -> bool {
    let CharacterConstraintInputContext {
        file_index,
        decl,
        fact,
        source,
        source_func,
        function,
        tainted_call_spans,
        taint_path,
    } = context;
    if tainted_call_spans.iter().any(|span| {
        spans_overlap(*span, fact.transform_span)
            || span_contains(*span, fact.transform_span)
            || span_contains(fact.transform_span, *span)
    }) {
        return true;
    }
    if source_func == function
        && place_depends_on_match_span(
            file_index,
            &fact.input_place,
            fact.transform_span,
            source.span,
            &mut AHashSet::new(),
        )
    {
        return true;
    }
    fact.input_param_index
        .and_then(|index| decl.params.get(index))
        .is_some_and(|parameter| {
            taint_path.iter().any(|step| {
                step.callee == decl.name
                    && step.tainted_args.iter().any(|argument| {
                        argument.param_name == *parameter
                            || argument.index == fact.input_param_index.unwrap_or(usize::MAX)
                    })
            })
        })
}

fn source_is_exact_parameter(decl: &bonsai_lang_api::Decl, source: &RuleMatch, parameter: &str) -> bool {
    span_contains(decl.span, source.span)
        && decl.params.iter().any(|candidate| candidate == parameter)
        && source.match_text.trim() == parameter
}

fn place_depends_on_match_span(
    file_index: &bonsai_lang_api::DeclIndex,
    place: &str,
    before: Span,
    match_span: Span,
    visited: &mut AHashSet<String>,
) -> bool {
    let Some(place) = clean_overwrite_target_key(place) else {
        return false;
    };
    if !visited.insert(place.clone()) {
        return false;
    }
    let assignment = file_index
        .assignment_values
        .iter()
        .filter(|assignment| {
            assignment.assignment_span.start < before.start
                && assignment
                    .target
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .as_deref()
                    == Some(place.as_str())
        })
        .max_by_key(|assignment| (assignment.assignment_span.start, assignment.assignment_span.end));
    let result = assignment.is_some_and(|assignment| {
        assignment.call_sites.iter().any(|call| {
            spans_overlap(*call, match_span)
                || span_contains(*call, match_span)
                || span_contains(match_span, *call)
        }) || assignment.call_sites.iter().any(|call_expression| {
            file_index.call_argument_values.iter().any(|argument| {
                (spans_overlap(*call_expression, argument.call_span)
                    || span_contains(*call_expression, argument.call_span)
                    || span_contains(argument.call_span, *call_expression))
                    && (spans_overlap(argument.argument_span, match_span)
                        || span_contains(argument.argument_span, match_span)
                        || expression_flow_depends_on_match_span(
                            &argument.value_flow,
                            file_index,
                            assignment.assignment_span,
                            match_span,
                        ))
            })
        }) || assignment.call_sites.iter().any(|call_expression| {
            file_index.call_receivers.iter().any(|receiver| {
                receiver.role == bonsai_lang_api::CallReceiverRole::Value
                    && span_contains(*call_expression, receiver.call_span)
                    && expression_flow_depends_on_match_span(
                        &receiver.value_flow,
                        file_index,
                        assignment.assignment_span,
                        match_span,
                    )
            })
        }) || assignment.value_flow.source_names.iter().any(|source| {
            place_depends_on_match_span(
                file_index,
                source,
                assignment.assignment_span,
                match_span,
                visited,
            )
        })
    });
    visited.remove(&place);
    result
}

fn expression_flow_depends_on_match_span(
    flow: &bonsai_lang_api::ExpressionFlow,
    file_index: &bonsai_lang_api::DeclIndex,
    before: Span,
    match_span: Span,
) -> bool {
    flow.place
        .iter()
        .chain(flow.source_names.iter())
        .any(|place| place_depends_on_match_span(file_index, place, before, match_span, &mut AHashSet::new()))
        || flow
            .aggregate_fields
            .iter()
            .any(|field| expression_flow_depends_on_match_span(&field.value, file_index, before, match_span))
        || flow
            .tuple_items
            .iter()
            .chain(flow.spreads.iter())
            .any(|item| expression_flow_depends_on_match_span(item, file_index, before, match_span))
}

fn character_constraint_output_reaches_lineage(
    ws: &Workspace,
    file_index: &bonsai_lang_api::DeclIndex,
    decl: &bonsai_lang_api::Decl,
    fact: &bonsai_lang_api::CharacterConstraintFact,
    tainted_call_spans: &AHashSet<Span>,
    taint_path: &[TaintPropagationStep],
    required_delimiter: Option<&str>,
) -> bool {
    match &fact.output {
        bonsai_lang_api::CharacterConstraintOutput::Return => {
            required_delimiter.is_none()
                && fact
                    .input_param_index
                    .and_then(|index| decl.params.get(index))
                    .is_some_and(|parameter| {
                        taint_path.iter().any(|step| {
                            step.callee == decl.name
                                && step.tainted_args.iter().any(|argument| {
                                    argument.param_name == *parameter
                                        || Some(argument.index) == fact.input_param_index
                                })
                        })
                    })
        }
        bonsai_lang_api::CharacterConstraintOutput::Assignment { target } => file_index
            .call_argument_values
            .iter()
            .filter(|argument| {
                fact.transform_span.start < argument.call_span.start
                    && argument.call_span.end <= decl.span.end
                    && (tainted_call_spans.contains(&argument.call_span)
                        || compiler_call_is_on_taint_path(ws, decl, argument.call_span, taint_path))
            })
            .any(|argument| {
                required_delimiter.map_or_else(
                    || {
                        expression_flow_depends_on_place(
                            &argument.value_flow,
                            target,
                            argument.call_span,
                            file_index,
                            &mut AHashSet::new(),
                        )
                    },
                    |delimiter| {
                        expression_flow_depends_on_delimited_place(
                            &argument.value_flow,
                            target,
                            delimiter,
                            argument.call_span,
                            file_index,
                            &mut AHashSet::new(),
                        )
                    },
                )
            }),
        bonsai_lang_api::CharacterConstraintOutput::Expression { span } => file_index
            .call_argument_values
            .iter()
            .filter(|argument| {
                argument.argument_span.file == span.file
                    && span_contains(argument.argument_span, *span)
                    && (tainted_call_spans.contains(&argument.call_span)
                        || compiler_call_is_on_taint_path(ws, decl, argument.call_span, taint_path))
            })
            .any(|argument| {
                required_delimiter.is_none()
                    || file_index.string_compositions.iter().any(|composition| {
                        composition.container_span == argument.argument_span
                            && composition.parts.iter().any(|part| matches!(
                                part,
                                bonsai_lang_api::StringCompositionPart::Call { span: call_span }
                                    | bonsai_lang_api::StringCompositionPart::CallOrLiteral { span: call_span, .. }
                                    if spans_overlap(*call_span, *span)
                                        || span_contains(*call_span, *span)
                                        || span_contains(*span, *call_span)
                            ))
                    })
            }),
    }
}

fn compiler_call_is_on_taint_path(
    ws: &Workspace,
    decl: &bonsai_lang_api::Decl,
    call_span: Span,
    taint_path: &[TaintPropagationStep],
) -> bool {
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let Some(call) = calls.iter().find(|call| call.span == call_span) else {
        return false;
    };
    let Ok(snapshot) = ws.vfs().snapshot(call_span.file) else {
        return false;
    };
    let location = bonsai_common::cached_span_map_arc(call_span.file, snapshot.version, &snapshot.text)
        .line_col(call_span.start);
    taint_path.iter().any(|step| {
        step.caller == decl.name
            && callee_spelling_tail(&step.callee) == callee_spelling_tail(call.name)
            && step.line == location.line
            && step.column == location.column
    })
}

fn expression_flow_depends_on_delimited_place(
    flow: &bonsai_lang_api::ExpressionFlow,
    wanted: &str,
    delimiter: &str,
    before: Span,
    file_index: &bonsai_lang_api::DeclIndex,
    visited: &mut AHashSet<String>,
) -> bool {
    for place in flow
        .place
        .iter()
        .chain(flow.source_names.iter())
        .filter_map(|place| clean_overwrite_target_key(place))
    {
        if place == wanted || !visited.insert(place.clone()) {
            continue;
        }
        let assignment = file_index
            .assignment_values
            .iter()
            .filter(|assignment| {
                assignment.assignment_span.start < before.start
                    && assignment
                        .target
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .as_deref()
                        == Some(place.as_str())
            })
            .max_by_key(|assignment| (assignment.assignment_span.start, assignment.assignment_span.end));
        let safe = assignment.is_some_and(|assignment| {
            file_index.string_compositions.iter().any(|composition| {
                composition.container_span == assignment.assignment_span
                    && composition.target.as_deref() == Some(place.as_str())
                    && composition_encloses_only_place(&composition.parts, wanted, delimiter)
            }) || expression_flow_depends_on_delimited_place(
                &assignment.value_flow,
                wanted,
                delimiter,
                assignment.assignment_span,
                file_index,
                visited,
            )
        });
        visited.remove(&place);
        if safe {
            return true;
        }
    }
    flow.aggregate_fields.iter().any(|field| {
        expression_flow_depends_on_delimited_place(
            &field.value,
            wanted,
            delimiter,
            before,
            file_index,
            visited,
        )
    }) || flow.tuple_items.iter().chain(flow.spreads.iter()).any(|item| {
        expression_flow_depends_on_delimited_place(item, wanted, delimiter, before, file_index, visited)
    })
}

fn composition_encloses_only_place(
    parts: &[bonsai_lang_api::StringCompositionPart],
    wanted: &str,
    delimiter: &str,
) -> bool {
    let mut inside = false;
    let mut saw_wanted = false;
    for part in parts {
        match part {
            bonsai_lang_api::StringCompositionPart::Literal { value } => {
                if value.matches(delimiter).count() % 2 == 1 {
                    inside = !inside;
                }
            }
            bonsai_lang_api::StringCompositionPart::Place { place } if place == wanted && inside => {
                saw_wanted = true;
            }
            bonsai_lang_api::StringCompositionPart::Place { .. }
            | bonsai_lang_api::StringCompositionPart::PlaceOrLiteral { .. }
            | bonsai_lang_api::StringCompositionPart::Call { .. }
            | bonsai_lang_api::StringCompositionPart::CallOrLiteral { .. } => return false,
        }
    }
    saw_wanted && !inside
}

fn expression_flow_depends_on_place(
    flow: &bonsai_lang_api::ExpressionFlow,
    wanted: &str,
    before: Span,
    file_index: &bonsai_lang_api::DeclIndex,
    visited: &mut AHashSet<String>,
) -> bool {
    let direct = flow
        .place
        .iter()
        .chain(flow.source_names.iter())
        .filter_map(|place| clean_overwrite_target_key(place))
        .any(|place| place == wanted);
    if direct {
        return true;
    }
    for place in flow
        .place
        .iter()
        .chain(flow.source_names.iter())
        .filter_map(|place| clean_overwrite_target_key(place))
    {
        if !visited.insert(place.clone()) {
            continue;
        }
        let depends = file_index
            .assignment_values
            .iter()
            .filter(|assignment| {
                assignment.assignment_span.start < before.start
                    && assignment
                        .target
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .as_deref()
                        == Some(place.as_str())
            })
            .max_by_key(|assignment| (assignment.assignment_span.start, assignment.assignment_span.end))
            .is_some_and(|assignment| {
                expression_flow_depends_on_place(
                    &assignment.value_flow,
                    wanted,
                    assignment.assignment_span,
                    file_index,
                    visited,
                )
            });
        visited.remove(&place);
        if depends {
            return true;
        }
    }
    flow.aggregate_fields
        .iter()
        .any(|field| expression_flow_depends_on_place(&field.value, wanted, before, file_index, visited))
        || flow
            .tuple_items
            .iter()
            .chain(flow.spreads.iter())
            .any(|item| expression_flow_depends_on_place(item, wanted, before, file_index, visited))
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
        let mappings = if fact.exact_mappings.is_empty() {
            let Some(map) = file_index
                .static_string_maps
                .iter()
                .filter(|map| {
                    map.target == fact.table && map.assignment_span.start < fact.transform_span.start
                })
                .max_by_key(|map| (map.assignment_span.start, map.assignment_span.end))
            else {
                continue;
            };
            map.entries.as_slice()
        } else {
            fact.exact_mappings.as_slice()
        };
        if !semantics.required_mappings.iter().all(|required| {
            mappings
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
    if file_index.string_compositions.iter().any(|composition| {
        (composition.container_span == before || composition.value_span == before)
            && character_escape_composition_is_safe(&composition.parts, helper_calls)
    }) {
        return true;
    }
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
                assignment.value_span,
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
        character_escape_flow_is_safe(
            &field.value,
            field.value_span.unwrap_or(before),
            file_index,
            helper_calls,
            visited_places,
        )
    }) && flow
        .tuple_items
        .iter()
        .all(|item| character_escape_flow_is_safe(item, before, file_index, helper_calls, visited_places))
}

fn character_escape_composition_is_safe(
    parts: &[bonsai_lang_api::StringCompositionPart],
    helper_calls: &[(StructuredCall<'_>, VerifiedCharacterHelper<'_>)],
) -> bool {
    let mut saw_transform = false;
    let safe = parts.iter().all(|part| match part {
        bonsai_lang_api::StringCompositionPart::Literal { .. } => true,
        bonsai_lang_api::StringCompositionPart::Call { span }
        | bonsai_lang_api::StringCompositionPart::CallOrLiteral { span, .. } => {
            let verified = helper_calls.iter().any(|(call, _)| {
                spans_overlap(call.span, *span)
                    || span_contains(*span, call.span)
                    || span_contains(call.span, *span)
            });
            saw_transform |= verified;
            verified
        }
        bonsai_lang_api::StringCompositionPart::Place { .. }
        | bonsai_lang_api::StringCompositionPart::PlaceOrLiteral { .. } => false,
    });
    safe && saw_transform
}

fn path_consumer_guard_span(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    decl: &bonsai_lang_api::Decl,
    consumer_span: Span,
    path_arg_index: usize,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
    expected_callee: Option<&str>,
) -> Option<Span> {
    let file_index = ws.exact_decl_index_shared(consumer_span.file)?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let required_tail = expected_callee.map(callee_spelling_tail).unwrap_or_default();
    let consumer_call = structured_call_at_match(&calls, consumer_span, &required_tail)?;
    let consumer_argument = consumer_call.args.get(path_arg_index)?;
    let candidate = consumer_argument
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)
        .or_else(|| {
            let mut assignments = Vec::new();
            collect_structured_assignments_before(&decl.flow_events, consumer_span, &mut assignments);
            let mut candidates = consumer_argument
                .source_names
                .iter()
                .filter_map(|source| clean_overwrite_target_key(source))
                .filter(|source| {
                    assignments.iter().rev().any(|assignment| {
                        clean_overwrite_target_key(assignment.target).as_deref() == Some(source.as_str())
                            && assignment
                                .source_call
                                .is_some_and(|call| rule_target_matches_call(call, &[], &guard.canonicalizer))
                    })
                });
            let candidate = candidates.next()?;
            candidates.next().is_none().then_some(candidate)
        })?;

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
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_consumer constructor_count={} candidate={} sink={}",
            path_constructor_calls.len(),
            candidate,
            consumer_call.name
        );
        return None;
    }
    let base = if guard.path_constructor_base_from_receiver {
        compiler_call_receiver_place(&file_index, path_constructor_calls[0])?
    } else {
        compiler_call_argument_place(
            &file_index,
            path_constructor_calls[0].span,
            guard.path_constructor_base_arg_index,
        )?
    };

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
    let base_is_static =
        place_has_static_canonical_provenance_or_static_callers(StaticCanonicalProvenanceContext {
            ws,
            call_graph,
            decl,
            place: &base,
            assignments: &file_assignments,
            assignment_values: &file_index.assignment_values,
            call_argument_values: &file_index.call_argument_values,
            canonicalizer: guard.base_canonicalizer.as_ref().unwrap_or(&guard.canonicalizer),
            static_base_factories: &guard.static_base_factories,
            before: candidate_assignment.span,
        });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_consumer sink={} candidate={} base={} base_static={}",
        consumer_call.name,
        candidate,
        base,
        base_is_static
    );
    if !base_is_static {
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
    });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_consumer sink={} guarded={:?}",
        consumer_call.name,
        branch.map(|branch| branch.span)
    );
    let branch = branch?;
    Some(branch.span)
}

struct StaticCanonicalProvenanceContext<'a> {
    ws: &'a Workspace,
    call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    decl: &'a bonsai_lang_api::Decl,
    place: &'a str,
    assignments: &'a [StructuredAssignment<'a>],
    assignment_values: &'a [bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &'a [bonsai_lang_api::CallArgumentValueFact],
    canonicalizer: &'a RuleTarget,
    static_base_factories: &'a [RuleTarget],
    before: Span,
}

fn place_has_static_canonical_provenance_or_static_callers(
    context: StaticCanonicalProvenanceContext<'_>,
) -> bool {
    let StaticCanonicalProvenanceContext {
        ws,
        call_graph,
        decl,
        place,
        assignments,
        assignment_values,
        call_argument_values,
        canonicalizer,
        static_base_factories,
        before,
    } = context;
    if place_has_static_canonical_provenance(
        place,
        assignments,
        assignment_values,
        call_argument_values,
        canonicalizer,
        static_base_factories,
        before,
    ) {
        return true;
    }
    let Some(root) = canonical_provenance_root_place(
        place,
        assignments,
        assignment_values,
        call_argument_values,
        canonicalizer,
        static_base_factories,
    ) else {
        return false;
    };
    let Some(parameter_index) = decl.params.iter().position(|parameter| parameter == &root) else {
        return false;
    };
    let callers = call_graph
        .callers_of(FuncId::new(decl.symbol.raw()))
        .filter(|edge| edge.precision.is_semantic())
        .collect::<Vec<_>>();
    !callers.is_empty()
        && callers.iter().all(|edge| {
            let Some(caller) = ws.exact_decl(SymbolId::new(edge.from.raw())) else {
                return false;
            };
            let Some(index) = ws.exact_decl_index_shared(caller.span.file) else {
                return false;
            };
            bonsai_lang_api::call_argument_value_fact(&index.call_argument_values, edge.span, parameter_index)
                .is_some_and(|argument| {
                    argument.static_value.is_some()
                        || expression_flow_is_literal(&argument.value_flow)
                        || expression_flow_has_static_binding_provenance(
                            &index,
                            &argument.value_flow,
                            edge.span,
                            &mut AHashSet::new(),
                        )
                })
        })
}

fn expression_flow_has_static_binding_provenance(
    index: &bonsai_lang_api::DeclIndex,
    flow: &bonsai_lang_api::ExpressionFlow,
    before: Span,
    seen: &mut AHashSet<String>,
) -> bool {
    if expression_flow_is_literal(flow) {
        return true;
    }
    let Some(place) = flow.place.as_deref() else {
        return false;
    };
    if !seen.insert(place.to_string()) {
        return false;
    }
    index.assignment_values.iter().rev().any(|fact| {
        fact.assignment_span.file == before.file
            && fact.assignment_span.end <= before.start
            && fact.target.as_deref() == Some(place)
            && expression_flow_has_static_binding_provenance(
                index,
                &fact.value_flow,
                fact.assignment_span,
                seen,
            )
    })
}

fn canonical_provenance_root_place(
    place: &str,
    assignments: &[StructuredAssignment<'_>],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    canonicalizer: &RuleTarget,
    static_base_factories: &[RuleTarget],
) -> Option<String> {
    let mut current = place.to_string();
    let mut visited = AHashSet::new();
    while visited.insert(current.clone()) {
        let Some(assignment) = assignments.iter().rev().find(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(current.as_str())
        }) else {
            return Some(current);
        };
        let value = assignment_values
            .iter()
            .find(|fact| fact.assignment_span == assignment.span)?;
        if value.direct_call_name.is_none() && expression_flow_is_literal(&value.value_flow) {
            return None;
        }
        let call = assignment.source_call?;
        if static_base_factories
            .iter()
            .any(|factory| rule_target_matches_call(call, &[], factory))
            && value
                .exact_static_call_args
                .as_ref()
                .is_some_and(|args| !args.is_empty())
        {
            return None;
        }
        if !rule_target_matches_call(call, &[], canonicalizer) {
            return None;
        }
        current = assignment_direct_call_argument_place(value, call_argument_values, 0).or_else(|| {
            assignment
                .source_call_args
                .first()
                .and_then(|argument| clean_overwrite_target_key(argument))
        })?;
    }
    None
}

pub(super) fn relative_path_containment_guard_sanitizer(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
    _sink_tainted_args: &[TaintedArgInfo],
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
    let sink_call = structured_call_at_match(&calls, sink.span, "")?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, sink.span, &mut assignments);
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "relative_path_start sink={} function={} assignments={}",
        sink.rule_id,
        decl.name,
        assignments.len()
    );

    let (candidate, candidate_assignment) =
        guarded_relative_path_candidate(sink_call, sink, guard, &assignments)?;
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "relative_path_candidate sink={} candidate={} assignment={:?} source_call={:?}",
        sink.rule_id,
        candidate,
        candidate_assignment.span,
        candidate_assignment.source_call
    );
    let candidate_is_canonical = candidate_assignment
        .source_call
        .is_some_and(|call| rule_target_matches_call(call, &[], &guard.candidate_canonicalizer));
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "relative_path_candidate_canonical sink={} exact={} target={:?}",
        sink.rule_id,
        candidate_is_canonical,
        guard.candidate_canonicalizer
    );
    if !candidate_is_canonical {
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
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "relative_path_rel sink={} call={:?} args={:?}",
        sink.rule_id,
        relative_call.span,
        relative_call.args
    );
    let base = relative_call
        .args
        .get(guard.relative_base_arg_index)?
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
            relative_call.span,
            &mut file_assignments,
        );
    }
    file_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let base_is_static =
        place_has_static_canonical_provenance_or_static_callers(StaticCanonicalProvenanceContext {
            ws,
            call_graph,
            decl: &decl,
            place: &base,
            assignments: &file_assignments,
            assignment_values: &file_index.assignment_values,
            call_argument_values: &file_index.call_argument_values,
            canonicalizer: &guard.base_canonicalizer,
            static_base_factories: &[],
            before: relative_call.span,
        });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "relative_path_base sink={} base={} static={}",
        sink.rule_id,
        base,
        base_is_static
    );
    if !base_is_static {
        return None;
    }
    // Exact compiler provenance wins over a conservative closure carrier.
    // Tuple joins or shared error variables can over-approximate the base as
    // tainted, but a literal/immutable canonical root proven at every exact
    // caller cannot contain attacker data. A genuinely dynamic base fails the
    // provenance proof above and remains reportable.

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
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "relative_path_result sink={} result={}",
        sink.rule_id,
        relative_result
    );

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
                &file_index,
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
        sink_rule.tag.as_deref()?,
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
    file_index: &bonsai_lang_api::DeclIndex,
    events: &[FlowEvent],
    branch: StructuredBranch<'_>,
    relative_result: &str,
    guard: &RelativePathContainmentGuardSemantics,
) -> bool {
    let Some(ConditionExpressionFact::Any { operands, .. }) =
        branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
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
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "relative_path_rejection missing exact value result={} operands={:?}",
            relative_result,
            operands
        );
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
            file_index,
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
    file_index: &'a bonsai_lang_api::DeclIndex,
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
            } if span_contains(query.condition_span, *span) => {
                let compiler_boundary_rejection = query.file_index.compiler_guards.iter().any(|guard| {
                    guard.capability == bonsai_lang_api::COMPILER_GUARD_RELATIVE_PATH_BOUNDARY_REJECTION
                        && spans_overlap(guard.guarded_call_span, *span)
                });
                if compiler_boundary_rejection
                    && matches!(args.as_slice(), [argument]
                        if argument.place.as_deref()
                            .and_then(clean_overwrite_target_key)
                            .as_deref() == Some(query.relative_result))
                {
                    return true;
                }
                if !rule_target_matches_call(name, receiver_types, &query.guard.rejection_check) {
                    continue;
                }
                let relative_argument_matches = args
                    .get(query.guard.rejection_check_arg_index)
                    .and_then(|argument| argument.place.as_deref())
                    .and_then(clean_overwrite_target_key)
                    .as_deref()
                    == Some(query.relative_result);
                let prefix_is_exact = relative_argument_matches
                    && relative_rejection_prefix_is_exact(events, *span, args, query);
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "relative_path_rejection call={} relative_match={} prefix_exact={} args={:?}",
                    name,
                    relative_argument_matches,
                    prefix_is_exact,
                    args
                );
                if prefix_is_exact {
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

fn relative_rejection_prefix_is_exact(
    events: &[FlowEvent],
    call_span: Span,
    args: &[bonsai_lang_api::CallArg],
    query: &RelativeRejectionCallQuery<'_>,
) -> bool {
    let Some(prefix_index) = query.guard.rejection_prefix_arg_index else {
        return true;
    };
    let Some(prefix_arg) = args.get(prefix_index) else {
        return false;
    };
    let Some(composition) = query
        .file_index
        .string_compositions
        .iter()
        .find(|fact| fact.value_span == prefix_arg.span)
    else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "relative_path_prefix missing composition argument_span={:?} available={:?}",
            prefix_arg.span,
            query
                .file_index
                .string_compositions
                .iter()
                .map(|fact| fact.value_span)
                .collect::<Vec<_>>()
        );
        return false;
    };
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "relative_path_prefix argument_span={:?} parts={:?}",
        prefix_arg.span,
        composition.parts
    );
    let [bonsai_lang_api::StringCompositionPart::Literal { value }, boundary @ ..] =
        composition.parts.as_slice()
    else {
        return false;
    };
    if call_span.file != composition.value_span.file
        || boundary.is_empty()
        || !query
            .guard
            .rejected_exact_values
            .iter()
            .any(|rejected| rejected == value)
    {
        return false;
    }
    boundary.iter().all(|part| match part {
        bonsai_lang_api::StringCompositionPart::Place { place } => query
            .guard
            .rejection_boundary_places
            .iter()
            .any(|accepted| accepted == place),
        bonsai_lang_api::StringCompositionPart::Call { span } => {
            relative_boundary_wrapper_call_is_exact(events, *span, query)
        }
        _ => false,
    })
}

fn relative_boundary_wrapper_call_is_exact(
    events: &[FlowEvent],
    wrapper_span: Span,
    query: &RelativeRejectionCallQuery<'_>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver_types,
                args,
                ..
            } if *span == wrapper_span => {
                let exact = query
                    .guard
                    .rejection_boundary_wrappers
                    .iter()
                    .any(|target| rule_target_matches_call(name, receiver_types, target))
                    && matches!(args.as_slice(), [argument] if argument
                        .place
                        .as_deref()
                        .is_some_and(|place| query.guard.rejection_boundary_places.iter().any(|accepted| accepted == place))
                        || argument.source_names.iter().any(|place| query
                            .guard
                            .rejection_boundary_places
                            .iter()
                            .any(|accepted| accepted == place)));
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "relative_path_boundary wrapper={} span={:?} exact={} args={:?}",
                    name,
                    span,
                    exact,
                    args
                );
                return exact;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if relative_boundary_wrapper_call_is_exact(then_events, wrapper_span, query)
                    || relative_boundary_wrapper_call_is_exact(else_events, wrapper_span, query)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if relative_boundary_wrapper_call_is_exact(body, wrapper_span, query) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if relative_boundary_wrapper_call_is_exact(body, wrapper_span, query)
                    || relative_boundary_wrapper_call_is_exact(catch_events, wrapper_span, query)
                    || relative_boundary_wrapper_call_is_exact(finally_events, wrapper_span, query)
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
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    canonicalizer: &RuleTarget,
    static_base_factories: &[RuleTarget],
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
                    && ((fact.direct_call_name.is_none() && expression_flow_is_literal(&fact.value_flow))
                        || (fact.direct_call_name.as_deref().is_some_and(|call| {
                            static_base_factories
                                .iter()
                                .any(|factory| rule_target_matches_call(call, &[], factory))
                        }) && fact
                            .exact_static_call_args
                            .as_ref()
                            .is_some_and(|args| !args.is_empty())))
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
        if static_base_factories
            .iter()
            .any(|factory| rule_target_matches_call(call, &[], factory))
            && value
                .exact_static_call_args
                .as_ref()
                .is_some_and(|args| !args.is_empty())
        {
            return true;
        }
        if !rule_target_matches_call(call, &[], canonicalizer) {
            return false;
        }
        let next = assignment_direct_call_argument_place(value, call_argument_values, 0)
            .or_else(|| {
                assignment
                    .source_call_args
                    .first()
                    .and_then(|argument| clean_overwrite_target_key(argument))
            })
            .or_else(|| {
                assignment
                    .source_names
                    .iter()
                    .filter_map(|source| clean_overwrite_target_key(source))
                    .find(|source| callee_spelling_tail(source) != callee_spelling_tail(call))
            });
        let Some(next) = next else { return false };
        current = next;
    }
    false
}

fn assignment_direct_call_argument_place(
    assignment: &bonsai_lang_api::AssignmentValueFact,
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    argument_index: usize,
) -> Option<String> {
    let mut candidates = call_argument_values.iter().filter(|argument| {
        argument.argument_index == argument_index
            && assignment.call_sites.iter().any(|call_expression| {
                span_contains(*call_expression, argument.call_span)
                    || spans_overlap(*call_expression, argument.call_span)
            })
    });
    let argument = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    argument
        .value_flow
        .projection
        .as_ref()
        .map(bonsai_lang_api::ExpressionProjection::canonical_place)
        .or_else(|| argument.value_flow.place.clone())
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
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_containment branch={:?} missing_condition_fact",
            branch.span
        );
        return false;
    };
    let query = ContainmentCheckQuery {
        condition_span: condition.condition_span,
        candidate,
        base,
        containment_check,
        boundary_places,
    };
    let Some(containment_call) = containment_check_call_before_body(events, &query) else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_containment branch={:?} candidate={} base={} missing_containment_call condition={:?}",
            branch.span,
            candidate,
            base,
            condition.condition_span
        );
        return false;
    };
    if condition.polarity == BranchConditionPolarity::Negated {
        return true;
    }
    let exact = condition.expression.as_ref().is_some_and(|expression| {
        path_containment_rejection_is_exact(expression, containment_call, candidate, base)
    });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_containment branch={:?} containment={:?} polarity={:?} exact={}",
        branch.span,
        containment_call,
        condition.polarity,
        exact
    );
    exact
}

/// Prove the common boundary-safe rejection form:
///
/// `candidate != base && !contains(candidate, base + separator)`
///
/// When the true arm exits abruptly, reaching the following sink means either
/// exact-base equality or boundary-aware containment. The frontend owns the
/// boolean/equality syntax; this proof only consumes its typed expression.
fn path_containment_rejection_is_exact(
    expression: &ConditionExpressionFact,
    containment_call: Span,
    candidate: &str,
    base: &str,
) -> bool {
    let ConditionExpressionFact::All { operands, .. } = expression else {
        return false;
    };
    if operands.len() != 2 {
        return false;
    }
    let rejects_non_contained = operands.iter().any(|operand| {
        matches!(
            operand,
            ConditionExpressionFact::Not { operand, .. }
                if matches!(operand.as_ref(), ConditionExpressionFact::Atom { span }
                    if span_contains(*span, containment_call))
        )
    });
    let rejects_non_base = operands.iter().any(|operand| {
        let ConditionExpressionFact::Equality {
            relation: ConditionEquality::NotEqual,
            left,
            right,
            ..
        } = operand
        else {
            return false;
        };
        (condition_operand_is_exact_place(left, candidate) && condition_operand_is_exact_place(right, base))
            || (condition_operand_is_exact_place(left, base)
                && condition_operand_is_exact_place(right, candidate))
    });
    rejects_non_contained && rejects_non_base
}

fn condition_operand_is_exact_place(operand: &ConditionOperandFact, expected: &str) -> bool {
    operand
        .value_flow
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)
        .as_deref()
        == Some(expected)
}

#[derive(Copy, Clone)]
struct ContainmentCheckQuery<'a> {
    condition_span: Span,
    candidate: &'a str,
    base: &'a str,
    containment_check: &'a RuleTarget,
    boundary_places: &'a [String],
}

fn containment_check_call_before_body(
    events: &[FlowEvent],
    query: &ContainmentCheckQuery<'_>,
) -> Option<Span> {
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
                    return Some(*span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(span) = containment_check_call_before_body(then_events, query)
                    .or_else(|| containment_check_call_before_body(else_events, query))
                {
                    return Some(span);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(span) = containment_check_call_before_body(body, query) {
                    return Some(span);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(span) = [body, catch_events, finally_events]
                    .into_iter()
                    .find_map(|region| containment_check_call_before_body(region, query))
                {
                    return Some(span);
                }
            }
            _ => {}
        }
    }
    None
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
    let sink_call = structured_call_at_match(&sink_calls, sink.span, "")?;
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
            .filter(|candidate| candidate.name == bonsai_lang_api::MODULE_DECL_NAME)
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

pub(super) fn configured_argument_receiver_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .configured_argument_receiver_guard
        .as_ref()?;
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut calls);
    let sink_call = structured_call_at_match(&calls, sink.span, "")?;
    let guarded_place = sink_call
        .args
        .get(guard.sink_argument_index)?
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)?;
    let assignment_span = latest_structured_assignment_to(&sink_decl.flow_events, sink.span, &guarded_place)?;
    let assignment =
        bonsai_lang_api::assignment_value_fact_for_span(&file_index.assignment_values, assignment_span)?;
    if !assignment
        .direct_call_name
        .as_deref()
        .is_some_and(|callee| rule_target_matches_call(callee, &[], &guard.wrapper_factory))
    {
        return None;
    }
    let wrapper_call = calls.iter().find(|call| {
        span_contains(assignment.value_span, call.span)
            && rule_target_matches_call(call.name, call.receiver_types, &guard.wrapper_factory)
    })?;
    let provider_argument = wrapper_call.args.get(guard.configured_receiver_argument_index)?;
    let provider_call = calls.iter().find(|call| {
        span_contains(provider_argument.span, call.span)
            && rule_target_matches_call(call.name, call.receiver_types, &guard.provider_factory)
    })?;
    let receiver = compiler_call_receiver_place(&file_index, provider_call)?;
    let prior_calls = guaranteed_calls_before(&sink_decl.flow_events, assignment.assignment_span);
    let proof =
        receiver_configuration_proof_span(&file_index, &prior_calls, &receiver, &guard.required_calls)?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        proof,
        "engine.sanitizer.configured_argument_receiver_guard",
        sink_rule.tag.as_deref()?,
        "compiler-proven-configured-receiver-wrapper",
    )
}

pub(super) fn configured_call_argument_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .configured_call_argument_guard
        .as_ref()?;
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut calls);
    let sink_call = structured_call_at_match(&calls, sink.span, "")?;
    let configuration = sink_call.args.get(guard.configuration_argument_index)?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let fact = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        sink_call.span,
        guard.configuration_argument_index,
    )?;
    if guard.required_fields.is_empty()
        || !guard.required_fields.iter().all(|required| {
            fact.exact_static_aggregate_fields
                .iter()
                .any(|field| field.path == required.path && field.value == required.value)
        })
    {
        return None;
    }
    let sanitised_arg_indices: Vec<u32> = sink_tainted_args
        .iter()
        .filter(|tainted| guard.guarded_value_argument_indices.contains(&tainted.index))
        .filter_map(|tainted| u32::try_from(tainted.index).ok())
        .collect();
    if sanitised_arg_indices.is_empty() {
        return None;
    }
    let mut finding = finding_for_guard_span_in_workspace(
        ws,
        sink,
        configuration.span,
        "engine.sanitizer.configured_call_argument_guard",
        sink_rule.tag.as_deref()?,
        "compiler-proven-configured-call-argument",
    )?;
    finding.sanitised_arg_indices = sanitised_arg_indices;
    Some(finding)
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
    let import_aliases = ws
        .db()
        .import_index(sink.span.file)
        .map(|imports| bonsai_lang_api::alias_map_from_imports(&imports))
        .unwrap_or_default();
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
    let sink_call = structured_call_at_match(&calls, sink.span, "")?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(
        &decl.flow_events,
        Span::empty(sink.span.file, decl.span.end),
        &mut assignments,
    );
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let Some(parsed) =
        url_guard_root_place(sink_call, sink.span, guard, &calls, &assignments, &import_aliases)
    else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} no parsed root",
            sink.rule_id
        );
        return None;
    };
    let Some(parser_assignment) = assignments.iter().rev().find(|assignment| {
        assignment.span.start <= sink.span.start
            && clean_overwrite_target_key(assignment.target).as_deref() == Some(parsed.as_str())
            && assignment.source_call.is_some_and(|call| {
                crate::matcher::rule_target_matches_call_with_aliases(
                    call,
                    &[],
                    &guard.parser,
                    &import_aliases,
                )
            })
    }) else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} root={} has no parser assignment",
            sink.rule_id,
            parsed
        );
        return None;
    };
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
    let Some(scheme_guard) = branches
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
        })
    else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} no scheme guard",
            sink.rule_id
        );
        return None;
    };
    let Some(host_guard) = branches
        .iter()
        .filter(|branch| {
            scheme_guard.span.start <= branch.span.start
                && branch.span.start < validation_end
                && branch_arm_abruptly_exits(branch.then_events)
        })
        .find(|branch| {
            let expression = branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
                .and_then(|fact| fact.expression.as_ref());
            let collection = expression.and_then(|expression| {
                url_rejected_host_collection(expression, &parsed, &guard.host_allowlist, &calls)
            });
            let is_static = collection.as_ref().is_some_and(|collection| {
                url_collection_is_static(
                    collection,
                    branch.span,
                    &file_index,
                    &file_calls,
                    &guard.host_allowlist.static_collection_factories,
                )
            });
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "url_network_guard host candidate span={:?} expression={:?} collection={:?} static={}",
                branch.span,
                expression,
                collection,
                is_static
            );
            is_static
        })
    else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} no host guard",
            sink.rule_id
        );
        return None;
    };

    let Some(resolver_call) = calls.iter().find(|call| {
        host_guard.span.start < call.span.start
            && call.span.start < validation_end
            && crate::matcher::rule_target_matches_call_with_aliases(
                call.name,
                call.receiver_types,
                &guard.dns.resolver,
                &import_aliases,
            )
            && call.args.iter().any(|argument| {
                url_call_argument_reads_component(argument, &parsed, &guard.host_allowlist.component, &calls)
            })
    }) else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} no resolver call · candidates={:?}",
            sink.rule_id,
            calls
                .iter()
                .filter(|call| host_guard.span.start < call.span.start && call.span.start < validation_end)
                .map(|call| {
                    (
                        call.name,
                        call.span,
                        rule_target_matches_call(call.name, call.receiver_types, &guard.dns.resolver),
                        crate::matcher::rule_target_matches_call_with_aliases(
                            call.name,
                            call.receiver_types,
                            &guard.dns.resolver,
                            &import_aliases,
                        ),
                    )
                })
                .collect::<Vec<_>>()
        );
        return None;
    };
    let resolver_targets: Vec<String> = assignments
        .iter()
        .filter(|assignment| {
            // Foreach/range bindings use the complete loop span and may not
            // repeat the iterable call as `source_call`; containment against
            // the exact resolver call still binds only those header targets.
            span_contains(assignment.span, resolver_call.span)
                && assignment
                    .source_call
                    .is_none_or(|call| rule_target_matches_call(call, &[], &guard.dns.resolver))
        })
        .filter_map(|assignment| clean_overwrite_target_key(assignment.target))
        .collect();
    if resolver_targets.is_empty() {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} no resolver targets",
            sink.rule_id
        );
        return None;
    }
    let Some(_private_guard) = branches
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
                let receiver = url_private_predicate_receiver(
                    expression,
                    condition.condition_span,
                    predicate,
                    &calls,
                );
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "url_network_guard private candidate span={:?} expression={:?} predicate={:?} receiver={:?} resolver_targets={:?}",
                    branch.span,
                    expression,
                    predicate,
                    receiver,
                    resolver_targets
                );
                let Some(receiver) = receiver else {
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
                url_private_value_derives_from_resolver(
                    &receiver,
                    &resolver_targets,
                    &assignments,
                    branch.span,
                    &guard.dns,
                    &calls,
                    &import_aliases,
                )
            })
        })
    else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} no private-address guard",
            sink.rule_id
        );
        return None;
    };
    if !url_redirect_guard_is_exact(
        &decl.flow_events,
        decl.span,
        sink_call,
        sink.span,
        &parsed,
        guard.redirect.as_ref(),
        &file_index,
    ) {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} redirect policy failed",
            sink.rule_id
        );
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

pub(super) fn url_reconstruction_guard_sanitizer(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .url_reconstruction_guard
        .as_ref()?;
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let sink_file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = structured_call_at_match(&sink_calls, sink.span, "")?;
    if !url_redirect_guard_is_exact(
        &sink_decl.flow_events,
        sink_decl.span,
        sink_call,
        sink.span,
        "",
        guard.redirect.as_ref(),
        &sink_file_index,
    ) {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_reconstruction sink={} redirect policy failed",
            sink.rule_id
        );
        return None;
    }
    let Some(target) =
        url_reconstruction_target_for_sink(ws, call_graph, sink_func, sink, guard, sink_tainted_args)
    else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_reconstruction sink={} reconstructed target failed",
            sink.rule_id
        );
        return None;
    };
    let Some(guard_span) = compiler_proven_url_reconstruction_guard(ws, target, guard) else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_reconstruction sink={} helper proof failed",
            sink.rule_id
        );
        return None;
    };
    let mut finding = finding_for_guard_span_in_workspace(
        ws,
        sink,
        guard_span,
        "engine.sanitizer.url_reconstruction_guard",
        sink_rule.tag.as_deref()?,
        "compiler-proven-url-reconstruction-guard",
    )?;
    finding.sanitised_arg_indices = sink_tainted_args
        .iter()
        .filter(|argument| argument.index == guard.sink_argument_index)
        .filter_map(|argument| u32::try_from(argument.index).ok())
        .collect();
    Some(finding)
}

#[derive(Copy, Clone)]
struct UrlReconstructionTarget {
    function: FuncId,
    /// Assignment that binds the reconstructed value. `None` means the
    /// reconstructed value is the helper's sole return expression.
    output_span: Option<Span>,
}

fn url_reconstruction_target_for_sink(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink_func: FuncId,
    sink: &RuleMatch,
    guard: &crate::rule::UrlReconstructionGuardSemantics,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<UrlReconstructionTarget> {
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let sink_file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = structured_call_at_match(&sink_calls, sink.span, "")?;
    let sink_argument = sink_call.args.get(guard.sink_argument_index)?;
    if !sink_tainted_args
        .iter()
        .any(|argument| argument.index == guard.sink_argument_index)
        || !required_named_call_arguments_match(
            sink_call,
            &guard.required_sink_named_arguments,
            &sink_file_index,
        )
    {
        return None;
    }

    let tainted_targets: AHashSet<String> = sink_tainted_args
        .iter()
        .filter(|argument| argument.index == guard.sink_argument_index)
        .flat_map(tainted_arg_target_keys)
        .collect();
    if let Some(argument_place) = sink_argument
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)
    {
        if tainted_targets.contains(&argument_place) {
            if let Some(composition) = sink_file_index
                .string_compositions
                .iter()
                .filter(|fact| {
                    fact.container_span.start < sink.span.start
                        && fact.target.as_deref() == Some(argument_place.as_str())
                })
                .max_by_key(|fact| (fact.container_span.start, fact.container_span.end))
            {
                return Some(UrlReconstructionTarget {
                    function: sink_func,
                    output_span: Some(composition.container_span),
                });
            }
        }
    }
    let helper_call = sink_calls
        .iter()
        .filter(|call| {
            call.span != sink_call.span
                && span_contains(sink_argument.span, call.span)
                && call.args.len() == 1
                && call_arg_target_keys(&call.args[0])
                    .iter()
                    .any(|target| tainted_targets.contains(target))
        })
        .copied()
        .collect::<Vec<_>>();
    let [helper_call] = helper_call.as_slice() else {
        return None;
    };

    let helper_targets: AHashSet<FuncId> = call_graph
        .callees_of(sink_func)
        .filter(|edge| {
            edge.precision.is_semantic()
                && (edge.span == helper_call.span || spans_overlap(edge.span, helper_call.span))
        })
        .map(|edge| edge.to)
        .collect();
    let mut helper_targets = helper_targets.into_iter();
    let helper_func = helper_targets.next()?;
    if helper_targets.next().is_some() {
        return None;
    }
    Some(UrlReconstructionTarget {
        function: helper_func,
        output_span: None,
    })
}

fn compiler_proven_url_reconstruction_guard(
    ws: &Workspace,
    target: UrlReconstructionTarget,
    guard: &crate::rule::UrlReconstructionGuardSemantics,
) -> Option<Span> {
    let helper_decl = ws.exact_decl(SymbolId::new(target.function.raw()))?;
    if helper_decl.params.len() != 1 {
        return None;
    }
    let input = helper_decl.params.first()?;
    let helper_file_index = ws.exact_decl_index_shared(helper_decl.span.file)?;
    let mut helper_assignments = Vec::new();
    collect_structured_assignments_before(
        &helper_decl.flow_events,
        Span::empty(helper_decl.span.file, helper_decl.span.end),
        &mut helper_assignments,
    );
    helper_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let output_span = if let Some(span) = target.output_span {
        span
    } else {
        let mut returns = Vec::new();
        collect_return_bindings(&helper_decl.flow_events, &mut returns);
        let [(return_span, _)] = returns.as_slice() else {
            return None;
        };
        *return_span
    };
    let mut helper_calls = Vec::new();
    collect_structured_calls(&helper_decl.flow_events, &mut helper_calls);
    let mut helper_file_calls = Vec::new();
    for candidate in &helper_file_index.defs {
        collect_structured_calls(&candidate.flow_events, &mut helper_file_calls);
    }
    let mut branches = Vec::new();
    collect_all_structured_branches(&helper_decl.flow_events, &mut branches);
    let parser_candidates: Vec<_> = helper_assignments
        .iter()
        .filter(|assignment| {
            assignment.span.start < output_span.start
                && assignment.source_call.is_some_and(|call| {
                    rule_target_matches_call(call, &[], &guard.parser)
                        && assignment
                            .source_call_args
                            .first()
                            .and_then(|argument| clean_overwrite_target_key(argument))
                            .as_deref()
                            == Some(input.as_str())
                })
        })
        .filter_map(|assignment| {
            let parsed = clean_overwrite_target_key(assignment.target)?;
            let scheme_guard = branches
                .iter()
                .filter(|branch| {
                    assignment.span.start < branch.span.start
                        && branch.span.start < output_span.start
                        && branch_arm_abruptly_exits(branch.then_events)
                })
                .find(|branch| {
                    branch_condition_fact_for_span(&helper_file_index.branch_conditions, branch.span)
                        .and_then(|fact| fact.expression.as_ref())
                        .is_some_and(|expression| {
                            url_scheme_rejection_is_exact(
                                expression,
                                &parsed,
                                &guard.scheme,
                                &helper_calls,
                                &helper_file_index,
                            )
                        })
                })?;
            Some((assignment, parsed, scheme_guard))
        })
        .collect();
    let [(parser_assignment, parsed, scheme_guard)] = parser_candidates.as_slice() else {
        return None;
    };
    let _host_guard = branches
        .iter()
        .filter(|branch| {
            scheme_guard.span.start <= branch.span.start
                && branch.span.start < output_span.start
                && branch_arm_abruptly_exits(branch.then_events)
        })
        .find(|branch| {
            branch_condition_fact_for_span(&helper_file_index.branch_conditions, branch.span)
                .and_then(|fact| fact.expression.as_ref())
                .and_then(|expression| {
                    url_rejected_host_collection(expression, parsed, &guard.host_allowlist, &helper_calls)
                })
                .is_some_and(|collection| {
                    url_collection_is_static(
                        &collection,
                        branch.span,
                        &helper_file_index,
                        &helper_file_calls,
                        &guard.host_allowlist.static_collection_factories,
                    )
                })
        })?;
    let composition = helper_file_index.string_compositions.iter().find(|fact| {
        fact.container_span == output_span
            || spans_overlap(fact.container_span, output_span)
            || span_contains(fact.container_span, output_span)
            || span_contains(output_span, fact.container_span)
    })?;
    if !url_reconstruction_composition_is_exact(composition, parsed, guard, &helper_calls) {
        return None;
    }
    let mut immutable_places = vec![parsed.clone()];
    immutable_places.extend(
        [
            guard.scheme.component.field.as_deref(),
            guard.host_allowlist.component.field.as_deref(),
            guard.path_component.field.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(|field| format!("{parsed}.{field}")),
    );
    if immutable_places.iter().any(|place| {
        place_is_assigned_between(
            &helper_decl.flow_events,
            place,
            parser_assignment.span.end,
            output_span.start,
        )
    }) {
        return None;
    }
    Some(scheme_guard.span)
}

fn required_named_call_arguments_match(
    call: &StructuredCall<'_>,
    required: &[crate::rule::RequiredNamedArgumentSemantics],
    file_index: &bonsai_lang_api::DeclIndex,
) -> bool {
    required.iter().all(|requirement| {
        call.args.iter().enumerate().any(|(index, argument)| {
            argument.name.as_deref() == Some(requirement.name.as_str())
                && bonsai_lang_api::call_argument_value_fact(
                    &file_index.call_argument_values,
                    call.span,
                    index,
                )
                .and_then(|fact| fact.static_value.as_ref())
                    == Some(&requirement.value)
        })
    })
}

fn url_reconstruction_composition_is_exact(
    composition: &bonsai_lang_api::StringCompositionFact,
    parsed: &str,
    guard: &crate::rule::UrlReconstructionGuardSemantics,
    calls: &[StructuredCall<'_>],
) -> bool {
    let [StringCompositionPart::Literal { value: prefix }, host, path] = composition.parts.as_slice() else {
        return false;
    };
    let Some(scheme) = prefix.strip_suffix("://") else {
        return false;
    };
    let host_matches = string_composition_part_reads_url_component(
        host,
        parsed,
        &guard.host_allowlist.component,
        calls,
        None,
    );
    let path_matches = string_composition_part_reads_url_component(
        path,
        parsed,
        &guard.path_component,
        calls,
        guard.path_fallback.as_deref(),
    );
    let reconstructed_schemes = if guard.scheme.reconstructed_values.is_empty() {
        &guard.scheme.allowed_values
    } else {
        &guard.scheme.reconstructed_values
    };
    reconstructed_schemes.iter().any(|allowed| allowed == scheme) && host_matches && path_matches
}

fn string_composition_part_reads_url_component(
    part: &StringCompositionPart,
    parsed: &str,
    component: &crate::rule::UrlComponentSemantics,
    calls: &[StructuredCall<'_>],
    fallback: Option<&str>,
) -> bool {
    match (part, fallback) {
        (StringCompositionPart::Place { place }, None) => component
            .field
            .as_deref()
            .is_some_and(|field| place == &format!("{parsed}.{field}")),
        (
            StringCompositionPart::PlaceOrLiteral {
                place,
                fallback: actual,
            },
            Some(required),
        ) => {
            actual == required
                && component
                    .field
                    .as_deref()
                    .is_some_and(|field| place == &format!("{parsed}.{field}"))
        }
        (StringCompositionPart::Call { span }, None) => {
            url_component_call_matches(*span, parsed, component, calls)
        }
        (
            StringCompositionPart::CallOrLiteral {
                span,
                fallback: actual,
            },
            Some(required),
        ) => actual == required && url_component_call_matches(*span, parsed, component, calls),
        _ => false,
    }
}

fn url_component_call_matches(
    span: Span,
    parsed: &str,
    component: &crate::rule::UrlComponentSemantics,
    calls: &[StructuredCall<'_>],
) -> bool {
    let Some(accessor) = component.accessor.as_ref() else {
        return false;
    };
    calls.iter().any(|call| {
        call.span == span
            && call.receiver.and_then(clean_overwrite_target_key).as_deref() == Some(parsed)
            && rule_target_matches_call(call.name, call.receiver_types, accessor)
    })
}

fn url_guard_root_place(
    sink_call: &StructuredCall<'_>,
    sink_span: Span,
    guard: &crate::rule::UrlNetworkGuardSemantics,
    calls: &[StructuredCall<'_>],
    assignments: &[StructuredAssignment<'_>],
    import_aliases: &std::collections::HashMap<String, bonsai_lang_api::AliasTarget>,
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
                    && assignment.source_call.is_some_and(|call| {
                        crate::matcher::rule_target_matches_call_with_aliases(
                            call,
                            &[],
                            &guard.parser,
                            import_aliases,
                        )
                    })
            })
            .and_then(|assignment| clean_overwrite_target_key(assignment.target)),
        crate::rule::UrlGuardRootSemantics::SinkArgumentParserInput {
            sink_argument_index,
            parser_argument_index,
        } => {
            let sink_value = sink_call.args.get(*sink_argument_index).and_then(|argument| {
                argument
                    .place
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .or_else(|| {
                        argument
                            .source_names
                            .iter()
                            .find_map(|name| clean_overwrite_target_key(name))
                    })
            })?;
            assignments
                .iter()
                .rev()
                .find(|assignment| {
                    assignment.source_call.is_some_and(|call| {
                        crate::matcher::rule_target_matches_call_with_aliases(
                            call,
                            &[],
                            &guard.parser,
                            import_aliases,
                        )
                    }) && assignment
                        .source_call_args
                        .get(*parser_argument_index)
                        .and_then(|argument| clean_overwrite_target_key(argument))
                        .as_deref()
                        == Some(sink_value.as_str())
                })
                .and_then(|assignment| clean_overwrite_target_key(assignment.target))
        }
        crate::rule::UrlGuardRootSemantics::SinkArgumentAccessor {
            argument_index,
            accessor,
        } => {
            let argument = sink_call.args.get(*argument_index)?;
            let mut matching = calls.iter().filter(|call| {
                span_contains(argument.span, call.span)
                    && crate::matcher::rule_target_matches_call_with_aliases(
                        call.name,
                        call.receiver_types,
                        accessor,
                        import_aliases,
                    )
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
            .any(|argument| url_call_argument_reads_component(argument, parsed, &guard.component, calls));
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
        let exact_projection = operand.value_flow.projection.as_ref().is_some_and(|projection| {
            projection.base == parsed
                && projection.path.len() == 1
                && projection.path.first().is_some_and(|segment| segment == field)
        });
        if exact_projection {
            return true;
        }

        // A language frontend may lower a scalar expression such as a
        // null/empty fallback (`parsed.host or ""`) as a compound value.
        // It is still an exact read of the component when every dynamic
        // operand is that same projection; static fallback pieces do not
        // appear in `source_names`. Reject mixed dynamic expressions so a
        // host combined with another value cannot masquerade as an exact
        // allowlist check.
        let expected = format!("{parsed}.{field}");
        return !operand.value_flow.source_names.is_empty()
            && operand
                .value_flow
                .source_names
                .iter()
                .all(|source| source == &expected);
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

fn url_call_argument_reads_component(
    argument: &bonsai_lang_api::CallArg,
    parsed: &str,
    component: &crate::rule::UrlComponentSemantics,
    calls: &[StructuredCall<'_>],
) -> bool {
    if let Some(field) = component.field.as_deref() {
        let expected = format!("{parsed}.{field}");
        return argument.place.as_deref().map(str::trim) == Some(expected.as_str());
    }
    url_span_reads_component(argument.span, parsed, component, calls)
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
                                url_call_argument_reads_component(argument, parsed, &guard.component, calls)
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
    // Some languages represent typed aggregate literals with constructor-like
    // syntax (for example a map or record literal). The frontend therefore
    // retains a `direct_call_name` for type/receiver analysis even though the
    // exact aggregate value is wholly static. Accept that compiler-proven
    // aggregate shape, while keeping an empty call-result flow non-static.
    let has_exact_literal_aggregate =
        !assignment.value_flow.aggregate_fields.is_empty() || !assignment.value_flow.tuple_items.is_empty();
    if expression_flow_is_literal(&assignment.value_flow)
        && (assignment.direct_call_name.is_none() || has_exact_literal_aggregate)
    {
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
                .is_some_and(|fact| {
                    fact.static_value.is_some()
                        || fact
                            .exact_static_sequence_values
                            .as_ref()
                            .is_some_and(|values| !values.is_empty() && values.iter().all(Option::is_some))
                })
        })
}

fn url_condition_is_disjunction(expression: &ConditionExpressionFact) -> bool {
    match expression {
        ConditionExpressionFact::Atom { .. } | ConditionExpressionFact::Truthy { .. } => true,
        ConditionExpressionFact::Any { operands, .. } => operands.iter().all(|operand| {
            matches!(
                operand,
                ConditionExpressionFact::Atom { .. } | ConditionExpressionFact::Truthy { .. }
            )
        }),
        _ => false,
    }
}

fn url_private_predicate_receiver(
    expression: &ConditionExpressionFact,
    condition_span: Span,
    predicate: &RuleTarget,
    calls: &[StructuredCall<'_>],
) -> Option<String> {
    let terms: &[ConditionExpressionFact] = match expression {
        ConditionExpressionFact::Any { operands, .. } => operands,
        expression => std::slice::from_ref(expression),
    };
    terms.iter().find_map(|term| match term {
        ConditionExpressionFact::Truthy { operand, .. } => operand
            .value_flow
            .projection
            .as_ref()
            .filter(|projection| {
                projection.path.len() == 1
                    && rule_target_matches_call(&projection.canonical_place(), &[], predicate)
            })
            .map(|projection| projection.base.clone()),
        ConditionExpressionFact::Atom { span } => calls.iter().find_map(|call| {
            (span_contains(condition_span, call.span)
                && span_contains(*span, call.span)
                && rule_target_matches_call(call.name, call.receiver_types, predicate))
            .then(|| call.receiver.and_then(clean_overwrite_target_key))
            .flatten()
        }),
        _ => None,
    })
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

fn url_private_value_derives_from_resolver(
    place: &str,
    resolver_roots: &[String],
    assignments: &[StructuredAssignment<'_>],
    before: Span,
    dns: &crate::rule::UrlDnsGuardSemantics,
    calls: &[StructuredCall<'_>],
    import_aliases: &std::collections::HashMap<String, bonsai_lang_api::AliasTarget>,
) -> bool {
    if url_place_derives_from_any(place, resolver_roots, assignments, before, &mut AHashSet::new()) {
        return true;
    }
    let Some(parser) = dns.address_parser.as_ref() else {
        return false;
    };
    let Some(assignment) = assignments.iter().rev().find(|assignment| {
        assignment.span.start < before.start
            && clean_overwrite_target_key(assignment.target).as_deref() == Some(place)
            && assignment.source_call.is_some_and(|call| {
                crate::matcher::rule_target_matches_call_with_aliases(
                    call,
                    &[],
                    &parser.target,
                    import_aliases,
                )
            })
    }) else {
        return false;
    };
    let Some(parser_call) = calls.iter().find(|call| {
        span_contains(assignment.span, call.span)
            && crate::matcher::rule_target_matches_call_with_aliases(
                call.name,
                call.receiver_types,
                &parser.target,
                import_aliases,
            )
    }) else {
        return false;
    };
    let Some(argument) = parser_call.args.get(parser.argument_index) else {
        return false;
    };
    argument.place.as_deref().is_some_and(|place| {
        let place = place.trim();
        resolver_roots.iter().any(|root| root == place)
            || bonsai_lang_api::ExpressionProjection::from_adapter_place(place)
                .is_some_and(|projection| resolver_roots.iter().any(|root| root == &projection.base))
    })
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
        crate::rule::UrlRedirectGuardSemantics::CallArgumentFields {
            argument_index,
            required_fields,
        } => {
            !required_fields.is_empty()
                && bonsai_lang_api::call_argument_value_fact(
                    &file_index.call_argument_values,
                    sink_call.span,
                    *argument_index,
                )
                .is_some_and(|fact| {
                    required_fields.iter().all(|required| {
                        fact.exact_static_aggregate_fields
                            .iter()
                            .any(|field| field.path == required.path && field.value == required.value)
                    })
                })
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

pub(super) fn compiler_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let semantics = sink_rule.analysis_semantics.as_ref()?.compiler_guard.as_ref()?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let guard = file_index.compiler_guards.iter().find(|guard| {
        guard.function_span == decl.span
            && guard.capability == semantics.capability
            && semantics
                .required_evidence
                .iter()
                .all(|required| guard.evidence.contains(required))
            && semantics
                .forbidden_evidence
                .iter()
                .all(|forbidden| !guard.evidence.contains(forbidden))
            && spans_overlap(guard.guarded_call_span, snk.span)
    })?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        guard.proof_span,
        "engine.sanitizer.compiler_guard",
        &semantics.sanitizer_tag,
        &semantics.category,
    )
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
        .min_by_key(|call| {
            (
                call.span != matched_span,
                call.span.start.abs_diff(matched_span.start),
                call.span.end.abs_diff(matched_span.end),
                call.span.end.saturating_sub(call.span.start),
            )
        })
}

fn callee_spelling_tail(name: &str) -> String {
    bonsai_common::short_qualified_tail(name).trim().to_string()
}

#[derive(Clone, Copy)]
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

pub(super) fn nosql_eq_filter_wrapper_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    source: &RuleMatch,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink_tainted_args.is_empty() {
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
    let sink_call = structured_call_at_match(&calls, snk.span, "")?;
    let file_index = ws.exact_decl_index_shared(snk.span.file)?;
    let argument = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        sink_call.span,
        semantics.filter_arg_index,
    )?;
    if !nosql_filter_uses_only_literal_value_operators(NosqlFilterProofContext {
        filter: &argument.value_flow,
        literal_value_operators: &semantics.literal_value_operators,
        safe_scalar_types: &semantics.safe_scalar_compiler_types,
        type_aliases: &decl.type_aliases,
        safe_scalar_source_rules: &semantics.safe_scalar_source_rules,
        source,
        file_index: &file_index,
        before: snk.span,
    }) {
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
        tag: sink_rule.tag.clone(),
        severity: None,
        category: Some("nosql-eq-wrapper".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: vec![u32::try_from(semantics.filter_arg_index).ok()?],
    })
}

struct NosqlFilterProofContext<'a> {
    filter: &'a bonsai_lang_api::ExpressionFlow,
    literal_value_operators: &'a [String],
    safe_scalar_types: &'a [String],
    type_aliases: &'a [bonsai_lang_api::TypeAliasBinding],
    safe_scalar_source_rules: &'a [String],
    source: &'a RuleMatch,
    file_index: &'a bonsai_lang_api::DeclIndex,
    before: Span,
}

fn nosql_filter_uses_only_literal_value_operators(context: NosqlFilterProofContext<'_>) -> bool {
    let NosqlFilterProofContext {
        filter,
        literal_value_operators,
        safe_scalar_types,
        type_aliases,
        safe_scalar_source_rules,
        source,
        file_index,
        before,
    } = context;
    if filter.aggregate_fields.is_empty() || !filter.spreads.is_empty() || !filter.tuple_items.is_empty() {
        return false;
    }
    let mut saw_literal_operator = false;
    let mut saw_typed_scalar = false;
    for field in &filter.aggregate_fields {
        if field.name.starts_with('$') {
            return false;
        }
        if expression_flow_is_literal(&field.value) {
            continue;
        }
        if expression_flow_has_only_safe_scalar_places(&field.value, safe_scalar_types, type_aliases)
            || expression_flow_has_rule_declared_scalar_source(
                &field.value,
                safe_scalar_source_rules,
                source,
                file_index,
                before,
            )
        {
            saw_typed_scalar = true;
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
    saw_literal_operator || saw_typed_scalar
}

fn expression_flow_has_rule_declared_scalar_source(
    flow: &bonsai_lang_api::ExpressionFlow,
    safe_source_rules: &[String],
    source: &RuleMatch,
    file_index: &bonsai_lang_api::DeclIndex,
    before: Span,
) -> bool {
    safe_source_rules.iter().any(|rule_id| rule_id == &source.rule_id)
        && flow.aggregate_fields.is_empty()
        && flow.tuple_items.is_empty()
        && flow.spreads.is_empty()
        && expression_flow_depends_on_match_span(flow, file_index, before, source.span)
}

fn expression_flow_has_only_safe_scalar_places(
    flow: &bonsai_lang_api::ExpressionFlow,
    safe_types: &[String],
    type_aliases: &[bonsai_lang_api::TypeAliasBinding],
) -> bool {
    if safe_types.is_empty()
        || !flow.call_sites.is_empty()
        || !flow.aggregate_fields.is_empty()
        || !flow.tuple_items.is_empty()
        || !flow.spreads.is_empty()
    {
        return false;
    }
    let mut places = flow
        .place
        .as_deref()
        .into_iter()
        .chain(flow.source_names.iter().map(String::as_str))
        .filter_map(clean_overwrite_target_key)
        .collect::<Vec<_>>();
    places.sort();
    places.dedup();
    !places.is_empty()
        && places.iter().all(|place| {
            let root = place.split('.').next().unwrap_or(place);
            type_aliases.iter().any(|alias| {
                alias.name == root
                    && safe_types
                        .iter()
                        .any(|safe| type_name_matches(&alias.type_name, safe))
            })
        })
}

fn type_name_matches(actual: &str, expected: &str) -> bool {
    bonsai_common::qualified_names_match(actual, expected)
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
    then_events: &'a [FlowEvent],
}

fn collect_completed_branches_on_path<'a>(
    events: &'a [FlowEvent],
    target: Span,
    out: &mut Vec<StructuredBranch<'a>>,
) {
    for (event_index, event) in events.iter().enumerate() {
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
                _ if events[event_index.saturating_add(1)..]
                    .iter()
                    .any(|later| span_contains(later.span(), target)) =>
                {
                    // Some frontends emit a broad binding event beside the
                    // structured region it initializes (for example a loop
                    // target assignment whose span is the complete loop).
                    // Prefer the later, tighter sibling instead of treating
                    // this duplicate projection as the target's control path.
                    continue;
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
            condition: Some(_),
            then_events,
            ..
        } = event
        {
            out.push(StructuredBranch {
                span: *span,
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
                if condition.is_some() {
                    out.push(StructuredBranch {
                        span: *span,
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
            condition: Some(_),
            then_events,
            ..
        } = event
        {
            out.push(StructuredBranch {
                span: *span,
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
    let enclosing_fn = ws
        .exact_decl_index_shared(span.file)
        .and_then(|index| {
            index
                .defs
                .iter()
                .filter(|decl| span_contains(decl.body_span.unwrap_or(decl.span), span))
                .min_by_key(|decl| decl.span.len())
                .map(|decl| decl.name.clone())
        })
        .or_else(|| hit.enclosing_fn.clone());
    Some(FindingMatch {
        origin: MatchOrigin::EngineSanitizer,
        rule_id: rule_id.to_string(),
        file,
        line,
        column,
        text,
        enclosing_fn,
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
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let sink_call = structured_call_at_match(&calls, sink.span, "")?;
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
        sink_rule.tag.as_deref()?,
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

#[cfg(test)]
mod structured_guard_tests {
    use super::*;
    use std::sync::Arc;

    fn span(start: u64, end: u64) -> Span {
        Span::new(FileId::new(0), start, end)
    }

    #[test]
    fn context_rewrite_requires_a_compiler_proven_non_null_branch() {
        use bonsai_lang_api::LanguageAdapter;

        for (condition, expected) in [("rid != null", true), ("enabled", false), ("rid == null", false)] {
            let source = format!(
                r#"
class Context {{
  void handle(String rid, boolean enabled) {{
    if ({condition}) {{ MDC.put("rid", rid); }}
    LOG.info("request");
  }}
}}
"#
            );
            let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
            let ws = bonsai_testkit::workspace_with(vec![adapter], &[("Context.java", &source)]);
            let file = ws.db().vfs().all_files()[0];
            let index = ws.db().decl_index(file).expect("Java declaration index");
            let decl = index
                .defs
                .iter()
                .find(|decl| decl.name == "handle")
                .expect("handle declaration");
            let mut calls = Vec::new();
            collect_structured_calls(&decl.flow_events, &mut calls);
            let rewrite_span = calls
                .iter()
                .find(|call| callee_spelling_tail(call.name) == "put")
                .expect("MDC.put")
                .span;
            let consumer_span = calls
                .iter()
                .find(|call| callee_spelling_tail(call.name) == "info")
                .expect("LOG.info")
                .span;
            let hit = |rule_id: &str, span: Span| RuleMatch {
                origin: MatchOrigin::Rulepack,
                rule_id: rule_id.to_string(),
                language: bonsai_lang_java::LANG_ID.as_str().to_string(),
                file: "Context.java".to_string(),
                line: 1,
                column: 1,
                span,
                match_text: rule_id.to_string(),
                enclosing_fn: Some("handle".to_string()),
            };
            assert_eq!(
                sanitized_context_rewrite_covers_consumer(
                    &ws,
                    &hit("java.log_injection.mdc_put", rewrite_span),
                    &hit("java.log_injection.mdc_context_logger_info", consumer_span),
                    &["rid".to_string()].into_iter().collect(),
                ),
                expected,
                "condition {condition:?}"
            );
        }
    }

    #[test]
    fn nested_python_zip_write_uses_typed_boundary_containment() {
        use bonsai_lang_api::LanguageAdapter;

        let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_python::PythonAdapter::new());
        let ws = bonsai_testkit::workspace_with(
            vec![adapter],
            &[(
                "extract.py",
                r#"
import os
def unzip_into(blob, base):
    base_real = os.path.realpath(base)
    for entry in entries(blob):
        target = os.path.realpath(os.path.join(base_real, entry))
        if target != base_real and not target.startswith(base_real + os.sep):
            raise ValueError("escape")
        with open(target, "wb") as output:
            output.write(blob)

def upload(blob):
    unzip_into(blob, "/var/data/upload")
"#,
            )],
        );
        let file = ws.db().vfs().all_files()[0];
        let index = ws.db().decl_index(file).expect("Python declaration index");
        let decl = index
            .defs
            .iter()
            .find(|decl| decl.name == "unzip_into")
            .expect("unzip_into declaration");
        let mut calls = Vec::new();
        collect_structured_calls(&decl.flow_events, &mut calls);
        let open = calls
            .iter()
            .find(|call| call.args.get(1).is_some_and(|arg| arg.value_text == "\"wb\""))
            .expect("consumer of the proven target path");
        let target = |attribute: Option<&[&str]>, name: Option<&str>| RuleTarget {
            attribute: attribute.map(|parts| parts.iter().map(|part| (*part).to_string()).collect()),
            name: name.map(str::to_string),
            ..RuleTarget::default()
        };
        let guard = crate::rule::PathConsumerContainmentGuardSemantics {
            canonicalizer: target(Some(&["os", "path", "realpath"]), None),
            base_canonicalizer: None,
            path_constructor: target(Some(&["os", "path", "join"]), None),
            path_constructor_base_from_receiver: false,
            containment_check: target(None, Some("startswith")),
            static_base_factories: Vec::new(),
            sink_path_arg_index: 0,
            path_constructor_base_arg_index: 0,
            containment_check_is_segment_aware: false,
            boundary_places: vec!["os.sep".to_string()],
        };
        let call_graph = ws.cached_resolved_call_graph();
        assert!(
            path_consumer_guard_span(&ws, call_graph.as_ref(), decl, open.span, 0, &guard, None,).is_some(),
            "typed branch facts: {:#?}",
            index.branch_conditions
        );
    }

    #[test]
    fn exact_nested_call_wins_over_an_overlapping_outer_call() {
        let calls = [
            StructuredCall {
                span: span(10, 40),
                name: "_env.from_string(text).render",
                receiver: Some("_env.from_string(text)"),
                receiver_types: &[],
                args: &[],
            },
            StructuredCall {
                span: span(10, 28),
                name: "_env.from_string",
                receiver: Some("_env"),
                receiver_types: &[],
                args: &[],
            },
        ];

        let selected =
            structured_call_at_match(&calls, span(10, 28), "from_string").expect("inner call must match");
        assert_eq!(selected.receiver, Some("_env"));
    }
}
