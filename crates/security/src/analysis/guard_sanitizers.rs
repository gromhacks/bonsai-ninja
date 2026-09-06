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
    pub(super) source_rule: Option<&'a Rule>,
    pub(super) source_func: FuncId,
    pub(super) sink: &'a RuleMatch,
    pub(super) sink_rule: &'a Rule,
    pub(super) candidate_funcs: &'a [FuncId],
    pub(super) tainted_call_spans: &'a AHashSet<Span>,
    pub(super) taint_path: &'a [TaintPropagationStep],
    pub(super) sink_tainted_args: &'a [TaintedArgInfo],
}

/// Immutable graph state required by the path-consumer containment proof.
/// Grouping it keeps the sanitizer entry point focused on the finding-specific
/// values while retaining each independently compiled evidence source.
pub(super) struct PathConsumerGuardContext<'a> {
    pub(super) ws: &'a Workspace,
    pub(super) global: &'a bonsai_index::GlobalIndex,
    pub(super) call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    pub(super) static_provenance_call_graph: &'a bonsai_callgraph::ResolvedCallGraph,
    pub(super) callback_invocations: &'a [bonsai_taint::CallbackInvocation],
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
    accepted_predicate_value: bool,
    predicate_falsey_result_is_null: bool,
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
        let proven = condition_truth_implies_predicate_value(
            expression,
            false,
            predicate_span,
            accepted_predicate_value,
            predicate_falsey_result_is_null,
        );
        if !proven {
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "terminal_predicate_guard call={:?} accepted={} expression={:?}",
                predicate_span,
                accepted_predicate_value,
                expression
            );
        }
        proven.then_some(branch.span)
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
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
    tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
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
    });
    if let Some(selection) = selection {
        return finding_for_guard_span_in_workspace(
            ws,
            sink,
            selection.selection_span,
            "engine.sanitizer.finite_literal_selection",
            sink_rule.tag.as_deref()?,
            "compiler-proven-finite-literal-selection",
        );
    }
    let selection_span = finite_literal_returning_helper_selection(
        ws,
        call_graph,
        sink_func,
        &file_index,
        &decl,
        sink,
        tainted_args,
    )?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        selection_span,
        "engine.sanitizer.finite_literal_selection",
        sink_rule.tag.as_deref()?,
        "compiler-proven-finite-literal-selection",
    )
}

/// Validate one exact sanitizer-rule match as a finite literal-map
/// selection. The matcher owns the selector identity; this proof owns only
/// compiler facts for the map binding, positional roles, dominance, and
/// local use safety.
pub(super) fn finite_literal_map_selector_call_is_proven(
    ws: &Workspace,
    function: FuncId,
    sanitizer: &RuleMatch,
    rule: &Rule,
) -> bool {
    let Some(semantics) = rule
        .taint_semantics
        .as_ref()
        .and_then(|semantics| semantics.finite_literal_map_selector.as_ref())
    else {
        return true;
    };
    let Some(decl) = ws.exact_decl(SymbolId::new(function.raw())) else {
        return false;
    };
    if !span_contains(decl.body_span.unwrap_or(decl.span), sanitizer.span) {
        return false;
    }
    let Some(file_index) = ws.exact_decl_index_shared(sanitizer.span.file) else {
        return false;
    };
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let Some(call) = calls.iter().find(|call| call.span == sanitizer.span) else {
        return false;
    };
    let map_place = if let Some(index) = semantics.map_argument_index {
        let Some(fact) =
            bonsai_lang_api::call_argument_value_fact(&file_index.call_argument_values, call.span, index)
        else {
            return false;
        };
        if call
            .args
            .get(index)
            .is_none_or(|argument| argument.span != fact.argument_span)
        {
            return false;
        }
        fact.value_flow
            .projection
            .as_ref()
            .map(bonsai_lang_api::ExpressionProjection::canonical_place)
            .or_else(|| fact.value_flow.place.clone())
    } else {
        call.receiver.map(str::trim).map(str::to_string)
    };
    let Some(map_place) = map_place.filter(|name| simple_local_place(name)) else {
        return false;
    };
    let Some(key) = call.args.get(semantics.key_argument_index) else {
        return false;
    };
    let Some(fallback) = call.args.get(semantics.fallback_argument_index) else {
        return false;
    };
    if key.name.is_some() || fallback.name.is_some() {
        return false;
    }
    if !bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        call.span,
        semantics.fallback_argument_index,
    )
    .is_some_and(|fact| {
        fact.argument_span == fallback.span
            && matches!(
                fact.static_value,
                Some(bonsai_lang_api::StaticScalarValue::String(_))
            )
    }) {
        return false;
    }

    let maps = file_index
        .static_string_maps
        .iter()
        .filter(|map| {
            map.target == map_place
                && (map.target_is_immutable
                    || span_contains(decl.body_span.unwrap_or(decl.span), map.assignment_span))
        })
        .collect::<Vec<_>>();
    let [map] = maps.as_slice() else {
        return false;
    };
    if map.assignment_span.end > call.span.start {
        return false;
    }
    if decl.params.iter().any(|param| param == &map_place)
        || file_index.call_argument_values.iter().any(|fact| {
            fact.call_span.file == sanitizer.span.file
                && span_contains(decl.body_span.unwrap_or(decl.span), fact.call_span)
                && fact
                    .inline_callback_params
                    .iter()
                    .any(|param| param == &map_place)
        })
    {
        return false;
    }

    let mut proof = FiniteMapUseProof {
        safe: true,
        ..FiniteMapUseProof::default()
    };
    inspect_finite_map_uses(
        &decl.flow_events,
        &file_index.call_argument_values,
        &map_place,
        map.assignment_span,
        call.span,
        true,
        &mut proof,
    );
    let expected_assignments = usize::from(!map.target_is_immutable);
    proof.safe && proof.direct_map_assignments == expected_assignments && proof.selector_calls == 1
}

#[derive(Default)]
struct FiniteMapUseProof {
    safe: bool,
    direct_map_assignments: usize,
    selector_calls: usize,
}

fn inspect_finite_map_uses(
    events: &[FlowEvent],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    map: &str,
    map_assignment: Span,
    selector_call: Span,
    direct: bool,
    proof: &mut FiniteMapUseProof,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_names,
                ..
            } => {
                if *span == map_assignment && target == map && direct {
                    proof.direct_map_assignments += 1;
                } else if place_is_or_projects_from(target, map) {
                    proof.safe = false;
                }
                if source_name.as_deref() == Some(map)
                    || (source_names.iter().any(|source| source == map)
                        && !assignment_value_owns_call_span(*span, selector_call))
                {
                    proof.safe = false;
                }
            }
            FlowEvent::AggregateAssign {
                span,
                target,
                value_flow,
                ..
            } => {
                // Aggregate lowering and scalar assignment lowering describe
                // the same parsed map initializer. The exact static-map fact
                // proves that initializer finite, so its companion aggregate
                // event is not a mutation or escape. Any other aggregate
                // write/read of the map remains disqualifying.
                let initializes_proven_map = direct && *span == map_assignment && target == map;
                if !initializes_proven_map
                    && (place_is_or_projects_from(target, map)
                        || expression_flow_reads_place(value_flow, map))
                {
                    proof.safe = false;
                }
            }
            FlowEvent::Call {
                span, receiver, args, ..
            } => {
                if *span == selector_call {
                    let selects_map = receiver.as_deref().map(str::trim) == Some(map)
                        || args.iter().any(|argument| {
                            argument
                                .place
                                .as_deref()
                                .and_then(clean_overwrite_target_key)
                                .as_deref()
                                == Some(map)
                        });
                    if selects_map {
                        proof.selector_calls += 1;
                    } else {
                        proof.safe = false;
                    }
                } else if receiver.as_deref().map(str::trim) == Some(map) {
                    proof.safe = false;
                }
                if *span != selector_call {
                    for (argument_index, argument) in args.iter().enumerate() {
                        if !call_argument_reads_place(argument, map) {
                            continue;
                        }
                        // A selector may be nested directly in the consumer
                        // argument (`sink(TABLE.fetch(key, fallback))`). The
                        // map receiver contributes to that argument's source
                        // inventory, but it does not escape the selector. Only
                        // the exact compiler direct-call fact proves this;
                        // compositions or aggregate siblings that also expose
                        // the map remain unsafe.
                        let selector_is_entire_argument = bonsai_lang_api::call_argument_value_fact(
                            call_argument_values,
                            *span,
                            argument_index,
                        )
                        .is_some_and(|fact| {
                            fact.argument_span == argument.span
                                && fact
                                    .direct_call_span
                                    .is_some_and(|direct| spans_overlap(direct, selector_call))
                                && matches!(fact.value_flow.call_sites.as_slice(), [call]
                                    if spans_overlap(*call, selector_call))
                                && fact.value_flow.aggregate_fields.is_empty()
                                && fact.value_flow.tuple_items.is_empty()
                                && fact.value_flow.spreads.is_empty()
                        });
                        if !selector_is_entire_argument {
                            proof.safe = false;
                        }
                    }
                }
            }
            FlowEvent::Return {
                span,
                value_name,
                value_flow,
                ..
            } => {
                if value_name.as_deref() == Some(map)
                    || (expression_flow_reads_place(value_flow, map) && !span_contains(*span, selector_call))
                {
                    proof.safe = false;
                }
            }
            FlowEvent::Yield { value_flow, .. } => {
                if expression_flow_reads_place(value_flow, map) {
                    proof.safe = false;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inspect_finite_map_uses(
                    then_events,
                    call_argument_values,
                    map,
                    map_assignment,
                    selector_call,
                    false,
                    proof,
                );
                inspect_finite_map_uses(
                    else_events,
                    call_argument_values,
                    map,
                    map_assignment,
                    selector_call,
                    false,
                    proof,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inspect_finite_map_uses(
                    body,
                    call_argument_values,
                    map,
                    map_assignment,
                    selector_call,
                    false,
                    proof,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inspect_finite_map_uses(
                    body,
                    call_argument_values,
                    map,
                    map_assignment,
                    selector_call,
                    false,
                    proof,
                );
                inspect_finite_map_uses(
                    catch_events,
                    call_argument_values,
                    map,
                    map_assignment,
                    selector_call,
                    false,
                    proof,
                );
                inspect_finite_map_uses(
                    finally_events,
                    call_argument_values,
                    map,
                    map_assignment,
                    selector_call,
                    false,
                    proof,
                );
            }
            FlowEvent::Throw { value_name, .. } => {
                if value_name.as_deref() == Some(map) {
                    proof.safe = false;
                }
            }
            FlowEvent::Await { value_name, .. } => {
                if value_name.as_deref() == Some(map) {
                    proof.safe = false;
                }
            }
            FlowEvent::Lifecycle { name, .. } => {
                if name == map {
                    proof.safe = false;
                }
            }
            FlowEvent::Break { .. } | FlowEvent::Continue { .. } => {}
        }
    }
}

fn assignment_value_owns_call_span(assignment: Span, call: Span) -> bool {
    assignment.file == call.file && assignment.start <= call.start && call.end <= assignment.end
}

fn simple_local_place(place: &str) -> bool {
    !place.is_empty()
        && place
            .chars()
            .enumerate()
            .all(|(index, ch)| ch == '_' || ch.is_alphabetic() || index > 0 && ch.is_numeric())
}

fn place_is_or_projects_from(place: &str, root: &str) -> bool {
    place == root
        || place
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('.') || suffix.starts_with('['))
}

fn call_argument_reads_place(argument: &bonsai_lang_api::CallArg, place: &str) -> bool {
    argument.place.as_deref() == Some(place) || argument.source_names.iter().any(|source| source == place)
}

fn expression_flow_reads_place(flow: &bonsai_lang_api::ExpressionFlow, place: &str) -> bool {
    flow.place.as_deref() == Some(place)
        || flow.source_names.iter().any(|source| source == place)
        || flow
            .aggregate_fields
            .iter()
            .any(|field| expression_flow_reads_place(&field.value, place))
        || flow
            .tuple_items
            .iter()
            .chain(flow.spreads.iter())
            .any(|item| expression_flow_reads_place(item, place))
}

/// Follow only exact compiler-resolved calls that contribute to a tainted sink
/// argument. If the unique callee returns a frontend-proven finite literal
/// selection, the caller receives one of those literals rather than the
/// selector value. Ambiguous/unresolved calls and selections used anywhere
/// other than the helper's complete return expression fail closed.
fn finite_literal_returning_helper_selection(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    caller_func: FuncId,
    caller_index: &bonsai_lang_api::DeclIndex,
    caller: &bonsai_lang_api::Decl,
    sink: &RuleMatch,
    tainted_args: &[TaintedArgInfo],
) -> Option<Span> {
    let mut calls = Vec::new();
    collect_structured_calls(&caller.flow_events, &mut calls);
    let sink_call = structured_call_at_match(&calls, sink.span, "")?;
    let mut reaching_calls = Vec::new();
    for argument in tainted_args {
        let Some(value) = bonsai_lang_api::call_argument_value_fact(
            &caller_index.call_argument_values,
            sink_call.span,
            argument.index,
        ) else {
            continue;
        };
        if let Some(span) = value.direct_call_span {
            reaching_calls.push(span);
        }
        collect_compiler_call_sites_reaching_value(
            caller_index,
            &value.value_flow,
            sink_call.span,
            &mut reaching_calls,
            &mut AHashSet::new(),
        );
        // The taint engine preserves the adapter-lowered operands that made
        // this particular sink argument tainted. A direct receiver transform
        // may intentionally leave its generic ExpressionFlow rooted at the
        // call result (library passthrough meaning belongs to rules), while
        // the proven tainted operand still names the reaching local. Follow
        // those exact operands through compiler assignment facts instead of
        // guessing that every receiver method is a passthrough.
        let mut seen_places = AHashSet::new();
        for source in &argument.source_names {
            let source = clean_overwrite_target_key(source);
            let Some(source) = source.as_deref() else {
                continue;
            };
            let source_flow = bonsai_lang_api::ExpressionFlow {
                place: Some(source.to_string()),
                source_names: vec![source.to_string()],
                ..bonsai_lang_api::ExpressionFlow::default()
            };
            collect_compiler_call_sites_reaching_value(
                caller_index,
                &source_flow,
                sink_call.span,
                &mut reaching_calls,
                &mut seen_places,
            );
        }
    }
    reaching_calls.sort_unstable_by_key(|span| (span.file.raw(), span.start, span.end));
    reaching_calls.dedup();

    for call_span in reaching_calls {
        let mut targets = call_graph
            .callees_of(caller_func)
            .filter(|edge| spans_overlap(edge.span, call_span))
            .map(|edge| edge.to)
            .collect::<AHashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        targets.sort_unstable_by_key(|target| target.raw());
        if targets.is_empty() {
            continue;
        }

        // Pattern-dispatched and overloaded callables may have several exact
        // compiler-resolved targets. The result is finite only when every
        // possible target independently proves a complete literal return;
        // one missing, dynamic, or undecodable body fails closed.
        let mut representative = None;
        let mut complete = true;
        for target in targets {
            let Some(helper) = ws.exact_decl(SymbolId::new(target.raw())) else {
                complete = false;
                break;
            };
            let Some(helper_index) = ws.exact_decl_index_shared(helper.span.file) else {
                complete = false;
                break;
            };
            let candidate_spans = helper_index
                .finite_literal_selections
                .iter()
                .filter(|selection| {
                    selection.assignment_span.is_none()
                        && selection.call_span.is_none()
                        && span_contains(helper.span, selection.selection_span)
                })
                .map(|selection| selection.selection_span)
                .collect::<Vec<_>>();
            let Some(selection_span) = bonsai_lang_api::kit::complete_finite_selection_return_span(
                &helper.flow_events,
                &candidate_spans,
            ) else {
                complete = false;
                break;
            };
            representative =
                Some(representative.map_or(selection_span, |current: Span| current.min(selection_span)));
        }
        if complete && representative.is_some() {
            return representative;
        }
    }
    None
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
            ..
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

/// Prove a finite allowed result set for a rule-selected direct call.
fn condition_truth_implies_call_result_allowed(
    expression: &ConditionExpressionFact,
    truth: bool,
    call: Span,
    accepted: &[bonsai_lang_api::StaticScalarValue],
) -> bool {
    let proves = |operand, truth| condition_truth_implies_call_result_allowed(operand, truth, call, accepted);
    match expression {
        ConditionExpressionFact::Not { operand, .. } => proves(operand, !truth),
        ConditionExpressionFact::All { operands, .. } if truth => {
            operands.iter().any(|operand| proves(operand, true))
        }
        ConditionExpressionFact::All { operands, .. } => {
            !operands.is_empty() && operands.iter().all(|operand| proves(operand, false))
        }
        ConditionExpressionFact::Any { operands, .. } if truth => {
            !operands.is_empty() && operands.iter().all(|operand| proves(operand, true))
        }
        ConditionExpressionFact::Any { operands, .. } => {
            operands.iter().any(|operand| proves(operand, false))
        }
        ConditionExpressionFact::Equality {
            relation,
            left,
            right,
            ..
        } => {
            let equality_holds = match relation {
                ConditionEquality::Equal => truth,
                ConditionEquality::NotEqual => !truth,
            };
            equality_holds
                && ((condition_operand_is_exact_call_result(left, call)
                    && right
                        .static_value
                        .as_ref()
                        .is_some_and(|value| accepted.contains(value)))
                    || (condition_operand_is_exact_call_result(right, call)
                        && left
                            .static_value
                            .as_ref()
                            .is_some_and(|value| accepted.contains(value))))
        }
        ConditionExpressionFact::Atom { .. }
        | ConditionExpressionFact::Truthy { .. }
        | ConditionExpressionFact::TypeTest { .. }
        | ConditionExpressionFact::Membership { .. } => false,
    }
}

/// Prove one exact predicate's accepted value under a selected branch truth.
/// The frontend owns expression shape and the rule owns the result domain.
/// Merely containing the predicate (for example in an unknown wrapper call)
/// never establishes its result.
fn condition_truth_implies_predicate_value(
    expression: &ConditionExpressionFact,
    truth: bool,
    call: Span,
    accepted: bool,
    falsey_is_null: bool,
) -> bool {
    let proves = |operand, truth| {
        condition_truth_implies_predicate_value(operand, truth, call, accepted, falsey_is_null)
    };
    match expression {
        ConditionExpressionFact::Not { operand, .. } => proves(operand, !truth),
        ConditionExpressionFact::All { operands, .. } if truth => {
            operands.iter().any(|operand| proves(operand, true))
        }
        ConditionExpressionFact::All { operands, .. } => {
            !operands.is_empty() && operands.iter().all(|operand| proves(operand, false))
        }
        ConditionExpressionFact::Any { operands, .. } if truth => {
            !operands.is_empty() && operands.iter().all(|operand| proves(operand, true))
        }
        ConditionExpressionFact::Any { operands, .. } => {
            operands.iter().any(|operand| proves(operand, false))
        }
        ConditionExpressionFact::Equality {
            relation,
            left,
            right,
            ..
        } => {
            let equality_holds = match relation {
                ConditionEquality::Equal => truth,
                ConditionEquality::NotEqual => !truth,
            };
            let value = if condition_operand_is_exact_call_result(left, call) {
                right.static_value.as_ref()
            } else if condition_operand_is_exact_call_result(right, call) {
                left.static_value.as_ref()
            } else {
                None
            };
            match value {
                Some(bonsai_lang_api::StaticScalarValue::Boolean(value)) => {
                    equality_holds && *value == accepted
                }
                Some(bonsai_lang_api::StaticScalarValue::Null) => {
                    if falsey_is_null {
                        equality_holds != accepted
                    } else {
                        equality_holds && !accepted
                    }
                }
                _ => false,
            }
        }
        ConditionExpressionFact::Atom { span } => *span == call && truth == accepted,
        ConditionExpressionFact::TypeTest {
            predicate_call_span, ..
        } => *predicate_call_span == Some(call) && truth == accepted,
        ConditionExpressionFact::Truthy { operand, .. } => {
            condition_operand_is_exact_call_result(operand, call) && truth == accepted
        }
        ConditionExpressionFact::Membership { .. } => false,
    }
}

/// Evaluate a compiler-lowered helper return without assigning meaning to the
/// referenced call. The sanitizer rule supplies the accepted truth value and
/// any stronger result-domain contract; the adapter keeps null and booleans
/// distinct in the compiler IR.
pub(super) fn predicate_return_implies_call_value(
    expression: &ConditionExpressionFact,
    call: Span,
    accepted: bool,
    falsey_is_null: bool,
) -> bool {
    condition_truth_implies_predicate_value(expression, true, call, accepted, falsey_is_null)
}

fn condition_operand_is_exact_call_result(operand: &ConditionOperandFact, call: Span) -> bool {
    operand.direct_call_span.is_some_and(|direct| direct == call)
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
            &file_index,
            &file_index.branch_conditions,
            branch,
            &candidate,
            &base,
            &guard.containment_check,
            None,
            None,
            None,
            guard.containment_check_candidate_arg_index,
            guard.containment_check_base_arg_index,
            &guard.boundary_places,
            &[],
            &[],
            &[],
            false,
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
    context: &PathConsumerGuardContext<'_>,
    taint_path: &[TaintPropagationStep],
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let PathConsumerGuardContext {
        ws,
        global,
        call_graph,
        static_provenance_call_graph,
        callback_invocations,
    } = context;
    let semantics = sink_rule.analysis_semantics.as_ref()?;
    if semantics.guard_profile != Some(GuardProfile::PathConsumerContainment) {
        return None;
    }
    let guard = semantics.path_consumer_containment_guard.as_ref()?;
    let decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let guarded_span = path_consumer_guard_span(
        ws,
        global,
        static_provenance_call_graph,
        &decl,
        sink.span,
        guard.sink_path_arg_index,
        guard,
        None,
    )
    .or_else(|| {
        path_consumer_helper_guard_span(
            ws,
            global,
            call_graph,
            static_provenance_call_graph,
            sink_func,
            &decl,
            sink.span,
            guard,
        )
    })
    .or_else(|| {
        let guarded = call_graph.callers_of(sink_func).find_map(|edge| {
            let caller = ws.exact_decl(SymbolId::new(edge.from.raw()))?;
            path_consumer_guard_span(
                ws,
                global,
                static_provenance_call_graph,
                &caller,
                edge.span,
                guard.sink_path_arg_index,
                guard,
                Some(&decl.name),
            )
        });
        guarded
    })
    .or_else(|| {
        path_consumer_callback_guard_span(
            ws,
            global,
            static_provenance_call_graph,
            callback_invocations,
            taint_path,
            sink_func,
            &decl,
            guard,
        )
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

#[allow(clippy::too_many_arguments)] // Each input is an independent compiler or rule proof.
fn path_consumer_callback_guard_span(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    static_provenance_call_graph: &bonsai_callgraph::ResolvedCallGraph,
    invocations: &[bonsai_taint::CallbackInvocation],
    taint_path: &[TaintPropagationStep],
    callback: FuncId,
    callback_decl: &bonsai_lang_api::Decl,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> Option<Span> {
    for invocation in invocations {
        let Some(outer_arg) = invocation
            .forwarded_args_from
            .map(|start| start.saturating_add(guard.sink_path_arg_index))
        else {
            continue;
        };
        for (call_span, target) in &invocation.resolved_callback_targets {
            if *target != callback {
                continue;
            }
            let Some(owner) = ws
                .enclosing_index()
                .enclosing_for(global, call_span.file, call_span.start)
            else {
                continue;
            };
            let Some(caller) = ws.exact_decl(owner.symbol) else {
                continue;
            };
            if !callback_host_call_is_on_taint_path(ws, &caller, *call_span, callback_decl, taint_path) {
                continue;
            }
            if let Some(span) = path_consumer_guard_span(
                ws,
                global,
                static_provenance_call_graph,
                &caller,
                *call_span,
                outer_arg,
                guard,
                None,
            ) {
                return Some(span);
            }
        }
    }
    None
}

fn callback_host_call_is_on_taint_path(
    ws: &Workspace,
    caller: &bonsai_lang_api::Decl,
    call_span: Span,
    callback: &bonsai_lang_api::Decl,
    taint_path: &[TaintPropagationStep],
) -> bool {
    let Ok(snapshot) = ws.vfs().snapshot(call_span.file) else {
        return false;
    };
    let location = bonsai_common::cached_span_map_arc(call_span.file, snapshot.version, &snapshot.text)
        .line_col(call_span.start);
    taint_path.iter().any(|step| {
        step.caller == caller.name
            && callee_spelling_tail(&step.callee) == callee_spelling_tail(&callback.name)
            && step.line == location.line
            && step.column == location.column
    })
}

#[allow(clippy::too_many_arguments)] // Every argument is a distinct compiler proof input; bundling would obscure provenance.
fn path_consumer_helper_guard_span(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    static_provenance_call_graph: &bonsai_callgraph::ResolvedCallGraph,
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
            .filter(|edge| spans_overlap(edge.span, helper_call.span))
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
        if let Some(span) = path_guarded_helper_return_span(
            ws,
            global,
            call_graph,
            static_provenance_call_graph,
            helper_func,
            &helper,
            guard,
            &mut AHashSet::new(),
        ) {
            return Some(span);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)] // Recursive proof state is intentionally explicit and independently auditable.
fn path_guarded_helper_return_span(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    static_provenance_call_graph: &bonsai_callgraph::ResolvedCallGraph,
    helper_func: FuncId,
    helper: &bonsai_lang_api::Decl,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
    visited: &mut AHashSet<FuncId>,
) -> Option<Span> {
    if !visited.insert(helper_func) {
        return None;
    }
    if let Some(span) =
        path_guarded_helper_direct_return_span(ws, global, static_provenance_call_graph, helper, guard)
    {
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
        .filter(|edge| spans_overlap(edge.span, call.span))
        .map(|edge| edge.to)
        .collect::<AHashSet<_>>();
    let mut targets = targets.into_iter();
    let target = targets.next()?;
    if targets.next().is_some() {
        return None;
    }
    let target_decl = ws.exact_decl(SymbolId::new(target.raw()))?;
    drop(file_index);
    path_guarded_helper_return_span(
        ws,
        global,
        call_graph,
        static_provenance_call_graph,
        target,
        &target_decl,
        guard,
        visited,
    )
}

fn path_guarded_helper_direct_return_span(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    static_provenance_call_graph: &bonsai_callgraph::ResolvedCallGraph,
    helper: &bonsai_lang_api::Decl,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> Option<Span> {
    let path_constructor = guard.path_constructor.as_ref()?;
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
            && assignment_uses_rule_owned_transform(
                assignment,
                &file_index.assignment_values,
                &guard.canonicalizer,
            )
    })?;
    let mut calls = Vec::new();
    collect_structured_calls(&helper.flow_events, &mut calls);
    let path_constructor_calls = calls
        .iter()
        .filter(|call| {
            span_contains(candidate_assignment.span, call.span)
                && rule_target_matches_call(call.name, &[], path_constructor)
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
            path_constructor_call,
            guard.path_constructor_base_arg_index,
        )?
    };
    let visible_assignment_values = assignment_values_visible_to_decl(&file_index, helper);
    let base_is_static =
        place_has_static_canonical_provenance_or_static_callers(StaticCanonicalProvenanceContext {
            ws,
            global,
            caller_call_graph: Some(static_provenance_call_graph),
            decl: helper,
            place: &base,
            assignments: &assignments,
            assignment_values: &visible_assignment_values,
            call_argument_values: &file_index.call_argument_values,
            call_receivers: &file_index.call_receivers,
            canonicalizer: guard.base_canonicalizer.as_ref().unwrap_or(&guard.canonicalizer),
            canonicalizer_input_from_receiver: guard.canonicalizer_input_from_receiver,
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
                &file_index,
                &file_index.branch_conditions,
                branch,
                &candidate,
                &base,
                &guard.containment_check,
                guard.base_canonicalizer.as_ref().or(Some(&guard.canonicalizer)),
                guard.containment_candidate_projection.as_ref(),
                guard.containment_base_projection.as_ref(),
                guard.containment_check_candidate_arg_index,
                guard.containment_check_base_arg_index,
                &guard.boundary_places,
                &guard.boundary_builders,
                &guard.accepted_boundary_values,
                &guard.accepted_containment_results,
                guard.containment_check_is_segment_aware,
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
    call: &StructuredCall<'_>,
    argument_index: usize,
) -> Option<String> {
    let fact = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        call.span,
        argument_index,
    );
    fact.and_then(|fact| {
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
    .or_else(|| {
        call.args
            .get(argument_index)
            .and_then(|argument| argument.place.as_deref())
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
    if !guard.required_arguments.is_empty() {
        let arguments = assignment.exact_static_call_args.as_ref()?;
        if !guard.required_arguments.iter().all(|required| {
            arguments
                .get(required.index)
                .is_some_and(|actual| required.accepted_values.contains(actual))
        }) {
            return None;
        }
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
    let sink_call = structured_call_at_match(
        &sink_calls,
        sink.span,
        &clean_overwrite_callee_tail(&sink.match_text),
    )?;
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
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
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
        file_index.character_substitutions.len() + file_index.character_constraints.len(),
        file_index.string_compositions.len(),
        verified_helpers.len()
    );
    let mut calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut calls);
    let helper_calls =
        resolved_character_substitution_calls(call_graph, sink_func, &calls, &verified_helpers);
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "character_escape sink={} helper_calls={}",
        sink.rule_id,
        helper_calls.len()
    );
    let local_proof = !helper_calls.is_empty()
        && if semantics.value_arg_indices.is_empty() {
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
    let mut transform_span = helper_calls
        .iter()
        .map(|(_, helper)| helper.transform_span)
        .min_by_key(|span| (span.file.raw(), span.start, span.end));
    let proof = if local_proof {
        true
    } else if semantics.value_arg_indices.is_empty() {
        let return_flow = return_value_flow_at_match(&sink_decl.flow_events, sink.span)?;
        transform_span = character_escape_resolved_flow_proof(
            ws,
            call_graph,
            sink_func,
            return_flow,
            sink.span,
            None,
            semantics,
            &mut AHashSet::new(),
        );
        transform_span.is_some()
    } else {
        let sink_call = structured_call_at_match(&calls, sink.span, "")?;
        let mut proofs = Vec::new();
        for index in &semantics.value_arg_indices {
            let argument = bonsai_lang_api::call_argument_value_fact(
                &file_index.call_argument_values,
                sink_call.span,
                *index,
            )?;
            proofs.push(character_escape_resolved_flow_proof(
                ws,
                call_graph,
                sink_func,
                &argument.value_flow,
                argument.argument_span,
                argument.direct_call_span,
                semantics,
                &mut AHashSet::new(),
            )?);
        }
        transform_span = proofs
            .into_iter()
            .min_by_key(|span| (span.file.raw(), span.start, span.end));
        transform_span.is_some()
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
    let transform_span = transform_span?;
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

/// Prove that a complete compiler value is the result of one exact resolved
/// helper whose every return path performs the rule-declared character
/// substitution. Callgraph ambiguity, unresolved calls, mixed raw operands,
/// and recursion all fail closed. This is deliberately provider-agnostic:
/// adapters lower call/value structure and rule data defines the required
/// escaping alphabet.
#[allow(clippy::too_many_arguments)] // Recursive proof keeps caller, exact value/span, rule semantics, and cycle state explicit.
fn character_escape_resolved_flow_proof(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    caller_func: FuncId,
    flow: &bonsai_lang_api::ExpressionFlow,
    before: Span,
    direct_call_span: Option<Span>,
    semantics: &crate::rule::CharacterEscapeSemantics,
    visited: &mut AHashSet<FuncId>,
) -> Option<Span> {
    if flow.place.is_some()
        || flow.projection.is_some()
        || !flow.source_names.is_empty()
        || !flow.aggregate_fields.is_empty()
        || !flow.tuple_items.is_empty()
        || !flow.spreads.is_empty()
    {
        return None;
    }

    let mut call_sites = direct_call_span.into_iter().collect::<Vec<_>>();
    let file_index = ws.exact_decl_index_shared(before.file)?;
    if call_sites.is_empty() {
        if let Some(composition) = file_index.string_compositions.iter().find(|composition| {
            composition.container_span == before
                || composition.value_span == before
                || spans_overlap(composition.container_span, before)
                || spans_overlap(composition.value_span, before)
        }) {
            for part in &composition.parts {
                match part {
                    bonsai_lang_api::StringCompositionPart::Literal { .. } => {}
                    bonsai_lang_api::StringCompositionPart::Call { span }
                    | bonsai_lang_api::StringCompositionPart::CallOrLiteral { span, .. } => {
                        call_sites.push(*span);
                    }
                    bonsai_lang_api::StringCompositionPart::Place { .. }
                    | bonsai_lang_api::StringCompositionPart::PlaceOrLiteral { .. } => return None,
                }
            }
        }
    }
    if call_sites.is_empty() {
        call_sites.clone_from(&flow.call_sites);
    }
    let caller = ws.exact_decl(SymbolId::new(caller_func.raw()))?;
    let mut caller_calls = Vec::new();
    collect_structured_calls(&caller.flow_events, &mut caller_calls);
    for span in &mut call_sites {
        if caller_calls.iter().any(|call| call.span == *span) {
            continue;
        }
        let mut candidates = caller_calls
            .iter()
            .filter(|call| span_contains(*span, call.span) && call.span.start == span.start);
        let candidate = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }
        *span = candidate.span;
    }
    call_sites.sort_unstable_by_key(|span| (span.file.raw(), span.start, span.end));
    call_sites.dedup();
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "character_escape_resolved_flow caller={} before={:?} calls={:?}",
        caller_func.raw(),
        before,
        call_sites
    );
    let [call_span] = call_sites.as_slice() else {
        return None;
    };

    let targets = call_graph
        .callees_of(caller_func)
        .filter(|edge| edge.span == *call_span)
        .map(|edge| edge.to)
        .collect::<AHashSet<_>>();
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "character_escape_resolved_flow caller={} call={:?} targets={:?}",
        caller_func.raw(),
        call_span,
        targets
    );
    let mut targets = targets.into_iter();
    let target = targets.next()?;
    if targets.next().is_some() || !visited.insert(target) {
        return None;
    }
    let result = character_escape_resolved_return_proof(ws, call_graph, target, semantics, visited);
    visited.remove(&target);
    result
}

fn character_escape_resolved_return_proof(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    helper_func: FuncId,
    semantics: &crate::rule::CharacterEscapeSemantics,
    visited: &mut AHashSet<FuncId>,
) -> Option<Span> {
    let helper = ws.exact_decl(SymbolId::new(helper_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(helper.span.file)?;
    let verified_helpers = verified_character_substitution_helpers(&file_index, semantics);
    let mut calls = Vec::new();
    collect_structured_calls(&helper.flow_events, &mut calls);
    let helper_calls =
        resolved_character_substitution_calls(call_graph, helper_func, &calls, &verified_helpers);
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "character_escape_resolved_return helper={} facts={} calls={} resolved_helpers={}",
        helper.name,
        file_index.character_substitutions.len() + file_index.character_constraints.len(),
        calls.len(),
        helper_calls.len()
    );

    let mut returns = Vec::new();
    collect_return_bindings(&helper.flow_events, &mut returns);
    if returns.is_empty() {
        return None;
    }
    let mut proofs = Vec::with_capacity(returns.len());
    for (return_span, _) in returns {
        let flow = return_value_flow_at_match(&helper.flow_events, return_span)?;
        let locally_safe = character_escape_flow_is_safe(
            flow,
            return_span,
            &file_index,
            &helper_calls,
            &mut AHashSet::new(),
        );
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "character_escape_resolved_return helper={} return={:?} local={}",
            helper.name,
            return_span,
            locally_safe
        );
        if locally_safe {
            proofs.push(
                helper_calls
                    .iter()
                    .map(|(_, candidate)| candidate.transform_span)
                    .min_by_key(|span| (span.file.raw(), span.start, span.end))?,
            );
        } else {
            proofs.push(character_escape_resolved_flow_proof(
                ws,
                call_graph,
                helper_func,
                flow,
                return_span,
                None,
                semantics,
                visited,
            )?);
        }
    }
    proofs
        .into_iter()
        .min_by_key(|span| (span.file.raw(), span.start, span.end))
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
            let proof = fact.proof == bonsai_lang_api::CharacterConstraintProof::ExactRuntimeSemantics
                || context.source_rule.is_some_and(|source_rule| {
                    source_rule.payload_types.iter().any(|payload_type| {
                        semantics
                            .accepted_untyped_source_payload_types
                            .contains(payload_type)
                    })
                });
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
                "character_constraint_candidate function={} span={:?} proof={} domain={} input={} output={}",
                decl.name,
                fact.transform_span,
                proof,
                domain,
                input,
                output
            );
            if !proof || !domain || !input || !output {
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
                // A sink argument can contain a call owned by an inline
                // callback nested below the security source's enclosing
                // declaration. Resolve from the compiler-proven innermost
                // owner of the exact call span; querying the outer caller
                // silently loses those semantic edges.
                let headers = ws.compiler_header_index();
                let Some(call_owner) =
                    ws.enclosing_index()
                        .enclosing_for(headers.as_ref(), call_span.file, call_span.start)
                else {
                    continue;
                };
                let targets = graph
                    .callees_of(FuncId::new(call_owner.symbol.raw()))
                    .filter(|edge| spans_overlap(edge.span, call_span))
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
            .guarded_value_constraints
            .iter()
            .filter(|fact| fact.function_span == decl.span)
        {
            if !guarded_value_constraint_satisfies_rule(fact, required, &decl, &file_index) {
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
                    .filter(|edge| spans_overlap(edge.span, helper_call_span))
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
                    .guarded_value_constraints
                    .iter()
                    .filter(|fact| fact.function_span == helper.span)
                {
                    if !guarded_value_constraint_satisfies_rule(fact, required, &helper, &helper_index) {
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

fn guarded_value_constraint_satisfies_rule(
    fact: &bonsai_lang_api::GuardedValueConstraintFact,
    required: &crate::rule::SameOriginPathConstraintSemantics,
    decl: &bonsai_lang_api::Decl,
    file_index: &bonsai_lang_api::DeclIndex,
) -> bool {
    let provider_is_accepted = match fact.provider_call.as_deref() {
        // A provider-bound fact is only security-relevant when the rulepack
        // explicitly assigns semantics to that imported runtime call.
        Some(provider) => required
            .accepted_providers
            .iter()
            .any(|target| rule_target_matches_call(provider, &[], target)),
        // Syntax-only facts are valid only for semantics that do not require
        // a particular runtime provider.
        None => required.accepted_providers.is_empty(),
    };
    provider_is_accepted
        && required
            .required_predicates
            .iter()
            .all(|predicate| guarded_predicate_requirement_is_satisfied(fact, predicate, decl, file_index))
        && required
            .required_accepted_prefixes
            .iter()
            .all(|prefix| fact.accepted_prefixes.contains(prefix))
        && required
            .required_rejected_prefixes
            .iter()
            .all(|prefix| fact.rejected_prefixes.contains(prefix))
        && required
            .required_rejected_components
            .iter()
            .all(|component| fact.rejected_components.contains(component))
        && (required.accepted_static_fallbacks.is_empty()
            || fact
                .static_fallbacks
                .iter()
                .any(|fallback| required.accepted_static_fallbacks.contains(fallback)))
}

fn guarded_predicate_requirement_is_satisfied(
    fact: &bonsai_lang_api::GuardedValueConstraintFact,
    required: &crate::rule::GuardedPredicateRequirement,
    decl: &bonsai_lang_api::Decl,
    file_index: &bonsai_lang_api::DeclIndex,
) -> bool {
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    fact.predicate_calls.iter().any(|predicate| {
        predicate.required_result == required.required_result
            && calls.iter().any(|call| {
                spans_overlap(call.span, predicate.call_expression_span)
                    && rule_target_matches_call(call.name, call.receiver_types, &required.target)
                    && bonsai_lang_api::call_argument_value_fact(
                        &file_index.call_argument_values,
                        call.span,
                        required.argument_index,
                    )
                    .and_then(|argument| argument.static_value.as_ref())
                        == Some(&required.argument_value)
            })
    })
}

pub(super) fn collect_compiler_call_sites_reaching_value(
    file_index: &bonsai_lang_api::DeclIndex,
    flow: &bonsai_lang_api::ExpressionFlow,
    before: Span,
    out: &mut Vec<Span>,
    seen_places: &mut AHashSet<String>,
) {
    out.extend(flow.call_sites.iter().copied());
    // Aggregate/tuple lowering deliberately clears the container's scalar
    // call list; each exact child owns its own dependencies. Recurse through
    // those compiler projections before following an optional addressable
    // place so sanitizers nested in a sink option/filter object are not lost.
    for child in flow
        .aggregate_fields
        .iter()
        .map(|field| &field.value)
        .chain(flow.tuple_items.iter())
        .chain(flow.spreads.iter())
    {
        collect_compiler_call_sites_reaching_value(file_index, child, before, out, seen_places);
    }
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
    out.extend(assignment.direct_call_span);
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
            provider.factory.as_ref().is_none_or(|factory| {
                !factory_call.is_empty() && rule_target_matches_call(factory_call, &[], factory)
            }) && rule_target_matches_call(operation_call, &[], &provider.operation)
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
                receiver.role.is_runtime_value()
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
struct VerifiedCharacterHelper {
    function: FuncId,
    transform_span: Span,
}

fn verified_character_substitution_helpers(
    file_index: &bonsai_lang_api::DeclIndex,
    semantics: &crate::rule::CharacterEscapeSemantics,
) -> Vec<VerifiedCharacterHelper> {
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
                function: FuncId::new(decl.symbol.raw()),
                transform_span: fact.transform_span,
            });
        }
    }
    for fact in &file_index.character_constraints {
        let Some(input_param_index) = fact.input_param_index else {
            continue;
        };
        if !matches!(fact.output, bonsai_lang_api::CharacterConstraintOutput::Return)
            || !character_escape_domain_matches(&fact.domain, semantics)
        {
            continue;
        }
        let Some(decl) = file_index
            .defs
            .iter()
            .find(|decl| decl.span == fact.function_span)
        else {
            continue;
        };
        if input_param_index >= decl.params.len()
            || decl.params.get(input_param_index) != Some(&fact.input_place)
        {
            continue;
        }
        helpers.push(VerifiedCharacterHelper {
            function: FuncId::new(decl.symbol.raw()),
            transform_span: fact.transform_span,
        });
    }
    helpers.sort_by_key(|helper| (helper.function.raw(), helper.transform_span.start));
    helpers.dedup_by_key(|helper| (helper.function, helper.transform_span));
    helpers
}

fn character_escape_domain_matches(
    domain: &bonsai_lang_api::CharacterConstraintDomain,
    semantics: &crate::rule::CharacterEscapeSemantics,
) -> bool {
    if let bonsai_lang_api::CharacterConstraintDomain::ProviderBound {
        factory_call,
        operation_call,
        domain,
    } = domain
    {
        return semantics.accepted_providers.iter().any(|provider| {
            provider.factory.as_ref().is_none_or(|factory| {
                !factory_call.is_empty() && rule_target_matches_call(factory_call, &[], factory)
            }) && rule_target_matches_call(operation_call, &[], &provider.operation)
        }) && character_domain_substitutes(domain, &semantics.required_mappings);
    }
    character_domain_substitutes(domain, &semantics.required_mappings)
}

/// Bind a character-substitution fact to a call only when the resolved graph
/// proves that the call has exactly one semantic target and that target is
/// the function that owns the compiler fact. A same-spelled method, imported
/// helper, or ambiguous dispatch must not borrow another function's summary.
fn resolved_character_substitution_calls<'a>(
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    caller: FuncId,
    calls: &[StructuredCall<'a>],
    helpers: &[VerifiedCharacterHelper],
) -> Vec<(StructuredCall<'a>, VerifiedCharacterHelper)> {
    calls
        .iter()
        .filter_map(|call| {
            let mut targets = call_graph
                .callees_of(caller)
                .filter(|edge| spans_overlap(edge.span, call.span))
                .map(|edge| edge.to)
                .collect::<AHashSet<_>>()
                .into_iter();
            let target = targets.next()?;
            if targets.next().is_some() {
                return None;
            }
            helpers
                .iter()
                .find(|helper| helper.function == target)
                .map(|helper| (*call, *helper))
        })
        .collect()
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
    helper_calls: &[(StructuredCall<'_>, VerifiedCharacterHelper)],
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
                call.span == *call_site
                    || (span_contains(*call_site, call.span) && call.span.start == call_site.start)
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
    helper_calls: &[(StructuredCall<'_>, VerifiedCharacterHelper)],
) -> bool {
    let mut saw_transform = false;
    let safe = parts.iter().all(|part| match part {
        bonsai_lang_api::StringCompositionPart::Literal { .. } => true,
        bonsai_lang_api::StringCompositionPart::Call { span }
        | bonsai_lang_api::StringCompositionPart::CallOrLiteral { span, .. } => {
            let verified = helper_calls.iter().any(|(call, _)| {
                call.span == *span || (span_contains(*span, call.span) && call.span.start == span.start)
            });
            saw_transform |= verified;
            verified
        }
        bonsai_lang_api::StringCompositionPart::Place { .. }
        | bonsai_lang_api::StringCompositionPart::PlaceOrLiteral { .. } => false,
    });
    safe && saw_transform
}

#[allow(clippy::too_many_arguments)] // Rule-owned roles and compiler graph inputs must remain explicit at this boundary.
fn path_consumer_guard_span(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    static_provenance_call_graph: &bonsai_callgraph::ResolvedCallGraph,
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
    let consumer_call = structured_call_at_match(&calls, consumer_span, &required_tail);
    let consumer_call = consumer_call?;
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_consumer_start sink={} receiver={:?} from_receiver={}",
        consumer_call.name,
        consumer_call.receiver,
        guard.sink_path_from_receiver
    );
    let candidate = if guard.sink_path_from_receiver {
        consumer_call.receiver.and_then(clean_overwrite_target_key)
    } else {
        let consumer_argument = consumer_call.args.get(path_arg_index)?;
        consumer_argument
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
                                && assignment.source_call.is_some_and(|call| {
                                    rule_target_matches_call(call, &[], &guard.canonicalizer)
                                })
                        })
                    });
                let candidate = candidates.next()?;
                candidates.next().is_none().then_some(candidate)
            })
    };
    let candidate = candidate?;
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_consumer_candidate sink={} candidate={}",
        consumer_call.name,
        candidate
    );

    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, consumer_span, &mut assignments);
    let candidate_assignment = assignments.iter().rev().find(|assignment| {
        clean_overwrite_target_key(assignment.target).as_deref() == Some(candidate.as_str())
            && assignment_uses_rule_owned_transform(
                assignment,
                &file_index.assignment_values,
                &guard.canonicalizer,
            )
    });
    let candidate_assignment = candidate_assignment?;
    let path_constructor_calls: Vec<_> = guard
        .path_constructor
        .as_ref()
        .map(|target| {
            calls
                .iter()
                .filter(|call| {
                    span_contains(candidate_assignment.span, call.span)
                        && rule_target_matches_call(call.name, &[], target)
                })
                .collect()
        })
        .unwrap_or_default();
    if !guard.path_constructor_is_string_composition && path_constructor_calls.len() != 1 {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_consumer constructor_count={} candidate={} sink={}",
            path_constructor_calls.len(),
            candidate,
            consumer_call.name
        );
        return None;
    }
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_consumer_assignment candidate={} source_call={:?} constructors={}",
        candidate,
        candidate_assignment.source_call,
        path_constructor_calls.len()
    );
    let canonicalizer_calls: Vec<_> = calls
        .iter()
        .filter(|call| {
            span_contains(candidate_assignment.span, call.span)
                && rule_target_matches_call(call.name, call.receiver_types, &guard.canonicalizer)
        })
        .collect();
    let candidate_value = bonsai_lang_api::assignment_value_fact_for_span(
        &file_index.assignment_values,
        candidate_assignment.span,
    );
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_consumer_value candidate={} direct_call={:?} receiver={:?} call_sites={:?}",
        candidate,
        candidate_value.and_then(|value| value.direct_call_name.as_deref()),
        candidate_value.and_then(|value| value.direct_call_receiver.as_deref()),
        candidate_value
            .map(|value| value.call_sites.as_slice())
            .unwrap_or_default()
    );
    let construction_composition = guard
        .path_constructor_is_string_composition
        .then(|| {
            let [canonicalizer_call] = canonicalizer_calls.as_slice() else {
                return None;
            };
            let input_span = if guard.canonicalizer_input_from_receiver {
                bonsai_lang_api::call_receiver_fact_for_span(
                    &file_index.call_receivers,
                    canonicalizer_call.span,
                )?
                .receiver_span
            } else {
                canonicalizer_call.args.first()?.span
            };
            file_index
                .string_compositions
                .iter()
                .filter(|composition| {
                    span_contains(candidate_assignment.span, composition.container_span)
                        && (composition.value_span == input_span
                            || span_contains(input_span, composition.value_span)
                            || span_contains(composition.value_span, input_span))
                })
                // A nested binary expression can share the canonicalizer
                // input's start byte. Prefer the complete exact expression;
                // only then use the largest containing compiler fact.
                .max_by_key(|composition| {
                    (
                        usize::from(composition.value_span == input_span),
                        composition.value_span.len(),
                    )
                })
        })
        .flatten();
    if guard.path_constructor_is_string_composition && construction_composition.is_none() {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_consumer missing construction composition assignment={:?} canonicalizers={:?} compositions={:?}",
            candidate_assignment.span,
            canonicalizer_calls
                .iter()
                .map(|call| (call.span, call.args.iter().map(|argument| argument.span).collect::<Vec<_>>()))
                .collect::<Vec<_>>(),
            file_index.string_compositions
        );
    }
    let canonicalizes_constructed_value = if guard.path_constructor_is_string_composition {
        construction_composition.is_some()
    } else {
        match canonicalizer_calls.as_slice() {
            [canonicalizer_call] => compiler_call_input_contains_call(
                &file_index,
                canonicalizer_call,
                path_constructor_calls[0],
                guard.canonicalizer_input_from_receiver,
            ),
            [] if guard.canonicalizer_input_from_receiver => candidate_value.is_some_and(|value| {
                assignment_uses_rule_owned_transform(
                    candidate_assignment,
                    &file_index.assignment_values,
                    &guard.canonicalizer,
                ) && value.call_sites.iter().any(|span| {
                    *span == path_constructor_calls[0].span
                        || span_contains(*span, path_constructor_calls[0].span)
                        || span_contains(path_constructor_calls[0].span, *span)
                        || spans_overlap(*span, path_constructor_calls[0].span)
                })
            }),
            _ => false,
        }
    };
    if !canonicalizes_constructed_value {
        return None;
    }
    let direct_constructor_base = if guard.path_constructor_is_string_composition {
        None
    } else if guard.path_constructor_base_from_receiver {
        compiler_call_receiver_place(&file_index, path_constructor_calls[0])
    } else {
        compiler_call_argument_place(
            &file_index,
            path_constructor_calls[0],
            guard.path_constructor_base_arg_index,
        )
    };
    let base = direct_constructor_base.clone().or_else(|| {
        containment_base_place_before_consumer(
            &calls,
            &file_index,
            candidate_assignment.span,
            consumer_span,
            &candidate,
            guard,
        )
    })?;

    let visible_assignment_values = assignment_values_visible_to_decl(&file_index, decl);
    let base_is_static =
        place_has_static_canonical_provenance_or_static_callers(StaticCanonicalProvenanceContext {
            ws,
            global,
            caller_call_graph: Some(static_provenance_call_graph),
            decl,
            place: &base,
            assignments: &assignments,
            assignment_values: &visible_assignment_values,
            call_argument_values: &file_index.call_argument_values,
            call_receivers: &file_index.call_receivers,
            canonicalizer: guard.base_canonicalizer.as_ref().unwrap_or(&guard.canonicalizer),
            canonicalizer_input_from_receiver: guard.canonicalizer_input_from_receiver,
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
    if let Some(composition) = construction_composition {
        if !string_path_composition_uses_canonical_base(
            composition,
            &base,
            CanonicalProvenanceFacts {
                assignments: &assignments,
                assignment_values: &visible_assignment_values,
                call_argument_values: &file_index.call_argument_values,
                call_receivers: &file_index.call_receivers,
                calls: &calls,
            },
            guard,
        ) {
            return None;
        }
    } else if direct_constructor_base.is_none()
        && !constructor_receiver_has_same_static_root(
            &file_index,
            path_constructor_calls[0],
            &base,
            &assignments,
            &visible_assignment_values,
            &calls,
            guard,
        )
    {
        return None;
    }

    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, consumer_span, &mut branches);
    let branch = branches
        .into_iter()
        .rev()
        .find(|branch| {
            branch_arm_abruptly_exits(branch.then_events)
                && path_containment_guard_condition(
                    &decl.flow_events,
                    &file_index,
                    &file_index.branch_conditions,
                    *branch,
                    &candidate,
                    &base,
                    &guard.containment_check,
                    guard.base_canonicalizer.as_ref().or(Some(&guard.canonicalizer)),
                    guard.containment_candidate_projection.as_ref(),
                    guard.containment_base_projection.as_ref(),
                    guard.containment_check_candidate_arg_index,
                    guard.containment_check_base_arg_index,
                    &guard.boundary_places,
                    &guard.boundary_builders,
                    &guard.accepted_boundary_values,
                    &guard.accepted_containment_results,
                    guard.containment_check_is_segment_aware,
                )
        })
        .map(|branch| branch.span)
        .or_else(|| {
            let mut containing = Vec::new();
            collect_containing_branches_on_path(&decl.flow_events, consumer_span, &mut containing);
            containing.into_iter().rev().find_map(|branch| {
                path_containment_acceptance_condition(
                    &decl.flow_events,
                    &file_index,
                    &file_index.branch_conditions,
                    branch.span,
                    branch.accepting_condition_truth,
                    &candidate,
                    &base,
                    guard,
                )
                .then_some(branch.span)
            })
        })
        .or_else(|| {
            path_containment_acceptance_guard_span(
                &decl.flow_events,
                &file_index,
                &calls,
                consumer_span,
                &candidate,
                &base,
                guard,
            )
        });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_consumer sink={} guarded={:?}",
        consumer_call.name,
        branch
    );
    branch
}

fn containment_base_place_before_consumer(
    calls: &[StructuredCall<'_>],
    file_index: &bonsai_lang_api::DeclIndex,
    after: Span,
    before: Span,
    candidate: &str,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> Option<String> {
    let mut bases = calls.iter().filter_map(|call| {
        if call.span.start < after.end
            || call.span.end > before.start
            || !rule_target_matches_call(call.name, call.receiver_types, &guard.containment_check)
        {
            return None;
        }
        let candidate_matches = guard.containment_check_candidate_arg_index.map_or_else(
            || {
                call.receiver.is_some_and(|receiver| {
                    containment_projection_matches(
                        receiver,
                        candidate,
                        guard.containment_candidate_projection.as_ref(),
                    )
                })
            },
            |index| {
                call.args.get(index).is_some_and(|argument| {
                    argument.place.as_deref().is_some_and(|place| {
                        containment_projection_matches(
                            place,
                            candidate,
                            guard.containment_candidate_projection.as_ref(),
                        )
                    })
                })
            },
        );
        let argument = candidate_matches
            .then(|| call.args.get(guard.containment_check_base_arg_index))
            .flatten()?;
        argument
            .place
            .as_deref()
            .and_then(clean_overwrite_target_key)
            .or_else(|| {
                file_index
                    .string_compositions
                    .iter()
                    .find(|composition| composition.value_span == argument.span)
                    .and_then(|composition| match composition.parts.as_slice() {
                        [
                            bonsai_lang_api::StringCompositionPart::Place { place },
                            bonsai_lang_api::StringCompositionPart::Literal { value },
                        ] if guard.accepted_boundary_values.iter().any(|accepted| {
                            matches!(accepted, bonsai_lang_api::StaticScalarValue::String(candidate) if candidate == value)
                        }) => clean_overwrite_target_key(place),
                        _ => None,
                    })
            })
    });
    let base = bases.next()?;
    bases.next().is_none().then_some(base)
}

fn constructor_receiver_has_same_static_root(
    file_index: &bonsai_lang_api::DeclIndex,
    constructor: &StructuredCall<'_>,
    canonical_base: &str,
    assignments: &[StructuredAssignment<'_>],
    assignment_values: &[&bonsai_lang_api::AssignmentValueFact],
    calls: &[StructuredCall<'_>],
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> bool {
    let Some(receiver) =
        bonsai_lang_api::call_receiver_fact_for_span(&file_index.call_receivers, constructor.span)
    else {
        return false;
    };
    let factory = calls
        .iter()
        .filter(|call| {
            call.span.file == receiver.receiver_span.file
                && call.span.start >= receiver.receiver_span.start
                && call.span.end <= receiver.receiver_span.end
                && guard
                    .static_base_factories
                    .iter()
                    .any(|factory| rule_target_matches_call(call.name, call.receiver_types, factory))
        })
        .max_by_key(|call| call.span.len());
    let Some(factory) = factory else { return false };
    let Some(factory_root) = compiler_call_argument_place(file_index, factory, 0) else {
        return false;
    };
    canonical_provenance_root_place(
        canonical_base,
        CanonicalProvenanceFacts {
            assignments,
            assignment_values,
            call_argument_values: &file_index.call_argument_values,
            call_receivers: &file_index.call_receivers,
            calls,
        },
        guard.base_canonicalizer.as_ref().unwrap_or(&guard.canonicalizer),
        guard.canonicalizer_input_from_receiver,
        &guard.static_base_factories,
    )
    .as_deref()
        == Some(factory_root.as_str())
}

fn string_path_composition_uses_canonical_base(
    composition: &bonsai_lang_api::StringCompositionFact,
    canonical_base: &str,
    facts: CanonicalProvenanceFacts<'_, '_>,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> bool {
    let Some(root) = canonical_provenance_root_place(
        canonical_base,
        facts,
        guard.base_canonicalizer.as_ref().unwrap_or(&guard.canonicalizer),
        guard.canonicalizer_input_from_receiver,
        &guard.static_base_factories,
    ) else {
        return false;
    };
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_composition canonical_base={} root={} parts={:?}",
        canonical_base,
        root,
        composition.parts
    );
    let [bonsai_lang_api::StringCompositionPart::Place { place }, boundary, tail @ ..] =
        composition.parts.as_slice()
    else {
        return false;
    };
    if clean_overwrite_target_key(place).as_deref() != clean_overwrite_target_key(&root).as_deref() {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_composition root mismatch place={} root={}",
            place,
            root
        );
        return false;
    }
    let bonsai_lang_api::StringCompositionPart::Literal { value } = boundary else {
        return false;
    };
    let boundary_is_exact = guard.accepted_boundary_values.iter().any(|accepted| {
        matches!(accepted, bonsai_lang_api::StaticScalarValue::String(candidate) if candidate == value)
    });
    boundary_is_exact
        && tail.iter().any(|part| {
            matches!(
                part,
                bonsai_lang_api::StringCompositionPart::Place { .. }
                    | bonsai_lang_api::StringCompositionPart::Call { .. }
            )
        })
}

/// Prove that one parsed nested call is the complete value input of another
/// parsed call. Adapters own receiver/argument syntax and emit the spans;
/// shared analysis only joins those exact compiler facts.
fn compiler_call_input_contains_call(
    file_index: &bonsai_lang_api::DeclIndex,
    outer: &StructuredCall<'_>,
    inner: &StructuredCall<'_>,
    input_from_receiver: bool,
) -> bool {
    // Some runtimes expose one operation that both combines path components
    // and canonicalizes the result (for example, a rule may assign the same
    // exact call target both roles). The two rule-owned matches then refer to
    // one compiler call span; no synthetic nested call should be required.
    if outer.span == inner.span {
        return true;
    }
    let contains_inner = |span: Span| {
        span.file == inner.span.file
            && (spans_overlap(span, inner.span)
                || span_contains(span, inner.span)
                || span_contains(inner.span, span))
    };
    if input_from_receiver {
        return bonsai_lang_api::call_receiver_fact_for_span(&file_index.call_receivers, outer.span)
            .filter(|fact| fact.role.is_runtime_value())
            .is_some_and(|fact| fact.value_flow.call_sites.iter().copied().any(contains_inner));
    }
    bonsai_lang_api::call_argument_value_fact(&file_index.call_argument_values, outer.span, 0)
        .and_then(|fact| fact.direct_call_span)
        .is_some_and(contains_inner)
        || outer
            .args
            .first()
            .is_some_and(|argument| span_contains(argument.span, inner.span))
}

/// Select assignment-value facts visible from one callable scope.
///
/// File indexes contain bodies for every sibling callable. A bare local or
/// parameter name must never resolve against an assignment in a different
/// function merely because the spelling and file match. The innermost
/// compiler declaration containing the assignment owns it; facts outside
/// every callable remain module/class-level and are visible normally.
fn assignment_values_visible_to_decl<'a>(
    file_index: &'a bonsai_lang_api::DeclIndex,
    decl: &bonsai_lang_api::Decl,
) -> Vec<&'a bonsai_lang_api::AssignmentValueFact> {
    file_index
        .assignment_values
        .iter()
        .filter(|fact| {
            if let Some(owner) = fact.target_owner {
                let mut current = decl.parent;
                while let Some(symbol) = current {
                    if symbol == owner {
                        return true;
                    }
                    current = file_index
                        .defs
                        .iter()
                        .find(|candidate| candidate.symbol == symbol)
                        .and_then(|candidate| candidate.parent);
                }
                return decl.symbol == owner;
            }
            file_index
                .defs
                .iter()
                .filter(|candidate| {
                    matches!(
                        candidate.kind,
                        bonsai_lang_api::DeclKind::Function
                            | bonsai_lang_api::DeclKind::Method
                            | bonsai_lang_api::DeclKind::Constructor
                    ) && candidate.name != bonsai_lang_api::kit::MODULE_DECL_NAME
                        && span_contains(candidate.span, fact.assignment_span)
                })
                .min_by_key(|candidate| candidate.span.len())
                .is_none_or(|owner| owner.symbol == decl.symbol)
        })
        .collect()
}

struct StaticCanonicalProvenanceContext<'a> {
    ws: &'a Workspace,
    global: &'a bonsai_index::GlobalIndex,
    caller_call_graph: Option<&'a bonsai_callgraph::ResolvedCallGraph>,
    decl: &'a bonsai_lang_api::Decl,
    place: &'a str,
    assignments: &'a [StructuredAssignment<'a>],
    assignment_values: &'a [&'a bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &'a [bonsai_lang_api::CallArgumentValueFact],
    call_receivers: &'a [bonsai_lang_api::CallReceiverFact],
    canonicalizer: &'a RuleTarget,
    canonicalizer_input_from_receiver: bool,
    static_base_factories: &'a [RuleTarget],
    before: Span,
}

fn place_has_static_canonical_provenance_or_static_callers(
    context: StaticCanonicalProvenanceContext<'_>,
) -> bool {
    let StaticCanonicalProvenanceContext {
        ws,
        global,
        caller_call_graph,
        decl,
        place,
        assignments,
        assignment_values,
        call_argument_values,
        call_receivers,
        canonicalizer,
        canonicalizer_input_from_receiver,
        static_base_factories,
        before,
    } = context;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    if place_has_static_canonical_provenance(
        place,
        assignments,
        assignment_values,
        call_argument_values,
        call_receivers,
        &calls,
        canonicalizer,
        canonicalizer_input_from_receiver,
        static_base_factories,
        before,
        &decl.params,
    ) {
        return true;
    }
    let Some(root) = canonical_provenance_root_place(
        place,
        CanonicalProvenanceFacts {
            assignments,
            assignment_values,
            call_argument_values,
            call_receivers,
            calls: &calls,
        },
        canonicalizer,
        canonicalizer_input_from_receiver,
        static_base_factories,
    ) else {
        return false;
    };
    let Some(parameter_index) = decl.params.iter().position(|parameter| parameter == &root) else {
        return false;
    };
    let caller_argument_is_static = |caller_symbol: SymbolId, call_span: Span| {
        let Some(caller) = ws.exact_decl(caller_symbol) else {
            return false;
        };
        let Some(index) = ws.exact_decl_index_shared(caller.span.file) else {
            return false;
        };
        let visible_assignment_values = assignment_values_visible_to_decl(&index, &caller);
        bonsai_lang_api::call_argument_value_fact(&index.call_argument_values, call_span, parameter_index)
            .is_some_and(|argument| {
                argument.static_value.is_some()
                    || expression_flow_is_literal(&argument.value_flow)
                    || expression_flow_has_static_binding_provenance(
                        &visible_assignment_values,
                        &argument.value_flow,
                        call_span,
                        &mut AHashSet::new(),
                    )
            })
    };
    if let Some(caller_call_graph) = caller_call_graph {
        return function_parameter_has_only_static_callers(
            ws,
            caller_call_graph,
            FuncId::new(decl.symbol.raw()),
            parameter_index,
            &mut AHashSet::new(),
        );
    }
    let callers = global
        .refs_to(decl.symbol)
        .into_iter()
        .filter(|(_, reference)| reference.kind == bonsai_lang_api::RefKind::Call)
        .collect::<Vec<_>>();
    !callers.is_empty()
        && callers.iter().all(|(file, reference)| {
            ws.enclosing_index()
                .enclosing_for(global, *file, reference.span.start)
                .is_some_and(|caller| caller_argument_is_static(caller.symbol, reference.span))
        })
}

/// Prove that every exact compiler-resolved invocation supplies a static
/// value for one formal, following parameters through first-party callback
/// and helper boundaries when necessary.
///
/// This is deliberately an all-callers proof. A missing, ambiguous, dynamic,
/// or cyclic edge fails closed; API identity and security meaning remain in
/// rule data. The recursion only follows adapter-lowered parameter positions
/// and exact call-argument value facts.
fn function_parameter_has_only_static_callers(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    function: FuncId,
    parameter_index: usize,
    visited: &mut AHashSet<(FuncId, usize)>,
) -> bool {
    if !visited.insert((function, parameter_index)) {
        return false;
    }
    let callers = call_graph.callers_of(function).collect::<Vec<_>>();
    if callers.is_empty() {
        visited.remove(&(function, parameter_index));
        return false;
    }
    let all_static = callers.iter().all(|edge| {
        let Some(caller) = ws.exact_decl(SymbolId::new(edge.from.raw())) else {
            return false;
        };
        let Some(index) = ws.exact_decl_index_shared(caller.span.file) else {
            return false;
        };
        let Some(argument) = bonsai_lang_api::call_argument_value_fact(
            &index.call_argument_values,
            edge.span,
            parameter_index,
        ) else {
            return false;
        };
        let visible_assignment_values = assignment_values_visible_to_decl(&index, &caller);
        if argument.static_value.is_some()
            || expression_flow_is_literal(&argument.value_flow)
            || expression_flow_has_static_binding_provenance(
                &visible_assignment_values,
                &argument.value_flow,
                edge.span,
                &mut AHashSet::new(),
            )
        {
            return true;
        }
        let argument_place = argument
            .value_flow
            .projection
            .as_ref()
            .map(bonsai_lang_api::ExpressionProjection::canonical_place)
            .or_else(|| {
                argument
                    .value_flow
                    .place
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
            });
        let Some(caller_parameter_index) = argument_place
            .as_deref()
            .and_then(|place| caller.params.iter().position(|parameter| parameter == place))
        else {
            return false;
        };
        function_parameter_has_only_static_callers(
            ws,
            call_graph,
            FuncId::new(caller.symbol.raw()),
            caller_parameter_index,
            visited,
        )
    });
    visited.remove(&(function, parameter_index));
    all_static
}

fn expression_flow_has_static_binding_provenance(
    assignment_values: &[&bonsai_lang_api::AssignmentValueFact],
    flow: &bonsai_lang_api::ExpressionFlow,
    before: Span,
    seen: &mut AHashSet<String>,
) -> bool {
    if expression_flow_is_literal(flow) {
        return true;
    }
    let Some(place) = flow
        .projection
        .as_ref()
        .map(bonsai_lang_api::ExpressionProjection::canonical_place)
        .or_else(|| flow.place.clone())
        .or_else(|| {
            // Some grammars represent a yielded/returned class constant as
            // one exact source dependency rather than an addressable place.
            // It is static only when an adapter assignment fact for that
            // same identity proves a static RHS; a bare source spelling is
            // never sufficient on its own.
            let mut sources = flow
                .source_names
                .iter()
                .map(String::as_str)
                .filter(|source| !source.trim().is_empty())
                .collect::<Vec<_>>();
            sources.sort_unstable();
            sources.dedup();
            let [source] = sources.as_slice() else {
                return None;
            };
            assignment_values
                .iter()
                .any(|fact| fact.target.as_deref() == Some(*source))
                .then(|| (*source).to_string())
        })
    else {
        return false;
    };
    if !seen.insert(place.clone()) {
        return false;
    }
    assignment_values.iter().rev().any(|fact| {
        fact.assignment_span.file == before.file
            && fact.assignment_span.end <= before.start
            && fact.target.as_deref() == Some(place.as_str())
            && (fact.static_value.is_some()
                || expression_flow_is_literal(&fact.value_flow)
                || expression_flow_has_static_binding_provenance(
                    assignment_values,
                    &fact.value_flow,
                    fact.assignment_span,
                    seen,
                ))
    })
}

fn rule_owned_factory_call_has_static_input(
    call_name: &str,
    assignment: &bonsai_lang_api::AssignmentValueFact,
    assignment_values: &[&bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    calls: &[StructuredCall<'_>],
    factories: &[RuleTarget],
) -> bool {
    if !factories
        .iter()
        .any(|factory| rule_target_matches_call(call_name, &[], factory))
    {
        return false;
    }
    if assignment
        .exact_static_call_args
        .as_ref()
        .is_some_and(|args| !args.is_empty())
    {
        return true;
    }
    let matching_calls = calls
        .iter()
        .filter(|call| {
            span_contains(assignment.assignment_span, call.span)
                && factories
                    .iter()
                    .any(|factory| rule_target_matches_call(call.name, call.receiver_types, factory))
        })
        .collect::<Vec<_>>();
    let [call] = matching_calls.as_slice() else {
        return false;
    };
    if let Some(receiver) = bonsai_lang_api::call_receiver_fact_for_span(call_receivers, call.span) {
        if receiver.role.is_runtime_value()
            && (receiver.static_value.is_some()
                || expression_flow_is_literal(&receiver.value_flow)
                || expression_flow_has_static_binding_provenance(
                    assignment_values,
                    &receiver.value_flow,
                    assignment.assignment_span,
                    &mut AHashSet::new(),
                ))
        {
            return true;
        }
    }
    let arguments = call_argument_values
        .iter()
        .filter(|argument| argument.call_span == call.span)
        .collect::<Vec<_>>();
    !arguments.is_empty()
        && arguments.iter().all(|argument| {
            argument.static_value.is_some()
                || expression_flow_is_literal(&argument.value_flow)
                || expression_flow_has_static_binding_provenance(
                    assignment_values,
                    &argument.value_flow,
                    assignment.assignment_span,
                    &mut AHashSet::new(),
                )
        })
}

#[derive(Clone, Copy)]
struct CanonicalProvenanceFacts<'borrow, 'facts> {
    assignments: &'borrow [StructuredAssignment<'facts>],
    assignment_values: &'borrow [&'facts bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &'borrow [bonsai_lang_api::CallArgumentValueFact],
    call_receivers: &'borrow [bonsai_lang_api::CallReceiverFact],
    calls: &'borrow [StructuredCall<'facts>],
}

fn canonical_provenance_root_place(
    place: &str,
    facts: CanonicalProvenanceFacts<'_, '_>,
    canonicalizer: &RuleTarget,
    canonicalizer_input_from_receiver: bool,
    static_base_factories: &[RuleTarget],
) -> Option<String> {
    let CanonicalProvenanceFacts {
        assignments,
        assignment_values,
        call_argument_values,
        call_receivers,
        calls,
    } = facts;
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
        let call = assignment.source_call;
        if call.is_some_and(|call| {
            rule_owned_factory_call_has_static_input(
                call,
                value,
                assignment_values,
                call_argument_values,
                call_receivers,
                calls,
                static_base_factories,
            )
        }) {
            return None;
        }
        let projection_receiver = rule_owned_transform_projection_receiver(value, canonicalizer);
        let call_matches = call.is_some_and(|call| rule_target_matches_call(call, &[], canonicalizer));
        if !call_matches && projection_receiver.is_none() {
            return None;
        }
        current = if canonicalizer_input_from_receiver {
            projection_receiver.or_else(|| {
                value
                    .direct_call_receiver
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .or_else(|| {
                        canonical_assignment_receiver_root(
                            assignment.span,
                            call?,
                            calls,
                            call_receivers,
                            canonicalizer,
                        )
                    })
            })
        } else {
            assignment_direct_call_argument_place(value, call_argument_values, 0).or_else(|| {
                assignment
                    .source_call_args
                    .first()
                    .and_then(|argument| clean_overwrite_target_key(argument))
            })
        }?;
    }
    None
}

pub(super) fn relative_path_containment_guard_sanitizer(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    caller_call_graph: &bonsai_callgraph::ResolvedCallGraph,
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

    let mut file_assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, relative_call.span, &mut file_assignments);
    file_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let visible_assignment_values = assignment_values_visible_to_decl(&file_index, &decl);
    let base_is_static =
        place_has_static_canonical_provenance_or_static_callers(StaticCanonicalProvenanceContext {
            ws,
            global,
            caller_call_graph: Some(caller_call_graph),
            decl: &decl,
            place: &base,
            assignments: &file_assignments,
            assignment_values: &visible_assignment_values,
            call_argument_values: &file_index.call_argument_values,
            call_receivers: &file_index.call_receivers,
            canonicalizer: &guard.base_canonicalizer,
            canonicalizer_input_from_receiver: false,
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
                    guard.capability == bonsai_lang_api::COMPILER_GUARD_PREFIX_BOUNDARY_EQUALITY
                        && spans_overlap(guard.guarded_call_span, *span)
                        && prefix_boundary_evidence_matches_rule(&guard.evidence, query.guard)
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

fn prefix_boundary_evidence_matches_rule(
    evidence: &[String],
    guard: &RelativePathContainmentGuardSemantics,
) -> bool {
    let value = |prefix: &str| evidence.iter().find_map(|item| item.strip_prefix(prefix));
    let Some(literal) = value("literal:") else {
        return false;
    };
    let Some(boundary_place) = value("boundary-place:") else {
        return false;
    };
    let Some(boundary_wrapper) = value("boundary-wrapper:") else {
        return false;
    };
    let Some(slice_end) = value("slice-end:").and_then(|value| value.parse::<usize>().ok()) else {
        return false;
    };
    let Some(length_minimum) = value("length-minimum:").and_then(|value| value.parse::<usize>().ok()) else {
        return false;
    };
    guard
        .rejected_exact_values
        .iter()
        .any(|accepted| accepted == literal)
        && guard
            .rejection_boundary_places
            .iter()
            .any(|accepted| accepted == boundary_place)
        && guard
            .rejection_boundary_wrappers
            .iter()
            .any(|target| rule_target_matches_call(boundary_wrapper, &[], target))
        && slice_end == literal.len().saturating_add(1)
        && length_minimum >= slice_end
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

#[allow(clippy::too_many_arguments)] // Static provenance is an exact conjunction of these independent compiler facts.
fn place_has_static_canonical_provenance(
    place: &str,
    assignments: &[StructuredAssignment<'_>],
    assignment_values: &[&bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    calls: &[StructuredCall<'_>],
    canonicalizer: &RuleTarget,
    canonicalizer_input_from_receiver: bool,
    static_base_factories: &[RuleTarget],
    before: Span,
    shadowed_unassigned_places: &[String],
) -> bool {
    let mut current = place.to_string();
    let mut visited = AHashSet::new();
    while visited.insert(current.clone()) {
        let Some(assignment) = assignments.iter().rev().find(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(current.as_str())
        }) else {
            if shadowed_unassigned_places.contains(&current) {
                return false;
            }
            let static_binding = assignment_values.iter().rev().any(|fact| {
                fact.assignment_span.file == before.file
                    && fact.assignment_span.start < before.start
                    && fact.target.as_deref() == Some(current.as_str())
                    && (fact.static_value.is_some()
                        || (fact.direct_call_name.as_deref().is_some_and(|call| {
                            static_base_factories
                                .iter()
                                .any(|factory| rule_target_matches_call(call, &[], factory))
                        }) && fact
                            .exact_static_call_args
                            .as_ref()
                            .is_some_and(|args| !args.is_empty())))
            });
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "static_canonical_terminal place={} proven={} candidates={:?}",
                current,
                static_binding,
                assignment_values
                    .iter()
                    .filter(|fact| fact.target.as_deref() == Some(current.as_str()))
                    .map(|fact| (
                        fact.target.as_deref(),
                        fact.static_value.as_ref(),
                        fact.direct_call_name.as_deref(),
                        fact.exact_static_call_args.as_ref(),
                    ))
                    .collect::<Vec<_>>()
            );
            return static_binding;
        };
        let Some(value) = assignment_values
            .iter()
            .find(|fact| fact.assignment_span == assignment.span)
        else {
            return false;
        };
        if value.static_value.is_some() {
            return true;
        }
        let call = assignment.source_call;
        if call.is_some_and(|call| {
            rule_owned_factory_call_has_static_input(
                call,
                value,
                assignment_values,
                call_argument_values,
                call_receivers,
                calls,
                static_base_factories,
            )
        }) {
            return true;
        }
        let projection_receiver = rule_owned_transform_projection_receiver(value, canonicalizer);
        let call_matches = call.is_some_and(|call| rule_target_matches_call(call, &[], canonicalizer));
        if !call_matches && projection_receiver.is_none() {
            return false;
        }
        if canonicalizer_input_from_receiver
            && call.is_some_and(|call| {
                canonical_assignment_receiver_has_static_factory(
                    assignment.span,
                    call,
                    calls,
                    call_receivers,
                    call_argument_values,
                    assignment_values,
                    canonicalizer,
                    static_base_factories,
                )
            })
        {
            return true;
        }
        if canonicalizer_input_from_receiver
            && rule_owned_nullary_selection_has_static_factory(
                value,
                assignment_values,
                call_argument_values,
                call_receivers,
                calls,
                canonicalizer,
                static_base_factories,
            )
        {
            return true;
        }
        let next = if canonicalizer_input_from_receiver {
            projection_receiver.or_else(|| {
                value
                    .direct_call_receiver
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .or_else(|| {
                        canonical_assignment_receiver_root(
                            assignment.span,
                            call?,
                            calls,
                            call_receivers,
                            canonicalizer,
                        )
                    })
                    .or_else(|| {
                        let mut sources = assignment
                            .source_names
                            .iter()
                            .filter_map(|source| clean_overwrite_target_key(source));
                        let source = sources.next()?;
                        sources.next().is_none().then_some(source)
                    })
            })
        } else {
            assignment_direct_call_argument_place(value, call_argument_values, 0)
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
                        .find(|source| {
                            call.is_none_or(|call| callee_spelling_tail(source) != callee_spelling_tail(call))
                        })
                })
        };
        let Some(next) = next else { return false };
        current = next;
    }
    false
}

/// Prove a rule-owned nullary member selection is rooted in one static
/// factory call using only adapter-emitted assignment/call facts.
///
/// Scala's `value.normalize` syntax is a `field_expression`, not a
/// `call_expression`, even when type checking resolves it to a Java nullary
/// method.  The Scala adapter records the outer member identity on the
/// assignment and retains every explicit nested call span.  The rule owns
/// which outer member is a canonicalizer and which nested call is a static
/// base factory; this shared proof never interprets either API spelling.
fn rule_owned_nullary_selection_has_static_factory(
    assignment: &bonsai_lang_api::AssignmentValueFact,
    assignment_values: &[&bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    calls: &[StructuredCall<'_>],
    canonicalizer: &RuleTarget,
    static_base_factories: &[RuleTarget],
) -> bool {
    let Some(direct_call) = assignment.direct_call_name.as_deref() else {
        return false;
    };
    if !rule_target_matches_call(direct_call, &[], canonicalizer) {
        return false;
    }
    let nested = calls
        .iter()
        .filter(|call| {
            span_contains(assignment.value_span, call.span)
                && assignment.call_sites.iter().any(|site| {
                    *site == call.span || span_contains(*site, call.span) || span_contains(call.span, *site)
                })
        })
        .collect::<Vec<_>>();
    if nested.is_empty()
        || nested.iter().any(|call| {
            !rule_target_matches_call(call.name, call.receiver_types, canonicalizer)
                && !static_base_factories
                    .iter()
                    .any(|factory| rule_target_matches_call(call.name, call.receiver_types, factory))
        })
    {
        return false;
    }
    let factories = nested
        .iter()
        .filter(|call| {
            static_base_factories
                .iter()
                .any(|factory| rule_target_matches_call(call.name, call.receiver_types, factory))
        })
        .collect::<Vec<_>>();
    let [factory] = factories.as_slice() else {
        return false;
    };
    rule_owned_factory_call_has_static_input(
        factory.name,
        assignment,
        assignment_values,
        call_argument_values,
        call_receivers,
        calls,
        static_base_factories,
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_assignment_receiver_has_static_factory(
    assignment_span: Span,
    direct_call_name: &str,
    calls: &[StructuredCall<'_>],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    assignment_values: &[&bonsai_lang_api::AssignmentValueFact],
    canonicalizer: &RuleTarget,
    static_base_factories: &[RuleTarget],
) -> bool {
    let direct_tail = callee_spelling_tail(direct_call_name);
    let Some(outer) = calls
        .iter()
        .filter(|call| {
            span_contains(assignment_span, call.span)
                && callee_spelling_tail(call.name) == direct_tail
                && rule_target_matches_call(call.name, call.receiver_types, canonicalizer)
        })
        .max_by_key(|call| (call.span.start, call.span.end))
    else {
        return false;
    };
    canonical_receiver_chain_has_static_factory(
        outer,
        calls,
        call_receivers,
        call_argument_values,
        assignment_values,
        canonicalizer,
        static_base_factories,
        &mut AHashSet::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_receiver_chain_has_static_factory(
    call: &StructuredCall<'_>,
    calls: &[StructuredCall<'_>],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    assignment_values: &[&bonsai_lang_api::AssignmentValueFact],
    canonicalizer: &RuleTarget,
    static_base_factories: &[RuleTarget],
    seen: &mut AHashSet<Span>,
) -> bool {
    if !seen.insert(call.span) {
        return false;
    }
    let Some(receiver) = bonsai_lang_api::call_receiver_fact_for_span(call_receivers, call.span) else {
        return false;
    };
    let Some(nested) = calls
        .iter()
        .filter(|candidate| {
            candidate.span != call.span
                && candidate.span.file == receiver.receiver_span.file
                && candidate.span.start >= receiver.receiver_span.start
                && candidate.span.end <= receiver.receiver_span.end
                && (rule_target_matches_call(candidate.name, candidate.receiver_types, canonicalizer)
                    || static_base_factories.iter().any(|factory| {
                        rule_target_matches_call(candidate.name, candidate.receiver_types, factory)
                    }))
        })
        .max_by_key(|candidate| candidate.span.len())
    else {
        return false;
    };
    if static_base_factories
        .iter()
        .any(|factory| rule_target_matches_call(nested.name, nested.receiver_types, factory))
    {
        let arguments = call_argument_values
            .iter()
            .filter(|argument| argument.call_span == nested.span)
            .collect::<Vec<_>>();
        return !arguments.is_empty()
            && arguments.iter().all(|argument| {
                argument.static_value.is_some()
                    || expression_flow_is_literal(&argument.value_flow)
                    || expression_flow_has_static_binding_provenance(
                        assignment_values,
                        &argument.value_flow,
                        nested.span,
                        &mut AHashSet::new(),
                    )
            });
    }
    rule_target_matches_call(nested.name, nested.receiver_types, canonicalizer)
        && canonical_receiver_chain_has_static_factory(
            nested,
            calls,
            call_receivers,
            call_argument_values,
            assignment_values,
            canonicalizer,
            static_base_factories,
            seen,
        )
}

/// Follow an adapter-lowered nested receiver chain without parsing rendered
/// source text. Every call in the chain must match the rule-owned canonical
/// transform target; the terminal input must be one exact compiler place.
/// This covers shapes such as
/// `BASE.toAbsolutePath().normalize()` while rejecting
/// `dynamicBase(BASE).normalize()` unless the rule explicitly declares the
/// intermediate transform.
fn canonical_assignment_receiver_root(
    assignment_span: Span,
    direct_call_name: &str,
    calls: &[StructuredCall<'_>],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    canonicalizer: &RuleTarget,
) -> Option<String> {
    let direct_tail = callee_spelling_tail(direct_call_name);
    let outer = calls
        .iter()
        .filter(|call| {
            span_contains(assignment_span, call.span)
                && callee_spelling_tail(call.name) == direct_tail
                && rule_target_matches_call(call.name, call.receiver_types, canonicalizer)
        })
        .max_by_key(|call| (call.span.start, call.span.end))?;
    canonical_call_receiver_root(outer, calls, call_receivers, canonicalizer, &mut AHashSet::new())
}

fn canonical_call_receiver_root(
    call: &StructuredCall<'_>,
    calls: &[StructuredCall<'_>],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    canonicalizer: &RuleTarget,
    seen: &mut AHashSet<Span>,
) -> Option<String> {
    if !seen.insert(call.span) {
        return None;
    }
    let receiver = bonsai_lang_api::call_receiver_fact_for_span(call_receivers, call.span)?;
    if !receiver.role.is_runtime_value() {
        return None;
    }
    if receiver.value_flow.call_sites.is_empty() {
        return receiver
            .value_flow
            .projection
            .as_ref()
            .map(bonsai_lang_api::ExpressionProjection::canonical_place)
            .or_else(|| receiver.value_flow.place.clone())
            .and_then(|place| clean_overwrite_target_key(&place));
    }
    let [nested_span] = receiver.value_flow.call_sites.as_slice() else {
        return None;
    };
    let nested = calls.iter().find(|candidate| {
        (candidate.span == *nested_span
            || span_contains(*nested_span, candidate.span)
            || span_contains(candidate.span, *nested_span)
            || spans_overlap(candidate.span, *nested_span))
            && rule_target_matches_call(candidate.name, candidate.receiver_types, canonicalizer)
    })?;
    canonical_call_receiver_root(nested, calls, call_receivers, canonicalizer, seen)
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
        .or_else(|| {
            if !argument.value_flow.call_sites.is_empty()
                || !argument.value_flow.aggregate_fields.is_empty()
                || !argument.value_flow.tuple_items.is_empty()
                || !argument.value_flow.spreads.is_empty()
            {
                return None;
            }
            let mut sources = argument
                .value_flow
                .source_names
                .iter()
                .filter_map(|source| clean_overwrite_target_key(source));
            let source = sources.next()?;
            sources.next().is_none().then_some(source)
        })
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

#[allow(clippy::too_many_arguments)] // The proof consumes each rule-declared callable/argument role plus exact branch facts.
fn path_containment_guard_condition(
    events: &[FlowEvent],
    file_index: &bonsai_lang_api::DeclIndex,
    condition_facts: &[BranchConditionFact],
    branch: StructuredBranch<'_>,
    candidate: &str,
    base: &str,
    containment_check: &RuleTarget,
    base_canonicalizer: Option<&RuleTarget>,
    containment_candidate_projection: Option<&RuleTarget>,
    containment_base_projection: Option<&RuleTarget>,
    containment_check_candidate_arg_index: Option<usize>,
    containment_check_base_arg_index: usize,
    boundary_places: &[String],
    boundary_builders: &[crate::rule::PathBoundaryBuilderSemantics],
    accepted_boundary_values: &[bonsai_lang_api::StaticScalarValue],
    accepted_containment_results: &[bonsai_lang_api::StaticScalarValue],
    containment_check_is_segment_aware: bool,
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
        base_canonicalizer,
        containment_check,
        containment_candidate_projection,
        containment_base_projection,
        containment_check_candidate_arg_index,
        containment_check_base_arg_index,
        boundary_places,
        boundary_builders,
        accepted_boundary_values,
        containment_check_is_segment_aware,
        file_index,
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
    if accepted_containment_results.is_empty() && condition.polarity == BranchConditionPolarity::Negated {
        return true;
    }
    let exact = condition.expression.as_ref().is_some_and(|expression| {
        if accepted_containment_results.is_empty() {
            // This branch's true arm exits abruptly, so reaching the sink
            // proves the complete parsed condition false. Preserve the
            // specialized equal-base-or-contained form, and also accept any
            // compiler boolean tree whose false value necessarily makes the
            // exact containment atom true (for example validation failures
            // OR-ed with `!contains(candidate, baseWithBoundary)`).
            condition_false_implies_atom_true(expression, containment_call)
                || path_containment_rejection_is_exact(
                    expression,
                    containment_call,
                    candidate,
                    base,
                    containment_check_is_segment_aware,
                )
        } else {
            condition_truth_implies_call_result_allowed(
                expression,
                false,
                containment_call,
                accepted_containment_results,
            )
        }
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

#[allow(clippy::too_many_arguments)] // Parsed branch truth and rule-owned argument roles form one explicit proof query.
fn path_containment_acceptance_condition(
    events: &[FlowEvent],
    file_index: &bonsai_lang_api::DeclIndex,
    condition_facts: &[BranchConditionFact],
    branch_span: Span,
    accepting_condition_truth: bool,
    candidate: &str,
    base: &str,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> bool {
    let Some(condition) = branch_condition_fact_for_span(condition_facts, branch_span) else {
        return false;
    };
    let query = ContainmentCheckQuery {
        condition_span: condition.condition_span,
        candidate,
        base,
        base_canonicalizer: guard.base_canonicalizer.as_ref().or(Some(&guard.canonicalizer)),
        containment_check: &guard.containment_check,
        containment_candidate_projection: guard.containment_candidate_projection.as_ref(),
        containment_base_projection: guard.containment_base_projection.as_ref(),
        containment_check_candidate_arg_index: guard.containment_check_candidate_arg_index,
        containment_check_base_arg_index: guard.containment_check_base_arg_index,
        boundary_places: &guard.boundary_places,
        boundary_builders: &guard.boundary_builders,
        accepted_boundary_values: &guard.accepted_boundary_values,
        containment_check_is_segment_aware: guard.containment_check_is_segment_aware,
        file_index,
    };
    let Some(containment_call) = containment_check_call_before_body(events, &query) else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_acceptance branch={:?} candidate={} base={} missing_containment_call expression={:?}",
            branch_span,
            candidate,
            base,
            condition.expression
        );
        return false;
    };
    let accepted = condition.expression.as_ref().is_some_and(|expression| {
        // `ConditionExpressionFact` already preserves the complete parsed
        // boolean expression, including a top-level negation.  The separate
        // polarity field is a compatibility summary and must not invert that
        // expression a second time.
        if guard.accepted_containment_results.is_empty() {
            if accepting_condition_truth {
                condition_true_implies_atom_true(expression, containment_call)
            } else {
                condition_false_implies_atom_true(expression, containment_call)
            }
        } else {
            condition_truth_implies_call_result_allowed(
                expression,
                accepting_condition_truth,
                containment_call,
                &guard.accepted_containment_results,
            )
        }
    });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_acceptance branch={:?} truth={} containment={:?} expression={:?} accepted={}",
        branch_span,
        accepting_condition_truth,
        containment_call,
        condition.expression,
        accepted
    );
    accepted
}

/// Prove a rule-declared precondition call whose selected predicate argument
/// must be true for execution to continue.  The language frontend owns the
/// exact predicate expression and call spans; rule data owns both the API
/// identity and the continuation contract.
fn path_containment_acceptance_guard_span(
    events: &[FlowEvent],
    file_index: &bonsai_lang_api::DeclIndex,
    calls: &[StructuredCall<'_>],
    consumer_span: Span,
    candidate: &str,
    base: &str,
    guard: &crate::rule::PathConsumerContainmentGuardSemantics,
) -> Option<Span> {
    let acceptance_guard = guard.acceptance_guard.as_ref()?;
    calls.iter().rev().find_map(|call| {
        if call.span.start >= consumer_span.start
            || !rule_target_matches_call(call.name, call.receiver_types, acceptance_guard)
        {
            return None;
        }
        let predicate = call.args.get(guard.acceptance_guard_condition_arg_index)?;
        let condition = file_index.branch_conditions.iter().find(|fact| {
            fact.branch_span == call.span
                && (fact.condition_span == predicate.span
                    || span_contains(predicate.span, fact.condition_span)
                    || span_contains(fact.condition_span, predicate.span))
        })?;
        let query = ContainmentCheckQuery {
            condition_span: condition.condition_span,
            candidate,
            base,
            base_canonicalizer: guard.base_canonicalizer.as_ref().or(Some(&guard.canonicalizer)),
            containment_check: &guard.containment_check,
            containment_candidate_projection: guard.containment_candidate_projection.as_ref(),
            containment_base_projection: guard.containment_base_projection.as_ref(),
            containment_check_candidate_arg_index: guard.containment_check_candidate_arg_index,
            containment_check_base_arg_index: guard.containment_check_base_arg_index,
            boundary_places: &guard.boundary_places,
            boundary_builders: &guard.boundary_builders,
            accepted_boundary_values: &guard.accepted_boundary_values,
            containment_check_is_segment_aware: guard.containment_check_is_segment_aware,
            file_index,
        };
        let containment_call = containment_check_call_before_body(events, &query)?;
        let accepted = condition.expression.as_ref().is_some_and(|expression| {
            if guard.accepted_containment_results.is_empty() {
                condition_true_implies_atom_true(expression, containment_call)
            } else {
                condition_truth_implies_call_result_allowed(
                    expression,
                    true,
                    containment_call,
                    &guard.accepted_containment_results,
                )
            }
        });
        accepted.then_some(call.span)
    })
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
    containment_check_is_segment_aware: bool,
) -> bool {
    if containment_check_is_segment_aware
        && matches!(
            expression,
            ConditionExpressionFact::Not { operand, .. }
                if matches!(operand.as_ref(), ConditionExpressionFact::Atom { span }
                    if span_contains(*span, containment_call))
        )
    {
        return true;
    }
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
    base_canonicalizer: Option<&'a RuleTarget>,
    containment_check: &'a RuleTarget,
    containment_candidate_projection: Option<&'a RuleTarget>,
    containment_base_projection: Option<&'a RuleTarget>,
    containment_check_candidate_arg_index: Option<usize>,
    containment_check_base_arg_index: usize,
    boundary_places: &'a [String],
    boundary_builders: &'a [crate::rule::PathBoundaryBuilderSemantics],
    accepted_boundary_values: &'a [bonsai_lang_api::StaticScalarValue],
    containment_check_is_segment_aware: bool,
    file_index: &'a bonsai_lang_api::DeclIndex,
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
                let candidate_matches = query.containment_check_candidate_arg_index.map_or_else(
                    || {
                        receiver.as_deref().is_some_and(|receiver| {
                            containment_projection_matches(
                                receiver,
                                query.candidate,
                                query.containment_candidate_projection,
                            )
                        }) || containment_receiver_projection_call_matches(
                            events,
                            query.file_index,
                            *span,
                            query.candidate,
                            query.containment_candidate_projection,
                        )
                    },
                    |index| {
                        args.get(index)
                            .and_then(|argument| argument.place.as_deref())
                            .is_some_and(|place| {
                                containment_projection_matches(
                                    place,
                                    query.candidate,
                                    query.containment_candidate_projection,
                                )
                            })
                    },
                );
                if !candidate_matches
                    || !rule_target_matches_call(name, receiver_types, query.containment_check)
                {
                    continue;
                }
                let Some(argument) = args.get(query.containment_check_base_arg_index) else {
                    continue;
                };
                let boundary_matches =
                    containment_argument_proves_boundary_base(events, query, *span, argument);
                if boundary_matches {
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

fn containment_receiver_projection_call_matches(
    events: &[FlowEvent],
    file_index: &bonsai_lang_api::DeclIndex,
    call_span: Span,
    base: &str,
    projection: Option<&RuleTarget>,
) -> bool {
    let Some(projection) = projection else {
        return false;
    };
    let Some(receiver) = bonsai_lang_api::call_receiver_fact_for_span(&file_index.call_receivers, call_span)
    else {
        return false;
    };
    let mut calls = Vec::new();
    collect_structured_calls(events, &mut calls);
    let mut candidates = receiver.value_flow.call_sites.iter().filter_map(|site| {
        calls.iter().find(|call| {
            (call.span == *site || spans_overlap(call.span, *site))
                && rule_target_matches_call(call.name, call.receiver_types, projection)
                && call.receiver.and_then(clean_overwrite_target_key).as_deref() == Some(base)
        })
    });
    candidates.next().is_some() && candidates.next().is_none()
}

/// Prove the containment operand either directly names the canonical base or
/// names the latest compiler assignment that composes that base with every
/// rule-declared boundary place. This preserves the common value-equivalent
/// spelling `root = canonical(base) + separator; candidate.StartsWith(root)`
/// without interpreting a language/API spelling in shared analysis.
fn containment_argument_proves_boundary_base(
    events: &[FlowEvent],
    query: &ContainmentCheckQuery<'_>,
    containment_call_span: Span,
    argument: &bonsai_lang_api::CallArg,
) -> bool {
    let contains_required = |place: Option<&str>, sources: &[String]| {
        let has_base = place.is_some_and(|place| {
            containment_projection_matches(place, query.base, query.containment_base_projection)
                || containment_canonical_base_alias(events, query, place)
        }) || sources.iter().any(|source| {
            containment_projection_matches(source, query.base, query.containment_base_projection)
                || containment_canonical_base_alias(events, query, source)
        });
        has_base
            && (query.containment_check_is_segment_aware
                || (!query.boundary_places.is_empty()
                    && query
                        .boundary_places
                        .iter()
                        .all(|boundary| sources.iter().any(|source| source == boundary))))
    };
    if contains_required(argument.place.as_deref(), &argument.source_names) {
        return true;
    }
    if boundary_builder_proves_base(events, query, containment_call_span, argument) {
        return true;
    }
    if literal_boundary_composition_proves_base(events, query, argument) {
        return true;
    }
    let Some(argument_place) = argument.place.as_deref().and_then(clean_overwrite_target_key) else {
        return false;
    };
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, query.condition_span, &mut assignments);
    let Some(assignment) = assignments.iter().rev().find(|assignment| {
        clean_overwrite_target_key(assignment.target).as_deref() == Some(argument_place.as_str())
    }) else {
        return false;
    };
    contains_required(assignment.source_name, assignment.source_names)
}

fn containment_canonical_base_alias(
    events: &[FlowEvent],
    query: &ContainmentCheckQuery<'_>,
    candidate: &str,
) -> bool {
    let Some(canonicalizer) = query.base_canonicalizer else {
        return false;
    };
    let Some(candidate) = clean_overwrite_target_key(candidate) else {
        return false;
    };
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, query.condition_span, &mut assignments);
    let result = assignments
        .iter()
        .rev()
        .find(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(candidate.as_str())
        })
        .is_some_and(|assignment| {
            assignment
                .source_call
                .is_some_and(|call| rule_target_matches_call(call, &[], canonicalizer))
                && {
                    let mut sources = assignment
                        .source_name
                        .into_iter()
                        .chain(assignment.source_names.iter().map(String::as_str))
                        .filter_map(clean_overwrite_target_key)
                        .filter(|source| {
                            callee_spelling_tail(source)
                                != callee_spelling_tail(assignment.source_call.unwrap_or_default())
                        });
                    let source = sources.next();
                    source.as_deref() == Some(query.base) && sources.next().is_none()
                }
        });
    bonsai_diagnostics::debug_log!(
        "security-taint",
        "path_containment_base_alias candidate={} base={} proven={} assignments={:?}",
        candidate,
        query.base,
        result,
        assignments
            .iter()
            .filter(
                |assignment| clean_overwrite_target_key(assignment.target).as_deref()
                    == Some(candidate.as_str())
            )
            .map(|assignment| (
                assignment.source_call,
                assignment.source_name,
                assignment.source_names
            ))
            .collect::<Vec<_>>()
    );
    result
}

/// Match either an exact compiler place or one rule-declared terminal value
/// projection of that place. The shared engine understands only structural
/// projection; property/method identity stays in the rule target.
fn containment_projection_matches(value: &str, base: &str, projection: Option<&RuleTarget>) -> bool {
    let Some(base) = clean_overwrite_target_key(base) else {
        return false;
    };
    if clean_overwrite_target_key(value).as_deref() == Some(base.as_str()) {
        return true;
    }
    let Some(projection) = projection else {
        return false;
    };
    let value = value
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    let Some(suffix) = value.strip_prefix(&base) else {
        return false;
    };
    if !suffix.starts_with('.') || suffix.len() <= 1 || suffix.contains([' ', '(', ')', '[', ']']) {
        return false;
    }
    rule_target_matches_call(value, &[], projection)
}

fn literal_boundary_composition_proves_base(
    events: &[FlowEvent],
    query: &ContainmentCheckQuery<'_>,
    argument: &bonsai_lang_api::CallArg,
) -> bool {
    if query.accepted_boundary_values.is_empty() {
        return false;
    }
    let argument_place = argument.place.as_deref().and_then(clean_overwrite_target_key);
    let composition = query.file_index.string_compositions.iter().find(|composition| {
        composition.value_span == argument.span
            || argument_place.as_deref().is_some_and(|place| {
                composition.target.as_deref() == Some(place)
                    && composition.container_span.start < query.condition_span.start
            })
    });
    let Some(composition) = composition else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "path_containment_literal_boundary missing argument={:?} facts={:?}",
            argument.span,
            query.file_index.string_compositions
        );
        return false;
    };
    let [base_part, bonsai_lang_api::StringCompositionPart::Literal { value }] = composition.parts.as_slice()
    else {
        return false;
    };
    let base_matches = match base_part {
        bonsai_lang_api::StringCompositionPart::Place { place } => {
            containment_projection_matches(place, query.base, query.containment_base_projection)
                || containment_canonical_base_alias(events, query, place)
        }
        bonsai_lang_api::StringCompositionPart::Call { span } => {
            let Some(canonicalizer) = query.base_canonicalizer else {
                return false;
            };
            let mut calls = Vec::new();
            collect_structured_calls(events, &mut calls);
            let candidates = calls
                .into_iter()
                .filter(|call| {
                    spans_overlap(call.span, *span)
                        && rule_target_matches_call(call.name, call.receiver_types, canonicalizer)
                        && call.args.first().is_some_and(|argument| {
                            argument
                                .place
                                .as_deref()
                                .and_then(clean_overwrite_target_key)
                                .as_deref()
                                == Some(query.base)
                        })
                })
                .count();
            candidates == 1
        }
        _ => false,
    };
    base_matches
        && query.accepted_boundary_values.iter().any(|accepted| {
            matches!(accepted, bonsai_lang_api::StaticScalarValue::String(candidate) if candidate == value)
        })
}

fn boundary_builder_proves_base(
    events: &[FlowEvent],
    query: &ContainmentCheckQuery<'_>,
    containment_call_span: Span,
    argument: &bonsai_lang_api::CallArg,
) -> bool {
    if query.boundary_builders.is_empty() {
        return false;
    }
    let argument_fact = bonsai_lang_api::call_argument_value_fact(
        &query.file_index.call_argument_values,
        containment_call_span,
        0,
    );
    let Some(direct_call_span) = argument_fact.and_then(|fact| fact.direct_call_span) else {
        return false;
    };
    let dynamic_sources = argument
        .source_names
        .iter()
        .filter_map(|source| clean_overwrite_target_key(source))
        .collect::<AHashSet<_>>();
    if dynamic_sources.len() != 1 || !dynamic_sources.contains(query.base) {
        return false;
    }

    let mut calls = Vec::new();
    collect_structured_calls(events, &mut calls);
    let candidates = calls
        .into_iter()
        .filter(|call| {
            spans_overlap(call.span, direct_call_span)
                && span_contains(argument.span, call.span)
                && query
                    .boundary_builders
                    .iter()
                    .any(|builder| rule_target_matches_call(call.name, call.receiver_types, &builder.call))
        })
        .collect::<Vec<_>>();
    let [call] = candidates.as_slice() else {
        return false;
    };

    query.boundary_builders.iter().any(|builder| {
        if !rule_target_matches_call(call.name, call.receiver_types, &builder.call) {
            return false;
        }
        let base_matches = if builder.base_from_receiver {
            call.receiver.and_then(clean_overwrite_target_key).as_deref() == Some(query.base)
        } else {
            call.args
                .get(builder.base_arg_index)
                .and_then(|argument| {
                    argument
                        .place
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .or_else(|| {
                            let mut sources = argument
                                .source_names
                                .iter()
                                .filter_map(|source| clean_overwrite_target_key(source));
                            let source = sources.next()?;
                            sources.next().is_none().then_some(source)
                        })
                })
                .as_deref()
                == Some(query.base)
        };
        if !base_matches {
            return false;
        }
        bonsai_lang_api::call_argument_value_fact(
            &query.file_index.call_argument_values,
            call.span,
            builder.boundary_arg_index,
        )
        .and_then(|fact| fact.static_value.as_ref())
        .is_some_and(|value| builder.accepted_boundary_values.contains(value))
    })
}

pub(super) fn configured_argument_factory_guard_sanitizer(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
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
    });
    let mut file_calls = sink_calls;
    for candidate in &file_decls {
        collect_structured_calls(&candidate.flow_events, &mut file_calls);
    }
    if let Some(assignment_span) = assignment_span {
        if let Some(assignment) =
            bonsai_lang_api::assignment_value_fact_for_span(&file_index.assignment_values, assignment_span)
        {
            if let Some(factory_call) = file_calls.iter().find(|call| {
                assignment
                    .call_sites
                    .iter()
                    .any(|call_site| span_contains(*call_site, call.span))
                    && rule_target_matches_call(call.name, call.receiver_types, &guard.factory)
            }) {
                if configured_factory_call_is_exact(&file_index, factory_call, guard) {
                    return finding_for_guard_span_in_workspace(
                        ws,
                        sink,
                        assignment.assignment_span,
                        "engine.sanitizer.configured_argument_factory_guard",
                        sink_rule.tag.as_deref()?,
                        "compiler-proven-configured-argument-factory",
                    );
                }
            }
        }
    }

    // If the sink consumes a parameter, prove the rule-owned factory shape
    // on every compiler-resolved caller edge. This retains element-level
    // structure across one ordinary function boundary without giving shared
    // analysis any knowledge of the provider or its security meaning. The
    // proof deliberately considers all callers, rather than only the current
    // source path: one caller with a dynamic command position must keep the
    // helper reportable for every source.
    let parameter_index = sink_decl.params.iter().position(|parameter| {
        clean_overwrite_target_key(parameter).as_deref() == Some(guarded_place.as_str())
    })?;
    let callers = call_graph.callers_of(sink_func).collect::<Vec<_>>();
    if callers.is_empty() {
        return None;
    }
    let mut proof_span: Option<Span> = None;
    for edge in callers {
        let caller = ws.exact_decl(SymbolId::new(edge.from.raw()))?;
        let caller_index = ws.exact_decl_index_shared(caller.span.file)?;
        let mut caller_calls = Vec::new();
        collect_structured_calls(&caller.flow_events, &mut caller_calls);
        // The semantic edge already proves the callee identity. Resolve its
        // exact call span without re-checking rendered receiver qualification
        // (`this.helper` versus `helper`), which is presentation rather than
        // callable identity.
        let caller_call = structured_call_at_match(&caller_calls, edge.span, "")?;
        let argument = caller_call.args.get(parameter_index)?;
        let span = configured_factory_argument_proof_span(
            &caller.flow_events,
            &caller_index,
            &caller_calls,
            argument,
            edge.span,
            guard,
        )?;
        proof_span = Some(proof_span.map_or(span, |current| current.min(span)));
    }

    finding_for_guard_span_in_workspace(
        ws,
        sink,
        proof_span?,
        "engine.sanitizer.configured_argument_factory_guard",
        sink_rule.tag.as_deref()?,
        "compiler-proven-configured-argument-factory",
    )
}

fn configured_factory_call_is_exact(
    file_index: &bonsai_lang_api::DeclIndex,
    factory_call: &StructuredCall<'_>,
    guard: &crate::rule::ConfiguredArgumentFactoryGuardSemantics,
) -> bool {
    if guard.required_arguments.is_empty()
        && guard.required_named_arguments.is_empty()
        && guard.required_aggregate_argument.is_none()
    {
        return false;
    }
    let positional_arguments_configured = guard
        .required_arguments
        .iter()
        .all(|required| receiver_configuration_argument_matches(file_index, factory_call.span, required));
    let named_arguments_configured = guard.required_named_arguments.iter().all(|required| {
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
    let aggregate_argument_configured =
        guard
            .required_aggregate_argument
            .as_ref()
            .is_none_or(|required_argument| {
                !required_argument.required_fields.is_empty()
                    && bonsai_lang_api::call_argument_value_fact(
                        &file_index.call_argument_values,
                        factory_call.span,
                        required_argument.argument_index,
                    )
                    .is_some_and(|fact| {
                        required_argument.required_fields.iter().all(|required| {
                            fact.exact_static_aggregate_fields
                                .iter()
                                .any(|field| field.path == required.path && field.value == required.value)
                        })
                    })
            });
    positional_arguments_configured && named_arguments_configured && aggregate_argument_configured
}

fn configured_factory_argument_proof_span(
    events: &[FlowEvent],
    file_index: &bonsai_lang_api::DeclIndex,
    calls: &[StructuredCall<'_>],
    argument: &bonsai_lang_api::CallArg,
    before: Span,
    guard: &crate::rule::ConfiguredArgumentFactoryGuardSemantics,
) -> Option<Span> {
    let inline = calls
        .iter()
        .filter(|call| {
            span_contains(argument.span, call.span)
                && rule_target_matches_call(call.name, call.receiver_types, &guard.factory)
        })
        .collect::<Vec<_>>();
    if let [factory_call] = inline.as_slice() {
        if configured_factory_call_is_exact(file_index, factory_call, guard) {
            return Some(factory_call.span);
        }
    }

    let place = argument.place.as_deref().and_then(clean_overwrite_target_key)?;
    let assignment_span = latest_structured_assignment_to(events, before, &place)?;
    let assignment =
        bonsai_lang_api::assignment_value_fact_for_span(&file_index.assignment_values, assignment_span)?;
    let factory_call = calls.iter().find(|call| {
        assignment
            .call_sites
            .iter()
            .any(|call_site| span_contains(*call_site, call.span))
            && rule_target_matches_call(call.name, call.receiver_types, &guard.factory)
    })?;
    configured_factory_call_is_exact(file_index, factory_call, guard).then_some(assignment_span)
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

/// Prove receiver hardening performed inside an exact, immediately-invoked
/// inline callback such as a language scope/configuration function.
///
/// The rule supplies all runtime roles and callable identities. The compiler
/// supplies the sink receiver-builder call, immutable reaching assignment,
/// nested provider call, wrapper call, callback declaration, and typed
/// argument values. A bare call in the callback is treated as a receiver call
/// only because the rule explicitly declares that wrapper's callback role.
pub(super) fn receiver_callback_configuration_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    let guard = sink_rule
        .analysis_semantics
        .as_ref()?
        .receiver_callback_configuration_guard
        .as_ref()?;
    let sink_decl = ws.exact_decl(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.exact_decl_index_shared(sink.span.file)?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = structured_call_at_match(&sink_calls, sink.span, "")?;

    // The sink receiver may itself be a builder call (`factory.builder().sink`).
    // Require exactly one rule-selected builder nested in the matched sink and
    // use its compiler receiver place as the configured value.
    let builders = sink_calls
        .iter()
        .filter(|call| {
            call.span != sink_call.span
                && span_contains(sink_call.span, call.span)
                && rule_target_matches_call(call.name, call.receiver_types, &guard.sink_receiver_builder)
        })
        .collect::<Vec<_>>();
    let [builder] = builders.as_slice() else {
        return None;
    };
    let configured_place = compiler_call_receiver_place(&file_index, builder)?;
    let assignment = latest_assignment_to_compiler_place(
        &file_index.assignment_values,
        &configured_place,
        sink.span.start,
    )?;
    if !assignment.target_is_immutable
        || !assignment
            .direct_call_name
            .as_deref()
            .is_some_and(|callee| rule_target_matches_call(callee, &[], &guard.wrapper_call))
    {
        return None;
    }

    let wrappers = sink_calls
        .iter()
        .filter(|call| {
            span_contains(assignment.value_span, call.span)
                && rule_target_matches_call(call.name, call.receiver_types, &guard.wrapper_call)
        })
        .collect::<Vec<_>>();
    let [wrapper] = wrappers.as_slice() else {
        return None;
    };
    let provider_receiver_span = assignment.direct_call_receiver_span?;
    let providers = sink_calls
        .iter()
        .filter(|call| {
            span_contains(provider_receiver_span, call.span)
                && rule_target_matches_call(call.name, call.receiver_types, &guard.provider_factory)
        })
        .collect::<Vec<_>>();
    let [_provider] = providers.as_slice() else {
        return None;
    };

    let callback_fact = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        wrapper.span,
        guard.callback_argument_index,
    )?;
    let callback_span = callback_fact.inline_callback_span?;
    let callback = file_index
        .defs
        .iter()
        .find(|decl| decl.span == callback_span)
        .and_then(|header| ws.exact_decl(header.symbol))?;
    let target = Span::empty(callback.span.file, callback.span.end);
    let callback_calls = guaranteed_calls_before(&callback.flow_events, target);
    let proof =
        implicit_receiver_configuration_proof_span(&file_index, &callback_calls, &guard.required_calls)?;
    finding_for_guard_span_in_workspace(
        ws,
        sink,
        proof,
        "engine.sanitizer.receiver_callback_configuration_guard",
        sink_rule.tag.as_deref()?,
        "compiler-proven-inline-receiver-configuration",
    )
}

fn implicit_receiver_configuration_proof_span(
    file_index: &bonsai_lang_api::DeclIndex,
    calls: &[StructuredCall<'_>],
    required_calls: &[crate::rule::RequiredReceiverCallSemantics],
) -> Option<Span> {
    let mut proof = None;
    for required in required_calls {
        let call = calls.iter().rev().find(|call| {
            call.receiver.is_none()
                && bonsai_common::qualified_name_owner(call.name).is_none()
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
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
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
    let static_collection_context = UrlStaticCollectionContext {
        ws,
        call_graph,
        sink_func,
        file_index: &file_index,
        calls: &file_calls,
        factories: &guard.host_allowlist.static_collection_factories,
    };
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
    let Some(parsed_root) =
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
            && clean_overwrite_target_key(assignment.target).as_deref() == Some(parsed_root.as_str())
            && assignment_contains_url_parser_call(assignment, &calls, &guard.parser, None, &import_aliases)
    }) else {
        bonsai_diagnostics::debug_log!(
            "security-taint",
            "url_network_guard sink={} root={} has no parser assignment",
            sink.rule_id,
            parsed_root
        );
        return None;
    };
    let parsed_places = url_guard_alias_places(&parsed_root, &assignments, sink.span.start);
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
    let positive_guard = branches
        .iter()
        .filter(|branch| span_contains(branch.span, sink.span))
        .find_map(|branch| {
            let expression = branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
                .and_then(|fact| fact.expression.as_ref())?;
            parsed_places.iter().find_map(|parsed| {
                let scheme_ok =
                    url_scheme_acceptance_is_exact(expression, parsed, &guard.scheme, &calls, &file_index);
                let collection = url_accepted_host_collection(
                    expression,
                    parsed,
                    &guard.host_allowlist,
                    &calls,
                    &file_index,
                );
                let host_ok = collection.as_ref().is_some_and(|collection| {
                    url_collection_is_static(
                        collection,
                        branch.span,
                        &static_collection_context,
                    )
                });
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "url_network_guard positive candidate span={:?} parsed={} expression={:?} scheme={} collection={:?} host={}",
                    branch.span,
                    parsed,
                    expression,
                    scheme_ok,
                    collection,
                    host_ok
                );
                (scheme_ok && host_ok).then_some((branch, parsed.clone()))
            })
        });

    let (scheme_guard, host_guard, parsed) = if let Some((branch, parsed)) = positive_guard {
        (branch, branch, parsed)
    } else {
        let Some((scheme_guard, parsed)) = branches
            .iter()
            .filter(|branch| {
                parser_assignment.span.start < branch.span.start
                    && branch.span.start < validation_end
                    && branch_arm_abruptly_exits(branch.then_events)
            })
            .find_map(|branch| {
                branch_condition_fact_for_span(&file_index.branch_conditions, branch.span)
                    .and_then(|fact| fact.expression.as_ref())
                    .and_then(|expression| {
                        parsed_places
                            .iter()
                            .find(|parsed| {
                                url_scheme_rejection_is_exact(
                                    expression,
                                    parsed,
                                    &guard.scheme,
                                    &calls,
                                    &file_index,
                                )
                            })
                            .cloned()
                    })
                    .map(|parsed| (branch, parsed))
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
                    url_rejected_host_collection(
                        expression,
                        &parsed,
                        &guard.host_allowlist,
                        &calls,
                        &file_index,
                    )
                });
                let is_static = collection.as_ref().is_some_and(|collection| {
                    url_collection_is_static(collection, branch.span, &static_collection_context)
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
        (scheme_guard, host_guard, parsed)
    };

    if let Some(dns) = guard.dns.as_ref() {
        let Some(resolver_call) = calls.iter().find(|call| {
            host_guard.span.start < call.span.start
                && call.span.start < validation_end
                && crate::matcher::rule_target_matches_call_with_aliases(
                    call.name,
                    call.receiver_types,
                    &dns.resolver,
                    &import_aliases,
                )
                && call.args.iter().any(|argument| {
                    url_call_argument_reads_component(
                        argument,
                        &parsed,
                        &guard.host_allowlist.component,
                        &calls,
                    )
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
                        rule_target_matches_call(call.name, call.receiver_types, &dns.resolver),
                        crate::matcher::rule_target_matches_call_with_aliases(
                            call.name,
                            call.receiver_types,
                            &dns.resolver,
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
                        .is_none_or(|call| rule_target_matches_call(call, &[], &dns.resolver))
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
            for predicate in &dns.private_address_predicates {
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
                    dns,
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
    }
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
    let Some(guard_span) = compiler_proven_url_reconstruction_guard(ws, call_graph, target, guard) else {
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
        .filter(|edge| edge.span == helper_call.span || spans_overlap(edge.span, helper_call.span))
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
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
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
    let static_collection_context = UrlStaticCollectionContext {
        ws,
        call_graph,
        sink_func: target.function,
        file_index: &helper_file_index,
        calls: &helper_file_calls,
        factories: &guard.host_allowlist.static_collection_factories,
    };
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
                    url_rejected_host_collection(
                        expression,
                        parsed,
                        &guard.host_allowlist,
                        &helper_calls,
                        &helper_file_index,
                    )
                })
                .is_some_and(|collection| {
                    url_collection_is_static(&collection, branch.span, &static_collection_context)
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
        crate::rule::UrlGuardRootSemantics::SinkArgumentParsedValue { argument_index } => {
            sink_call.args.get(*argument_index).and_then(|argument| {
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
            })
        }
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
                    assignment_contains_url_parser_call(
                        assignment,
                        calls,
                        &guard.parser,
                        Some((*parser_argument_index, sink_value.as_str())),
                        import_aliases,
                    )
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

/// Prove that an assignment contains the rule-declared parser call. Some
/// languages wrap a throwing constructor in an option/result helper before
/// assigning it (`Try(new URI(raw)).toOption`). The compiler retains the
/// nested constructor call span, so wrapper syntax never needs to be named or
/// guessed by shared analysis.
fn assignment_contains_url_parser_call(
    assignment: &StructuredAssignment<'_>,
    calls: &[StructuredCall<'_>],
    parser: &RuleTarget,
    required_input: Option<(usize, &str)>,
    import_aliases: &std::collections::HashMap<String, bonsai_lang_api::AliasTarget>,
) -> bool {
    let direct = assignment.source_call.is_some_and(|call| {
        crate::matcher::rule_target_matches_call_with_aliases(call, &[], parser, import_aliases)
            && required_input.is_none_or(|(index, expected)| {
                assignment
                    .source_call_args
                    .get(index)
                    .and_then(|argument| clean_overwrite_target_key(argument))
                    .as_deref()
                    == Some(expected)
            })
    });
    direct
        || calls.iter().any(|call| {
            span_contains(assignment.span, call.span)
                && crate::matcher::rule_target_matches_call_with_aliases(
                    call.name,
                    call.receiver_types,
                    parser,
                    import_aliases,
                )
                && required_input.is_none_or(|(index, expected)| {
                    call.args.get(index).is_some_and(|argument| {
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
                            .as_deref()
                            == Some(expected)
                    })
                })
        })
}

/// Follow only exact compiler assignment aliases from a parsed URL binding to
/// later pattern/local bindings. This handles option/result destructuring
/// without assigning meaning to wrapper or case-constructor names.
fn url_guard_alias_places(root: &str, assignments: &[StructuredAssignment<'_>], before: u64) -> Vec<String> {
    let mut places = vec![root.to_string()];
    let mut changed = true;
    while changed {
        changed = false;
        for assignment in assignments
            .iter()
            .filter(|assignment| assignment.span.start < before)
        {
            let Some(target) = clean_overwrite_target_key(assignment.target) else {
                continue;
            };
            if places.iter().any(|place| place == &target) {
                continue;
            }
            let aliases_known = assignment
                .source_name
                .into_iter()
                .chain(assignment.source_names.iter().map(String::as_str))
                .filter_map(clean_overwrite_target_key)
                .any(|source| places.iter().any(|place| place == &source));
            if aliases_known {
                places.push(target);
                changed = true;
            }
        }
    }
    places
}

fn url_scheme_acceptance_is_exact(
    expression: &ConditionExpressionFact,
    parsed: &str,
    guard: &crate::rule::UrlSchemeGuardSemantics,
    calls: &[StructuredCall<'_>],
    file_index: &bonsai_lang_api::DeclIndex,
) -> bool {
    let terms: &[ConditionExpressionFact] = match expression {
        ConditionExpressionFact::All { operands, .. } => operands,
        expression => std::slice::from_ref(expression),
    };
    terms.iter().any(|term| match term {
        ConditionExpressionFact::Equality {
            relation: ConditionEquality::Equal,
            left,
            right,
            ..
        } => {
            url_scheme_equality_matches(left, right, parsed, guard, calls)
                || url_scheme_equality_matches(right, left, parsed, guard, calls)
        }
        ConditionExpressionFact::Atom { span }
        | ConditionExpressionFact::Truthy {
            operand:
                ConditionOperandFact {
                    direct_call_span: Some(span),
                    ..
                },
            ..
        } => guard.comparison_predicate.as_ref().is_some_and(|predicate| {
            url_scheme_predicate_matches(*span, parsed, guard, predicate, calls, file_index)
        }),
        _ => false,
    })
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
            ConditionExpressionFact::Atom { span }
            | ConditionExpressionFact::Truthy {
                operand:
                    ConditionOperandFact {
                        direct_call_span: Some(span),
                        ..
                    },
                ..
            } => guard.comparison_predicate.as_ref().is_some_and(|predicate| {
                url_scheme_predicate_matches(*span, parsed, guard, predicate, calls, file_index)
            }),
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
        let contained = span_contains(atom_span, call.span);
        let predicate_matches = rule_target_matches_call(call.name, call.receiver_types, predicate);
        if !contained || !predicate_matches {
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
        // Operator-style equality is lowered as one exact call whose two
        // operands are ordinary arguments. Accept either ordering only when
        // one operand is the parsed component and the other is an exact
        // compiler-decoded allowed string.
        let has_component_argument = call
            .args
            .iter()
            .any(|argument| url_call_argument_reads_component(argument, parsed, &guard.component, calls));
        let has_allowed_argument = call.args.iter().enumerate().any(|(index, _)| {
            bonsai_lang_api::call_argument_value_fact(&file_index.call_argument_values, call.span, index)
                .and_then(|fact| fact.static_value.as_ref())
                .and_then(|value| match value {
                    bonsai_lang_api::StaticScalarValue::String(value) => Some(value),
                    _ => None,
                })
                .is_some_and(|value| guard.allowed_values.iter().any(|allowed| allowed == value))
        });
        if has_component_argument && has_allowed_argument {
            return true;
        }
        let receiver_reads_component = receiver_fact.is_some_and(|fact| {
            url_expression_flow_reads_component(&fact.value_flow, parsed, &guard.component)
                || url_span_reads_component(fact.receiver_span, parsed, &guard.component, calls)
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
    if component.field.is_some() {
        return url_expression_flow_reads_component(&operand.value_flow, parsed, component);
    }
    url_span_reads_component(operand.span, parsed, component, calls)
}

fn url_expression_flow_reads_component(
    flow: &bonsai_lang_api::ExpressionFlow,
    parsed: &str,
    component: &crate::rule::UrlComponentSemantics,
) -> bool {
    let Some(field) = component.field.as_deref() else {
        return false;
    };
    let exact_projection = flow.projection.as_ref().is_some_and(|projection| {
        projection.base == parsed
            && projection.path.len() == 1
            && projection.path.first().is_some_and(|segment| segment == field)
    });
    if exact_projection {
        return true;
    }

    // A language frontend may lower a scalar expression such as a null/empty
    // fallback (`parsed.host or ""`) as a compound value. It is still an
    // exact read of the component when every dynamic operand is that same
    // projection; static fallback pieces do not appear in `source_names`.
    // Reject mixed dynamic expressions so a host combined with another value
    // cannot masquerade as an exact allowlist check.
    let expected = format!("{parsed}.{field}");
    !flow.source_names.is_empty() && flow.source_names.iter().all(|source| source == &expected)
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum UrlCollectionSource {
    Place(String),
    Call(Span),
}

fn url_membership_collection_source(
    call: &StructuredCall<'_>,
    calls: &[StructuredCall<'_>],
    file_index: &bonsai_lang_api::DeclIndex,
) -> Option<UrlCollectionSource> {
    if let Some(place) = call.receiver.and_then(clean_overwrite_target_key) {
        return Some(UrlCollectionSource::Place(place));
    }
    let receiver = bonsai_lang_api::call_receiver_fact_for_span(&file_index.call_receivers, call.span)?;
    let mut nested = calls.iter().filter(|candidate| {
        candidate.span != call.span
            && span_contains(receiver.receiver_span, candidate.span)
            && receiver
                .value_flow
                .call_sites
                .iter()
                .any(|site| span_contains(*site, candidate.span))
    });
    let call_span = nested.next()?.span;
    nested
        .next()
        .is_none()
        .then_some(UrlCollectionSource::Call(call_span))
}

fn url_rejected_host_collection(
    expression: &ConditionExpressionFact,
    parsed: &str,
    guard: &crate::rule::UrlHostAllowlistSemantics,
    calls: &[StructuredCall<'_>],
    file_index: &bonsai_lang_api::DeclIndex,
) -> Option<UrlCollectionSource> {
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
            .and_then(clean_overwrite_target_key)
            .map(UrlCollectionSource::Place),
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
                .and_then(clean_overwrite_target_key)
                .map(UrlCollectionSource::Place),
            ConditionExpressionFact::Atom { span }
            | ConditionExpressionFact::Truthy {
                operand:
                    ConditionOperandFact {
                        direct_call_span: Some(span),
                        ..
                    },
                ..
            } => guard.membership_predicate.as_ref().and_then(|predicate| {
                calls.iter().find_map(|call| {
                    (span_contains(*span, call.span)
                        && rule_target_matches_call(call.name, call.receiver_types, predicate)
                        && call.args.iter().any(|argument| {
                            url_call_argument_reads_component(argument, parsed, &guard.component, calls)
                        }))
                    .then(|| url_membership_collection_source(call, calls, file_index))
                    .flatten()
                })
            }),
            _ => None,
        },
        _ => None,
    })
}

fn url_accepted_host_collection(
    expression: &ConditionExpressionFact,
    parsed: &str,
    guard: &crate::rule::UrlHostAllowlistSemantics,
    calls: &[StructuredCall<'_>],
    file_index: &bonsai_lang_api::DeclIndex,
) -> Option<UrlCollectionSource> {
    let terms: &[ConditionExpressionFact] = match expression {
        ConditionExpressionFact::All { operands, .. } => operands,
        expression => std::slice::from_ref(expression),
    };
    terms.iter().find_map(|term| match term {
        ConditionExpressionFact::Membership {
            subject,
            collection,
            then_contains: true,
            ..
        } if url_operand_reads_component(subject, parsed, &guard.component, calls) => collection
            .value_flow
            .place
            .as_deref()
            .and_then(clean_overwrite_target_key)
            .map(UrlCollectionSource::Place),
        ConditionExpressionFact::Atom { span }
        | ConditionExpressionFact::Truthy {
            operand:
                ConditionOperandFact {
                    direct_call_span: Some(span),
                    ..
                },
            ..
        } => guard.membership_predicate.as_ref().and_then(|predicate| {
            calls.iter().find_map(|call| {
                (span_contains(*span, call.span)
                    && rule_target_matches_call(call.name, call.receiver_types, predicate)
                    && call.args.iter().any(|argument| {
                        url_call_argument_reads_component(argument, parsed, &guard.component, calls)
                    }))
                .then(|| url_membership_collection_source(call, calls, file_index))
                .flatten()
            })
        }),
        _ => None,
    })
}

struct UrlStaticCollectionContext<'borrow, 'facts> {
    ws: &'borrow Workspace,
    call_graph: &'borrow bonsai_callgraph::ResolvedCallGraph,
    sink_func: FuncId,
    file_index: &'borrow bonsai_lang_api::DeclIndex,
    calls: &'borrow [StructuredCall<'facts>],
    factories: &'borrow [RuleTarget],
}

fn url_collection_is_static(
    collection: &UrlCollectionSource,
    before: Span,
    context: &UrlStaticCollectionContext<'_, '_>,
) -> bool {
    match collection {
        UrlCollectionSource::Place(collection) => context
            .file_index
            .assignment_values
            .iter()
            .filter(|fact| {
                fact.assignment_span.start < before.start
                    && fact
                        .target
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .as_deref()
                        == Some(collection.as_str())
            })
            .max_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end))
            .is_some_and(|assignment| {
                url_collection_assignment_is_static(
                    assignment,
                    context.file_index,
                    context.calls,
                    context.factories,
                )
            }),
        UrlCollectionSource::Call(call_span) => url_collection_provider_call_is_static(
            context.ws,
            context.call_graph,
            context.sink_func,
            *call_span,
            context.factories,
        ),
    }
}

fn url_collection_provider_call_is_static(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink_func: FuncId,
    call_span: Span,
    factories: &[RuleTarget],
) -> bool {
    let mut targets = call_graph.callees_of(sink_func).filter_map(|edge| {
        (edge.span == call_span).then_some(edge.to).filter(|target| {
            ws.exact_decl(SymbolId::new(target.raw()))
                .is_some_and(|decl| decl.body_span.is_some())
        })
    });
    let (Some(target), None) = (targets.next(), targets.next()) else {
        return false;
    };
    let Some(provider) = ws.exact_decl(SymbolId::new(target.raw())) else {
        return false;
    };
    let Some(provider_index) = ws.exact_decl_index_shared(provider.span.file) else {
        return false;
    };
    let mut provider_calls = Vec::new();
    for candidate in &provider_index.defs {
        collect_structured_calls(&candidate.flow_events, &mut provider_calls);
    }
    let mut returns = Vec::new();
    collect_return_bindings(&provider.flow_events, &mut returns);
    !returns.is_empty()
        && returns.into_iter().all(|(return_span, place)| {
            let Some(place) = place.and_then(clean_overwrite_target_key) else {
                return false;
            };
            let assignments = provider_index.assignment_values.iter().filter(|assignment| {
                provider.span.start <= assignment.assignment_span.start
                    && assignment.assignment_span.end <= provider.span.end
                    && assignment.assignment_span.start < return_span.start
                    && assignment
                        .target
                        .as_deref()
                        .and_then(clean_overwrite_target_key)
                        .as_deref()
                        == Some(place.as_str())
            });
            let mut saw_assignment = false;
            let all_static = assignments.fold(true, |all_static, assignment| {
                saw_assignment = true;
                all_static
                    && url_collection_assignment_is_static(
                        assignment,
                        &provider_index,
                        &provider_calls,
                        factories,
                    )
            });
            saw_assignment && all_static
        })
}

fn url_collection_assignment_is_static(
    assignment: &bonsai_lang_api::AssignmentValueFact,
    file_index: &bonsai_lang_api::DeclIndex,
    calls: &[StructuredCall<'_>],
    factories: &[RuleTarget],
) -> bool {
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
            let configured = |candidate: &StructuredCall<'_>| {
                rule_target_matches_call(candidate.name, candidate.receiver_types, call)
                    && bonsai_lang_api::call_argument_value_fact(
                        &file_index.call_argument_values,
                        candidate.span,
                        *argument_index,
                    )
                    .and_then(|fact| fact.static_value.as_ref())
                        == Some(required_value)
            };
            if let Some(result) = assignment_target_containing_span(events, sink_span) {
                if following_direct_call(events, sink_span, |candidate| {
                    configured(&candidate)
                        && candidate.receiver.and_then(clean_overwrite_target_key).as_deref()
                            == Some(result.as_str())
                })
                .is_some()
                {
                    return true;
                }
            }
            // Fluent clients commonly configure redirects on the request
            // value in the same expression (`client.url(raw).redirect(false)`).
            // The adapter emits nested calls with exact containing spans; no
            // API spelling or source-text interpretation is needed here.
            let mut calls = Vec::new();
            collect_structured_calls(events, &mut calls);
            calls.iter().any(|candidate| {
                candidate.span.start == sink_call.span.start
                    && candidate.span.end > sink_call.span.end
                    && span_contains(candidate.span, sink_call.span)
                    && configured(candidate)
            })
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
    value_kind: Option<bonsai_lang_api::AssignValueKind>,
}

/// Prove that the complete assignment value is either a compiler-lowered
/// call to the rule-owned transform or an exact property projection whose
/// terminal identity is owned by the same rule target. Property syntax is a
/// value read in languages such as Kotlin; it must not be fabricated as a
/// call merely so downstream guard logic can recognize it.
fn assignment_uses_rule_owned_transform(
    assignment: &StructuredAssignment<'_>,
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    target: &RuleTarget,
) -> bool {
    assignment
        .source_call
        .is_some_and(|call| rule_target_matches_call(call, &[], target))
        || bonsai_lang_api::assignment_value_fact_for_span(assignment_values, assignment.span)
            .is_some_and(|value| rule_owned_transform_projection_receiver(value, target).is_some())
        || (assignment.value_kind == Some(bonsai_lang_api::AssignValueKind::PropertyRead)
            && assignment
                .source_names
                .iter()
                .filter(|source| rule_target_matches_call(source, &[], target))
                .count()
                == 1)
}

fn rule_owned_transform_projection_receiver(
    value: &bonsai_lang_api::AssignmentValueFact,
    target: &RuleTarget,
) -> Option<String> {
    let projection = value.value_flow.projection.as_ref()?;
    let canonical = projection.canonical_place();
    if value.value_flow.place.as_deref() != Some(canonical.as_str())
        || !rule_target_matches_call(&canonical, &[], target)
    {
        return None;
    }
    clean_overwrite_target_key(&projection.base)
}

#[derive(Copy, Clone)]
struct StructuredBranch<'a> {
    span: Span,
    then_events: &'a [FlowEvent],
}

#[derive(Copy, Clone)]
struct ContainingBranch {
    span: Span,
    /// Truth value of the source condition that selects the arm containing
    /// the guarded consumer after applying the adapter's branch polarity.
    accepting_condition_truth: bool,
}

fn collect_containing_branches_on_path(events: &[FlowEvent], target: Span, out: &mut Vec<ContainingBranch>) {
    for event in events {
        if !span_contains(event.span(), target) {
            continue;
        }
        match event {
            FlowEvent::Branch {
                span,
                condition: Some(_),
                then_events,
                else_events: _,
            } if events_contain_target(then_events, target) => {
                out.push(ContainingBranch {
                    span: *span,
                    accepting_condition_truth: true,
                });
                collect_containing_branches_on_path(then_events, target, out);
            }
            FlowEvent::Branch {
                span,
                condition: Some(_),
                then_events: _,
                else_events,
            } if events_contain_target(else_events, target) => {
                out.push(ContainingBranch {
                    span: *span,
                    accepting_condition_truth: false,
                });
                collect_containing_branches_on_path(else_events, target, out);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if events_contain_target(then_events, target) {
                    collect_containing_branches_on_path(then_events, target, out);
                } else if events_contain_target(else_events, target) {
                    collect_containing_branches_on_path(else_events, target, out);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_containing_branches_on_path(body, target, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                for region in [body, catch_events, finally_events] {
                    if events_contain_target(region, target) {
                        collect_containing_branches_on_path(region, target, out);
                        break;
                    }
                }
            }
            _ => {}
        }
        return;
    }
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
    // A syntactic return/throw proves rejection; a callee's spelling does
    // not. Fold the structured IR once, joining alternatives without path
    // enumeration or native-stack recursion. Loop transfers must survive a
    // join: an unreachable later throw cannot turn a break into rejection.
    const FALLTHROUGH: u8 = 1;
    const UNPROVEN_TRANSFER: u8 = 2;
    enum Work<'a> {
        Sequence(&'a [FlowEvent]),
        JoinAlternatives,
        ComposeSequence,
    }
    let mut work = vec![Work::Sequence(events)];
    let mut results = Vec::<u8>::new();
    while let Some(next) = work.pop() {
        match next {
            Work::Sequence(events) => {
                let Some((event, rest)) = events.split_first() else {
                    results.push(FALLTHROUGH);
                    continue;
                };
                match event {
                    FlowEvent::Return { .. } | FlowEvent::Throw { .. } => results.push(0),
                    FlowEvent::Break { .. } | FlowEvent::Continue { .. } => {
                        results.push(UNPROVEN_TRANSFER);
                    }
                    FlowEvent::Branch {
                        then_events,
                        else_events,
                        ..
                    } => {
                        work.push(Work::ComposeSequence);
                        work.push(Work::Sequence(rest));
                        work.push(Work::JoinAlternatives);
                        work.push(Work::Sequence(else_events));
                        work.push(Work::Sequence(then_events));
                    }
                    // These regions need their own destination/handler proof.
                    // Treating them as an ordinary statement could hide an
                    // escaping loop transfer or cleanup that replaces a return.
                    FlowEvent::Loop { .. }
                    | FlowEvent::Try { .. }
                    | FlowEvent::Using { .. }
                    | FlowEvent::Defer { .. } => {
                        results.push(FALLTHROUGH | UNPROVEN_TRANSFER);
                    }
                    _ => work.push(Work::Sequence(rest)),
                }
            }
            Work::JoinAlternatives => {
                let right = results.pop().expect("right branch exit state");
                let left = results.pop().expect("left branch exit state");
                results.push(left | right);
            }
            Work::ComposeSequence => {
                let tail = results.pop().expect("continuation exit state");
                let head = results.pop().expect("preceding branch exit state");
                results.push((head & !FALLTHROUGH) | if head & FALLTHROUGH != 0 { tail } else { 0 });
            }
        }
    }
    results == [0]
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
                value_kind,
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
                        value_kind: *value_kind,
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
    fn loop_control_does_not_make_an_unreachable_throw_a_terminal_guard() {
        for control in [
            FlowEvent::Break {
                span: span(1, 2),
                target: None,
            },
            FlowEvent::Continue {
                span: span(1, 2),
                target: None,
            },
        ] {
            let throw = FlowEvent::Throw {
                span: span(3, 4),
                value_name: None,
                thrown_type: None,
            };
            assert!(!branch_arm_abruptly_exits(&[control.clone(), throw.clone()]));
            assert!(!branch_arm_abruptly_exits(&[
                FlowEvent::Branch {
                    span: span(0, 3),
                    condition: Some("condition".to_string()),
                    then_events: vec![control],
                    else_events: Vec::new(),
                },
                throw,
            ]));
        }
    }

    #[test]
    fn terminal_guard_joins_both_arms_and_their_fallthrough_continuation() {
        let throw = || FlowEvent::Throw {
            span: span(3, 4),
            value_name: None,
            thrown_type: None,
        };
        let branch = |then_events, else_events| FlowEvent::Branch {
            span: span(0, 5),
            condition: Some("condition".to_string()),
            then_events,
            else_events,
        };
        assert!(!branch_arm_abruptly_exits(&[]));
        assert!(!branch_arm_abruptly_exits(&[branch(vec![throw()], vec![])]));
        assert!(branch_arm_abruptly_exits(&[branch(vec![throw()], vec![throw()])]));
        assert!(branch_arm_abruptly_exits(&[
            branch(vec![throw()], vec![]),
            throw()
        ]));
        assert!(branch_arm_abruptly_exits(&[
            throw(),
            FlowEvent::Break {
                span: span(6, 7),
                target: None,
            }
        ]));
    }

    #[test]
    fn deeply_nested_terminal_guard_folds_on_the_heap() {
        let throw = || FlowEvent::Throw {
            span: span(3, 4),
            value_name: None,
            thrown_type: None,
        };
        let mut events = vec![throw()];
        for _ in 0..10_000 {
            events = vec![FlowEvent::Branch {
                span: span(0, 5),
                condition: Some("condition".to_string()),
                then_events: events,
                else_events: vec![throw()],
            }];
        }
        let result = branch_arm_abruptly_exits(&events);
        // Drop the synthetic nested Vec tree iteratively as well; this test
        // checks the proof traversal, not Rust's recursive derived drop glue.
        let mut pending = events;
        while let Some(event) = pending.pop() {
            if let FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } = event
            {
                pending.extend(then_events);
                pending.extend(else_events);
            }
        }
        assert!(result);
    }

    #[test]
    fn null_comparison_requires_the_rule_owned_predicate_result_domain() {
        let call = span(10, 20);
        let operand = |span, direct_call_span, static_value| ConditionOperandFact {
            span,
            direct_call_span,
            value_flow: Default::default(),
            static_string: None,
            static_value,
        };
        for relation in [ConditionEquality::Equal, ConditionEquality::NotEqual] {
            for reversed in [false, true] {
                let call_operand = operand(call, Some(call), None);
                let null_operand =
                    operand(span(24, 27), None, Some(bonsai_lang_api::StaticScalarValue::Null));
                let (left, right) = if reversed {
                    (null_operand, call_operand)
                } else {
                    (call_operand, null_operand)
                };
                let expression = ConditionExpressionFact::Equality {
                    span: span(10, 27),
                    relation,
                    left,
                    right,
                };
                for truth in [false, true] {
                    let is_null = truth == (relation == ConditionEquality::Equal);
                    for accepted in [false, true] {
                        assert_eq!(
                            condition_truth_implies_predicate_value(&expression, truth, call, accepted, true),
                            is_null != accepted
                        );
                        assert_eq!(
                            condition_truth_implies_predicate_value(
                                &expression,
                                truth,
                                call,
                                accepted,
                                false
                            ),
                            is_null && !accepted
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn predicate_proof_never_uses_a_nested_call_as_the_complete_result() {
        let call = span(10, 20);
        let wrapper = span(5, 25);
        for expression in [
            ConditionExpressionFact::Atom { span: wrapper },
            ConditionExpressionFact::Truthy {
                span: wrapper,
                operand: ConditionOperandFact {
                    span: wrapper,
                    direct_call_span: Some(wrapper),
                    value_flow: Default::default(),
                    static_string: None,
                    static_value: None,
                },
            },
            ConditionExpressionFact::Equality {
                span: span(5, 30),
                relation: ConditionEquality::NotEqual,
                left: ConditionOperandFact {
                    span: wrapper,
                    direct_call_span: Some(wrapper),
                    value_flow: Default::default(),
                    static_string: None,
                    static_value: None,
                },
                right: ConditionOperandFact {
                    span: span(27, 30),
                    direct_call_span: None,
                    value_flow: Default::default(),
                    static_string: None,
                    static_value: Some(bonsai_lang_api::StaticScalarValue::Null),
                },
            },
        ] {
            for truth in [false, true] {
                for accepted in [false, true] {
                    assert!(!condition_truth_implies_predicate_value(
                        &expression,
                        truth,
                        call,
                        accepted,
                        true
                    ));
                }
            }
        }
    }

    #[test]
    fn nested_aggregate_value_calls_are_part_of_the_compiler_value_projection() {
        let aggregate_call = span(20, 30);
        let tuple_call = span(40, 50);
        let spread_call = span(60, 70);
        let flow = bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                name: "filter".to_string(),
                value_span: Some(span(10, 35)),
                value: bonsai_lang_api::ExpressionFlow {
                    call_sites: vec![aggregate_call],
                    ..Default::default()
                },
            }],
            tuple_items: vec![bonsai_lang_api::ExpressionFlow {
                call_sites: vec![tuple_call],
                ..Default::default()
            }],
            spreads: vec![bonsai_lang_api::ExpressionFlow {
                call_sites: vec![spread_call],
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut calls = Vec::new();
        collect_compiler_call_sites_reaching_value(
            &bonsai_lang_api::DeclIndex::default(),
            &flow,
            span(100, 110),
            &mut calls,
            &mut AHashSet::new(),
        );
        calls.sort_by_key(|call| call.start);
        assert_eq!(calls, vec![aggregate_call, tuple_call, spread_call]);
    }

    #[test]
    fn boolean_ir_proves_rejection_predicate_polarity_without_text_parsing() {
        let first = span(10, 20);
        let second = span(30, 40);
        let disjunction = ConditionExpressionFact::Any {
            span: span(5, 45),
            operands: vec![
                ConditionExpressionFact::Atom { span: first },
                ConditionExpressionFact::Atom { span: second },
            ],
        };
        assert!(condition_truth_implies_predicate_value(
            &disjunction,
            false,
            first,
            false,
            false
        ));
        assert!(condition_truth_implies_predicate_value(
            &disjunction,
            false,
            second,
            false,
            false
        ));
        assert!(!condition_false_implies_atom_true(&disjunction, first));

        let conjunction = ConditionExpressionFact::All {
            span: span(5, 45),
            operands: vec![
                ConditionExpressionFact::Atom { span: first },
                ConditionExpressionFact::Atom { span: second },
            ],
        };
        assert!(
            !condition_truth_implies_predicate_value(&conjunction, false, first, false, false),
            "either conjunct may reject, so one atom's false value is not guaranteed"
        );
        let negated = ConditionExpressionFact::Not {
            span: span(5, 25),
            operand: Box::new(ConditionExpressionFact::Atom { span: first }),
        };
        assert!(condition_truth_implies_predicate_value(
            &negated, true, first, false, false
        ));
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
            canonicalizer_input_from_receiver: false,
            base_canonicalizer: None,
            path_constructor: Some(target(Some(&["os", "path", "join"]), None)),
            path_constructor_is_string_composition: false,
            path_constructor_base_from_receiver: false,
            containment_check: target(None, Some("startswith")),
            acceptance_guard: None,
            acceptance_guard_condition_arg_index: 0,
            containment_candidate_projection: None,
            containment_base_projection: None,
            containment_check_candidate_arg_index: None,
            containment_check_base_arg_index: 0,
            accepted_containment_results: Vec::new(),
            static_base_factories: Vec::new(),
            sink_path_from_receiver: false,
            sink_path_arg_index: 0,
            path_constructor_base_arg_index: 0,
            containment_check_is_segment_aware: false,
            boundary_places: vec!["os.sep".to_string()],
            boundary_builders: Vec::new(),
            accepted_boundary_values: Vec::new(),
        };
        let global = ws.db().global_index();
        let static_graph = ws.cached_resolved_call_graph();
        assert!(
            path_consumer_guard_span(
                &ws,
                global.as_ref(),
                static_graph.as_ref(),
                decl,
                open.span,
                0,
                &guard,
                None,
            )
            .is_some(),
            "typed branch facts: {:#?}",
            index.branch_conditions
        );
    }

    #[test]
    fn java_normalized_absolute_base_containment_requires_a_rejecting_branch() {
        use bonsai_lang_api::LanguageAdapter;

        let source = r#"
import java.nio.file.Files;
import java.nio.file.Path;
class AssetReader {
  private static final Path BASE = Path.of("/var/data/assets");
  byte[] safe(String name) throws Exception {
    Path base = BASE.toAbsolutePath().normalize();
    Path target = base.resolve(name).normalize();
    if (!target.startsWith(base)) throw new Exception("outside");
    return Files.readAllBytes(target);
  }
  byte[] wrongDirection(String name) throws Exception {
    Path base = BASE.toAbsolutePath().normalize();
    Path target = base.resolve(name).normalize();
    if (target.startsWith(base)) throw new Exception("inside");
    return Files.readAllBytes(target);
  }
}
"#;
        let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
        let ws = bonsai_testkit::workspace_with(vec![adapter], &[("AssetReader.java", source)]);
        let file = ws.db().vfs().all_files()[0];
        let index = ws.db().decl_index(file).expect("Java declaration index");
        let named = |name: &str| RuleTarget {
            name: Some(name.to_string()),
            ..RuleTarget::default()
        };
        let guard = crate::rule::PathConsumerContainmentGuardSemantics {
            canonicalizer: named("normalize"),
            canonicalizer_input_from_receiver: true,
            base_canonicalizer: Some(RuleTarget {
                regex: Some(r"(?:^|\.)(?:toAbsolutePath|normalize)$".to_string()),
                ..RuleTarget::default()
            }),
            path_constructor: Some(named("resolve")),
            path_constructor_is_string_composition: false,
            path_constructor_base_from_receiver: true,
            containment_check: named("startsWith"),
            acceptance_guard: None,
            acceptance_guard_condition_arg_index: 0,
            containment_candidate_projection: None,
            containment_base_projection: None,
            containment_check_candidate_arg_index: None,
            containment_check_base_arg_index: 0,
            accepted_containment_results: Vec::new(),
            static_base_factories: vec![RuleTarget {
                attribute: Some(vec!["Path".to_string(), "of".to_string()]),
                ..RuleTarget::default()
            }],
            sink_path_from_receiver: false,
            sink_path_arg_index: 0,
            path_constructor_base_arg_index: 0,
            containment_check_is_segment_aware: true,
            boundary_places: Vec::new(),
            boundary_builders: Vec::new(),
            accepted_boundary_values: Vec::new(),
        };
        let global = ws.db().global_index();
        let static_graph = ws.cached_resolved_call_graph();

        for (name, expected) in [("safe", true), ("wrongDirection", false)] {
            let decl = index
                .defs
                .iter()
                .find(|decl| decl.name == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            let mut calls = Vec::new();
            collect_structured_calls(&decl.flow_events, &mut calls);
            let read = calls
                .iter()
                .find(|call| call.name == "Files.readAllBytes")
                .unwrap_or_else(|| panic!("missing read in {name}"));
            assert_eq!(
                path_consumer_guard_span(
                    &ws,
                    global.as_ref(),
                    static_graph.as_ref(),
                    decl,
                    read.span,
                    0,
                    &guard,
                    None,
                )
                .is_some(),
                expected,
                "method={name}; events={:#?}; assignments={:#?}; branches={:#?}",
                decl.flow_events,
                index.assignment_values,
                index.branch_conditions,
            );
        }
    }

    #[test]
    fn fused_path_constructor_canonicalizer_requires_a_static_base_and_rejecting_branch() {
        use bonsai_lang_api::LanguageAdapter;

        let source = r#"
const fs = require("fs").promises;
const path = require("path");
const BASE = "/var/data/assets";
async function safe(name) {
  const base = await fs.realpath(BASE);
  const target = path.resolve(base, name);
  if (!target.startsWith(base + path.sep)) throw new Error("outside");
  return fs.writeFile(target, "x");
}
async function wrongDirection(name) {
  const base = await fs.realpath(BASE);
  const target = path.resolve(base, name);
  if (target.startsWith(base + path.sep)) throw new Error("inside");
  return fs.writeFile(target, "x");
}
"#;
        let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
        let ws = bonsai_testkit::workspace_with(vec![adapter], &[("store.js", source)]);
        let file = ws.db().vfs().all_files()[0];
        let index = ws.db().decl_index(file).expect("JavaScript declaration index");
        let guard = crate::rule::PathConsumerContainmentGuardSemantics {
            canonicalizer: RuleTarget {
                attribute: Some(vec!["path".to_string(), "resolve".to_string()]),
                ..RuleTarget::default()
            },
            canonicalizer_input_from_receiver: false,
            base_canonicalizer: Some(RuleTarget {
                attribute: Some(vec!["fs".to_string(), "realpath".to_string()]),
                ..RuleTarget::default()
            }),
            path_constructor: Some(RuleTarget {
                attribute: Some(vec!["path".to_string(), "resolve".to_string()]),
                ..RuleTarget::default()
            }),
            path_constructor_is_string_composition: false,
            path_constructor_base_from_receiver: false,
            containment_check: RuleTarget {
                name: Some("startsWith".to_string()),
                ..RuleTarget::default()
            },
            acceptance_guard: None,
            acceptance_guard_condition_arg_index: 0,
            containment_candidate_projection: None,
            containment_base_projection: None,
            containment_check_candidate_arg_index: None,
            containment_check_base_arg_index: 0,
            accepted_containment_results: Vec::new(),
            static_base_factories: Vec::new(),
            sink_path_from_receiver: false,
            sink_path_arg_index: 0,
            path_constructor_base_arg_index: 0,
            containment_check_is_segment_aware: false,
            boundary_places: vec!["path.sep".to_string()],
            boundary_builders: Vec::new(),
            accepted_boundary_values: Vec::new(),
        };
        let global = ws.db().global_index();
        let static_graph = ws.cached_resolved_call_graph();

        for (name, expected) in [("safe", true), ("wrongDirection", false)] {
            let decl = index
                .defs
                .iter()
                .find(|decl| decl.name == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            let mut calls = Vec::new();
            collect_structured_calls(&decl.flow_events, &mut calls);
            let write = calls
                .iter()
                .find(|call| call.name == "fs.writeFile")
                .unwrap_or_else(|| panic!("missing write in {name}"));
            assert_eq!(
                path_consumer_guard_span(
                    &ws,
                    global.as_ref(),
                    static_graph.as_ref(),
                    decl,
                    write.span,
                    0,
                    &guard,
                    None,
                )
                .is_some(),
                expected,
                "method={name}; events={:#?}; assignments={:#?}; branches={:#?}",
                decl.flow_events,
                index.assignment_values,
                index.branch_conditions,
            );
        }
    }

    #[test]
    fn assigned_boundary_root_uses_exact_compiler_value_dependencies() {
        use bonsai_lang_api::LanguageAdapter;

        for (root_assignment, expected) in [
            (
                "var root = Path.GetFullPath(Base) + Path.DirectorySeparatorChar;",
                true,
            ),
            ("var root = Path.GetFullPath(Base);", false),
            (
                "var root = Path.GetFullPath(Base) + Path.DirectorySeparatorChar; root = input;",
                false,
            ),
        ] {
            let source = format!(
                r#"
using System;
using System.IO;
class Store {{
  private const string Base = "/srv/assets";
  byte[] Read(string input) {{
    {root_assignment}
    var candidate = Path.GetFullPath(Path.Combine(Base, input));
    if (!candidate.StartsWith(root, StringComparison.Ordinal))
      throw new InvalidOperationException();
    return File.ReadAllBytes(candidate);
  }}
}}
"#
            );
            let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
            let ws = bonsai_testkit::workspace_with(vec![adapter], &[("Store.cs", &source)]);
            let file = ws.db().vfs().all_files()[0];
            let index = ws.db().decl_index(file).expect("C# declaration index");
            let decl = index
                .defs
                .iter()
                .find(|decl| decl.name == "Read")
                .expect("Read declaration");
            let mut calls = Vec::new();
            collect_structured_calls(&decl.flow_events, &mut calls);
            let read = calls
                .iter()
                .find(|call| call.name == "File.ReadAllBytes")
                .expect("file consumer");
            let target = |attribute: Option<&[&str]>, name: Option<&str>| RuleTarget {
                attribute: attribute.map(|parts| parts.iter().map(|part| (*part).to_string()).collect()),
                name: name.map(str::to_string),
                ..RuleTarget::default()
            };
            let guard = crate::rule::PathConsumerContainmentGuardSemantics {
                canonicalizer: target(Some(&["Path", "GetFullPath"]), None),
                canonicalizer_input_from_receiver: false,
                base_canonicalizer: Some(target(Some(&["Path", "GetFullPath"]), None)),
                path_constructor: Some(target(Some(&["Path", "Combine"]), None)),
                path_constructor_is_string_composition: false,
                path_constructor_base_from_receiver: false,
                containment_check: target(None, Some("StartsWith")),
                acceptance_guard: None,
                acceptance_guard_condition_arg_index: 0,
                containment_candidate_projection: None,
                containment_base_projection: None,
                containment_check_candidate_arg_index: None,
                containment_check_base_arg_index: 0,
                accepted_containment_results: Vec::new(),
                static_base_factories: Vec::new(),
                sink_path_from_receiver: false,
                sink_path_arg_index: 0,
                path_constructor_base_arg_index: 0,
                containment_check_is_segment_aware: false,
                boundary_places: vec!["Path.DirectorySeparatorChar".to_string()],
                boundary_builders: Vec::new(),
                accepted_boundary_values: Vec::new(),
            };
            let global = ws.db().global_index();
            let static_graph = ws.cached_resolved_call_graph();
            assert_eq!(
                path_consumer_guard_span(
                    &ws,
                    global.as_ref(),
                    static_graph.as_ref(),
                    decl,
                    read.span,
                    0,
                    &guard,
                    None,
                )
                .is_some(),
                expected,
                "root assignment {root_assignment:?}; events={:#?}",
                decl.flow_events
            );
        }
    }

    #[test]
    fn namespace_containment_roles_are_rule_owned_and_fail_closed() {
        use bonsai_lang_api::LanguageAdapter;

        for (condition, expected) in [
            ("!paths.within(root, candidate)", true),
            ("!paths.within(candidate, root)", false),
            ("!paths.within(other, candidate)", false),
        ] {
            let source = format!(
                r#"
const rootPath = '/srv/static';
String consume(String value) => value;
String readValue(String input, String other) {{
  final root = paths.canonical(rootPath);
  final candidate = paths.canonical(paths.combine(root, input));
  if ({condition}) throw StateError('outside root');
  return consume(candidate);
}}
"#
            );
            let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
            let ws = bonsai_testkit::workspace_with(vec![adapter], &[("paths.dart", &source)]);
            let file = ws.db().vfs().all_files()[0];
            let index = ws.db().decl_index(file).expect("Dart declaration index");
            let decl = index
                .defs
                .iter()
                .find(|decl| decl.name == "readValue")
                .expect("readValue declaration");
            let mut calls = Vec::new();
            collect_structured_calls(&decl.flow_events, &mut calls);
            let consume = calls
                .iter()
                .find(|call| call.name == "consume")
                .expect("path consumer");
            let attribute = |parts: &[&str]| RuleTarget {
                attribute: Some(parts.iter().map(|part| (*part).to_string()).collect()),
                ..RuleTarget::default()
            };
            let guard = crate::rule::PathConsumerContainmentGuardSemantics {
                canonicalizer: attribute(&["paths", "canonical"]),
                canonicalizer_input_from_receiver: false,
                base_canonicalizer: None,
                path_constructor: Some(attribute(&["paths", "combine"])),
                path_constructor_is_string_composition: false,
                path_constructor_base_from_receiver: false,
                containment_check: attribute(&["paths", "within"]),
                acceptance_guard: None,
                acceptance_guard_condition_arg_index: 0,
                containment_candidate_projection: None,
                containment_base_projection: None,
                containment_check_candidate_arg_index: Some(1),
                containment_check_base_arg_index: 0,
                accepted_containment_results: Vec::new(),
                static_base_factories: Vec::new(),
                sink_path_from_receiver: false,
                sink_path_arg_index: 0,
                path_constructor_base_arg_index: 0,
                containment_check_is_segment_aware: true,
                boundary_places: Vec::new(),
                boundary_builders: Vec::new(),
                accepted_boundary_values: Vec::new(),
            };
            let global = ws.db().global_index();
            let static_graph = ws.cached_resolved_call_graph();
            assert_eq!(
                path_consumer_guard_span(
                    &ws,
                    global.as_ref(),
                    static_graph.as_ref(),
                    decl,
                    consume.span,
                    0,
                    &guard,
                    None,
                )
                .is_some(),
                expected,
                "condition={condition:?}; facts={:#?}; events={:#?}",
                index.branch_conditions,
                decl.flow_events,
            );
        }
    }

    #[test]
    fn rule_owned_boundary_builder_requires_exact_static_literal_and_base_receiver() {
        use bonsai_lang_api::LanguageAdapter;

        for (boundary_expression, canonicalizer_input_from_receiver, expected) in [
            (r#"[base suffixed:@"/"]"#, true, true),
            (r#"[base suffixed:@"/"]"#, false, false),
            (r#"[base suffixed:@"-"]"#, true, false),
            (r#"[other suffixed:@"/"]"#, true, false),
            (r#"[base suffixed:runtimeBoundary]"#, true, false),
        ] {
            let source = format!(
                r#"
id makeBase(id literal);
void consume(id value);
void readValue(id input, id other, id runtimeBoundary) {{
  id base = makeBase(@"/srv");
  id candidate = [[base joined:input] normalized];
  if (![candidate includes:{boundary_expression}]) return;
  consume(candidate);
}}
"#
            );
            let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_objc::ObjCAdapter::new());
            let ws = bonsai_testkit::workspace_with(vec![adapter], &[("Boundary.m", &source)]);
            let file = ws.db().vfs().all_files()[0];
            let index = ws.db().decl_index(file).expect("Objective-C declaration index");
            let decl = index
                .defs
                .iter()
                .find(|decl| decl.name == "readValue")
                .expect("readValue declaration");
            let mut calls = Vec::new();
            collect_structured_calls(&decl.flow_events, &mut calls);
            let consume = calls
                .iter()
                .find(|call| call.name == "consume")
                .expect("path consumer");
            let named = |name: &str| RuleTarget {
                name: Some(name.to_string()),
                ..RuleTarget::default()
            };
            let guard = crate::rule::PathConsumerContainmentGuardSemantics {
                canonicalizer: named("normalized"),
                canonicalizer_input_from_receiver,
                base_canonicalizer: Some(named("normalized")),
                path_constructor: Some(named("joined")),
                path_constructor_is_string_composition: false,
                path_constructor_base_from_receiver: true,
                containment_check: named("includes"),
                acceptance_guard: None,
                acceptance_guard_condition_arg_index: 0,
                containment_candidate_projection: None,
                containment_base_projection: None,
                containment_check_candidate_arg_index: None,
                containment_check_base_arg_index: 0,
                accepted_containment_results: Vec::new(),
                static_base_factories: vec![named("makeBase")],
                sink_path_from_receiver: false,
                sink_path_arg_index: 0,
                path_constructor_base_arg_index: 0,
                containment_check_is_segment_aware: false,
                boundary_places: Vec::new(),
                boundary_builders: vec![crate::rule::PathBoundaryBuilderSemantics {
                    call: named("suffixed"),
                    base_from_receiver: true,
                    base_arg_index: 0,
                    boundary_arg_index: 0,
                    accepted_boundary_values: vec![bonsai_lang_api::StaticScalarValue::String(
                        "/".to_string(),
                    )],
                }],
                accepted_boundary_values: Vec::new(),
            };
            let global = ws.db().global_index();
            let static_graph = ws.cached_resolved_call_graph();
            assert_eq!(
                path_consumer_guard_span(
                    &ws,
                    global.as_ref(),
                    static_graph.as_ref(),
                    decl,
                    consume.span,
                    0,
                    &guard,
                    None,
                )
                .is_some(),
                expected,
                "boundary={boundary_expression}; facts={:#?}; events={:#?}",
                index.call_argument_values,
                decl.flow_events,
            );
        }
    }

    #[test]
    fn exact_returning_finite_selection_covers_direct_and_assigned_calls_only() {
        use bonsai_lang_api::LanguageAdapter;

        for (helper_body, direct, expected) in [
            (
                r#"key switch { "first" => "First", _ => "Default" }"#,
                false,
                true,
            ),
            (r#"key switch { "first" => "First", _ => "Default" }"#, true, true),
            (r#"key switch { "first" => "First", _ => key }"#, false, false),
        ] {
            let consumer_body = if direct {
                "Consume(Choose(input));"
            } else {
                "var chosen = Choose(input); Consume(chosen);"
            };
            let source = format!(
                r#"
class Selector {{
  static string Choose(string key) => {helper_body};
  static void Consume(string value) {{ }}
  static void Run(string input) {{ {consumer_body} }}
}}
"#
            );
            let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
            let ws = bonsai_testkit::workspace_with(vec![adapter], &[("Selector.cs", &source)]);
            let global = ws.db().global_index();
            let run = global
                .all_files()
                .flat_map(|file| global.decls_in(file))
                .find(|decl| decl.name == "Run")
                .expect("Run declaration");
            let file_index = ws
                .exact_decl_index_shared(run.span.file)
                .expect("C# declaration index");
            let mut calls = Vec::new();
            collect_structured_calls(&run.flow_events, &mut calls);
            let consume = calls
                .iter()
                .find(|call| callee_spelling_tail(call.name) == "Consume")
                .expect("Consume call");
            let sink = RuleMatch {
                origin: MatchOrigin::Rulepack,
                rule_id: "neutral.consumer".to_string(),
                language: bonsai_lang_csharp::LANG_ID.as_str().to_string(),
                file: "Selector.cs".to_string(),
                line: 1,
                column: 1,
                span: consume.span,
                match_text: "Consume".to_string(),
                enclosing_fn: Some("Run".to_string()),
            };
            let tainted_args = [TaintedArgInfo {
                index: 0,
                value_text: if direct { "Choose(input)" } else { "chosen" }.to_string(),
                place: (!direct).then(|| "chosen".to_string()),
                source_names: if direct {
                    vec!["input".to_string()]
                } else {
                    vec!["chosen".to_string()]
                },
            }];
            let graph = ws.cached_resolved_call_graph();
            assert_eq!(
                finite_literal_returning_helper_selection(
                    &ws,
                    graph.as_ref(),
                    FuncId::new(run.symbol.raw()),
                    &file_index,
                    run,
                    &sink,
                    &tainted_args,
                )
                .is_some(),
                expected,
                "helper={helper_body:?}, direct={direct}; run={:#?}; facts={:#?}",
                run.flow_events,
                file_index.finite_literal_selections
            );
        }
    }

    #[test]
    fn finite_literal_selection_requires_every_resolved_pattern_clause() {
        use bonsai_lang_api::LanguageAdapter;

        for (fallback, expected) in [("\"default\"", true), ("Input", false)] {
            let source = format!(
                "-module(selector).\n-export([run/1]).\nchoose(<<\"first\">>) -> \"one\";\nchoose(Input) -> {fallback}.\nconsume(_Value) -> ok.\nrun(Input) -> Chosen = choose(Input), consume(Chosen).\n"
            );
            let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
            let ws = bonsai_testkit::workspace_with(vec![adapter], &[("selector.erl", &source)]);
            let global = ws.db().global_index();
            let run = global
                .all_files()
                .flat_map(|file| global.decls_in(file))
                .find(|decl| decl.name == "run")
                .expect("run declaration");
            let file_index = ws
                .exact_decl_index_shared(run.span.file)
                .expect("Erlang declaration index");
            let mut calls = Vec::new();
            collect_structured_calls(&run.flow_events, &mut calls);
            let consume = calls
                .iter()
                .find(|call| callee_spelling_tail(call.name) == "consume")
                .expect("consumer call");
            let sink = RuleMatch {
                origin: MatchOrigin::Rulepack,
                rule_id: "neutral.consumer".to_string(),
                language: bonsai_lang_erlang::LANG_ID.as_str().to_string(),
                file: "selector.erl".to_string(),
                line: 1,
                column: 1,
                span: consume.span,
                match_text: "consume".to_string(),
                enclosing_fn: Some("run".to_string()),
            };
            let tainted_args = [TaintedArgInfo {
                index: 0,
                value_text: "Chosen".to_string(),
                place: Some("Chosen".to_string()),
                source_names: vec!["Chosen".to_string()],
            }];
            let graph = ws.cached_resolved_call_graph();
            assert_eq!(
                finite_literal_returning_helper_selection(
                    &ws,
                    graph.as_ref(),
                    FuncId::new(run.symbol.raw()),
                    &file_index,
                    run,
                    &sink,
                    &tainted_args,
                )
                .is_some(),
                expected,
                "fallback={fallback:?}; events={:#?}; finite={:#?}",
                run.flow_events,
                file_index.finite_literal_selections
            );
        }
    }

    #[test]
    fn finite_literal_helper_reaches_receiver_transform_sink_argument() {
        use bonsai_lang_api::LanguageAdapter;

        let source = r#"
#include <string>
static const char* choose(const std::string& key) {
  if (key == "first") return "one";
  if (key == "second") return "two";
  return "default";
}
void consume(const char* value) { (void)value; }
void run(const std::string& input) {
  std::string selected = std::string("prefix:") + choose(input);
  consume(selected.c_str());
}
"#;
        let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_cpp::CppAdapter::new());
        let ws = bonsai_testkit::workspace_with(vec![adapter], &[("selector.cpp", source)]);
        let global = ws.db().global_index();
        let run = global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == "run")
            .expect("run declaration");
        let file_index = ws
            .exact_decl_index_shared(run.span.file)
            .expect("C++ declaration index");
        let mut calls = Vec::new();
        collect_structured_calls(&run.flow_events, &mut calls);
        let consume = calls
            .iter()
            .find(|call| callee_spelling_tail(call.name) == "consume")
            .expect("consumer call");
        let sink = RuleMatch {
            origin: MatchOrigin::Rulepack,
            rule_id: "neutral.consumer".to_string(),
            language: bonsai_lang_cpp::LANG_ID.as_str().to_string(),
            file: "selector.cpp".to_string(),
            line: 1,
            column: 1,
            span: consume.span,
            match_text: "consume".to_string(),
            enclosing_fn: Some("run".to_string()),
        };
        let tainted_args = [TaintedArgInfo {
            index: 0,
            value_text: "selected.c_str()".to_string(),
            place: None,
            source_names: vec!["selected".to_string()],
        }];
        let graph = ws.cached_resolved_call_graph();
        let graph_edges = graph
            .callees_of(FuncId::new(run.symbol.raw()))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            finite_literal_returning_helper_selection(
                &ws,
                graph.as_ref(),
                FuncId::new(run.symbol.raw()),
                &file_index,
                run,
                &sink,
                &tainted_args,
            )
            .is_some(),
            "events={:#?}; assignments={:#?}; calls={:#?}; finite={:#?}; edges={:#?}",
            run.flow_events,
            file_index.assignment_values,
            file_index.call_argument_values,
            file_index.finite_literal_selections,
            graph_edges,
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

    #[test]
    fn kotlin_url_reconstruction_requires_all_exact_guard_facts() {
        use bonsai_lang_api::LanguageAdapter;

        let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
        let ws = bonsai_testkit::workspace_with(
            vec![adapter],
            &[(
                "Guard.kt",
                r##"
import java.net.URI
fun consume(value: String) {}

class Service(private val marker: String) {
  fun complete(raw: String) {
    val parsed = URI.create(raw)
    if (parsed.scheme != "https") { throw IllegalArgumentException() }
    val allowed = setOf("one.test", "two.test")
    if (!allowed.contains(parsed.host)) { throw IllegalArgumentException() }
    val rebuilt = "https://${parsed.host}${parsed.path ?: "/"}"
    consume(rebuilt)
  }

  fun missingHostCheck(raw: String) {
    val parsed = URI.create(raw)
    if (parsed.scheme != "https") { throw IllegalArgumentException() }
    val rebuilt = "https://${parsed.host}${parsed.path ?: "/"}"
    consume(rebuilt)
  }
}
"##,
            )],
        );
        let file = ws.db().vfs().all_files()[0];
        let index = ws.db().decl_index(file).expect("Kotlin declaration index");
        let rules_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns");
        let pack = crate::load_rulepack(&rules_root).expect("load rulepack");
        let guard = pack
            .packs
            .get("kotlin")
            .and_then(|pack| {
                pack.sinks
                    .iter()
                    .find(|rule| rule.id == "kotlin.ssrf.play_wsclient_url")
            })
            .and_then(|rule| rule.analysis_semantics.as_ref())
            .and_then(|semantics| semantics.url_reconstruction_guard.as_ref())
            .expect("Kotlin URL reconstruction semantics");

        for (function, expected) in [("complete", true), ("missingHostCheck", false)] {
            let decl = index
                .defs
                .iter()
                .find(|decl| decl.name == function)
                .expect("guard helper declaration");
            let composition = index
                .string_compositions
                .iter()
                .find(|fact| {
                    fact.target.as_deref() == Some("rebuilt") && span_contains(decl.span, fact.container_span)
                })
                .expect("reconstruction composition");
            let result = compiler_proven_url_reconstruction_guard(
                &ws,
                ws.cached_resolved_call_graph().as_ref(),
                UrlReconstructionTarget {
                    function: FuncId::new(decl.symbol.raw()),
                    output_span: Some(composition.container_span),
                },
                guard,
            );
            assert_eq!(
                result.is_some(),
                expected,
                "function={function}; events={:#?}; assignments={:#?}; arguments={:#?}; branches={:#?}; compositions={:#?}",
                decl.flow_events,
                index.assignment_values,
                index.call_argument_values,
                index.branch_conditions,
                index.string_compositions,
            );
        }
    }
}
