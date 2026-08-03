//! Compiler-fact validation for dynamic-key denylist guards.
//!
//! Rulepacks declare constructor, membership, and rejected-value roles.
//! Language adapters decode literals and boolean syntax into typed facts.
//! This module proves only generic control flow; it never parses source text
//! or carries a language/API/value inventory.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::rule::DynamicKeyDenylistGuardSemantics;

pub(super) fn prototype_pollution_sink_is_guarded(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink_rule: &Rule,
    sink: &RuleMatch,
    tainted_call: &TaintedCall,
) -> bool {
    let Some(semantics) = sink_rule
        .analysis_semantics
        .as_ref()
        .and_then(|analysis| analysis.dynamic_key_denylist_guard.as_ref())
    else {
        return false;
    };
    if filtered_property_path_is_guarded(ws, sink, tainted_call, semantics) {
        return true;
    }
    if recursive_dynamic_key_filter_is_guarded(ws, call_graph, sink, tainted_call, semantics) {
        return true;
    }
    if semantics.require_recursive_filter {
        return false;
    }
    let Some(file_index) = ws.exact_decl_index_shared(sink.span.file) else {
        return false;
    };
    let Some(decl) = file_index
        .defs
        .iter()
        .filter(|decl| span_contains(decl.body_span.unwrap_or(decl.span), sink.span))
        .min_by_key(|decl| decl.span.len())
    else {
        return false;
    };
    let Some(call) = find_call_event_at(&decl.flow_events, sink.span) else {
        return false;
    };
    let FlowEvent::Call { span: call_span, .. } = call else {
        return false;
    };
    let key_variables = dynamic_sink_key_variables(call, semantics);
    if key_variables.is_empty() {
        return false;
    }
    let context = DynamicKeyGuardContext {
        file_index: file_index.as_ref(),
        root_events: &decl.flow_events,
        semantics,
        key_variables: &key_variables,
    };
    let mut guarded = false;
    flow_guard_state_at_sink(&decl.flow_events, *call_span, &context, &mut guarded) && guarded
}

fn filtered_property_path_is_guarded(
    ws: &Workspace,
    sink: &RuleMatch,
    tainted_call: &TaintedCall,
    semantics: &DynamicKeyDenylistGuardSemantics,
) -> bool {
    let Some(argument_index) = semantics.sink_key_argument_index else {
        return false;
    };
    if !tainted_call
        .tainted_args
        .iter()
        .any(|argument| argument.index == argument_index)
    {
        return false;
    }
    let Some(file_index) = ws.exact_decl_index_shared(sink.span.file) else {
        return false;
    };
    let Some(decl) = file_index
        .defs
        .iter()
        .filter(|decl| span_contains(decl.body_span.unwrap_or(decl.span), sink.span))
        .min_by_key(|decl| decl.span.len())
    else {
        return false;
    };
    let Some(call) = find_call_event_at(&decl.flow_events, sink.span) else {
        return false;
    };
    let FlowEvent::Call { args, .. } = call else {
        return false;
    };
    let Some(argument) = args.get(argument_index) else {
        return false;
    };
    let output_places = call_arg_target_keys(argument);
    if output_places.is_empty() {
        return false;
    }
    file_index.dynamic_key_filters.iter().any(|fact| {
        fact.function_span == decl.span
            && !fact.recursive
            && fact.guard_span.end <= sink.span.start
            && fact
                .output_place
                .as_deref()
                .is_some_and(|output| output_places.iter().any(|place| place == output))
            && rule_target_matches_call(
                &fact.collection_constructor,
                &[],
                &semantics.collection_constructor,
            )
            && rule_target_matches_call(&fact.membership_check, &[], &semantics.membership_check)
            && exact_string_sets_equal(&fact.rejected_exact_values, &semantics.rejected_exact_values)
            && branch_then_events_with_span(&decl.flow_events, fact.guard_span)
                .is_some_and(prototype_guard_arm_abruptly_exits)
    })
}

fn branch_then_events_with_span(events: &[FlowEvent], wanted: Span) -> Option<&[FlowEvent]> {
    for event in events {
        match event {
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                if *span == wanted {
                    return condition.as_ref().map(|_| then_events.as_slice());
                }
                if let Some(branch) = branch_then_events_with_span(then_events, wanted)
                    .or_else(|| branch_then_events_with_span(else_events, wanted))
                {
                    return Some(branch);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(branch) = branch_then_events_with_span(body, wanted) {
                    return Some(branch);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(branch) = branch_then_events_with_span(body, wanted)
                    .or_else(|| branch_then_events_with_span(catch_events, wanted))
                    .or_else(|| branch_then_events_with_span(finally_events, wanted))
                {
                    return Some(branch);
                }
            }
            _ => {}
        }
    }
    None
}

fn prototype_guard_arm_abruptly_exits(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return { .. } | FlowEvent::Throw { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            !else_events.is_empty()
                && prototype_guard_arm_abruptly_exits(then_events)
                && prototype_guard_arm_abruptly_exits(else_events)
        }
        FlowEvent::Try {
            body, finally_events, ..
        } => prototype_guard_arm_abruptly_exits(body) || prototype_guard_arm_abruptly_exits(finally_events),
        _ => false,
    })
}

fn recursive_dynamic_key_filter_is_guarded(
    ws: &Workspace,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    sink: &RuleMatch,
    tainted_call: &TaintedCall,
    semantics: &DynamicKeyDenylistGuardSemantics,
) -> bool {
    let Some(argument_index) = semantics.filtered_value_argument_index else {
        return false;
    };
    if !tainted_call
        .tainted_args
        .iter()
        .any(|argument| argument.index == argument_index)
    {
        return false;
    }
    let Some(file_index) = ws.exact_decl_index_shared(sink.span.file) else {
        return false;
    };
    let Some(argument) = bonsai_lang_api::call_argument_value_fact(
        &file_index.call_argument_values,
        tainted_call.call_span,
        argument_index,
    ) else {
        return false;
    };
    let Some(helper_call_span) = argument.direct_call_span else {
        return false;
    };
    if argument.value_flow.place.is_some()
        || argument.value_flow.projection.is_some()
        || !argument.value_flow.aggregate_fields.is_empty()
        || !argument.value_flow.tuple_items.is_empty()
        || !argument.value_flow.spreads.is_empty()
    {
        return false;
    }

    let targets: AHashSet<_> = call_graph
        .callees_of(tainted_call.caller)
        .filter(|edge| edge.precision.is_semantic() && edge.span == helper_call_span)
        .map(|edge| edge.to)
        .collect();
    let mut targets = targets.into_iter();
    let Some(helper) = targets.next() else {
        return false;
    };
    if targets.next().is_some() {
        return false;
    }
    let Some(decl) = ws.exact_decl(SymbolId::new(helper.raw())) else {
        return false;
    };
    let Some(helper_index) = ws.exact_decl_index_shared(decl.span.file) else {
        return false;
    };
    helper_index.dynamic_key_filters.iter().any(|fact| {
        fact.function_span == decl.span
            && fact.input_param_index < decl.params.len()
            && (!semantics.require_recursive_filter || fact.recursive)
            && rule_target_matches_call(
                &fact.collection_constructor,
                &[],
                &semantics.collection_constructor,
            )
            && rule_target_matches_call(&fact.membership_check, &[], &semantics.membership_check)
            && exact_string_sets_equal(&fact.rejected_exact_values, &semantics.rejected_exact_values)
    })
}

fn dynamic_sink_key_variables(
    call: &FlowEvent,
    semantics: &DynamicKeyDenylistGuardSemantics,
) -> AHashSet<String> {
    let FlowEvent::Call { name, args, .. } = call else {
        return AHashSet::new();
    };
    if let Some(index) = semantics.sink_key_argument_index {
        return args
            .get(index)
            .into_iter()
            .flat_map(call_arg_target_keys)
            .collect();
    }
    if clean_overwrite_callee_tail(name) == "__setitem__" {
        return args
            .first()
            .into_iter()
            .flat_map(|arg| arg.place.iter().chain(arg.source_names.iter()))
            .filter_map(|name| simple_place_key(name))
            .collect();
    }

    // Recursive merge rules require two indexed arguments. The adapters
    // expose the index operand as the one simple source name shared by both
    // expressions; bases and normalized projections are excluded.
    let mut occurrences: AHashMap<String, usize> = AHashMap::new();
    for arg in args {
        let Some(place) = arg.place.as_deref() else {
            continue;
        };
        let Some((base, _projection)) = place.split_once('.') else {
            continue;
        };
        let base = simple_place_key(base);
        let mut seen = AHashSet::new();
        for source in &arg.source_names {
            let Some(source) = simple_place_key(source) else {
                continue;
            };
            if Some(source.as_str()) == base.as_deref() || !seen.insert(source.clone()) {
                continue;
            }
            *occurrences.entry(source).or_default() += 1;
        }
    }
    occurrences
        .into_iter()
        .filter_map(|(name, count)| (count >= 1).then_some(name))
        .collect()
}

fn simple_place_key(text: &str) -> Option<String> {
    let key = clean_overwrite_target_key(text)?;
    (!key.contains('.')).then_some(key)
}

struct DynamicKeyGuardContext<'a> {
    file_index: &'a bonsai_lang_api::DeclIndex,
    root_events: &'a [FlowEvent],
    semantics: &'a DynamicKeyDenylistGuardSemantics,
    key_variables: &'a AHashSet<String>,
}

fn flow_guard_state_at_sink(
    events: &[FlowEvent],
    sink_span: Span,
    context: &DynamicKeyGuardContext<'_>,
    guarded: &mut bool,
) -> bool {
    for event in events {
        if event.span() == sink_span {
            return true;
        }
        match event {
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } if flow_events_have_exact_span(then_events, sink_span)
                || flow_events_have_exact_span(else_events, sink_span) =>
            {
                let in_then = flow_events_have_exact_span(then_events, sink_span);
                let target_events = if in_then { then_events } else { else_events };
                if branch_safe_arms(*span, context).is_some_and(|safe| {
                    if in_then {
                        safe.then_safe
                    } else {
                        safe.else_safe
                    }
                }) {
                    *guarded = true;
                }
                return flow_guard_state_at_sink(target_events, sink_span, context, guarded);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. }
                if flow_events_have_exact_span(body, sink_span) =>
            {
                return flow_guard_state_at_sink(body, sink_span, context, guarded);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                for nested in [
                    body.as_slice(),
                    catch_events.as_slice(),
                    finally_events.as_slice(),
                ] {
                    if flow_events_have_exact_span(nested, sink_span) {
                        return flow_guard_state_at_sink(nested, sink_span, context, guarded);
                    }
                }
            }
            _ => {}
        }
        if event.span().start < sink_span.start {
            apply_guard_event(event, context, guarded);
        }
    }
    false
}

fn flow_events_have_exact_span(events: &[FlowEvent], target: Span) -> bool {
    events.iter().any(|event| {
        event.span() == target
            || match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    flow_events_have_exact_span(then_events, target)
                        || flow_events_have_exact_span(else_events, target)
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => flow_events_have_exact_span(body, target),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    flow_events_have_exact_span(body, target)
                        || flow_events_have_exact_span(catch_events, target)
                        || flow_events_have_exact_span(finally_events, target)
                }
                _ => false,
            }
    })
}

fn apply_guard_events(events: &[FlowEvent], context: &DynamicKeyGuardContext<'_>, guarded: &mut bool) {
    for event in events {
        apply_guard_event(event, context, guarded);
    }
}

fn apply_guard_event(event: &FlowEvent, context: &DynamicKeyGuardContext<'_>, guarded: &mut bool) {
    match event {
        FlowEvent::Branch {
            span,
            then_events,
            else_events,
            ..
        } => {
            let safe = branch_safe_arms(*span, context).unwrap_or_default();
            let mut then_guarded = *guarded || safe.then_safe;
            apply_guard_events(then_events, context, &mut then_guarded);
            let mut else_guarded = *guarded || safe.else_safe;
            apply_guard_events(else_events, context, &mut else_guarded);
            *guarded = (events_guarantee_abrupt_exit(then_events) || then_guarded)
                && (events_guarantee_abrupt_exit(else_events) || else_guarded);
        }
        FlowEvent::Loop { .. } | FlowEvent::Defer { .. } => {
            // These regions are not guaranteed to execute before a later sink.
        }
        FlowEvent::Using { body, .. } => apply_guard_events(body, context, guarded),
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            let mut body_guarded = *guarded;
            apply_guard_events(body, context, &mut body_guarded);
            let mut catch_guarded = *guarded;
            apply_guard_events(catch_events, context, &mut catch_guarded);
            *guarded = (events_guarantee_abrupt_exit(body) || body_guarded)
                && (events_guarantee_abrupt_exit(catch_events) || catch_guarded);
            apply_guard_events(finally_events, context, guarded);
        }
        _ => {}
    }
}

fn events_guarantee_abrupt_exit(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Continue { .. } | FlowEvent::Return { .. } | FlowEvent::Throw { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            !else_events.is_empty()
                && events_guarantee_abrupt_exit(then_events)
                && events_guarantee_abrupt_exit(else_events)
        }
        FlowEvent::Using { body, .. } => events_guarantee_abrupt_exit(body),
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            events_guarantee_abrupt_exit(finally_events)
                || (events_guarantee_abrupt_exit(body) && events_guarantee_abrupt_exit(catch_events))
        }
        _ => false,
    })
}

#[derive(Copy, Clone, Debug, Default)]
struct SafeArms {
    then_safe: bool,
    else_safe: bool,
}

fn branch_safe_arms(branch_span: Span, context: &DynamicKeyGuardContext<'_>) -> Option<SafeArms> {
    let fact = branch_condition_fact_for_span(&context.file_index.branch_conditions, branch_span)?;
    let expression = fact.expression.as_ref()?;
    let membership_atoms = exact_membership_atom_spans(fact, expression, context);
    let rejected = &context.semantics.rejected_exact_values;
    if rejected.is_empty() {
        return None;
    }
    let evaluations: Vec<_> = rejected
        .iter()
        .map(|value| evaluate_condition(expression, value, context.key_variables, &membership_atoms))
        .collect();
    Some(SafeArms {
        then_safe: evaluations.iter().all(|value| *value == TruthValue::False),
        else_safe: evaluations.iter().all(|value| *value == TruthValue::True),
    })
}

fn exact_membership_atom_spans(
    fact: &BranchConditionFact,
    expression: &ConditionExpressionFact,
    context: &DynamicKeyGuardContext<'_>,
) -> AHashSet<Span> {
    let mut calls = Vec::new();
    collect_calls_in_span(context.root_events, fact.condition_span, &mut calls);
    calls
        .into_iter()
        .filter_map(|call| {
            let FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                args,
                ..
            } = call
            else {
                return None;
            };
            if !rule_target_matches_call(name, receiver_types, &context.semantics.membership_check) {
                return None;
            }
            let subject = args.get(context.semantics.membership_subject_arg_index)?;
            if !call_arg_mentions_key(subject, context.key_variables) {
                return None;
            }
            let collection = receiver.as_deref().and_then(clean_overwrite_target_key)?;
            if !collection_is_exact_denylist(&collection, fact.branch_span, context) {
                return None;
            }
            condition_atom_containing(expression, *span)
        })
        .collect()
}

fn collect_calls_in_span<'a>(events: &'a [FlowEvent], wanted: Span, out: &mut Vec<&'a FlowEvent>) {
    for event in events {
        if let FlowEvent::Call { span, .. } = event {
            if span_contains(wanted, *span) {
                out.push(event);
            }
        }
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls_in_span(then_events, wanted, out);
                collect_calls_in_span(else_events, wanted, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls_in_span(body, wanted, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls_in_span(body, wanted, out);
                collect_calls_in_span(catch_events, wanted, out);
                collect_calls_in_span(finally_events, wanted, out);
            }
            _ => {}
        }
    }
}

fn call_arg_mentions_key(arg: &bonsai_lang_api::CallArg, key_variables: &AHashSet<String>) -> bool {
    arg.place
        .iter()
        .chain(arg.source_names.iter())
        .filter_map(|name| simple_place_key(name))
        .any(|name| key_variables.contains(&name))
}

fn collection_is_exact_denylist(
    collection: &str,
    before: Span,
    context: &DynamicKeyGuardContext<'_>,
) -> bool {
    context
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
                    == Some(collection)
        })
        .next_back()
        .is_some_and(|assignment| {
            assignment.direct_call_name.as_deref().is_some_and(|callee| {
                rule_target_matches_call(callee, &[], &context.semantics.collection_constructor)
            }) && context.file_index.call_argument_values.iter().any(|argument| {
                argument.argument_index == context.semantics.collection_values_arg_index
                    && span_contains(assignment.value_span, argument.call_span)
                    && exact_literal_values_for_argument(context.file_index, argument).is_some_and(|values| {
                        exact_string_sets_equal(&values, &context.semantics.rejected_exact_values)
                    })
            })
        })
}

fn exact_literal_values_for_argument(
    file_index: &bonsai_lang_api::DeclIndex,
    argument: &bonsai_lang_api::CallArgumentValueFact,
) -> Option<Vec<String>> {
    let flow = &argument.value_flow;
    if flow.tuple_items.is_empty()
        || !flow.aggregate_fields.is_empty()
        || !flow.spreads.is_empty()
        || !flow.tuple_items.iter().all(expression_flow_is_literal)
    {
        return None;
    }
    let values: Vec<_> = file_index
        .strings
        .iter()
        .filter(|literal| span_contains(argument.argument_span, literal.span))
        .filter_map(|literal| literal.static_value.clone())
        .collect();
    (values.len() == flow.tuple_items.len()).then_some(values)
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

fn exact_string_sets_equal(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn condition_atom_containing(expression: &ConditionExpressionFact, target: Span) -> Option<Span> {
    match expression {
        ConditionExpressionFact::Atom { span } | ConditionExpressionFact::TypeTest { span, .. } => {
            span_contains(*span, target).then_some(*span)
        }
        ConditionExpressionFact::Not { operand, .. } => condition_atom_containing(operand, target),
        ConditionExpressionFact::All { operands, .. } | ConditionExpressionFact::Any { operands, .. } => {
            operands
                .iter()
                .filter_map(|operand| condition_atom_containing(operand, target))
                .min_by_key(|span| span.len())
        }
        ConditionExpressionFact::Equality { .. } | ConditionExpressionFact::Membership { .. } => None,
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TruthValue {
    True,
    False,
    Unknown,
}

fn evaluate_condition(
    expression: &ConditionExpressionFact,
    rejected_value: &str,
    key_variables: &AHashSet<String>,
    membership_atoms: &AHashSet<Span>,
) -> TruthValue {
    match expression {
        ConditionExpressionFact::Atom { span } => {
            if membership_atoms.contains(span) {
                TruthValue::True
            } else {
                TruthValue::Unknown
            }
        }
        ConditionExpressionFact::Not { operand, .. } => invert_truth(evaluate_condition(
            operand,
            rejected_value,
            key_variables,
            membership_atoms,
        )),
        ConditionExpressionFact::All { operands, .. } => {
            let mut saw_unknown = false;
            for operand in operands {
                match evaluate_condition(operand, rejected_value, key_variables, membership_atoms) {
                    TruthValue::False => return TruthValue::False,
                    TruthValue::Unknown => saw_unknown = true,
                    TruthValue::True => {}
                }
            }
            if saw_unknown {
                TruthValue::Unknown
            } else {
                TruthValue::True
            }
        }
        ConditionExpressionFact::Any { operands, .. } => {
            let mut saw_unknown = false;
            for operand in operands {
                match evaluate_condition(operand, rejected_value, key_variables, membership_atoms) {
                    TruthValue::True => return TruthValue::True,
                    TruthValue::Unknown => saw_unknown = true,
                    TruthValue::False => {}
                }
            }
            if saw_unknown {
                TruthValue::Unknown
            } else {
                TruthValue::False
            }
        }
        ConditionExpressionFact::Equality {
            relation,
            left,
            right,
            ..
        } => evaluate_key_literal_equality(*relation, left, right, rejected_value, key_variables)
            .or_else(|| evaluate_key_literal_equality(*relation, right, left, rejected_value, key_variables))
            .unwrap_or(TruthValue::Unknown),
        ConditionExpressionFact::Membership { .. } | ConditionExpressionFact::TypeTest { .. } => {
            TruthValue::Unknown
        }
    }
}

fn evaluate_key_literal_equality(
    relation: ConditionEquality,
    key: &ConditionOperandFact,
    literal: &ConditionOperandFact,
    rejected_value: &str,
    key_variables: &AHashSet<String>,
) -> Option<TruthValue> {
    if !condition_operand_mentions_key(key, key_variables) {
        return None;
    }
    let literal = literal.static_string.as_deref()?;
    let equal = literal == rejected_value;
    Some(match (relation, equal) {
        (ConditionEquality::Equal, true) | (ConditionEquality::NotEqual, false) => TruthValue::True,
        (ConditionEquality::Equal, false) | (ConditionEquality::NotEqual, true) => TruthValue::False,
    })
}

fn condition_operand_mentions_key(operand: &ConditionOperandFact, key_variables: &AHashSet<String>) -> bool {
    operand
        .value_flow
        .place
        .iter()
        .chain(operand.value_flow.source_names.iter())
        .filter_map(|name| simple_place_key(name))
        .any(|name| key_variables.contains(&name))
}

fn invert_truth(value: TruthValue) -> TruthValue {
    match value {
        TruthValue::True => TruthValue::False,
        TruthValue::False => TruthValue::True,
        TruthValue::Unknown => TruthValue::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::CallArg;

    fn span(start: u64, end: u64) -> Span {
        Span::new(FileId::new(0), start, end)
    }

    fn operand(name: Option<&str>, literal: Option<&str>) -> ConditionOperandFact {
        ConditionOperandFact {
            span: span(0, 1),
            value_flow: name
                .map(bonsai_lang_api::ExpressionFlow::from_place)
                .unwrap_or_default(),
            static_string: literal.map(str::to_string),
            static_value: literal.map(|value| bonsai_lang_api::StaticScalarValue::String(value.to_string())),
        }
    }

    fn recursive_call_arg(place: &str, source_names: &[&str]) -> CallArg {
        CallArg {
            span: span(0, 1),
            passing_mode: bonsai_lang_api::ArgumentPassingMode::Value,
            name: None,
            value_text: String::new(),
            place: Some(place.to_string()),
            source_names: source_names.iter().map(|name| (*name).to_string()).collect(),
        }
    }

    #[test]
    fn recursive_call_uses_projected_argument_index_as_dynamic_key() {
        let call = FlowEvent::Call {
            span: span(0, 1),
            name: "merge".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![
                recursive_call_arg("target.key", &["target", "key", "target.key"]),
                recursive_call_arg("source.key", &["source", "key", "source.key"]),
            ],
        };
        let semantics = DynamicKeyDenylistGuardSemantics {
            collection_constructor: Default::default(),
            membership_check: Default::default(),
            membership_subject_arg_index: 0,
            collection_values_arg_index: 0,
            rejected_exact_values: vec![
                "__proto__".to_string(),
                "constructor".to_string(),
                "prototype".to_string(),
            ],
            sink_key_argument_index: None,
            require_recursive_filter: false,
            filtered_value_argument_index: None,
        };

        assert_eq!(
            dynamic_sink_key_variables(&call, &semantics),
            AHashSet::from_iter(["key".to_string()])
        );
    }

    #[test]
    fn typed_disjunction_excludes_every_declared_rejected_value() {
        let rejected = ["__proto__", "constructor", "prototype"];
        let expression = ConditionExpressionFact::Any {
            span: span(0, 30),
            operands: rejected
                .iter()
                .enumerate()
                .map(|(index, value)| ConditionExpressionFact::Equality {
                    span: span(index as u64, index as u64 + 1),
                    relation: ConditionEquality::Equal,
                    left: operand(Some("key"), None),
                    right: operand(None, Some(value)),
                })
                .collect(),
        };
        let keys = AHashSet::from_iter(["key".to_string()]);
        let atoms = AHashSet::new();

        assert!(rejected
            .iter()
            .all(|value| { evaluate_condition(&expression, value, &keys, &atoms) == TruthValue::True }));
    }

    #[test]
    fn unknown_conjunct_does_not_claim_a_safe_false_arm() {
        let membership_span = span(1, 2);
        let expression = ConditionExpressionFact::All {
            span: span(0, 4),
            operands: vec![
                ConditionExpressionFact::Atom {
                    span: membership_span,
                },
                ConditionExpressionFact::Atom { span: span(3, 4) },
            ],
        };
        let keys = AHashSet::from_iter(["key".to_string()]);
        let atoms = AHashSet::from_iter([membership_span]);

        assert_eq!(
            evaluate_condition(&expression, "__proto__", &keys, &atoms),
            TruthValue::Unknown
        );
    }
}
