//! Receiver field-write / state-source collection and place analysis.
//!
//! Walks flow events to collect `receiver_field_writes` (constructor /
//! method writes into `self`/`this` fields), `receiver_state_sources`
//! (reads of receiver state), assignment targets, and implicit member
//! reads — the facts the IDG uses to thread taint through object fields.
//! Also owns the "place" classification helpers (`argument_place`) that
//! decide whether an argument expression names a storable location.

#[allow(clippy::wildcard_imports)]
use super::*;

#[must_use]
pub fn collect_receiver_field_writes(
    events: &[crate::FlowEvent],
    params: &[String],
    receiver_param_index: Option<usize>,
    implicit_receiver_names: &[&str],
    implicit_receiver_prefixes: &[&str],
) -> Vec<crate::FieldWrite> {
    let param_keys: Vec<Vec<String>> = params.iter().map(|param| name_variants(param)).collect();
    let mut out = Vec::new();
    if let Some(receiver_idx) = receiver_param_index {
        if let Some(receiver_param) = params.get(receiver_idx) {
            collect_receiver_field_writes_inner(
                events,
                &[receiver_param.as_str()],
                &[],
                Some(receiver_idx),
                &param_keys,
                &mut out,
            );
        }
    }
    if !implicit_receiver_names.is_empty() || !implicit_receiver_prefixes.is_empty() {
        collect_receiver_field_writes_inner(
            events,
            implicit_receiver_names,
            implicit_receiver_prefixes,
            None,
            &param_keys,
            &mut out,
        );
    }
    out.sort_by_key(|write| (write.span.start, write.target.clone()));
    out.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
    out
}

fn collect_receiver_field_writes_inner(
    events: &[crate::FlowEvent],
    receiver_names: &[&str],
    receiver_prefixes: &[&str],
    receiver_idx: Option<usize>,
    param_keys: &[Vec<String>],
    out: &mut Vec<crate::FieldWrite>,
) {
    for event in events {
        match event {
            crate::FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call_args,
                source_names,
                ..
            } => {
                if !place_matches_receiver(target, receiver_names, receiver_prefixes) {
                    continue;
                }
                let source_values =
                    assignment_source_values(source_name.as_ref(), source_call_args, source_names);
                let mut source_param_indices = Vec::new();
                for (idx, variants) in param_keys.iter().enumerate() {
                    if receiver_idx == Some(idx) {
                        continue;
                    }
                    if source_values
                        .iter()
                        .any(|source| variants.iter().any(|variant| source == variant))
                    {
                        source_param_indices.push(idx);
                    }
                }
                if !source_param_indices.is_empty() {
                    out.push(crate::FieldWrite {
                        span: *span,
                        target: target.clone(),
                        source_param_indices,
                    });
                }
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_receiver_field_writes_inner(
                    then_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
                collect_receiver_field_writes_inner(
                    else_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                collect_receiver_field_writes_inner(
                    body,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_receiver_field_writes_inner(
                    body,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
                collect_receiver_field_writes_inner(
                    catch_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
                collect_receiver_field_writes_inner(
                    finally_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn place_matches_receiver(place: &str, receiver_names: &[&str], receiver_prefixes: &[&str]) -> bool {
    let trimmed = place.trim_start();
    receiver_names
        .iter()
        .any(|receiver| place_base_matches(place, receiver))
        || receiver_prefixes.iter().any(|prefix| trimmed.starts_with(prefix))
}

pub fn collect_receiver_state_sources(
    events: &[crate::FlowEvent],
    params: &[String],
    implicit_receiver_names: &[&str],
) -> Vec<String> {
    if implicit_receiver_names.is_empty() {
        return Vec::new();
    }
    let mut locals: std::collections::HashSet<String> = params.iter().cloned().collect();
    collect_assign_targets(events, &mut locals);
    let mut out: std::collections::BTreeSet<String> = implicit_receiver_names
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    collect_receiver_state_sources_inner(events, &locals, implicit_receiver_names, &mut out);
    out.into_iter().collect()
}

pub fn collect_assign_targets<S: std::hash::BuildHasher>(
    events: &[crate::FlowEvent],
    out: &mut std::collections::HashSet<String, S>,
) {
    for event in events {
        match event {
            crate::FlowEvent::Assign { target, .. } if !target.is_empty() => {
                out.insert(target.trim().to_string());
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assign_targets(then_events, out);
                collect_assign_targets(else_events, out);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => collect_assign_targets(body, out),
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assign_targets(body, out);
                collect_assign_targets(catch_events, out);
                collect_assign_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

pub struct ImplicitMemberReadCall {
    pub source_call: String,
    pub call_name: String,
    pub receiver: Option<String>,
    pub call_kind: crate::CallKind,
}

pub fn rewrite_implicit_member_reads<F, SG, SL>(
    events: &mut Vec<crate::FlowEvent>,
    getters: &std::collections::HashSet<String, SG>,
    locals: &std::collections::HashSet<String, SL>,
    call_for_name: F,
) where
    F: Fn(&str) -> ImplicitMemberReadCall + Copy,
    SG: std::hash::BuildHasher,
    SL: std::hash::BuildHasher,
{
    for event in events.iter_mut() {
        match event {
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_implicit_member_reads(then_events, getters, locals, call_for_name);
                rewrite_implicit_member_reads(else_events, getters, locals, call_for_name);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                rewrite_implicit_member_reads(body, getters, locals, call_for_name);
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_implicit_member_reads(body, getters, locals, call_for_name);
                rewrite_implicit_member_reads(catch_events, getters, locals, call_for_name);
                rewrite_implicit_member_reads(finally_events, getters, locals, call_for_name);
            }
            _ => {}
        }
    }

    let mut idx = 0usize;
    while idx < events.len() {
        let (qualify_name, span) = match &events[idx] {
            crate::FlowEvent::Assign {
                target,
                source_name,
                source_call,
                span,
                ..
            } => {
                if source_call.is_some() {
                    (None, *span)
                } else if let Some(name) = source_name.as_deref().map(str::trim).map(str::to_string) {
                    if getters.contains(&name) && !locals.contains(&name) && name != target.trim() {
                        (Some(name), *span)
                    } else {
                        (None, *span)
                    }
                } else {
                    (None, *span)
                }
            }
            _ => {
                idx += 1;
                continue;
            }
        };
        let Some(name) = qualify_name else {
            idx += 1;
            continue;
        };
        let call = call_for_name(&name);
        if let crate::FlowEvent::Assign {
            source_name,
            source_call,
            source_call_args,
            source_names,
            value_kind,
            ..
        } = &mut events[idx]
        {
            *source_call = Some(call.source_call.clone());
            *source_call_args = Vec::new();
            *source_name = None;
            source_names.retain(|s| {
                let trimmed = s.trim();
                trimmed != name && trimmed != call.source_call
            });
            *value_kind = Some(crate::AssignValueKind::CallResult);
        }
        events.insert(
            idx,
            crate::FlowEvent::Call {
                span,
                name: call.call_name,
                receiver: call.receiver,
                receiver_types: Vec::new(),
                call_kind: call.call_kind,
                args: Vec::new(),
            },
        );
        idx += 2;
    }
}

fn collect_receiver_state_sources_inner(
    events: &[crate::FlowEvent],
    locals: &std::collections::HashSet<String>,
    implicit_receiver_names: &[&str],
    out: &mut std::collections::BTreeSet<String>,
) {
    for event in events {
        match event {
            crate::FlowEvent::Assign {
                source_name,
                source_names,
                ..
            } => {
                if let Some(source) = source_name {
                    collect_receiver_state_source_name(source, locals, implicit_receiver_names, out);
                }
                for source in source_names {
                    collect_receiver_state_source_name(source, locals, implicit_receiver_names, out);
                }
            }
            crate::FlowEvent::Call { receiver, .. } => {
                if let Some(receiver) = receiver {
                    if implicit_receiver_names
                        .iter()
                        .any(|name| place_base_matches(receiver, name))
                    {
                        out.insert(receiver.clone());
                    }
                }
                if let crate::FlowEvent::Call { args, .. } = event {
                    for arg in args {
                        if let Some(place) = &arg.place {
                            collect_receiver_state_source_name(place, locals, implicit_receiver_names, out);
                        }
                        for source in &arg.source_names {
                            collect_receiver_state_source_name(source, locals, implicit_receiver_names, out);
                        }
                    }
                }
            }
            crate::FlowEvent::Return { value_flow, .. } => {
                collect_receiver_state_expression_flow(value_flow, locals, implicit_receiver_names, out);
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_receiver_state_sources_inner(then_events, locals, implicit_receiver_names, out);
                collect_receiver_state_sources_inner(else_events, locals, implicit_receiver_names, out);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                collect_receiver_state_sources_inner(body, locals, implicit_receiver_names, out);
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_receiver_state_sources_inner(body, locals, implicit_receiver_names, out);
                collect_receiver_state_sources_inner(catch_events, locals, implicit_receiver_names, out);
                collect_receiver_state_sources_inner(finally_events, locals, implicit_receiver_names, out);
            }
            _ => {}
        }
    }
}

fn collect_receiver_state_expression_flow(
    flow: &crate::ExpressionFlow,
    locals: &std::collections::HashSet<String>,
    implicit_receiver_names: &[&str],
    out: &mut std::collections::BTreeSet<String>,
) {
    if let Some(place) = &flow.place {
        collect_receiver_state_source_name(place, locals, implicit_receiver_names, out);
    }
    for source in &flow.source_names {
        collect_receiver_state_source_name(source, locals, implicit_receiver_names, out);
    }
    for field in &flow.aggregate_fields {
        collect_receiver_state_expression_flow(&field.value, locals, implicit_receiver_names, out);
    }
    for item in &flow.tuple_items {
        collect_receiver_state_expression_flow(item, locals, implicit_receiver_names, out);
    }
    for spread in &flow.spreads {
        collect_receiver_state_expression_flow(spread, locals, implicit_receiver_names, out);
    }
}

fn collect_receiver_state_source_name(
    source: &str,
    locals: &std::collections::HashSet<String>,
    implicit_receiver_names: &[&str],
    out: &mut std::collections::BTreeSet<String>,
) {
    let source = source.trim();
    if source.is_empty() || locals.contains(source) {
        return;
    }
    let base_is_local = normalised_place_base(source).is_some_and(|base| locals.contains(&base));
    if implicit_receiver_names
        .iter()
        .any(|name| place_base_matches(source, name))
        || bonsai_common::qualified_name_owner(source).is_none()
        || !base_is_local
    {
        out.insert(source.to_string());
    }
}

pub(crate) fn argument_place(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let text = normalize_call_name_whitespace(node_text(node, src));
    if looks_like_literal_value(node.kind(), &text) {
        return None;
    }
    if !text.is_empty() && argument_node_is_place(node, text.as_str()) && qualified_place_text(&text) {
        return canonical_argument_place(&text);
    }
    if let Some(value) = node.child_by_field_name("value") {
        let text = normalize_call_name_whitespace(node_text(&value, src));
        if looks_like_literal_value(value.kind(), &text) {
            return None;
        }
        if !text.is_empty() && argument_node_is_place(&value, text.as_str()) {
            return canonical_argument_place(&text);
        }
    }
    if text.is_empty() || !argument_node_is_place(node, text.as_str()) {
        return None;
    }
    canonical_argument_place(&text)
}

fn canonical_argument_place(text: &str) -> Option<String> {
    let place = normalise_qualified_text(text);
    // Preserve the adapter-emitted place exactly, including language-owned
    // identifier sigils. Shared consumers compare compiler places through
    // vocabulary-free name normalization when tolerant matching is needed;
    // stripping arbitrary leading punctuation here destroys exact identities
    // such as PHP `$value` and Perl `@items`.
    let place = place.trim();
    (!place.is_empty()).then(|| place.to_string())
}

fn qualified_place_text(text: &str) -> bool {
    bonsai_common::qualified_name_owner(text).is_some()
}

fn argument_node_is_place(node: &Node<'_>, text: &str) -> bool {
    if looks_like_literal_value(node.kind(), text) {
        return false;
    }
    if looks_like_bare_identifier(text) {
        return true;
    }
    if matches!(
        node.kind(),
        "identifier"
            | "variable_name"
            | "var"
            | "varname"
            | "identifier_dollar_escaped"
            | "yul_identifier"
            | "field_identifier"
            | "member_expression"
            | "member_access_expression"
            | "navigation_expression"
            | "attribute"
            | "dot_index_expression"
            | "subscript_expression"
            | "subscript"
            | "element_reference"
            | "array_access"
            | "element_access_expression"
            | "bracket_index_expression"
            | "index_expression"
            | "indexing_expression"
            | "pointer_expression"
            | "unary_expression"
            | "field_expression"
            | "selector_expression"
            | "assignable_selector"
            | "unconditional_assignable_selector"
    ) {
        return true;
    }
    text.trim_start().starts_with(['&', '*'])
}

fn assignment_source_values(
    source_name: Option<&String>,
    source_call_args: &[String],
    source_names: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(source_name) = source_name {
        out.extend(name_variants(source_name));
    }
    for source in source_call_args.iter().chain(source_names.iter()) {
        out.extend(name_variants(source));
    }
    out.sort();
    out.dedup();
    out
}

fn name_variants(name: &str) -> Vec<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let stripped = bonsai_common::trim_leading_name_punctuation(trimmed);
    if stripped == trimmed || stripped.is_empty() {
        vec![trimmed.to_string()]
    } else {
        vec![trimmed.to_string(), stripped.to_string()]
    }
}

fn place_base_matches(place: &str, expected_base: &str) -> bool {
    let Some(base) = normalised_place_base(place) else {
        return false;
    };
    name_variants(expected_base)
        .iter()
        .any(|candidate| candidate == &base)
}

fn normalised_place_base(place: &str) -> Option<String> {
    let place = place.trim();
    if place.is_empty() {
        return None;
    }
    let normalised = normalise_qualified_text(place);
    let base = normalised
        .split('.')
        .next()
        .map(str::trim)
        .filter(|base| !base.is_empty())?;
    Some(base.to_string())
}
