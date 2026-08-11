//! Call-result assignment source normalization.
//!
//! Normalizes `target = callee(args...)` assignment facts so dataflow
//! crosses the call edge instead of also treating the callee and
//! argument tokens as direct assignment RHS carriers, which fabricates
//! self-loop / overtainted chains.

/// Normalize `target = callee(args...)` assignment facts so dataflow
/// crosses the call edge instead of also treating the callee and
/// argument tokens as direct assignment RHS carriers.
///
/// Adapters often synthesize call-result assignments from a broad CST
/// expression node, which can leave `source_name = Some(callee)` and
/// `source_names = [callee, arg, ...]`. That duplicates the
/// source-to-target path and can fabricate self-loop or overtainted
/// chains. Keep semantic receiver tokens because method receivers can be
/// data-bearing (`target.call(payload)`), but always remove the callee tail.
/// Capitalization is not static/type evidence.
pub fn normalize_call_result_assignment_sources(events: &mut [crate::FlowEvent]) {
    for event_index in 0..events.len() {
        let adjacent_call_args = adjacent_call_args_for_call_result_assignment(events, event_index);
        match &mut events[event_index] {
            crate::FlowEvent::Assign {
                source_name,
                source_call: Some(source_call),
                source_call_args,
                source_names,
                ..
            } => {
                if !adjacent_call_args.is_empty()
                    && (source_call_args.is_empty() || adjacent_call_args.len() > source_call_args.len())
                {
                    *source_call_args = adjacent_call_args;
                }
                *source_name = None;
                prune_call_result_source_names(source_call, source_call_args, source_names);
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_call_result_assignment_sources(then_events);
                normalize_call_result_assignment_sources(else_events);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                normalize_call_result_assignment_sources(body);
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_call_result_assignment_sources(body);
                normalize_call_result_assignment_sources(catch_events);
                normalize_call_result_assignment_sources(finally_events);
            }
            _ => {}
        }
    }
}

fn adjacent_call_args_for_call_result_assignment(
    events: &[crate::FlowEvent],
    event_index: usize,
) -> Vec<String> {
    let Some(crate::FlowEvent::Assign {
        source_call: Some(source_call),
        source_call_args,
        span: assign_span,
        ..
    }) = events.get(event_index)
    else {
        return Vec::new();
    };

    events
        .iter()
        .skip(event_index + 1)
        .find_map(|event| match event {
            crate::FlowEvent::Call { name, args, span, .. }
                if call_result_names_match(source_call, name)
                    && span.file == assign_span.file
                    && span.start >= assign_span.start
                    && span.end <= assign_span.end
                    && !args.is_empty()
                    && (source_call_args.is_empty() || args.len() > source_call_args.len()) =>
            {
                Some(args.iter().map(|arg| arg.value_text.clone()).collect())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn prune_call_result_source_names(
    source_call: &str,
    source_call_args: &[String],
    source_names: &mut Vec<String>,
) {
    let call = source_call.trim();
    if call.is_empty() {
        return;
    }
    let receiver_and_tail = call_receiver_and_tail(call);
    let arg_texts = source_call_args
        .iter()
        .map(|arg| arg.trim())
        .filter(|arg| !arg.is_empty())
        .collect::<Vec<_>>();
    let arg_identifiers = source_call_args
        .iter()
        .flat_map(|arg| call_result_identifier_tokens(arg))
        .collect::<Vec<_>>();

    source_names.retain(|name| {
        let name = name.trim();
        if name.is_empty()
            || name == call
            || arg_texts
                .iter()
                .any(|arg| call_result_identifier_names_match(arg, name))
        {
            return false;
        }
        let Some((receiver, tail)) = receiver_and_tail else {
            return !arg_identifiers
                .iter()
                .any(|arg| call_result_identifier_names_match(arg, name));
        };
        if name == receiver {
            return true;
        }
        if name == tail {
            return false;
        }
        !arg_identifiers
            .iter()
            .any(|arg| call_result_identifier_names_match(arg, name))
    });
    dedup_call_result_source_names(source_names);
}

fn call_result_identifier_names_match(left: &str, right: &str) -> bool {
    let left = left.trim().trim_start_matches(bonsai_common::is_name_punctuation);
    let right = right
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    !left.is_empty() && left == right
}

fn call_result_names_match(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    if left == right {
        return true;
    }
    call_result_short_tail(left) == call_result_short_tail(right)
}

fn call_receiver_and_tail(call: &str) -> Option<(&str, &str)> {
    let receiver = bonsai_common::qualified_name_owner(call)?.trim();
    let tail = bonsai_common::short_qualified_tail(call).trim();
    if receiver.is_empty() || tail.is_empty() {
        return None;
    }
    Some((receiver, tail))
}

fn call_result_short_tail(name: &str) -> &str {
    bonsai_common::short_qualified_tail(name).trim()
}

fn call_result_identifier_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            push_unique_call_result_identifier(&mut out, &current);
            current.clear();
        }
    }
    if !current.is_empty() {
        push_unique_call_result_identifier(&mut out, &current);
    }
    out
}

fn push_unique_call_result_identifier(out: &mut Vec<String>, token: &str) {
    if token
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && !out.iter().any(|existing| existing == token)
    {
        out.push(token.to_string());
    }
}

fn dedup_call_result_source_names(source_names: &mut Vec<String>) {
    let mut seen = Vec::<String>::new();
    source_names.retain(|name| {
        if seen.iter().any(|existing| existing == name) {
            false
        } else {
            seen.push(name.clone());
            true
        }
    });
}
