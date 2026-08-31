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
        let adjacent_call = adjacent_call_evidence_for_call_result_assignment(events, event_index);
        match &mut events[event_index] {
            crate::FlowEvent::Assign {
                source_name,
                source_call: Some(source_call),
                source_call_args,
                source_names,
                ..
            } => {
                if let Some(adjacent_call) = adjacent_call.as_ref() {
                    if !adjacent_call.renderings.is_empty()
                        && (source_call_args.is_empty()
                            || adjacent_call.renderings.len() > source_call_args.len())
                    {
                        source_call_args.clone_from(&adjacent_call.renderings);
                    }
                }
                *source_name = None;
                prune_call_result_source_names(
                    source_call,
                    adjacent_call
                        .as_ref()
                        .map_or(&[][..], |evidence| evidence.semantic_sources.as_slice()),
                    source_names,
                );
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_call_result_assignment_sources(then_events);
                normalize_call_result_assignment_sources(else_events);
            }
            crate::FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                normalize_call_result_assignment_sources(condition_events);
                normalize_call_result_assignment_sources(body);
                normalize_call_result_assignment_sources(update_events);
            }
            crate::FlowEvent::Defer { body, .. } | crate::FlowEvent::Using { body, .. } => {
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

#[derive(Default)]
struct AdjacentCallEvidence {
    /// Rendering retained only for legacy trace/output compatibility.
    renderings: Vec<String>,
    /// Exact value identities lowered from the argument CST.
    semantic_sources: Vec<String>,
}

fn adjacent_call_evidence_for_call_result_assignment(
    events: &[crate::FlowEvent],
    event_index: usize,
) -> Option<AdjacentCallEvidence> {
    let Some(crate::FlowEvent::Assign {
        source_call: Some(source_call),
        span: assign_span,
        ..
    }) = events.get(event_index)
    else {
        return None;
    };

    events.iter().skip(event_index + 1).find_map(|event| match event {
        crate::FlowEvent::Call { name, args, span, .. }
            if call_result_names_match(source_call, name)
                && span.file == assign_span.file
                && span.start >= assign_span.start
                && span.end <= assign_span.end
                && !args.is_empty() =>
        {
            let mut semantic_sources = Vec::new();
            for argument in args {
                if let Some(place) = argument.place.as_deref() {
                    push_unique_call_result_source(&mut semantic_sources, place);
                }
                for source in &argument.source_names {
                    push_unique_call_result_source(&mut semantic_sources, source);
                }
            }
            Some(AdjacentCallEvidence {
                renderings: args.iter().map(|arg| arg.value_text.clone()).collect(),
                semantic_sources,
            })
        }
        _ => None,
    })
}

fn prune_call_result_source_names(
    source_call: &str,
    exact_argument_sources: &[String],
    source_names: &mut Vec<String>,
) {
    let call = source_call.trim();
    if call.is_empty() {
        return;
    }
    let receiver_and_tail = call_receiver_and_tail(call);
    source_names.retain(|name| {
        let name = name.trim();
        if name.is_empty()
            || name == call
            || exact_argument_sources
                .iter()
                .any(|arg| call_result_identifier_names_match(arg, name))
        {
            return false;
        }
        let Some((receiver, tail)) = receiver_and_tail else {
            return true;
        };
        if name == receiver {
            return true;
        }
        if name == tail {
            return false;
        }
        true
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

fn push_unique_call_result_source(out: &mut Vec<String>, source: &str) {
    let source = source.trim();
    if source.is_empty() {
        return;
    }
    for candidate in std::iter::once(source).chain(bonsai_common::qualified_name_segments(source)) {
        let candidate = candidate.trim();
        if !candidate.is_empty() && !out.iter().any(|existing| existing == candidate) {
            out.push(candidate.to_string());
        }
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
