//! Language-neutral rendering for typed flow facts.

use bonsai_common::Span;

use crate::FlowEvent;

/// Render an assignment trace from compiler-owned [`crate::FlowEvent::Assign`]
/// fields without reparsing source text.
#[must_use]
pub fn assignment_trace_message(
    prefix: &str,
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
) -> String {
    match assignment_trace_rhs(source_name, source_call, source_call_args, source_names) {
        Some(rhs) => format!("{prefix} {target} = {rhs}"),
        None => format!("{prefix} {target}"),
    }
}

/// Collect every return span from a function's nested typed flow regions.
pub fn collect_return_spans(events: &[FlowEvent], out: &mut Vec<Span>) {
    for_each_flow_event(events, &mut |event| {
        if let FlowEvent::Return { span, .. } = event {
            out.push(*span);
        }
    });
}

/// Visit every typed flow event in deterministic pre-order, including nested
/// branch, loop, defer, using, and try regions.
pub fn for_each_flow_event<'a>(events: &'a [FlowEvent], visitor: &mut impl FnMut(&'a FlowEvent)) {
    let mut pending = Vec::with_capacity(events.len());
    pending.extend(events.iter().rev());
    while let Some(event) = pending.pop() {
        visitor(event);
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                pending.extend(else_events.iter().rev());
                pending.extend(then_events.iter().rev());
            }
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                pending.extend(update_events.iter().rev());
                pending.extend(body.iter().rev());
                pending.extend(condition_events.iter().rev());
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                pending.extend(body.iter().rev());
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                pending.extend(finally_events.iter().rev());
                pending.extend(catch_events.iter().rev());
                pending.extend(body.iter().rev());
            }
            _ => {}
        }
    }
}

fn assignment_trace_rhs(
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
) -> Option<String> {
    if let Some(name) = source_name.map(str::trim).filter(|name| !name.is_empty()) {
        return Some(name.to_string());
    }
    if let Some(call) = source_call.map(str::trim).filter(|call| !call.is_empty()) {
        return Some(if source_call_args.is_empty() {
            format!("{call}()")
        } else {
            format!("{call}({})", source_call_args.join(", "))
        });
    }
    if !source_names.is_empty() {
        return Some(source_names.join(" + "));
    }
    if !source_call_args.is_empty() {
        return Some(source_call_args.join(", "));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_rendering_prefers_typed_rhs_evidence() {
        assert_eq!(
            assignment_trace_message("assign", "result", Some("input"), None, &[], &[]),
            "assign result = input"
        );
        assert_eq!(
            assignment_trace_message(
                "Assign",
                "result",
                None,
                Some("build"),
                &["left".into(), "right".into()],
                &[]
            ),
            "Assign result = build(left, right)"
        );
        assert_eq!(
            assignment_trace_message("assign", "result", None, None, &[], &[]),
            "assign result"
        );
    }

    #[test]
    fn flow_event_visit_uses_an_explicit_stack_for_deep_compiler_ir() {
        let span = Span::new(bonsai_common::FileId::new(1), 1, 2);
        let mut events = vec![FlowEvent::Return {
            span,
            value_kind: None,
            value_name: None,
            value_text: None,
            value_flow: Default::default(),
        }];
        for _ in 0..4_096 {
            events = vec![FlowEvent::Using { span, body: events }];
        }

        let mut visited = 0usize;
        for_each_flow_event(&events, &mut |_| visited += 1);
        assert_eq!(visited, 4_097);

        // Consume the synthetic recursive owner iteratively as well. Generated
        // enum Drop glue is outside the visitor contract and would otherwise
        // make this test depend on the test harness thread's stack size.
        while let Some(event) = events.pop() {
            if let FlowEvent::Using { body, .. } = event {
                events.extend(body);
            }
        }
    }
}
