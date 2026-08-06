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
    for event in events {
        visitor(event);
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                for_each_flow_event(then_events, visitor);
                for_each_flow_event(else_events, visitor);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                for_each_flow_event(body, visitor);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                for_each_flow_event(body, visitor);
                for_each_flow_event(catch_events, visitor);
                for_each_flow_event(finally_events, visitor);
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
}
