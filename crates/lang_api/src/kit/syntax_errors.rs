//! Syntax-error gating and oversized-literal skip heuristics.
//!
//! Flow facts must come only from syntactically correct code: a
//! recovered parse can mis-scope reads, writes, and calls, so events
//! overlapping ERROR/MISSING spans are dropped. Also detects huge
//! embedded data-literal initializers that are safe to skip walking.

#[allow(clippy::wildcard_imports)]
use super::*;

/// True when this callable's syntax is broken — its node (or detached
/// body, for split signature/body grammars) contains an ERROR or
/// MISSING node. Flow facts must come only from syntactically correct
/// code: a recovered parse can mis-scope reads, writes, and calls, so a
/// broken callable contributes NO flow events (its decl is still
/// indexed for browsing). `has_error` is the tree-sitter subtree flag —
/// it covers MISSING nodes too and is O(1).
pub(super) fn callable_has_syntax_error(node: &Node<'_>, body_node: Option<&Node<'_>>) -> bool {
    node.has_error() || body_node.is_some_and(tree_sitter::Node::has_error)
}

/// True when `span` overlaps any of `error_spans`. Zero-width MISSING
/// spans (`start == end`) are treated as touching either side.
fn span_overlaps_error(span: Span, error_spans: &[Span]) -> bool {
    error_spans.iter().any(|err| {
        if err.start == err.end {
            span.start <= err.start && err.start <= span.end
        } else {
            span.start < err.end && err.start < span.end
        }
    })
}

/// Drop the LEAF flow events whose span falls inside a recovered
/// ERROR / MISSING span, while keeping control-flow containers and
/// recursing into their bodies. A container's span covers its whole
/// extent, so filtering it by its own span would discard valid
/// children — instead we keep the container and prune only the leaf
/// events (calls, assigns, returns, …) that the error actually
/// mis-scopes. This preserves flows from the correctly-parsed parts of
/// a callable that has one localized parse error.
pub(super) fn retain_flow_events_outside_errors(
    events: &mut Vec<FlowEvent>,
    error_spans: &[Span],
    tolerant_call_names: &[&str],
) {
    events.retain_mut(|event| match event {
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            retain_flow_events_outside_errors(then_events, error_spans, tolerant_call_names);
            retain_flow_events_outside_errors(else_events, error_spans, tolerant_call_names);
            true
        }
        FlowEvent::Loop { body, .. } => {
            retain_flow_events_outside_errors(body, error_spans, tolerant_call_names);
            true
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            retain_flow_events_outside_errors(body, error_spans, tolerant_call_names);
            retain_flow_events_outside_errors(catch_events, error_spans, tolerant_call_names);
            retain_flow_events_outside_errors(finally_events, error_spans, tolerant_call_names);
            true
        }
        FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            retain_flow_events_outside_errors(body, error_spans, tolerant_call_names);
            true
        }
        // An adapter may declare a call whose type-metadata operand is a
        // known Tree-sitter recovery error. Its value operand still parses
        // cleanly, so retain that assignment without teaching this shared
        // filter the builtin spelling.
        leaf @ FlowEvent::Assign { .. } if assign_uses_tolerated_call(leaf, tolerant_call_names) => true,
        leaf => !span_overlaps_error(leaf.span(), error_spans),
    });
}

/// True when an assignment invokes one of the active adapter's explicitly
/// tolerated calls. These are exempt from error-span pruning only because the
/// adapter has proven that the damaged operand is non-value syntax.
fn assign_uses_tolerated_call(event: &FlowEvent, tolerant_call_names: &[&str]) -> bool {
    matches!(
        event,
        FlowEvent::Assign { source_call: Some(call), .. }
            if tolerant_call_names.contains(&call.as_str())
    )
}

/// Byte spans of every ERROR / MISSING node in the tree. Mirrors the
/// parser's diagnostic walk; only called when the root has errors.
pub(super) fn syntax_error_spans(tree: &tree_sitter::Tree, file: FileId) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() {
            spans.push(span_of(file, &node));
        }
        if !node.is_error() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.has_error() || child.is_missing() {
                    stack.push(child);
                }
            }
        }
    }
    spans
}
