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
pub(super) fn retain_flow_events_outside_errors(events: &mut Vec<FlowEvent>, error_spans: &[Span]) {
    events.retain_mut(|event| match event {
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            retain_flow_events_outside_errors(then_events, error_spans);
            retain_flow_events_outside_errors(else_events, error_spans);
            true
        }
        FlowEvent::Loop { body, .. } => {
            retain_flow_events_outside_errors(body, error_spans);
            true
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            retain_flow_events_outside_errors(body, error_spans);
            retain_flow_events_outside_errors(catch_events, error_spans);
            retain_flow_events_outside_errors(finally_events, error_spans);
            true
        }
        FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            retain_flow_events_outside_errors(body, error_spans);
            true
        }
        // C/C++ `x = va_arg(ap, TYPE)`: tree-sitter-c/cpp cannot parse the
        // TYPE operand of the `va_arg` builtin (`const char *` → an ERROR
        // node), so the assignment's span always overlaps a benign error.
        // The taint-relevant operand — the `ap` va_list — parses cleanly,
        // and `va_start` taint propagation depends on this Assign surviving.
        // Keep it: the error is in a non-runtime type position, not the
        // value flow.
        leaf @ FlowEvent::Assign { .. } if assign_is_variadic_builtin_read(leaf) => true,
        leaf => !span_overlaps_error(leaf.span(), error_spans),
    });
}

/// True when `event` is an `Assign` whose RHS is a C/C++ `va_arg` /
/// `__builtin_va_arg` builtin read. These are exempt from
/// error-span pruning because the macro's TYPE argument is unparseable
/// by tree-sitter and produces a spurious ERROR node that would
/// otherwise discard the whole assignment.
fn assign_is_variadic_builtin_read(event: &FlowEvent) -> bool {
    matches!(
        event,
        FlowEvent::Assign { source_call: Some(call), .. }
            if call == "va_arg" || call == "__builtin_va_arg"
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

const LARGE_LITERAL_INITIALIZER_BYTES: usize = 64 * 1024;

pub(super) fn is_large_literal_initializer_node(kind: &str, node: &Node<'_>) -> bool {
    is_initializer_list_kind(kind)
        && node.end_byte().saturating_sub(node.start_byte()) > LARGE_LITERAL_INITIALIZER_BYTES
}

pub(super) fn is_initializer_list_kind(kind: &str) -> bool {
    matches!(
        kind,
        "initializer_list" | "initializer_list_expression" | "braced_initializer_list"
    )
}

pub(super) fn is_large_data_declaration_node(kind: &str, node: &Node<'_>) -> bool {
    matches!(kind, "declaration" | "init_declarator" | "field_declaration")
        && node.end_byte().saturating_sub(node.start_byte()) > LARGE_LITERAL_INITIALIZER_BYTES
        && (has_direct_large_literal_initializer_child(node)
            || has_direct_large_initializer_declarator_child(node))
}

pub(super) fn has_direct_large_literal_initializer_child(node: &Node<'_>) -> bool {
    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .any(|child| is_large_literal_initializer_node(child.kind(), &child));
    found
}

fn has_direct_large_initializer_declarator_child(node: &Node<'_>) -> bool {
    let mut cursor = node.walk();
    let found = node.named_children(&mut cursor).any(|child| {
        child.kind() == "init_declarator"
            && child.end_byte().saturating_sub(child.start_byte()) > LARGE_LITERAL_INITIALIZER_BYTES
            && has_direct_large_literal_initializer_child(&child)
    });
    found
}
