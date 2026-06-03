//! Pseudo-call synthesis for grammar shapes that are semantically
//! function calls but syntactically something else.
//!
//! Adapters lower these constructs into a uniform `FlowEvent::Call`
//! so source/sink rules and taint propagation can ride the same
//! call-site model regardless of source syntax:
//!
//! - **JSX / TSX elements** — `<Foo a={x} />` → `Foo({a: x})`
//! - **Go channel send** — `ch <- x` → synthetic `send(ch, x)`
//! - **C++ delete** — `delete p` / `delete[] p` → synthetic `delete(p)`
//! - **Perl scalar eval** — `eval $expr` → synthetic `eval($expr)`
//!   (does NOT lower `eval { BLOCK }` blocks — those are try/catch
//!   control flow, not string-code execution).
//! - **PHP echo** — `echo $x;` → synthetic `echo($x)` (echo is a
//!   language construct, not a function call).
//! - **Ruby backticks** — `` `cmd` `` parses as `subshell` → synthetic
//!   `` `(cmd)`` `` for the rulepack to anchor on.
//! - **Scala infix expressions** — `obj op arg`. Symbolic `+` →
//!   synthetic `+` call for the rulepack's string-concat XSS shape;
//!   any alphabetic-named infix method (`obj method arg`) → a real
//!   method `Call { receiver: obj, name: method, args: [arg] }`.
//!
//! Each lowering preserves the source span so downstream consumers
//! can still tie the synthesized call back to its original syntax.
//!
//! Why a shared module: the lowering for each construct is small but
//! every adapter that supports any of these constructs would
//! otherwise need its own copy. The list grows conservatively —
//! adding a new pseudo-call shape requires the lowering be
//! expressible as a node-kind dispatch, not arbitrary grammar walking.

use bonsai_common::FileId;
use tree_sitter::Node;

use super::{
    argument_place, extract_rhs_expr_operands, first_named_child, looks_like_bare_identifier,
    looks_like_identifier, node_text, normalize_call_name_whitespace, span_of, CallArg, CallKind, FlowEvent,
};

pub(super) fn pseudo_call_event(node: &Node<'_>, file: FileId, src: &[u8]) -> Option<FlowEvent> {
    // JSX/TSX elements are syntactic sugar for a function call:
    //   `<Foo a={x} />`             ≡ `Foo({a: x})`
    //   `<Foo a={x}>{kid}</Foo>`    ≡ `Foo({a: x, children: kid})`
    // The runtime semantics that matter for taint analysis are the
    // attribute/child expressions becoming arguments of the
    // component callable. Synthesizing a Call event here makes
    // those expressions participate in source/sink resolution and
    // taint propagation without requiring the JS/TS adapter to
    // re-implement the surrounding pipeline.
    if matches!(node.kind(), "jsx_self_closing_element" | "jsx_opening_element") {
        if let Some(call) = jsx_call_from_opening(node, file, src) {
            return Some(call);
        }
    }
    // Scala general infix method call (`obj method arg`). Lower it to a
    // real method Call so infix-applied sinks/transfers ride the call
    // model. Gated on an alphabetic-named operator; symbolic `+` falls
    // through to its dedicated string-concat arm below.
    if node.kind() == "infix_expression" {
        if let Some(call) = infix_method_call_event(node, file, src) {
            return Some(call);
        }
    }
    let (name, args) = match node.kind() {
        // Go `ch <- x` channel send: lower to a synthetic `send(ch,
        // x)` call so the value `x` participates in taint flow as a
        // call argument and rules can anchor on channel-write shapes.
        // Field layout: `channel` (receiver-like) + the value as
        // arg0; the channel name is preserved in `receiver` so
        // consumer can still see the name without confusing the
        // synthesized call shape for a real `send` call.
        "send_statement" => {
            let channel = node.child_by_field_name("channel")?;
            let value = node.child_by_field_name("value")?;
            let args = vec![
                CallArg {
                    span: span_of(file, &channel),
                    name: None,
                    place: argument_place(&channel, src),
                    source_names: extract_rhs_expr_operands(&channel, src),
                    value_text: normalize_call_name_whitespace(node_text(&channel, src)),
                },
                CallArg {
                    span: span_of(file, &value),
                    name: None,
                    place: argument_place(&value, src),
                    source_names: extract_rhs_expr_operands(&value, src),
                    value_text: normalize_call_name_whitespace(node_text(&value, src)),
                },
            ];
            (String::from("send"), args)
        }
        // C++ `delete p` / `delete[] p` is an operator expression, not
        // a call_expression, but security rules treat the free site as
        // a sink-like call.
        "delete_expression" => (String::from("delete"), named_child_args(node, file, src)),
        // Perl scalar eval parses as a dedicated eval_expression. Do
        // not lower `eval { ... }` blocks: those are try/catch-like
        // control flow, not string-code execution.
        "eval_expression" if first_named_child(node).is_none_or(|child| child.kind() != "block") => {
            (String::from("eval"), named_child_args(node, file, src))
        }
        // PHP echo is a language construct, not a function call.
        "echo_statement" => (String::from("echo"), named_child_args(node, file, src)),
        // Ruby backticks parse as `subshell`.
        "subshell" => (String::from("`"), named_child_args(node, file, src)),
        // Scala string concatenation is an infix operator expression.
        "infix_expression" if infix_operator_text(node, src).as_deref() == Some("+") => {
            (String::from("+"), infix_expression_args(node, file, src))
        }
        _ => return None,
    };

    Some(FlowEvent::Call {
        span: span_of(file, node),
        receiver: None,
        receiver_types: Vec::new(),
        name,
        call_kind: CallKind::Function,
        args,
    })
}

fn jsx_call_from_opening(node: &Node<'_>, file: FileId, src: &[u8]) -> Option<FlowEvent> {
    // Component identifier: prefer the `name` field (tree-sitter-js
    // grammar declares it). Fall back to the first named child of
    // an identifier-shaped kind for grammar variants that omit the
    // field annotation. JSX namespaces (`<svg:circle ...>`) and
    // member access (`<Foo.Bar ...>`) flatten via the textual form.
    let name_node = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        let mut found: Option<Node<'_>> = None;
        for c in node.named_children(&mut cursor) {
            if matches!(
                c.kind(),
                "identifier"
                    | "nested_identifier"
                    | "member_expression"
                    | "jsx_namespace_name"
                    | "jsx_member_expression"
            ) {
                found = Some(c);
                break;
            }
        }
        found
    })?;
    let component = node_text(&name_node, src).trim().to_string();
    if component.is_empty() {
        return None;
    }
    let mut args: Vec<CallArg> = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let kind = child.kind();
        if kind != "jsx_attribute" {
            continue;
        }
        let attr_name = child
            .named_child(0)
            .map(|n| node_text(&n, src).trim().to_string())
            .unwrap_or_default();
        // The value is the second named child for `attr={expr}` or
        // `attr="literal"`; absent for boolean attributes (`<Foo
        // disabled />`). Drill into jsx_expression / jsx_string to
        // get the actual expression text.
        let value_node = child.named_child(1);
        let value_text = match value_node {
            Some(v) => {
                let inner = v
                    .named_child(0)
                    .map(|c| node_text(&c, src))
                    .unwrap_or_else(|| node_text(&v, src));
                normalize_call_name_whitespace(inner)
            }
            None => attr_name.clone(),
        };
        if value_text.is_empty() {
            continue;
        }
        args.push(CallArg {
            span: span_of(file, &child),
            name: if attr_name.is_empty() {
                None
            } else {
                Some(attr_name)
            },
            place: value_node
                .as_ref()
                .and_then(|v| v.named_child(0).and_then(|inner| argument_place(&inner, src))),
            source_names: value_node
                .as_ref()
                .map(|v| {
                    v.named_child(0)
                        .map(|inner| extract_rhs_expr_operands(&inner, src))
                        .unwrap_or_else(|| extract_rhs_expr_operands(v, src))
                })
                .unwrap_or_else(Vec::new),
            value_text,
        });
    }
    Some(FlowEvent::Call {
        span: span_of(file, node),
        receiver: None,
        receiver_types: Vec::new(),
        name: component,
        call_kind: CallKind::Function,
        args,
    })
}

/// Pull every named child of `node` into a `CallArg` list — preserves
/// place, value text, and span. Used by lowerings whose argument list is
/// the named children directly (no `arguments` field wrapper).
///
/// The lowering captures every named child by design: it catches
/// expression args like `eval $expr`, `echo "x"`, and `delete obj.field`
/// without needing to enumerate every literal/identifier kind upfront.
fn named_child_args(node: &Node<'_>, file: FileId, src: &[u8]) -> Vec<CallArg> {
    // Suppress `looks_like_identifier` unused-import warning — we keep
    // the import so the predicate stays available for future filters.
    let _ = looks_like_identifier;
    let mut call_args = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        call_args.push(CallArg {
            span: span_of(file, &child),
            name: None,
            place: argument_place(&child, src),
            source_names: extract_rhs_expr_operands(&child, src),
            value_text: normalize_call_name_whitespace(node_text(&child, src)),
        });
    }
    call_args
}

/// Pull infix expression operands into a CallArg list, skipping the
/// operator marker / keyword child. Used to lower Scala `a + b` shapes
/// into a synthetic `+`-call so XSS rules can anchor on string concat.
fn infix_expression_args(node: &Node<'_>, file: FileId, src: &[u8]) -> Vec<CallArg> {
    let mut call_args = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let child_kind = child.kind();
        // Skip the operator itself — we already recorded it as the call name.
        if child_kind == "operator" || child_kind.ends_with("_keyword") {
            continue;
        }
        let argument_text = normalize_call_name_whitespace(node_text(&child, src));
        if argument_text.is_empty() {
            continue;
        }
        call_args.push(CallArg {
            span: span_of(file, &child),
            name: None,
            place: argument_place(&child, src),
            source_names: extract_rhs_expr_operands(&child, src),
            value_text: argument_text,
        });
    }
    call_args
}

/// Lower a Scala general infix method call (`receiver method arg`) into a
/// method `Call`. Scala applies any single-arg method infix, parsed as
/// `infix_expression` with `left` / `operator` / `right` fields. Gated on an
/// alphabetic-identifier operator so symbolic/comparison operators (`+`,
/// `==`, `::`) stay out — `+` keeps its dedicated string-concat lowering.
fn infix_method_call_event(node: &Node<'_>, file: FileId, src: &[u8]) -> Option<FlowEvent> {
    let operator = node.child_by_field_name("operator")?;
    let name = node_text(&operator, src).trim().to_string();
    // Only method-name operators; symbolic operators are not method calls.
    if !looks_like_bare_identifier(&name) {
        return None;
    }
    // tree-sitter-kotlin parses `object Foo { ... }` as an
    // `infix_expression` with the declaration keyword in the operator
    // slot (handled by the Kotlin adapter, not a method call). Keep
    // those declaration keywords out of the call lowering.
    if matches!(name.as_str(), "object" | "companion") {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    // The single infix argument is the right operand.
    let arg = CallArg {
        span: span_of(file, &right),
        name: None,
        place: argument_place(&right, src),
        source_names: extract_rhs_expr_operands(&right, src),
        value_text: normalize_call_name_whitespace(node_text(&right, src)),
    };
    Some(FlowEvent::Call {
        span: span_of(file, node),
        receiver: Some(normalize_call_name_whitespace(node_text(&left, src))),
        receiver_types: Vec::new(),
        name,
        call_kind: CallKind::Method,
        args: vec![arg],
    })
}

/// Read the operator-marker text on an `infix_expression` node, or `None`
/// when the grammar didn't expose an `operator` field.
fn infix_operator_text(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let operator_node = node.child_by_field_name("operator")?;
    Some(node_text(&operator_node, src).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::pseudo_call_event;
    use crate::kit::language_from_pack;
    use crate::{CallKind, FlowEvent};
    use bonsai_common::FileId;
    use tree_sitter::{Node, Parser};

    fn find_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        for i in 0..node.named_child_count() {
            let idx = u32::try_from(i).ok()?;
            if let Some(child) = node.named_child(idx) {
                if let Some(found) = find_kind(child, kind) {
                    return Some(found);
                }
            }
        }
        None
    }

    #[test]
    fn scala_alphabetic_infix_method_lowered_to_method_call() {
        // `payload concat suffix` is `payload.concat(suffix)` applied
        // infix; only `+` was lowered before, so this produced no Call.
        let src = "object A { val r = payload concat suffix }";
        let language = language_from_pack("scala").expect("scala pack available");
        let mut parser = Parser::new();
        parser.set_language(&language).expect("set language");
        let tree = parser.parse(src, None).expect("parse succeeded");
        let infix = find_kind(tree.root_node(), "infix_expression").expect("infix node");

        let event = pseudo_call_event(&infix, FileId::INVALID, src.as_bytes())
            .expect("infix method call lowered to a Call event");
        let FlowEvent::Call {
            name,
            receiver,
            call_kind,
            args,
            ..
        } = event
        else {
            panic!("expected a Call event, got {event:?}");
        };
        assert_eq!(name, "concat");
        assert_eq!(call_kind, CallKind::Method);
        assert_eq!(receiver.as_deref(), Some("payload"));
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].value_text, "suffix");
    }
}
