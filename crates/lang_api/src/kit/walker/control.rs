use super::super::{
    emit_using_as_pattern_assigns, extract_catch_param, extract_return_value_flow_with_handler,
    extract_return_value_name_with_handler, extract_return_value_text, extract_throw_value_name,
    extract_yield_value_flow_with_handler, looks_like_bare_identifier, node_text, span_of, FlowEvent, Node,
};
use super::{walk_into, LoweringContext};

pub(super) fn lower_control_and_scope(
    node: Node<'_>,
    context: LoweringContext<'_>,
    out: &mut Vec<FlowEvent>,
) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if handler.is_break(kind) {
        let label = node
            .child_by_field_name("label")
            .map(|n| node_text(&n, src).trim().to_string())
            .filter(|s| !s.is_empty());
        // Perl's `loopex_expression` is a bucket for `last`, `next`, and
        // `redo` — sort by the leading keyword so the flow surfaces the
        // right event.
        let leading = node_text(&node, src).trim_start();
        if leading.starts_with("next") {
            out.push(FlowEvent::Continue {
                span: span_of(file, &node),
                label,
            });
        } else {
            out.push(FlowEvent::Break {
                span: span_of(file, &node),
                label,
            });
        }
        return true;
    }

    if handler.is_continue(kind) {
        let label = node
            .child_by_field_name("label")
            .map(|n| node_text(&n, src).trim().to_string())
            .filter(|s| !s.is_empty());
        out.push(FlowEvent::Continue {
            span: span_of(file, &node),
            label,
        });
        return true;
    }

    if handler.is_yield(kind) {
        let value_text = {
            let full = node_text(&node, src).trim();
            let stripped = full
                .strip_prefix("yield from ")
                .or_else(|| full.strip_prefix("yield "))
                .unwrap_or(full)
                .trim();
            if stripped.is_empty() || stripped == "yield" {
                None
            } else {
                Some(stripped.to_string())
            }
        };
        out.push(FlowEvent::Yield {
            span: span_of(file, &node),
            value_text,
            value_flow: extract_yield_value_flow_with_handler(&node, file, src, handler),
        });
        // Descend so calls inside `yield f()` still surface.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        return true;
    }

    if handler.is_await(kind) {
        // Capture the awaited value name when the node is a bare
        // identifier (`await promise`) so the intra pass can
        // propagate taint through the await boundary. Compound
        // awaited expressions (`await f(x)`) leave `value_name =
        // None`; their taint is tracked via the nested Call event
        // the child walk emits.
        let value_name = {
            let mut cursor = node.walk();
            let first_child = node.named_children(&mut cursor).next();
            first_child.and_then(|child| {
                let child_text = node_text(&child, src).trim();
                // Bare-identifier awaited values get a `value_name`;
                // anything compound is left None and tracked via the
                // nested call event.
                if looks_like_bare_identifier(child_text) {
                    Some(child_text.to_string())
                } else {
                    None
                }
            })
        };
        out.push(FlowEvent::Await {
            span: span_of(file, &node),
            value_name,
        });
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        return true;
    }

    if handler.is_defer(kind) {
        let mut body = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, &mut body, false);
        }
        out.push(FlowEvent::Defer {
            span: span_of(file, &node),
            body,
        });
        return true;
    }

    if handler.is_using(kind) {
        let body_node = node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("block"));
        let mut body = Vec::new();
        if let Some(b) = body_node {
            walk_into(b, file, src, handler, class_names, &mut body, false);
            // Python `with open('f') as fh:` / C# `using (var x = init()) {...}`
            // — the init expression (`open('f')`, `init()`) is NOT in the body
            // field, it's a sibling (`with_clause` / the init). Walk every
            // non-body named child into the OUTER flow so those calls surface
            // at the enclosing scope instead of disappearing.
            let body_id = b.id();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() == body_id {
                    continue;
                }
                emit_using_as_pattern_assigns(child, file, src, out);
                walk_into(child, file, src, handler, class_names, out, false);
            }
        } else {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                emit_using_as_pattern_assigns(child, file, src, &mut body);
                walk_into(child, file, src, handler, class_names, &mut body, false);
            }
        }
        out.push(FlowEvent::Using {
            span: span_of(file, &node),
            body,
        });
        return true;
    }

    false
}

pub(super) fn lower_try(node: Node<'_>, context: LoweringContext<'_>, out: &mut Vec<FlowEvent>) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if handler.is_try(kind) {
        let mut body = Vec::new();
        let mut catch_events = Vec::new();
        let mut finally_events = Vec::new();
        // Prefer the `body` / `block` field for the try body; otherwise the
        // first named block-like child that isn't itself a catch/finally.
        let body_node = node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("block"));
        let body_id = body_node.map(|n| n.id());
        let mut pre_body_child_ids = Vec::new();
        if let Some(b) = body_node {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() == b.id() {
                    break;
                }
                let ck = child.kind();
                if handler.is_catch(ck) || handler.is_finally(ck) || ck == "on_part" {
                    continue;
                }
                walk_into(child, file, src, handler, class_names, &mut body, false);
                pre_body_child_ids.push(child.id());
            }
            walk_into(b, file, src, handler, class_names, &mut body, false);
        }
        let mut cursor = node.walk();
        let mut saw_catch_kind = false;
        let mut saw_finally_kind = false;
        let mut block_children: Vec<Node<'_>> = Vec::new();
        // Dart parses `catch (e) { body }` as TWO siblings: a catch_clause
        // (containing only the parameters) followed by a sibling `block`
        // that IS the catch body. Same for `on E catch (e) { body }`.
        // Track whether the previous named sibling was a catch/on marker
        // so the following block gets routed into catch_events.
        let mut prev_was_catch_marker = false;
        for child in node.named_children(&mut cursor) {
            if pre_body_child_ids.contains(&child.id()) {
                prev_was_catch_marker = false;
                continue;
            }
            let ck = child.kind();
            if handler.is_catch(ck) || ck == "on_part" {
                saw_catch_kind = true;
                walk_into(child, file, src, handler, class_names, &mut catch_events, false);
                prev_was_catch_marker = true;
                continue;
            } else if handler.is_finally(ck) {
                saw_finally_kind = true;
                walk_into(child, file, src, handler, class_names, &mut finally_events, false);
                prev_was_catch_marker = false;
                continue;
            } else if prev_was_catch_marker && (ck == "block" || ck == "compound_statement") {
                // Dart: the block right after a catch_clause/on_part is the
                // catch body. Route it into catch_events.
                walk_into(child, file, src, handler, class_names, &mut catch_events, false);
                prev_was_catch_marker = false;
                continue;
            } else if Some(child.id()) == body_id {
                // Already walked via the body field — don't double-count.
                prev_was_catch_marker = false;
                continue;
            } else if body_node.is_none() {
                // Blocks are DEFERRED to `block_children` and assigned
                // after the loop (first = try body, second = catch body).
                // Walking them into `body` here as well would duplicate the
                // catch block, which the fallback below also routes into
                // `catch_events` (Perl-shape grammars with no catch kind).
                if ck == "block" || ck == "compound_statement" {
                    block_children.push(child);
                } else {
                    walk_into(child, file, src, handler, class_names, &mut body, false);
                }
            } else if ck == "block" || ck == "compound_statement" {
                block_children.push(child);
            } else {
                // Solidity: `try <call_expression> returns (r) <body> catch
                // { ... }` parses the tried expression as a sibling of the
                // body block. The expression IS the protected operation,
                // so walk its calls into body so callgraph sees them as
                // part of the try scope.
                walk_into(child, file, src, handler, class_names, &mut body, false);
            }
            prev_was_catch_marker = false;
        }
        // When the body came from deferred blocks (no `body` field), the
        // FIRST block child is the try body — walk it now (the loop only
        // collected it, to keep the second block for the catch body).
        if body_node.is_none() {
            if let Some(first_block) = block_children.first() {
                walk_into(*first_block, file, src, handler, class_names, &mut body, false);
            }
        }
        // Fallback for grammars (e.g. Perl) that don't label the catch
        // block with a dedicated kind: when we saw zero catch/finally
        // kinds and there are at least two sibling `block` children, the
        // second is the catch body (the first was already used as the
        // try body above).
        if !saw_catch_kind && !saw_finally_kind && block_children.len() >= 2 {
            // The second block-child is the catch body regardless of
            // whether the first was assigned as body via a named field or
            // via the walked-children fallback.
            let catch_block = &block_children[1];
            walk_into(
                *catch_block,
                file,
                src,
                handler,
                class_names,
                &mut catch_events,
                false,
            );
        }
        out.push(FlowEvent::Try {
            span: span_of(file, &node),
            body,
            catch_events,
            finally_events,
            catch_param: extract_catch_param(&node, src),
            catch_types: Vec::new(),
        });
        return true;
    }

    false
}

pub(super) fn lower_function_exit(
    node: Node<'_>,
    context: LoweringContext<'_>,
    out: &mut Vec<FlowEvent>,
) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if handler.is_return(kind) {
        let leading = node_text(&node, src).trim_start();
        if leading.starts_with("break") {
            out.push(FlowEvent::Break {
                span: span_of(file, &node),
                label: None,
            });
            return true;
        } else if leading.starts_with("continue") {
            out.push(FlowEvent::Continue {
                span: span_of(file, &node),
                label: None,
            });
            return true;
        }
        // Expression effects must precede the terminator in CFG order.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        if leading.starts_with("throw") {
            out.push(FlowEvent::Throw {
                span: span_of(file, &node),
                value_name: extract_throw_value_name(&node, src),
                thrown_type: None,
            });
        } else {
            out.push(FlowEvent::Return {
                span: span_of(file, &node),
                value_text: extract_return_value_text(&node, src),
                value_name: extract_return_value_name_with_handler(&node, src, handler),
                value_flow: extract_return_value_flow_with_handler(&node, file, src, handler),
            });
        }
        return true;
    }
    if handler.is_throw(kind) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !handler.is_assignment(child.kind()) {
                walk_into(child, file, src, handler, class_names, out, false);
            }
        }
        out.push(FlowEvent::Throw {
            span: span_of(file, &node),
            value_name: extract_throw_value_name(&node, src),
            thrown_type: None,
        });
        return true;
    }

    false
}
