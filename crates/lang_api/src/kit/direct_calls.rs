//! Direct-call callee/argument extraction.
//!
//! Given a CST node that may be (or transparently wrap) a call
//! expression, extract the callee path and positional argument texts so
//! an enclosing `FlowEvent::Assign` can carry the call as its RHS
//! signal. Handles member/await/paren wrapper chains, Dart selector
//! chains, variadic parameter detection, and synthetic function names
//! for unnamed callables.

#[allow(clippy::wildcard_imports)]
use super::*;

/// If `node` is a direct call expression (call / method-invocation /
/// similar), extract `(Some(callee_name), positional_arg_texts)`
/// so the surrounding `FlowEvent::Assign` can carry the call as its
/// RHS signal. Returns `None` for non-call RHS.
///
/// The returned callee name preserves receivers (`item.get`, not just
/// `get`) so downstream taint can model receiver-derived return
/// values. Resolver code still falls back to the short tail when it
/// needs to bind to a local function declaration. The returned arg
/// texts are the raw source strings of each positional argument.
pub(crate) fn extract_direct_call_info(
    node: &Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<(Option<String>, Vec<String>)> {
    if let Some(info) = handler
        .direct_call_info_extractor
        .and_then(|extract| extract(*node, src, handler))
    {
        return Some(info);
    }
    if !handler.is_call(node.kind()) {
        // Follow only the direct operand of a syntax-proven transparent
        // wrapper. Searching arbitrary descendants is unsound here: in
        // `x = ({"v": raw} if len(raw) else None)`, `len(raw)` is nested in
        // the condition and is not the value-producing call for `x`.
        return transparent_direct_call_child(node, handler)
            .and_then(|child| extract_direct_call_info(&child, src, handler));
    }
    let full = normalize_call_name_whitespace(&parsed_call_target(node, src, handler)?.full_text);
    if full.is_empty() {
        return None;
    }
    let mut args: Vec<String> = Vec::new();
    let argument_containers = call_argument_containers(*node, handler);
    for container in &argument_containers {
        let arguments = if handler.is_call(container.kind()) {
            vec![*container]
        } else {
            let mut cursor = container.walk();
            container.named_children(&mut cursor).collect()
        };
        for argument in arguments {
            let (name, value) = argument_name_and_value(argument, src, handler);
            if name.is_some() {
                continue;
            }
            let t = normalize_call_name_whitespace(node_text(&value, src));
            if !t.is_empty() {
                args.push(t);
            }
        }
    }
    if argument_containers.is_empty() && handler.has_special_form(SyntaxSpecialForm::DirectCallArguments) {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let excluded = cursor
                    .field_name()
                    .is_some_and(|field| handler.direct_call_argument_excluded_fields.contains(&field));
                if child.is_named() && !excluded {
                    let t = normalize_call_name_whitespace(node_text(&child, src));
                    if !t.is_empty() {
                        args.push(t);
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    Some((Some(full), args))
}

/// Grammar node kinds that group a comma-separated expression series
/// (Go `expression_list`, Python tuple targets). When such a list wraps
/// exactly ONE expression it is a transparent wrapper around that single
/// expression; with more than one it is a genuine multi-value series and
/// must not be collapsed to its first call.
pub(super) fn grouping_list_kind(kind: &str, handler: &GrammarHandler) -> bool {
    handler.single_expression_group_kinds.contains(&kind)
}

/// Return the single direct child through which a transparent expression
/// wrapper can carry a call result.
///
/// This deliberately reasons from the CST's immediate structure. A wrapper
/// around one expression may recurse into that expression; it may never scan
/// through an unrelated compound expression to find an arbitrary nested call.
/// Member/type wrappers can have additional named children (a field or type),
/// so they are transparent only when exactly one direct child is itself a call
/// or another declared transparent wrapper.
pub(super) fn transparent_direct_call_child<'tree>(
    node: &Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    if grouping_list_kind(node.kind(), handler) {
        return (node.named_child_count() == 1)
            .then(|| first_named_child(node))
            .flatten();
    }
    if !handler.transparent_call_wrapper_kinds.contains(&node.kind()) {
        return None;
    }

    let mut cursor = node.walk();
    let mut candidates = node.named_children(&mut cursor).filter(|child| {
        handler.is_call(child.kind())
            || handler.transparent_call_wrapper_kinds.contains(&child.kind())
            || (grouping_list_kind(child.kind(), handler) && child.named_child_count() == 1)
    });
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}

/// True when the function's parameter list ends in a positional variadic
/// collector (`*args`, `...rest`, `T...`). Combined by callers with the
/// synthetic `__bonsai_varargs` marker (C-family bare `...`). Checks the
/// DIRECT children of the parameter container only, so a splat inside a
/// default-value expression (`def f(x=[*a])`) does not falsely flag the
/// callee. Keyword collectors (`**kwargs`, Ruby `**opts`) are deliberately
/// excluded -- they do not absorb overflow POSITIONAL args (audit M1).
pub(super) fn parameter_list_is_variadic(fn_node: &Node<'_>, handler: &GrammarHandler) -> bool {
    let Some(container) = fn_node.child_by_field_name("parameters").or_else(|| {
        handler
            .parameter_container_kinds
            .iter()
            .find_map(|kind| first_named_child_of_kind(fn_node, kind))
    }) else {
        return false;
    };
    // Collect into Vecs first: tree-sitter cursors cannot outlive a borrow
    // inside an `.any()` closure, so the codebase materializes children
    // before iterating.
    let mut cursor = container.walk();
    let params: Vec<Node<'_>> = container.named_children(&mut cursor).collect();
    for param in params {
        if handler.variadic_parameter_kinds.contains(&param.kind()) {
            return true;
        }
        // A rest element nested inside a DESTRUCTURING pattern parameter
        // (`function f({a, ...rest}, b)` / `function f([x, ...tail])`) is
        // NOT a positional overflow collector -- it gathers the remaining
        // keys/elements of THAT one argument, so it must not flag the whole
        // callee variadic. Skip the nested scan for destructuring patterns.
        if handler.destructured_parameter_kinds.contains(&param.kind()) {
            continue;
        }
        // Some grammars wrap the splat one level down (a `parameter` whose
        // child is a `rest_pattern` / `list_splat_pattern`).
        let mut inner = param.walk();
        let nested: Vec<Node<'_>> = param.named_children(&mut inner).collect();
        if nested
            .iter()
            .any(|child| handler.variadic_parameter_kinds.contains(&child.kind()))
        {
            return true;
        }
    }
    false
}

/// For a C/C++ `function_declarator` (or a definition node wrapping one),
/// if its declarator is a qualified/scoped name (`Class::method`), return
/// the `name` field node so an out-of-line definition is keyed under
/// `method`, not the leftmost scope token `Class` (H8).
pub(super) fn qualified_method_name_node<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let inner = if node.kind() == "function_declarator" {
        node.child_by_field_name("declarator")?
    } else {
        node.child_by_field_name("declarator")
            .filter(|d| d.kind() == "function_declarator")
            .and_then(|d| d.child_by_field_name("declarator"))?
    };
    if matches!(inner.kind(), "qualified_identifier" | "scoped_identifier") {
        inner.child_by_field_name("name")
    } else {
        None
    }
}

pub(super) fn first_call_descendant<'tree>(
    node: Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    for child in children {
        if handler.is_call(child.kind()) {
            return Some(child);
        }
        if let Some(found) = first_call_descendant(child, handler) {
            return Some(found);
        }
    }
    None
}

pub(super) fn next_named_sibling_within<'tree>(
    parent: &Node<'tree>,
    after: Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    let mut cursor = parent.walk();
    let mut seen = false;
    for child in parent.named_children(&mut cursor) {
        if child.id() == after.id() {
            seen = true;
            continue;
        }
        if !seen {
            continue;
        }
        if handler.branch_arm_kinds.contains(&child.kind()) {
            return Some(child);
        }
    }
    None
}
