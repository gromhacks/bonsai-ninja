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
pub(crate) fn extract_direct_call_info(node: &Node<'_>, src: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    if !COMMON_CALL_KINDS.contains(&node.kind()) {
        // Recurse only where a descendant call genuinely IS the RHS's
        // operative call: transparent single-call wrappers (member /
        // await / paren chains), a grouping list wrapping exactly one
        // expression (Go / Python `x := f()` → `expression_list` of one
        // call). A
        // compound RHS (`a + f()`) or a multi-value list (`f(), g()`)
        // must NOT collapse to its first call — it falls through to
        // `source_names`.
        let single_expr_grouping = grouping_list_kind(node.kind()) && node.named_child_count() == 1;
        if !direct_call_wrapper_kind(node.kind()) && !single_expr_grouping {
            return None;
        }
        return first_call_descendant(*node).and_then(|call| extract_direct_call_info(&call, src));
    }
    let erlang_remote = node
        .child_by_field_name("expr")
        .and_then(|expr| erlang_remote_callee(&expr, src));
    let method_compound = method_receiver_name(node, src);
    // Callee node via common field names.
    let callee = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("callee"))
        .or_else(|| erlang_remote.as_ref().map(|(n, _)| *n))
        .or_else(|| method_compound.as_ref().map(|(n, _)| *n))
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| first_callee_expression_child(node))
        .or_else(|| first_identifier_like_child(node))?;
    let full = erlang_remote
        .as_ref()
        .map(|(_, name)| name.clone())
        .or_else(|| method_compound.as_ref().map(|(_, name)| name.clone()))
        .unwrap_or_else(|| node_text(&callee, src).trim().to_string());
    let full = normalize_call_name_whitespace(&full);
    if full.is_empty() {
        return None;
    }
    // Positional args — the arguments field is most commonly
    // `arguments`; grammars also expose it via `argument_list`.
    let args_node = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("args"))
        .or_else(|| first_named_child_of_kind(node, "arguments"))
        .or_else(|| first_named_child_of_kind(node, "argument_list"));
    let mut args: Vec<String> = Vec::new();
    if let Some(an) = args_node {
        let mut cursor = an.walk();
        for child in an.named_children(&mut cursor) {
            // Skip keyword-argument wrappers — we only want positional
            // text here. Keyword args don't participate in G1's
            // param-index-based summary lookup.
            if matches!(child.kind(), "keyword_argument" | "named_argument") {
                continue;
            }
            let t = normalize_call_name_whitespace(node_text(&child, src));
            if !t.is_empty() {
                args.push(t);
            }
        }
    } else {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !matches!(child.kind(), "argument" | "call_argument") {
                continue;
            }
            let t = normalize_call_name_whitespace(node_text(&child, src));
            if !t.is_empty() {
                args.push(t);
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
fn grouping_list_kind(kind: &str) -> bool {
    matches!(kind, "expression_list" | "expressions" | "expression_series")
}

fn direct_call_wrapper_kind(kind: &str) -> bool {
    matches!(
        kind,
        "field_expression"
            | "member_expression"
            | "member_access_expression"
            | "navigation_expression"
            | "selector_expression"
            | "scoped_identifier"
            | "scope_resolution"
            | "selector"
            | "postfix_expression"
            | "parenthesized_expression"
            | "expression"
            | "primary_expression"
            // `await EXPR` is a transparent wrapper around its operand —
            // Python's grammar names the node `await` (bare), C++/JS use
            // `await_expression` / `co_await_expression`. Without `await`
            // here, `x = await f(arg)` fell through to `source_names` and
            // tokenized the `await` keyword + callee as pseudo-operands,
            // dropping the real `f(arg)` call (and overwriting `x`'s
            // taint with a clean value — see the async-for `chunk`
            // regression in examples/python/mega_flow).
            | "await"
            | "await_expression"
            | "co_await_expression"
            // Rust `expr?` (H25): a transparent single-call wrapper around
            // its operand, so `let x = foo()?` binds the `foo` call result
            // just like `let x = foo()` and return-summary taint flows.
            | "try_expression"
            // TS/C# type-assertion wrappers (M20): `const y = f(x) as T`,
            // `g() satisfies T`, `h()!`, `<T>i()`. These are transparent
            // single-call wrappers around their operand for the purpose of
            // the Assign->call source-call binding. `direct_call_wrapper_kind`
            // feeds ONLY `extract_direct_call_info` (the source_call binding
            // at the Assign RHS) and param extraction -- NOT
            // `extract_rhs_expr_operands` -- so this does not drop `raw` from
            // C# `new List<string>{ raw! }` ctor operands (the earlier
            // regression came from a broader change; the bare-operand path is
            // untouched here). For a no-arg transit `g() as T`, binding the
            // call result keeps `classify_assign_value_kinds` from labeling
            // the RHS a `Literal` and erasing prior taint.
            | "as_expression"
            | "satisfies_expression"
            | "non_null_expression"
            | "type_assertion"
            | "dot"
    )
}

/// True when the function's parameter list ends in a positional variadic
/// collector (`*args`, `...rest`, `T...`). Combined by callers with the
/// synthetic `__bonsai_varargs` marker (C-family bare `...`). Checks the
/// DIRECT children of the parameter container only, so a splat inside a
/// default-value expression (`def f(x=[*a])`) does not falsely flag the
/// callee. Keyword collectors (`**kwargs`, Ruby `**opts`) are deliberately
/// excluded -- they do not absorb overflow POSITIONAL args (audit M1).
pub(super) fn parameter_list_is_variadic(fn_node: &Node<'_>) -> bool {
    const VARIADIC_PARAM_KINDS: &[&str] = &[
        "variadic_parameter", // go `...T`, php `...$x`, c `...`
        "variadic_declaration",
        "vararg_expression",  // lua `...`
        "spread_parameter",   // java `T... args`
        "rest_parameter",     // typescript `...args`
        "rest_pattern",       // javascript `...args`
        "list_splat_pattern", // python `*args`
        "splat_parameter",    // ruby `*args`
    ];
    let Some(container) = fn_node
        .child_by_field_name("parameters")
        .or_else(|| first_named_child_of_kind(fn_node, "parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "parameter_list"))
        .or_else(|| first_named_child_of_kind(fn_node, "function_value_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameter_list"))
    else {
        return false;
    };
    // Collect into Vecs first: tree-sitter cursors cannot outlive a borrow
    // inside an `.any()` closure, so the codebase materializes children
    // before iterating.
    let mut cursor = container.walk();
    let params: Vec<Node<'_>> = container.named_children(&mut cursor).collect();
    for param in params {
        if VARIADIC_PARAM_KINDS.contains(&param.kind()) {
            return true;
        }
        // A rest element nested inside a DESTRUCTURING pattern parameter
        // (`function f({a, ...rest}, b)` / `function f([x, ...tail])`) is
        // NOT a positional overflow collector -- it gathers the remaining
        // keys/elements of THAT one argument, so it must not flag the whole
        // callee variadic. Skip the nested scan for destructuring patterns.
        if matches!(
            param.kind(),
            "object_pattern" | "array_pattern" | "object_type" | "tuple_pattern"
        ) {
            continue;
        }
        // Some grammars wrap the splat one level down (a `parameter` whose
        // child is a `rest_pattern` / `list_splat_pattern`).
        let mut inner = param.walk();
        let nested: Vec<Node<'_>> = param.named_children(&mut inner).collect();
        if nested.iter().any(|c| VARIADIC_PARAM_KINDS.contains(&c.kind())) {
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

pub(super) fn first_call_descendant<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    for child in children {
        if COMMON_CALL_KINDS.contains(&child.kind()) {
            return Some(child);
        }
        if let Some(found) = first_call_descendant(child) {
            return Some(found);
        }
    }
    None
}

pub(super) fn extract_dart_selector_call_info(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<(Option<String>, Vec<String>)> {
    let selector = if node.kind() == "selector" {
        Some(node)
    } else {
        first_dart_selector_call_descendant(node)
    }?;
    let FlowEvent::Call { name, args, .. } = build_dart_selector_call_event(selector, file, src)? else {
        return None;
    };
    let positional_args = args
        .into_iter()
        .filter(|arg| arg.name.is_none())
        .map(|arg| arg.value_text)
        .filter(|arg| !arg.trim().is_empty())
        .collect();
    Some((Some(name), positional_args))
}

fn first_dart_selector_call_descendant<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    for child in children {
        if child.kind() == "selector" && first_named_child_of_kind(&child, "argument_part").is_some() {
            return Some(child);
        }
        if let Some(found) = first_dart_selector_call_descendant(child) {
            return Some(found);
        }
    }
    None
}

pub(super) fn next_named_sibling_within<'tree>(
    parent: &Node<'tree>,
    after: Node<'tree>,
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
        if looks_like_branch_arm_node(child.kind()) {
            return Some(child);
        }
    }
    None
}

pub(super) fn synthetic_function_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "constructor_definition" {
        return Some("constructor".to_string());
    }
    if node.kind() == "fallback_receive_definition" {
        let text = node_text(node, src).trim_start();
        if text.starts_with("receive") {
            return Some("receive".to_string());
        }
        if text.starts_with("fallback") {
            return Some("fallback".to_string());
        }
        return Some("fallback_receive".to_string());
    }
    None
}
