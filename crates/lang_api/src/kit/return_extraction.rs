//! Return / throw / catch value extraction.
//!
//! Adapters report `FlowEvent::Return { value_name, value_text }` and
//! `FlowEvent::Throw { value_name, value_text }`; this module computes
//! those fields from a `return`/`throw` statement node by combining
//! per-grammar field-name probes with a text-fallback path that
//! handles grammars whose `return`/`throw` nodes don't expose a
//! dedicated value field.
//!
//! Why a text fallback. Some tree-sitter grammars (notably older
//! grammar revisions) emit `return EXPR;` as a flat statement node
//! with no `value` / `expression` / `argument` field. Rather than
//! per-grammar special cases, we strip the leading `return`/`throw`
//! keyword from the node text and use that. The fallback only fires
//! when the structural probes return `None`.
//!
//! `extract_catch_param` is the matching reader for try/catch
//! binding patterns — `catch (FooException e)`, `except E as e`,
//! `rescue => e`. The structure varies wildly across languages so
//! this lives next to the throw extractor rather than in a separate
//! module.

use tree_sitter::Node;

use super::{
    first_identifier_descendant, first_identifier_like_child, looks_like_bare_identifier,
    looks_like_identifier, node_text,
};

/// Extract the single value-bearing identifier of the value being
/// returned when the adapter can determine one precisely.
/// `return x` and `return `${x}`` → `Some("x")`; multi-operand
/// expressions such as `return x + y` remain `None`.
pub fn extract_return_value_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    // Try the textual fallback first — works on grammars that don't
    // expose a value field at all.
    if let Some(value_text) = return_statement_value_text(node, src) {
        if looks_like_bare_identifier(&value_text) {
            return Some(value_text);
        }
    }
    let value_node = return_value_node(node)?;
    let value_kind = value_node.kind();
    // Direct identifier — most languages parse `return x` this way.
    if looks_like_identifier(value_kind) {
        return Some(node_text(&value_node, src).trim().to_string());
    }
    // Some grammars wrap the value in a single-expression container
    // with no sibling type node — the lone identifier child is the
    // value, so first-identifier-like is safe here.
    if matches!(
        value_kind,
        "parenthesized_expression" | "expression_statement" | "single_expression"
    ) {
        let unwrapped = first_identifier_like_child(&value_node)?;
        return Some(node_text(&unwrapped, src).trim().to_string());
    }
    // TypeScript type-assertion wrappers carry a TYPE node beside the
    // value (`x as T`, `x satisfies T`, `x!`, `<T>x`). We must peel to
    // the VALUE child specifically — `first_identifier_like_child`
    // would otherwise grab the `type_identifier` (e.g. return `T`
    // instead of `x` for `return f(x) as T;`). The value is fielded as
    // `expression`/`argument`; fall back to the first named non-type
    // child. Once peeled, re-apply the same identifier / single-operand
    // logic so `return f(x) as T;` resolves the call's lone operand `x`
    // (audit M20).
    if matches!(
        value_kind,
        "as_expression" | "satisfies_expression" | "non_null_expression" | "type_assertion"
    ) {
        let inner = value_node
            .child_by_field_name("expression")
            .or_else(|| value_node.child_by_field_name("argument"))
            .or_else(|| {
                let mut cursor = value_node.walk();
                let children: Vec<_> = value_node.named_children(&mut cursor).collect();
                children.into_iter().find(|child| !child.kind().contains("type"))
            })?;
        if looks_like_identifier(inner.kind()) {
            return Some(node_text(&inner, src).trim().to_string());
        }
        let operands = super::extract_rhs_expr_operands(&inner, src);
        if operands.len() == 1 {
            return operands.into_iter().next();
        }
        return None;
    }
    let operands = super::extract_rhs_expr_operands(&value_node, src);
    if operands.len() == 1 {
        return operands.into_iter().next();
    }
    None
}

/// Drill into a catch/rescue/except binding subtree to the actual binding
/// identifier (the `e` in `catch (Foo e)`, the `b` in `except Bar as b:`,
/// the `err` in `rescue => err`). Returns `None` if the node isn't a
/// recognised binding shape.
fn catch_binding_identifier<'a>(node: Node<'a>) -> Option<Node<'a>> {
    // `as_pattern` / `alias` wrap the binding; the renamed identifier
    // lives under an `alias` field.
    if matches!(node.kind(), "as_pattern" | "alias") {
        if let Some(alias_node) = node.child_by_field_name("alias") {
            return first_identifier_descendant(alias_node).or_else(|| {
                if looks_like_identifier(alias_node.kind()) {
                    Some(alias_node)
                } else {
                    None
                }
            });
        }
    }
    // Standalone parameter shapes — first identifier wins.
    if matches!(
        node.kind(),
        "as_pattern_target" | "catch_parameter" | "exception_parameter"
    ) {
        return first_identifier_descendant(node).or_else(|| {
            if looks_like_identifier(node.kind()) {
                Some(node)
            } else {
                None
            }
        });
    }
    None
}

/// Like [`extract_return_value_name`] but returns the full source
/// text of the return value (without the leading `return` keyword).
/// Used by the inter pass when matching return-text-shaped patterns
/// against the caller's tainted token set.
pub fn extract_return_value_text(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if let Some(text) = return_statement_value_text(node, src) {
        return Some(text);
    }
    return_value_node(node).map(|n| node_text(&n, src).trim().to_string())
}

/// Strip the leading `return` keyword and any trailing `;` from a return
/// statement's raw text. Used as a fallback for grammars whose return
/// statement doesn't expose a value field.
fn return_statement_value_text(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let raw_text = node_text(node, src).trim();
    let after_keyword = raw_text.strip_prefix("return")?;
    let value_text = after_keyword.trim_start();
    if value_text.is_empty() {
        return None;
    }
    let trimmed_value = value_text
        .strip_suffix(';')
        .unwrap_or(value_text)
        .trim()
        .to_string();
    (!trimmed_value.is_empty()).then_some(trimmed_value)
}

/// Locate the value child of a return statement across the four field
/// names the supported grammars use, falling back to the first non-keyword
/// named child for grammars that emit anonymous keywords.
fn return_value_node<'a>(node: &'a Node<'a>) -> Option<Node<'a>> {
    // Field-named lookups first — JS/TS use `value`, C/C++ `expression`,
    // Ruby `argument`, expression-bodied closures `body`.
    if let Some(value_field) = node.child_by_field_name("value") {
        return Some(value_field);
    }
    if let Some(expression_field) = node.child_by_field_name("expression") {
        return Some(expression_field);
    }
    if let Some(argument_field) = node.child_by_field_name("argument") {
        return Some(argument_field);
    }
    if let Some(body_field) = node.child_by_field_name("body") {
        return Some(body_field);
    }
    // Fallback: first non-keyword named child. Grammars that don't
    // expose a value field still emit the value as the first non-keyword
    // child — the `return` keyword itself is anonymous.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "return"
            && child.kind() != "return_keyword"
            && !child.kind().starts_with("comment")
        {
            return Some(child);
        }
    }
    None
}

/// Extract the bare-identifier name being thrown. Mirror of
/// [`extract_return_value_name`] for `throw` / `raise` / `panic` /
/// `die` constructs. Returns the rethrow-target's bare name when
/// the throw is a value-rethrow; returns the constructed exception
/// type name when the throw is a `throw new FooException(msg)`
/// (callers use the type name to look up matching catches).
pub fn extract_throw_value_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    // Field-named lookups across the throw/raise grammars we support.
    let value_node = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("exception"))
        .or_else(|| node.child_by_field_name("cause"));
    // Fallback: first non-keyword named child for grammars (Kotlin,
    // Scala, Swift, Rust) that nest the thrown value without a field name.
    let value_node = value_node.or_else(|| {
        let mut cursor = node.walk();
        let named_children: Vec<_> = node.named_children(&mut cursor).collect();
        named_children
            .into_iter()
            .find(|child| !matches!(child.kind(), "throw" | "raise" | "throws"))
    })?;
    // Catch-param linking only applies to bare identifier rethrows.
    // Compound expressions (`foo.bar`, `new Error(...)`) need the
    // adapter's typed-throw signal instead.
    if looks_like_identifier(value_node.kind()) {
        Some(node_text(&value_node, src).trim().to_string())
    } else {
        None
    }
}

/// Extract the catch-clause binding identifier. `catch (Foo e)` →
/// `Some("e")`, `except Bar as b:` → `Some("b")`, `rescue => err` →
/// `Some("err")`. Returns `None` if the catch clause has no
/// explicit binding (`catch { ... }` with no parameter).
pub fn extract_catch_param(try_node: &Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = try_node.walk();
    for catch_arm in try_node.named_children(&mut cursor) {
        let arm_kind = catch_arm.kind();
        // Recognise every grammar's catch-arm node kind. `on_part` is
        // Dart's `on E catch (e)` shape.
        if !(arm_kind.contains("catch")
            || arm_kind.contains("except")
            || arm_kind.contains("rescue")
            || arm_kind == "on_part")
        {
            continue;
        }
        // Try every field name known to wrap the binding.
        if let Some(parameter_node) = catch_arm
            .child_by_field_name("parameter")
            .or_else(|| catch_arm.child_by_field_name("catch_parameter"))
            .or_else(|| catch_arm.child_by_field_name("exception_parameter"))
            .or_else(|| catch_arm.child_by_field_name("name"))
            .or_else(|| catch_arm.child_by_field_name("variable"))
        {
            let binding_identifier = catch_binding_identifier(parameter_node).or_else(|| {
                first_identifier_descendant(parameter_node).or_else(|| {
                    if looks_like_identifier(parameter_node.kind()) {
                        Some(parameter_node)
                    } else {
                        None
                    }
                })
            });
            if let Some(identifier) = binding_identifier {
                return Some(node_text(&identifier, src).trim().to_string());
            }
        }
        // Python: catch parameter wrapped under a `value` field.
        if let Some(value_node) = catch_arm.child_by_field_name("value") {
            if let Some(identifier) = catch_binding_identifier(value_node) {
                return Some(node_text(&identifier, src).trim().to_string());
            }
        }
        // Python `except E as e` — walk for the alias subtree directly.
        let mut inner_cursor = catch_arm.walk();
        for inner_child in catch_arm.named_children(&mut inner_cursor) {
            let inner_kind = inner_child.kind();
            if inner_kind == "as_pattern" || inner_kind == "as_pattern_target" || inner_kind == "alias" {
                if let Some(identifier) =
                    catch_binding_identifier(inner_child).or_else(|| first_identifier_descendant(inner_child))
                {
                    return Some(node_text(&identifier, src).trim().to_string());
                }
            }
        }
        // Fallback: first identifier descendant of the catch-arm itself —
        // covers compact forms like Ruby `rescue => e`. Note: for shapes
        // where the type identifier appears before the variable, the
        // fallback returns the type instead. Adapter post-processing
        // (e.g. `collect_java_catch_param_name`) corrects that.
        if let Some(identifier) = first_identifier_descendant(catch_arm) {
            return Some(node_text(&identifier, src).trim().to_string());
        }
    }
    None
}
