//! Return / throw / catch value extraction.
//!
//! Adapters report structured `ExpressionFlow` facts alongside display-only
//! return/yield text. This module obtains those facts from tree-sitter value
//! nodes; semantic consumers never reparse the display text.
//!
//! Text remains useful for rendering. Some tree-sitter grammars (notably older
//! grammar revisions) emit `return EXPR;` as a flat statement node
//! with no `value` / `expression` / `argument` field. Rather than
//! per-grammar special cases, the renderer strips the leading keyword. That
//! fallback does not populate `ExpressionFlow`.
//!
//! `extract_catch_param` is the matching reader for try/catch
//! binding patterns — `catch (FooException e)`, `except E as e`,
//! `rescue => e`. The structure varies wildly across languages so
//! this lives next to the throw extractor rather than in a separate
//! module.

use bonsai_common::{FileId, Span};
use tree_sitter::Node;

use crate::ExpressionFlow;

use super::{
    expression_flow_from_node, first_identifier_descendant, first_identifier_like_child,
    looks_like_identifier, looks_like_literal_value, node_text,
};

/// Lower the parsed return operand into structured compiler facts.
#[must_use]
pub fn extract_return_value_flow(node: &Node<'_>, file: FileId, src: &[u8]) -> ExpressionFlow {
    let Some(value) = return_value_node(node) else {
        return ExpressionFlow::default();
    };
    if let Some(selector) = dart_selector_call(&value) {
        // Dart's grammar represents `f(x)` as sibling AST nodes rather than
        // one call node. Join those exact syntax spans into the same call-site
        // identity emitted by the call walker; no callee spelling is parsed.
        return ExpressionFlow {
            call_sites: vec![Span::new(
                file,
                value.start_byte() as u64,
                selector.end_byte() as u64,
            )],
            ..ExpressionFlow::default()
        };
    }
    expression_flow_from_node(value, file, src)
}

/// Lower the parsed yield operand into structured compiler facts.
#[must_use]
pub fn extract_yield_value_flow(node: &Node<'_>, file: FileId, src: &[u8]) -> ExpressionFlow {
    yield_value_node(node)
        .map(|value| expression_flow_from_node(value, file, src))
        .unwrap_or_default()
}

/// Extract the single value-bearing identifier of the value being
/// returned when the adapter can determine one precisely.
/// `return x` and `return `${x}`` → `Some("x")`; multi-operand
/// expressions such as `return x + y` remain `None`.
pub fn extract_return_value_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let Some(value_node) = return_value_node(node) else {
        // Without an operand node there is no compiler fact. Raw statement
        // text remains available to the renderer, but semantic lowering must
        // not recover an identifier by reparsing it.
        return None;
    };
    let value_kind = value_node.kind();
    // Direct identifier — most languages parse `return x` this way.
    if looks_like_identifier(value_kind) {
        // Dart models a call as a bare `identifier` (the callee) followed by
        // a sibling `selector` holding the `argument_part` — `return foo(x)`
        // parses as `identifier "foo"` + `selector((x))`, with no unified
        // call node. The identifier is the CALLEE, not the returned value:
        // recording it as `value_name` fabricates a read of the function
        // name (a spurious `read` ref) and a return-of-a-symbol. The value
        // is the call's result, carried by the Call event + value_text.
        if dart_selector_call_callee(&value_node) {
            return None;
        }
        let text = node_text(&value_node, src).trim().to_string();
        if !looks_like_literal_value(value_kind, &text) {
            return Some(text);
        }
        return None;
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
    // Perl wraps a sigiled variable in `scalar` / `array` / `hash` and
    // exposes the binding as its sole `varname` child. Preserve the sigil
    // from that exact AST node; compound dereferences/subscripts have extra
    // children and deliberately do not take this single-place path.
    if matches!(value_kind, "scalar" | "array" | "hash") {
        let mut cursor = value_node.walk();
        let children: Vec<Node<'_>> = value_node.named_children(&mut cursor).collect();
        if children.len() == 1 && children[0].kind() == "varname" {
            let value = node_text(&value_node, src).trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
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

/// True when `node` is the callee identifier of a Dart selector call —
/// a bare `identifier` immediately followed by a sibling `selector` whose
/// child is an `argument_part` (`foo` `(args)`). tree-sitter-dart has no
/// unified call node, so this is how `foo(x)` is shaped; the identifier is
/// the callee, not a value. Property/cascade selectors (`.field`, `..m()`)
/// carry no `argument_part`, so a pure member read still returns its name.
fn dart_selector_call_callee(node: &Node<'_>) -> bool {
    dart_selector_call(node).is_some()
}

fn dart_selector_call<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let selector = node.next_named_sibling()?;
    if selector.kind() != "selector" {
        return None;
    }
    let mut cursor = selector.walk();
    let has_argument_part = selector
        .named_children(&mut cursor)
        .any(|child| child.kind() == "argument_part");
    has_argument_part.then_some(selector)
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
/// This field is rendering-only; dataflow comes from
/// [`extract_return_value_flow`].
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

fn yield_value_node<'a>(node: &'a Node<'a>) -> Option<Node<'a>> {
    for field in ["value", "expression", "argument", "operand", "body"] {
        if let Some(value) = node.child_by_field_name(field) {
            return Some(value);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !matches!(child.kind(), "yield" | "yield_from" | "from" | "yield_keyword")
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
