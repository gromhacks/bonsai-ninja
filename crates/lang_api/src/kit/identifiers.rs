//! Identifier-shape probes shared by every adapter.
//!
//! These helpers answer "does this node look like an identifier?" /
//! "does this string look like a bare identifier?" without committing
//! to any one grammar's vocabulary. Adapters use them through the
//! `kit` re-exports; the implementations here aim to be the smallest
//! cross-language predicate that's correct for every supported
//! tree-sitter grammar.
//!
//! Why a shared module rather than per-adapter:
//!
//! - The kind names tree-sitter uses for identifiers are remarkably
//!   uniform — every grammar emits something ending in `identifier`
//!   or `_name`, with a small handful of exceptions (`name`, `word`,
//!   Erlang's `var`).
//! - The string-shape predicate `looks_like_bare_identifier` is
//!   used in three different stages of the kit (return-value
//!   extraction, foreach binding shapes, generic call-arg parsing)
//!   and divergence between callers would silently change how
//!   identifier-shaped fallbacks fire.

use tree_sitter::Node;

/// First named child regardless of kind.
#[must_use]
pub fn first_named_child<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next();
    first
}

/// First named child of the given kind, if any.
#[must_use]
pub fn first_named_child_of_kind<'tree>(node: &Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

/// True when `node` has at least one direct named child of the given kind.
pub(crate) fn has_direct_child_kind(node: &Node<'_>, kind: &str) -> bool {
    first_named_child_of_kind(node, kind).is_some()
}

/// Pre-order DFS for the first descendant whose kind looks like an
/// identifier. Visits children in source order (leftmost first), so for
/// `void f(int x)` the result is `f`, not the parameter's `x`.
#[must_use]
pub fn first_identifier_descendant<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    // Stack-based pre-order: push children right-to-left so the leftmost
    // child is popped first.
    let mut work_stack = vec![node];
    while let Some(current) = work_stack.pop() {
        // Skip the original root — we only return a descendant.
        if current != node && looks_like_identifier(current.kind()) {
            return Some(current);
        }
        let mut cursor = current.walk();
        let children: Vec<Node<'tree>> = current.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            work_stack.push(child);
        }
    }
    None
}

/// First named child whose kind name looks like an identifier.
#[must_use]
pub fn first_identifier_like_child<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if looks_like_identifier(child.kind()) {
            return Some(child);
        }
    }
    None
}

/// True when `kind` (a tree-sitter node kind name) is identifier-shaped.
///
/// Most grammars use `*identifier` or `*_name`. Erlang's `var` node
/// is a bound variable binding (capitalized by language convention —
/// `Token`, `Action`); treat it as identifier-like for param extraction.
#[inline]
#[must_use]
pub fn looks_like_identifier(kind: &str) -> bool {
    kind.ends_with("identifier")
        || kind.ends_with("_name")
        || kind == "name"
        || kind == "word"
        || kind == "var"
}

/// True when `s` is a single, sigil-free identifier (`_`, ASCII
/// alphanumeric, no separators, no whitespace, no operators).
#[inline]
#[must_use]
pub fn looks_like_bare_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::{looks_like_bare_identifier, looks_like_identifier};

    #[test]
    fn identifier_kinds_recognized() {
        assert!(looks_like_identifier("identifier"));
        assert!(looks_like_identifier("type_identifier"));
        assert!(looks_like_identifier("scoped_identifier"));
        assert!(looks_like_identifier("field_name"));
        assert!(looks_like_identifier("name"));
        assert!(looks_like_identifier("word"));
        assert!(looks_like_identifier("var"));
        assert!(!looks_like_identifier("call_expression"));
        assert!(!looks_like_identifier("string_literal"));
        assert!(!looks_like_identifier(""));
    }

    #[test]
    fn bare_identifier_predicate() {
        assert!(looks_like_bare_identifier("foo"));
        assert!(looks_like_bare_identifier("_foo"));
        assert!(looks_like_bare_identifier("Foo123"));
        assert!(looks_like_bare_identifier("snake_case_name"));
        assert!(!looks_like_bare_identifier(""));
        assert!(!looks_like_bare_identifier("123abc"));
        assert!(!looks_like_bare_identifier("foo.bar"));
        assert!(!looks_like_bare_identifier("foo->bar"));
        assert!(!looks_like_bare_identifier("foo bar"));
        assert!(!looks_like_bare_identifier("$foo"));
        assert!(!looks_like_bare_identifier("@foo"));
    }
}
