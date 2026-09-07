//! Language-neutral counting primitives. Adapters select every body span and
//! delimiter; this module neither recognizes source syntax nor decodes values.

use tree_sitter::Node;

/// Count Unicode scalar values in an exact source range, including whitespace.
pub fn count(src: &[u8], start: usize, end: usize) -> Option<usize> {
    Some(std::str::from_utf8(src.get(start..end)?).ok()?.chars().count())
}

/// Count the source between two adapter-selected delimiter nodes.
pub fn between(src: &[u8], opening: Node<'_>, closing: Node<'_>) -> Option<usize> {
    if opening.is_missing() || closing.is_missing() {
        return None;
    }
    count(src, opening.end_byte(), closing.start_byte())
}

/// For grammars where the first and last children are the complete delimiters.
/// Adapters must opt in only for node kinds with that grammar contract.
pub fn between_outer_children(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() || node.child_count() < 2 {
        return None;
    }
    let last = u32::try_from(node.child_count() - 1).ok()?;
    between(src, node.child(0)?, node.child(last)?)
}

/// Strip one exact adapter-specified delimiter pair from a lexical token.
/// An empty closing delimiter is useful for line comments. No trimming,
/// decoding, or repeated marker removal is performed.
pub fn delimited(text: &str, opening: &str, closing: &str) -> Option<usize> {
    Some(text.strip_prefix(opening)?.strip_suffix(closing)?.chars().count())
}
