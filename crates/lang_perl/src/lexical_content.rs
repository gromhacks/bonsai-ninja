//! perl grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    // The content field skips leading whitespace as grammar extras. Count
    // between the actual delimiters for both empty and populated bodies.
    // q/qq and their paired delimiters are separate tokens; the delimiters
    // share this grammar alias, independent of their source spelling.
    let mut cursor = node.walk();
    let mut delimiters = node.children(&mut cursor).filter(|child| child.kind() == "'");
    body::between(src, delimiters.next()?, delimiters.next()?)
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    body::delimited(node_text(&node, src), "#", "")
}
