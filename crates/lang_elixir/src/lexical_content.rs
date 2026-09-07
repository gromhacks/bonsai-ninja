//! elixir grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    body::between(
        src,
        node.child_by_field_name("quoted_start")?,
        node.child_by_field_name("quoted_end")?,
    )
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    body::delimited(node_text(&node, src), "#", "")
}
