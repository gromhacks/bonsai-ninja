//! lua grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    body::between(
        src,
        node.child_by_field_name("start")?,
        node.child_by_field_name("end")?,
    )
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    if node.kind() == "hash_bang_line" {
        return body::delimited(node_text(&node, src), "#!", "");
    }
    let opening = node.child_by_field_name("start")?;
    if let Some(closing) = node.child_by_field_name("end") {
        return body::between(src, opening, closing);
    }
    let start = if node_text(&node, src).starts_with("---") {
        opening.end_byte() + 1
    } else {
        opening.end_byte()
    };
    body::count(src, start, node.end_byte())
}
