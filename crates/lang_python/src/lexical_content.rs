//! python grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    let mut pending = vec![node];
    let mut total = 0;
    while let Some(part) = pending.pop() {
        if part.has_error() {
            return None;
        }
        match part.kind() {
            "concatenated_string" => pending.extend(part.named_children(&mut part.walk())),
            "comment" => {}
            "string" => total += body::between_outer_children(part, src)?,
            _ => return None,
        }
    }
    Some(total)
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    body::delimited(node_text(&node, src), "#", "")
}
