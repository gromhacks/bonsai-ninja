//! rust grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    match node.kind() {
        "raw_string_literal" => {
            // The scanner exposes the exact body even for r"", arbitrary
            // hash delimiters, and byte/C prefixes.
            let content = node
                .named_children(&mut node.walk())
                .find(|child| child.kind() == "string_content")?;
            body::count(src, content.start_byte(), content.end_byte())
        }
        "char_literal" => {
            let text = node_text(&node, src);
            body::delimited(text.strip_prefix('b').unwrap_or(text), "'", "'")
        }
        "string_literal" => body::between_outer_children(node, src),
        _ => None,
    }
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    let opening = node.child(0)?;
    let start = node
        .child_by_field_name("outer")
        .or_else(|| node.child_by_field_name("inner"))
        .map_or(opening.end_byte(), |marker| marker.end_byte());
    if node.kind() == "block_comment" {
        let closing = node.child(u32::try_from(node.child_count().checked_sub(1)?).ok()?)?;
        return body::count(src, start, closing.start_byte());
    }
    // Rust doc-comment tokens include the line terminator; it is not body.
    let text = node_text(&node, src);
    let without_newline = text.strip_suffix('\n').unwrap_or(text);
    let without_newline = without_newline.strip_suffix('\r').unwrap_or(without_newline);
    body::count(src, start, node.start_byte() + without_newline.len())
}
