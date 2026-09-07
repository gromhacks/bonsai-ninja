//! scala grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(mut node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    if node.kind() == "interpolated_string_expression" {
        node = node
            .named_children(&mut node.walk())
            .find(|child| child.kind() == "interpolated_string")?;
    }
    // The scanner hides the closing quote and, for ordinary strings, both.
    let text = node_text(&node, src);
    let quote = if node.kind() == "character_literal" {
        "'"
    } else if text.starts_with("\"\"\"") {
        "\"\"\""
    } else {
        "\""
    };
    body::delimited(text, quote, quote)
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    let text = node_text(&node, src);
    if text.starts_with("/*") {
        // /**/ is an empty block, with overlapping doc/closing spellings.
        let opening = if text.starts_with("/**") && text.len() > 4 {
            "/**"
        } else {
            "/*"
        };
        return body::delimited(text, opening, "*/");
    }
    let opening = ["//"].into_iter().find(|prefix| text.starts_with(prefix))?;
    body::delimited(text, opening, "")
}
