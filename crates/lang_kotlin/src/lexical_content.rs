//! kotlin grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    if node.kind() == "character_literal" {
        return body::between_outer_children(node, src);
    }
    // This scanner hides the quotes, including on empty strings.
    let text = node_text(&node, src);
    let quote = if text.starts_with("\"\"\"") {
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
