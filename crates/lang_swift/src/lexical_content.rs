//! swift grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    if node.kind() != "raw_string_literal" {
        return body::between_outer_children(node, src);
    }
    // Raw strings are scanner tokens, including their pound delimiters.
    let text = node_text(&node, src);
    let hashes = text.bytes().take_while(|byte| *byte == b'#').count();
    let marker = text.get(..hashes)?;
    let quoted = text.strip_prefix(marker)?.strip_suffix(marker)?;
    let quote = if quoted.starts_with("\"\"\"") {
        "\"\"\""
    } else {
        "\""
    };
    body::delimited(quoted, quote, quote)
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
    let opening = ["///", "//"]
        .into_iter()
        .find(|prefix| text.starts_with(prefix))?;
    body::delimited(text, opening, "")
}
