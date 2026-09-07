//! csharp grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    match node.kind() {
        "verbatim_string_literal" => {
            let text = node_text(&node, src);
            body::delimited(text.strip_suffix("u8").unwrap_or(text), "@\"", "\"")
        }
        "string_literal" => {
            let opening = node.child(0)?;
            // The encoding suffix is a separate child after the closing quote.
            let closing = node
                .children(&mut node.walk())
                .find(|child| child.kind() == "\"" && child.start_byte() >= opening.end_byte())?;
            body::between(src, opening, closing)
        }
        "interpolated_string_expression" => {
            // The scanner emits the dollar/at prefix separately from the quote.
            let opening = node.child(1)?;
            let closing = node.child(u32::try_from(node.child_count().checked_sub(1)?).ok()?)?;
            body::between(src, opening, closing)
        }
        "raw_string_literal" | "character_literal" => body::between_outer_children(node, src),
        _ => None,
    }
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
