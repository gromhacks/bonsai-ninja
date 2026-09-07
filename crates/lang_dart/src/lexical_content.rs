//! dart grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_text};
use tree_sitter::Node;

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    // Adjacent literals share a single node. Content text is often anonymous,
    // so sum the intervals between each pair of grammar-emitted quote tokens.
    let mut opening = None;
    let mut total = 0;
    let mut saw_pair = false;
    for child in node.children(&mut node.walk()) {
        if matches!(
            child.kind(),
            "\"" | "'" | "\"\"\"" | "'''" | "r\"" | "r'" | "r\"\"\"" | "r'''"
        ) {
            if let Some(start) = opening.take() {
                total += body::between(src, start, child)?;
                saw_pair = true;
            } else {
                opening = Some(child);
            }
        }
    }
    (saw_pair && opening.is_none()).then_some(total)
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
