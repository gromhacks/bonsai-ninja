//! cpp grammar-owned lexical body boundaries.

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
            // A macro identifier between literal pieces is adjacency syntax;
            // its expansion is not a lexical source body in this occurrence.
            "comment" | "identifier" => {}
            "raw_string_literal" => {
                let content = part
                    .named_children(&mut part.walk())
                    .find(|child| child.kind() == "raw_string_content")?;
                total += body::count(src, content.start_byte(), content.end_byte())?;
            }
            "string_literal" | "char_literal" => total += body::between_outer_children(part, src)?,
            _ => return None,
        }
    }
    Some(total)
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
    let opening = ["///", "//!", "//"]
        .into_iter()
        .find(|prefix| text.starts_with(prefix))?;
    body::delimited(text, opening, "")
}
