//! objc grammar-owned lexical body boundaries.

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
            // Macro identifiers have no explicit lexical literal body here.
            "comment" | "identifier" => {}
            "string_literal" | "char_literal" => {
                // Objective-C emits @ as a separate token before the opening quote.
                let first = part.child(0)?;
                let opening = if first.kind() == "@" {
                    part.child(1)?
                } else {
                    first
                };
                let last = u32::try_from(part.child_count().checked_sub(1)?).ok()?;
                total += body::between(src, opening, part.child(last)?)?;
            }
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
