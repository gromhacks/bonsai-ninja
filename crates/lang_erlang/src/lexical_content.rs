//! erlang grammar-owned lexical body boundaries.

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
            "multi_string" => pending.extend(part.named_children(&mut part.walk())),
            "comment" => {}
            "macro_string" => {
                let name = part.child_by_field_name("name")?;
                total += body::count(src, name.start_byte(), name.end_byte())?;
            }
            "string" => {
                // The Erlang scanner emits quoted strings as indivisible tokens.
                let text = node_text(&part, src);
                let quoted = if let Some(sigil) = text.strip_prefix('~') {
                    sigil.strip_prefix(['s', 'S', 'b', 'B']).unwrap_or(sigil)
                } else {
                    text
                };
                if quoted.starts_with("\"\"\"") {
                    // Erlang permits any matching quote run of length >= 3.
                    let quotes = quoted.bytes().take_while(|byte| *byte == b'"').count();
                    let delimiter = quoted.get(..quotes)?;
                    total += body::delimited(quoted, delimiter, delimiter)?;
                } else {
                    let opening = quoted.get(..quoted.chars().next()?.len_utf8())?;
                    let closing = match opening {
                        "(" => ")",
                        "[" => "]",
                        "{" => "}",
                        "<" => ">",
                        other => other,
                    };
                    total += body::delimited(quoted, opening, closing)?;
                }
            }
            _ => return None,
        }
    }
    Some(total)
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    let text = node_text(&node, src);
    // Erlang comment/documentation markers are a leading run of percent signs.
    let marker_len = text.bytes().take_while(|byte| *byte == b'%').count();
    (marker_len > 0).then(|| text[marker_len..].chars().count())
}
