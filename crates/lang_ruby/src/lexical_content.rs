//! ruby grammar-owned lexical body boundaries.

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
            "chained_string" => pending.extend(part.named_children(&mut part.walk())),
            "comment" => {}
            "string" => total += body::between_outer_children(part, src)?,
            "heredoc_body" => {
                let end = part
                    .named_children(&mut part.walk())
                    .find(|child| child.kind() == "heredoc_end")?;
                // Heredoc content is a separate parser-owned body; the start
                // marker belongs to a different node on the preceding line.
                total += body::count(src, part.start_byte(), end.start_byte())?;
            }
            _ => return None,
        }
    }
    Some(total)
}

pub(super) fn comment_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    let text = node_text(&node, src);
    if text.starts_with("=begin") {
        // The end directive may carry trailing text. The scanner owns the
        // complete comment token, so locate its final line-start directive.
        let end = text.rfind("\n=end")? + 1;
        return body::count(src, node.start_byte() + "=begin".len(), node.start_byte() + end);
    }
    body::delimited(text, "#", "")
}
