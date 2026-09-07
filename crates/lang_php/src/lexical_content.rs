//! php grammar-owned lexical body boundaries.

use bonsai_lang_api::kit::{lexical_content as body, node_at_span, node_text};
use bonsai_lang_api::{StringCategory, StringLiteral};
use tree_sitter::{Node, Tree};

/// Preserve body-based browse categories when the inventory retains the
/// complete multiline literal, including its opening and closing tags.
pub(super) fn classify_multiline_strings(strings: &mut [StringLiteral], tree: &Tree, src: &[u8]) {
    for literal in strings {
        if !literal.text.starts_with("<<<") {
            continue;
        }
        let Some(node) = node_at_span(tree.root_node(), literal.span, &["heredoc", "nowdoc"]) else {
            continue;
        };
        if !matches!(node.kind(), "heredoc" | "nowdoc")
            || node.has_error()
            || node.start_byte() != literal.span.start as usize
            || node.end_byte() != literal.span.end as usize
        {
            continue;
        }
        literal.category = node
            .child_by_field_name("value")
            .map_or(StringCategory::Generic, |value| {
                StringCategory::classify(node_text(&value, src))
            });
    }
}

pub(super) fn string_content_len(node: Node<'_>, src: &[u8]) -> Option<usize> {
    if node.has_error() {
        return None;
    }
    match node.kind() {
        "heredoc" | "nowdoc" => {
            // The parser-owned body includes its leading newline and excludes
            // the end tag. An absent body denotes an empty heredoc/nowdoc.
            // Select the complete literal: empty nowdocs have no string child.
            node.child_by_field_name("end_tag")?;
            match node.child_by_field_name("value") {
                Some(content) => body::count(src, content.start_byte(), content.end_byte()),
                None => Some(0),
            }
        }
        "string" | "encapsed_string" => {
            // PHP's binary prefix/opening quote can be hidden by the grammar.
            let text = node_text(&node, src);
            let quoted = text
                .strip_prefix('b')
                .or_else(|| text.strip_prefix('B'))
                .unwrap_or(text);
            let quote = match quoted.as_bytes().first()? {
                b'\'' => "'",
                b'"' => "\"",
                _ => return None,
            };
            body::delimited(quoted, quote, quote)
        }
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
    let opening = ["//", "#"].into_iter().find(|prefix| text.starts_with(prefix))?;
    body::delimited(text, opening, "")
}
