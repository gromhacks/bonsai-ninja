//! Comment / doc-comment / docstring extraction.
//!
//! Collects every comment node across the supported grammars as a
//! [`crate::Comment`], classifying doc-comments by grammar-native kinds
//! where available and by marker-sniffing (`///`, `/**`, `#'`, `"""..."""`
//! docstrings) as a fallback.

use bonsai_common::FileId;

#[allow(clippy::wildcard_imports)]
use super::*;

/// Whether a grammar node is comment-only syntax rather than a value-bearing
/// expression. Adapters and shared lowering use this at syntax boundaries so
/// a named comment node can never shift positional argument indices.
pub(super) fn is_comment_node_kind(handler: &GrammarHandler, kind: &str) -> bool {
    handler.comment_kinds.contains(&kind)
}

/// Collect every comment node in the tree, classifying each by its
/// stripped body. Tree-sitter grammars surface comments as one of a
/// small set of node kinds (`comment`, `line_comment`, `block_comment`,
/// Python's `comment`, Ruby's `comment`, Erlang's `comment`, etc.).
/// We accept the union so every supported grammar contributes.
///
/// Doc-comments are detected by grammar-native kinds where available
/// (`doc_comment`, `documentation_comment`, `outer_doc_comment_marker`)
/// and by marker-sniffing (`///`, `/**`, `#'`, `"""..."""` docstrings)
/// as a fallback.
pub fn extract_comments(
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<crate::Comment> {
    let mut out = Vec::new();
    let mut cursor = tree.walk();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if is_comment_node_kind(handler, node.kind()) {
            let text = node_text(&node, src).trim().to_string();
            if !text.is_empty() {
                let is_doc = handler.doc_comment_kinds.contains(&node.kind())
                    || handler
                        .doc_comment_prefixes
                        .iter()
                        .any(|prefix| text.starts_with(prefix));
                out.push(crate::Comment {
                    span: span_of(file, &node),
                    kind: crate::CommentKind::classify(&text, is_doc),
                    text,
                });
                continue;
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extraction_preserves_large_ast_comments() {
        let content = "x".repeat(8_192);
        let source = format!("// {content}\nconst value = 1;");
        let language = language_from_pack("javascript").expect("javascript grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set grammar");
        let tree = parser.parse(source.as_bytes(), None).expect("parse source");

        let comments = extract_comments(&tree, FileId::new(0), source.as_bytes(), &GENERIC_HANDLER);

        assert!(comments.iter().any(|comment| comment.text.contains(&content)));
    }
}
