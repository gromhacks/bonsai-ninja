//! Comment / doc-comment / docstring extraction.
//!
//! Collects every comment node across the supported grammars as a
//! [`crate::Comment`], classifying doc-comments by grammar-native kinds
//! where available and by marker-sniffing (`///`, `/**`, `#'`, `"""..."""`
//! docstrings) as a fallback.

use bonsai_common::FileId;

#[allow(clippy::wildcard_imports)]
use super::*;

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
pub fn extract_comments(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::Comment> {
    // Every tree-sitter grammar in the pack emits comments as one of
    // these node kinds. Union is language-agnostic; the adapter
    // doesn't need to opt in.
    const COMMENT_KINDS: &[&str] = &[
        "comment",
        "line_comment",
        "block_comment",
        "shebang",
        "hash_bang_line",
        // Rust grammar distinguishes these.
        "doc_comment",
        "inner_doc_comment_marker",
        "outer_doc_comment_marker",
        // Kotlin / Swift doc comment variants.
        "documentation_comment",
        "multiline_comment",
        // Dart / JS dedicated doc variants.
        "dartdoc_comment",
        "jsdoc_comment",
        // Python docstring — tree-sitter-python surfaces it as a
        // string inside an expression_statement, handled separately
        // below so we don't double-count regular strings.
    ];
    let mut out = Vec::new();
    let mut cursor = tree.walk();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if COMMENT_KINDS.contains(&node.kind()) {
            let text = node_text(&node, src).trim().to_string();
            if !text.is_empty() {
                let body = strip_comment_markers(&text);
                let is_doc = is_doc_comment_kind_or_text(node.kind(), &text);
                out.push(crate::Comment {
                    span: span_of(file, &node),
                    kind: crate::CommentKind::classify(&body, is_doc),
                    text,
                });
                continue;
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    // Python docstring convention: the first statement of a
    // function / class / module body is a bare string expression.
    // Tree-sitter surfaces it as `expression_statement > string`;
    // treat those as Doc comments so `comments --kind doc` finds
    // them alongside `///` / `/** */` docs in other grammars.
    collect_python_docstrings(tree, src, file, &mut out);
    out
}

/// Strip the syntactic comment markers from a raw comment slice so
/// the classifier sees just the content. Handles `//`, `#`, `--`,
/// `%`, `;`, `/* ... */`, `"""..."""`, `'''...'''`.
fn strip_comment_markers(text: &str) -> String {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("///") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("//!") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("//") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("#!") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix('#') {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("--") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix('%') {
        return rest.trim().to_string();
    }
    if t.starts_with("/**") {
        return t
            .trim_start_matches("/**")
            .trim_end_matches("*/")
            .lines()
            .map(|l| l.trim().trim_start_matches('*').trim())
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
    }
    if t.starts_with("/*") {
        return t
            .trim_start_matches("/*")
            .trim_end_matches("*/")
            .trim()
            .to_string();
    }
    if t.starts_with("\"\"\"") {
        return t.trim_matches('"').trim().to_string();
    }
    if t.starts_with("'''") {
        return t.trim_matches('\'').trim().to_string();
    }
    t.to_string()
}

fn is_doc_comment_kind_or_text(kind: &str, text: &str) -> bool {
    matches!(
        kind,
        "doc_comment"
            | "documentation_comment"
            | "dartdoc_comment"
            | "jsdoc_comment"
            | "outer_doc_comment_marker"
            | "inner_doc_comment_marker"
    ) || text.starts_with("///")
        || text.starts_with("//!")
        || text.starts_with("/**")
        || text.starts_with("#'")
}

fn collect_python_docstrings(
    tree: &tree_sitter::Tree,
    src: &[u8],
    file: FileId,
    out: &mut Vec<crate::Comment>,
) {
    // Python tree-sitter: function_definition / class_definition /
    // module have a `body` field whose first named child may be an
    // `expression_statement` whose first child is a `string`.
    let mut cursor = tree.walk();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let is_scope = matches!(
            node.kind(),
            "module" | "function_definition" | "class_definition" | "async_function_definition"
        );
        if is_scope {
            let body = node
                .child_by_field_name("body")
                .or_else(|| first_named_child_of_kind(&node, "block"))
                .unwrap_or(node);
            if let Some(first) = body.named_children(&mut body.walk()).next() {
                let target = if first.kind() == "expression_statement" {
                    first.named_children(&mut first.walk()).next().unwrap_or(first)
                } else {
                    first
                };
                if matches!(target.kind(), "string" | "string_literal") {
                    let text = node_text(&target, src).trim().to_string();
                    if text.starts_with("\"\"\"") || text.starts_with("'''") {
                        let body_text = strip_comment_markers(&text);
                        out.push(crate::Comment {
                            span: span_of(file, &target),
                            kind: crate::CommentKind::classify(&body_text, true),
                            text,
                        });
                    }
                }
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
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

        let comments = extract_comments(&tree, FileId::new(0), source.as_bytes());

        assert!(comments.iter().any(|comment| comment.text.contains(&content)));
    }
}
