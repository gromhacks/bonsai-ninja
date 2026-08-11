//! Decorator / annotation / attribute reference extraction.
//!
//! Surfaces `@decorator` (Python/JS/TS), `@Annotation` (Java/Kotlin),
//! `#[attr]` (Rust), `[[attr]]` (C/C++), `[Attr]` (C#), and Perl `:attr`
//! subroutine attributes as [`crate::RefKind::Decorator`] references, so
//! rule/browse surfaces can match them without per-grammar handling.

use bonsai_common::FileId;
use tree_sitter::Tree;

use super::{
    collect_kinds, first_identifier_descendant, first_identifier_like_child, node_text, span_of,
    GrammarHandler,
};

/// Scan the tree for decorator / annotation nodes across common grammars.
/// Returns one [`crate::Ref`] per decorator usage (not per definition); the
/// `name` is the decorator's identifier (e.g. `audited` for `@audited`,
/// `Deprecated` for `@Deprecated`). `kind` is always
/// [`crate::RefKind::Decorator`].
pub fn extract_decorators(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<crate::Ref> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, handler.decorator_kinds) {
        // Prefer a named-field lookup for the decorator's target name.
        let name_node = node
            .child_by_field_name("name")
            .or_else(|| first_identifier_like_child(&node))
            .or_else(|| first_identifier_descendant(node));
        let Some(name_node) = name_node else { continue };
        let name = node_text(&name_node, src)
            .trim_start_matches('@')
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        out.push(crate::Ref {
            span: span_of(file, &node),
            name,
            kind: crate::RefKind::Decorator,
            scope: None,
            resolved: None,
        });
    }
    out
}
