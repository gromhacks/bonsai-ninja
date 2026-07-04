//! Decorator / annotation / attribute reference extraction.
//!
//! Surfaces `@decorator` (Python/JS/TS), `@Annotation` (Java/Kotlin),
//! `#[attr]` (Rust), `[[attr]]` (C/C++), `[Attr]` (C#), and Perl `:attr`
//! subroutine attributes as [`crate::RefKind::Decorator`] references, so
//! rule/browse surfaces can match them without per-grammar handling.

use bonsai_common::FileId;
use tree_sitter::{Node, Tree};

use super::{collect_kinds, first_identifier_descendant, first_identifier_like_child, node_text, span_of};

/// Scan the tree for decorator / annotation nodes across common grammars.
/// Returns one [`crate::Ref`] per decorator usage (not per definition); the
/// `name` is the decorator's identifier (e.g. `audited` for `@audited`,
/// `Deprecated` for `@Deprecated`). `kind` is always
/// [`crate::RefKind::Decorator`].
pub fn extract_decorators(tree: &Tree, file: FileId, src: &[u8]) -> Vec<crate::Ref> {
    const DECORATOR_KINDS: &[&str] = &[
        "decorator",
        "annotation",
        "marker_annotation",
        "normal_annotation",
        "single_element_annotation",
        "attribute",
        "attribute_item",
        "attribute_list",
        "property_modifier",
    ];
    let mut out = Vec::new();
    for node in collect_kinds(tree, DECORATOR_KINDS) {
        if !decorator_node_is_marker_syntax(&node, src) {
            continue;
        }
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

fn decorator_node_is_marker_syntax(node: &Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        // Python uses `attribute` for normal member access
        // (`pickle.loads`), while Swift and several annotation
        // grammars also use it for real `@objc`-style attributes.
        // Keep generic `attribute` support, but only when the node is
        // visibly marker syntax or lives under a real attribute list.
        "attribute" => {
            let raw = node_text(node, src);
            let trimmed = raw.trim_start();
            trimmed.starts_with('@')
                || trimmed.starts_with("#[")
                || trimmed.starts_with("[[")
                || node.parent().is_some_and(|parent| {
                    matches!(
                        parent.kind(),
                        // C# `[Attr]` → attribute_list; Java → attribute_item;
                        // C/C++ `[[nodiscard]]` → attribute_declaration; Perl
                        // `sub f :lvalue` → attrlist. All are real
                        // attribute/annotation markers, unlike Python's
                        // `attribute` member access (whose parent is a call /
                        // expression, so it stays excluded).
                        "attribute_list"
                            | "attribute_item"
                            | "attribute_declaration"
                            | "attribute_specifier"
                            | "attrlist"
                    )
                })
        }
        _ => true,
    }
}
