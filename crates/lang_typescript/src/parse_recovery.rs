//! Narrow recovery for valid TypeScript import-type queries.
//!
//! The upstream grammar accepts `import("pkg").Type`, but currently damages
//! that same type when an array suffix participates in a function type, for
//! example `() => import("pkg").Type[]`. TypeScript accepts the construct.
//! The raw CST still proves the complete `import` call and terminal property.
//! Replacing only the call-shaped object with a same-width synthetic type
//! identifier leaves `.Type[]`, preserves every source byte offset, and lets
//! the normal qualified-type production recover. The recovered node still
//! spans the complete original `import("pkg").Type`, so downstream adapters
//! read the exact source identity rather than a guessed bare `Type`.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};

pub(crate) fn typescript_parse_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let source = snapshot.text.as_bytes();
    let mut edits = Vec::new();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.is_error() {
            collect_import_type_qualifier_edits(node, source, &mut edits);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.has_error() || child.is_missing() {
                pending.push(child);
            }
        }
    }

    edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
    edits.dedup();
    edits
}

fn collect_import_type_qualifier_edits(
    error: tree_sitter::Node<'_>,
    source: &[u8],
    edits: &mut Vec<ParseRecoveryEdit>,
) {
    let mut pending = vec![error];
    while let Some(node) = pending.pop() {
        if node.kind() == "member_expression" {
            let object = node.child_by_field_name("object");
            let property = node.child_by_field_name("property");
            if let (Some(object), Some(property)) = (object, property) {
                if import_call_is_exact(object, source)
                    && has_type_context(node)
                    && object.start_byte() < property.start_byte()
                    && source
                        .get(object.end_byte()..property.start_byte())
                        .is_some_and(|separator| separator.contains(&b'.'))
                {
                    edits.push(ParseRecoveryEdit::replace_ascii(
                        object.start_byte(),
                        object.end_byte(),
                        b"IMPORTTYPE",
                    ));
                }
            }
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
}

fn has_type_context(mut node: tree_sitter::Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "type_annotation" | "function_type") {
            return true;
        }
        node = parent;
    }
    false
}

fn import_call_is_exact(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    function.kind() == "import"
        && source.get(function.start_byte()..function.end_byte()) == Some(b"import")
        && node
            .child_by_field_name("arguments")
            .is_some_and(|arguments| arguments.kind() == "arguments")
}
