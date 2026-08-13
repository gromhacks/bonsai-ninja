//! Narrow recovery for a valid Kotlin multiplatform declaration shape.
//!
//! The bundled grammar can synthesize a hidden `_import_list_delimiter`
//! immediately before a KDoc comment on an `actual` top-level class. The
//! declaration itself is otherwise parsed correctly, but the hidden missing
//! node marks the entire file incomplete and is not iterable through the
//! public Tree-sitter node API. Masking only that independently recognized
//! KDoc comment in the private parser buffer lets the grammar consume the
//! same newline-delimited import/declaration boundary. Original source and
//! every declaration span remain unchanged.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};

pub(crate) fn kotlin_parse_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let root = tree.root_node();
    let mut cursor = root.walk();
    let children = root.named_children(&mut cursor).collect::<Vec<_>>();
    for pair in children.windows(2) {
        let imports = pair[0];
        let declaration = pair[1];
        if imports.kind() != "import_list" || declaration.kind() != "class_declaration" {
            continue;
        }
        let source = snapshot.text.as_ref();
        let Some(declaration_text) = source.get(declaration.start_byte()..declaration.end_byte()) else {
            continue;
        };
        if !declaration_text
            .strip_prefix("actual")
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        {
            continue;
        }
        let mut import_cursor = imports.walk();
        let Some(last_import) = imports
            .named_children(&mut import_cursor)
            .filter(|child| child.kind() == "import_header")
            .max_by_key(|child| child.end_byte())
        else {
            continue;
        };
        let mut header_cursor = last_import.walk();
        let gap_start = last_import
            .named_children(&mut header_cursor)
            .last()
            .map_or(last_import.start_byte(), |child| child.end_byte());
        let gap_end = declaration.start_byte();
        let Some(gap) = source.get(gap_start..gap_end) else {
            continue;
        };
        let leading = gap.len().saturating_sub(gap.trim_start().len());
        let trimmed = gap.trim();
        if !trimmed.starts_with("/**") || !trimmed.ends_with("*/") {
            continue;
        }
        let trailing = gap.len().saturating_sub(gap.trim_end().len());
        let comment_start = gap_start + leading;
        let comment_end = gap_end.saturating_sub(trailing);
        if comment_start < comment_end {
            return vec![ParseRecoveryEdit::new(comment_start, comment_end)];
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::{kit::language_from_pack, Vfs};

    #[test]
    fn recovers_kdoc_before_actual_class_without_moving_spans() {
        let source = "package sample\n\nimport sample.Platform\n\n/** Docs. */\nactual class PlatformLogger actual private constructor()\n";
        let vfs = Vfs::new();
        let file = vfs.write("PlatformLogger.kt", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("kotlin").expect("Kotlin grammar"))
            .expect("set Kotlin grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());
        let edits = kotlin_parse_recovery_edits(&snapshot, &tree);
        assert_eq!(edits.len(), 1);
        let mut recovered = source.as_bytes().to_vec();
        assert!(edits[0].apply_to(source, &mut recovered));
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        let recovered_tree = parser.parse(recovered, None).expect("recovery parse");
        assert!(!recovered_tree.root_node().has_error());
        assert_eq!(recovered.len(), source.len());
    }

    #[test]
    fn does_not_mask_kdoc_before_ordinary_class() {
        let source = "package sample\n\nimport sample.Platform\n\n/** Docs. */\nclass PlatformLogger\n";
        let vfs = Vfs::new();
        let file = vfs.write("PlatformLogger.kt", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("kotlin").expect("Kotlin grammar"))
            .expect("set Kotlin grammar");
        let tree = parser.parse(source, None).expect("parse");

        assert!(kotlin_parse_recovery_edits(&snapshot, &tree).is_empty());
    }
}
