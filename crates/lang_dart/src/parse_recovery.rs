//! Recovery for Dart's unnamed library declaration.
//!
//! Modern Dart accepts `library;` to attach library-level metadata without a
//! name. The bundled grammar still requires a name inside its `library_name`
//! node. Masking that exact top-level declaration changes no executable or
//! import semantics and keeps all following source coordinates stable.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};

pub(crate) fn dart_parse_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }
    let source = snapshot.text.as_ref();
    let root = tree.root_node();
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .filter(|node| node.kind() == "library_name" && node.has_error())
        .filter(|node| source.get(node.start_byte()..node.end_byte()) == Some("library;"))
        .map(|node| ParseRecoveryEdit::new(node.start_byte(), node.end_byte()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::{kit::language_from_pack, Vfs};

    #[test]
    fn recovers_unnamed_library_declaration_without_moving_spans() {
        let source = "library;\nimport 'dart:io';\nvoid main() { print('ok'); }\n";
        let vfs = Vfs::new();
        let file = vfs.write("main.dart", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("dart").expect("Dart grammar"))
            .expect("set Dart grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());

        let edits = dart_parse_recovery_edits(&snapshot, &tree);
        assert_eq!(edits.len(), 1);
        let mut recovered = source.as_bytes().to_vec();
        assert!(edits[0].apply_to(source, &mut recovered));
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        let candidate = parser.parse(recovered, None).expect("recovery parse");
        assert!(!candidate.root_node().has_error());
        assert_eq!(recovered.len(), source.len());
    }

    #[test]
    fn named_library_declaration_is_never_masked() {
        let source = "library sample;\nvoid main() {}\n";
        let vfs = Vfs::new();
        let file = vfs.write("main.dart", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("dart").expect("Dart grammar"))
            .expect("set Dart grammar");
        let tree = parser.parse(source, None).expect("parse");

        assert!(dart_parse_recovery_edits(&snapshot, &tree).is_empty());
    }
}
