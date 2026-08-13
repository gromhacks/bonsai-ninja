//! Recovery for branch-free C# conditional-compilation regions.
//!
//! C# permits preprocessor directives inside declarations and expressions.
//! Tree-sitter cannot always attach tokens wrapped by a no-alternative `#if`
//! block to the surrounding construct. Retaining those tokens models the
//! conservative union of build configurations; shared recovery rejects every
//! region with `#else`/`#elif` and preserves original byte coordinates.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};

pub(crate) fn csharp_parse_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    bonsai_lang_api::branch_free_conditional_recovery_edits(
        snapshot,
        tree,
        bonsai_lang_api::ConditionalDirectiveSyntax {
            openings_with_condition: &["#if"],
            alternatives_with_condition: &["#elif"],
            alternatives_without_condition: &["#else"],
            closing: "#endif",
            trailing_comment_prefixes: &["//"],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::{kit::language_from_pack, Vfs};

    fn recovered_tree(source: &str) -> tree_sitter::Tree {
        let vfs = Vfs::new();
        let file = vfs.write("Example.cs", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("csharp").expect("C# grammar"))
            .expect("set C# grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());
        let edits = csharp_parse_recovery_edits(&snapshot, &tree);
        assert_eq!(edits.len(), 2);
        let mut recovered = source.as_bytes().to_vec();
        for edit in edits {
            assert!(edit.apply_to(source, &mut recovered));
        }
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        assert_eq!(recovered.len(), source.len());
        parser.parse(recovered, None).expect("recovery parse")
    }

    #[test]
    fn recovers_branch_free_conditional_access_modifier() {
        let source = "namespace Sample\n{\n#if !SAMPLE_INTERNAL\n    public\n#endif\n    enum EitherType { Left, Right }\n}\n";
        assert!(!recovered_tree(source).root_node().has_error());
    }

    #[test]
    fn recovers_branch_free_conditional_expression_fragment() {
        let source = "class Example { object Get(bool flag) { return\n#if FEATURE\nflag ? new object() :\n#endif\nnull; } }\n";
        assert!(!recovered_tree(source).root_node().has_error());
    }

    #[test]
    fn rejects_conditional_block_with_an_else_branch() {
        let source = "#if PUBLIC\npublic\n#else\ninternal\n#endif\nclass Example {}\n";
        let vfs = Vfs::new();
        let file = vfs.write("Example.cs", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("csharp").expect("C# grammar"))
            .expect("set C# grammar");
        let tree = parser.parse(source, None).expect("parse");

        assert!(csharp_parse_recovery_edits(&snapshot, &tree).is_empty());
    }
}
