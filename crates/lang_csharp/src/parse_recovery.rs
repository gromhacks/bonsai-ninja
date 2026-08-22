//! Recovery for C# compiler directives that are outside Tree-sitter's grammar.
//!
//! C# permits preprocessor directives inside declarations and expressions.
//! Tree-sitter cannot always attach tokens wrapped by a no-alternative `#if`
//! block to the surrounding construct. Retaining those tokens models the
//! conservative union of build configurations; shared recovery rejects every
//! region with `#else`/`#elif` and preserves original byte coordinates.
//!
//! File-based programs also permit `#:` compiler directives such as SDK,
//! package, and build properties before the program body. They are compiler
//! metadata rather than executable C# syntax. Masking the complete directive
//! line in the parser buffer is therefore exact and leaves the original source
//! and every byte span authoritative.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};

pub(crate) fn csharp_parse_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let mut edits = bonsai_lang_api::branch_free_conditional_recovery_edits(
        snapshot,
        tree,
        bonsai_lang_api::ConditionalDirectiveSyntax {
            openings_with_condition: &["#if"],
            alternatives_with_condition: &["#elif"],
            alternatives_without_condition: &["#else"],
            closing: "#endif",
            trailing_comment_prefixes: &["//"],
        },
    );
    edits.extend(csharp_file_directive_edits(snapshot.text.as_ref()));
    edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
    edits.dedup();
    edits
}

fn csharp_file_directive_edits(source: &str) -> Vec<ParseRecoveryEdit> {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    let mut edits = Vec::new();
    while cursor < bytes.len() {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor..).is_some_and(|tail| tail.starts_with(b"//")) {
            cursor = line_end(bytes, cursor);
            continue;
        }
        if bytes.get(cursor..).is_some_and(|tail| tail.starts_with(b"/*")) {
            let Some(close) = bytes[cursor + 2..].windows(2).position(|window| window == b"*/") else {
                break;
            };
            cursor += close + 4;
            continue;
        }
        if cursor == 0 && bytes.starts_with(b"#!") {
            cursor = line_end(bytes, cursor);
            continue;
        }
        if bytes.get(cursor..).is_some_and(|tail| tail.starts_with(b"#:")) {
            let line_start = bytes[..cursor]
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |newline| newline + 1);
            if !bytes[line_start..cursor].iter().all(u8::is_ascii_whitespace) {
                break;
            }
            let end = line_end(bytes, cursor);
            edits.push(ParseRecoveryEdit::new(line_start, end));
            cursor = end;
            continue;
        }

        // File directives are compiler metadata only in the leading program
        // preamble. A later `#:` line is invalid C# and must remain a parser
        // diagnostic rather than being hidden by recovery.
        break;
    }
    edits
}

fn line_end(source: &[u8], start: usize) -> usize {
    source[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(source.len(), |newline| start + newline + 1)
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

    #[test]
    fn recovers_file_based_program_compiler_directives() {
        let source = "#:sdk Microsoft.NET.Sdk\n#:package Example.Package@1.2.3\n#:property PublishAot=true\n\nvar message = \"hello\";\nConsole.WriteLine(message);\n";
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
        assert_eq!(edits.len(), 3);
        let mut recovered = source.as_bytes().to_vec();
        for edit in edits {
            assert!(edit.apply_to(source, &mut recovered));
        }
        assert_eq!(recovered.len(), source.len());
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        assert!(!parser
            .parse(recovered, None)
            .expect("recovery parse")
            .root_node()
            .has_error());
    }

    #[test]
    fn does_not_recover_file_directive_after_program_tokens() {
        let source = "var message = \"hello\";\n#:package Example.Package@1.2.3\n";
        assert!(csharp_file_directive_edits(source).is_empty());

        let source = "/* comment */ var message = \"hello\";\n#:package Example.Package@1.2.3\n";
        assert!(csharp_file_directive_edits(source).is_empty());
    }
}
