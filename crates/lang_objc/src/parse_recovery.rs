//! Objective-C parser recovery from exact preprocessor/declaration shape.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree, Vfs};
use tree_sitter::Node;

pub(crate) fn objc_parse_recovery_edits(
    snapshot: &FileSnapshot,
    vfs: &Vfs,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    let mut edits = bonsai_lang_api::branch_free_conditional_recovery_edits(
        snapshot,
        tree,
        bonsai_lang_api::ConditionalDirectiveSyntax {
            openings_with_condition: &["#if", "#ifdef", "#ifndef"],
            alternatives_with_condition: &["#elif", "#elifdef", "#elifndef"],
            alternatives_without_condition: &["#else"],
            closing: "#endif",
            trailing_comment_prefixes: &["//", "/*"],
        },
    );
    edits.extend(bonsai_lang_api::c_family_declaration_macro_recovery_edits(
        snapshot,
        vfs,
        tree,
        &["va_arg", "__builtin_va_arg"],
    ));
    edits.extend(standalone_declaration_marker_edits(snapshot, tree));
    edits.extend(enum_macro_recovery_edits(snapshot, tree));
    edits.extend(nullability_qualifier_recovery_edits(snapshot, tree));
    edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
    edits.dedup();
    edits
}

/// Recover an otherwise-unparseable standalone preprocessor marker around an
/// Objective-C declaration region.
///
/// No macro spelling is assumed. In valid Objective-C, a bare identifier with
/// no semicolon cannot be a declaration or expression at file scope. When the
/// exact adjacent syntax is an `@interface`/`@protocol`/`@implementation`
/// region and Tree-sitter placed the marker in an ERROR span, its only valid
/// role is preprocessing metadata. Masking it preserves the declaration CST.
fn standalone_declaration_marker_edits(snapshot: &FileSnapshot, tree: &SyntaxTree) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }
    let source = snapshot.text.as_ref();
    let mut edits = Vec::new();
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let start = offset;
        let end = start + line.len();
        offset = end;
        let trimmed = line.trim();
        if !is_standalone_marker(trimmed) {
            continue;
        }
        let before = source[..start].trim_end();
        let begins_declaration = marker_chain_begins_declaration(&source[end..]);
        if begins_declaration || before.ends_with("@end") {
            edits.push(ParseRecoveryEdit::new(start, end));
        }
    }
    edits
}

fn marker_chain_begins_declaration(mut source: &str) -> bool {
    loop {
        source = skip_whitespace_and_comments(source);
        if ["@interface", "@protocol", "@implementation"]
            .iter()
            .any(|keyword| starts_keyword(source, keyword))
        {
            return true;
        }
        let (line, rest) = source.split_once('\n').unwrap_or((source, ""));
        if !is_standalone_marker(line.trim()) || rest.is_empty() {
            return false;
        }
        source = rest;
    }
}

fn error_ranges(tree: &SyntaxTree) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_error() {
            ranges.push((node.start_byte(), node.end_byte()));
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.has_error() || child.is_missing() {
                stack.push(child);
            }
        }
    }
    ranges
}

/// Mask Objective-C nullability specifiers only where the concrete grammar
/// placed them inside an ERROR node. They affect type contracts, not runtime
/// expression structure or dataflow.
fn nullability_qualifier_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    const QUALIFIERS: &[&str] = &[
        "nullable",
        "nonnull",
        "null_unspecified",
        "null_resettable",
        "_Nullable",
        "_Nonnull",
        "_Null_unspecified",
    ];
    let source = snapshot.text.as_ref();
    let bytes = source.as_bytes();
    let mut edits = Vec::new();
    for (error_start, error_end) in error_ranges(tree) {
        let Some(fragment) = source.get(error_start..error_end) else {
            continue;
        };
        for qualifier in QUALIFIERS {
            for (relative, _) in fragment.match_indices(qualifier) {
                let start = error_start + relative;
                let end = start + qualifier.len();
                if token_boundary(bytes, start, end) {
                    edits.push(ParseRecoveryEdit::new(start, end));
                }
            }
        }
    }
    edits
}

fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn is_standalone_marker(text: &str) -> bool {
    if is_identifier(text) {
        return true;
    }
    let Some(open) = text.find('(') else {
        return false;
    };
    if !is_identifier(text[..open].trim()) || !text.ends_with(')') {
        return false;
    }
    let mut depth = 0usize;
    for byte in text[open..].bytes() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            _ => {}
        }
    }
    depth == 0
}

/// Recover the structural `typedef MACRO(underlying, Name) { ... };` enum
/// form used by Objective-C SDK headers without knowing the macro spelling.
fn enum_macro_recovery_edits(snapshot: &FileSnapshot, tree: &SyntaxTree) -> Vec<ParseRecoveryEdit> {
    let source = snapshot.text.as_ref();
    let bytes = source.as_bytes();
    let errors = error_ranges(tree);
    let mut edits = Vec::new();
    for (typedef_start, _) in source.match_indices("typedef") {
        let typedef_end = typedef_start + "typedef".len();
        if !token_boundary(bytes, typedef_start, typedef_end) {
            continue;
        }
        let macro_start = skip_ascii_whitespace(bytes, typedef_end);
        let macro_end = scan_identifier(bytes, macro_start);
        if macro_end == macro_start || bytes.get(macro_end) != Some(&b'(') {
            continue;
        }
        let open = macro_end;
        let Some(close) = matching_paren(bytes, open) else {
            continue;
        };
        let Some(comma) = top_level_comma(bytes, open + 1, close) else {
            continue;
        };
        let name_start = skip_ascii_whitespace(bytes, comma + 1);
        let name_end = scan_identifier(bytes, name_start);
        if name_end == name_start
            || bytes[name_end..close]
                .iter()
                .any(|byte| !byte.is_ascii_whitespace())
        {
            continue;
        }
        let body_start = skip_ascii_whitespace(bytes, close + 1);
        if bytes.get(body_start) != Some(&b'{')
            || !errors
                .iter()
                .any(|(start, end)| typedef_start < *end && *start < body_start + 1)
        {
            continue;
        }
        edits.push(ParseRecoveryEdit::replace_ascii(
            typedef_start,
            typedef_end,
            b"enum",
        ));
        edits.push(ParseRecoveryEdit::new(macro_start, name_start));
        edits.push(ParseRecoveryEdit::new(close, close + 1));
    }
    edits
}

fn token_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let is_identifier_byte = |byte: u8| byte == b'_' || byte.is_ascii_alphanumeric();
    bytes
        .get(start.wrapping_sub(1))
        .is_none_or(|byte| !is_identifier_byte(*byte))
        && bytes.get(end).is_none_or(|byte| !is_identifier_byte(*byte))
}

fn skip_ascii_whitespace(bytes: &[u8], mut offset: usize) -> usize {
    while bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
        offset += 1;
    }
    offset
}

fn scan_identifier(bytes: &[u8], mut offset: usize) -> usize {
    if !bytes
        .get(offset)
        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphabetic())
    {
        return offset;
    }
    offset += 1;
    while bytes
        .get(offset)
        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
    {
        offset += 1;
    }
    offset
}

fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in bytes.iter().copied().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(offset);
                }
            }
            b'\n' | b'\r' if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

fn top_level_comma(bytes: &[u8], start: usize, end: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut comma = None;
    for (offset, byte) in bytes.iter().copied().enumerate().take(end).skip(start) {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => {
                if comma.replace(offset).is_some() {
                    return None;
                }
            }
            _ => {}
        }
    }
    comma
}

fn skip_whitespace_and_comments(mut source: &str) -> &str {
    loop {
        source = source.trim_start();
        if let Some(rest) = source.strip_prefix("//") {
            source = rest.split_once('\n').map_or("", |(_, tail)| tail);
        } else if let Some(rest) = source.strip_prefix("/*") {
            source = rest.split_once("*/").map_or("", |(_, tail)| tail);
        } else {
            return source;
        }
    }
}

fn starts_keyword(source: &str, keyword: &str) -> bool {
    source.strip_prefix(keyword).is_some_and(|rest| {
        rest.as_bytes()
            .first()
            .is_none_or(|byte| !(*byte == b'_' || byte.is_ascii_alphanumeric()))
    })
}

pub(crate) fn objc_tree_proves_language(snapshot: &FileSnapshot, tree: &SyntaxTree) -> bool {
    let source = snapshot.text.as_bytes();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "class_interface"
                | "class_implementation"
                | "category_interface"
                | "category_implementation"
                | "protocol_declaration"
        ) || node.is_error() && error_contains_objc_declaration(node, source)
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn error_contains_objc_declaration(node: Node<'_>, source: &[u8]) -> bool {
    let Some(fragment) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    let Ok(fragment) = std::str::from_utf8(fragment) else {
        return false;
    };
    fragment.lines().any(|line| {
        let line = line.trim_start();
        ["@interface", "@implementation", "@protocol"]
            .iter()
            .any(|keyword| starts_keyword(line, keyword))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::kit::language_from_pack;

    #[test]
    fn recovers_unresolved_standalone_markers_around_protocol() {
        let source = "ASSUMPTIONS_BEGIN\n/** Cache. */\n@protocol ImageCache <NSObject>\n- (void)addImage:(UIImage *)image;\n@end\nASSUMPTIONS_END\n";
        let vfs = Vfs::new();
        let file = vfs.write("ImageCache.h", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("objc").expect("Objective-C grammar"))
            .expect("set Objective-C grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());

        let edits = objc_parse_recovery_edits(&snapshot, &vfs, &tree);
        let mut recovered = source.as_bytes().to_vec();
        for edit in edits {
            assert!(edit.apply_to(source, &mut recovered));
        }
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        let candidate = parser.parse(recovered, None).expect("recovery parse");
        assert!(!candidate.root_node().has_error());
    }

    #[test]
    fn recovers_invoked_marker_before_interface() {
        let source = "DECLARATION_ATTRIBUTE(\"message\")\n@interface Manager : NSObject\n@property (nonatomic) BOOL enabled;\n- (void)setAction:(nullable void (^)(BOOL enabled))block;\n@end\n";
        assert!(is_standalone_marker("DECLARATION_ATTRIBUTE(\"message\")"));
        let vfs = Vfs::new();
        let file = vfs.write("Manager.h", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("objc").expect("Objective-C grammar"))
            .expect("set Objective-C grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());

        let edits = objc_parse_recovery_edits(&snapshot, &vfs, &tree);
        assert!(!edits.is_empty());
        let mut recovered = source.as_bytes().to_vec();
        for edit in edits {
            assert!(edit.apply_to(source, &mut recovered));
        }
        let candidate = parser
            .parse(std::str::from_utf8(&recovered).expect("UTF-8"), None)
            .expect("recovery parse");
        assert!(!candidate.root_node().has_error());
    }

    #[test]
    fn recovers_structural_enum_macro_without_provider_spelling() {
        let source = "typedef SDK_ENUM(NSUInteger, Mode) { ModeNone, ModeStrict };\n";
        let vfs = Vfs::new();
        let file = vfs.write("Mode.h", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("objc").expect("Objective-C grammar"))
            .expect("set Objective-C grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());

        let edits = objc_parse_recovery_edits(&snapshot, &vfs, &tree);
        let mut recovered = source.as_bytes().to_vec();
        for edit in edits {
            assert!(edit.apply_to(source, &mut recovered));
        }
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        let candidate = parser.parse(recovered, None).expect("recovery parse");
        assert!(!candidate.root_node().has_error());
        assert!(recovered.contains("enum"));
        assert!(recovered.contains("Mode"));
    }

    #[test]
    fn documentation_text_does_not_prove_objective_c_ownership() {
        let source = "/// The @interface spelling is documentation only.\ntemplate <typename T> struct Box { T value; };\n";
        let vfs = Vfs::new();
        let file = vfs.write("Box.h", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("objc").expect("Objective-C grammar"))
            .expect("set Objective-C grammar");
        let tree = parser.parse(source, None).expect("parse");

        assert!(!objc_tree_proves_language(&snapshot, &tree));
    }
}
