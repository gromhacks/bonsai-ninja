//! Narrow recovery for valid Java syntax missing from the bundled grammar.
//!
//! The upstream grammar understands Java 21 record patterns, but its
//! `record_pattern` production accepts only an unqualified terminal type.
//! Java permits qualified record types. The raw CST consequently parses a
//! qualified record pattern as a type or method invocation followed by an
//! error, even though the component list itself is structurally available.
//! Masking only the qualifier lets the existing record-pattern production
//! build the intended tree while preserving every original byte offset.
//!
//! The grammar also treats `var` as a reserved token where the
//! record-component production expects a type identifier. Uppercasing its
//! first byte only in the parser buffer selects that identifier production;
//! adapters still read `var` from the original source at the same span.
//!
//! Finally, the grammar tokenizes a decimal floating literal containing only
//! digits plus a suffix through a non-leading-zero integer rule. Valid values
//! such as `00d` become an octal integer plus an error token. Removing only
//! redundant leading zeroes is value-preserving and lets the floating-literal
//! production own the token.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};
use tree_sitter::Node;

pub(crate) fn java_parse_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let source = snapshot.text.as_bytes();
    let mut edits = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_error() {
            if is_record_pattern_error(node, source) {
                if let Some(edit) = qualified_record_pattern_edit(node, source) {
                    edits.push(edit);
                }
                collect_contextual_var_edits(node, source, &mut edits);
            }
            if let Some(edit) = suffixed_decimal_literal_edit(node, source) {
                edits.push(edit);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.has_error() || child.is_missing() {
                stack.push(child);
            }
        }
    }

    edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
    edits.dedup();
    edits
}

fn is_record_pattern_error(error: Node<'_>, source: &[u8]) -> bool {
    let instanceof_shape =
        source.get(error.start_byte()) == Some(&b'(') && instanceof_expression_for_error(error).is_some();
    let switch_shape = error.parent().is_some_and(|parent| {
        parent.kind() == "argument_list"
            && error
                .next_named_sibling()
                .is_some_and(|sibling| sibling.kind() == "identifier")
            && parent.parent().is_some_and(|invocation| {
                invocation.kind() == "method_invocation" && has_ancestor_kind(invocation, "switch_label")
            })
    });
    instanceof_shape || switch_shape
}

fn collect_contextual_var_edits(error: Node<'_>, source: &[u8], edits: &mut Vec<ParseRecoveryEdit>) {
    let mut stack = vec![error];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_identifier" && source.get(node.start_byte()..node.end_byte()) == Some(b"var")
        {
            edits.push(ParseRecoveryEdit::uppercase_ascii(node.start_byte()));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
}

fn qualified_record_pattern_edit(error: Node<'_>, source: &[u8]) -> Option<ParseRecoveryEdit> {
    qualified_instanceof_record_pattern_edit(error, source)
        .or_else(|| qualified_switch_record_pattern_edit(error, source))
}

fn qualified_instanceof_record_pattern_edit(error: Node<'_>, source: &[u8]) -> Option<ParseRecoveryEdit> {
    if source.get(error.start_byte()) != Some(&b'(') {
        return None;
    }
    let instanceof = instanceof_expression_for_error(error)?;
    let record_type = instanceof.child_by_field_name("right")?;
    qualifier_edit(record_type, source)
}

fn instanceof_expression_for_error(error: Node<'_>) -> Option<Node<'_>> {
    let mut current = error;
    loop {
        if current.kind() == "instanceof_expression" {
            return Some(current);
        }
        if let Some(previous) = current.prev_named_sibling() {
            if let Some(instanceof) = last_descendant_of_kind(previous, "instanceof_expression") {
                return Some(instanceof);
            }
        }
        current = current.parent()?;
    }
}

fn last_descendant_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut found = (root.kind() == kind).then_some(root);
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == kind && found.is_none_or(|previous| child.end_byte() > previous.end_byte()) {
                found = Some(child);
            }
            stack.push(child);
        }
    }
    found
}

fn qualified_switch_record_pattern_edit(error: Node<'_>, source: &[u8]) -> Option<ParseRecoveryEdit> {
    let arguments = error.parent().filter(|parent| parent.kind() == "argument_list")?;
    // A method call cannot contain a declaration-shaped `Type binding`
    // argument. In a switch label this exact damaged shape is the grammar's
    // representation of a qualified record-pattern component.
    if error.next_named_sibling()?.kind() != "identifier" {
        return None;
    }
    let invocation = arguments
        .parent()
        .filter(|parent| parent.kind() == "method_invocation")?;
    if !has_ancestor_kind(invocation, "switch_label") {
        return None;
    }
    let name = invocation.child_by_field_name("name")?;
    let object = invocation.child_by_field_name("object")?;
    if object.end_byte() >= name.start_byte() || source.get(object.end_byte()) != Some(&b'.') {
        return None;
    }
    Some(ParseRecoveryEdit::new(invocation.start_byte(), name.start_byte()))
}

fn qualifier_edit(record_type: Node<'_>, source: &[u8]) -> Option<ParseRecoveryEdit> {
    let terminal = terminal_type_name(record_type)?;
    if terminal.start_byte() <= record_type.start_byte()
        || !source[record_type.start_byte()..terminal.start_byte()].contains(&b'.')
    {
        return None;
    }
    Some(ParseRecoveryEdit::new(
        record_type.start_byte(),
        terminal.start_byte(),
    ))
}

fn terminal_type_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "scoped_type_identifier" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).last()
        }
        "generic_type" => {
            let mut cursor = node.walk();
            let base = node.named_children(&mut cursor).next()?;
            terminal_type_name(base).or(Some(base))
        }
        _ => None,
    }
}

fn has_ancestor_kind(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
}

fn suffixed_decimal_literal_edit(error: Node<'_>, source: &[u8]) -> Option<ParseRecoveryEdit> {
    let mut token_start = error.start_byte().min(source.len());
    while token_start > 0 && is_decimal_digit_or_separator(source[token_start - 1]) {
        token_start -= 1;
    }
    if token_start > 0 && is_java_identifier_continue(source[token_start - 1]) {
        return None;
    }

    let mut suffix = token_start;
    while suffix < source.len() && is_decimal_digit_or_separator(source[suffix]) {
        suffix += 1;
    }
    if !matches!(source.get(suffix), Some(b'd' | b'D' | b'f' | b'F')) {
        return None;
    }
    let token_end = suffix + 1;
    if error.start_byte() >= token_end
        || error.end_byte() <= token_start
        || source
            .get(token_end)
            .is_some_and(|byte| is_java_identifier_continue(*byte))
    {
        return None;
    }

    let digits = source.get(token_start..suffix)?;
    if digits.len() < 2 || digits.first() != Some(&b'0') || !valid_decimal_digits_and_separators(digits) {
        return None;
    }

    let first_nonzero = digits
        .iter()
        .position(|byte| byte.is_ascii_digit() && *byte != b'0');
    let keep_from = first_nonzero.unwrap_or_else(|| {
        digits
            .iter()
            .rposition(u8::is_ascii_digit)
            .expect("validated decimal literal contains a digit")
    });
    (keep_from > 0).then(|| ParseRecoveryEdit::new(token_start, token_start + keep_from))
}

const fn is_decimal_digit_or_separator(byte: u8) -> bool {
    byte.is_ascii_digit() || byte == b'_'
}

const fn is_java_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn valid_decimal_digits_and_separators(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(u8::is_ascii_digit)
        && bytes.last().is_some_and(u8::is_ascii_digit)
        && bytes
            .windows(2)
            .all(|pair| pair != [b'_', b'_'] && pair.iter().all(|byte| is_decimal_digit_or_separator(*byte)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::{kit::language_from_pack, Vfs};
    use std::sync::Arc;
    use tree_sitter::Parser;

    fn recovered_tree(source: &str) -> tree_sitter::Tree {
        let vfs = Vfs::new();
        let file = vfs.write("/w/A.java", Arc::<str>::from(source));
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let language = language_from_pack("java").expect("Java grammar");
        let mut parser = Parser::new();
        parser.set_language(&language).expect("set language");
        let mut tree = parser.parse(source, None).expect("raw parse");
        let raw_sexp = tree.root_node().to_sexp();
        let mut recovered = source.as_bytes().to_vec();
        loop {
            let edits = java_parse_recovery_edits(&snapshot, &tree);
            let mut changed = false;
            for edit in edits {
                changed |= edit.apply_to(source, &mut recovered);
            }
            if !changed {
                break;
            }
            tree = parser.parse(&recovered, None).expect("iterative recovery parse");
        }
        assert_ne!(
            recovered,
            source.as_bytes(),
            "expected recovery edits for {raw_sexp}"
        );
        let recovered = std::str::from_utf8(&recovered).expect("UTF-8 recovery");
        assert!(
            !tree.root_node().has_error(),
            "recovery source: {recovered}\n{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    #[test]
    fn recovers_qualified_record_patterns_and_contextual_var() {
        recovered_tree("class A { int f(Object x) { return x instanceof pkg.Sample(var value) ? 1 : 0; } }");
        recovered_tree(
            "class A { int f(Object x) { return switch (x) { case pkg.Pair(var a, String b) -> 1; default -> 0; }; } }",
        );
    }

    #[test]
    fn recovers_leading_zero_decimal_floats() {
        recovered_tree("class A { double f() { return 00d + 0012D + 0_0f; } }");
    }
}
