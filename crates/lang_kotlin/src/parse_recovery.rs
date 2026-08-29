//! Narrow recovery for a valid multiline Kotlin `if/else` used directly as
//! a `when` arm body.
//!
//! The bundled grammar can terminate the first arm after the `if`
//! consequence when `else` begins on the following line, then parse the
//! alternative as the next `when` condition. The raw CST still proves the
//! exact shape: a preceding `when_entry` ends in an `if_expression` with a
//! consequence but no alternative, the following entry is damaged, and the
//! only intervening non-whitespace token is `else`. The recovery puts braces
//! into two existing indentation bytes around that arm. Line breaks and byte
//! widths are unchanged, so every downstream source position remains exact.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};
use tree_sitter::Node;

pub(crate) fn kotlin_parse_recovery_edits(
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
        if node.kind() == "when_expression" && node.has_error() {
            collect_multiline_if_else_edits(node, source, &mut edits);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
    edits.dedup();
    edits
}

fn collect_multiline_if_else_edits(
    when_expression: Node<'_>,
    source: &[u8],
    edits: &mut Vec<ParseRecoveryEdit>,
) {
    let mut cursor = when_expression.walk();
    let entries = when_expression
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "when_entry")
        .collect::<Vec<_>>();
    for pair in entries.windows(2) {
        let [preceding, damaged] = pair else {
            continue;
        };
        let Some(if_expression) = when_entry_unpaired_if(*preceding) else {
            continue;
        };
        if !damaged.has_error() {
            continue;
        }
        let Some(gap) = source.get(preceding.end_byte()..damaged.start_byte()) else {
            continue;
        };
        let Some(else_offset) = find_standalone_else(gap) else {
            continue;
        };
        let indentation = &gap[..else_offset];
        let suffix = &gap[else_offset + b"else".len()..];
        if !indentation.contains(&b'\n')
            || !indentation.iter().all(u8::is_ascii_whitespace)
            || !suffix.iter().all(u8::is_ascii_whitespace)
        {
            continue;
        }
        let Some(open_brace) = indentation_slot_before(source, if_expression.start_byte()) else {
            continue;
        };
        let Some(alternative) = first_named_descendant_of_kind(*damaged, "string_literal") else {
            continue;
        };
        if alternative.start_byte() != damaged.start_byte() {
            continue;
        }
        let Some(close_brace) = indentation_slot_after(source, alternative.end_byte(), damaged.end_byte())
        else {
            continue;
        };
        // The grammar has classified the valid alternative and the following
        // arm as one damaged production, while prematurely closing the first
        // arm at the consequence. Mark that complete adjacent region as the
        // damaged owner: the parser's monotone-recovery validator may then
        // replace only these proven participants while still protecting all
        // unrelated clean compiler nodes.
        let owner_start = preceding.start_byte();
        let owner_end = damaged.end_byte();
        edits.push(ParseRecoveryEdit::replace_damaged_descendant_prefix_ascii(
            open_brace,
            open_brace + 1,
            b"{",
            owner_start,
            owner_end,
        ));
        edits.push(ParseRecoveryEdit::replace_damaged_descendant_prefix_ascii(
            close_brace,
            close_brace + 1,
            b"}",
            owner_start,
            owner_end,
        ));
    }
}

fn when_entry_unpaired_if(entry: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = entry.walk();
    let body = entry
        .named_children(&mut cursor)
        .find(|child| child.kind() == "control_structure_body")?;
    let expression = body.named_child(0)?;
    (expression.kind() == "if_expression"
        && expression.child_by_field_name("consequence").is_some()
        && expression.child_by_field_name("alternative").is_none())
    .then_some(expression)
}

fn find_standalone_else(bytes: &[u8]) -> Option<usize> {
    bytes.windows(b"else".len()).position(|window| window == b"else")
}

fn indentation_slot_before(source: &[u8], expression_start: usize) -> Option<usize> {
    let prefix = source.get(..expression_start)?;
    let line_start = prefix.iter().rposition(|byte| *byte == b'\n')? + 1;
    (line_start..expression_start).find(|offset| source[*offset] == b' ')
}

fn indentation_slot_after(source: &[u8], value_end: usize, owner_end: usize) -> Option<usize> {
    let suffix = source.get(value_end..owner_end)?;
    let newline = suffix.iter().position(|byte| *byte == b'\n')?;
    let indentation_start = value_end + newline + 1;
    (indentation_start..owner_end).find(|offset| source[*offset] == b' ')
}

fn first_named_descendant_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == kind {
            return Some(current);
        }
        let mut cursor = current.walk();
        let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    None
}
