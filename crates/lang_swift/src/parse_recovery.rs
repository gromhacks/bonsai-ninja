//! Recovery for valid Swift syntax not yet accepted by the bundled grammar.

use bonsai_lang_api::{FileSnapshot, ParseRecoveryEdit, SyntaxTree};

pub(crate) fn swift_parse_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &SyntaxTree,
) -> Vec<ParseRecoveryEdit> {
    let mut edits = bonsai_lang_api::branch_free_conditional_recovery_edits(
        snapshot,
        tree,
        bonsai_lang_api::ConditionalDirectiveSyntax {
            openings_with_condition: &["#if"],
            alternatives_with_condition: &["#elseif"],
            alternatives_without_condition: &["#else"],
            closing: "#endif",
            trailing_comment_prefixes: &["//"],
        },
    );
    if !tree.root_node().has_error() {
        return edits;
    }

    let source = snapshot.text.as_ref();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        collect_conditional_cast_before_coalescing(node, source, &mut edits);
        if node.kind() == "tuple_expression"
            && source.get(node.start_byte()..node.end_byte()) == Some("()")
            && has_zero_width_bang(node)
        {
            // The grammar currently requires a synthetic `!` child for
            // Swift's valid empty-tuple value. A scalar literal is the exact
            // dataflow equivalent here: both contain no identifier carrier.
            edits.push(ParseRecoveryEdit::replace_ascii(
                node.start_byte(),
                node.end_byte(),
                b"0",
            ));
        }
        if node.is_error() {
            let Some(fragment) = source.get(node.start_byte()..node.end_byte()) else {
                continue;
            };
            collect_keyword(fragment, node.start_byte(), "sending", &mut edits);
            collect_exact_fragment(fragment, node.start_byte(), "nonisolated(unsafe)", &mut edits);
            continue;
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

/// Recover `value as? Type ?? fallback`, which older Swift grammars can read
/// as a doubly optional type and wrap in an `ERROR`. Masking only the cast in
/// the private parser buffer leaves `value ?? fallback`: the exact
/// value-producing operands needed by dataflow, at their original byte spans.
/// The shared recovery driver accepts this edit only when the reparsed tree has
/// strictly less syntax damage.
fn collect_conditional_cast_before_coalescing(
    damaged: tree_sitter::Node<'_>,
    source: &str,
    edits: &mut Vec<ParseRecoveryEdit>,
) {
    let eligible = damaged.is_error() || (damaged.kind() == "infix_expression" && damaged.has_error());
    if !eligible {
        return;
    }

    let mut stack = vec![damaged];
    while let Some(expression) = stack.pop() {
        if expression.kind() != "as_expression" {
            let mut cursor = expression.walk();
            stack.extend(expression.named_children(&mut cursor));
            continue;
        }
        let mut expression_cursor = expression.walk();
        let Some(operator) = expression
            .named_children(&mut expression_cursor)
            .find(|child| child.kind() == "as_operator")
        else {
            continue;
        };
        if source.get(operator.start_byte()..operator.end_byte()) != Some("as?") {
            continue;
        }
        let Some(tail) = source.get(operator.end_byte()..damaged.end_byte()) else {
            continue;
        };
        let Some(coalescing_offset) = tail.rfind("??") else {
            continue;
        };
        let coalescing_start = operator.end_byte() + coalescing_offset;
        let type_syntax = &tail[..coalescing_offset];
        let after_coalescing = &tail[coalescing_offset + 2..];
        if type_syntax.trim().is_empty()
            || type_syntax.contains(['\n', '\r'])
            // The broken grammar must have consumed the coalescer as part of
            // the cast/type expression. If it lies beyond that exact CST
            // extent, another operator intervenes and masking would alter the
            // program rather than normalize the known ambiguity.
            || coalescing_start > expression.end_byte()
            || (damaged.is_error() && !after_coalescing.trim().is_empty())
        {
            continue;
        }
        edits.push(ParseRecoveryEdit::new(
            operator.start_byte(),
            operator.end_byte() + coalescing_offset,
        ));
    }
}

fn has_zero_width_bang(node: tree_sitter::Node<'_>) -> bool {
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|child| child.kind() == "bang" && child.start_byte() == child.end_byte());
    found
}

fn collect_keyword(fragment: &str, base: usize, keyword: &str, edits: &mut Vec<ParseRecoveryEdit>) {
    let bytes = fragment.as_bytes();
    for (offset, _) in fragment.match_indices(keyword) {
        let end = offset + keyword.len();
        let boundary = |byte: u8| byte != b'_' && !byte.is_ascii_alphanumeric();
        if bytes
            .get(offset.wrapping_sub(1))
            .is_none_or(|byte| boundary(*byte))
            && bytes.get(end).is_none_or(|byte| boundary(*byte))
        {
            edits.push(ParseRecoveryEdit::new(base + offset, base + end));
        }
    }
}

fn collect_exact_fragment(fragment: &str, base: usize, syntax: &str, edits: &mut Vec<ParseRecoveryEdit>) {
    for (offset, _) in fragment.match_indices(syntax) {
        edits.push(ParseRecoveryEdit::new(
            base + offset,
            base + offset + syntax.len(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::{kit::language_from_pack, Vfs};

    #[test]
    fn recovers_modern_concurrency_modifiers_without_moving_spans() {
        let source = "final class Box<Value> {\n  private nonisolated(unsafe) var value: Value\n  func send(_ event: sending @escaping (Value) -> Void) { returnResult(.success(())) }\n}\n";
        let vfs = Vfs::new();
        let file = vfs.write("Box.swift", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("swift").expect("Swift grammar"))
            .expect("set Swift grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());
        let edits = swift_parse_recovery_edits(&snapshot, &tree);
        assert_eq!(edits.len(), 3);
        let mut recovered = source.as_bytes().to_vec();
        for edit in edits {
            assert!(edit.apply_to(source, &mut recovered));
        }
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        let candidate = parser.parse(recovered, None).expect("recovery parse");
        assert!(!candidate.root_node().has_error());
        assert_eq!(recovered.len(), source.len());
    }

    #[test]
    fn recovers_conditional_cast_before_nil_coalescing_without_moving_spans() {
        let source = "func value(record: [String: Any]) -> String {\n  return record[\"name\"] as? String ?? \"\"\n}\n";
        let vfs = Vfs::new();
        let file = vfs.write("Value.swift", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("swift").expect("Swift grammar"))
            .expect("set Swift grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());
        let edits = swift_parse_recovery_edits(&snapshot, &tree);
        assert_eq!(edits.len(), 1);
        let mut recovered = source.as_bytes().to_vec();
        assert!(edits[0].apply_to(source, &mut recovered));
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        let candidate = parser.parse(recovered, None).expect("recovery parse");
        assert!(!candidate.root_node().has_error());
        assert_eq!(recovered.len(), source.len());
        assert_eq!(recovered.find("record"), source.find("record"));
        assert_eq!(recovered.rfind("??"), source.rfind("??"));
    }

    #[test]
    fn recovers_conditional_cast_in_property_initializer() {
        let source = "func values(records: [[String: Any]]) {\n  for record in records {\n    let id = record[\"id\"] as? String ?? \"\"\n    let name = record[\"name\"] as? String ?? \"\"\n  }\n}\n";
        let vfs = Vfs::new();
        let file = vfs.write("Values.swift", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("swift").expect("Swift grammar"))
            .expect("set Swift grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());

        let edits = swift_parse_recovery_edits(&snapshot, &tree);
        assert_eq!(edits.len(), 2);
        let mut recovered = source.as_bytes().to_vec();
        for edit in edits {
            assert!(edit.apply_to(source, &mut recovered));
        }
        let recovered = std::str::from_utf8(&recovered).expect("same-width UTF-8");
        let candidate = parser.parse(recovered, None).expect("recovery parse");
        assert!(!candidate.root_node().has_error());
        assert_eq!(recovered.len(), source.len());
    }

    #[test]
    fn does_not_recover_conditional_cast_without_a_type() {
        let source = "func value(input: Any) -> String { return input as? ?? \"\" }\n";
        let vfs = Vfs::new();
        let file = vfs.write("Value.swift", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("swift").expect("Swift grammar"))
            .expect("set Swift grammar");
        let tree = parser.parse(source, None).expect("raw parse");

        assert!(swift_parse_recovery_edits(&snapshot, &tree).is_empty());
    }

    #[test]
    fn does_not_mask_an_intervening_operator_before_coalescing() {
        let source = "func value(input: Any, flag: Bool) -> String { return input as? String || flag ?? }\n";
        let vfs = Vfs::new();
        let file = vfs.write("Value.swift", source);
        let snapshot = vfs.snapshot(file).expect("snapshot");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language_from_pack("swift").expect("Swift grammar"))
            .expect("set Swift grammar");
        let tree = parser.parse(source, None).expect("raw parse");
        assert!(tree.root_node().has_error());

        assert!(swift_parse_recovery_edits(&snapshot, &tree).is_empty());
    }
}
