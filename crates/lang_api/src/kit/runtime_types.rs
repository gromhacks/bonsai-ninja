use super::{
    first_named_child_of_kind, looks_like_bare_identifier, looks_like_identifier, looks_like_literal_value,
    node_text, parsed_call_target, span_of, FileId, GrammarHandler, Node, Tree,
};

/// Extract branch-local runtime type refinements from parsed guard nodes.
/// The traversal and relationship recovery are uncapped; only guards with a
/// grammar-proven subject, type, and guarded arm produce a fact.
pub fn extract_runtime_type_narrowing_facts(
    tree: &Tree,
    file: FileId,
    handler: &GrammarHandler,
    src: &[u8],
) -> Vec<crate::RuntimeTypeNarrowingFact> {
    let mut facts = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if handler.is_if(node.kind()) {
            let condition = node
                .child_by_field_name("condition")
                .or_else(|| node.child_by_field_name("predicate"));
            let guarded = node
                .child_by_field_name("consequence")
                .or_else(|| node.child_by_field_name("then"))
                .or_else(|| node.child_by_field_name("body"));
            if let (Some(condition), Some(guarded)) = (condition, guarded) {
                if let Some((subject, type_name)) = runtime_type_guard_parts(condition, handler, src) {
                    facts.push(crate::RuntimeTypeNarrowingFact {
                        branch_span: span_of(file, &node),
                        guarded_span: span_of(file, &guarded),
                        subject,
                        type_name,
                    });
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    facts.sort_by(|left, right| {
        (
            left.branch_span.start,
            left.branch_span.end,
            left.guarded_span.start,
            left.guarded_span.end,
            &left.subject,
            &left.type_name,
        )
            .cmp(&(
                right.branch_span.start,
                right.branch_span.end,
                right.guarded_span.start,
                right.guarded_span.end,
                &right.subject,
                &right.type_name,
            ))
    });
    facts.dedup();
    facts
}

fn runtime_type_guard_parts(
    condition: Node<'_>,
    handler: &GrammarHandler,
    src: &[u8],
) -> Option<(String, String)> {
    let condition = unwrap_runtime_guard(condition);
    if !handler.runtime_type_guard_calls.is_empty() && handler.is_call(condition.kind()) {
        let target = parsed_call_target(&condition, src)?;
        let tail = bonsai_common::short_qualified_tail(&target.full_text);
        if !handler.runtime_type_guard_calls.contains(&tail) {
            return None;
        }
        let arguments = condition
            .child_by_field_name("arguments")
            .or_else(|| condition.child_by_field_name("args"))
            .or_else(|| first_named_child_of_kind(&condition, "argument_list"))
            .or_else(|| first_named_child_of_kind(&condition, "arguments"))?;
        let mut cursor = arguments.walk();
        let values = arguments
            .named_children(&mut cursor)
            .map(unwrap_runtime_guard)
            .collect::<Vec<_>>();
        if values.len() != 2 {
            return None;
        }
        return Some((
            runtime_guard_identifier(values[0], src)?,
            runtime_guard_identifier(values[1], src)?,
        ));
    }

    if let Some(narrowing) = runtime_typeof_guard_parts(condition, handler, src) {
        return Some(narrowing);
    }

    (0..condition.child_count())
        .filter_map(|index| condition.child(u32::try_from(index).ok()?))
        .find(|child| handler.runtime_type_guard_operators.contains(&child.kind()))?;
    let left = condition
        .child_by_field_name("left")
        .or_else(|| condition.child_by_field_name("expression"))
        .or_else(|| condition.named_child(0))?;
    let right = condition
        .child_by_field_name("right")
        .or_else(|| condition.child_by_field_name("type"))
        .or_else(|| {
            let last = u32::try_from(condition.named_child_count().checked_sub(1)?).ok()?;
            condition.named_child(last)
        })?;
    Some((
        runtime_guard_identifier(unwrap_runtime_guard(left), src)?,
        runtime_guard_identifier(unwrap_runtime_guard(right), src)?,
    ))
}

fn runtime_typeof_guard_parts(
    condition: Node<'_>,
    handler: &GrammarHandler,
    src: &[u8],
) -> Option<(String, String)> {
    if handler.runtime_typeof_operators.is_empty() || handler.runtime_type_equality_operators.is_empty() {
        return None;
    }
    (0..condition.child_count())
        .filter_map(|index| condition.child(u32::try_from(index).ok()?))
        .find(|child| handler.runtime_type_equality_operators.contains(&child.kind()))?;
    let left = condition
        .child_by_field_name("left")
        .or_else(|| condition.named_child(0))?;
    let right = condition.child_by_field_name("right").or_else(|| {
        let last = u32::try_from(condition.named_child_count().checked_sub(1)?).ok()?;
        condition.named_child(last)
    })?;
    runtime_typeof_pair(left, right, handler, src).or_else(|| runtime_typeof_pair(right, left, handler, src))
}

fn runtime_typeof_pair(
    typeof_node: Node<'_>,
    type_node: Node<'_>,
    handler: &GrammarHandler,
    src: &[u8],
) -> Option<(String, String)> {
    let typeof_node = unwrap_runtime_guard(typeof_node);
    (0..typeof_node.child_count())
        .filter_map(|index| typeof_node.child(u32::try_from(index).ok()?))
        .find(|child| handler.runtime_typeof_operators.contains(&child.kind()))?;
    let subject = typeof_node
        .child_by_field_name("argument")
        .or_else(|| typeof_node.named_child(0))?;
    let subject = runtime_guard_identifier(unwrap_runtime_guard(subject), src)?;
    let type_node = unwrap_runtime_guard(type_node);
    if !matches!(
        type_node.kind(),
        "string" | "string_literal" | "interpreted_string_literal"
    ) {
        return None;
    }
    let type_name = node_text(&type_node, src)
        .trim()
        .trim_matches(['\'', '"'])
        .to_string();
    (!type_name.is_empty()
        && type_name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
    .then_some((subject, type_name))
}

fn unwrap_runtime_guard(mut node: Node<'_>) -> Node<'_> {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "parenthesized" | "condition"
    ) && node.named_child_count() == 1
    {
        if let Some(inner) = node.named_child(0) {
            node = inner;
        } else {
            break;
        }
    }
    node
}

fn runtime_guard_identifier(node: Node<'_>, src: &[u8]) -> Option<String> {
    if !looks_like_identifier(node.kind()) {
        return None;
    }
    let text = node_text(&node, src).trim();
    (looks_like_bare_identifier(text) && !looks_like_literal_value(node.kind(), text))
        .then(|| text.to_string())
}
