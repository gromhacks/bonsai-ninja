use super::{node_text, span_of, FileId, GrammarHandler, Node, Tree};

/// Extract compiler-owned branch-condition spans and polarity from parsed
/// syntax. The traversal is uncapped and records one fact per grammar-proven
/// conditional node.
pub fn extract_branch_condition_facts(
    tree: &Tree,
    file: FileId,
    handler: &GrammarHandler,
    src: &[u8],
) -> Vec<crate::BranchConditionFact> {
    let mut facts = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if handler.is_if(node.kind()) {
            if let Some(condition) = node
                .child_by_field_name("condition")
                .or_else(|| node.child_by_field_name("predicate"))
            {
                facts.push(crate::BranchConditionFact {
                    branch_span: span_of(file, &node),
                    condition_span: span_of(file, &condition),
                    polarity: condition_polarity(condition, src),
                    membership: membership_condition(condition, src),
                    expression: None,
                });
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    facts.sort_by_key(|fact| {
        (
            fact.branch_span.start,
            fact.branch_span.end,
            fact.condition_span.start,
            fact.condition_span.end,
        )
    });
    facts.dedup();
    facts
}

fn condition_polarity(condition: Node<'_>, src: &[u8]) -> crate::BranchConditionPolarity {
    let (_, negated) = strip_top_level_negations(condition, src);
    if negated {
        crate::BranchConditionPolarity::Negated
    } else {
        crate::BranchConditionPolarity::Positive
    }
}

fn membership_condition(condition: Node<'_>, src: &[u8]) -> Option<crate::MembershipConditionFact> {
    let (condition, outer_negated) = strip_top_level_negations(condition, src);
    if condition.named_child_count() != 2 {
        return None;
    }
    let subject = condition.named_child(0)?;
    let collection = condition.named_child(1)?;
    let operator = src
        .get(subject.end_byte()..collection.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut then_contains = match operator.as_str() {
        "in" => true,
        "not in" => false,
        _ => return None,
    };
    if outer_negated {
        then_contains = !then_contains;
    }
    let subject = node_text(&subject, src).trim().to_string();
    let collection = node_text(&collection, src).trim().to_string();
    if subject.is_empty() || collection.is_empty() {
        return None;
    }
    Some(crate::MembershipConditionFact {
        subject,
        collection,
        then_contains,
    })
}

fn strip_top_level_negations<'tree>(mut condition: Node<'tree>, src: &[u8]) -> (Node<'tree>, bool) {
    let mut negated = false;
    loop {
        while matches!(
            condition.kind(),
            "parenthesized_expression" | "parenthesized_expression_list"
        ) {
            let Some(inner) = condition.named_child(0) else {
                break;
            };
            condition = inner;
        }
        if condition.kind() != "not_operator" && !leading_negation_token(condition, src) {
            break;
        }
        negated = !negated;
        let Some(operand) = condition
            .child_by_field_name("argument")
            .or_else(|| condition.child_by_field_name("operand"))
            .or_else(|| condition.named_child(0))
        else {
            break;
        };
        condition = operand;
    }
    (condition, negated)
}

fn leading_negation_token(condition: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = condition.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    let child = cursor.node();
    !child.is_named() && matches!(node_text(&child, src).trim(), "!" | "not")
}
