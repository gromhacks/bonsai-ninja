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

fn condition_polarity(mut condition: Node<'_>, src: &[u8]) -> crate::BranchConditionPolarity {
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
        if condition.kind() != "not_operator" && !direct_negation_token(condition, src) {
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
    if negated {
        crate::BranchConditionPolarity::Negated
    } else {
        crate::BranchConditionPolarity::Positive
    }
}

fn direct_negation_token(condition: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = condition.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && matches!(node_text(&child, src).trim(), "!" | "not") {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}
