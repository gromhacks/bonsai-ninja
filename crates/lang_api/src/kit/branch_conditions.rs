use super::{node_text, span_of, FileId, GrammarHandler, Node, Tree};

/// Return the exact direct syntax nodes that form one branch condition.
///
/// Fielded and adapter-declared wrapper nodes remain the preferred shapes.
/// Some grammars instead expose an unfielded condition as a sequence of
/// siblings before the first branch arm. The owning adapter opts into that
/// exact arm-bounded sequence; no token or API vocabulary is inferred here.
pub(super) fn branch_condition_nodes<'tree>(node: Node<'tree>, handler: &GrammarHandler) -> Vec<Node<'tree>> {
    let mut conditions = handler
        .branch_condition_field_names
        .iter()
        .filter_map(|field| node.child_by_field_name(field))
        .collect::<Vec<_>>();
    if conditions.is_empty() {
        let mut cursor = node.walk();
        conditions.extend(
            node.named_children(&mut cursor)
                .filter(|child| handler.branch_condition_kinds.contains(&child.kind())),
        );
    }
    if handler.branch_condition_is_first_named_child {
        let first_arm = handler
            .branch_then_field_names
            .iter()
            .find_map(|field| node.child_by_field_name(field))
            .or_else(|| {
                let mut cursor = node.walk();
                let found = node
                    .named_children(&mut cursor)
                    .find(|child| handler.branch_arm_kinds.contains(&child.kind()));
                found
            });
        let mut direct_condition = Vec::new();
        if let Some(arm_start) = first_arm.map(|arm| arm.start_byte()) {
            let mut cursor = node.walk();
            direct_condition.extend(
                node.named_children(&mut cursor)
                    .filter(|child| child.end_byte() <= arm_start),
            );
        } else {
            direct_condition.extend(node.named_child(0));
        }
        if !direct_condition.is_empty() {
            // A grammar may assign its condition field only to the first
            // component of a selector-style expression. The opt-in direct
            // prefix is the complete adapter-owned condition in that shape.
            conditions = direct_condition;
        }
    }
    conditions.sort_by_key(|condition| (condition.start_byte(), condition.end_byte()));
    conditions.dedup_by_key(|condition| condition.id());
    conditions
}

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
            let conditions = branch_condition_nodes(node, handler);
            if let (Some(first), Some(last)) = (conditions.first(), conditions.last()) {
                let condition_span =
                    bonsai_common::Span::new(file, first.start_byte() as u64, last.end_byte() as u64);
                let expression = if let [condition] = conditions.as_slice() {
                    lower_boolean_condition_expression(*condition, file, handler, src)
                } else {
                    crate::ConditionExpressionFact::Atom { span: condition_span }
                };
                facts.push(crate::BranchConditionFact {
                    branch_span: span_of(file, &node),
                    condition_span,
                    polarity: condition_polarity(*first, src),
                    membership: (conditions.len() == 1)
                        .then(|| membership_condition(*first, src))
                        .flatten(),
                    expression: Some(expression),
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

/// Lower conjunction, disjunction, and negation using only operator and
/// wrapper syntax declared by the owning adapter. Richer adapter-specific
/// facts (type tests, equality, membership) may replace this baseline.
pub fn lower_boolean_condition_expression(
    mut node: Node<'_>,
    file: FileId,
    handler: &GrammarHandler,
    src: &[u8],
) -> crate::ConditionExpressionFact {
    while handler.condition_group_kinds.contains(&node.kind()) && node.named_child_count() == 1 {
        let Some(inner) = node.named_child(0) else {
            break;
        };
        node = inner;
    }
    let span = span_of(file, &node);
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let [operand] = children.as_slice() {
        let operator = normalized_operator(src, node.start_byte(), operand.start_byte());
        if handler.condition_not_operators.contains(&operator.as_str()) {
            return crate::ConditionExpressionFact::Not {
                span,
                operand: Box::new(lower_boolean_condition_expression(*operand, file, handler, src)),
            };
        }
    }
    if children.len() >= 2 && handler.condition_not_operator_kinds.contains(&children[0].kind()) {
        // Selector-style grammars can represent `!namespace.predicate(a, b)`
        // as one operator node followed by several direct expression pieces
        // (base identifier, member selector, argument selector).  The whole
        // suffix is the negated operand.  Choosing only the final child would
        // shrink the compiler fact to `(a, b)` and lose the exact call span.
        // Preserve the complete parsed suffix without interpreting any name.
        let operand = if children.len() == 2 {
            lower_boolean_condition_expression(children[1], file, handler, src)
        } else {
            crate::ConditionExpressionFact::Atom {
                span: bonsai_common::Span::new(
                    file,
                    children[1].start_byte() as u64,
                    children.last().expect("negation operand").end_byte() as u64,
                ),
            }
        };
        return crate::ConditionExpressionFact::Not {
            span,
            operand: Box::new(operand),
        };
    }
    if let (Some(left), Some(right)) = (children.first(), children.last()) {
        if left.id() != right.id() {
            let operator = normalized_operator(src, left.end_byte(), right.start_byte());
            if handler.condition_all_operators.contains(&operator.as_str()) {
                return merge_boolean_operands(
                    span,
                    true,
                    lower_boolean_condition_expression(*left, file, handler, src),
                    lower_boolean_condition_expression(*right, file, handler, src),
                );
            }
            if handler.condition_any_operators.contains(&operator.as_str()) {
                return merge_boolean_operands(
                    span,
                    false,
                    lower_boolean_condition_expression(*left, file, handler, src),
                    lower_boolean_condition_expression(*right, file, handler, src),
                );
            }
        }
    }
    if let Some(call_span) = super::direct_call_callee_span(node, file, src, handler) {
        return crate::ConditionExpressionFact::Truthy {
            span,
            operand: crate::ConditionOperandFact {
                span,
                direct_call_span: Some(call_span),
                value_flow: Default::default(),
                static_string: None,
                static_value: None,
            },
        };
    }
    crate::ConditionExpressionFact::Atom { span }
}

fn normalized_operator(src: &[u8], start: usize, end: usize) -> String {
    src.get(start..end)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn merge_boolean_operands(
    span: bonsai_common::Span,
    all: bool,
    left: crate::ConditionExpressionFact,
    right: crate::ConditionExpressionFact,
) -> crate::ConditionExpressionFact {
    let mut operands = Vec::new();
    let mut push = |operand| match (all, operand) {
        (true, crate::ConditionExpressionFact::All { operands: nested, .. })
        | (false, crate::ConditionExpressionFact::Any { operands: nested, .. }) => operands.extend(nested),
        (_, operand) => operands.push(operand),
    };
    push(left);
    push(right);
    if all {
        crate::ConditionExpressionFact::All { span, operands }
    } else {
        crate::ConditionExpressionFact::Any { span, operands }
    }
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
