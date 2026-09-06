//! Typed conditions for Dart's flattened, sibling-based selector syntax.

use super::{dart_selector_semantic_call_span, first_named_child_of_kind, node_text, span_of};
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{ConditionExpressionFact as Condition, ConditionOperandFact};
use bonsai_lang_api::{DeclIndex, ExpressionFlow};
use tree_sitter::{Node, Tree};

pub(super) fn refine_branch_conditions(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for fact in &mut index.branch_conditions {
        let Some(branch) =
            bonsai_lang_api::kit::node_at_span(tree.root_node(), fact.branch_span, &["if_statement"])
        else {
            continue;
        };
        if branch.kind() != "if_statement" || span_of(file, &branch) != fact.branch_span {
            continue;
        }
        let mut cursor = branch.walk();
        let nodes = branch
            .named_children(&mut cursor)
            .filter(|child| {
                child.start_byte() as u64 >= fact.condition_span.start
                    && child.end_byte() as u64 <= fact.condition_span.end
                    && !child.is_extra()
            })
            .collect::<Vec<_>>();
        if !nodes.is_empty() {
            fact.expression = Some(lower(&nodes, file, src));
        }
    }
}

fn lower(nodes: &[Node<'_>], file: FileId, src: &[u8]) -> Condition {
    let first = nodes[0];
    let last = nodes[nodes.len() - 1];
    let span = Span::new(file, first.start_byte() as u64, last.end_byte() as u64);
    if let [node] = nodes {
        if matches!(
            node.kind(),
            "parenthesized_expression"
                | "unary_expression"
                | "logical_and_expression"
                | "logical_or_expression"
        ) {
            let mut cursor = node.walk();
            let children = node
                .named_children(&mut cursor)
                .filter(|child| !child.is_extra())
                .collect::<Vec<_>>();
            if !children.is_empty() {
                return lower(&children, file, src);
            }
        }
    }
    // Operators are direct CST children. Nested arguments and opaque wrapper
    // calls are not searched for predicates whose result they may discard.
    for (kind, all) in [("logical_or_operator", false), ("logical_and_operator", true)] {
        if nodes.iter().any(|node| node.kind() == kind) {
            let parts = nodes.split(|node| node.kind() == kind).collect::<Vec<_>>();
            if parts.iter().all(|part| !part.is_empty()) {
                let operands = parts.into_iter().map(|part| lower(part, file, src)).collect();
                return if all {
                    Condition::All { span, operands }
                } else {
                    Condition::Any { span, operands }
                };
            }
            return Condition::Atom { span };
        }
    }
    if first.kind() == "prefix_operator" && node_text(&first, src).trim() == "!" && nodes.len() > 1 {
        return Condition::Not {
            span,
            operand: Box::new(lower(&nodes[1..], file, src)),
        };
    }
    if nodes.len() > 1
        && nodes[1..].iter().all(|node| node.kind() == "selector")
        && first_named_child_of_kind(&last, "argument_part").is_some()
    {
        if let Some(call_span) =
            dart_selector_semantic_call_span(last, file, src).filter(|call| *call == span)
        {
            return Condition::Truthy {
                span,
                operand: ConditionOperandFact {
                    span,
                    direct_call_span: Some(call_span),
                    value_flow: ExpressionFlow {
                        call_sites: vec![call_span],
                        ..Default::default()
                    },
                    static_string: None,
                    static_value: None,
                },
            };
        }
    }
    Condition::Atom { span }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DartAdapter;
    use bonsai_lang_api::FlowEvent;

    #[test]
    fn selector_conditions_keep_boolean_structure_and_only_the_outer_call_identity() {
        let source = "void check(String value) { if (left(value) || value.right()) yes(); if (!left(value)) no(); if (wrap(left(value))) unknown(); if (left(value).flag) opaque(); }\n";
        let workspace = bonsai_testkit::workspace_with(
            vec![std::sync::Arc::new(DartAdapter)],
            &[("condition.dart", source)],
        );
        assert!(workspace.diagnostics().is_empty());
        let index = workspace.db().decl_index(workspace.vfs().all_files()[0]).unwrap();
        let conditions = index
            .branch_conditions
            .iter()
            .map(|fact| fact.expression.as_ref().unwrap())
            .collect::<Vec<_>>();
        let Condition::Any { operands, .. } = conditions[0] else {
            panic!("{conditions:#?}")
        };
        assert_eq!(operands.len(), 2);
        let direct = |condition: &Condition| {
            let Condition::Truthy { operand, .. } = condition else {
                panic!("{condition:#?}")
            };
            let span = operand.direct_call_span.unwrap();
            source[span.start as usize..span.end as usize].to_string()
        };
        assert_eq!(direct(&operands[0]), "left(value)");
        assert_eq!(direct(&operands[1]), "value.right()");
        let Condition::Not { operand, .. } = conditions[1] else {
            panic!("{conditions:#?}")
        };
        assert_eq!(direct(operand), "left(value)");
        assert_eq!(direct(conditions[2]), "wrap(left(value))");
        assert!(matches!(conditions[3], Condition::Atom { .. }));
        let mut calls = Vec::new();
        for decl in &index.defs {
            bonsai_lang_api::for_each_flow_event(&decl.flow_events, &mut |event| {
                if let FlowEvent::Call { span, .. } = event {
                    calls.push(*span);
                }
            });
        }
        for condition in operands.iter().chain([operand.as_ref(), conditions[2]]) {
            let Condition::Truthy { operand, .. } = condition else {
                unreachable!()
            };
            assert!(
                calls.contains(&operand.direct_call_span.unwrap()),
                "{condition:#?}"
            );
        }
    }
}
