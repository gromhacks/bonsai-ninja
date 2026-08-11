//! Tree-sitter lowering for return/yield value dependencies.

use bonsai_common::{FileId, Span};
use tree_sitter::Node;

use crate::{ExpressionField, ExpressionFlow, ExpressionProjection};

#[cfg(test)]
use super::GENERIC_HANDLER;
use super::{argument_place, extract_rhs_expr_operands, node_text, span_of, GrammarHandler};

/// Lower one parsed value expression into compiler-owned flow facts.
#[must_use]
#[cfg(test)]
pub fn expression_flow_from_node(node: Node<'_>, file: FileId, src: &[u8]) -> ExpressionFlow {
    expression_flow_from_node_with_handler(node, file, src, &GENERIC_HANDLER)
}

/// Lower an expression with the active adapter's exact grammar semantics.
#[must_use]
pub fn expression_flow_from_node_with_handler(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> ExpressionFlow {
    let place = argument_place(&node, src, handler);
    let projection = place
        .as_deref()
        .filter(|place| projection_is_static(place))
        .and_then(ExpressionProjection::from_adapter_place);
    let mut flow = ExpressionFlow {
        place,
        projection,
        source_names: scalar_source_names(node, src, handler),
        call_sites: expression_call_spans(node, file, handler),
        ..ExpressionFlow::default()
    };

    if is_nested_aggregate(node.kind(), handler) {
        let mut fields = Vec::new();
        let mut spreads = Vec::new();
        collect_aggregate_members(node, node, file, src, handler, &mut fields, &mut spreads);
        if !fields.is_empty() || !spreads.is_empty() {
            flow.aggregate_fields = fields;
            flow.spreads = spreads;
            // Aggregate keys and container syntax are not scalar operands. Each
            // field/spread carries its own exact dependencies below.
            flow.source_names.clear();
            flow.place = None;
            flow.projection = None;
            flow.call_sites.clear();
            return flow;
        }
    }

    if is_positional_aggregate(node.kind(), handler) {
        let mut items = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if is_spread_node(child.kind(), handler) {
                if let Some(value) = spread_value_node(child, handler) {
                    flow.spreads
                        .push(expression_flow_from_node_with_handler(value, file, src, handler));
                }
                continue;
            }
            let value = aggregate_value_node(child, handler).unwrap_or(child);
            if !is_syntax_only_tuple_child(value.kind(), handler) {
                items.push(expression_flow_from_node_with_handler(value, file, src, handler));
            }
        }
        if !items.is_empty() || !flow.spreads.is_empty() {
            flow.tuple_items = items;
            flow.source_names.clear();
            flow.place = None;
            flow.projection = None;
            flow.call_sites.clear();
        }
    }
    flow
}

/// Lower a grammar-proven positional initializer from its direct item nodes.
/// Unlike the general expression lowerer, this intentionally does not scan
/// descendants for named fields: a field identifier inside one item
/// (`raw.size()`) is not a field of the enclosing aggregate.
#[must_use]
pub(super) fn positional_expression_flow_from_node(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> ExpressionFlow {
    let mut tuple_items = Vec::new();
    let mut spreads = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_spread_node(child.kind(), handler) {
            if let Some(value) = spread_value_node(child, handler) {
                spreads.push(expression_flow_from_node_with_handler(value, file, src, handler));
            }
        } else if !is_syntax_only_tuple_child(child.kind(), handler) {
            tuple_items.push(expression_flow_from_node_with_handler(child, file, src, handler));
        }
    }
    ExpressionFlow {
        tuple_items,
        spreads,
        ..ExpressionFlow::default()
    }
}

fn scalar_source_names(node: Node<'_>, src: &[u8], handler: &GrammarHandler) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], handler: &GrammarHandler, out: &mut Vec<String>) {
        if handler.is_call(node.kind()) {
            return;
        }
        if !contains_call(node, handler) {
            out.extend(extract_rhs_expr_operands(&node, src, handler));
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, src, handler, out);
        }
    }

    let mut out = Vec::new();
    collect(node, src, handler, &mut out);
    out.sort();
    out.dedup();
    // The operand extractor deliberately reports both `obj.field` and its
    // structural base `obj`. Return flow wants the exact projected read only;
    // independent uses of `obj` elsewhere remain because they have their own
    // AST occurrence and therefore another non-prefixed operand.
    let snapshot = out.clone();
    out.retain(|candidate| {
        !snapshot.iter().any(|other| {
            other != candidate
                && (other.starts_with(&format!("{candidate}."))
                    || other.starts_with(&format!("{candidate}->")))
        })
    });
    out
}

fn contains_call(node: Node<'_>, handler: &GrammarHandler) -> bool {
    if handler.is_call(node.kind()) {
        return true;
    }
    if handler
        .expression_call_span_extractor
        .is_some_and(|extract| !extract(node).is_empty())
    {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if contains_call(child, handler) {
            return true;
        }
    }
    false
}

pub(super) fn expression_call_spans(node: Node<'_>, file: FileId, handler: &GrammarHandler) -> Vec<Span> {
    fn collect(node: Node<'_>, file: FileId, handler: &GrammarHandler, out: &mut Vec<Span>) {
        if let Some(extract) = handler.expression_call_span_extractor {
            out.extend(
                extract(node)
                    .into_iter()
                    .map(|(start, end)| Span::new(file, start as u64, end as u64)),
            );
        }
        if handler.is_call(node.kind()) {
            out.push(span_of(file, &node));
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, file, handler, out);
        }
    }
    let mut out = Vec::new();
    collect(node, file, handler, &mut out);
    out.sort_by_key(|span| (span.file.raw(), span.start, span.end));
    out.dedup();
    out
}

fn collect_aggregate_members(
    root: Node<'_>,
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    fields: &mut Vec<ExpressionField>,
    spreads: &mut Vec<ExpressionFlow>,
) {
    if node.id() != root.id() && is_nested_aggregate(node.kind(), handler) {
        return;
    }
    if is_spread_node(node.kind(), handler) {
        if let Some(value) = spread_value_node(node, handler) {
            spreads.push(expression_flow_from_node_with_handler(value, file, src, handler));
        }
        return;
    }
    let pairs = field_pair_nodes(node, handler);
    if !pairs.is_empty() {
        for (key, value) in pairs {
            let Some(name) = static_field_name(key, src, handler) else {
                continue;
            };
            fields.push(ExpressionField {
                name,
                value_span: Some(span_of(file, &value)),
                value: expression_flow_from_node_with_handler(value, file, src, handler),
            });
        }
        return;
    }
    if handler.shorthand_field_kinds.contains(&node.kind()) {
        if let Some(name) = static_field_name(node, src, handler) {
            let value_node = {
                let mut cursor = node.walk();
                let mut values = node
                    .named_children(&mut cursor)
                    .filter(|child| handler.static_field_name_kinds.contains(&child.kind()));
                let first = values.next();
                if values.next().is_none() {
                    first
                } else {
                    None
                }
            };
            fields.push(ExpressionField {
                name,
                value_span: Some(span_of(file, &value_node.unwrap_or(node))),
                value: expression_flow_from_node_with_handler(value_node.unwrap_or(node), file, src, handler),
            });
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_aggregate_members(root, child, file, src, handler, fields, spreads);
    }
}

pub(super) fn field_pair_nodes<'tree>(
    node: Node<'tree>,
    handler: &GrammarHandler,
) -> Vec<(Node<'tree>, Node<'tree>)> {
    if let Some(pairs) = handler
        .aggregate_pair_extractor
        .map(|extract| extract(node))
        .filter(|pairs| !pairs.is_empty())
    {
        return pairs;
    }
    if handler.two_child_aggregate_pair_kinds.contains(&node.kind()) {
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        if children.len() == 2 {
            return vec![(children[0], children[1])];
        }
        return Vec::new();
    }
    if !handler.aggregate_pair_kinds.contains(&node.kind()) {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    let mut pending_key = None;
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.is_named() {
                if cursor
                    .field_name()
                    .is_some_and(|field| handler.aggregate_key_field_names.contains(&field))
                {
                    pending_key = Some(child);
                } else if cursor
                    .field_name()
                    .is_some_and(|field| handler.aggregate_value_field_names.contains(&field))
                {
                    if let Some(key) = pending_key.take().filter(|key| key.id() != child.id()) {
                        pairs.push((key, child));
                    }
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    pairs
}

pub(super) fn static_field_name(node: Node<'_>, src: &[u8], handler: &GrammarHandler) -> Option<String> {
    if let Some(name) = handler
        .static_subscript_key_extractor
        .and_then(|extract| extract(node, src))
    {
        return Some(name);
    }
    if !handler.static_field_name_kinds.contains(&node.kind()) {
        let mut cursor = node.walk();
        let mut static_children = node
            .named_children(&mut cursor)
            .filter(|child| handler.static_field_name_kinds.contains(&child.kind()));
        let child = static_children.next()?;
        if static_children.next().is_some() {
            return None;
        }
        return static_field_name(child, src, handler);
    }
    let name = handler
        .reference_name_extractor
        .and_then(|extract| extract(node, src))
        .unwrap_or_else(|| node_text(&node, src).trim().to_string());
    (!name.is_empty()).then_some(name)
}

fn is_spread_node(kind: &str, handler: &GrammarHandler) -> bool {
    handler.spread_kinds.contains(&kind)
}

fn spread_value_node<'tree>(node: Node<'tree>, handler: &GrammarHandler) -> Option<Node<'tree>> {
    let field_value = handler
        .spread_value_field_names
        .iter()
        .find_map(|field| node.child_by_field_name(field));
    if field_value.is_some() {
        return field_value;
    }
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    children.next()
}

fn aggregate_value_node<'tree>(node: Node<'tree>, handler: &GrammarHandler) -> Option<Node<'tree>> {
    let field_value = handler
        .aggregate_value_field_names
        .iter()
        .find_map(|field| node.child_by_field_name(field));
    if field_value.is_some() {
        return field_value;
    }
    if handler.two_child_aggregate_pair_kinds.contains(&node.kind()) {
        let mut cursor = node.walk();
        let mut children = node.named_children(&mut cursor);
        return children.next();
    }
    None
}

fn is_nested_aggregate(kind: &str, handler: &GrammarHandler) -> bool {
    handler.named_aggregate_kinds.contains(&kind)
}

/// Decode exact scalar fields from a structurally complete, spread-free
/// aggregate.
///
/// The shared walker contributes only grammar structure and static field
/// relationships already used by [`expression_flow_from_node_with_handler`]. Literal
/// spelling remains language-owned through `decode`. Any dynamic key,
/// spread or duplicate field makes the aggregate inexact. Unrelated dynamic
/// leaves remain absent from the returned table; they cannot override a
/// returned static field because every field path is tracked independently.
pub(super) fn exact_static_aggregate_fields(
    node: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
    decode: fn(Node<'_>, &[u8]) -> Option<crate::StaticScalarValue>,
) -> Option<Vec<crate::StaticAggregateFieldValue>> {
    fn collect(
        node: Node<'_>,
        src: &[u8],
        handler: &GrammarHandler,
        decode: fn(Node<'_>, &[u8]) -> Option<crate::StaticScalarValue>,
        path: &mut Vec<String>,
        out: &mut Vec<crate::StaticAggregateFieldValue>,
        seen: &mut std::collections::HashSet<Vec<String>>,
    ) -> Option<()> {
        if !is_nested_aggregate(node.kind(), handler) {
            return None;
        }
        let mut saw_field = false;
        let direct_pairs = field_pair_nodes(node, handler);
        if !direct_pairs.is_empty() {
            for (key, value) in direct_pairs {
                let name = static_field_name(key, src, handler)?;
                saw_field = true;
                path.push(name);
                if !seen.insert(path.clone()) {
                    return None;
                }
                if is_nested_aggregate(value.kind(), handler) {
                    collect(value, src, handler, decode, path, out, seen)?;
                } else if let Some(value) = decode(value, src) {
                    out.push(crate::StaticAggregateFieldValue {
                        path: path.clone(),
                        value,
                    });
                }
                path.pop();
            }
            return saw_field.then_some(());
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if is_spread_node(child.kind(), handler) {
                return None;
            }
            let pairs = field_pair_nodes(child, handler);
            if pairs.is_empty() {
                // Comments and grammar-owned punctuation are not named
                // members. Any other named aggregate child is unsupported
                // and therefore cannot prove a complete configuration.
                if !handler.comment_kinds.contains(&child.kind()) {
                    return None;
                }
                continue;
            }
            for (key, value) in pairs {
                let name = static_field_name(key, src, handler)?;
                saw_field = true;
                path.push(name);
                if !seen.insert(path.clone()) {
                    return None;
                }
                if is_nested_aggregate(value.kind(), handler) {
                    collect(value, src, handler, decode, path, out, seen)?;
                } else if let Some(value) = decode(value, src) {
                    out.push(crate::StaticAggregateFieldValue {
                        path: path.clone(),
                        value,
                    });
                }
                path.pop();
            }
        }
        saw_field.then_some(())
    }

    let mut out = Vec::new();
    collect(
        node,
        src,
        handler,
        decode,
        &mut Vec::new(),
        &mut out,
        &mut std::collections::HashSet::new(),
    )?;
    Some(out)
}

/// Decode the complete ordered shape of one positional aggregate. Structure
/// comes from Tree-sitter; scalar spelling remains adapter-owned through
/// `decode`. Dynamic items are retained as `None`, while spreads or unknown
/// container shapes reject the entire fact.
pub(super) fn exact_static_sequence_values(
    node: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
    decode: fn(Node<'_>, &[u8]) -> Option<crate::StaticScalarValue>,
) -> Option<Vec<Option<crate::StaticScalarValue>>> {
    if !is_positional_aggregate(node.kind(), handler) {
        return None;
    }
    let mut values = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_spread_node(child.kind(), handler) {
            return None;
        }
        if is_syntax_only_tuple_child(child.kind(), handler) {
            continue;
        }
        let value = aggregate_value_node(child, handler).unwrap_or(child);
        values.push(decode(value, src));
    }
    (!values.is_empty()).then_some(values)
}

fn is_positional_aggregate(kind: &str, handler: &GrammarHandler) -> bool {
    handler.positional_aggregate_kinds.contains(&kind)
}

fn is_syntax_only_tuple_child(kind: &str, handler: &GrammarHandler) -> bool {
    handler.aggregate_syntax_only_kinds.contains(&kind) || handler.comment_kinds.contains(&kind)
}

fn projection_is_static(place: &str) -> bool {
    !bonsai_common::qualified_name_segments(place).contains(&"*")
}
