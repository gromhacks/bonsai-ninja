//! Tree-sitter lowering for return/yield value dependencies.

use bonsai_common::{FileId, Span};
use tree_sitter::Node;

use crate::{ExpressionField, ExpressionFlow, ExpressionProjection};

use super::{
    argument_place, extract_rhs_expr_operands, looks_like_identifier, looks_like_literal_value, node_text,
    span_of, COMMON_CALL_KINDS,
};

/// Lower one parsed value expression into compiler-owned flow facts.
#[must_use]
pub fn expression_flow_from_node(node: Node<'_>, file: FileId, src: &[u8]) -> ExpressionFlow {
    let place = argument_place(&node, src);
    let projection = place
        .as_deref()
        .filter(|_| projection_is_static(&node, src))
        .and_then(ExpressionProjection::from_adapter_place);
    let mut flow = ExpressionFlow {
        place,
        projection,
        source_names: scalar_source_names(node, src),
        call_sites: expression_call_spans(node, file),
        ..ExpressionFlow::default()
    };

    if is_nested_aggregate(node.kind()) {
        let mut fields = Vec::new();
        let mut spreads = Vec::new();
        collect_aggregate_members(node, node, file, src, &mut fields, &mut spreads);
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

    if is_positional_aggregate(node.kind()) {
        let mut items = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if is_spread_node(child.kind()) {
                if let Some(value) = spread_value_node(child) {
                    flow.spreads.push(expression_flow_from_node(value, file, src));
                }
                continue;
            }
            let value = aggregate_value_node(child).unwrap_or(child);
            if !is_syntax_only_tuple_child(value.kind()) {
                items.push(expression_flow_from_node(value, file, src));
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
) -> ExpressionFlow {
    let mut tuple_items = Vec::new();
    let mut spreads = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_spread_node(child.kind()) {
            if let Some(value) = spread_value_node(child) {
                spreads.push(expression_flow_from_node(value, file, src));
            }
        } else if !is_syntax_only_tuple_child(child.kind()) {
            tuple_items.push(expression_flow_from_node(child, file, src));
        }
    }
    ExpressionFlow {
        tuple_items,
        spreads,
        ..ExpressionFlow::default()
    }
}

fn scalar_source_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if is_call_node(node.kind()) {
            return;
        }
        if !contains_call(node) {
            out.extend(extract_rhs_expr_operands(&node, src));
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, src, out);
        }
    }

    let mut out = Vec::new();
    collect(node, src, &mut out);
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

fn contains_call(node: Node<'_>) -> bool {
    if is_call_node(node.kind()) {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if contains_call(child) {
            return true;
        }
    }
    false
}

fn is_call_node(kind: &str) -> bool {
    COMMON_CALL_KINDS.contains(&kind)
        || matches!(
            kind,
            "method_call" | "message_expression" | "remote_call" | "function_call_expression"
        )
}

pub(super) fn expression_call_spans(node: Node<'_>, file: FileId) -> Vec<Span> {
    fn collect(node: Node<'_>, file: FileId, out: &mut Vec<Span>) {
        if is_call_node(node.kind()) {
            out.push(span_of(file, &node));
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, file, out);
        }
    }
    let mut out = Vec::new();
    collect(node, file, &mut out);
    out.sort_by_key(|span| (span.file.raw(), span.start, span.end));
    out.dedup();
    out
}

fn collect_aggregate_members(
    root: Node<'_>,
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    fields: &mut Vec<ExpressionField>,
    spreads: &mut Vec<ExpressionFlow>,
) {
    if node.id() != root.id() && is_nested_aggregate(node.kind()) {
        return;
    }
    if is_spread_node(node.kind()) {
        if let Some(value) = spread_value_node(node) {
            spreads.push(expression_flow_from_node(value, file, src));
        }
        return;
    }
    if let Some((key, value)) = field_pair_nodes(node) {
        if let Some(name) = static_field_name(key, src) {
            fields.push(ExpressionField {
                name,
                value: expression_flow_from_node(value, file, src),
            });
        }
        return;
    }
    if is_shorthand_field(node.kind()) {
        let name = node_text(&node, src).trim();
        if !name.is_empty() {
            fields.push(ExpressionField {
                name: name.to_string(),
                value: expression_flow_from_node(node, file, src),
            });
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_aggregate_members(root, child, file, src, fields, spreads);
    }
}

fn field_pair_nodes(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if matches!(node.kind(), "dictionary_pair" | "array_element_initializer") {
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        if children.len() == 2 {
            return Some((children[0], children[1]));
        }
    }
    let value = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("right"))
        .or_else(|| node.child_by_field_name("initializer"))?;
    let key = node
        .child_by_field_name("key")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("field"))
        .or_else(|| node.child_by_field_name("left"))?;
    (key.id() != value.id()).then_some((key, value))
}

pub(super) fn static_field_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let kind = node.kind();
    if !looks_like_identifier(kind)
        && !kind.contains("string")
        && !kind.contains("symbol")
        && !kind.contains("number")
        && !kind.contains("integer")
        && !matches!(
            kind,
            "property_identifier" | "field_identifier" | "hash_key_symbol"
        )
    {
        return None;
    }
    if looks_like_literal_value(kind, node_text(&node, src))
        && !["string", "symbol", "number", "integer"]
            .iter()
            .any(|class| kind.contains(class))
    {
        return None;
    }
    let name = node_text(&node, src)
        .trim()
        .trim_start_matches(['.', ':'])
        .trim_end_matches(':')
        .trim_matches(['\'', '"'])
        .to_string();
    (!name.is_empty()).then_some(name)
}

fn is_shorthand_field(kind: &str) -> bool {
    matches!(
        kind,
        "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "shorthand_field_initializer"
            | "field_identifier"
    )
}

fn is_spread_node(kind: &str) -> bool {
    kind.contains("spread") || kind.contains("splat") || kind == "base_field_initializer"
}

fn spread_value_node(node: Node<'_>) -> Option<Node<'_>> {
    let field_value = node
        .child_by_field_name("argument")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("base"));
    if field_value.is_some() {
        return field_value;
    }
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    children.next()
}

fn aggregate_value_node(node: Node<'_>) -> Option<Node<'_>> {
    let field_value = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("element"));
    if field_value.is_some() {
        return field_value;
    }
    if node.kind() == "array_element_initializer" {
        let mut cursor = node.walk();
        let mut children = node.named_children(&mut cursor);
        return children.next();
    }
    None
}

fn is_nested_aggregate(kind: &str) -> bool {
    matches!(
        kind,
        "object"
            | "object_literal"
            | "dictionary"
            | "dictionary_literal"
            | "hash"
            | "map"
            | "map_literal"
            | "set_or_map_literal"
            | "struct_expression"
            | "initializer_list"
            | "array_creation_expression"
            | "table_constructor"
    )
}

fn is_positional_aggregate(kind: &str) -> bool {
    matches!(
        kind,
        "tuple"
            | "tuple_expression"
            | "tuple_literal"
            | "set"
            | "set_literal"
            | "list"
            | "list_literal"
            | "array"
            | "array_literal"
            | "array_expression"
            | "initializer_list"
            | "array_creation_expression"
    )
}

fn is_syntax_only_tuple_child(kind: &str) -> bool {
    kind.contains("type") || matches!(kind, "comment" | "label")
}

fn projection_is_static(node: &Node<'_>, src: &[u8]) -> bool {
    let text = node_text(node, src);
    if !text.contains('[') {
        return true;
    }
    let mut stack = vec![*node];
    let mut saw_subscript = false;
    while let Some(current) = stack.pop() {
        if current.kind().contains("subscript")
            || current.kind().contains("index")
            || current.kind().contains("element_access")
        {
            saw_subscript = true;
            let Some(index) = current
                .child_by_field_name("index")
                .or_else(|| current.child_by_field_name("subscript"))
                .or_else(|| current.child_by_field_name("argument"))
                .or_else(|| {
                    // PHP and a few other grammars keep the subscript key as
                    // the second named CST child without assigning a field
                    // id. The child order is still grammar structure: base,
                    // then key. Consume that parsed relationship rather than
                    // rejecting a statically named projection.
                    let mut cursor = current.walk();
                    let index = current.named_children(&mut cursor).nth(1);
                    index
                })
            else {
                return false;
            };
            let kind = index.kind();
            if !kind.contains("string")
                && !kind.contains("symbol")
                && !kind.contains("number")
                && !kind.contains("integer")
            {
                return false;
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    saw_subscript
}
