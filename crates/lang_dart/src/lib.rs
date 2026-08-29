//! Dart language adapter.

use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, call_arg_from_nodes_with_handler, collect_kinds,
        expression_flow_from_node_with_handler, first_identifier_descendant, first_identifier_like_child,
        first_named_child, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, CallArg, CallKind, CallReceiverFact, CallReceiverRole,
    CharacterConstraintDomain, CharacterConstraintFact, CharacterConstraintOutput, DeclIndex, DeclKind,
    ExpressionFlow, ExpressionPlaceExtraction, ExpressionProjection, FieldWrite, FlowEvent, GrammarHandler,
    ImplicitMemberReadCall, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities,
    LanguageId, PatternBindingSite, Ref, RefKind, StaticScalarValue, StaticStringMapEntry, TypeAliasBinding,
    Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("dart");
const PACK_NAME: &str = "dart";

fn dart_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    if node.kind() == "string_literal" {
        return dart_exact_static_string(node, src).map(StaticScalarValue::String);
    }
    match node_text(&node, src).trim() {
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "null" if node.kind() == "null_literal" => Some(StaticScalarValue::Null),
        _ => None,
    }
}

fn dart_static_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let raw = node_text(&node, src).trim();
    let quoted = raw
        .strip_prefix("r\"")
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| raw.strip_prefix("r'").and_then(|value| value.strip_suffix('\'')))
        .or_else(|| raw.strip_prefix('"').and_then(|value| value.strip_suffix('"')))
        .or_else(|| raw.strip_prefix('\'').and_then(|value| value.strip_suffix('\'')))?;
    (!quoted.contains('\\') && !quoted.contains('$') && !quoted.is_empty()).then(|| quoted.to_string())
}

fn dart_exact_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let raw = node_text(&node, src).trim();
    let (is_raw, quoted) = raw
        .strip_prefix("r\"")
        .and_then(|value| value.strip_suffix('"'))
        .map(|value| (true, value))
        .or_else(|| {
            raw.strip_prefix("r'")
                .and_then(|value| value.strip_suffix('\''))
                .map(|value| (true, value))
        })
        .or_else(|| {
            raw.strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .map(|value| (false, value))
        })
        .or_else(|| {
            raw.strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
                .map(|value| (false, value))
        })?;
    if is_raw {
        return Some(quoted.to_string());
    }
    let mut decoded = String::with_capacity(quoted.len());
    let mut characters = quoted.chars();
    while let Some(character) = characters.next() {
        if character == '$' {
            return None;
        }
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match characters.next()? {
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{000b}'),
            '"' => decoded.push('"'),
            '\'' => decoded.push('\''),
            '\\' => decoded.push('\\'),
            '$' => decoded.push('$'),
            _ => return None,
        }
    }
    Some(decoded)
}

/// Lower a complete expression-bodied chain of identical, typed two-string
/// operations into a provider-bound substitution candidate. The adapter
/// records only parsed structure, exact declared receiver type, operation
/// identity, and decoded mappings. Rule data decides whether that provider
/// and mapping have security meaning.
fn dart_provider_bound_string_substitutions(
    defs: &[bonsai_lang_api::Decl],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterConstraintFact> {
    let mut facts = Vec::new();
    for body in collect_kinds(tree, &["function_body"]) {
        let body_span = span_of(file, &body);
        let Some(decl) = defs.iter().find(|decl| {
            matches!(decl.kind, DeclKind::Function | DeclKind::Method) && decl.body_span == Some(body_span)
        }) else {
            continue;
        };
        let mut cursor = body.walk();
        let children = body.named_children(&mut cursor).collect::<Vec<_>>();
        if children.len() < 3 || children.len() % 2 == 0 || children[0].kind() != "identifier" {
            continue;
        }
        let input = node_text(&children[0], src).trim();
        let Some(input_param_index) = decl.params.iter().position(|param| param == input) else {
            continue;
        };
        let mut receiver_types = decl
            .type_aliases
            .iter()
            .filter(|alias| alias.name == input)
            .map(|alias| alias.type_name.trim())
            .filter(|type_name| !type_name.is_empty())
            .collect::<Vec<_>>();
        receiver_types.sort_unstable();
        receiver_types.dedup();
        let [receiver_type] = receiver_types.as_slice() else {
            continue;
        };

        let mut operation = None;
        let mut mappings = Vec::<StaticStringMapEntry>::new();
        let mut valid = true;
        for pair in children[1..].chunks_exact(2) {
            let [member_selector, argument_selector] = pair else {
                valid = false;
                break;
            };
            let Some(member) =
                first_named_child_of_kind(member_selector, "unconditional_assignable_selector")
                    .and_then(|selector| first_identifier_like_child(&selector))
                    .map(|identifier| node_text(&identifier, src).trim())
                    .filter(|member| !member.is_empty())
            else {
                valid = false;
                break;
            };
            if operation.is_some_and(|existing| existing != member) {
                valid = false;
                break;
            }
            operation = Some(member);
            let Some(arguments) = first_named_child_of_kind(argument_selector, "argument_part")
                .and_then(|part| first_named_child_of_kind(&part, "arguments"))
            else {
                valid = false;
                break;
            };
            let mut argument_cursor = arguments.walk();
            let arguments = arguments
                .named_children(&mut argument_cursor)
                .filter(|argument| argument.kind() == "argument")
                .collect::<Vec<_>>();
            let [pattern, replacement] = arguments.as_slice() else {
                valid = false;
                break;
            };
            let Some(pattern) = first_named_child(pattern) else {
                valid = false;
                break;
            };
            let Some(replacement) = first_named_child(replacement) else {
                valid = false;
                break;
            };
            let Some(input_character) = dart_exact_static_string(pattern, src) else {
                valid = false;
                break;
            };
            let Some(output) = dart_exact_static_string(replacement, src) else {
                valid = false;
                break;
            };
            if input_character.chars().count() != 1
                || mappings
                    .iter()
                    .any(|mapping| mapping.key == input_character && mapping.value != output)
            {
                valid = false;
                break;
            }
            if !mappings.iter().any(|mapping| mapping.key == input_character) {
                mappings.push(StaticStringMapEntry {
                    key: input_character,
                    value: output,
                });
            }
        }
        let Some(operation) = valid.then_some(operation).flatten() else {
            continue;
        };
        if mappings.is_empty() {
            continue;
        }
        mappings.sort_by(|left, right| left.key.cmp(&right.key));
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span: body_span,
            input_place: input.to_string(),
            input_param_index: Some(input_param_index),
            proof: bonsai_lang_api::CharacterConstraintProof::ExactRuntimeSemantics,
            output: CharacterConstraintOutput::Return,
            domain: CharacterConstraintDomain::ProviderBound {
                factory_call: String::new(),
                operation_call: format!("{receiver_type}.{operation}"),
                domain: Box::new(CharacterConstraintDomain::SubstitutesExact { mappings }),
            },
        });
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.transform_span.start));
    facts.dedup();
    facts
}

/// Preserve field precision only when every entry in a Dart map has a
/// compile-time string key. Identifiers in map-key position are evaluated
/// expressions, not object-field names; admitting even one would make mixed
/// maps lose whole-object value dependencies when the structured fields are
/// lowered.
fn dart_static_map_pairs<'tree>(node: Node<'tree>) -> Vec<(Node<'tree>, Node<'tree>)> {
    if node.kind() != "set_or_map_literal" {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    let mut cursor = node.walk();
    for pair in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "pair")
    {
        let (Some(key), Some(value)) = (pair.child_by_field_name("key"), pair.child_by_field_name("value"))
        else {
            return Vec::new();
        };
        if key.kind() != "string_literal" {
            return Vec::new();
        }
        pairs.push((key, value));
    }
    pairs
}

fn dart_binding_name(name: &str) -> bool {
    name != "_"
}

fn dart_pattern_bindings(node: Node<'_>) -> Vec<PatternBindingSite<'_>> {
    if node.kind() != "switch_statement" {
        return Vec::new();
    }
    let (Some(source), Some(body)) = (
        node.child_by_field_name("condition"),
        node.child_by_field_name("body"),
    ) else {
        return Vec::new();
    };
    let mut sites = Vec::new();
    let mut cursor = body.walk();
    for arm in body
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "switch_statement_case")
    {
        for pattern in collect_named_descendants(arm, "variable_pattern") {
            sites.push(PatternBindingSite {
                span_node: arm,
                pattern,
                source,
            });
        }
    }
    sites
}

fn dart_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    if node.kind() == "assignable_expression" {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        let Some(base) = children.first().copied() else {
            return ExpressionPlaceExtraction::default();
        };
        if !matches!(base.kind(), "identifier" | "this" | "super") {
            return ExpressionPlaceExtraction::default();
        }
        let base = node_text(&base, src).trim();
        if base.is_empty() {
            return ExpressionPlaceExtraction::default();
        }
        let mut parts = vec![base.to_string()];
        for selector in children.iter().copied().skip(1) {
            let selector = if matches!(
                selector.kind(),
                "unconditional_assignable_selector" | "conditional_assignable_selector"
            ) {
                selector
            } else if selector.kind() == "selector"
                && first_named_child_of_kind(&selector, "argument_part").is_none()
            {
                let Some(inner) = first_named_child(&selector) else {
                    return ExpressionPlaceExtraction::default();
                };
                inner
            } else {
                return ExpressionPlaceExtraction::default();
            };
            let Some(field) =
                first_identifier_like_child(&selector).or_else(|| first_identifier_descendant(selector))
            else {
                return ExpressionPlaceExtraction::default();
            };
            let field = node_text(&field, src).trim();
            if field.is_empty() {
                return ExpressionPlaceExtraction::default();
            }
            parts.push(field.to_string());
        }
        return ExpressionPlaceExtraction {
            places: vec![parts.join(".")],
            consumed_node_ids: vec![node.id()],
        };
    }

    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    let mut result = ExpressionPlaceExtraction::default();
    let mut index = 0usize;
    while index < children.len() {
        let base = children[index];
        if !matches!(base.kind(), "identifier" | "this" | "super") {
            index += 1;
            continue;
        }
        let mut parts = vec![node_text(&base, src).trim().to_string()];
        let mut consumed = vec![base.id()];
        let mut next = index + 1;
        while let Some(selector) = children.get(next) {
            if selector.kind() != "selector" || first_named_child_of_kind(selector, "argument_part").is_some()
            {
                break;
            }
            let Some(inner) = first_named_child(selector) else {
                break;
            };
            if !matches!(
                inner.kind(),
                "unconditional_assignable_selector" | "conditional_assignable_selector"
            ) {
                break;
            }
            let Some(field) =
                first_identifier_like_child(&inner).or_else(|| first_identifier_descendant(inner))
            else {
                break;
            };
            let field = node_text(&field, src).trim();
            if field.is_empty() {
                break;
            }
            parts.push(field.to_string());
            consumed.push(selector.id());
            next += 1;
        }
        if parts.len() > 1 && parts.iter().all(|part| !part.is_empty()) {
            result.places.push(parts.join("."));
            result.consumed_node_ids.extend(consumed);
            index = next;
        } else {
            index += 1;
        }
    }
    result
}

fn dart_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut cursor = node.walk();
    let parts = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "for_loop_parts")?;
    let binding = parts.child_by_field_name("name")?;
    let mut parts_cursor = parts.walk();
    let has_call = parts.named_children(&mut parts_cursor).any(|child| {
        child.kind() == "selector" && first_named_child_of_kind(&child, "argument_part").is_some()
    });
    let iterable = if has_call {
        parts
    } else {
        parts.child_by_field_name("value")?
    };
    Some((binding, iterable))
}

fn dart_receiver_from_name(name: &str) -> Option<String> {
    name.rsplit_once('.')
        .map(|(receiver, _)| receiver.trim())
        .filter(|receiver| !receiver.is_empty())
        .map(str::to_string)
}

fn dart_call_args(arguments: Node<'_>, file: FileId, src: &[u8], handler: &GrammarHandler) -> Vec<CallArg> {
    let mut args = Vec::new();
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if argument.kind() != "named_argument" {
            // Dart wraps each positional expression in an `argument` node.
            // The wrapper owns the diagnostic span; its sole named child is
            // the value whose place/callable identity the compiler lowers.
            let value = if argument.kind() == "argument" && argument.named_child_count() == 1 {
                first_named_child(&argument).unwrap_or(argument)
            } else {
                argument
            };
            if let Some(arg) = call_arg_from_nodes_with_handler(argument, value, file, src, None, handler) {
                args.push(arg);
            }
            continue;
        }
        let mut children_cursor = argument.walk();
        let children = argument.named_children(&mut children_cursor).collect::<Vec<_>>();
        let Some(label_index) = children.iter().position(|child| child.kind() == "label") else {
            continue;
        };
        let name = first_named_child(&children[label_index])
            .map(|name| node_text(&name, src).trim().to_string())
            .filter(|name| !name.is_empty());
        let Some(value) = children.get(label_index + 1).copied() else {
            continue;
        };
        let Some(mut arg) = call_arg_from_nodes_with_handler(argument, value, file, src, name, handler)
        else {
            continue;
        };
        let mut end = value.end_byte();
        for selector in children.iter().skip(label_index + 2) {
            if selector.kind() != "selector" {
                break;
            }
            end = selector.end_byte();
        }
        if end > value.end_byte() {
            arg.value_text = std::str::from_utf8(&src[value.start_byte()..end])
                .unwrap_or_default()
                .split_whitespace()
                .collect::<String>();
        }
        args.push(arg);
    }
    args
}

fn dart_selector_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    let argument_part = first_named_child_of_kind(&node, "argument_part")?;
    let previous = node.prev_named_sibling()?;
    let (name, receiver, call_kind) =
        if let Some((receiver, member, ..)) = dart_selector_method_receiver(node, src) {
            (format!("{receiver}.{member}"), Some(receiver), CallKind::Method)
        } else {
            let name = node_text(&previous, src).trim().to_string();
            if name.is_empty() {
                return None;
            }
            (name, None, CallKind::Function)
        };
    let call_start = dart_selector_call_start(node)?;
    let args = first_named_child_of_kind(&argument_part, "arguments")
        .map(|arguments| dart_call_args(arguments, file, src, handler))
        .unwrap_or_default();
    Some(FlowEvent::Call {
        span: Span::new(file, call_start as u64, node.end_byte() as u64),
        receiver,
        receiver_types: Vec::new(),
        name,
        call_kind,
        args,
    })
}

/// Return the first CST byte of a flattened Dart selector call.
///
/// Tree-sitter-dart represents `f(x)` as a base expression followed by an
/// argument selector, and `object.method(x)` as a base plus member and
/// argument selectors. The compiler call fact and every value-flow reference
/// to its result must use one identical span, including the base expression.
/// This is derived only from the parsed sibling chain; no callable/API name is
/// interpreted.
fn dart_selector_call_start(call_selector: Node<'_>) -> Option<usize> {
    let mut candidate = call_selector.prev_named_sibling()?;
    while matches!(
        candidate.kind(),
        "selector" | "unconditional_assignable_selector" | "conditional_assignable_selector"
    ) {
        candidate = candidate.prev_named_sibling()?;
    }
    Some(candidate.start_byte())
}

fn dart_selector_semantic_call_span(call_selector: Node<'_>, file: FileId, _src: &[u8]) -> Option<Span> {
    let start = dart_selector_call_start(call_selector)?;
    Some(Span::new(file, start as u64, call_selector.end_byte() as u64))
}

/// Recover the exact value expression to the left of one flattened Dart
/// method selector. Tree-sitter-dart stores the base, property selectors, and
/// each `(...)` selector as siblings, so a chained call's receiver is not one
/// descendant node. The nearest non-selector sibling is the base; any earlier
/// argument selector between it and the current member is the exact call that
/// produced the receiver value.
fn dart_selector_method_receiver<'tree>(
    call_selector: Node<'tree>,
    src: &[u8],
) -> Option<(String, String, Node<'tree>, Node<'tree>, Option<Node<'tree>>)> {
    let member_selector = call_selector.prev_named_sibling()?;
    let inner = match member_selector.kind() {
        "selector" => first_named_child(&member_selector)?,
        "unconditional_assignable_selector" | "conditional_assignable_selector" => member_selector,
        _ => return None,
    };
    if !matches!(
        inner.kind(),
        "unconditional_assignable_selector" | "conditional_assignable_selector"
    ) {
        return None;
    }
    let member = first_identifier_like_child(&inner)
        .map(|node| node_text(&node, src).trim().to_string())
        .filter(|name| !name.is_empty())?;

    let mut candidate = member_selector.prev_named_sibling()?;
    let mut previous_call = None;
    let base = loop {
        let is_selector_component = matches!(
            candidate.kind(),
            "selector" | "unconditional_assignable_selector" | "conditional_assignable_selector"
        );
        if !is_selector_component {
            break candidate;
        }
        if previous_call.is_none() && first_named_child_of_kind(&candidate, "argument_part").is_some() {
            previous_call = Some(candidate);
        }
        candidate = candidate.prev_named_sibling()?;
    };
    let receiver = std::str::from_utf8(&src[base.start_byte()..member_selector.start_byte()])
        .ok()?
        .split_whitespace()
        .collect::<String>();
    (!receiver.is_empty()).then_some((receiver, member, base, member_selector, previous_call))
}

fn dart_selector_call_receiver_facts(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CallReceiverFact> {
    let mut facts = Vec::new();
    for call_selector in collect_kinds(tree, &["selector"]) {
        if first_named_child_of_kind(&call_selector, "argument_part").is_none() {
            continue;
        }
        let Some((receiver, _, base, member_selector, previous_call)) =
            dart_selector_method_receiver(call_selector, src)
        else {
            continue;
        };
        let value_flow = if let Some(previous_call) = previous_call {
            ExpressionFlow {
                call_sites: dart_selector_semantic_call_span(previous_call, file, src)
                    .into_iter()
                    .collect(),
                ..ExpressionFlow::default()
            }
        } else {
            let mut flow = expression_flow_from_node_with_handler(base, file, src, &HANDLER);
            let base_text = node_text(&base, src).split_whitespace().collect::<String>();
            if receiver != base_text {
                flow.place = Some(receiver.clone());
                flow.projection = ExpressionProjection::from_adapter_place(&receiver);
                flow.source_names.clear();
                flow.source_names.push(receiver);
            }
            flow
        };
        let Some(call_span) = dart_selector_semantic_call_span(call_selector, file, src) else {
            continue;
        };
        facts.push(CallReceiverFact {
            call_span,
            receiver_span: Span::new(
                file,
                base.start_byte() as u64,
                member_selector.start_byte() as u64,
            ),
            value_flow,
            role: CallReceiverRole::Value,
            static_value: None,
        });
    }
    facts.sort_by_key(|fact| (fact.call_span.start, fact.call_span.end));
    facts.dedup();
    facts
}

fn dart_direct_call_info(
    node: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<(Option<String>, Vec<String>)> {
    let selector = dart_direct_selector_call_value(node)?;
    let FlowEvent::Call { name, args, .. } = dart_selector_call(selector, FileId::INVALID, src, handler)?
    else {
        return None;
    };
    let positional = args
        .into_iter()
        .filter(|arg| arg.name.is_none())
        .map(|arg| arg.value_text)
        .filter(|value| !value.trim().is_empty())
        .collect();
    Some((Some(name), positional))
}

/// Find the selector that produces the value of one Dart expression.
///
/// `await` is a value-preserving suspension wrapper, but the grammar nests it
/// below a `unary_expression` and keeps the callee base/selectors as siblings
/// inside the `await_expression`. Follow only that exact shape; ordinary
/// unary/conditional expressions remain compound and fail closed.
fn dart_direct_selector_call_value(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "unary_expression" => {
            let child = (node.named_child_count() == 1)
                .then(|| node.named_child(0))
                .flatten()?;
            (child.kind() == "await_expression")
                .then(|| dart_direct_selector_call_value(child))
                .flatten()
        }
        "await_expression" => dart_direct_selector_call(node.named_child(0)?),
        _ => dart_direct_selector_call(node),
    }
}

fn dart_direct_selector_call(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "selector" && first_named_child_of_kind(&node, "argument_part").is_some() {
        return Some(node);
    }
    if HANDLER
        .transparent_expression_wrapper_kinds
        .contains(&node.kind())
        && node.named_child_count() == 1
    {
        return dart_direct_selector_call(node.named_child(0)?);
    }
    let tail = std::iter::successors(node.next_named_sibling(), |sibling| sibling.next_named_sibling())
        .collect::<Vec<_>>();
    let selector_count = tail.iter().take_while(|child| child.kind() == "selector").count();
    let selector = tail.get(selector_count.checked_sub(1)?)?.to_owned();
    // A cascade mutates/calls the same receiver and evaluates to that
    // receiver. It may follow the direct constructor/call selector without
    // changing which call produced the initializer value. Any other named
    // suffix makes the expression compound and therefore ambiguous.
    (tail[selector_count..]
        .iter()
        .all(|child| child.kind() == "cascade_section")
        && first_named_child_of_kind(&selector, "argument_part").is_some())
    .then_some(selector)
}

/// Repair Dart's flattened selector-chain initializer facts.
///
/// Tree-sitter-dart represents `final value = module.build(input)` as three
/// sibling `value` fields (`module`, `.build`, `(input)`) rather than one call
/// expression node. Shared assignment lowering correctly keeps the first
/// exact value node, but that node alone cannot carry the complete direct-call
/// identity. Join only the exact adapter-owned sibling chain whose final
/// selector is an argument part; compound expressions and incomplete chains
/// remain untouched and therefore fail closed.
fn repair_dart_selector_assignment_value_facts(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for definition in collect_kinds(tree, &["initialized_variable_definition"]) {
        let Some(base) = definition.child_by_field_name("value") else {
            continue;
        };
        let assignment_span = span_of(file, &definition);
        let Some(fact) = index
            .assignment_values
            .iter_mut()
            .find(|fact| fact.assignment_span == assignment_span)
        else {
            continue;
        };
        let Some(selector) = dart_direct_selector_call_value(base) else {
            // A Dart cascade evaluates to its receiver after every cascade
            // section has executed.  For a collection literal initializer,
            // the grammar has no addressable base place, so the adapter
            // deliberately gives the in-progress receiver the binding name
            // (`final values = <T>[]..addAll(input)`).  Preserve that exact
            // post-cascade value in both the compiler fact and executable
            // flow event.  Otherwise the generic literal assignment emitted
            // after the cascade becomes a clean overwrite and erases the
            // receiver mutation that precedes it.
            let Some(target) = dart_collection_literal_cascade_target(definition, base, src) else {
                continue;
            };
            fact.direct_call_receiver = None;
            fact.direct_call_name = None;
            fact.value_flow = bonsai_lang_api::ExpressionFlow::from_place(target.clone());
            for decl in &mut index.defs {
                repair_dart_cascade_result_assignment_event(&mut decl.flow_events, assignment_span, &target);
            }
            continue;
        };
        let Some(FlowEvent::Call {
            span,
            name,
            receiver,
            args,
            ..
        }) = dart_selector_call(selector, file, src, &HANDLER)
        else {
            continue;
        };
        let positional_args = args
            .iter()
            .filter(|arg| arg.name.is_none())
            .map(|arg| arg.value_text.clone())
            .filter(|value| !value.trim().is_empty())
            .collect::<Vec<_>>();
        fact.direct_call_receiver = dart_receiver_from_name(&name);
        fact.direct_call_name = Some(name.clone());
        fact.call_sites.clear();
        fact.call_sites.push(span);
        fact.value_flow.call_sites.clear();
        fact.value_flow.call_sites.push(span);

        for decl in &mut index.defs {
            repair_dart_selector_assignment_event(
                &mut decl.flow_events,
                assignment_span,
                &name,
                &positional_args,
                receiver.as_deref(),
            );
        }
    }
}

/// Return the adapter-owned synthetic receiver for a collection-literal
/// cascade initializer.
///
/// Tree-sitter-dart represents the literal and each cascade section as
/// sibling `value` fields.  This helper accepts only that exact shape: one
/// language-defined collection literal followed exclusively by one or more
/// cascade sections.  Existing-value and constructor cascades retain their
/// ordinary place/call-result lowering and therefore never enter this path.
fn dart_collection_literal_cascade_target(
    definition: Node<'_>,
    base: Node<'_>,
    src: &[u8],
) -> Option<String> {
    if !matches!(base.kind(), "list_literal" | "set_or_map_literal" | "set") {
        return None;
    }
    let suffixes = std::iter::successors(base.next_named_sibling(), |node| node.next_named_sibling())
        .collect::<Vec<_>>();
    if suffixes.is_empty() || suffixes.iter().any(|node| node.kind() != "cascade_section") {
        return None;
    }
    let name = definition.child_by_field_name("name")?;
    let target = node_text(&name, src).trim();
    (!target.is_empty()).then(|| target.to_string())
}

fn repair_dart_cascade_result_assignment_event(
    events: &mut [FlowEvent],
    assignment_span: Span,
    target: &str,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } if *span == assignment_span => {
                *source_name = Some(target.to_string());
                *source_call = None;
                source_call_args.clear();
                source_names.clear();
                source_names.push(target.to_string());
                *value_kind = Some(bonsai_lang_api::AssignValueKind::Compound);
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if repair_dart_cascade_result_assignment_event(then_events, assignment_span, target)
                    || repair_dart_cascade_result_assignment_event(else_events, assignment_span, target)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if repair_dart_cascade_result_assignment_event(body, assignment_span, target) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if repair_dart_cascade_result_assignment_event(body, assignment_span, target)
                    || repair_dart_cascade_result_assignment_event(catch_events, assignment_span, target)
                    || repair_dart_cascade_result_assignment_event(finally_events, assignment_span, target)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Repair direct-call identities for Dart call arguments whose complete value
/// is a flattened selector call.
///
/// Tree-sitter-dart represents `outer(module.inner(value))` as a base value
/// followed by selector siblings. The generic argument walker deliberately
/// does not know that grammar shape, so it cannot attach the inner call span
/// to the outer argument. Rejoin only the exact argument span whose complete
/// value resolves through [`dart_direct_selector_call_value`]. Compound
/// expressions remain without a direct-call identity and therefore fail
/// closed in downstream compiler proofs.
fn repair_dart_selector_call_argument_value_facts(
    index: &mut DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    let mut nodes_by_span = std::collections::HashMap::<(u64, u64), Vec<Node<'_>>>::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_named() {
            let span = span_of(file, &node);
            nodes_by_span
                .entry((span.start, span.end))
                .or_default()
                .push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    for fact in &mut index.call_argument_values {
        if fact.direct_call_span.is_some() || fact.argument_span.file != file {
            continue;
        }
        let Some(nodes) = nodes_by_span.get(&(fact.argument_span.start, fact.argument_span.end)) else {
            continue;
        };
        fact.direct_call_span = nodes.iter().find_map(|node| {
            let value = if node.kind() == "argument" {
                first_named_child(node).unwrap_or(*node)
            } else {
                *node
            };
            let selector = dart_direct_selector_call_value(value)?;
            match dart_selector_call(selector, file, src, &HANDLER)? {
                FlowEvent::Call { span, .. } => Some(span),
                _ => None,
            }
        });
    }
}

fn repair_dart_selector_assignment_event(
    events: &mut [FlowEvent],
    assignment_span: Span,
    call_name: &str,
    positional_args: &[String],
    receiver: Option<&str>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } if *span == assignment_span => {
                *source_name = None;
                *source_call = Some(call_name.to_string());
                source_call_args.clone_from(&positional_args.to_vec());
                source_names.clear();
                source_names.extend(receiver.filter(|value| !value.is_empty()).map(str::to_string));
                *value_kind = Some(bonsai_lang_api::AssignValueKind::CallResult);
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if repair_dart_selector_assignment_event(
                    then_events,
                    assignment_span,
                    call_name,
                    positional_args,
                    receiver,
                ) || repair_dart_selector_assignment_event(
                    else_events,
                    assignment_span,
                    call_name,
                    positional_args,
                    receiver,
                ) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if repair_dart_selector_assignment_event(
                    body,
                    assignment_span,
                    call_name,
                    positional_args,
                    receiver,
                ) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if repair_dart_selector_assignment_event(
                    body,
                    assignment_span,
                    call_name,
                    positional_args,
                    receiver,
                ) || repair_dart_selector_assignment_event(
                    catch_events,
                    assignment_span,
                    call_name,
                    positional_args,
                    receiver,
                ) || repair_dart_selector_assignment_event(
                    finally_events,
                    assignment_span,
                    call_name,
                    positional_args,
                    receiver,
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn dart_expression_call_spans(node: Node<'_>) -> Vec<(usize, usize)> {
    let Some(selector) = node.next_named_sibling() else {
        return Vec::new();
    };
    if selector.kind() != "selector" || first_named_child_of_kind(&selector, "argument_part").is_none() {
        return Vec::new();
    }
    let Some(start) = dart_selector_call_start(selector) else {
        return Vec::new();
    };
    vec![(start, selector.end_byte())]
}

fn dart_cascade_receiver(node: Node<'_>, src: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if matches!(
        parent.kind(),
        "initialized_variable_definition" | "initialized_identifier"
    ) {
        if let Some(name) = parent.child_by_field_name("name") {
            let receiver = node_text(&name, src).trim();
            if !receiver.is_empty() {
                return Some(receiver.to_string());
            }
        }
    }
    let mut cursor = parent.walk();
    let mut base = None;
    for child in parent.named_children(&mut cursor) {
        match child.kind() {
            "identifier" | "this" | "super" => {
                base = Some(node_text(&child, src).trim().to_string());
            }
            "selector" | "argument_part" => {}
            "cascade_section" => break,
            _ => {}
        }
    }
    base.filter(|value| !value.is_empty())
}

fn dart_cascade_events(node: Node<'_>, file: FileId, src: &[u8], handler: &GrammarHandler) -> Vec<FlowEvent> {
    let Some(selector) = first_named_child_of_kind(&node, "cascade_selector") else {
        return Vec::new();
    };
    let Some(member) = first_identifier_like_child(&selector)
        .map(|member| node_text(&member, src).trim().to_string())
        .filter(|member| !member.is_empty())
    else {
        return Vec::new();
    };
    let receiver = dart_cascade_receiver(node, src);
    if let Some(argument_part) = first_named_child_of_kind(&node, "argument_part") {
        let args = first_named_child_of_kind(&argument_part, "arguments")
            .map(|arguments| dart_call_args(arguments, file, src, handler))
            .unwrap_or_default();
        let name = receiver
            .as_deref()
            .map_or_else(|| member.clone(), |receiver| format!("{receiver}.{member}"));
        return vec![FlowEvent::Call {
            span: span_of(file, &node),
            receiver: receiver.or_else(|| dart_receiver_from_name(&name)),
            receiver_types: Vec::new(),
            name,
            call_kind: CallKind::Method,
            args,
        }];
    }
    let mut cursor = node.walk();
    let Some(value) = node
        .named_children(&mut cursor)
        .find(|child| child.id() != selector.id() && child.start_byte() > selector.end_byte())
    else {
        return Vec::new();
    };
    let target = receiver
        .as_deref()
        .map_or_else(|| member.clone(), |receiver| format!("{receiver}.{member}"));
    if let Some(selector) = dart_direct_selector_call_value(value) {
        if let Some(FlowEvent::Call {
            name, receiver, args, ..
        }) = dart_selector_call(selector, file, src, handler)
        {
            let positional_args = args
                .iter()
                .filter(|arg| arg.name.is_none())
                .map(|arg| arg.value_text.clone())
                .collect();
            return vec![FlowEvent::Assign {
                span: span_of(file, &node),
                target,
                source_name: None,
                source_call: Some(name),
                source_call_args: positional_args,
                source_names: receiver.into_iter().collect(),
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
            }];
        }
    }
    let value_arg = call_arg_from_node_with_handler(value, file, src, None, handler);
    vec![FlowEvent::Assign {
        span: span_of(file, &node),
        target,
        source_name: value_arg.as_ref().and_then(|arg| arg.place.clone()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: value_arg.map_or_else(Vec::new, |arg| arg.source_names),
        declares_new_binding: false,
        value_kind: None,
    }]
}

fn dart_object_construction(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if !matches!(node.kind(), "new_expression" | "const_object_expression") {
        return None;
    }
    let arguments = first_named_child_of_kind(&node, "arguments")?;
    let type_node =
        first_named_child_of_kind(&node, "type_identifier").or_else(|| first_identifier_like_child(&node))?;
    let name = node_text(&type_node, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: None,
        receiver_types: Vec::new(),
        name,
        call_kind: CallKind::Constructor,
        args: dart_call_args(arguments, file, src, handler),
    })
}

fn extract_dart_syntax_events(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    match node.kind() {
        "selector" => dart_selector_call(node, file, src, handler).into_iter().collect(),
        "cascade_section" => dart_cascade_events(node, file, src, handler),
        "new_expression" | "const_object_expression" => dart_object_construction(node, file, src, handler)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

// Dart (tree-sitter-dart UserNobody14) handler. Function bodies live in
// a sibling `function_body` of the signature (kit's body fallback finds
// it via the parent chain). Class methods wrap the signature in a
// `method_signature` — we index only the inner signature to avoid
// double-counting. Calls in Dart use the unique split-grammar pattern
// `identifier selector(args)`; the walker has a Dart-specific branch
// that synthesizes a Call event from the previous-sibling identifier.
const HANDLER: GrammarHandler = GrammarHandler {
    literal_value_kinds: &[
        "_literal",
        "null_literal",
        "decimal_floating_point_literal",
        "decimal_integer_literal",
        "hex_integer_literal",
        "symbol_literal",
        "true",
        "false",
    ],
    literal_value_spellings: &[],
    string_literal_kinds: &["string_literal"],
    comment_kinds: &["comment", "documentation_comment"],
    doc_comment_kinds: &["documentation_comment"],
    doc_comment_prefixes: &["///", "/**"],
    decorator_kinds: &["annotation"],
    parameter_container_kinds: &["formal_parameter_list"],
    parameter_kinds: &["formal_parameter"],
    parameter_modifier_kinds: &[],
    parameter_annotation_kinds: &["annotation"],
    parameter_annotation_name_extractor: None,
    keyword_parameter_kinds: &[],
    parameter_selector_kinds: &[],
    implicit_parameter_kinds: &[],
    self_parameter_kinds: &[],
    last_identifier_parameter_kinds: &[],
    binding_identifier_kinds: &["identifier"],
    non_binding_pattern_kinds: &[],
    binding_lhs_pattern_kinds: &[],
    binding_pattern_field_names: &[],
    pattern_head_value_kinds: &[],
    multi_segment_value_pattern_kinds: &[],
    non_binding_pattern_field_names: &["type", "key"],
    binding_name_extractor: None,
    binding_name_filter: Some(dart_binding_name),
    pattern_binding_extractor: Some(dart_pattern_bindings),
    projected_pattern_binding_extractor: None,
    anonymous_variadic_token: None,
    variadic_parameter_kinds: &[],
    destructured_parameter_kinds: &[],
    // `$name` inside a Dart string template is a distinct Tree-sitter read
    // node. It cannot declare a binding, but it must participate in
    // expression flow just like an ordinary identifier.
    // `this` and `super` are dedicated expression nodes in the Dart CST,
    // not `identifier` children. They are nevertheless compiler value
    // operands and must reach call arguments/receiver-state flow.
    identifier_kinds: &["identifier", "identifier_dollar_escaped", "this", "super"],
    aggregate_pattern_kinds: &[],
    comprehension_kinds: &[],
    comprehension_binding_clause_kinds: &[],
    comprehension_binding_extractor: None,
    named_aggregate_kinds: &["set_or_map_literal"],
    positional_aggregate_kinds: &["list_literal", "set"],
    aggregate_pair_kinds: &[],
    two_child_aggregate_pair_kinds: &[],
    aggregate_pair_extractor: Some(dart_static_map_pairs),
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["string_literal"],
    // Dot shorthands such as `.red` are values, not aggregate field
    // shorthands. Their identifier child remains an ordinary value read.
    shorthand_field_kinds: &[],
    spread_kinds: &["spread_element"],
    spread_value_field_names: &[],
    aggregate_syntax_only_kinds: &[],
    multi_child_aggregate_pattern_kinds: &[],
    lambda_value_container_kinds: &[],
    transparent_call_wrapper_kinds: &["selector", "postfix_expression", "parenthesized_expression"],
    single_expression_group_kinds: &["function_expression_body"],
    assignment_target_wrapper_kinds: &["initialized_variable_definition"],
    binding_declaration_keyword_spellings: &["var", "final", "const", "late"],
    nested_type_ownership: true,
    fn_kinds: &[
        "function_signature",
        "getter_signature",
        "setter_signature",
        "constructor_signature",
        "factory_constructor_signature",
    ],
    class_kinds: &[
        "class_definition",
        "mixin_declaration",
        "extension_declaration",
        "enum_declaration",
    ],
    class_decl_kinds: &[
        ("class_definition", DeclKind::Class),
        ("mixin_declaration", DeclKind::Trait),
        ("extension_declaration", DeclKind::Class),
        ("enum_declaration", DeclKind::Enum),
    ],
    method_kinds: &["method_signature"],
    method_context_kinds: &["class_definition", "mixin_declaration", "extension_declaration"],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &["constructor_signature", "factory_constructor_signature"],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    function_definition_extractor: None,
    inline_closure_yield_extractor: None,
    if_kinds: &["if_statement", "switch_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition"],
    branch_condition_kinds: &[],
    branch_condition_is_first_named_child: true,
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    condition_not_operator_kinds: &["prefix_operator"],
    branch_alias_extractor: None,
    branch_arm_kinds: &["block", "expression_statement"],
    exclusive_branch_arm_kinds: &["switch_statement_case", "switch_statement_default"],
    fallthrough_branch_arm_kinds: &[],
    additional_alternative_kinds: &[],
    for_kinds: &["for_statement"],
    foreach_kinds: &[],
    foreach_binding_extractor: Some(dart_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    loop_kinds: &[],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block", "expression_statement"],
    loop_header_container_kinds: &["for_loop_parts"],
    loop_update_field_names: &["update"],
    call_kinds: &[],
    constructor_call_kinds: &[],
    nested_call_component_kinds: &[],
    call_callee_field_names: &[],
    call_receiver_field_names: &[],
    call_member_field_names: &[],
    constructor_type_field_names: &[],
    call_argument_field_names: &[],
    call_argument_container_kinds: &[],
    call_argument_wrapper_kinds: &[],
    call_callee_is_first_named_child: false,
    argument_wrapper_kinds: &["named_argument"],
    argument_name_field_names: &[],
    argument_value_field_names: &[],
    named_argument_extractor: None,
    direct_call_info_extractor: Some(dart_direct_call_info),
    call_target_extractor: None,
    call_receiver_extractor: None,
    call_ref_node_filter: None,
    expression_call_span_extractor: Some(dart_expression_call_spans),
    writeback_operand_field_names: &[],
    direct_call_argument_excluded_fields: &[],
    transparent_expression_wrapper_kinds: &["parenthesized_expression"],
    pseudo_call_extractor: None,
    syntax_event_extractor: None,
    syntax_events_extractor: Some(extract_dart_syntax_events),
    call_encoded_control_flow_extractor: None,
    pseudo_call_receiver_extractor: None,
    argument_passing_mode_extractor: None,
    expression_value_kind_extractor: None,
    assignment_kinds: &[
        "assignment_expression",
        "initialized_variable_definition",
        "static_final_declaration",
    ],
    assignment_semantics_extractor: None,
    assignment_place_extractor: None,
    compound_assignment_kinds: &[],
    compound_assignment_operators: &[
        "+=", "-=", "*=", "/=", "~/=", "%=", "<<=", ">>=", ">>>=", "&=", "^=", "|=", "??=",
    ],
    type_only_declaration_kinds: &[],
    positional_aggregate_assignment_kinds: &[],
    positional_aggregate_value_kinds: &[],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_expression"],
    lambda_kinds: &["function_expression", "lambda_expression"],
    inline_closure_kinds: &[],
    implicit_lambda_parameter_name: None,
    lambda_body_field_names: &["body"],
    lambda_body_kinds: &["function_expression", "lambda_expression"],
    try_kinds: &["try_statement"],
    // `on Type catch (e)` is represented as sibling `type_identifier`,
    // `catch_clause`, and body nodes under the try statement. There is no
    // `on_part` wrapper in the parser shipped by this adapter.
    catch_kinds: &["catch_clause"],
    exclusive_catch_arm_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    try_fallback_body_kinds: &["block"],
    catch_body_follows_marker: true,
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    yield_kinds: &["yield_statement"],
    yield_value_field_names: &[],
    await_kinds: &["await_expression"],
    defer_kinds: &[],
    deferred_body_extractor: None,
    using_kinds: &[],
    using_body_field_names: &[],
    try_body_field_names: &["body"],
    using_alias_extractor: None,
    special_forms: &[],
    runtime_type_guard_calls: &[],
    runtime_type_guard_operators: &["is"],
    runtime_typeof_operators: &[],
    runtime_type_equality_operators: &[],
    runtime_type_wrapper_kinds: &["parenthesized_expression"],
    value_free_expression_kinds: &[],
    value_free_call_names: &[],
    value_free_unary_operators: &[],
    call_ref_kinds: &[],
    member_expression_kinds: &[
        "assignable_expression",
        "unconditional_assignable_selector",
        "conditional_assignable_selector",
    ],
    subscript_expression_kinds: &[],
    member_base_field_names: &[],
    member_name_field_names: &["name"],
    subscript_base_field_names: &[],
    subscript_index_field_names: &[],
    static_subscript_key_extractor: Some(dart_static_key),
    computed_subscript_extractor: None,
    sigil_variable_kinds: &[],
    global_variable_kinds: &[],
    reference_name_extractor: None,
    expression_place_extractor: Some(dart_expression_places),
    indirect_place_operand_extractor: None,
    subscript_base_call_refs: false,
    non_call_ref_names: &[],
    call_name_suffix_tokens: &[],
    syntax_error_tolerant_call_names: &[],
    callable_reference_kinds: &[],
    callable_reference_extractor: None,
    method_receiver_param_index: None,
    receiver_presence_extractor: None,
    implicit_receiver_names: &["this", "super"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
};

#[derive(Debug, Default, Copy, Clone)]
pub struct DartAdapter;

impl DartAdapter {
    /// Construct a stateless Dart adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for DartAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Dart"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["dart"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Object", "dynamic"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            // Dart permits `Widget(...)` without `new`, and Tree-sitter
            // therefore lowers class construction through the same call
            // expression shape as a function call. The resolver must refine
            // that ambiguous syntax from the scoped class declaration.
            bare_call_constructor_syntax: true,
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "argument"),
            ("custom lowering", "argument_part"),
            ("custom lowering", "arguments"),
            ("custom lowering", "assignable_expression"),
            ("custom lowering", "block"),
            ("custom lowering", "cascade_section"),
            ("custom lowering", "cascade_selector"),
            ("custom lowering", "catch_clause"),
            ("custom lowering", "class_body"),
            ("custom lowering", "class_definition"),
            ("custom lowering", "combinator"),
            ("custom lowering", "conditional_assignable_selector"),
            ("custom lowering", "configurable_uri"),
            ("custom lowering", "const_object_expression"),
            ("custom lowering", "constructor_param"),
            ("custom lowering", "constructor_signature"),
            ("custom lowering", "declaration"),
            ("custom lowering", "factory_constructor_signature"),
            ("custom lowering", "for_loop_parts"),
            ("custom lowering", "formal_parameter"),
            ("custom lowering", "formal_parameter_list"),
            ("custom lowering", "function_body"),
            ("custom lowering", "function_expression_body"),
            ("custom lowering", "function_signature"),
            ("custom lowering", "function_type"),
            ("custom lowering", "getter_signature"),
            ("custom lowering", "identifier"),
            ("custom lowering", "import_or_export"),
            ("custom lowering", "import_specification"),
            ("custom lowering", "initialized_identifier"),
            ("custom lowering", "initialized_identifier_list"),
            ("custom lowering", "initialized_variable_definition"),
            ("custom lowering", "label"),
            ("custom lowering", "library_import"),
            ("custom lowering", "method_signature"),
            ("custom lowering", "mixin_declaration"),
            ("custom lowering", "named_argument"),
            ("custom lowering", "new_expression"),
            ("custom lowering", "pair"),
            ("custom lowering", "selector"),
            ("custom lowering", "set_or_map_literal"),
            ("custom lowering", "setter_signature"),
            ("custom lowering", "string_literal"),
            ("custom lowering", "super"),
            ("custom lowering", "switch_statement"),
            ("custom lowering", "switch_statement_case"),
            ("custom lowering", "this"),
            ("custom lowering", "type"),
            ("custom lowering", "type_arguments"),
            ("custom lowering", "type_cast"),
            ("custom lowering", "type_cast_expression"),
            ("custom lowering", "type_identifier"),
            ("custom lowering", "unconditional_assignable_selector"),
            ("custom lowering", "uri"),
        ]
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let parsed = parse_with(PACK_NAME, file, ctx);
        let mut decl_index = parsed.as_ref().map_or_else(
            || DeclIndex {
                file,
                ..DeclIndex::default()
            },
            |(snapshot, tree)| {
                decl_index_from_tree_with_handler(file, snapshot.text.as_bytes(), tree, &HANDLER)
            },
        );
        if let Some((snapshot, tree)) = parsed.as_ref() {
            rewrite_dart_named_constructor_declarations(
                &mut decl_index,
                tree,
                file,
                snapshot.text.as_bytes(),
            );
        }
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        // Dart privacy is name-based: `_`-prefixed identifiers are
        // library-private (Visibility::Module).
        for decl in &mut decl_index.defs {
            if decl.name.starts_with('_') {
                decl.visibility = Visibility::Module;
            }
        }
        // Per-decl `type_aliases` from typed parameters
        // (`String name`, `HttpClient client`). Brings Dart in
        // lockstep with Java/Kotlin/Scala/TS/C#/Swift/Rust/Python so
        // `attribute: [HttpClient, getUrl]`-style rules can resolve
        // `client.getUrl(...)` semantically per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        let mut declared_fields_by_parent = std::collections::HashMap::new();
        let mut declared_field_types_by_parent = std::collections::HashMap::new();
        let mut lexical_local_bindings = std::collections::HashMap::new();
        let mut module_type_aliases = Vec::new();
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let source_bytes = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `T foo() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, tree, source_bytes, &HANDLER);
            let aliases_by_span = collect_dart_method_type_aliases(tree, file, source_bytes);
            for decl in &mut decl_index.defs {
                if let Some(aliases) = aliases_by_span.iter().find_map(|(span, aliases)| {
                    (span.file == decl.span.file && span.start == decl.span.start).then_some(aliases)
                }) {
                    decl.type_aliases = aliases.clone();
                }
            }
            // Per-class `bases`: `class Echo extends WebSocketHandler with M implements I`
            // → ["WebSocketHandler", "M", "I"]. Dart wraps the parent
            // class under `superclass:` (which can also embed a
            // `mixins` sibling carrying `with` clauses) and lists
            // `interfaces:` separately.
            let bases_by_span = collect_dart_class_bases(tree, file, source_bytes);
            for decl in &mut decl_index.defs {
                if !is_class_like(decl.kind) {
                    continue;
                }
                // Match by exact span first; fall back to name to handle
                // cases where the decl span differs from the class node.
                if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
            }
            let signature_formals_by_span = collect_dart_signature_formals(tree, file, source_bytes);
            let expression_returns_by_span = collect_dart_expression_body_returns(tree, file, source_bytes);
            (declared_fields_by_parent, declared_field_types_by_parent) =
                collect_dart_declared_instance_fields(&decl_index, tree, file, source_bytes);
            lexical_local_bindings = collect_dart_lexical_local_bindings(tree, file, source_bytes);
            module_type_aliases = collect_dart_module_type_aliases(tree, source_bytes);
            for decl in &mut decl_index.defs {
                if let Some((params, writes)) = dart_formals_for_decl(decl, &signature_formals_by_span) {
                    if !params.is_empty() {
                        decl.params = params.clone();
                    }
                    if decl.kind == DeclKind::Constructor {
                        decl.receiver_field_writes.extend(writes.clone());
                    }
                }
                if let Some(return_event) = dart_expression_return_for_decl(decl, &expression_returns_by_span)
                {
                    if !decl.flow_events.iter().any(|event| {
                        matches!(
                            (event, return_event),
                            (FlowEvent::Return { span: existing, .. }, FlowEvent::Return { span: added, .. })
                                if existing == added
                        )
                    }) {
                        decl.flow_events.push(return_event.clone());
                        decl.has_implicit_returns = true;
                    }
                }
            }
            // The kit's generic catch-param walk picks Dart's `on Type`
            // identifier over the bound variable in `on E catch (e)`.
            // Recompute `Try::catch_param` from the structural context so
            // the catch body's read of `e` gets G8-seeded.
            for decl in &mut decl_index.defs {
                fix_dart_catch_params(&mut decl.flow_events, tree, source_bytes);
            }
            let property_reads = synthesize_dart_property_reads(tree, source_bytes, file);
            enrich_dart_property_read_dependencies(&mut decl_index, &property_reads);
            decl_index.refs.extend(property_reads);
            decl_index
                .refs
                .extend(synthesize_dart_call_refs(tree, source_bytes, file));
            decl_index
                .call_receivers
                .extend(dart_selector_call_receiver_facts(tree, file, source_bytes));
            decl_index
                .call_receivers
                .sort_by_key(|fact| (fact.call_span.start, fact.call_span.end));
            decl_index.call_receivers.dedup();
            repair_dart_selector_assignment_value_facts(&mut decl_index, tree, file, source_bytes);
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut decl_index,
                tree,
                file,
                source_bytes,
                &HANDLER,
                dart_static_scalar,
            );
            repair_dart_selector_call_argument_value_facts(&mut decl_index, tree, file, source_bytes);
            let switch_break_spans = collect_dart_switch_break_spans(tree, file);
            for decl in &mut decl_index.defs {
                bonsai_lang_api::kit::lower_adapter_local_breaks(&mut decl.flow_events, &switch_break_spans);
            }
            bonsai_lang_api::kit::populate_assignment_inline_callback_static_returns(
                &mut decl_index,
                tree,
                source_bytes,
                &HANDLER,
                dart_static_scalar,
            );
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // A Dart instance field may be declared directly in the class body
        // (`String payload = ''`) rather than through a constructor field
        // formal (`FeedJob(this.payload)`).  Tree-sitter exposes the former
        // as an exact class-body declaration, but an unqualified read inside
        // a method is otherwise indistinguishable from a local to shared IR.
        // Join the parsed declaration with the owning method here and retain
        // lexical local shadowing while canonicalizing field places to
        // `this.<field>` for the IDG.
        qualify_dart_declared_instance_field_reads(
            &mut decl_index,
            &declared_fields_by_parent,
            &lexical_local_bindings,
        );
        apply_dart_module_type_aliases(&mut decl_index, &module_type_aliases, &lexical_local_bindings);
        apply_dart_declared_instance_field_types(&mut decl_index, &declared_field_types_by_parent);
        // Qualify expression-bodied getter fields from constructor-emitted
        // class storage facts, then qualify bare reads of a
        // sibling zero-arg member (`final c = cmd;`) into an
        // `Assign{source_call}` plus an explicit `Call` event whose
        // argless walk_call fallback synthesizes a `CallArg{idx=0}`
        // recv-slot so `recv_slots_for_call_span` has something to
        // bridge caller-receiver taint through.
        qualify_dart_member_access_getters(&mut decl_index);
        qualify_dart_implicit_member_reads(&mut decl_index);
        for decl in &mut decl_index.defs {
            decl.receiver_field_writes
                .extend(bonsai_lang_api::kit::collect_receiver_field_writes(
                    &decl.flow_events,
                    &decl.params,
                    None,
                    &["this"],
                    &[],
                ));
            decl.receiver_field_writes.sort_by_key(|write| {
                (
                    write.span.start,
                    write.target.clone(),
                    write.source_param_indices.clone(),
                )
            });
            decl.receiver_field_writes.dedup();
            decl.receiver_field_initializers =
                bonsai_lang_api::kit::collect_receiver_field_initializers(&decl.flow_events, &["this"]);
            decl.receiver_state_sources = bonsai_lang_api::kit::collect_receiver_state_sources(
                &decl.flow_events,
                &decl.params,
                &["this"],
            );
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`var c = Foo()` →
        // `c: Foo`) is driven by Dart's object-construction syntax or an
        // exactly resolved declaration, never by identifier capitalization.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        // Constructor and class-field passes add exact aliases after the
        // generic walker first annotated calls. Re-run receiver enrichment so
        // those late compiler facts reach the final call IR.
        bonsai_lang_api::apply_call_receiver_types(&mut decl_index);
        if let Some((snapshot, tree)) = parsed.as_ref() {
            decl_index
                .character_constraints
                .extend(dart_provider_bound_string_substitutions(
                    &decl_index.defs,
                    tree,
                    file,
                    snapshot.text.as_bytes(),
                ));
            decl_index
                .character_constraints
                .sort_by_key(|fact| (fact.function_span.start, fact.transform_span.start));
            decl_index.character_constraints.dedup();
        }
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Dart `break` exits the nearest loop or switch.  Resolve that target from
/// Tree-sitter ancestry so switch-arm terminators do not become enclosing
/// function terminators in the structured compiler IR.
fn collect_dart_switch_break_spans(tree: &Tree, file: FileId) -> std::collections::HashSet<Span> {
    let mut out = std::collections::HashSet::new();
    for break_node in collect_kinds(tree, &["break_statement"]) {
        let mut current = break_node.parent();
        while let Some(ancestor) = current {
            if matches!(
                ancestor.kind(),
                "for_statement" | "while_statement" | "do_statement"
            ) {
                break;
            }
            if ancestor.kind() == "switch_statement" {
                out.insert(span_of(file, &break_node));
                break;
            }
            if matches!(ancestor.kind(), "function_body" | "function_expression") {
                break;
            }
            current = ancestor.parent();
        }
    }
    out
}

/// Preserve the member portion of a named Dart constructor declaration.
///
/// Tree-sitter represents `Type.member(...)` as two direct identifier
/// children of a constructor signature, but the shared declaration lowerer
/// deliberately chooses the grammar's `name` field when one exists. For Dart
/// that field names the owning type, so a named constructor would otherwise
/// collide with the unnamed constructor and could not resolve a call to
/// `Type.member(...)`. The adapter owns this split-signature grammar detail;
/// shared resolution continues to consume an ordinary member declaration.
fn rewrite_dart_named_constructor_declarations(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut named = std::collections::HashMap::new();
    for signature in collect_kinds(tree, &["constructor_signature", "factory_constructor_signature"]) {
        let mut cursor = signature.walk();
        let identifiers = signature
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .collect::<Vec<_>>();
        let Some(member) = (identifiers.len() >= 2).then(|| *identifiers.last().expect("non-empty")) else {
            continue;
        };
        let member_name = node_text(&member, src).trim();
        if member_name.is_empty() {
            continue;
        }
        named.insert(
            signature.start_byte() as u64,
            (member_name.to_string(), span_of(file, &member)),
        );
    }
    for decl in &mut index.defs {
        if decl.kind != DeclKind::Constructor {
            continue;
        }
        let Some((name, name_span)) = named.get(&decl.span.start) else {
            continue;
        };
        decl.name.clone_from(name);
        decl.name_span = *name_span;
    }
}

fn collect_named_descendants<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == kind {
            out.push(current);
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    out.sort_by_key(Node::start_byte);
    out
}

fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

/// The parser represents `on E catch (e)` as sibling type, catch marker, and
/// body nodes under the try statement. Recompute `Try::catch_param` from the
/// catch marker's exact `exception` field so the preceding type identifier can
/// never be mistaken for the value binding.
const DART_SELECTOR_KINDS: &[&str] = &[
    "unconditional_assignable_selector",
    "conditional_assignable_selector",
];

fn synthesize_dart_call_refs(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    collect_kinds(tree, &["selector"])
        .into_iter()
        .filter_map(|node| match dart_selector_call(node, file, src, &HANDLER) {
            Some(FlowEvent::Call { span, name, .. }) => Some(Ref {
                span,
                name,
                kind: RefKind::Call,
                scope: None,
                resolved: None,
            }),
            _ => None,
        })
        .collect()
}

/// tree-sitter-dart splits `uri.queryParameters` into sibling nodes — a base
/// expression and a trailing `(selector (unconditional_assignable_selector
/// (identifier)))` — so the kit's member-chain extractor (which expects a
/// nested member expression) returns `None` for the single-segment selector
/// and never surfaces the dotted name. Reconstruct the full access via source
/// span slicing (base start .. selector end) and emit a `Read` ref for the
/// adapter-owned [`DART_SELECTOR_KINDS`]. This lets source and navigation
/// consumers bind to the exact member chain. Security meaning is intentionally
/// absent here: rules constrain the emitted syntax with receiver types,
/// packages, and trust metadata.
fn synthesize_dart_property_reads(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    let mut refs = Vec::new();
    for sel_inner in collect_kinds(tree, DART_SELECTOR_KINDS) {
        let Some(prop) = first_named_child_of_kind(&sel_inner, "identifier") else {
            continue;
        };
        let name = node_text(&prop, src).trim();
        if name.is_empty() {
            continue;
        }
        // Navigate to the postfix `selector` wrapper (where the receiver is a
        // preceding sibling), then walk back over any earlier selector levels
        // to the base expression that opens the chain.
        let selector_node = match sel_inner.parent() {
            Some(parent) if parent.kind() == "selector" => parent,
            _ => sel_inner,
        };
        let mut base = selector_node.prev_named_sibling();
        loop {
            match base {
                Some(node) if node.kind() == "selector" => base = node.prev_named_sibling(),
                _ => break,
            }
        }
        let Some(base_node) = base else {
            continue;
        };
        let start = base_node.start_byte();
        let end = sel_inner.end_byte();
        if start >= end {
            continue;
        }
        let Ok(chain) = std::str::from_utf8(&src[start..end]) else {
            continue;
        };
        let chain = chain.trim().to_string();
        // Require a dotted access — a bare selector with no recoverable
        // receiver is not a member read compiler consumers can bind.
        if !chain.contains('.') {
            continue;
        }
        refs.push(Ref {
            span: span_of(file, &sel_inner),
            name: chain,
            kind: RefKind::Read,
            scope: None,
            resolved: None,
        });
    }
    refs
}

/// Dart selector chains are flattened into sibling nodes. The expression-flow
/// extractor retains the complete terminal place, while source matching can
/// legitimately anchor an earlier property in the same chain. Preserve every
/// parsed property prefix contained by an event so exact syntax anchors and
/// the terminal value remain connected without assigning meaning to a member
/// name in the adapter.
fn enrich_dart_property_read_dependencies(index: &mut DeclIndex, reads: &[Ref]) {
    for decl in &mut index.defs {
        enrich_dart_event_property_reads(&mut decl.flow_events, reads);
    }
}

fn enrich_dart_event_property_reads(events: &mut [FlowEvent], reads: &[Ref]) {
    for event in events {
        let span = event.span();
        let contained = reads
            .iter()
            .filter(|read| {
                read.kind == RefKind::Read
                    && read.span.file == span.file
                    && span.start <= read.span.start
                    && read.span.end <= span.end
            })
            .map(|read| read.name.clone())
            .collect::<Vec<_>>();
        match event {
            FlowEvent::Assign { source_names, .. } => {
                source_names.extend(contained);
                source_names.sort();
                source_names.dedup();
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    for read in reads.iter().filter(|read| {
                        read.kind == RefKind::Read
                            && read.span.file == arg.span.file
                            && arg.span.start <= read.span.start
                            && read.span.end <= arg.span.end
                    }) {
                        if !arg.source_names.iter().any(|source| source == &read.name) {
                            arg.source_names.push(read.name.clone());
                        }
                    }
                    arg.source_names.sort();
                    arg.source_names.dedup();
                }
            }
            FlowEvent::AggregateAssign { value_flow, .. }
            | FlowEvent::Return { value_flow, .. }
            | FlowEvent::Yield { value_flow, .. } => {
                value_flow.source_names.extend(contained);
                value_flow.source_names.sort();
                value_flow.source_names.dedup();
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_dart_event_property_reads(then_events, reads);
                enrich_dart_event_property_reads(else_events, reads);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_dart_event_property_reads(body, reads);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_dart_event_property_reads(body, reads);
                enrich_dart_event_property_reads(catch_events, reads);
                enrich_dart_event_property_reads(finally_events, reads);
            }
            _ => {}
        }
    }
}

fn fix_dart_catch_params(events: &mut [FlowEvent], tree: &Tree, src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if let Some(name) = dart_catch_param_name(node, src) {
                        *catch_param = Some(name);
                    }
                }
                fix_dart_catch_params(body, tree, src);
                fix_dart_catch_params(catch_events, tree, src);
                fix_dart_catch_params(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                fix_dart_catch_params(then_events, tree, src);
                fix_dart_catch_params(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                fix_dart_catch_params(body, tree, src);
            }
            _ => {}
        }
    }
}

/// Extract the bound exception variable from the first direct Dart
/// `catch_clause`. Parameterless `on E { ... }` arms have no marker and return
/// `None`.
fn dart_catch_param_name(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = try_node.walk();
    for child in try_node.named_children(&mut cursor) {
        if child.kind() == "catch_clause" {
            return dart_catch_clause_binding(child, src);
        }
    }
    None
}

/// Read the compiler grammar's exception field. The optional stack-trace
/// field is deliberately excluded because only the primary exception binding
/// receives the thrown value.
fn dart_catch_clause_binding(catch_clause: Node<'_>, src: &[u8]) -> Option<String> {
    catch_clause
        .child_by_field_name("exception")
        .or_else(|| first_identifier_descendant(catch_clause))
        .map(|binding| node_text(&binding, src).trim().to_string())
        .filter(|binding| !binding.is_empty())
}

/// Collect instance storage declared directly in each parsed class body.
///
/// Dart's constructor field-formals already become `receiver_field_writes`,
/// but an ordinary declaration such as `String payload = ''` is storage too.
/// Keep this as a syntax fact: the adapter records only the parsed binding and
/// its exact owner; consumers assign no API or security meaning to the name.
fn collect_dart_declared_instance_fields(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> (
    std::collections::HashMap<bonsai_common::SymbolId, std::collections::HashSet<String>>,
    std::collections::HashMap<bonsai_common::SymbolId, Vec<TypeAliasBinding>>,
) {
    let mut out = std::collections::HashMap::new();
    let mut typed = std::collections::HashMap::new();
    for class_node in collect_kinds(tree, &["class_definition"]) {
        let Some(body) = class_node.child_by_field_name("body") else {
            continue;
        };
        let class_span = span_of(file, &class_node);
        let class_name = class_node
            .child_by_field_name("name")
            .map(|name| node_text(&name, src).trim().to_string())
            .unwrap_or_default();
        let Some(owner) = index
            .defs
            .iter()
            .find(|decl| {
                is_class_like(decl.kind)
                    && (decl.span == class_span || (!class_name.is_empty() && decl.name == class_name))
            })
            .map(|decl| decl.symbol)
        else {
            continue;
        };

        let mut fields = std::collections::HashSet::new();
        let mut aliases = Vec::new();
        let mut cursor = body.walk();
        for declaration in body
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "declaration")
        {
            // `static` is an anonymous grammar token. A static binding is
            // class storage, not receiver storage, so never canonicalize it
            // to `this.<field>`.
            if node_text(&declaration, src).trim_start().starts_with("static ") {
                continue;
            }
            let Some(list) = first_named_child_of_kind(&declaration, "initialized_identifier_list") else {
                continue;
            };
            let declared_type = {
                let mut declaration_cursor = declaration.walk();
                let declared_type = declaration
                    .named_children(&mut declaration_cursor)
                    .find(|child| child.id() != list.id() && child.kind() != "metadata")
                    .map(|node| bonsai_lang_api::kit::canonical_simple_type_name(node_text(&node, src)))
                    .filter(|name| !name.is_empty());
                declared_type
            };
            let mut list_cursor = list.walk();
            for initialized in list
                .named_children(&mut list_cursor)
                .filter(|child| child.kind() == "initialized_identifier")
            {
                let binding = initialized
                    .child_by_field_name("name")
                    .or_else(|| first_identifier_like_child(&initialized));
                let Some(binding) = binding else { continue };
                let name = node_text(&binding, src).trim();
                if !name.is_empty() {
                    fields.insert(name.to_string());
                    if let Some(type_name) = &declared_type {
                        aliases.push(TypeAliasBinding {
                            name: format!("this.{name}"),
                            type_name: type_name.clone(),
                        });
                    }
                }
            }
        }
        if !fields.is_empty() {
            out.insert(owner, fields);
        }
        aliases.sort_by(|left, right| {
            (left.name.as_str(), left.type_name.as_str())
                .cmp(&(right.name.as_str(), right.type_name.as_str()))
        });
        aliases.dedup();
        if !aliases.is_empty() {
            typed.insert(owner, aliases);
        }
    }
    (out, typed)
}

fn apply_dart_declared_instance_field_types(
    index: &mut DeclIndex,
    field_types: &std::collections::HashMap<bonsai_common::SymbolId, Vec<TypeAliasBinding>>,
) {
    for decl in &mut index.defs {
        let Some(parent) = decl.parent else { continue };
        let Some(aliases) = field_types.get(&parent) else {
            continue;
        };
        for alias in aliases {
            if !decl.type_aliases.contains(alias) {
                decl.type_aliases.push(alias.clone());
            }
        }
    }
}

/// Record local variable declarations by their exact compiler span.
///
/// Tree-sitter Dart represents `final value = expression` as an
/// `initialized_variable_definition`, which is distinct from a class body's
/// `declaration`. Shared assignment lowering preserves the definition span but
/// intentionally does not own this grammar-specific declaration role. Keeping
/// this fact in the adapter lets field canonicalization honor lexical shadows
/// without inferring them from identifier spelling.
fn collect_dart_lexical_local_bindings(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, String> {
    collect_kinds(tree, &["initialized_variable_definition"])
        .into_iter()
        .filter_map(|definition| {
            let binding = definition
                .child_by_field_name("name")
                .or_else(|| first_identifier_like_child(&definition))?;
            let name = node_text(&binding, src).trim();
            (!name.is_empty()).then(|| (span_of(file, &definition), name.to_string()))
        })
        .collect()
}

/// Collect explicitly typed Dart library variables as lexical receiver facts.
///
/// A declaration such as `late Client client;` is represented by a top-level
/// `type_identifier` followed by an `initialized_identifier_list`. The value is
/// visible to every callable in the same library file. Class storage and local
/// declarations are excluded structurally; they have narrower owners and are
/// handled by the corresponding field/local passes.
fn collect_dart_module_type_aliases(tree: &Tree, src: &[u8]) -> Vec<TypeAliasBinding> {
    let mut aliases = Vec::new();
    for list in collect_kinds(tree, &["initialized_identifier_list"]) {
        let mut ancestor = list.parent();
        let mut module_scoped = true;
        while let Some(node) = ancestor {
            if matches!(
                node.kind(),
                "class_definition" | "function_signature" | "function_body"
            ) {
                module_scoped = false;
                break;
            }
            ancestor = node.parent();
        }
        if !module_scoped {
            continue;
        }
        let Some(type_node) = list
            .prev_named_sibling()
            .filter(|node| matches!(node.kind(), "type_identifier" | "type" | "function_type"))
        else {
            continue;
        };
        let Some(type_name) = canonical_dart_type_name(node_text(&type_node, src)) else {
            continue;
        };
        let mut cursor = list.walk();
        for initialized in list
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "initialized_identifier")
        {
            let Some(binding) = initialized
                .child_by_field_name("name")
                .or_else(|| first_identifier_like_child(&initialized))
            else {
                continue;
            };
            push_dart_type_alias(&mut aliases, node_text(&binding, src).trim(), &type_name);
        }
    }
    dedup_dart_type_aliases(&mut aliases);
    aliases
}

/// Make exact library-variable types visible to each callable while retaining
/// lexical shadowing. A parameter, typed local, or untyped local declaration
/// with the same binding prevents the module alias from being copied into that
/// declaration.
fn apply_dart_module_type_aliases(
    index: &mut DeclIndex,
    module_aliases: &[TypeAliasBinding],
    lexical_local_bindings: &std::collections::HashMap<Span, String>,
) {
    for decl in &mut index.defs {
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let decl_range = decl.body_span.unwrap_or(decl.span);
        for alias in module_aliases {
            let shadowed = decl.params.iter().any(|param| param == &alias.name)
                || decl.type_aliases.iter().any(|local| local.name == alias.name)
                || lexical_local_bindings
                    .iter()
                    .any(|(span, name)| name == &alias.name && span_contains(decl_range, *span));
            if !shadowed && !decl.type_aliases.contains(alias) {
                decl.type_aliases.push(alias.clone());
            }
        }
    }
}

fn qualify_dart_declared_instance_field_reads(
    index: &mut DeclIndex,
    fields_by_parent: &std::collections::HashMap<bonsai_common::SymbolId, std::collections::HashSet<String>>,
    lexical_local_bindings: &std::collections::HashMap<Span, String>,
) {
    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
            continue;
        }
        let Some(fields) = decl.parent.and_then(|parent| fields_by_parent.get(&parent)) else {
            continue;
        };
        let mut locals = decl
            .params
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        qualify_dart_field_events(&mut decl.flow_events, fields, lexical_local_bindings, &mut locals);
    }
}

fn qualify_dart_field_events(
    events: &mut [FlowEvent],
    fields: &std::collections::HashSet<String>,
    lexical_local_bindings: &std::collections::HashMap<Span, String>,
    locals: &mut std::collections::HashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call { receiver, args, .. } => {
                if let Some(receiver) = receiver {
                    qualify_dart_field_place(receiver, fields, locals);
                }
                for arg in args {
                    if let Some(place) = &mut arg.place {
                        qualify_dart_field_place(place, fields, locals);
                    }
                    for source in &mut arg.source_names {
                        qualify_dart_field_place(source, fields, locals);
                    }
                }
            }
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call_args,
                source_names,
                declares_new_binding,
                ..
            } => {
                if let Some(source) = source_name {
                    qualify_dart_field_place(source, fields, locals);
                }
                for source in source_call_args.iter_mut().chain(source_names.iter_mut()) {
                    qualify_dart_field_place(source, fields, locals);
                }
                let compiler_declares_local = lexical_local_bindings
                    .get(span)
                    .is_some_and(|binding| binding == target);
                if *declares_new_binding || compiler_declares_local {
                    if let Some(local) = dart_bare_binding(target) {
                        locals.insert(local.to_string());
                    }
                } else {
                    qualify_dart_field_place(target, fields, locals);
                }
            }
            FlowEvent::AggregateAssign { value_flow, .. }
            | FlowEvent::Return { value_flow, .. }
            | FlowEvent::Yield { value_flow, .. } => {
                qualify_dart_field_expression(value_flow, fields, locals);
                if let FlowEvent::Return { value_name, .. } = event {
                    if let Some(value) = value_name {
                        qualify_dart_field_place(value, fields, locals);
                    }
                }
            }
            FlowEvent::Throw { value_name, .. } | FlowEvent::Await { value_name, .. } => {
                if let Some(value) = value_name {
                    qualify_dart_field_place(value, fields, locals);
                }
            }
            FlowEvent::Lifecycle { name, .. } => qualify_dart_field_place(name, fields, locals),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let mut then_locals = locals.clone();
                qualify_dart_field_events(then_events, fields, lexical_local_bindings, &mut then_locals);
                let mut else_locals = locals.clone();
                qualify_dart_field_events(else_events, fields, lexical_local_bindings, &mut else_locals);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                let mut nested_locals = locals.clone();
                qualify_dart_field_events(body, fields, lexical_local_bindings, &mut nested_locals);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                let mut body_locals = locals.clone();
                qualify_dart_field_events(body, fields, lexical_local_bindings, &mut body_locals);
                let mut catch_locals = locals.clone();
                if let Some(param) = catch_param {
                    catch_locals.insert(param.clone());
                }
                qualify_dart_field_events(catch_events, fields, lexical_local_bindings, &mut catch_locals);
                let mut finally_locals = locals.clone();
                qualify_dart_field_events(
                    finally_events,
                    fields,
                    lexical_local_bindings,
                    &mut finally_locals,
                );
            }
            _ => {}
        }
    }
}

fn qualify_dart_field_expression(
    flow: &mut bonsai_lang_api::ExpressionFlow,
    fields: &std::collections::HashSet<String>,
    locals: &std::collections::HashSet<String>,
) {
    if let Some(place) = &mut flow.place {
        qualify_dart_field_place(place, fields, locals);
    }
    if let Some(projection) = &mut flow.projection {
        if fields.contains(&projection.base) && !locals.contains(&projection.base) {
            projection.path.insert(0, std::mem::take(&mut projection.base));
            projection.base = "this".to_string();
            flow.place = Some(projection.canonical_place());
        }
    }
    for source in &mut flow.source_names {
        qualify_dart_field_place(source, fields, locals);
    }
    for field in &mut flow.aggregate_fields {
        qualify_dart_field_expression(&mut field.value, fields, locals);
    }
    for item in &mut flow.tuple_items {
        qualify_dart_field_expression(item, fields, locals);
    }
    for spread in &mut flow.spreads {
        qualify_dart_field_expression(spread, fields, locals);
    }
}

fn qualify_dart_field_place(
    place: &mut String,
    fields: &std::collections::HashSet<String>,
    locals: &std::collections::HashSet<String>,
) {
    let trimmed = place.trim();
    let base_end = trimmed.find(['.', '[']).unwrap_or(trimmed.len());
    let base = &trimmed[..base_end];
    if fields.contains(base) && !locals.contains(base) {
        *place = format!("this.{trimmed}");
    }
}

fn dart_bare_binding(place: &str) -> Option<&str> {
    let place = place.trim();
    (!place.is_empty()
        && place
            .bytes()
            .all(|byte| byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
        && !place.as_bytes()[0].is_ascii_digit())
    .then_some(place)
}

/// Qualify a getter projection such as `data.cmd` to `this.data.cmd` when
/// `data` is proven to be class storage by a constructor field-formal.  The
/// exact IDG can then substitute the caller receiver for `this` while
/// preserving the complete field suffix; no synthetic getter call or textual
/// member-name guess is needed.
fn qualify_dart_member_access_getters(index: &mut DeclIndex) {
    let mut fields_by_parent: std::collections::HashMap<
        bonsai_common::SymbolId,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();
    for decl in &index.defs {
        let Some(parent) = decl.parent else { continue };
        for write in &decl.receiver_field_writes {
            let Some(field) = write.target.strip_prefix("this.") else {
                continue;
            };
            let field = field.split('.').next().unwrap_or(field).trim();
            if !field.is_empty() {
                fields_by_parent
                    .entry(parent)
                    .or_default()
                    .insert(field.to_string());
            }
        }
    }
    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
            continue;
        }
        if !decl.params.is_empty() {
            continue;
        }
        if decl.flow_events.len() != 1 {
            continue;
        }
        let Some(fields) = decl.parent.and_then(|parent| fields_by_parent.get(&parent)) else {
            continue;
        };
        let FlowEvent::Return { value_flow, .. } = &mut decl.flow_events[0] else {
            continue;
        };
        let Some(projection) = value_flow.projection.as_mut() else {
            continue;
        };
        if fields.contains(&projection.base) {
            projection.path.insert(0, std::mem::take(&mut projection.base));
            projection.base = "this".to_string();
            let place = projection.canonical_place();
            value_flow.place = Some(place.clone());
            value_flow.source_names.clear();
            value_flow.source_names.push(place);
        }
    }
}

/// Rewrite a bare read (`final c = cmd;`) of a sibling zero-arg member
/// (getter / property / record accessor) into an `Assign{source_call}`
/// plus an explicit `Call` event so `walk_call`'s argless fallback
/// creates a `CallArg{idx=0}` recv-slot. Without that synthetic slot,
/// `recv_slots_for_call_span` returns nothing and the interprocedural
/// receiver-field bridge can't propagate caller-receiver taint into
/// the getter's body.
fn qualify_dart_implicit_member_reads(index: &mut DeclIndex) {
    bonsai_lang_api::qualify_implicit_member_reads_in_index(index, |name| ImplicitMemberReadCall {
        source_call: name.to_string(),
        call_name: name.to_string(),
        receiver: None,
        call_kind: CallKind::Function,
    });
}

fn dart_expression_return_for_decl<'a>(
    decl: &bonsai_lang_api::Decl,
    returns_by_span: &'a [(bonsai_common::Span, FlowEvent)],
) -> Option<&'a FlowEvent> {
    returns_by_span
        .iter()
        .find(|(span, _)| span.file == decl.span.file && span.start == decl.span.start)
        .map(|(_, event)| event)
        .or_else(|| {
            returns_by_span
                .iter()
                .find(|(span, _)| {
                    span.file == decl.span.file && span.start <= decl.span.start && decl.span.end <= span.end
                })
                .map(|(_, event)| event)
        })
}

fn dart_formals_for_decl<'a>(
    decl: &bonsai_lang_api::Decl,
    formals_by_span: &'a [(bonsai_common::Span, Vec<String>, Vec<FieldWrite>)],
) -> Option<(&'a Vec<String>, &'a Vec<FieldWrite>)> {
    let same_file = |span: &bonsai_common::Span| span.file == decl.span.file;
    let exact_start = |span: &bonsai_common::Span| same_file(span) && span.start == decl.span.start;
    let contains_decl = |span: &bonsai_common::Span| {
        same_file(span) && span.start <= decl.span.start && decl.span.end <= span.end
    };

    if decl.kind == DeclKind::Constructor {
        if let Some((_, params, writes)) = formals_by_span
            .iter()
            .find(|(span, _, writes)| exact_start(span) && !writes.is_empty())
        {
            return Some((params, writes));
        }
    }
    if let Some((_, params, writes)) = formals_by_span.iter().find(|(span, _, _)| exact_start(span)) {
        return Some((params, writes));
    }

    if decl.kind == DeclKind::Constructor {
        if let Some((_, params, writes)) = formals_by_span
            .iter()
            .find(|(span, _, writes)| contains_decl(span) && !writes.is_empty())
        {
            return Some((params, writes));
        }
    }
    if let Some((_, params, writes)) = formals_by_span.iter().find(|(span, _, _)| contains_decl(span)) {
        return Some((params, writes));
    }

    if decl.kind != DeclKind::Constructor {
        return None;
    }
    formals_by_span
        .iter()
        .find(|(span, params, writes)| {
            same_file(span) && !writes.is_empty() && params.as_slice() == decl.params.as_slice()
        })
        .map(|(_, params, writes)| (params, writes))
}

fn collect_dart_expression_body_returns(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, FlowEvent)> {
    let mut out = Vec::new();
    for signature in collect_kinds(
        tree,
        &[
            "function_signature",
            "getter_signature",
            "setter_signature",
            "method_signature",
            "constructor_signature",
            "factory_constructor_signature",
        ],
    ) {
        let signature = dart_signature_node_for_formals(signature);
        let Some(body) = dart_signature_body_node(signature) else {
            continue;
        };
        if !dart_function_body_is_expression(&body) {
            continue;
        }
        let Some(value_text) = dart_expression_body_text(&body, src) else {
            continue;
        };
        let value_name = first_named_child_of_kind(&body, "identifier")
            .map(|identifier| node_text(&identifier, src).trim().to_string())
            .filter(|name| !name.is_empty());
        let mut value_flow =
            bonsai_lang_api::kit::expression_flow_from_node_with_handler(body, file, src, &HANDLER);
        if let Some(projection) = dart_split_selector_projection(&body, src) {
            let place = projection.canonical_place();
            value_flow.place = Some(place.clone());
            value_flow.projection = Some(projection);
            value_flow.source_names.clear();
            value_flow.source_names.push(place);
        }
        out.push((
            span_of(file, &signature),
            FlowEvent::Return {
                span: span_of(file, &body),
                value_kind: HANDLER.expression_value_kind(body, src),
                value_text: Some(value_text),
                value_name,
                value_flow,
            },
        ));
    }
    out
}

/// Tree-sitter Dart represents `base.field.subfield` as a base identifier
/// followed by sibling selector nodes rather than one nested member node.
/// Lower that exact CST sequence into the language-neutral projection fact.
fn dart_split_selector_projection(
    body: &Node<'_>,
    src: &[u8],
) -> Option<bonsai_lang_api::ExpressionProjection> {
    let mut cursor = body.walk();
    let children: Vec<Node<'_>> = body.named_children(&mut cursor).collect();
    let base_node = children.first()?;
    if !matches!(base_node.kind(), "identifier" | "this" | "super") {
        return None;
    }
    let base = node_text(base_node, src).trim().to_string();
    let mut path = Vec::new();
    for selector in children.iter().skip(1) {
        if selector.kind() != "selector" {
            return None;
        }
        if first_named_child_of_kind(selector, "argument_part").is_some() {
            return None;
        }
        let inner = first_named_child(selector)?;
        if !matches!(
            inner.kind(),
            "unconditional_assignable_selector" | "conditional_assignable_selector"
        ) {
            return None;
        }
        let identifier = first_named_child_of_kind(&inner, "identifier")?;
        let field = node_text(&identifier, src).trim();
        if field.is_empty() {
            return None;
        }
        path.push(field.to_string());
    }
    (!base.is_empty() && !path.is_empty()).then_some(bonsai_lang_api::ExpressionProjection { base, path })
}

fn dart_signature_body_node(signature: Node<'_>) -> Option<Node<'_>> {
    signature
        .next_named_sibling()
        .filter(|node| node.kind() == "function_body")
        .or_else(|| {
            let parent = signature.parent()?;
            parent
                .next_named_sibling()
                .filter(|node| node.kind() == "function_body")
        })
}

fn dart_function_body_is_expression(body: &Node<'_>) -> bool {
    first_named_child_of_kind(body, "block").is_none()
}

fn dart_expression_body_text(body: &Node<'_>, src: &[u8]) -> Option<String> {
    let text = node_text(body, src).trim();
    let text = text.strip_prefix("=>").unwrap_or(text).trim();
    let text = text.strip_suffix(';').unwrap_or(text).trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn collect_dart_signature_formals(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>, Vec<FieldWrite>)> {
    let mut out = Vec::new();
    for signature in collect_kinds(
        tree,
        &[
            "function_signature",
            "getter_signature",
            "setter_signature",
            "method_signature",
            "constructor_signature",
            "factory_constructor_signature",
        ],
    ) {
        let signature = dart_signature_node_for_formals(signature);
        let Some(params) = first_named_child_of_kind(&signature, "formal_parameter_list") else {
            continue;
        };
        let mut formals = Vec::new();
        collect_dart_constructor_formal_params(params, file, src, &mut formals);
        let param_names = formals
            .iter()
            .map(|formal| formal.name.clone())
            .collect::<Vec<_>>();
        let mut writes = Vec::new();
        for (idx, formal) in formals.iter().enumerate() {
            if let Some(field_span) = formal.field_formal_span {
                writes.push(FieldWrite {
                    span: field_span,
                    target: format!("this.{}", formal.name),
                    source_param_indices: vec![idx],
                });
            }
        }
        if !param_names.is_empty() || !writes.is_empty() {
            out.push((span_of(file, &signature), param_names, writes));
        }
    }
    out
}

fn dart_signature_node_for_formals(signature: Node<'_>) -> Node<'_> {
    if signature.kind() == "method_signature" {
        if let Some(inner) = first_named_child_of_kind(&signature, "function_signature") {
            return inner;
        }
    }
    if signature.kind() == "declaration" {
        if let Some(inner) = first_named_child(&signature) {
            if matches!(
                inner.kind(),
                "function_signature"
                    | "getter_signature"
                    | "setter_signature"
                    | "method_signature"
                    | "constructor_signature"
                    | "factory_constructor_signature"
            ) {
                return dart_signature_node_for_formals(inner);
            }
        }
    }
    signature
}

struct DartConstructorFormal {
    name: String,
    field_formal_span: Option<bonsai_common::Span>,
}

fn collect_dart_constructor_formal_params(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<DartConstructorFormal>,
) {
    if node.kind() == "formal_parameter" {
        if let Some(formal) = dart_constructor_formal(node, file, src) {
            out.push(formal);
            return;
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_dart_constructor_formal_params(child, file, src, out);
    }
}

fn dart_constructor_formal(
    parameter_node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<DartConstructorFormal> {
    if let Some(field_formal) = first_descendant_of_kind(parameter_node, "constructor_param") {
        let field_name = first_named_child_of_kind(&field_formal, "identifier")
            .map(|identifier| node_text(&identifier, src).trim().to_string())
            .filter(|field_name| !field_name.is_empty())?;
        return Some(DartConstructorFormal {
            name: field_name,
            field_formal_span: Some(span_of(file, &field_formal)),
        });
    }
    let name = dart_parameter_binding_name(parameter_node, src)?;
    Some(DartConstructorFormal {
        name,
        field_formal_span: None,
    })
}

fn dart_parameter_binding_name(parameter_node: Node<'_>, src: &[u8]) -> Option<String> {
    if let Some(name_node) = parameter_node.child_by_field_name("name") {
        let name = node_text(&name_node, src).trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    let mut last_identifier: Option<Node<'_>> = None;
    let mut cursor = parameter_node.walk();
    for child in parameter_node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            last_identifier = Some(child);
        }
    }
    last_identifier
        .map(|identifier| node_text(&identifier, src).trim().to_string())
        .filter(|name| !name.is_empty())
}

fn first_descendant_of_kind<'tree>(
    node: tree_sitter::Node<'tree>,
    kind: &str,
) -> Option<tree_sitter::Node<'tree>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_descendant_of_kind(child, kind) {
            return Some(found);
        }
    }
    None
}

/// Extract Dart `import` directives into the canonical `ImportSpec` shape
/// used by the matcher index.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Dart's `import 'pkg:foo/bar.dart' as x show A, B;` parses as
    //   import_or_export
    //     library_import
    //       import_specification
    //         configurable_uri > uri > string_literal "'pkg:...'"
    //         identifier "x"               <- alias (optional)
    for import_node in collect_kinds(tree, &["import_or_export"]) {
        let Some(import_spec) = first_named_child_of_kind(&import_node, "library_import")
            .and_then(|library_import| first_named_child_of_kind(&library_import, "import_specification"))
        else {
            continue;
        };
        let Some(uri_node) = first_named_child_of_kind(&import_spec, "configurable_uri")
            .and_then(|configurable_uri| first_named_child_of_kind(&configurable_uri, "uri"))
            .and_then(|uri| first_named_child_of_kind(&uri, "string_literal"))
        else {
            continue;
        };
        // Dart import URIs come in three flavours:
        //   1. `package:foo/foo.dart` — pub package; canonical name is `foo`.
        //   2. `dart:io` — core library; canonical name is `dart:io`.
        //   3. `relative.dart` — local file; pass through unchanged.
        // Strip the `package:` prefix so the matcher's import-index
        // sees the package name (`foo/foo.dart` → first-segment
        // `foo`) instead of being shadowed by the `package:` scheme.
        // Without this strip, `pkg::import_matches_package(needle="foo",
        // module="package:foo/foo.dart")` is false (no prefix match
        // against the leading `package:` literal).
        let raw_uri = node_text(&uri_node, src).trim_matches(|ch: char| matches!(ch, '\'' | '"'));
        let module = raw_uri.strip_prefix("package:").unwrap_or(raw_uri).to_string();
        // The optional `as x` alias appears as the first identifier
        // child of the import specification.
        let mut spec_cursor = import_spec.walk();
        let alias = import_spec
            .named_children(&mut spec_cursor)
            .find(|child| child.kind() == "identifier")
            .map(|alias_node| node_text(&alias_node, src).to_string());
        // Dart's `show A, B` combinators bind specific symbols from
        // the imported library to the file scope. Each becomes its own
        // member-style ImportSpec so the rule matcher can chase
        // `A` / `B` back through the alias map to the package.
        let mut combinator_names: Vec<String> = Vec::new();
        let mut combinator_cursor = import_spec.walk();
        for child in import_spec.named_children(&mut combinator_cursor) {
            if child.kind() != "combinator" {
                continue;
            }
            // `show` and `hide` both appear as `combinator` nodes;
            // only `show` introduces a binding (hide *removes* names),
            // so skip non-`show` keywords. Match on the first
            // whitespace-delimited token to avoid catching identifiers
            // that incidentally start with `show` characters.
            let combinator_text = node_text(&child, src);
            if combinator_text.split_whitespace().next() != Some("show") {
                continue;
            }
            let mut child_cursor = child.walk();
            for ident in child.named_children(&mut child_cursor) {
                if ident.kind() == "identifier" {
                    let name = node_text(&ident, src).to_string();
                    if !name.is_empty() {
                        combinator_names.push(name);
                    }
                }
            }
        }
        let exposes_unqualified_library = alias.is_none() && combinator_names.is_empty();
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module: module.clone(),
            alias,
            is_wildcard: exposes_unqualified_library,
            original_name: None,
            scope: ImportScope::Module,
        });
        for name in combinator_names {
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module.clone(),
                alias: None,
                is_wildcard: false,
                original_name: Some(name),
                scope: ImportScope::Module,
            });
        }
    }
    imports
}

/// Walk every Dart function/method body once and record the
/// parameter type-alias bindings. Tree-sitter-dart names function
/// declarations as `function_signature` / `getter_signature` /
/// `setter_signature` / `method_signature` and class constructors
/// as `constructor_signature`; each carries a `formal_parameter_list`
/// with `formal_parameter` children (including those nested under
/// `optional_formal_parameters`).
fn collect_dart_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_per_signature = Vec::new();
    for signature_node in collect_kinds(
        tree,
        &[
            "function_signature",
            "getter_signature",
            "setter_signature",
            "method_signature",
            "constructor_signature",
            "factory_constructor_signature",
        ],
    ) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut signature_cursor = signature_node.walk();
        for child in signature_node.named_children(&mut signature_cursor) {
            if child.kind() == "formal_parameter_list" {
                collect_dart_parameter_aliases(child, src, &mut aliases);
            }
        }
        // WS2: typed locals (`Foo c = make();`) declared in the body —
        // the cast / factory-typed receiver case. The body is the
        // signature's sibling, not a child, so reach for it explicitly.
        if let Some(body) = signature_node
            .next_named_sibling()
            .filter(|sibling| sibling.kind() == "function_body")
        {
            collect_dart_local_decl_aliases(body, src, &mut aliases);
        }
        dedup_dart_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            aliases_per_signature.push((span_of(file, &signature_node), aliases));
        }
    }
    aliases_per_signature
}

/// Walk a Dart `function_body` for typed local declarations
/// (`Foo c = make();`) and emit `(name, type)` aliases, so cast /
/// factory-typed receivers resolve `receiver_type_in`. The
/// `initialized_variable_definition` node carries a `name` field + a
/// leading `type_identifier`, the same shape `dart_typed_parameter_alias`
/// already handles. Nested function bodies are skipped — their locals
/// scope to themselves.
fn collect_dart_local_decl_aliases(body: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let mut work = vec![body];
    while let Some(node) = work.pop() {
        if node != body && node.kind() == "function_body" {
            continue;
        }
        if node.kind() == "initialized_variable_definition" {
            dart_typed_parameter_alias(node, src, aliases);
            // WS2: `var c = make() as Foo` — an inferred local typed only
            // by an `as` cast on its initializer.
            dart_cast_local_alias(node, src, aliases);
            // Dart collection literals have a language-defined nominal type
            // even when the binding uses `final`/`var`.  Preserve that exact
            // compiler fact so rulepack-owned core-library summaries can
            // distinguish `List.addAll`/`List.map` from same-spelled methods
            // on application receivers. Cascades keep the literal as the
            // first `value:` child (`<String>[]..addAll(...)`).
            dart_collection_literal_local_alias(node, src, aliases);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            work.push(child);
        }
    }
}

fn dart_collection_literal_local_alias(
    definition: Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    let Some(name_node) = definition.child_by_field_name("name") else {
        return;
    };
    let Some(value) = definition.child_by_field_name("value") else {
        return;
    };
    let type_name = match value.kind() {
        "list_literal" => "List",
        _ => return,
    };
    push_dart_type_alias(aliases, node_text(&name_node, src).trim(), type_name);
}

/// WS2 cast typing for dart inferred locals: `var c = expr as Foo`. The
/// `as` cast surfaces as a `type_cast` / `type_cast_expression` node that
/// is a DIRECT child of the `initialized_variable_definition` (a cast
/// nested in a call argument is not a direct child, so it can't mistype
/// the local). Binds the definition's name to the cast's target type when
/// that type is the explicit cast target.
fn dart_cast_local_alias(def: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let Some(name_node) = def.child_by_field_name("name") else {
        return;
    };
    let name = node_text(&name_node, src).trim().to_string();
    // Only fire when the initializer IS directly an `as` cast
    // (`type_cast` / `type_cast_expression`) — a cast nested in a call
    // argument is not the `value`, so it can't mistype the local.
    let Some(value) = def.child_by_field_name("value") else {
        return;
    };
    if !matches!(value.kind(), "type_cast" | "type_cast_expression") {
        return;
    }
    // The cast target `type_identifier` is nested
    // (type_cast_expression -> type_cast -> type_identifier); take the
    // outermost (smallest start byte) so a generic `Foo<Bar>` resolves to
    // `Foo`.
    let mut best: Option<Node<'_>> = None;
    let mut stack = vec![value];
    while let Some(n) = stack.pop() {
        if n.kind() == "type_identifier" && best.is_none_or(|b| n.start_byte() < b.start_byte()) {
            best = Some(n);
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    let Some(type_node) = best else {
        return;
    };
    let ty = node_text(&type_node, src).trim().to_string();
    if name.is_empty() || ty.is_empty() {
        return;
    }
    let binding = TypeAliasBinding { name, type_name: ty };
    if !aliases.contains(&binding) {
        aliases.push(binding);
    }
}

/// Recurse through a Dart `formal_parameter_list` and emit a type-alias
/// binding for each typed parameter we can identify.
fn collect_dart_parameter_aliases(
    parameter_list_node: Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    let mut cursor = parameter_list_node.walk();
    for child in parameter_list_node.named_children(&mut cursor) {
        match child.kind() {
            "formal_parameter" => {
                dart_typed_parameter_alias(child, src, aliases);
            }
            // Recurse for grouped parameter lists (`{a, b}`, `[a, b]`).
            _ => collect_dart_parameter_aliases(child, src, aliases),
        }
    }
}

/// Pull the `(binding, declared type)` pair out of a single Dart formal
/// parameter node. Best-effort: many parameter shapes lack a `type`
/// field, in which case we scan unnamed children.
fn dart_typed_parameter_alias(parameter_node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    // tree-sitter-dart's `formal_parameter` exposes the binding
    // identifier under the `name` field but the type is an unnamed
    // `type_identifier` / `type` child preceding the identifier. Keep a
    // structural fallback for field-formals and recovery trees that omit the
    // field label.
    let binding_node = if let Some(name_node) = parameter_node.child_by_field_name("name") {
        name_node
    } else {
        let mut last_identifier: Option<Node<'_>> = None;
        let mut param_cursor = parameter_node.walk();
        for child in parameter_node.named_children(&mut param_cursor) {
            if child.kind() == "identifier" {
                last_identifier = Some(child);
            }
        }
        match last_identifier {
            Some(identifier_node) => identifier_node,
            None => return,
        }
    };
    let binding_name = node_text(&binding_node, src).trim().to_string();
    if binding_name.is_empty() {
        return;
    }
    // Dart's grammar represents a qualified nominal type as two adjacent
    // `type_identifier` children and exposes its prefix through the `type:`
    // field. Select the
    // final type-shaped child before the binding instead. Generic arguments
    // are nested under the leading nominal node, so this also keeps
    // `List<String> values` bound to `List`, not `String`.
    let mut type_node = None;
    let mut param_cursor = parameter_node.walk();
    for child in parameter_node.named_children(&mut param_cursor) {
        if child.end_byte() <= binding_node.start_byte()
            && matches!(child.kind(), "type_identifier" | "type" | "function_type")
        {
            type_node = Some(child);
        }
    }
    if let Some(type_node) = type_node {
        if let Some(canonical) = canonical_dart_type_name(node_text(&type_node, src)) {
            push_dart_type_alias(aliases, &binding_name, &canonical);
        }
    }
}

/// Strip generics / nullable markers / function-type tail down to
/// the leftmost type identifier. `List<String>` → `List`,
/// `String?` → `String`, `Future<HttpClient>` → `Future`.
fn canonical_dart_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('?').trim();
    // Drop generics: keep everything up to the first `<`.
    let without_generics = trimmed.split('<').next().unwrap_or(trimmed).trim();
    // Drop module prefixes: `prefix.Type` → `Type`.
    let bare = without_generics
        .rsplit('.')
        .next()
        .unwrap_or(without_generics)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Append a `(name, type_name)` alias unless either side is empty or
/// they collapse to the same identifier (which would be a no-op alias).
fn push_dart_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

/// Drop duplicate `(name, type_name)` pairs in place, preserving order.
fn dedup_dart_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// `true` when `kind` is a Dart class-shaped declaration eligible for
/// `bases:` enrichment (extends / implements / mixins).
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Dart class / mixin / extension definitions and collect bare
/// base type names. Grammar shape (verified):
///
///   `class Echo extends WebSocketHandler with M1 implements I1`
///     → (class_definition name: (identifier)
///          superclass: (superclass (type_identifier)
///                                  (mixins (type_identifier)))
///          interfaces: (interfaces (type_identifier)))
///
/// The `superclass:` field wraps the `extends` parent and any
/// `with` mixins. `interfaces:` carries `implements` types.
/// Generic / qualified bases collapse to the bare tail.
fn collect_dart_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_per_class = Vec::new();
    let class_kinds = &["class_definition", "mixin_declaration", "extension_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        // Prefer the named `name:` field; older grammars expose only an
        // unnamed `identifier` child.
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "identifier"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
        let mut bases: Vec<String> = Vec::new();
        // `superclass:` carries `extends` plus any embedded `with` mixins.
        if let Some(superclass_node) = class_node.child_by_field_name("superclass") {
            collect_dart_base_names(superclass_node, src, &mut bases);
        }
        // `interfaces:` carries `implements` types.
        if let Some(interfaces_node) = class_node.child_by_field_name("interfaces") {
            collect_dart_base_names(interfaces_node, src, &mut bases);
        }
        if !bases.is_empty() {
            bases_per_class.push((span_of(file, &class_node), class_name.to_string(), bases));
        }
    }
    bases_per_class
}

/// Walk a Dart parent-clause wrapper (`superclass`, `interfaces`,
/// `mixins`) and pick out every type identifier. Skip
/// `type_arguments` so generic params (e.g. `<String, int>`) don't
/// leak into the bases list.
fn collect_dart_base_names(parent_clause: Node<'_>, src: &[u8], bases: &mut Vec<String>) {
    let mut stack = vec![parent_clause];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_arguments" => {
                // Skip generics — these are type params of the base,
                // not bases of their own.
                continue;
            }
            "type_identifier" => {
                if let Some(name) = canonical_dart_type_name(node_text(&node, src)) {
                    // De-dup: a class can list the same name twice via
                    // mixins + implements clauses.
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}

#[cfg(test)]
mod read_synth_tests {
    use super::*;
    use bonsai_lang_api::kit::language_from_pack;

    fn property_reads(src: &str) -> Vec<Ref> {
        let language = language_from_pack(PACK_NAME).expect("dart grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set dart grammar");
        let tree = parser.parse(src.as_bytes(), None).expect("parse dart source");
        synthesize_dart_property_reads(&tree, src.as_bytes(), FileId::new(0))
    }

    #[test]
    fn qualified_parameter_type_alias_uses_terminal_type() {
        let src = "import 'package:http/http.dart' as http;\nString consume(http.Response response) => response.body;\n";
        let language = language_from_pack(PACK_NAME).expect("dart grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set dart grammar");
        let tree = parser.parse(src.as_bytes(), None).expect("parse dart source");
        let aliases = collect_dart_method_type_aliases(&tree, FileId::new(0), src.as_bytes());
        assert!(
            aliases.iter().any(|(_, aliases)| aliases
                .iter()
                .any(|alias| { alias.name == "response" && alias.type_name == "Response" })),
            "qualified parameter type must preserve its terminal nominal type; aliases={aliases:?}; tree={}",
            tree.root_node().to_sexp()
        );
    }

    #[test]
    fn allowlisted_property_read_emits_full_chain_read_ref() {
        let reads = property_reads("void f(Uri uri) {\n  var q = uri.queryParameters;\n}\n");
        assert!(
            reads
                .iter()
                .any(|r| r.name == "uri.queryParameters" && r.kind == RefKind::Read),
            "expected uri.queryParameters Read ref, got {reads:?}"
        );
    }

    #[test]
    fn literal_static_receiver_property_read_emits_read_ref() {
        let reads = property_reads("import 'dart:io';\nvoid f() {\n  var e = Platform.environment;\n}\n");
        assert!(
            reads
                .iter()
                .any(|r| r.name == "Platform.environment" && r.kind == RefKind::Read),
            "expected Platform.environment Read ref, got {reads:?}"
        );
    }

    #[test]
    fn ordinary_property_read_is_lowered_without_security_meaning() {
        let reads = property_reads("void f(Widget widget) {\n  var t = widget.title;\n}\n");
        assert!(
            reads
                .iter()
                .any(|r| r.name == "widget.title" && r.kind == RefKind::Read),
            "the adapter must emit generic property syntax and leave security meaning to rules: {reads:?}"
        );
    }

    #[test]
    fn expression_body_property_read_preserves_the_receiver_chain() {
        let reads = property_reads(
            "import 'package:http/http.dart' as http;\nString consume(http.Response response) => response.body;\n",
        );
        assert!(
            reads
                .iter()
                .any(|r| r.name == "response.body" && r.kind == RefKind::Read),
            "expression-bodied property reads must retain their exact receiver chain: {reads:?}"
        );
    }
}
