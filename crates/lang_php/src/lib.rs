//! PHP language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_from_tree_with_handler,
    extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, collect_kinds, collect_receiver_field_initializers,
        collect_receiver_field_writes, collect_receiver_state_sources, first_named_child_of_kind,
        language_from_pack, named_child_call_args_with_handler, node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, CallArg, CallKind, CallTargetExtraction,
    CompilerGuardFact, DeclIndex, DeclKind, FieldWrite, FlowEvent, FragmentParseContext, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModifierVocabulary, StaticScalarValue, StringCompositionFact, StringCompositionPart, TypeAliasBinding,
    TypeAliasVocabulary, Visibility, EMPTY_HANDLER,
};
use std::collections::{BTreeMap, BTreeSet};
fn php_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let (target, full_text) = match node.kind() {
        "function_call_expression" => {
            let target = node.child_by_field_name("function")?;
            (target, node_text(&target, src).trim().to_string())
        }
        "member_call_expression" | "nullsafe_member_call_expression" => {
            let receiver = node.child_by_field_name("object")?;
            let target = node.child_by_field_name("name")?;
            (
                target,
                format!(
                    "{}.{}",
                    node_text(&receiver, src).trim(),
                    node_text(&target, src).trim()
                ),
            )
        }
        "scoped_call_expression" => {
            let receiver = node.child_by_field_name("scope")?;
            let target = node.child_by_field_name("name")?;
            (
                target,
                format!(
                    "{}::{}",
                    node_text(&receiver, src).trim(),
                    node_text(&target, src).trim()
                ),
            )
        }
        "object_creation_expression" => {
            // The PHP grammar exposes the constructed qualified name as the
            // first named child rather than a `type` field.
            let target = node.child_by_field_name("type").or_else(|| node.named_child(0))?;
            (target, node_text(&target, src).trim().to_string())
        }
        _ => return None,
    };
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

const PHP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition", "method_declaration"],
    param_kinds: &["simple_parameter", "property_promotion_parameter"],
    name_field: "name",
    type_field: "type",
};

const PHP_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "method_declaration",
        "property_declaration",
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "enum_declaration",
    ],
    modifier_container_kinds: &["visibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("protected", Visibility::Protected),
        ("public", Visibility::Public),
    ],
    // PHP's default visibility for class members is `public`.
    default_visibility: Visibility::Public,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("php");
const PACK_NAME: &str = "php";

fn extract_php_callable_reference(node: Node<'_>, src: &[u8]) -> Option<String> {
    if !matches!(
        node.kind(),
        "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
    ) {
        return None;
    }
    let callee = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("target"))?;
    let arguments = node.child_by_field_name("arguments")?;
    if arguments.named_child_count() != 1 || arguments.named_child(0)?.kind() != "variadic_placeholder" {
        return None;
    }
    let name = node_text(&callee, src).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn php_subscript_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "subscript_expression" {
        return None;
    }
    // tree-sitter-php does not assign field names to either operand of a
    // subscript. Its grammar contract is the first named child as the base
    // and the second named child as the index. Keep the field lookups for
    // forward compatibility, then use that exact ordered shape.
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    let first = children.next()?;
    let second = children.next()?;
    let object = node.child_by_field_name("object").unwrap_or(first);
    let key = node.child_by_field_name("index").unwrap_or(second);
    Some((object, key))
}

fn php_static_subscript_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    if !matches!(node.kind(), "string" | "encapsed_string") {
        return None;
    }
    // A double-quoted PHP literal is represented as `encapsed_string` even
    // when it contains only a `string_content` child. Reject interpolation,
    // escape, and every other named child: only a compiler-proven static key
    // may become a field projection.
    if node.kind() == "encapsed_string" {
        let mut cursor = node.walk();
        if node
            .named_children(&mut cursor)
            .any(|child| child.kind() != "string_content")
        {
            return None;
        }
    }
    let text = node_text(&node, src).trim();
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || text.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let value = text.get(1..text.len().checked_sub(1)?)?;
    (!value.contains('\\')).then(|| value.to_string())
}

/// Decode scalar syntax owned by PHP into the language-neutral compiler fact.
///
/// PHP keywords are case-insensitive, while quoted strings are static only
/// when the same CST proof used for subscript keys rejects interpolation and
/// escapes. Integer/float spellings are intentionally not projected into
/// `StaticScalarValue`: the current wire type models only configuration
/// booleans, null, and exact strings.
fn php_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    let text = node_text(&node, src).trim();
    match node.kind() {
        "boolean" if text.eq_ignore_ascii_case("true") => Some(StaticScalarValue::Boolean(true)),
        "boolean" if text.eq_ignore_ascii_case("false") => Some(StaticScalarValue::Boolean(false)),
        "null" if text.eq_ignore_ascii_case("null") => Some(StaticScalarValue::Null),
        "string" | "encapsed_string" => Some(StaticScalarValue::String(php_static_subscript_key(node, src)?)),
        _ => None,
    }
}

/// Lower PHP's string-concatenation operator into complete ordered compiler
/// facts. Unsupported operands reject the entire expression; downstream
/// proofs never infer meaning from a partially lowered concatenation.
fn php_string_compositions(tree: &Tree, file: FileId, src: &[u8]) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        let Some(target) = php_exact_composition_place(target, src) else {
            continue;
        };
        let mut parts = Vec::new();
        if lower_php_string_composition(value, file, src, &mut parts) && parts.len() > 1 {
            facts.push(StringCompositionFact {
                container_span: span_of(file, &assignment),
                value_span: span_of(file, &value),
                target: Some(target),
                dynamic_anchor_span: None,
                parts,
            });
        }
    }
    // Call arguments and branch predicates are expression-owned rather than
    // assignments. Preserve every complete concatenation by its exact CST
    // span so consumers can join it to CallArgumentValueFact.
    for value in collect_kinds(tree, &["binary_expression"]) {
        let mut parts = Vec::new();
        if lower_php_string_composition(value, file, src, &mut parts) && parts.len() > 1 {
            let value_span = span_of(file, &value);
            facts.push(StringCompositionFact {
                container_span: value_span,
                value_span,
                target: None,
                dynamic_anchor_span: None,
                parts,
            });
        }
    }
    facts.sort_by_key(|fact| {
        (
            fact.container_span.start,
            fact.container_span.end,
            fact.value_span.start,
            fact.value_span.end,
        )
    });
    facts.dedup();
    facts
}

fn lower_php_string_composition(
    mut node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<StringCompositionPart>,
) -> bool {
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = node.named_child(0) else {
            return false;
        };
        node = inner;
    }
    if let Some(StaticScalarValue::String(value)) = php_static_scalar(node, src) {
        out.push(StringCompositionPart::Literal { value });
        return true;
    }
    if let Some(place) = php_exact_composition_place(node, src) {
        out.push(StringCompositionPart::Place { place });
        return true;
    }
    if matches!(
        node.kind(),
        "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
    ) {
        out.push(StringCompositionPart::Call {
            span: span_of(file, &node),
        });
        return true;
    }
    if node.kind() != "binary_expression" {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    operator == Some(".")
        && lower_php_string_composition(left, file, src, out)
        && lower_php_string_composition(right, file, src, out)
}

fn php_exact_composition_place(mut node: Node<'_>, src: &[u8]) -> Option<String> {
    while matches!(node.kind(), "parenthesized_expression" | "argument") {
        node = node.named_child(0)?;
    }
    match node.kind() {
        "variable_name" => php_reference_name(node, src),
        "class_constant_access_expression"
            if node
                .named_child(0)
                .is_some_and(|scope| scope.kind() == "relative_scope") =>
        {
            // `self::ROOT` / `static::ROOT` name one immutable binding in
            // the containing class. Keep the declaration spelling as the
            // compiler place so it joins the class-owned constant fact below;
            // a qualified external class constant retains its full spelling.
            let mut cursor = node.walk();
            let name = node.named_children(&mut cursor).last()?;
            let place = node_text(&name, src).trim();
            (!place.is_empty()).then(|| place.to_string())
        }
        "class_constant_access_expression" => {
            let raw = node_text(&node, src);
            let place = raw
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            (!place.is_empty()).then_some(place)
        }
        "member_access_expression" | "nullsafe_member_access_expression" => {
            let object = php_exact_composition_place(node.child_by_field_name("object")?, src)?;
            let name = node_text(&node.child_by_field_name("name")?, src).trim();
            (!name.is_empty()).then(|| format!("{object}.{name}"))
        }
        "subscript_expression" => {
            let (object, key) = php_subscript_parts(node)?;
            let object = php_exact_composition_place(object, src)?;
            let key = php_static_subscript_key(key, src)?;
            Some(format!("{object}.{key}"))
        }
        _ => None,
    }
}

/// Add exact immutable scalar facts for PHP `const` elements.
///
/// Tree-sitter represents class and namespace constants as `const_element`
/// rather than ordinary assignments, so the shared assignment extractor
/// cannot infer their value. This adapter-owned pass lowers only a complete
/// scalar initializer and records the containing class symbol when present.
fn augment_php_constant_values(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for element in collect_kinds(tree, &["const_element"]) {
        let Some(name) = element.named_child(0).filter(|child| child.kind() == "name") else {
            continue;
        };
        let mut cursor = element.walk();
        let Some(value) = element
            .named_children(&mut cursor)
            .last()
            .filter(|child| child.id() != name.id())
        else {
            continue;
        };
        let Some(static_value) = php_static_scalar(value, src) else {
            continue;
        };
        let target = node_text(&name, src).trim();
        if target.is_empty() {
            continue;
        }
        let assignment_span = span_of(file, &element);
        let target_owner = index
            .defs
            .iter()
            .filter(|decl| {
                is_class_like(decl.kind)
                    && decl.span.file == assignment_span.file
                    && decl.span.start <= assignment_span.start
                    && assignment_span.end <= decl.span.end
            })
            .min_by_key(|decl| decl.span.len())
            .map(|decl| decl.symbol);
        index
            .assignment_values
            .push(bonsai_lang_api::AssignmentValueFact {
                assignment_span,
                target: Some(target.to_string()),
                target_is_immutable: true,
                target_owner,
                target_span: Some(span_of(file, &name)),
                value_span: span_of(file, &value),
                call_sites: Vec::new(),
                value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                    value, file, src, &HANDLER,
                ),
                static_value: Some(static_value),
                exact_callable_return: None,
                inline_callback_static_return: None,
                inline_callback_fields: Vec::new(),
                exact_static_call_args: None,
                direct_call_name: None,
                direct_call_span: None,
                direct_call_receiver: None,
                direct_call_receiver_span: None,
                direct_call_receiver_flow: None,
            });
    }
    index.assignment_values.sort_by_key(|fact| {
        (
            fact.assignment_span.start,
            fact.assignment_span.end,
            fact.target.clone(),
        )
    });
    index.assignment_values.dedup();
}

const PHP_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST: &str = "terminal-predicate.compound-static-allowlist";

/// Lower a terminal compound predicate and the later calls it guards into
/// API-neutral compiler evidence. The adapter proves only parsed relations:
/// one call result is inspected through two static projections, one branch
/// rejects a non-equal static scalar or a negated call against a finite
/// static string collection, and a later call consumes the parser input.
/// Rule data assigns security meaning to every emitted call/component/value.
fn php_compound_static_allowlist_guards(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CompilerGuardFact> {
    let static_collections = php_static_string_collections(tree, src);
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition", "method_declaration"]) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let calls = collect_kinds_below(
            body,
            &[
                "function_call_expression",
                "member_call_expression",
                "nullsafe_member_call_expression",
                "scoped_call_expression",
            ],
        );
        for branch in collect_kinds_below(body, &["if_statement"]) {
            let (Some(condition), Some(consequence)) = (
                branch.child_by_field_name("condition"),
                branch.child_by_field_name("body"),
            ) else {
                continue;
            };
            if !php_compound_statement_is_terminal(consequence) {
                continue;
            }
            let Some(predicate) = php_compound_rejection_predicate(condition, src, &static_collections)
            else {
                continue;
            };
            let Some(parser_assignment) = collect_kinds_below(body, &["assignment_expression"])
                .into_iter()
                .filter(|assignment| assignment.end_byte() <= branch.start_byte())
                .filter_map(|assignment| php_parser_assignment(assignment, src))
                .filter(|assignment| assignment.output == predicate.parsed_place)
                .max_by_key(|assignment| assignment.start)
            else {
                continue;
            };
            for guarded_call in calls
                .iter()
                .copied()
                .filter(|call| call.start_byte() > branch.end_byte())
            {
                let guarded_args = php_direct_call_arguments(guarded_call);
                let guarded_relations = guarded_args
                    .iter()
                    .enumerate()
                    .filter(|(_, argument)| {
                        php_exact_composition_place(**argument, src).as_deref()
                            == Some(parser_assignment.input.as_str())
                    })
                    .map(|(index, _)| format!("guarded-argument:{index}=predicate-argument:0"))
                    .collect::<Vec<_>>();
                if guarded_relations.is_empty() {
                    continue;
                }
                let Some(target) = php_call_target(guarded_call, src) else {
                    continue;
                };
                let mut evidence = vec![
                    "predicate-complete:true".to_string(),
                    "finite-static-string-membership:true".to_string(),
                    format!("parser-call:{}", parser_assignment.call_name),
                    format!("scheme-component:{}", predicate.scheme_component),
                    format!("scheme-value:string:{}", predicate.scheme_value),
                    format!("membership-call:{}", predicate.membership_call),
                    format!("membership-component:{}", predicate.host_component),
                ];
                evidence.extend(predicate.membership_extra_evidence.clone());
                evidence.extend(guarded_relations);
                for related in calls
                    .iter()
                    .copied()
                    .filter(|call| call.start_byte() > branch.end_byte() && call.id() != guarded_call.id())
                {
                    let Some(related_target) = php_call_target(related, src) else {
                        continue;
                    };
                    for (index, argument) in php_direct_call_arguments(related).iter().enumerate() {
                        if let Some((guarded_index, _)) =
                            guarded_args.iter().enumerate().find(|(_, guarded)| {
                                let guarded = php_exact_composition_place(**guarded, src);
                                let related = php_exact_composition_place(*argument, src);
                                guarded.is_some() && guarded == related
                            })
                        {
                            evidence.push(format!(
                                "related-call:{}:argument:{index}=guarded-argument:{guarded_index}",
                                related_target.full_text
                            ));
                            continue;
                        }
                        if let Some(value) = php_compiler_evidence_operand(*argument, src) {
                            evidence.push(format!(
                                "related-call:{}:argument:{index}={value}",
                                related_target.full_text
                            ));
                        }
                    }
                }
                evidence.sort();
                evidence.dedup();
                facts.push(CompilerGuardFact {
                    function_span: span_of(file, &function),
                    guarded_call_span: span_of(file, &target.node),
                    proof_span: span_of(file, &branch),
                    capability: PHP_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST.to_string(),
                    evidence,
                });
            }
        }
    }
    facts.sort_by(|left, right| {
        (
            left.function_span.start,
            left.guarded_call_span.start,
            left.proof_span.start,
            &left.evidence,
        )
            .cmp(&(
                right.function_span.start,
                right.guarded_call_span.start,
                right.proof_span.start,
                &right.evidence,
            ))
    });
    facts.dedup();
    facts
}

#[derive(Clone)]
struct PhpParserAssignment {
    start: usize,
    output: String,
    input: String,
    call_name: String,
}

#[derive(Clone)]
struct PhpCompoundPredicate {
    parsed_place: String,
    scheme_component: String,
    scheme_value: String,
    membership_call: String,
    host_component: String,
    membership_extra_evidence: Vec<String>,
}

fn php_parser_assignment(assignment: Node<'_>, src: &[u8]) -> Option<PhpParserAssignment> {
    let output = php_exact_composition_place(assignment.child_by_field_name("left")?, src)?;
    let call = assignment.child_by_field_name("right")?;
    let target = php_call_target(call, src)?;
    let arguments = php_direct_call_arguments(call);
    let [argument] = arguments.as_slice() else {
        return None;
    };
    Some(PhpParserAssignment {
        start: assignment.start_byte(),
        output,
        input: php_exact_composition_place(*argument, src)?,
        call_name: target.full_text,
    })
}

fn php_compound_rejection_predicate(
    mut condition: Node<'_>,
    src: &[u8],
    static_collections: &std::collections::HashMap<String, Vec<String>>,
) -> Option<PhpCompoundPredicate> {
    while condition.kind() == "parenthesized_expression" {
        condition = condition.named_child(0)?;
    }
    let (left, right) = (
        condition.child_by_field_name("left")?,
        condition.child_by_field_name("right")?,
    );
    if php_binary_operator(condition, left, right, src)? != "||" {
        return None;
    }
    let scheme_projection = collect_kinds_below(left, &["subscript_expression"])
        .into_iter()
        .find_map(|subscript| php_projection_parts(subscript, src));
    let (parsed_place, scheme_component) = scheme_projection?;
    let scheme_value = collect_kinds_below(left, &["string", "encapsed_string"])
        .into_iter()
        .filter_map(|literal| php_static_subscript_key(literal, src))
        .find(|value| !value.is_empty() && value != &scheme_component)?;

    if right.kind() != "unary_op_expression" {
        return None;
    }
    let mut operand = right.named_child(0)?;
    let operator = src
        .get(right.start_byte()..operand.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    if operator != Some("!") {
        return None;
    }
    while operand.kind() == "parenthesized_expression" {
        operand = operand.named_child(0)?;
    }
    if operand.kind() != "function_call_expression" {
        return None;
    }
    let membership_target = php_call_target(operand, src)?;
    let membership_args = php_direct_call_arguments(operand);
    if membership_args.len() < 2 {
        return None;
    }
    let (membership_base, host_component) =
        collect_kinds_below(membership_args[0], &["subscript_expression"])
            .into_iter()
            .find_map(|subscript| php_projection_parts(subscript, src))?;
    if membership_base != parsed_place {
        return None;
    }
    let collection = php_exact_composition_place(membership_args[1], src)?;
    let collection = collection.rsplit("::").next().unwrap_or(&collection);
    if !static_collections.contains_key(collection) {
        return None;
    }
    let mut membership_extra_evidence = Vec::new();
    for (index, argument) in membership_args.iter().enumerate().skip(2) {
        if let Some(value) = php_compiler_evidence_operand(*argument, src) {
            membership_extra_evidence.push(format!("membership-argument:{index}={value}"));
        }
    }
    Some(PhpCompoundPredicate {
        parsed_place,
        scheme_component,
        scheme_value,
        membership_call: membership_target.full_text,
        host_component,
        membership_extra_evidence,
    })
}

fn php_static_string_collections(tree: &Tree, src: &[u8]) -> std::collections::HashMap<String, Vec<String>> {
    let mut collections = std::collections::HashMap::new();
    for element in collect_kinds(tree, &["const_element"]) {
        let Some(name) = element.named_child(0).filter(|node| node.kind() == "name") else {
            continue;
        };
        let mut cursor = element.walk();
        let Some(array) = element
            .named_children(&mut cursor)
            .find(|node| node.kind() == "array_creation_expression")
        else {
            continue;
        };
        let mut values = Vec::new();
        let mut array_cursor = array.walk();
        let mut complete = true;
        for item in array.named_children(&mut array_cursor) {
            let Some(value_node) = item.named_child(0) else {
                complete = false;
                break;
            };
            let Some(value) = php_static_subscript_key(value_node, src) else {
                complete = false;
                break;
            };
            values.push(value);
        }
        if complete && !values.is_empty() {
            collections.insert(node_text(&name, src).trim().to_string(), values);
        }
    }
    collections
}

fn php_projection_parts(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    let (base, key) = php_subscript_parts(node)?;
    Some((
        php_exact_composition_place(base, src)?,
        php_static_subscript_key(key, src)?,
    ))
}

fn php_compound_statement_is_terminal(statement: Node<'_>) -> bool {
    if statement.kind() == "return_statement" || statement.kind() == "throw_expression" {
        return true;
    }
    if statement.kind() != "compound_statement" {
        return false;
    }
    let mut cursor = statement.walk();
    let mut children = statement
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment");
    matches!(
        children.next().map(|child| child.kind()),
        Some("return_statement" | "throw_expression")
    ) && children.next().is_none()
}

fn php_direct_call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter_map(|argument| {
            (argument.kind() == "argument")
                .then(|| argument.named_child(0))
                .flatten()
                .or_else(|| (argument.kind() != "argument").then_some(argument))
        })
        .collect()
}

fn php_binary_operator<'a>(
    _node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    src: &'a [u8],
) -> Option<&'a str> {
    src.get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim)
}

fn php_compiler_evidence_operand(node: Node<'_>, src: &[u8]) -> Option<String> {
    match php_static_scalar(node, src) {
        Some(StaticScalarValue::String(value)) => Some(format!("string:{value}")),
        Some(StaticScalarValue::Boolean(value)) => Some(format!("boolean:{value}")),
        Some(StaticScalarValue::Null) => Some("null".to_string()),
        Some(StaticScalarValue::Integer(value)) => Some(format!("number:{value}")),
        None => php_exact_composition_place(node, src)
            .or_else(|| {
                matches!(node.kind(), "name" | "qualified_name")
                    .then(|| node_text(&node, src).trim().to_string())
            })
            .filter(|value| !value.is_empty())
            .map(|value| format!("place:{value}")),
    }
}

fn collect_kinds_below<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut result = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.id() != node.id() && kinds.contains(&current.kind()) {
            result.push(current);
        }
        let mut cursor = current.walk();
        let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    result
}

fn php_reference_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    // `$` is part of a PHP variable's language identity and distinguishes a
    // runtime value from a class/function name. Preserve it in every place
    // fact; generic name comparison already understands adapter-owned sigils.
    (!raw.is_empty()).then(|| raw.to_string())
}

fn php_binding_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let binding = raw.strip_prefix('$').unwrap_or(raw);
    (!binding.is_empty()).then(|| binding.to_string())
}

/// PHP's append assignment (`$items[] = $value`) is represented by a
/// `subscript_expression` with no index child.  The append mutates the whole
/// aggregate value, so its compiler place is the parsed base expression.  A
/// normal keyed subscript continues through the shared field-sensitive place
/// lowering.
fn php_assignment_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "subscript_expression" || node.named_child_count() != 1 {
        return None;
    }
    let base = node.named_child(0)?;
    if base.kind() == "variable_name" {
        return php_reference_name(base, src);
    }
    None
}

fn php_aggregate_pairs(node: Node<'_>) -> Vec<(Node<'_>, Node<'_>)> {
    if node.kind() != "list_literal" {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    let mut pending_key = None;
    let mut saw_pair_operator = false;
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.is_named() {
                if saw_pair_operator {
                    if let Some(key) = pending_key.take() {
                        pairs.push((key, child));
                    }
                    saw_pair_operator = false;
                } else {
                    pending_key = Some(child);
                }
            } else if child.kind() == "=>" {
                saw_pair_operator = true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    pairs
}

fn php_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "foreach_statement" {
        return None;
    }
    let body_id = node.child_by_field_name("body").map(|body| body.id());
    let mut cursor = node.walk();
    let mut header = node
        .named_children(&mut cursor)
        .filter(|child| Some(child.id()) != body_id);
    let iterable = header.next()?;
    let binding = header.next()?;
    Some((binding, iterable))
}
const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &["null", "boolean", "integer", "float"],
    string_literal_kinds: &["string", "encapsed_string", "heredoc", "nowdoc_string"],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["formal_parameters"],
    parameter_kinds: &[
        "simple_parameter",
        "variadic_parameter",
        "property_promotion_parameter",
    ],
    parameter_modifier_kinds: &["attribute_list"],
    parameter_annotation_kinds: &["attribute"],
    variadic_parameter_kinds: &["variadic_parameter"],
    binding_identifier_kinds: &["variable_name", "name"],
    non_binding_pattern_field_names: &["type"],
    binding_name_extractor: Some(php_binding_name),
    identifier_kinds: &["variable_name", "name"],
    aggregate_pattern_kinds: &["list_literal", "array_creation_expression"],
    named_aggregate_kinds: &["array_creation_expression"],
    positional_aggregate_kinds: &["array", "list", "list_literal", "array_creation_expression"],
    two_child_aggregate_pair_kinds: &["array_element_initializer"],
    aggregate_pair_extractor: Some(php_aggregate_pairs),
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["name"],
    lambda_value_container_kinds: &["array_creation_expression", "array_element_initializer"],
    transparent_call_wrapper_kinds: &[
        "member_access_expression",
        "scoped_call_expression",
        "parenthesized_expression",
    ],
    assignment_target_wrapper_kinds: &["property_element"],
    assignment_place_extractor: Some(php_assignment_place),
    binding_declaration_keyword_spellings: &["static"],
    fn_kinds: &["function_definition", "method_declaration"],
    call_kinds: &[
        "function_call_expression",
        "member_call_expression",
        "nullsafe_member_call_expression",
        "scoped_call_expression",
        "object_creation_expression",
    ],
    constructor_call_kinds: &["object_creation_expression"],
    call_callee_field_names: &["function"],
    call_receiver_field_names: &["object", "scope"],
    call_member_field_names: &["name"],
    constructor_type_field_names: &["type"],
    call_target_extractor: Some(php_call_target),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["arguments"],
    // tree-sitter-php wraps both positional and named arguments in `argument`;
    // the optional `name` field distinguishes the latter. Unwrap that exact
    // grammar node so an addressable `$value` remains an exact CallArg place.
    argument_wrapper_kinds: &["argument"],
    argument_name_field_names: &["name"],
    argument_value_field_names: &["value"],
    lambda_body_field_names: &["body"],
    pseudo_call_extractor: Some(extract_php_pseudo_call),
    syntax_event_extractor: None,
    argument_passing_mode_extractor: None,
    call_ref_kinds: &[
        "function_call_expression",
        "member_call_expression",
        "nullsafe_member_call_expression",
        "scoped_call_expression",
        "object_creation_expression",
    ],
    member_expression_kinds: &["member_access_expression", "nullsafe_member_access_expression"],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["object"],
    member_name_field_names: &["name"],
    subscript_base_field_names: &["object"],
    subscript_index_field_names: &[],
    static_subscript_key_extractor: Some(php_static_subscript_key),
    computed_subscript_extractor: Some(php_subscript_parts),
    sigil_variable_kinds: &["variable_name"],
    reference_name_extractor: Some(php_reference_name),
    callable_reference_extractor: Some(extract_php_callable_reference),
    constructor_names: &["__construct"],
    runtime_type_guard_operators: &["instanceof"],
    runtime_type_wrapper_kinds: &["parenthesized_expression"],
    class_kinds: &[
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "enum_declaration",
    ],
    class_decl_kinds: &[
        ("class_declaration", DeclKind::Class),
        ("interface_declaration", DeclKind::Interface),
        ("trait_declaration", DeclKind::Trait),
        ("enum_declaration", DeclKind::Enum),
    ],
    method_kinds: &["method_declaration"],
    method_context_kinds: &[
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "enum_declaration",
    ],
    if_kinds: &[
        "if_statement",
        "conditional_expression",
        "switch_statement",
        "match_expression",
    ],
    branch_then_field_names: &["body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&", "and"],
    condition_any_operators: &["||", "or"],
    condition_not_operators: &["!"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["compound_statement", "expression_statement"],
    loop_update_field_names: &["update"],
    branch_arm_kinds: &["compound_statement", "else_clause", "else_if_clause"],
    exclusive_branch_arm_kinds: &["case_statement", "default_statement"],
    fallthrough_branch_arm_kinds: &["case_statement", "default_statement"],
    additional_alternative_kinds: &["else_clause", "else_if_clause"],
    for_kinds: &["for_statement"],
    foreach_kinds: &["foreach_statement"],
    foreach_binding_extractor: Some(php_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    assignment_kinds: &[
        "assignment_expression",
        "augmented_assignment_expression",
        "reference_assignment_expression",
        "property_declaration",
    ],
    compound_assignment_kinds: &["augmented_assignment_expression"],
    compound_assignment_operators: &[
        "+=", "-=", "*=", "/=", "%=", "**=", ".=", "<<=", ">>=", "&=", "^=", "|=", "??=",
    ],
    type_only_declaration_kinds: &["property_declaration"],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_expression"],
    lambda_kinds: &["anonymous_function", "arrow_function"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    exclusive_catch_arm_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    yield_kinds: &["yield_expression"],
    yield_value_field_names: &["value"],
    try_body_field_names: &["body"],
    implicit_receiver_names: &["$this", "this"],
    ..EMPTY_HANDLER
};

/// PHP-specific compiler passes consume these node kinds outside the shared
/// grammar-handler walker. Conformance checks each spelling against the
/// adapter's actual Tree-sitter grammar.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("type alias declaration", "function_definition"),
    ("type alias declaration", "method_declaration"),
    ("type alias parameter", "simple_parameter"),
    ("type alias parameter", "property_promotion_parameter"),
    ("visibility declaration", "property_declaration"),
    ("visibility declaration", "class_declaration"),
    ("visibility declaration", "interface_declaration"),
    ("visibility declaration", "trait_declaration"),
    ("visibility declaration", "enum_declaration"),
    ("visibility modifier", "visibility_modifier"),
    ("call target", "function_call_expression"),
    ("call target", "member_call_expression"),
    ("call target", "nullsafe_member_call_expression"),
    ("call target", "scoped_call_expression"),
    ("call target", "object_creation_expression"),
    ("callable reference", "variadic_placeholder"),
    ("subscript expression", "subscript_expression"),
    ("static subscript key", "string"),
    ("static subscript key", "encapsed_string"),
    ("static subscript content", "string_content"),
    ("assignment base", "variable_name"),
    ("string composition assignment", "assignment_expression"),
    ("string composition operator", "binary_expression"),
    ("constant declaration", "const_declaration"),
    ("constant element", "const_element"),
    (
        "string composition class constant",
        "class_constant_access_expression",
    ),
    ("string composition member", "member_access_expression"),
    ("string composition parenthesis", "parenthesized_expression"),
    ("aggregate pair", "list_literal"),
    ("aggregate pair operator", "=>"),
    ("foreach binding", "foreach_statement"),
    ("pseudo call", "echo_statement"),
    ("pseudo call", "unset_statement"),
    ("namespace import", "namespace_use_clause"),
    ("namespace import group", "namespace_use_group"),
    ("namespace import prefix", "namespace_name"),
    ("namespace import prefix", "qualified_name"),
    ("include construct", "include_expression"),
    ("include construct", "include_once_expression"),
    ("include construct", "require_expression"),
    ("include construct", "require_once_expression"),
    ("shell construct", "shell_command_expression"),
    ("shell interpolation", "member_access_expression"),
    ("promoted property name", "name"),
    ("class base", "base_clause"),
    ("class interface", "class_interface_clause"),
    ("namespace declaration", "namespace_definition"),
];

fn extract_php_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    let name = match node.kind() {
        "echo_statement" => "echo",
        "unset_statement" => "unset",
        _ => return None,
    };
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: None,
        receiver_types: Vec::new(),
        name: name.to_string(),
        call_kind: CallKind::Function,
        args: named_child_call_args_with_handler(&node, file, src, handler),
    })
}

/// Tree-sitter adapter for PHP.
#[derive(Debug, Default, Copy, Clone)]
pub struct PhpAdapter;

impl PhpAdapter {
    /// Construct a fresh adapter; the type carries no state.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for PhpAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "PHP"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["php"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn fragment_parse_context(&self) -> FragmentParseContext {
        // The PHP grammar starts in HTML host mode and enters PHP only after
        // this grammar token. Central renderers must not know that syntax.
        FragmentParseContext {
            prefix: "<?php\n",
            suffix: "",
        }
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["mixed", "object"],
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                rooted_prefixes: &["\\"],
                repeatable_rooted_prefixes: &[],
            },
            constructor_method_names: &["__construct"],
            super_receiver_tokens: &["parent"],
            // PHP distinguishes the current object (`$this`) from current-
            // class dispatch (`self` / late-bound `static`). None denotes a
            // parent type; that role belongs exclusively to `parent` above.
            implicit_receiver_tokens: &["$this", "self", "static"],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &[],
                class_object_suffixes: &["::class"],
            },
            quoted_callable_literals: true,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        ADDITIONAL_GRAMMAR_NODE_KINDS
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        let source = snapshot.text.to_string();
        let src = source.as_bytes();
        let mut idx = decl_index_from_tree_with_handler(file, src, &tree, &HANDLER);
        idx.string_compositions = php_string_compositions(&tree, file, src);
        idx.compiler_guards
            .extend(php_compound_static_allowlist_guards(&tree, file, src));
        idx.compiler_guards.sort_by(|left, right| {
            (
                left.function_span.start,
                left.guarded_call_span.start,
                left.proof_span.start,
                &left.capability,
                &left.evidence,
            )
                .cmp(&(
                    right.function_span.start,
                    right.guarded_call_span.start,
                    right.proof_span.start,
                    &right.capability,
                    &right.evidence,
                ))
        });
        idx.compiler_guards.dedup();
        // Synthesize Call FlowEvents for PHP language constructs the
        // tree-sitter grammar exposes as dedicated expression kinds
        // rather than call_expression nodes:
        //   - `include $tainted` / `include_once $tainted`
        //   - `require $tainted` / `require_once $tainted`
        //   - `` `cmd $tainted` `` (shell_command_expression)
        // The emitted callable spelling is the exact language construct;
        // rule data, not this adapter, assigns security meaning.
        let synthesized = synthesize_php_construct_events(&tree, src, file);
        if !synthesized.is_empty() {
            attach_synthesized_calls_to_decls(&mut idx, synthesized);
        }
        // Use the `namespace Foo\Bar;` segments as the module path so
        // private symbols cross-link only inside the namespace.
        let namespace_segments = extract_php_namespace(tree.root_node(), src);
        if let Some(segments) = namespace_segments {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            // No `namespace` declaration — fall back to file-stem.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        augment_php_constant_values(&mut idx, &tree, file, src);
        {
            let visibility_by_span = collect_modifier_visibility(tree.root_node(), file, src, &PHP_VOCAB);
            let mut aliases_by_span = collect_param_type_aliases(&tree, file, src, &PHP_TYPE_ALIASES);
            // Parameter type hints use the locally imported alias (`Request
            // $request`), while rule constraints intentionally name the
            // declared interface (`ServerRequestInterface`). Preserve the
            // source spelling and add the compiler-resolved import target so
            // receiver typing remains exact even when `use ... as ...`
            // chooses an arbitrary local alias.
            let import_specs = parse_imports(&tree, src, file);
            for aliases in aliases_by_span.values_mut() {
                let mut expanded = Vec::new();
                for alias in aliases.iter() {
                    for import in &import_specs {
                        if import.alias.as_deref() == Some(alias.type_name.as_str())
                            && import.module != alias.type_name
                        {
                            expanded.push(TypeAliasBinding {
                                name: alias.name.clone(),
                                type_name: import.module.clone(),
                            });
                        }
                    }
                }
                for alias in expanded {
                    if !aliases.contains(&alias) {
                        aliases.push(alias);
                    }
                }
            }
            for decl in &mut idx.defs {
                if let Some(visibility) = visibility_by_span.get(&decl.span).copied() {
                    decl.visibility = visibility;
                }
                if let Some(aliases) = aliases_by_span.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
            }
            // Per-class `bases`: `class Echo extends Base implements I, J`
            // → ["Base", "I", "J"]. PHP exposes them as separate
            // `base_clause` (single) and `class_interface_clause`
            // (one or more) children of the class node.
            let bases_by_span = collect_php_class_bases(&tree, file, src);
            for decl in &mut idx.defs {
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
            }
            let promoted_writes_by_span = collect_php_property_promotion_writes(&tree, file, src);
            for decl in &mut idx.defs {
                if !matches!(decl.kind, DeclKind::Constructor) {
                    continue;
                }
                let Some(promotions) = promoted_writes_by_span
                    .iter()
                    .find_map(|(span, promotions)| (*span == decl.span).then_some(promotions))
                else {
                    continue;
                };
                for promotion in promotions {
                    let Some(param_idx) = decl.params.iter().position(|param| {
                        php_param_matches_promoted_property(
                            param,
                            &promotion.param_name,
                            &promotion.field_name,
                        )
                    }) else {
                        continue;
                    };
                    decl.receiver_field_writes.push(FieldWrite {
                        span: promotion.span,
                        target: format!("this.{}", promotion.field_name),
                        source_param_indices: vec![param_idx],
                    });
                    // Constructor property promotion is a declaration-level
                    // direct field binding even though PHP has no assignment
                    // statement in the body. Materialize the exact receiver
                    // field type here so the shared class-field propagation
                    // can type `$this->field` calls in sibling methods.
                    if let Some(type_name) = decl.type_aliases.iter().find_map(|alias| {
                        (alias.name.trim_start_matches('$') == decl.params[param_idx].trim_start_matches('$'))
                            .then(|| alias.type_name.clone())
                    }) {
                        let field_alias = TypeAliasBinding {
                            name: format!("this.{}", promotion.field_name),
                            type_name,
                        };
                        if !decl.type_aliases.contains(&field_alias) {
                            decl.type_aliases.push(field_alias);
                        }
                    }
                }
                decl.receiver_field_writes.sort_by_key(|write| {
                    (
                        write.span.start,
                        write.target.clone(),
                        write.source_param_indices.clone(),
                    )
                });
                decl.receiver_field_writes.dedup();
            }
        }
        bonsai_lang_api::kit::populate_call_argument_static_values(
            &mut idx,
            &tree,
            file,
            src,
            &HANDLER,
            php_static_scalar,
        );
        let callable_literals = idx
            .assignment_values
            .iter()
            .filter_map(|fact| match fact.static_value.as_ref() {
                Some(StaticScalarValue::String(value)) => {
                    php_bare_callable_name(value).map(|name| (fact.assignment_span, name.to_string()))
                }
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        for decl in &mut idx.defs {
            let invoked_variables = php_invoked_variables(&decl.flow_events);
            augment_php_quoted_callable_literals(
                &mut decl.flow_events,
                &callable_literals,
                &invoked_variables,
            );
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            decl.receiver_field_writes.extend(collect_receiver_field_writes(
                &decl.flow_events,
                &decl.params,
                None,
                &["$this", "this"],
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
                collect_receiver_field_initializers(&decl.flow_events, &["$this", "this"]);
            decl.receiver_state_sources =
                collect_receiver_state_sources(&decl.flow_events, &decl.params, &["$this", "this"]);
        }
        bonsai_lang_api::kit::populate_assignment_inline_callback_static_returns(
            &mut idx,
            &tree,
            src,
            &HANDLER,
            php_static_scalar,
        );
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing
        // (`$x = new Foo()` → `$x: Foo`) so `$x->method(...)` carries a
        // resolved receiver type for `receiver_type_in` / `[Type, method]`
        // rules. The constructor identity comes from the adapter-lowered
        // object-creation node, never from identifier casing.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        let capabilities = self.capabilities();
        bonsai_lang_api::apply_call_receiver_types_with_language_syntax(
            &mut idx,
            capabilities.super_receiver_tokens,
            capabilities.implicit_receiver_tokens,
            capabilities.constructor_method_names,
            capabilities.receiver_type_syntax,
        );
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// PHP permits a string literal containing a function name to be invoked as a
/// runtime callable (`$cb = 'helper'; $cb($value)`). The assignment and its
/// RHS span are selected by Tree-sitter before this adapter hook runs; this
/// step decodes only that literal value. Expression structure and value
/// carriers remain exclusively compiler-owned [`FlowEvent`] facts.
fn augment_php_quoted_callable_literals(
    events: &mut [FlowEvent],
    callable_literals: &BTreeMap<Span, String>,
    invoked_variables: &BTreeSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                span,
                source_name,
                value_kind,
                ..
            } => {
                if matches!(value_kind, Some(AssignValueKind::Destructure)) {
                    continue;
                }
                if invoked_variables.contains(target) {
                    if let Some(callable) = target
                        .trim_start()
                        .starts_with('$')
                        .then(|| callable_literals.get(span))
                        .flatten()
                    {
                        *source_name = Some(callable.clone());
                        *value_kind = Some(AssignValueKind::CallableReference);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_php_quoted_callable_literals(then_events, callable_literals, invoked_variables);
                augment_php_quoted_callable_literals(else_events, callable_literals, invoked_variables);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_php_quoted_callable_literals(body, callable_literals, invoked_variables);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_php_quoted_callable_literals(body, callable_literals, invoked_variables);
                augment_php_quoted_callable_literals(catch_events, callable_literals, invoked_variables);
                augment_php_quoted_callable_literals(finally_events, callable_literals, invoked_variables);
            }
            _ => {}
        }
    }
}

/// Return variables that the parsed PHP function actually invokes as
/// callables. A quoted string is a normal literal unless the CST-derived call
/// event proves that the assigned variable is used in callable position.
fn php_invoked_variables(events: &[FlowEvent]) -> BTreeSet<String> {
    let mut invoked = BTreeSet::new();
    bonsai_lang_api::for_each_flow_event(events, &mut |event| {
        if let FlowEvent::Call {
            name,
            call_kind: CallKind::Function | CallKind::Indirect,
            ..
        } = event
        {
            if name.starts_with('$') {
                invoked.insert(name.clone());
            }
        }
    });
    invoked
}

fn php_bare_callable_name(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty()
        || value
            .chars()
            .any(|ch| !(ch == '_' || ch == '\\' || ch.is_ascii_alphanumeric()))
        || value.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    Some(value)
}

/// Parse PHP `use`/`require`/`include` statements into `ImportSpec`s.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Two PHP import shapes:
    //   1. `use X\Y;` / `use X\Y as Z;` / `use X\{A, B};`
    //      → only `namespace_use_clause`. The outer
    //        `namespace_use_declaration` wraps one or more clauses,
    //        so collecting both kinds emits each import twice.
    //   2. `require '...';` / `require_once '...';` / `include '...';`
    //      → dedicated expression nodes (NOT call expressions)
    for clause in collect_kinds(tree, &["namespace_use_clause"]) {
        let alias_node = clause.child_by_field_name("alias");
        let mut clause_cursor = clause.walk();
        let Some(module_node) = clause.named_children(&mut clause_cursor).find(|child| {
            alias_node.is_none_or(|alias| child.id() != alias.id())
                && matches!(child.kind(), "name" | "namespace_name" | "qualified_name")
        }) else {
            continue;
        };
        let module_text = node_text(&module_node, src).trim().to_string();
        let explicit_alias = alias_node.map(|alias| node_text(&alias, src).trim().to_string());
        // Grouped import `use Foo\{A, B as BB};` lowers each member
        // to a `namespace_use_clause` whose text is just `A` / `B as
        // BB` — the `Foo\` prefix lives on the outer
        // `namespace_use_group`'s namespace child. Walk up and
        // prepend so resolve sees the fully-qualified module path.
        let qualified_module = match group_namespace_prefix(&clause, src) {
            Some(prefix) if !module_text.starts_with(&prefix) => format!("{prefix}\\{module_text}"),
            _ => module_text,
        };
        // PHP `use App\Middle;` binds `Middle` even without an explicit
        // `as` clause. This is grammar semantics, so emit the binding here
        // instead of asking the language-neutral resolver to infer a basename
        // from every path-like import.
        let alias = explicit_alias.or_else(|| canonical_php_base_name(&qualified_module));
        imports.push(ImportSpec {
            span: span_of(file, &clause),
            module: qualified_module,
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    for node in collect_kinds(
        tree,
        &[
            "require_expression",
            "require_once_expression",
            "include_expression",
            "include_once_expression",
        ],
    ) {
        // The argument can be a bare string or a binary expression like
        // `__DIR__ . '/foo.php'`. Surface the FIRST string descendant —
        // that matches what the user would query against.
        let module = first_string_descendant(&node, src);
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &node),
            module,
            alias: None,
            is_wildcard: true,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// For a `namespace_use_clause` nested inside `use Foo\{A, B};`,
/// return the `Foo` prefix carried by the enclosing
/// `namespace_use_group`'s namespace child. Returns `None` for
/// non-grouped `use Foo\Bar;` clauses.
fn group_namespace_prefix(clause: &tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut ancestor = clause.parent();
    while let Some(parent) = ancestor {
        if parent.kind() == "namespace_use_group" {
            // tree-sitter-php doesn't expose the prefix as a named
            // field on the enclosing `namespace_use_declaration`;
            // walk the outer declaration's named children up to the
            // group node and pick the last `namespace_name` /
            // `qualified_name` we see (handles multi-segment
            // prefixes like `Foo\Bar\{A, B}`).
            let outer = parent.parent()?;
            let mut outer_cursor = outer.walk();
            let mut last_prefix: Option<String> = None;
            for child in outer.named_children(&mut outer_cursor) {
                // Stop scanning once we reach the group itself —
                // anything past it is a member, not a prefix.
                if child.id() == parent.id() {
                    break;
                }
                if matches!(child.kind(), "namespace_name" | "qualified_name") {
                    let text = node_text(&child, src).trim().to_string();
                    if !text.is_empty() {
                        last_prefix = Some(text);
                    }
                }
            }
            return last_prefix;
        }
        ancestor = parent.parent();
    }
    None
}

/// Return the source text of the first `string` literal descendant
/// (without quotes) under `node`, or an empty string if none.
fn first_string_descendant(node: &tree_sitter::Node<'_>, src: &[u8]) -> String {
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "string" {
            if let Some(content) = first_named_child_of_kind(&current, "string_content") {
                return node_text(&content, src).to_string();
            }
            return php_static_subscript_key(current, src).unwrap_or_default();
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    String::new()
}

/// Synthesize Call FlowEvents for PHP language constructs that
/// tree-sitter exposes as dedicated expression kinds.
///
/// Mappings:
///   - include_expression           → name = "include"
///   - include_once_expression      → name = "include_once"
///   - require_expression           → name = "require"
///   - require_once_expression      → name = "require_once"
///   - shell_command_expression     → name = "`"
///
/// The expression's argument (the included path / shell command) becomes one
/// positional `CallArg`. Its `place` and `source_names` come from the exact
/// argument node and carry dataflow; `value_text` is rendering-only.
fn synthesize_php_construct_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    // Pairs of (grammar kind, exact PHP construct spelling).
    const CONSTRUCT_KINDS: &[(&str, &str)] = &[
        ("include_expression", "include"),
        ("include_once_expression", "include_once"),
        ("require_expression", "require"),
        ("require_once_expression", "require_once"),
        ("shell_command_expression", "`"),
    ];
    let mut synthesized = Vec::new();
    for (kind, callee) in CONSTRUCT_KINDS {
        for node in collect_kinds(tree, &[*kind]) {
            let span = span_of(file, &node);
            let mut args: Vec<CallArg> = Vec::new();
            // For include/require the first non-keyword child is the
            // argument expression; for shell_command_expression the
            // interpolated scalars / identifiers inside become args.
            if *kind == "shell_command_expression" {
                let mut cursor = node.walk();
                let mut stack: Vec<tree_sitter::Node<'_>> = Vec::new();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
                while let Some(current) = stack.pop() {
                    // Only nodes that can carry user data become args;
                    // literal text inside the backticks is ignored.
                    if matches!(
                        current.kind(),
                        "variable_name" | "subscript_expression" | "member_access_expression"
                    ) {
                        if let Some(argument) =
                            call_arg_from_node_with_handler(current, file, src, None, &HANDLER)
                        {
                            args.push(argument);
                        }
                        continue;
                    }
                    let mut child_cursor = current.walk();
                    for child in current.named_children(&mut child_cursor) {
                        stack.push(child);
                    }
                }
            } else {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if let Some(argument) = call_arg_from_node_with_handler(child, file, src, None, &HANDLER)
                    {
                        args.push(argument);
                        // include/require has exactly one argument.
                        break;
                    }
                }
            }
            let event = FlowEvent::Call {
                span,
                name: (*callee).to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            };
            synthesized.push((span, event));
        }
    }
    synthesized
}

/// Assign each synthesized call event to the smallest decl whose body
/// contains the event span.
fn attach_synthesized_calls_to_decls(idx: &mut DeclIndex, events: Vec<(Span, FlowEvent)>) {
    // PHP allows nested `function inner()` inside another function
    // body. tree-sitter-php parses both as `function_definition`, so
    // pre-order extraction yields [outer, inner]. Picking the FIRST
    // containing decl would route the synthesized event (require /
    // include / backtick) to `outer`, hiding it from `inner`'s
    // intra-taint pass. Pick the smallest containing decl instead.
    for (event_span, event) in events {
        let mut best_decl: Option<usize> = None;
        let mut best_body_len: u64 = u64::MAX;
        for (decl_idx, decl) in idx.defs.iter().enumerate() {
            let body = decl.body_span.unwrap_or(decl.span);
            if event_span.file == body.file && event_span.start >= body.start && event_span.end <= body.end {
                let body_len = body.end.saturating_sub(body.start);
                if body_len < best_body_len {
                    best_decl = Some(decl_idx);
                    best_body_len = body_len;
                }
            }
        }
        if let Some(decl_idx) = best_decl {
            idx.defs[decl_idx].flow_events.push(event);
        }
    }
}

/// True for decl kinds that can declare an `extends`/`implements`
/// list — used to gate which decls receive `bases` entries.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

#[derive(Clone, Debug)]
struct PhpPromotedPropertyWrite {
    span: Span,
    param_name: String,
    field_name: String,
}

fn collect_php_property_promotion_writes(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<PhpPromotedPropertyWrite>)> {
    let mut out = Vec::new();
    for method_node in collect_kinds(tree, &["method_declaration"]) {
        let Some(name_node) = method_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&method_node, "name"))
        else {
            continue;
        };
        if node_text(&name_node, src).trim() != "__construct" {
            continue;
        }
        let mut promotions = Vec::new();
        collect_php_property_promotion_writes_inner(method_node, file, src, &mut promotions);
        if !promotions.is_empty() {
            out.push((span_of(file, &method_node), promotions));
        }
    }
    out
}

fn collect_php_property_promotion_writes_inner(
    node: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<PhpPromotedPropertyWrite>,
) {
    if node.kind() == "property_promotion_parameter" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let param_name = node_text(&name_node, src).trim().to_string();
            let field_name = php_promoted_property_field_name(&name_node, src)
                .unwrap_or_else(|| param_name.trim_start_matches('$').to_string());
            if !param_name.is_empty() && !field_name.is_empty() {
                out.push(PhpPromotedPropertyWrite {
                    span: span_of(file, &node),
                    param_name,
                    field_name,
                });
            }
        }
        return;
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children {
        collect_php_property_promotion_writes_inner(child, file, src, out);
    }
}

fn php_promoted_property_field_name(name_node: &tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    if name_node.kind() == "variable_name" {
        let mut cursor = name_node.walk();
        for child in name_node.named_children(&mut cursor) {
            if child.kind() == "name" {
                let name = node_text(&child, src).trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    let raw = node_text(name_node, src);
    let bare = raw.trim().trim_start_matches('$');
    (!bare.is_empty()).then(|| bare.to_string())
}

fn php_param_matches_promoted_property(param: &str, promoted_param: &str, field_name: &str) -> bool {
    let param = param.trim();
    let promoted_param = promoted_param.trim();
    param == promoted_param
        || param.trim_start_matches('$') == promoted_param.trim_start_matches('$')
        || param.trim_start_matches('$') == field_name
}

/// Walk PHP class / interface / trait declarations and collect bare
/// base type names. Grammar shape (verified):
///
///   `class Handler extends Base implements I, J { ... }` →
///     (class_declaration name: (name)
///        (base_clause (name))
///        (class_interface_clause (name) (name))
///        body: (declaration_list))
///
/// `interface_declaration` uses the same `base_clause` for `extends`.
/// `trait_declaration` has no parent list.
fn collect_php_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_declaration", "interface_declaration", "enum_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "name"))
            .or_else(|| first_named_child_of_kind(&class_node, "qualified_name"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
        let mut bases: Vec<String> = Vec::new();
        let mut cursor = class_node.walk();
        for child in class_node.named_children(&mut cursor) {
            match child.kind() {
                "base_clause" | "class_interface_clause" => {
                    let mut clause_cursor = child.walk();
                    for entry in child.named_children(&mut clause_cursor) {
                        // Children of the parent-clause are
                        // `name` / `qualified_name` identifiers in
                        // tree-sitter-php.
                        if matches!(entry.kind(), "name" | "qualified_name") {
                            let raw = node_text(&entry, src);
                            if let Some(name) = canonical_php_base_name(raw) {
                                if !bases.iter().any(|existing| existing == &name) {
                                    bases.push(name);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), class_name.to_string(), bases));
        }
    }
    bases_by_class
}

/// Strip namespace qualifiers from a base name. `\Foo\Bar` → `Bar`,
/// `Bar` → `Bar`. Returns `None` for empty input.
fn canonical_php_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('\\');
    let bare = trimmed.rsplit('\\').next().unwrap_or(trimmed).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Return the namespace path (split on `\`) of the file's
/// `namespace Foo\Bar;` declaration, or `None` if absent.
fn extract_php_namespace(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "namespace_definition" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            let text = node_text(&name_node, src);
            let segments: Vec<String> = text
                .split('\\')
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
                .collect();
            if !segments.is_empty() {
                return Some(segments);
            }
        }
    }
    None
}

#[cfg(test)]
mod callable_reference_tests {
    use super::*;

    #[test]
    fn first_class_callable_placeholder_is_adapter_owned() {
        let language = language_from_pack(PACK_NAME).expect("php grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set php grammar");
        let src = "<?php function f() { $cb = system(...); $value = system($x); }";
        let tree = parser.parse(src, None).expect("parse php source");
        let refs = collect_kinds(
            &tree,
            &[
                "function_call_expression",
                "member_call_expression",
                "nullsafe_member_call_expression",
                "scoped_call_expression",
            ],
        )
        .into_iter()
        .filter_map(|node| extract_php_callable_reference(node, src.as_bytes()))
        .collect::<Vec<_>>();
        assert_eq!(refs, vec!["system"]);
    }

    #[test]
    fn quoted_static_subscript_key_is_decoded_from_php_string_node() {
        let language = language_from_pack(PACK_NAME).expect("php grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set php grammar");
        let src = "<?php function f() { sink($_SERVER[\"HTTP_HOST\"]); }";
        let tree = parser.parse(src, None).expect("parse php source");
        let subscript = collect_kinds(&tree, &["subscript_expression"])
            .into_iter()
            .next()
            .expect("subscript expression");
        let (_, key) = php_subscript_parts(subscript).expect("ordered PHP subscript operands");
        assert_eq!(
            php_static_subscript_key(key, src.as_bytes()),
            Some("HTTP_HOST".to_string()),
            "key kind={} sexp={}",
            key.kind(),
            key.to_sexp()
        );
    }
}
