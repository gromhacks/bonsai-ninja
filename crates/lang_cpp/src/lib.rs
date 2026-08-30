//! C++ language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, collect_param_type_aliases,
        expression_operand_names_with_handler, first_named_child_of_kind, language_from_pack,
        named_child_call_args_with_handler, node_text, parse_with, span_of, walk_flow_events,
    },
    AdapterContext, AdapterError, AggregateLayout, ArgumentPassingMode, BranchConditionFact,
    BranchConditionPolarity, CallArg, CallKind, CallTargetExtraction, CompilerGuardFact, ConditionEquality,
    ConditionExpressionFact, ConditionOperandFact, DeclIndex, DeclKind, FieldWrite, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModulePath, StaticScalarValue, StringCompositionFact, StringCompositionPart, TypeAliasBinding,
    TypeAliasVocabulary, Visibility, EMPTY_HANDLER,
};
use std::sync::OnceLock;
use tree_sitter::{Language, Node, Tree};

/// C++ parameter shape: `parameter_declaration` carries `type` and
/// `declarator` fields (the declarator may be a pointer / array /
/// reference wrapper around the binding identifier). The kit
/// helper drops back to `child_by_field_name("declarator")` when
/// `name` isn't present, then walks down to the inner identifier.
// `parameter_declaration` covers the function's formal parameters;
// `declaration` covers local stack-allocated bindings inside the
// body (`Box obj;`, `Logger log = ...;`). Both shapes carry a
// `type` field and a `declarator` field, so the kit's generic
// param-alias extractor pulls a `name : Type` binding from either.
const CPP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition", "lambda_expression"],
    param_kinds: &["parameter_declaration", "declaration"],
    name_field: "declarator",
    type_field: "type",
};

/// Preserve provider-qualified parameter types alongside the generic short
/// alias emitted by `collect_param_type_aliases`.
///
/// Short aliases remain useful for ordinary C++ dispatch, but they cannot
/// distinguish two unrelated libraries that both declare `Request`. This
/// adapter-owned pass reads only the qualified type syntax and binding
/// declarator. Security/provider meaning remains entirely in rule data.
fn collect_cpp_qualified_parameter_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Vec<TypeAliasBinding>> {
    let mut out = std::collections::HashMap::new();
    for function in collect_kinds(tree, &["function_definition", "lambda_expression"]) {
        let Some(declarator) = function.child_by_field_name("declarator") else {
            continue;
        };
        let mut pending = vec![declarator];
        let mut aliases = Vec::new();
        while let Some(node) = pending.pop() {
            if node.id() != function.id()
                && matches!(node.kind(), "function_definition" | "lambda_expression")
            {
                continue;
            }
            if node.kind() == "parameter_declaration" {
                let (Some(type_node), Some(binding_node)) = (
                    node.child_by_field_name("type"),
                    node.child_by_field_name("declarator")
                        .and_then(first_identifier_descendant_cpp),
                ) else {
                    continue;
                };
                let type_name = node_text(&type_node, src)
                    .trim()
                    .trim_start_matches("::")
                    .to_string();
                let binding = node_text(&binding_node, src).trim();
                if type_name.contains("::") && !binding.is_empty() {
                    aliases.push(TypeAliasBinding {
                        name: binding.to_string(),
                        type_name,
                    });
                }
                continue;
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                pending.push(child);
            }
        }
        aliases.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.type_name.cmp(&right.type_name))
        });
        aliases.dedup();
        if !aliases.is_empty() {
            out.insert(span_of(file, &function), aliases);
        }
    }
    out
}

fn cpp_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "for_range_loop")
        .then(|| {
            Some((
                node.child_by_field_name("declarator")?,
                node.child_by_field_name("right")?,
            ))
        })
        .flatten()
}

pub const LANG_ID: LanguageId = LanguageId::new("cpp");
const PACK_NAME: &str = "cpp";
const CPP_CALL_KINDS: &[&str] = &["call_expression", "new_expression"];

fn cpp_indirect_place_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "pointer_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let has_indirection = node
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "*" | "&"));
    has_indirection
        .then(|| node.child_by_field_name("argument"))
        .flatten()
}

/// C++ call targets are grammar-delimited `function`/`type` nodes. Preserve
/// the complete callable path (`absl::GetFlag`, `object.method`, and operator
/// calls), while removing parsed template-argument nodes: `tokenize<T>` and
/// its declaration `tokenize` are one compiler callable identity. The adapter
/// owns this CST normalization so shared resolution never parses `<...>`.
fn cpp_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = match node.kind() {
        "call_expression" => node.child_by_field_name("function")?,
        "new_expression" => node.child_by_field_name("type")?,
        _ => return None,
    };
    let full_text = cpp_call_target_without_template_arguments(target, src);
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

fn cpp_call_target_without_template_arguments(target: Node<'_>, src: &[u8]) -> String {
    let mut argument_ranges = Vec::new();
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if node.kind() == "template_argument_list" {
            argument_ranges.push(node.byte_range());
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    if argument_ranges.is_empty() {
        return node_text(&target, src).trim().to_string();
    }
    argument_ranges.sort_by_key(|range| (range.start, range.end));
    let mut out = String::new();
    let mut cursor = target.start_byte();
    for range in argument_ranges {
        if range.start > cursor {
            out.push_str(std::str::from_utf8(&src[cursor..range.start]).unwrap_or_default());
        }
        cursor = cursor.max(range.end);
    }
    if cursor < target.end_byte() {
        out.push_str(std::str::from_utf8(&src[cursor..target.end_byte()]).unwrap_or_default());
    }
    out.trim().to_string()
}

const HANDLER: GrammarHandler = GrammarHandler {
    literal_value_kinds: &["null", "nullptr", "true", "false"],
    string_literal_kinds: &[
        "string_literal",
        "raw_string_literal",
        "char_literal",
        "concatenated_string",
    ],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["///", "//!", "/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["parameter_list"],
    parameter_kinds: &["parameter_declaration", "optional_parameter_declaration"],
    parameter_annotation_kinds: &["attribute"],
    variadic_parameter_kinds: &["variadic_parameter_declaration", "variadic_declarator"],
    binding_identifier_kinds: &["identifier"],
    anonymous_variadic_token: Some("..."),
    identifier_kinds: &["identifier"],
    named_aggregate_kinds: &["initializer_list"],
    positional_aggregate_kinds: &["initializer_list"],
    aggregate_pair_kinds: &["initializer_pair"],
    aggregate_key_field_names: &["designator"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["field_identifier"],
    aggregate_syntax_only_kinds: &["type_identifier"],
    transparent_call_wrapper_kinds: &[
        "field_expression",
        "qualified_identifier",
        "parenthesized_expression",
        "co_await_expression",
    ],
    single_expression_group_kinds: &[],
    assignment_target_wrapper_kinds: &[
        "init_declarator",
        "structured_binding_declarator",
        "function_declarator",
        "pointer_declarator",
        "reference_declarator",
        "parenthesized_declarator",
    ],
    binding_declaration_keyword_spellings: &["auto", "const"],
    aggregate_pattern_kinds: &["structured_binding_declarator"],
    fn_kinds: &["function_definition"],
    call_kinds: CPP_CALL_KINDS,
    constructor_call_kinds: &["new_expression"],
    call_callee_field_names: &["function"],
    constructor_type_field_names: &["type"],
    call_target_extractor: Some(cpp_call_target),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    writeback_operand_field_names: &["argument"],
    indirect_place_operand_extractor: Some(cpp_indirect_place_operand),
    lambda_body_field_names: &["body"],
    pseudo_call_extractor: Some(extract_cpp_pseudo_call),
    syntax_event_extractor: Some(extract_cpp_syntax_event),
    syntax_events_extractor: Some(extract_cpp_syntax_events),
    argument_passing_mode_extractor: Some(cpp_argument_passing_mode),
    expression_value_kind_extractor: Some(cpp_expression_value_kind),
    call_ref_kinds: CPP_CALL_KINDS,
    member_expression_kinds: &["field_expression", "qualified_identifier"],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["argument", "scope"],
    member_name_field_names: &["field", "name"],
    subscript_base_field_names: &["argument"],
    subscript_index_field_names: &[],
    syntax_error_tolerant_call_names: &["va_arg", "__builtin_va_arg"],
    value_free_expression_kinds: &["sizeof_expression", "alignof_expression"],
    class_kinds: &["class_specifier", "struct_specifier", "union_specifier"],
    class_decl_kinds: &[
        ("class_specifier", DeclKind::Class),
        ("struct_specifier", DeclKind::Struct),
        ("union_specifier", DeclKind::Struct),
    ],
    method_context_kinds: &["class_specifier", "struct_specifier", "union_specifier"],
    if_kinds: &["if_statement", "conditional_expression", "switch_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    condition_group_kinds: &["condition_clause", "parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["compound_statement", "expression_statement"],
    loop_update_field_names: &["update"],
    branch_arm_kinds: &["compound_statement", "expression_statement"],
    exclusive_branch_arm_kinds: &["case_statement"],
    fallthrough_branch_arm_kinds: &["case_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &["for_range_loop"],
    foreach_binding_extractor: Some(cpp_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    assignment_kinds: &["assignment_expression", "init_declarator"],
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="],
    positional_aggregate_assignment_kinds: &["init_declarator"],
    positional_aggregate_value_kinds: &["initializer_list"],
    return_kinds: &["return_statement", "co_return_statement"],
    throw_kinds: &["throw_statement"],
    lambda_kinds: &["lambda_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    exclusive_catch_arm_kinds: &["catch_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    yield_kinds: &["co_yield_statement"],
    yield_value_field_names: &["argument", "value"],
    try_body_field_names: &["body"],
    await_kinds: &["co_await_expression"],
    // `this` for instance methods; C++ has no `super` keyword, but
    // `Base::method()` is a qualified call that the resolver
    // already narrows by qualified-name matching, so the explicit
    // implicit-receiver list stays at `this`.
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    implicit_receiver_names: &["this"],
    ..EMPTY_HANDLER
};

fn cpp_expression_value_kind(node: Node<'_>, _src: &[u8]) -> Option<bonsai_lang_api::AssignValueKind> {
    matches!(
        node.kind(),
        "string_literal" | "char_literal" | "number_literal" | "true" | "false" | "nullptr"
    )
    .then_some(bonsai_lang_api::AssignValueKind::Literal)
}

fn cpp_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if [argument, value].into_iter().any(|node| {
        matches!(node.kind(), "pointer_expression" | "unary_expression") && {
            let mut cursor = node.walk();
            let has_address_of = node.children(&mut cursor).any(|child| child.kind() == "&");
            has_address_of
        }
    }) {
        ArgumentPassingMode::WriteBack
    } else {
        ArgumentPassingMode::Value
    }
}

fn extract_cpp_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "delete_expression" {
        return None;
    }
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: None,
        receiver_types: Vec::new(),
        name: "delete".to_string(),
        call_kind: CallKind::Operator,
        args: named_child_call_args_with_handler(&node, file, src, handler),
    })
}

/// Lower C++ direct initialization (`Type value(args)`) as the constructor
/// call it denotes. Tree-sitter represents this as an `init_declarator` whose
/// value is an `argument_list`, not as a `call_expression`; without this
/// adapter-owned CST rule the compiler sees the assignment and nested
/// argument calls but loses the constructor boundary itself.
fn extract_cpp_syntax_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    let (name, value) = match node.kind() {
        "init_declarator" => {
            let value = node.child_by_field_name("value")?;
            if value.kind() != "argument_list" {
                return None;
            }
            let declaration = node.parent().filter(|parent| parent.kind() == "declaration")?;
            let type_node = declaration.child_by_field_name("type")?;
            (cpp_type_descriptor_name(&type_node, src)?, value)
        }
        // A constructor's member/base initializer list lives outside its
        // compound body. The adapter explicitly walks that list below; base
        // identifiers resolve to constructor declarations, while member
        // identifiers remain unresolved unless their own typed declaration
        // provides a callable identity.
        "field_initializer" => {
            let name_node = node.named_child(0)?;
            let value = first_named_child_of_kind(&node, "argument_list")?;
            (node_text(&name_node, src).trim().to_string(), value)
        }
        _ => return None,
    };
    if name.is_empty() {
        return None;
    }
    Some(FlowEvent::Call {
        span: span_of(file, &value),
        receiver: None,
        receiver_types: Vec::new(),
        name,
        call_kind: CallKind::Constructor,
        args: named_child_call_args_with_handler(&value, file, src, handler),
    })
}

/// Lower `left >> right` as an ordinary binary operator value operation.
///
/// The token alone does not distinguish integral shifting from an overloaded
/// extraction operator. The syntax pass therefore keeps the parsed left
/// operand as the operator receiver and the right operand as an ordinary value
/// argument, but deliberately emits no write-back fact.
/// [`prove_cpp_stream_extraction_events`] upgrades this event only when the
/// same compiler snapshot proves both the receiver's declared class and that
/// class's exact one-argument `operator>>` with a mutable lvalue-reference
/// parameter.
fn cpp_shift_right_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "binary_expression" {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let mut cursor = node.walk();
    let is_shift_right = node
        .children(&mut cursor)
        .filter(|child| !child.is_named())
        .any(|child| child.kind() == ">>");
    if !is_shift_right {
        return None;
    }

    let mut root = left;
    while root.kind() == "binary_expression" {
        let mut inner_cursor = root.walk();
        let inner_is_shift_right = root
            .children(&mut inner_cursor)
            .filter(|child| !child.is_named())
            .any(|child| child.kind() == ">>");
        if !inner_is_shift_right {
            break;
        }
        root = root.child_by_field_name("left")?;
    }
    let receiver = node_text(&root, src).trim().to_string();
    let right_text = node_text(&right, src).trim().to_string();
    if receiver.is_empty() || right_text.is_empty() {
        return None;
    }
    let argument = |value: Node<'_>, value_text: String| CallArg {
        span: span_of(file, &value),
        passing_mode: ArgumentPassingMode::Value,
        name: None,
        place: matches!(
            value.kind(),
            "identifier" | "field_identifier" | "qualified_identifier" | "field_expression"
        )
        .then_some(value_text.clone()),
        source_names: expression_operand_names_with_handler(&value, src, handler),
        value_text,
    };
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: Some(receiver),
        receiver_types: Vec::new(),
        name: ">>".to_string(),
        call_kind: CallKind::Operator,
        args: vec![argument(right, right_text)],
    })
}

fn cpp_is_shift_right_expression(node: Node<'_>) -> bool {
    if node.kind() != "binary_expression" {
        return false;
    }
    let mut cursor = node.walk();
    let is_shift = node
        .children(&mut cursor)
        .filter(|child| !child.is_named())
        .any(|child| child.kind() == ">>");
    is_shift
}

fn cpp_binary_operator_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "binary_expression" {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())?
        .trim();
    if operator != "/" {
        return None;
    }
    let argument = |value: Node<'_>| {
        let value_text = node_text(&value, src).trim().to_string();
        let mut source_names = expression_operand_names_with_handler(&value, src, handler);
        source_names.sort();
        source_names.dedup();
        let place = matches!(
            value.kind(),
            "identifier" | "field_identifier" | "qualified_identifier" | "field_expression"
        )
        .then_some(value_text.clone());
        CallArg {
            span: span_of(file, &value),
            passing_mode: ArgumentPassingMode::Value,
            name: None,
            value_text,
            place,
            source_names,
        }
    };
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: None,
        receiver_types: Vec::new(),
        name: operator.to_string(),
        call_kind: CallKind::Operator,
        args: vec![argument(left), argument(right)],
    })
}

/// Emit a complete left-associative shift chain in runtime order. The
/// shared walker visits parents before children, so emitting individual
/// parent events would reverse `left >> first >> second`. Only the outermost
/// chain emits; its nested binary nodes are suppressed by the parent check.
fn extract_cpp_syntax_events(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    if let Some(operator) = cpp_binary_operator_event(node, file, src, handler) {
        return vec![operator];
    }
    if !cpp_is_shift_right_expression(node) {
        return Vec::new();
    }
    if node.parent().is_some_and(|parent| {
        cpp_is_shift_right_expression(parent)
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| left.id() == node.id())
    }) {
        return Vec::new();
    }

    let mut chain = Vec::new();
    let mut current = node;
    loop {
        chain.push(current);
        let Some(left) = current.child_by_field_name("left") else {
            break;
        };
        if !cpp_is_shift_right_expression(left) {
            break;
        }
        current = left;
    }
    chain.reverse();
    chain
        .into_iter()
        .filter_map(|expression| cpp_shift_right_event(expression, file, src, handler))
        .collect()
}

/// Return the class types whose own declaration proves a mutating member
/// extraction operator: `T::operator>>(U&)` with exactly one non-const lvalue
/// reference parameter.  Item-looking names or a `>>` token at the use site
/// are not evidence; both the receiver type and the operator signature must be
/// present in this compiler snapshot.
fn collect_cpp_mutating_member_shift_types(tree: &Tree, src: &[u8]) -> std::collections::HashSet<String> {
    let mut types = std::collections::HashSet::new();
    for class in collect_kinds(tree, &["class_specifier", "struct_specifier"]) {
        let Some(name_node) = class.child_by_field_name("name") else {
            continue;
        };
        let Some(class_name) = canonical_cpp_base_name(node_text(&name_node, src)) else {
            continue;
        };
        let mut stack = class.child_by_field_name("body").into_iter().collect::<Vec<_>>();
        let mut proven = false;
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier"
            ) && node.id() != class.id()
            {
                continue;
            }
            if node.kind() == "operator_name"
                && node_text(&node, src)
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .eq("operator>>".chars())
            {
                let function = node.parent().and_then(|mut parent| {
                    while parent.id() != class.id() && parent.kind() != "function_declarator" {
                        parent = parent.parent()?;
                    }
                    (parent.kind() == "function_declarator").then_some(parent)
                });
                if function.is_some_and(|function| cpp_member_shift_has_mutable_output(function, src)) {
                    proven = true;
                    break;
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        if proven {
            types.insert(class_name);
        }
    }
    types
}

fn cpp_member_shift_has_mutable_output(function: Node<'_>, src: &[u8]) -> bool {
    let Some(parameters) = first_named_child_of_kind(&function, "parameter_list") else {
        return false;
    };
    let mut cursor = parameters.walk();
    let parameters = parameters
        .named_children(&mut cursor)
        .filter(|parameter| parameter.kind() == "parameter_declaration")
        .collect::<Vec<_>>();
    let [output] = parameters.as_slice() else {
        return false;
    };
    let mut stack = vec![*output];
    let mut has_lvalue_reference = false;
    let mut has_const_qualifier = false;
    while let Some(node) = stack.pop() {
        if node.kind() == "reference_declarator" {
            let rendered = node_text(&node, src).trim_start();
            has_lvalue_reference |= rendered.starts_with('&') && !rendered.starts_with("&&");
        }
        if node.kind() == "type_qualifier" && node_text(&node, src).trim() == "const" {
            has_const_qualifier = true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    has_lvalue_reference && !has_const_qualifier
}

fn prove_cpp_stream_extraction_events(
    events: &mut [FlowEvent],
    aliases: &[TypeAliasBinding],
    mutating_shift_types: &std::collections::HashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind: CallKind::Operator,
                args,
                ..
            } if name == ">>" && receiver.is_some() && args.len() == 1 => {
                let receiver_place = receiver.clone().expect("guarded operator receiver");
                let proven_types = aliases
                    .iter()
                    .filter(|alias| alias.name == receiver_place)
                    .filter_map(|alias| {
                        let canonical = bonsai_lang_api::kit::canonical_simple_type_name(&alias.type_name);
                        mutating_shift_types
                            .contains(&canonical)
                            .then_some(alias.type_name.clone())
                    })
                    .collect::<Vec<_>>();
                if proven_types.is_empty() {
                    continue;
                }
                let mut output = args.remove(0);
                output.passing_mode = ArgumentPassingMode::WriteBack;
                *args = vec![output];
                receiver_types.extend(proven_types);
                receiver_types.sort();
                receiver_types.dedup();
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                prove_cpp_stream_extraction_events(then_events, aliases, mutating_shift_types);
                prove_cpp_stream_extraction_events(else_events, aliases, mutating_shift_types);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                prove_cpp_stream_extraction_events(body, aliases, mutating_shift_types);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                prove_cpp_stream_extraction_events(body, aliases, mutating_shift_types);
                prove_cpp_stream_extraction_events(catch_events, aliases, mutating_shift_types);
                prove_cpp_stream_extraction_events(finally_events, aliases, mutating_shift_types);
            }
            _ => {}
        }
    }
}

/// Zero-sized adapter handle; all state lives in the shared parser pack.
#[derive(Debug, Default, Copy, Clone)]
pub struct CppAdapter;

impl CppAdapter {
    /// Construct a fresh adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn cpp_tree_proves_language(tree: &Tree) -> bool {
    static C_GRAMMAR: OnceLock<Option<Language>> = OnceLock::new();
    let Some(c_grammar) = C_GRAMMAR.get_or_init(|| language_from_pack("c").ok()) else {
        return false;
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_named()
            && !node.is_error()
            && (!grammar_has_named_kind(c_grammar, node.kind()) || is_cpp_braced_construction(node))
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn grammar_has_named_kind(grammar: &Language, kind: &str) -> bool {
    let id = grammar.id_for_node_kind(kind, true);
    id != 0 && grammar.node_kind_is_named(id) && grammar.node_kind_for_id(id) == Some(kind)
}

/// Distinguish C++ uniform construction (`Type { ... }`) from C's standard
/// compound literal (`(Type) { ... }`) using the grammar's typed child span.
/// Both grammars call the parent a `compound_literal_expression`, so the node
/// kind alone is not language proof.
fn is_cpp_braced_construction(node: Node<'_>) -> bool {
    node.kind() == "compound_literal_expression"
        && node
            .child_by_field_name("type")
            .is_some_and(|ty| ty.start_byte() == node.start_byte())
}

impl LanguageAdapter for CppAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C++"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.h` is shared with C and Objective-C. Grammar-owned C++ constructs
        // prove this specialized frontend; a C-compatible header with no C++
        // syntax stays with the generic C adapter.
        &["cpp", "cc", "cxx", "hpp", "hh", "hxx", "h"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn source_syntax_proves_language(
        &self,
        _snapshot: &bonsai_lang_api::FileSnapshot,
        tree: &Tree,
    ) -> bonsai_lang_api::LanguageOwnershipEvidence {
        if cpp_tree_proves_language(tree) {
            bonsai_lang_api::LanguageOwnershipEvidence::Proven
        } else {
            bonsai_lang_api::LanguageOwnershipEvidence::Excluded
        }
    }
    fn parse_context_fingerprint(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
    ) -> u64 {
        bonsai_lang_api::c_family_preprocessor_context_fingerprint(snapshot, vfs)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        self.parse_recovery_edit_batches(snapshot, vfs, tree)
            .into_iter()
            .flatten()
            .collect()
    }
    fn parse_recovery_edit_batches(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<Vec<bonsai_lang_api::ParseRecoveryEdit>> {
        let conditionals = bonsai_lang_api::branch_free_conditional_recovery_edits(
            snapshot,
            tree,
            bonsai_lang_api::ConditionalDirectiveSyntax {
                openings_with_condition: &["#if", "#ifdef", "#ifndef"],
                alternatives_with_condition: &["#elif", "#elifdef", "#elifndef"],
                alternatives_without_condition: &["#else"],
                closing: "#endif",
                trailing_comment_prefixes: &["//", "/*"],
                non_directive_node_kinds: &[
                    "comment",
                    "string_literal",
                    "raw_string_literal",
                    "char_literal",
                    "concatenated_string",
                ],
            },
        );
        let declarations = bonsai_lang_api::c_family_declaration_macro_recovery_edits(
            snapshot,
            vfs,
            tree,
            &["va_arg", "__builtin_va_arg"],
        );
        [conditionals, declarations]
            .into_iter()
            .filter(|batch| !batch.is_empty())
            .collect()
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: same story as C — tree-sitter-cpp parses
        // `STR_CPY(...)` / `LOG(...)` / `assert(...)` as ordinary
        // call expressions and the engine narrows them by name.
        // `#define` expansion is not performed.
        LanguageCapabilities {
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                rooted_prefixes: &["::"],
                repeatable_rooted_prefixes: &[],
            },
            // C++ constructors are class-named; the kind-based
            // `DeclKind::Constructor` lookup is authoritative.
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &["this"],
            same_directory_unqualified_calls: true,
            build_target_linkage: true,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "&"),
            ("custom lowering", "*"),
            ("custom lowering", "/"),
            ("custom lowering", ">>"),
            ("custom lowering", "access_specifier"),
            ("custom lowering", "argument_list"),
            ("custom lowering", "alias_declaration"),
            ("custom lowering", "base_class_clause"),
            ("custom lowering", "binary_expression"),
            ("custom lowering", "call_expression"),
            ("custom lowering", "cast_expression"),
            ("custom lowering", "catch_clause"),
            ("custom lowering", "char_literal"),
            ("custom lowering", "class_specifier"),
            ("custom lowering", "compound_literal_expression"),
            ("custom lowering", "declaration"),
            ("custom lowering", "delete_expression"),
            ("custom lowering", "destructor_name"),
            ("custom lowering", "false"),
            ("custom lowering", "field_declaration"),
            ("custom lowering", "field_identifier"),
            ("custom lowering", "field_initializer"),
            ("custom lowering", "field_initializer_list"),
            ("custom lowering", "for_range_loop"),
            ("custom lowering", "function_declarator"),
            ("custom lowering", "function_definition"),
            ("custom lowering", "identifier"),
            ("custom lowering", "init_declarator"),
            ("custom lowering", "namespace"),
            ("custom lowering", "namespace_alias_definition"),
            ("custom lowering", "namespace_definition"),
            ("custom lowering", "namespace_identifier"),
            ("custom lowering", "nested_namespace_specifier"),
            ("custom lowering", "new_expression"),
            ("custom lowering", "nullptr"),
            ("custom lowering", "number_literal"),
            ("custom lowering", "operator_name"),
            ("custom lowering", "parameter_declaration"),
            ("custom lowering", "parameter_list"),
            ("custom lowering", "placeholder_type_specifier"),
            ("custom lowering", "pointer_expression"),
            ("custom lowering", "qualified_identifier"),
            ("custom lowering", "storage_class_specifier"),
            ("custom lowering", "string_literal"),
            ("custom lowering", "struct_specifier"),
            ("custom lowering", "template_argument_list"),
            ("custom lowering", "template_declaration"),
            ("custom lowering", "template_function"),
            ("custom lowering", "template_parameter_list"),
            ("custom lowering", "template_type"),
            ("custom lowering", "true"),
            ("custom lowering", "type_identifier"),
            ("custom lowering", "type_parameter_declaration"),
            ("custom lowering", "unary_expression"),
            ("custom lowering", "union_specifier"),
            ("custom lowering", "using_declaration"),
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
        mark_cpp_constructors(&mut decl_index);
        // Populate qualified_name + module_path + visibility per the
        // semantic-identity contract
        // (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`).
        // Two TU-private surfaces in C++:
        //   - `static` storage class on a free function (C-inherited).
        //   - Definition inside an anonymous namespace.
        // Both must surface as `Visibility::Private` so the resolver
        // refuses cross-TU linking by name.
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        if let Some((snapshot, tree)) = parsed.as_ref() {
            apply_cpp_namespace_semantic_identity(&mut decl_index, tree, file, snapshot.text.as_bytes());
            decl_index
                .compiler_guards
                .extend(cpp_compound_predicate_call_guards(
                    tree,
                    file,
                    snapshot.text.as_bytes(),
                ));
            populate_cpp_condition_expressions(
                &mut decl_index.branch_conditions,
                tree,
                file,
                snapshot.text.as_bytes(),
            );
            decl_index.string_compositions.extend(cpp_string_compositions(
                tree,
                file,
                snapshot.text.as_bytes(),
            ));
            decl_index
                .string_compositions
                .sort_by_key(|fact| (fact.container_span.start, fact.container_span.end));
            decl_index.string_compositions.dedup();
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut decl_index,
                tree,
                file,
                snapshot.text.as_bytes(),
                &HANDLER,
                cpp_static_scalar,
            );
        }
        let private_function_names = parsed
            .as_ref()
            .map(|(snapshot, tree)| collect_tu_private_function_names(tree, snapshot.text.as_bytes()))
            .unwrap_or_default();
        for decl in &mut decl_index.defs {
            if private_function_names.contains(&decl.name) {
                decl.visibility = Visibility::Private;
            }
        }
        // Per-class `bases`: `class C : public Base, private Other {…}`
        // → ["Base", "Other"]. C++ exposes them as a single
        // `base_class_clause` whose access_specifier+type_identifier
        // pairs alternate. Per-decl `type_aliases` from typed
        // parameters bring C++ in lockstep with the rest per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            let translation_unit_aliases = collect_cpp_translation_unit_type_aliases(tree, src);
            let private_template_substitutions = collect_cpp_private_template_substitutions(
                tree,
                src,
                &translation_unit_aliases,
                &private_function_names,
            );
            // Phase-6 return-type extraction: `T foo() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, tree, src, &HANDLER);
            let bases_by_span = collect_cpp_class_bases(tree, file, src);
            let fields_by_class = collect_cpp_class_fields(tree, file, src);
            decl_index.aggregate_layouts = fields_by_class
                .iter()
                .map(|(_, type_name, fields)| AggregateLayout {
                    type_name: type_name.clone(),
                    fields: fields.clone(),
                })
                .collect();
            let fields_by_parent = cpp_fields_by_parent_symbol(&decl_index, &fields_by_class);
            let access_by_span = collect_cpp_member_visibility(tree, file, src);
            let alias_map = collect_param_type_aliases(tree, file, src, &CPP_TYPE_ALIASES);
            let qualified_param_aliases = collect_cpp_qualified_parameter_type_aliases(tree, file, src);
            let proven_direct_initializers =
                collect_cpp_locally_proven_direct_initializers(tree, file, src, &decl_index);
            // WS2: `auto c = static_cast<Foo>(x)` / `auto c = (Foo) x` — the
            // kit types declared-type locals (`Foo c = make()`) but not the
            // inferred-`auto` form, where the type lives only on the cast.
            let cast_aliases = collect_cpp_cast_aliases(tree, file, src).into_iter().fold(
                std::collections::HashMap::<Span, Vec<TypeAliasBinding>>::new(),
                |mut by_span, (span, binding)| {
                    by_span.entry(span).or_default().push(binding);
                    by_span
                },
            );
            let initializer_specs = collect_cpp_initializer_field_specs(tree, file, src)
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>();
            let initializer_events = collect_cpp_constructor_initializer_events(tree, file, src)
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>();
            for decl in &mut decl_index.defs {
                if let Some(events) = proven_direct_initializers.get(&decl.span) {
                    for event in events.iter().cloned() {
                        let position = decl
                            .flow_events
                            .iter()
                            .position(|existing| existing.span().start > event.span().start)
                            .unwrap_or(decl.flow_events.len());
                        decl.flow_events.insert(position, event);
                    }
                }
                if let Some(events) = initializer_events.get(&decl.span) {
                    let mut ordered = events.clone();
                    ordered.append(&mut decl.flow_events);
                    decl.flow_events = ordered;
                }
                if let Some(fields) = decl.parent.and_then(|parent| fields_by_parent.get(&parent)) {
                    bonsai_lang_api::qualify_receiver_field_expression_flows(
                        &mut decl.flow_events,
                        fields,
                        "this",
                    );
                }
                if let Some(visibility) = access_by_span.get(&decl.span).copied() {
                    decl.visibility = visibility;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(aliases) = qualified_param_aliases.get(&decl.span) {
                    decl.type_aliases.extend(aliases.iter().cloned());
                    decl.type_aliases.sort_by(|left, right| {
                        left.name
                            .cmp(&right.name)
                            .then_with(|| left.type_name.cmp(&right.type_name))
                    });
                    decl.type_aliases.dedup();
                }
                if let Some(bindings) = cast_aliases.get(&decl.span) {
                    decl.type_aliases.extend(bindings.iter().cloned());
                }
                expand_cpp_type_alias_bindings(&mut decl.type_aliases, &translation_unit_aliases);
                if let Some(substitutions) = private_template_substitutions.get(&decl.name) {
                    apply_cpp_private_template_substitutions(decl, substitutions, &translation_unit_aliases);
                }
                collapse_cpp_same_type_copy_initializers(&mut decl.flow_events, &decl.type_aliases);
                // Complete exact C++ exception facts. Generic binding
                // extraction cannot distinguish the type from the declarator
                // in `catch (const T& e)`, and C++ throw constructors use a
                // call expression rather than a language-neutral `new` node.
                populate_cpp_exception_facts(&mut decl.flow_events, tree, src);
                // Bases only attach to class-shaped decls; skip
                // free functions, methods, vars, etc.
                if let Some(specs) = initializer_specs.get(&decl.span) {
                    for spec in specs {
                        let source_param_indices = decl
                            .params
                            .iter()
                            .enumerate()
                            .filter_map(|(idx, param)| {
                                spec.sources
                                    .iter()
                                    .any(|source| cpp_source_mentions_param(source, param))
                                    .then_some(idx)
                            })
                            .collect::<Vec<_>>();
                        if source_param_indices.is_empty() {
                            continue;
                        }
                        decl.receiver_field_writes.push(FieldWrite {
                            span: spec.span,
                            target: format!("this.{}", spec.field),
                            source_param_indices,
                        });
                    }
                    decl.receiver_field_writes
                        .sort_by_key(|write| (write.span.start, write.target.clone()));
                    decl.receiver_field_writes.dedup_by(|a, b| {
                        a.span == b.span
                            && a.target == b.target
                            && a.source_param_indices == b.source_param_indices
                    });
                }
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
            }
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            let has_variadic_param = decl
                .params
                .iter()
                .any(|param| param == bonsai_lang_api::kit::SYNTHETIC_VARARGS_PARAM);
            bonsai_lang_api::kit::normalize_variadic_builtin_flow(
                &mut decl.flow_events,
                has_variadic_param,
                &["va_start", "__builtin_va_start"],
                &["va_arg", "__builtin_va_arg"],
            );
            apply_cpp_moved_argument_places(&mut decl.flow_events);
        }
        decl_index.finite_literal_selections = decl_index
            .defs
            .iter()
            .filter_map(|decl| {
                bonsai_lang_api::kit::complete_finite_literal_return_span(&decl.flow_events).map(
                    |selection_span| bonsai_lang_api::FiniteLiteralSelectionFact {
                        selection_span,
                        assignment_span: None,
                        target: None,
                        call_span: None,
                        argument_index: None,
                    },
                )
            })
            .collect();
        bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut decl_index.finite_literal_selections);
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing follows constructor CST
        // nodes and declaration resolution, never identifier capitalization.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let switch_break_spans = collect_cpp_switch_break_spans(tree, file, snapshot.text.as_bytes());
            let mutating_shift_types =
                collect_cpp_mutating_member_shift_types(tree, snapshot.text.as_bytes());
            for decl in &mut decl_index.defs {
                bonsai_lang_api::kit::lower_adapter_local_breaks(&mut decl.flow_events, &switch_break_spans);
                if !mutating_shift_types.is_empty() {
                    prove_cpp_stream_extraction_events(
                        &mut decl.flow_events,
                        &decl.type_aliases,
                        &mutating_shift_types,
                    );
                }
            }
        }
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

const CPP_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST: &str = "terminal-predicate.compound-static-allowlist";

#[derive(Clone)]
struct CppCompoundPredicateSummary {
    name: String,
    input_parameter: String,
    evidence: Vec<String>,
}

fn cpp_compound_predicate_call_guards(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CompilerGuardFact> {
    let collections = cpp_static_string_collections(tree, src);
    let summaries = collect_kinds(tree, &["function_definition"])
        .into_iter()
        .filter_map(|function| cpp_compound_predicate_summary(function, src, &collections))
        .collect::<Vec<_>>();
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let calls = cpp_descendants_of_kind(body, "call_expression");
        for branch in cpp_descendants_of_kind(body, "if_statement") {
            let (Some(condition), Some(consequence)) = (
                branch.child_by_field_name("condition"),
                branch.child_by_field_name("consequence"),
            ) else {
                continue;
            };
            if !cpp_statement_is_terminal(consequence) {
                continue;
            }
            let Some(predicate_call) = cpp_negated_single_call(condition, src) else {
                continue;
            };
            let Some(predicate_name) = predicate_call
                .child_by_field_name("function")
                .map(|node| node_text(&node, src).trim())
            else {
                continue;
            };
            let matching = summaries
                .iter()
                .filter(|summary| summary.name == predicate_name)
                .collect::<Vec<_>>();
            let [summary] = matching.as_slice() else {
                continue;
            };
            let predicate_args = predicate_call
                .child_by_field_name("arguments")
                .map(cpp_direct_named_children)
                .unwrap_or_default();
            let Some(predicate_input_index) = predicate_args
                .iter()
                .position(|argument| node_text(argument, src).trim() == summary.input_parameter)
                .or(Some(0))
            else {
                continue;
            };
            let Some(predicate_input) = predicate_args.get(predicate_input_index) else {
                continue;
            };
            let predicate_input = node_text(predicate_input, src).trim();
            for guarded_call in calls
                .iter()
                .copied()
                .filter(|call| call.start_byte() > branch.end_byte())
            {
                let Some(callee) = guarded_call.child_by_field_name("function") else {
                    continue;
                };
                let guarded_args = guarded_call
                    .child_by_field_name("arguments")
                    .map(cpp_direct_named_children)
                    .unwrap_or_default();
                let relations = guarded_args
                    .iter()
                    .enumerate()
                    .filter(|(_, argument)| {
                        cpp_expression_is_place_projection(**argument, predicate_input, src)
                    })
                    .map(|(index, _)| {
                        format!("guarded-argument:{index}=predicate-argument:{predicate_input_index}")
                    })
                    .collect::<Vec<_>>();
                if relations.is_empty() {
                    continue;
                }
                let mut evidence = summary.evidence.clone();
                evidence.extend(relations);
                evidence.extend(cpp_related_static_call_evidence(guarded_call, &calls, src));
                evidence.sort();
                evidence.dedup();
                facts.push(CompilerGuardFact {
                    function_span: span_of(file, &function),
                    guarded_call_span: span_of(file, &callee),
                    proof_span: span_of(file, &branch),
                    capability: CPP_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST.to_string(),
                    evidence,
                });
            }
        }
    }
    facts.sort_by(|left, right| {
        (
            left.function_span.start,
            left.guarded_call_span.start,
            left.evidence.as_slice(),
        )
            .cmp(&(
                right.function_span.start,
                right.guarded_call_span.start,
                right.evidence.as_slice(),
            ))
    });
    facts.dedup();
    facts
}

fn cpp_compound_predicate_summary(
    function: Node<'_>,
    src: &[u8],
    collections: &std::collections::HashMap<String, Vec<String>>,
) -> Option<CppCompoundPredicateSummary> {
    let name = cpp_function_name(function, src)?;
    let parameters = cpp_function_parameters(function, src);
    if parameters.len() < 2 {
        return None;
    }
    let input = parameters[0].clone();
    let output = parameters[1].clone();
    let body = function.child_by_field_name("body")?;
    let direct = cpp_direct_named_children(body);
    let final_return = direct.last().copied()?.filter_kind("return_statement")?;
    let final_value = cpp_first_named_child(final_return)?;
    let prefix = cpp_descendants_of_kind(body, "if_statement")
        .into_iter()
        .find_map(|branch| {
            let consequence = branch.child_by_field_name("consequence")?;
            if !cpp_return_has_boolean(consequence, false, src) {
                return None;
            }
            let condition = branch.child_by_field_name("condition")?;
            cpp_descendants_of_kind(condition, "call_expression")
                .into_iter()
                .find_map(|call| {
                    let function = call.child_by_field_name("function")?;
                    let (receiver, method) = cpp_field_call_parts(function, src)?;
                    if receiver != input {
                        return None;
                    }
                    let args = cpp_direct_named_children(call.child_by_field_name("arguments")?);
                    let [literal, offset] = args.as_slice() else {
                        return None;
                    };
                    let prefix = cpp_static_string(*literal, src)?;
                    let offset = cpp_integer_literal(*offset, src)?;
                    (offset == 0).then_some((method, prefix, branch))
                })
        })?;
    let rest_binding = cpp_descendants_of_kind(body, "init_declarator")
        .into_iter()
        .find_map(|initializer| {
            let binding = initializer
                .child_by_field_name("declarator")
                .and_then(first_identifier_descendant_cpp)?;
            let value = initializer.child_by_field_name("value")?;
            let call = (value.kind() == "call_expression").then_some(value)?;
            let (receiver, method) = cpp_field_call_parts(call.child_by_field_name("function")?, src)?;
            let args = cpp_direct_named_children(call.child_by_field_name("arguments")?);
            let [offset] = args.as_slice() else {
                return None;
            };
            (receiver == input && cpp_integer_literal(*offset, src) == u128::try_from(prefix.1.len()).ok())
                .then(|| (node_text(&binding, src).trim().to_string(), method))
        })?;
    let token_assignment = cpp_descendants_of_kind(body, "assignment_expression")
        .into_iter()
        .find(|assignment| {
            let Some(left) = assignment.child_by_field_name("left") else {
                return false;
            };
            let Some(right) = assignment.child_by_field_name("right") else {
                return false;
            };
            if node_text(&left, src).trim() != output || right.kind() != "call_expression" {
                return false;
            }
            let Some((receiver, _)) = right
                .child_by_field_name("function")
                .and_then(|function| cpp_field_call_parts(function, src))
            else {
                return false;
            };
            receiver == rest_binding.0
                && cpp_descendants_of_kind(right, "char_literal")
                    .iter()
                    .any(|literal| node_text(literal, src).trim() == "'/'")
        })?;
    let membership_call = cpp_descendants_of_kind(final_value, "call_expression")
        .into_iter()
        .find_map(|call| {
            let (receiver, method) = cpp_field_call_parts(call.child_by_field_name("function")?, src)?;
            if !collections.contains_key(&receiver) {
                return None;
            }
            let args = cpp_direct_named_children(call.child_by_field_name("arguments")?);
            let [subject] = args.as_slice() else {
                return None;
            };
            (node_text(subject, src).trim() == output).then_some(method)
        })?;
    let mut evidence = vec![
        "predicate-complete:true".to_string(),
        "finite-static-string-membership:true".to_string(),
        format!("prefix-call:{}", prefix.0),
        format!("prefix-value:string:{}", prefix.1),
        "prefix-position:number:0".to_string(),
        format!("prefix-remainder-call:{}", rest_binding.1),
        format!("membership-call:{membership_call}"),
        "membership-token-boundary:true".to_string(),
    ];
    if token_assignment.start_byte() <= final_return.start_byte() {
        evidence.push("membership-subject-derived-from-prefix:true".to_string());
    }
    Some(CppCompoundPredicateSummary {
        name,
        input_parameter: input,
        evidence,
    })
}

trait CppNodeKindExt {
    fn filter_kind(self, kind: &str) -> Option<Self>
    where
        Self: Sized;
}

impl CppNodeKindExt for Node<'_> {
    fn filter_kind(self, kind: &str) -> Option<Self> {
        (self.kind() == kind).then_some(self)
    }
}

fn cpp_function_name(function: Node<'_>, src: &[u8]) -> Option<String> {
    let declarator = function.child_by_field_name("declarator")?;
    let function_declarator = if declarator.kind() == "function_declarator" {
        declarator
    } else {
        first_named_child_of_kind(&declarator, "function_declarator")?
    };
    let binding = first_identifier_descendant_cpp(function_declarator.child_by_field_name("declarator")?)?;
    Some(node_text(&binding, src).trim().to_string())
}

fn cpp_function_parameters(function: Node<'_>, src: &[u8]) -> Vec<String> {
    let Some(parameters) = function
        .child_by_field_name("declarator")
        .and_then(|declarator| first_named_child_of_kind(&declarator, "parameter_list"))
    else {
        return Vec::new();
    };
    cpp_direct_named_children(parameters)
        .into_iter()
        .filter(|node| node.kind() == "parameter_declaration")
        .filter_map(|parameter| {
            parameter
                .child_by_field_name("declarator")
                .and_then(first_identifier_descendant_cpp)
                .map(|binding| node_text(&binding, src).trim().to_string())
        })
        .collect()
}

fn cpp_field_call_parts(function: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    if function.kind() != "field_expression" {
        return None;
    }
    Some((
        node_text(&function.child_by_field_name("argument")?, src)
            .trim()
            .to_string(),
        node_text(&function.child_by_field_name("field")?, src)
            .trim()
            .to_string(),
    ))
}

fn cpp_negated_single_call<'tree>(condition: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    let condition = cpp_unwrap_condition(condition);
    let argument = condition.child_by_field_name("argument")?;
    let operator = src
        .get(condition.start_byte()..argument.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    (condition.kind() == "unary_expression" && operator == Some("!") && argument.kind() == "call_expression")
        .then_some(argument)
}

fn cpp_unwrap_condition(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "condition_clause" | "parenthesized_expression") {
        let Some(inner) = node
            .child_by_field_name("value")
            .or_else(|| cpp_first_named_child(node))
        else {
            break;
        };
        node = inner;
    }
    node
}

fn cpp_return_has_boolean(statement: Node<'_>, expected: bool, src: &[u8]) -> bool {
    let return_statement = if statement.kind() == "return_statement" {
        Some(statement)
    } else if statement.kind() == "compound_statement" {
        cpp_direct_named_children(statement)
            .into_iter()
            .find(|node| node.kind() == "return_statement")
    } else {
        None
    };
    return_statement
        .and_then(cpp_first_named_child)
        .is_some_and(|value| node_text(&value, src).trim() == if expected { "true" } else { "false" })
}

fn cpp_statement_is_terminal(statement: Node<'_>) -> bool {
    if statement.kind() == "return_statement" {
        return true;
    }
    statement.kind() == "compound_statement"
        && cpp_direct_named_children(statement)
            .last()
            .is_some_and(|last| cpp_statement_is_terminal(*last))
}

fn cpp_static_string_collections(tree: &Tree, src: &[u8]) -> std::collections::HashMap<String, Vec<String>> {
    let mut collections = std::collections::HashMap::new();
    for declaration in collect_kinds(tree, &["declaration"])
        .into_iter()
        .filter(|node| !cpp_has_ancestor_kind(*node, "function_definition"))
    {
        for initializer in cpp_descendants_of_kind(declaration, "init_declarator") {
            let (Some(declarator), Some(value)) = (
                initializer.child_by_field_name("declarator"),
                initializer.child_by_field_name("value"),
            ) else {
                continue;
            };
            if value.kind() != "initializer_list" {
                continue;
            }
            let Some(binding) = first_identifier_descendant_cpp(declarator) else {
                continue;
            };
            let items = cpp_direct_named_children(value);
            let values = items
                .iter()
                .copied()
                .filter_map(|item| cpp_static_string(item, src))
                .collect::<Vec<_>>();
            if !values.is_empty() && values.len() == items.len() {
                collections.insert(node_text(&binding, src).trim().to_string(), values);
            }
        }
    }
    collections
}

fn cpp_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains('\\')).then(|| inner.to_string())
}

fn cpp_integer_literal(node: Node<'_>, src: &[u8]) -> Option<u128> {
    if node.kind() != "number_literal" {
        return None;
    }
    node_text(&node, src)
        .trim()
        .trim_end_matches(['u', 'U', 'l', 'L'])
        .parse()
        .ok()
}

fn cpp_expression_is_place_projection(expression: Node<'_>, place: &str, src: &[u8]) -> bool {
    if node_text(&expression, src).trim() == place {
        return true;
    }
    if expression.kind() != "call_expression" {
        return false;
    }
    let Some(function) = expression.child_by_field_name("function") else {
        return false;
    };
    cpp_field_call_parts(function, src).is_some_and(|(receiver, _)| receiver == place)
        && expression
            .child_by_field_name("arguments")
            .is_some_and(|arguments| cpp_direct_named_children(arguments).is_empty())
}

fn cpp_related_static_call_evidence(guarded_call: Node<'_>, calls: &[Node<'_>], src: &[u8]) -> Vec<String> {
    let guarded_args = guarded_call
        .child_by_field_name("arguments")
        .map(cpp_direct_named_children)
        .unwrap_or_default();
    let Some(receiver) = guarded_args.first().map(|arg| node_text(arg, src).trim()) else {
        return Vec::new();
    };
    let mut evidence = Vec::new();
    for related in calls
        .iter()
        .copied()
        .filter(|call| call.id() != guarded_call.id())
    {
        let Some(callee) = related.child_by_field_name("function") else {
            continue;
        };
        let args = related
            .child_by_field_name("arguments")
            .map(cpp_direct_named_children)
            .unwrap_or_default();
        if args.first().map(|arg| node_text(arg, src).trim()) != Some(receiver) {
            continue;
        }
        let name = node_text(&callee, src).trim();
        evidence.push(format!("related-call:{name}:argument:0=guarded-argument:0"));
        for (index, argument) in args.iter().copied().enumerate().skip(1) {
            let value = match argument.kind() {
                "number_literal" => cpp_integer_literal(argument, src).map(|value| format!("number:{value}")),
                "identifier" => Some(format!("place:{}", node_text(&argument, src).trim())),
                _ => None,
            };
            if let Some(value) = value {
                evidence.push(format!("related-call:{name}:argument:{index}={value}"));
            }
        }
    }
    evidence
}

fn cpp_has_ancestor_kind(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
}

fn cpp_descendants_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.id() != root.id() && node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    out
}

fn cpp_direct_named_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn cpp_first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let child = node.named_children(&mut cursor).next();
    child
}

/// C++ `break` exits the nearest loop or switch. The shared structured HIR
/// already represents a switch as one mutually exclusive `Branch`; retaining
/// the switch-local `Break` as a function/loop terminator would incorrectly
/// make every statement after the switch unreachable. Resolve the target from
/// Tree-sitter ancestors and remove only switch-targeted break events, while
/// truncating source events after that break within the same arm.
fn collect_cpp_switch_break_spans(tree: &Tree, file: FileId, _src: &[u8]) -> std::collections::HashSet<Span> {
    let mut out = std::collections::HashSet::new();
    for break_node in collect_kinds(tree, &["break_statement"]) {
        let mut current = break_node.parent();
        while let Some(ancestor) = current {
            if matches!(
                ancestor.kind(),
                "for_statement" | "for_range_loop" | "while_statement" | "do_statement"
            ) {
                break;
            }
            if ancestor.kind() == "switch_statement" {
                out.insert(span_of(file, &break_node));
                break;
            }
            if ancestor.kind() == "function_definition" {
                break;
            }
            current = ancestor.parent();
        }
    }
    out
}

fn populate_cpp_condition_expressions(
    facts: &mut [BranchConditionFact],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    for branch in collect_kinds(tree, &["if_statement"]) {
        let branch_span = span_of(file, &branch);
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        let Some(fact) = facts.iter_mut().find(|fact| fact.branch_span == branch_span) else {
            continue;
        };
        let expression = lower_cpp_condition_expression(condition, file, src);
        fact.polarity = if matches!(expression, ConditionExpressionFact::Not { .. }) {
            BranchConditionPolarity::Negated
        } else {
            BranchConditionPolarity::Positive
        };
        fact.expression = Some(expression);
    }
}

fn lower_cpp_condition_expression(mut node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    while matches!(node.kind(), "condition_clause" | "parenthesized_expression")
        && node.named_child_count() == 1
    {
        let Some(inner) = node.named_child(0) else {
            break;
        };
        node = inner;
    }
    let span = span_of(file, &node);
    if let Some(operand) = node
        .child_by_field_name("argument")
        .filter(|_| cpp_operator_between_children(node, src).as_deref() == Some("!"))
    {
        return ConditionExpressionFact::Not {
            span,
            operand: Box::new(lower_cpp_condition_expression(operand, file, src)),
        };
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left").or_else(|| node.named_child(0)),
        node.child_by_field_name("right").or_else(|| node.named_child(1)),
    ) else {
        return ConditionExpressionFact::Atom { span };
    };
    match cpp_operator_between(left, right, src).as_deref() {
        Some("&&") => merge_cpp_condition(
            span,
            true,
            lower_cpp_condition_expression(left, file, src),
            lower_cpp_condition_expression(right, file, src),
        ),
        Some("||") => merge_cpp_condition(
            span,
            false,
            lower_cpp_condition_expression(left, file, src),
            lower_cpp_condition_expression(right, file, src),
        ),
        Some(operator @ ("==" | "!=")) => ConditionExpressionFact::Equality {
            span,
            relation: if operator == "==" {
                ConditionEquality::Equal
            } else {
                ConditionEquality::NotEqual
            },
            left: cpp_condition_operand(left, file, src),
            right: cpp_condition_operand(right, file, src),
        },
        _ => ConditionExpressionFact::Atom { span },
    }
}

fn cpp_operator_between_children(node: Node<'_>, src: &[u8]) -> Option<String> {
    let first = node.named_child(0)?;
    src.get(node.start_byte()..first.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim)
        .filter(|operator| !operator.is_empty())
        .map(ToOwned::to_owned)
}

fn cpp_operator_between(left: Node<'_>, right: Node<'_>, src: &[u8]) -> Option<String> {
    src.get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim)
        .filter(|operator| !operator.is_empty())
        .map(ToOwned::to_owned)
}

fn merge_cpp_condition(
    span: Span,
    all: bool,
    left: ConditionExpressionFact,
    right: ConditionExpressionFact,
) -> ConditionExpressionFact {
    let mut operands = Vec::new();
    let mut push = |operand| match (all, operand) {
        (true, ConditionExpressionFact::All { operands: nested, .. })
        | (false, ConditionExpressionFact::Any { operands: nested, .. }) => operands.extend(nested),
        (_, operand) => operands.push(operand),
    };
    push(left);
    push(right);
    if all {
        ConditionExpressionFact::All { span, operands }
    } else {
        ConditionExpressionFact::Any { span, operands }
    }
}

fn cpp_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    let direct_call_span = (node.kind() == "call_expression")
        .then(|| cpp_call_target(node, src).map(|target| span_of(file, &target.node)))
        .flatten();
    ConditionOperandFact {
        span: span_of(file, &node),
        direct_call_span,
        value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER),
        static_string: cpp_static_string_literal(node, src),
        static_value: cpp_static_scalar(node, src),
    }
}

fn cpp_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "string_literal" => cpp_static_string_literal(node, src).map(StaticScalarValue::String),
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "null" | "nullptr" => Some(StaticScalarValue::Null),
        "number_literal" => node_text(&node, src)
            .trim()
            .parse::<i64>()
            .ok()
            .map(StaticScalarValue::Integer),
        _ => None,
    }
}

fn cpp_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains('\\')).then(|| inner.to_string())
}

fn cpp_string_compositions(tree: &Tree, file: FileId, src: &[u8]) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for expression in collect_kinds(tree, &["binary_expression"]) {
        let mut parts = Vec::new();
        if lower_cpp_string_composition(expression, src, &mut parts)
            && parts.len() > 1
            && parts
                .iter()
                .any(|part| matches!(part, StringCompositionPart::Literal { .. }))
        {
            let span = span_of(file, &expression);
            facts.push(StringCompositionFact {
                container_span: span,
                value_span: span,
                dynamic_anchor_span: None,
                target: None,
                parts,
            });
        }
    }
    facts
}

fn lower_cpp_string_composition(node: Node<'_>, src: &[u8], out: &mut Vec<StringCompositionPart>) -> bool {
    if node.kind() == "binary_expression" {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        if cpp_operator_between(left, right, src).as_deref() != Some("+") {
            return false;
        }
        return lower_cpp_string_composition(left, src, out) && lower_cpp_string_composition(right, src, out);
    }
    if let Some(value) = cpp_static_string_literal(node, src) {
        out.push(StringCompositionPart::Literal { value });
        return true;
    }
    let place = node_text(&node, src).trim();
    if place.is_empty()
        || !matches!(
            node.kind(),
            "identifier" | "field_identifier" | "qualified_identifier" | "field_expression"
        )
    {
        return false;
    }
    out.push(StringCompositionPart::Place {
        place: place.to_string(),
    });
    true
}

/// Extend file-stem semantic identities with exact named C++ namespace
/// ancestry.
///
/// The shared file-stem identity is the correct linkage root for a translation
/// unit, but a scoped call such as `net::get(value)` must resolve to a
/// definition nested in `namespace net { ... }`. Tree-sitter preserves the
/// namespace-definition ancestor for every declaration, including compact
/// nested namespace syntax (`namespace a::b`). Anonymous namespaces add no
/// public path segment; their translation-unit privacy is handled separately.
fn apply_cpp_namespace_semantic_identity(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let namespaces_by_span = collect_kinds(tree, &["function_definition"])
        .into_iter()
        .map(|function| {
            let mut ancestors = Vec::new();
            let mut current = function.parent();
            while let Some(node) = current {
                if node.kind() == "namespace_definition" {
                    ancestors.push(cpp_named_namespace_segments(&node, src));
                }
                current = node.parent();
            }
            ancestors.reverse();
            (
                span_of(file, &function),
                ancestors.into_iter().flatten().collect::<Vec<_>>(),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();

    for decl in &mut index.defs {
        let Some(namespaces) = namespaces_by_span.get(&decl.span) else {
            continue;
        };
        if namespaces.is_empty() {
            continue;
        }
        let mut segments = decl.module_path.segments.clone();
        segments.extend(namespaces.iter().cloned());
        decl.module_path = ModulePath {
            segments: segments.clone(),
        };
        segments.push(decl.name.clone());
        decl.qualified_name = Some(segments.join("."));
    }
}

fn cpp_named_namespace_segments(node: &Node<'_>, src: &[u8]) -> Vec<String> {
    let name = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        let name = node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "identifier" | "namespace_identifier" | "nested_namespace_specifier"
            )
        });
        name
    });
    let Some(name) = name else {
        return Vec::new();
    };
    node_text(&name, src)
        .split("::")
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Recover direct initialization from the C++ grammar's most-vexing-parse
/// ambiguity only when lexical value bindings prove constructor semantics.
///
/// Tree-sitter parses both `Type value(arg)` and a block-local prototype as a
/// `declaration/function_declarator`. If `arg` is already a parameter or a
/// preceding local value, however, it cannot be a type name in the same
/// namespace and the syntax is unambiguously direct initialization. This
/// compiler pass retains the constructor call and the constructed object's
/// value dependency without guessing a type or API spelling.
fn collect_cpp_locally_proven_direct_initializers(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    index: &DeclIndex,
) -> std::collections::HashMap<Span, Vec<FlowEvent>> {
    let mut by_function = std::collections::HashMap::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let function_span = span_of(file, &function);
        let Some(decl) = index.defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let mut bound = decl
            .params
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let mut events = Vec::new();
        let mut cursor = body.walk();
        for statement in body.named_children(&mut cursor) {
            if statement.kind() != "declaration" {
                continue;
            }
            let Some(type_node) = statement.child_by_field_name("type") else {
                continue;
            };
            let Some(declarator) = statement.child_by_field_name("declarator") else {
                continue;
            };
            if declarator.kind() != "function_declarator" {
                if let Some(identifier) = cpp_binding_identifier(declarator) {
                    bound.insert(node_text(&identifier, src).trim().to_string());
                }
                continue;
            }
            let Some(binding_node) = declarator
                .child_by_field_name("declarator")
                .and_then(cpp_binding_identifier)
            else {
                continue;
            };
            let binding = node_text(&binding_node, src).trim().to_string();
            let Some(arguments) = declarator.child_by_field_name("parameters") else {
                continue;
            };
            let mut args = Vec::new();
            let mut proves_value_argument = false;
            let mut argument_cursor = arguments.walk();
            for parameter in arguments.named_children(&mut argument_cursor) {
                let Some(value) = parameter.child_by_field_name("type") else {
                    continue;
                };
                let value_text = node_text(&value, src).trim().to_string();
                let mut source_names = expression_operand_names_with_handler(&value, src, &HANDLER)
                    .into_iter()
                    .filter(|name| bound.contains(name))
                    .collect::<Vec<_>>();
                // In the ambiguous `Type value(arg)` production, the C++
                // grammar classifies a single bare `arg` as the parameter's
                // type node. Lexical binding is the disambiguating compiler
                // fact: a preceding value binding cannot simultaneously be a
                // type in this scope. Retain that exact value dependency even
                // though the CST labels the token as a type identifier.
                if bound.contains(&value_text) && !source_names.contains(&value_text) {
                    source_names.push(value_text.clone());
                }
                if !source_names.is_empty() {
                    proves_value_argument = true;
                }
                args.push(CallArg {
                    span: span_of(file, &parameter),
                    passing_mode: ArgumentPassingMode::Value,
                    name: None,
                    place: bound.contains(&value_text).then_some(value_text.clone()),
                    value_text,
                    source_names,
                });
            }
            if !proves_value_argument || args.is_empty() {
                // A block-local declaration such as `Type f(Other)` remains
                // a prototype unless lexical value facts disambiguate it.
                continue;
            }
            let Some(type_name) = cpp_type_descriptor_name(&type_node, src) else {
                continue;
            };
            let sources = args
                .iter()
                .flat_map(|arg| arg.source_names.iter().cloned())
                .collect::<Vec<_>>();
            let call_span = span_of(file, &arguments);
            events.push(FlowEvent::Call {
                span: call_span,
                receiver: None,
                receiver_types: Vec::new(),
                name: type_name,
                call_kind: CallKind::Constructor,
                args,
            });
            events.push(FlowEvent::Assign {
                span: span_of(file, &statement),
                target: binding.clone(),
                source_name: (sources.len() == 1).then(|| sources[0].clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: if sources.len() != 1 {
                    sources
                } else {
                    Default::default()
                },
                declares_new_binding: true,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Unknown),
            });
            bound.insert(binding);
        }
        if !events.is_empty() {
            events.sort_by_key(|event| (event.span().start, event.span().end));
            by_function.insert(function_span, events);
        }
    }
    by_function
}

/// C++ direct-list initialization with one value of the declared type is copy
/// construction, not positional aggregate initialization:
/// `Envelope valid{env}` carries the whole object. Tree-sitter deliberately
/// uses the same `initializer_list` node as `Envelope env{kind, cmd}`, so the
/// adapter resolves the distinction from its parsed declaration types before
/// shared aggregate lowering assigns positional field names.
fn collapse_cpp_same_type_copy_initializers(events: &mut Vec<FlowEvent>, aliases: &[TypeAliasBinding]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collapse_cpp_same_type_copy_initializers(then_events, aliases);
                collapse_cpp_same_type_copy_initializers(else_events, aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collapse_cpp_same_type_copy_initializers(body, aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collapse_cpp_same_type_copy_initializers(body, aliases);
                collapse_cpp_same_type_copy_initializers(catch_events, aliases);
                collapse_cpp_same_type_copy_initializers(finally_events, aliases);
            }
            _ => {}
        }
    }
    events.retain(|event| {
        let FlowEvent::AggregateAssign {
            target,
            type_name,
            value_flow,
            ..
        } = event
        else {
            return true;
        };
        if !value_flow.aggregate_fields.is_empty()
            || !value_flow.spreads.is_empty()
            || value_flow.tuple_items.len() != 1
        {
            return true;
        }
        let Some(source) = value_flow.tuple_items[0].place.as_deref() else {
            return true;
        };
        let declared_type = type_name.as_deref().or_else(|| {
            aliases
                .iter()
                .find(|alias| alias.name == *target)
                .map(|alias| alias.type_name.as_str())
        });
        let source_type = aliases
            .iter()
            .find(|alias| alias.name == source)
            .map(|alias| alias.type_name.as_str());
        let (Some(declared_type), Some(source_type)) = (declared_type, source_type) else {
            return true;
        };
        bonsai_lang_api::kit::canonical_simple_type_name(declared_type)
            != bonsai_lang_api::kit::canonical_simple_type_name(source_type)
    });
}

fn collect_cpp_constructor_initializer_events(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<FlowEvent>)> {
    let mut out = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let Some(initializers) = first_named_child_of_kind(&function, "field_initializer_list") else {
            continue;
        };
        let events = walk_flow_events(initializers, file, src, &HANDLER, &[]);
        if !events.is_empty() {
            out.push((span_of(file, &function), events));
        }
    }
    out
}

/// Preserve object identity through a parsed move expression nested inside a
/// larger call argument (`run(std::move(env))`). Lifecycle injection has
/// already classified the inner call from the adapter-owned C++ semantics;
/// this pass uses only that semantic event plus AST spans to mark the outer
/// argument as the same addressable place. The IDG can then forward exact
/// descendant fields without knowing any library function names.
fn apply_cpp_moved_argument_places(events: &mut [FlowEvent]) {
    let mut moved = Vec::new();
    collect_cpp_moved_events(events, &mut moved);
    apply_cpp_moved_argument_places_with_events(events, &moved);
}

fn collect_cpp_moved_events(events: &[FlowEvent], out: &mut Vec<(Span, String)>) {
    for event in events {
        match event {
            FlowEvent::Lifecycle {
                span,
                name,
                transition,
            } if transition == "moved" && !name.is_empty() => out.push((*span, name.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_cpp_moved_events(then_events, out);
                collect_cpp_moved_events(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_cpp_moved_events(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_cpp_moved_events(body, out);
                collect_cpp_moved_events(catch_events, out);
                collect_cpp_moved_events(finally_events, out);
            }
            _ => {}
        }
    }
}

fn apply_cpp_moved_argument_places_with_events(events: &mut [FlowEvent], moved: &[(Span, String)]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    if arg.place.is_some() {
                        continue;
                    }
                    let candidate = moved.iter().find_map(|(span, name)| {
                        (arg.span.file == span.file
                            && arg.span.start <= span.start
                            && span.end <= arg.span.end
                            && arg.source_names.iter().any(|source| source == name))
                        .then_some(name)
                    });
                    if let Some(candidate) = candidate {
                        arg.place = Some(candidate.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_cpp_moved_argument_places_with_events(then_events, moved);
                apply_cpp_moved_argument_places_with_events(else_events, moved);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_cpp_moved_argument_places_with_events(body, moved);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_cpp_moved_argument_places_with_events(body, moved);
                apply_cpp_moved_argument_places_with_events(catch_events, moved);
                apply_cpp_moved_argument_places_with_events(finally_events, moved);
            }
            _ => {}
        }
    }
}

/// C++ constructors are identified by the grammar-owned class/member
/// relationship: a member whose identifier equals its parent class identifier
/// is a constructor.  This uses declaration identity emitted from the CST;
/// downstream resolution never guesses from capitalization or a name list.
fn mark_cpp_constructors(decl_index: &mut DeclIndex) {
    let class_names = decl_index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.symbol, decl.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    for decl in &mut decl_index.defs {
        if !matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
            continue;
        }
        let Some(parent_name) = decl.parent.and_then(|parent| class_names.get(&parent)) else {
            continue;
        };
        if decl.name == *parent_name {
            decl.kind = DeclKind::Constructor;
            if decl.implicit_receiver_names.is_empty() {
                decl.implicit_receiver_names.push("this".to_string());
            }
        }
    }
}

fn collect_cpp_class_fields(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String, Vec<String>)> {
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, &["class_specifier", "struct_specifier", "union_specifier"]) {
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "type_identifier"))
        else {
            continue;
        };
        let Some(body) = class_node.child_by_field_name("body") else {
            continue;
        };
        let mut fields = Vec::new();
        let mut body_cursor = body.walk();
        for field_decl in body
            .named_children(&mut body_cursor)
            .filter(|child| child.kind() == "field_declaration")
        {
            for child_index in 0..field_decl.child_count() {
                if field_decl.field_name_for_child(child_index as u32) != Some("declarator") {
                    continue;
                }
                let Some(child) = field_decl.child(child_index as u32) else {
                    continue;
                };
                if !child.is_named() || cpp_declarator_is_function(child) {
                    continue;
                }
                if let Some(identifier) = cpp_binding_identifier(child) {
                    let name = node_text(&identifier, src).trim();
                    if !name.is_empty() && !fields.iter().any(|field| field == name) {
                        fields.push(name.to_string());
                    }
                }
            }
        }
        if !fields.is_empty() {
            out.push((
                span_of(file, &class_node),
                node_text(&name_node, src).trim().to_string(),
                fields,
            ));
        }
    }
    out
}

fn cpp_declarator_is_function(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "function_declarator" {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn cpp_binding_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if matches!(node.kind(), "identifier" | "field_identifier") {
        return Some(node);
    }
    for field in ["declarator", "name"] {
        if let Some(child) = node.child_by_field_name(field) {
            if let Some(identifier) = cpp_binding_identifier(child) {
                return Some(identifier);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(identifier) = cpp_binding_identifier(child) {
            return Some(identifier);
        }
    }
    None
}

fn cpp_fields_by_parent_symbol(
    index: &DeclIndex,
    fields_by_class: &[(Span, String, Vec<String>)],
) -> std::collections::HashMap<bonsai_common::SymbolId, std::collections::HashSet<String>> {
    index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .filter_map(|decl| {
            fields_by_class
                .iter()
                .find(|(span, name, _)| *span == decl.span || *name == decl.name)
                .map(|(_, _, fields)| (decl.symbol, fields.iter().cloned().collect()))
        })
        .collect()
}

/// Collect every C++ function name that's TU-private:
///
/// - Function definitions with a `static` storage class specifier.
/// - Function definitions whose body lives inside an anonymous
///   `namespace { ... }` block (no namespace identifier).
fn collect_tu_private_function_names(tree: &Tree, src: &[u8]) -> std::collections::HashSet<String> {
    let mut private_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let root = tree.root_node();
    walk_for_tu_private(root, src, false, &mut private_names);
    private_names
}

#[derive(Clone, Debug)]
struct CppInitializerFieldSpec {
    span: Span,
    field: String,
    sources: Vec<String>,
}

fn collect_cpp_initializer_field_specs(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<CppInitializerFieldSpec>)> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_definition"]) {
        let Some(initializers) = first_named_child_of_kind(&fn_node, "field_initializer_list") else {
            continue;
        };
        let mut specs = Vec::new();
        let mut cursor = initializers.walk();
        for init in initializers.named_children(&mut cursor) {
            if init.kind() != "field_initializer" {
                continue;
            }
            let Some(field_node) = first_named_child_of_kind(&init, "field_identifier") else {
                continue;
            };
            let Some(value_node) = first_named_child_of_kind(&init, "argument_list") else {
                continue;
            };
            let field = node_text(&field_node, src).trim().to_string();
            let sources = expression_operand_names_with_handler(&value_node, src, &HANDLER);
            if field.is_empty() || sources.is_empty() {
                continue;
            }
            specs.push(CppInitializerFieldSpec {
                span: span_of(file, &init),
                field,
                sources,
            });
        }
        if !specs.is_empty() {
            out.push((span_of(file, &fn_node), specs));
        }
    }
    out
}

fn cpp_source_mentions_param(source: &str, param: &str) -> bool {
    let source = bonsai_common::normalize_qualified_name(source);
    let param = bonsai_common::normalize_qualified_name(param);
    source == param
        || source
            .strip_prefix(&param)
            .is_some_and(|projection| projection.starts_with('.'))
}

fn collect_cpp_member_visibility(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut out = std::collections::HashMap::new();
    for class_node in collect_kinds(tree, &["class_specifier", "struct_specifier"]) {
        let default_visibility = if class_node.kind() == "struct_specifier" {
            Visibility::Public
        } else {
            Visibility::Private
        };
        let mut current_visibility = default_visibility;
        if let Some(body) = class_node.child_by_field_name("body") {
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                if child.kind() == "access_specifier" {
                    current_visibility = cpp_access_visibility(node_text(&child, src), default_visibility);
                    continue;
                }
                if child.kind() == "function_definition" {
                    out.insert(span_of(file, &child), current_visibility);
                }
            }
        }
    }
    out
}

fn cpp_access_visibility(raw: &str, default_visibility: Visibility) -> Visibility {
    match raw.trim().trim_end_matches(':') {
        "public" => Visibility::Public,
        "protected" => Visibility::Protected,
        "private" => Visibility::Private,
        _ => default_visibility,
    }
}

/// Recursive walker tracking whether we're currently inside an
/// anonymous namespace; when we are, every nested function definition
/// counts as TU-private even without a `static` specifier.
fn walk_for_tu_private(
    root: Node<'_>,
    src: &[u8],
    inside_anonymous_ns: bool,
    private_names: &mut std::collections::HashSet<String>,
) {
    let mut stack = vec![(root, inside_anonymous_ns)];
    while let Some((node, inside_anonymous_ns)) = stack.pop() {
        if node.kind() == "function_definition"
            && (inside_anonymous_ns || function_has_static_specifier(&node, src))
        {
            if let Some(name) = function_name(&node, src) {
                private_names.insert(name);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // An anonymous namespace child flips the flag for the
            // subtree; inner namespaces inherit privacy.
            let entering_anonymous = inside_anonymous_ns
                || (child.kind() == "namespace_definition" && !namespace_is_named(&child));
            stack.push((child, entering_anonymous));
        }
    }
}

/// True when a `namespace_definition` has any identifier — a missing
/// name means the namespace is anonymous (TU-local).
fn namespace_is_named(node: &Node<'_>) -> bool {
    if node.child_by_field_name("name").is_some() {
        return true;
    }
    let mut cursor = node.walk();
    let has_identifier = node
        .children(&mut cursor)
        .any(|child| child.kind() == "namespace_identifier" || child.kind() == "identifier");
    has_identifier
}

/// True when `node` (a `function_definition`) carries a `static`
/// storage-class specifier as a direct child.
fn function_has_static_specifier(node: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" && node_text(&child, src) == "static" {
            return true;
        }
    }
    false
}

/// Resolve the bare function name from a `function_definition`'s
/// declarator chain. Falls through pointer / reference declarators.
fn function_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    extract_function_identifier(&declarator, src)
}

/// File-scope `using Alias = Type` declarations are compiler type facts, not
/// imports. Preserve their exact target spelling so typed locals and explicit
/// template arguments can be expanded without teaching shared analysis any
/// standard-library or provider names.
fn collect_cpp_translation_unit_type_aliases(
    tree: &Tree,
    src: &[u8],
) -> std::collections::HashMap<String, String> {
    let mut aliases = std::collections::HashMap::new();
    for declaration in collect_kinds(tree, &["alias_declaration"]) {
        if declaration
            .parent()
            .is_none_or(|parent| parent.kind() != "translation_unit")
        {
            continue;
        }
        let (Some(name), Some(target)) = (
            declaration.child_by_field_name("name"),
            declaration.child_by_field_name("type"),
        ) else {
            continue;
        };
        let name = node_text(&name, src).trim();
        let target = node_text(&target, src).trim();
        if !name.is_empty() && !target.is_empty() {
            aliases.insert(name.to_string(), target.to_string());
        }
    }
    aliases
}

fn resolve_cpp_translation_unit_type_alias(
    raw: &str,
    aliases: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let mut current = raw.trim();
    let mut seen = std::collections::HashSet::new();
    let mut resolved = None;
    while let Some(next) = aliases.get(current) {
        if !seen.insert(current.to_string()) {
            return None;
        }
        resolved = Some(next.clone());
        current = next.trim();
    }
    resolved
}

fn expand_cpp_type_alias_bindings(
    bindings: &mut Vec<TypeAliasBinding>,
    aliases: &std::collections::HashMap<String, String>,
) {
    let expanded = bindings
        .iter()
        .filter_map(|binding| {
            resolve_cpp_translation_unit_type_alias(&binding.type_name, aliases).map(|type_name| {
                TypeAliasBinding {
                    name: binding.name.clone(),
                    type_name,
                }
            })
        })
        .collect::<Vec<_>>();
    bindings.extend(expanded);
    bindings.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.type_name.cmp(&right.type_name))
    });
    bindings.dedup();
}

/// Refine a TU-private function template only when every call in the same
/// translation unit supplies the same explicit concrete type for a parameter.
/// Internal linkage proves there can be no unseen instantiation in another
/// file. A missing, deduced, mixed, or cyclic type argument leaves the generic
/// type untouched, so the shared body never borrows evidence from one call and
/// applies it to an incompatible specialization.
fn collect_cpp_private_template_substitutions(
    tree: &Tree,
    src: &[u8],
    aliases: &std::collections::HashMap<String, String>,
    private_functions: &std::collections::HashSet<String>,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    let mut definitions = std::collections::HashMap::<String, Vec<String>>::new();
    for template in collect_kinds(tree, &["template_declaration"]) {
        let mut template_cursor = template.walk();
        let Some(function) = template
            .named_children(&mut template_cursor)
            .find(|child| child.kind() == "function_definition")
        else {
            continue;
        };
        let Some(name) = function_name(&function, src) else {
            continue;
        };
        if !private_functions.contains(&name) {
            continue;
        }
        let Some(parameters) = template.child_by_field_name("parameters") else {
            continue;
        };
        let mut names = Vec::new();
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            if parameter.kind() != "type_parameter_declaration" {
                continue;
            }
            let Some(identifier) = cpp_first_descendant_of_kind(&parameter, "type_identifier") else {
                continue;
            };
            let identifier = node_text(&identifier, src).trim();
            if !identifier.is_empty() {
                names.push(identifier.to_string());
            }
        }
        if !names.is_empty() {
            definitions.insert(name, names);
        }
    }

    let mut invocations = std::collections::HashMap::<String, Vec<Option<Vec<String>>>>::new();
    for call in collect_kinds(tree, &["call_expression"]) {
        let Some(target) = call.child_by_field_name("function") else {
            continue;
        };
        let (name, arguments) = if target.kind() == "template_function" {
            let Some(name_node) = target.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(&name_node, src).trim().to_string();
            let arguments = target.child_by_field_name("arguments").map(|argument_list| {
                let mut values = Vec::new();
                let mut cursor = argument_list.walk();
                for argument in argument_list.named_children(&mut cursor) {
                    let rendered = node_text(&argument, src).trim();
                    if rendered.is_empty() {
                        continue;
                    }
                    values.push(
                        resolve_cpp_translation_unit_type_alias(rendered, aliases)
                            .unwrap_or_else(|| rendered.to_string()),
                    );
                }
                values
            });
            (name, arguments)
        } else {
            (cpp_call_target_without_template_arguments(target, src), None)
        };
        if definitions.contains_key(&name) {
            invocations.entry(name).or_default().push(arguments);
        }
    }

    let mut out = std::collections::HashMap::new();
    for (name, parameters) in definitions {
        let Some(calls) = invocations.get(&name).filter(|calls| !calls.is_empty()) else {
            continue;
        };
        let concrete_calls = calls.iter().filter_map(Option::as_ref).collect::<Vec<_>>();
        if concrete_calls.len() != calls.len()
            || concrete_calls
                .iter()
                .any(|arguments| arguments.len() != parameters.len())
        {
            continue;
        }
        let mut substitutions = std::collections::HashMap::new();
        let mut compatible = true;
        for (index, parameter) in parameters.iter().enumerate() {
            let first = concrete_calls[0][index].trim();
            if first.is_empty()
                || concrete_calls
                    .iter()
                    .skip(1)
                    .any(|arguments| arguments[index].trim() != first)
            {
                compatible = false;
                break;
            }
            substitutions.insert(parameter.clone(), first.to_string());
        }
        if compatible && !substitutions.is_empty() {
            out.insert(name, substitutions);
        }
    }
    out
}

fn apply_cpp_private_template_substitutions(
    decl: &mut bonsai_lang_api::Decl,
    substitutions: &std::collections::HashMap<String, String>,
    aliases: &std::collections::HashMap<String, String>,
) {
    let concrete = decl
        .type_aliases
        .iter()
        .filter_map(|binding| {
            substitutions
                .get(binding.type_name.trim())
                .map(|type_name| TypeAliasBinding {
                    name: binding.name.clone(),
                    type_name: resolve_cpp_translation_unit_type_alias(type_name, aliases)
                        .unwrap_or_else(|| type_name.clone()),
                })
        })
        .collect::<Vec<_>>();
    decl.type_aliases.extend(concrete);
    decl.type_aliases.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.type_name.cmp(&right.type_name))
    });
    decl.type_aliases.dedup();
    if let Some(return_type) = decl.return_type.as_deref() {
        if let Some(concrete) = substitutions.get(return_type.trim()) {
            decl.return_type = Some(
                resolve_cpp_translation_unit_type_alias(concrete, aliases)
                    .unwrap_or_else(|| concrete.clone()),
            );
        }
    }
}

/// Recursively unwrap a declarator subtree until a leaf identifier
/// surfaces. Includes destructor / operator names so e.g. `~Foo` or
/// `operator==` still produce a name.
fn extract_function_identifier(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier" | "field_identifier" | "destructor_name" | "operator_name"
    ) {
        return Some(node_text(node, src).to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = extract_function_identifier(&child, src) {
            return Some(found);
        }
    }
    None
}

/// True for decl kinds that may carry a base list — only those need
/// `bases` populated.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk C++ class / struct specifiers and collect bare base type
/// names. Grammar shape (verified):
///
///   `class Echo : public Base, private Other { … };` →
///     (class_specifier name: (type_identifier)
///        (base_class_clause (access_specifier) (type_identifier)
///                           (access_specifier) (type_identifier))
///        body: (field_declaration_list))
///
/// Within `base_class_clause`, parents are listed as
/// `type_identifier` / `qualified_identifier` / `template_type`
/// nodes (alternating with `access_specifier` keywords). Generic /
/// qualified bases collapse to the bare tail.
fn collect_cpp_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_specifier", "struct_specifier", "union_specifier"];
    for class_node in collect_kinds(tree, class_kinds) {
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "type_identifier"))
            .or_else(|| first_named_child_of_kind(&class_node, "identifier"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for class_child in class_node.named_children(&mut class_cursor) {
            // Bases live exclusively under the `base_class_clause`
            // child; everything else (the body, attributes, etc.) is
            // skipped.
            if class_child.kind() != "base_class_clause" {
                continue;
            }
            let mut clause_cursor = class_child.walk();
            for clause_child in class_child.named_children(&mut clause_cursor) {
                match clause_child.kind() {
                    "type_identifier" | "qualified_identifier" | "template_type" => {
                        if let Some(name) = canonical_cpp_base_name(node_text(&clause_child, src)) {
                            // Dedup so `class C : public Base, public Base` collapses.
                            if !bases.iter().any(|existing| existing == &name) {
                                bases.push(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), class_name.to_string(), bases));
        }
    }
    bases_by_class
}

/// WS2 cast typing for `auto`-LHS locals: `auto c = static_cast<Foo>(x)` and
/// `auto c = (Foo) x`. The kit's param-alias extractor already types the
/// declared-type form `Foo c = make()`, but NOT the inferred-`auto` form where
/// the class lives only on the cast initializer. Mirrors the Java/C#
/// `var c = (Foo) x` handling. Returns `(enclosing-fn span, binding)` pairs;
/// the fn span matches the function decl's `span` so the caller merges into
/// `decl.type_aliases`. Only fires when the declared type IS `auto`
/// (`placeholder_type_specifier`) — never clobbers a real declared type — and
/// reads the init_declarator's DIRECT `value` so a cast nested in a call
/// argument cannot mistype the local.
fn collect_cpp_cast_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, TypeAliasBinding)> {
    let mut out = Vec::new();
    for decl_node in collect_kinds(tree, &["declaration"]) {
        let Some(type_node) = decl_node.child_by_field_name("type") else {
            continue;
        };
        if type_node.kind() != "placeholder_type_specifier" {
            continue;
        }
        let Some(init) = first_named_child_of_kind(&decl_node, "init_declarator") else {
            continue;
        };
        let Some(decl_field) = init.child_by_field_name("declarator") else {
            continue;
        };
        let name_node = if decl_field.kind() == "identifier" {
            decl_field
        } else {
            match cpp_first_descendant_of_kind(&decl_field, "identifier") {
                Some(n) => n,
                None => continue,
            }
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let Some(value) = init.child_by_field_name("value") else {
            continue;
        };
        let Some(type_name) = cpp_cast_type_of_value(&value, src) else {
            continue;
        };
        let Some(fn_span) = cpp_enclosing_fn_span(&decl_node, file) else {
            continue;
        };
        out.push((fn_span, TypeAliasBinding { name, type_name }));
    }
    out
}

/// Cast target type of a direct initializer value, or `None` for any non-cast
/// shape. Handles C-style `(Foo) x` (`cast_expression`) and the `*_cast<Foo>(x)`
/// family (a `call_expression` whose `function` is a `template_function` named
/// `static_cast` / `reinterpret_cast` / `dynamic_cast` / `const_cast`).
fn cpp_cast_type_of_value(value: &Node<'_>, src: &[u8]) -> Option<String> {
    match value.kind() {
        "cast_expression" => {
            let type_node = value.child_by_field_name("type")?;
            cpp_type_descriptor_name(&type_node, src)
        }
        "call_expression" => {
            let func = value.child_by_field_name("function")?;
            if func.kind() != "template_function" {
                return None;
            }
            let name = func.child_by_field_name("name")?;
            if !matches!(
                node_text(&name, src).trim(),
                "static_cast" | "reinterpret_cast" | "dynamic_cast" | "const_cast"
            ) {
                return None;
            }
            let args = func.child_by_field_name("arguments")?;
            cpp_type_descriptor_name(&args, src)
        }
        _ => None,
    }
}

/// Bare tail name of the first `type_identifier` under a `type_descriptor` /
/// `template_argument_list` node (`ns::Foo<T>*` → `Foo`).
fn cpp_type_descriptor_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let ti = if node.kind() == "type_identifier" {
        *node
    } else {
        cpp_first_descendant_of_kind(node, "type_identifier")?
    };
    canonical_cpp_base_name(node_text(&ti, src))
}

/// First descendant found by an iterative syntax-tree walk, or `None`.
fn cpp_first_descendant_of_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            if child.kind() == kind {
                return Some(child);
            }
            stack.push(child);
        }
    }
    None
}

/// Span of the nearest enclosing `function_definition` (matches the function
/// decl's `span` so cast aliases merge into the right method's type_aliases).
fn cpp_enclosing_fn_span(node: &Node<'_>, file: FileId) -> Option<bonsai_common::Span> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "function_definition" {
            return Some(span_of(file, &n));
        }
        cur = n.parent();
    }
    None
}

/// Reduce a base-class type expression to its bare tail identifier:
/// strip template arguments and namespace qualifiers so
/// `ns::Base<T>` → `Base`.
fn canonical_cpp_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let without_template = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = without_template
        .rsplit("::")
        .next()
        .unwrap_or(without_template)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Translate `#include` directives and `using` declarations into
/// `ImportSpec`s. The two flavours produce indistinguishable
/// downstream lookups; `using namespace` is recorded as a wildcard import.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = c_family_preproc_imports(tree, src, file);
    // C-style preproc_include + C++ `using namespace X;` / `using X::Y;`.
    for using_node in collect_kinds(tree, &["using_declaration"]) {
        // The path is the declaration's single named child. The anonymous
        // `namespace` token distinguishes the wildcard form, so semantic
        // classification never depends on re-tokenizing statement text.
        //
        //   * `using namespace X::Y;` — wildcard import; brings every
        //     name in `X::Y` into scope, no single local binding.
        //   * `using X::Y::Z;`        — single-symbol import; binds
        //     `Z` locally to `X::Y::Z`.
        let is_wildcard_namespace = (0..using_node.child_count())
            .filter_map(|index| u32::try_from(index).ok())
            .any(|index| {
                using_node
                    .child(index)
                    .is_some_and(|child| child.kind() == "namespace")
            });
        let mut path_cursor = using_node.walk();
        let Some(path_node) = using_node
            .named_children(&mut path_cursor)
            .find(|child| matches!(child.kind(), "identifier" | "qualified_identifier"))
        else {
            continue;
        };
        let mut path_segments = cpp_import_path_segments(path_node, src);
        if path_segments.is_empty() {
            continue;
        }
        if is_wildcard_namespace {
            imports.push(ImportSpec {
                span: span_of(file, &using_node),
                module: path_segments.join("::"),
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Module,
            });
        } else if let Some(original_name) = path_segments.pop() {
            imports.push(ImportSpec {
                span: span_of(file, &using_node),
                module: path_segments.join("::"),
                alias: None,
                is_wildcard: false,
                original_name: Some(original_name),
                scope: ImportScope::Module,
            });
        }
    }
    // C++ `namespace h = util;` — explicit namespace alias. The
    // `name` field is the local alias (`h`); the `aliased` /
    // `value` field is the original namespace identifier (`util`).
    // Bind `h` as a `Namespace` target so `h::helper(...)` resolves
    // to `util::helper(...)`.
    for alias_node in collect_kinds(tree, &["namespace_alias_definition"]) {
        let alias_name_node = alias_node.child_by_field_name("name").or_else(|| {
            let mut cursor = alias_node.walk();
            let mut found = None;
            for child in alias_node.named_children(&mut cursor) {
                if matches!(child.kind(), "identifier" | "namespace_identifier") {
                    found = Some(child);
                    break;
                }
            }
            found
        });
        let module_name_node = alias_node
            .child_by_field_name("aliased")
            .or_else(|| alias_node.child_by_field_name("value"))
            .or_else(|| {
                let alias_name_node = alias_name_node?;
                let mut cursor = alias_node.walk();
                let target = alias_node.named_children(&mut cursor).find(|child| {
                    *child != alias_name_node
                        && matches!(
                            child.kind(),
                            "namespace_identifier" | "nested_namespace_specifier"
                        )
                });
                target
            });
        let (Some(alias_name_node), Some(module_name_node)) = (alias_name_node, module_name_node) else {
            continue;
        };
        let alias_name = node_text(&alias_name_node, src).trim().to_string();
        let module = node_text(&module_name_node, src).trim().to_string();
        if alias_name.is_empty() || module.is_empty() || alias_name == module {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &alias_node),
            module,
            alias: Some(alias_name),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn cpp_import_path_segments(path: Node<'_>, src: &[u8]) -> Vec<String> {
    if path.kind() == "qualified_identifier" {
        let mut segments = path
            .child_by_field_name("scope")
            .map(|scope| cpp_import_path_segments(scope, src))
            .unwrap_or_default();
        if let Some(name) = path.child_by_field_name("name") {
            segments.extend(cpp_import_path_segments(name, src));
        }
        return segments;
    }
    if path.kind() == "nested_namespace_specifier" {
        let mut segments = Vec::new();
        let mut cursor = path.walk();
        for child in path.named_children(&mut cursor) {
            segments.extend(cpp_import_path_segments(child, src));
        }
        return segments;
    }
    let segment = node_text(&path, src).trim();
    if segment.is_empty() {
        Vec::new()
    } else {
        vec![segment.to_string()]
    }
}

/// Complete exception facts on C++ `Throw` / `Try` events. The kit's generic
/// extractor returns the first identifier descendant of the catch
/// clause, which on `catch (const std::exception& e)` is the type
/// identifier rather than the binding. We re-extract the binding
/// from the parse tree via the standard `parameter_declaration` →
/// `declarator` → identifier chain, and retain each arm's exact declared
/// type. Throw constructors are typed from their parsed call target.
fn populate_cpp_exception_facts(events: &mut [bonsai_lang_api::FlowEvent], tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Throw {
                span, thrown_type, ..
            } => {
                if thrown_type.is_none() {
                    if let Some(node) =
                        bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["throw_statement"])
                    {
                        *thrown_type = cpp_thrown_type(node, src);
                    }
                }
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
                catch_arms,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if let Some(name) = cpp_catch_param_binding(node, src) {
                        *catch_param = Some(name);
                    }
                    if catch_types.is_empty() {
                        *catch_types = cpp_catch_types(node, src);
                    }
                    for arm in catch_arms {
                        if let Some(clause) =
                            bonsai_lang_api::kit::node_at_span(tree.root_node(), arm.span, &["catch_clause"])
                        {
                            arm.parameter = cpp_catch_clause_param_binding(clause, src);
                            arm.types = cpp_catch_clause_types(clause, src);
                        }
                    }
                }
                populate_cpp_exception_facts(body, tree, src);
                populate_cpp_exception_facts(catch_events, tree, src);
                populate_cpp_exception_facts(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_cpp_exception_facts(then_events, tree, src);
                populate_cpp_exception_facts(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_cpp_exception_facts(body, tree, src);
            }
            _ => {}
        }
    }
}

fn cpp_thrown_type(throw_node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = throw_node.walk();
    let expression = throw_node
        .child_by_field_name("expression")
        .or_else(|| throw_node.named_children(&mut cursor).next())?;
    let type_node = if expression.kind() == "call_expression" {
        expression.child_by_field_name("function")?
    } else {
        expression
    };
    let ty = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&type_node, src));
    (!ty.is_empty()).then_some(ty)
}

fn cpp_catch_types(try_node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut types = Vec::new();
    let mut cursor = try_node.walk();
    for clause in try_node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "catch_clause")
    {
        types.extend(cpp_catch_clause_types(clause, src));
    }
    types.sort();
    types.dedup();
    types
}

fn cpp_catch_clause_types(clause: Node<'_>, src: &[u8]) -> Vec<String> {
    let Some(parameter) = cpp_catch_parameter_declaration(clause) else {
        return Vec::new();
    };
    let Some(type_node) = parameter.child_by_field_name("type") else {
        return Vec::new();
    };
    let ty = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&type_node, src));
    if ty.is_empty() {
        Vec::new()
    } else {
        vec![ty]
    }
}

fn cpp_catch_param_binding(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut tcur = try_node.walk();
    for child in try_node.named_children(&mut tcur) {
        if child.kind() != "catch_clause" {
            continue;
        }
        if let Some(binding) = cpp_catch_clause_param_binding(child, src) {
            return Some(binding);
        }
    }
    None
}

fn cpp_catch_clause_param_binding(clause: Node<'_>, src: &[u8]) -> Option<String> {
    let parameter = cpp_catch_parameter_declaration(clause)?;
    let declarator = parameter.child_by_field_name("declarator")?;
    let identifier = first_identifier_descendant_cpp(declarator)?;
    let binding = node_text(&identifier, src).trim();
    (!binding.is_empty()).then(|| binding.to_string())
}

fn cpp_catch_parameter_declaration(clause: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            return Some(child);
        }
        if child.kind() == "parameter_list" {
            let mut parameters = child.walk();
            let parameter = child
                .named_children(&mut parameters)
                .find(|candidate| candidate.kind() == "parameter_declaration");
            if let Some(parameter) = parameter {
                return Some(parameter);
            }
        }
    }
    None
}

fn first_identifier_descendant_cpp<'a>(node: Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "identifier" || node.kind() == "field_identifier" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_identifier_descendant_cpp(child) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod import_tests {
    use super::*;

    fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
        let language = language_from_pack(PACK_NAME).expect("cpp grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set cpp grammar");
        let tree = parser.parse(src.as_bytes(), None).expect("parse cpp source");
        parse_imports(&tree, src.as_bytes(), FileId::new(0))
    }

    #[test]
    fn using_declarations_are_lowered_from_cst_nodes() {
        let imports = parse_import_specs(
            "using /* trivia */ namespace alpha::beta;\n\
             using alpha::beta::Thing;\n\
             namespace short_name = alpha::beta;\n",
        );

        assert!(imports
            .iter()
            .any(|spec| spec.module == "alpha::beta" && spec.is_wildcard));
        assert!(imports.iter().any(|spec| {
            spec.module == "alpha::beta"
                && spec.alias.is_none()
                && spec.original_name.as_deref() == Some("Thing")
        }));
        assert!(imports.iter().any(|spec| {
            spec.module == "alpha::beta"
                && spec.alias.as_deref() == Some("short_name")
                && spec.original_name.is_none()
        }));
    }
}
