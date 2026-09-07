//! Python language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        call_arg_from_nodes_with_handler, collect_kinds, expression_flow_from_node_with_handler,
        language_from_pack, node_text, normalize_call_name_whitespace, parse_with, span_of,
    },
    AdapterContext, AdapterError, CallKind, CallTargetExtraction, CharacterClass, CharacterConstraintDomain,
    CharacterConstraintFact, CharacterConstraintOutput, CharacterSubstitutionDomain,
    CharacterSubstitutionFact, Comment, CommentKind, ConditionEquality, ConditionExpressionFact,
    ConditionOperandFact, DeclIndex, DeclKind, ExpressionFlow, FiniteLiteralSelectionFact, FlowEvent,
    GrammarHandler, GuardedPredicateCallFact, GuardedValueConstraintFact, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, PatternSourceProjection,
    ProjectedPatternBindingSite, Ref, RefKind, StaticScalarValue, StaticStringMapEntry,
    StringCompositionFact, StringCompositionPart, TypeAliasBinding, Visibility, EMPTY_HANDLER,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("python");
const PACK_NAME: &str = "python";

fn python_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() != "call" {
        return None;
    }
    let target = node.child_by_field_name("function")?;
    let full_text = node_text(&target, src).trim();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text: full_text.to_string(),
    })
}

fn python_pattern_bindings<'tree>(node: Node<'tree>, src: &[u8]) -> Vec<ProjectedPatternBindingSite<'tree>> {
    if node.kind() != "match_statement" {
        return Vec::new();
    }
    let Some(source) = node.child_by_field_name("subject") else {
        return Vec::new();
    };
    let mut sites = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.id() != node.id() && current.kind() == "match_statement" {
            continue;
        }
        if current.kind() == "case_clause" {
            let mut cursor = current.walk();
            for pattern in current
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "case_pattern")
            {
                // The capture is established by the pattern header, before
                // the case body executes.  Using the whole `case_clause`
                // span would place the synthetic write after calls in its
                // body when the IDG orders transfers by source span.
                collect_python_pattern_bindings(pattern, pattern, source, &[], src, &mut sites);
            }
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    sites
}

fn collect_python_pattern_bindings<'tree>(
    pattern: Node<'tree>,
    span_node: Node<'tree>,
    source: Node<'tree>,
    projection: &[PatternSourceProjection],
    src: &[u8],
    out: &mut Vec<ProjectedPatternBindingSite<'tree>>,
) {
    match pattern.kind() {
        "case_pattern" => {
            if let Some(child) = pattern.named_child(0) {
                collect_python_pattern_bindings(child, span_node, source, projection, src, out);
            }
        }
        "dotted_name" => {
            let mut cursor = pattern.walk();
            let identifiers = pattern
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "identifier")
                .collect::<Vec<_>>();
            if identifiers.len() == 1 {
                push_python_pattern_binding(identifiers[0], span_node, source, projection, src, out);
            }
        }
        "identifier" => {
            push_python_pattern_binding(pattern, span_node, source, projection, src, out);
        }
        "dict_pattern" => {
            let mut pending_key = None;
            let mut cursor = pattern.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.is_named() {
                        match cursor.field_name() {
                            Some("key") => {
                                pending_key = Some(python_static_subscript_key(child, src).map_or(
                                    PatternSourceProjection::Descendants,
                                    PatternSourceProjection::Field,
                                ));
                            }
                            Some("value") => {
                                let mut child_projection = projection.to_vec();
                                child_projection
                                    .push(pending_key.take().unwrap_or(PatternSourceProjection::Descendants));
                                collect_python_pattern_bindings(
                                    child,
                                    span_node,
                                    source,
                                    &child_projection,
                                    src,
                                    out,
                                );
                            }
                            _ if child.kind() == "splat_pattern" => {
                                let mut child_projection = projection.to_vec();
                                child_projection.push(PatternSourceProjection::Descendants);
                                collect_python_pattern_bindings(
                                    child,
                                    span_node,
                                    source,
                                    &child_projection,
                                    src,
                                    out,
                                );
                            }
                            _ => {}
                        }
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        "class_pattern" => {
            let mut cursor = pattern.walk();
            let children = pattern.named_children(&mut cursor).collect::<Vec<_>>();
            for child in children.into_iter().skip(1) {
                let core = child.named_child(0).unwrap_or(child);
                let child_projection = if core.kind() == "keyword_pattern" {
                    projection.to_vec()
                } else {
                    let mut projected = projection.to_vec();
                    projected.push(PatternSourceProjection::Descendants);
                    projected
                };
                collect_python_pattern_bindings(child, span_node, source, &child_projection, src, out);
            }
        }
        "keyword_pattern" => {
            let mut cursor = pattern.walk();
            let children = pattern.named_children(&mut cursor).collect::<Vec<_>>();
            if let (Some(label), Some(value)) = (children.first(), children.get(1)) {
                let label = node_text(label, src).trim();
                let mut child_projection = projection.to_vec();
                if label.is_empty() {
                    child_projection.push(PatternSourceProjection::Descendants);
                } else {
                    child_projection.push(PatternSourceProjection::Field(label.to_string()));
                }
                collect_python_pattern_bindings(*value, span_node, source, &child_projection, src, out);
            }
        }
        "as_pattern" => {
            let alias_wrapper = pattern.child_by_field_name("alias");
            let mut cursor = pattern.walk();
            for child in pattern.named_children(&mut cursor) {
                if alias_wrapper.is_some_and(|alias| alias.id() == child.id()) {
                    if let Some(alias) = first_python_identifier(child) {
                        push_python_pattern_binding(alias, span_node, source, projection, src, out);
                    }
                } else {
                    collect_python_pattern_bindings(child, span_node, source, projection, src, out);
                }
            }
        }
        "list_pattern" | "tuple_pattern" => {
            let mut cursor = pattern.walk();
            let children = pattern.named_children(&mut cursor).collect::<Vec<_>>();
            let has_remainder = children.iter().any(|child| {
                child.kind() == "splat_pattern"
                    || child
                        .named_child(0)
                        .is_some_and(|nested| nested.kind() == "splat_pattern")
            });
            for (index, child) in children.into_iter().enumerate() {
                let mut child_projection = projection.to_vec();
                if has_remainder {
                    child_projection.push(PatternSourceProjection::Descendants);
                } else {
                    child_projection.push(PatternSourceProjection::Element(index));
                }
                collect_python_pattern_bindings(child, span_node, source, &child_projection, src, out);
            }
        }
        "splat_pattern" => {
            if let Some(target) = first_python_identifier(pattern) {
                push_python_pattern_binding(target, span_node, source, projection, src, out);
            }
        }
        "union_pattern" => {
            let mut cursor = pattern.walk();
            for child in pattern.named_children(&mut cursor) {
                collect_python_pattern_bindings(child, span_node, source, projection, src, out);
            }
        }
        _ => {}
    }
}

fn first_python_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "identifier" {
        return Some(node);
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if child.kind() == "identifier" {
                return Some(child);
            }
            stack.push(child);
        }
    }
    None
}

fn push_python_pattern_binding<'tree>(
    target: Node<'tree>,
    span_node: Node<'tree>,
    source: Node<'tree>,
    projection: &[PatternSourceProjection],
    src: &[u8],
    out: &mut Vec<ProjectedPatternBindingSite<'tree>>,
) {
    let name = node_text(&target, src).trim();
    if !python_match_capture_identifier(name) {
        return;
    }
    let site = ProjectedPatternBindingSite {
        span_node,
        target,
        source,
        projection: projection.to_vec(),
    };
    if !out.iter().any(|existing| {
        existing.target.id() == site.target.id()
            && existing.source.id() == site.source.id()
            && existing.projection == site.projection
    }) {
        out.push(site);
    }
}

fn python_using_alias(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "as_pattern" {
        return None;
    }
    let alias_wrapper = node.child_by_field_name("alias")?;
    let alias = if alias_wrapper.kind() == "identifier" {
        alias_wrapper
    } else {
        let mut cursor = alias_wrapper.walk();
        let alias = alias_wrapper
            .named_children(&mut cursor)
            .find(|child| child.kind() == "identifier");
        alias?
    };
    let mut cursor = node.walk();
    let value = node
        .named_children(&mut cursor)
        .find(|child| child.id() != alias_wrapper.id());
    Some((alias, value?))
}

fn python_comprehension_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for_in_clause" {
        return None;
    }
    // tree-sitter-python assigns the iteration target to `left` and the
    // evaluated iterable expression to `right`. These roles are semantic:
    // reversing them turns `[p for p in parts]` into the false overwrite
    // `parts = p`, which kills the real reaching definition of `parts`.
    let binding = node.child_by_field_name("left")?;
    let iterable = node.child_by_field_name("right")?;
    Some((binding, iterable))
}

fn python_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "for_statement")
        .then(|| {
            Some((
                node.child_by_field_name("left")?,
                node.child_by_field_name("right")?,
            ))
        })
        .flatten()
}

mod lexical_content;

const HANDLER: GrammarHandler = GrammarHandler {
    string_content_len: Some(lexical_content::string_content_len),
    comment_content_len: Some(lexical_content::comment_content_len),
    pseudo_call_receiver_role: bonsai_lang_api::CallReceiverRole::Value,
    literal_value_kinds: &["none", "integer", "float", "true", "false"],
    literal_value_spellings: &[],
    string_literal_kinds: &["string", "concatenated_string"],
    comment_kinds: &["comment"],
    doc_comment_kinds: &[],
    doc_comment_prefixes: &[],
    decorator_kinds: &["decorator"],
    parameter_container_kinds: &["parameters"],
    parameter_kinds: &[
        "identifier",
        "typed_parameter",
        "default_parameter",
        "typed_default_parameter",
        "list_splat_pattern",
        "dictionary_splat_pattern",
    ],
    parameter_modifier_kinds: &[],
    parameter_annotation_kinds: &["decorator"],
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
    pattern_head_value_kinds: &["class_pattern"],
    multi_segment_value_pattern_kinds: &["dotted_name"],
    non_binding_pattern_field_names: &["type", "key", "guard"],
    binding_name_extractor: None,
    binding_name_filter: None,
    pattern_binding_extractor: None,
    projected_pattern_binding_extractor: Some(python_pattern_bindings),
    anonymous_variadic_token: None,
    variadic_parameter_kinds: &["list_splat_pattern"],
    // Python 3 parameters cannot destructure collection patterns. `*args`
    // and `**kwargs` are handled by their exact parameter node kinds above.
    destructured_parameter_kinds: &[],
    identifier_kinds: &["identifier"],
    aggregate_pattern_kinds: &["pattern_list", "list_pattern", "tuple_pattern"],
    comprehension_kinds: &[
        "list_comprehension",
        "dictionary_comprehension",
        "set_comprehension",
        "generator_expression",
    ],
    comprehension_binding_clause_kinds: &["for_in_clause"],
    comprehension_binding_extractor: Some(python_comprehension_binding),
    named_aggregate_kinds: &["dictionary"],
    positional_aggregate_kinds: &["tuple", "list", "set"],
    aggregate_pair_kinds: &["pair", "dict_pattern"],
    two_child_aggregate_pair_kinds: &[],
    aggregate_pair_extractor: None,
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["identifier"],
    shorthand_field_kinds: &[],
    spread_kinds: &["list_splat", "dictionary_splat", "parenthesized_list_splat"],
    spread_value_field_names: &["value"],
    aggregate_syntax_only_kinds: &[],
    multi_child_aggregate_pattern_kinds: &[],
    lambda_value_container_kinds: &["dictionary", "list", "set"],
    transparent_call_wrapper_kinds: &["attribute", "subscript", "parenthesized_expression", "await"],
    single_expression_group_kinds: &["expression_list"],
    assignment_target_wrapper_kinds: &[],
    binding_declaration_keyword_spellings: &[],
    nested_type_ownership: true,
    fn_kinds: &["function_definition"],
    class_kinds: &["class_definition"],
    class_decl_kinds: &[("class_definition", DeclKind::Class)],
    method_kinds: &[],
    method_context_kinds: &["class_definition"],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: &["__init__"],
    function_definition_extractor: None,
    inline_closure_yield_extractor: None,
    if_kinds: &[
        "if_statement",
        "conditional_expression",
        "match_statement",
        "elif_clause",
    ],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "subject"],
    branch_condition_kinds: &[],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["and"],
    condition_any_operators: &["or"],
    condition_not_operators: &["not"],
    condition_not_operator_kinds: &[],
    branch_alias_extractor: None,
    branch_arm_kinds: &["block", "elif_clause", "else_clause"],
    exclusive_branch_arm_kinds: &["case_clause"],
    fallthrough_branch_arm_kinds: &[],
    additional_alternative_kinds: &["elif_clause", "else_clause"],
    for_kinds: &[],
    foreach_kinds: &["for_statement"],
    foreach_binding_extractor: Some(python_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &[],
    loop_kinds: &[],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &[],
    loop_condition_field_names: &["condition"],
    loop_condition_extractor: None,
    loop_kind_extractor: None,
    call_kinds: &["call"],
    constructor_call_kinds: &[],
    nested_call_component_kinds: &[],
    call_callee_field_names: &["function"],
    call_target_extractor: Some(python_call_target),
    call_receiver_extractor: None,
    call_receiver_field_names: &[],
    call_member_field_names: &[],
    constructor_type_field_names: &[],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    call_argument_wrapper_kinds: &[],
    call_callee_is_first_named_child: false,
    argument_wrapper_kinds: &["keyword_argument"],
    argument_name_field_names: &["name"],
    argument_value_field_names: &["value"],
    named_argument_extractor: None,
    direct_call_info_extractor: None,
    call_ref_node_filter: None,
    expression_call_span_extractor: None,
    writeback_operand_field_names: &[],
    direct_call_argument_excluded_fields: &[],
    transparent_expression_wrapper_kinds: &["parenthesized_expression"],
    pseudo_call_extractor: None,
    syntax_event_extractor: None,
    syntax_events_extractor: None,
    call_encoded_control_flow_extractor: None,
    pseudo_call_receiver_extractor: None,
    argument_passing_mode_extractor: None,
    expression_value_kind_extractor: None,
    assignment_kinds: &["assignment", "augmented_assignment", "named_expression"],
    assignment_semantics_extractor: None,
    assignment_place_extractor: None,
    compound_assignment_kinds: &["augmented_assignment"],
    compound_assignment_operators: &[],
    type_only_declaration_kinds: &[],
    positional_aggregate_assignment_kinds: &[],
    positional_aggregate_value_kinds: &[],
    return_kinds: &["return_statement"],
    throw_kinds: &["raise_statement"],
    lambda_kinds: &["lambda"],
    inline_closure_kinds: &[],
    implicit_lambda_parameter_name: None,
    lambda_body_field_names: &["body"],
    lambda_body_kinds: &[],
    try_kinds: &["try_statement"],
    try_node_filter: None,
    catch_kinds: &["except_clause"],
    exclusive_catch_arm_kinds: &["except_clause"],
    finally_kinds: &["finally_clause"],
    try_fallback_body_kinds: &["block"],
    catch_body_follows_marker: false,
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    control_target_extractor: None,
    loop_label_extractor: None,
    yield_kinds: &["yield"],
    yield_value_field_names: &["value", "expression"],
    await_kinds: &["await"],
    defer_kinds: &[],
    deferred_body_extractor: None,
    using_kinds: &["with_statement"],
    using_body_field_names: &["body"],
    try_body_field_names: &["body"],
    using_alias_extractor: Some(python_using_alias),
    special_forms: &[],
    runtime_type_guard_calls: &["isinstance"],
    runtime_type_guard_operators: &[],
    runtime_typeof_operators: &[],
    runtime_type_equality_operators: &[],
    runtime_type_wrapper_kinds: &["parenthesized_expression"],
    value_free_expression_kinds: &[],
    value_free_call_names: &[],
    value_free_unary_operators: &[],
    call_ref_kinds: &["call"],
    member_expression_kinds: &["attribute"],
    subscript_expression_kinds: &["subscript"],
    member_base_field_names: &["object"],
    member_name_field_names: &["attribute"],
    subscript_base_field_names: &["value"],
    subscript_index_field_names: &["subscript"],
    static_subscript_key_extractor: Some(python_static_subscript_key),
    computed_subscript_extractor: None,
    sigil_variable_kinds: &[],
    global_variable_kinds: &[],
    reference_name_extractor: None,
    expression_place_extractor: None,
    indirect_place_operand_extractor: None,
    subscript_base_call_refs: true,
    non_call_ref_names: &[],
    call_name_suffix_tokens: &[],
    syntax_error_tolerant_call_names: &[],
    callable_reference_kinds: &[],
    callable_reference_extractor: None,
    method_receiver_param_index: Some(0),
    receiver_presence_extractor: Some(python_function_has_receiver),
    // `self` for ordinary instance methods; `super` so `super().foo()`
    // and `super(Class, self).foo()` resolve to the parent class's
    // `foo` via the engine's `resolve_super_method_candidates`. The adapter
    // normalizes these call receivers to the two forms declared below.
    implicit_receiver_names: &["self", "super"],
    implicit_receiver_prefixes: EMPTY_HANDLER.implicit_receiver_prefixes,
    tail_expression_returns: EMPTY_HANDLER.tail_expression_returns,
    void_return_type_names: EMPTY_HANDLER.void_return_type_names,
};

/// Python-specific compiler passes consume these node kinds outside the
/// shared grammar-handler walker. The conformance suite validates this exact
/// inventory against the active Tree-sitter grammar.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("pattern match", "match_statement"),
    ("pattern arm", "case_clause"),
    ("pattern wrapper", "case_pattern"),
    ("pattern name", "dotted_name"),
    ("binding", "identifier"),
    ("mapping pattern", "dict_pattern"),
    ("pattern remainder", "splat_pattern"),
    ("class pattern", "class_pattern"),
    ("keyword pattern", "keyword_pattern"),
    ("pattern alias", "as_pattern"),
    ("list pattern", "list_pattern"),
    ("tuple pattern", "tuple_pattern"),
    ("union pattern", "union_pattern"),
    ("comprehension binding", "for_in_clause"),
    ("loop binding", "for_statement"),
    ("loop remainder", "list_splat_pattern"),
    ("decorated definition", "decorated_definition"),
    ("decorator", "decorator"),
    ("call expression", "call"),
    ("keyword argument", "keyword_argument"),
    ("boolean literal", "true"),
    ("boolean literal", "false"),
    ("member expression", "attribute"),
    ("assignment", "assignment"),
    ("augmented assignment", "augmented_assignment"),
    ("named assignment", "named_expression"),
    ("module scope", "module"),
    ("function scope", "function_definition"),
    ("class scope", "class_definition"),
    ("expression statement", "expression_statement"),
    ("if branch", "if_statement"),
    ("else-if branch", "elif_clause"),
    ("if filter", "if_clause"),
    ("grouped expression", "parenthesized_expression"),
    ("logical negation", "not_operator"),
    ("boolean expression", "boolean_operator"),
    ("comparison", "comparison_operator"),
    ("type expression", "type"),
    ("generic type", "generic_type"),
    ("union type", "union_type"),
    ("subscript", "subscript"),
    ("null literal", "none"),
    ("integer literal", "integer"),
    ("float literal", "float"),
    ("string literal", "string"),
    ("concatenated string", "concatenated_string"),
    ("conditional expression", "conditional_expression"),
    ("set literal", "set"),
    ("list literal", "list"),
    ("tuple literal", "tuple"),
    ("dictionary literal", "dictionary"),
    ("dictionary pair", "pair"),
    ("generator expression", "generator_expression"),
    ("list comprehension", "list_comprehension"),
    ("dictionary comprehension", "dictionary_comprehension"),
    ("set comprehension", "set_comprehension"),
    ("return statement", "return_statement"),
    ("raise statement", "raise_statement"),
    ("global directive", "global_statement"),
    ("nonlocal directive", "nonlocal_statement"),
    ("block", "block"),
    ("comment filter", "comment"),
    ("binary expression", "binary_operator"),
    ("default parameter", "default_parameter"),
    ("typed default parameter", "typed_default_parameter"),
    ("typed parameter", "typed_parameter"),
    ("lambda", "lambda"),
    ("formatted string start", "string_start"),
    ("formatted string content", "string_content"),
    ("formatted string interpolation", "interpolation"),
    ("formatted string end", "string_end"),
    ("parenthesized splat", "parenthesized_list_splat"),
    ("loop pattern list", "pattern_list"),
    ("import", "import_statement"),
    ("from import", "import_from_statement"),
    ("aliased import", "aliased_import"),
    ("wildcard import", "wildcard_import"),
];

/// Python methods normally bind parameter zero as their receiver, except for
/// the exact built-in `staticmethod` decorator forms. This syntax belongs to
/// the Python adapter; shared lowering receives only the resulting boolean.
fn python_function_has_receiver(node: Node<'_>, src: &[u8]) -> bool {
    let Some(parent) = node
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
    else {
        return true;
    };
    let mut cursor = parent.walk();
    let is_static = parent
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "decorator")
        .any(|decorator| python_decorator_is_staticmethod(decorator, src));
    !is_static
}

fn python_decorator_is_staticmethod(decorator: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = decorator.walk();
    let is_static = decorator
        .named_children(&mut cursor)
        .next()
        .is_some_and(|expression| python_expr_is_staticmethod(expression, src));
    is_static
}

fn python_expr_is_staticmethod(node: Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        "identifier" => node_text(&node, src).trim() == "staticmethod",
        "attribute" => {
            node.child_by_field_name("attribute")
                .is_some_and(|attribute| node_text(&attribute, src).trim() == "staticmethod")
                && node
                    .child_by_field_name("object")
                    .is_some_and(|object| node_text(&object, src).trim() == "builtins")
        }
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            let is_static = node
                .named_children(&mut cursor)
                .next()
                .is_some_and(|inner| python_expr_is_staticmethod(inner, src));
            is_static
        }
        "call" => node
            .child_by_field_name("function")
            .is_some_and(|callee| python_expr_is_staticmethod(callee, src)),
        _ => false,
    }
}

/// Exact keyword presence and static values attached to Python decorators.
///
/// The shared decorator extractor records the decorator target. Python also
/// permits keyword configuration on the decorator call itself. Emit an exact
/// provider-neutral presence fact for every parsed keyword and an additional
/// value fact only for literal booleans. Rule data can therefore distinguish
/// an absent option from `option=false`, `option=true`, and a runtime-unknown
/// expression without teaching the compiler what the option means.
fn python_decorator_identity_refs(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    imports: &[ImportSpec],
    index: &DeclIndex,
) -> Vec<Ref> {
    let mut refs = Vec::new();
    for decorator in collect_kinds(tree, &["decorator"]) {
        let mut cursor = decorator.walk();
        let Some(expression) = decorator.named_children(&mut cursor).next() else {
            continue;
        };
        let (target_node, call) = if expression.kind() == "call" {
            let Some(target) = python_call_target(expression, src) else {
                continue;
            };
            (target.node, Some(expression))
        } else {
            (expression, None)
        };
        let target_text = node_text(&target_node, src).trim();
        if target_text.is_empty() {
            continue;
        }
        let expanded = python_imported_call_identity(target_node, imports, src);
        let call_result = python_decorator_receiver_call_identity(
            target_text,
            span_of(file, &decorator).start,
            imports,
            index,
        );
        let mut identities = vec![target_text.to_string()];
        for identity in [expanded, call_result].into_iter().flatten() {
            if !identities.iter().any(|existing| existing == &identity) {
                identities.push(identity);
            }
        }
        for identity in identities.iter().skip(1) {
            refs.push(Ref {
                span: span_of(file, &decorator),
                name: identity.clone(),
                kind: RefKind::Decorator,
                scope: None,
                resolved: None,
            });
        }
        let Some(call) = call else { continue };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut argument_cursor = arguments.walk();
        for argument in arguments
            .named_children(&mut argument_cursor)
            .filter(|child| child.kind() == "keyword_argument")
        {
            let Some(name_node) = argument.child_by_field_name("name") else {
                continue;
            };
            let keyword = node_text(&name_node, src).trim();
            if keyword.is_empty() {
                continue;
            }
            for identity in &identities {
                refs.push(Ref {
                    span: span_of(file, &decorator),
                    name: format!("{identity}.{keyword}"),
                    kind: RefKind::Decorator,
                    scope: None,
                    resolved: None,
                });
            }
            let Some(value_node) = argument.child_by_field_name("value") else {
                continue;
            };
            let literal = match value_node.kind() {
                "true" => "true",
                "false" => "false",
                _ => continue,
            };
            for identity in &identities {
                refs.push(Ref {
                    span: span_of(file, &decorator),
                    name: format!("{identity}.{keyword}={literal}"),
                    kind: RefKind::Decorator,
                    scope: None,
                    resolved: None,
                });
            }
        }
    }
    refs
}

/// Resolve a decorator receiver through its latest exact call assignment.
///
/// `worker = Factory(); @worker.callback` becomes
/// `imported.Factory.callback`. Reassignment to any non-call value, local
/// shadowing of the imported call, nested receivers, and unknown call
/// results fail closed. The adapter reports only compiler identity; rule data
/// decides whether that identity is a security boundary.
fn python_decorator_receiver_call_identity(
    decorator_target: &str,
    before: u64,
    imports: &[ImportSpec],
    index: &DeclIndex,
) -> Option<String> {
    let (receiver, member) = decorator_target.rsplit_once('.')?;
    if receiver.is_empty() || member.is_empty() || receiver.contains('.') {
        return None;
    }
    let assignment = index
        .assignment_values
        .iter()
        .filter(|fact| fact.assignment_span.start < before && fact.target.as_deref() == Some(receiver))
        .max_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end))?;
    let call = assignment.direct_call_name.as_deref()?;
    let call_head = call.split('.').next().unwrap_or(call);
    if index.defs.iter().any(|decl| {
        decl.parent.is_none() && decl.name == call_head && decl.span.start < assignment.assignment_span.start
    }) || index.assignment_values.iter().any(|fact| {
        fact.assignment_span.start < assignment.assignment_span.start
            && fact.target.as_deref() == Some(call_head)
    }) {
        return None;
    }
    let call = python_imported_text_identity(call, imports).unwrap_or_else(|| call.to_string());
    Some(format!("{call}.{member}"))
}

#[derive(Debug, Default, Copy, Clone)]
pub struct PythonAdapter;

impl PythonAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for PythonAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Python"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["py", "pyi"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Any", "object"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            // Reflective attribute selection is a runtime operation. Even a
            // literal attribute name does not prove that reading or testing
            // that attribute invokes it, so the exact call remains unresolved.
            reflection: bonsai_lang_api::CapabilityLevel::Unsupported,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            // Static attribute/subscript projections are exact, but Python
            // still has dynamic subscripts and reflective projections whose
            // selected field is unknowable from syntax alone. Keep the
            // workspace field universe open for those aggregate reads.
            field_places_complete: false,
            constructor_method_names: &["__init__"],
            bare_call_constructor_syntax: true,
            super_receiver_tokens: &["super", "super()"],
            // Python's receiver is the adapter-proven first method parameter;
            // `self` is a convention, not an implicit grammar token.
            implicit_receiver_tokens: &[],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &["type"],
                class_object_suffixes: &[".__class__"],
            },
            module_resolution_extensions: &["py", "pyi"],
            unqualified_imports_search_current_directory: true,
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
        let src = snapshot.text.as_bytes();
        let mut idx = decl_index_from_tree_with_handler(file, src, &tree, &HANDLER);
        // Python module path: the dotted module name derived from the
        // file path. e.g. `pkg/sub/foo.py` -> ["pkg", "sub", "foo"].
        // Falls back to file-stem if the path isn't usable.
        // Workspace-relative path → dotted module path. Adapters
        // without a workspace root (unit tests) fall through to
        // file-stem-only via the helper below.
        let segments: Vec<String> = ctx
            .workspace_relative_path(file)
            .and_then(|path| {
                let stem = path.file_stem()?.to_string_lossy().into_owned();
                let mut segs: Vec<String> = path
                    .parent()?
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect();
                segs.push(stem);
                Some(segs)
            })
            .unwrap_or_default();
        if segments.is_empty() {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        } else {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        }
        // Python privacy is convention-based but the `__name` (dunder)
        // form triggers actual name-mangling at runtime, so the
        // resolver should treat it as truly Private. Single-underscore
        // `_name` is convention only — keep `Public`.
        for decl in &mut idx.defs {
            if decl.name.starts_with("__") && !decl.name.ends_with("__") {
                decl.visibility = Visibility::Private;
            }
        }
        // `__all__ = ["foo", "bar"]` (or the tuple form) declares the
        // names exported by `from module import *` ONLY. It is NOT a
        // visibility boundary: `from module import run_query` and
        // `import module; module.run_query(x)` are legal for names
        // absent from `__all__`. Downgrading unlisted top-level decls
        // to `Visibility::Module` made the resolver drop every
        // cross-module flow through an internal helper (the common
        // "public API in __all__, sink-bearing helpers omitted" idiom),
        // a soundness false-negative. We therefore keep such decls
        // `Public` and let the `__name` -> Private dunder rule above be
        // the only visibility filter. Precise wildcard-import narrowing
        // (consult `__all__` only on the `from module import *` path)
        // belongs in the resolver as a separate exported-names fact.
        // Per-decl compiler facts: walk the tree and record `param: Type`
        // annotations plus the exact direct call used as a parameter default
        // (`param: T = module.factory(...)`). The adapter deliberately does
        // not interpret framework/API names: rules decide what a default call
        // means through `target.default_call`. The matcher consults
        // `Decl.type_aliases` when resolving `attribute: [Type, method]`
        // rules, so typed receivers such as `[UploadFile, filename]` still
        // resolve per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        {
            let imports = parse_imports(&tree, src, file);
            let decorator_refs = python_decorator_identity_refs(&tree, file, src, &imports, &idx);
            idx.refs.extend(decorator_refs);
            idx.comments.extend(python_docstring_comments(&tree, file, src));
            populate_python_condition_expressions(&mut idx, &tree, file, src);
            idx.string_compositions = python_string_compositions(&tree, file, src, &idx.call_argument_values);
            idx.finite_literal_selections = python_finite_literal_selections(&idx, &tree, file, src);
            idx.character_substitutions = python_character_substitutions(&idx, &tree, file, src);
            idx.character_constraints = python_character_constraints(&idx, &tree, file, src, &imports);
            idx.guarded_value_constraints = python_guarded_value_constraints(&idx, &tree, file, src);
            // Phase-6 return-type extraction: `def f() -> T:` populates
            // `Decl.return_type`, which `apply_assign_call_result_types`
            // then propagates onto LHS type_aliases.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            let aliases_by_span = collect_python_method_type_aliases(&tree, file, src);
            let param_default_calls_by_span = collect_python_param_default_calls(&tree, file, src);
            for decl in &mut idx.defs {
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(default_calls) = param_default_calls_by_span
                    .iter()
                    .find_map(|(span, calls)| (*span == decl.span).then_some(calls))
                {
                    merge_python_param_default_calls(decl, default_calls);
                }
            }
            // Per-class `bases`: `class C(Base, Mixin):` →
            // ["Base", "Mixin"]. Lets `kind: param` rules require
            // an ancestor type (`in_class: [WebSocketHandler]`
            // matching a user `class Echo(WebSocketHandler):`).
            let bases_by_span = collect_python_class_bases(&tree, file, src);
            for decl in &mut idx.defs {
                if !matches!(decl.kind, bonsai_lang_api::DeclKind::Class) {
                    continue;
                }
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
            }
            let iterable_yield_bindings = collect_python_iterable_yield_bindings(&tree, file, src);
            let property_fn_spans = collect_python_property_function_spans(&tree, file, src);
            let property_aliases = collect_python_property_aliases(&idx, &property_fn_spans);
            let property_aliases_by_decl = python_property_aliases_by_decl(&idx, &property_aliases);
            let assignment_projected_reads = collect_python_assignment_projected_reads(&tree, file, src);
            let conditional_aggregates = collect_python_conditional_aggregate_assignments(&tree, file, src);
            for fact in &mut idx.assignment_values {
                if let Some((_, _, flow)) = conditional_aggregates
                    .iter()
                    .find(|(span, _, _)| *span == fact.assignment_span)
                {
                    fact.value_flow
                        .aggregate_fields
                        .clone_from(&flow.aggregate_fields);
                    fact.value_flow.spreads.clone_from(&flow.spreads);
                }
            }
            let call_argument_places = collect_python_call_argument_places(&tree, file, src);
            let return_places = collect_python_return_places(&tree, file, src);
            let callable_spans: Vec<Span> = idx
                .defs
                .iter()
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        bonsai_lang_api::DeclKind::Function
                            | bonsai_lang_api::DeclKind::Method
                            | bonsai_lang_api::DeclKind::Constructor
                    )
                })
                .map(|decl| decl.span)
                .collect();
            for decl in &mut idx.defs {
                let owned_yield_bindings = iterable_yield_bindings
                    .iter()
                    .filter(|event| {
                        python_span_owned_by_decl(python_flow_event_span(event), decl.span, &callable_spans)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let comprehension_iterable_calls =
                    collect_python_comprehension_iterable_call_events(&tree, file, src, decl.span);
                insert_python_flow_events_by_span(
                    &mut decl.flow_events,
                    decl.span,
                    &comprehension_iterable_calls,
                );
                insert_python_iterable_yield_bindings(&mut decl.flow_events, &owned_yield_bindings);
                augment_python_dict_flow_events(&mut decl.flow_events, &assignment_projected_reads);
                inject_python_conditional_aggregate_assignments(
                    &mut decl.flow_events,
                    &conditional_aggregates,
                );
                if let Some(property_aliases_for_decl) = property_aliases_by_decl.get(&decl.symbol) {
                    augment_python_property_flow_events(&mut decl.flow_events, property_aliases_for_decl);
                }
                apply_python_call_argument_places(&mut decl.flow_events, &call_argument_places);
                apply_python_return_places(&mut decl.flow_events, &return_places);
            }
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                &tree,
                file,
                src,
                &HANDLER,
                python_static_scalar,
            );
        }
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each class's
        // constructor `receiver_field_writes` so receiver-typed
        // dispatch through stable instance state is an O(1) lookup
        // against the method's `type_aliases` instead of a per-call
        // walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Lower the value arms of Python's conditional expression as one possible
/// aggregate value. Tree-sitter gives the consequence, condition, and
/// alternative as separate children; only the two value children contribute
/// fields. This is deliberately adapter-owned syntax handling: a call or
/// dictionary nested in the condition can never become the assigned value.
fn collect_python_conditional_aggregate_assignments(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, String, ExpressionFlow)> {
    fn transparent_value(mut node: Node<'_>) -> Node<'_> {
        while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
            let Some(child) = node.named_child(0) else { break };
            node = child;
        }
        node
    }

    let mut out = Vec::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let conditional = transparent_value(value);
        if conditional.kind() != "conditional_expression" {
            continue;
        }
        let mut cursor = conditional.walk();
        let values = conditional.named_children(&mut cursor).collect::<Vec<_>>();
        let [consequence, _condition, alternative] = values.as_slice() else {
            continue;
        };
        let mut merged = ExpressionFlow::default();
        for branch in [*consequence, *alternative] {
            let branch = transparent_value(branch);
            if !HANDLER.named_aggregate_kinds.contains(&branch.kind()) {
                continue;
            }
            let flow = expression_flow_from_node_with_handler(branch, file, src, &HANDLER);
            merged.aggregate_fields.extend(flow.aggregate_fields);
            merged.spreads.extend(flow.spreads);
        }
        if merged.aggregate_fields.is_empty() && merged.spreads.is_empty() {
            continue;
        }
        out.push((
            span_of(file, &assignment),
            node_text(&target, src).trim().to_string(),
            merged,
        ));
    }
    out.sort_by_key(|(span, target, _)| (span.start, span.end, target.clone()));
    out.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
    out
}

fn inject_python_conditional_aggregate_assignments(
    events: &mut Vec<FlowEvent>,
    facts: &[(Span, String, ExpressionFlow)],
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_python_conditional_aggregate_assignments(then_events, facts);
                inject_python_conditional_aggregate_assignments(else_events, facts);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_python_conditional_aggregate_assignments(body, facts);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_python_conditional_aggregate_assignments(body, facts);
                inject_python_conditional_aggregate_assignments(catch_events, facts);
                inject_python_conditional_aggregate_assignments(finally_events, facts);
            }
            _ => {}
        }
    }

    let mut index = 0usize;
    while index < events.len() {
        let aggregate = match &events[index] {
            FlowEvent::Assign { span, target, .. } => facts
                .iter()
                .find(|(fact_span, fact_target, _)| fact_span == span && fact_target == target)
                .map(|(_, _, flow)| FlowEvent::AggregateAssign {
                    span: *span,
                    target: target.clone(),
                    type_name: None,
                    value_flow: flow.clone(),
                }),
            _ => None,
        };
        if let Some(aggregate) = aggregate {
            events.insert(index + 1, aggregate);
            index += 2;
        } else {
            index += 1;
        }
    }
}

/// Python defines a docstring as the first bare string expression in a
/// module, function, async function, or class body. This is language syntax,
/// so the adapter owns the scope and wrapper kinds; shared comment lowering
/// only consumes explicit comment nodes declared by its active handler.
fn python_docstring_comments(tree: &Tree, file: FileId, src: &[u8]) -> Vec<Comment> {
    let mut out = Vec::new();
    for scope in collect_kinds(tree, &["module", "function_definition", "class_definition"]) {
        let body = scope.child_by_field_name("body").unwrap_or(scope);
        let Some(first_statement) = body
            .named_children(&mut body.walk())
            .find(|child| child.kind() != "comment")
        else {
            continue;
        };
        // The current grammar inlines bare expression statements; accept an
        // explicit wrapper too, but never peel one element from a tuple.
        let mut value = first_statement;
        if value.kind() == "expression_statement" {
            if value.named_child_count() != 1 {
                continue;
            }
            let Some(inner) = value.named_child(0) else {
                continue;
            };
            value = inner;
        }
        while value.kind() == "parenthesized_expression" && value.named_child_count() == 1 {
            let Some(inner) = value.named_child(0) else { break };
            value = inner;
        }
        if !python_is_docstring_literal(value, src) {
            continue;
        }
        let text = node_text(&value, src).trim().to_string();
        if text.is_empty() {
            continue;
        }
        out.push(Comment {
            span: span_of(file, &value),
            content_len: lexical_content::string_content_len(value, src),
            kind: CommentKind::classify(&text, true),
            text,
        });
    }
    out.sort_by_key(|comment| (comment.span.start, comment.span.end));
    out.dedup_by_key(|comment| comment.span);
    out
}

fn python_is_docstring_literal(node: Node<'_>, src: &[u8]) -> bool {
    let mut pending = vec![node];
    while let Some(value) = pending.pop() {
        if value.has_error() {
            return false;
        }
        if value.kind() == "concatenated_string" {
            pending.extend(
                value
                    .named_children(&mut value.walk())
                    .filter(|child| child.kind() != "comment"),
            );
            continue;
        }
        if value.kind() != "string" {
            return false;
        }
        let text = node_text(&value, src);
        let Some(quote_start) = text.find(['\'', '"']) else {
            return false;
        };
        // Raw and Unicode text literals are docstrings; byte strings and
        // formatted expressions never are, even without interpolations.
        if !text[..quote_start]
            .chars()
            .all(|ch| matches!(ch, 'r' | 'R' | 'u' | 'U'))
        {
            return false;
        }
    }
    true
}

/// Lower Python's boolean-expression grammar into the shared semantic
/// condition IR. Operator spellings are consumed here, in the language
/// frontend; security and dataflow analyses only see `Any`/`All`/`Not`,
/// equality, membership, and exact syntax spans.
fn populate_python_condition_expressions(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for branch in collect_kinds(tree, &["if_statement", "elif_clause"]) {
        let branch_span = span_of(file, &branch);
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        let Some(fact) = index
            .branch_conditions
            .iter_mut()
            .find(|fact| fact.branch_span == branch_span)
        else {
            continue;
        };
        fact.expression = Some(lower_python_condition_expression(condition, file, src));
    }
}

fn lower_python_condition_expression(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    if matches!(node.kind(), "parenthesized_expression") {
        if let Some(inner) = node.named_child(0) {
            return lower_python_condition_expression(inner, file, src);
        }
    }

    let span = span_of(file, &node);
    if node.kind() == "not_operator" {
        if let Some(operand) = node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("operand"))
            .or_else(|| node.named_child(0))
        {
            return ConditionExpressionFact::Not {
                span,
                operand: Box::new(lower_python_condition_expression(operand, file, src)),
            };
        }
    }

    if node.kind() == "boolean_operator" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            match operator {
                Some("or") => {
                    return merge_python_condition_junction(
                        span,
                        lower_python_condition_expression(left, file, src),
                        lower_python_condition_expression(right, file, src),
                        false,
                    );
                }
                Some("and") => {
                    return merge_python_condition_junction(
                        span,
                        lower_python_condition_expression(left, file, src),
                        lower_python_condition_expression(right, file, src),
                        true,
                    );
                }
                _ => {}
            }
        }
    }

    if node.kind() == "comparison_operator" && node.named_child_count() == 2 {
        if let (Some(left), Some(right)) = (node.named_child(0), node.named_child(1)) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            match operator {
                Some("==" | "!=") => {
                    return ConditionExpressionFact::Equality {
                        span,
                        relation: if operator == Some("==") {
                            ConditionEquality::Equal
                        } else {
                            ConditionEquality::NotEqual
                        },
                        left: python_condition_operand(left, file, src),
                        right: python_condition_operand(right, file, src),
                    };
                }
                Some("in" | "not in") => {
                    return ConditionExpressionFact::Membership {
                        span,
                        subject: python_condition_operand(left, file, src),
                        collection: python_condition_operand(right, file, src),
                        then_contains: operator == Some("in"),
                    };
                }
                _ => {}
            }
        }
    }

    if node.kind() == "call" {
        let function = node.child_by_field_name("function");
        let arguments = node.child_by_field_name("arguments");
        if let (Some(function), Some(arguments)) = (function, arguments) {
            let mut cursor = arguments.walk();
            let values: Vec<_> = arguments.named_children(&mut cursor).collect();
            if function.kind() == "identifier"
                && node_text(&function, src).trim() == "isinstance"
                && values.len() == 2
                && matches!(
                    values[1].kind(),
                    "identifier" | "type" | "attribute" | "generic_type"
                )
            {
                let type_name = node_text(&values[1], src).trim().to_string();
                if !type_name.is_empty() {
                    return ConditionExpressionFact::TypeTest {
                        span,
                        predicate_call_span: bonsai_lang_api::kit::direct_call_callee_span(
                            node, file, src, &HANDLER,
                        ),
                        subject: python_condition_operand(values[0], file, src),
                        type_name,
                    };
                }
            }
        }
    }

    if matches!(node.kind(), "identifier" | "attribute" | "subscript") {
        return ConditionExpressionFact::Truthy {
            span,
            operand: python_condition_operand(node, file, src),
        };
    }

    ConditionExpressionFact::Atom { span }
}

fn merge_python_condition_junction(
    span: Span,
    left: ConditionExpressionFact,
    right: ConditionExpressionFact,
    all: bool,
) -> ConditionExpressionFact {
    let mut operands = Vec::new();
    let mut push = |operand: ConditionExpressionFact| match (all, operand) {
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

fn python_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    let value_node = python_condition_dynamic_value_node(node, src);
    ConditionOperandFact {
        span: span_of(file, &node),
        direct_call_span: bonsai_lang_api::kit::direct_call_callee_span(value_node, file, src, &HANDLER),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
            value_node, file, src, &HANDLER,
        ),
        static_string: python_static_string(node, src),
        static_value: python_static_scalar(node, src),
    }
}

/// Preserve the exact dynamic operand of Python's common falsey-fallback
/// expression (`value or <static>`). The complete operand span remains on the
/// condition fact, while value-flow points at the Tree-sitter node whose
/// runtime value is being constrained. This is language semantics, not a
/// security classification.
fn python_condition_dynamic_value_node<'tree>(mut node: Node<'tree>, src: &[u8]) -> Node<'tree> {
    loop {
        if matches!(node.kind(), "parenthesized_expression") {
            if let Some(inner) = node.named_child(0) {
                node = inner;
                continue;
            }
        }
        if node.kind() == "boolean_operator" {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                let operator = src
                    .get(left.end_byte()..right.start_byte())
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .map(str::trim);
                if operator == Some("or") && python_static_scalar(right, src).is_some() {
                    node = left;
                    continue;
                }
            }
        }
        return node;
    }
}

fn python_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "none" => Some(StaticScalarValue::Null),
        "string" => Some(StaticScalarValue::String(python_static_string(node, src)?)),
        _ => None,
    }
}

fn python_static_subscript_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    match python_static_scalar(node, src)? {
        StaticScalarValue::String(value) => Some(value),
        StaticScalarValue::Boolean(_) | StaticScalarValue::Integer(_) | StaticScalarValue::Null => None,
    }
}

fn python_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "concatenated_string" {
        let mut value = String::new();
        let mut cursor = node.walk();
        let mut children = node.named_children(&mut cursor).peekable();
        children.peek()?;
        for child in children {
            value.push_str(&python_static_string(child, src)?);
        }
        return Some(value);
    }
    if node.kind() != "string" {
        return None;
    }
    let text = node_text(&node, src).trim();
    let quote_start = text.find(['\'', '"'])?;
    let prefix = text.get(..quote_start)?.to_ascii_lowercase();
    if prefix.contains('f') || prefix.contains('b') || prefix.chars().any(|ch| !matches!(ch, 'r' | 'u')) {
        return None;
    }
    let quoted = text.get(quote_start..)?;
    let delimiter = if quoted.starts_with("'''") {
        "'''"
    } else if quoted.starts_with("\"\"\"") {
        "\"\"\""
    } else if quoted.starts_with('\'') {
        "'"
    } else if quoted.starts_with('"') {
        "\""
    } else {
        return None;
    };
    let inner = quoted.strip_prefix(delimiter)?.strip_suffix(delimiter)?;
    if prefix.contains('r') {
        return Some(inner.to_string());
    }
    let mut decoded = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        decoded.push(match characters.next()? {
            'r' => '\r',
            'n' => '\n',
            't' => '\t',
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            'x' => {
                let digits = [characters.next()?, characters.next()?];
                let value = u8::from_str_radix(&digits.iter().collect::<String>(), 16).ok()?;
                char::from(value)
            }
            _ => return None,
        });
    }
    Some(decoded)
}

fn python_character_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
    imports: &[ImportSpec],
) -> Vec<CharacterConstraintFact> {
    let mut facts = python_comprehension_character_constraints(index, tree, file, src, imports);
    facts.extend(python_regex_substitution_constraints(
        index, tree, file, src, imports,
    ));
    facts.extend(python_regex_validation_constraints(
        index, tree, file, src, imports,
    ));
    facts.sort_by_key(|fact| (fact.transform_span.start, fact.transform_span.end));
    facts.dedup_by_key(|fact| fact.transform_span);
    facts
}

fn python_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    #[derive(Clone)]
    struct FiniteMapBinding {
        name: String,
        declaration_end: usize,
        owner: Option<Span>,
    }

    fn binding_visible(
        resolver: &PythonLexicalBindingResolver<'_, '_>,
        bindings: &[FiniteMapBinding],
        map_name: &str,
        use_start: usize,
        use_span: Span,
    ) -> bool {
        let owner = resolver.owner_for_use(use_span, map_name);
        bindings.iter().any(|binding| {
            binding.name == map_name
                && (binding.owner.is_none() || binding.declaration_end <= use_start)
                && binding.owner == owner
        })
    }

    let assignments = collect_kinds(tree, &["assignment"]);
    let aliases_or_mutation_candidates = collect_kinds(tree, &["assignment", "augmented_assignment", "call"]);
    let binding_resolver = PythonLexicalBindingResolver::new(index, tree, file, src, &assignments);
    let mut finite_maps = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" || !python_finite_static_map(value, src) {
            continue;
        }
        let name = node_text(&target, src).trim().to_string();
        let owner = binding_resolver.owner_for_use(span_of(file, assignment), &name);
        let writes = assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| left.kind() == "identifier" && node_text(&left, src).trim() == name)
                    && binding_resolver.owner_for_use(span_of(file, candidate), &name) == owner
            })
            .count();
        let projected_write = assignments.iter().any(|candidate| {
            candidate.child_by_field_name("left").is_some_and(|left| {
                left.kind() == "subscript"
                    && left.child_by_field_name("value").is_some_and(|base| {
                        base.kind() == "identifier" && node_text(&base, src).trim() == name
                    })
            }) && binding_resolver.owner_for_use(span_of(file, candidate), &name) == owner
        });
        let aliases_or_mutations =
            aliases_or_mutation_candidates.iter().copied().any(|candidate| {
                binding_resolver.owner_for_use(span_of(file, &candidate), &name) == owner
                    && python_map_binding_may_escape_or_mutate(candidate, &name, assignment.id(), src)
            }) || python_map_binding_has_unsafe_use(&binding_resolver, &name, assignment.id(), owner);
        if writes == 1 && !projected_write && !aliases_or_mutations {
            finite_maps.push(FiniteMapBinding {
                name,
                declaration_end: assignment.end_byte(),
                owner,
            });
        }
    }

    let mut facts = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" || value.kind() != "conditional_expression" {
            continue;
        }
        let mut cursor = value.walk();
        let operands: Vec<_> = value.named_children(&mut cursor).collect();
        let [selected, condition, fallback] = operands.as_slice() else {
            continue;
        };
        let Some(collection) = python_positive_membership_collection(*condition, *selected, src) else {
            continue;
        };
        let collection_is_finite = python_finite_literal_collection(collection, src)
            || (collection.kind() == "identifier"
                && binding_visible(
                    &binding_resolver,
                    &finite_maps,
                    node_text(&collection, src).trim(),
                    condition.start_byte(),
                    span_of(file, condition),
                ));
        if !collection_is_finite || !python_finite_membership_literal(*fallback, src) {
            continue;
        }
        facts.push(FiniteLiteralSelectionFact {
            selection_span: span_of(file, &value),
            assignment_span: Some(span_of(file, assignment)),
            target: Some(node_text(&target, src).trim().to_string()),
            call_span: None,
            argument_index: None,
        });
    }
    for call in collect_kinds(tree, &["call"]) {
        let Some((function, arguments)) = python_call_parts(call) else {
            continue;
        };
        let Some((receiver, method)) = python_attribute_parts(function, src) else {
            continue;
        };
        if method != "get" || receiver.kind() != "identifier" {
            continue;
        }
        let map_name = node_text(&receiver, src).trim();
        let selection_span = span_of(file, &call);
        let finite_match = binding_visible(
            &binding_resolver,
            &finite_maps,
            map_name,
            call.start_byte(),
            selection_span,
        );
        if !finite_match {
            continue;
        }
        // `dict.get` can return its default. Accept exactly one key and an
        // optional proven constant; no keyword/spread argument may be hidden
        // by the generic positional argument view.
        let arguments = arguments
            .named_children(&mut arguments.walk())
            .filter(|child| child.kind() != "comment")
            .collect::<Vec<_>>();
        if !(1..=2).contains(&arguments.len())
            || arguments.iter().any(|argument| {
                matches!(
                    argument.kind(),
                    "keyword_argument" | "list_splat" | "dictionary_splat" | "parenthesized_list_splat"
                )
            })
        {
            continue;
        }
        if let Some(fallback) = arguments.get(1) {
            let finite_map_read = fallback.kind() == "subscript"
                && fallback.child_by_field_name("value").is_some_and(|base| {
                    base.kind() == "identifier"
                        && binding_visible(
                            &binding_resolver,
                            &finite_maps,
                            node_text(&base, src).trim(),
                            fallback.start_byte(),
                            span_of(file, fallback),
                        )
                });
            if !python_statically_constructed_value(*fallback, src) && !finite_map_read {
                continue;
            }
        }
        // Only the complete RHS can establish a clean assignment. A lookup
        // inside concatenation or another call proves nothing about that
        // surrounding expression's value.
        let mut value = call;
        while let Some(parent) = value
            .parent()
            .filter(|parent| parent.kind() == "parenthesized_expression" && parent.named_child_count() == 1)
        {
            value = parent;
        }
        let value_span = span_of(file, &value);
        let Some(assignment) = index
            .assignment_values
            .iter()
            .filter(|fact| fact.target.is_some() && fact.value_span == value_span)
            .min_by_key(|fact| fact.value_span.len())
        else {
            continue;
        };
        facts.push(FiniteLiteralSelectionFact {
            selection_span,
            assignment_span: Some(assignment.assignment_span),
            target: assignment.target.clone(),
            call_span: None,
            argument_index: None,
        });
    }
    facts.sort_by_key(|fact| {
        let span = fact.assignment_span.unwrap_or(fact.selection_span);
        (span.start, span.end, fact.selection_span.start)
    });
    facts.dedup();
    facts
}

/// Return the collection from a positive `selected in collection` condition
/// whose subject is the conditional's selected value. The caller proves that
/// collection is either literal syntax or an immutable finite-map binding.
fn python_positive_membership_collection<'tree>(
    condition: Node<'tree>,
    selected: Node<'tree>,
    src: &[u8],
) -> Option<Node<'tree>> {
    if condition.kind() != "comparison_operator" || selected.kind() != "identifier" {
        return None;
    }
    let mut cursor = condition.walk();
    let operands: Vec<_> = condition.named_children(&mut cursor).collect();
    let [subject, collection] = operands.as_slice() else {
        return None;
    };
    if subject.kind() != "identifier" || node_text(subject, src).trim() != node_text(&selected, src).trim() {
        return None;
    }
    let operator = src
        .get(subject.end_byte()..collection.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    if operator != Some("in") {
        return None;
    }
    Some(*collection)
}

fn python_finite_literal_collection(collection: Node<'_>, src: &[u8]) -> bool {
    if !matches!(collection.kind(), "set" | "list" | "tuple") {
        return false;
    }
    let mut collection_cursor = collection.walk();
    let values: Vec<_> = collection.named_children(&mut collection_cursor).collect();
    !values.is_empty()
        && values
            .into_iter()
            .all(|value| python_finite_membership_literal(value, src))
}

fn python_finite_membership_literal(node: Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        "string" => python_static_string(node, src).is_some(),
        "integer" | "float" | "true" | "false" | "none" => true,
        _ => false,
    }
}

fn python_character_substitutions(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterSubstitutionFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let aliases_or_mutation_candidates = collect_kinds(tree, &["assignment", "augmented_assignment", "call"]);
    let binding_resolver = PythonLexicalBindingResolver::new(index, tree, file, src, &assignments);
    let mut tables = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some(entries) = python_static_string_map(value, src) else {
            continue;
        };
        let name = node_text(&target, src).trim().to_string();
        let owner = binding_resolver.owner_for_use(span_of(file, assignment), &name);
        let writes = assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| left.kind() == "identifier" && node_text(&left, src).trim() == name)
                    && binding_resolver.owner_for_use(span_of(file, candidate), &name) == owner
            })
            .count();
        let projected_write = assignments.iter().any(|candidate| {
            candidate.child_by_field_name("left").is_some_and(|left| {
                left.kind() == "subscript"
                    && left.child_by_field_name("value").is_some_and(|base| {
                        base.kind() == "identifier" && node_text(&base, src).trim() == name
                    })
            }) && binding_resolver.owner_for_use(span_of(file, candidate), &name) == owner
        });
        let aliases_or_mutations =
            aliases_or_mutation_candidates.iter().copied().any(|candidate| {
                binding_resolver.owner_for_use(span_of(file, &candidate), &name) == owner
                    && python_map_binding_may_escape_or_mutate(candidate, &name, assignment.id(), src)
            }) || python_map_binding_has_unsafe_use(&binding_resolver, &name, assignment.id(), owner);
        if writes == 1 && !projected_write && !aliases_or_mutations {
            tables.push((name, assignment.end_byte(), owner, entries));
        }
    }

    let mut facts = Vec::new();
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let Some(returned) = return_node.named_child(0) else {
            continue;
        };
        let Some((join_function, join_arguments)) = python_call_parts(returned) else {
            continue;
        };
        let Some((join_receiver, join_method)) = python_attribute_parts(join_function, src) else {
            continue;
        };
        if join_method != "join" || python_static_string(join_receiver, src).as_deref() != Some("") {
            continue;
        }
        let generator = if join_arguments.kind() == "generator_expression" {
            join_arguments
        } else {
            let arguments = python_argument_nodes(join_arguments);
            let [generator] = arguments.as_slice() else {
                continue;
            };
            *generator
        };
        let Some((table, input_place)) = python_static_map_substitution_generator(generator, src) else {
            continue;
        };
        let transform_span = span_of(file, &return_node);
        let Some(decl) = python_enclosing_callable(index, transform_span) else {
            continue;
        };
        if !python_is_single_statement_return(return_node) {
            continue;
        }
        let Some(input_param_index) = decl.params.iter().position(|parameter| parameter == &input_place)
        else {
            continue;
        };
        let owner = binding_resolver.owner_for_use(transform_span, &table);
        let Some((_, _, _, exact_mappings)) =
            tables.iter().find(|(name, declaration_end, binding_owner, _)| {
                name == &table
                    && (binding_owner.is_none() || *declaration_end <= return_node.start_byte())
                    && *binding_owner == owner
            })
        else {
            continue;
        };
        facts.push(CharacterSubstitutionFact {
            function_span: decl.span,
            transform_span,
            input_param_index,
            exact_mappings: exact_mappings.clone(),
            table,
            domain: CharacterSubstitutionDomain::TableKeysWithIdentityFallback,
        });
    }
    facts.sort_by_key(|fact| (fact.transform_span.start, fact.transform_span.end));
    facts.dedup_by_key(|fact| fact.transform_span);
    facts
}

fn python_static_string_map(node: Node<'_>, src: &[u8]) -> Option<Vec<StaticStringMapEntry>> {
    if node.kind() != "dictionary" || node.named_child_count() == 0 {
        return None;
    }
    let mut entries = Vec::new();
    let mut cursor = node.walk();
    for entry in node.named_children(&mut cursor) {
        if entry.kind() != "pair" {
            return None;
        }
        let key = entry
            .child_by_field_name("key")
            .and_then(|key| python_static_string(key, src))?;
        let value = entry
            .child_by_field_name("value")
            .and_then(|value| python_static_string(value, src))?;
        entries.push(StaticStringMapEntry { key, value });
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    entries.dedup_by(|left, right| left.key == right.key && left.value == right.value);
    Some(entries)
}

fn python_static_map_substitution_generator(generator: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    if generator.kind() != "generator_expression" {
        return None;
    }
    let body = generator.named_child(0)?;
    let (function, arguments) = python_call_parts(body)?;
    let (receiver, method) = python_attribute_parts(function, src)?;
    if receiver.kind() != "identifier" || method != "get" {
        return None;
    }
    let table = node_text(&receiver, src).trim().to_string();
    let lookup_arguments = python_argument_nodes(arguments);
    let [key, fallback] = lookup_arguments.as_slice() else {
        return None;
    };
    if key.kind() != "identifier" || fallback.kind() != "identifier" {
        return None;
    }
    let loop_variable = node_text(key, src).trim().to_string();
    if node_text(fallback, src).trim() != loop_variable {
        return None;
    }
    let mut cursor = generator.walk();
    let clauses = generator.named_children(&mut cursor).skip(1).collect::<Vec<_>>();
    let [for_clause] = clauses.as_slice() else {
        return None;
    };
    if for_clause.kind() != "for_in_clause" {
        return None;
    }
    let left = for_clause
        .child_by_field_name("left")
        .or_else(|| for_clause.named_child(0))?;
    let right = for_clause
        .child_by_field_name("right")
        .or_else(|| for_clause.named_child(1))?;
    if left.kind() != "identifier" || node_text(&left, src).trim() != loop_variable {
        return None;
    }
    let input_place = python_identity_fallback_input(right, src)?;
    Some((table, input_place))
}

fn python_identity_fallback_input(mut node: Node<'_>, src: &[u8]) -> Option<String> {
    while node.kind() == "parenthesized_expression" {
        node = node.named_child(0)?;
    }
    if node.kind() == "identifier" {
        return Some(node_text(&node, src).trim().to_string());
    }
    if node.kind() != "boolean_operator" {
        return None;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return None;
    };
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    (operator == Some("or")
        && left.kind() == "identifier"
        && python_static_string(right, src).as_deref() == Some(""))
    .then(|| node_text(&left, src).trim().to_string())
}

fn python_lexical_owner(index: &DeclIndex, span: bonsai_common::Span) -> Option<bonsai_common::Span> {
    index
        .defs
        .iter()
        .filter(|decl| {
            decl.name != bonsai_lang_api::MODULE_DECL_NAME
                && matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor | DeclKind::Class
                )
                && decl.span.start <= span.start
                && span.end <= decl.span.end
        })
        .min_by_key(|decl| decl.span.len())
        .map(|decl| decl.span)
}

/// Per-file Python lexical binding resolver shared by value-shape lowerers.
/// Directive nodes are indexed once so repeated candidate checks remain
/// linear in the small set of relevant scopes instead of rescanning the CST.
struct PythonLexicalBindingResolver<'a, 'tree> {
    index: &'a DeclIndex,
    file: FileId,
    src: &'a [u8],
    assignments: &'a [Node<'tree>],
    directives: Vec<Node<'tree>>,
    identifiers: Vec<Node<'tree>>,
}

impl<'a, 'tree> PythonLexicalBindingResolver<'a, 'tree> {
    fn new(
        index: &'a DeclIndex,
        tree: &'tree Tree,
        file: FileId,
        src: &'a [u8],
        assignments: &'a [Node<'tree>],
    ) -> Self {
        let mut resolver = Self::for_binding_owners(index, tree, file, src, assignments);
        resolver.identifiers = collect_kinds(tree, &["identifier"]);
        resolver
    }

    fn for_binding_owners(
        index: &'a DeclIndex,
        tree: &'tree Tree,
        file: FileId,
        src: &'a [u8],
        assignments: &'a [Node<'tree>],
    ) -> Self {
        Self {
            index,
            file,
            src,
            assignments,
            directives: collect_kinds(tree, &["global_statement", "nonlocal_statement"]),
            identifiers: Vec::new(),
        }
    }

    /// Resolve one Python binding spelling to its lexical compiler owner.
    ///
    /// Python decides whether a name is local for the whole callable from
    /// parsed parameters and assignments, not source order. Nested callables
    /// close over the nearest such owner; `global` and `nonlocal` directives
    /// alter that lookup. Class bodies own their direct assignments, but a
    /// method does not capture the class namespace through a bare identifier.
    fn owner_for_use(&self, use_span: Span, name: &str) -> Option<Span> {
        let mut scopes = self
            .index
            .defs
            .iter()
            .filter(|decl| {
                decl.name != bonsai_lang_api::MODULE_DECL_NAME
                    && matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor | DeclKind::Class
                    )
                    && decl.span.start <= use_span.start
                    && use_span.end <= decl.span.end
            })
            .collect::<Vec<_>>();
        scopes.sort_by_key(|decl| decl.span.len());

        let mut inside_callable = false;
        for scope in scopes {
            let callable = matches!(
                scope.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            );
            if scope.kind == DeclKind::Class && inside_callable {
                continue;
            }
            if callable {
                inside_callable = true;
                if self.scope_has_name_directive(scope.span, "global_statement", name) {
                    return None;
                }
                if self.scope_has_name_directive(scope.span, "nonlocal_statement", name) {
                    continue;
                }
            }
            let parameter = callable && scope.params.iter().any(|parameter| parameter == name);
            let assigned = self.assignments.iter().any(|assignment| {
                python_lexical_owner(self.index, span_of(self.file, assignment)) == Some(scope.span)
                    && assignment.child_by_field_name("left").is_some_and(|left| {
                        left.kind() == "identifier" && node_text(&left, self.src).trim() == name
                    })
            });
            if parameter || assigned {
                return Some(scope.span);
            }
        }
        None
    }

    fn scope_has_name_directive(&self, scope: Span, kind: &str, name: &str) -> bool {
        self.directives.iter().any(|directive| {
            if directive.kind() != kind
                || python_lexical_owner(self.index, span_of(self.file, directive)) != Some(scope)
            {
                return false;
            }
            let mut cursor = directive.walk();
            let contains_name = directive
                .named_children(&mut cursor)
                .any(|child| child.kind() == "identifier" && node_text(&child, self.src).trim() == name);
            contains_name
        })
    }
}

fn python_map_binding_may_escape_or_mutate(
    node: Node<'_>,
    map_name: &str,
    declaration_id: usize,
    src: &[u8],
) -> bool {
    if node.id() == declaration_id {
        return false;
    }
    match node.kind() {
        "assignment" | "augmented_assignment" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            left.is_some_and(|left| {
                (left.kind() == "identifier" && node_text(&left, src).trim() == map_name)
                    || (left.kind() == "subscript"
                        && left.child_by_field_name("value").is_some_and(|base| {
                            base.kind() == "identifier" && node_text(&base, src).trim() == map_name
                        }))
            }) || right.is_some_and(|right| {
                right.kind() == "identifier" && node_text(&right, src).trim() == map_name
            })
        }
        "call" => {
            let Some((function, _)) = python_call_parts(node) else {
                return false;
            };
            python_attribute_parts(function, src).is_some_and(|(receiver, method)| {
                receiver.kind() == "identifier"
                    && node_text(&receiver, src).trim() == map_name
                    && method != "get"
            })
        }
        _ => false,
    }
}

fn python_map_binding_has_unsafe_use(
    resolver: &PythonLexicalBindingResolver<'_, '_>,
    map_name: &str,
    declaration_id: usize,
    owner: Option<Span>,
) -> bool {
    resolver.identifiers.iter().any(|identifier| {
        if node_text(identifier, resolver.src).trim() != map_name {
            return false;
        }
        if resolver.owner_for_use(span_of(resolver.file, identifier), map_name) != owner {
            return false;
        }
        if identifier
            .parent()
            .is_some_and(|parent| parent.kind() == "assignment" && parent.id() == declaration_id)
        {
            return false;
        }
        if identifier
            .parent()
            .is_some_and(|parent| matches!(parent.kind(), "global_statement" | "nonlocal_statement"))
        {
            // Binding directives carry no runtime value and cannot expose
            // or mutate the selected map by themselves.
            return false;
        }
        let Some(attribute) = identifier.parent().filter(|parent| parent.kind() == "attribute") else {
            // Reading one entry from a complete immutable literal map
            // cannot introduce the dynamic key into its selected value.
            // Projected writes were rejected above; this is only the
            // parsed value/base position of a subscript expression.
            if identifier.parent().is_some_and(|parent| {
                parent.kind() == "subscript"
                    && parent
                        .child_by_field_name("value")
                        .is_some_and(|value| value.id() == identifier.id())
            }) {
                return false;
            }
            // `candidate in STATIC_MAP` reads only the immutable map's
            // finite key set. It neither exposes nor mutates the map and
            // is the exact runtime predicate used to constrain a later
            // subscript selection.
            if identifier.parent().is_some_and(|parent| {
                if parent.kind() != "comparison_operator" {
                    return false;
                }
                let mut cursor = parent.walk();
                let operands = parent.named_children(&mut cursor).collect::<Vec<_>>();
                let [subject, collection] = operands.as_slice() else {
                    return false;
                };
                collection.id() == identifier.id()
                    && resolver
                        .src
                        .get(subject.end_byte()..collection.start_byte())
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .is_some_and(|operator| operator.trim() == "in")
            }) {
                return false;
            }
            return true;
        };
        if attribute
            .child_by_field_name("object")
            .is_none_or(|object| object.id() != identifier.id())
        {
            return true;
        }
        let Some(call) = attribute.parent().filter(|parent| parent.kind() == "call") else {
            return true;
        };
        call.child_by_field_name("function")
            .is_none_or(|function| function.id() != attribute.id())
            || attribute
                .child_by_field_name("attribute")
                .is_none_or(|method| node_text(&method, resolver.src).trim() != "get")
    })
}

fn python_finite_static_map(node: Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "dictionary" || node.named_child_count() == 0 {
        return false;
    }
    let mut cursor = node.walk();
    let finite = node.named_children(&mut cursor).all(|entry| {
        entry.kind() == "pair"
            && entry
                .child_by_field_name("key")
                .is_some_and(|key| python_static_string(key, src).is_some())
            && entry
                .child_by_field_name("value")
                .is_some_and(|value| python_statically_constructed_value(value, src))
    });
    finite
}

fn python_statically_constructed_value(node: Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        "string" | "concatenated_string" => python_static_string(node, src).is_some(),
        "integer" | "float" | "true" | "false" | "none" => true,
        "tuple" => {
            let mut cursor = node.walk();
            let finite = node
                .named_children(&mut cursor)
                .all(|child| python_statically_constructed_value(child, src));
            finite
        }
        // Literal arguments do not make a call result constant; a factory can
        // read external input. Mutable literal containers can acquire tainted
        // state through a selected alias, so they are not clean-value proofs.
        _ => false,
    }
}

fn python_comprehension_character_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
    imports: &[ImportSpec],
) -> Vec<CharacterConstraintFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let mut facts = Vec::new();
    for assignment in &assignments {
        let Some(target_node) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(mut value_node) = assignment.child_by_field_name("right") else {
            continue;
        };
        if target_node.kind() != "identifier" {
            continue;
        }
        while matches!(value_node.kind(), "subscript" | "parenthesized_expression") {
            let Some(inner) = value_node
                .child_by_field_name("value")
                .or_else(|| value_node.named_child(0))
            else {
                break;
            };
            value_node = inner;
        }
        let Some((function, arguments)) = python_call_parts(value_node) else {
            continue;
        };
        let Some((receiver, method)) = python_attribute_parts(function, src) else {
            continue;
        };
        if method != "join" || python_static_string(receiver, src).as_deref() != Some("") {
            continue;
        }
        let generator = if arguments.kind() == "generator_expression" {
            arguments
        } else {
            let args = python_argument_nodes(arguments);
            let [generator] = args.as_slice() else {
                continue;
            };
            *generator
        };
        let Some((input_place, classes, exact_characters)) =
            python_filtered_character_generator(generator, src)
        else {
            continue;
        };
        let transform_span = span_of(file, assignment);
        let Some(decl) = python_enclosing_callable(index, transform_span) else {
            continue;
        };
        let Some(function) =
            bonsai_lang_api::kit::node_at_span(tree.root_node(), decl.span, &["function_definition"])
        else {
            continue;
        };
        let exact_runtime_semantics = python_value_is_unshadowed_builtin_str(
            function,
            &input_place,
            transform_span,
            imports,
            index,
            &assignments,
            file,
            src,
        );
        let target = node_text(&target_node, src).trim().to_string();
        let input_param_index = decl.params.iter().position(|param| param == &input_place);
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span,
            input_place,
            input_param_index,
            proof: if exact_runtime_semantics {
                bonsai_lang_api::CharacterConstraintProof::ExactRuntimeSemantics
            } else {
                bonsai_lang_api::CharacterConstraintProof::RequiresSourcePayloadEvidence
            },
            output: CharacterConstraintOutput::Assignment { target },
            domain: CharacterConstraintDomain::AllowOnly {
                classes,
                exact_characters,
            },
        });
    }
    facts
}

/// Prove that a comprehension's iterated value is Python's built-in string
/// type at the transform site. The proof is either an exact parameter
/// annotation or an adapter-lowered, branch-local runtime narrowing.
/// Character predicate spellings such as `isalnum` are only meaningful as
/// compiler facts on that exact receiver; a user class with a same-spelled
/// method must not acquire sanitizer credit.
#[allow(clippy::too_many_arguments)]
fn python_value_is_unshadowed_builtin_str(
    function: Node<'_>,
    parameter_name: &str,
    use_span: Span,
    imports: &[ImportSpec],
    index: &DeclIndex,
    assignments: &[Node<'_>],
    file: FileId,
    src: &[u8],
) -> bool {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = parameters.walk();
    let exact_annotation = parameters.named_children(&mut cursor).any(|parameter| {
        parameter
            .child_by_field_name("name")
            .or_else(|| {
                parameter
                    .named_child(0)
                    .filter(|child| child.kind() == "identifier")
            })
            .is_some_and(|name| node_text(&name, src).trim() == parameter_name)
            && parameter
                .child_by_field_name("type")
                .is_some_and(|annotation| node_text(&annotation, src).trim() == "str")
    });
    let runtime_narrowing = index.runtime_type_narrowings.iter().any(|fact| {
        fact.subject == parameter_name
            && fact.type_name == "str"
            && function.start_byte() <= fact.branch_span.start as usize
            && fact.branch_span.end as usize <= function.end_byte()
            && fact.guarded_span.start <= use_span.start
            && use_span.end <= fact.guarded_span.end
    });
    (exact_annotation || runtime_narrowing)
        && python_imported_text_identity("str", imports).is_none()
        && !python_provider_root_is_lexically_shadowed("str", use_span, index, assignments, file, src)
}

fn python_filtered_character_generator(
    generator: Node<'_>,
    src: &[u8],
) -> Option<(String, Vec<CharacterClass>, Vec<String>)> {
    if generator.kind() != "generator_expression" {
        return None;
    }
    let body = generator.named_child(0)?;
    if body.kind() != "identifier" {
        return None;
    }
    let loop_variable = node_text(&body, src).trim();
    let mut cursor = generator.walk();
    let clauses: Vec<_> = generator.named_children(&mut cursor).skip(1).collect();
    let [for_clause, if_clause] = clauses.as_slice() else {
        return None;
    };
    if for_clause.kind() != "for_in_clause" || if_clause.kind() != "if_clause" {
        return None;
    }
    let left = for_clause
        .child_by_field_name("left")
        .or_else(|| for_clause.named_child(0))?;
    let right = for_clause
        .child_by_field_name("right")
        .or_else(|| for_clause.named_child(1))?;
    if left.kind() != "identifier"
        || right.kind() != "identifier"
        || node_text(&left, src).trim() != loop_variable
    {
        return None;
    }
    let condition = if_clause
        .child_by_field_name("condition")
        .or_else(|| if_clause.named_child(0))?;
    let mut classes = Vec::new();
    let mut exact_characters = Vec::new();
    if !python_character_predicate(condition, loop_variable, src, &mut classes, &mut exact_characters) {
        return None;
    }
    classes.sort_by_key(|class| match class {
        CharacterClass::Alphabetic => 0,
        CharacterClass::Alphanumeric => 1,
        CharacterClass::Digit => 2,
    });
    classes.dedup();
    exact_characters.sort();
    exact_characters.dedup();
    Some((
        node_text(&right, src).trim().to_string(),
        classes,
        exact_characters,
    ))
}

fn python_character_predicate(
    node: Node<'_>,
    variable: &str,
    src: &[u8],
    classes: &mut Vec<CharacterClass>,
    exact_characters: &mut Vec<String>,
) -> bool {
    if node.kind() == "boolean_operator" {
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
        return operator == Some("or")
            && python_character_predicate(left, variable, src, classes, exact_characters)
            && python_character_predicate(right, variable, src, classes, exact_characters);
    }
    if let Some((function, arguments)) = python_call_parts(node) {
        let Some((receiver, method)) = python_attribute_parts(function, src) else {
            return false;
        };
        if receiver.kind() != "identifier"
            || node_text(&receiver, src).trim() != variable
            || !python_argument_nodes(arguments).is_empty()
        {
            return false;
        }
        let class = match method {
            "isalpha" => CharacterClass::Alphabetic,
            "isalnum" => CharacterClass::Alphanumeric,
            "isdigit" => CharacterClass::Digit,
            _ => return false,
        };
        classes.push(class);
        return true;
    }
    if node.kind() != "comparison_operator" || node.named_child_count() != 2 {
        return false;
    }
    let (Some(left), Some(right)) = (node.named_child(0), node.named_child(1)) else {
        return false;
    };
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    if operator != Some("==") {
        return false;
    }
    let literal = if left.kind() == "identifier" && node_text(&left, src).trim() == variable {
        python_static_string(right, src)
    } else if right.kind() == "identifier" && node_text(&right, src).trim() == variable {
        python_static_string(left, src)
    } else {
        None
    };
    let Some(literal) = literal.filter(|value| value.chars().count() == 1) else {
        return false;
    };
    exact_characters.push(literal);
    true
}

fn python_regex_substitution_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
    imports: &[ImportSpec],
) -> Vec<CharacterConstraintFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let binding_resolver =
        PythonLexicalBindingResolver::for_binding_owners(index, tree, file, src, &assignments);
    let mut compiled = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some((function, arguments)) = python_call_parts(value) else {
            continue;
        };
        let Some(factory_call) = python_canonical_provider_call_identity(
            function,
            span_of(file, &value),
            imports,
            index,
            &assignments,
            file,
            src,
        ) else {
            continue;
        };
        let Some([pattern]) = python_exact_positional_arguments(arguments) else {
            continue;
        };
        let Some(pattern) = python_static_string(pattern, src) else {
            continue;
        };
        let Some(characters) = python_exact_regex_character_class(&pattern) else {
            continue;
        };
        let name = node_text(&target, src).trim().to_string();
        let writes = assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| node_text(&left, src).trim() == name)
            })
            .count();
        if writes == 1 {
            compiled.push((name, span_of(file, assignment), characters, factory_call));
        }
    }

    let mut facts = Vec::new();
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let Some(call) = return_node.named_child(0) else {
            continue;
        };
        let Some((function, arguments)) = python_call_parts(call) else {
            continue;
        };
        let Some((receiver, _)) = python_attribute_parts(function, src) else {
            continue;
        };
        if receiver.kind() != "identifier" {
            continue;
        }
        let receiver_name = node_text(&receiver, src).trim();
        let Some((_, _, mut excluded, factory_call)) = compiled
            .iter()
            .find(|(name, assignment_span, _, _)| {
                name == receiver_name
                    && assignment_span.start < return_node.start_byte() as u64
                    && binding_resolver.owner_for_use(*assignment_span, name)
                        == binding_resolver.owner_for_use(span_of(file, &return_node), name)
            })
            .cloned()
        else {
            continue;
        };
        let Some([replacement, input]) = python_exact_positional_arguments(arguments) else {
            continue;
        };
        let (Some(replacement), true) = (
            python_exact_replacement_string(replacement, src),
            input.kind() == "identifier",
        ) else {
            continue;
        };
        excluded.retain(|character| !replacement.contains(character));
        if excluded.is_empty() {
            continue;
        }
        let return_span = span_of(file, &return_node);
        let Some(decl) = python_enclosing_callable(index, return_span) else {
            continue;
        };
        if !python_is_single_statement_return(return_node) {
            continue;
        }
        let input_place = node_text(&input, src).trim().to_string();
        let Some(input_param_index) = decl.params.iter().position(|param| param == &input_place) else {
            continue;
        };
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span: return_span,
            input_place,
            input_param_index: Some(input_param_index),
            proof: bonsai_lang_api::CharacterConstraintProof::ExactRuntimeSemantics,
            output: CharacterConstraintOutput::Return,
            domain: CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call: node_text(&function, src).trim().to_string(),
                domain: Box::new(CharacterConstraintDomain::ExcludesExact { characters: excluded }),
            },
        });
    }
    facts
}

/// Lower a compiled-regex rejection guard as a provider-bound alphabet fact.
/// The frontend proves anchoring, the accepted character domain, branch
/// polarity, and terminal rejection from Python syntax. It records the exact
/// factory and predicate calls but does not decide that those APIs are a
/// sanitizer; rulepack metadata performs that selection.
fn python_regex_validation_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
    imports: &[ImportSpec],
) -> Vec<CharacterConstraintFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let binding_resolver =
        PythonLexicalBindingResolver::for_binding_owners(index, tree, file, src, &assignments);
    let mut compiled = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some((function, arguments)) = python_call_parts(value) else {
            continue;
        };
        let Some(factory_call) = python_canonical_provider_call_identity(
            function,
            span_of(file, &value),
            imports,
            index,
            &assignments,
            file,
            src,
        ) else {
            continue;
        };
        let Some([pattern]) = python_exact_positional_arguments(arguments) else {
            continue;
        };
        let Some(pattern) = python_static_string(pattern, src) else {
            continue;
        };
        let Some(domain) = python_anchored_regex_character_domain(&pattern) else {
            continue;
        };
        let name = node_text(&target, src).trim().to_string();
        if assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| node_text(&left, src).trim() == name)
            })
            .count()
            != 1
        {
            continue;
        }
        compiled.push((name, span_of(file, assignment), factory_call, domain));
    }

    let mut facts = Vec::new();
    for branch in collect_kinds(tree, &["if_statement"]) {
        let (Some(condition), Some(consequence)) = (
            branch.child_by_field_name("condition"),
            branch.child_by_field_name("consequence"),
        ) else {
            continue;
        };
        if branch.child_by_field_name("alternative").is_some() || !python_block_abruptly_exits(consequence) {
            continue;
        }
        let Some(call) = python_negated_guard_call(condition) else {
            continue;
        };
        let Some((function, arguments)) = python_call_parts(call) else {
            continue;
        };
        let Some((receiver, _)) = python_attribute_parts(function, src) else {
            continue;
        };
        if receiver.kind() != "identifier" {
            continue;
        }
        let Some([input]) = python_exact_positional_arguments(arguments) else {
            continue;
        };
        let Some(input_place) = python_exact_guarded_identifier(input, src) else {
            continue;
        };
        let receiver_name = node_text(&receiver, src).trim();
        let Some((_, _, factory_call, domain)) = compiled
            .iter()
            .filter(|(name, span, _, _)| {
                name == receiver_name
                    && span.start < branch.start_byte() as u64
                    && binding_resolver.owner_for_use(*span, name)
                        == binding_resolver.owner_for_use(span_of(file, &branch), name)
            })
            .max_by_key(|(_, span, _, _)| (span.start, span.end))
            .cloned()
        else {
            continue;
        };
        let branch_span = span_of(file, &branch);
        let Some(decl) = python_enclosing_callable(index, branch_span) else {
            continue;
        };
        if assignments.iter().any(|assignment| {
            assignment.start_byte() > branch.end_byte()
                && assignment.end_byte() <= decl.span.end as usize
                && assignment
                    .child_by_field_name("left")
                    .is_some_and(|left| node_text(&left, src).trim() == input_place)
        }) {
            continue;
        }
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span: branch_span,
            input_param_index: decl.params.iter().position(|parameter| parameter == &input_place),
            input_place: input_place.clone(),
            proof: bonsai_lang_api::CharacterConstraintProof::ExactRuntimeSemantics,
            output: CharacterConstraintOutput::Assignment { target: input_place },
            domain: CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call: node_text(&function, src).trim().to_string(),
                domain: Box::new(domain),
            },
        });
    }
    facts
}

fn python_negated_guard_call(mut condition: Node<'_>) -> Option<Node<'_>> {
    while matches!(condition.kind(), "parenthesized_expression") {
        condition = condition.named_child(0)?;
    }
    if condition.kind() != "not_operator" {
        return None;
    }
    condition
        .child_by_field_name("argument")
        .or_else(|| condition.named_child(0))
}

fn python_block_abruptly_exits(block: Node<'_>) -> bool {
    let mut cursor = block.walk();
    let last = block
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .last();
    last.is_some_and(|node| matches!(node.kind(), "return_statement" | "raise_statement"))
}

fn python_exact_guarded_identifier(mut node: Node<'_>, src: &[u8]) -> Option<String> {
    while node.kind() == "parenthesized_expression" {
        node = node.named_child(0)?;
    }
    (node.kind() == "identifier").then(|| node_text(&node, src).trim().to_string())
}

fn python_anchored_regex_character_domain(pattern: &str) -> Option<CharacterConstraintDomain> {
    let body = pattern.strip_prefix('^')?.strip_suffix('$')?;
    if body.is_empty() || body.contains("[^") || body.contains("(?") {
        return None;
    }
    let mut in_class = false;
    let mut escaped = false;
    let mut class = String::new();
    let mut group_depth = 0usize;
    for character in body.chars() {
        if escaped {
            if !matches!(character, '.' | '-' | '_' | 'd' | 'w') {
                return None;
            }
            escaped = false;
            if in_class {
                class.push(character);
            }
            continue;
        }
        match character {
            '\\' => escaped = true,
            '[' if !in_class => {
                in_class = true;
                class.clear();
            }
            ']' if in_class => {
                if !python_safe_regex_character_class(&class) {
                    return None;
                }
                in_class = false;
            }
            '/' => return None,
            '.' if !in_class => return None,
            character if in_class => class.push(character),
            '(' => group_depth += 1,
            ')' => group_depth = group_depth.checked_sub(1)?,
            '|' if group_depth == 0 => return None,
            character if character.is_ascii_alphanumeric() || "_-|{}?+*,".contains(character) => {}
            _ => return None,
        }
    }
    if escaped || in_class || group_depth != 0 {
        return None;
    }
    Some(CharacterConstraintDomain::ExcludesExact {
        characters: vec!["/".to_string(), "\\".to_string()],
    })
}

fn python_safe_regex_character_class(class: &str) -> bool {
    if class.is_empty() || class.contains('/') || class.contains('\\') {
        return false;
    }
    let characters = class.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < characters.len() {
        if index + 2 < characters.len() && characters[index + 1] == '-' {
            if !matches!(
                (characters[index], characters[index + 2]),
                ('A', 'Z') | ('a', 'z') | ('0', '9')
            ) {
                return false;
            }
            index += 3;
        } else {
            let character = characters[index];
            if !(character.is_ascii_alphanumeric()
                || matches!(character, '_' | '.')
                || (character == '-' && (index == 0 || index + 1 == characters.len())))
            {
                return false;
            }
            index += 1;
        }
    }
    true
}

fn python_exact_replacement_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    python_static_string(node, src)
}

fn python_exact_regex_character_class(pattern: &str) -> Option<Vec<String>> {
    let inner = pattern.strip_prefix('[')?.strip_suffix(']')?;
    if inner.starts_with('^') {
        return None;
    }
    let mut characters = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(character) = chars.next() {
        if matches!(character, '-' | '[' | ']') {
            return None;
        }
        let decoded = if character != '\\' {
            character
        } else {
            match chars.next()? {
                'r' => '\r',
                'n' => '\n',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                '\'' => '\'',
                'x' => {
                    let digits = [chars.next()?, chars.next()?];
                    let value = u8::from_str_radix(&digits.iter().collect::<String>(), 16).ok()?;
                    char::from(value)
                }
                _ => return None,
            }
        };
        characters.push(decoded.to_string());
    }
    characters.sort();
    characters.dedup();
    (!characters.is_empty()).then_some(characters)
}

fn python_call_parts(call: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (call.kind() == "call").then_some((
        call.child_by_field_name("function")?,
        call.child_by_field_name("arguments")?,
    ))
}

fn python_attribute_parts<'a>(attribute: Node<'a>, src: &'a [u8]) -> Option<(Node<'a>, &'a str)> {
    if attribute.kind() != "attribute" {
        return None;
    }
    let object = attribute.child_by_field_name("object")?;
    let name = attribute.child_by_field_name("attribute")?;
    Some((object, node_text(&name, src).trim()))
}

fn python_argument_nodes(arguments: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "keyword_argument")
        .collect()
}

/// A proof requiring a fixed call shape cannot ignore keywords or expansion.
fn python_exact_positional_arguments<const N: usize>(arguments: Node<'_>) -> Option<[Node<'_>; N]> {
    let arguments = arguments
        .named_children(&mut arguments.walk())
        .filter(|node| node.kind() != "comment")
        .collect::<Vec<_>>();
    if arguments.iter().any(|node| {
        matches!(
            node.kind(),
            "keyword_argument" | "list_splat" | "dictionary_splat" | "parenthesized_list_splat"
        )
    }) {
        return None;
    }
    arguments.try_into().ok()
}

fn python_enclosing_callable(index: &DeclIndex, span: Span) -> Option<&bonsai_lang_api::Decl> {
    index
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) && decl.span.start <= span.start
                && span.end <= decl.span.end
        })
        .min_by_key(|decl| decl.span.len())
}

fn python_is_single_statement_return(return_node: Node<'_>) -> bool {
    return_node.parent().is_some_and(|block| {
        block.kind() == "block"
            && block
                .named_children(&mut block.walk())
                .filter(|node| node.kind() != "comment")
                .count()
                == 1
    })
}

fn python_guarded_value_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<GuardedValueConstraintFact> {
    let imports = parse_imports(tree, src, file);
    let assignments = collect_kinds(tree, &["assignment"]);
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let function_span = span_of(file, &function);
        let Some(decl) = index.defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let mut cursor = body.walk();
        let statements: Vec<_> = body
            .named_children(&mut cursor)
            .filter(|node| node.kind() != "comment")
            .collect();
        let [assignment, guard, final_return] = statements.as_slice() else {
            continue;
        };
        if assignment.kind() != "expression_statement" && assignment.kind() != "assignment" {
            continue;
        }
        let assignment = if assignment.kind() == "assignment" {
            *assignment
        } else {
            assignment.named_child(0).unwrap_or(*assignment)
        };
        let (Some(parsed_node), Some(parser_call)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if parsed_node.kind() != "identifier" {
            continue;
        }
        let parsed = node_text(&parsed_node, src).trim();
        let Some((parser, parser_arguments)) = python_call_parts(parser_call) else {
            continue;
        };
        let Some(provider_call) = python_canonical_provider_call_identity(
            parser,
            span_of(file, &parser_call),
            &imports,
            index,
            &assignments,
            file,
            src,
        ) else {
            continue;
        };
        let parser_args = python_argument_nodes(parser_arguments);
        let [input_node] = parser_args.as_slice() else {
            continue;
        };
        if input_node.kind() != "identifier" {
            continue;
        }
        let input = node_text(input_node, src).trim();
        let Some(input_param_index) = decl.params.iter().position(|parameter| parameter == input) else {
            continue;
        };
        if guard.kind() != "if_statement" || guard.child_by_field_name("alternative").is_some() {
            continue;
        }
        let (Some(condition), Some(consequence)) = (
            guard.child_by_field_name("condition"),
            guard.child_by_field_name("consequence"),
        ) else {
            continue;
        };
        let Some(fallback) = python_block_static_return(consequence, src) else {
            continue;
        };
        if !python_return_is_exact_place(*final_return, input, src) {
            continue;
        }
        let mut terms = Vec::new();
        python_collect_or_terms(condition, src, &mut terms);
        let mut predicate_calls = Vec::new();
        let mut rejected_components = Vec::new();
        for term in terms {
            if let Some(component) = python_attribute_component(term, parsed, src) {
                if !rejected_components.contains(&component) {
                    rejected_components.push(component);
                }
                continue;
            }
            if let Some((call_expression_span, required_result)) =
                python_guarded_predicate_call(term, input, file, src)
            {
                predicate_calls.push(GuardedPredicateCallFact {
                    call_expression_span,
                    required_result,
                });
            }
        }
        if predicate_calls.is_empty() && rejected_components.is_empty() {
            continue;
        }
        predicate_calls.sort_by_key(|fact| {
            (
                fact.call_expression_span.start,
                fact.call_expression_span.end,
                fact.required_result,
            )
        });
        predicate_calls.dedup();
        facts.push(GuardedValueConstraintFact {
            function_span,
            guard_span: span_of(file, guard),
            input_place: input.to_string(),
            input_param_index: Some(input_param_index),
            provider_call: Some(provider_call),
            predicate_calls,
            accepted_prefixes: Vec::new(),
            rejected_prefixes: Vec::new(),
            rejected_components,
            static_fallbacks: vec![fallback],
        });
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.guard_span.start));
    facts.dedup();
    facts
}

fn python_imported_call_identity(callee: Node<'_>, imports: &[ImportSpec], src: &[u8]) -> Option<String> {
    let rendered = node_text(&callee, src).trim();
    python_imported_text_identity(rendered, imports)
}

/// Canonical provider identity for one runtime call.
///
/// Imported aliases are expanded to their declared module/member identity,
/// but only while the import binding is not shadowed by an exact Python
/// lexical binding. Security meaning remains in rule data: this helper merely
/// distinguishes an imported provider from a same-spelled local value.
fn python_canonical_provider_call_identity(
    callee: Node<'_>,
    use_span: Span,
    imports: &[ImportSpec],
    index: &DeclIndex,
    assignments: &[Node<'_>],
    file: FileId,
    src: &[u8],
) -> Option<String> {
    let rendered = node_text(&callee, src).trim();
    let root = rendered.split('.').next()?.trim();
    if root.is_empty()
        || python_provider_root_is_lexically_shadowed(root, use_span, index, assignments, file, src)
    {
        return None;
    }
    python_imported_text_identity(rendered, imports)
}

fn python_provider_root_is_lexically_shadowed(
    root: &str,
    use_span: Span,
    index: &DeclIndex,
    assignments: &[Node<'_>],
    file: FileId,
    src: &[u8],
) -> bool {
    let enclosing = index
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) && decl.span.start <= use_span.start
                && use_span.end <= decl.span.end
        })
        .min_by_key(|decl| decl.span.len());

    if let Some(owner) = enclosing {
        if owner.params.iter().any(|parameter| parameter == root)
            || assignments.iter().any(|assignment| {
                python_lexical_owner(index, span_of(file, assignment)) == Some(owner.span)
                    && assignment.child_by_field_name("left").is_some_and(|left| {
                        left.kind() == "identifier" && node_text(&left, src).trim() == root
                    })
            })
            || index
                .defs
                .iter()
                .any(|decl| decl.parent == Some(owner.symbol) && decl.name == root)
        {
            return true;
        }
    }

    // A module binding competes with an imported spelling for every nested
    // callable. At module execution sites source order is exact; inside a
    // callable, invocation order is external, so any module-level writer is
    // ambiguous and must fail closed.
    let nested_use = enclosing.is_some();
    assignments.iter().any(|assignment| {
        python_lexical_owner(index, span_of(file, assignment)).is_none()
            && assignment
                .child_by_field_name("left")
                .is_some_and(|left| left.kind() == "identifier" && node_text(&left, src).trim() == root)
            && (nested_use || assignment.end_byte() as u64 <= use_span.start)
    }) || index.defs.iter().any(|decl| {
        decl.parent.is_none() && decl.name == root && (nested_use || decl.span.end <= use_span.start)
    })
}

fn python_imported_text_identity(rendered: &str, imports: &[ImportSpec]) -> Option<String> {
    if rendered.is_empty() {
        return None;
    }
    for import in imports {
        if let Some(original) = import.original_name.as_deref() {
            let local = import.alias.as_deref().unwrap_or(original);
            if rendered == local {
                return Some(format!("{}.{}", import.module, original));
            }
            if let Some(suffix) = rendered
                .strip_prefix(local)
                .and_then(|tail| tail.strip_prefix('.'))
            {
                return Some(format!("{}.{}.{}", import.module, original, suffix));
            }
            continue;
        }
        if rendered == import.module || rendered.starts_with(&format!("{}.", import.module)) {
            return Some(rendered.to_string());
        }
        let Some(local) = import.alias.as_deref() else {
            continue;
        };
        if rendered == local {
            return Some(import.module.clone());
        }
        if let Some(suffix) = rendered
            .strip_prefix(local)
            .and_then(|tail| tail.strip_prefix('.'))
        {
            return Some(format!("{}.{}", import.module, suffix));
        }
    }
    None
}

fn python_collect_or_terms<'tree>(node: Node<'tree>, src: &[u8], out: &mut Vec<Node<'tree>>) {
    if node.kind() == "boolean_operator" {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            out.push(node);
            return;
        };
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        if operator == Some("or") {
            python_collect_or_terms(left, src, out);
            python_collect_or_terms(right, src, out);
            return;
        }
    }
    out.push(node);
}

fn python_attribute_component(node: Node<'_>, object: &str, src: &[u8]) -> Option<String> {
    let (receiver, name) = python_attribute_parts(node, src)?;
    (receiver.kind() == "identifier" && node_text(&receiver, src).trim() == object).then(|| name.to_string())
}

fn python_guarded_predicate_call(
    mut node: Node<'_>,
    receiver: &str,
    file: FileId,
    src: &[u8],
) -> Option<(bonsai_common::Span, bool)> {
    let negated = node.kind() == "not_operator";
    if negated {
        node = node.named_child(0)?;
    }
    let (function, _arguments) = python_call_parts(node)?;
    let (object, _method) = python_attribute_parts(function, src)?;
    if object.kind() != "identifier" || node_text(&object, src).trim() != receiver {
        return None;
    }
    Some((span_of(file, &node), negated))
}

fn python_block_static_return(block: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = block.walk();
    let statements: Vec<_> = block
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .collect();
    let [return_node] = statements.as_slice() else {
        return None;
    };
    (return_node.kind() == "return_statement")
        .then(|| {
            return_node
                .named_child(0)
                .and_then(|value| python_static_string(value, src))
        })
        .flatten()
}

fn python_return_is_exact_place(return_node: Node<'_>, expected: &str, src: &[u8]) -> bool {
    return_node.kind() == "return_statement"
        && return_node
            .named_child(0)
            .is_some_and(|value| value.kind() == "identifier" && node_text(&value, src).trim() == expected)
}

/// Lower Python string concatenation and `value or literal` fallback syntax
/// into a complete, typed composition. Unsupported operands fail closed, so
/// consumers never infer safety from a partial expression.
fn python_string_compositions(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    call_arguments: &[bonsai_lang_api::CallArgumentValueFact],
) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let mut parts = Vec::new();
        let mut dynamic_spans = Vec::new();
        if lower_python_string_composition(value, file, src, &mut parts, &mut dynamic_spans)
            && parts.len() > 1
        {
            facts.push(StringCompositionFact {
                container_span: span_of(file, &assignment),
                value_span: span_of(file, &value),
                target: Some(node_text(&target, src).trim().to_string()),
                dynamic_anchor_span: (dynamic_spans.len() == 1).then(|| dynamic_spans[0]),
                parts,
            });
        }
    }
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let Some(value) = return_node.named_child(0) else {
            continue;
        };
        let mut parts = Vec::new();
        let mut dynamic_spans = Vec::new();
        if lower_python_string_composition(value, file, src, &mut parts, &mut dynamic_spans)
            && parts.len() > 1
        {
            facts.push(StringCompositionFact {
                container_span: span_of(file, &return_node),
                value_span: span_of(file, &value),
                target: None,
                dynamic_anchor_span: (dynamic_spans.len() == 1).then(|| dynamic_spans[0]),
                parts,
            });
        }
    }
    // Direct call arguments are executable value expressions too. Join the
    // ordinary compiler argument directory through Tree-sitter's exact range
    // lookup; never rescan the complete tree once per argument.
    for argument in call_arguments {
        let Some(value) = bonsai_lang_api::kit::node_at_span(
            tree.root_node(),
            argument.argument_span,
            &["binary_operator", "string", "parenthesized_expression"],
        )
        .filter(|node| span_of(file, node) == argument.argument_span) else {
            continue;
        };
        let mut parts = Vec::new();
        let mut dynamic_spans = Vec::new();
        if lower_python_string_composition(value, file, src, &mut parts, &mut dynamic_spans)
            && parts.len() > 1
        {
            facts.push(StringCompositionFact {
                container_span: argument.argument_span,
                value_span: argument.argument_span,
                target: None,
                dynamic_anchor_span: (dynamic_spans.len() == 1).then(|| dynamic_spans[0]),
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

fn lower_python_string_composition(
    mut node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<StringCompositionPart>,
    dynamic_spans: &mut Vec<Span>,
) -> bool {
    while matches!(node.kind(), "parenthesized_expression") {
        let Some(inner) = node.named_child(0) else {
            return false;
        };
        node = inner;
    }
    if let Some(value) = python_static_string(node, src) {
        out.push(StringCompositionPart::Literal { value });
        return true;
    }
    if node.kind() == "string" && lower_python_formatted_string(node, file, src, out, dynamic_spans) {
        return true;
    }
    if let Some(place) = python_exact_place(node, src) {
        out.push(StringCompositionPart::Place { place });
        dynamic_spans.push(span_of(file, &node));
        return true;
    }
    if let Some((function, _)) = python_call_parts(node) {
        out.push(StringCompositionPart::Call {
            span: span_of(file, &function),
        });
        return true;
    }
    if node.kind() == "binary_operator" {
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
        return operator == Some("+")
            && lower_python_string_composition(left, file, src, out, dynamic_spans)
            && lower_python_string_composition(right, file, src, out, dynamic_spans);
    }
    if node.kind() == "boolean_operator" {
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
        let (Some(place), Some(fallback)) = (python_exact_place(left, src), python_static_string(right, src))
        else {
            return false;
        };
        if operator == Some("or") {
            out.push(StringCompositionPart::PlaceOrLiteral { place, fallback });
            dynamic_spans.push(span_of(file, &left));
            return true;
        }
    }
    false
}

fn lower_python_formatted_string(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<StringCompositionPart>,
    dynamic_spans: &mut Vec<Span>,
) -> bool {
    let text = node_text(&node, src).trim();
    let Some(quote_start) = text.find(['\'', '"']) else {
        return false;
    };
    let prefix = text[..quote_start].to_ascii_lowercase();
    if !prefix.contains('f')
        || prefix.contains('b')
        || prefix
            .chars()
            .any(|character| !matches!(character, 'f' | 'r' | 'u'))
    {
        return false;
    }
    let mut saw_interpolation = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" | "string_end" => {}
            "string_content" => {
                let value = node_text(&child, src);
                if value.contains('\\') {
                    return false;
                }
                push_python_composition_literal(out, value);
            }
            "interpolation" => {
                let Some(expression) = child
                    .child_by_field_name("expression")
                    .or_else(|| child.named_child(0))
                else {
                    return false;
                };
                let Some(place) = python_exact_place(expression, src) else {
                    return false;
                };
                out.push(StringCompositionPart::Place { place });
                dynamic_spans.push(span_of(file, &expression));
                saw_interpolation = true;
            }
            _ => return false,
        }
    }
    saw_interpolation
}

fn push_python_composition_literal(out: &mut Vec<StringCompositionPart>, value: &str) {
    if value.is_empty() {
        return;
    }
    if let Some(StringCompositionPart::Literal { value: previous }) = out.last_mut() {
        previous.push_str(value);
    } else {
        out.push(StringCompositionPart::Literal {
            value: value.to_string(),
        });
    }
}

fn python_exact_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let name = node_text(&node, src).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            let object = python_exact_place(object, src)?;
            let attribute = node_text(&attribute, src).trim();
            (!attribute.is_empty()).then(|| format!("{object}.{attribute}"))
        }
        "parenthesized_expression" => python_exact_place(node.named_child(0)?, src),
        _ => None,
    }
}

/// Walk every function/method/lambda body once and record the
/// parameter type-alias bindings emitted by typed parameters. Returns
/// `(decl_span, aliases)` pairs so `extract_declarations` can attach them to
/// the right `Decl`.
fn collect_python_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_definition", "lambda"]) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        if let Some(params) = fn_node.child_by_field_name("parameters") {
            collect_python_parameter_aliases(params, src, &mut aliases);
        }
        if let Some(body) = fn_node.child_by_field_name("body") {
            collect_python_annotated_assignment_aliases(body, src, &mut aliases);
        }
        dedup_python_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            out.push((span_of(file, &fn_node), aliases));
        }
    }
    out
}

/// Collect exact local / receiver-field annotations from one function body.
/// Nested callables and classes own separate declaration scopes and are
/// indexed independently, so this walk deliberately does not descend into
/// them.
fn collect_python_annotated_assignment_aliases(node: Node<'_>, src: &[u8], out: &mut Vec<TypeAliasBinding>) {
    if node.kind() == "assignment" {
        if let (Some(left), Some(type_node)) =
            (node.child_by_field_name("left"), node.child_by_field_name("type"))
        {
            if let (Some(place), Some(type_name)) = (
                python_exact_place(left, src),
                canonical_python_type_from_node(type_node, src),
            ) {
                push_python_type_alias(out, &place, &type_name);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "function_definition" | "lambda" | "class_definition"
        ) {
            continue;
        }
        collect_python_annotated_assignment_aliases(child, src, out);
    }
}

/// Collect direct parameter-default calls without assigning them any
/// framework semantics. For example, both `x = Body(...)` and
/// `x = project.Body(...)` become syntax facts owned by the matching
/// parameter; rulepack `default_call` constraints decide whether either fact
/// represents a source, sanitizer, or other security boundary.
fn collect_python_param_default_calls(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<(String, String)>)> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_definition", "lambda"]) {
        let mut calls = Vec::new();
        if let Some(params) = fn_node.child_by_field_name("parameters") {
            collect_python_parameter_default_calls(params, src, &mut calls);
        }
        dedup_python_param_default_calls(&mut calls);
        if !calls.is_empty() {
            out.push((span_of(file, &fn_node), calls));
        }
    }
    out
}

fn collect_python_parameter_default_calls(node: Node<'_>, src: &[u8], out: &mut Vec<(String, String)>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "typed_default_parameter" | "default_parameter" => {
                if let Some(binding) = python_param_default_call(child, src) {
                    out.push(binding);
                }
            }
            _ => collect_python_parameter_default_calls(child, src, out),
        }
    }
}

fn python_param_default_call(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    let name_node = node
        .child_by_field_name("name")
        .or_else(|| first_named_child_of_kind(node, &["identifier"]))?;
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value_node = node.child_by_field_name("value")?;
    if value_node.kind() != "call" {
        return None;
    }
    let function = value_node.child_by_field_name("function")?;
    let callee = python_exact_place(function, src)?;
    Some((name, callee))
}

fn dedup_python_param_default_calls(calls: &mut Vec<(String, String)>) {
    let mut deduped = Vec::new();
    for (name, callee) in calls.drain(..) {
        if !deduped
            .iter()
            .any(|(existing_name, existing_callee)| existing_name == &name && existing_callee == &callee)
        {
            deduped.push((name, callee));
        }
    }
    *calls = deduped;
}

fn merge_python_param_default_calls(decl: &mut bonsai_lang_api::Decl, calls: &[(String, String)]) {
    if decl.params.is_empty() || calls.is_empty() {
        return;
    }
    if decl.param_default_calls.len() < decl.params.len() {
        decl.param_default_calls.resize_with(decl.params.len(), Vec::new);
    }
    for (name, callee) in calls {
        let Some(idx) = decl.params.iter().position(|param| param == name) else {
            continue;
        };
        let defaults = &mut decl.param_default_calls[idx];
        if !defaults.iter().any(|existing| existing == callee) {
            defaults.push(callee.clone());
            defaults.sort();
            defaults.dedup();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PythonPropertyAlias {
    class_symbol: SymbolId,
    property_name: String,
    receiver_name: String,
    target_tail: String,
}

fn collect_python_property_function_spans(tree: &Tree, file: FileId, src: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    for decorated in collect_kinds(tree, &["decorated_definition"]) {
        if !python_decorated_definition_has_property(&decorated, src) {
            continue;
        }
        let Some(function) = first_named_child_of_kind(decorated, &["function_definition"]) else {
            continue;
        };
        let span = span_of(file, &function);
        if !spans.contains(&span) {
            spans.push(span);
        }
    }
    spans
}

fn python_decorated_definition_has_property(node: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    let has_property = node
        .named_children(&mut cursor)
        .any(|child| child.kind() == "decorator" && python_decorator_is_property(&child, src));
    has_property
}

fn python_decorator_is_property(node: &Node<'_>, src: &[u8]) -> bool {
    let text = node_text(node, src).trim();
    text.strip_prefix('@')
        .map(str::trim)
        .is_some_and(|decorator| decorator == "property")
}

fn collect_python_property_aliases(idx: &DeclIndex, property_fn_spans: &[Span]) -> Vec<PythonPropertyAlias> {
    let mut aliases = Vec::new();
    for decl in &idx.defs {
        if !property_fn_spans.contains(&decl.span) {
            continue;
        }
        let Some(class_symbol) = decl.parent else {
            continue;
        };
        let Some(receiver_idx) = decl.receiver_param_index else {
            continue;
        };
        let Some(receiver_name) = decl.params.get(receiver_idx) else {
            continue;
        };
        let Some(target_tail) = python_property_return_tail(decl, receiver_name) else {
            continue;
        };
        aliases.push(PythonPropertyAlias {
            class_symbol,
            property_name: decl.name.clone(),
            receiver_name: receiver_name.clone(),
            target_tail,
        });
    }
    aliases
}

fn python_property_return_tail(decl: &bonsai_lang_api::Decl, receiver_name: &str) -> Option<String> {
    for event in &decl.flow_events {
        if let Some(tail) = python_property_return_tail_from_event(event, receiver_name) {
            return Some(tail);
        }
    }
    None
}

fn python_property_return_tail_from_event(
    event: &bonsai_lang_api::FlowEvent,
    receiver_name: &str,
) -> Option<String> {
    match event {
        bonsai_lang_api::FlowEvent::Return { value_flow, .. } => value_flow
            .projection
            .as_ref()
            .filter(|projection| projection.base == receiver_name)
            .map(|projection| projection.path.join("."))
            .filter(|tail| !tail.is_empty()),
        bonsai_lang_api::FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => then_events
            .iter()
            .chain(else_events.iter())
            .find_map(|event| python_property_return_tail_from_event(event, receiver_name)),
        bonsai_lang_api::FlowEvent::Loop { body, .. }
        | bonsai_lang_api::FlowEvent::Defer { body, .. }
        | bonsai_lang_api::FlowEvent::Using { body, .. } => body
            .iter()
            .find_map(|event| python_property_return_tail_from_event(event, receiver_name)),
        bonsai_lang_api::FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => body
            .iter()
            .chain(catch_events.iter())
            .chain(finally_events.iter())
            .find_map(|event| python_property_return_tail_from_event(event, receiver_name)),
        _ => None,
    }
}

fn python_property_aliases_for_decl(
    idx: &DeclIndex,
    decl: &bonsai_lang_api::Decl,
    property_aliases: &[PythonPropertyAlias],
) -> Vec<PythonPropertyAlias> {
    let Some(class_symbol) = decl.parent else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen_classes = std::collections::HashSet::new();
    collect_python_property_aliases_for_class(
        idx,
        class_symbol,
        property_aliases,
        &mut seen_classes,
        &mut out,
    );
    if let Some(receiver_name) = python_decl_receiver_name(decl) {
        for alias in &mut out {
            alias.receiver_name.clone_from(&receiver_name);
        }
    }
    out
}

fn python_decl_receiver_name(decl: &bonsai_lang_api::Decl) -> Option<String> {
    decl.receiver_param_index
        .and_then(|idx| decl.params.get(idx))
        .filter(|name| !name.trim().is_empty())
        .cloned()
}

fn python_property_aliases_by_decl(
    idx: &DeclIndex,
    property_aliases: &[PythonPropertyAlias],
) -> std::collections::HashMap<SymbolId, Vec<PythonPropertyAlias>> {
    let mut by_decl = std::collections::HashMap::new();
    for decl in &idx.defs {
        let aliases = python_property_aliases_for_decl(idx, decl, property_aliases);
        if !aliases.is_empty() {
            by_decl.insert(decl.symbol, aliases);
        }
    }
    by_decl
}

fn collect_python_property_aliases_for_class(
    idx: &DeclIndex,
    class_symbol: SymbolId,
    property_aliases: &[PythonPropertyAlias],
    seen_classes: &mut std::collections::HashSet<SymbolId>,
    out: &mut Vec<PythonPropertyAlias>,
) {
    if !seen_classes.insert(class_symbol) {
        return;
    }
    for alias in property_aliases
        .iter()
        .filter(|alias| alias.class_symbol == class_symbol)
    {
        if !out.iter().any(|existing| existing == alias) {
            out.push(alias.clone());
        }
    }
    let Some(class_decl) = idx.defs.iter().find(|decl| decl.symbol == class_symbol) else {
        return;
    };
    for base in &class_decl.bases {
        let Some(base_symbol) = idx
            .defs
            .iter()
            .find(|decl| {
                matches!(decl.kind, bonsai_lang_api::DeclKind::Class)
                    && (decl.name == *base || decl.name == base.rsplit('.').next().unwrap_or(base))
            })
            .map(|decl| decl.symbol)
        else {
            continue;
        };
        collect_python_property_aliases_for_class(idx, base_symbol, property_aliases, seen_classes, out);
    }
}

fn augment_python_property_flow_events(
    events: &mut [bonsai_lang_api::FlowEvent],
    property_aliases: &[PythonPropertyAlias],
) {
    if property_aliases.is_empty() {
        return;
    }
    for event in events {
        match event {
            bonsai_lang_api::FlowEvent::Assign { source_names, .. } => {
                augment_python_property_source_names(source_names, property_aliases);
            }
            bonsai_lang_api::FlowEvent::Call { args, .. } => {
                for arg in args {
                    augment_python_property_source_names(&mut arg.source_names, property_aliases);
                }
            }
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_property_flow_events(then_events, property_aliases);
                augment_python_property_flow_events(else_events, property_aliases);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                augment_python_property_flow_events(body, property_aliases);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_property_flow_events(body, property_aliases);
                augment_python_property_flow_events(catch_events, property_aliases);
                augment_python_property_flow_events(finally_events, property_aliases);
            }
            _ => {}
        }
    }
}

fn augment_python_property_source_names(
    source_names: &mut Vec<String>,
    property_aliases: &[PythonPropertyAlias],
) {
    let existing = source_names.clone();
    for source in existing {
        for alias in property_aliases {
            if let Some(rewritten) = python_property_alias_source_name(&source, alias) {
                push_python_source_name(source_names, rewritten);
            }
        }
    }
}

fn python_property_alias_source_name(source: &str, alias: &PythonPropertyAlias) -> Option<String> {
    let prefix = format!("{}.{}", alias.receiver_name, alias.property_name);
    let source = source.trim();
    if source == prefix {
        return Some(format!("{}.{}", alias.receiver_name, alias.target_tail));
    }
    let tail = source.strip_prefix(&prefix)?.strip_prefix('.')?;
    if tail.is_empty() {
        return None;
    }
    Some(format!("{}.{}.{}", alias.receiver_name, alias.target_tail, tail))
}

fn collect_python_comprehension_iterable_call_events(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    decl_span: Span,
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for clause in collect_kinds(tree, &["for_in_clause"]) {
        let clause_span = span_of(file, &clause);
        if !python_span_contains(decl_span, clause_span) || !python_for_in_clause_is_comprehension(&clause) {
            continue;
        }
        let Some(iterable) = clause.child_by_field_name("right") else {
            continue;
        };
        collect_python_call_events_from_node(iterable, file, src, &mut out);
    }
    out.sort_by_key(|event| python_flow_event_span(event).start);
    out.dedup_by(|left, right| python_flow_event_same_call(left, right));
    out
}

fn python_for_in_clause_is_comprehension(clause: &Node<'_>) -> bool {
    let mut parent = clause.parent();
    while let Some(node) = parent {
        if matches!(
            node.kind(),
            "list_comprehension" | "dictionary_comprehension" | "set_comprehension" | "generator_expression"
        ) {
            return true;
        }
        if matches!(
            node.kind(),
            "function_definition" | "lambda" | "for_statement" | "while_statement" | "if_statement" | "block"
        ) {
            return false;
        }
        parent = node.parent();
    }
    false
}

fn collect_python_call_events_from_node(node: Node<'_>, file: FileId, src: &[u8], out: &mut Vec<FlowEvent>) {
    if node.kind() == "call" {
        if let Some(event) = build_python_call_event(node, file, src) {
            out.push(event);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_call_events_from_node(child, file, src, out);
    }
}

fn build_python_call_event(node: Node<'_>, file: FileId, src: &[u8]) -> Option<FlowEvent> {
    if node.kind() != "call" {
        return None;
    }
    let callee_node = node.child_by_field_name("function")?;
    let name = normalize_call_name_whitespace(node_text(&callee_node, src));
    if name.is_empty() {
        return None;
    }
    let receiver = python_call_receiver_from_name(&name);
    let call_kind = if receiver.is_some() {
        CallKind::Method
    } else {
        CallKind::Function
    };
    let mut args = Vec::new();
    if let Some(arguments) = node.child_by_field_name("arguments") {
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            let (name, value_node) = if arg.kind() == "keyword_argument" {
                let key = arg
                    .child_by_field_name("name")
                    .map(|node| node_text(&node, src).trim().to_string())
                    .filter(|name| !name.is_empty());
                let value = arg.child_by_field_name("value").unwrap_or(arg);
                (key, value)
            } else {
                (None, arg)
            };
            if let Some(argument) =
                call_arg_from_nodes_with_handler(arg, value_node, file, src, name, &HANDLER)
            {
                let mut argument = argument;
                if let Some(place) = python_exact_expression_place(value_node, src) {
                    argument.place = Some(place);
                }
                args.push(argument);
            }
        }
    }
    Some(FlowEvent::Call {
        span: span_of(file, &callee_node),
        name,
        receiver,
        receiver_types: Vec::new(),
        call_kind,
        args,
    })
}

/// Exact addressable call arguments lowered from Python's Tree-sitter nodes.
///
/// The shared call walker deliberately does not interpret language syntax.
/// Python static subscripts therefore have to become canonical compiler
/// places here: `obj["field"]` is `obj.field`, while `obj[key]` remains an
/// aggregate read because its selected field is not statically known.
fn collect_python_call_argument_places(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            let value = if argument.kind() == "keyword_argument" {
                argument.child_by_field_name("value").unwrap_or(argument)
            } else {
                argument
            };
            let Some(place) = python_exact_expression_place(value, src) else {
                continue;
            };
            out.push((span_of(file, &argument), place));
        }
    }
    out.sort_by_key(|(span, _)| (span.start, span.end));
    out.dedup_by_key(|(span, _)| *span);
    out
}

fn python_exact_expression_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let name = node_text(&node, src).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            let base = python_exact_expression_place(object, src)?;
            let field = node_text(&attribute, src).trim();
            (!field.is_empty()).then(|| format!("{base}.{field}"))
        }
        "subscript" => {
            let value = node.child_by_field_name("value")?;
            let subscript = node.child_by_field_name("subscript")?;
            let base = python_exact_expression_place(value, src)?;
            let field = python_static_string(subscript, src)?;
            if field.is_empty()
                || !field
                    .chars()
                    .next()
                    .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
                || !field.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            {
                return None;
            }
            Some(format!("{base}.{field}"))
        }
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            let child = node.named_children(&mut cursor).next()?;
            python_exact_expression_place(child, src)
        }
        _ => None,
    }
}

/// Exact addressable return operands lowered from Python's Tree-sitter nodes.
/// Static attribute/subscript returns carry their complete storage place;
/// dynamic subscripts deliberately retain the generic aggregate fact.
fn collect_python_return_places(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for statement in collect_kinds(tree, &["return_statement"]) {
        let Some(value) = statement.named_child(0) else {
            continue;
        };
        let Some(place) = python_exact_expression_place(value, src) else {
            continue;
        };
        out.push((span_of(file, &statement), place));
    }
    out.sort_by_key(|(span, _)| (span.start, span.end));
    out.dedup_by_key(|(span, _)| *span);
    out
}

fn apply_python_return_places(events: &mut [FlowEvent], places: &[(Span, String)]) {
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_name,
                value_flow,
                ..
            } => {
                if let Ok(index) = places.binary_search_by_key(&(span.start, span.end), |(candidate, _)| {
                    (candidate.start, candidate.end)
                }) {
                    let place = places[index].1.clone();
                    *value_name = Some(place.clone());
                    value_flow.place = Some(place.clone());
                    value_flow.source_names.clear();
                    value_flow.source_names.push(place);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_python_return_places(then_events, places);
                apply_python_return_places(else_events, places);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_python_return_places(body, places);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_python_return_places(body, places);
                apply_python_return_places(catch_events, places);
                apply_python_return_places(finally_events, places);
            }
            _ => {}
        }
    }
}

fn apply_python_call_argument_places(events: &mut [FlowEvent], places: &[(Span, String)]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for argument in args {
                    if let Ok(index) = places
                        .binary_search_by_key(&(argument.span.start, argument.span.end), |(span, _)| {
                            (span.start, span.end)
                        })
                    {
                        argument.place = Some(places[index].1.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_python_call_argument_places(then_events, places);
                apply_python_call_argument_places(else_events, places);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_python_call_argument_places(body, places);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_python_call_argument_places(body, places);
                apply_python_call_argument_places(catch_events, places);
                apply_python_call_argument_places(finally_events, places);
            }
            _ => {}
        }
    }
}

/// Lower the value delivered by a direct iterable call into a sparse
/// yield-result binding. Python uses the same `for_statement` grammar shape
/// for synchronous and asynchronous iteration; the IDG only activates this
/// relation when resolution proves that the callee owns a `Yield` endpoint.
/// Ordinary container-returning calls therefore retain their existing return
/// semantics, while generator fields remain field-precise at the loop target.
fn collect_python_iterable_yield_bindings(tree: &Tree, file: FileId, src: &[u8]) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for loop_node in collect_kinds(tree, &["for_statement"]) {
        let (Some(binding), Some(iterable)) = (
            loop_node.child_by_field_name("left"),
            loop_node.child_by_field_name("right"),
        ) else {
            continue;
        };
        let Some(FlowEvent::Call { name, args, .. }) = build_python_call_event(iterable, file, src) else {
            continue;
        };
        let source_call_args = args.into_iter().map(|arg| arg.value_text).collect::<Vec<_>>();
        for target in python_loop_binding_targets(binding, src) {
            out.push(FlowEvent::Assign {
                // Use the loop statement's write span, not the callee token.
                // The generic frontend already lowered the loop binding at
                // this span. Inserting the sparse YieldResult relation next
                // to that event reuses the same IDG write node, so unresolved
                // ordinary iterables cannot overwrite and kill the compiler's
                // local loop flow. `assign_call_site_hint` still joins this
                // containing span to the exact sibling Call event.
                span: span_of(file, &loop_node),
                target,
                source_name: None,
                source_call: Some(name.clone()),
                source_call_args: source_call_args.clone(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::YieldResult),
            });
        }
    }
    out.sort_by_key(|event| {
        let span = python_flow_event_span(event);
        let target = match event {
            FlowEvent::Assign { target, .. } => target.as_str(),
            _ => "",
        };
        (span.start, span.end, target.to_string())
    });
    out.dedup_by(|left, right| match (left, right) {
        (
            FlowEvent::Assign {
                span: left_span,
                target: left_target,
                source_call: left_call,
                ..
            },
            FlowEvent::Assign {
                span: right_span,
                target: right_target,
                source_call: right_call,
                ..
            },
        ) => left_span == right_span && left_target == right_target && left_call == right_call,
        _ => false,
    });
    out
}

/// Place Python's generator relation beside the generic loop-binding event.
///
/// The shared walker lowers a `for` binding before its `Loop` body. Keeping
/// this adapter-owned refinement in the same event vector and at the same
/// statement span makes both facts refer to one compiler write. Appending it
/// inside the body would create a later definition and incorrectly erase the
/// generic binding whenever the iterable resolves to external code.
fn insert_python_iterable_yield_bindings(events: &mut Vec<FlowEvent>, bindings: &[FlowEvent]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_python_iterable_yield_bindings(then_events, bindings);
                insert_python_iterable_yield_bindings(else_events, bindings);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_python_iterable_yield_bindings(body, bindings);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_python_iterable_yield_bindings(body, bindings);
                insert_python_iterable_yield_bindings(catch_events, bindings);
                insert_python_iterable_yield_bindings(finally_events, bindings);
            }
            _ => {}
        }
    }

    let loop_spans = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Loop { span, .. } => Some(*span),
            _ => None,
        })
        .collect::<Vec<_>>();
    for loop_span in loop_spans {
        let Some(mut insert_at) = events
            .iter()
            .position(|event| matches!(event, FlowEvent::Loop { span, .. } if *span == loop_span))
        else {
            continue;
        };
        for binding in bindings
            .iter()
            .filter(|binding| python_flow_event_span(binding) == loop_span)
        {
            let mut binding = binding.clone();
            // Tuple loop bindings are lowered twice at the same statement:
            // the generic call-result fallback owns an exact synthetic tuple
            // projection, while this Python refinement adds the generator
            // yield alternative. Give both facts the same compiler place so
            // the refinement cannot become a later clean overwrite merely
            // because the target was destructured.
            if let FlowEvent::Assign {
                target,
                source_names,
                value_kind: Some(bonsai_lang_api::AssignValueKind::YieldResult),
                ..
            } = &mut binding
            {
                if let Some(tuple_sources) = events.iter().find_map(|existing| match existing {
                    FlowEvent::Assign {
                        span,
                        target: existing_target,
                        source_names: existing_sources,
                        value_kind,
                        ..
                    } if *span == loop_span
                        && existing_target == target
                        && !matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::YieldResult))
                        && existing_sources.iter().any(|source| {
                            source.starts_with(bonsai_lang_api::kit::SYNTHETIC_TUPLE_RESULT_PREFIX)
                        }) =>
                    {
                        Some(existing_sources.clone())
                    }
                    _ => None,
                }) {
                    *source_names = tuple_sources;
                }
            }
            if events.iter().any(|existing| existing == &binding) {
                continue;
            }
            events.insert(insert_at, binding);
            insert_at += 1;
        }
    }
}

fn python_loop_binding_targets(node: Node<'_>, src: &[u8]) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if node.kind() == "identifier" {
            let name = node_text(&node, src).trim();
            if python_match_capture_identifier(name) {
                out.push(name.to_string());
            }
            return;
        }
        if !matches!(
            node.kind(),
            "pattern_list" | "tuple_pattern" | "list_pattern" | "list_splat_pattern"
        ) {
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
    out
}

fn python_call_receiver_from_name(name: &str) -> Option<String> {
    let (receiver, _) = name.rsplit_once('.')?;
    let receiver = receiver.trim();
    (!receiver.is_empty()).then(|| receiver.to_string())
}

fn insert_python_flow_events_by_span(events: &mut Vec<FlowEvent>, owner_span: Span, synthetic: &[FlowEvent]) {
    for event in events.iter_mut() {
        let event_span = python_flow_event_span(event);
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_python_flow_events_by_span(then_events, event_span, synthetic);
                insert_python_flow_events_by_span(else_events, event_span, synthetic);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_python_flow_events_by_span(body, event_span, synthetic);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_python_flow_events_by_span(body, event_span, synthetic);
                insert_python_flow_events_by_span(catch_events, event_span, synthetic);
                insert_python_flow_events_by_span(finally_events, event_span, synthetic);
            }
            _ => {}
        }
    }

    let mut pending: Vec<FlowEvent> = synthetic
        .iter()
        .filter(|event| {
            let span = python_flow_event_span(event);
            python_span_contains(owner_span, span)
                && !python_event_tree_contains_call(events, event)
                && !events.iter().any(|candidate| {
                    python_flow_event_is_container(candidate)
                        && python_span_contains(python_flow_event_span(candidate), span)
                })
        })
        .cloned()
        .collect();
    pending.sort_by_key(|event| python_flow_event_span(event).start);
    for event in pending {
        let span = python_flow_event_span(&event);
        let insert_at = events
            .iter()
            .position(|existing| python_flow_event_span(existing).start > span.start)
            .unwrap_or(events.len());
        events.insert(insert_at, event);
    }
}

fn python_flow_event_is_container(event: &FlowEvent) -> bool {
    matches!(
        event,
        FlowEvent::Branch { .. }
            | FlowEvent::Loop { .. }
            | FlowEvent::Try { .. }
            | FlowEvent::Defer { .. }
            | FlowEvent::Using { .. }
    )
}

fn python_event_tree_contains_call(events: &[FlowEvent], needle: &FlowEvent) -> bool {
    events.iter().any(|event| {
        python_flow_event_same_call(event, needle)
            || match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    python_event_tree_contains_call(then_events, needle)
                        || python_event_tree_contains_call(else_events, needle)
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => python_event_tree_contains_call(body, needle),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    python_event_tree_contains_call(body, needle)
                        || python_event_tree_contains_call(catch_events, needle)
                        || python_event_tree_contains_call(finally_events, needle)
                }
                _ => false,
            }
    })
}

fn python_flow_event_same_call(left: &FlowEvent, right: &FlowEvent) -> bool {
    matches!(
        (left, right),
        (
            FlowEvent::Call {
                span: left_span,
                name: left_name,
                ..
            },
            FlowEvent::Call {
                span: right_span,
                name: right_name,
                ..
            }
        ) if left_span == right_span && left_name == right_name
    )
}

fn push_python_source_name(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

fn python_match_capture_identifier(text: &str) -> bool {
    if matches!(
        text,
        "" | "_" | "True" | "False" | "None" | "case" | "if" | "in" | "and" | "or" | "not"
    ) {
        return false;
    }
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn python_span_owned_by_decl(span: Span, decl_span: Span, callable_spans: &[Span]) -> bool {
    if !python_span_contains(decl_span, span) {
        return false;
    }
    let Some(owner) = callable_spans
        .iter()
        .copied()
        .filter(|candidate| python_span_contains(*candidate, span))
        .min_by_key(|span| span.end.saturating_sub(span.start))
    else {
        return false;
    };
    owner == decl_span
}

fn python_span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn python_flow_event_span(event: &bonsai_lang_api::FlowEvent) -> Span {
    match event {
        bonsai_lang_api::FlowEvent::Assign { span, .. }
        | bonsai_lang_api::FlowEvent::AggregateAssign { span, .. }
        | bonsai_lang_api::FlowEvent::Call { span, .. }
        | bonsai_lang_api::FlowEvent::Return { span, .. }
        | bonsai_lang_api::FlowEvent::Throw { span, .. }
        | bonsai_lang_api::FlowEvent::Branch { span, .. }
        | bonsai_lang_api::FlowEvent::Loop { span, .. }
        | bonsai_lang_api::FlowEvent::Try { span, .. }
        | bonsai_lang_api::FlowEvent::Defer { span, .. }
        | bonsai_lang_api::FlowEvent::Using { span, .. }
        | bonsai_lang_api::FlowEvent::Yield { span, .. }
        | bonsai_lang_api::FlowEvent::Await { span, .. }
        | bonsai_lang_api::FlowEvent::Break { span, .. }
        | bonsai_lang_api::FlowEvent::Continue { span, .. }
        | bonsai_lang_api::FlowEvent::Lifecycle { span, .. } => *span,
    }
}

fn augment_python_dict_flow_events(
    events: &mut Vec<bonsai_lang_api::FlowEvent>,
    assignment_projected_reads: &[(Span, Vec<String>)],
) {
    for event in events.iter_mut() {
        match event {
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_dict_flow_events(then_events, assignment_projected_reads);
                augment_python_dict_flow_events(else_events, assignment_projected_reads);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                augment_python_dict_flow_events(body, assignment_projected_reads);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_dict_flow_events(body, assignment_projected_reads);
                augment_python_dict_flow_events(catch_events, assignment_projected_reads);
                augment_python_dict_flow_events(finally_events, assignment_projected_reads);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let mut synthetic = Vec::new();
        if let bonsai_lang_api::FlowEvent::Assign { span, target, .. } = &event {
            for field_read in assignment_projected_reads
                .binary_search_by_key(&(span.start, span.end), |(candidate, _)| {
                    (candidate.start, candidate.end)
                })
                .ok()
                .and_then(|index| assignment_projected_reads.get(index))
                .map_or(&[][..], |(_, reads)| reads.as_slice())
            {
                synthetic.push(bonsai_lang_api::FlowEvent::Assign {
                    span: *span,
                    target: target.clone(),
                    source_name: Some(field_read.clone()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec![field_read.clone()],
                    declares_new_binding: false,
                    value_kind: None,
                });
            }
        }
        rewritten.push(event);
        rewritten.extend(synthetic);
    }
    *events = rewritten;
}

/// AST-derived projected reads on assignment right-hand sides.
///
/// The generic expression walker intentionally treats a subscript as an
/// aggregate unless the owning adapter proves its key is static. Python can
/// prove literal string subscripts from the CST, so it emits an additional
/// exact read beside the conservative aggregate fact. Dynamic keys remain
/// aggregate reads and therefore cannot be mistaken for a sibling field.
fn collect_python_assignment_projected_reads(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<String>)> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if node.kind() == "subscript" {
            if let Some(place) = python_exact_expression_place(node, src) {
                push_python_source_name(out, place);
                return;
            }
        }
        if node.kind() == "call" {
            let selected_field = (|| {
                let function = node.child_by_field_name("function")?;
                let (receiver, method) = python_attribute_parts(function, src)?;
                if method != "get" {
                    return None;
                }
                let arguments = node.child_by_field_name("arguments")?;
                let first = python_argument_nodes(arguments).into_iter().next()?;
                let field = python_static_string(first, src)?;
                let base = python_exact_expression_place(receiver, src)?;
                Some(format!("{base}.{field}"))
            })();
            if let Some(place) = selected_field {
                push_python_source_name(out, place);
            }
            // A call is a semantic value boundary. A keyed read used as one
            // of its arguments does not become the call result:
            //
            //     repo = Repository(data, who=envelope.get("user"))
            //
            // The resolver/IDG owns argument-to-parameter and return
            // transfer. Recursing into an arbitrary call here used to lower
            // the example above as `repo <- envelope.user`, collapsing every
            // field of the constructed object into the `who` argument.
            // Exact `.get(literal)` calls remain value-producing projections
            // themselves; all other calls stop this assignment projection
            // walk, including constructors and user functions.
            return;
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, src, out);
        }
    }

    let mut reads = Vec::new();
    for assignment in collect_kinds(tree, &["assignment", "named_expression"]) {
        let Some(value) = assignment.child_by_field_name("right") else {
            continue;
        };
        // Aggregate members already lower independently to field writes.
        // Adding their projected operands as a second whole-target
        // assignment would overwrite those fields at the same statement and
        // erase the exact spread/return relation.
        if matches!(value.kind(), "dictionary" | "list" | "set" | "tuple") {
            continue;
        }
        let mut projected = Vec::new();
        collect(value, src, &mut projected);
        if !projected.is_empty() {
            reads.push((span_of(file, &assignment), projected));
        }
    }
    reads.sort_by_key(|(span, _)| (span.start, span.end));
    reads
}

fn collect_python_parameter_aliases(node: Node<'_>, src: &[u8], out: &mut Vec<TypeAliasBinding>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "typed_parameter" | "typed_default_parameter" => {
                python_typed_parameter_alias(child, src, out);
            }
            // Recurse for nested parameter lists (lambda's `parameters`
            // node sometimes nests under `lambda_parameters`).
            _ => collect_python_parameter_aliases(child, src, out),
        }
    }
}

fn python_typed_parameter_alias(node: Node<'_>, src: &[u8], out: &mut Vec<TypeAliasBinding>) {
    let Some(name_node) = first_named_child_of_kind(node, &["identifier"]) else {
        return;
    };
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return;
    }
    // Type annotation: `name: T` — `type` field, which is a `type` node
    // wrapping a `genericised_type` / `identifier` / etc.
    let type_node = node.child_by_field_name("type");
    if let Some(t) = type_node {
        if let Some(canonical) = canonical_python_type_from_node(t, src) {
            push_python_type_alias(out, &name, &canonical);
        }
    }
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kinds: &[&str]) -> Option<Node<'a>> {
    let count = node.named_child_count();
    for i in 0..count {
        let idx = u32::try_from(i).ok()?;
        let child = node.named_child(idx)?;
        if kinds.contains(&child.kind()) {
            return Some(child);
        }
    }
    None
}

/// Lower a Python type-annotation AST to the runtime receiver type used for
/// dispatch. Container generics keep their outer type (`list[str]` → `list`),
/// while typing-only wrappers expose their first payload (`Annotated[T, …]`
/// and `Optional[T]` → `T`). Union syntax chooses the first non-`None` arm.
fn canonical_python_type_from_node(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "type" | "parenthesized_expression" | "parenthesized_list_splat" => {
            let mut cursor = node.walk();
            let canonical = node
                .named_children(&mut cursor)
                .find_map(|child| canonical_python_type_from_node(child, src));
            canonical
        }
        "generic_type" | "subscript" => {
            let base = node
                .child_by_field_name("value")
                .or_else(|| node.named_child(0))?;
            let base_name = canonical_python_type_name(node_text(&base, src))?;
            let base_tail = bonsai_common::short_qualified_tail(&base_name);
            if matches!(
                base_tail,
                "Annotated" | "Optional" | "ClassVar" | "Final" | "Required" | "NotRequired"
            ) {
                let parameters = node
                    .child_by_field_name("subscript")
                    .or_else(|| node.named_child(1))?;
                if parameters.kind() != "type_parameter" && parameters.kind() != "type_parameter_list" {
                    return canonical_python_type_from_node(parameters, src);
                }
                let mut cursor = parameters.walk();
                return parameters
                    .named_children(&mut cursor)
                    .find_map(|child| canonical_python_type_from_node(child, src));
            }
            Some(base_name)
        }
        "union_type" | "binary_operator" => {
            let mut cursor = node.walk();
            let canonical = node.named_children(&mut cursor).find_map(|child| {
                let candidate = canonical_python_type_from_node(child, src)?;
                (!matches!(candidate.as_str(), "None" | "NoneType")).then_some(candidate)
            });
            canonical
        }
        _ => canonical_python_type_name(node_text(&node, src)),
    }
}

fn canonical_python_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().split('|').next().unwrap_or(raw).trim();
    let head = trimmed.split('[').next().unwrap_or(trimmed).trim();
    if head.is_empty() {
        return None;
    }
    // Preserve the exact source-qualified annotation. Receiver matching can
    // always compare its structural terminal type, while discarding the
    // provider here makes two distinct compiler identities indistinguishable
    // before import/local-shadow resolution can run.
    Some(head.to_string())
}

fn push_python_type_alias(out: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    out.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

fn dedup_python_type_aliases(out: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    out.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// Walk every `class_definition` once and record the bare base-type
/// names listed in the parenthesized parent list. `class C(A, B):`
/// → `[("A".into(), "B".into())]` keyed by the class decl's span.
fn collect_python_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, &["class_definition"]) {
        let Some(superclasses) = class_node.child_by_field_name("superclasses") else {
            continue;
        };
        let mut bases: Vec<String> = Vec::new();
        let count = superclasses.named_child_count();
        for i in 0..count {
            let Some(idx) = u32::try_from(i).ok() else {
                continue;
            };
            let Some(child) = superclasses.named_child(idx) else {
                continue;
            };
            // Skip kwargs and other non-base entries (`metaclass=Foo`).
            if child.kind() == "keyword_argument" {
                continue;
            }
            let raw = node_text(&child, src);
            if let Some(canonical) = canonical_python_type_name(raw) {
                if !bases.iter().any(|b| b == &canonical) {
                    bases.push(canonical);
                }
            }
        }
        if !bases.is_empty() {
            out.push((span_of(file, &class_node), bases));
        }
    }
    out
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    // `import X` / `import X as Y` — `import_statement` with one or more
    // `name:` children, each either a `dotted_name` or an
    // `aliased_import` (name + alias).
    for import_node in collect_kinds(tree, &["import_statement"]) {
        let mut cursor = import_node.walk();
        for child in import_node.named_children(&mut cursor) {
            // Two shapes: `import X` (dotted_name) or `import X as Y` (aliased_import).
            let (module_node, alias_text) = if child.kind() == "aliased_import" {
                let module_field = child.child_by_field_name("name");
                let alias_field = child
                    .child_by_field_name("alias")
                    .map(|alias_node| node_text(&alias_node, src).to_string());
                (module_field, alias_field)
            } else if child.kind() == "dotted_name" {
                (Some(child), None)
            } else {
                continue;
            };
            let Some(module_name_node) = module_node else {
                continue;
            };
            let module_name = node_text(&module_name_node, src).trim().to_string();
            if module_name.is_empty() {
                continue;
            }
            // Bare `import X` and `import X.Y` bind the FIRST segment
            // as the local name (`X` in both forms) — Python imports
            // a module by binding its head, not its leaf. Without a
            // self-binding alias here, the resolver cannot rewrite
            // `service.load_file(...)` through the workspace
            // `service` module, so cross-module edges from
            // `import`-form callers stay invisible. The `import X.Y
            // as Z` form already supplied an alias and skips this
            // fallback; wildcard imports never apply because
            // `import *` isn't a Python `import_statement` shape
            // (only `from X import *` is).
            let alias = alias_text.or_else(|| {
                module_name
                    .split('.')
                    .next()
                    .map(str::trim)
                    .filter(|leaf| !leaf.is_empty())
                    .map(str::to_string)
            });
            out.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module_name,
                alias,
                is_wildcard: false,
                original_name: None,
                scope: ImportScope::Module,
            });
        }
    }
    // `from X import Y [as Z]` / `from . import Y` — emit one ImportSpec
    // per imported symbol (`from x import y as z` → original=y, alias=z).
    for from_import_node in collect_kinds(tree, &["import_from_statement"]) {
        let Some(module_node) = from_import_node.child_by_field_name("module_name") else {
            continue;
        };
        let module_name = node_text(&module_node, src).trim().to_string();
        let mut cursor = from_import_node.walk();
        // (original_name, alias) pairs — one per imported symbol.
        let mut imported_symbols: Vec<(Option<String>, Option<String>)> = Vec::new();
        let mut is_wildcard = false;
        for child in from_import_node.named_children(&mut cursor) {
            // Skip the module child itself; we already captured it above.
            if child.id() == module_node.id() {
                continue;
            }
            if child.kind() == "wildcard_import" {
                is_wildcard = true;
                continue;
            }
            if child.kind() == "aliased_import" {
                let original_name = child
                    .child_by_field_name("name")
                    .map(|name_node| node_text(&name_node, src).to_string());
                let alias_text = child
                    .child_by_field_name("alias")
                    .map(|alias_node| node_text(&alias_node, src).to_string());
                imported_symbols.push((original_name, alias_text));
            } else if child.kind() == "dotted_name" {
                imported_symbols.push((Some(node_text(&child, src).to_string()), None));
            }
        }
        // Bare `from X import *` — emit a single wildcard ImportSpec.
        if imported_symbols.is_empty() {
            out.push(ImportSpec {
                span: span_of(file, &from_import_node),
                module: module_name,
                alias: None,
                is_wildcard,
                original_name: None,
                scope: ImportScope::Module,
            });
        } else {
            // One ImportSpec per imported symbol so call resolution can
            // bind `y` to the unaliased original name and `z` to the alias.
            for (original_name, alias_text) in imported_symbols {
                out.push(ImportSpec {
                    span: span_of(file, &from_import_node),
                    module: module_name.clone(),
                    alias: alias_text,
                    is_wildcard,
                    original_name,
                    scope: ImportScope::Module,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod pattern_tests {
    use super::*;

    #[test]
    fn match_bindings_follow_only_capture_positions_with_exact_projections() {
        let src = br#"match subject:
    case {"value": value, "nested": {"item": item}, **rest} if limit:
        pass
    case Point(x=px, y=py) as point:
        pass
"#;
        let mut parser = tree_sitter::Parser::new();
        let language = language_from_pack(PACK_NAME).expect("Python grammar");
        parser.set_language(&language).expect("Python grammar");
        let tree = parser.parse(src, None).expect("Python parse");
        let match_node = tree
            .root_node()
            .named_child(0)
            .expect("top-level match statement");
        let sites = python_pattern_bindings(match_node, src);
        let mut facts = sites
            .iter()
            .map(|site| {
                (
                    node_text(&site.target, src).trim().to_string(),
                    site.projection.clone(),
                )
            })
            .collect::<Vec<_>>();
        facts.sort_by(|left, right| left.0.cmp(&right.0));

        let mut expected = vec![
            (
                "item".to_string(),
                vec![
                    PatternSourceProjection::Field("nested".to_string()),
                    PatternSourceProjection::Field("item".to_string()),
                ],
            ),
            ("point".to_string(), Vec::<PatternSourceProjection>::new()),
            (
                "px".to_string(),
                vec![PatternSourceProjection::Field("x".to_string())],
            ),
            (
                "py".to_string(),
                vec![PatternSourceProjection::Field("y".to_string())],
            ),
            ("rest".to_string(), vec![PatternSourceProjection::Descendants]),
            (
                "value".to_string(),
                vec![PatternSourceProjection::Field("value".to_string())],
            ),
        ];
        expected.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(facts, expected);
    }
}
