//! Perl language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, collect_kinds, first_named_child_of_kind, language_from_pack,
        named_child_call_args_with_handler, node_at_span, node_text, parse_with,
        populate_call_argument_static_values, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, AssignmentNodeSemantics, AssignmentValueIndex, CallArg,
    CallKind, CallTargetExtraction, CompilerGuardFact, ConditionEquality, ConditionExpressionFact,
    ConditionOperandFact, DeclIndex, DeclKind, ExpressionPlaceExtraction, FieldWrite,
    FiniteLiteralSelectionFact, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath, Ref, RefKind, StaticScalarValue,
    StringCompositionFact, StringCompositionPart, TypeAliasBinding,
};

fn extract_perl_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() == "substitution_regexp" {
        let content = node.child_by_field_name("content")?;
        let mut args = vec![perl_call_arg_from_node(content, file, src, None)?];
        let replacement = node.child_by_field_name("replacement").or_else(|| {
            let mut cursor = node.walk();
            let replacement = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "replacement");
            replacement
        });
        if let Some(replacement) = replacement {
            args.push(perl_call_arg_from_node(replacement, file, src, None)?);
        }
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            args.push(perl_call_arg_from_node(modifiers, file, src, None)?);
        }
        return Some(FlowEvent::Call {
            span: span_of(file, &node),
            receiver: perl_substitution_receiver(node, src)
                .and_then(|receiver| perl_expression_places(receiver, src).places.into_iter().next())
                .or_else(|| Some("$_".to_string())),
            receiver_types: Vec::new(),
            name: "s".to_string(),
            call_kind: CallKind::Operator,
            args,
        });
    }
    let name = match node.kind() {
        "eval_expression" if node.named_child(0).is_none_or(|child| child.kind() != "block") => "eval",
        // `undef EXPR` is a Perl language operator with call-like value
        // semantics. The grammar gives it a dedicated node rather than a
        // function callee, so lower that syntax identity here and leave its
        // lifecycle meaning to rule data.
        "undef_expression" => "undef",
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

/// Return the exact mutable operand of `$value =~ s///`. A bare `s///`
/// operates on Perl's implicit `$_` carrier and therefore has no explicit
/// receiver node.
fn perl_substitution_receiver<'tree>(node: Node<'tree>, _src: &[u8]) -> Option<Node<'tree>> {
    let parent = node
        .parent()
        .filter(|parent| parent.kind() == "binary_expression")?;
    parent
        .child_by_field_name("right")
        .is_some_and(|right| right.id() == node.id())
        .then(|| parent.child_by_field_name("left"))
        .flatten()
}
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("perl");
const PACK_NAME: &str = "perl";

/// Lower Perl's shared `loopex_expression` CST bucket from the leading
/// language keyword. Tree-sitter uses the same node kind for `last`, `next`,
/// and `redo`, so the adapter must classify the runtime control effect rather
/// than asking shared analysis to interpret Perl tokens.
fn extract_perl_syntax_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    _handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "loopex_expression" {
        return None;
    }
    let span = span_of(file, &node);
    match node_text(&node, src).split_whitespace().next()? {
        "last" => Some(FlowEvent::Break { span, label: None }),
        "next" | "redo" => Some(FlowEvent::Continue { span, label: None }),
        _ => None,
    }
}

fn perl_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for_statement" {
        return None;
    }
    if let (Some(binding), Some(iterable)) = (
        node.child_by_field_name("variable"),
        node.child_by_field_name("list"),
    ) {
        return Some((binding, iterable));
    }
    let body_id = node.child_by_field_name("body").map(|body| body.id());
    let mut cursor = node.walk();
    let mut header = node
        .named_children(&mut cursor)
        .filter(|child| Some(child.id()) != body_id);
    let binding = header.next()?;
    let iterable = header.next()?;
    Some((binding, iterable))
}

fn perl_identifier_text(value: &str) -> &str {
    value.trim_start_matches(['$', '@', '%'])
}

fn perl_reference_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let canonical = perl_identifier_text(node_text(&node, src).trim());
    (!canonical.is_empty()).then(|| canonical.to_string())
}

/// Preserve Perl's sigil-bearing variable wrapper as the canonical place.
/// Tree-sitter stores the bare identifier in the child `varname`, while the
/// parent `scalar`/`array`/`hash` node owns the execution-relevant sigil.
fn perl_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    if node.kind() == "hash_element_expression" {
        let Some(base) = node.named_child(0) else {
            return ExpressionPlaceExtraction::default();
        };
        let Some(key) = node.child_by_field_name("key") else {
            return ExpressionPlaceExtraction::default();
        };
        if key.kind() != "autoquoted_bareword" {
            return ExpressionPlaceExtraction::default();
        }
        let base_place = perl_expression_places(base, src);
        let Some(base) = base_place.places.first() else {
            return ExpressionPlaceExtraction::default();
        };
        let key = node_text(&key, src).trim();
        if key.is_empty() {
            return ExpressionPlaceExtraction::default();
        }
        return ExpressionPlaceExtraction {
            places: vec![format!("{base}.{key}")],
            consumed_node_ids: vec![node.id()],
        };
    }
    if !matches!(node.kind(), "scalar" | "array" | "hash" | "container_variable") {
        return ExpressionPlaceExtraction::default();
    }
    let Some(identifier) = node.named_child(0) else {
        return ExpressionPlaceExtraction::default();
    };
    if identifier.kind() != "varname" || node.named_child_count() != 1 {
        return ExpressionPlaceExtraction::default();
    }
    let raw = node_text(&node, src).trim();
    if raw.len() < 2 || !raw.starts_with(['$', '@', '%']) || raw.chars().any(char::is_whitespace) {
        return ExpressionPlaceExtraction::default();
    }
    ExpressionPlaceExtraction {
        places: vec![raw.to_string()],
        consumed_node_ids: vec![node.id()],
    }
}

/// Accept Perl's grammar-specific `function` callee node. It is neither an
/// identifier nor a variable node, so generic extraction intentionally
/// refuses to guess it. Builtin meaning remains entirely in rule data.
fn perl_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if !matches!(
        node.kind(),
        "function_call_expression" | "method_call_expression" | "ambiguous_function_call_expression"
    ) {
        return None;
    }
    let target = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("function_name"))
        .or_else(|| node.named_child(0))?;
    let full_text = node_text(&target, src).trim();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text: full_text.to_string(),
    })
}

/// Decode the value-producing call on the right side of a Perl assignment.
///
/// `tree-sitter-perl` represents `Class->method(...)` as a method-call node
/// whose generic `function` field is only the invocant.  Reading that field
/// alone turns `my $x = Class->method()` into the false fact
/// `source_call = Class`.  Keep this adapter fact purely syntactic: combine
/// the grammar's exact `invocant` and `method` fields and lower its argument
/// field, without assigning any library meaning to either spelling.
fn perl_direct_call_info(
    node: Node<'_>,
    src: &[u8],
    _handler: &GrammarHandler,
) -> Option<(Option<String>, Vec<String>)> {
    fn direct_call_node<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
        if matches!(
            node.kind(),
            "function_call_expression" | "method_call_expression" | "ambiguous_function_call_expression"
        ) {
            return Some(node);
        }
        // `my $value = source() // <static default>` still has one exact
        // value-producing call: Perl's defined-or operator returns the left
        // operand unchanged whenever it is defined. Preserve that compiler
        // dependency without treating arbitrary nested calls as assignment
        // results. A dynamic RHS is deliberately rejected because both
        // operands could then provide the value.
        if node.kind() == "binary_expression" {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if operator == Some("//") && perl_static_scalar(right, src).is_some() {
                return direct_call_node(left, src);
            }
            return None;
        }
        // Assignment/declaration wrappers may own the grammar field while
        // the RHS call is their one direct value child.  Never search an
        // arbitrary descendant: a nested call in a condition or aggregate
        // is not the assignment's value-producing call.
        for field in ["right", "value", "initializer"] {
            if let Some(child) = node.child_by_field_name(field) {
                return direct_call_node(child, src);
            }
        }
        None
    }

    let call = direct_call_node(node, src)?;
    let name = if call.kind() == "method_call_expression" {
        let invocant = call.child_by_field_name("invocant")?;
        let method = call.child_by_field_name("method")?;
        let receiver = node_text(&invocant, src)
            .trim()
            .trim_start_matches(['$', '@', '%']);
        let method = node_text(&method, src).trim();
        if receiver.is_empty() || method.is_empty() {
            return None;
        }
        format!("{receiver}->{method}")
    } else {
        perl_call_target(call, src)?.full_text
    };
    let args = call
        .child_by_field_name("arguments")
        .map(|arguments| perl_list_args(&arguments, src, FileId::INVALID))
        .unwrap_or_default()
        .into_iter()
        .filter(|argument| argument.name.is_none())
        .map(|argument| argument.value_text)
        .filter(|value| !value.trim().is_empty())
        .collect();
    Some((Some(name), args))
}

/// Perl's `variable_declaration` is the binding pattern on the left of an
/// enclosing `assignment_expression`; it never owns the initializer itself.
/// Classifying that exact grammar role prevents a multi-variable pattern from
/// being mistaken for a nested assignment merely because it has siblings.
fn perl_assignment_semantics(node: Node<'_>, _src: &[u8]) -> AssignmentNodeSemantics {
    if node.kind() == "variable_declaration" {
        AssignmentNodeSemantics::Other
    } else {
        AssignmentNodeSemantics::Assignment
    }
}
// Perl5 OO uses bare `package Foo;` declarations as class
// boundaries; tree-sitter-perl exposes them as `package_statement`
// nodes with a `name:` field. The grammar's `class_statement` form
// (newer perl5 OO syntax) is also surfaced for completeness.
const PERL_CLASS_KINDS: &[&str] = &["package_statement", "class_statement"];

const HANDLER: GrammarHandler = GrammarHandler {
    literal_value_kinds: &["number"],
    literal_value_spellings: &[],
    string_literal_kinds: &["interpolated_string_literal", "string_literal"],
    comment_kinds: &["comment"],
    doc_comment_kinds: &[],
    doc_comment_prefixes: &[],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["signature"],
    parameter_kinds: &["mandatory_parameter", "optional_parameter", "slurpy_parameter"],
    parameter_modifier_kinds: &[],
    parameter_annotation_kinds: &["attribute"],
    parameter_annotation_name_extractor: None,
    keyword_parameter_kinds: &[],
    parameter_selector_kinds: &[],
    implicit_parameter_kinds: &[],
    self_parameter_kinds: &[],
    last_identifier_parameter_kinds: &[],
    binding_identifier_kinds: &["identifier", "varname"],
    non_binding_pattern_kinds: &[],
    binding_lhs_pattern_kinds: &[],
    binding_pattern_field_names: &[],
    pattern_head_value_kinds: &[],
    multi_segment_value_pattern_kinds: &[],
    non_binding_pattern_field_names: &["type", "key"],
    binding_name_extractor: Some(perl_reference_name),
    binding_name_filter: None,
    pattern_binding_extractor: None,
    projected_pattern_binding_extractor: None,
    anonymous_variadic_token: None,
    variadic_parameter_kinds: &["slurpy_parameter"],
    destructured_parameter_kinds: &[],
    identifier_kinds: &["identifier", "varname"],
    aggregate_pattern_kinds: &["list_expression"],
    comprehension_kinds: &[],
    comprehension_binding_clause_kinds: &[],
    comprehension_binding_extractor: None,
    named_aggregate_kinds: &[],
    positional_aggregate_kinds: &["array", "list_expression"],
    aggregate_pair_kinds: &[],
    two_child_aggregate_pair_kinds: &[],
    aggregate_pair_extractor: None,
    aggregate_key_field_names: &[],
    aggregate_value_field_names: &[],
    static_field_name_kinds: &[],
    shorthand_field_kinds: &[],
    spread_kinds: &[],
    spread_value_field_names: &[],
    aggregate_syntax_only_kinds: &[],
    multi_child_aggregate_pattern_kinds: &[],
    lambda_value_container_kinds: &[],
    transparent_call_wrapper_kinds: &[],
    single_expression_group_kinds: &[],
    assignment_target_wrapper_kinds: &["variable_declaration"],
    binding_declaration_keyword_spellings: &["my", "our", "state", "local"],
    nested_type_ownership: true,
    fn_kinds: &["subroutine_declaration_statement"],
    class_kinds: PERL_CLASS_KINDS,
    class_decl_kinds: &[
        ("package_statement", DeclKind::Module),
        ("class_statement", DeclKind::Class),
    ],
    method_kinds: &[],
    // A Perl package is a namespace until its lowered body proves OO
    // semantics (explicit invocant, constructor, or ancestry).  Treating
    // every package-contained subroutine as a method loses ordinary package
    // function resolution before `promote_perl_oo_packages` can classify it.
    method_context_kinds: &[],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: &["new"],
    function_definition_extractor: None,
    inline_closure_yield_extractor: None,
    if_kinds: &[
        "conditional_statement",
        "conditional_expression",
        "postfix_conditional_expression",
        "elsif",
    ],
    branch_then_field_names: &["body", "block"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition"],
    branch_condition_kinds: &[],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &[],
    condition_all_operators: &["&&", "and"],
    condition_any_operators: &["||", "or"],
    condition_not_operators: &["!", "not"],
    condition_not_operator_kinds: &[],
    branch_alias_extractor: None,
    branch_arm_kinds: &[
        "block",
        "block_statement",
        "expression_statement",
        "elsif",
        "else",
    ],
    exclusive_branch_arm_kinds: &[],
    fallthrough_branch_arm_kinds: &[],
    exclusive_catch_arm_kinds: &[],
    // `tree-sitter-perl` wraps the trailing branch in an unfielded `else`
    // node rather than attaching it as `alternative` on the conditional.
    additional_alternative_kinds: &[],
    for_kinds: &["cstyle_for_statement"],
    foreach_kinds: &["for_statement"],
    foreach_binding_extractor: Some(perl_foreach_binding),
    while_kinds: &["loop_statement"],
    do_kinds: &[],
    loop_kinds: &[],
    loop_body_field_names: &["body", "block"],
    loop_body_kinds: &["block", "block_statement", "expression_statement"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &["iterator"],
    call_kinds: &[
        "function_call_expression",
        "method_call_expression",
        "ambiguous_function_call_expression",
    ],
    constructor_call_kinds: &[],
    nested_call_component_kinds: &[],
    call_callee_field_names: &["function"],
    call_receiver_field_names: &["invocant"],
    call_member_field_names: &["method"],
    constructor_type_field_names: &[],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &[],
    call_argument_wrapper_kinds: &[],
    call_callee_is_first_named_child: true,
    argument_wrapper_kinds: &[],
    argument_name_field_names: &[],
    argument_value_field_names: &[],
    named_argument_extractor: None,
    direct_call_info_extractor: Some(perl_direct_call_info),
    call_target_extractor: Some(perl_call_target),
    call_receiver_extractor: None,
    call_ref_node_filter: None,
    expression_call_span_extractor: None,
    writeback_operand_field_names: &[],
    direct_call_argument_excluded_fields: &[],
    transparent_expression_wrapper_kinds: &[],
    pseudo_call_extractor: Some(extract_perl_pseudo_call),
    syntax_event_extractor: Some(extract_perl_syntax_event),
    syntax_events_extractor: None,
    call_encoded_control_flow_extractor: None,
    pseudo_call_receiver_extractor: Some(perl_substitution_receiver),
    argument_passing_mode_extractor: None,
    expression_value_kind_extractor: None,
    assignment_kinds: &["assignment_expression", "variable_declaration"],
    assignment_semantics_extractor: Some(perl_assignment_semantics),
    assignment_place_extractor: None,
    compound_assignment_kinds: &[],
    compound_assignment_operators: &[
        "+=", "-=", "*=", "/=", "%=", "**=", ".=", "x=", "<<=", ">>=", "&=", "^=", "|=", "//=",
    ],
    type_only_declaration_kinds: &["variable_declaration"],
    positional_aggregate_assignment_kinds: &[],
    positional_aggregate_value_kinds: &[],
    return_kinds: &["return_expression"],
    throw_kinds: &[],
    lambda_kinds: &["anonymous_subroutine_expression"],
    inline_closure_kinds: &[],
    implicit_lambda_parameter_name: None,
    lambda_body_field_names: &["body"],
    lambda_body_kinds: &[],
    try_kinds: &["try_statement"],
    catch_kinds: &[],
    finally_kinds: &[],
    try_fallback_body_kinds: &["block"],
    catch_body_follows_marker: false,
    break_kinds: &[],
    continue_kinds: &[],
    control_label_field_names: &[],
    yield_kinds: &[],
    yield_value_field_names: &[],
    await_kinds: &[],
    defer_kinds: &[],
    deferred_body_extractor: None,
    using_kinds: &[],
    using_body_field_names: &[],
    try_body_field_names: &["body", "block"],
    using_alias_extractor: None,
    special_forms: &[],
    runtime_type_guard_calls: &[],
    runtime_type_guard_operators: &[],
    runtime_typeof_operators: &[],
    runtime_type_equality_operators: &[],
    runtime_type_wrapper_kinds: &[],
    value_free_expression_kinds: &[],
    value_free_call_names: &[],
    value_free_unary_operators: &[],
    call_ref_kinds: &[
        "function_call_expression",
        "method_call_expression",
        "ambiguous_function_call_expression",
    ],
    member_expression_kinds: &[],
    subscript_expression_kinds: &[],
    member_base_field_names: &[],
    member_name_field_names: &[],
    subscript_base_field_names: &[],
    subscript_index_field_names: &[],
    static_subscript_key_extractor: None,
    computed_subscript_extractor: None,
    sigil_variable_kinds: &["scalar", "array", "hash", "container_variable"],
    global_variable_kinds: &[],
    reference_name_extractor: Some(perl_reference_name),
    expression_place_extractor: Some(perl_expression_places),
    indirect_place_operand_extractor: None,
    subscript_base_call_refs: false,
    non_call_ref_names: &[],
    call_name_suffix_tokens: &[],
    syntax_error_tolerant_call_names: &[],
    callable_reference_kinds: &[],
    callable_reference_extractor: None,
    method_receiver_param_index: None,
    receiver_presence_extractor: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
};

/// Tree-sitter adapter for Perl 5.
#[derive(Debug, Default, Copy, Clone)]
pub struct PerlAdapter;

impl PerlAdapter {
    /// Construct a fresh adapter; the type carries no state.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for PerlAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Perl"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.t` is the standard Perl test-file extension — the same
        // module loader and grammar applies; without claiming it,
        // every Perl test file's calls were invisible to the index.
        &["pl", "pm", "t"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: &["new"],
            // Perl uses `SUPER::` (case-sensitive) for super-class
            // dispatch, but the syntactic receiver token preceding
            // `::method` is `SUPER`.
            super_receiver_tokens: &["SUPER"],
            // Perl's invocant is an explicit first `@_` binding whose name is
            // adapter-derived (`$self`, `$class`, or another identifier).
            implicit_receiver_tokens: &[],
            same_directory_unqualified_calls: true,
            callable_reference_syntax: bonsai_lang_api::CallableReferenceSyntax {
                prefixes: &["\\&"],
                numeric_arity_suffix: false,
                symbol_wrapper: None,
                trailing_invocation_punctuation: false,
            },
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "ambiguous_function_call_expression"),
            ("custom lowering", "anonymous_hash_expression"),
            ("custom lowering", "array"),
            ("custom lowering", "assignment_expression"),
            ("custom lowering", "autoquoted_bareword"),
            ("custom lowering", "bareword"),
            ("custom lowering", "binary_expression"),
            ("custom lowering", "block"),
            ("custom lowering", "class_statement"),
            ("custom lowering", "command_string"),
            ("custom lowering", "container_variable"),
            ("custom lowering", "eval_expression"),
            ("custom lowering", "filehandle"),
            ("custom lowering", "for_statement"),
            ("custom lowering", "func1op_call_expression"),
            ("custom lowering", "function_call_expression"),
            ("custom lowering", "hash"),
            ("custom lowering", "hash_element_expression"),
            ("custom lowering", "heredoc_content"),
            ("custom lowering", "heredoc_token"),
            ("custom lowering", "mandatory_parameter"),
            ("custom lowering", "list_expression"),
            ("custom lowering", "lowprec_logical_expression"),
            ("custom lowering", "loopex_expression"),
            ("custom lowering", "map_grep_expression"),
            ("custom lowering", "match_regexp"),
            ("custom lowering", "method_call_expression"),
            ("custom lowering", "optional_parameter"),
            ("custom lowering", "package_statement"),
            ("custom lowering", "quoted_word_list"),
            ("custom lowering", "regexp_content"),
            ("custom lowering", "require_expression"),
            ("custom lowering", "scalar"),
            ("custom lowering", "signature"),
            ("custom lowering", "slurpy_parameter"),
            ("custom lowering", "string_content"),
            ("custom lowering", "string_literal"),
            ("custom lowering", "substitution_regexp"),
            ("custom lowering", "undef"),
            ("custom lowering", "undef_expression"),
            ("custom lowering", "use_statement"),
            ("custom lowering", "variable_declaration"),
            ("custom lowering", "varname"),
        ]
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let parsed = parse_with(PACK_NAME, file, ctx);
        let mut idx = parsed.as_ref().map_or_else(
            || DeclIndex {
                file,
                ..DeclIndex::default()
            },
            |(snapshot, tree)| {
                decl_index_from_tree_with_handler(file, snapshot.text.as_bytes(), tree, &HANDLER)
            },
        );
        let source = parsed
            .as_ref()
            .map(|(snapshot, _)| snapshot.text.to_string())
            .unwrap_or_default();
        if let Some((_, tree)) = parsed.as_ref() {
            idx.finite_literal_selections =
                collect_perl_finite_literal_selections(&idx, tree, file, source.as_bytes());
            populate_call_argument_static_values(
                &mut idx,
                tree,
                file,
                source.as_bytes(),
                &HANDLER,
                perl_static_scalar,
            );
            populate_perl_constant_static_values(&mut idx, tree, file, source.as_bytes());
            populate_perl_assignment_static_call_arguments(&mut idx);
            populate_perl_condition_expressions(&mut idx.branch_conditions, tree, file, source.as_bytes());
            idx.compiler_guards.extend(perl_compound_static_allowlist_guards(
                tree,
                file,
                source.as_bytes(),
            ));
            let string_compositions = collect_perl_string_compositions(&idx, tree, file, source.as_bytes());
            idx.string_compositions.extend(string_compositions);
            idx.string_compositions
                .sort_by_key(|fact| (fact.value_span.start, fact.value_span.end));
            idx.string_compositions.dedup();
        }
        let assignment_values = AssignmentValueIndex::new(&idx.assignment_values);
        let heredoc_sources = parsed
            .as_ref()
            .map(|(_, tree)| collect_perl_heredoc_assignment_sources(tree, file, source.as_bytes()));
        let readline_sources = parsed
            .as_ref()
            .map(|(_, tree)| collect_perl_readline_assignment_sources(tree, file, source.as_bytes()));
        // Perl's tree-sitter grammar doesn't label subroutine
        // parameters structurally — every sub is parameterless at
        // the grammar level. Real code binds positional args via
        // `my ($a, $b) = @_;` (or shifts `$_[0]`). Scan the
        // leading flow events of each sub for that idiom and
        // synthesize `params` so entry-point inference (G5) and
        // taint seeding work.
        for decl in &mut idx.defs {
            add_perl_sigil_source_variants(&mut decl.flow_events);
            if let Some((_, tree)) = parsed.as_ref() {
                normalize_perl_foreach_binding_targets(&mut decl.flow_events, tree, source.as_bytes(), file);
            }
            let consumes_implicit_variadic_args = perl_implicit_args_foreach(&decl.flow_events);
            let list_params =
                rewrite_perl_list_param_bindings(&mut decl.flow_events, &source, &assignment_values);
            let inferred = list_params.unwrap_or_else(|| {
                if consumes_implicit_variadic_args {
                    decl.is_variadic = true;
                    vec!["@_".to_string()]
                } else {
                    infer_perl_params_from_body(&decl.flow_events)
                }
            });
            if !inferred.is_empty() {
                decl.params = inferred;
            }
        }
        // Synthesize Call FlowEvents for `qx//` and backtick `` `cmd` ``
        // expressions. tree-sitter-perl parses both as `command_string`
        // nodes with no `Call` exposure of their own, so the
        // `perl.cmdi.qx_backticks` rule (kind: call, callee.name: qx)
        // can't match real code without this lowering. The interpolated
        // scalars inside become CallArgs so the matcher can evaluate
        // arg-shape constraints and the taint engine can see them as
        // tainted-arg call sites.
        if let Some((_, tree)) = parsed.as_ref() {
            idx.refs
                .extend(extract_perl_special_variable_refs(tree, source.as_bytes(), file));
            let mut calls = synthesize_qx_call_events(tree, source.as_bytes(), file);
            calls.extend(synthesize_method_call_events(tree, source.as_bytes(), file));
            calls.extend(synthesize_qualified_function_call_events(
                tree,
                source.as_bytes(),
                file,
            ));
            calls.extend(synthesize_builtin_call_events(tree, source.as_bytes(), file));
            calls.extend(synthesize_builtin_expression_arg_call_events(
                tree,
                source.as_bytes(),
                file,
            ));
            calls.extend(synthesize_match_regex_call_events(tree, source.as_bytes(), file));
            calls.extend(synthesize_coderef_invocation_events(source.as_bytes(), file));
            calls.extend(synthesize_map_grep_topic_call_events(
                tree,
                source.as_bytes(),
                file,
            ));
            if !calls.is_empty() {
                attach_synthesized_calls_to_decls(&mut idx, calls);
            }
        }
        for decl in &mut idx.defs {
            if let Some(heredoc_sources) = heredoc_sources.as_ref() {
                normalize_perl_heredoc_assignments(&mut decl.flow_events, heredoc_sources);
            }
            if let Some(readline_sources) = readline_sources.as_ref() {
                normalize_perl_readline_assignments(&mut decl.flow_events, readline_sources);
            }
            normalize_perl_package_call_kinds(&mut decl.flow_events);
            rewrite_perl_call_arg_texts(&mut decl.flow_events, &source);
            normalize_perl_hash_deref_flow_events(&mut decl.flow_events, &source, &assignment_values);
            if let Some((_, tree)) = parsed.as_ref() {
                expand_perl_anonymous_hash_field_assigns(&mut decl.flow_events, tree, source.as_bytes());
            }
            normalize_perl_simple_scalar_renames(&mut decl.flow_events, &source, &assignment_values);
            normalize_perl_list_result_targets(&mut decl.flow_events, &source, &assignment_values);
            augment_perl_collection_flow_events(&mut decl.flow_events, &source, &assignment_values);
            inject_perl_coderef_aliases(&mut decl.flow_events, &source, &assignment_values);
            if let Some((_, tree)) = parsed.as_ref() {
                normalize_perl_eval_exception_flow_events(
                    &mut decl.flow_events,
                    tree,
                    &source,
                    &assignment_values,
                );
                normalize_perl_short_circuit_flow(&mut decl.flow_events, tree, file, source.as_bytes());
            }
            // L1: lower `die` to Throw across the WHOLE sub body, not
            // just inside an `eval {}; if ($@)` region. This seeds a
            // native `try { die $x; } catch ($e) { ... }` body (the
            // kit builds the Try + catch_param; we make the die a
            // Throw inside it) and models cross-procedural propagation
            // of an uncaught top-level `die`. The lowering is
            // idempotent: a `die` Call left in place by the eval
            // normalization (which already emitted its Throw) is
            // recognised by the Throw that immediately precedes it and
            // is NOT lowered a second time.
            let body = std::mem::take(&mut decl.flow_events);
            decl.flow_events = lower_perl_die_calls_to_throws(body);
        }
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        apply_perl_package_semantic_identity(&mut idx);
        // Perl convention: subroutines starting with `_` are
        // module-private. Mark those Visibility::Module so the
        // resolver refuses cross-package calls to internal helpers.
        for decl in &mut idx.defs {
            if decl.name.starts_with('_') {
                decl.visibility = bonsai_lang_api::Visibility::Module;
            }
        }
        // Per-package `bases`: Perl5 has no syntactic
        // `extends`/`implements` — class hierarchy is set by
        // `use base 'Parent::Class'` / `use parent 'Foo'` calls
        // inside the package body. Walk every `use_statement` in
        // the file and assign the named parents to the package
        // decl that contains them. Bare-tail (right-most segment of
        // `Foo::Bar`) is the bases entry.
        if let Some((_, tree)) = parsed.as_ref() {
            let bases_by_span = collect_perl_class_bases(tree, file, source.as_bytes(), &idx);
            for decl in &mut idx.defs {
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
            }
        }
        for decl in &mut idx.defs {
            mark_perl_method_receiver_param(decl);
            if decl.receiver_param_index.is_some() && matches!(decl.kind, DeclKind::Function) {
                decl.kind = DeclKind::Method;
            }
            if let Some((_, tree)) = parsed.as_ref() {
                enrich_perl_bless_receiver_field_writes(decl, tree, source.as_bytes());
            }
            let mut aliases = collect_perl_bless_type_aliases(&decl.flow_events);
            dedup_perl_type_aliases(&mut aliases);
            for alias in aliases {
                if !decl.type_aliases.contains(&alias) {
                    decl.type_aliases.push(alias);
                }
            }
        }
        promote_perl_oo_packages(&mut idx);
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Several Perl syntax repairs append exact Call facts after the
        // generic declaration walk. Restore compiler evaluation order only
        // after every repair has run; otherwise CFG normalization can see a
        // later `return` before an earlier synthesized call and correctly
        // discard that call as unreachable. The shared normalizer uses AST
        // containment and source spans, not API names.
        bonsai_lang_api::normalize_decl_event_evaluation_order(&mut idx);
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing follows adapter-classified
        // constructor calls and declared types; spelling alone is not proof.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        bonsai_lang_api::apply_call_receiver_types(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Associate Perl's out-of-line heredoc body with the assignment whose RHS is
/// the grammar's `heredoc_token`. Tree-sitter stores `heredoc_content` as the
/// next named sibling of the assignment statement, so the generic assignment
/// walker cannot see interpolated values as descendants of the RHS node.
/// This adapter-owned relation is exact: only that grammar-proven sibling
/// shape contributes value dependencies.
fn collect_perl_heredoc_assignment_sources(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Vec<String>> {
    let mut out = std::collections::HashMap::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "assignment_expression"
            && node
                .child_by_field_name("right")
                .is_some_and(|right| right.kind() == "heredoc_token")
        {
            let content = node
                .parent()
                .filter(|parent| parent.kind() == "expression_statement")
                .and_then(|statement| statement.next_named_sibling())
                .filter(|sibling| sibling.kind() == "heredoc_content");
            if let Some(content) = content {
                let flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                    content, file, src, &HANDLER,
                );
                let mut sources = flow.source_names;
                if let Some(place) = flow.place {
                    if !sources.contains(&place) {
                        sources.push(place);
                    }
                }
                sources.sort();
                sources.dedup();
                out.insert(span_of(file, &node), sources);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    out
}

fn normalize_perl_heredoc_assignments(
    events: &mut [FlowEvent],
    heredoc_sources: &std::collections::HashMap<Span, Vec<String>>,
) {
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
            } if heredoc_sources.contains_key(span) => {
                let sources = heredoc_sources.get(span).expect("checked heredoc source span");
                *source_name = (sources.len() == 1).then(|| sources[0].clone());
                *source_call = None;
                source_call_args.clear();
                source_names.clone_from(sources);
                *value_kind = Some(if sources.is_empty() {
                    AssignValueKind::Literal
                } else {
                    AssignValueKind::Compound
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_heredoc_assignments(then_events, heredoc_sources);
                normalize_perl_heredoc_assignments(else_events, heredoc_sources);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_heredoc_assignments(body, heredoc_sources);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_heredoc_assignments(body, heredoc_sources);
                normalize_perl_heredoc_assignments(catch_events, heredoc_sources);
                normalize_perl_heredoc_assignments(finally_events, heredoc_sources);
            }
            _ => {}
        }
    }
}

/// Record the exact filehandle value read by Perl's `<HANDLE>` syntax.
///
/// Tree-sitter exposes this as `assignment_expression(right:
/// readline_expression(filehandle))`. The shared expression walker cannot
/// treat every filehandle token as an ordinary variable place, so the Perl
/// frontend attaches the grammar-proven handle identity to the assignment.
/// Rule data decides whether a particular handle is a security source.
fn collect_perl_readline_assignment_sources(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, String> {
    let mut out = std::collections::HashMap::new();
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let Some(readline) = assignment
            .child_by_field_name("right")
            .filter(|right| right.kind() == "readline_expression")
        else {
            continue;
        };
        let mut cursor = readline.walk();
        let Some(handle) = readline
            .named_children(&mut cursor)
            .find(|child| child.kind() == "filehandle")
        else {
            continue;
        };
        let name = node_text(&handle, src).trim();
        if !name.is_empty() {
            out.insert(span_of(file, &assignment), name.to_string());
        }
    }
    out
}

fn normalize_perl_readline_assignments(
    events: &mut [FlowEvent],
    sources: &std::collections::HashMap<Span, String>,
) {
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
            } if sources.contains_key(span) => {
                let source = sources.get(span).expect("checked readline assignment span");
                *source_name = Some(source.clone());
                *source_call = None;
                source_call_args.clear();
                source_names.clear();
                source_names.push(source.clone());
                *value_kind = Some(AssignValueKind::Compound);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_readline_assignments(then_events, sources);
                normalize_perl_readline_assignments(else_events, sources);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_readline_assignments(body, sources);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_readline_assignments(body, sources);
                normalize_perl_readline_assignments(catch_events, sources);
                normalize_perl_readline_assignments(finally_events, sources);
            }
            _ => {}
        }
    }
}

fn collect_perl_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    struct FiniteHash {
        name: String,
        declaration_end: u64,
    }

    let assignments = collect_kinds(tree, &["assignment_expression"]);
    let mut maps = Vec::new();
    for assignment in &assignments {
        if node_has_ancestor_kind(*assignment, "subroutine_declaration_statement") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = perl_assignment_rhs(*assignment, left) else {
            continue;
        };
        let Some(hash) = first_named_child_of_kind(&left, "hash") else {
            continue;
        };
        let name = perl_identifier_text(node_text(&hash, src).trim()).to_string();
        if name.is_empty()
            || !perl_static_string_hash(right, src)
            || !perl_hash_binding_is_stable(tree, hash.id(), &name, src)
        {
            continue;
        }
        maps.push(FiniteHash {
            name,
            declaration_end: assignment.end_byte() as u64,
        });
    }

    let mut facts = Vec::new();
    for assignment in assignments {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(value) = perl_assignment_rhs(assignment, left) else {
            continue;
        };
        let Some(lookup) = perl_finite_hash_lookup(value, src) else {
            continue;
        };
        let Some(map_name) = lookup
            .child_by_field_name("hash")
            .or_else(|| lookup.named_child(0))
            .map(|hash| perl_identifier_text(node_text(&hash, src).trim()))
        else {
            continue;
        };
        if !maps
            .iter()
            .any(|map| map.name == map_name && map.declaration_end <= assignment.start_byte() as u64)
        {
            continue;
        }
        let selection_span = span_of(file, &lookup);
        if !perl_value_is_finite_hash_selection(value, map_name, src) {
            continue;
        }
        let assignment_span = span_of(file, &assignment);
        let target = index
            .assignment_values
            .iter()
            .find(|fact| fact.assignment_span == assignment_span)
            .and_then(|fact| fact.target.clone());
        if target.is_some() {
            facts.push(FiniteLiteralSelectionFact {
                selection_span,
                assignment_span: Some(assignment_span),
                target,
                call_span: None,
                argument_index: None,
            });
        }
    }
    bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut facts);
    facts
}

fn perl_assignment_rhs<'tree>(assignment: Node<'tree>, left: Node<'tree>) -> Option<Node<'tree>> {
    assignment
        .child_by_field_name("right")
        .filter(Node::is_named)
        .or_else(|| {
            let mut cursor = assignment.walk();
            assignment
                .named_children(&mut cursor)
                .filter(|child| child.id() != left.id())
                .last()
        })
}

fn node_has_ancestor_kind(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
}

fn perl_static_string_hash(node: Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "list_expression" || node.named_child_count() == 0 || node.named_child_count() % 2 != 0
    {
        return false;
    }
    let mut cursor = node.walk();
    let is_static = node
        .named_children(&mut cursor)
        .all(|value| perl_static_string(value, src).is_some());
    is_static
}

const PERL_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST: &str = "terminal-predicate.compound-static-allowlist";

/// Lower Perl's terminal compound predicate into API-neutral evidence. The
/// frontend proves the parser assignment, exact scalar comparison, lookup in
/// a finite map built from a quoted-word list, parsed-component consumption,
/// and exact receiver factory options. Rule data owns all security meaning.
fn perl_compound_static_allowlist_guards(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CompilerGuardFact> {
    let static_collections = perl_static_map_collections(tree, src);
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["subroutine_declaration_statement"]) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let calls = perl_collect_kinds_below(body, &["method_call_expression"]);
        for branch in perl_collect_kinds_below(body, &["postfix_conditional_expression"]) {
            let (Some(terminal), Some(condition)) =
                (branch.named_child(0), branch.child_by_field_name("condition"))
            else {
                continue;
            };
            let keyword = src
                .get(terminal.end_byte()..condition.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if terminal.kind() != "return_expression" || keyword != Some("unless") {
                continue;
            }
            let Some(predicate) = perl_compound_acceptance_predicate(condition, src, &static_collections)
            else {
                continue;
            };
            let Some(parser) = perl_collect_kinds_below(body, &["assignment_expression"])
                .into_iter()
                .filter(|assignment| assignment.end_byte() <= branch.start_byte())
                .filter_map(|assignment| perl_parser_assignment(assignment, src))
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
                let guarded_args = perl_direct_method_arguments(guarded_call);
                let component_relations = guarded_args
                    .iter()
                    .enumerate()
                    .filter_map(|(index, argument)| {
                        let (receiver, component, _) = perl_accessor_call(*argument, src)?;
                        (receiver == predicate.parsed_place)
                            .then(|| format!("guarded-argument:{index}=predicate-component:{component}"))
                    })
                    .collect::<Vec<_>>();
                if component_relations.is_empty() {
                    continue;
                }
                let (Some(guarded_receiver), Some(guarded_method)) = (
                    guarded_call
                        .child_by_field_name("invocant")
                        .and_then(|node| perl_exact_place(node, src)),
                    guarded_call.child_by_field_name("method"),
                ) else {
                    continue;
                };
                let Some(factory) =
                    perl_receiver_factory_before(body, guarded_call.start_byte(), &guarded_receiver, src)
                else {
                    continue;
                };
                let mut evidence = vec![
                    "predicate-complete:true".to_string(),
                    "finite-static-string-membership:true".to_string(),
                    format!("parser-call:{}", parser.call_name),
                    format!("scheme-component:{}", predicate.scheme_component),
                    format!("scheme-value:string:{}", predicate.scheme_value),
                    "membership-kind:hash-element".to_string(),
                    format!("membership-component:{}", predicate.host_component),
                    format!("receiver-factory-call:{}", factory.call_name),
                ];
                evidence.extend(component_relations);
                evidence.extend(factory.argument_evidence);
                evidence.sort();
                evidence.dedup();
                facts.push(CompilerGuardFact {
                    function_span: span_of(file, &function),
                    guarded_call_span: span_of(file, &guarded_method),
                    proof_span: span_of(file, &branch),
                    capability: PERL_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST.to_string(),
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

struct PerlParserAssignment {
    start: usize,
    output: String,
    call_name: String,
}

struct PerlCompoundPredicate {
    parsed_place: String,
    scheme_component: String,
    scheme_value: String,
    host_component: String,
}

struct PerlReceiverFactory {
    call_name: String,
    argument_evidence: Vec<String>,
}

fn perl_parser_assignment(assignment: Node<'_>, src: &[u8]) -> Option<PerlParserAssignment> {
    let output = perl_assignment_target_place(assignment.child_by_field_name("left")?, src)?;
    let call = assignment.child_by_field_name("right")?;
    let (receiver, method) = perl_method_identity(call, src)?;
    let arguments = perl_direct_method_arguments(call);
    let [_argument] = arguments.as_slice() else {
        return None;
    };
    Some(PerlParserAssignment {
        start: assignment.start_byte(),
        output,
        call_name: format!("{receiver}.{method}"),
    })
}

fn perl_compound_acceptance_predicate(
    condition: Node<'_>,
    src: &[u8],
    static_collections: &std::collections::HashMap<String, Vec<String>>,
) -> Option<PerlCompoundPredicate> {
    let equality = perl_collect_kinds_below(condition, &["equality_expression"])
        .into_iter()
        .next()?;
    let (equality_left, equality_right) = (
        equality.child_by_field_name("left")?,
        equality.child_by_field_name("right")?,
    );
    let (parsed_place, scheme_component, _) = perl_accessor_call(equality_left, src)?;
    let scheme_value = perl_static_string(equality_right, src)?;
    let membership = perl_collect_kinds_below(condition, &["hash_element_expression"])
        .into_iter()
        .next()?;
    let collection = membership
        .child_by_field_name("hash")
        .or_else(|| membership.named_child(0))
        .and_then(|node| perl_exact_place(node, src))?;
    if !static_collections.contains_key(perl_place_key(&collection)) {
        return None;
    }
    let key = membership
        .child_by_field_name("key")
        .or_else(|| membership.named_child(1))?;
    let host_call = perl_collect_kinds_below(key, &["method_call_expression"])
        .into_iter()
        .next()?;
    let (host_receiver, host_component, _) = perl_accessor_call(host_call, src)?;
    if host_receiver != parsed_place {
        return None;
    }
    Some(PerlCompoundPredicate {
        parsed_place,
        scheme_component,
        scheme_value,
        host_component,
    })
}

fn perl_static_map_collections(tree: &Tree, src: &[u8]) -> std::collections::HashMap<String, Vec<String>> {
    let mut collections = std::collections::HashMap::new();
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let Some(target) = assignment
            .child_by_field_name("left")
            .and_then(|left| perl_collect_kinds_below(left, &["hash"]).into_iter().next())
            .and_then(|hash| perl_exact_place(hash, src))
        else {
            continue;
        };
        let Some(map) = assignment
            .child_by_field_name("right")
            .filter(|right| right.kind() == "map_grep_expression")
        else {
            continue;
        };
        let Some(callback) = map.child_by_field_name("callback").or_else(|| map.named_child(0)) else {
            continue;
        };
        let callback_text = node_text(&callback, src)
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        if callback_text != "{$_=>1}" {
            continue;
        }
        let Some(words) = map.child_by_field_name("list").or_else(|| {
            perl_collect_kinds_below(map, &["quoted_word_list"])
                .into_iter()
                .next()
        }) else {
            continue;
        };
        let Some(content) = words
            .child_by_field_name("content")
            .or_else(|| words.named_child(0))
        else {
            continue;
        };
        let raw = node_text(&content, src);
        if raw.contains('\\') {
            continue;
        }
        let values = raw.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        if !values.is_empty() {
            collections.insert(perl_place_key(&target).to_string(), values);
        }
    }
    collections
}

fn perl_receiver_factory_before(
    body: Node<'_>,
    before: usize,
    receiver: &str,
    src: &[u8],
) -> Option<PerlReceiverFactory> {
    perl_collect_kinds_below(body, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| assignment.end_byte() <= before)
        .filter_map(|assignment| {
            let target = perl_assignment_target_place(assignment.child_by_field_name("left")?, src)?;
            if target != receiver {
                return None;
            }
            let call = assignment.child_by_field_name("right")?;
            let (factory_receiver, method) = perl_method_identity(call, src)?;
            let arguments = perl_direct_method_arguments(call);
            let mut argument_evidence = Vec::new();
            for pair in arguments.chunks_exact(2) {
                let key = node_text(&pair[0], src).trim();
                let value = perl_compiler_evidence_operand(pair[1], src)?;
                if key.is_empty() {
                    return None;
                }
                argument_evidence.push(format!("receiver-config:{key}={value}"));
            }
            Some((
                assignment.start_byte(),
                PerlReceiverFactory {
                    call_name: format!("{factory_receiver}.{method}"),
                    argument_evidence,
                },
            ))
        })
        .max_by_key(|(start, _)| *start)
        .map(|(_, factory)| factory)
}

fn perl_assignment_target_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    if let Some(place) = perl_exact_place(node, src) {
        return Some(place);
    }
    perl_collect_kinds_below(node, &["scalar", "hash", "array"])
        .into_iter()
        .next()
        .and_then(|node| perl_exact_place(node, src))
}

fn perl_exact_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "scalar" | "hash" | "array" | "container_variable" | "bareword" | "package" => {
            let value = node_text(&node, src).trim();
            (!value.is_empty()).then(|| value.to_string())
        }
        _ => None,
    }
}

fn perl_place_key(place: &str) -> &str {
    place.trim_start_matches(['$', '%', '@'])
}

fn perl_method_identity(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    if node.kind() != "method_call_expression" {
        return None;
    }
    let receiver = node
        .child_by_field_name("invocant")
        .and_then(|receiver| perl_exact_place(receiver, src))?;
    let method = node_text(&node.child_by_field_name("method")?, src)
        .trim()
        .to_string();
    (!method.is_empty()).then_some((receiver, method))
}

fn perl_accessor_call<'tree>(node: Node<'tree>, src: &[u8]) -> Option<(String, String, Node<'tree>)> {
    if !perl_direct_method_arguments(node).is_empty() {
        return None;
    }
    let receiver = node
        .child_by_field_name("invocant")
        .and_then(|receiver| perl_exact_place(receiver, src))?;
    let method = node.child_by_field_name("method")?;
    let component = node_text(&method, src).trim();
    (!component.is_empty()).then(|| (receiver, component.to_string(), method))
}

fn perl_direct_method_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    if arguments.kind() == "list_expression" {
        let mut cursor = arguments.walk();
        return arguments.named_children(&mut cursor).collect();
    }
    vec![arguments]
}

fn perl_compiler_evidence_operand(node: Node<'_>, src: &[u8]) -> Option<String> {
    match perl_static_scalar(node, src) {
        Some(StaticScalarValue::String(value)) => Some(format!("string:{value}")),
        Some(StaticScalarValue::Boolean(value)) => Some(format!("boolean:{value}")),
        Some(StaticScalarValue::Null) => Some("null".to_string()),
        Some(StaticScalarValue::Integer(value)) => Some(format!("number:{value}")),
        None => perl_exact_place(node, src).map(|value| format!("place:{value}")),
    }
}

fn perl_collect_kinds_below<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
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

fn perl_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "autoquoted_bareword" => Some(node_text(&node, src).trim().to_string()),
        "string_content" if !node_has_descendant_kind(node, "scalar") => {
            let text = node_text(&node, src);
            (!text.contains(['\\', '\n', '\r'])).then(|| text.to_string())
        }
        "string_literal" | "interpolated_string_literal" if !node_has_descendant_kind(node, "scalar") => {
            let text = node_text(&node, src).trim();
            if text.len() < 2 {
                return None;
            }
            let quote = text.as_bytes()[0];
            ((quote == b'\'' || quote == b'"') && text.as_bytes().last() == Some(&quote))
                .then(|| text[1..text.len() - 1].to_string())
        }
        _ => None,
    }
}

/// Perl method-call facts key arguments to the callee span while assignment
/// values cover the complete invocation. Join those two compiler-owned spans
/// to retain a complete ordered scalar vector; ambiguity or any dynamic
/// argument keeps the vector unknown.
fn populate_perl_assignment_static_call_arguments(index: &mut DeclIndex) {
    for assignment in &mut index.assignment_values {
        if assignment.direct_call_name.is_none() {
            continue;
        }
        let mut candidates = index
            .call_argument_values
            .iter()
            .filter(|argument| {
                assignment.value_span.start <= argument.call_span.start
                    && argument.call_span.end <= assignment.value_span.end
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|argument| (argument.call_span.start, argument.argument_index));
        let Some(first) = candidates.first() else {
            continue;
        };
        if candidates
            .iter()
            .any(|argument| argument.call_span != first.call_span)
        {
            continue;
        }
        let mut values = Vec::with_capacity(candidates.len());
        for (expected_index, argument) in candidates.into_iter().enumerate() {
            if argument.argument_index != expected_index {
                values.clear();
                break;
            }
            let Some(value) = argument.static_value.clone() else {
                values.clear();
                break;
            };
            values.push(value);
        }
        if !values.is_empty() {
            assignment.exact_static_call_args = Some(values);
        }
    }
}

/// Decode only Perl scalars whose runtime truth value is unambiguous from the
/// parsed literal. Security meaning remains in rule data; this frontend fact
/// merely preserves the exact language value used by configuration APIs.
fn perl_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    if let Some(value) = perl_static_string(node, src) {
        return Some(StaticScalarValue::String(value));
    }
    if node.kind() == "number" {
        return match node_text(&node, src).trim() {
            "0" => Some(StaticScalarValue::Boolean(false)),
            "1" => Some(StaticScalarValue::Boolean(true)),
            _ => None,
        };
    }
    (node.kind() == "undef").then_some(StaticScalarValue::Null)
}

/// Preserve the exact immutable scalar introduced by Perl's declarative
/// `use constant NAME => VALUE` form. Tree-sitter represents this as a
/// `use_statement`, not as an assignment, so the shared assignment extractor
/// cannot publish the binding without this grammar-owned bridge.
fn populate_perl_constant_static_values(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for statement in collect_kinds(tree, &["use_statement"]) {
        let Some(module) = statement.child_by_field_name("module") else {
            continue;
        };
        if node_text(&module, src).trim() != "constant" {
            continue;
        }
        let Some(arguments) = first_named_child_of_kind(&statement, "list_expression") else {
            continue;
        };
        let mut cursor = arguments.walk();
        let children = arguments.named_children(&mut cursor).collect::<Vec<_>>();
        let [name, value] = children.as_slice() else {
            continue;
        };
        if name.kind() != "autoquoted_bareword" {
            continue;
        }
        let target = node_text(name, src).trim();
        let Some(static_value) = perl_static_scalar(*value, src) else {
            continue;
        };
        let assignment_span = span_of(file, &statement);
        if index
            .assignment_values
            .iter()
            .any(|fact| fact.assignment_span == assignment_span && fact.target.as_deref() == Some(target))
        {
            continue;
        }
        index
            .assignment_values
            .push(bonsai_lang_api::AssignmentValueFact {
                assignment_span,
                target: Some(target.to_string()),
                target_is_immutable: true,
                target_owner: None,
                target_span: Some(span_of(file, name)),
                value_span: span_of(file, value),
                call_sites: Vec::new(),
                value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                    *value, file, src, &HANDLER,
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
            fact.target_span.map_or(0, |span| span.start),
        )
    });
    index.assignment_values.dedup();
}

fn perl_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    ConditionOperandFact {
        span: span_of(file, &node),
        direct_call_span: matches!(
            node.kind(),
            "function_call_expression"
                | "method_call_expression"
                | "ambiguous_function_call_expression"
                | "func1op_call_expression"
        )
        .then(|| span_of(file, &node)),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER),
        static_string: perl_static_string(node, src),
        static_value: perl_static_scalar(node, src),
    }
}

fn lower_perl_condition_expression(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    let span = span_of(file, &node);
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let [operand] = children.as_slice() {
        let operator = src
            .get(node.start_byte()..operand.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        if matches!(operator, Some("!" | "not")) {
            return ConditionExpressionFact::Not {
                span,
                operand: Box::new(lower_perl_condition_expression(*operand, file, src)),
            };
        }
    }
    if matches!(node.kind(), "binary_expression" | "equality_expression") {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left").or_else(|| node.named_child(0)),
            node.child_by_field_name("right").or_else(|| node.named_child(1)),
        ) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if matches!(operator, Some("==" | "eq" | "!=" | "ne")) {
                return ConditionExpressionFact::Equality {
                    span,
                    relation: if matches!(operator, Some("==" | "eq")) {
                        ConditionEquality::Equal
                    } else {
                        ConditionEquality::NotEqual
                    },
                    left: perl_condition_operand(left, file, src),
                    right: perl_condition_operand(right, file, src),
                };
            }
            let all = matches!(operator, Some("&&" | "and"));
            let any = matches!(operator, Some("||" | "or"));
            if all || any {
                let operands = vec![
                    lower_perl_condition_expression(left, file, src),
                    lower_perl_condition_expression(right, file, src),
                ];
                return if all {
                    ConditionExpressionFact::All { span, operands }
                } else {
                    ConditionExpressionFact::Any { span, operands }
                };
            }
        }
    }
    ConditionExpressionFact::Atom { span }
}

fn populate_perl_condition_expressions(
    facts: &mut [bonsai_lang_api::BranchConditionFact],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    for fact in facts {
        let Some(condition) = node_at_span(tree.root_node(), fact.condition_span, &[]) else {
            continue;
        };
        let expression = lower_perl_condition_expression(condition, file, src);
        let is_unless = condition.parent().is_some_and(|parent| {
            let mut cursor = parent.walk();
            let found = parent.children(&mut cursor).any(|child| child.kind() == "unless");
            found
        });
        if is_unless {
            fact.polarity = bonsai_lang_api::BranchConditionPolarity::Negated;
            fact.expression = Some(ConditionExpressionFact::Not {
                span: fact.condition_span,
                operand: Box::new(expression),
            });
        } else {
            fact.expression = Some(expression);
        }
    }
}

fn collect_perl_string_compositions(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<StringCompositionFact> {
    fn lower(node: Node<'_>, file: FileId, src: &[u8], out: &mut Vec<StringCompositionPart>) -> bool {
        if let Some(value) = perl_static_string(node, src) {
            out.push(StringCompositionPart::Literal { value });
            return true;
        }
        if node.kind() == "interpolated_string_literal" {
            let Some(content) = node
                .child_by_field_name("content")
                .or_else(|| node.named_child(0))
            else {
                return false;
            };
            let mut cursor = content.walk();
            let children = content.named_children(&mut cursor).collect::<Vec<_>>();
            if children.is_empty() {
                return false;
            }
            let mut offset = content.start_byte();
            for child in children {
                if child.start_byte() > offset {
                    let Some(literal) = src
                        .get(offset..child.start_byte())
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    else {
                        return false;
                    };
                    if literal.contains('\\') {
                        return false;
                    }
                    if !literal.is_empty() {
                        out.push(StringCompositionPart::Literal {
                            value: literal.to_string(),
                        });
                    }
                }
                let places = perl_expression_places(child, src).places;
                let [place] = places.as_slice() else {
                    return false;
                };
                out.push(StringCompositionPart::Place { place: place.clone() });
                offset = child.end_byte();
            }
            if offset < content.end_byte() {
                let Some(literal) = src
                    .get(offset..content.end_byte())
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                else {
                    return false;
                };
                if literal.contains('\\') {
                    return false;
                }
                if !literal.is_empty() {
                    out.push(StringCompositionPart::Literal {
                        value: literal.to_string(),
                    });
                }
            }
            return out.len() >= 2;
        }
        let places = perl_expression_places(node, src).places;
        if places.len() == 1 && node.kind() != "binary_expression" {
            out.push(StringCompositionPart::Place {
                place: places[0].clone(),
            });
            return true;
        }
        if node.kind() != "binary_expression" {
            return false;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left").or_else(|| node.named_child(0)),
            node.child_by_field_name("right").or_else(|| node.named_child(1)),
        ) else {
            return false;
        };
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        operator == Some(".") && lower(left, file, src, out) && lower(right, file, src, out)
    }

    let mut facts = Vec::new();
    for expression in collect_kinds(tree, &["binary_expression", "interpolated_string_literal"]) {
        let mut parts = Vec::new();
        if !lower(expression, file, src, &mut parts) || parts.len() < 2 {
            continue;
        }
        let value_span = span_of(file, &expression);
        let assignment = index
            .assignment_values
            .iter()
            .filter(|fact| fact.value_span.start <= value_span.start && value_span.end <= fact.value_span.end)
            .min_by_key(|fact| fact.value_span.len());
        facts.push(StringCompositionFact {
            container_span: assignment.map_or(value_span, |fact| fact.assignment_span),
            value_span,
            target: assignment.and_then(|fact| fact.target.clone()),
            dynamic_anchor_span: None,
            parts,
        });
    }
    facts
}

fn node_has_descendant_kind(node: Node<'_>, kind: &str) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.id() != node.id() && current.kind() == kind {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn perl_hash_binding_is_stable(tree: &Tree, declaration_hash_id: usize, name: &str, src: &[u8]) -> bool {
    for hash in collect_kinds(tree, &["hash"]) {
        if perl_identifier_text(node_text(&hash, src).trim()) == name && hash.id() != declaration_hash_id {
            return false;
        }
    }
    for variable in collect_kinds(tree, &["container_variable"]) {
        if perl_identifier_text(node_text(&variable, src).trim()) != name {
            continue;
        }
        let Some(projected) = variable
            .parent()
            .filter(|parent| parent.kind() == "hash_element_expression")
        else {
            return false;
        };
        let mut current = Some(projected);
        while let Some(node) = current {
            if matches!(node.kind(), "delete_expression" | "undef_expression") {
                return false;
            }
            if node.kind() == "assignment_expression" {
                if node.child_by_field_name("left").is_some_and(|left| {
                    left.start_byte() <= projected.start_byte() && projected.end_byte() <= left.end_byte()
                }) {
                    return false;
                }
                break;
            }
            current = node.parent();
        }
    }
    true
}

fn perl_finite_hash_lookup<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    if node.kind() == "hash_element_expression" {
        return Some(node);
    }
    if node.kind() != "binary_expression" || !node_text(&node, src).contains("//") {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    (left.kind() == "hash_element_expression" && perl_static_string(right, src).is_some()).then_some(left)
}

fn perl_value_is_finite_hash_selection(node: Node<'_>, map_name: &str, src: &[u8]) -> bool {
    let Some(lookup) = perl_finite_hash_lookup(node, src) else {
        return false;
    };
    lookup
        .child_by_field_name("hash")
        .or_else(|| lookup.named_child(0))
        .is_some_and(|hash| perl_identifier_text(node_text(&hash, src).trim()) == map_name)
}

/// Preserve both the exact sigil-bearing storage place and its canonical
/// bare binding alias on assignment sources. Perl resolution uses the bare
/// identity while the dataflow graph must retain `$`/`@`/`%` storage shape.
fn add_perl_sigil_source_variants(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                source_name,
                source_names,
                ..
            } => {
                if let Some(source) = source_name.as_deref() {
                    let bare = perl_identifier_text(source);
                    if bare != source && !bare.is_empty() {
                        push_unique_string(source_names, bare.to_string());
                    }
                }
                let sigiled = source_names
                    .iter()
                    .filter_map(|source| {
                        let bare = perl_identifier_text(source);
                        (bare != source && !bare.is_empty()).then(|| bare.to_string())
                    })
                    .collect::<Vec<_>>();
                for bare in sigiled {
                    push_unique_string(source_names, bare);
                }
                source_names.sort_by_key(|source| (!source.starts_with(['$', '@', '%']), source.clone()));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                add_perl_sigil_source_variants(then_events);
                add_perl_sigil_source_variants(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                add_perl_sigil_source_variants(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                add_perl_sigil_source_variants(body);
                add_perl_sigil_source_variants(catch_events);
                add_perl_sigil_source_variants(finally_events);
            }
            _ => {}
        }
    }
}

/// Perl's `Package::sub(...)` form is a statically-qualified subroutine call,
/// not method dispatch. The shared lowering deliberately treats `::` as a
/// method separator for languages such as C++ and Rust; correct that one
/// language-specific runtime distinction here. True Perl method dispatch uses
/// `->` and remains `CallKind::Method` (or `Constructor` for `->new`).
fn normalize_perl_package_call_kinds(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                call_kind,
                ..
            } if *call_kind == CallKind::Method && receiver.is_none() && name.contains("::") => {
                *call_kind = CallKind::Function;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_package_call_kinds(then_events);
                normalize_perl_package_call_kinds(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_package_call_kinds(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_package_call_kinds(body);
                normalize_perl_package_call_kinds(catch_events);
                normalize_perl_package_call_kinds(finally_events);
            }
            _ => {}
        }
    }
}

fn enrich_perl_bless_receiver_field_writes(decl: &mut bonsai_lang_api::Decl, tree: &Tree, src: &[u8]) {
    if decl.name != "new" || decl.params.len() < 2 {
        return;
    }
    let Some(receiver) = decl.params.first().cloned() else {
        return;
    };
    let mut writes = Vec::new();
    for call in collect_kinds(
        tree,
        &["ambiguous_function_call_expression", "function_call_expression"],
    ) {
        let call_span = span_of(decl.span.file, &call);
        if call_span.start < decl.span.start || call_span.end > decl.span.end {
            continue;
        }
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        if node_text(&function, src).trim() != "bless" {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let Some(hash) = first_descendant_of_kind(arguments, "anonymous_hash_expression") else {
            continue;
        };
        for (field, value) in perl_anonymous_hash_fields(hash, src) {
            let source_param_indices = perl_value_variable_names(value, src)
                .into_iter()
                .filter_map(|value_name| {
                    decl.params
                        .iter()
                        .position(|param| perl_param_matches_value(param, &value_name))
                })
                .collect::<Vec<_>>();
            if source_param_indices.is_empty() {
                continue;
            }
            writes.push(FieldWrite {
                span: span_of(decl.span.file, &value),
                target: format!("{receiver}.{field}"),
                source_param_indices,
            });
        }
    }
    if writes.is_empty() {
        return;
    }
    decl.receiver_field_writes.extend(writes);
    decl.receiver_field_writes
        .sort_by_key(|write| (write.span.start, write.target.clone()));
    decl.receiver_field_writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
}

fn first_descendant_of_kind<'tree>(node: Node<'tree>, expected: &str) -> Option<Node<'tree>> {
    if node.kind() == expected {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_descendant_of_kind(child, expected) {
            return Some(found);
        }
    }
    None
}

fn perl_anonymous_hash_fields<'tree>(hash: Node<'tree>, src: &[u8]) -> Vec<(String, Node<'tree>)> {
    if hash.kind() != "anonymous_hash_expression" {
        return Vec::new();
    }
    let Some(items_root) = first_named_child_of_kind(&hash, "list_expression") else {
        return Vec::new();
    };
    let mut items = Vec::new();
    flatten_perl_list_expression(items_root, &mut items);
    let mut fields = Vec::new();
    for pair in items.chunks_exact(2) {
        if let Some(key) = perl_static_hash_key(pair[0], src) {
            fields.push((key, pair[1]));
        }
    }
    fields
}

fn flatten_perl_list_expression<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if node.kind() != "list_expression" {
        out.push(node);
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        flatten_perl_list_expression(child, out);
    }
}

fn perl_static_hash_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    if matches!(node.kind(), "autoquoted_bareword" | "bareword") {
        let key = node_text(&node, src).trim();
        return (!key.is_empty()).then(|| key.to_string());
    }
    if node.kind() != "string_literal" {
        return None;
    }
    let content = first_descendant_of_kind(node, "string_content")?;
    let key = node_text(&content, src).trim();
    (!key.is_empty()).then(|| key.to_string())
}

fn perl_value_variable_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if matches!(node.kind(), "scalar" | "array" | "hash" | "container_variable") {
            let raw = node_text(&node, src).trim();
            let canonical = perl_identifier_text(raw);
            if !canonical.is_empty() {
                push_unique_string(out, raw.to_string());
                push_unique_string(out, canonical.to_string());
            }
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, src, out);
        }
    }

    let mut out = Vec::new();
    collect(node, src, &mut out);
    out
}

fn expand_perl_anonymous_hash_field_assigns(events: &mut Vec<FlowEvent>, tree: &Tree, src: &[u8]) {
    let mut index = 0usize;
    while index < events.len() {
        match &mut events[index] {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                expand_perl_anonymous_hash_field_assigns(then_events, tree, src);
                expand_perl_anonymous_hash_field_assigns(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                expand_perl_anonymous_hash_field_assigns(body, tree, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                expand_perl_anonymous_hash_field_assigns(body, tree, src);
                expand_perl_anonymous_hash_field_assigns(catch_events, tree, src);
                expand_perl_anonymous_hash_field_assigns(finally_events, tree, src);
            }
            _ => {}
        }

        let fields = perl_anonymous_hash_fields_for_event(&events[index], tree, src);
        if fields.is_empty() {
            index += 1;
            continue;
        }
        let inserted = fields.len();
        events.splice((index + 1)..=index, fields);
        index += inserted + 1;
    }
}

fn perl_anonymous_hash_fields_for_event(event: &FlowEvent, tree: &Tree, src: &[u8]) -> Vec<FlowEvent> {
    let FlowEvent::Assign { span, target, .. } = event else {
        return Vec::new();
    };
    let target = target.trim();
    if target.is_empty() || target.contains(['.', '{', '[']) {
        return Vec::new();
    }
    let Some(assignment) = node_at_span(tree.root_node(), *span, &["assignment_expression"]) else {
        return Vec::new();
    };
    let rhs = assignment
        .child_by_field_name("right")
        .filter(tree_sitter::Node::is_named)
        .or_else(|| {
            let mut cursor = assignment.walk();
            assignment.named_children(&mut cursor).last()
        });
    let Some(rhs) = rhs.filter(|rhs| rhs.kind() == "anonymous_hash_expression") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (key, value) in perl_anonymous_hash_fields(rhs, src) {
        if key.is_empty() || !key.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
            continue;
        }
        let sources = perl_value_variable_names(value, src);
        out.push(FlowEvent::Assign {
            span: *span,
            target: format!("{target}.{key}"),
            source_name: (sources.len() == 1).then(|| sources[0].clone()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: sources.clone(),
            declares_new_binding: false,
            value_kind: Some(if sources.is_empty() {
                AssignValueKind::Literal
            } else {
                AssignValueKind::Compound
            }),
        });
    }
    out
}

fn perl_param_matches_value(param: &str, value: &str) -> bool {
    let param = param.trim();
    let value = value.trim();
    if value == param {
        return true;
    }
    let param_bare = param.trim_start_matches('$');
    let value_bare = value.trim_start_matches('$');
    !param_bare.is_empty() && param_bare == value_bare
}

fn apply_perl_package_semantic_identity(idx: &mut DeclIndex) {
    let mut packages: Vec<(Span, String, bonsai_common::SymbolId)> = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.name.clone(), decl.symbol))
        .collect();
    packages.sort_by_key(|(span, _, _)| span.start);
    if packages.is_empty() {
        return;
    }
    for decl in &mut idx.defs {
        if is_class_like(decl.kind) {
            // Perl writes the complete namespace in one `package`
            // declaration (`package Domain::Repository`).  The shared type
            // resolver, like a compiler symbol table, stores the terminal
            // declaration name separately from its owning module path.  A
            // qualified package must therefore lower to:
            //
            //   name           = Repository
            //   module_path    = Domain
            //   qualified_name = Domain::Repository
            //
            // Keeping the complete namespace in `name` makes an exact
            // compiler-proven receiver type impossible to resolve from a
            // different package, even though both facts carry the same
            // qualified identity.
            let qualified = decl.name.clone();
            let mut segments = qualified
                .split("::")
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if let Some(name) = segments.pop() {
                decl.name = name;
                decl.module_path = ModulePath::from_segments(segments);
            }
            decl.qualified_name = Some(qualified);
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some((_, package_name, package_symbol)) = packages
            .iter()
            .filter(|(span, _, _)| span.start <= decl.span.start)
            .max_by_key(|(span, _, _)| span.start)
        else {
            continue;
        };
        decl.parent = Some(*package_symbol);
        decl.module_path = ModulePath::from_segments(
            package_name
                .split("::")
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(str::to_string),
        );
        decl.qualified_name = Some(format!("{package_name}::{}", decl.name));
    }
}

fn mark_perl_method_receiver_param(decl: &mut bonsai_lang_api::Decl) {
    if decl.receiver_param_index.is_some() {
        return;
    }
    let Some(first_param) = decl.params.first().map(String::as_str) else {
        return;
    };
    // Perl method dispatch passes the invocant as the first @_ item.
    // The conventional bindings are `$self` for instance methods and
    // `$class` for class methods; mark only those explicit shapes so
    // ordinary package functions keep positional argument binding.
    if matches!(first_param, "$self" | "self" | "$class" | "class") {
        decl.receiver_param_index = Some(0);
    }
}

/// Reclassify syntax-proven Perl OO packages as type containers.
///
/// `package` is used both for plain namespaces and for Perl 5 classes. The
/// grammar alone therefore lowers it initially as [`DeclKind::Module`]. A
/// package becomes class-like only when its own compiler IR proves OO
/// semantics: it declares a method with an explicit invocant or an ancestry
/// relation (`use parent`, `use base`, or `@ISA`). This preserves ordinary
/// package-function resolution while allowing `$obj->method(...)` to use the
/// same typed receiver and inheritance machinery as other languages.
fn promote_perl_oo_packages(idx: &mut DeclIndex) {
    let oo_packages = idx
        .defs
        .iter()
        .filter(|decl| decl.kind == DeclKind::Module)
        .filter(|package| {
            !package.bases.is_empty()
                || idx.defs.iter().any(|decl| {
                    decl.parent == Some(package.symbol)
                        && (decl.receiver_param_index.is_some() || decl.kind == DeclKind::Constructor)
                })
        })
        .map(|decl| decl.symbol)
        .collect::<std::collections::HashSet<_>>();
    for decl in &mut idx.defs {
        if oo_packages.contains(&decl.symbol) {
            decl.kind = DeclKind::Class;
        }
    }
}

fn collect_perl_bless_type_aliases(events: &[FlowEvent]) -> Vec<TypeAliasBinding> {
    let mut out = Vec::new();
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                source_call_args,
                ..
            } if source_call == "bless" => {
                if let Some(type_name) = source_call_args
                    .get(1)
                    .and_then(|arg| canonical_perl_base_name(arg))
                {
                    push_perl_type_alias(&mut out, target, &type_name);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                out.extend(collect_perl_bless_type_aliases(then_events));
                out.extend(collect_perl_bless_type_aliases(else_events));
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                out.extend(collect_perl_bless_type_aliases(body));
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                out.extend(collect_perl_bless_type_aliases(body));
                out.extend(collect_perl_bless_type_aliases(catch_events));
                out.extend(collect_perl_bless_type_aliases(finally_events));
            }
            _ => {}
        }
    }
    out
}

fn push_perl_type_alias(out: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    let name = name.trim();
    let type_name = type_name.trim();
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    out.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

fn dedup_perl_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// Augment Assign events with extra `source_names` so collection
/// transforms (`map`/`grep`/`sort`) and `push @arr, $tainted` calls
/// surface the underlying collection in taint flow.
///
/// Recurses into branches, loops, defers, using-blocks and try/catch
/// bodies so deeply-nested transforms still get their sources.
fn augment_perl_collection_flow_events(
    events: &mut Vec<FlowEvent>,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_names,
                ..
            } => {
                if let Some(rhs) = assignment_values.rendering(*span, source) {
                    add_perl_collection_transform_sources(target, rhs, source_names);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_perl_collection_flow_events(then_events, source, assignment_values);
                augment_perl_collection_flow_events(else_events, source, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_perl_collection_flow_events(body, source, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_perl_collection_flow_events(body, source, assignment_values);
                augment_perl_collection_flow_events(catch_events, source, assignment_values);
                augment_perl_collection_flow_events(finally_events, source, assignment_values);
            }
            _ => {}
        }
    }

    // Second pass: lower `push @arr, $x` calls into a synthetic Assign
    // event so taint flowing into `$x` propagates to `@arr`. Foreach
    // bindings already come from the shared Tree-sitter field lowering.
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let push_assignment = perl_push_assignment(&event);
        rewritten.push(event);
        if let Some(assign) = push_assignment {
            rewritten.push(assign);
        }
    }
    *events = rewritten;
}

/// Add exact callable-alias facts for Perl coderef assignments such
/// as `my $cb = \&helper;`.
///
/// The generic assignment walker sees the same statement, but the
/// declaration wrapper can add unrelated operands to `source_names`.
/// A clean synthetic alias keeps callback resolution semantic: it is
/// emitted only when the RHS is Perl's explicit subroutine-reference
/// syntax and the LHS contains one scalar binding.
fn inject_perl_coderef_aliases(
    events: &mut Vec<FlowEvent>,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_perl_coderef_aliases(then_events, source, assignment_values);
                inject_perl_coderef_aliases(else_events, source, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_perl_coderef_aliases(body, source, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_perl_coderef_aliases(body, source, assignment_values);
                inject_perl_coderef_aliases(catch_events, source, assignment_values);
                inject_perl_coderef_aliases(finally_events, source, assignment_values);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let alias = perl_coderef_alias_assignment(&event, source, assignment_values);
        rewritten.push(event);
        if let Some(alias) = alias {
            rewritten.push(alias);
        }
    }
    *events = rewritten;
}

fn perl_coderef_alias_assignment(
    event: &FlowEvent,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, target, .. } = event else {
        return None;
    };
    let lhs = assignment_values.target_rendering(*span, source)?;
    let rhs = assignment_values.rendering(*span, source)?;
    let target = perl_coderef_lhs_target(lhs)
        .or_else(|| target.trim().starts_with('$').then(|| target.trim().to_string()))?;
    let source_name = perl_coderef_rhs_source(rhs)?;
    Some(FlowEvent::Assign {
        span: *span,
        target,
        source_name: Some(source_name),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    })
}

fn perl_coderef_lhs_target(lhs: &str) -> Option<String> {
    let vars = perl_sigiled_identifiers(lhs, ['$']);
    if vars.len() != 1 {
        return None;
    }
    vars.into_iter().next()
}

fn perl_coderef_rhs_source(rhs: &str) -> Option<String> {
    let trimmed = rhs.trim().trim_end_matches(';').trim();
    let rest = trimmed.strip_prefix("\\&")?.trim_start();
    let mut end = 0usize;
    for (idx, ch) in rest.char_indices() {
        if ch == '_' || ch == ':' || ch.is_ascii_alphanumeric() {
            end = idx + ch.len_utf8();
            continue;
        }
        break;
    }
    if end == 0 {
        return None;
    }
    let name = rest[..end].trim();
    if name.is_empty() {
        return None;
    }
    let suffix = rest[end..].trim();
    if !suffix.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Lower Perl's exception idiom `eval { die ... }; if ($@) { ... }`
/// into a structural Try/Throw region. Tree-sitter-perl exposes the
/// eval block's body as ordinary calls and the `$@` handler as an
/// unrelated branch, so downstream taint cannot otherwise connect the
/// thrown value to the handler binding.
fn normalize_perl_eval_exception_flow_events(
    events: &mut Vec<FlowEvent>,
    tree: &Tree,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) {
    let eval_blocks = perl_eval_block_ranges(tree);
    if eval_blocks.is_empty() {
        return;
    }
    rewrite_perl_eval_exception_regions(events, source, assignment_values, &eval_blocks);
}

#[derive(Clone, Copy, Debug)]
struct PerlEvalBlockRange {
    start: usize,
    body_start: usize,
    body_end: usize,
}

fn perl_eval_block_ranges(tree: &Tree) -> Vec<PerlEvalBlockRange> {
    let mut out = Vec::new();
    for eval in collect_kinds(tree, &["eval_expression"]) {
        let Some(block) = first_named_child_of_kind(&eval, "block") else {
            continue;
        };
        out.push(PerlEvalBlockRange {
            start: eval.start_byte(),
            body_start: block.start_byte(),
            body_end: block.end_byte(),
        });
    }
    out.sort_by_key(|block| block.start);
    out
}

fn rewrite_perl_eval_exception_regions(
    events: &mut Vec<FlowEvent>,
    source: &str,
    assignment_values: &AssignmentValueIndex,
    eval_blocks: &[PerlEvalBlockRange],
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_perl_eval_exception_regions(then_events, source, assignment_values, eval_blocks);
                rewrite_perl_eval_exception_regions(else_events, source, assignment_values, eval_blocks);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_perl_eval_exception_regions(body, source, assignment_values, eval_blocks);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_perl_eval_exception_regions(body, source, assignment_values, eval_blocks);
                rewrite_perl_eval_exception_regions(catch_events, source, assignment_values, eval_blocks);
                rewrite_perl_eval_exception_regions(finally_events, source, assignment_values, eval_blocks);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    let mut idx = 0usize;
    while idx < events.len() {
        let Some(block) = event_span(&events[idx])
            .and_then(|span| {
                eval_blocks
                    .iter()
                    .find(|block| span_inside_eval_body(span, **block))
            })
            .copied()
        else {
            rewritten.push(events[idx].clone());
            idx += 1;
            continue;
        };

        let mut body_end = idx;
        while body_end < events.len() {
            let Some(span) = event_span(&events[body_end]) else {
                break;
            };
            if !span_inside_eval_body(span, block) {
                break;
            }
            body_end += 1;
        }
        if body_end == idx || body_end >= events.len() {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        }

        let FlowEvent::Branch {
            span: branch_span,
            condition,
            then_events,
            ..
        } = &events[body_end]
        else {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        };
        if !perl_condition_is_dollar_at(condition.as_deref()) {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        }

        let mut body = events[idx..body_end].to_vec();
        body = lower_perl_die_calls_to_throws(body);
        let (catch_param, catch_events) = perl_dollar_at_catch_events(then_events, source, assignment_values);
        let file = branch_span.file;
        let try_span = Span::new(
            file,
            u64::try_from(block.start).unwrap_or(branch_span.start),
            branch_span.end,
        );
        rewritten.push(FlowEvent::Try {
            span: try_span,
            body,
            catch_events,
            finally_events: Vec::new(),
            catch_param,
            catch_types: Vec::new(),
            catch_arms: Vec::new(),
        });
        idx = body_end + 1;
    }
    *events = rewritten;
}

fn event_span(event: &FlowEvent) -> Option<Span> {
    Some(event.span())
}

#[derive(Clone, Debug)]
struct PerlShortCircuitRegion {
    span: Span,
    right_span: Span,
    branch_condition: String,
}

/// Lower Perl's expression-level `or`/`and` (and `||`/`&&`) effects into
/// explicit conditional control flow. The generic walker correctly extracts
/// calls, assignments, returns, and throws from both operands, but a flat
/// event list would make a right-hand `return` unconditional and let CFG
/// reachability delete every later statement. Tree-sitter supplies exact
/// operand fields and the adapter owns the operator vocabulary, so shared CFG
/// and IDG code consume only an ordinary [`FlowEvent::Branch`].
fn normalize_perl_short_circuit_flow(events: &mut Vec<FlowEvent>, tree: &Tree, file: FileId, src: &[u8]) {
    let mut regions = collect_kinds(tree, &["lowprec_logical_expression", "binary_expression"])
        .into_iter()
        .filter_map(|node| {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let operator = std::str::from_utf8(src.get(left.end_byte()..right.start_byte())?)
                .ok()?
                .trim();
            let executes_when_true = match operator {
                "and" | "&&" => true,
                "or" | "||" => false,
                _ => return None,
            };
            let left_text = node_text(&left, src).trim();
            if left_text.is_empty() {
                return None;
            }
            Some(PerlShortCircuitRegion {
                span: span_of(file, &node),
                right_span: span_of(file, &right),
                branch_condition: if executes_when_true {
                    left_text.to_string()
                } else {
                    format!("!({left_text})")
                },
            })
        })
        .collect::<Vec<_>>();
    // Inner expressions must acquire their own branch before an outer right
    // operand can move that complete branch into its conditional arm.
    regions.sort_by_key(|region| region.span.len());
    for region in regions {
        rewrite_perl_short_circuit_region(events, &region);
    }
}

fn rewrite_perl_short_circuit_region(events: &mut Vec<FlowEvent>, region: &PerlShortCircuitRegion) -> bool {
    let selected = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            let span = event.span();
            (span.file == region.right_span.file
                && span.start >= region.right_span.start
                && span.end <= region.right_span.end)
                .then_some(index)
        })
        .collect::<Vec<_>>();
    if let Some(&insert_at) = selected.first() {
        let selected_set = selected.into_iter().collect::<std::collections::HashSet<_>>();
        let mut right_events = Vec::new();
        let mut retained = Vec::with_capacity(events.len());
        for (index, event) in std::mem::take(events).into_iter().enumerate() {
            if selected_set.contains(&index) {
                right_events.push(event);
            } else {
                retained.push(event);
            }
        }
        if right_events.is_empty() {
            *events = retained;
            return false;
        }
        let retained_insert = insert_at.min(retained.len());
        retained.insert(
            retained_insert,
            FlowEvent::Branch {
                span: region.span,
                condition: Some(region.branch_condition.clone()),
                then_events: right_events,
                else_events: Vec::new(),
            },
        );
        *events = retained;
        return true;
    }

    for event in events {
        let rewritten = match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_perl_short_circuit_region(then_events, region)
                    || rewrite_perl_short_circuit_region(else_events, region)
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_perl_short_circuit_region(body, region)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_perl_short_circuit_region(body, region)
                    || rewrite_perl_short_circuit_region(catch_events, region)
                    || rewrite_perl_short_circuit_region(finally_events, region)
            }
            _ => false,
        };
        if rewritten {
            return true;
        }
    }
    false
}

fn span_inside_eval_body(span: Span, block: PerlEvalBlockRange) -> bool {
    let Ok(start) = usize::try_from(span.start) else {
        return false;
    };
    let Ok(end) = usize::try_from(span.end) else {
        return false;
    };
    start >= block.body_start && end <= block.body_end
}

fn perl_condition_is_dollar_at(condition: Option<&str>) -> bool {
    condition
        .map(str::trim)
        .is_some_and(|condition| matches!(condition, "$@" | "($@)"))
}

fn lower_perl_die_calls_to_throws(events: Vec<FlowEvent>) -> Vec<FlowEvent> {
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                call_kind,
                args,
            } if name == "die" => {
                // Idempotency guard: if the event we just emitted is
                // already the Throw lowered from THIS die (same span
                // start, since `perl_die_throw_span` preserves the
                // call's start byte), this `die` Call is the residual
                // kept by a prior lowering pass. Re-lowering it would
                // emit a duplicate Throw, so pass it through unchanged.
                let already_lowered = matches!(
                    out.last(),
                    Some(FlowEvent::Throw { span: throw_span, .. })
                        if throw_span.start == span.start && throw_span.file == span.file
                );
                if already_lowered {
                    out.push(FlowEvent::Call {
                        span,
                        name,
                        receiver,
                        receiver_types,
                        call_kind,
                        args,
                    });
                } else {
                    out.push(FlowEvent::Throw {
                        span: perl_die_throw_span(span, &args),
                        value_name: perl_die_value_name(&args),
                        thrown_type: None,
                    });
                    out.push(FlowEvent::Call {
                        span,
                        name,
                        receiver,
                        receiver_types,
                        call_kind,
                        args,
                    });
                }
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => out.push(FlowEvent::Branch {
                span,
                condition,
                then_events: lower_perl_die_calls_to_throws(then_events),
                else_events: lower_perl_die_calls_to_throws(else_events),
            }),
            FlowEvent::Loop {
                span,
                loop_kind,
                body,
            } => out.push(FlowEvent::Loop {
                span,
                loop_kind,
                body: lower_perl_die_calls_to_throws(body),
            }),
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
                catch_arms,
            } => out.push(FlowEvent::Try {
                span,
                body: lower_perl_die_calls_to_throws(body),
                catch_events: lower_perl_die_calls_to_throws(catch_events),
                finally_events: lower_perl_die_calls_to_throws(finally_events),
                catch_param,
                catch_types,
                catch_arms,
            }),
            FlowEvent::Defer { span, body } => out.push(FlowEvent::Defer {
                span,
                body: lower_perl_die_calls_to_throws(body),
            }),
            FlowEvent::Using { span, body } => out.push(FlowEvent::Using {
                span,
                body: lower_perl_die_calls_to_throws(body),
            }),
            other => out.push(other),
        }
    }
    out
}

fn perl_die_throw_span(span: Span, args: &[CallArg]) -> Span {
    let end = args
        .iter()
        .map(|arg| arg.span.end)
        .max()
        .unwrap_or(span.end)
        .max(span.end);
    Span::new(span.file, span.start, end)
}

fn perl_die_value_name(args: &[CallArg]) -> Option<String> {
    let arg = args.first()?;
    if let Some(place) = arg
        .place
        .as_deref()
        .map(str::trim)
        .filter(|place| !place.is_empty())
    {
        return Some(place.to_string());
    }
    if let Some(source) = arg
        .source_names
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .find(|source| !source.is_empty())
    {
        return Some(source.to_string());
    }
    let value = arg.value_text.trim();
    if perl_sigiled_identifiers(value, ['$', '@', '%'])
        .first()
        .is_some_and(|identifier| identifier == value)
    {
        return Some(value.to_string());
    }
    (!value.is_empty() && value.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()))
        .then(|| value.to_string())
}

fn perl_dollar_at_catch_events(
    events: &[FlowEvent],
    source: &str,
    assignment_values: &AssignmentValueIndex,
) -> (Option<String>, Vec<FlowEvent>) {
    let mut aliases = Vec::new();
    for event in events {
        if let FlowEvent::Assign { span, target, .. } = event {
            if perl_assignment_rhs_is_dollar_at(source, *span, assignment_values) {
                push_unique_string(&mut aliases, target.clone());
            }
        }
    }
    let catch_param = aliases
        .iter()
        .find(|alias| alias.starts_with('$'))
        .cloned()
        .or_else(|| aliases.first().cloned())
        .or_else(|| Some("$@".to_string()));

    let catch_events = events
        .iter()
        .filter(|event| {
            !matches!(
                event,
                FlowEvent::Assign { span, .. }
                    if perl_assignment_rhs_is_dollar_at(source, *span, assignment_values)
            )
        })
        .cloned()
        .collect();
    (catch_param, catch_events)
}

fn perl_assignment_rhs_is_dollar_at(
    source: &str,
    span: Span,
    assignment_values: &AssignmentValueIndex,
) -> bool {
    assignment_values
        .rendering(span, source)
        .map(|rhs| rhs.trim_end_matches(';').trim() == "$@")
        .unwrap_or(false)
}

/// Rewrite exact Perl scalar/array/hash renames (`my $y = $x`) from
/// generic compound-token assignments into `source_name` assignments.
/// This keeps true compound/deref RHSs (`$obj->{k}`, `$x . $y`,
/// function calls) on the broader `source_names` path while making the
/// simple rename case exact.
fn normalize_perl_simple_scalar_renames(
    events: &mut [FlowEvent],
    source: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } => {
                if source_call.is_some() || !source_call_args.is_empty() {
                    continue;
                }
                if let Some(rhs) = assignment_values
                    .rendering(*span, source)
                    .and_then(perl_exact_variable_rhs)
                {
                    *source_name = Some(rhs);
                    source_names.clear();
                    *value_kind = None;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_simple_scalar_renames(then_events, source, assignment_values);
                normalize_perl_simple_scalar_renames(else_events, source, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_simple_scalar_renames(body, source, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_simple_scalar_renames(body, source, assignment_values);
                normalize_perl_simple_scalar_renames(catch_events, source, assignment_values);
                normalize_perl_simple_scalar_renames(finally_events, source, assignment_values);
            }
            _ => {}
        }
    }
}

fn perl_exact_variable_rhs(rhs: &str) -> Option<String> {
    let rhs = rhs.trim().trim_end_matches(';').trim();
    if rhs == "@_" || rhs == "$@" {
        return None;
    }
    let vars = perl_sigiled_identifiers(rhs, ['$', '@', '%']);
    if vars.len() == 1 && vars[0] == rhs {
        return Some(vars[0].clone());
    }
    None
}

/// Rewrite Perl hash-deref expressions like `$h->{k}` into the
/// dotted form `$h.k` so the resolver and taint engine treat them as
/// member accesses rather than opaque text.
///
/// Recurses into nested control-flow event lists; merges adjacent
/// Assigns that share a span (the grammar can split a single
/// hash-deref assignment into multiple events).
fn normalize_perl_hash_deref_flow_events(
    events: &mut Vec<FlowEvent>,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call_args,
                source_names,
                ..
            } => {
                if let Some(name) = source_name {
                    *name = normalize_perl_hash_deref_text(name);
                }
                for arg in source_call_args {
                    *arg = normalize_perl_hash_deref_text(arg);
                }
                for name in source_names.iter_mut() {
                    *name = normalize_perl_hash_deref_text(name);
                }
                if let Some(rhs) = assignment_values.rendering(*span, source) {
                    add_perl_hash_deref_sources(rhs, source_names);
                }
            }
            FlowEvent::Call { args, .. } => {
                for arg in &mut *args {
                    // Rewrite call arguments only — `value_text` and
                    // `place` should stay in sync.
                    if let Some(access) = perl_hash_deref_access(&arg.value_text) {
                        arg.value_text.clone_from(&access);
                        arg.place = Some(access.clone());
                        let structural_base = access
                            .split_once('.')
                            .map(|(base, _)| base.trim_start_matches(['$', '@', '%']))
                            .unwrap_or_default();
                        arg.source_names
                            .retain(|name| name.trim_start_matches(['$', '@', '%']) != structural_base);
                        push_unique_string(&mut arg.source_names, access);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_hash_deref_flow_events(then_events, source, assignment_values);
                normalize_perl_hash_deref_flow_events(else_events, source, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_hash_deref_flow_events(body, source, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_hash_deref_flow_events(body, source, assignment_values);
                normalize_perl_hash_deref_flow_events(catch_events, source, assignment_values);
                normalize_perl_hash_deref_flow_events(finally_events, source, assignment_values);
            }
            _ => {}
        }
    }

    // Second pass: collapse a hash-deref Assign plus any later
    // same-span Assigns into a single normalized Assign.
    let mut rewritten = Vec::with_capacity(events.len());
    let mut event_idx = 0usize;
    while event_idx < events.len() {
        let Some((span, target, rhs)) =
            perl_hash_deref_assignment(&events[event_idx], source, assignment_values)
        else {
            rewritten.push(events[event_idx].clone());
            event_idx += 1;
            continue;
        };

        let mut source_name = None;
        let mut source_call = None;
        let mut source_call_args = Vec::new();
        let mut source_names = Vec::new();
        // Walk forward absorbing every Assign that shares this span.
        while event_idx < events.len() {
            let FlowEvent::Assign {
                span: next_span,
                source_name: next_source_name,
                source_call: next_source_call,
                source_call_args: next_source_call_args,
                source_names: next_source_names,
                ..
            } = &events[event_idx]
            else {
                break;
            };
            if *next_span != span {
                break;
            }
            if source_name.is_none() {
                // Drop any source_name that's actually the LHS itself
                // — these are extractor noise from hash-deref shapes.
                source_name = next_source_name
                    .as_deref()
                    .map(normalize_perl_hash_deref_text)
                    .filter(|name| !perl_source_name_is_lhs_artifact(name, &target));
            }
            if source_call.is_none() {
                source_call.clone_from(next_source_call);
            }
            if source_call_args.is_empty() {
                source_call_args = next_source_call_args
                    .iter()
                    .map(|arg| normalize_perl_hash_deref_text(arg))
                    .collect();
            }
            for name in next_source_names {
                let normalized = normalize_perl_hash_deref_text(name);
                if !perl_source_name_is_lhs_artifact(&normalized, &target) {
                    push_unique_string(&mut source_names, normalized);
                }
            }
            event_idx += 1;
        }

        // Final pass: also surface every sigil'd identifier in the
        // textual RHS so taint sees both the variable and its bare
        // form (`$x` and `x`). A hash-deref root is structural here:
        // `$c->{capacity}` reads only `$c.capacity`, not the whole `$c`.
        let projected_bases = perl_hash_deref_accesses(&rhs)
            .into_iter()
            .filter_map(|access| access.split_once('.').map(|(base, _)| base.to_string()))
            .collect::<std::collections::HashSet<_>>();
        for name in perl_sigiled_identifiers(&rhs, ['$', '@', '%']) {
            if projected_bases.contains(&name) {
                continue;
            }
            push_unique_string(&mut source_names, name.clone());
            push_unique_string(
                &mut source_names,
                name.trim_start_matches(['$', '@', '%']).to_string(),
            );
        }

        rewritten.push(FlowEvent::Assign {
            span,
            target,
            source_name,
            source_call,
            source_call_args,
            source_names,
            declares_new_binding: false,
            value_kind: None,
        });
    }
    *events = rewritten;
}

/// If `event` is an Assign whose LHS is a hash-deref expression,
/// return the canonical span/target/rhs triple; otherwise `None`.
fn perl_hash_deref_assignment(
    event: &FlowEvent,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) -> Option<(Span, String, String)> {
    let FlowEvent::Assign { span, .. } = event else {
        return None;
    };
    let lhs = assignment_values.target_rendering(*span, source)?;
    let rhs = assignment_values.rendering(*span, source)?;
    let target = perl_hash_deref_access(lhs)?;
    Some((*span, target, rhs.to_string()))
}

/// When the LHS of `@arr = map { ... } @other` is a collection and
/// the RHS is a `map`/`grep`/`sort` form, register every sigil'd
/// collection identifier in the RHS as an extra taint source.
fn add_perl_collection_transform_sources(target: &str, rhs: &str, source_names: &mut Vec<String>) {
    let target = target.trim();
    // Only collections (arrays, hashes) get this treatment.
    if !target.starts_with(['@', '%']) {
        return;
    }
    let rhs_trimmed = rhs.trim_start();
    // Match the four canonical forms with optional whitespace before
    // the block. Keeps us conservative — a user-defined `map_*` sub
    // wouldn't trigger.
    if !(rhs_trimmed.starts_with("map ")
        || rhs_trimmed.starts_with("map{")
        || rhs_trimmed.starts_with("grep ")
        || rhs_trimmed.starts_with("grep{")
        || rhs_trimmed.starts_with("sort "))
    {
        return;
    }
    for collection in perl_sigiled_identifiers(rhs, ['@', '%']) {
        push_unique_string(source_names, collection.clone());
        push_unique_string(
            source_names,
            collection.trim_start_matches(['@', '%']).to_string(),
        );
    }
}

/// If `event` is a `push @arr, $val` call, synthesize an Assign that
/// flows the value(s) into `@arr`. Returns `None` for any other
/// shape.
fn perl_push_assignment(event: &FlowEvent) -> Option<FlowEvent> {
    let FlowEvent::Call { span, name, args, .. } = event else {
        return None;
    };
    if name != "push" || args.len() < 2 {
        return None;
    }
    let target = args.first()?.value_text.trim();
    // First arg must be the target array — sanity gate.
    if !target.starts_with('@') {
        return None;
    }
    let mut source_names = Vec::new();
    for arg in args.iter().skip(1) {
        let value = arg.value_text.trim();
        if value.is_empty() {
            continue;
        }
        push_unique_string(&mut source_names, value.to_string());
        // Surface both the sigil'd and bare forms so the taint engine
        // matches against either spelling.
        if value.starts_with(['$', '@', '%']) {
            push_unique_string(
                &mut source_names,
                value.trim_start_matches(['$', '@', '%']).to_string(),
            );
        }
    }
    (!source_names.is_empty()).then(|| FlowEvent::Assign {
        span: *span,
        target: target.to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names,
        declares_new_binding: false,
        value_kind: None,
    })
}

/// Normalize a hash-deref expression to dotted form, falling back to
/// the trimmed input when the text isn't a deref.
fn normalize_perl_hash_deref_text(text: &str) -> String {
    perl_hash_deref_access(text).unwrap_or_else(|| text.trim().to_string())
}

fn add_perl_hash_deref_sources(text: &str, source_names: &mut Vec<String>) {
    for access in perl_hash_deref_accesses(text) {
        push_unique_string(source_names, access.clone());
        let bare = access.trim_start_matches(['$', '@', '%']).to_string();
        push_unique_string(source_names, bare);
    }
}

fn perl_hash_deref_accesses(text: &str) -> Vec<String> {
    let mut accesses = Vec::new();
    let mut chars = text.char_indices().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some((idx, ch)) = chars.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if !matches!(ch, '$' | '@' | '%') {
            continue;
        }

        let ident_start = idx + ch.len_utf8();
        let mut ident_end = ident_start;
        while let Some((next_idx, next_ch)) = chars.peek().copied() {
            if next_ch == '_' || next_ch.is_ascii_alphanumeric() {
                ident_end = next_idx + next_ch.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        if ident_end == ident_start {
            continue;
        }

        let access_end = extend_perl_deref_end(text, ident_end);
        if access_end <= ident_end {
            continue;
        }
        if let Some(access) = perl_hash_deref_access(&text[idx..access_end]) {
            push_unique_string(&mut accesses, access);
        }
        while chars.peek().is_some_and(|(next_idx, _)| *next_idx < access_end) {
            chars.next();
        }
    }

    accesses
}

/// Convert `$h->{k}` / `$h{k}` / `@arr->{k}` style hash-deref text
/// into the canonical `$h.k` form. Returns `None` for any other
/// shape (so callers can skip non-deref text).
fn perl_hash_deref_access(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_end_matches(';').trim();
    let mut cursor = 0usize;
    let sigil = trimmed[cursor..].chars().next()?;
    // Must start with a Perl sigil — otherwise it's not a deref.
    if !matches!(sigil, '$' | '@' | '%') {
        return None;
    }
    cursor += sigil.len_utf8();
    let ident_start = cursor;
    while let Some(ch) = trimmed[cursor..].chars().next() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            cursor += ch.len_utf8();
        } else {
            break;
        }
    }
    // Need at least one identifier char after the sigil.
    if cursor == ident_start {
        return None;
    }
    let base = &trimmed[..cursor];
    cursor = skip_ascii_ws(trimmed, cursor);
    // Optional `->` arrow before `{`.
    if trimmed[cursor..].starts_with("->") {
        cursor += 2;
        cursor = skip_ascii_ws(trimmed, cursor);
    }
    if !trimmed[cursor..].starts_with('{') {
        return None;
    }
    let close_end = skip_balanced_perl_braces(trimmed, cursor);
    if close_end <= cursor + 1
        || close_end > trimmed.len()
        || trimmed.as_bytes().get(close_end - 1).copied() != Some(b'}')
    {
        return None;
    }
    let field = perl_hash_field_name(&trimmed[cursor + 1..close_end - 1])?;
    cursor = skip_ascii_ws(trimmed, close_end);
    // Reject anything trailing — `$h->{k}->[0]` etc. — so we don't
    // mis-collapse multi-level accesses.
    (cursor == trimmed.len()).then(|| format!("{base}.{field}"))
}

/// Advance `idx` past any ASCII whitespace bytes in `text`.
fn skip_ascii_ws(text: &str, mut idx: usize) -> usize {
    while idx < text.len() && text.as_bytes()[idx].is_ascii_whitespace() {
        idx += 1;
    }
    idx
}

/// Validate and unquote a hash key. Accepts bareword identifiers
/// (matching `[A-Za-z_][A-Za-z0-9_]*`) optionally wrapped in single
/// or double quotes; returns `None` otherwise.
fn perl_hash_field_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Strip matching surrounding quotes if present.
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|part| part.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|part| part.strip_suffix('\''))
        })
        .unwrap_or(trimmed)
        .trim();
    // Reject anything that isn't a simple identifier — `$h->{$k}` and
    // `$h->{a-b}` shouldn't collapse to a dotted form.
    if unquoted.is_empty()
        || unquoted
            .chars()
            .next()
            .is_some_and(|ch| !(ch == '_' || ch.is_ascii_alphabetic()))
        || !unquoted.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(unquoted.to_string())
}

/// True if `name` is just a re-spelling of the LHS `target` (or its
/// base / field). Used to drop extractor noise where the same span
/// reports the LHS as one of its `source_names`.
fn perl_source_name_is_lhs_artifact(name: &str, target: &str) -> bool {
    let target = target.trim();
    let Some((base, field)) = target.rsplit_once('.') else {
        return false;
    };
    let bare_base = base.trim_start_matches(['$', '@', '%']);
    let bare_target = target.trim_start_matches(['$', '@', '%']);
    let normalized = normalize_perl_hash_deref_text(name);
    // Collapse `->` and `{}`/`}` shapes so we compare canonical forms.
    let collapsed = normalized
        .replace("->", ".")
        .replace(['{', '}'], "")
        .trim_matches('.')
        .to_string();
    [name.trim(), normalized.as_str(), collapsed.as_str()]
        .iter()
        .any(|candidate| {
            !candidate.is_empty()
                && (*candidate == target
                    || *candidate == bare_target
                    || *candidate == base
                    || *candidate == bare_base
                    || *candidate == field)
        })
}

/// Scan `text` for sigil'd identifiers (e.g. `$x`, `@arr`, `%h`)
/// matching any of `sigils`, ignoring matches inside string
/// literals. Returns each unique identifier (with sigil) in source
/// order.
fn perl_sigiled_identifiers(text: &str, sigils: impl IntoIterator<Item = char>) -> Vec<String> {
    let sigils = sigils.into_iter().collect::<Vec<_>>();
    let mut identifiers = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut chars = text.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if !sigils.contains(&ch) {
            continue;
        }
        let mut end = idx + ch.len_utf8();
        while let Some((next_idx, next_ch)) = chars.peek().copied() {
            if next_ch == '_' || next_ch.is_ascii_alphanumeric() {
                chars.next();
                end = next_idx + next_ch.len_utf8();
            } else {
                break;
            }
        }
        // Bare sigil with no name (`$$` etc.) — skip.
        if end > idx + ch.len_utf8() {
            push_unique_string(&mut identifiers, text[idx..end].to_string());
        }
    }
    identifiers
}

/// Append `value` to `out` only if it's non-empty and not already
/// present. Linear-scan dedup is fine here because the call sites
/// produce O(few) names per event.
fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

/// Walk every Call event and rewrite its arg `value_text` so that
/// (a) string literals include their surrounding quotes, and
/// (b) sigil'd variables with deref tails (`$h->{k}`, `$h{k}`) cover
/// the full expression.
///
/// Recurses into nested control-flow event lists so deeply-nested
/// calls get the same treatment.
fn rewrite_perl_call_arg_texts(events: &mut [FlowEvent], source: &str) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in &mut *args {
                    if let Some(source_name) = perl_coderef_rhs_source(&arg.value_text) {
                        // `\&name` is a grammar-recognized exact Perl
                        // coderef, not a compound expression containing a
                        // callable-looking token. Preserve that proof in the
                        // language-neutral CallArg place fact.
                        arg.value_text.clone_from(&source_name);
                        arg.place = Some(source_name.clone());
                        arg.source_names.clear();
                        arg.source_names.push(source_name);
                        continue;
                    }
                    let start = usize::try_from(arg.span.start).unwrap_or(usize::MAX);
                    let end = usize::try_from(arg.span.end).unwrap_or(usize::MAX);
                    if start == usize::MAX || end > source.len() || start > end {
                        continue;
                    }
                    let bytes = source.as_bytes();
                    // String literal check: the byte just before the
                    // span and the byte AT the span end form a matched
                    // quote pair (the grammar exposes the inner
                    // content).
                    if start > 0
                        && end < bytes.len()
                        && matches!(bytes[start - 1], b'\'' | b'"' | b'`')
                        && bytes[start - 1] == bytes[end]
                    {
                        arg.value_text = source[start - 1..=end].to_string();
                        arg.place = None;
                        continue;
                    }
                    // Locate the sigil. The grammar sometimes places
                    // the span at the sigil and sometimes one byte
                    // past it, so check both.
                    let sigil_start = if matches!(bytes.get(start), Some(b'$' | b'@' | b'%')) {
                        Some(start)
                    } else if start > 0 && matches!(bytes[start - 1], b'$' | b'@' | b'%') {
                        Some(start - 1)
                    } else {
                        None
                    };
                    if let Some(sigil_start) = sigil_start {
                        // Extend through any chained `->{k}` / `{k}`
                        // accesses so the full deref shows up in the
                        // arg text.
                        let extended_end = extend_perl_deref_end(source, end);
                        arg.value_text = source[sigil_start..extended_end].to_string();
                        arg.place = Some(arg.value_text.clone());
                        for source_name in perl_collection_source_names(&arg.value_text) {
                            push_unique_string(&mut arg.source_names, source_name);
                        }
                    }
                }
                combine_perl_fat_comma_call_args(args, source);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_perl_call_arg_texts(then_events, source);
                rewrite_perl_call_arg_texts(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_perl_call_arg_texts(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_perl_call_arg_texts(body, source);
                rewrite_perl_call_arg_texts(catch_events, source);
                rewrite_perl_call_arg_texts(finally_events, source);
            }
            _ => {}
        }
    }
}

fn combine_perl_fat_comma_call_args(args: &mut Vec<CallArg>, source: &str) {
    if args.len() < 2 {
        return;
    }
    let mut combined = Vec::with_capacity(args.len());
    let mut idx = 0usize;
    while idx < args.len() {
        if idx + 1 < args.len() && perl_args_have_fat_comma_between(&args[idx], &args[idx + 1], source) {
            let key = args[idx].value_text.trim().to_string();
            let value = &args[idx + 1];
            let start = usize::try_from(args[idx].span.start).unwrap_or(usize::MAX);
            let end = usize::try_from(value.span.end).unwrap_or(usize::MAX);
            let value_text = if start != usize::MAX && end <= source.len() && start <= end {
                source[start..end].trim().to_string()
            } else {
                format!("{key} => {}", value.value_text.trim())
            };
            combined.push(CallArg {
                passing_mode: Default::default(),
                span: Span::new(args[idx].span.file, args[idx].span.start, value.span.end),
                name: (!key.is_empty()).then_some(key),
                value_text,
                place: value.place.clone(),
                source_names: value.source_names.clone(),
            });
            idx += 2;
        } else {
            combined.push(args[idx].clone());
            idx += 1;
        }
    }
    *args = combined;
}

fn perl_args_have_fat_comma_between(left: &CallArg, right: &CallArg, source: &str) -> bool {
    if left.span.file != right.span.file || left.span.end > right.span.start {
        return false;
    }
    let start = usize::try_from(left.span.end).unwrap_or(usize::MAX);
    let end = usize::try_from(right.span.start).unwrap_or(usize::MAX);
    if start == usize::MAX || end > source.len() || start > end {
        return false;
    }
    let key = left.value_text.trim();
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric() || ch == ':')
        && source[start..end].contains("=>")
}

/// Starting at `end`, advance past any chained `->{k}`, `->ident`, or
/// bare `{k}` deref tails and return the new end byte.
fn extend_perl_deref_end(source: &str, mut end: usize) -> usize {
    loop {
        let rest = &source[end..];
        if let Some(after_arrow) = rest.strip_prefix("->") {
            end += 2;
            // `->{` opens a balanced brace deref.
            if after_arrow.starts_with('{') {
                end = skip_balanced_perl_braces(source, end);
                continue;
            }
            // `->ident` consumes the identifier characters.
            while let Some(ch) = source[end..].chars().next() {
                if ch == '_' || ch.is_ascii_alphanumeric() {
                    end += ch.len_utf8();
                } else {
                    break;
                }
            }
            continue;
        }
        // Bare `{k}` after a variable (no arrow needed).
        if rest.starts_with('{') {
            end = skip_balanced_perl_braces(source, end);
            continue;
        }
        return end;
    }
}

/// Walk forward from `open` (which must point at `{`) to its matching
/// `}` and return the byte index just past the close brace. Tolerates
/// nested braces and skips over quoted strings.
fn skip_balanced_perl_braces(source: &str, open: usize) -> usize {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut cursor = open;
    while cursor < source.len() {
        let Some(ch) = source[cursor..].chars().next() else {
            break;
        };
        cursor += ch.len_utf8();
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return cursor;
                }
            }
            _ => {}
        }
    }
    source.len()
}

/// Replace `my ($a, $b) = @_;` style list-context destructures with
/// one explicit Assign per bound variable so taint sees each parameter
/// individually, and report the bound names back as the inferred
/// parameter list.
///
/// Returns `None` when no list binding is found (callers fall back to
/// `infer_perl_params_from_body`).
fn rewrite_perl_list_param_bindings(
    events: &mut Vec<FlowEvent>,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) -> Option<Vec<String>> {
    let mut rewritten = Vec::with_capacity(events.len());
    let mut inferred_params = None;
    let mut event_idx = 0;
    while event_idx < events.len() {
        let Some((span, vars)) = perl_list_binding_at(&events[event_idx], source, assignment_values) else {
            rewritten.push(events[event_idx].clone());
            event_idx += 1;
            continue;
        };
        // First binding wins — that's the canonical positional list.
        if inferred_params.is_none() {
            inferred_params = Some(vars.clone());
        }
        // Skip any subsequent same-span Assigns the extractor emitted
        // for this binding.
        while event_idx < events.len() {
            match &events[event_idx] {
                FlowEvent::Assign { span: next_span, .. } if *next_span == span => event_idx += 1,
                _ => break,
            }
        }
        // Replace the original Assigns with one Assign per variable
        // so each parameter has its own taint seed.
        for var in vars {
            let bare = var.trim_start_matches(['$', '@', '%']).to_string();
            rewritten.push(FlowEvent::Assign {
                span,
                target: var.clone(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec![var, bare],
                declares_new_binding: false,
                value_kind: None,
            });
        }
    }
    *events = rewritten;
    inferred_params
}

/// If `event` is a `my (...) = @_;` destructure, return the span and
/// the list of bound variable names (with sigils preserved).
fn perl_list_binding_at(
    event: &FlowEvent,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) -> Option<(bonsai_common::Span, Vec<String>)> {
    let FlowEvent::Assign {
        span, source_names, ..
    } = event
    else {
        return None;
    };
    // The extractor surfaces `_` / `@_` in source_names whenever the
    // RHS references the implicit args array.
    if !source_names.iter().any(|name| name == "_" || name == "@_") {
        return None;
    }
    let vars = assignment_values
        .target_rendering(*span, source)
        .zip(assignment_values.rendering(*span, source))
        .and_then(|(lhs, rhs)| {
            if !rhs.contains("@_") {
                return None;
            }
            let vars = perl_sigiled_identifiers(lhs, ['$', '@', '%'])
                .into_iter()
                .filter(|var| var != "@_")
                .collect::<Vec<_>>();
            (!vars.is_empty()).then_some(vars)
        })
        .unwrap_or_else(|| {
            // Fallback for synthetic events that have no parsed target fact:
            // synthesize from `source_names`, normalizing to `$name` and
            // reversing because `source_names` is right-to-left in stack
            // order.
            let mut vars = source_names
                .iter()
                .filter(|name| name.as_str() != "_" && name.as_str() != "@_")
                .map(|name| {
                    if name.starts_with('$') {
                        name.clone()
                    } else {
                        format!("${name}")
                    }
                })
                .collect::<Vec<_>>();
            vars.reverse();
            vars
        });
    if vars.is_empty() {
        None
    } else {
        Some((*span, vars))
    }
}

/// Preserve Perl sigils on list-context call-result bindings.
///
/// The shared tuple lowering correctly emits one assignment per result slot,
/// but `tree-sitter-perl` exposes each list-pattern variable's inner
/// `varname`, so those synthetic targets arrive as `count` / `bytes`.  The
/// assignment syntax fact still owns the exact `my ($count, $bytes)` pattern;
/// map each compiler-emitted tuple-result ordinal back to that parsed binding
/// and remove the grammar's redundant same-slot alias.
fn normalize_perl_list_result_targets(
    events: &mut Vec<FlowEvent>,
    source: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_names,
                ..
            } => {
                let tuple_index = source_names.iter().find_map(|name| {
                    name.strip_prefix("__bonsai_tuple_result_")
                        .and_then(|index| index.parse::<usize>().ok())
                });
                let Some(tuple_index) = tuple_index else {
                    continue;
                };
                let Some(lhs) = assignment_values.target_rendering(*span, source) else {
                    continue;
                };
                let bindings = perl_sigiled_identifiers(lhs, ['$', '@', '%']);
                if let Some(binding) = bindings.get(tuple_index) {
                    target.clone_from(binding);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_list_result_targets(then_events, source, assignment_values);
                normalize_perl_list_result_targets(else_events, source, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_list_result_targets(body, source, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_list_result_targets(body, source, assignment_values);
                normalize_perl_list_result_targets(catch_events, source, assignment_values);
                normalize_perl_list_result_targets(finally_events, source, assignment_values);
            }
            _ => {}
        }
    }

    let mut seen_tuple_slots = std::collections::HashSet::new();
    events.retain(|event| {
        let FlowEvent::Assign {
            span,
            target,
            source_names,
            ..
        } = event
        else {
            return true;
        };
        let Some(tuple_index) = source_names.iter().find_map(|name| {
            name.strip_prefix("__bonsai_tuple_result_")
                .and_then(|index| index.parse::<usize>().ok())
        }) else {
            return true;
        };
        seen_tuple_slots.insert((*span, tuple_index, target.clone()))
    });
}

/// Walk the leading flow events of a Perl sub looking for the
/// canonical positional-arg binding patterns:
///
///   my ($a, $b) = @_;   — list-context destructure
///   my $a = shift;      — sequential shift
///   my $a = `$_[0]`;    — explicit positional index
///
/// Returns the parameter names (with `$` sigil preserved) in the
/// order they bind, so G5 entry-point seeding and the taint seed
/// match how Perl code actually declares its params.
fn infer_perl_params_from_body(events: &[FlowEvent]) -> Vec<String> {
    let mut params: Vec<String> = Vec::new();
    for event in events {
        let FlowEvent::Assign {
            target,
            source_name,
            source_names,
            ..
        } = event
        else {
            // Only look at the contiguous prefix of Assigns — any
            // non-Assign event marks the end of the parameter-
            // binding prologue (call/branch/loop/try/return/throw,
            // plus yield/await/defer/using/break/continue all imply
            // the prologue is over).
            break;
        };
        // Shape 1: `my $a = shift` — target is a sigil'd var, RHS
        // references `shift` or `@_`.
        let rhs_mentions_args = source_name
            .as_deref()
            .is_some_and(|s| s == "shift" || s == "@_" || s.starts_with("$_["))
            || source_names
                .iter()
                .any(|n| n == "shift" || n == "@_" || n == "_" || n.starts_with("_["));
        if !target.is_empty()
            && rhs_mentions_args
            && target.starts_with('$')
            && !params.iter().any(|p| p == target)
        {
            params.push(target.clone());
        }
    }
    params
}

/// Perl exposes a subroutine's unnamed variadic arguments through `@_`.
/// When a parsed foreach iterable is exactly that array, model `@_` as the
/// formal variadic pack rather than misclassifying the loop variable as a
/// declared parameter. The shared foreach frontend has already attached the
/// iterable's AST-derived source names to same-span Assign events.
fn perl_implicit_args_foreach(events: &[FlowEvent]) -> bool {
    let mut loop_spans = std::collections::HashSet::new();
    collect_perl_loop_spans(events, &mut loop_spans);
    event_tree_contains_implicit_args_binding(events, &loop_spans)
}

fn normalize_perl_foreach_binding_targets(events: &mut [FlowEvent], tree: &Tree, src: &[u8], file: FileId) {
    let mut targets = std::collections::HashMap::new();
    for loop_node in collect_kinds(tree, &["for_statement"]) {
        let Some(variable) = loop_node.child_by_field_name("variable") else {
            continue;
        };
        let target = node_text(&variable, src).trim();
        if !target.starts_with('$') {
            continue;
        }
        targets.insert(span_of(file, &loop_node), target.to_string());
    }
    normalize_perl_foreach_targets_in_events(events, &targets);
}

fn normalize_perl_foreach_targets_in_events(
    events: &mut [FlowEvent],
    targets: &std::collections::HashMap<Span, String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign { span, target, .. } => {
                if let Some(parsed_target) = targets.get(span) {
                    target.clone_from(parsed_target);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_foreach_targets_in_events(then_events, targets);
                normalize_perl_foreach_targets_in_events(else_events, targets);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_foreach_targets_in_events(body, targets);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_foreach_targets_in_events(body, targets);
                normalize_perl_foreach_targets_in_events(catch_events, targets);
                normalize_perl_foreach_targets_in_events(finally_events, targets);
            }
            _ => {}
        }
    }
}

fn collect_perl_loop_spans(events: &[FlowEvent], out: &mut std::collections::HashSet<Span>) {
    for event in events {
        match event {
            FlowEvent::Loop { span, body, .. } => {
                out.insert(*span);
                collect_perl_loop_spans(body, out);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_perl_loop_spans(then_events, out);
                collect_perl_loop_spans(else_events, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_perl_loop_spans(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_perl_loop_spans(body, out);
                collect_perl_loop_spans(catch_events, out);
                collect_perl_loop_spans(finally_events, out);
            }
            _ => {}
        }
    }
}

fn event_tree_contains_implicit_args_binding(
    events: &[FlowEvent],
    loop_spans: &std::collections::HashSet<Span>,
) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Assign {
            span,
            source_name,
            source_names,
            ..
        } => {
            loop_spans.contains(span)
                && (source_name.as_deref() == Some("@_") || source_names.iter().any(|name| name == "@_"))
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            event_tree_contains_implicit_args_binding(then_events, loop_spans)
                || event_tree_contains_implicit_args_binding(else_events, loop_spans)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            event_tree_contains_implicit_args_binding(body, loop_spans)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            event_tree_contains_implicit_args_binding(body, loop_spans)
                || event_tree_contains_implicit_args_binding(catch_events, loop_spans)
                || event_tree_contains_implicit_args_binding(finally_events, loop_spans)
        }
        _ => false,
    })
}

/// Surface Perl's intrinsic process-input variables from parsed variable and
/// filehandle nodes. Comments and string contents never enter this walk.
fn extract_perl_special_variable_refs(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    let mut refs = Vec::new();
    for node in collect_kinds(tree, &["varname", "filehandle"]) {
        let name = node_text(&node, src).trim();
        if !matches!(name, "ARGV" | "ENV" | "STDIN") {
            continue;
        }
        let anchor = if node.kind() == "varname" {
            node.parent()
                .filter(|parent| matches!(parent.kind(), "scalar" | "array" | "hash" | "container_variable"))
        } else {
            None
        }
        .unwrap_or(node);
        let reference = Ref {
            span: span_of(file, &anchor),
            name: name.to_string(),
            kind: RefKind::Read,
            scope: None,
            resolved: None,
        };
        if !refs
            .iter()
            .any(|existing: &Ref| existing.span == reference.span && existing.name == reference.name)
        {
            refs.push(reference);
        }
    }
    refs.sort_by_key(|reference| (reference.span.start, reference.span.end));
    refs
}

/// Parse Perl `use Foo;` and `require Foo;` statements into
/// `ImportSpec` records.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Perl `use_statement` is a dedicated grammar node:
    //   `use Foo;`              → module: package "Foo"
    //   `use Foo qw(a b);`      → module + quoted_word_list (export list)
    //   `use Foo ();`           → module + stub_expression (no exports)
    //   `use parent 'Bar';`     → module: parent + bareword string
    // Per-symbol import lists (`qw(a b)`) are resolver-local bindings:
    // `a()` should resolve to `Foo::a` without making every bare `a`
    // in the workspace eligible.
    for use_node in collect_kinds(tree, &["use_statement"]) {
        let Some(module_node) = use_node.child_by_field_name("module") else {
            continue;
        };
        let module = node_text(&module_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &use_node),
            module: module.clone(),
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if !is_perl_inheritance_pragma(&module) {
            for exported in perl_use_qw_imports(&use_node, src) {
                imports.push(ImportSpec {
                    span: span_of(file, &use_node),
                    module: module.clone(),
                    alias: None,
                    is_wildcard: false,
                    original_name: Some(exported),
                    scope: ImportScope::Local,
                });
            }
        }
    }
    // `require Some::Module;` is a dedicated `require_expression` wrapping
    // a `bareword`. Different from PHP's require — no string literal,
    // just a module name.
    for require_node in collect_kinds(tree, &["require_expression"]) {
        let mut cursor = require_node.walk();
        let Some(first_child) = require_node.named_children(&mut cursor).next() else {
            continue;
        };
        // Accept either bareword module names or string literals
        // (`require 'module.pl'` is a runtime path-load form).
        let module = match first_child.kind() {
            "bareword" => node_text(&first_child, src).to_string(),
            "interpolated_string_literal" | "string_literal" => node_text(&first_child, src)
                .trim_matches(|ch: char| matches!(ch, '"' | '\''))
                .to_string(),
            _ => continue,
        };
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &require_node),
            module,
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn perl_use_qw_imports(use_node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = use_node.walk();
    for child in use_node.named_children(&mut cursor) {
        if child.kind() != "quoted_word_list" {
            continue;
        }
        collect_qw_words(child, src, &mut out);
    }
    out
}

fn is_perl_inheritance_pragma(module: &str) -> bool {
    matches!(module, "base" | "parent" | "mro" | "parent::versioned")
}

fn collect_qw_words(node: tree_sitter::Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if matches!(node.kind(), "string_content" | "bareword") {
        for word in node_text(&node, src).split_whitespace() {
            let word = word.trim();
            if word.is_empty() || out.iter().any(|seen| seen == word) {
                continue;
            }
            out.push(word.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_qw_words(child, src, out);
    }
}

/// Walk the parse tree for `command_string` nodes (the tree-sitter
/// shape covering both `qx//` quote-like operators and backtick
/// `` `cmd` ``) and synthesize a `FlowEvent::Call` for each one.
/// The synthesized call is named `qx` so the shipped
/// `perl.cmdi.qx_backticks` rule (callee.name: qx) matches.
///
/// Each interpolated scalar variable inside the command string
/// becomes a `CallArg` whose `value_text` is the variable text
/// (`$tainted`). Plain literal command strings (no interpolation)
/// also surface as a Call but with an empty arg list — the rule
/// still matches at the call kind, but the taint engine has
/// nothing to flow into so the finding is correctly silent.
fn synthesize_qx_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for command_node in collect_kinds(tree, &["command_string"]) {
        let span = span_of(file, &command_node);
        let mut args: Vec<CallArg> = Vec::new();
        // The interpolated parts live under the `content` /
        // `string_content` child as `scalar` nodes. Walk
        // descendants so sigils inside nested expressions surface.
        let mut cursor = command_node.walk();
        let mut stack: Vec<tree_sitter::Node<'_>> = Vec::new();
        for child in command_node.named_children(&mut cursor) {
            stack.push(child);
        }
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "scalar" | "array" | "hash") {
                if let Some(argument) = perl_call_arg_from_node(node, file, src, None) {
                    args.push(argument);
                }
                continue;
            }
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                stack.push(child);
            }
        }
        let event = FlowEvent::Call {
            span,
            name: "qx".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args,
        };
        events.push((span, event));
    }
    events
}

/// Synthesize Call events for `$obj->method(args)` invocations.
/// tree-sitter-perl exposes them as `method_call_expression` rather
/// than `call_expression`, so the generic call extraction misses
/// them.
fn synthesize_method_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["method_call_expression"]) {
        let Some(invocant) = call_node.child_by_field_name("invocant") else {
            continue;
        };
        let Some(method) = call_node.child_by_field_name("method") else {
            continue;
        };
        // Strip the sigil so the receiver is a plain identifier.
        let receiver = node_text(&invocant, src)
            .trim()
            .trim_start_matches(['$', '@', '%']);
        let method_name = node_text(&method, src).trim();
        if receiver.is_empty() || method_name.is_empty() {
            continue;
        }
        let args = call_node
            .child_by_field_name("arguments")
            .map(|arguments| perl_list_args(&arguments, src, file))
            .unwrap_or_default();
        let span = span_of(file, &call_node);
        let is_constructor = method_name == "new";
        events.push((
            span,
            FlowEvent::Call {
                span,
                name: format!("{receiver}->{method_name}"),
                receiver: Some(receiver.to_string()),
                receiver_types: if is_constructor {
                    vec![receiver.to_string()]
                } else {
                    Vec::new()
                },
                // Perl convention: `Class->new` is the constructor.
                call_kind: if is_constructor {
                    CallKind::Constructor
                } else {
                    CallKind::Method
                },
                args,
            },
        ));
    }
    events
}

/// Synthesize exact calls for Perl's statically-qualified
/// `Package::function(args)` form.
///
/// In this grammar a single argument is the `arguments` field itself rather
/// than a child of an argument-list wrapper.  The shared lowering therefore
/// retains the exact qualified callee but can see an empty argument vector.
/// Re-lower that grammar shape here so argument-count and value-flow facts are
/// exact.  Package/API meaning remains entirely in rule data.
fn synthesize_qualified_function_call_events(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(
        tree,
        &["function_call_expression", "ambiguous_function_call_expression"],
    ) {
        let Some(target) = perl_call_target(call_node, src) else {
            continue;
        };
        if !target.full_text.contains("::") {
            continue;
        }
        let args = call_node
            .child_by_field_name("arguments")
            .map(|arguments| perl_list_args(&arguments, src, file))
            .unwrap_or_default();
        let span = span_of(file, &call_node);
        events.push((
            span,
            FlowEvent::Call {
                span,
                name: target.full_text,
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            },
        ));
    }
    events
}

/// Convert a Perl argument-list node into `CallArg`s. Recognises
/// `key => value` fat-comma pairs as named args; everything else
/// becomes a positional arg.
fn perl_call_arg_from_node(
    node: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
    name: Option<String>,
) -> Option<CallArg> {
    let mut argument = call_arg_from_node_with_handler(node, file, src, name, &HANDLER)?;
    if matches!(node.kind(), "scalar" | "array" | "hash") {
        if argument.place.is_none() {
            argument.place = Some(argument.value_text.clone());
        }
        for source_name in perl_collection_source_names(&argument.value_text) {
            push_unique_string(&mut argument.source_names, source_name);
        }
    }
    Some(argument)
}

fn perl_list_args(node: &tree_sitter::Node<'_>, src: &[u8], file: FileId) -> Vec<CallArg> {
    // Single-value forms (`$x`, `'lit'`, `42`) wrap the argument
    // directly — emit a one-element CallArg list.
    if perl_node_is_single_arg(node.kind()) {
        return perl_call_arg_from_node(*node, file, src, None)
            .into_iter()
            .collect();
    }

    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    let mut args = Vec::new();
    let mut child_idx = 0;
    while child_idx < children.len() {
        let child = children[child_idx];
        // Detect fat-comma named args: `key => value` pairs.
        if matches!(child.kind(), "bareword" | "autoquoted_bareword") && child_idx + 1 < children.len() {
            let value_idx = child_idx + 1;
            if let Some(next) = children
                .get(value_idx)
                .copied()
                .filter(|next| perl_args_have_fat_comma_token(*node, child, *next))
            {
                let name = node_text(&child, src).trim().to_string();
                if let Some(mut argument) = perl_call_arg_from_node(next, file, src, Some(name)) {
                    argument.span = Span::new(
                        file,
                        u64::try_from(child.start_byte()).unwrap_or(u64::MAX),
                        u64::try_from(next.end_byte()).unwrap_or(u64::MAX),
                    );
                    args.push(argument);
                }
                child_idx = value_idx + 1;
                continue;
            }
        }
        if let Some(argument) = perl_call_arg_from_node(child, file, src, None) {
            args.push(argument);
        }
        child_idx += 1;
    }
    args
}

fn perl_args_have_fat_comma_token(
    container: tree_sitter::Node<'_>,
    left: tree_sitter::Node<'_>,
    right: tree_sitter::Node<'_>,
) -> bool {
    let mut cursor = container.walk();
    let found = container.children(&mut cursor).any(|token| {
        token.kind() == "=>"
            && token.start_byte() >= left.end_byte()
            && token.end_byte() <= right.start_byte()
    });
    found
}

/// True if `kind` represents a single-value expression node — used to
/// decide whether an argument list wraps one value or many.
fn perl_node_is_single_arg(kind: &str) -> bool {
    matches!(
        kind,
        "scalar"
            | "array"
            | "hash"
            | "number"
            | "interpolated_string_literal"
            | "string_literal"
            | "command_string"
            | "bareword"
            | "autoquoted_bareword"
    )
}

/// Synthesize Call events for `rand` / `stat` builtins parsed by
/// tree-sitter-perl as `func1op_call_expression`. The shipped rules
/// expect them as named function calls.
fn synthesize_builtin_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["func1op_call_expression"]) {
        let text = node_text(&call_node, src).trim();
        // Only handle the small set of builtins the rulepack queries.
        // Match `name`, `name(...)`, or `name <ws>...` shapes.
        // Builtins surfaced as named Call events. `close` / `read` /
        // `unlink` feed the lifecycle injector; `rand` / `stat` feed
        // the rulepack.
        let Some(name) = ["rand", "stat", "close", "read", "unlink"]
            .into_iter()
            .find(|name| {
                text == *name
                    || text.strip_prefix(*name).is_some_and(|rest| {
                        rest.starts_with('(') || rest.chars().next().is_some_and(char::is_whitespace)
                    })
            })
        else {
            continue;
        };
        let mut args = Vec::new();
        let mut cursor = call_node.walk();
        let mut stack: Vec<tree_sitter::Node<'_>> = call_node.named_children(&mut cursor).collect();
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "scalar" | "array" | "hash") {
                if let Some(argument) = perl_call_arg_from_node(node, file, src, None) {
                    args.push(argument);
                }
                continue;
            }
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                stack.push(child);
            }
        }
        events.push((
            span_of(file, &call_node),
            FlowEvent::Call {
                span: span_of(file, &call_node),
                name: name.to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            },
        ));
    }
    events
}

/// Synthesize Call events for `system "cmd $arg"` / `eval "code"`
/// where the argument is a binary string-concatenation expression.
/// The grammar wraps these as `function_call_expression`s but the
/// arguments don't surface through the generic call extraction.
fn synthesize_builtin_expression_arg_call_events(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["function_call_expression"]) {
        let Some(function_node) = call_node.child_by_field_name("function") else {
            continue;
        };
        let name = node_text(&function_node, src).trim();
        // Only `system` and `eval` are interesting here — others
        // already lower correctly through the generic extraction.
        if !matches!(name, "system" | "eval") {
            continue;
        }
        let Some(arguments) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        // Restrict to string-concat expressions; literal-only calls
        // already have no taint surface.
        if arguments.kind() != "binary_expression" {
            continue;
        }
        let span = span_of(file, &call_node);
        let Some(argument) = perl_call_arg_from_node(arguments, file, src, None) else {
            continue;
        };
        events.push((
            span,
            FlowEvent::Call {
                span,
                name: name.to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: vec![argument],
            },
        ));
    }
    events
}

/// Synthesize a Call event named `m` for each `match_regexp` node so
/// regex-based rules can match on the pattern text.
fn synthesize_match_regex_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for match_node in collect_kinds(tree, &["match_regexp"]) {
        // In `split /pattern/, $value`, tree-sitter-perl reuses the
        // `match_regexp` node for the delimiter. Perl evaluates that node as
        // split's pattern argument; it does not execute an implicit `m//`
        // against `$_`. Emitting a second match call also gives the synthetic
        // foreach binding's loop-wide span a false late prerequisite. Classify
        // the intrinsic syntax from the exact parsed callee/argument position.
        if perl_match_regexp_is_split_pattern(match_node, src) {
            continue;
        }
        let Some(content) = match_node.child_by_field_name("content") else {
            continue;
        };
        let Some(content_argument) = perl_call_arg_from_node(content, file, src, None) else {
            continue;
        };
        let args = vec![content_argument];
        let span = span_of(file, &match_node);
        events.push((
            span,
            FlowEvent::Call {
                span,
                name: "m".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            },
        ));
    }
    events
}

fn perl_match_regexp_is_split_pattern(match_node: Node<'_>, src: &[u8]) -> bool {
    let mut current = match_node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "ambiguous_function_call_expression" | "function_call_expression"
        ) {
            let Some(function) = parent.child_by_field_name("function") else {
                return false;
            };
            if node_text(&function, src).trim() != "split" {
                return false;
            }
            let Some(arguments) = parent.child_by_field_name("arguments") else {
                return false;
            };
            let mut cursor = arguments.walk();
            return arguments
                .named_children(&mut cursor)
                .next()
                .is_some_and(|first| first.id() == match_node.id());
        }
        if matches!(parent.kind(), "statement" | "expression_statement" | "block") {
            return false;
        }
        current = parent;
    }
    false
}

/// Detect coderef invocations (`$cb->(...)` / `&$cb(...)`) by textual
/// search and emit a Call event so taint sees them as call sites. The
/// grammar's `method_call_expression` shape doesn't fire for
/// arrow-with-parens-only forms.
fn synthesize_coderef_invocation_events(src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    let mut search_idx = 0usize;
    while search_idx + 3 <= src.len() {
        let Some(relative_arrow) = find_bytes(&src[search_idx..], b"->(") else {
            break;
        };
        let arrow_idx = search_idx + relative_arrow;
        let Some((name_start, name_end)) = perl_coderef_name_before_arrow(src, arrow_idx) else {
            // No identifier before the arrow — skip past it.
            search_idx = arrow_idx + 2;
            continue;
        };
        let Some(close) = find_matching_perl_paren(src, arrow_idx + 2) else {
            // Unbalanced parens — skip and keep scanning.
            search_idx = arrow_idx + 2;
            continue;
        };
        let name = String::from_utf8_lossy(&src[name_start..name_end])
            .trim()
            .to_string();
        if name.is_empty() {
            search_idx = close + 1;
            continue;
        }
        let call_end = close + 1;
        let span = Span::new(
            file,
            u64::try_from(name_start).unwrap_or(u64::MAX),
            u64::try_from(call_end).unwrap_or(u64::MAX),
        );
        events.push((
            span,
            FlowEvent::Call {
                span,
                name,
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: perl_text_args(src, arrow_idx + 3, close, file),
            },
        ));
        search_idx = call_end;
    }
    events
}

/// Naive byte-window search for `needle` inside `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Locate the identifier (with optional sigil) immediately preceding
/// `arrow` in `src`. Used to find the coderef name in `$cb->(...)`.
fn perl_coderef_name_before_arrow(src: &[u8], arrow: usize) -> Option<(usize, usize)> {
    let mut end = arrow;
    while end > 0 && src[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let byte = src[start - 1];
        if byte == b'_' || byte.is_ascii_alphanumeric() {
            start -= 1;
        } else {
            break;
        }
    }
    // No identifier before arrow — bail.
    if start == end {
        return None;
    }
    // Include the sigil if it directly precedes the name.
    if start > 0 && matches!(src[start - 1], b'$' | b'@' | b'%') {
        start -= 1;
    }
    Some((start, end))
}

/// Find the byte index of the `)` that matches `(` at `open`, or
/// `None` if unbalanced. Skips quoted segments.
fn find_matching_perl_paren(src: &[u8], open: usize) -> Option<usize> {
    if src.get(open).copied() != Some(b'(') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (idx, &byte) in src.iter().enumerate().skip(open) {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == open_quote {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split the byte range `start..end` of `src` on top-level commas
/// into `CallArg`s, trimming whitespace and skipping empty pieces.
fn perl_text_args(src: &[u8], start: usize, end: usize, file: FileId) -> Vec<CallArg> {
    if start >= end || end > src.len() {
        return Vec::new();
    }
    let mut args = Vec::new();
    let mut arg_start = start;
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for idx in start..=end {
        // Treat the end as a virtual comma so the final arg is flushed.
        let byte = if idx == end { b',' } else { src[idx] };
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == open_quote {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                let mut part_start = arg_start;
                let mut part_end = idx;
                // Trim leading/trailing whitespace from the piece.
                while part_start < part_end && src[part_start].is_ascii_whitespace() {
                    part_start += 1;
                }
                while part_end > part_start && src[part_end - 1].is_ascii_whitespace() {
                    part_end -= 1;
                }
                if part_start < part_end {
                    let value_text = String::from_utf8_lossy(&src[part_start..part_end]).to_string();
                    let source_names = perl_collection_source_names(&value_text);
                    args.push(CallArg {
                        passing_mode: Default::default(),
                        span: Span::new(
                            file,
                            u64::try_from(part_start).unwrap_or(u64::MAX),
                            u64::try_from(part_end).unwrap_or(u64::MAX),
                        ),
                        name: None,
                        // Sigil'd args double as `place`s for taint.
                        place: value_text
                            .starts_with(['$', '@', '%'])
                            .then(|| value_text.clone()),
                        value_text,
                        source_names,
                    });
                }
                arg_start = idx + 1;
            }
            _ => {}
        }
    }
    args
}

/// Perl's `map { ... } @items` / `grep { ... } @items` binds each
/// element to the implicit topic variable `$_` inside the callback
/// block. The generic walker sees calls inside the block (`step($_)`)
/// but does not have a scoped variable binding for `$_`. Instead of
/// globally tainting `$_`, synthesize a parallel callback call whose
/// topic argument is the mapped collection expression.
fn synthesize_map_grep_topic_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for map_node in collect_kinds(tree, &["map_grep_expression"]) {
        let Some(callback) = map_node.child_by_field_name("callback") else {
            continue;
        };
        let Some(list) = map_node.child_by_field_name("list") else {
            continue;
        };
        let list_span = span_of(file, &list);
        let source_names = perl_collection_source_names(node_text(&list, src));
        let Some(primary_source) = source_names.first().cloned() else {
            continue;
        };
        for call_node in descendant_nodes_of_kind(callback, "function_call_expression") {
            let Some(function) = call_node.child_by_field_name("function") else {
                continue;
            };
            let name = node_text(&function, src).trim().to_string();
            if name.is_empty() {
                continue;
            }
            let Some(arguments) = call_node.child_by_field_name("arguments") else {
                continue;
            };
            let mut args = perl_list_args(&arguments, src, file);
            let mut rewrote_topic_arg = false;
            for arg in &mut args {
                if perl_arg_uses_topic_var(&arg.value_text) {
                    arg.span = list_span;
                    arg.value_text.clone_from(&primary_source);
                    arg.place = Some(primary_source.clone());
                    arg.source_names.clone_from(&source_names);
                    rewrote_topic_arg = true;
                }
            }
            if !rewrote_topic_arg {
                continue;
            }
            let span = span_of(file, &call_node);
            events.push((
                span,
                FlowEvent::Call {
                    span,
                    name,
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args,
                },
            ));
        }
    }
    events
}

fn descendant_nodes_of_kind<'tree>(
    root: tree_sitter::Node<'tree>,
    kind: &str,
) -> Vec<tree_sitter::Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node != root && node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    out
}

fn perl_collection_source_names(text: &str) -> Vec<String> {
    let mut source_names = Vec::new();
    for name in perl_sigiled_identifiers(text, ['$', '@', '%']) {
        push_unique_string(&mut source_names, name.clone());
        push_unique_string(
            &mut source_names,
            name.trim_start_matches(['$', '@', '%']).to_string(),
        );
    }
    source_names
}

fn perl_arg_uses_topic_var(text: &str) -> bool {
    text.split(|ch: char| !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()))
        .any(|part| matches!(part, "$_" | "_"))
}

/// Attach each synthesized (span, event) pair to the decl whose
/// body contains it. Pick the SMALLEST containing decl — Perl
/// supports nested `sub { ... }` blocks inside an outer sub, so
/// picking the first match would silently route synthetic events
/// (qx// shell-out etc.) to the outer sub. If no enclosing decl
/// exists (top-level qx// in a script body), the event is dropped
/// — the rulepack's qx rule already requires a sub context for
/// the finding to chain to a source. Linear walk over decls — Perl
/// files rarely have more than a handful of subs, so
/// O(events × decls) is fine.
fn attach_synthesized_calls_to_decls(idx: &mut DeclIndex, events: Vec<(Span, FlowEvent)>) {
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
            // Keep an already-complete kit call in its compiler-owned
            // control/evaluation position. The synthesized fact exists only
            // to repair grammar shapes whose generic call is incomplete.
            if perl_synth_call_duplicates_kit_call(&idx.defs[decl_idx].flow_events, event_span, &event) {
                continue;
            }
            // The grammar's generic call lowering also sees these nodes, but
            // for an arrow call it exposes only the invocant as the callee,
            // and for a qualified function with a leaf argument field it
            // exposes an empty arg vector. Replace that exact event in place
            // so its branch/loop membership and statement order survive the
            // repair. Removing it and appending the replacement to the end
            // made earlier calls appear after a terminal return, where CFG
            // normalization correctly discarded them as unreachable.
            if replace_perl_incomplete_call_for_synth(&mut idx.defs[decl_idx].flow_events, event_span, &event)
            {
                continue;
            }
            idx.defs[decl_idx].flow_events.push(event);
        }
    }
}

fn replace_perl_incomplete_call_for_synth(
    events: &mut [FlowEvent],
    synth_span: Span,
    synth: &FlowEvent,
) -> bool {
    let FlowEvent::Call {
        name: synth_name,
        receiver: synth_receiver,
        call_kind: synth_kind,
        ..
    } = synth
    else {
        return false;
    };
    for event in events {
        let replace = match event {
            FlowEvent::Call {
                span, name, receiver, ..
            } => {
                let same_node_prefix = span.file == synth_span.file
                    && span.start == synth_span.start
                    && span.end <= synth_span.end;
                if !same_node_prefix {
                    false
                } else {
                    match synth_kind {
                        CallKind::Function => name == synth_name,
                        CallKind::Method | CallKind::Constructor => {
                            let Some(expected_receiver) = synth_receiver.as_deref() else {
                                return false;
                            };
                            let name_receiver = name.trim().trim_start_matches(['$', '@', '%']);
                            let emitted_receiver = receiver
                                .as_deref()
                                .unwrap_or_default()
                                .trim()
                                .trim_start_matches(['$', '@', '%']);
                            name_receiver == expected_receiver && emitted_receiver == expected_receiver
                        }
                        _ => false,
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if replace_perl_incomplete_call_for_synth(then_events, synth_span, synth)
                    || replace_perl_incomplete_call_for_synth(else_events, synth_span, synth)
                {
                    return true;
                }
                false
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if replace_perl_incomplete_call_for_synth(body, synth_span, synth) {
                    return true;
                }
                false
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if replace_perl_incomplete_call_for_synth(body, synth_span, synth)
                    || replace_perl_incomplete_call_for_synth(catch_events, synth_span, synth)
                    || replace_perl_incomplete_call_for_synth(finally_events, synth_span, synth)
                {
                    return true;
                }
                false
            }
            _ => false,
        };
        if replace {
            *event = synth.clone();
            return true;
        }
    }
    false
}

/// True when `event` is a synthesized `$obj->method(...)` Call that
/// the kit already emitted for the same node. The kit's Call uses the
/// `method`-identifier span (a name-span), which falls inside this
/// synth event's whole-`method_call_expression` span, and carries the
/// same `name`/`receiver`. Matching on overlap (CONTAINS) rather than
/// identical spans is required because the two spans deliberately
/// differ. Recurses into nested bodies since a kit Call inside an
/// `if`/`while`/`try` lands in a child event list.
fn perl_synth_call_duplicates_kit_call(existing: &[FlowEvent], synth_span: Span, event: &FlowEvent) -> bool {
    let FlowEvent::Call {
        name: synth_name,
        receiver: synth_receiver,
        call_kind,
        ..
    } = event
    else {
        return false;
    };
    // Only the method-call synth produces `receiver->method` names
    // with a Method/Constructor kind; qx/builtin synths are Functions.
    if !matches!(call_kind, CallKind::Method | CallKind::Constructor) || !synth_name.contains("->") {
        return false;
    }
    perl_flow_has_contained_call(existing, synth_span, synth_name, synth_receiver.as_deref())
}

fn perl_flow_has_contained_call(
    events: &[FlowEvent],
    synth_span: Span,
    synth_name: &str,
    synth_receiver: Option<&str>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span, name, receiver, ..
            } => {
                let contained = span.file == synth_span.file
                    && span.start >= synth_span.start
                    && span.end <= synth_span.end;
                if contained && name == synth_name && receiver.as_deref() == synth_receiver {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if perl_flow_has_contained_call(then_events, synth_span, synth_name, synth_receiver)
                    || perl_flow_has_contained_call(else_events, synth_span, synth_name, synth_receiver)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if perl_flow_has_contained_call(body, synth_span, synth_name, synth_receiver) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if perl_flow_has_contained_call(body, synth_span, synth_name, synth_receiver)
                    || perl_flow_has_contained_call(catch_events, synth_span, synth_name, synth_receiver)
                    || perl_flow_has_contained_call(finally_events, synth_span, synth_name, synth_receiver)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// True for decl kinds that represent Perl-style class-like
/// constructs — used to gate which decls receive `bases` entries.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Module
            | DeclKind::Class
            | DeclKind::Interface
            | DeclKind::Trait
            | DeclKind::Struct
            | DeclKind::Enum
    )
}

/// Walk every Perl `use_statement` whose module is `base` /
/// `parent` / `mro` and collect the string-literal arguments as
/// parent class names. Each `use base 'Foo::Bar';` adds `Bar` (the
/// right-most `::` segment of the literal). Multiple parents are
/// supported via `use base ('A', 'B');` or `use base qw(A B);`.
///
/// The collected bases are keyed by the smallest-containing class
/// decl span — for files with a single `package` and a few `use base`
/// lines that's the package decl, but a single `.pm` file can
/// declare multiple packages so we attach to the smallest match.
fn collect_perl_class_bases(
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
    idx: &DeclIndex,
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    use std::collections::HashMap;
    // Parse `use base/parent/mro 'X';` statements anywhere in the file.
    let mut bases_by_decl: HashMap<bonsai_common::Span, Vec<String>> = HashMap::new();
    for use_node in collect_kinds(tree, &["use_statement"]) {
        let Some(module_node) = use_node.child_by_field_name("module") else {
            continue;
        };
        let module = node_text(&module_node, src).trim();
        // Only the inheritance pragmas register parents.
        if !matches!(module, "base" | "parent" | "mro" | "parent::versioned") {
            continue;
        }
        // The use-statement's args follow the module name: walk all
        // descendant `string_content` nodes (covers single and double
        // quoted literals plus `qw(...)` words).
        let mut bases: Vec<String> = Vec::new();
        let mut stack: Vec<tree_sitter::Node<'_>> = vec![use_node];
        while let Some(node) = stack.pop() {
            // Skip the module-name node itself — we only want args.
            if node.id() == module_node.id() {
                continue;
            }
            match node.kind() {
                "string_content" | "bareword" => {
                    let raw = node_text(&node, src).trim();
                    // `qw(A B C)` content is a single text node;
                    // split on whitespace to get each parent name.
                    for piece in raw.split_whitespace() {
                        if let Some(name) = canonical_perl_base_name(piece) {
                            if !bases.iter().any(|existing| existing == &name) {
                                bases.push(name);
                            }
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
        if bases.is_empty() {
            continue;
        }
        // Find the smallest class-decl span that contains this
        // use_statement; attach the bases there. If the grammar
        // models `package Foo;` as a statement rather than a
        // container, fall back to the package range ending at the
        // next package statement.
        let use_span = span_of(file, &use_node);
        if let Some(decl_idx) = perl_class_decl_for_span(use_span, idx, file, src.len()) {
            push_perl_bases(&mut bases_by_decl, idx.defs[decl_idx].span, bases);
        }
    }
    collect_perl_isa_assignment_bases(tree, src, file, idx, &mut bases_by_decl);
    bases_by_decl.into_iter().collect()
}

fn perl_class_decl_for_span(span: Span, idx: &DeclIndex, file: FileId, source_len: usize) -> Option<usize> {
    let mut best_decl: Option<(usize, u64)> = None;
    for (decl_idx, decl) in idx.defs.iter().enumerate() {
        if !is_class_like(decl.kind) {
            continue;
        }
        let body = decl.body_span.unwrap_or(decl.span);
        if span.file == body.file && span.start >= body.start && span.end <= body.end {
            let body_len = body.end.saturating_sub(body.start);
            if best_decl.is_none_or(|(_, prev_len)| body_len < prev_len) {
                best_decl = Some((decl_idx, body_len));
            }
        }
    }
    if let Some((decl_idx, _)) = best_decl {
        return Some(decl_idx);
    }
    perl_package_ranges(idx, file, source_len)
        .into_iter()
        .find_map(|(decl_idx, range)| {
            (span.file == range.file && span.start >= range.start && span.end <= range.end)
                .then_some(decl_idx)
        })
}

fn perl_package_ranges(idx: &DeclIndex, file: FileId, source_len: usize) -> Vec<(usize, Span)> {
    let mut packages: Vec<(usize, Span)> = idx
        .defs
        .iter()
        .enumerate()
        .filter(|(_, decl)| is_class_like(decl.kind) && decl.span.file == file)
        .map(|(idx, decl)| (idx, decl.span))
        .collect();
    packages.sort_by_key(|(_, span)| span.start);
    let file_end = u64::try_from(source_len).unwrap_or(u64::MAX);
    let mut ranges = Vec::new();
    for pos in 0..packages.len() {
        let (decl_idx, span) = packages[pos];
        let end = packages
            .get(pos + 1)
            .map(|(_, next_span)| next_span.start)
            .unwrap_or(file_end);
        ranges.push((decl_idx, Span::new(file, span.start, end)));
    }
    ranges
}

fn collect_perl_isa_assignment_bases(
    tree: &Tree,
    src: &[u8],
    file: FileId,
    idx: &DeclIndex,
    bases_by_decl: &mut std::collections::HashMap<bonsai_common::Span, Vec<String>>,
) {
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let mut left_stack = vec![left];
        let mut is_isa = false;
        while let Some(node) = left_stack.pop() {
            if node.kind() == "varname"
                && node.parent().is_some_and(|parent| parent.kind() == "array")
                && node_text(&node, src).trim() == "ISA"
            {
                is_isa = true;
                break;
            }
            let mut cursor = node.walk();
            left_stack.extend(node.named_children(&mut cursor));
        }
        if !is_isa {
            continue;
        }
        let right = assignment
            .child_by_field_name("right")
            .filter(tree_sitter::Node::is_named)
            .or_else(|| {
                let mut cursor = assignment.walk();
                assignment.named_children(&mut cursor).last()
            });
        let Some(right) = right else {
            continue;
        };
        let mut base_nodes = Vec::new();
        let mut stack = vec![right];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "string_content" | "bareword" | "autoquoted_bareword") {
                base_nodes.push(node);
                continue;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        base_nodes.sort_by_key(tree_sitter::Node::start_byte);
        let mut bases = Vec::new();
        for node in base_nodes {
            for piece in node_text(&node, src).split_whitespace() {
                push_perl_base_name(&mut bases, piece);
            }
        }
        if bases.is_empty() {
            continue;
        }
        let assignment_span = span_of(file, &assignment);
        if let Some(decl_idx) = perl_class_decl_for_span(assignment_span, idx, file, src.len()) {
            push_perl_bases(bases_by_decl, idx.defs[decl_idx].span, bases);
        }
    }
}

fn push_perl_bases(
    bases_by_decl: &mut std::collections::HashMap<bonsai_common::Span, Vec<String>>,
    decl_span: Span,
    bases: Vec<String>,
) {
    let entry = bases_by_decl.entry(decl_span).or_default();
    for name in bases {
        if !entry.iter().any(|existing| existing == &name) {
            entry.push(name);
        }
    }
}

fn push_perl_base_name(out: &mut Vec<String>, raw: &str) {
    if let Some(name) = canonical_perl_base_name(raw) {
        if !out.iter().any(|existing| existing == &name) {
            out.push(name);
        }
    }
}

/// Strip Perl namespace separators (`::`) from a base name, returning
/// just the rightmost segment. Rejects flag-style arguments (e.g.
/// `-norequire`) and empty inputs.
fn canonical_perl_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(|ch: char| matches!(ch, '\'' | '"'));
    if trimmed.is_empty() {
        return None;
    }
    // Skip `-norequire` / `-no_isa` style flags occasionally passed
    // before module names.
    if trimmed.starts_with('-') {
        return None;
    }
    let bare = trimmed.rsplit("::").next().unwrap_or(trimmed).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

#[cfg(test)]
mod tests;
