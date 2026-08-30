//! Perl language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, collect_kinds, first_named_child_of_kind, language_from_pack,
        named_child_call_args_with_handler, node_at_span, node_text, parse_with,
        populate_call_argument_static_values, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, AssignmentNodeSemantics, CallArg, CallKind,
    CallTargetExtraction, CompilerGuardFact, ConditionEquality, ConditionExpressionFact,
    ConditionOperandFact, DeclIndex, DeclKind, ExpressionField, ExpressionFlow, ExpressionPlaceExtraction,
    FieldWrite, FiniteLiteralSelectionFact, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath, StaticScalarValue, StringCompositionFact,
    StringCompositionPart, TypeAliasBinding,
};
use std::collections::{HashMap, HashSet};

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
    let keyword = node
        .child(0)
        .map(|child| child.kind())
        .or_else(|| node_text(&node, src).split_whitespace().next())?;
    match keyword {
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

/// Exact assignment syntax needed by Perl-specific lowering.
///
/// Tree-sitter-perl deliberately preserves several runtime-significant forms
/// as patterns rather than ordinary scalar assignments (`my ($a, $b) = @_`,
/// `\&callable`, `map { ... } @items`, and `$@`).  Collect those forms once
/// from named CST nodes.  Later flow rewriting is keyed only by the parsed
/// assignment span and never reparses rendered source text.
#[derive(Clone, Debug, Default)]
struct PerlAssignmentSyntaxFacts {
    scalar_renames: HashMap<Span, String>,
    coderef_aliases: HashMap<Span, (String, String)>,
    collection_sources: HashMap<Span, Vec<String>>,
    ordered_bindings: HashMap<Span, Vec<String>>,
    implicit_arg_bindings: HashMap<Span, Vec<String>>,
    dollar_at_assignments: HashSet<Span>,
}

fn collect_perl_assignment_syntax_facts(tree: &Tree, file: FileId, src: &[u8]) -> PerlAssignmentSyntaxFacts {
    let mut facts = PerlAssignmentSyntaxFacts::default();
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let (Some(left), Some(right)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        let span = span_of(file, &assignment);
        let bindings = perl_binding_places(left, src);
        if !bindings.is_empty() {
            facts.ordered_bindings.insert(span, bindings.clone());
        }

        let exact_rhs = perl_expression_places(right, src).places;
        if exact_rhs.as_slice() == ["@_"] && !bindings.is_empty() {
            facts.implicit_arg_bindings.insert(span, bindings.clone());
        }
        if exact_rhs.as_slice() == ["$@"] {
            facts.dollar_at_assignments.insert(span);
        }
        if bindings.len() == 1
            && matches!(right.kind(), "scalar" | "array" | "hash" | "container_variable")
            && exact_rhs.len() == 1
            && exact_rhs[0] != "@_"
            && exact_rhs[0] != "$@"
        {
            facts.scalar_renames.insert(span, exact_rhs[0].clone());
        }

        if bindings.len() == 1 && right.kind() == "refgen_expression" {
            let callable = first_named_child_of_kind(&right, "function")
                .and_then(|function| first_named_child_of_kind(&function, "varname").or(Some(function)))
                .and_then(|name| perl_reference_name(name, src));
            if let Some(callable) = callable {
                facts
                    .coderef_aliases
                    .insert(span, (bindings[0].clone(), callable));
            }
        }

        if matches!(right.kind(), "map_grep_expression" | "sort_expression") {
            let list = right.child_by_field_name("list").or_else(|| {
                let mut cursor = right.walk();
                right.named_children(&mut cursor).last()
            });
            if let Some(list) = list {
                let sources = perl_node_value_sources(list, file, src);
                if !sources.is_empty() {
                    facts.collection_sources.insert(span, sources);
                }
            }
        }
    }
    facts
}

fn perl_binding_places(node: Node<'_>, src: &[u8]) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        let exact = perl_expression_places(node, src).places;
        if let [place] = exact.as_slice() {
            push_unique_string(out, place.clone());
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

fn collect_perl_expression_flow_sources(flow: &ExpressionFlow, out: &mut Vec<String>) {
    if let Some(place) = flow.place.as_ref() {
        push_perl_place_aliases(out, place);
    }
    for source in &flow.source_names {
        push_perl_place_aliases(out, source);
    }
    for field in &flow.aggregate_fields {
        collect_perl_expression_flow_sources(&field.value, out);
    }
    for item in &flow.tuple_items {
        collect_perl_expression_flow_sources(item, out);
    }
    for spread in &flow.spreads {
        collect_perl_expression_flow_sources(spread, out);
    }
}

fn perl_node_value_sources(node: Node<'_>, file: FileId, src: &[u8]) -> Vec<String> {
    fn collect_exact_places(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        let exact = perl_expression_places(node, src).places;
        if let [place] = exact.as_slice() {
            push_perl_place_aliases(out, place);
        }
        // A dereference wrapper is itself an addressable Perl place, but its
        // nested scalar reference is also a value dependency.  For example,
        // Tree-sitter represents `@$ref` as an `array` containing a nested
        // `scalar`; retaining both `@$ref` and `$ref` is what lets ordinary
        // parameter flow reach the dereferenced value without interpreting
        // rendered Perl text in the shared graph engine.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_exact_places(child, src, out);
        }
    }

    let mut sources = Vec::new();
    collect_exact_places(node, src, &mut sources);
    collect_perl_expression_flow_sources(
        &bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER),
        &mut sources,
    );
    sources
}

fn push_perl_place_aliases(out: &mut Vec<String>, place: &str) {
    let place = place.trim();
    if place.is_empty() {
        return;
    }
    push_unique_string(out, place.to_string());
    if place.starts_with(['$', '@', '%']) {
        push_unique_string(out, place.trim_start_matches(['$', '@', '%']).to_string());
    }
}

/// Accept Perl's grammar-specific `function` callee node. It is neither an
/// identifier nor a variable node, so generic extraction intentionally
/// refuses to guess it. Builtin meaning remains entirely in rule data.
fn perl_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if !matches!(
        node.kind(),
        "function_call_expression"
            | "method_call_expression"
            | "ambiguous_function_call_expression"
            | "coderef_call_expression"
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
            "function_call_expression"
                | "method_call_expression"
                | "ambiguous_function_call_expression"
                | "coderef_call_expression"
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
        "coderef_call_expression",
    ],
    constructor_call_kinds: &[],
    nested_call_component_kinds: &[],
    call_callee_field_names: &["function"],
    call_receiver_field_names: &["invocant"],
    call_member_field_names: &["method"],
    constructor_type_field_names: &[],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["list_expression"],
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
    pseudo_call_receiver_role: bonsai_lang_api::CallReceiverRole::Value,
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
        "coderef_call_expression",
    ],
    member_expression_kinds: &[],
    subscript_expression_kinds: &[],
    member_base_field_names: &[],
    member_name_field_names: &[],
    subscript_base_field_names: &[],
    subscript_index_field_names: &[],
    static_subscript_key_extractor: None,
    computed_subscript_extractor: None,
    sigil_variable_kinds: &["scalar", "array", "hash", "container_variable", "filehandle"],
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
            ("custom lowering", "coderef_call_expression"),
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
        let assignment_syntax = parsed
            .as_ref()
            .map(|(_, tree)| collect_perl_assignment_syntax_facts(tree, file, source.as_bytes()))
            .unwrap_or_default();
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
            let list_params = rewrite_perl_list_param_bindings(
                &mut decl.flow_events,
                &assignment_syntax.implicit_arg_bindings,
            );
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
        // Lower call-like Perl syntax whose grammar nodes are outside the
        // generic call inventory. Names and arguments come from the parsed
        // node itself; this frontend does not select operations for a rule.
        if let Some((_, tree)) = parsed.as_ref() {
            let mut calls = synthesize_qx_call_events(tree, source.as_bytes(), file);
            calls.extend(synthesize_method_call_events(tree, source.as_bytes(), file));
            calls.extend(synthesize_qualified_function_call_events(
                tree,
                source.as_bytes(),
                file,
            ));
            calls.extend(synthesize_func1op_call_events(tree, source.as_bytes(), file));
            calls.extend(synthesize_expression_arg_call_events(
                tree,
                source.as_bytes(),
                file,
            ));
            calls.extend(synthesize_match_regex_call_events(tree, source.as_bytes(), file));
            calls.extend(synthesize_map_grep_topic_call_events(
                tree,
                source.as_bytes(),
                file,
            ));
            if !calls.is_empty() {
                attach_synthesized_calls_to_decls(&mut idx, calls);
            }
        }
        let parsed_call_arguments = parsed
            .as_ref()
            .map(|(_, tree)| perl_call_arguments_by_span(tree, source.as_bytes(), file))
            .unwrap_or_default();
        for decl in &mut idx.defs {
            if let Some(heredoc_sources) = heredoc_sources.as_ref() {
                normalize_perl_heredoc_assignments(&mut decl.flow_events, heredoc_sources);
            }
            if let Some(readline_sources) = readline_sources.as_ref() {
                normalize_perl_readline_assignments(&mut decl.flow_events, readline_sources);
            }
            normalize_perl_package_call_kinds(&mut decl.flow_events);
            apply_perl_call_arguments(&mut decl.flow_events, &parsed_call_arguments);
            if let Some((_, tree)) = parsed.as_ref() {
                expand_perl_anonymous_hash_field_assigns(&mut decl.flow_events, tree, source.as_bytes());
            }
            normalize_perl_simple_scalar_renames(&mut decl.flow_events, &assignment_syntax.scalar_renames);
            normalize_perl_list_result_targets(&mut decl.flow_events, &assignment_syntax.ordered_bindings);
            augment_perl_collection_flow_events(&mut decl.flow_events, &assignment_syntax.collection_sources);
            inject_perl_coderef_aliases(&mut decl.flow_events, &assignment_syntax.coderef_aliases);
            if let Some((_, tree)) = parsed.as_ref() {
                normalize_perl_eval_exception_flow_events(
                    &mut decl.flow_events,
                    tree,
                    source.as_bytes(),
                    &assignment_syntax.dollar_at_assignments,
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
        let Some(lookup) = perl_finite_hash_selection(value, src) else {
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
    if node.kind() != "binary_expression" {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    if operator != Some("//") {
        return None;
    }
    (left.kind() == "hash_element_expression" && perl_static_string(right, src).is_some()).then_some(left)
}

/// Return the single runtime value represented by a callback block.
///
/// Comments are extras in the Perl grammar and therefore do not appear in
/// `named_children`. Requiring exactly one parsed statement/expression keeps
/// this proof closed over callbacks that append another value or mutate state.
fn perl_single_callback_value(mut node: Node<'_>) -> Option<Node<'_>> {
    while matches!(
        node.kind(),
        "block" | "expression_statement" | "parenthesized_expression"
    ) {
        let mut cursor = node.walk();
        let mut children = node.named_children(&mut cursor);
        let value = children.next()?;
        if children.next().is_some() {
            return None;
        }
        node = value;
    }
    Some(node)
}

/// Prove that the complete Perl expression can only return values selected
/// from one finite literal hash.
///
/// `map` changes the list's values, so its callback must be exactly the hash
/// selection (optionally with a literal `//` fallback). Perl aliases `$_`
/// inside `grep`, so only its language-native, non-mutating `defined`
/// predicate may preserve a proven finite input. The operator identity is read
/// from Tree-sitter's anonymous keyword token; no library API or security name
/// is interpreted here.
fn perl_finite_hash_selection<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    if let Some(lookup) = perl_finite_hash_lookup(node, src) {
        return Some(lookup);
    }
    if node.kind() != "map_grep_expression" {
        return None;
    }
    let operator = node.child(0)?.kind();
    let callback = node.child_by_field_name("callback")?;
    let list = node.child_by_field_name("list")?;
    match operator {
        "map" => perl_finite_hash_lookup(perl_single_callback_value(callback)?, src),
        "grep" => {
            let predicate = perl_single_callback_value(callback)?;
            let builtin = predicate.child(0).filter(|child| !child.is_named())?;
            (predicate.kind() == "func1op_call_expression"
                && builtin.kind() == "defined"
                && predicate.named_child_count() == 0)
                .then(|| perl_finite_hash_selection(list, src))
                .flatten()
        }
        _ => None,
    }
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

        let aggregate = perl_anonymous_hash_aggregate_for_event(&events[index], tree, src);
        let Some(aggregate) = aggregate else {
            index += 1;
            continue;
        };
        events.insert(index + 1, aggregate);
        index += 2;
    }
}

fn perl_anonymous_hash_aggregate_for_event(event: &FlowEvent, tree: &Tree, src: &[u8]) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, target, .. } = event else {
        return None;
    };
    let target = target.trim();
    if target.is_empty() || target.contains(['.', '{', '[']) {
        return None;
    }
    let Some(assignment) = node_at_span(tree.root_node(), *span, &["assignment_expression"]) else {
        return None;
    };
    let rhs = assignment
        .child_by_field_name("right")
        .filter(tree_sitter::Node::is_named)
        .or_else(|| {
            let mut cursor = assignment.walk();
            assignment.named_children(&mut cursor).last()
        });
    let Some(rhs) = rhs.filter(|rhs| rhs.kind() == "anonymous_hash_expression") else {
        return None;
    };

    let mut aggregate_fields = Vec::new();
    for (key, value) in perl_anonymous_hash_fields(rhs, src) {
        if key.is_empty() || !key.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
            continue;
        }
        let sources = perl_value_variable_names(value, src);
        aggregate_fields.push(ExpressionField {
            name: key,
            value_span: Some(span_of(span.file, &value)),
            value: ExpressionFlow::from_source_names(sources),
        });
    }
    (!aggregate_fields.is_empty()).then(|| FlowEvent::AggregateAssign {
        span: *span,
        target: target.to_string(),
        type_name: None,
        value_flow: ExpressionFlow {
            aggregate_fields,
            ..ExpressionFlow::default()
        },
    })
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
    collection_sources: &HashMap<Span, Vec<String>>,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_names,
                ..
            } => {
                if target.trim().starts_with(['@', '%']) {
                    if let Some(sources) = collection_sources.get(span) {
                        for source in sources {
                            push_unique_string(source_names, source.clone());
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_perl_collection_flow_events(then_events, collection_sources);
                augment_perl_collection_flow_events(else_events, collection_sources);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_perl_collection_flow_events(body, collection_sources);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_perl_collection_flow_events(body, collection_sources);
                augment_perl_collection_flow_events(catch_events, collection_sources);
                augment_perl_collection_flow_events(finally_events, collection_sources);
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
    coderef_aliases: &HashMap<Span, (String, String)>,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_perl_coderef_aliases(then_events, coderef_aliases);
                inject_perl_coderef_aliases(else_events, coderef_aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_perl_coderef_aliases(body, coderef_aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_perl_coderef_aliases(body, coderef_aliases);
                inject_perl_coderef_aliases(catch_events, coderef_aliases);
                inject_perl_coderef_aliases(finally_events, coderef_aliases);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let alias = perl_coderef_alias_assignment(&event, coderef_aliases);
        rewritten.push(event);
        if let Some(alias) = alias {
            rewritten.push(alias);
        }
    }
    *events = rewritten;
}

fn perl_coderef_alias_assignment(
    event: &FlowEvent,
    coderef_aliases: &HashMap<Span, (String, String)>,
) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, .. } = event else {
        return None;
    };
    let (target, source_name) = coderef_aliases.get(span)?.clone();
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

/// Lower Perl's exception idiom `eval { die ... }; if ($@) { ... }`
/// into a structural Try/Throw region. Tree-sitter-perl exposes the
/// eval block's body as ordinary calls and the `$@` handler as an
/// unrelated branch, so downstream taint cannot otherwise connect the
/// thrown value to the handler binding.
fn normalize_perl_eval_exception_flow_events(
    events: &mut Vec<FlowEvent>,
    tree: &Tree,
    src: &[u8],
    dollar_at_assignments: &HashSet<Span>,
) {
    let eval_blocks = perl_eval_block_ranges(tree);
    if eval_blocks.is_empty() {
        return;
    }
    let dollar_at_branches = perl_dollar_at_branch_ranges(tree, src);
    rewrite_perl_eval_exception_regions(events, dollar_at_assignments, &eval_blocks, &dollar_at_branches);
}

fn perl_dollar_at_branch_ranges(tree: &Tree, src: &[u8]) -> HashSet<(u64, u64)> {
    let mut ranges = HashSet::new();
    for branch in collect_kinds(tree, HANDLER.if_kinds) {
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        if perl_expression_places(condition, src).places.as_slice() == ["$@"] {
            ranges.insert((branch.start_byte() as u64, branch.end_byte() as u64));
        }
    }
    ranges
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
    dollar_at_assignments: &HashSet<Span>,
    eval_blocks: &[PerlEvalBlockRange],
    dollar_at_branches: &HashSet<(u64, u64)>,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_perl_eval_exception_regions(
                    then_events,
                    dollar_at_assignments,
                    eval_blocks,
                    dollar_at_branches,
                );
                rewrite_perl_eval_exception_regions(
                    else_events,
                    dollar_at_assignments,
                    eval_blocks,
                    dollar_at_branches,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_perl_eval_exception_regions(
                    body,
                    dollar_at_assignments,
                    eval_blocks,
                    dollar_at_branches,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_perl_eval_exception_regions(
                    body,
                    dollar_at_assignments,
                    eval_blocks,
                    dollar_at_branches,
                );
                rewrite_perl_eval_exception_regions(
                    catch_events,
                    dollar_at_assignments,
                    eval_blocks,
                    dollar_at_branches,
                );
                rewrite_perl_eval_exception_regions(
                    finally_events,
                    dollar_at_assignments,
                    eval_blocks,
                    dollar_at_branches,
                );
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
            then_events,
            ..
        } = &events[body_end]
        else {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        };
        if !dollar_at_branches.contains(&(branch_span.start, branch_span.end)) {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        }

        let mut body = events[idx..body_end].to_vec();
        body = lower_perl_die_calls_to_throws(body);
        let (catch_param, catch_events) = perl_dollar_at_catch_events(then_events, dollar_at_assignments);
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
    None
}

fn perl_dollar_at_catch_events(
    events: &[FlowEvent],
    dollar_at_assignments: &HashSet<Span>,
) -> (Option<String>, Vec<FlowEvent>) {
    let mut aliases = Vec::new();
    for event in events {
        if let FlowEvent::Assign { span, target, .. } = event {
            if dollar_at_assignments.contains(span) {
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
                    if dollar_at_assignments.contains(span)
            )
        })
        .cloned()
        .collect();
    (catch_param, catch_events)
}

/// Rewrite exact Perl scalar/array/hash renames (`my $y = $x`) from
/// generic compound-token assignments into `source_name` assignments.
/// This keeps true compound/deref RHSs (`$obj->{k}`, `$x . $y`,
/// function calls) on the broader `source_names` path while making the
/// simple rename case exact.
fn normalize_perl_simple_scalar_renames(events: &mut [FlowEvent], scalar_renames: &HashMap<Span, String>) {
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
                if let Some(rhs) = scalar_renames.get(span) {
                    *source_name = Some(rhs.clone());
                    source_names.clear();
                    *value_kind = None;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_simple_scalar_renames(then_events, scalar_renames);
                normalize_perl_simple_scalar_renames(else_events, scalar_renames);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_simple_scalar_renames(body, scalar_renames);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_simple_scalar_renames(body, scalar_renames);
                normalize_perl_simple_scalar_renames(catch_events, scalar_renames);
                normalize_perl_simple_scalar_renames(finally_events, scalar_renames);
            }
            _ => {}
        }
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
    let target = args.first()?.place.as_deref()?.trim();
    // First arg must be the target array — sanity gate.
    if !target.starts_with('@') {
        return None;
    }
    let mut source_names = Vec::new();
    for arg in args.iter().skip(1) {
        if let Some(place) = arg.place.as_deref() {
            push_perl_place_aliases(&mut source_names, place);
        }
        for source in &arg.source_names {
            push_perl_place_aliases(&mut source_names, source);
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

/// Append `value` to `out` only if it's non-empty and not already
/// present. Linear-scan dedup is fine here because the call sites
/// produce O(few) names per event.
fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
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
    implicit_arg_bindings: &HashMap<Span, Vec<String>>,
) -> Option<Vec<String>> {
    let mut rewritten = Vec::with_capacity(events.len());
    let mut inferred_params = None;
    let mut event_idx = 0;
    while event_idx < events.len() {
        let Some((span, vars)) = perl_list_binding_at(&events[event_idx], implicit_arg_bindings) else {
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
    implicit_arg_bindings: &HashMap<Span, Vec<String>>,
) -> Option<(bonsai_common::Span, Vec<String>)> {
    let FlowEvent::Assign { span, .. } = event else {
        return None;
    };
    implicit_arg_bindings
        .get(span)
        .filter(|vars| !vars.is_empty())
        .cloned()
        .map(|vars| (*span, vars))
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
    ordered_bindings: &HashMap<Span, Vec<String>>,
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
                let Some(bindings) = ordered_bindings.get(span) else {
                    continue;
                };
                if let Some(binding) = bindings.get(tuple_index) {
                    target.clone_from(binding);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_list_result_targets(then_events, ordered_bindings);
                normalize_perl_list_result_targets(else_events, ordered_bindings);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_list_result_targets(body, ordered_bindings);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_list_result_targets(body, ordered_bindings);
                normalize_perl_list_result_targets(catch_events, ordered_bindings);
                normalize_perl_list_result_targets(finally_events, ordered_bindings);
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
/// Both spellings are forms of Perl's `qx` language operator, so the canonical
/// compiler identity is `qx`; downstream consumers decide what it means.
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
    if node.kind() == "hash_element_expression" {
        argument.place = perl_expression_places(node, src).places.into_iter().next();
    }
    if node.kind() == "refgen_expression" {
        if let Some(function) = first_named_child_of_kind(&node, "function") {
            let name = first_named_child_of_kind(&function, "varname").unwrap_or(function);
            let source = perl_reference_name(name, src)?;
            argument.value_text.clone_from(&source);
            argument.place = Some(source.clone());
            argument.source_names = vec![source];
        } else if let Some(referent) = node.named_child(0) {
            // Data-reference construction (`\@items`, `\%table`, `\$value`)
            // carries the referent's value into the reference.  This is a
            // grammar fact, not a Perl API special case.  Keep the reference
            // argument value-shaped while exposing the exact referent place
            // and all nested dereference operands to the language-neutral
            // IDG call-argument stitcher.
            argument.place = perl_expression_places(referent, src).places.into_iter().next();
            argument.source_names = perl_node_value_sources(referent, file, src);
        }
    }
    if matches!(node.kind(), "scalar" | "array" | "hash") {
        if argument.place.is_none() {
            argument.place = perl_expression_places(node, src).places.into_iter().next();
        }
        argument.source_names = perl_node_value_sources(node, file, src);
    }
    Some(argument)
}

fn perl_call_arguments_by_span(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> std::collections::HashMap<Span, Vec<CallArg>> {
    let mut arguments = std::collections::HashMap::new();
    for call in collect_kinds(
        tree,
        &[
            "function_call_expression",
            "method_call_expression",
            "ambiguous_function_call_expression",
            "coderef_call_expression",
        ],
    ) {
        let Some(target) = perl_call_target(call, src) else {
            continue;
        };
        let args = call
            .child_by_field_name("arguments")
            .map(|container| perl_list_args(&container, src, file))
            .unwrap_or_default();
        arguments.insert(span_of(file, &target.node), args);
    }
    arguments
}

fn apply_perl_call_arguments(
    events: &mut [FlowEvent],
    parsed: &std::collections::HashMap<Span, Vec<CallArg>>,
) {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if let Some(exact) = parsed.get(span) {
                    args.clone_from(exact);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_perl_call_arguments(then_events, parsed);
                apply_perl_call_arguments(else_events, parsed);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_perl_call_arguments(body, parsed)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_perl_call_arguments(body, parsed);
                apply_perl_call_arguments(catch_events, parsed);
                apply_perl_call_arguments(finally_events, parsed);
            }
            _ => {}
        }
    }
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
            | "hash_element_expression"
            | "refgen_expression"
            | "number"
            | "interpolated_string_literal"
            | "string_literal"
            | "command_string"
            | "bareword"
            | "autoquoted_bareword"
    )
}

/// Lower every Perl `func1op_call_expression` as the call-like language
/// construct represented by that CST node. Tree-sitter omits a named callee
/// child for this production, so the exact leading source slice before the
/// first parsed operand is its compiler identity. No builtin inventory is
/// maintained here.
fn synthesize_func1op_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["func1op_call_expression"]) {
        let Some(function) = call_node.child(0).filter(|child| !child.is_named()) else {
            continue;
        };
        let name = node_text(&function, src).trim().to_string();
        if !perl_call_identity_is_exact(&name) {
            continue;
        }
        let mut args = Vec::new();
        let mut cursor = call_node.walk();
        for operand in call_node.named_children(&mut cursor) {
            if let Some(argument) = perl_call_arg_from_node(operand, file, src, None) {
                args.push(argument);
            }
        }
        events.push((
            span_of(file, &call_node),
            FlowEvent::Call {
                span: span_of(file, &call_node),
                name,
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            },
        ));
    }
    events
}

fn perl_call_identity_is_exact(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// Repair every ordinary Perl call whose exact argument is a binary
/// expression. The grammar places that expression directly in the
/// `arguments` field and the generic wrapper extractor cannot see through
/// it; the operation name is still the parsed `function` field.
fn synthesize_expression_arg_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["function_call_expression"]) {
        let Some(function_node) = call_node.child_by_field_name("function") else {
            continue;
        };
        let name = node_text(&function_node, src).trim();
        if !perl_call_identity_is_exact(name) {
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
        let source_names = perl_node_value_sources(list, file, src);
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
                if perl_arg_uses_topic_var(arg) {
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

fn perl_arg_uses_topic_var(arg: &CallArg) -> bool {
    arg.place
        .as_deref()
        .is_some_and(|place| matches!(place, "$_" | "_"))
        || arg
            .source_names
            .iter()
            .any(|source| matches!(source.as_str(), "$_" | "_"))
}

/// Attach each synthesized (span, event) pair to the decl whose
/// body contains it. Pick the SMALLEST containing decl — Perl
/// supports nested `sub { ... }` blocks inside an outer sub, so
/// picking the first match would silently route synthetic events
/// (including quote-like language operators) to the outer sub. If no
/// enclosing declaration exists, the event cannot be attributed and is
/// dropped. Linear walk over declarations is bounded by one file.
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
