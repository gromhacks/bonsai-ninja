//! Kotlin language adapter.
mod parse_recovery;

use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    collect_modifier_visibility, decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        collect_kinds, collect_receiver_field_writes, first_named_child_of_kind, language_from_pack,
        named_child_call_args_with_handler, node_text, package_module_segments_with_workspace_prefix,
        parse_with, span_of, walk_flow_events,
    },
    AdapterContext, AdapterError, AssignmentNodeSemantics, BranchConditionFact, BranchConditionPolarity,
    CallKind, CallTargetExtraction, ConditionEquality, ConditionExpressionFact, ConditionOperandFact, Decl,
    DeclIndex, DeclKind, ExpressionPlaceExtraction, FieldWrite, FileSnapshot, FlowEvent, GrammarHandler,
    ImplicitMemberReadCall, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities,
    LanguageId, ModifierVocabulary, ParseRecoveryEdit, PatternBindingSite, ReceiverFieldInitializer,
    StaticScalarValue, StringCompositionFact, StringCompositionPart, SyntaxTree, TypeAliasBinding, Vfs,
    Visibility, EMPTY_HANDLER,
};
use parse_recovery::kotlin_parse_recovery_edits;
use tree_sitter::{Language, Node, Tree};

fn kotlin_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for_statement" {
        return None;
    }
    let binding = node
        .child_by_field_name("variable")
        .or_else(|| node.child_by_field_name("left"))
        .or_else(|| node.named_child(0))?;
    let iterable = node
        .child_by_field_name("range")
        .or_else(|| node.child_by_field_name("right"))
        .or_else(|| node.named_child(1))?;
    Some((binding, iterable))
}

/// Extract Kotlin's callee expression from its grammar-owned call shape.
///
/// `call_expression` does not expose a named `function` field. Its first
/// named child is instead either a `simple_identifier` or a complete
/// `navigation_expression` such as `stream.close`; the following
/// `call_suffix` owns the arguments. Keeping that distinction here prevents
/// shared lowering from learning Kotlin CST node names or guessing callees
/// from source tokens.
fn kotlin_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = if node.kind() == "constructor_invocation" {
        node.child_by_field_name("type").or_else(|| node.named_child(0))?
    } else if node.kind() == "call_expression" {
        node.named_child(0)?
    } else {
        return None;
    };
    if !matches!(
        target.kind(),
        "simple_identifier" | "navigation_expression" | "constructor_invocation" | "user_type"
    ) {
        return None;
    }
    let full_text = node_text(&target, src).trim();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text: full_text.to_string(),
    })
}

/// Kotlin call receivers are positional inside the call target's
/// `navigation_expression`. The first named child is the exact receiver
/// expression and may itself be a call in a method chain.
fn kotlin_call_receiver<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    let target = kotlin_call_target(node, src)?.node;
    (target.kind() == "navigation_expression")
        .then(|| target.named_child(0))
        .flatten()
}

/// Lower Kotlin's sibling-based navigation CST into one canonical place.
/// Each `navigation_suffix` contributes exactly one parsed identifier; calls
/// are handled separately by `kotlin_call_target` and never acquire library
/// or security meaning here.
fn kotlin_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    fn collect(node: Node<'_>, src: &[u8], parts: &mut Vec<String>) -> bool {
        if matches!(
            node.kind(),
            "simple_identifier" | "this_expression" | "super_expression"
        ) {
            let name = node_text(&node, src).trim();
            if name.is_empty() {
                return false;
            }
            parts.push(name.to_string());
            return true;
        }
        if !matches!(
            node.kind(),
            "navigation_expression" | "directly_assignable_expression"
        ) {
            return false;
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        let Some(base) = children.first().copied() else {
            return false;
        };
        if !collect(base, src, parts) {
            return false;
        }
        for suffix in children.iter().copied().skip(1) {
            if suffix.kind() != "navigation_suffix" {
                return false;
            }
            let Some(identifier) = first_named_child_of_kind(&suffix, "simple_identifier") else {
                return false;
            };
            if !collect(identifier, src, parts) {
                return false;
            }
        }
        true
    }

    if !matches!(
        node.kind(),
        "navigation_expression" | "directly_assignable_expression"
    ) {
        return ExpressionPlaceExtraction::default();
    }
    let mut parts = Vec::new();
    if !collect(node, src, &mut parts) || parts.len() < 2 {
        return ExpressionPlaceExtraction::default();
    }
    ExpressionPlaceExtraction {
        places: vec![parts.join(".")],
        consumed_node_ids: vec![node.id()],
    }
}

/// Recover the complete addressable place from Kotlin's assignment-only
/// `directly_assignable_expression` wrapper. The ordinary expression decoder
/// already understands the wrapper's exact navigation children; exposing the
/// same fact through the assignment-scoped capability prevents a write such
/// as `this.cmd = token` from collapsing to the terminal `cmd` binding.
fn kotlin_assignment_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    (node.kind() == "directly_assignable_expression")
        .then(|| kotlin_expression_places(node, src).places.into_iter().next())
        .flatten()
}

/// Kotlin member selection is a property read when it is evaluated as a
/// value, even though the source language omits call punctuation for the
/// accessor. Preserve that dual identity in typed IR: the exact storage
/// projection remains available, and a locally resolved custom getter may
/// independently contribute its return value.
fn kotlin_expression_value_kind(node: Node<'_>, src: &[u8]) -> Option<bonsai_lang_api::AssignValueKind> {
    kotlin_terminal_property_accessor(node, FileId::INVALID, src)
        .map(|_| bonsai_lang_api::AssignValueKind::PropertyRead)
}

/// Kotlin uses `property_declaration` and `variable_declaration` for both
/// initialized and type-only bindings. The grammar leaves the initializer
/// unfielded, so classify the declaration from its direct `=` terminal here
/// instead of making shared lowering infer Kotlin token semantics.
fn kotlin_assignment_semantics(node: Node<'_>, _src: &[u8]) -> AssignmentNodeSemantics {
    if !matches!(node.kind(), "property_declaration" | "variable_declaration") {
        return AssignmentNodeSemantics::Assignment;
    }
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return AssignmentNodeSemantics::Other;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && child.kind() == "=" {
            return AssignmentNodeSemantics::Assignment;
        }
        if !cursor.goto_next_sibling() {
            return AssignmentNodeSemantics::Other;
        }
    }
}

fn kotlin_parameter_annotation_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "annotation" {
        return None;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "type_identifier" {
            let name = node_text(&current, src).trim();
            return (!name.is_empty()).then(|| name.to_string());
        }
        let mut cursor = current.walk();
        let children: Vec<_> = current.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn kotlin_pattern_bindings(node: Node<'_>) -> Vec<PatternBindingSite<'_>> {
    if node.kind() != "when_expression" {
        return Vec::new();
    }
    let mut cursor = node.walk();
    let Some(subject) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "when_subject")
    else {
        return Vec::new();
    };
    let mut cursor = subject.walk();
    let Some(declaration) = subject
        .named_children(&mut cursor)
        .find(|child| child.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let mut cursor = declaration.walk();
    let Some(pattern) = declaration
        .named_children(&mut cursor)
        .find(|child| child.kind() == "simple_identifier")
    else {
        return Vec::new();
    };
    let mut cursor = subject.walk();
    let source = subject
        .named_children(&mut cursor)
        .find(|child| child.id() != declaration.id() && !matches!(child.kind(), "annotation" | "type"));
    source
        .map(|source| {
            vec![PatternBindingSite {
                span_node: subject,
                pattern,
                source,
            }]
        })
        .unwrap_or_default()
}

pub const LANG_ID: LanguageId = LanguageId::new("kotlin");
const PACK_NAME: &str = "kotlin";

// Kotlin-only CST spellings inspected outside the shared `GrammarHandler`.
// Conformance validates this inventory against the loaded grammar so custom
// compiler facts cannot rot invisibly when Tree-sitter changes a node name.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("adapter_postprocessor", "="),
    ("adapter_postprocessor", "annotation"),
    ("adapter_postprocessor", "anonymous_initializer"),
    ("adapter_postprocessor", "as_expression"),
    ("adapter_postprocessor", "call_expression"),
    ("adapter_postprocessor", "catch_block"),
    ("adapter_postprocessor", "boolean_literal"),
    ("adapter_postprocessor", "character_literal"),
    ("adapter_postprocessor", "class_body"),
    ("adapter_postprocessor", "class_declaration"),
    ("adapter_postprocessor", "class_modifier"),
    ("adapter_postprocessor", "control_structure_body"),
    ("adapter_postprocessor", "class_parameter"),
    ("adapter_postprocessor", "constructor_delegation_call"),
    ("adapter_postprocessor", "constructor_invocation"),
    ("adapter_postprocessor", "delegation_specifier"),
    ("adapter_postprocessor", "directly_assignable_expression"),
    ("adapter_postprocessor", "enum"),
    ("adapter_postprocessor", "for_statement"),
    ("adapter_postprocessor", "function_body"),
    ("adapter_postprocessor", "function_declaration"),
    ("adapter_postprocessor", "getter"),
    ("adapter_postprocessor", "identifier"),
    ("adapter_postprocessor", "import_header"),
    ("adapter_postprocessor", "infix_expression"),
    ("adapter_postprocessor", "integer_literal"),
    ("adapter_postprocessor", "interface"),
    ("adapter_postprocessor", "jump_expression"),
    ("adapter_postprocessor", "lambda_literal"),
    ("adapter_postprocessor", "modifiers"),
    ("adapter_postprocessor", "navigation_expression"),
    ("adapter_postprocessor", "navigation_suffix"),
    ("adapter_postprocessor", "nullable_type"),
    ("adapter_postprocessor", "null_literal"),
    ("adapter_postprocessor", "object_declaration"),
    ("adapter_postprocessor", "object_literal"),
    ("adapter_postprocessor", "package_header"),
    ("adapter_postprocessor", "parameter"),
    ("adapter_postprocessor", "primary_constructor"),
    ("adapter_postprocessor", "property_declaration"),
    ("adapter_postprocessor", "property_delegate"),
    ("adapter_postprocessor", "real_literal"),
    ("adapter_postprocessor", "secondary_constructor"),
    ("adapter_postprocessor", "setter"),
    ("adapter_postprocessor", "simple_identifier"),
    ("adapter_postprocessor", "statements"),
    ("adapter_postprocessor", "string_literal"),
    ("adapter_postprocessor", "type_identifier"),
    ("adapter_postprocessor", "user_type"),
    ("adapter_postprocessor", "value_argument"),
    ("adapter_postprocessor", "value_arguments"),
    ("adapter_postprocessor", "variable_declaration"),
    ("adapter_postprocessor", "visibility_modifier"),
    ("adapter_postprocessor", "when_expression"),
    ("adapter_postprocessor", "when_entry"),
    ("adapter_postprocessor", "when_subject"),
];
const MODULE_SOURCE_ROOTS: &[&[&str]] = &[
    &["src", "main", "kotlin"],
    &["src", "test", "kotlin"],
    &["src", "kotlin"],
];

fn extract_kotlin_syntax_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "jump_expression" {
        return None;
    }
    let keyword = node.child(0)?.kind();
    let value = node.named_child(0);
    match keyword {
        "throw" => {
            let value_name = value.and_then(|value| {
                let flow =
                    bonsai_lang_api::kit::expression_flow_from_node_with_handler(value, file, src, handler);
                let operands =
                    bonsai_lang_api::kit::expression_operand_names_with_handler(&value, src, handler);
                single_kotlin_value_source(&flow, operands)
            });
            Some(FlowEvent::Throw {
                span: span_of(file, &node),
                value_name,
                thrown_type: None,
            })
        }
        "return" => {
            let value_flow = value.map_or_else(bonsai_lang_api::ExpressionFlow::default, |value| {
                bonsai_lang_api::kit::expression_flow_from_node_with_handler(value, file, src, handler)
            });
            Some(FlowEvent::Return {
                span: span_of(file, &node),
                value_kind: value.and_then(|value| handler.expression_value_kind(value, src)),
                value_text: value.map(|value| node_text(&value, src).trim().to_string()),
                value_name: single_kotlin_value_source(&value_flow, Vec::new()),
                value_flow,
            })
        }
        "break" => Some(FlowEvent::Break {
            span: span_of(file, &node),
            label: value.map(|value| node_text(&value, src).trim().to_string()),
        }),
        "continue" => Some(FlowEvent::Continue {
            span: span_of(file, &node),
            label: value.map(|value| node_text(&value, src).trim().to_string()),
        }),
        _ => None,
    }
}

fn single_kotlin_value_source(
    flow: &bonsai_lang_api::ExpressionFlow,
    mut sources: Vec<String>,
) -> Option<String> {
    sources.extend(flow.source_names.iter().cloned());
    sources.sort();
    sources.dedup();
    if sources.len() == 1 {
        return Some(sources.remove(0));
    }
    (sources.is_empty())
        .then(|| {
            flow.place
                .as_ref()
                .filter(|place| !place.trim().is_empty())
                .cloned()
        })
        .flatten()
}

fn kotlin_named_argument<'tree>(node: Node<'tree>, src: &[u8]) -> Option<(String, Node<'tree>)> {
    if node.kind() != "value_argument" {
        return None;
    }
    let mut cursor = node.walk();
    if !node
        .children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == "=")
    {
        return None;
    }
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    let [name, value] = children.as_slice() else {
        return None;
    };
    if name.kind() != "simple_identifier" {
        return None;
    }
    let name = node_text(name, src).trim();
    (!name.is_empty()).then(|| (name.to_string(), *value))
}
// `getter` and `setter` are property accessor bodies in
// tree-sitter-kotlin. Treating them as function-declaration kinds
// gives each accessor its own Decl with its own flow_events, so
// taint that flows through `var x: String get() = … set(v) { … }`
// is observed end-to-end. Without this, the whole property collapses
// into a single Field decl and accessor body events disappear
// (audit task #131).
const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: Some(kotlin_expression_value_kind),
    // Names are owned by the bundled Tree-sitter Kotlin grammar.  Keeping
    // this inventory adapter-local lets shared lowering classify values
    // without knowing Kotlin token kinds.
    literal_value_kinds: &["integer_literal", "real_literal", "null_literal"],
    literal_value_spellings: &["null", "true", "false"],
    // The current grammar represents both ordinary and triple-quoted strings
    // as `string_literal`; there is no separate multiline node kind.
    string_literal_kinds: &["string_literal", "character_literal"],
    comment_kinds: &["line_comment", "multiline_comment"],
    doc_comment_prefixes: &["/**"],
    decorator_kinds: &["annotation"],
    parameter_container_kinds: &["function_value_parameters", "lambda_parameters"],
    // Named lambda bindings are `variable_declaration` children of
    // `lambda_parameters` in the bundled grammar.
    parameter_kinds: &["parameter", "variable_declaration"],
    // A destructured lambda parameter is one parsed
    // `multi_variable_declaration`; every nested variable declaration is a
    // binding, while the wrapper itself is not a parameter identity.
    destructured_parameter_kinds: &["multi_variable_declaration"],
    parameter_modifier_kinds: &["modifiers", "parameter_modifiers"],
    parameter_annotation_kinds: &["annotation"],
    parameter_annotation_name_extractor: Some(kotlin_parameter_annotation_name),
    binding_identifier_kinds: &["simple_identifier"],
    pattern_binding_extractor: Some(kotlin_pattern_bindings),
    // Tree-sitter Kotlin gives the `$name` form in a string template its own
    // named node. It is an expression read (never a binding), so keep it in
    // the value-carrier inventory without admitting it as a declaration name.
    identifier_kinds: &["simple_identifier", "interpolated_identifier"],
    expression_place_extractor: Some(kotlin_expression_places),
    aggregate_pattern_kinds: &["destructuring_declaration", "multi_variable_declaration"],
    positional_aggregate_kinds: &["collection_literal"],
    spread_kinds: &["spread_expression"],
    spread_value_field_names: &[],
    transparent_call_wrapper_kinds: &["navigation_expression", "parenthesized_expression"],
    assignment_target_wrapper_kinds: &[
        "variable_declaration",
        "multi_variable_declaration",
        // The current grammar wraps the LHS of `x = value` and `x += value`
        // in this node.  It is an addressable target wrapper, not a value or
        // declaration of its own.
        "directly_assignable_expression",
    ],
    binding_declaration_keyword_spellings: &["val", "var"],
    fn_kinds: &["function_declaration", "getter", "setter"],
    // A primary-constructor delegation (`class Child(x) : Base(x)`) is a
    // real constructor call in Kotlin's grammar, represented by
    // `constructor_invocation` rather than `call_expression`. The synthetic
    // constructor pass walks only the direct delegation specifier, so adding
    // this node kind exposes the exact base call without pulling class-header
    // syntax into ordinary method bodies.
    call_kinds: &["call_expression", "constructor_invocation"],
    constructor_call_kinds: &["constructor_invocation"],
    constructor_type_field_names: &[],
    call_argument_container_kinds: &["value_arguments"],
    call_argument_wrapper_kinds: &["call_suffix"],
    call_callee_is_first_named_child: true,
    call_target_extractor: Some(kotlin_call_target),
    call_receiver_extractor: Some(kotlin_call_receiver),
    argument_wrapper_kinds: &["value_argument"],
    named_argument_extractor: Some(kotlin_named_argument),
    // `annotated_lambda` is the grammar wrapper around a trailing
    // `lambda_literal`; it does not introduce a second callable scope.
    // A trailing lambda without ordinary value arguments is wrapped in a
    // same-span `call_suffix`. The shared transparent-wrapper contract peels
    // it only when it has exactly one named child, so `f(x) { ... }` keeps
    // its argument container while `f { ... }` exposes the exact callback.
    transparent_expression_wrapper_kinds: &["parenthesized_expression", "annotated_lambda", "call_suffix"],
    // `annotated_lambda` is the call-argument wrapper; the nested
    // `lambda_literal` remains the sole callable declaration. Keeping these
    // roles separate lets call lowering retain the exact argument span
    // without manufacturing a second callable owner.
    inline_closure_kinds: &["annotated_lambda"],
    lambda_body_field_names: &[],
    // Kotlin trailing lambdas are exact direct chains:
    // `annotated_lambda -> lambda_literal -> statements`. Declaring both
    // wrapper and executable body lets shared extraction peel the wrapper
    // without treating lambda parameters as returned values.
    lambda_body_kinds: &["lambda_literal", "anonymous_function", "statements"],
    syntax_event_extractor: Some(extract_kotlin_syntax_event),
    argument_passing_mode_extractor: None,
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    runtime_type_guard_operators: &["is"],
    runtime_type_wrapper_kinds: &["parenthesized_expression"],
    call_ref_kinds: &["call_expression", "constructor_invocation", "callable_reference"],
    callable_reference_kinds: &["callable_reference"],
    member_expression_kinds: &["navigation_expression"],
    subscript_expression_kinds: &["indexing_expression", "indexing_suffix"],
    member_base_field_names: &["receiver"],
    member_name_field_names: &[],
    subscript_base_field_names: &["receiver"],
    subscript_index_field_names: &[],
    // Kotlin interfaces share `class_declaration` with classes. The adapter
    // refines their DeclKind from the exact `interface` grammar token below.
    class_kinds: &["class_declaration", "object_declaration"],
    class_decl_kinds: &[
        ("class_declaration", DeclKind::Class),
        ("object_declaration", DeclKind::Class),
    ],
    method_kinds: &["getter", "setter"],
    method_context_kinds: &["class_declaration", "object_declaration"],
    if_kinds: &["if_expression", "when_expression"],
    branch_then_field_names: &["consequence"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition"],
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    branch_condition_kinds: &["when_subject"],
    loop_body_field_names: &[],
    loop_body_kinds: &["control_structure_body", "statements"],
    branch_arm_kinds: &["control_structure_body", "statements", "when_entry"],
    exclusive_branch_arm_kinds: &["when_entry"],
    fallthrough_branch_arm_kinds: &[],
    for_kinds: &[],
    foreach_kinds: &["for_statement"],
    foreach_binding_extractor: Some(kotlin_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_while_statement"],
    assignment_kinds: &["assignment", "property_declaration", "variable_declaration"],
    assignment_semantics_extractor: Some(kotlin_assignment_semantics),
    assignment_place_extractor: Some(kotlin_assignment_place),
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%="],
    type_only_declaration_kinds: &[],
    // Return/throw/break/continue share `jump_expression` and are lowered by
    // `extract_kotlin_syntax_event`, which inspects the exact keyword token.
    return_kinds: &[],
    throw_kinds: &[],
    // `annotated_lambda` is a transparent grammar wrapper around the same
    // `lambda_literal`, not a second callable declaration.
    lambda_kinds: &["anonymous_function", "lambda_literal"],
    implicit_lambda_parameter_name: Some("it"),
    try_kinds: &["try_expression"],
    try_body_field_names: &[],
    catch_kinds: &["catch_block"],
    exclusive_catch_arm_kinds: &["catch_block"],
    finally_kinds: &["finally_block"],
    implicit_receiver_names: &["this", "super"],
    ..EMPTY_HANDLER
};

const KOTLIN_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "function_declaration",
        "class_declaration",
        "object_declaration",
        "property_declaration",
        "secondary_constructor",
    ],
    modifier_container_kinds: &["modifiers", "visibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("internal", Visibility::Crate),
        ("protected", Visibility::Protected),
        ("public", Visibility::Public),
    ],
    // Kotlin's default visibility is `public`.
    default_visibility: Visibility::Public,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct KotlinAdapter;

impl KotlinAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for KotlinAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Kotlin"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["kt", "kts"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &FileSnapshot,
        _vfs: &Vfs,
        tree: &SyntaxTree,
    ) -> Vec<ParseRecoveryEdit> {
        kotlin_parse_recovery_edits(snapshot, tree)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Exceptions: the adapter populates `Throw::thrown_type` from
        // `throw IOException(...)` and `Try::catch_types` from
        // `catch (e: IOException) { }`. Kotlin doesn't have multi-
        // catch syntax (uses `is` checks inside the body for that),
        // so each arm contributes one type.
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Any", "Object"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            exceptions: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            // Kotlin has no `new` keyword: `Widget(...)` is parsed with the
            // same call-expression shape as a top-level function call. The
            // workspace resolver must therefore use exact class/constructor
            // identity to distinguish the two forms.
            bare_call_constructor_syntax: true,
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &[],
                class_object_suffixes: &[".class"],
            },
            same_directory_unqualified_calls: true,
            callable_reference_syntax: bonsai_lang_api::CallableReferenceSyntax {
                prefixes: &["::"],
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
        ADDITIONAL_GRAMMAR_NODE_KINDS
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        // Parse once and thread the exact snapshot + tree through shared
        // declaration lowering and every Kotlin post-process pass.
        let parsed = parse_with(PACK_NAME, file, ctx);
        let mut idx = parsed.as_ref().map_or_else(
            || DeclIndex {
                file,
                ..Default::default()
            },
            |(snapshot, tree)| {
                decl_index_from_tree_with_handler(file, snapshot.text.as_bytes(), tree, &HANDLER)
            },
        );
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            populate_kotlin_condition_expressions(&mut idx.branch_conditions, tree, file, src);
            populate_kotlin_predicate_call_conditions(&mut idx.branch_conditions, tree, file, src);
            // `class` and `interface` intentionally share one named grammar
            // node. Refine the generic class declaration before constructor
            // synthesis so interfaces cannot acquire synthetic constructors.
            refine_kotlin_class_decl_kinds(&mut idx, file, tree);
            // Phase-6 return-type extraction: `fun f(): T {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, tree, src, &HANDLER);
            // Kotlin's `object Foo { fun bar() { ... } }` parses as
            // `infix_expression` (with `object` as the operator) in
            // tree-sitter-kotlin, so the kit's class-kind detection
            // doesn't see a class node. Synthesize a class decl for
            // each such pattern and re-parent the contained methods so
            // `Foo.bar(...)` dispatches correctly.
            synthesize_kotlin_object_decls(&mut idx, file, tree, src);
            synthesize_kotlin_constructor_decls(&mut idx, file, tree, src);
            synthesize_kotlin_property_getter_decls(&mut idx, file, tree, src);
            qualify_kotlin_receiver_field_getters(&mut idx);
            // Module path from `package com.foo.bar` declaration; falls
            // back to file-stem when absent.
            if let Some(segments) = extract_kotlin_package(tree.root_node(), src) {
                let segments =
                    package_module_segments_with_workspace_prefix(file, ctx, segments, MODULE_SOURCE_ROOTS);
                bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
            } else {
                bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
            }
            let vis_map = collect_modifier_visibility(tree.root_node(), file, src, &KOTLIN_VOCAB);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
            }
            // type_aliases for `[Type, method]` rule resolution.
            // Per-method walk for `name: Type` parameter shapes.
            let declared_type_names = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .flat_map(|decl| std::iter::once(decl.name.clone()).chain(decl.qualified_name.clone()))
                .map(|name| kotlin_call_tail(&name).to_string())
                .collect::<std::collections::HashSet<_>>();
            let aliases_by_span = collect_kotlin_type_aliases(tree, file, src, &declared_type_names);
            for decl in &mut idx.defs {
                if let Some(aliases) = aliases_by_span.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                classify_kotlin_constructor_calls(&mut decl.flow_events, &decl.type_aliases);
            }
            let class_aliases_by_span =
                collect_kotlin_class_type_aliases(tree, file, src, &declared_type_names);
            let class_spans_by_symbol: std::collections::HashMap<_, _> = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .map(|decl| (decl.symbol, decl.span))
                .collect();
            for decl in &mut idx.defs {
                let Some(parent) = decl.parent else { continue };
                let Some(parent_span) = class_spans_by_symbol.get(&parent) else {
                    continue;
                };
                let Some(class_aliases) = class_aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == *parent_span).then_some(aliases))
                else {
                    continue;
                };
                for alias in class_aliases {
                    if !decl.type_aliases.contains(alias) {
                        decl.type_aliases.push(alias.clone());
                    }
                }
            }
            // Per-class `bases`: `class Echo : WebSocketHandler(), Mixin {...}`
            // → ["WebSocketHandler", "Mixin"]. Kotlin lists every
            // parent (super-class call + interface types) as
            // `delegation_specifier` siblings of the class name.
            let bases_by_span = collect_kotlin_class_bases(tree, file, src);
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
            // Throw::thrown_type and Try::catch_types — done after
            // any flow_events mutation so this final enrichment is
            // the authoritative type fact.
            for decl in &mut idx.defs {
                populate_kotlin_exception_types(&mut decl.flow_events, tree, src);
            }
            let finite_selections = collect_kotlin_finite_literal_selections(&idx, tree, file);
            idx.finite_literal_selections.extend(finite_selections);
            bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut idx.finite_literal_selections);
            idx.character_constraints
                .extend(collect_kotlin_provider_bound_character_constraints(
                    &idx.defs, tree, file, src,
                ));
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                tree,
                file,
                src,
                &HANDLER,
                kotlin_static_scalar,
            );
            populate_kotlin_immutable_binding_owners(&mut idx, tree, file, src);
            bonsai_lang_api::kit::populate_assignment_inline_callback_static_returns(
                &mut idx,
                tree,
                src,
                &HANDLER,
                kotlin_static_scalar,
            );
            idx.string_compositions
                .extend(collect_kotlin_string_compositions(&idx, tree, file, src));
            idx.string_compositions
                .sort_by_key(|fact| (fact.container_span.start, fact.container_span.end));
            idx.string_compositions.dedup();
        } else {
            // Parse failed; still run the file-stem fallback so the
            // semantic-identity pass doesn't leave decls without
            // module paths.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        for decl in &mut idx.defs {
            synthesize_kotlin_data_copy_fields(
                &mut decl.flow_events,
                &decl.type_aliases,
                parsed
                    .as_ref()
                    .map(|(snapshot, tree)| (tree.as_ref(), file, snapshot.text.as_bytes())),
            );
        }
        qualify_kotlin_implicit_member_reads(&mut idx);
        bonsai_lang_api::kit::qualify_bare_hierarchy_member_calls(&mut idx);
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`val c = Foo()` →
        // `c: Foo`) requires an exactly declared type or a call already
        // classified as a constructor. Capitalization is not semantic proof.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Attach Kotlin's compiler-owned `val` immutability and lexical owner to the
/// corresponding assignment fact.
///
/// The shared assignment lowerer deliberately cannot interpret a language's
/// mutable-binding syntax.  Kotlin's `property_declaration` does, however,
/// distinguish `val` from `var` exactly.  Recording the containing class is
/// important for instance-initializer facts: the synthesized constructor spans
/// the class, so span containment alone would otherwise misclassify a class
/// field as constructor-local and hide it from sibling methods.
fn populate_kotlin_immutable_binding_owners(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let class_symbols = index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.symbol))
        .collect::<Vec<_>>();
    for declaration in collect_kinds(tree, &["property_declaration"]) {
        let is_immutable = declaration
            .named_children(&mut declaration.walk())
            .any(|child| child.kind() == "binding_pattern_kind" && node_text(&child, src).trim() == "val");
        if !is_immutable {
            continue;
        }
        let assignment_span = span_of(file, &declaration);
        let owner = kotlin_class_owner_of_property(declaration, file, &class_symbols);
        for fact in index
            .assignment_values
            .iter_mut()
            .filter(|fact| fact.assignment_span == assignment_span)
        {
            fact.target_is_immutable = true;
            fact.target_owner = owner;
        }
    }
}

fn kotlin_class_owner_of_property(
    declaration: Node<'_>,
    file: FileId,
    class_symbols: &[(Span, SymbolId)],
) -> Option<SymbolId> {
    let mut current = declaration.parent();
    while let Some(node) = current {
        match node.kind() {
            // A property declared inside executable syntax is local even when
            // that callable is nested in a class.
            "function_declaration" | "secondary_constructor" | "lambda_literal" => return None,
            "class_declaration" | "object_declaration" => {
                let span = span_of(file, &node);
                return class_symbols
                    .iter()
                    .find_map(|(candidate, symbol)| (*candidate == span).then_some(*symbol));
            }
            _ => current = node.parent(),
        }
    }
    None
}

/// Replace the shared boolean-shell facts with Kotlin's exact comparison
/// operands. The adapter owns the grammar/operator mapping; consumers receive
/// language-neutral equality and boolean structure without reparsing text.
fn populate_kotlin_condition_expressions(
    facts: &mut [bonsai_lang_api::BranchConditionFact],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    for branch in collect_kinds(tree, &["if_expression"]) {
        let branch_span = span_of(file, &branch);
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        let Some(fact) = facts.iter_mut().find(|fact| fact.branch_span == branch_span) else {
            continue;
        };
        fact.expression = Some(lower_kotlin_condition_expression(condition, file, src));
    }
}

/// Preserve boolean expressions passed to ordinary calls as compiler facts.
///
/// Kotlin uses library precondition calls as control boundaries. The adapter
/// does not assign continuation or security meaning to any callee: it merely
/// lowers each parsed argument predicate under the exact call-target span.
/// Rule semantics may later select a particular runtime contract.
fn populate_kotlin_predicate_call_conditions(
    facts: &mut Vec<BranchConditionFact>,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    let structured_condition_spans = facts.iter().map(|fact| fact.condition_span).collect::<Vec<_>>();
    for call in collect_kinds(tree, &["call_expression"]) {
        let call_span = span_of(file, &call);
        // Calls nested inside `if`/`when` conditions already belong to that
        // structured boolean expression. Publishing a second synthetic
        // precondition boundary for the inner call changes its control owner
        // and can double-count negation. Standalone call contracts such as
        // `require(predicate)` remain represented for rule-selected meaning.
        if structured_condition_spans.iter().any(|condition| {
            condition.file == call_span.file
                && call_span.start >= condition.start
                && call_span.end <= condition.end
        }) {
            continue;
        }
        let Some(target) = kotlin_call_target(call, src).map(|target| target.node) else {
            continue;
        };
        let Some(call_suffix) = first_named_child_of_kind(&call, "call_suffix") else {
            continue;
        };
        let Some(arguments) = first_named_child_of_kind(&call_suffix, "value_arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            let Some(value) = argument.named_child(0) else {
                continue;
            };
            let expression = lower_kotlin_condition_expression(value, file, src);
            let polarity = if matches!(expression, ConditionExpressionFact::Not { .. }) {
                BranchConditionPolarity::Negated
            } else {
                BranchConditionPolarity::Positive
            };
            facts.push(BranchConditionFact {
                branch_span: span_of(file, &target),
                condition_span: span_of(file, &value),
                polarity,
                membership: None,
                expression: Some(expression),
            });
        }
    }
    facts.sort_by_key(|fact| {
        (
            fact.branch_span.file.raw(),
            fact.branch_span.start,
            fact.branch_span.end,
            fact.condition_span.start,
            fact.condition_span.end,
        )
    });
    facts.dedup();
}

fn lower_kotlin_condition_expression(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return lower_kotlin_condition_expression(inner, file, src);
        }
    }

    let span = span_of(file, &node);
    if node.kind() == "prefix_expression" {
        if let Some(operand) = node.named_child(0) {
            let operator = src
                .get(node.start_byte()..operand.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if operator == Some("!") {
                return ConditionExpressionFact::Not {
                    span,
                    operand: Box::new(lower_kotlin_condition_expression(operand, file, src)),
                };
            }
        }
    }

    if let (Some(left), Some(right)) = (node.named_child(0), node.named_child(1)) {
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        match operator {
            Some("||") => {
                return merge_kotlin_condition_junction(
                    span,
                    lower_kotlin_condition_expression(left, file, src),
                    lower_kotlin_condition_expression(right, file, src),
                    false,
                );
            }
            Some("&&") => {
                return merge_kotlin_condition_junction(
                    span,
                    lower_kotlin_condition_expression(left, file, src),
                    lower_kotlin_condition_expression(right, file, src),
                    true,
                );
            }
            Some("==" | "!=") => {
                return ConditionExpressionFact::Equality {
                    span,
                    relation: if operator == Some("==") {
                        ConditionEquality::Equal
                    } else {
                        ConditionEquality::NotEqual
                    },
                    left: kotlin_condition_operand(left, file, src),
                    right: kotlin_condition_operand(right, file, src),
                };
            }
            _ => {}
        }
    }

    ConditionExpressionFact::Atom { span }
}

fn merge_kotlin_condition_junction(
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

fn kotlin_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    ConditionOperandFact {
        span: span_of(file, &node),
        direct_call_span: (node.kind() == "call_expression").then(|| span_of(file, &node)),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER),
        static_string: kotlin_static_string_literal(node, src),
        static_value: kotlin_static_scalar(node, src),
    }
}

fn kotlin_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "null_literal" => Some(StaticScalarValue::Null),
        "boolean_literal" => match node_text(&node, src).trim() {
            "true" => Some(StaticScalarValue::Boolean(true)),
            "false" => Some(StaticScalarValue::Boolean(false)),
            _ => None,
        },
        "string_literal" => kotlin_static_string_literal(node, src).map(StaticScalarValue::String),
        _ => None,
    }
}

fn collect_kotlin_string_compositions(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<StringCompositionFact> {
    let root = tree.root_node();
    index
        .assignment_values
        .iter()
        .filter_map(|assignment| {
            let value = kotlin_node_for_exact_span(root, assignment.value_span)?;
            if value.kind() != "string_literal" {
                return None;
            }
            let parts = lower_kotlin_string_template(value, file, src)?;
            (parts.len() > 1).then(|| StringCompositionFact {
                container_span: assignment.assignment_span,
                value_span: assignment.value_span,
                target: assignment.target.clone(),
                dynamic_anchor_span: None,
                parts,
            })
        })
        .collect()
}

fn lower_kotlin_string_template(
    literal: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<Vec<StringCompositionPart>> {
    let mut parts = Vec::new();
    let mut cursor = literal.walk();
    for child in literal.named_children(&mut cursor) {
        match child.kind() {
            "string_content" => {
                let value = node_text(&child, src);
                // Escape decoding is intentionally conservative: a frontend
                // fact is emitted only when the exact literal fragment needs
                // no source-level reinterpretation.
                if value.contains('\\') || value.contains('$') {
                    return None;
                }
                if !value.is_empty() {
                    parts.push(StringCompositionPart::Literal {
                        value: value.to_string(),
                    });
                }
            }
            "interpolated_identifier" => {
                let place = node_text(&child, src).trim().strip_prefix('$')?.trim();
                if place.is_empty() {
                    return None;
                }
                parts.push(StringCompositionPart::Place {
                    place: place.to_string(),
                });
            }
            "interpolated_expression" => {
                let expression = child.named_child(0)?;
                parts.push(lower_kotlin_interpolated_expression(expression, file, src)?);
            }
            "interpolation_expression_start" | "interpolation_expression_end" => {}
            _ => return None,
        }
    }
    Some(parts)
}

fn lower_kotlin_interpolated_expression(
    expression: Node<'_>,
    _file: FileId,
    src: &[u8],
) -> Option<StringCompositionPart> {
    if expression.kind() == "elvis_expression" {
        let place = kotlin_exact_place(expression.named_child(0)?, src)?;
        let fallback = kotlin_static_string_literal(expression.named_child(1)?, src)?;
        return Some(StringCompositionPart::PlaceOrLiteral { place, fallback });
    }
    kotlin_exact_place(expression, src).map(|place| StringCompositionPart::Place { place })
}

fn kotlin_exact_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "simple_identifier" {
        let value = node_text(&node, src).trim();
        return (!value.is_empty()).then(|| value.to_string());
    }
    kotlin_expression_places(node, src).places.into_iter().next()
}

fn kotlin_node_for_exact_span(root: Node<'_>, span: Span) -> Option<Node<'_>> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    let mut node = root.descendant_for_byte_range(start, end)?;
    loop {
        if node.start_byte() == start && node.end_byte() == end {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn kotlin_terminal_property_accessor(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<(String, Option<String>, Span)> {
    if node.kind() != "navigation_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    let suffixes = children.get(1..)?;
    if suffixes.is_empty() || suffixes.iter().any(|suffix| suffix.kind() != "navigation_suffix") {
        return None;
    }
    first_named_child_of_kind(suffixes.last()?, "simple_identifier")?;
    let accessor = node_text(&node, src).trim();
    if accessor.is_empty() {
        return None;
    }
    // The terminal suffix's receiver is the exact parsed prefix. With one
    // suffix this is the first child (and may itself be a constructor call);
    // with a longer navigation chain the range ends at the prior suffix.
    let first = *children.first()?;
    let receiver_end = if suffixes.len() == 1 {
        first.end_byte()
    } else {
        suffixes.get(suffixes.len().saturating_sub(2))?.end_byte()
    };
    let receiver_span = Span::new(
        file,
        u64::try_from(first.start_byte()).ok()?,
        u64::try_from(receiver_end).ok()?,
    );
    let receiver = std::str::from_utf8(src.get(first.start_byte()..receiver_end)?)
        .ok()?
        .trim();
    let receiver = (!receiver.is_empty()).then(|| receiver.to_string());
    Some((accessor.to_string(), receiver, receiver_span))
}

/// Lower Kotlin `when` expressions whose every branch produces a compiler
/// literal. The selected key can remain attacker-controlled, but it never
/// becomes part of the selected value. This is a generic value-shape fact;
/// security consumers decide whether a finite selection is relevant.
fn collect_kotlin_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
) -> Vec<bonsai_lang_api::FiniteLiteralSelectionFact> {
    let mut facts = Vec::new();
    for selection in collect_kinds(tree, &["when_expression"]) {
        if !kotlin_when_outputs_are_literals(selection) {
            continue;
        }
        let selection_span = span_of(file, &selection);
        if let Some(fact) = bonsai_lang_api::kit::finite_literal_selection_fact_for_span(
            index,
            tree,
            selection_span,
            |value| value.id() == selection.id(),
        ) {
            facts.push(fact);
            continue;
        }
        if kotlin_when_is_complete_expression_body(selection) {
            facts.push(bonsai_lang_api::FiniteLiteralSelectionFact {
                selection_span,
                assignment_span: None,
                target: None,
                call_span: None,
                argument_index: None,
            });
        }
    }
    facts
}

fn kotlin_when_outputs_are_literals(selection: Node<'_>) -> bool {
    let mut cursor = selection.walk();
    let entries = selection
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "when_entry")
        .collect::<Vec<_>>();
    !entries.is_empty()
        && entries.into_iter().all(|entry| {
            let mut entry_cursor = entry.walk();
            let bodies = entry
                .named_children(&mut entry_cursor)
                .filter(|child| child.kind() == "control_structure_body")
                .collect::<Vec<_>>();
            let [body] = bodies.as_slice() else {
                return false;
            };
            let mut body_cursor = body.walk();
            let values = body.named_children(&mut body_cursor).collect::<Vec<_>>();
            let [value] = values.as_slice() else {
                return false;
            };
            matches!(
                value.kind(),
                "string_literal"
                    | "integer_literal"
                    | "real_literal"
                    | "boolean_literal"
                    | "null_literal"
                    | "character_literal"
            )
        })
}

fn kotlin_when_is_complete_expression_body(selection: Node<'_>) -> bool {
    let Some(body) = selection
        .parent()
        .filter(|parent| parent.kind() == "function_body")
    else {
        return false;
    };
    let mut cursor = body.walk();
    let children = body.named_children(&mut cursor).collect::<Vec<_>>();
    children.len() == 1 && children[0].id() == selection.id()
}

/// Lower expression-bodied helpers whose return is a complete chain of one
/// parsed operation with exact one-character mapping arguments, rooted at one
/// input parameter. The operation identity is retained as provider-bound IR;
/// the adapter does not decide whether that operation performs replacement or
/// has any security meaning.
fn collect_kotlin_provider_bound_character_constraints(
    defs: &[Decl],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<bonsai_lang_api::CharacterConstraintFact> {
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_declaration"]) {
        let function_span = span_of(file, &function);
        let Some(decl) = defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        let Some(body) = first_named_child_of_kind(&function, "function_body") else {
            continue;
        };
        let mut body_cursor = body.walk();
        let values = body.named_children(&mut body_cursor).collect::<Vec<_>>();
        let [expression] = values.as_slice() else {
            continue;
        };
        let Some((input_param_index, operation_call, mappings)) =
            kotlin_inline_static_string_mapping_chain(*expression, &decl.params, src)
        else {
            continue;
        };
        facts.push(bonsai_lang_api::CharacterConstraintFact {
            function_span: decl.span,
            transform_span: span_of(file, &body),
            input_place: decl.params[input_param_index].clone(),
            input_param_index: Some(input_param_index),
            proof: bonsai_lang_api::CharacterConstraintProof::ExactRuntimeSemantics,
            output: bonsai_lang_api::CharacterConstraintOutput::Return,
            domain: bonsai_lang_api::CharacterConstraintDomain::ProviderBound {
                factory_call: String::new(),
                operation_call,
                domain: Box::new(bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact { mappings }),
            },
        });
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.transform_span.start));
    facts.dedup();
    facts
}

fn kotlin_inline_static_string_mapping_chain(
    expression: Node<'_>,
    params: &[String],
    src: &[u8],
) -> Option<(usize, String, Vec<bonsai_lang_api::StaticStringMapEntry>)> {
    let mut current = expression;
    let mut mappings = Vec::new();
    let mut operation_call: Option<String> = None;
    loop {
        if current.kind() != "call_expression" {
            break;
        }
        let target = current.named_child(0)?;
        if target.kind() != "navigation_expression" {
            break;
        }
        let mut target_cursor = target.walk();
        let target_children = target.named_children(&mut target_cursor).collect::<Vec<_>>();
        let [receiver, suffix] = target_children.as_slice() else {
            return None;
        };
        if suffix.kind() != "navigation_suffix" {
            return None;
        }
        let method = first_named_child_of_kind(suffix, "simple_identifier")?;
        let method = node_text(&method, src).trim();
        if method.is_empty() {
            return None;
        }
        match operation_call.as_deref() {
            Some(operation) if operation != method => return None,
            Some(_) => {}
            None => operation_call = Some(method.to_string()),
        }
        let call_suffix = current
            .named_children(&mut current.walk())
            .find(|child| child.kind() == "call_suffix")?;
        let arguments = first_named_child_of_kind(&call_suffix, "value_arguments")?;
        let args = arguments
            .named_children(&mut arguments.walk())
            .filter(|child| child.kind() == "value_argument")
            .collect::<Vec<_>>();
        let [pattern, replacement] = args.as_slice() else {
            return None;
        };
        let pattern = pattern.named_child(0)?;
        let replacement = replacement.named_child(0)?;
        let input = kotlin_static_string_literal(pattern, src)?;
        let output = kotlin_static_string_literal(replacement, src)?;
        if input.chars().count() != 1
            || mappings
                .iter()
                .any(|entry: &bonsai_lang_api::StaticStringMapEntry| {
                    entry.key == input && entry.value != output
                })
        {
            return None;
        }
        if !mappings
            .iter()
            .any(|entry: &bonsai_lang_api::StaticStringMapEntry| entry.key == input)
        {
            mappings.push(bonsai_lang_api::StaticStringMapEntry {
                key: input,
                value: output,
            });
        }
        current = *receiver;
    }
    if mappings.is_empty() || current.kind() != "simple_identifier" {
        return None;
    }
    let input = node_text(&current, src).trim();
    let input_param_index = params.iter().position(|param| param == input)?;
    mappings.sort_by(|left, right| left.key.cmp(&right.key));
    Some((input_param_index, operation_call?, mappings))
}

fn kotlin_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let raw = node_text(&node, src);
    if raw.starts_with("\"\"\"") {
        return None;
    }
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    let mut input = inner.chars().peekable();
    let mut decoded = String::with_capacity(inner.len());
    while let Some(character) = input.next() {
        if character == '$' {
            return None;
        }
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match input.next()? {
            'b' => decoded.push('\u{0008}'),
            't' => decoded.push('\t'),
            'n' => decoded.push('\n'),
            'f' => decoded.push('\u{000c}'),
            'r' => decoded.push('\r'),
            '"' => decoded.push('"'),
            '\'' => decoded.push('\''),
            '\\' => decoded.push('\\'),
            '$' => decoded.push('$'),
            'u' => {
                let mut value = 0_u32;
                for _ in 0..4 {
                    value = value.checked_mul(16)? + input.next()?.to_digit(16)?;
                }
                decoded.push(char::from_u32(value)?);
            }
            _ => return None,
        }
    }
    Some(decoded)
}

/// Refine Kotlin's shared `class_declaration` node using its exact anonymous
/// declaration token. This is syntax classification owned by the adapter; it
/// deliberately carries no framework or API vocabulary.
fn refine_kotlin_class_decl_kinds(idx: &mut DeclIndex, file: FileId, tree: &Tree) {
    let mut refined = std::collections::HashMap::new();
    for node in collect_kinds(tree, &["class_declaration"]) {
        let kind = if kotlin_declaration_has_token(node, "interface") {
            DeclKind::Interface
        } else if kotlin_declaration_has_token(node, "enum") {
            DeclKind::Enum
        } else {
            DeclKind::Class
        };
        refined.insert(span_of(file, &node), kind);
    }
    for decl in &mut idx.defs {
        if let Some(kind) = refined.get(&decl.span).copied() {
            decl.kind = kind;
        }
    }
}

fn kotlin_declaration_has_token(node: Node<'_>, token: &str) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        let mut cursor = current.walk();
        for child in current.children(&mut cursor) {
            if child.kind() == token {
                return true;
            }
            // Declaration-kind keywords can be direct children or live below
            // the grammar's modifier wrappers. Do not descend into the class
            // body, where an unrelated nested declaration could collide.
            if matches!(child.kind(), "modifiers" | "class_modifier") {
                stack.push(child);
            }
        }
    }
    false
}

/// Lower Kotlin data-class `copy(field = value, ...)` results into exact
/// field writes on the enclosing assignment target. `copy` is a
/// compiler-generated data-class operation; receiver type evidence and named
/// arguments come from tree-sitter facts, and the IDG remains API agnostic.
fn synthesize_kotlin_data_copy_fields(
    events: &mut Vec<FlowEvent>,
    type_aliases: &[TypeAliasBinding],
    syntax: Option<(&Tree, FileId, &[u8])>,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                synthesize_kotlin_data_copy_fields(then_events, type_aliases, syntax);
                synthesize_kotlin_data_copy_fields(else_events, type_aliases, syntax);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                synthesize_kotlin_data_copy_fields(body, type_aliases, syntax);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                synthesize_kotlin_data_copy_fields(body, type_aliases, syntax);
                synthesize_kotlin_data_copy_fields(catch_events, type_aliases, syntax);
                synthesize_kotlin_data_copy_fields(finally_events, type_aliases, syntax);
            }
            _ => {}
        }
    }

    let mut additions = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let FlowEvent::Assign { span, target, .. } = event else {
            continue;
        };
        let mut fields = Vec::new();
        for candidate in events.iter() {
            let FlowEvent::Call {
                span: call_span,
                name,
                receiver: Some(receiver),
                receiver_types,
                args,
                ..
            } = candidate
            else {
                continue;
            };
            let receiver_root = receiver.split('.').next().unwrap_or(receiver).trim();
            let receiver_is_typed = !receiver_types.is_empty()
                || type_aliases
                    .iter()
                    .any(|alias| alias.name == receiver_root && !alias.type_name.is_empty());
            if !receiver_is_typed
                || kotlin_call_tail(name) != "copy"
                || call_span.file != span.file
                || call_span.start < span.start
                || span.end < call_span.end
            {
                continue;
            }
            for arg in args {
                let Some(name) = arg.name.as_ref().filter(|name| !name.is_empty()) else {
                    continue;
                };
                let value = arg.place.as_ref().map_or_else(
                    || bonsai_lang_api::ExpressionFlow::from_source_names(arg.source_names.clone()),
                    bonsai_lang_api::ExpressionFlow::from_place,
                );
                fields.push(bonsai_lang_api::ExpressionField {
                    name: name.clone(),
                    value_span: Some(arg.span),
                    value,
                });
            }
        }
        if let Some((tree, file, src)) = syntax {
            fields.extend(kotlin_nested_data_copy_fields(
                tree,
                file,
                src,
                *span,
                type_aliases,
            ));
        }
        fields.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.value_span.cmp(&right.value_span))
        });
        fields.dedup();
        if !fields.is_empty() {
            additions.push((
                index + 1,
                FlowEvent::AggregateAssign {
                    span: *span,
                    target: target.clone(),
                    type_name: None,
                    value_flow: bonsai_lang_api::ExpressionFlow {
                        aggregate_fields: fields,
                        ..Default::default()
                    },
                },
            ));
        }
    }
    for (index, event) in additions.into_iter().rev() {
        events.insert(index, event);
    }
}

/// Collect data-class `copy` named arguments nested inside an assignment RHS.
/// Lambda bodies retain their own declaration ownership; this adapter fact
/// describes only the resulting aggregate fields of the enclosing expression.
fn kotlin_nested_data_copy_fields(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    assignment_span: Span,
    type_aliases: &[TypeAliasBinding],
) -> Vec<bonsai_lang_api::ExpressionField> {
    let Some(assignment) = kotlin_node_for_exact_span(tree.root_node(), assignment_span) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    let mut stack = vec![assignment];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            let Some(target) = kotlin_call_target(node, src) else {
                continue;
            };
            let receiver =
                kotlin_call_receiver(node, src).and_then(|receiver| kotlin_exact_place(receiver, src));
            let receiver_root = receiver
                .as_deref()
                .and_then(|receiver| receiver.split('.').next())
                .unwrap_or("")
                .trim();
            let receiver_is_typed = !receiver_root.is_empty()
                && type_aliases
                    .iter()
                    .any(|alias| alias.name == receiver_root && !alias.type_name.is_empty());
            if receiver_is_typed && kotlin_call_tail(&target.full_text) == "copy" {
                let arguments = first_named_child_of_kind(&node, "call_suffix")
                    .and_then(|suffix| first_named_child_of_kind(&suffix, "value_arguments"));
                if let Some(arguments) = arguments {
                    let mut cursor = arguments.walk();
                    for argument in arguments.named_children(&mut cursor) {
                        let Some((argument_name, _)) = kotlin_named_argument(argument, src) else {
                            continue;
                        };
                        let Some(arg) = bonsai_lang_api::kit::call_arg_from_node_with_handler(
                            argument,
                            file,
                            src,
                            Some(argument_name),
                            &HANDLER,
                        ) else {
                            continue;
                        };
                        let Some(name) = arg.name.filter(|name| !name.is_empty()) else {
                            continue;
                        };
                        let value = arg.place.as_ref().map_or_else(
                            || bonsai_lang_api::ExpressionFlow::from_source_names(arg.source_names),
                            bonsai_lang_api::ExpressionFlow::from_place,
                        );
                        fields.push(bonsai_lang_api::ExpressionField {
                            name,
                            value_span: Some(arg.span),
                            value,
                        });
                    }
                }
                continue;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    fields
}

/// Reclassify Kotlin call expressions as constructors when the surrounding
/// property binding supplies matching static type evidence.
///
/// The Kotlin CST uses the same `call_expression` node for `File(...)` and a
/// top-level function call, so syntax alone cannot distinguish them. The
/// adapter's property pass has already produced `target -> Type` aliases from
/// explicit annotations or constructor-shaped RHS syntax. Joining that fact
/// with the exact assignment/call span gives downstream graph builders a real
/// `CallKind::Constructor` without teaching them class or API names.
fn classify_kotlin_constructor_calls(events: &mut [FlowEvent], type_aliases: &[TypeAliasBinding]) {
    let constructor_assignments = events
        .iter()
        .filter_map(|event| {
            let FlowEvent::Assign {
                span,
                target,
                source_call: Some(source_call),
                ..
            } = event
            else {
                return None;
            };
            let bound_type = type_aliases
                .iter()
                .find(|alias| alias.name == *target)
                .map(|alias| kotlin_call_tail(&alias.type_name))?;
            (kotlin_call_tail(source_call) == bound_type).then(|| (*span, source_call.clone()))
        })
        .collect::<Vec<_>>();

    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                call_kind,
                ..
            } if matches!(call_kind, CallKind::Function | CallKind::Method)
                && constructor_assignments.iter().any(|(assign_span, source_call)| {
                    assign_span.file == span.file
                        && assign_span.start <= span.start
                        && span.end <= assign_span.end
                        && source_call == name
                }) =>
            {
                *call_kind = CallKind::Constructor;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                classify_kotlin_constructor_calls(then_events, type_aliases);
                classify_kotlin_constructor_calls(else_events, type_aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                classify_kotlin_constructor_calls(body, type_aliases);
                classify_kotlin_constructor_calls(catch_events, type_aliases);
                classify_kotlin_constructor_calls(finally_events, type_aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                classify_kotlin_constructor_calls(body, type_aliases);
            }
            _ => {}
        }
    }
}

fn kotlin_call_tail(name: &str) -> &str {
    name.rsplit(['.', ':', '\\']).next().unwrap_or(name).trim()
}

fn qualify_kotlin_implicit_member_reads(index: &mut DeclIndex) {
    bonsai_lang_api::qualify_implicit_member_reads_in_index(index, |name| ImplicitMemberReadCall {
        source_call: format!("this.{name}"),
        call_name: format!("this.{name}"),
        receiver: Some("this".to_string()),
        call_kind: CallKind::Method,
    });
}

/// Qualify an unadorned property root in a zero-argument member return as
/// receiver state when the owning class's parsed constructor declares that
/// property. Kotlin permits `get() = data.cmd` where the semantic place is
/// `this.data.cmd`; Tree-sitter correctly exposes the navigation projection
/// but, by design, does not invent the implicit receiver. The adapter joins
/// that projection with its constructor-owned `receiver_field_writes` and
/// emits the canonical place consumed by the IDG.
fn qualify_kotlin_receiver_field_getters(index: &mut DeclIndex) {
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
        if !matches!(decl.kind, DeclKind::Function | DeclKind::Method) || !decl.params.is_empty() {
            continue;
        }
        let Some(fields) = decl.parent.and_then(|parent| fields_by_parent.get(&parent)) else {
            continue;
        };
        bonsai_lang_api::qualify_receiver_field_expression_flows(&mut decl.flow_events, fields, "this");
    }
}

/// Lift each `import_header` into an `ImportSpec`. The aliased shape
/// (`import x.y.z as Z`) needs special care so the matcher doesn't
/// double-resolve the terminal symbol — see the inline comment.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Kotlin shapes:
    //   `import x.y.z`       → bare import
    //   `import x.y.z as Z`  → with `as` alias
    //   `import x.y.*`       → wildcard
    for import_node in collect_kinds(tree, &["import_header"]) {
        let text = node_text(&import_node, src)
            .trim_start_matches("import ")
            .trim_end_matches(';')
            .trim();
        if text.is_empty() {
            continue;
        }
        let (head, explicit_alias) = if let Some((module_part, alias_part)) = text.rsplit_once(" as ") {
            (
                module_part.trim().to_string(),
                Some(alias_part.trim().to_string()),
            )
        } else {
            (text.to_string(), None)
        };
        let is_wildcard = head.ends_with(".*");
        let full_path = head.trim_end_matches(".*").to_string();
        // `import x.y.z as Z` — record the terminal symbol as
        // `original_name` and store ONLY the namespace prefix as
        // `module`. Otherwise `kit::alias_map_from_imports` reads
        // `Member { module: "x.y.z", member: "z" }` and the matcher
        // expands `Z(...)` to `"x.y.z.z(...)"` (double tail). The
        // unaliased shape preserves the full path as `module` to
        // keep query-by-module-path semantics for downstream rule
        // lookup.
        let (module, alias, original_name) = if explicit_alias.is_some() {
            match full_path.rsplit_once('.') {
                Some((prefix, terminal_symbol)) => (
                    prefix.to_string(),
                    explicit_alias,
                    Some(terminal_symbol.to_string()),
                ),
                None => (String::new(), explicit_alias, Some(full_path.clone())),
            }
        } else if is_wildcard {
            (full_path, None, None)
        } else {
            let alias = import_tail_binding(&full_path);
            (full_path, alias, None)
        };
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module,
            alias,
            is_wildcard,
            original_name,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn import_tail_binding(module: &str) -> Option<String> {
    let tail = module
        .rsplit_once('.')
        .map(|(_, tail)| tail)
        .unwrap_or(module)
        .trim();
    (!tail.is_empty() && tail != module).then(|| tail.to_string())
}

/// Walk `decl.flow_events` recursively and populate
/// `Throw::thrown_type` / `Try::catch_types` from the Kotlin parse
/// tree. Kotlin syntax:
///   throw IOException("...")  → thrown_type: "IOException" (no `new`)
///   throw e                   → thrown_type: None (need data-flow)
///   `try { } catch (e: IOException) { } catch (e: A) { }`
///                             → `catch_types = vec!["IOException", "A"]`
fn populate_kotlin_exception_types(
    events: &mut [bonsai_lang_api::FlowEvent],
    tree: &tree_sitter::Tree,
    src: &[u8],
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Throw {
                span, thrown_type, ..
            } => {
                if thrown_type.is_some() {
                    continue;
                }
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["jump_expression"])
                {
                    if let Some(name) = kotlin_thrown_type_for_node(node, src) {
                        *thrown_type = Some(name);
                    }
                }
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_types,
                catch_arms,
                ..
            } => {
                if let Some(node) = bonsai_lang_api::kit::node_at_span(
                    tree.root_node(),
                    *span,
                    &["try_expression", "try_statement"],
                ) {
                    if catch_types.is_empty() {
                        *catch_types = collect_kotlin_catch_types(node, src);
                    }
                    for arm in catch_arms {
                        if let Some(block) =
                            bonsai_lang_api::kit::node_at_span(tree.root_node(), arm.span, &["catch_block"])
                        {
                            arm.parameter = bonsai_lang_api::kit::extract_catch_arm_param(&block, src);
                            arm.types = kotlin_catch_block_types(block, src);
                        }
                    }
                }
                populate_kotlin_exception_types(body, tree, src);
                populate_kotlin_exception_types(catch_events, tree, src);
                populate_kotlin_exception_types(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_kotlin_exception_types(then_events, tree, src);
                populate_kotlin_exception_types(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_kotlin_exception_types(body, tree, src);
            }
            _ => {}
        }
    }
}

/// Pull the constructor type out of `throw Foo(...)`. Kotlin omits the
/// `new` keyword, so a throw is just a call expression whose head is
/// the type name. Returns `None` for re-throws (`throw e`).
fn kotlin_thrown_type_for_node(throw_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    // throw_expression > call_expression > simple_identifier (the constructor name)
    let mut throw_cursor = throw_node.walk();
    for child in throw_node.named_children(&mut throw_cursor) {
        if child.kind() == "call_expression" {
            // Constructor call: first child is usually the type name
            let mut call_cursor = child.walk();
            for sub in child.named_children(&mut call_cursor) {
                if matches!(
                    sub.kind(),
                    "simple_identifier" | "user_type" | "navigation_expression"
                ) {
                    return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &sub, src,
                    )));
                }
            }
        }
    }
    None
}

/// Collect the `catch (e: T)` types in source order. Each arm
/// contributes one type (Kotlin has no multi-catch syntax — code uses
/// `is` checks inside the body for that case).
fn collect_kotlin_catch_types(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut catch_types: Vec<String> = Vec::new();
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_block" {
            continue;
        }
        for name in kotlin_catch_block_types(child, src) {
            if !catch_types.iter().any(|existing| existing == &name) {
                catch_types.push(name);
            }
        }
    }
    catch_types
}

fn kotlin_catch_block_types(child: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut catch_types = Vec::new();
    // Kotlin catch_block layout (tree-sitter-kotlin):
    //   catch_block
    //     simple_identifier   <- param name (skip)
    //     user_type           <- the catch type wrapper
    //       type_identifier   <- canonical name
    //     statements          <- catch body (skip)
    // We pick out the *type wrappers* (`user_type` / `type_reference`)
    // and read their type_identifier descendant; never read a top-level
    // `simple_identifier` directly because that's the param name.
    let mut catch_cursor = child.walk();
    for sub in child.named_children(&mut catch_cursor) {
        if sub.kind() == "user_type" {
            // Find the inner `type_identifier` descendant; for nested
            // generics we want the leftmost type name.
            let mut found: Option<String> = None;
            let mut wrapper_cursor = sub.walk();
            let mut work_stack: Vec<tree_sitter::Node<'_>> =
                sub.named_children(&mut wrapper_cursor).collect();
            while let Some(node) = work_stack.pop() {
                if node.kind() == "type_identifier" {
                    found = Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &node, src,
                    )));
                    break;
                }
                let mut inner_cursor = node.walk();
                for inner_child in node.named_children(&mut inner_cursor) {
                    work_stack.push(inner_child);
                }
            }
            // Fallback to the wrapper's text — covers grammar
            // shapes that don't have a `type_identifier` descendant
            // (e.g. some `nullable_type` wrappers).
            let name = found
                .unwrap_or_else(|| bonsai_lang_api::kit::canonical_simple_type_name(node_text(&sub, src)));
            if !name.is_empty() && !catch_types.iter().any(|existing| existing == &name) {
                catch_types.push(name);
            }
        }
    }
    catch_types
}

/// Find the `package com.foo.bar` declaration at the top of a Kotlin
/// file and return its segments.
fn extract_kotlin_package(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut root_cursor = root.walk();
    for child in root.children(&mut root_cursor) {
        if child.kind() != "package_header" {
            continue;
        }
        let mut header_cursor = child.walk();
        for header_child in child.children(&mut header_cursor) {
            if header_child.kind() == "identifier" {
                let text = node_text(&header_child, src);
                let segments: Vec<String> = text
                    .split('.')
                    .map(str::trim)
                    .filter(|segment| !segment.is_empty())
                    .map(str::to_string)
                    .collect();
                if !segments.is_empty() {
                    return Some(segments);
                }
            }
        }
    }
    None
}

/// Walk Kotlin function declarations and collect local receiver type
/// evidence (`name: Type` parameters and constructor-shaped
/// `val name = Type(...)` locals) as `TypeAliasBinding`. Used by the
/// resolver to narrow `[Type, method]` rule dispatch through adapter
/// facts instead of local receiver-name guesses.
fn collect_kotlin_type_aliases(
    tree: &Tree,
    file: bonsai_common::FileId,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let mut aliases_by_span = std::collections::HashMap::new();
    for fn_node in collect_kinds(tree, &["function_declaration"]) {
        let mut aliases = Vec::new();
        // DFS: walks every `parameter` / `class_parameter` descendant
        // (lambda receivers, default-value expressions, etc. all get
        // their parameters extracted).
        let mut work_stack = vec![fn_node];
        while let Some(node) = work_stack.pop() {
            if node != fn_node
                && matches!(
                    node.kind(),
                    "function_declaration" | "class_declaration" | "object_declaration"
                )
            {
                continue;
            }
            if matches!(
                node.kind(),
                "parameter" | "class_parameter" | "property_declaration"
            ) {
                if let Some(binding) = kotlin_param_alias(node, src, declared_type_names) {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                work_stack.push(child);
            }
        }
        if !aliases.is_empty() {
            aliases_by_span.insert(span_of(file, &fn_node), aliases);
        }
    }
    aliases_by_span
}

/// Synthesize class decls for Kotlin's `object Foo { ... }` pattern
/// because tree-sitter-kotlin parses it as `infix_expression` (with
/// `object` as the operator-literal, the name as a `simple_identifier`,
/// and the body as a `lambda_literal`) rather than a dedicated
/// `object_declaration` kind. Without a class decl there's no parent
/// for the contained methods, so `Foo.bar(args)` calls have nothing
/// to dispatch into. The synthesized class carries the
/// infix_expression span so any subsequent post-process keyed on
/// span (e.g. `apply_class_field_type_aliases`) lines up.
fn synthesize_kotlin_object_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let mut next_symbol_raw = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(0, |m| m + 1);
    for infix in collect_kinds(tree, &["infix_expression"]) {
        // tree-sitter-kotlin exposes the `object` keyword through the
        // infix expression's `operator` field. Some grammar revisions also
        // retain a named `object_literal` child, so accept both exact CST
        // shapes. The declaration and receiver-type passes below then treat
        // `Box.helper(...)` as class-side dispatch using syntax-derived owner
        // evidence; the shared resolver never needs a Kotlin name special
        // case.
        let mut cursor = infix.walk();
        let mut object_keyword = infix
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(&operator, src).trim() == "object");
        let mut name_node: Option<Node<'_>> = None;
        let mut lambda_node: Option<Node<'_>> = None;
        for child in infix.named_children(&mut cursor) {
            match child.kind() {
                "object_literal" => object_keyword = true,
                "simple_identifier" if name_node.is_none() => name_node = Some(child),
                "lambda_literal" => lambda_node = Some(child),
                _ => {}
            }
        }
        if !object_keyword {
            continue;
        }
        let (Some(name_node), Some(lambda_node)) = (name_node, lambda_node) else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let class_span = span_of(file, &infix);
        if idx.defs.iter().any(|d| d.span == class_span) {
            continue;
        }
        let class_symbol = bonsai_common::SymbolId::new(next_symbol_raw);
        next_symbol_raw += 1;
        let class_module_path = idx
            .defs
            .iter()
            .find(|d| !d.module_path.is_empty())
            .map(|d| d.module_path.clone())
            .unwrap_or_default();
        idx.defs.push(bonsai_lang_api::Decl {
            symbol: class_symbol,
            kind: DeclKind::Class,
            name: name.clone(),
            qualified_name: None,
            module_path: class_module_path,
            span: class_span,
            name_span: span_of(file, &name_node),
            visibility: bonsai_lang_api::Visibility::Public,
            parent: None,
            body_span: Some(span_of(file, &lambda_node)),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        // Re-parent the object body's direct function declarations to the
        // synthesized class. The generic Kotlin lowering initially sees the
        // object body as a lambda and may parent `helper` to its synthetic
        // `<lambda>` declaration. The CST's direct `statements` children are
        // the authoritative ownership fact, so replace that temporary parent
        // for direct members while leaving lambdas nested inside a member
        // attached to that member.
        let lambda_span = span_of(file, &lambda_node);
        let direct_member_spans = kotlin_object_direct_function_spans(lambda_node, file);
        for decl in &mut idx.defs {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let is_synthetic_object_body = decl.span == lambda_span;
            if is_synthetic_object_body || direct_member_spans.contains(&decl.span) {
                decl.parent = Some(class_symbol);
                decl.kind = DeclKind::Method;
            }
        }
    }
}

fn kotlin_object_direct_function_spans(lambda: Node<'_>, file: FileId) -> std::collections::HashSet<Span> {
    let Some(statements) = first_named_child_of_kind(&lambda, "statements") else {
        return std::collections::HashSet::new();
    };
    let mut cursor = statements.walk();
    statements
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "function_declaration")
        .map(|child| span_of(file, &child))
        .collect()
}

fn synthesize_kotlin_constructor_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let class_names = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();
    let classes = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| {
            (
                decl.span,
                decl.symbol,
                decl.kind,
                decl.name.clone(),
                decl.name_span,
            )
        })
        .collect::<Vec<_>>();
    let mut next = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for class_node in collect_kinds(tree, &["class_declaration"]) {
        let class_span = span_of(file, &class_node);
        let Some((_, class_symbol, class_kind, class_name, class_name_span)) =
            classes.iter().find(|(span, _, _, _, _)| *span == class_span)
        else {
            continue;
        };
        // Interfaces and annotation declarations use the same broad CST
        // declaration shape but are not constructible runtime classes.
        if !matches!(class_kind, DeclKind::Class | DeclKind::Enum) {
            continue;
        }
        let primary = first_named_child_of_kind(&class_node, "primary_constructor");
        let body = first_named_child_of_kind(&class_node, "class_body");
        let secondary_constructors = kotlin_direct_secondary_constructors(class_node);
        // Kotlin supplies an implicit primary constructor only when the class
        // declares no secondary constructors. A class with secondary
        // constructors and no explicit primary has no callable zero-argument
        // constructor; its instance initializer prefix belongs to the
        // secondary path that delegates directly to `super`.
        if primary.is_some() || secondary_constructors.is_empty() {
            let mut flow_events =
                kotlin_primary_constructor_delegation_events(class_node, file, src, &class_names);
            flow_events.extend(kotlin_instance_initialization_events(
                class_node,
                file,
                src,
                &class_names,
            ));
            qualify_kotlin_constructor_property_assignments(&mut flow_events, class_node, file, src);
            let receiver_field_initializers =
                bonsai_lang_api::collect_receiver_field_initializers(&flow_events, &["this"]);
            let params = primary.map_or_else(Vec::new, |primary| constructor_param_names(primary, src));
            let receiver_field_writes = primary.map_or_else(Vec::new, |primary| {
                kotlin_primary_constructor_field_writes(primary, file, src, &params)
            });
            idx.defs.push(kotlin_constructor_decl(
                bonsai_common::SymbolId::new(next),
                *class_symbol,
                class_name,
                KotlinConstructorSpans {
                    name: *class_name_span,
                    decl: class_span,
                    body: body
                        .map(|body| span_of(file, &body))
                        .or_else(|| primary.map(|primary| span_of(file, &primary)))
                        .unwrap_or(class_span),
                },
                KotlinConstructorFacts {
                    params,
                    flow_events,
                    receiver_field_writes,
                    receiver_field_initializers,
                },
            ));
            next = next.saturating_add(1);
        }
        for secondary in secondary_constructors {
            let body = first_named_child_of_kind(&secondary, "statements").unwrap_or(secondary);
            let (mut flow_events, delegates_to_super) =
                kotlin_secondary_constructor_delegation_events(secondary, file, src, class_name);
            if primary.is_none() && delegates_to_super {
                let mut initializers =
                    kotlin_instance_initialization_events(class_node, file, src, &class_names);
                qualify_kotlin_constructor_property_assignments(&mut initializers, class_node, file, src);
                flow_events.extend(initializers);
            }
            flow_events.extend(walk_flow_events(body, file, src, &HANDLER, &class_names));
            let params = constructor_param_names(secondary, src);
            let receiver_field_writes =
                collect_receiver_field_writes(&flow_events, &params, None, &["this", "super"], &[]);
            let receiver_field_initializers =
                bonsai_lang_api::collect_receiver_field_initializers(&flow_events, &["this"]);
            idx.defs.push(kotlin_constructor_decl(
                bonsai_common::SymbolId::new(next),
                *class_symbol,
                class_name,
                KotlinConstructorSpans {
                    name: *class_name_span,
                    decl: span_of(file, &secondary),
                    body: span_of(file, &body),
                },
                KotlinConstructorFacts {
                    params,
                    flow_events,
                    receiver_field_writes,
                    receiver_field_initializers,
                },
            ));
            next = next.saturating_add(1);
        }
    }
}

fn kotlin_direct_secondary_constructors<'tree>(class_node: Node<'tree>) -> Vec<Node<'tree>> {
    let Some(body) = first_named_child_of_kind(&class_node, "class_body") else {
        return Vec::new();
    };
    let mut cursor = body.walk();
    let constructors = body
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "secondary_constructor")
        .collect();
    constructors
}

/// Lower the mandatory `this(args)` / `super(args)` delegation of a Kotlin
/// secondary constructor. Tree-sitter gives this construct its own
/// `constructor_delegation_call` node rather than a `call_expression`, so the
/// adapter must preserve the edge explicitly. `this` is replaced by the
/// exact enclosing class identity; `super` remains an adapter-declared
/// ancestor receiver so shared resolution can select constructors from the
/// class's declared bases.
fn kotlin_secondary_constructor_delegation_events(
    secondary: Node<'_>,
    file: FileId,
    src: &[u8],
    class_name: &str,
) -> (Vec<FlowEvent>, bool) {
    let Some(delegation) = first_named_child_of_kind(&secondary, "constructor_delegation_call") else {
        return (Vec::new(), false);
    };
    let Some(keyword) = delegation.child(0).map(|child| child.kind()) else {
        return (Vec::new(), false);
    };
    let Some(arguments) = first_named_child_of_kind(&delegation, "value_arguments") else {
        return (Vec::new(), false);
    };
    let (name, receiver, delegates_to_super) = match keyword {
        "this" => (class_name.to_string(), None, false),
        "super" => ("super".to_string(), Some("super".to_string()), true),
        _ => return (Vec::new(), false),
    };
    (
        vec![FlowEvent::Call {
            span: span_of(file, &delegation),
            name,
            receiver,
            receiver_types: Vec::new(),
            call_kind: CallKind::Constructor,
            args: named_child_call_args_with_handler(&arguments, file, src, &HANDLER),
        }],
        delegates_to_super,
    )
}

/// Lower the executable class-body prefix of a Kotlin primary constructor.
/// Only direct property initializer expressions/delegates and `init {}`
/// blocks execute during construction. Walking the complete class body would
/// incorrectly pull computed accessors and sibling method bodies into every
/// constructor.
fn kotlin_instance_initialization_events(
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
    class_names: &[String],
) -> Vec<FlowEvent> {
    let Some(body) = first_named_child_of_kind(&class_node, "class_body") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        let executable = match child.kind() {
            "anonymous_initializer" => true,
            "property_declaration" => kotlin_property_initializer_node(child).is_some(),
            _ => false,
        };
        if executable {
            out.extend(walk_flow_events(child, file, src, &HANDLER, class_names));
        }
    }
    out
}

/// Return the executable initializer of one direct Kotlin property.
/// Tree-sitter's `expression` supertype appears at runtime as the concrete
/// expression kind (`call_expression`, `string_literal`, and so on), so node
/// kind matching cannot identify this boundary. The grammar exposes the
/// initializer after the property's direct `=` token; delegated properties
/// use the distinct `property_delegate` node. Accessor-local `=` tokens are
/// nested under `getter`/`setter` and therefore cannot be mistaken for the
/// property's initializer.
fn kotlin_property_initializer_node(property: Node<'_>) -> Option<Node<'_>> {
    let mut after_initializer_token = false;
    for index in 0..property.child_count() {
        let Ok(index) = u32::try_from(index) else {
            return None;
        };
        let child = property.child(index)?;
        if !child.is_named() {
            if child.kind() == "=" {
                after_initializer_token = true;
            }
            continue;
        }
        if child.kind() == "property_delegate" || after_initializer_token {
            return Some(child);
        }
    }
    None
}

/// Mark direct class-property initializers as receiver-field writes in the
/// constructor's flow tree.
///
/// Kotlin permits an implicit receiver for a property declaration inside a
/// class body (`private val service = Service()`). Tree-sitter correctly
/// exposes the declaration as a `property_declaration`, but the generic flow
/// walker necessarily lowers its target as the bare binding `service`.
/// Qualifying only direct class-body properties here preserves the language's
/// storage semantics while leaving locals inside `init` blocks and methods
/// untouched.
fn qualify_kotlin_constructor_property_assignments(
    events: &mut [FlowEvent],
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
) {
    let Some(body) = first_named_child_of_kind(&class_node, "class_body") else {
        return;
    };
    let mut properties = std::collections::HashMap::new();
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if child.kind() != "property_declaration" {
            continue;
        }
        let Some(name_node) = kotlin_property_name_node(child) else {
            continue;
        };
        let name = node_text(&name_node, src).trim();
        if !name.is_empty() {
            properties.insert(span_of(file, &child), name.to_string());
        }
    }
    if properties.is_empty() {
        return;
    }

    fn qualify(events: &mut [FlowEvent], properties: &std::collections::HashMap<Span, String>) {
        for event in events {
            match event {
                FlowEvent::Assign { span, target, .. } => {
                    let Some(name) = properties.get(span) else {
                        continue;
                    };
                    if target == name {
                        *target = format!("this.{name}");
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    qualify(then_events, properties);
                    qualify(else_events, properties);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => qualify(body, properties),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    qualify(body, properties);
                    qualify(catch_events, properties);
                    qualify(finally_events, properties);
                }
                _ => {}
            }
        }
    }

    qualify(events, &properties);
}

/// Lower direct superclass constructor invocations from the class header into
/// the synthetic primary constructor. Tree-sitter exposes these as
/// `delegation_specifier > constructor_invocation`; walking only direct class
/// children prevents nested class/method calls from leaking into the parent
/// constructor.
fn kotlin_primary_constructor_delegation_events(
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
    class_names: &[String],
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    let mut cursor = class_node.walk();
    for child in class_node.named_children(&mut cursor) {
        if child.kind() != "delegation_specifier"
            || first_named_child_of_kind(&child, "constructor_invocation").is_none()
        {
            continue;
        }
        let mut events = walk_flow_events(child, file, src, &HANDLER, class_names);
        for event in &mut events {
            if let FlowEvent::Call { call_kind, .. } = event {
                // A superclass delegation call constructs the ancestor part
                // of the current instance; it is not a fresh allocation.
                // Preserve constructor kind; the resolver proves that the
                // target is an ancestor of the synthetic constructor owner,
                // which lets the IDG stitch outbound state to the adapter's
                // canonical receiver without a source-language token here.
                *call_kind = CallKind::Constructor;
            }
        }
        out.extend(events);
    }
    out
}

fn synthesize_kotlin_property_getter_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let class_names = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();
    let classes = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| {
            (
                decl.body_span.unwrap_or(decl.span),
                decl.symbol,
                decl.module_path.clone(),
            )
        })
        .collect::<Vec<_>>();
    if classes.is_empty() {
        return;
    }

    let mut next = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let mut synthesized = Vec::new();
    for property in collect_kinds(tree, &["property_declaration"]) {
        let Some(getter) = first_named_child_of_kind(&property, "getter") else {
            continue;
        };
        let Some(name_node) = kotlin_property_name_node(property) else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let property_span = span_of(file, &property);
        let Some((_, parent, module_path)) = classes
            .iter()
            .filter(|(body_span, _, _)| span_contains(*body_span, property_span))
            .min_by_key(|(body_span, _, _)| body_span.end.saturating_sub(body_span.start))
        else {
            continue;
        };
        if idx
            .defs
            .iter()
            .chain(synthesized.iter())
            .any(|decl| decl.parent == Some(*parent) && decl.name == name && decl.params.is_empty())
        {
            continue;
        }
        let body = first_named_child_of_kind(&getter, "function_body").unwrap_or(getter);
        let body_span = span_of(file, &body);
        let mut flow_events = walk_flow_events(body, file, src, &HANDLER, &class_names);
        if !flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Return { .. }))
        {
            if let Some(expr) = kotlin_getter_expression_text(body, src) {
                let expression_node = body.named_child(0).unwrap_or(body);
                flow_events.push(FlowEvent::Return {
                    span: body_span,
                    value_kind: HANDLER.expression_value_kind(expression_node, src),
                    value_text: Some(expr.clone()),
                    value_name: kotlin_bare_identifier(&expr),
                    value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                        expression_node,
                        file,
                        src,
                        &HANDLER,
                    ),
                });
            }
        }
        if flow_events.is_empty() {
            continue;
        }
        synthesized.push(Decl {
            symbol: bonsai_common::SymbolId::new(next),
            kind: DeclKind::Method,
            name,
            qualified_name: None,
            module_path: module_path.clone(),
            span: span_of(file, &getter),
            name_span: span_of(file, &name_node),
            visibility: Visibility::Public,
            parent: Some(*parent),
            body_span: Some(body_span),
            flow_events,
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: vec!["this".to_string(), "super".to_string()],
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        next = next.saturating_add(1);
    }
    idx.defs.extend(synthesized);
}

fn kotlin_property_name_node(property: Node<'_>) -> Option<Node<'_>> {
    let variable = first_named_child_of_kind(&property, "variable_declaration")?;
    first_named_child_of_kind(&variable, "simple_identifier")
        .or_else(|| first_named_child_of_kind(&variable, "identifier"))
}

fn kotlin_getter_expression_text(body: Node<'_>, src: &[u8]) -> Option<String> {
    let mut text = node_text(&body, src).trim().trim_end_matches(';').trim();
    if let Some(rest) = text.strip_prefix('=') {
        text = rest.trim();
    }
    (!text.is_empty()).then(|| text.to_string())
}

fn kotlin_bare_identifier(text: &str) -> Option<String> {
    let text = text.trim();
    let mut chars = text.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    chars
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        .then(|| text.to_string())
}

fn span_contains(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

struct KotlinConstructorSpans {
    name: bonsai_common::Span,
    decl: bonsai_common::Span,
    body: bonsai_common::Span,
}

struct KotlinConstructorFacts {
    params: Vec<String>,
    flow_events: Vec<FlowEvent>,
    receiver_field_writes: Vec<FieldWrite>,
    receiver_field_initializers: Vec<ReceiverFieldInitializer>,
}

fn kotlin_constructor_decl(
    symbol: bonsai_common::SymbolId,
    parent: bonsai_common::SymbolId,
    class_name: &str,
    spans: KotlinConstructorSpans,
    facts: KotlinConstructorFacts,
) -> Decl {
    Decl {
        symbol,
        kind: DeclKind::Constructor,
        name: class_name.to_string(),
        qualified_name: None,
        module_path: bonsai_lang_api::ModulePath::default(),
        span: spans.decl,
        name_span: spans.name,
        visibility: Visibility::Public,
        parent: Some(parent),
        body_span: Some(spans.body),
        flow_events: facts.flow_events,
        has_implicit_returns: false,
        params: facts.params,
        param_annotations: Vec::new(),
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: facts.receiver_field_writes,
        receiver_field_initializers: facts.receiver_field_initializers,
        implicit_receiver_names: vec!["this".to_string(), "super".to_string()],
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn kotlin_primary_constructor_field_writes(
    primary: Node<'_>,
    file: FileId,
    src: &[u8],
    params: &[String],
) -> Vec<FieldWrite> {
    let mut writes = Vec::new();
    for param in collect_descendant_kinds(primary, &["class_parameter"]) {
        if !kotlin_class_parameter_declares_property(param, src) {
            continue;
        }
        let Some(name) = parameter_binding_name(param, src) else {
            continue;
        };
        let Some(source_idx) = params.iter().position(|param| param == &name) else {
            continue;
        };
        writes.push(FieldWrite {
            span: span_of(file, &param),
            target: format!("this.{name}"),
            source_param_indices: vec![source_idx],
        });
    }
    writes.sort_by_key(|write| (write.span.start, write.target.clone()));
    writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
    writes
}

fn kotlin_class_parameter_declares_property(param: Node<'_>, src: &[u8]) -> bool {
    node_text(&param, src)
        .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .any(|token| matches!(token, "val" | "var"))
}

fn collect_descendant_kinds<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if kinds.contains(&current.kind()) {
            out.push(current);
        }
        let mut cursor = current.walk();
        let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    out
}

fn constructor_param_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    collect_descendant_kinds(node, &["class_parameter", "parameter"])
        .into_iter()
        .filter_map(|param| parameter_binding_name(param, src))
        .collect()
}

fn parameter_binding_name(param: Node<'_>, src: &[u8]) -> Option<String> {
    let mut names = Vec::new();
    collect_binding_identifiers(param, src, &mut names);
    names.into_iter().find(|name| name != "_")
}

fn collect_binding_identifiers(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if matches!(node.kind(), "simple_identifier" | "identifier") {
        let name = node_text(&node, src).trim();
        if !name.is_empty() {
            out.push(name.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "user_type" | "type_identifier") {
            continue;
        }
        collect_binding_identifiers(child, src, out);
    }
}

/// Collect receiver-visible type aliases declared by Kotlin class
/// constructor properties / fields and attach them to methods through
/// `Decl.parent`. Example: `class H(private val conn: Connection)` makes
/// `conn: Connection` available inside every method of `H`.
fn collect_kotlin_class_type_aliases(
    tree: &Tree,
    file: bonsai_common::FileId,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, &["class_declaration", "object_declaration"]) {
        let mut aliases = Vec::new();
        collect_kotlin_class_aliases_from_node(class_node, src, declared_type_names, &mut aliases);
        if !aliases.is_empty() {
            out.push((span_of(file, &class_node), aliases));
        }
    }
    out
}

fn collect_kotlin_class_aliases_from_node(
    node: Node<'_>,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
    aliases: &mut Vec<TypeAliasBinding>,
) {
    match node.kind() {
        "function_declaration" | "getter" | "setter" | "secondary_constructor" => return,
        "class_parameter" | "property_declaration" => {
            if let Some(binding) = kotlin_param_alias(node, src, declared_type_names) {
                if !aliases.contains(&binding) {
                    aliases.push(binding);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_kotlin_class_aliases_from_node(child, src, declared_type_names, aliases);
    }
}

/// Extract a single `name: Type` pair from a `parameter` /
/// `class_parameter` node. Returns `None` when either side is missing
/// or when the binding name happens to equal the type (no useful alias).
fn kotlin_param_alias(
    node: Node<'_>,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Option<TypeAliasBinding> {
    // tree-sitter-kotlin's `parameter` exposes the binding identifier
    // and type as unnamed `simple_identifier` and `user_type`
    // children rather than `name`/`type` fields. Walk by kind so
    // both shapes resolve.
    let mut name_node: Option<Node<'_>> = node.child_by_field_name("name");
    let mut type_node: Option<Node<'_>> = node.child_by_field_name("type");
    if name_node.is_none() || type_node.is_none() {
        let mut child_cursor = node.walk();
        for child in node.named_children(&mut child_cursor) {
            match child.kind() {
                "simple_identifier" | "identifier" if name_node.is_none() => {
                    name_node = Some(child);
                }
                // `property_declaration` wraps the binding identifier
                // inside a `variable_declaration` node — descend so
                // type-inferred fields like `private val x = Y()` get
                // a name. The explicit type annotation (`val c: Foo`)
                // also lives INSIDE the variable_declaration, so pull
                // it from there too; otherwise typed locals
                // (`val c: Foo = make()` — WS2 cast / factory case)
                // fall through to the type-inferred path and lose `Foo`.
                "variable_declaration" if name_node.is_none() => {
                    let mut inner = child.walk();
                    for grandchild in child.named_children(&mut inner) {
                        match grandchild.kind() {
                            "simple_identifier" | "identifier" if name_node.is_none() => {
                                name_node = Some(grandchild);
                            }
                            "user_type" | "type_identifier" | "function_type" | "nullable_type"
                                if type_node.is_none() =>
                            {
                                type_node = Some(grandchild);
                            }
                            _ => {}
                        }
                    }
                }
                "user_type" | "type_identifier" | "function_type" | "nullable_type"
                    if type_node.is_none() =>
                {
                    type_node = Some(child);
                }
                _ => {}
            }
        }
    }
    let name_node = name_node?;
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let declared_type = if let Some(type_node) = type_node {
        canonical_declared_type(node_text(&type_node, src))?
    } else {
        // Type-inferred property (`val x = Y()`): the CST uses the same call
        // shape for functions and constructors, so bind only when `Y` is an
        // exactly declared type in this compiler object. Imported/library
        // factory return types belong in typing rules.
        // WS2: `val c = make() as Foo` / `as?` — the cast on the RHS is
        // the only type signal for an inferred local; prefer it, then fall
        // back to the constructor-shape inference.
        kotlin_property_cast_type(node, src)
            .or_else(|| kotlin_property_constructor_type(node, src, declared_type_names))?
    };
    if name == declared_type {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: declared_type,
    })
}

/// WS2: when an inferred local is initialized by a Kotlin `as` / `as?`
/// cast (`val c = make() as Foo`), the cast's right operand is the static
/// type. Scans the property's named children for the `as_expression` that
/// is the RHS and returns its canonical type. Returns `None` for any
/// non-cast RHS so only a genuine cast types the local.
fn kotlin_property_cast_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "as_expression" {
            // The cast target is a `user_type` / `type_identifier` /
            // `nullable_type` operand of the `as_expression` (the grammar
            // exposes operands as positional children, not a `right`
            // field).
            let mut inner = child.walk();
            for operand in child.named_children(&mut inner) {
                if matches!(operand.kind(), "user_type" | "type_identifier" | "nullable_type") {
                    return canonical_declared_type(node_text(&operand, src));
                }
            }
        }
    }
    None
}

/// When a `property_declaration` lacks an explicit type annotation,
/// look at its `expression` (RHS) for a `call_expression` whose
/// callee resolves to a type declaration in this compiler object. Returns the
/// canonical short type, or `None` when the RHS is ambiguous.
fn kotlin_property_constructor_type(
    node: Node<'_>,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Option<String> {
    let rhs = node.child_by_field_name("expression").or_else(|| {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "call_expression" {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    if rhs.kind() != "call_expression" {
        return None;
    }
    let callee = rhs.child_by_field_name("function").or_else(|| {
        let mut cursor = rhs.walk();
        let mut found = None;
        for child in rhs.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "simple_identifier" | "identifier" | "navigation_expression" | "user_type"
            ) {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    let callee_text = node_text(&callee, src);
    let canonical = canonical_short_type(callee_text)?;
    declared_type_names.contains(&canonical).then_some(canonical)
}

/// Strip a Kotlin type literal down to its bare class name. Drops
/// generics (`List<String>` -> `List`), array brackets, the nullable
/// `?` suffix, and namespace qualification (`kotlin.String` -> `String`).
fn canonical_short_type(raw: &str) -> Option<String> {
    let no_generics = raw.split('<').next().unwrap_or(raw);
    let no_arrays = no_generics.split('[').next().unwrap_or(no_generics);
    let stripped = no_arrays.trim().trim_end_matches('?');
    let short = stripped.rsplit('.').next().unwrap_or(stripped).trim();
    // Accept any letter prefix — Kotlin types are typically capital
    // (`String`, `List`, `HttpRequest`) but lowercase primitives
    // (`int`, `boolean` via Java interop) are valid too.
    if short.is_empty()
        || !short
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return None;
    }
    Some(short.to_string())
}

/// Preserve the complete source-qualified identity of an explicit Kotlin
/// type while removing only syntax that does not participate in identity.
/// Import expansion is a later compiler step: retaining `Alias.Nested` here
/// lets it prove the exact external type, whereas collapsing eagerly to
/// `Nested` would make unrelated providers indistinguishable.
fn canonical_declared_type(raw: &str) -> Option<String> {
    let no_generics = raw.split('<').next().unwrap_or(raw);
    let no_arrays = no_generics.split('[').next().unwrap_or(no_generics);
    let candidate = no_arrays.trim().trim_end_matches('?').trim();
    let mut segments = candidate.split('.');
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            && segment
                .chars()
                .all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
    };
    let first = segments.next()?;
    if !valid_segment(first) || !segments.all(valid_segment) {
        return None;
    }
    Some(candidate.to_string())
}

/// True for decl kinds that can carry a `bases` list. Shared with the
/// post-processing loop that copies `bases_by_span` onto matching decls.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Kotlin `class_declaration` / `object_declaration` nodes and collect
/// bare base type names. Interfaces use `class_declaration` too.
/// Kotlin grammar shape (verified via tree-sitter `to_sexp`):
///
///   `class Echo : WebSocketHandler(), Mixin { ... }` →
///     (class_declaration (type_identifier)
///        (delegation_specifier (constructor_invocation (user_type (type_identifier))))
///        (delegation_specifier (user_type (type_identifier))))
///
/// Each delegation_specifier wraps either a `constructor_invocation`
/// (parent class with init args) or a bare `user_type` (interface).
/// Both expose a `user_type` whose first `type_identifier` descendant
/// is the bare base name.
fn collect_kotlin_class_bases(
    tree: &Tree,
    file: bonsai_common::FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_table = Vec::new();
    let class_kinds = &["class_declaration", "object_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for child in class_node.named_children(&mut class_cursor) {
            if child.kind() != "delegation_specifier" {
                continue;
            }
            // `delegation_specifier`'s first named child is the
            // parent type — `constructor_invocation` (super-class
            // with args) or bare `user_type` (interface) or
            // `explicit_delegation`.
            let mut spec_cursor = child.walk();
            for spec_child in child.named_children(&mut spec_cursor) {
                if let Some(name) = kotlin_base_name_from(spec_child, src) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                    break;
                }
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), bases));
        }
    }
    bases_table
}

/// Resolve one `delegation_specifier` child to a bare base type name,
/// dispatching on the three shapes Kotlin uses (super call, interface
/// reference, `by`-delegation). Returns `None` for any node that
/// isn't a delegation target.
fn kotlin_base_name_from(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "constructor_invocation" => {
            // Has a `user_type` child carrying the parent class name.
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                if child.kind() == "user_type" {
                    return canonical_short_type(node_text(&child, src));
                }
            }
            None
        }
        "user_type" => canonical_short_type(node_text(&node, src)),
        "explicit_delegation" => {
            // `Foo by bar` — the type is the leading user_type.
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                if child.kind() == "user_type" {
                    return canonical_short_type(node_text(&child, src));
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
