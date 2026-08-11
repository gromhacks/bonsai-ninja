//! PHP language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, collect_kinds, first_named_child_of_kind, language_from_pack,
        named_child_call_args_with_handler, node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, AssignmentValueIndex, CallArg, CallKind,
    CallTargetExtraction, DeclIndex, DeclKind, FieldWrite, FlowEvent, FragmentParseContext, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModifierVocabulary, TypeAliasVocabulary, Visibility, EMPTY_HANDLER,
};
use std::collections::BTreeSet;
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
    modifier_container_kinds: &["visibility_modifier", "modifier"],
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
    let arguments = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument_list"))?;
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
    if node.kind() != "string" {
        return None;
    }
    let text = node_text(&node, src).trim();
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || text.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let value = text.get(1..text.len().checked_sub(1)?)?;
    (!value.contains('\\')).then(|| value.to_string())
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
    non_binding_pattern_field_names: &["type", "key"],
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
    assignment_target_wrapper_kinds: &["variable_declaration", "property_element"],
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
    // tree-sitter-php wraps every positional argument in `argument`; named
    // arguments use the dedicated `named_argument` shape. Unwrapping both is
    // required for an addressable `$value` to remain an exact CallArg place.
    argument_wrapper_kinds: &["argument", "named_argument"],
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
    member_expression_kinds: &[
        "member_access_expression",
        "member_expression",
        "nullsafe_member_access_expression",
    ],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["object"],
    member_name_field_names: &["name"],
    subscript_base_field_names: &["object"],
    subscript_index_field_names: &["index"],
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
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["compound_statement", "expression_statement"],
    branch_arm_kinds: &["compound_statement", "else_clause", "else_if_clause"],
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
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        let parsed = parse_with(PACK_NAME, file, ctx);
        let source = parsed
            .as_ref()
            .map(|(snapshot, _)| snapshot.text.to_string())
            .unwrap_or_default();
        // Synthesize Call FlowEvents for PHP language constructs the
        // tree-sitter grammar exposes as dedicated expression kinds
        // rather than call_expression nodes:
        //   - `include $tainted` / `include_once $tainted`
        //   - `require $tainted` / `require_once $tainted`
        //   - `` `cmd $tainted` `` (shell_command_expression)
        // Without this lowering the shipped php.eval.{include,require}_*
        // and php.cmdi.backtick rules can't match real code.
        if let Some((_, tree)) = parsed.as_ref() {
            let synthesized = synthesize_php_construct_events(tree, source.as_bytes(), file);
            if !synthesized.is_empty() {
                attach_synthesized_calls_to_decls(&mut idx, synthesized);
            }
        }
        // Use the `namespace Foo\Bar;` segments as the module path so
        // private symbols cross-link only inside the namespace.
        let namespace_segments = parsed
            .as_ref()
            .and_then(|(snapshot, tree)| extract_php_namespace(tree.root_node(), snapshot.text.as_bytes()));
        if let Some(segments) = namespace_segments {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            // No `namespace` declaration — fall back to file-stem.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            let visibility_by_span = collect_modifier_visibility(tree.root_node(), file, src, &PHP_VOCAB);
            let aliases_by_span = collect_param_type_aliases(tree, file, src, &PHP_TYPE_ALIASES);
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
            let bases_by_span = collect_php_class_bases(tree, file, src);
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
            let promoted_writes_by_span = collect_php_property_promotion_writes(tree, file, src);
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
        let assignment_values = AssignmentValueIndex::new(&idx.assignment_values);
        for decl in &mut idx.defs {
            let invoked_variables = php_invoked_variables(&decl.flow_events);
            augment_php_quoted_callable_literals(
                &mut decl.flow_events,
                &source,
                &assignment_values,
                &invoked_variables,
            );
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
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
    source: &str,
    assignment_values: &AssignmentValueIndex,
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
                    if let Some(rhs) = assignment_values.rendering(*span, source) {
                        if let Some(callable) = target
                            .trim_start()
                            .starts_with('$')
                            .then(|| php_quoted_bare_callable_literal(rhs))
                            .flatten()
                        {
                            *source_name = Some(callable.to_string());
                            *value_kind = Some(AssignValueKind::CallableReference);
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_php_quoted_callable_literals(
                    then_events,
                    source,
                    assignment_values,
                    invoked_variables,
                );
                augment_php_quoted_callable_literals(
                    else_events,
                    source,
                    assignment_values,
                    invoked_variables,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_php_quoted_callable_literals(body, source, assignment_values, invoked_variables);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_php_quoted_callable_literals(body, source, assignment_values, invoked_variables);
                augment_php_quoted_callable_literals(
                    catch_events,
                    source,
                    assignment_values,
                    invoked_variables,
                );
                augment_php_quoted_callable_literals(
                    finally_events,
                    source,
                    assignment_values,
                    invoked_variables,
                );
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

fn php_quoted_bare_callable_literal(value: &str) -> Option<&str> {
    let value = value.trim();
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || value.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let inner = value.get(1..value.len().saturating_sub(1))?.trim();
    if inner.is_empty()
        || inner
            .chars()
            .any(|ch| !(ch == '_' || ch == '\\' || ch.is_ascii_alphanumeric()))
        || inner.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    Some(inner)
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
        let raw = node_text(&clause, src)
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .trim();
        if raw.is_empty() {
            continue;
        }
        // Split off `as Alias` if present.
        let (module_text, explicit_alias) = if let Some((module_part, alias_part)) = raw.rsplit_once(" as ") {
            (
                module_part.trim().to_string(),
                Some(alias_part.trim().to_string()),
            )
        } else {
            (raw.to_string(), None)
        };
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
                    let text = node_text(&child, src).trim_end_matches('\\').trim().to_string();
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
            // Prefer the unquoted `string_content` child; otherwise
            // strip surrounding quotes manually.
            if let Some(content) = first_named_child_of_kind(&current, "string_content") {
                return node_text(&content, src).to_string();
            }
            return node_text(&current, src)
                .trim_matches(|ch: char| matches!(ch, '"' | '\''))
                .to_string();
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
///   - shell_command_expression     → name = "shell_exec" (matches
///     the existing php.cmdi.shell_exec rule's name without needing
///     a new rule for backtick literal)
///
/// The expression's argument (the included path / shell command)
/// becomes a single positional CallArg whose `value_text` is the
/// argument's source text — typically a `variable_name` like `$t`
/// or a string literal. The taint engine reads `value_text` to
/// decide whether the argument is tainted.
fn synthesize_php_construct_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    // Pairs of (grammar kind, synthesized callee name). The callee
    // name must match what the rulepack queries against.
    const CONSTRUCT_KINDS: &[(&str, &str)] = &[
        ("include_expression", "include"),
        ("include_once_expression", "include_once"),
        ("require_expression", "require"),
        ("require_once_expression", "require_once"),
        ("shell_command_expression", "shell_exec"),
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
/// `interface_declaration` uses its own `interface_base_clause` (just
/// `extends`). `trait_declaration` has no parent list.
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
                "base_clause" | "class_interface_clause" | "interface_base_clause" => {
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
}
