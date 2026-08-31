//! Scala language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, call_arg_from_nodes_with_handler, collect_kinds,
        collect_receiver_field_writes, first_named_child_of_kind, foreach_binding_assigns_from_nodes,
        language_from_pack, looks_like_bare_identifier, node_at_span, node_text,
        normalize_call_name_whitespace, package_module_segments_with_workspace_prefix, parse_with,
        pattern_binding_sites_from_arms, span_of, walk_flow_events, walk_flow_node_into,
    },
    AdapterContext, AdapterError, CallArg, CallKind, CallTargetExtraction, Decl, DeclIndex, DeclKind,
    FieldWrite, FlowEvent, GrammarHandler, ImplicitMemberReadCall, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, PatternBindingSite, StaticScalarValue,
    TypeAliasBinding, Visibility, EMPTY_HANDLER,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

fn scala_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = match node.kind() {
        "call_expression" | "generic_function" => node.child_by_field_name("function")?,
        // tree-sitter-scala gives constructor arguments a field but leaves
        // the constructor type as the first named child.
        "instance_expression" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0))
            .filter(|target| {
                matches!(
                    target.kind(),
                    "type_identifier" | "stable_type_identifier" | "generic_type" | "projected_type"
                )
            })?,
        _ => return None,
    };
    // Scala currying is represented as a call whose `function` is the
    // preceding call expression: `parameters("q") { q => ... }`. Preserve
    // the outer call's distinct compiler span, but normalize its callable
    // identity to the grammar-declared inner callee. This lets generic
    // callback-argument facts describe the second parameter list without
    // treating the directive-constructor result as request data.
    let full_text = if matches!(target.kind(), "call_expression" | "generic_function") {
        scala_call_target(target, src)?.full_text
    } else {
        node_text(&target, src).trim().to_string()
    };
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

fn scala_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for_expression" {
        return None;
    }
    let enumerators = node
        .child_by_field_name("enumerators")
        .filter(|child| matches!(child.kind(), "enumerators" | "enumerator"))
        .or_else(|| {
            let mut cursor = node.walk();
            let found = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "enumerators");
            found
        })
        .or_else(|| node.named_child(0))?;
    // This grammar exposes one `enumerator` as the container's first named
    // child. Selecting it positionally is exact and also survives language-
    // pack builds where the node kind is hidden behind an alias.
    let enumerator = if enumerators.kind() == "enumerator" {
        enumerators
    } else {
        enumerators.named_child(0)?
    };
    Some((enumerator.named_child(0)?, enumerator.named_child(1)?))
}

fn scala_pattern_bindings(node: Node<'_>) -> Vec<PatternBindingSite<'_>> {
    if node.kind() != "match_expression" {
        return Vec::new();
    }
    pattern_binding_sites_from_arms(node, &["value"], &["case_clause"], &["pattern"], &[])
}

/// Retain complete nominal type paths from Scala declarations and attach the
/// provider-qualified identity proven by one exact explicit import.
///
/// The shared parameter collector intentionally exposes the terminal type for
/// cross-language dispatch (`Client.Builder` -> `Builder`). Scala also uses
/// nested types as ordinary receiver identities, so discarding the enclosing
/// path loses the distinction between two providers' same-named builders.
/// Keep all three compiler facts when they are available:
///
/// - the terminal type emitted by the shared collector;
/// - the complete source type (`Client.Builder`);
/// - the complete imported type (`provider.api.Client.Builder`).
///
/// Wildcard and conflicting explicit imports cannot prove one provider and do
/// not synthesize the last identity.
fn collect_scala_declared_type_identities(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
    imports: &[ImportSpec],
) -> HashMap<Span, Vec<TypeAliasBinding>> {
    let explicit_imports = imports
        .iter()
        .filter(|import| !import.is_wildcard)
        .filter_map(scala_explicit_import_type_identity)
        .collect::<Vec<_>>();

    let mut aliases_by_decl = HashMap::<Span, Vec<TypeAliasBinding>>::new();
    for node in collect_kinds(
        tree,
        &["parameter", "class_parameter", "val_definition", "var_definition"],
    ) {
        let Some((name, source_type)) = scala_declared_nominal_type_binding(node, src) else {
            continue;
        };
        let node_span = span_of(file, &node);
        let Some(owner) = index
            .defs
            .iter()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && span_contains(decl.span, node_span)
            })
            .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
        else {
            continue;
        };
        let aliases = aliases_by_decl.entry(owner.span).or_default();
        if let Some(short) = canonical_simple_type_name(&source_type) {
            push_scala_type_alias(aliases, &name, &short);
        }
        push_scala_type_alias(aliases, &name, &source_type);
        let head = source_type.split('.').next().unwrap_or_default();
        let tail = source_type.strip_prefix(head).unwrap_or_default();
        let qualified = explicit_imports
            .iter()
            .filter(|(local, _)| local == head)
            .map(|(_, target)| format!("{target}{tail}"))
            .collect::<HashSet<_>>();
        if qualified.len() == 1 {
            if let Some(type_name) = qualified.into_iter().next() {
                push_scala_type_alias(aliases, &name, &type_name);
            }
        }
    }
    aliases_by_decl
}

fn scala_declared_nominal_type_binding(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    let name_node = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("pattern"))?;
    let name = node_text(&name_node, src).trim();
    if !looks_like_bare_identifier(name) {
        return None;
    }
    let type_node = node.child_by_field_name("type")?;
    let nominal = scala_nominal_type_node(type_node)?;
    let type_name = node_text(&nominal, src).trim();
    let valid_path = !type_name.is_empty() && type_name.split('.').all(looks_like_bare_identifier);
    valid_path.then(|| (name.to_string(), type_name.to_string()))
}

fn scala_nominal_type_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "type_identifier" | "stable_type_identifier" => Some(node),
        "generic_type" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0))
            .and_then(scala_nominal_type_node),
        _ => None,
    }
}

fn scala_explicit_import_type_identity(import: &ImportSpec) -> Option<(String, String)> {
    let local = import
        .alias
        .clone()
        .or_else(|| import.original_name.clone())
        .or_else(|| bonsai_lang_api::module_local_binding(&import.module))?;
    let target = match import.original_name.as_deref() {
        Some(original) if import.module.is_empty() => original.to_string(),
        Some(original) => format!("{}.{original}", import.module),
        None => import.module.clone(),
    };
    let target = bonsai_common::normalize_qualified_name(&target);
    (!local.is_empty() && !target.is_empty()).then_some((local, target))
}

fn push_scala_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    let binding = TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    };
    if !aliases.contains(&binding) {
        aliases.push(binding);
    }
}

const SCALA_DECL_KINDS: &[&str] = &[
    "function_definition",
    "function_declaration",
    "class_definition",
    "object_definition",
    "trait_definition",
    "type_definition",
    "val_definition",
    "var_definition",
];
use tree_sitter::{Language, Tree};
// (`Node` brought into scope above so class-scoped helpers can pass nodes around.)

pub const LANG_ID: LanguageId = LanguageId::new("scala");
const PACK_NAME: &str = "scala";
const MODULE_SOURCE_ROOTS: &[&[&str]] = &[
    &["src", "main", "scala"],
    &["src", "test", "scala"],
    &["src", "scala"],
];

fn extract_scala_syntax_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "throw_expression" {
        return None;
    }
    let value = node.named_child(0)?;
    let flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(value, file, src, handler);
    let value_name = {
        let mut sources = bonsai_lang_api::kit::expression_operand_names_with_handler(&value, src, handler);
        sources.extend(flow.source_names);
        sources.sort();
        sources.dedup();
        if sources.len() == 1 {
            Some(sources.remove(0))
        } else if sources.is_empty() {
            flow.place
        } else {
            None
        }
    };
    Some(FlowEvent::Throw {
        span: span_of(file, &node),
        value_name,
        thrown_type: None,
    })
}

const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &[
        "null_literal",
        "boolean_literal",
        "integer_literal",
        "floating_point_literal",
        "true",
        "false",
    ],
    string_literal_kinds: &["string", "interpolated_string_expression", "character_literal"],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["/**"],
    decorator_kinds: &["annotation"],
    parameter_container_kinds: &["parameters"],
    parameter_kinds: &["parameter", "class_parameter"],
    parameter_annotation_kinds: &["annotation"],
    // `value: T*` is one ordinary `parameter` whose `type` child is the
    // grammar's `repeated_parameter_type`; direct-call signature lowering
    // checks one wrapper level beneath the parameter.
    variadic_parameter_kinds: &["repeated_parameter_type"],
    binding_identifier_kinds: &["identifier"],
    pattern_binding_extractor: Some(scala_pattern_bindings),
    identifier_kinds: &["identifier"],
    aggregate_pattern_kinds: &["tuple_pattern"],
    positional_aggregate_kinds: &["tuple_expression"],
    transparent_call_wrapper_kinds: &["field_expression", "parenthesized_expression"],
    assignment_target_wrapper_kinds: &["val_definition", "var_definition"],
    binding_declaration_keyword_spellings: &["val", "var"],
    fn_kinds: &["function_definition", "function_declaration"],
    class_kinds: &[
        "class_definition",
        "object_definition",
        "trait_definition",
        "enum_definition",
    ],
    class_decl_kinds: &[
        ("class_definition", DeclKind::Class),
        ("object_definition", DeclKind::Class),
        ("trait_definition", DeclKind::Trait),
        ("enum_definition", DeclKind::Enum),
    ],
    method_context_kinds: &[
        "class_definition",
        "object_definition",
        "trait_definition",
        "enum_definition",
    ],
    if_kinds: &["if_expression", "match_expression"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    condition_not_operator_kinds: &[],
    loop_body_field_names: &["body"],
    // Scala's `for_expression` exposes both expression and block bodies via
    // the named `body` field, so only the actual block node is needed as a
    // defensive fallback.
    loop_body_kinds: &["block"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &[],
    loop_condition_field_names: &["condition"],
    branch_arm_kinds: &["block", "case_clause"],
    exclusive_branch_arm_kinds: &["case_clause"],
    fallthrough_branch_arm_kinds: &[],
    for_kinds: &[],
    foreach_kinds: &["for_expression"],
    foreach_binding_extractor: Some(scala_foreach_binding),
    while_kinds: &["while_expression"],
    do_kinds: &["do_while_expression"],
    // `generic_function` is a type application used as the callee of an
    // enclosing `call_expression`; it is not a second runtime invocation.
    call_kinds: &["call_expression", "instance_expression"],
    constructor_call_kinds: &["instance_expression"],
    call_callee_field_names: &["function"],
    constructor_type_field_names: &["type"],
    call_target_extractor: Some(scala_call_target),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["arguments"],
    call_callee_is_first_named_child: true,
    lambda_body_field_names: &["body"],
    pseudo_call_extractor: Some(extract_scala_pseudo_call),
    syntax_event_extractor: Some(extract_scala_syntax_event),
    pseudo_call_receiver_extractor: Some(extract_scala_pseudo_call_receiver),
    argument_passing_mode_extractor: None,
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    call_ref_kinds: &["call_expression", "instance_expression"],
    member_expression_kinds: &["field_expression"],
    member_base_field_names: &["value"],
    member_name_field_names: &["field", "name"],
    assignment_kinds: &[
        "assignment_expression",
        "val_definition",
        "var_definition",
        "var_declaration",
    ],
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="],
    type_only_declaration_kinds: &["var_declaration", "val_definition", "var_definition"],
    return_kinds: &["return_expression"],
    throw_kinds: &[],
    // A `case_block` passed as a value is a Scala PartialFunction: an
    // anonymous callable with capture-pattern parameters, not execution in
    // the enclosing template initializer.
    lambda_kinds: &["lambda_expression", "case_block"],
    lambda_body_kinds: &["case_block"],
    try_kinds: &["try_expression"],
    try_body_field_names: &["body"],
    catch_kinds: &["catch_clause"],
    exclusive_catch_arm_kinds: &["case_clause"],
    finally_kinds: &["finally_clause"],
    // Scala block-bodied `def f() = { …; tailExpr }` returns its tail
    // expression. The body node kind is `block` (never descended by
    // implicit-return synthesis), so — like Rust and Ruby — the tail
    // Return is emitted by the tail-expression path. Without this the
    // dominant Scala function shape emits NO Return, breaking
    // interprocedural return-taint. Expression-bodied `def f = expr`
    // keeps its existing direct-body Return (the caller prefers that
    // path and both emitters dedupe on span).
    tail_expression_returns: true,
    // A `def f(...): Unit = { …; log(x) }` returns no value; its tail is a
    // side-effecting call that consumes `x`, not one that returns it.
    // Suppress the synthetic tail Return so the argument isn't tokenised
    // into an over-tainted return that leaks to the caller.
    void_return_type_names: &["Unit"],
    implicit_receiver_names: &["this", "super"],
    ..EMPTY_HANDLER
};

/// Scala CST kinds consumed by adapter-owned normalization after/beside the
/// shared handler. The conformance suite validates this inventory against the
/// actual grammar so custom compiler facts cannot decay across parser updates.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("call-target", "call_expression"),
    ("call-target", "generic_function"),
    ("call-target", "instance_expression"),
    ("call-target", "type_identifier"),
    ("call-target", "stable_type_identifier"),
    ("call-target", "generic_type"),
    ("call-target", "projected_type"),
    ("foreach-binding", "for_expression"),
    ("foreach-binding", "enumerators"),
    ("foreach-binding", "enumerator"),
    ("pattern-bindings", "match_expression"),
    ("throw-value", "throw_expression"),
    ("postfix-call", "field_expression"),
    ("postfix-call", "infix_expression"),
    ("postfix-call", "operator_identifier"),
    ("template-initializer", "class_definition"),
    ("template-initializer", "object_definition"),
    ("template-initializer", "trait_definition"),
    ("template-initializer", "enum_definition"),
    ("template-initializer", "template_body"),
    ("template-initializer", "val_definition"),
    ("template-initializer", "var_definition"),
    ("partial-function", "case_block"),
    ("partial-function", "case_clause"),
    ("partial-function", "capture_pattern"),
    ("constructors", "class_parameters"),
    ("constructors", "class_parameter"),
    ("constructors", "parameter"),
    ("constructors", "arguments"),
    ("constructors", "assignment_expression"),
    ("constructors", "identifier"),
    ("case-class", "case"),
    ("case-class", "modifiers"),
    ("type-aliases", "function_definition"),
    ("type-aliases", "function_declaration"),
    ("imports", "import_declaration"),
    ("imports", "namespace_selectors"),
    ("imports", "as_renamed_identifier"),
    ("imports", "arrow_renamed_identifier"),
    ("imports", "namespace_wildcard"),
    ("imports", "wildcard"),
    ("visibility", "access_qualifier"),
    ("package", "package_clause"),
    ("package", "package_identifier"),
    ("package", "stable_identifier"),
];

fn extract_scala_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() == "field_expression" && scala_postfix_operator_call(node) {
        let receiver = node
            .child_by_field_name("value")
            .or_else(|| node.named_child(0))?;
        let name = normalize_call_name_whitespace(node_text(&node, src));
        return (!name.is_empty()).then(|| FlowEvent::Call {
            span: span_of(file, &node),
            receiver: Some(normalize_call_name_whitespace(node_text(&receiver, src))),
            receiver_types: Vec::new(),
            name,
            call_kind: CallKind::Method,
            args: Vec::new(),
        });
    }
    if node.kind() != "infix_expression" {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let operator = node.child_by_field_name("operator")?;
    let name = node_text(&operator, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut args = Vec::new();
    let (receiver, call_kind) = if looks_like_bare_identifier(&name) {
        args.push(call_arg_from_node_with_handler(right, file, src, None, handler)?);
        (
            Some(normalize_call_name_whitespace(node_text(&left, src))),
            CallKind::Method,
        )
    } else {
        args.push(call_arg_from_node_with_handler(left, file, src, None, handler)?);
        args.push(call_arg_from_node_with_handler(right, file, src, None, handler)?);
        (None, CallKind::Operator)
    };
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver,
        receiver_types: Vec::new(),
        name,
        call_kind,
        args,
    })
}

fn scala_postfix_operator_call(node: Node<'_>) -> bool {
    // Tree-sitter distinguishes Scala's explicit postfix-call grammar from
    // ordinary stable-member selection through the terminal node kind. Only
    // the former is an invocation fact. A source `value.field` remains a
    // value projection; declaration-aware accessor rewrites later in this
    // adapter add calls only when an exact compiler member proves one.
    let mut cursor = node.walk();
    let is_postfix = node
        .named_children(&mut cursor)
        .any(|child| child.kind() == "operator_identifier");
    is_postfix
}

fn extract_scala_pseudo_call_receiver<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    match node.kind() {
        "field_expression" if scala_postfix_operator_call(node) => {
            node.child_by_field_name("value").or_else(|| node.named_child(0))
        }
        "infix_expression" => {
            let operator = node.child_by_field_name("operator")?;
            looks_like_bare_identifier(node_text(&operator, src).trim())
                .then(|| node.child_by_field_name("left"))
                .flatten()
        }
        _ => None,
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct ScalaAdapter;

impl ScalaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ScalaAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Scala"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["scala", "sc"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Pattern matching: the adapter post-processes flat `Branch`
        // events emitted for `match_expression`s into nested `Branch`
        // chains so the engine forks state per arm. Each arm's body
        // sees a fresh copy of the pre-match taint state, runs in
        // isolation, and unions back at the merge — yielding
        // path-disjoint precision instead of the over-approximate
        // "any arm's taint reaches every other arm's body."
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Any", "AnyRef", "Object"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            pattern_matching: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            // Scala companion/object `apply` syntax invokes a declared type
            // identity without `new`. Shared resolution still requires an
            // exact scoped class/object declaration before treating the bare
            // call as construction; spelling alone never proves it.
            bare_call_constructor_syntax: true,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &[],
                class_object_suffixes: &[".class"],
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
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            normalize_scala_for_enumerator_bindings(&mut idx, tree, file, src);
            // Phase-6 return-type extraction: `def f(): T = ...` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, tree, src, &HANDLER);
            synthesize_scala_template_initializer_decls(&mut idx, tree, file, src);
            normalize_scala_partial_function_call_arguments(&mut idx, tree, file, src);
            remove_scala_partial_function_body_leaks(&mut idx, tree, file);
            lower_scala_match_case_bodies(&mut idx, tree, file, src);
            // Object initializer calls were added after the shared callable
            // lowering pass, so rebuild argument facts from the complete
            // adapter-owned flow inventory before framework-agnostic callback
            // post-processing.
            idx.call_argument_values =
                bonsai_lang_api::kit::extract_call_argument_value_facts(tree, file, &idx.defs, src, &HANDLER);
            let arm_spans = collect_scala_match_arm_spans(tree, src, file);
            let case_guards = collect_scala_case_guard_conditions(tree, file, src);
            for decl in &mut idx.defs {
                bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
                annotate_scala_case_guard_branches(&mut decl.flow_events, &case_guards);
                annotate_scala_named_call_args(&mut decl.flow_events, tree.root_node(), file, src);
            }
            idx.branch_conditions
                .extend(case_guards.iter().map(|(fact, _)| fact.clone()));
            idx.branch_conditions.sort_by_key(|fact| {
                (
                    fact.branch_span.start,
                    fact.branch_span.end,
                    fact.condition_span.start,
                    fact.condition_span.end,
                )
            });
            idx.branch_conditions.dedup();
            populate_scala_partial_function_callback_facts(&mut idx, tree, file, src);
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                tree,
                file,
                src,
                &HANDLER,
                scala_static_scalar,
            );
            populate_scala_immutable_static_values(&mut idx, tree, file, src);
            normalize_scala_nullary_call_assignments(&mut idx, tree, file, src);
            let finite_literal_selections = collect_scala_finite_literal_selections(&idx, tree, file);
            idx.finite_literal_selections.extend(finite_literal_selections);
            bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut idx.finite_literal_selections);
            bonsai_lang_api::kit::populate_assignment_inline_callback_static_returns(
                &mut idx,
                tree,
                src,
                &HANDLER,
                scala_static_scalar,
            );
        }
        let pkg_segments = parsed
            .as_ref()
            .and_then(|(snapshot, tree)| extract_scala_package(tree.root_node(), snapshot.text.as_bytes()));
        if let Some(segments) = pkg_segments {
            let segments =
                package_module_segments_with_workspace_prefix(file, ctx, segments, MODULE_SOURCE_ROOTS);
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_scala_visibility(tree.root_node(), file, src);
            let imports = parse_imports(tree, src, file);
            let alias_map = collect_scala_declared_type_identities(&idx, tree, file, src, &imports);
            let method_owners = collect_scala_method_owners(tree, file);
            let class_symbols: Vec<(Span, SymbolId)> = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .map(|decl| (decl.span, decl.symbol))
                .collect();
            // Class-level field type bindings — `private val
            // authService = new AuthService()` makes
            // `authService: AuthService` visible inside every method
            // of the enclosing class. Without this, the engine cannot
            // dispatch `authService.runAdminCommand(...)` to the real
            // `AuthService` decl.
            let declared_type_names = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .flat_map(|decl| std::iter::once(decl.name.clone()).chain(decl.qualified_name.clone()))
                .filter_map(|name| canonical_simple_type_name(&name))
                .collect::<std::collections::HashSet<_>>();
            let class_field_aliases =
                collect_scala_class_field_aliases(tree, file, src, &declared_type_names);
            // WS2: method-local `val c = make().asInstanceOf[Foo]` casts,
            // keyed by the enclosing method span (the class-field walk
            // skips method bodies, and the kit vocabulary only types
            // explicitly-annotated locals).
            let local_cast_aliases = collect_scala_local_cast_aliases(tree, file, src);
            synthesize_scala_constructor_decls(&mut idx, file, tree, src);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                let mut aliases = alias_map.get(&decl.span).cloned().unwrap_or_default();
                if let Some(casts) = local_cast_aliases
                    .iter()
                    .find_map(|(span, list)| (*span == decl.span).then_some(list))
                {
                    for alias in casts {
                        if !aliases.contains(alias) {
                            aliases.push(alias.clone());
                        }
                    }
                }
                if let Some((_, owner_span, owner_kind)) =
                    method_owners.iter().find(|(span, _, _)| *span == decl.span)
                {
                    if let Some((_, owner_symbol)) = class_symbols.iter().find(|(span, _)| span == owner_span)
                    {
                        decl.parent = Some(*owner_symbol);
                        decl.kind = DeclKind::Method;
                        if *owner_kind != "object_definition" && decl.implicit_receiver_names.is_empty() {
                            decl.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
                        }
                    }
                    if let Some(field_aliases) = class_field_aliases
                        .iter()
                        .find_map(|(span, list)| (*span == *owner_span).then_some(list))
                    {
                        for alias in field_aliases {
                            // A method parameter/local with the same binding
                            // name is the lexical receiver identity at that
                            // call site. Do not retain the captured class
                            // constructor parameter as a second possible type.
                            if !aliases.iter().any(|existing| existing.name == alias.name) {
                                aliases.push(alias.clone());
                            }
                        }
                    }
                }
                if !aliases.is_empty() {
                    decl.type_aliases = aliases;
                }
            }
            // Per-class `bases`: `class C extends Base with Mixin` →
            // ["Base", "Mixin"]. Scala wraps every parent (extends +
            // with) under a single `extends_clause` whose `type:`
            // fields list each parent.
            let bases_by_span = collect_scala_class_bases(tree, file, src);
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
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Mirror the lang_csharp / lang_dart synthesis passes: convert a method
        // body that's a simple dotted receiver field read
        // (`def cmd: String = data.cmd`) into a `Call+Return` chain
        // (lets the 1-level receiver-field bridge resolve it through
        // a record/case-class component accessor instead of staying
        // as a 2-level field read); qualify bare reads of sibling
        // zero-arg members (`val c = cmd`) by inserting an explicit
        // `Call` event so `walk_call`'s args-empty fallback creates
        // a `CallArg{idx=0}` recv-slot for the receiver bridge.
        rewrite_scala_member_access_accessors(&mut idx);
        qualify_scala_implicit_member_reads(&mut idx);
        // Scala compiles concrete `val`/`var` members and case-class
        // components to parameterless accessors. Surface those exact
        // compiler members so a pseudo-call emitted for `receiver.field`
        // resolves to a getter whose return reads `this.field`. This covers
        // ordinary classes/objects as well as case classes; abstract trait
        // declarations remain unresolved until an implementation proves a
        // body.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            synthesize_scala_stored_property_accessors(&mut idx, tree, file, snapshot.text.as_bytes());
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`val c = new Foo()`
        // / `Foo()` → `c: Foo`) so `c.method(...)` carries a resolved
        // receiver type for `receiver_type_in` / `[Type, method]` rules.
        // Constructor identity comes from `new` syntax or an exact type
        // declaration, never capitalization.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        // Scala adds constructor-property aliases and rewrites property
        // selections after the generic declaration pass. Re-run the shared
        // AST/type-fact projection once those facts exist so synthesized
        // `data.cmd` calls carry `data: Envelope` and resolve the case-class
        // accessor without any member-name inventory.
        bonsai_lang_api::apply_call_receiver_types_with_super_tokens(&mut idx, &["super"]);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Scala permits a parameterless method invocation to be written as a plain
/// member selection. The generic assignment lowerer can therefore select an
/// inner parenthesized call (`Paths.get`) instead of the value-producing outer
/// nullary call (`normalize`). Re-anchor those assignments to the exact
/// outermost compiler-emitted call. API meaning remains rulepack-owned.
fn normalize_scala_nullary_call_assignments(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut overrides = Vec::new();
    for fact in &mut idx.assignment_values {
        let outer = idx
            .defs
            .iter()
            .flat_map(|decl| scala_calls_within(&decl.flow_events, fact.value_span))
            .find(|call| call.span == fact.value_span)
            .or_else(|| scala_nullary_member_selection(tree, file, src, fact.value_span));
        let Some(call) = outer else { continue };
        fact.direct_call_name = Some(call.name.to_string());
        fact.direct_call_receiver = call.receiver.clone().or_else(|| {
            idx.call_receivers
                .iter()
                .find(|receiver| receiver.call_span == call.span)
                .and_then(|receiver| {
                    receiver
                        .value_flow
                        .projection
                        .as_ref()
                        .map(bonsai_lang_api::ExpressionProjection::canonical_place)
                        .or_else(|| receiver.value_flow.place.clone())
                })
        });
        if !fact.call_sites.contains(&call.span) {
            fact.call_sites.push(call.span);
            fact.call_sites.sort_unstable();
            fact.call_sites.dedup();
        }
        overrides.push((fact.assignment_span, call));
    }
    for decl in &mut idx.defs {
        normalize_scala_nullary_call_assignments_in_events(&mut decl.flow_events, &overrides);
    }
}

#[derive(Clone)]
struct ScalaCallSummary {
    span: Span,
    name: String,
    receiver: Option<String>,
    args: Vec<String>,
}

/// Return the exact outer member-selection value of a Scala assignment.
///
/// Scala permits a parameterless method to be selected without parentheses,
/// so Tree-sitter correctly represents both a field read and a nullary method
/// application as `field_expression`.  The adapter records that syntax as a
/// candidate value-producing member; rulepack targets or an exact workspace
/// declaration supply the callable meaning.  No library/member spelling is
/// interpreted here.
fn scala_nullary_member_selection(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    value_span: Span,
) -> Option<ScalaCallSummary> {
    let node = node_at_span(tree.root_node(), value_span, &["field_expression"])?;
    if node.kind() != "field_expression" || span_of(file, &node) != value_span {
        return None;
    }
    let receiver = node
        .child_by_field_name("value")
        .or_else(|| node.named_child(0))?;
    let field = node
        .child_by_field_name("field")
        .or_else(|| node.named_child(1))?;
    let receiver = normalize_call_name_whitespace(node_text(&receiver, src));
    let field = node_text(&field, src).trim();
    if receiver.is_empty() || !looks_like_bare_identifier(field) {
        return None;
    }
    Some(ScalaCallSummary {
        span: value_span,
        name: format!("{receiver}.{field}"),
        receiver: Some(receiver),
        args: Vec::new(),
    })
}

fn scala_calls_within(events: &[FlowEvent], span: Span) -> Vec<ScalaCallSummary> {
    let mut calls = Vec::new();
    fn visit(events: &[FlowEvent], span: Span, calls: &mut Vec<ScalaCallSummary>) {
        for event in events {
            match event {
                FlowEvent::Call {
                    span: call_span,
                    name,
                    args,
                    ..
                } if call_span.file == span.file
                    && call_span.start >= span.start
                    && call_span.end <= span.end =>
                {
                    calls.push(ScalaCallSummary {
                        span: *call_span,
                        name: name.clone(),
                        receiver: None,
                        args: args.iter().map(|arg| arg.value_text.clone()).collect(),
                    });
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    visit(then_events, span, calls);
                    visit(else_events, span, calls);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => visit(body, span, calls),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    visit(body, span, calls);
                    visit(catch_events, span, calls);
                    visit(finally_events, span, calls);
                }
                _ => {}
            }
        }
    }
    visit(events, span, &mut calls);
    calls
}

fn normalize_scala_nullary_call_assignments_in_events(
    events: &mut [FlowEvent],
    overrides: &[(Span, ScalaCallSummary)],
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                value_kind,
                ..
            } => {
                if let Some(call) = overrides
                    .iter()
                    .find_map(|(assignment, call)| (*assignment == *span).then_some(call))
                {
                    *source_name = None;
                    *source_call = Some(call.name.clone());
                    source_call_args.clone_from(&call.args);
                    *value_kind = Some(bonsai_lang_api::AssignValueKind::CallResult);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_scala_nullary_call_assignments_in_events(then_events, overrides);
                normalize_scala_nullary_call_assignments_in_events(else_events, overrides);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_scala_nullary_call_assignments_in_events(body, overrides);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_scala_nullary_call_assignments_in_events(body, overrides);
                normalize_scala_nullary_call_assignments_in_events(catch_events, overrides);
                normalize_scala_nullary_call_assignments_in_events(finally_events, overrides);
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
struct ScalaForEnumeratorBinding {
    loop_span: Span,
    value_span: Span,
    assigns: Vec<FlowEvent>,
}

/// Preserve the runtime order and complete binding set of Scala `for`
/// comprehensions.
///
/// The shared loop contract intentionally models the common one-binding loop
/// shape. Scala instead represents every generator as an ordered `enumerator`
/// child. Tree-sitter walks all generator calls before the shared synthetic
/// binding, which would make a later generator consume its predecessor before
/// that predecessor exists. Replace that one synthetic binding with one exact
/// assignment per enumerator and insert each immediately after its own value
/// expression. This is syntax lowering only; provider and security meaning
/// remain in rule data.
fn normalize_scala_for_enumerator_bindings(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut bindings = Vec::new();
    for for_expression in collect_kinds(tree, &["for_expression"]) {
        let Some(enumerators) = for_expression
            .child_by_field_name("enumerators")
            .filter(|child| matches!(child.kind(), "enumerators" | "enumerator"))
            .or_else(|| {
                let mut cursor = for_expression.walk();
                let found = for_expression
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "enumerators");
                found
            })
        else {
            continue;
        };
        let enumerator_nodes = if enumerators.kind() == "enumerator" {
            vec![enumerators]
        } else {
            let mut cursor = enumerators.walk();
            enumerators
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "enumerator")
                .collect::<Vec<_>>()
        };
        for enumerator in enumerator_nodes {
            let (Some(pattern), Some(value)) = (enumerator.named_child(0), enumerator.named_child(1)) else {
                continue;
            };
            let mut assigns =
                foreach_binding_assigns_from_nodes(file, enumerator, pattern, value, src, &HANDLER);
            for assign in &mut assigns {
                if let FlowEvent::Assign {
                    declares_new_binding, ..
                } = assign
                {
                    *declares_new_binding = true;
                }
            }
            if !assigns.is_empty() {
                bindings.push(ScalaForEnumeratorBinding {
                    loop_span: span_of(file, &for_expression),
                    value_span: span_of(file, &value),
                    assigns,
                });
            }
        }
    }
    bindings.sort_by_key(|binding| (binding.loop_span.start, binding.value_span.start));
    let mut bindings_by_loop = HashMap::<Span, Vec<ScalaForEnumeratorBinding>>::new();
    for binding in bindings {
        bindings_by_loop
            .entry(binding.loop_span)
            .or_default()
            .push(binding);
    }
    for decl in &mut idx.defs {
        rewrite_scala_for_binding_sequences(&mut decl.flow_events, &bindings_by_loop);
    }
}

fn rewrite_scala_for_binding_sequences(
    events: &mut Vec<FlowEvent>,
    bindings_by_loop: &HashMap<Span, Vec<ScalaForEnumeratorBinding>>,
) {
    let direct_loops = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Loop { span, .. } if bindings_by_loop.contains_key(span) => Some(*span),
            _ => None,
        })
        .collect::<Vec<_>>();
    for loop_span in direct_loops {
        if let Some(bindings) = bindings_by_loop.get(&loop_span) {
            for binding in bindings {
                insert_scala_for_binding(events, binding);
            }
        }
    }

    for event in events {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_scala_for_binding_sequences(then_events, bindings_by_loop);
                rewrite_scala_for_binding_sequences(else_events, bindings_by_loop);
            }
            FlowEvent::Loop { body, .. } => rewrite_scala_for_binding_sequences(body, bindings_by_loop),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_scala_for_binding_sequences(body, bindings_by_loop);
                rewrite_scala_for_binding_sequences(catch_events, bindings_by_loop);
                rewrite_scala_for_binding_sequences(finally_events, bindings_by_loop);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_scala_for_binding_sequences(body, bindings_by_loop);
            }
            _ => {}
        }
    }
}

fn insert_scala_for_binding(events: &mut Vec<FlowEvent>, binding: &ScalaForEnumeratorBinding) {
    let replacement_targets = binding
        .assigns
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    events.retain(|event| {
        !matches!(
            event,
            FlowEvent::Assign { span, target, .. }
                if *span == binding.loop_span && replacement_targets.contains(target.as_str())
        )
    });

    let loop_position = events
        .iter()
        .position(|event| matches!(event, FlowEvent::Loop { span, .. } if *span == binding.loop_span))
        .expect("Scala for-expression loop event was established above");
    let after_value = events[..loop_position]
        .iter()
        .enumerate()
        .filter(|(_, event)| span_contains(binding.value_span, scala_flow_event_span(event)))
        .map(|(index, _)| index + 1)
        .next_back()
        .unwrap_or_else(|| {
            events[..loop_position]
                .iter()
                .position(|event| scala_flow_event_span(event).start >= binding.value_span.end)
                .unwrap_or(loop_position)
        });
    events.splice(after_value..after_value, binding.assigns.clone());
}

fn scala_flow_event_span(event: &FlowEvent) -> Span {
    match event {
        FlowEvent::Call { span, .. }
        | FlowEvent::Branch { span, .. }
        | FlowEvent::Loop { span, .. }
        | FlowEvent::Assign { span, .. }
        | FlowEvent::AggregateAssign { span, .. }
        | FlowEvent::Return { span, .. }
        | FlowEvent::Throw { span, .. }
        | FlowEvent::Try { span, .. }
        | FlowEvent::Break { span, .. }
        | FlowEvent::Continue { span, .. }
        | FlowEvent::Yield { span, .. }
        | FlowEvent::Await { span, .. }
        | FlowEvent::Defer { span, .. }
        | FlowEvent::Using { span, .. }
        | FlowEvent::Lifecycle { span, .. } => *span,
    }
}

fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

/// Decode scalar literal syntax needed by generic compiler value facts.
/// Provider/API meaning stays in rule data; the adapter contributes only the
/// exact Scala literal value represented by the CST node.
fn scala_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "null_literal" => Some(StaticScalarValue::Null),
        "boolean_literal" => match node_text(&node, src).trim() {
            "true" => Some(StaticScalarValue::Boolean(true)),
            "false" => Some(StaticScalarValue::Boolean(false)),
            _ => None,
        },
        "string" => {
            let text = node_text(&node, src).trim();
            (text.len() >= 2
                && text.starts_with('"')
                && text.ends_with('"')
                && !text[1..text.len() - 1].contains(['\\', '"']))
            .then(|| StaticScalarValue::String(text[1..text.len() - 1].to_string()))
        }
        _ => None,
    }
}

fn populate_scala_immutable_static_values(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let class_symbols = index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.symbol))
        .collect::<Vec<_>>();
    for declaration in collect_kinds(tree, &["val_definition"]) {
        let (Some(pattern), Some(value)) = (
            declaration.child_by_field_name("pattern"),
            declaration.child_by_field_name("value"),
        ) else {
            continue;
        };
        if pattern.kind() != "identifier" {
            continue;
        }
        let assignment_span = span_of(file, &declaration);
        let target = node_text(&pattern, src).trim();
        if let Some(fact) = index
            .assignment_values
            .iter_mut()
            .find(|fact| fact.assignment_span == assignment_span && fact.target.as_deref() == Some(target))
        {
            fact.target_is_immutable = true;
            fact.target_owner = scala_class_owner_of_val(declaration, file, &class_symbols);
            if let Some(static_value) = scala_static_scalar(value, src) {
                fact.static_value = Some(static_value);
            }
        }
    }
}

fn scala_class_owner_of_val(
    declaration: Node<'_>,
    file: FileId,
    class_symbols: &[(Span, SymbolId)],
) -> Option<SymbolId> {
    let mut current = declaration.parent();
    while let Some(node) = current {
        match node.kind() {
            // Method/lambda-local vals must not become class state merely
            // because their containing method belongs to a class.
            "function_definition" | "lambda_expression" | "case_clause" => return None,
            "class_definition" | "object_definition" | "trait_definition" => {
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

/// Lower Scala `match` expressions whose every arm produces one compiler
/// literal. The selector may remain dynamic, but it cannot become part of the
/// selected value. Security consumers decide whether that finite value fact is
/// relevant to a sink; this adapter records syntax and value shape only.
fn collect_scala_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
) -> Vec<bonsai_lang_api::FiniteLiteralSelectionFact> {
    let mut facts = Vec::new();
    for selection in collect_kinds(tree, &["match_expression"]) {
        if !scala_match_outputs_are_literals(selection) {
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
        if scala_match_is_complete_expression_body(selection) {
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

fn scala_match_outputs_are_literals(selection: Node<'_>) -> bool {
    let Some(case_block) = first_named_child_of_kind(&selection, "case_block") else {
        return false;
    };
    let mut block_cursor = case_block.walk();
    let clauses = case_block
        .named_children(&mut block_cursor)
        .filter(|child| child.kind() == "case_clause")
        .collect::<Vec<_>>();
    !clauses.is_empty()
        && clauses.into_iter().all(|clause| {
            let mut clause_cursor = clause.walk();
            let bodies = clause
                .named_children(&mut clause_cursor)
                .enumerate()
                .filter_map(|(index, child)| {
                    (clause.field_name_for_named_child(index as u32) == Some("body")).then_some(child)
                })
                .collect::<Vec<_>>();
            let [value] = bodies.as_slice() else {
                return false;
            };
            matches!(
                value.kind(),
                "string"
                    | "character_literal"
                    | "integer_literal"
                    | "floating_point_literal"
                    | "boolean_literal"
                    | "null_literal"
            )
        })
}

fn scala_match_is_complete_expression_body(selection: Node<'_>) -> bool {
    selection.parent().is_some_and(|parent| {
        matches!(parent.kind(), "function_definition" | "function_declaration")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.id() == selection.id())
    })
}

/// Lower direct `val`/`var` initializers in a Scala class/object/trait into an
/// exact synthetic callable. These expressions execute during template
/// initialization; they are neither type-only declarations nor method bodies.
/// The shared module pass intentionally does not enter type bodies, so the
/// owning adapter must expose this execution boundary.
fn synthesize_scala_template_initializer_decls(
    index: &mut DeclIndex,
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
) {
    let mut next_symbol = index
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let class_names = index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();
    let templates = collect_kinds(
        tree,
        &[
            "class_definition",
            "object_definition",
            "trait_definition",
            "enum_definition",
        ],
    );
    for template in templates {
        let Some(body) = template.child_by_field_name("body") else {
            continue;
        };
        let mut events = Vec::new();
        let mut cursor = body.walk();
        for member in body.named_children(&mut cursor) {
            if !matches!(member.kind(), "val_definition" | "var_definition") {
                continue;
            }
            let Some(value) = member.child_by_field_name("value") else {
                continue;
            };
            events.extend(walk_flow_events(value, file, src, &HANDLER, &class_names));
        }
        if !events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Call { .. }
                    | FlowEvent::Assign { .. }
                    | FlowEvent::Yield { .. }
                    | FlowEvent::Await { .. }
            )
        }) {
            continue;
        }
        let template_span = span_of(file, &template);
        let parent = index
            .defs
            .iter()
            .find(|decl| is_class_like(decl.kind) && decl.span == template_span)
            .map(|decl| decl.symbol);
        let position = template.start_position();
        let name_span = template
            .child_by_field_name("name")
            .map_or(template_span, |name| span_of(file, &name));
        index.defs.push(Decl {
            symbol: SymbolId::new(next_symbol),
            kind: DeclKind::Function,
            name: format!("<template-init@{}:{}>", position.row + 1, position.column + 1),
            qualified_name: None,
            module_path: bonsai_lang_api::ModulePath::default(),
            span: span_of(file, &body),
            name_span,
            visibility: Visibility::Private,
            parent,
            body_span: Some(span_of(file, &body)),
            flow_events: events,
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
            receiver_state_sources: vec!["super".to_string(), "this".to_string()],
            return_type: None,
            is_variadic: false,
        });
        next_symbol = next_symbol.saturating_add(1);
    }
}

/// Scala partial-function arguments (`factory { case req @ ... => }`) are one
/// `case_block` value, not one call argument per case arm. Tree-sitter exposes
/// the block through the call's `arguments` field, whose named children are
/// clauses; the shared positional lowering therefore needs this adapter-owned
/// correction before compiler argument facts are derived.
fn normalize_scala_partial_function_call_arguments(
    index: &mut DeclIndex,
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
) {
    let blocks = collect_kinds(tree, &["case_block"])
        .into_iter()
        .filter_map(|block| {
            let mut cursor = block.walk();
            let clauses = block
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "case_clause")
                .map(|child| span_of(file, &child))
                .collect::<Vec<_>>();
            (!clauses.is_empty()).then_some((block, clauses))
        })
        .collect::<Vec<_>>();

    fn normalize_events(
        events: &mut [FlowEvent],
        blocks: &[(Node<'_>, Vec<Span>)],
        file: FileId,
        src: &[u8],
    ) {
        for event in events {
            match event {
                FlowEvent::Call { args, .. } => {
                    let matching_blocks = blocks
                        .iter()
                        .filter(|(block, clauses)| {
                            let block_span = span_of(file, block);
                            (args.len() == clauses.len()
                                && args
                                    .iter()
                                    .zip(clauses)
                                    .all(|(argument, clause)| argument.span == *clause))
                                || matches!(args.as_slice(), [argument]
                                    if argument.span.file == block_span.file
                                        && argument.span.start <= block_span.start
                                        && argument.span.end >= block_span.end)
                        })
                        .collect::<Vec<_>>();
                    // A single transparent `arguments` wrapper can surround
                    // the case block.  Normalize only when the compiler span
                    // proves one unique contained partial-function value;
                    // overlapping/nested candidates fail closed.
                    let [entry] = matching_blocks.as_slice() else {
                        continue;
                    };
                    let block = entry.0;
                    if let Some(argument) = call_arg_from_node_with_handler(block, file, src, None, &HANDLER)
                    {
                        args.clear();
                        args.push(argument);
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    normalize_events(then_events, blocks, file, src);
                    normalize_events(else_events, blocks, file, src);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => normalize_events(body, blocks, file, src),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    normalize_events(body, blocks, file, src);
                    normalize_events(catch_events, blocks, file, src);
                    normalize_events(finally_events, blocks, file, src);
                }
                _ => {}
            }
        }
    }

    for decl in &mut index.defs {
        normalize_events(&mut decl.flow_events, &blocks, file, src);
    }
}

/// Remove callback-body events that the generic call-argument walk observed
/// through Scala's unusual `arguments -> case_clause` field shape.
///
/// The same events remain on the exact synthetic callable whose declaration
/// span is the `case_block`. Only the enclosing caller copy is removed; the
/// outer call event itself lies outside the block and remains available for
/// compiler/rule callback-delivery facts. A `case_block` owned by a
/// `catch_clause` is different syntax: its cases execute as exception-handler
/// arms in the enclosing callable and must remain inside `FlowEvent::Try`.
fn remove_scala_partial_function_body_leaks(index: &mut DeclIndex, tree: &Tree, file: FileId) {
    let partial_function_spans = collect_kinds(tree, &["case_block"])
        .into_iter()
        .filter(|block| {
            block
                .parent()
                .is_none_or(|parent| !matches!(parent.kind(), "match_expression" | "catch_clause"))
        })
        .map(|block| span_of(file, &block))
        .collect::<Vec<_>>();
    if partial_function_spans.is_empty() {
        return;
    }

    for decl in &mut index.defs {
        let foreign_blocks = partial_function_spans
            .iter()
            .copied()
            .filter(|block| *block != decl.span)
            .collect::<Vec<_>>();
        remove_scala_events_inside_spans(&mut decl.flow_events, &foreign_blocks);
    }
}

fn remove_scala_events_inside_spans(events: &mut Vec<FlowEvent>, spans: &[Span]) {
    events.retain(|event| {
        let event_span = scala_flow_event_span(event);
        !spans.iter().any(|span| span_contains(*span, event_span))
    });
    for event in events {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                remove_scala_events_inside_spans(then_events, spans);
                remove_scala_events_inside_spans(else_events, spans);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                remove_scala_events_inside_spans(body, spans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                remove_scala_events_inside_spans(body, spans);
                remove_scala_events_inside_spans(catch_events, spans);
                remove_scala_events_inside_spans(finally_events, spans);
            }
            _ => {}
        }
    }
}

/// Retain the exact value bindings of one partial-function block on its
/// compiler argument fact. Rule data can then declare callback delivery
/// without teaching shared analysis any framework names.
fn populate_scala_partial_function_callback_facts(
    index: &mut DeclIndex,
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
) {
    fn push_binding(name: &str, params: &mut Vec<String>) {
        if !name.is_empty() && name != "_" && !params.iter().any(|value| value == name) {
            params.push(name.to_string());
        }
    }

    fn collect_case_pattern_bindings(node: Node<'_>, src: &[u8], params: &mut Vec<String>) {
        if node.kind() == "capture_pattern" {
            if let Some(name) = node.child_by_field_name("name") {
                push_binding(node_text(&name, src).trim(), params);
            }
            // The nested pattern names constructors/stable extractors; only
            // the grammar's explicit capture `name` is a binding.
            return;
        }

        if node.kind() == "tuple_pattern" {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "tuple_pattern" => collect_case_pattern_bindings(child, src, params),
                    "identifier" => {
                        let name = node_text(&child, src).trim();
                        // In a Scala pattern, a lowercase identifier is a
                        // fresh value binding. Uppercase and backtick forms
                        // are stable-identifier matches, not callback inputs.
                        if name.starts_with(|ch: char| ch.is_lowercase() || ch == '_') {
                            push_binding(name, params);
                        }
                    }
                    "capture_pattern" => collect_case_pattern_bindings(child, src, params),
                    _ => {}
                }
            }
            return;
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "case_clause" {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    collect_case_pattern_bindings(pattern, src, params);
                }
            } else if child.kind() != "identifier" {
                // Captures may be nested below infix/alternative/typed
                // pattern containers. Descend through syntax containers, but
                // never promote their bare identifiers: constructor and
                // extractor names are not value bindings. Tuple handling
                // above is the one grammar shape where lowercase identifier
                // children are independently proven bindings.
                collect_case_pattern_bindings(child, src, params);
            }
        }
    }

    let blocks = collect_kinds(tree, &["case_block"]);
    let mut collapsed_arguments = Vec::new();
    for block in blocks {
        let block_span = span_of(file, &block);
        let Some(fact_index) = index
            .call_argument_values
            .iter()
            .position(|fact| fact.argument_span == block_span)
        else {
            continue;
        };
        let mut params = Vec::new();
        collect_case_pattern_bindings(block, src, &mut params);
        if !params.is_empty() {
            let call_span = index.call_argument_values[fact_index].call_span;
            let fact = &mut index.call_argument_values[fact_index];
            fact.argument_index = 0;
            fact.inline_callback_params.clone_from(&params);
            fact.inline_callback_span = Some(block_span);
            if let Some(callback) = index.defs.iter_mut().find(|decl| {
                decl.span == block_span && matches!(decl.kind, DeclKind::Function | DeclKind::Method)
            }) {
                callback.params = params;
                callback.param_annotations = vec![Vec::new(); callback.params.len()];
            }
            let mut cursor = block.walk();
            let clause_spans = block
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "case_clause")
                .map(|child| span_of(file, &child))
                .collect::<Vec<_>>();
            collapsed_arguments.push((call_span, block_span, clause_spans));
        }
    }
    for (call_span, block_span, clause_spans) in collapsed_arguments {
        index.call_argument_values.retain(|fact| {
            fact.call_span != call_span
                || fact.argument_span == block_span
                || !clause_spans.contains(&fact.argument_span)
        });
    }
}

#[derive(Clone, Debug)]
struct ScalaBaseConstructorCall {
    base_name: String,
    args: Vec<String>,
    event: FlowEvent,
}

#[derive(Clone, Debug)]
struct ScalaConstructorDraft {
    class_span: Span,
    class_symbol: SymbolId,
    class_name: String,
    class_name_span: Span,
    module_path: bonsai_lang_api::ModulePath,
    body_span: Span,
    params: Vec<String>,
    flow_events: Vec<FlowEvent>,
    direct_receiver_field_writes: Vec<FieldWrite>,
    base_call: Option<ScalaBaseConstructorCall>,
}

fn synthesize_scala_constructor_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
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
                decl.name.clone(),
                decl.name_span,
                decl.module_path.clone(),
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

    let mut drafts = Vec::new();
    for class_node in collect_kinds(tree, &["class_definition"]) {
        let class_span = span_of(file, &class_node);
        let Some((_, class_symbol, class_name, class_name_span, module_path)) =
            classes.iter().find(|(span, _, _, _, _)| *span == class_span)
        else {
            continue;
        };
        // Case classes (`case class Envelope(...)`) and other
        // parameterised classes without an explicit body block still
        // declare a primary constructor whose `class_parameters`
        // become field-initializing writes — so don't skip when
        // `template_body` is absent. Body-less ctors get an empty
        // `flow_events` vec but real `receiver_field_writes` from
        // the param list, which is what drives the IDG's
        // `ConstructorReturnStitch` field-projection onto the
        // caller's allocation target.
        let body = first_named_child_of_kind(&class_node, "template_body");
        let flow_events = body
            .map(|b| walk_flow_events(b, file, src, &HANDLER, &class_names))
            .unwrap_or_default();
        let body_span = body.map_or(class_span, |b| span_of(file, &b));
        let class_params = first_named_child_of_kind(&class_node, "class_parameters");
        let params = class_params.map_or_else(Vec::new, |params| constructor_param_names(params, src));
        let is_case = scala_class_is_case(class_node, src);
        let mut receiver_field_writes = class_params.map_or_else(Vec::new, |params_node| {
            scala_constructor_param_field_writes_with_mode(params_node, file, src, &params, is_case)
        });
        let mut body_writes =
            collect_receiver_field_writes(&flow_events, &params, None, &["this", "super"], &[]);
        receiver_field_writes.append(&mut body_writes);
        let base_call = scala_primary_base_constructor_call(class_node, file, src);
        let mut constructor_flow_events = Vec::new();
        if let Some(call) = &base_call {
            constructor_flow_events.push(call.event.clone());
        }
        constructor_flow_events.extend(flow_events);
        drafts.push(ScalaConstructorDraft {
            class_span,
            class_symbol: *class_symbol,
            class_name: class_name.clone(),
            class_name_span: *class_name_span,
            module_path: module_path.clone(),
            body_span,
            params,
            flow_events: constructor_flow_events,
            direct_receiver_field_writes: receiver_field_writes,
            base_call,
        });
    }

    let mut draft_by_name = HashMap::new();
    for (idx, draft) in drafts.iter().enumerate() {
        draft_by_name.insert(draft.class_name.clone(), idx);
    }
    let mut memo: HashMap<String, Vec<FieldWrite>> = HashMap::new();
    let mut visiting: HashSet<String> = HashSet::new();
    for draft in &drafts {
        let receiver_field_writes = scala_constructor_receiver_field_writes(
            &draft.class_name,
            &drafts,
            &draft_by_name,
            &mut memo,
            &mut visiting,
        );
        if draft.flow_events.is_empty() && receiver_field_writes.is_empty() {
            continue;
        }
        idx.defs.push(scala_constructor_decl(
            bonsai_common::SymbolId::new(next),
            draft.class_symbol,
            &draft.class_name,
            draft.class_name_span,
            draft.class_span,
            draft.body_span,
            draft.params.clone(),
            draft.flow_events.clone(),
            receiver_field_writes,
            draft.module_path.clone(),
        ));
        next = next.saturating_add(1);
    }
}

fn scala_constructor_receiver_field_writes(
    class_name: &str,
    drafts: &[ScalaConstructorDraft],
    draft_by_name: &HashMap<String, usize>,
    memo: &mut HashMap<String, Vec<FieldWrite>>,
    visiting: &mut HashSet<String>,
) -> Vec<FieldWrite> {
    if let Some(cached) = memo.get(class_name) {
        return cached.clone();
    }
    let Some(&idx) = draft_by_name.get(class_name) else {
        return Vec::new();
    };
    if !visiting.insert(class_name.to_string()) {
        return Vec::new();
    }
    let draft = &drafts[idx];
    let mut writes = draft.direct_receiver_field_writes.clone();
    if let Some(base_call) = &draft.base_call {
        if base_call.base_name != draft.class_name {
            let base_writes = scala_constructor_receiver_field_writes(
                &base_call.base_name,
                drafts,
                draft_by_name,
                memo,
                visiting,
            );
            for write in base_writes {
                let Some(source_param_indices) =
                    remap_constructor_field_write_sources(&write, &base_call.args, &draft.params)
                else {
                    continue;
                };
                writes.push(FieldWrite {
                    span: write.span,
                    target: write.target,
                    source_param_indices,
                });
            }
        }
    }
    writes.sort_by_key(|write| {
        (
            write.span.file.raw(),
            write.span.start,
            write.target.clone(),
            write.source_param_indices.clone(),
        )
    });
    writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
    memo.insert(class_name.to_string(), writes.clone());
    visiting.remove(class_name);
    writes
}

fn remap_constructor_field_write_sources(
    write: &FieldWrite,
    base_args: &[String],
    subclass_params: &[String],
) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    for source_idx in &write.source_param_indices {
        let arg = base_args.get(*source_idx)?.trim();
        if arg.is_empty() {
            return None;
        }
        let subclass_idx = subclass_params.iter().position(|param| param == arg)?;
        out.push(subclass_idx);
    }
    Some(out)
}

fn scala_primary_base_constructor_call(
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<ScalaBaseConstructorCall> {
    let extend = class_node.child_by_field_name("extend")?;
    let mut cursor = extend.walk();
    let mut base_node = None;
    let mut args_node = None;
    for child in extend.named_children(&mut cursor) {
        if base_node.is_none() {
            let raw = node_text(&child, src);
            if canonical_scala_base_name(raw).is_some() {
                base_node = Some(child);
            }
            continue;
        }
        if child.kind() == "arguments" {
            args_node = Some(child);
        }
        break;
    }
    let base_node = base_node?;
    let base_name = canonical_scala_base_name(node_text(&base_node, src))?;
    let args = args_node.map_or_else(Vec::new, |node| scala_constructor_argument_texts(node, src));
    let event_args = args_node.map_or_else(Vec::new, |node| scala_constructor_call_args(node, file, src));
    let event = FlowEvent::Call {
        span: span_of(file, &extend),
        name: base_name.clone(),
        receiver: None,
        receiver_types: vec![base_name.clone()],
        call_kind: CallKind::Constructor,
        args: event_args,
    };
    Some(ScalaBaseConstructorCall {
        base_name,
        args,
        event,
    })
}

fn scala_constructor_argument_texts(args_node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let text = node_text(&child, src).trim();
        if !text.is_empty() {
            out.push(text.to_string());
        }
    }
    out
}

fn scala_constructor_call_args(args_node: Node<'_>, file: FileId, src: &[u8]) -> Vec<CallArg> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let named_value = (child.kind() == "assignment_expression")
            .then(|| {
                let label = child.child_by_field_name("left")?;
                let value = child.child_by_field_name("right")?;
                (label.kind() == "identifier").then(|| {
                    let name = node_text(&label, src).trim().to_string();
                    (value, (!name.is_empty()).then_some(name))
                })
            })
            .flatten();
        let argument = if let Some((value, name)) = named_value {
            call_arg_from_nodes_with_handler(child, value, file, src, name, &HANDLER)
        } else {
            call_arg_from_node_with_handler(child, file, src, None, &HANDLER)
        };
        if let Some(argument) = argument {
            out.push(argument);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn scala_constructor_decl(
    symbol: bonsai_common::SymbolId,
    parent: bonsai_common::SymbolId,
    class_name: &str,
    name_span: Span,
    span: Span,
    body_span: Span,
    params: Vec<String>,
    flow_events: Vec<bonsai_lang_api::FlowEvent>,
    receiver_field_writes: Vec<FieldWrite>,
    module_path: bonsai_lang_api::ModulePath,
) -> Decl {
    Decl {
        symbol,
        kind: DeclKind::Constructor,
        name: class_name.to_string(),
        qualified_name: None,
        module_path,
        span,
        name_span,
        visibility: Visibility::Public,
        parent: Some(parent),
        body_span: Some(body_span),
        flow_events,
        has_implicit_returns: false,
        params,
        param_annotations: Vec::new(),
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes,
        receiver_field_initializers: Vec::new(),
        implicit_receiver_names: vec!["this".to_string(), "super".to_string()],
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn constructor_param_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|param| matches!(param.kind(), "class_parameter" | "parameter"))
        .filter_map(|param| parameter_binding_name(param, src))
        .collect()
}

/// `is_case_class` forces every class-parameter to count as a field-
/// initializing write, regardless of `val`/`var` modifier — Scala
/// case classes promote every positional parameter to a public `val`
/// implicitly, so without this flag the synthesized ctor would emit
/// no `receiver_field_writes` for `case class Envelope(kind, cmd,
/// user, ...)` and the constructor-return field stitch couldn't
/// project `envelope.cmd ← raw` onto the caller's allocation.
fn scala_constructor_param_field_writes_with_mode(
    params_node: Node<'_>,
    file: FileId,
    src: &[u8],
    params: &[String],
    is_case_class: bool,
) -> Vec<FieldWrite> {
    let mut writes = Vec::new();
    let mut cursor = params_node.walk();
    for param in params_node
        .named_children(&mut cursor)
        .filter(|param| param.kind() == "class_parameter")
    {
        if !is_case_class && !scala_class_parameter_declares_property(param, src) {
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
    writes
}

fn annotate_scala_named_call_args(events: &mut [FlowEvent], root: Node<'_>, file: FileId, src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    if arg.name.is_some() {
                        continue;
                    }
                    let Some(argument_node) = node_at_span(root, arg.span, &["assignment_expression"]) else {
                        continue;
                    };
                    // `node_at_span` deliberately falls back to an exact node
                    // of another kind when no requested kind exists. Named
                    // arguments require an actual assignment-expression AST;
                    // an infix `input + "x"` also has left/right fields but is
                    // value syntax, not `name = value`.
                    if argument_node.kind() != "assignment_expression" {
                        continue;
                    }
                    let Some(label_node) = argument_node.child_by_field_name("left") else {
                        continue;
                    };
                    let Some(value_node) = argument_node.child_by_field_name("right") else {
                        continue;
                    };
                    if label_node.kind() != "identifier" {
                        continue;
                    }
                    let label = node_text(&label_node, src).trim().to_string();
                    if label.is_empty() {
                        continue;
                    }
                    if let Some(ast_arg) = call_arg_from_nodes_with_handler(
                        argument_node,
                        value_node,
                        file,
                        src,
                        Some(label),
                        &HANDLER,
                    ) {
                        *arg = ast_arg;
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                annotate_scala_named_call_args(then_events, root, file, src);
                annotate_scala_named_call_args(else_events, root, file, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                annotate_scala_named_call_args(body, root, file, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                annotate_scala_named_call_args(body, root, file, src);
                annotate_scala_named_call_args(catch_events, root, file, src);
                annotate_scala_named_call_args(finally_events, root, file, src);
            }
            _ => {}
        }
    }
}

fn scala_class_parameter_declares_property(param: Node<'_>, _src: &[u8]) -> bool {
    let mut cursor = param.walk();
    let declares_property = param
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "val" | "var"));
    declares_property
}

/// Detect a Scala `case class` (modifier `case` on a `class_definition`).
fn scala_class_is_case(class_node: Node<'_>, _src: &[u8]) -> bool {
    let mut cw = class_node.walk();
    for child in class_node.children(&mut cw) {
        if child.kind() == "case" {
            return true;
        }
        if child.kind() == "modifiers" {
            let mut mw = child.walk();
            for m in child.children(&mut mw) {
                if m.kind() == "case" {
                    return true;
                }
            }
        }
    }
    false
}

fn parameter_binding_name(param: Node<'_>, src: &[u8]) -> Option<String> {
    let mut names = Vec::new();
    collect_binding_identifiers(param, src, &mut names);
    names.into_iter().find(|name| name != "_")
}

fn collect_binding_identifiers(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "identifier" {
        let name = node_text(&node, src).trim();
        if !name.is_empty() {
            out.push(name.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "type_identifier" {
            continue;
        }
        collect_binding_identifiers(child, src, out);
    }
}

/// Walk every Scala class-like declaration and pull `(name, type)`
/// bindings from `val_definition` / `var_definition` children and from every
/// primary-constructor parameter. Scala permits an unadorned constructor
/// parameter to be referenced by a member; the compiler captures that value
/// in instance storage even though it does not expose a public accessor.
/// Returns `(class_span, [TypeAliasBinding])` so the per-method merge can
/// attach the exact captured receiver types to methods nested inside it.
fn collect_scala_class_field_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Vec<(Span, Vec<TypeAliasBinding>)> {
    let class_kinds = &["class_definition", "trait_definition", "object_definition"];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![class_node];
        while let Some(node) = work.pop() {
            // Don't descend into nested classes; their methods get
            // their own scope.
            if node != class_node && class_kinds.contains(&node.kind()) {
                continue;
            }
            // Don't descend into method bodies — local vals are
            // covered by the per-method `collect_param_type_aliases`
            // pass and would pollute the class-scope set.
            if node != class_node && matches!(node.kind(), "function_definition" | "function_declaration") {
                continue;
            }
            if matches!(node.kind(), "val_definition" | "var_definition") {
                if let Some(binding) = scala_field_alias(node, src, declared_type_names) {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            if node.kind() == "class_parameter" {
                if let Some(binding) = scala_field_alias(node, src, declared_type_names) {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        if !aliases.is_empty() {
            out.push((span_of(file, &class_node), aliases));
        }
    }
    out
}

/// Extract a `name: Type` binding from one Scala field or class-parameter
/// node. Handles both explicit annotations
/// (`val x: Foo = ...`) and constructor-shaped initializers
/// (`val x = new Foo()`), since Scala source frequently relies on
/// type inference for class fields.
fn scala_field_alias(
    node: Node<'_>,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Option<TypeAliasBinding> {
    let pattern = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("name"))?;
    let name = node_text(&pattern, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let type_short = node
        .child_by_field_name("type")
        .map(|t| node_text(&t, src).to_string())
        .and_then(|t| canonical_simple_type_name(&t))
        .or_else(|| scala_value_constructor_type(node, src, declared_type_names))
        .or_else(|| scala_value_cast_type(node, src))?;
    if type_short.is_empty() || name == type_short {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: type_short,
    })
}

/// WS2: collect method-LOCAL `asInstanceOf` cast type bindings, keyed by
/// the enclosing function span. The class-field walk skips method bodies
/// and the kit vocabulary only types explicitly-annotated locals, so an
/// inferred local typed by a cast (`val c = make().asInstanceOf[Foo]`)
/// would otherwise lose its receiver type.
fn collect_scala_local_cast_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<TypeAliasBinding>)> {
    let fn_kinds = &["function_definition", "function_declaration"];
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, fn_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![fn_node];
        while let Some(node) = work.pop() {
            if node != fn_node && fn_kinds.contains(&node.kind()) {
                continue;
            }
            if matches!(node.kind(), "val_definition" | "var_definition")
                && node.child_by_field_name("type").is_none()
            {
                if let Some(ty) = scala_value_cast_type(node, src) {
                    if let Some(pattern) = node
                        .child_by_field_name("pattern")
                        .or_else(|| node.child_by_field_name("name"))
                    {
                        let name = node_text(&pattern, src).trim().to_string();
                        if !name.is_empty() && !ty.is_empty() && name != ty {
                            let binding = TypeAliasBinding { name, type_name: ty };
                            if !aliases.contains(&binding) {
                                aliases.push(binding);
                            }
                        }
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        if !aliases.is_empty() {
            out.push((span_of(file, &fn_node), aliases));
        }
    }
    out
}

/// WS2: `val c = make().asInstanceOf[Foo]` — Scala's `asInstanceOf[T]`
/// cast. The initializer is a `call_expression` whose `field` is the
/// `asInstanceOf` identifier and which carries the target type as a
/// `type_identifier` / `generic_type` argument. Returns that type so a
/// cast-typed receiver resolves `receiver_type_in`.
fn scala_value_cast_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let value = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))?;
    // Current tree-sitter-scala lowers `value.asInstanceOf[Type]` as a
    // `generic_function` whose `function` is the field expression and whose
    // `type_arguments` own the cast target. Older grammar revisions exposed
    // the field directly on a call expression. Accept only those two exact
    // compiler shapes; ordinary generic calls do not become casts.
    let function = match value.kind() {
        "generic_function" => value.child_by_field_name("function")?,
        "call_expression" => value,
        _ => return None,
    };
    let field = function.child_by_field_name("field").or_else(|| {
        function
            .child_by_field_name("function")?
            .child_by_field_name("field")
    })?;
    if node_text(&field, src).trim() != "asInstanceOf" {
        return None;
    }
    let mut cursor = value.walk();
    for child in value.named_children(&mut cursor) {
        if matches!(child.kind(), "type_identifier" | "generic_type") {
            return canonical_simple_type_name(node_text(&child, src));
        }
        if child.kind() == "type_arguments" {
            let mut arguments = child.walk();
            for target in child.named_children(&mut arguments) {
                if matches!(target.kind(), "type_identifier" | "generic_type") {
                    return canonical_simple_type_name(node_text(&target, src));
                }
            }
        }
    }
    None
}

fn scala_value_constructor_type(
    node: Node<'_>,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Option<String> {
    let value = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))?;
    let (candidate, syntax_proves_constructor) = match value.kind() {
        // `new Foo(...)` shape across grammar versions.
        "instance_expression" => {
            let mut found = None;
            let mut cursor = value.walk();
            for child in value.named_children(&mut cursor) {
                if child.kind() == "type_identifier" {
                    found = Some(node_text(&child, src).to_string());
                    break;
                }
                if child.kind() == "call_expression" {
                    let mut inner = child.walk();
                    for sub in child.named_children(&mut inner) {
                        if matches!(sub.kind(), "type_identifier" | "identifier") {
                            found = Some(node_text(&sub, src).to_string());
                            break;
                        }
                    }
                    if found.is_some() {
                        break;
                    }
                }
            }
            (found?, true)
        }
        // `val x = Foo()` is ambiguous (ordinary function vs companion
        // apply). Only an exact type declaration can prove this type.
        "call_expression" => {
            let func = value.child_by_field_name("function").or_else(|| {
                let mut cursor = value.walk();
                let mut found = None;
                for child in value.named_children(&mut cursor) {
                    if matches!(child.kind(), "identifier" | "type_identifier") {
                        found = Some(child);
                        break;
                    }
                }
                found
            })?;
            (node_text(&func, src).to_string(), false)
        }
        _ => return None,
    };
    let canonical = canonical_simple_type_name(&candidate)?;
    (syntax_proves_constructor || declared_type_names.contains(&canonical)).then_some(canonical)
}

fn canonical_simple_type_name(raw: &str) -> Option<String> {
    let no_generics = raw.split('[').next().unwrap_or(raw);
    let no_generics = no_generics.split('<').next().unwrap_or(no_generics);
    let trimmed = no_generics
        .trim()
        .trim_start_matches("new ")
        .trim()
        .trim_end_matches('?');
    let short = trimmed.rsplit('.').next().unwrap_or(trimmed).trim();
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

fn collect_scala_method_owners(tree: &Tree, file: FileId) -> Vec<(Span, Span, &'static str)> {
    let mut out = Vec::new();
    for method in collect_kinds(tree, &["function_definition", "function_declaration"]) {
        let Some(owner) = nearest_scala_owner(method) else {
            continue;
        };
        out.push((span_of(file, &method), span_of(file, &owner), owner.kind()));
    }
    out
}

fn nearest_scala_owner(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        match candidate.kind() {
            "class_definition" | "trait_definition" | "object_definition" => return Some(candidate),
            "function_definition" | "function_declaration" => return None,
            _ => parent = candidate.parent(),
        }
    }
    None
}

/// Parse `import_declaration` nodes into `ImportSpec`s, one per surfaced symbol.
///
/// Scala shapes:
///   `import x.y.Z`            — straight
///   `import x.y.{A, B}`       — braced selector list
///   `import x.y.{A => B}`     — renaming alias (Scala 2)
///   `import x.y.{A as B}`     — renaming alias (Scala 3)
///   `import x.y._` / `x.y.*`  — wildcard (Scala 2 / Scala 3)
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_declaration"]) {
        let path = scala_import_path(&import_node, src);
        if path.is_empty() {
            continue;
        }
        let span = span_of(file, &import_node);
        let mut cursor = import_node.walk();
        let children: Vec<Node<'_>> = import_node.named_children(&mut cursor).collect();

        if let Some(selectors) = children
            .iter()
            .find(|child| child.kind() == "namespace_selectors")
        {
            append_scala_selectors(*selectors, &path, span, src, &mut imports);
            continue;
        }

        if let Some(rename) = children
            .iter()
            .find(|child| matches!(child.kind(), "as_renamed_identifier" | "arrow_renamed_identifier"))
        {
            append_scala_renamed_selector(*rename, &path, span, src, &mut imports);
            continue;
        }

        let is_wildcard = children.iter().any(|child| child.kind() == "namespace_wildcard");
        imports.push(ImportSpec {
            span,
            module: path,
            alias: None,
            is_wildcard,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn scala_import_path(import_node: &Node<'_>, src: &[u8]) -> String {
    let mut segments = Vec::new();
    for index in 0..import_node.child_count() {
        let Ok(field_index) = u32::try_from(index) else {
            continue;
        };
        if import_node.field_name_for_child(field_index) != Some("path") {
            continue;
        }
        let Some(child) = import_node.child(field_index) else {
            continue;
        };
        if !child.is_named() {
            continue;
        }
        let segment = node_text(&child, src).trim();
        if !segment.is_empty() {
            segments.push(segment);
        }
    }
    segments.join(".")
}

fn append_scala_selectors(
    selectors: Node<'_>,
    module: &str,
    span: Span,
    src: &[u8],
    imports: &mut Vec<ImportSpec>,
) {
    let mut cursor = selectors.walk();
    for selector in selectors.named_children(&mut cursor) {
        match selector.kind() {
            "namespace_wildcard" => imports.push(ImportSpec {
                span,
                module: module.to_string(),
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Module,
            }),
            "as_renamed_identifier" | "arrow_renamed_identifier" => {
                append_scala_renamed_selector(selector, module, span, src, imports);
            }
            _ => {
                let original = node_text(&selector, src).trim();
                if !original.is_empty() {
                    imports.push(ImportSpec {
                        span,
                        module: module.to_string(),
                        alias: None,
                        is_wildcard: false,
                        original_name: Some(original.to_string()),
                        scope: ImportScope::Module,
                    });
                }
            }
        }
    }
}

fn append_scala_renamed_selector(
    selector: Node<'_>,
    module: &str,
    span: Span,
    src: &[u8],
    imports: &mut Vec<ImportSpec>,
) {
    let (Some(name_node), Some(alias_node)) = (
        selector.child_by_field_name("name"),
        selector.child_by_field_name("alias"),
    ) else {
        return;
    };
    if alias_node.kind() == "wildcard" {
        return;
    }
    let original = node_text(&name_node, src).trim();
    let alias = node_text(&alias_node, src).trim();
    if original.is_empty() || alias.is_empty() {
        return;
    }
    imports.push(ImportSpec {
        span,
        module: module.to_string(),
        alias: Some(alias.to_string()),
        is_wildcard: false,
        original_name: Some(original.to_string()),
        scope: ImportScope::Module,
    });
}

/// Scala-aware visibility collector that recognises scoped forms:
/// `private[X]` / `protected[X]` / `private[this]`. Maps to the
/// four-level lattice as follows:
///
/// - `private[this]` → `Private` (instance-only is the strictest)
/// - `private` (bare) → `Private`
/// - `private[X]` → `Crate` (broader scope within the same compilation unit)
/// - `protected[X]` → `Protected` (we don't have a tighter level)
/// - `protected` → `Protected`
/// - default → `Public`
///
/// Visibility comes from real syntax markers; per-language scoping
/// handling lives in the adapter.
fn collect_scala_visibility(
    root: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    // Iterative DFS — tree-sitter trees can be deep enough that recursion
    // would risk blowing the stack on pathological inputs.
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if SCALA_DECL_KINDS.contains(&node.kind()) {
            visibility_by_span.insert(span_of(file, &node), scala_node_visibility(node, src));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    visibility_by_span
}

/// Map a single Scala decl's `modifiers` block to the four-level visibility
/// lattice. See `collect_scala_visibility`'s doc comment for the rules.
fn scala_node_visibility(node: tree_sitter::Node<'_>, src: &[u8]) -> Visibility {
    let mut found_private = false;
    let mut found_protected = false;
    let mut scope_marker: Option<String> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        // Walk exact modifier syntax. Current tree-sitter-scala nests the
        // keyword token and optional qualifier beneath `access_modifier`.
        // Anonymous keyword tokens and named qualifier identifiers are both
        // grammar facts; no bracketed source text is reparsed.
        let mut modifiers_cursor = child.walk();
        for modifier in child.children(&mut modifiers_cursor) {
            let mut stack = vec![modifier];
            while let Some(part) = stack.pop() {
                match part.kind() {
                    "private" => found_private = true,
                    "protected" => found_protected = true,
                    "access_qualifier" => {
                        let mut qualifier_cursor = part.walk();
                        let identifiers = part
                            .named_children(&mut qualifier_cursor)
                            .filter(|child| matches!(child.kind(), "identifier" | "this"))
                            .collect::<Vec<_>>();
                        if let [identifier] = identifiers.as_slice() {
                            let value = node_text(identifier, src).trim();
                            if !value.is_empty() {
                                scope_marker = Some(value.to_string());
                            }
                        }
                    }
                    _ => {
                        let mut part_cursor = part.walk();
                        stack.extend(part.children(&mut part_cursor));
                    }
                }
            }
        }
    }
    match (found_private, found_protected, scope_marker.as_deref()) {
        // `private[this]` is the strictest form — instance-only.
        (true, _, Some("this")) => Visibility::Private,
        // `private[X]` widens to package-level within the same compilation unit.
        (true, _, Some(_)) => Visibility::Crate,
        (true, _, None) => Visibility::Private,
        (_, true, _) => Visibility::Protected,
        _ => Visibility::Public,
    }
}

/// True when the decl is a type-defining container that can carry `bases`.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Scala class / object / trait definitions and collect the
/// type names listed in `extends_clause`. Grammar shape (verified):
///
///   `class Echo extends WebSocketHandler with Mixin` →
///     (class_definition name: (identifier)
///        extend: (extends_clause type: (type_identifier) type: (type_identifier)))
///
/// `extends_clause` carries every parent (the initial `extends` plus
/// every `with` mixin) under repeating `type:` fields. Scala doesn't
/// distinguish "the super-class" vs "mixin traits" syntactically.
fn collect_scala_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_definition", "object_definition", "trait_definition"];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        // `extend:` field holds the entire `extends_clause` (extends + every with-mixin).
        let extend_node = class_node.child_by_field_name("extend");
        if let Some(extend) = extend_node {
            let mut extend_cursor = extend.walk();
            for child in extend.named_children(&mut extend_cursor) {
                let raw = node_text(&child, src);
                if let Some(name) = canonical_scala_base_name(raw) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Canonicalize a Scala base reference to a bare type name.
///
/// Strips type parameter brackets (`Foo[T]` → `Foo`) and any qualifying
/// path (`pkg.Foo` → `Foo`). The caller supplies only `extends_clause`
/// children, so capitalization is neither necessary nor correct.
fn canonical_scala_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Strip type parameter brackets: `Foo[T]` → `Foo`.
    let head = trimmed.split(['[', '(']).next().unwrap_or(trimmed).trim();
    // Strip qualifying path: `pkg.Foo` → `Foo`.
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    if bare.is_empty()
        || !bare
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        || !bare.chars().all(|c| c.is_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(bare.to_string())
}

/// Per-arm body spans collected from every `match_expression` in the
/// file. The kit emits a single `Branch { then_events: [arm1_body...,
/// arm2_body..., ...] }` for the whole match, lumping arm bodies
/// together. We use these spans in `split_match_arms_in_branch_events`
/// to peel each arm into its own nested `Branch` so the engine forks
/// state per arm.
fn collect_scala_match_arm_spans(tree: &Tree, _src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut spans_per_match: Vec<Vec<bonsai_common::Span>> = Vec::new();
    for match_node in collect_kinds(tree, &["match_expression"]) {
        let mut arm_body_spans: Vec<bonsai_common::Span> = Vec::new();
        let mut match_cursor = match_node.walk();
        for child in match_node.named_children(&mut match_cursor) {
            if child.kind() != "case_block" {
                continue;
            }
            let mut block_cursor = child.walk();
            for case in child.named_children(&mut block_cursor) {
                if case.kind() != "case_clause" {
                    continue;
                }
                // Scala's case_clause exposes one `body:` field per
                // statement (multi-statement arms produce multiple
                // body children). Span the union from min start to
                // max end across every named child whose role is
                // `body` so we capture the full arm scope.
                let mut min_start: Option<u64> = None;
                let mut max_end: Option<u64> = None;
                let mut case_cursor = case.walk();
                for (field_idx, body_node) in case.named_children(&mut case_cursor).enumerate() {
                    if case.field_name_for_named_child(field_idx as u32) == Some("body") {
                        let body_start = body_node.start_byte() as u64;
                        let body_end = body_node.end_byte() as u64;
                        min_start = Some(min_start.map_or(body_start, |m| m.min(body_start)));
                        max_end = Some(max_end.map_or(body_end, |m| m.max(body_end)));
                    }
                }
                if let (Some(start), Some(end)) = (min_start, max_end) {
                    arm_body_spans.push(bonsai_common::Span::new(file, start, end));
                }
            }
        }
        if !arm_body_spans.is_empty() {
            spans_per_match.push(arm_body_spans);
        }
    }
    spans_per_match
}

/// Lower the optional boolean guard on each Scala `case` clause against the
/// exact synthetic branch span used for that arm. The shared match-arm
/// splitter owns only control-flow shape; Scala owns the grammar fact that a
/// `case pattern if condition => body` executes the body precisely when that
/// parsed condition is true.
fn collect_scala_case_guard_conditions(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_lang_api::BranchConditionFact, String)> {
    let mut facts = Vec::new();
    for match_node in collect_kinds(tree, &["match_expression"]) {
        let Some(case_block) = first_named_child_of_kind(&match_node, "case_block") else {
            continue;
        };
        let mut block_cursor = case_block.walk();
        for clause in case_block
            .named_children(&mut block_cursor)
            .filter(|child| child.kind() == "case_clause")
        {
            let mut clause_cursor = clause.walk();
            let children = clause.named_children(&mut clause_cursor).collect::<Vec<_>>();
            let Some(guard) = children.iter().copied().find(|child| child.kind() == "guard") else {
                continue;
            };
            let Some(condition) = guard
                .child_by_field_name("condition")
                .or_else(|| guard.named_child(0))
            else {
                continue;
            };
            let bodies = children
                .iter()
                .enumerate()
                .filter_map(|(index, child)| {
                    (clause.field_name_for_named_child(index as u32) == Some("body")).then_some(*child)
                })
                .collect::<Vec<_>>();
            let (Some(first), Some(last)) = (bodies.first(), bodies.last()) else {
                continue;
            };
            let branch_span = Span::new(file, first.start_byte() as u64, last.end_byte() as u64);
            let condition_span = span_of(file, &condition);
            facts.push((
                bonsai_lang_api::BranchConditionFact {
                    branch_span,
                    condition_span,
                    polarity: bonsai_lang_api::BranchConditionPolarity::Positive,
                    membership: None,
                    expression: Some(bonsai_lang_api::kit::lower_boolean_condition_expression(
                        condition, file, &HANDLER, src,
                    )),
                },
                node_text(&condition, src).trim().to_string(),
            ));
        }
    }
    facts
}

fn annotate_scala_case_guard_branches(
    events: &mut [FlowEvent],
    guards: &[(bonsai_lang_api::BranchConditionFact, String)],
) {
    for event in events {
        match event {
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                if let Some((_, rendering)) = guards.iter().find(|(fact, _)| fact.branch_span == *span) {
                    *condition = Some(rendering.clone());
                }
                annotate_scala_case_guard_branches(then_events, guards);
                annotate_scala_case_guard_branches(else_events, guards);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                annotate_scala_case_guard_branches(body, guards);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                annotate_scala_case_guard_branches(body, guards);
                annotate_scala_case_guard_branches(catch_events, guards);
                annotate_scala_case_guard_branches(finally_events, guards);
            }
            _ => {}
        }
    }
}

/// Lower the executable bodies of `case` clauses that belong to a parsed
/// `match_expression`.
///
/// Scala uses the same `case_block` CST node for two different runtime
/// constructs: the arms of an immediately evaluated `match`, and a
/// first-class `PartialFunction` value passed to another call. The handler
/// therefore keeps `case_block` as a callable boundary. This adapter-owned
/// pass re-enters only case blocks whose direct parent is the exact
/// `match_expression`, so ordinary PartialFunction arguments remain dormant
/// until compiler/rule facts prove a callback invocation.
fn lower_scala_match_case_bodies(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let class_names = index
        .defs
        .iter()
        .filter(|decl| matches!(decl.kind, DeclKind::Class | DeclKind::Struct | DeclKind::Enum))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();

    for match_node in collect_kinds(tree, &["match_expression"]) {
        let match_span = span_of(file, &match_node);
        let Some(case_block) = first_named_child_of_kind(&match_node, "case_block") else {
            continue;
        };
        if case_block
            .parent()
            .is_none_or(|parent| parent.id() != match_node.id())
        {
            continue;
        }

        let mut body_events = Vec::new();
        let mut block_cursor = case_block.walk();
        for clause in case_block
            .named_children(&mut block_cursor)
            .filter(|child| child.kind() == "case_clause")
        {
            let mut clause_cursor = clause.walk();
            for (index, body) in clause.named_children(&mut clause_cursor).enumerate() {
                if clause.field_name_for_named_child(index as u32) != Some("body") {
                    continue;
                }
                walk_flow_node_into(body, file, src, &HANDLER, &class_names, &mut body_events);
            }
        }
        if body_events.is_empty() {
            continue;
        }

        for decl in &mut index.defs {
            if append_scala_match_body_events(&mut decl.flow_events, match_span, &body_events) {
                break;
            }
        }
    }
}

fn append_scala_match_body_events(
    events: &mut [FlowEvent],
    match_span: Span,
    body_events: &[FlowEvent],
) -> bool {
    for event in events {
        match event {
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } => {
                if *span == match_span {
                    for body_event in body_events {
                        let body_span = scala_flow_event_span(body_event);
                        if !then_events.iter().any(|existing| {
                            scala_flow_event_span(existing) == body_span
                                && std::mem::discriminant(existing) == std::mem::discriminant(body_event)
                        }) {
                            then_events.push(body_event.clone());
                        }
                    }
                    return true;
                }
                if append_scala_match_body_events(then_events, match_span, body_events)
                    || append_scala_match_body_events(else_events, match_span, body_events)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if append_scala_match_body_events(body, match_span, body_events) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if append_scala_match_body_events(body, match_span, body_events)
                    || append_scala_match_body_events(catch_events, match_span, body_events)
                    || append_scala_match_body_events(finally_events, match_span, body_events)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Extract the dotted package path from a file's `package_clause`, if any.
///
/// Returns the path as a list of segments (e.g. `package com.acme` →
/// `["com", "acme"]`) so callers can feed it to
/// `apply_module_path_semantic_identity`. Returns `None` for files without
/// an explicit `package` declaration.
fn extract_scala_package(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        // Look for the dotted path child; grammars vary on which named
        // kind exposes it.
        let mut clause_cursor = child.walk();
        for subchild in child.children(&mut clause_cursor) {
            if matches!(
                subchild.kind(),
                "package_identifier" | "stable_identifier" | "identifier"
            ) {
                let text = node_text(&subchild, src);
                let segments: Vec<String> = text
                    .split('.')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
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

/// Convert a Scala accessor method whose single Return reads a dotted
/// receiver field (`def cmd: String = data.cmd`) into a `Call+Return`
/// chain so the call dispatches to the receiver-typed member (case-
/// class accessor / sibling getter) and threads taint through the
/// 1-level interprocedural receiver-field bridge. Mirrors the equivalent
/// lang_csharp / lang_dart conversion.
fn rewrite_scala_member_access_accessors(index: &mut DeclIndex) {
    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
            continue;
        }
        if !decl.params.is_empty() {
            continue;
        }
        let Some((return_span, return_flow)) = decl.flow_events.iter().find_map(|event| match event {
            FlowEvent::Return { span, value_flow, .. } => Some((*span, value_flow.clone())),
            _ => None,
        }) else {
            continue;
        };
        let Some(projection) = return_flow.projection.as_ref() else {
            continue;
        };
        let Some((call_receiver, call_name)) = scala_dotted_member_access_parts(projection) else {
            continue;
        };
        if decl.flow_events.iter().any(|event| match event {
            FlowEvent::Return { span, .. } => *span != return_span,
            FlowEvent::Call { span, name, .. } => *span != return_span || name != &call_name,
            _ => true,
        }) {
            continue;
        }
        // A primary-constructor `val`/`var` is an instance field even when
        // Scala source refers to it without `this.`. Preserve that compiler
        // place explicitly so constructor state and later accessor reads use
        // the same IDG storage identity. The decision comes from the
        // adapter's typed class-field aliases, not from a field-name list.
        if !call_receiver.contains('.')
            && decl.implicit_receiver_names.iter().any(|name| name == "this")
            && decl.type_aliases.iter().any(|alias| alias.name == call_receiver)
        {
            // This is a field projection, not a method invocation. Keep it as
            // an exact compiler place so `this.data` written by the primary
            // constructor and `this.data.cmd` read here share the same IDG
            // storage prefix. Synthesizing a zero-argument call would make
            // the result depend on an accessor declaration and split the
            // projected field state at that artificial call boundary.
            let place = format!("this.{call_name}");
            let body_span = return_span;
            decl.flow_events = vec![FlowEvent::Return {
                span: body_span,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                value_text: Some(place.clone()),
                value_name: Some(place.clone()),
                value_flow: bonsai_lang_api::ExpressionFlow::from_place(&place),
            }];
            continue;
        }
        let body_span = return_span;
        decl.flow_events = vec![
            FlowEvent::Call {
                span: body_span,
                name: call_name.clone(),
                receiver: Some(call_receiver),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
            FlowEvent::Return {
                span: body_span,
                value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
                value_text: Some(format!("{call_name}()")),
                value_name: None,
                value_flow: bonsai_lang_api::ExpressionFlow {
                    call_sites: vec![body_span],
                    ..Default::default()
                },
            },
        ];
    }
}

/// If `body` is a simple dotted member-access of identifiers
/// (`data.cmd`, optionally prefixed `this.`/`super.`), return
/// `(receiver, call_name)` so the synthesized accessor can model it
/// as a method call. Returns `None` for non-trivial bodies.
fn scala_dotted_member_access_parts(
    projection: &bonsai_lang_api::ExpressionProjection,
) -> Option<(String, String)> {
    let mut segments: Vec<&str> = std::iter::once(projection.base.as_str())
        .chain(projection.path.iter().map(String::as_str))
        .collect();
    if matches!(segments.first(), Some(&"this" | &"super")) {
        segments.remove(0);
    }
    if segments.len() < 2 {
        return None;
    }
    // Every segment must be a plain ASCII identifier.
    for seg in &segments {
        if seg.is_empty()
            || !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || !seg
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            return None;
        }
    }
    // Receiver = up-to-last-dot; call_name = full dotted form.
    let call_name = segments.join(".");
    let receiver = segments[..segments.len() - 1].join(".");
    Some((receiver, call_name))
}

/// Qualify a bare read `val c = cmd` of a sibling zero-arg member by
/// rewriting to `Assign{source_call:cmd}` plus an explicit `Call`
/// event so `walk_call`'s argless fallback synthesizes a recv-slot
/// for the interprocedural receiver-field bridge.
fn qualify_scala_implicit_member_reads(index: &mut DeclIndex) {
    bonsai_lang_api::qualify_implicit_member_reads_in_index(index, |name| ImplicitMemberReadCall {
        source_call: name.to_string(),
        call_name: name.to_string(),
        receiver: None,
        call_kind: CallKind::Function,
    });
}

/// Synthesize the parameterless getter methods Scala generates for concrete
/// stored `val`/`var` members and public primary-constructor properties.
///
/// The source grammar uses the same `field_expression` for a stored member
/// and a source-defined parameterless method. The adapter therefore emits a
/// generic receiver call for the read; this exact declaration inventory gives
/// that call a real compiler target without putting field names in shared
/// analysis.
fn synthesize_scala_stored_property_accessors(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut next = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(1, |m| m + 1);
    let mut synthesized: Vec<Decl> = Vec::new();
    for class_node in collect_kinds(tree, &["class_definition", "object_definition"]) {
        // Detect the grammar's `case` token, usually nested under the
        // `modifiers` child.
        let mut is_case = false;
        let mut cw = class_node.walk();
        for child in class_node.children(&mut cw) {
            if matches!(child.kind(), "modifiers") {
                let mut mw = child.walk();
                for m in child.children(&mut mw) {
                    if m.kind() == "case" {
                        is_case = true;
                        break;
                    }
                }
            }
            if child.kind() == "case" {
                is_case = true;
            }
        }
        let class_span = span_of(file, &class_node);
        let Some(parent_decl) = idx
            .defs
            .iter()
            .find(|d| is_class_like(d.kind) && d.span == class_span)
        else {
            continue;
        };
        let parent_sym = parent_decl.symbol;
        let module_path = parent_decl.module_path.clone();
        let mut comps: Vec<(String, Span, Visibility)> = Vec::new();
        if let Some(params_node) = first_named_child_of_kind(&class_node, "class_parameters") {
            let mut pw = params_node.walk();
            for child in params_node.children(&mut pw) {
                if child.kind() != "class_parameter"
                    || (!is_case && !scala_class_parameter_declares_property(child, src))
                {
                    continue;
                }
                let mut subw = child.walk();
                if let Some(name_node) = child.children(&mut subw).find(|sub| sub.kind() == "identifier") {
                    let name = node_text(&name_node, src).trim().to_string();
                    if !name.is_empty() {
                        comps.push((name, span_of(file, &name_node), scala_node_visibility(child, src)));
                    }
                };
            }
        }
        // Only direct template members are instance storage. Local bindings
        // inside methods and nested type members belong to their own scopes.
        if let Some(body) = first_named_child_of_kind(&class_node, "template_body") {
            let mut cursor = body.walk();
            for member in body.named_children(&mut cursor) {
                if !matches!(member.kind(), "val_definition" | "var_definition") {
                    continue;
                }
                let Some(pattern) = member
                    .child_by_field_name("pattern")
                    .or_else(|| member.named_child(0))
                else {
                    continue;
                };
                let Some(name) = parameter_binding_name(pattern, src) else {
                    continue;
                };
                let name_span = pattern
                    .child_by_field_name("name")
                    .or_else(|| (pattern.kind() == "identifier").then_some(pattern))
                    .map_or_else(|| span_of(file, &pattern), |node| span_of(file, &node));
                if !comps.iter().any(|(existing, _, _)| existing == &name) {
                    comps.push((name, name_span, scala_node_visibility(member, src)));
                }
            }
        }
        if comps.is_empty() {
            continue;
        }
        for (comp, comp_span, visibility) in &comps {
            let already = idx.defs.iter().chain(synthesized.iter()).any(|d| {
                d.parent == Some(parent_sym)
                    && d.name == *comp
                    && d.params.is_empty()
                    && matches!(d.kind, DeclKind::Method | DeclKind::Function)
            });
            if already {
                continue;
            }
            let field = format!("this.{comp}");
            synthesized.push(Decl {
                symbol: SymbolId::new(next),
                kind: DeclKind::Method,
                name: comp.clone(),
                qualified_name: None,
                module_path: module_path.clone(),
                span: *comp_span,
                name_span: *comp_span,
                visibility: *visibility,
                parent: Some(parent_sym),
                body_span: Some(*comp_span),
                flow_events: vec![FlowEvent::Return {
                    span: *comp_span,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                    value_text: Some(field.clone()),
                    value_name: Some(field.clone()),
                    value_flow: bonsai_lang_api::ExpressionFlow::from_place(field.clone()),
                }],
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
                receiver_state_sources: vec![field],
                return_type: None,
                is_variadic: false,
            });
            next += 1;
        }
    }
    idx.defs.extend(synthesized);
}

#[cfg(test)]
mod import_tests {
    use super::*;

    fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
        let language = language_from_pack(PACK_NAME).expect("scala grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set scala grammar");
        let tree = parser.parse(src.as_bytes(), None).expect("parse scala source");
        parse_imports(&tree, src.as_bytes(), FileId::new(0))
    }

    #[test]
    fn selectors_are_lowered_from_cst_nodes() {
        let imports = parse_import_specs(
            "import a.b.{A, B => BB, C as CC, *, given, given Foo}\n\
             import a.b.Item as Renamed\n",
        );

        assert!(
            imports.iter().any(|spec| {
                spec.module == "a.b" && spec.original_name.as_deref() == Some("A") && spec.alias.is_none()
            }),
            "{imports:#?}"
        );
        assert!(imports.iter().any(|spec| {
            spec.module == "a.b"
                && spec.original_name.as_deref() == Some("B")
                && spec.alias.as_deref() == Some("BB")
        }));
        assert!(imports
            .iter()
            .any(|spec| spec.module == "a.b" && spec.is_wildcard));
        assert!(imports.iter().any(|spec| {
            spec.module == "a.b" && spec.original_name.as_deref() == Some("Foo") && spec.alias.is_none()
        }));
        assert!(imports.iter().any(|spec| {
            spec.module == "a.b"
                && spec.original_name.as_deref() == Some("Item")
                && spec.alias.as_deref() == Some("Renamed")
        }));
    }
}
