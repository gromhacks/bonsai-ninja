//! C# language adapter.
mod parse_recovery;

use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_assign_targets, collect_param_type_aliases, decl_index_from_tree_with_handler,
    extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, canonical_simple_type_name, collect_kinds,
        collect_receiver_field_writes, collect_receiver_state_sources,
        expression_flow_from_node_with_handler, language_from_pack, node_text,
        package_module_segments_with_workspace_prefix, parse_with, sort_dedup_finite_literal_selections,
        span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, CallArg, CallKind, CallTargetExtraction, DeclIndex,
    DeclKind, FieldWrite, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter,
    LanguageCapabilities, LanguageId, PatternBindingSite, StaticAggregateFieldValue, StaticScalarValue,
    TypeAliasBinding, TypeAliasVocabulary, Visibility, EMPTY_HANDLER,
};
use parse_recovery::csharp_parse_recovery_edits;
use tree_sitter::Node;

fn csharp_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = match node.kind() {
        "invocation_expression" => node.child_by_field_name("function")?,
        "object_creation_expression" => node.child_by_field_name("type")?,
        _ => return None,
    };
    let full_text = node_text(&target, src).trim();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text: full_text.to_string(),
    })
}

/// Lower member assignments inside a directly assigned object initializer as
/// ordinary qualified writes on that newly-bound receiver.
///
/// C#'s CST stores `var options = new Config { Mode = value }` as a
/// constructor call containing a bare `Mode = value` assignment. The bare
/// member has no receiver in source syntax, but the enclosing direct
/// initializer proves that its receiver is exactly `options`. This adapter
/// fact keeps the shared write matcher and IDG vocabulary-free. Object
/// creations nested in another expression are deliberately rejected because
/// their fields do not belong to the outer assignment target.
fn csharp_object_initializer_member_write_events(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    if node.kind() != "object_creation_expression" {
        return Vec::new();
    }
    let Some(parent) = node.parent() else {
        return Vec::new();
    };
    let owner = match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("name").filter(|_| {
            let mut cursor = parent.walk();
            parent
                .named_children(&mut cursor)
                .last()
                .is_some_and(|value| value.id() == node.id())
        }),
        "assignment_expression" => parent
            .child_by_field_name("right")
            .filter(|value| value.id() == node.id())
            .and_then(|_| parent.child_by_field_name("left")),
        _ => None,
    };
    let Some(owner) = owner else {
        return Vec::new();
    };
    let owner = expression_flow_from_node_with_handler(owner, file, src, handler)
        .place
        .unwrap_or_else(|| node_text(&owner, src).trim().to_string());
    if owner.is_empty() {
        return Vec::new();
    }
    let Some(initializer) = node.child_by_field_name("initializer") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut cursor = initializer.walk();
    for member in initializer
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "assignment_expression")
    {
        let (Some(left), Some(right)) = (
            member.child_by_field_name("left"),
            member.child_by_field_name("right"),
        ) else {
            continue;
        };
        if left.kind() != "identifier" {
            continue;
        }
        let field = node_text(&left, src).trim();
        if field.is_empty() {
            continue;
        }
        let value_flow = expression_flow_from_node_with_handler(right, file, src, handler);
        let source_name = value_flow.place.clone().filter(|place| !place.contains('.'));
        out.push(FlowEvent::Assign {
            span: span_of(file, &member),
            target: format!("{owner}.{field}"),
            source_name,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: value_flow.source_names,
            declares_new_binding: false,
            value_kind: handler.expression_value_kind(right, src),
        });
    }
    out
}

fn csharp_pattern_bindings(node: Node<'_>) -> Vec<PatternBindingSite<'_>> {
    let mut sites = Vec::new();
    if let Some(condition) = node.child_by_field_name("condition") {
        let mut stack = vec![condition];
        while let Some(current) = stack.pop() {
            if current.kind() == "is_pattern_expression" {
                if let (Some(source), Some(pattern)) = (
                    current.child_by_field_name("expression"),
                    current.child_by_field_name("pattern"),
                ) {
                    csharp_pattern_binding_names(pattern, current, source, &mut sites);
                }
                continue;
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
    }
    if let (Some(source), Some(body)) = (
        node.child_by_field_name("value"),
        node.child_by_field_name("body"),
    ) {
        let mut stack = vec![body];
        while let Some(current) = stack.pop() {
            if current.kind() == "switch_section" {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    csharp_pattern_binding_names(child, current, source, &mut sites);
                }
                continue;
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
    }
    sites
}

fn csharp_pattern_binding_names<'tree>(
    pattern: Node<'tree>,
    span_node: Node<'tree>,
    source: Node<'tree>,
    out: &mut Vec<PatternBindingSite<'tree>>,
) {
    if matches!(
        pattern.kind(),
        "declaration_pattern" | "var_pattern" | "recursive_pattern"
    ) {
        if let Some(name) = pattern.child_by_field_name("name") {
            out.push(PatternBindingSite {
                span_node,
                pattern: name,
                source,
            });
        }
    }
    if pattern.kind() == "parenthesized_variable_designation" {
        let mut cursor = pattern.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.is_named() && cursor.field_name() == Some("name") {
                    out.push(PatternBindingSite {
                        span_node,
                        pattern: child,
                        source,
                    });
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    if !matches!(
        pattern.kind(),
        "pattern"
            | "declaration_pattern"
            | "var_pattern"
            | "recursive_pattern"
            | "parenthesized_pattern"
            | "and_pattern"
            | "or_pattern"
            | "negated_pattern"
            | "list_pattern"
            | "tuple_pattern"
            | "subpattern"
            | "positional_pattern_clause"
            | "property_pattern_clause"
            | "parenthesized_variable_designation"
    ) {
        return;
    }
    let mut cursor = pattern.walk();
    for child in pattern.named_children(&mut cursor) {
        if pattern
            .child_by_field_name("type")
            .is_some_and(|ty| ty.id() == child.id())
        {
            continue;
        }
        csharp_pattern_binding_names(child, span_node, source, out);
    }
}

const CSHARP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &[
        "method_declaration",
        "constructor_declaration",
        "local_function_statement",
    ],
    param_kinds: &["parameter"],
    name_field: "name",
    type_field: "type",
};

const CSHARP_DECL_KINDS: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "class_declaration",
    "struct_declaration",
    "interface_declaration",
    "record_declaration",
    "enum_declaration",
    "delegate_declaration",
    "property_declaration",
    "event_declaration",
    "field_declaration",
    "local_function_statement",
];

// C# default for type members is `private` and for top-level
// types it's `internal`, but applying that strictly when
// module_path is the file-stem fallback would block legitimate
// cross-file calls within the same project. Default to `Public`
// until real module_path coverage (namespace declarations) lands;
// tighten then.
const CSHARP_DEFAULT_VISIBILITY: Visibility = Visibility::Public;
use tree_sitter::{Language, Tree};

fn csharp_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "foreach_statement")
        .then(|| {
            Some((
                node.child_by_field_name("left")?,
                node.child_by_field_name("right")?,
            ))
        })
        .flatten()
}

pub const LANG_ID: LanguageId = LanguageId::new("csharp");
const PACK_NAME: &str = "csharp";
// `accessor_declaration` is C#'s property getter/setter body. Treating
// it as a function-declaration kind gives each accessor its own Decl
// with its own flow_events so taint that flows through `string X
// { get => …; set => _x = value; }` is observed end-to-end. Without
// this the property collapses into a Field decl and accessor body
// events disappear (audit task #131). `constructor_declaration` and
// `destructor_declaration` join the set so RAII / dtor flows surface.
const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &[
        "null_literal",
        "boolean_literal",
        "integer_literal",
        "real_literal",
        "true",
        "false",
    ],
    string_literal_kinds: &[
        "string_literal",
        "verbatim_string_literal",
        "raw_string_literal",
        "interpolated_string_expression",
        "character_literal",
    ],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["///", "/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["parameter_list"],
    parameter_kinds: &["parameter", "implicit_parameter"],
    parameter_modifier_kinds: &["attribute_list"],
    parameter_annotation_kinds: &["attribute"],
    implicit_parameter_kinds: &["implicit_parameter"],
    binding_identifier_kinds: &["identifier"],
    pattern_binding_extractor: Some(csharp_pattern_bindings),
    identifier_kinds: &["identifier"],
    aggregate_pattern_kinds: &["tuple_pattern"],
    positional_aggregate_kinds: &[
        "tuple_expression",
        "initializer_expression",
        "array_creation_expression",
    ],
    aggregate_value_field_names: &["value", "expression"],
    spread_kinds: &["spread_element"],
    spread_value_field_names: &["expression"],
    aggregate_syntax_only_kinds: &["type"],
    transparent_call_wrapper_kinds: &[
        "member_access_expression",
        "parenthesized_expression",
        "await_expression",
        "as_expression",
        "postfix_unary_expression",
    ],
    assignment_target_wrapper_kinds: &["variable_declarator", "variable_declaration"],
    binding_declaration_keyword_spellings: &["const"],
    fn_kinds: &[
        "method_declaration",
        "local_function_statement",
        "accessor_declaration",
        "constructor_declaration",
        "destructor_declaration",
    ],
    call_kinds: &["invocation_expression", "object_creation_expression"],
    constructor_call_kinds: &["object_creation_expression"],
    call_callee_field_names: &["function"],
    constructor_type_field_names: &["type"],
    call_target_extractor: Some(csharp_call_target),
    syntax_events_extractor: Some(csharp_object_initializer_member_write_events),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    argument_wrapper_kinds: &["argument"],
    argument_name_field_names: &["name"],
    argument_value_field_names: &["expression"],
    writeback_operand_field_names: &["expression"],
    transparent_expression_wrapper_kinds: &["expression"],
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: Some(csharp_argument_passing_mode),
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    runtime_type_guard_operators: &["is"],
    runtime_type_wrapper_kinds: &["parenthesized_expression"],
    value_free_expression_kinds: &["sizeof_expression", "typeof_expression"],
    value_free_call_names: &["nameof"],
    call_ref_kinds: &["invocation_expression", "object_creation_expression"],
    member_expression_kinds: &["member_access_expression"],
    subscript_expression_kinds: &["element_access_expression"],
    member_base_field_names: &["expression"],
    member_name_field_names: &["name"],
    subscript_base_field_names: &["expression"],
    subscript_index_field_names: &["argument"],
    class_kinds: &[
        "class_declaration",
        "struct_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
    ],
    class_decl_kinds: &[
        ("class_declaration", DeclKind::Class),
        ("record_declaration", DeclKind::Class),
        ("struct_declaration", DeclKind::Struct),
        ("interface_declaration", DeclKind::Interface),
        ("enum_declaration", DeclKind::Enum),
    ],
    method_kinds: &["method_declaration", "accessor_declaration"],
    method_context_kinds: &[
        "class_declaration",
        "struct_declaration",
        "interface_declaration",
        "record_declaration",
    ],
    constructor_method_kinds: &["constructor_declaration"],
    if_kinds: &[
        "if_statement",
        "conditional_expression",
        "switch_statement",
        "switch_expression",
    ],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block", "expression_statement"],
    loop_update_field_names: &["update"],
    loop_condition_field_names: &["condition"],
    loop_condition_extractor: None,
    branch_arm_kinds: &["block", "expression_statement", "switch_section"],
    exclusive_branch_arm_kinds: &["switch_section"],
    fallthrough_branch_arm_kinds: &[],
    for_kinds: &["for_statement"],
    foreach_kinds: &["foreach_statement"],
    foreach_binding_extractor: Some(csharp_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    assignment_kinds: &[
        "assignment_expression",
        "variable_declarator",
        "property_declaration",
        "variable_declaration",
        "local_declaration_statement",
    ],
    compound_assignment_operators: &[
        "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|=", "??=",
    ],
    type_only_declaration_kinds: &[
        "property_declaration",
        "variable_declaration",
        "local_declaration_statement",
    ],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_statement", "throw_expression"],
    lambda_kinds: &["lambda_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    exclusive_catch_arm_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    yield_kinds: &["yield_statement"],
    yield_value_field_names: &["expression"],
    await_kinds: &["await_expression"],
    using_kinds: &["using_statement"],
    using_body_field_names: &["body"],
    try_body_field_names: &["body"],
    implicit_receiver_names: &["this", "base"],
    ..EMPTY_HANDLER
};

fn csharp_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if [argument, value].into_iter().any(|node| {
        matches!(node.kind(), "argument" | "ref_expression") && {
            let mut cursor = node.walk();
            let has_writeback_marker = node
                .children(&mut cursor)
                .any(|child| matches!(child.kind(), "ref" | "out"));
            has_writeback_marker
        }
    }) {
        ArgumentPassingMode::WriteBack
    } else {
        ArgumentPassingMode::Value
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct CSharpAdapter;

impl CSharpAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for CSharpAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C#"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.csx` is C#'s script / interactive form — same grammar and
        // lookup semantics apply.
        &["cs", "csx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        _vfs: &bonsai_lang_api::Vfs,
        tree: &bonsai_lang_api::SyntaxTree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        csharp_parse_recovery_edits(snapshot, tree)
    }
    fn parse_recovery_edit_batches(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        _vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<Vec<bonsai_lang_api::ParseRecoveryEdit>> {
        parse_recovery::csharp_parse_recovery_edit_batches(snapshot, tree)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Exceptions: the adapter populates `Throw::thrown_type` from
        // `throw new IOException(...)` and `Try::catch_types` from
        // `catch (IOException e)`. Catch-all `catch { }` arms produce
        // an empty `catch_types` and the engine falls back to the
        // conservative seed-on-any-tainted-throw behavior.
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["object", "Object", "dynamic"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            exceptions: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["base"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "and_pattern"),
            ("custom lowering", "argument"),
            ("custom lowering", "argument_list"),
            ("custom lowering", "arrow_expression_clause"),
            ("custom lowering", "as_expression"),
            ("custom lowering", "base"),
            ("custom lowering", "base_list"),
            ("custom lowering", "block"),
            ("custom lowering", "cast_expression"),
            ("custom lowering", "catch_clause"),
            ("custom lowering", "catch_declaration"),
            ("custom lowering", "class_declaration"),
            ("custom lowering", "constructor_declaration"),
            ("custom lowering", "constructor_initializer"),
            ("custom lowering", "declaration_pattern"),
            ("custom lowering", "delegate_declaration"),
            ("custom lowering", "destructor_declaration"),
            ("custom lowering", "enum_declaration"),
            ("custom lowering", "event_declaration"),
            ("custom lowering", "event_field_declaration"),
            ("custom lowering", "field_declaration"),
            ("custom lowering", "file_scoped_namespace_declaration"),
            ("custom lowering", "foreach_statement"),
            ("custom lowering", "generic_name"),
            ("custom lowering", "identifier"),
            ("custom lowering", "implicit_type"),
            ("custom lowering", "in"),
            ("custom lowering", "interface_declaration"),
            ("custom lowering", "invocation_expression"),
            ("custom lowering", "is_pattern_expression"),
            ("custom lowering", "list_pattern"),
            ("custom lowering", "local_declaration_statement"),
            ("custom lowering", "local_function_statement"),
            ("custom lowering", "method_declaration"),
            ("custom lowering", "modifier"),
            ("custom lowering", "namespace_declaration"),
            ("custom lowering", "negated_pattern"),
            ("custom lowering", "object_creation_expression"),
            ("custom lowering", "or_pattern"),
            ("custom lowering", "out"),
            ("custom lowering", "parenthesized_expression"),
            ("custom lowering", "parenthesized_pattern"),
            ("custom lowering", "parenthesized_variable_designation"),
            ("custom lowering", "pattern"),
            ("custom lowering", "positional_pattern_clause"),
            ("custom lowering", "property_declaration"),
            ("custom lowering", "property_pattern_clause"),
            ("custom lowering", "qualified_name"),
            ("custom lowering", "record_declaration"),
            ("custom lowering", "recursive_pattern"),
            ("custom lowering", "ref"),
            ("custom lowering", "ref_expression"),
            ("custom lowering", "static"),
            ("custom lowering", "struct"),
            ("custom lowering", "struct_declaration"),
            ("custom lowering", "subpattern"),
            ("custom lowering", "switch_section"),
            ("custom lowering", "switch_expression_arm"),
            ("custom lowering", "this"),
            ("custom lowering", "tuple_pattern"),
            ("custom lowering", "type"),
            ("custom lowering", "using_directive"),
            ("custom lowering", "var_pattern"),
            ("custom lowering", "variable_declaration"),
            ("custom lowering", "variable_declarator"),
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
        let mut class_member_names_by_symbol: std::collections::HashMap<
            bonsai_common::SymbolId,
            std::collections::HashSet<String>,
        > = std::collections::HashMap::new();
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            mark_csharp_record_structs(&mut idx, tree, file);
            // Phase-6 return-type extraction: `T Method() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, tree, src, &HANDLER);
            for decl in &mut idx.defs {
                populate_csharp_exception_types(&mut decl.flow_events, tree, src);
            }
        }
        let pkg = parsed.as_ref().and_then(|(snapshot, tree)| {
            extract_csharp_namespace(tree.root_node(), snapshot.text.as_bytes())
        });
        if let Some(segments) = pkg {
            let segments = package_module_segments_with_workspace_prefix(file, ctx, segments, &[]);
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_csharp_visibility(tree.root_node(), file, src);
            let alias_map = collect_param_type_aliases(tree, file, src, &CSHARP_TYPE_ALIASES);
            // Locally-declared receiver types (casts / typed locals).
            let local_alias_map = collect_csharp_local_type_aliases(tree, file, src);
            // Class-level field/property type bindings extend each
            // method's `type_aliases`. A field declared as `private
            // readonly AuthService _authService = new AuthService();`
            // must be visible inside the class's methods so receiver
            // calls like `_authService.RunAdminCommand(...)` resolve
            // through the workspace's `AuthService` decl. The
            // class-scoped collection mirrors Java's pattern in
            // `lang_java` and applies symmetrically to property
            // declarations (`public Foo Bar { get; set; }` carries
            // the same `Bar : Foo` binding).
            let class_field_aliases = collect_csharp_class_field_aliases(tree, file, src);
            // Pre-compute the parent class span for each method-like
            // decl so the per-decl pass below can patch `type_aliases`
            // without re-borrowing `idx.defs` while it's already
            // mutably borrowed.
            let class_span_for_parent: std::collections::HashMap<bonsai_common::SymbolId, Span> = idx
                .defs
                .iter()
                .filter(|candidate| is_class_like(candidate.kind))
                .map(|candidate| (candidate.symbol, candidate.span))
                .collect();
            for (class_symbol, class_span) in &class_span_for_parent {
                let Some(field_aliases) = class_field_aliases
                    .iter()
                    .find_map(|(span, aliases)| (*span == *class_span).then_some(aliases))
                else {
                    continue;
                };
                let names = class_member_names_by_symbol.entry(*class_symbol).or_default();
                names.extend(
                    field_aliases
                        .iter()
                        .map(|alias| alias.name.trim())
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                );
            }
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                let mut aliases = alias_map.get(&decl.span).cloned().unwrap_or_default();
                if let Some(locals) = local_alias_map.get(&decl.span) {
                    for alias in locals {
                        // Param annotations (added first) take precedence
                        // over a local of the same name.
                        if !aliases.iter().any(|existing| existing.name == alias.name) {
                            aliases.push(alias.clone());
                        }
                    }
                }
                if matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    if let Some(class_span) = decl
                        .parent
                        .and_then(|parent_sym| class_span_for_parent.get(&parent_sym).copied())
                    {
                        if let Some(field_aliases) = class_field_aliases
                            .iter()
                            .find_map(|(span, list)| (*span == class_span).then_some(list))
                        {
                            for alias in field_aliases {
                                if !aliases.contains(alias) {
                                    aliases.push(alias.clone());
                                }
                            }
                        }
                    }
                }
                if !aliases.is_empty() {
                    decl.type_aliases = aliases;
                }
            }
            // Per-class `bases`: `class Echo : Base, IFoo` → ["Base", "IFoo"].
            // C# uses a single `base_list` for both class super and
            // interface impls — they're indistinguishable in syntax.
            let bases_by_span = collect_csharp_class_bases(tree, file, src);
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
        // Synthesize implicit members of positional `record`
        // declarations (canonical constructor + component accessors) so
        // `new R(.., tainted, ..)` and `r.Comp` thread taint — C#
        // records have no grammar nodes for these. Shared with lang_java.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            bonsai_lang_api::kit::synthesize_record_members(&mut idx, tree, src, file);
            // Expression-bodied properties (`X => expr;`) have no
            // accessor node, so synthesize their getter before resolving
            // bare property reads below.
            synthesize_csharp_expression_bodied_properties(&mut idx, tree, src, file);
            // Constructor initializer clauses are not ordinary body calls in
            // the C# grammar, so lower their exact `this(...)` / `base(...)`
            // call facts explicitly. Constructor arguments do not become a
            // synthetic whole-object return: instance state is represented by
            // the exact receiver-field writes collected below.
            synthesize_csharp_constructor_initializer_calls(&mut idx, tree, src, file);
            let selections = collect_csharp_finite_literal_selections(&idx, tree, file);
            idx.finite_literal_selections.extend(selections);
            sort_dedup_finite_literal_selections(&mut idx.finite_literal_selections);
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                tree,
                file,
                src,
                &HANDLER,
                csharp_static_scalar,
            );
            bonsai_lang_api::kit::populate_assignment_inline_callback_static_returns(
                &mut idx,
                tree,
                src,
                &HANDLER,
                csharp_static_scalar,
            );
            populate_csharp_assigned_aggregate_arguments(&mut idx, tree, file, src);
        }
        // Resolve bare implicit-`this` property reads/writes. C# accesses a
        // zero-arg property/getter by its bare name (`var c = Cmd;` for
        // `string Cmd => Data.Cmd;`) and writes instance properties as
        // `Data = data;` inside constructors. Rewrite those implicit
        // receiver accesses so the IDG can stitch property returns and
        // constructor field writes onto object instances.
        qualify_csharp_implicit_member_accesses(&mut idx, &class_member_names_by_symbol);
        for decl in &mut idx.defs {
            enrich_csharp_receiver_field_writes(decl);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`var c = new Foo()`
        // → `c: Foo`) is driven by the object-creation CST node or an
        // exactly resolved declaration. Identifier casing is never type
        // evidence: legal C# type names need not follow style conventions.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

#[derive(Clone)]
struct CSharpAggregateAssignment {
    assignment_span: Span,
    block: Option<Span>,
    next_use: Option<u64>,
    fields: Option<Vec<StaticAggregateFieldValue>>,
}

/// Carry fields from a fresh local initializer to its first use in the same
/// block. Mutations, aliases, escapes, and conditional definitions do not
/// provide exact configuration. This is compiler structure only:
/// framework/API identities and the security meaning of fields stay in rule
/// data. Same-spelled locals in another callable are never considered, and a
/// later non-aggregate/dynamic assignment clears the earlier proof.
fn populate_csharp_assigned_aggregate_arguments(
    index: &mut DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    let root = tree.root_node();
    let mut identifiers = std::collections::HashMap::<&str, Vec<u64>>::new();
    for node in collect_kinds(tree, &["identifier"]) {
        identifiers
            .entry(node_text(&node, src))
            .or_default()
            .push(node.start_byte() as u64);
    }
    for offsets in identifiers.values_mut() {
        offsets.sort_unstable();
    }
    let mut assignments = std::collections::HashMap::<
        Option<Span>,
        std::collections::HashMap<&str, Vec<CSharpAggregateAssignment>>,
    >::new();
    for (scope, target, assignment) in index.assignment_values.iter().filter_map(|fact| {
        let target = fact.target.as_ref()?;
        if !is_csharp_local_identifier(target) {
            return None;
        }
        let value = csharp_node_for_exact_span(root, fact.value_span)?;
        let offsets = identifiers.get(target.as_str());
        let next_use = offsets.and_then(|offsets| {
            offsets
                .get(offsets.partition_point(|offset| *offset < fact.assignment_span.end))
                .copied()
        });
        Some((
            csharp_callable_scope(value, file),
            target.as_str(),
            CSharpAggregateAssignment {
                assignment_span: fact.assignment_span,
                block: csharp_direct_local_initializer_block(value).map(|block| span_of(file, &block)),
                next_use,
                fields: csharp_object_initializer_fields(value, src),
            },
        ))
    }) {
        assignments
            .entry(scope)
            .or_default()
            .entry(target)
            .or_default()
            .push(assignment);
    }
    for scopes in assignments.values_mut() {
        for values in scopes.values_mut() {
            values.sort_by_key(|value| value.assignment_span.end);
        }
    }

    for argument in &mut index.call_argument_values {
        let Some(place) = argument
            .value_flow
            .place
            .as_deref()
            .filter(|place| is_csharp_local_identifier(place))
        else {
            continue;
        };
        let Some(argument_node) = csharp_node_for_exact_span(root, argument.argument_span) else {
            continue;
        };
        if !csharp_argument_is_local_read(argument_node, place, src) {
            continue;
        }
        let mut call = argument_node;
        while !HANDLER.call_kinds.contains(&call.kind()) {
            let Some(parent) = call.parent() else {
                break;
            };
            call = parent;
        }
        // C# evaluates every argument before entering the callee. A later
        // argument may mutate/escape this same object after its earlier
        // argument expression has been evaluated.
        if !HANDLER.call_kinds.contains(&call.kind())
            || identifiers.get(place).is_some_and(|offsets| {
                offsets
                    .get(offsets.partition_point(|offset| *offset < argument.argument_span.end))
                    .is_some_and(|offset| *offset < call.end_byte() as u64)
            })
        {
            continue;
        }
        let scope = csharp_callable_scope(argument_node, file);
        let Some(values) = assignments.get(&scope).and_then(|values| values.get(place)) else {
            continue;
        };
        let count = values
            .partition_point(|assignment| assignment.assignment_span.end <= argument.argument_span.start);
        let Some(latest) = count.checked_sub(1).and_then(|at| values.get(at)) else {
            continue;
        };
        let block = csharp_enclosing_block(argument_node).map(|block| span_of(file, &block));
        if latest.block.is_none()
            || latest.block != block
            || latest
                .next_use
                .is_some_and(|offset| offset < argument.argument_span.start)
        {
            continue;
        }
        argument.exact_static_aggregate_fields = latest.fields.clone().unwrap_or_default();
    }
}

fn csharp_argument_is_local_read(mut node: Node<'_>, place: &str, src: &[u8]) -> bool {
    if node.kind() == "argument" {
        let mut cursor = node.walk();
        if node
            .children(&mut cursor)
            .any(|child| matches!(child.kind(), "ref" | "out"))
        {
            return false;
        }
        let mut cursor = node.walk();
        let Some(value) = node.named_children(&mut cursor).last() else {
            return false;
        };
        node = value;
    }
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        let Some(value) = node.named_child(0) else {
            return false;
        };
        node = value;
    }
    node.kind() == "identifier" && node_text(&node, src) == place
}

fn csharp_direct_local_initializer_block(value: Node<'_>) -> Option<Node<'_>> {
    let declarator = value
        .parent()
        .filter(|node| node.kind() == "variable_declarator")?;
    let declaration = declarator
        .parent()
        .filter(|node| node.kind() == "variable_declaration")?;
    let statement = declaration
        .parent()
        .filter(|node| node.kind() == "local_declaration_statement")?;
    statement.parent().filter(|node| node.kind() == "block")
}

fn csharp_enclosing_block(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "block" {
            return Some(node);
        }
        if HANDLER.fn_kinds.contains(&node.kind()) || HANDLER.lambda_kinds.contains(&node.kind()) {
            return None;
        }
        node = node.parent()?;
    }
}

fn is_csharp_local_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn csharp_node_for_exact_span(root: Node<'_>, span: Span) -> Option<Node<'_>> {
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

fn csharp_callable_scope(mut node: Node<'_>, file: FileId) -> Option<Span> {
    loop {
        if HANDLER.fn_kinds.contains(&node.kind()) || HANDLER.lambda_kinds.contains(&node.kind()) {
            return Some(span_of(file, &node));
        }
        node = node.parent()?;
    }
}

fn csharp_object_initializer_fields(value: Node<'_>, src: &[u8]) -> Option<Vec<StaticAggregateFieldValue>> {
    let initializer = if value.kind() == "initializer_expression" {
        value
    } else if value.kind() == "object_creation_expression" {
        value.child_by_field_name("initializer").or_else(|| {
            let mut cursor = value.walk();
            let initializer = value
                .named_children(&mut cursor)
                .find(|child| child.kind() == "initializer_expression");
            initializer
        })?
    } else {
        return None;
    };

    let mut fields = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut saw_member = false;
    let mut cursor = initializer.walk();
    for member in initializer.named_children(&mut cursor) {
        if member.kind() != "assignment_expression" {
            return None;
        }
        let key = member.child_by_field_name("left")?;
        let value = member.child_by_field_name("right")?;
        if key.kind() != "identifier" {
            return None;
        }
        let path = vec![node_text(&key, src).trim().to_string()];
        if path[0].is_empty() || !seen.insert(path.clone()) {
            return None;
        }
        saw_member = true;
        if let Some(value) = csharp_static_scalar(value, src) {
            fields.push(StaticAggregateFieldValue { path, value });
        }
    }
    saw_member.then_some(fields)
}

fn csharp_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "null_literal" => Some(StaticScalarValue::Null),
        "boolean_literal" | "true" | "false" => match node_text(&node, src).trim() {
            "true" => Some(StaticScalarValue::Boolean(true)),
            "false" => Some(StaticScalarValue::Boolean(false)),
            _ => None,
        },
        "string_literal" | "verbatim_string_literal" | "raw_string_literal" => {
            csharp_static_string_literal(node, src).map(StaticScalarValue::String)
        }
        _ => None,
    }
}

/// Decode the runtime value of a complete non-interpolated C# string
/// literal. C# escape and delimiter syntax belongs to this frontend; shared
/// analysis receives only the exact scalar or no fact at all.
fn csharp_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    let text = node_text(&node, src).trim();
    match node.kind() {
        "string_literal" => {
            let inner = text.strip_prefix('"')?.strip_suffix('"')?;
            decode_csharp_regular_string(inner)
        }
        "verbatim_string_literal" => {
            let inner = text.strip_prefix("@\"")?.strip_suffix('"')?;
            let mut decoded = String::with_capacity(inner.len());
            let mut chars = inner.chars().peekable();
            while let Some(character) = chars.next() {
                if character != '"' {
                    decoded.push(character);
                    continue;
                }
                if chars.next() != Some('"') {
                    return None;
                }
                decoded.push('"');
            }
            Some(decoded)
        }
        "raw_string_literal" => {
            // Single-line raw literals have no indentation normalization.
            // Multiline raw strings require column-sensitive trimming, so
            // leave those unknown until the frontend carries that exact
            // grammar fact rather than approximating their runtime value.
            if text.contains(['\r', '\n']) {
                return None;
            }
            let delimiter = text.bytes().take_while(|byte| *byte == b'"').count();
            if delimiter < 3 || text.bytes().rev().take_while(|byte| *byte == b'"').count() != delimiter {
                return None;
            }
            text.get(delimiter..text.len().checked_sub(delimiter)?)
                .map(str::to_string)
        }
        _ => None,
    }
}

fn decode_csharp_regular_string(inner: &str) -> Option<String> {
    let mut chars = inner.chars().peekable();
    let mut decoded = String::with_capacity(inner.len());
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match chars.next()? {
            '\'' => decoded.push('\''),
            '"' => decoded.push('"'),
            '\\' => decoded.push('\\'),
            '0' => decoded.push('\0'),
            'a' => decoded.push('\u{0007}'),
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{000b}'),
            'u' => decoded.push(decode_csharp_hex_scalar(&mut chars, 4, 4)?),
            'U' => decoded.push(decode_csharp_hex_scalar(&mut chars, 8, 8)?),
            'x' => decoded.push(decode_csharp_hex_scalar(&mut chars, 1, 4)?),
            _ => return None,
        }
    }
    Some(decoded)
}

fn decode_csharp_hex_scalar<I>(
    chars: &mut std::iter::Peekable<I>,
    minimum: usize,
    maximum: usize,
) -> Option<char>
where
    I: Iterator<Item = char>,
{
    let mut value = 0_u32;
    let mut digits = 0;
    while digits < maximum {
        let Some(digit) = chars.peek().and_then(|character| character.to_digit(16)) else {
            break;
        };
        chars.next();
        value = value.checked_mul(16)?.checked_add(digit)?;
        digits += 1;
    }
    (digits >= minimum).then(|| char::from_u32(value)).flatten()
}

/// Lower a C# switch expression only when every arm produces a compiler
/// literal. The selected key can remain dynamic, but it cannot become part of
/// the returned value. This is syntax/value-shape evidence only; consumers
/// decide whether a finite literal selection is security-relevant.
fn collect_csharp_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
) -> Vec<bonsai_lang_api::FiniteLiteralSelectionFact> {
    let mut facts = Vec::new();
    for selection in collect_kinds(tree, &["switch_expression"]) {
        if !csharp_switch_outputs_are_literals(selection) {
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
        if csharp_switch_is_complete_return_value(selection) {
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

fn csharp_switch_outputs_are_literals(selection: Node<'_>) -> bool {
    let mut cursor = selection.walk();
    let arms = selection
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "switch_expression_arm")
        .collect::<Vec<_>>();
    !arms.is_empty()
        && arms.into_iter().all(|arm| {
            let mut arm_cursor = arm.walk();
            arm.named_children(&mut arm_cursor).last().is_some_and(|value| {
                matches!(
                    value.kind(),
                    "null_literal"
                        | "boolean_literal"
                        | "integer_literal"
                        | "real_literal"
                        | "string_literal"
                        | "verbatim_string_literal"
                        | "raw_string_literal"
                        | "character_literal"
                )
            })
        })
}

fn csharp_switch_is_complete_return_value(selection: Node<'_>) -> bool {
    let Some(parent) = selection.parent() else {
        return false;
    };
    match parent.kind() {
        "arrow_expression_clause" => {
            let mut cursor = parent.walk();
            parent
                .named_children(&mut cursor)
                .last()
                .is_some_and(|value| value.id() == selection.id())
        }
        "return_statement" => parent
            .child_by_field_name("expression")
            .is_some_and(|value| value.id() == selection.id()),
        _ => false,
    }
}

/// Current tree-sitter-c-sharp represents both `record class` and `record
/// struct` with `record_declaration`; the anonymous `struct` token is the
/// discriminant. Preserve that exact syntax distinction in the compiler IR
/// instead of depending on the obsolete `record_struct_declaration` alias.
fn mark_csharp_record_structs(index: &mut DeclIndex, tree: &Tree, file: FileId) {
    for record in collect_kinds(tree, &["record_declaration"]) {
        let mut cursor = record.walk();
        if !record.children(&mut cursor).any(|child| child.kind() == "struct") {
            continue;
        }
        let record_span = span_of(file, &record);
        if let Some(decl) = index
            .defs
            .iter_mut()
            .find(|decl| decl.span == record_span && decl.kind == DeclKind::Class)
        {
            decl.kind = DeclKind::Struct;
        }
    }
}

/// Synthesize getter `Method` decls for C# expression-bodied properties
/// (`public string Cmd => Data.Cmd;`). The grammar emits these as a
/// `property_declaration` whose body is an `arrow_expression_clause` with
/// no `accessor_declaration` child — so the HANDLER's fn-kind extraction
/// (which keys on `accessor_declaration`) produces no decl at all and the
/// property's return expression is invisible to the IDG. Mirror the
/// record-accessor synthesis: one zero-arg `Method` named after the
/// property whose single `Return` forwards the (receiver-qualified) body
/// expression, so a getter call resolves the property's value and a
/// tainted receiver field flows out through the property.
fn synthesize_csharp_expression_bodied_properties(
    index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let mut next_symbol = index
        .defs
        .iter()
        .map(|d| d.symbol.raw())
        .max()
        .map_or(1, |m| m + 1);
    let mut synthesized: Vec<bonsai_lang_api::Decl> = Vec::new();
    for prop in collect_kinds(tree, &["property_declaration"]) {
        // Expression-bodied only: a direct `arrow_expression_clause`
        // child. Properties with an `accessor_list` (`{ get; set; }`)
        // surface their bodies through `accessor_declaration` decls.
        let mut pc = prop.walk();
        let Some(arrow) = prop
            .children(&mut pc)
            .find(|c| c.kind() == "arrow_expression_clause")
        else {
            continue;
        };
        let Some(name_node) = prop.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        // Body expression = the arrow clause's last named child (the
        // node after the `=>` token).
        let mut ac = arrow.walk();
        let named: Vec<_> = arrow.children(&mut ac).filter(|c| c.is_named()).collect();
        let Some(expr) = named.last().copied() else {
            continue;
        };
        let body_text = node_text(&expr, src).trim().to_string();
        if body_text.is_empty() {
            continue;
        }
        let Some((parent, module_path, visibility)) = csharp_enclosing_type_decl(index, prop, file) else {
            continue;
        };
        // A property with an explicit getter/field of the same name
        // already covers this; don't double-declare.
        if index
            .defs
            .iter()
            .chain(synthesized.iter())
            .any(|d| d.parent == parent && d.name == name && d.params.is_empty())
        {
            continue;
        }
        let body_span = span_of(file, &expr);
        // If the body is a simple dotted member access (`Data.Cmd` —
        // optionally prefixed with `this.`/`base.`), model it as a
        // CALL chain rather than a single 2-level field read. The
        // IDG's interprocedural receiver-field bridge is 1-level, so
        // `Cmd => Data.Cmd` modeled as `Return this.Data.Cmd` (2-
        // level read) never connects to the caller's tainted
        // `repo.Data.Cmd`. Modeling as `Call Data.Cmd(); Return
        // call-result` mirrors the Java accessor pattern
        // (`String cmd() { return data.cmd(); }`) which the bridge
        // already handles — the call resolves to the receiver-typed
        // member (e.g. the record component's synthesized accessor),
        // and that 1-level hop forwards the tainted field.
        let flow_events = if let Some((call_receiver, call_name)) = csharp_member_access_call_parts(expr, src)
        {
            // Look up the receiver's static type from sibling
            // `property_declaration` / `field_declaration` siblings in
            // the same class so the resolver can disambiguate the
            // call's `name` against the receiver's class instead of
            // resolving back to the synthesizing property itself
            // (which would self-recurse).
            let lookup_member = csharp_receiver_member_lookup_name(&call_receiver);
            let receiver_types = csharp_lookup_member_type(prop, lookup_member, src)
                .into_iter()
                .collect();
            let mut return_flow = bonsai_lang_api::ExpressionFlow::from_place(call_name.clone());
            return_flow.call_sites.push(body_span);
            vec![
                FlowEvent::Call {
                    span: body_span,
                    name: call_name.clone(),
                    receiver: Some(call_receiver),
                    receiver_types,
                    call_kind: CallKind::Method,
                    args: Vec::new(),
                },
                FlowEvent::Return {
                    span: body_span,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
                    value_text: Some(call_name.clone()),
                    value_name: Some(call_name),
                    // Preserve both compiler facts: this is a resolved
                    // nested member call and an exact projected value.
                    // The call-site fact composes accessor summaries;
                    // the projection lets field-sensitive lowering
                    // consume only the selected member (`Data.Cmd`) and
                    // never a sibling (`Data.User`).
                    value_flow: return_flow,
                },
            ]
        } else {
            let mut value_flow = expression_flow_from_node_with_handler(expr, file, src, &HANDLER);
            if let Some(place) = csharp_exact_member_place(expr, src).map(csharp_qualify_member_place) {
                value_flow = bonsai_lang_api::ExpressionFlow::from_place(place);
            }
            let value_name = value_flow.place.clone();
            vec![FlowEvent::Return {
                span: body_span,
                value_kind: HANDLER
                    .expression_value_kind(expr, src)
                    .or(Some(bonsai_lang_api::AssignValueKind::Compound)),
                value_text: Some(body_text),
                value_name,
                value_flow,
            }]
        };
        let receiver_state_sources =
            collect_receiver_state_sources(&flow_events, &[], HANDLER.implicit_receiver_names);
        synthesized.push(bonsai_lang_api::Decl {
            symbol: bonsai_common::SymbolId::new(next_symbol),
            kind: DeclKind::Method,
            name,
            qualified_name: None,
            module_path,
            span: span_of(file, &name_node),
            name_span: span_of(file, &name_node),
            visibility,
            parent,
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
            implicit_receiver_names: vec!["this".to_string(), "base".to_string()],
            receiver_state_sources,
            return_type: None,
            is_variadic: false,
        });
        next_symbol += 1;
    }
    index.defs.extend(synthesized);
}

/// Lower exact `this(...)` / `base(...)` constructor initializer calls.
///
/// The initializer is a distinct C# grammar node rather than an ordinary
/// invocation in the constructor body. Retaining it as a constructor call is
/// required for inherited receiver-field writes. It must not also synthesize
/// a constructor return: doing so promotes every parameter mentioned in the
/// body to the entire constructed object and destroys field sensitivity.
fn synthesize_csharp_constructor_initializer_calls(
    index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let class_info_by_symbol: std::collections::HashMap<_, _> = index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.symbol, (decl.name.clone(), decl.bases.clone())))
        .collect();
    for ctor_node in collect_kinds(tree, &["constructor_declaration"]) {
        let ctor_span = span_of(file, &ctor_node);
        let Some(decl) = index
            .defs
            .iter_mut()
            .find(|d| matches!(d.kind, DeclKind::Constructor) && d.span == ctor_span)
        else {
            continue;
        };
        let parent_info = decl.parent.and_then(|parent| class_info_by_symbol.get(&parent));
        let mut initializer_call: Option<FlowEvent> = None;
        let mut cw = ctor_node.walk();
        for child in ctor_node.children(&mut cw) {
            if child.kind() == "constructor_initializer" {
                if let Some((callee, args)) =
                    csharp_constructor_initializer_call(child, file, src, parent_info)
                {
                    let span = span_of(file, &child);
                    initializer_call = Some(FlowEvent::Call {
                        span,
                        name: callee,
                        // Both `this(...)` and `base(...)` initialize the
                        // current object. The shared resolved IDG composes
                        // their exact field effects, including overloads.
                        receiver: Some("this".to_string()),
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Constructor,
                        args,
                    });
                }
            }
        }
        if let Some(call) = initializer_call {
            let already_present = decl.flow_events.iter().any(|event| {
                matches!(
                    (event, &call),
                    (
                        FlowEvent::Call { span: existing_span, name: existing_name, .. },
                        FlowEvent::Call { span, name, .. }
                    ) if existing_span == span && existing_name == name
                )
            });
            if !already_present {
                decl.flow_events.insert(0, call);
            }
        }
    }
}

fn csharp_constructor_initializer_call(
    initializer: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
    parent_info: Option<&(String, Vec<String>)>,
) -> Option<(String, Vec<CallArg>)> {
    if initializer.kind() != "constructor_initializer" {
        return None;
    }
    let mut children = initializer.walk();
    let target = initializer
        .children(&mut children)
        .find_map(|child| match child.kind() {
            "base" => parent_info.and_then(|(_, bases)| bases.first()).cloned(),
            "this" => parent_info.map(|(name, _)| name.clone()),
            _ => None,
        })?;
    let argument_list = initializer
        .named_children(&mut initializer.walk())
        .find(|child| child.kind() == "argument_list")?;
    let mut args = Vec::new();
    let mut cursor = argument_list.walk();
    for argument in argument_list.named_children(&mut cursor) {
        if argument.kind() != "argument" {
            continue;
        }
        let name = argument
            .child_by_field_name("name")
            .map(|name| node_text(&name, src).trim().to_string())
            .filter(|name| !name.is_empty());
        if let Some(argument) = call_arg_from_node_with_handler(argument, file, src, name, &HANDLER) {
            args.push(argument);
        }
    }
    let callee = target;
    Some((callee, args))
}

fn csharp_bare_identifier(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        Some(trimmed)
    } else {
        None
    }
}

fn csharp_receiver_member_lookup_name(receiver: &str) -> &str {
    receiver
        .trim()
        .strip_prefix("this.")
        .or_else(|| receiver.trim().strip_prefix("base."))
        .unwrap_or_else(|| receiver.trim())
        .rsplit('.')
        .next()
        .unwrap_or_else(|| receiver.trim())
}

/// Find a sibling `property_declaration` / `field_declaration` named
/// `member` in the type that lexically encloses `prop`, returning its
/// declared (canonical) type name. Used to set `receiver_types` on a
/// synthesized member-access Call so the resolver dispatches against
/// the receiver's class — without this, `Cmd => Data.Cmd` resolves
/// `Data.Cmd` back to the same `Cmd` property and self-recurses.
fn csharp_lookup_member_type(prop: tree_sitter::Node<'_>, member: &str, src: &[u8]) -> Option<String> {
    let mut cur = prop.parent();
    let mut class_node = None;
    while let Some(n) = cur {
        if matches!(
            n.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration" | "interface_declaration"
        ) {
            class_node = Some(n);
            break;
        }
        cur = n.parent();
    }
    let class_node = class_node?;
    let body = class_node.child_by_field_name("body")?;
    let mut walker = body.walk();
    for child in body.children(&mut walker) {
        match child.kind() {
            "property_declaration" => {
                let name_node = child.child_by_field_name("name")?;
                if node_text(&name_node, src).trim() == member {
                    let type_node = child.child_by_field_name("type")?;
                    let raw = node_text(&type_node, src).trim();
                    if raw.is_empty() {
                        return None;
                    }
                    return Some(canonical_simple_type_name(raw).to_string());
                }
            }
            "field_declaration" => {
                // C# field_declaration: `Type Name [, Name2];` — the
                // type is the `type` field; the name(s) are inside
                // `variable_declaration` children.
                let Some(type_node) = child.child_by_field_name("type") else {
                    continue;
                };
                let mut cw = child.walk();
                for cc in child.children(&mut cw) {
                    if cc.kind() != "variable_declaration" {
                        continue;
                    }
                    let mut vw = cc.walk();
                    for v in cc.children(&mut vw) {
                        if v.kind() != "variable_declarator" {
                            continue;
                        }
                        if let Some(name_node) = v.child_by_field_name("name") {
                            if node_text(&name_node, src).trim() == member {
                                let raw = node_text(&type_node, src).trim();
                                if raw.is_empty() {
                                    return None;
                                }
                                return Some(canonical_simple_type_name(raw).to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Lower a pure C# identifier/member-access chain from its CST. This never
/// tokenizes a rendered expression: calls, indexers, conditionals, and other
/// non-member syntax fail closed at their node kind.
fn csharp_exact_member_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "this_expression" | "base_expression" => {
            let value = node_text(&node, src).trim();
            csharp_bare_identifier(value).map(str::to_string)
        }
        "member_access_expression" => {
            let base = node
                .child_by_field_name("expression")
                .or_else(|| node.child_by_field_name("object"))?;
            let member = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("member"))?;
            let base = csharp_exact_member_place(base, src)?;
            let member = node_text(&member, src).trim();
            let member = csharp_bare_identifier(member)?;
            Some(format!("{base}.{member}"))
        }
        _ => None,
    }
}

fn csharp_qualify_member_place(place: String) -> String {
    if place == "this" || place == "base" || place.starts_with("this.") || place.starts_with("base.") {
        place
    } else {
        format!("this.{place}")
    }
}

fn csharp_member_access_call_parts(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    (node.kind() == "member_access_expression").then_some(())?;
    let name = csharp_qualify_member_place(csharp_exact_member_place(node, src)?);
    let (receiver, _) = name.rsplit_once('.')?;
    Some((receiver.to_string(), name))
}

/// Resolve the type declaration (`class`/`struct`/`record`/`interface`)
/// that lexically encloses `node`, returning its symbol / module / visibility.
fn csharp_enclosing_type_decl(
    index: &DeclIndex,
    node: tree_sitter::Node<'_>,
    file: FileId,
) -> Option<(
    Option<bonsai_common::SymbolId>,
    bonsai_lang_api::ModulePath,
    Visibility,
)> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if matches!(
            n.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration" | "interface_declaration"
        ) {
            let span = span_of(file, &n);
            return index
                .defs
                .iter()
                .find(|d| d.span == span)
                .map(|d| (Some(d.symbol), d.module_path.clone(), d.visibility));
        }
        cur = n.parent();
    }
    None
}

/// Rewrite bare reads of zero-arg member accessors (C# properties /
/// expression-bodied `=> expr` getters) into getter calls. C# reads a
/// property by its bare name (`var c = Cmd;` for `string Cmd =>
/// Data.Cmd;`), which the generic walker emits as `Assign { source_name:
/// "Cmd" }` — a plain identifier read that never connects to the
/// property's return, so taint stops at the property boundary. When the
/// bare RHS name matches a zero-arg member decl in this file and is NOT
/// a local/param of the method, convert it into a `source_call` so the
/// IDG resolves the getter and forwards its return into the assignment.
fn qualify_csharp_implicit_member_accesses(
    index: &mut DeclIndex,
    class_member_names_by_symbol: &std::collections::HashMap<
        bonsai_common::SymbolId,
        std::collections::HashSet<String>,
    >,
) {
    use std::collections::{HashMap, HashSet};
    // Member lookup is lexical: a getter in another class or a typed local
    // that happens to share a field's type is not an implicit `this` member.
    // Keep the declaration owner's symbol in the key instead of building a
    // file-wide name inventory.
    let mut getter_names_by_parent: HashMap<Option<bonsai_common::SymbolId>, HashSet<String>> =
        HashMap::new();
    let mut class_symbols_by_name: HashMap<String, Vec<bonsai_common::SymbolId>> = HashMap::new();
    let mut class_bases_by_symbol: HashMap<bonsai_common::SymbolId, Vec<String>> = HashMap::new();
    for decl in &index.defs {
        if matches!(decl.kind, DeclKind::Method) && decl.params.is_empty() && !decl.name.is_empty() {
            getter_names_by_parent
                .entry(decl.parent)
                .or_default()
                .insert(decl.name.clone());
        }
        if is_class_like(decl.kind) {
            class_symbols_by_name
                .entry(decl.name.clone())
                .or_default()
                .push(decl.symbol);
            class_bases_by_symbol.insert(decl.symbol, decl.bases.clone());
        }
    }
    for decl in &mut index.defs {
        if decl.flow_events.is_empty() {
            continue;
        }
        // A local binding (param or assignment target) shadows the
        // member, so those names must keep their plain-read semantics.
        let mut locals: HashSet<String> = decl.params.iter().cloned().collect();
        collect_assign_targets(&decl.flow_events, &mut locals);
        let mut getter_names = HashSet::new();
        let mut member_names = HashSet::new();
        let mut owner_stack: Vec<bonsai_common::SymbolId> = decl.parent.into_iter().collect();
        let mut seen_owners = HashSet::new();
        while let Some(owner) = owner_stack.pop() {
            if !seen_owners.insert(owner) {
                continue;
            }
            if let Some(names) = getter_names_by_parent.get(&Some(owner)) {
                getter_names.extend(names.iter().cloned());
            }
            if let Some(names) = class_member_names_by_symbol.get(&owner) {
                member_names.extend(names.iter().cloned());
            }
            for base in class_bases_by_symbol.get(&owner).into_iter().flatten() {
                if let Some(symbols) = class_symbols_by_name.get(base) {
                    owner_stack.extend(symbols.iter().copied());
                }
            }
        }
        // File-level functions have no class owner. Preserve ordinary
        // top-level getter semantics without mixing them into class methods.
        if decl.parent.is_none() {
            if let Some(names) = getter_names_by_parent.get(&None) {
                getter_names.extend(names.iter().cloned());
            }
        }
        member_names.extend(getter_names.iter().cloned());
        let params: HashSet<String> = decl.params.iter().cloned().collect();
        bonsai_lang_api::qualify_implicit_member_assign_targets(
            &mut decl.flow_events,
            &member_names,
            &params,
            |name| csharp_bare_identifier(name).map(|_| format!("this.{name}")),
        );
        bonsai_lang_api::rewrite_implicit_member_reads(
            &mut decl.flow_events,
            &getter_names,
            &locals,
            |name| bonsai_lang_api::ImplicitMemberReadCall {
                source_call: format!("this.{name}"),
                call_name: format!("this.{name}"),
                receiver: Some("this".to_string()),
                call_kind: CallKind::Method,
            },
        );
    }
}

fn enrich_csharp_receiver_field_writes(decl: &mut bonsai_lang_api::Decl) {
    if !matches!(decl.kind, DeclKind::Constructor | DeclKind::Method) {
        return;
    }
    let writes = collect_receiver_field_writes(
        &decl.flow_events,
        &decl.params,
        decl.receiver_param_index,
        &["this", "base"],
        &[],
    );
    decl.receiver_field_writes.extend(writes);
    dedup_csharp_receiver_field_writes(&mut decl.receiver_field_writes);
}

fn dedup_csharp_receiver_field_writes(writes: &mut Vec<FieldWrite>) {
    for write in writes.iter_mut() {
        write.source_param_indices.sort_unstable();
        write.source_param_indices.dedup();
    }
    writes.sort_by_key(|write| {
        (
            write.span.start,
            write.target.clone(),
            write.source_param_indices.clone(),
        )
    });
    writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
}

/// Lift every `using_directive` into an `ImportSpec`. C# splits the
/// alias out of the path: `using IO = System.IO` exposes `IO` as
/// `name:` and `System.IO` as the trailing qualified path child.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // `using_directive` shapes:
    //   `using System.Data;`              → qualified_name only
    //   `using static System.Math;`       → qualified_name (with `static` keyword)
    //   `using IO = System.IO;`           → name: identifier (alias) + qualified_name
    for using_node in collect_kinds(tree, &["using_directive"]) {
        let mut child_cursor = using_node.walk();
        // The path is the *last* qualified_name / identifier child that
        // isn't the alias `name:` field — this is the only shape that
        // works across all three forms above.
        let mut last_path: Option<tree_sitter::Node<'_>> = None;
        for child in using_node.named_children(&mut child_cursor) {
            if matches!(child.kind(), "qualified_name" | "identifier")
                && Some(child) != using_node.child_by_field_name("name")
            {
                last_path = Some(child);
            }
        }
        let Some(path_node) = last_path.or_else(|| using_node.child_by_field_name("name")) else {
            continue;
        };
        let module = node_text(&path_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        let alias = using_node
            .child_by_field_name("name")
            .map(|alias_node| node_text(&alias_node, src).to_string());
        let is_static = csharp_using_is_static(&using_node);
        imports.push(ImportSpec {
            span: span_of(file, &using_node),
            module: module.clone(),
            // `using Namespace;` makes the namespace's public type names
            // available unqualified, which is the ImportSpec wildcard
            // contract. Aliases bind one exact local name instead. Static
            // imports receive a separate local-scope wildcard below because
            // they expose members rather than namespace types.
            is_wildcard: alias.is_none() && !is_static,
            alias,
            original_name: None,
            scope: ImportScope::Module,
        });
        if is_static {
            imports.push(ImportSpec {
                span: span_of(file, &using_node),
                module,
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Local,
            });
        }
    }
    imports
}

fn csharp_using_is_static(using_node: &tree_sitter::Node<'_>) -> bool {
    // `static` is an anonymous grammar token on `using_directive`. Inspect
    // that CST child directly; re-tokenizing the whole statement would make
    // comments and whitespace part of semantic classification.
    (0..using_node.child_count())
        .filter_map(|index| u32::try_from(index).ok())
        .any(|index| {
            using_node
                .child(index)
                .is_some_and(|child| child.kind() == "static")
        })
}

/// Walk every C# class-like declaration and pull `(name, type)`
/// bindings from its `field_declaration` and `property_declaration`
/// children. Returns `(class_span, [TypeAliasBinding])` so the
/// per-method merge can attach a class's bindings to every method
/// nested inside it, matching the resolver's caller-decl
/// `type_aliases` lookup contract.
/// Collect locally-declared receiver types per method
/// (`SqlCommand c = (SqlCommand) o;`, `using var conn = Open();`),
/// keyed by the owning method/constructor span. The cast type the goal
/// (WS2) calls out surfaces on the LOCAL DECLARATION, not the
/// taint-engine flow event (which strips it), so capturing the declared
/// type here lets `receiver_type_in` / `[Type, method]` resolve a cast
/// or factory-typed receiver. Reuses the field extractor since a C#
/// `local_declaration_statement` wraps the same `variable_declaration`
/// (`type` + `variable_declarator`) shape as a `field_declaration`.
fn collect_csharp_local_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let fn_kinds = &[
        "method_declaration",
        "constructor_declaration",
        "local_function_statement",
    ];
    let mut out = std::collections::HashMap::new();
    for fn_node in collect_kinds(tree, fn_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![fn_node];
        while let Some(node) = work.pop() {
            // A nested local function owns its own locals; let its own
            // iteration scope them rather than leaking into the parent.
            if node != fn_node && fn_kinds.contains(&node.kind()) {
                continue;
            }
            if node.kind() == "local_declaration_statement" {
                extend_aliases_from_field_or_event(node, src, &mut aliases);
                // WS2: `var c = (Foo) x` / `var c = x as Foo` — an inferred
                // (`var`) LHS leaves the type only on the cast, which the
                // declared-type extractor (it sees `var`) drops. Capture the
                // cast/as type so `c.Method(...)` resolves receiver_type_in.
                extend_aliases_from_var_cast(node, src, &mut aliases);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        if !aliases.is_empty() {
            out.insert(span_of(file, &fn_node), aliases);
        }
    }
    out
}

/// WS2 cast-expression typing for inferred (`var`) locals. The declared
/// type `var` carries no class, so the only type signal is the cast on the
/// initializer (`var c = (Foo) x` / `var c = x as Foo`). Reads ONLY the
/// direct initializer (not nested casts in arguments, which would mistype
/// the local), and only when the declared type is `var` — so it never
/// clobbers a real declared type already captured by the field extractor.
fn extend_aliases_from_var_cast(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    let mut var_decl = node.child_by_field_name("declaration");
    if var_decl.is_none() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                var_decl = Some(child);
                break;
            }
        }
    }
    let Some(var_decl) = var_decl else {
        return;
    };
    let Some(type_node) = var_decl.child_by_field_name("type") else {
        return;
    };
    if node_text(&type_node, src).trim() != "var" {
        return;
    }
    let mut cursor = var_decl.walk();
    for declarator in var_decl.named_children(&mut cursor) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let mut name_node = declarator.child_by_field_name("name");
        if name_node.is_none() {
            let mut inner = declarator.walk();
            for child in declarator.named_children(&mut inner) {
                if child.kind() == "identifier" {
                    name_node = Some(child);
                    break;
                }
            }
        }
        let Some(name_node) = name_node else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        // The initializer is the declarator's `value` field (the
        // top-level RHS expression). Use the field directly so a cast
        // nested inside a call argument (`var c = Wrap((Foo) x)`) does NOT
        // mistype the local — only a cast that IS the initializer counts.
        let mut init = declarator.child_by_field_name("value");
        if init.is_none() {
            // Fallback for grammars that don't field-tag the value: take
            // the last named child that is not the binding name.
            let mut inner = declarator.walk();
            for child in declarator.named_children(&mut inner) {
                if child.id() != name_node.id() {
                    init = Some(child);
                }
            }
        }
        let Some(init) = init else {
            continue;
        };
        let Some(type_name) = csharp_cast_type_of_init(init, src) else {
            continue;
        };
        let canonical = canonical_simple_type_name(&type_name);
        if canonical.is_empty() {
            continue;
        }
        // Replace any non-useful `var`-typed binding the field extractor
        // added for this same local; the cast type is the real one.
        aliases.retain(|a| a.name != name);
        aliases.push(TypeAliasBinding {
            name,
            type_name: canonical,
        });
    }
}

/// The cast/as type of a direct initializer expression (`(Foo) x` →
/// `Foo`, `x as Foo` → `Foo`), unwrapping redundant parentheses. Returns
/// `None` for any other initializer shape so only genuine casts type the
/// local.
fn csharp_cast_type_of_init(init: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut n = init;
    while n.kind() == "parenthesized_expression" {
        let mut cursor = n.walk();
        n = n.named_children(&mut cursor).next()?;
    }
    match n.kind() {
        "cast_expression" => n
            .child_by_field_name("type")
            .map(|t| node_text(&t, src).to_string()),
        "as_expression" => n
            .child_by_field_name("type")
            .or_else(|| n.child_by_field_name("right"))
            .map(|t| node_text(&t, src).to_string()),
        _ => None,
    }
}

fn collect_csharp_class_field_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "record_struct_declaration",
        "interface_declaration",
    ];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![class_node];
        while let Some(node) = work.pop() {
            // Don't descend into nested classes — their own iteration
            // produces the right scope for their methods. A nested
            // class's fields are visible only to its own methods, not
            // the outer class's methods.
            if node != class_node && class_kinds.contains(&node.kind()) {
                continue;
            }
            match node.kind() {
                "field_declaration" | "event_field_declaration" => {
                    extend_aliases_from_field_or_event(node, src, &mut aliases);
                }
                "property_declaration" => {
                    if let Some(binding) = property_alias_from_node(node, src) {
                        if !aliases.contains(&binding) {
                            aliases.push(binding);
                        }
                    }
                }
                _ => {}
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

fn extend_aliases_from_field_or_event(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    // C# `field_declaration` wraps a `variable_declaration` whose
    // `type` field carries the field type and whose
    // `variable_declarator` children name each binding. Multi-name
    // forms (`Foo a, b, c;`) are valid for value-type fields.
    let var_decl = node.child_by_field_name("declaration").or_else(|| {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                found = Some(child);
                break;
            }
        }
        found
    });
    let Some(var_decl) = var_decl else {
        return;
    };
    let Some(type_node) = var_decl.child_by_field_name("type") else {
        return;
    };
    // `var` is an inference marker, not a declared receiver type. Cast
    // initializers are handled by `extend_aliases_from_var_cast`; all real
    // type nodes, including lowercase user-defined identifiers and language
    // primitives, remain exact compiler facts.
    if type_node.kind() == "implicit_type" || node_text(&type_node, src).trim() == "var" {
        return;
    }
    let canonical = canonical_simple_type_name(node_text(&type_node, src));
    if canonical.is_empty() {
        return;
    }
    let mut cursor = var_decl.walk();
    for declarator in var_decl.named_children(&mut cursor) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let name_node = declarator.child_by_field_name("name").or_else(|| {
            let mut inner = declarator.walk();
            let mut found = None;
            for child in declarator.named_children(&mut inner) {
                if child.kind() == "identifier" {
                    found = Some(child);
                    break;
                }
            }
            found
        });
        let Some(name_node) = name_node else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() || name == canonical {
            continue;
        }
        let binding = TypeAliasBinding {
            name,
            type_name: canonical.clone(),
        };
        if !aliases.contains(&binding) {
            aliases.push(binding);
        }
    }
}

fn property_alias_from_node(node: tree_sitter::Node<'_>, src: &[u8]) -> Option<TypeAliasBinding> {
    let type_node = node.child_by_field_name("type")?;
    let canonical = canonical_simple_type_name(node_text(&type_node, src));
    if canonical.is_empty() {
        return None;
    }
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() || name == canonical {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: canonical,
    })
}

/// C#-aware visibility collector.
///
/// Differs from the generic `collect_modifier_visibility` helper in
/// that it recognises the compound forms `protected internal` (broader
/// than either alone — caller is in the same assembly OR is a derived
/// class anywhere) and `private protected` (narrower — derived classes
/// in the same assembly only). Maps to the four-level lattice in
/// `Visibility` as follows:
///
/// - `private`            → `Private`
/// - `private protected`  → `Protected` (assembly-bounded but derived-callable)
/// - `protected`          → `Protected`
/// - `protected internal` → `Crate` (visible to whole assembly)
/// - `internal`           → `Crate`
/// - `public`             → `Public`
///
/// Visibility comes from real syntax markers; per-language
/// compound-modifier handling lives in the adapter.
fn collect_csharp_visibility(
    root: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    // Iterative DFS over the whole tree. Every CSHARP_DECL_KINDS node
    // contributes one entry; nested classes / nested local functions
    // each get their own.
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if CSHARP_DECL_KINDS.contains(&node.kind()) {
            visibility_by_span.insert(span_of(file, &node), csharp_node_visibility(node, src));
        }
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            work_stack.push(child);
        }
    }
    visibility_by_span
}

/// Resolve a single decl's visibility from its `modifier` children.
/// Compound forms (`protected internal`, `private protected`) are
/// distinct visibility levels in C# that don't map 1:1 to either side.
fn csharp_node_visibility(node: tree_sitter::Node<'_>, src: &[u8]) -> Visibility {
    let mut keywords: Vec<&str> = Vec::new();
    let mut child_cursor = node.walk();
    for child in node.children(&mut child_cursor) {
        if child.kind() == "modifier" {
            let text = node_text(&child, src);
            if matches!(text, "private" | "protected" | "internal" | "public") {
                keywords.push(text);
            }
        }
    }
    let has_private = keywords.contains(&"private");
    let has_protected = keywords.contains(&"protected");
    let has_internal = keywords.contains(&"internal");
    let has_public = keywords.contains(&"public");
    // `public` always wins — C# doesn't allow it to combine with the
    // other access modifiers.
    if has_public {
        return Visibility::Public;
    }
    if has_protected && has_internal {
        // `protected internal` — accessible in the whole assembly +
        // derived classes outside. Closest in the four-level lattice
        // is `Crate` (assembly-wide).
        return Visibility::Crate;
    }
    if has_private && has_protected {
        // `private protected` — derived classes in the same assembly
        // only. Closer to `Protected` than `Private` for resolver
        // narrowing purposes; assembly-bounded narrowing is the
        // module_path filter applied separately.
        return Visibility::Protected;
    }
    if has_protected {
        return Visibility::Protected;
    }
    if has_internal {
        return Visibility::Crate;
    }
    if has_private {
        return Visibility::Private;
    }
    CSHARP_DEFAULT_VISIBILITY
}

/// True for decl kinds that can carry a `bases` list (class super /
/// interface impl). Shared with the post-processing loop that copies
/// `bases_by_span` onto matching decls.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk C# class / struct / record / interface declarations and
/// pull bare base type names from `base_list`. Grammar shape:
///
///   `class Echo : Base, IFoo, IBar { ... }` →
///     (class_declaration name: (identifier)
///        (base_list (identifier) (identifier) (identifier))
///        body: ...)
///
/// The `base_list` lists both the parent class and any implemented
/// interfaces in source order; C# does not distinguish them
/// syntactically. Generic / qualified bases collapse to the bare tail.
fn collect_csharp_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_table = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "record_struct_declaration",
        "interface_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for child in class_node.named_children(&mut class_cursor) {
            if child.kind() != "base_list" {
                continue;
            }
            let mut entry_cursor = child.walk();
            for entry in child.named_children(&mut entry_cursor) {
                let raw = node_text(&entry, src);
                if let Some(name) = canonical_csharp_base_name(raw) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), bases));
        }
    }
    bases_table
}

/// Strip a base entry down to the bare type name. Drops generic
/// parameters (`Foo<T>` -> `Foo`) and namespace qualification
/// (`System.IO.Stream` -> `Stream`); the resolver keys on bare names.
fn canonical_csharp_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let head = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Walk `decl.flow_events` recursively and populate
/// `Throw::thrown_type` / `Try::catch_types` from the C# parse tree.
/// C# syntax:
///   throw new IOException("...")  → thrown_type: "IOException"
///   throw err                     → thrown_type: None (need data-flow)
///   `try { } catch (IOException e) { } catch (FormatException e) { }`
///                                 → `catch_types = vec!["IOException", "FormatException"]`
///   `try { } catch { }`           → `catch_types = vec![]` (catch-all)
fn populate_csharp_exception_types(
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
                if let Some(node) = bonsai_lang_api::kit::node_at_span(
                    tree.root_node(),
                    *span,
                    &["throw_statement", "throw_expression"],
                ) {
                    if let Some(name) = csharp_thrown_type_for_node(node, src) {
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
                catch_param,
                catch_arms,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if catch_types.is_empty() {
                        *catch_types = collect_csharp_catch_types(node, src);
                    }
                    // The kit's generic catch_param extractor picks the
                    // type identifier (or qualified type) on C#'s
                    // `catch (T name)` shape. Fix in the adapter where
                    // we have the structural context.
                    *catch_param = collect_csharp_catch_param_name(node, src);
                    for arm in catch_arms {
                        if let Some(clause) =
                            bonsai_lang_api::kit::node_at_span(tree.root_node(), arm.span, &["catch_clause"])
                        {
                            arm.parameter = csharp_catch_clause_param_name(clause, src);
                            arm.types = csharp_catch_clause_types(clause, src);
                        }
                    }
                }
                populate_csharp_exception_types(body, tree, src);
                populate_csharp_exception_types(catch_events, tree, src);
                populate_csharp_exception_types(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_csharp_exception_types(then_events, tree, src);
                populate_csharp_exception_types(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_csharp_exception_types(body, tree, src);
            }
            _ => {}
        }
    }
}

/// Pull the constructor type out of `throw new Foo(...)`. Returns
/// `None` for re-throws (`throw e`), where the thrown type is whatever
/// data-flow eventually proves about `e` — beyond syntactic reach.
fn csharp_thrown_type_for_node(throw_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    // throw_statement > object_creation_expression > identifier (or qualified_name)
    let mut throw_cursor = throw_node.walk();
    for child in throw_node.named_children(&mut throw_cursor) {
        if child.kind() == "object_creation_expression" {
            // Newer grammar releases expose the type via the `type:` field.
            if let Some(type_node) = child.child_by_field_name("type") {
                return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                    &type_node, src,
                )));
            }
            // Older releases inline the identifier as a named child.
            let mut type_cursor = child.walk();
            for descendant in child.named_children(&mut type_cursor) {
                if matches!(
                    descendant.kind(),
                    "identifier" | "qualified_name" | "generic_name"
                ) {
                    return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &descendant,
                        src,
                    )));
                }
            }
        }
    }
    None
}

/// Pull the binding name out of `catch (T name)`. Returns `None` for
/// catch-all (`catch { }`) and for catch declarations that omit the
/// name (`catch (T) { }` — unusual but legal in C#).
fn collect_csharp_catch_param_name(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        if let Some(parameter) = csharp_catch_clause_param_name(child, src) {
            return Some(parameter);
        }
    }
    None
}

fn csharp_catch_clause_param_name(clause: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut clause_cursor = clause.walk();
    for sub in clause.named_children(&mut clause_cursor) {
        if sub.kind() != "catch_declaration" {
            continue;
        }
        // The `name` field is the binding identifier; the `type`
        // field is the exception type.
        if let Some(name_node) = sub.child_by_field_name("name") {
            return Some(node_text(&name_node, src).trim().to_string());
        }
    }
    None
}

/// Collect the `catch (T e)` types in source order. Catch-all (`catch
/// { }`) is omitted — the engine's seed-on-any-throw path handles it.
fn collect_csharp_catch_types(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut catch_types: Vec<String> = Vec::new();
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        for name in csharp_catch_clause_types(child, src) {
            if !catch_types.iter().any(|existing| existing == &name) {
                catch_types.push(name);
            }
        }
    }
    catch_types
}

fn csharp_catch_clause_types(clause: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut catch_types = Vec::new();
    // catch_clause > catch_declaration > type
    let mut clause_cursor = clause.walk();
    for sub in clause.named_children(&mut clause_cursor) {
        if sub.kind() != "catch_declaration" {
            continue;
        }
        if let Some(type_node) = sub.child_by_field_name("type") {
            let name = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&type_node, src));
            if !name.is_empty() && !catch_types.iter().any(|existing| existing == &name) {
                catch_types.push(name);
            }
        }
    }
    catch_types
}

/// Find the file's top-level `namespace` declaration and return its
/// dotted segments. Both block-form (`namespace Foo.Bar { ... }`) and
/// file-scoped (`namespace Foo.Bar;`) shapes resolve identically.
fn extract_csharp_namespace(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut child_cursor = root.walk();
    for child in root.children(&mut child_cursor) {
        if !matches!(
            child.kind(),
            "namespace_declaration" | "file_scoped_namespace_declaration"
        ) {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            let text = node_text(&name_node, src);
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
    None
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
