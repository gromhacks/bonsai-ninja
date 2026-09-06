//! TypeScript language adapter.
mod parse_recovery;

use bonsai_common::FileId;
use bonsai_lang_api::{
    collect_modifier_visibility, decl_index_from_tree_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, CallTargetExtraction, DeclIndex, DeclKind, FieldWrite, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModifierVocabulary, ParseRecoveryEdit, SourceFileRepresentation, SyntaxTree, TypeAliasBinding, Vfs,
    Visibility, EMPTY_HANDLER,
};
use tree_sitter::Node;

fn typescript_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = match node.kind() {
        "call_expression" => node.child_by_field_name("function")?,
        "new_expression" => node.child_by_field_name("constructor")?,
        _ => return None,
    };
    // A call whose callee is a function literal (an IIFE) is named the way
    // the lowering names lambdas, `<iife@line:col>`, instead of carrying
    // the whole function body as its callee text.
    let function_literal = |node: Node<'tree>| {
        matches!(
            node.kind(),
            "function_expression" | "function" | "arrow_function" | "generator_function" | "class"
        )
    };
    let literal_callee = function_literal(target)
        || (target.kind() == "parenthesized_expression"
            && target.named_child(0).is_some_and(function_literal));
    let full_text = if literal_callee {
        format!(
            "<iife@{}:{}>",
            target.start_position().row + 1,
            target.start_position().column + 1
        )
    } else {
        node_text(&target, src).trim().to_string()
    };
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

fn typescript_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "for_in_statement")
        .then(|| {
            Some((
                node.child_by_field_name("left")?,
                node.child_by_field_name("right")?,
            ))
        })
        .flatten()
}

/// Preserve the runtime value expression through TypeScript-only type
/// wrappers before applying the ECMAScript value-shape classifier. The
/// grammar places the runtime operand first for `as`/`satisfies` and last for
/// angle-bracket assertions; type nodes are never treated as value operands.
fn typescript_expression_value_kind(
    mut node: Node<'_>,
    src: &[u8],
) -> Option<bonsai_lang_api::AssignValueKind> {
    loop {
        if let Some(kind) = ecmascript_expression_value_kind(node, src) {
            return Some(kind);
        }
        node = match node.kind() {
            "parenthesized_expression" | "non_null_expression" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let child = children.next()?;
                if children.next().is_some() {
                    return None;
                }
                child
            }
            "as_expression" | "satisfies_expression" => node.named_child(0)?,
            "type_assertion" => {
                let index = node.named_child_count().checked_sub(1)?;
                node.named_child(u32::try_from(index).ok()?)?
            }
            _ => return None,
        };
    }
}

const TYPESCRIPT_FUNCTION_KINDS: &[&str] = &[
    "function_declaration",
    "method_definition",
    "method_signature",
    "function_expression",
    "arrow_function",
    "generator_function_declaration",
    "generator_function",
];

const TYPESCRIPT_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "method_definition",
        "method_signature",
        "public_field_definition",
        "abstract_method_signature",
    ],
    modifier_container_kinds: &["accessibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("protected", Visibility::Protected),
        ("public", Visibility::Public),
    ],
    // TypeScript's default class-member visibility is `public`.
    default_visibility: Visibility::Public,
};
use bonsai_lang_javascript::{
    apply_ecmascript_assigned_member_callable_owners, apply_javascript_getter_property_sources,
    apply_js_ts_commonjs_named_export_aliases, apply_js_ts_default_export_aliases,
    ecmascript_expression_value_kind, ecmascript_loop_kind, ecmascript_loop_label,
    ecmascript_source_file_representation, ecmascript_static_scalar, extract_ecmascript_pseudo_call,
    js_ts_imports, js_ts_module_segments, js_ts_require_calls, normalize_node_builtin_scheme,
    populate_ecmascript_compiler_facts, JS_TS_MODULE_RESOLUTION_EXTENSIONS,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("typescript");
const PACK_NAME: &str = "typescript";
const TSX_PACK_NAME: &str = "tsx";

// TypeScript/TSX CST spellings inspected outside the path-selected handlers,
// including the ECMAScript compiler post-processing reused from
// `lang_javascript` and the adapter's narrow import-type parse recovery. This
// inventory is grammar checked as part of conformance rather than trusted as
// an unverified string table.
macro_rules! declare_typescript_grammar_node_kinds {
    (
        common: [$($common:expr,)*],
        typescript_only: [$($typescript_only:expr,)*],
        tsx_only: [$($tsx_only:expr,)*],
    ) => {
        const TYPESCRIPT_ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] =
            &[$($common,)* $($typescript_only,)*];
        const TSX_ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[$($common,)* $($tsx_only,)*];
        const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] =
            &[$($common,)* $($typescript_only,)* $($tsx_only,)*];
    };
}

declare_typescript_grammar_node_kinds! {
    common: [
    ("adapter_postprocessor", "abstract_method_signature"),
    ("adapter_postprocessor", "accessibility_modifier"),
    ("adapter_postprocessor", "arguments"),
    ("adapter_postprocessor", "array"),
    ("adapter_postprocessor", "arrow_function"),
    ("adapter_postprocessor", "as_expression"),
    ("adapter_postprocessor", "assignment_expression"),
    ("adapter_postprocessor", "assignment_pattern"),
    ("adapter_postprocessor", "augmented_assignment_expression"),
    ("adapter_postprocessor", "binary_expression"),
    ("adapter_postprocessor", "call_expression"),
    ("adapter_postprocessor", "catch_clause"),
    ("adapter_postprocessor", "class"),
    ("adapter_postprocessor", "class_declaration"),
    ("adapter_postprocessor", "class_heritage"),
    ("adapter_postprocessor", "const"),
    ("adapter_postprocessor", "continue_statement"),
    ("adapter_postprocessor", "default"),
    ("adapter_postprocessor", "delete"),
    ("adapter_postprocessor", "export_specifier"),
    ("adapter_postprocessor", "export_statement"),
    ("adapter_postprocessor", "expression_statement"),
    ("adapter_postprocessor", "extends_clause"),
    ("adapter_postprocessor", "false"),
    ("adapter_postprocessor", "for_in_statement"),
    ("adapter_postprocessor", "for_statement"),
    ("adapter_postprocessor", "formal_parameters"),
    ("adapter_postprocessor", "function_declaration"),
    ("adapter_postprocessor", "function_expression"),
    ("adapter_postprocessor", "function_type"),
    ("adapter_postprocessor", "generator_function"),
    ("adapter_postprocessor", "generator_function_declaration"),
    ("adapter_postprocessor", "generic_type"),
    ("adapter_postprocessor", "identifier"),
    ("adapter_postprocessor", "if_statement"),
    ("adapter_postprocessor", "import"),
    ("adapter_postprocessor", "import_require_clause"),
    ("adapter_postprocessor", "import_clause"),
    ("adapter_postprocessor", "import_specifier"),
    ("adapter_postprocessor", "import_statement"),
    ("adapter_postprocessor", "lexical_declaration"),
    ("loop-control-label", "labeled_statement"),
    ("loop-control-label", "statement_identifier"),
    ("adapter_postprocessor", "member_expression"),
    ("adapter_postprocessor", "method_definition"),
    ("adapter_postprocessor", "method_signature"),
    ("adapter_postprocessor", "named_imports"),
    ("adapter_postprocessor", "namespace_import"),
    ("adapter_postprocessor", "nested_identifier"),
    ("adapter_postprocessor", "nested_type_identifier"),
    ("adapter_postprocessor", "new_expression"),
    ("adapter_postprocessor", "null"),
    ("adapter_postprocessor", "number"),
    ("adapter_postprocessor", "object"),
    ("adapter_postprocessor", "object_assignment_pattern"),
    ("adapter_postprocessor", "object_pattern"),
    ("adapter_postprocessor", "optional_parameter"),
    ("adapter_postprocessor", "pair"),
    ("adapter_postprocessor", "pair_pattern"),
    ("adapter_postprocessor", "parenthesized_expression"),
    ("adapter_postprocessor", "predefined_type"),
    ("adapter_postprocessor", "private_property_identifier"),
    ("adapter_postprocessor", "program"),
    ("adapter_postprocessor", "property_identifier"),
    ("adapter_postprocessor", "public_field_definition"),
    ("adapter_postprocessor", "regex"),
    ("adapter_postprocessor", "required_parameter"),
    ("adapter_postprocessor", "rest_pattern"),
    ("adapter_postprocessor", "return_statement"),
    ("adapter_postprocessor", "satisfies_expression"),
    ("adapter_postprocessor", "shorthand_property_identifier"),
    ("adapter_postprocessor", "shorthand_property_identifier_pattern"),
    ("adapter_postprocessor", "spread_element"),
    ("adapter_postprocessor", "statement_block"),
    ("adapter_postprocessor", "string"),
    ("adapter_postprocessor", "string_fragment"),
    ("adapter_postprocessor", "subscript_expression"),
    ("adapter_postprocessor", "switch_body"),
    ("adapter_postprocessor", "template_string"),
    ("adapter_postprocessor", "template_substitution"),
    ("adapter_postprocessor", "ternary_expression"),
    ("adapter_postprocessor", "this"),
    ("adapter_postprocessor", "true"),
    ("adapter_postprocessor", "type_annotation"),
    ("adapter_postprocessor", "type_identifier"),
    ("adapter_postprocessor", "unary_expression"),
    ("adapter_postprocessor", "undefined"),
    ("adapter_postprocessor", "update_expression"),
    ("adapter_postprocessor", "variable_declarator"),
    ],
    typescript_only: [
        ("adapter_postprocessor", "type_assertion"),
    ],
    tsx_only: [
        ("adapter_postprocessor", "jsx_attribute"),
        ("adapter_postprocessor", "jsx_namespace_name"),
        ("adapter_postprocessor", "jsx_opening_element"),
        ("adapter_postprocessor", "jsx_self_closing_element"),
    ],
}

fn grammar_pack_for_file(file: FileId, ctx: &AdapterContext<'_>) -> &'static str {
    ctx.vfs
        .path(file)
        .ok()
        .as_deref()
        .and_then(|path| path.extension())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|extension| extension.eq_ignore_ascii_case("tsx"))
        .map_or(PACK_NAME, |_| TSX_PACK_NAME)
}
const COMMON_HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: Some(typescript_expression_value_kind),
    literal_value_kinds: &["null", "number", "true", "false"],
    string_literal_kinds: &["string", "template_string"],
    comment_kinds: &["comment", "hash_bang_line"],
    doc_comment_prefixes: &["/**"],
    decorator_kinds: &["decorator"],
    parameter_container_kinds: &["formal_parameters"],
    parameter_kinds: &["identifier", "required_parameter", "optional_parameter"],
    parameter_modifier_kinds: &["decorator"],
    parameter_annotation_kinds: &["decorator"],
    variadic_parameter_kinds: &["rest_pattern"],
    destructured_parameter_kinds: &["object_pattern", "array_pattern", "object_type"],
    binding_identifier_kinds: &["identifier", "shorthand_property_identifier_pattern"],
    binding_lhs_pattern_kinds: &["assignment_pattern"],
    binding_pattern_field_names: &["left"],
    non_binding_pattern_field_names: &["type", "key", "property"],
    identifier_kinds: &["identifier", "shorthand_property_identifier", "this", "super"],
    aggregate_pattern_kinds: &["array_pattern", "object_pattern"],
    named_aggregate_kinds: &["object"],
    positional_aggregate_kinds: &["array"],
    aggregate_pair_kinds: &["pair", "pair_pattern"],
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["identifier", "property_identifier"],
    shorthand_field_kinds: &["shorthand_property_identifier"],
    spread_kinds: &["spread_element"],
    spread_value_field_names: &["argument"],
    lambda_value_container_kinds: &["object", "pair", "array", "object_type"],
    transparent_call_wrapper_kinds: &[
        "member_expression",
        "parenthesized_expression",
        "await_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
    ],
    single_expression_group_kinds: &[],
    assignment_target_wrapper_kinds: &["variable_declarator"],
    binding_declaration_keyword_spellings: &["var", "let", "const"],
    fn_kinds: &[
        "function_declaration",
        "method_definition",
        "method_signature",
        "generator_function_declaration",
        "generator_function",
    ],
    call_kinds: &["call_expression", "new_expression"],
    constructor_call_kinds: &["new_expression"],
    call_callee_field_names: &["function", "constructor"],
    constructor_type_field_names: &["constructor"],
    call_target_extractor: Some(typescript_call_target),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["arguments"],
    argument_wrapper_kinds: &["pair"],
    argument_name_field_names: &["key"],
    argument_value_field_names: &["value"],
    transparent_expression_wrapper_kinds: &["parenthesized_expression"],
    lambda_body_field_names: &["body"],
    pseudo_call_extractor: Some(extract_ecmascript_pseudo_call),
    syntax_event_extractor: None,
    argument_passing_mode_extractor: None,
    call_ref_kinds: &["call_expression", "new_expression"],
    member_expression_kinds: &["member_expression"],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["object"],
    member_name_field_names: &["property", "name"],
    subscript_base_field_names: &["object"],
    subscript_index_field_names: &["index", "argument"],
    static_subscript_key_extractor: Some(bonsai_lang_javascript::ecmascript_static_subscript_key),
    constructor_names: &["constructor"],
    runtime_type_guard_operators: &["instanceof"],
    runtime_typeof_operators: &["typeof"],
    runtime_type_equality_operators: &["==", "==="],
    runtime_type_wrapper_kinds: &["parenthesized_expression"],
    value_free_unary_operators: &["typeof"],
    // TypeScript exposes `abstract class Foo` under
    // `abstract_class_declaration`; without the exact adapter entry,
    // abstract base classes are missed at decl-emission time, and
    // every subclass ends up with `decl.parent = None`. That
    // breaks Phase 3c/3d field-flow stitching: the inheritance
    // walk has no class to attach `BaseRepository` to.
    class_kinds: &[
        "class_declaration",
        "abstract_class_declaration",
        "interface_declaration",
        "enum_declaration",
    ],
    class_decl_kinds: &[
        ("class_declaration", DeclKind::Class),
        ("abstract_class_declaration", DeclKind::Class),
        ("interface_declaration", DeclKind::Interface),
        ("enum_declaration", DeclKind::Enum),
    ],
    method_kinds: &["method_definition", "method_signature"],
    method_context_kinds: &[
        "class_declaration",
        "abstract_class_declaration",
        "interface_declaration",
    ],
    if_kinds: &["if_statement", "switch_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["statement_block", "expression_statement"],
    loop_update_field_names: &["increment"],
    loop_condition_field_names: &["condition"],
    loop_condition_extractor: None,
    loop_kind_extractor: Some(ecmascript_loop_kind),
    branch_arm_kinds: &[
        "statement_block",
        "expression_statement",
        "switch_case",
        "switch_default",
    ],
    exclusive_branch_arm_kinds: &["switch_case", "switch_default"],
    fallthrough_branch_arm_kinds: &["switch_case", "switch_default"],
    for_kinds: &["for_statement"],
    foreach_kinds: &["for_in_statement"],
    foreach_binding_extractor: Some(typescript_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    assignment_kinds: &[
        "assignment_expression",
        "augmented_assignment_expression",
        "variable_declarator",
        "variable_declaration",
    ],
    compound_assignment_kinds: &["augmented_assignment_expression"],
    compound_assignment_operators: &[
        "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "^=", "|=", "&&=", "||=", "??=",
    ],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_statement"],
    lambda_kinds: &["arrow_function", "function_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &["label"],
    loop_label_extractor: Some(ecmascript_loop_label),
    yield_kinds: &["yield_expression"],
    yield_value_field_names: &["argument"],
    await_kinds: &["await_expression"],
    using_kinds: &["with_statement"],
    using_body_field_names: &["body"],
    try_body_field_names: &["body"],
    implicit_receiver_names: &["this"],
    ..EMPTY_HANDLER
};

const TYPESCRIPT_HANDLER: GrammarHandler = GrammarHandler {
    transparent_call_wrapper_kinds: &[
        "member_expression",
        "parenthesized_expression",
        "await_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
    ],
    ..COMMON_HANDLER
};

const TSX_HANDLER: GrammarHandler = GrammarHandler { ..COMMON_HANDLER };

fn grammar_handler_for_grammar(grammar: &str) -> &'static GrammarHandler {
    if grammar == TSX_PACK_NAME {
        &TSX_HANDLER
    } else {
        &TYPESCRIPT_HANDLER
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct TypeScriptAdapter;

impl TypeScriptAdapter {
    /// Construct a fresh adapter. Stateless; cheap to copy.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for TypeScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "TypeScript"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ts", "tsx", "mts", "cts"]
    }

    fn source_file_representation(&self, path: &std::path::Path) -> SourceFileRepresentation {
        ecmascript_source_file_representation(path)
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn grammar_name_for_path(&self, path: &std::path::Path) -> &'static str {
        path.extension()
            .and_then(std::ffi::OsStr::to_str)
            .filter(|extension| extension.eq_ignore_ascii_case("tsx"))
            .map_or(PACK_NAME, |_| TSX_PACK_NAME)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        _vfs: &Vfs,
        tree: &SyntaxTree,
    ) -> Vec<ParseRecoveryEdit> {
        parse_recovery::typescript_parse_recovery_edits(snapshot, tree)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            universal_type_names: &["any", "unknown", "object", "Object"],
            module_export_aliases: &["exports", "module.exports"],
            module_default_export_names: &["default"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: &["constructor"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &[],
                class_object_suffixes: &[".constructor"],
            },
            module_resolution_extensions: JS_TS_MODULE_RESOLUTION_EXTENSIONS,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&TYPESCRIPT_HANDLER)
    }

    fn grammar_handler_for_path(&self, path: &std::path::Path) -> Option<&'static GrammarHandler> {
        Some(grammar_handler_for_grammar(self.grammar_name_for_path(path)))
    }

    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        ADDITIONAL_GRAMMAR_NODE_KINDS
    }

    fn additional_grammar_node_kinds_for_path(
        &self,
        path: &std::path::Path,
    ) -> &'static [(&'static str, &'static str)] {
        if self.grammar_name_for_path(path) == TSX_PACK_NAME {
            TSX_ADDITIONAL_GRAMMAR_NODE_KINDS
        } else {
            TYPESCRIPT_ADDITIONAL_GRAMMAR_NODE_KINDS
        }
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let grammar = grammar_pack_for_file(file, ctx);
        let handler = grammar_handler_for_grammar(grammar);
        let parsed = parse_with(grammar, file, ctx);
        let mut decl_index = parsed.as_ref().map_or_else(
            || DeclIndex {
                file,
                ..Default::default()
            },
            |(snapshot, tree)| {
                decl_index_from_tree_with_handler(file, snapshot.text.as_bytes(), tree, handler)
            },
        );
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            populate_ecmascript_compiler_facts(&mut decl_index, tree, file, src);
            populate_typescript_readonly_instance_literals(&mut decl_index, tree, file, src);
            apply_ecmascript_assigned_member_callable_owners(&mut decl_index, tree, file, src);
            apply_js_ts_commonjs_named_export_aliases(&mut decl_index, tree, src, file);
        }
        // TS/JS module = workspace-relative file path with `.ts`/`.tsx` (etc.) stripped.
        let module_segments = ctx
            .workspace_relative_path(file)
            .map(|p| js_ts_module_segments(&p))
            .unwrap_or_default();
        if !module_segments.is_empty() {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut decl_index, module_segments);
        } else {
            // Fall back to the file stem when the workspace root is unknown.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        }
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            apply_js_ts_default_export_aliases(&mut decl_index, tree, src, file);
            // Phase-6 return-type extraction: `function f(): T {}` / `(): T => ...`
            // populates `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, tree, src, handler);
            // Visibility from `public/protected/private` keywords, and parameter type aliases.
            let visibility_by_span =
                collect_modifier_visibility(tree.root_node(), file, src, &TYPESCRIPT_VOCAB);
            let type_aliases_by_span = collect_typescript_parameter_aliases(tree, file, src);
            // WS2 cast typing: `const c = make() as Foo` / `const c = <Foo>make()`.
            // The cast type lives only on the initializer (the declared-type /
            // return-type paths don't see it), so capture it as a local type
            // alias so `c.method(...)` resolves `receiver_type_in` / `[Foo, m]`.
            let cast_aliases_by_span = collect_typescript_cast_aliases(tree, file, src);
            // TypeScript constructor parameter properties are both parameters
            // and instance fields: `constructor(private svc: Service)`.
            // The generic assignment walker sees no `this.svc = svc` write,
            // so emit the equivalent precise field/type facts from the syntax.
            let parameter_properties_by_span = collect_typescript_parameter_properties(tree, file, src);
            for decl in &mut decl_index.defs {
                if let Some(vis) = visibility_by_span.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                if let Some(aliases) = type_aliases_by_span.get(&decl.span) {
                    decl.type_aliases
                        .retain(|alias| !decl.params.contains(&alias.name));
                    decl.type_aliases.extend(aliases.iter().cloned());
                }
                if let Some(cast_aliases) = cast_aliases_by_span.get(&decl.span) {
                    decl.type_aliases.extend(cast_aliases.iter().cloned());
                }
                if let Some(parameter_properties) = parameter_properties_by_span.get(&decl.span) {
                    for property in parameter_properties {
                        if let Some(alias) = &property.alias {
                            if !decl.type_aliases.contains(alias) {
                                decl.type_aliases.push(alias.clone());
                            }
                        }
                        let positions = decl
                            .params
                            .iter()
                            .enumerate()
                            .filter_map(|(position, name)| {
                                (name == &property.parameter_name).then_some(position)
                            })
                            .collect::<Vec<_>>();
                        if let [position] = positions.as_slice() {
                            let mut write = property.field_write.clone();
                            write.source_param_indices = vec![*position];
                            if !decl.receiver_field_writes.contains(&write) {
                                decl.receiver_field_writes.push(write);
                            }
                        }
                    }
                }
            }
            // ECMAScript `#name` private fields/methods are syntactically marked.
            for decl in &mut decl_index.defs {
                if decl.name.starts_with('#') {
                    decl.visibility = Visibility::Private;
                }
            }
            // Per-class `bases`: `class Echo extends WebSocketHandler implements Mixin { ... }`
            // becomes `["WebSocketHandler", "Mixin"]`. The TS grammar groups extends +
            // implements under a `class_heritage` child of the class.
            let bases_by_span = collect_typescript_class_bases(tree, file, src);
            for decl in &mut decl_index.defs {
                // Bases only make sense on type-defining declarations.
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span.get(&decl.span) {
                    decl.bases = bases.clone();
                }
            }
            apply_javascript_getter_property_sources(&mut decl_index, tree, src, file);
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing
        // (`const c = new Foo()` → `c: Foo`); see the JS adapter for the
        // exact CST/declaration-evidence contract.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_call_receiver_types(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(grammar_pack_for_file(file, ctx), file, ctx, parse_imports)
    }
}

/// Lower immutable instance-field literals into the same exact assignment IR
/// used for local bindings. TypeScript spells a field read as `this.name`,
/// while the declaration node contains only `name`; recording the canonical
/// receiver projection here keeps shared analyses language-agnostic.
fn populate_typescript_readonly_instance_literals(
    index: &mut DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    let owners = index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.symbol))
        .collect::<std::collections::HashMap<_, _>>();
    let writes = index
        .assignment_values
        .iter()
        .filter_map(|fact| {
            let target = fact.target.as_deref()?.strip_prefix("this.")?;
            let node = tree.root_node().descendant_for_byte_range(
                usize::try_from(fact.assignment_span.start).ok()?,
                usize::try_from(fact.assignment_span.end).ok()?,
            )?;
            let owner = typescript_owning_class(node)?;
            Some((span_of(file, &owner), target.to_string()))
        })
        .collect::<std::collections::HashSet<_>>();
    for field in collect_kinds(tree, &["public_field_definition"]) {
        let has_modifier = |wanted: &str| {
            let mut cursor = field.walk();
            let found = field.children(&mut cursor).any(|child| child.kind() == wanted);
            found
        };
        if !has_modifier("readonly") || has_modifier("static") {
            continue;
        }
        let (Some(name_node), Some(value)) = (
            field.child_by_field_name("name"),
            field.child_by_field_name("value"),
        ) else {
            continue;
        };
        if name_node.kind() != "property_identifier"
            || !matches!(value.kind(), "string" | "number" | "true" | "false" | "null")
        {
            continue;
        }
        let name = node_text(&name_node, src).trim();
        let canonical = format!("this.{name}");
        let field_span = span_of(file, &field);
        let Some(owner) = typescript_owning_class(field) else {
            continue;
        };
        let owner_span = span_of(file, &owner);
        let Some(owner_symbol) = owners.get(&owner_span).copied() else {
            continue;
        };
        // Field initialization runs before the constructor body regardless
        // of declaration order. Any write in this class prevents treating
        // this initializer as immutable cross-method state.
        if writes.contains(&(owner_span, name.to_string())) {
            continue;
        }
        index
            .assignment_values
            .push(bonsai_lang_api::AssignmentValueFact {
                assignment_span: field_span,
                target: Some(canonical),
                target_is_immutable: true,
                target_owner: Some(owner_symbol),
                target_span: Some(span_of(file, &name_node)),
                value_span: span_of(file, &value),
                call_sites: Vec::new(),
                value_flow: bonsai_lang_api::ExpressionFlow::default(),
                static_value: ecmascript_static_scalar(value, src),
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
            fact.target_span.map_or(0, |span| span.end),
            fact.value_span.start,
            fact.value_span.end,
        )
    });
    index.assignment_values.dedup();
}

fn typescript_owning_class(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(
            node.kind(),
            "class" | "class_declaration" | "abstract_class_declaration"
        ) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn collect_typescript_parameter_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let mut out = std::collections::HashMap::new();
    for function in collect_kinds(tree, TYPESCRIPT_FUNCTION_KINDS) {
        let Some(parameters) = function.child_by_field_name("parameters") else {
            continue;
        };
        let mut cursor = parameters.walk();
        let mut aliases = Vec::new();
        for parameter in parameters.named_children(&mut cursor) {
            if !matches!(parameter.kind(), "required_parameter" | "optional_parameter") {
                continue;
            }
            let (Some(pattern), Some(ty)) = (
                parameter.child_by_field_name("pattern"),
                parameter.child_by_field_name("type"),
            ) else {
                continue;
            };
            if pattern.kind() != "identifier" {
                continue;
            }
            if let Some(type_name) = typescript_type_name_leaf(ty, src) {
                aliases.push(TypeAliasBinding {
                    name: node_text(&pattern, src).to_string(),
                    type_name,
                });
            }
        }
        // Keep empty entries too: a compound/unknown type must not leave an
        // earlier shortened alias behind as purported receiver proof.
        out.insert(span_of(file, &function), aliases);
    }
    out
}

/// Combine ES-module imports, CommonJS `require(...)` calls, and the
/// TypeScript-only `import x = require("y")` legacy form. Delegates to
/// the JS helpers so the two adapters cannot drift on import semantics.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = js_ts_imports(file, tree, src);
    imports.extend(js_ts_require_calls(file, tree, src));
    // `import x = require("y")` is an `import_statement` containing an
    // `import_require_clause` in the pinned grammar.  It is neither an
    // ECMAScript import clause nor a call expression, so both shared passes
    // intentionally leave it to this exact TypeScript syntax pass.
    imports.extend(parse_ts_import_require_clauses(file, tree, src));
    imports
}

/// Parse TypeScript-only `import x = require("y")` statements. The
/// grammar emits an `import_require_clause` whose first identifier is `x`
/// and whose `source` field is the module string. Emits one Module-scope ImportSpec
/// with `alias = Some("x")` so resolve sees `x` as an alias for
/// the `y` module.
fn parse_ts_import_require_clauses(file: FileId, tree: &Tree, src: &[u8]) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for clause in collect_kinds(tree, &["import_require_clause"]) {
        let mut cursor = clause.walk();
        let local_alias = clause
            .named_children(&mut cursor)
            .find(|child| child.kind() == "identifier")
            .map(|name| node_text(&name, src).to_string());
        let Some(source) = clause.child_by_field_name("source") else {
            continue;
        };
        let module = first_named_child_of_kind(&source, "string_fragment")
            .map(|fragment| node_text(&fragment, src).to_string())
            .unwrap_or_else(|| node_text(&source, src).trim_matches(['\'', '"']).to_string());
        let module = normalize_node_builtin_scheme(&module);
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &clause),
            module,
            alias: local_alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Whether a declaration kind can carry a base list (`extends` / `implements`).
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// WS2 cast-expression typing. A `const c = make() as Foo` / `const c =
/// <Foo>make()` carries its type ONLY on the cast — the declared-type
/// extractor (`collect_param_type_aliases` handles params, not locals)
/// and the return-type path (`make(): Foo`) both miss it. Capture the
/// cast type as a per-enclosing-function `c -> Foo` alias so
/// `c.method(tainted)` resolves `receiver_type_in: [Foo]` / `[Foo, m]`.
///
/// Keyed by the enclosing function declaration's span (matching how
/// `collect_param_type_aliases` keys). The cast's type node is authoritative;
/// capitalization is only a style convention and must not filter facts.
fn collect_typescript_cast_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let mut out = std::collections::HashMap::new();
    for fn_node in collect_kinds(tree, TYPESCRIPT_FUNCTION_KINDS) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![fn_node];
        while let Some(node) = work.pop() {
            // A nested function owns its own locals — let its own
            // iteration scope them rather than leaking into the parent.
            if node != fn_node && TYPESCRIPT_FUNCTION_KINDS.contains(&node.kind()) {
                continue;
            }
            if node.kind() == "variable_declarator" {
                extend_ts_aliases_from_cast(node, src, &mut aliases);
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

/// Emit a `name -> Type` alias when a `variable_declarator`'s initializer
/// IS a cast (`x as Foo` / `<Foo>x`). Reads only the declarator's `value`
/// field, so a cast nested in a call argument (`const c = wrap(x as Foo)`)
/// does NOT mistype the local — only a cast that is the whole initializer.
fn extend_ts_aliases_from_cast(declarator: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let Some(name_node) = declarator.child_by_field_name("name") else {
        return;
    };
    // Only simple identifier bindings (`const c = ...`); destructuring
    // patterns don't bind a single receiver.
    if name_node.kind() != "identifier" {
        return;
    }
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return;
    }
    let Some(value) = declarator.child_by_field_name("value") else {
        return;
    };
    // `x as Foo` is `as_expression`; `<Foo>x` is `type_assertion`.
    if !matches!(value.kind(), "as_expression" | "type_assertion") {
        return;
    }
    let Some(type_name) = ts_cast_type_name(value, src) else {
        return;
    };
    if type_name.is_empty() {
        return;
    }
    aliases.push(TypeAliasBinding { name, type_name });
}

/// The cast's target type. For `x as Foo` the `type_identifier` is the
/// trailing child; for `<Foo>x` it is the leading child. Generic casts
/// (`as Foo<T>`) surface a `generic_type` whose `name` is the base type.
fn ts_cast_type_name(cast: Node<'_>, src: &[u8]) -> Option<String> {
    let ty = match cast.kind() {
        "as_expression" => cast.named_child(u32::try_from(cast.named_child_count().checked_sub(1)?).ok()?)?,
        "type_assertion" => first_named_child_of_kind(&cast, "type_arguments")?,
        _ => return None,
    };
    typescript_type_name_leaf(ty, src)
}

#[derive(PartialEq)]
struct TypeScriptParameterProperty {
    alias: Option<TypeAliasBinding>,
    field_write: FieldWrite,
    parameter_name: String,
}

/// TypeScript parameter properties are the syntax-level equivalent of:
///
///   constructor(private readonly diag: DiagService) { this.diag = diag; }
///
/// Tree-sitter exposes this as a normal constructor parameter carrying
/// an `accessibility_modifier` token rather than an assignment event. Emit
/// the same `this.diag -> DiagService` type and `this.diag` field-write facts
/// that a handwritten assignment would have produced, but only for the
/// syntactic parameter-property forms (`public` / `private` / `protected` /
/// `readonly`). The ordinary parameter type (`diag -> DiagService`) is already
/// lowered by `collect_param_type_aliases`.
fn collect_typescript_parameter_properties(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeScriptParameterProperty>> {
    let mut out = std::collections::HashMap::new();
    for ctor in collect_kinds(tree, &["method_definition"]) {
        if !typescript_method_name_is(&ctor, src, "constructor") {
            continue;
        }
        let Some(params_node) = ctor
            .child_by_field_name("parameters")
            .or_else(|| first_named_child_of_kind(&ctor, "formal_parameters"))
        else {
            continue;
        };

        let mut bindings = Vec::new();
        let mut cursor = params_node.walk();
        for param in params_node.named_children(&mut cursor) {
            if !matches!(param.kind(), "required_parameter" | "optional_parameter") {
                continue;
            }
            if !typescript_parameter_property_declares_field(&param) {
                continue;
            }
            let Some(name) = typescript_parameter_property_name(&param, src) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            // A parameter property is a TypeScript syntax-level declaration
            // of the receiver field. Record that exact receiver projection so
            // shared class-field propagation does not need to invent a
            // synthetic assignment event to prove the type.
            let receiver_field = format!("this.{name}");
            let alias = typescript_parameter_property_type(&param, src).map(|type_name| TypeAliasBinding {
                name: receiver_field.clone(),
                type_name,
            });
            let field_write = FieldWrite {
                span: span_of(file, &param),
                target: receiver_field,
                source_param_indices: Vec::new(),
            };
            let entry = TypeScriptParameterProperty {
                alias,
                field_write,
                parameter_name: name,
            };
            if !bindings.contains(&entry) {
                bindings.push(entry);
            }
        }
        if !bindings.is_empty() {
            out.insert(span_of(file, &ctor), bindings);
        }
    }
    out
}

fn typescript_method_name_is(node: &Node<'_>, src: &[u8], expected: &str) -> bool {
    node.child_by_field_name("name")
        .map(|name| node_text(&name, src).trim() == expected)
        .unwrap_or(false)
}

fn typescript_parameter_property_declares_field(param: &Node<'_>) -> bool {
    let mut cursor = param.walk();
    // `readonly` is an anonymous keyword; accessibility is a named CST
    // modifier. Text inside a decorator or comment declares neither.
    let declares_field = param
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "accessibility_modifier" | "readonly"));
    declares_field
}

fn typescript_parameter_property_name(param: &Node<'_>, src: &[u8]) -> Option<String> {
    let pattern = param.child_by_field_name("pattern")?;
    (pattern.kind() == "identifier").then(|| node_text(&pattern, src).to_string())
}

fn typescript_parameter_property_type(param: &Node<'_>, src: &[u8]) -> Option<String> {
    let type_node = param.child_by_field_name("type")?;
    typescript_type_name_leaf(type_node, src)
}

fn typescript_type_name_leaf(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" | "predefined_type" | "nested_type_identifier" => {
            return canonical_ts_type_name(node_text(&node, src));
        }
        "generic_type" => {
            if let Some(name) = node.child_by_field_name("name") {
                return canonical_ts_type_name(node_text(&name, src));
            }
        }
        "type_annotation" | "type_arguments" | "parenthesized_type" => {
            let mut cursor = node.walk();
            let mut children = node
                .named_children(&mut cursor)
                .filter(|child| child.kind() != "comment");
            let child = children.next()?;
            if children.next().is_none() {
                return typescript_type_name_leaf(child, src);
            }
        }
        _ => {}
    }
    None
}

fn canonical_ts_type_name(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_start_matches(':').trim();
    canonical_ts_base_name(raw)
}

/// Walk TS class / interface / abstract-class declarations and
/// collect bare base type names. Grammar shape:
///
///   `class Echo extends WebSocketHandler implements Mixin { ... }` →
///     (class_declaration name: (type_identifier)
///        (class_heritage
///           (extends_clause value: (identifier))
///           (implements_clause (type_identifier))))
///
/// `interface_declaration` uses `extends_type_clause` (multiple
/// type identifiers under one wrapper) instead of `class_heritage`.
fn collect_typescript_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<String>> {
    let mut bases_by_class = std::collections::HashMap::new();
    let class_kinds = &[
        "class_declaration",
        "abstract_class_declaration",
        "class",
        "interface_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for class_child in class_node.named_children(&mut class_cursor) {
            match class_child.kind() {
                // Class wrapper containing both `extends_clause` and `implements_clause`.
                "class_heritage" => {
                    collect_ts_heritage_names(class_child, src, &mut bases);
                }
                // `interface_declaration` and direct `extends_clause` children.
                "extends_type_clause" | "extends_clause" => {
                    collect_ts_heritage_names(class_child, src, &mut bases);
                }
                _ => {}
            }
        }
        if !bases.is_empty() {
            bases_by_class.insert(span_of(file, &class_node), bases);
        }
    }
    bases_by_class
}

/// Walk a TS heritage wrapper (class_heritage / extends_clause /
/// implements_clause / extends_type_clause) and pick out every
/// identifier-like base name. Generics → leftmost name.
fn collect_ts_heritage_names(node: Node<'_>, src: &[u8], collected_bases: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            // Wrapper kinds — descend; the actual identifier is one or more levels down.
            "extends_clause" => {
                if let Some(value) = current.child_by_field_name("value") {
                    stack.push(value);
                }
            }
            "implements_clause" | "extends_type_clause" | "class_heritage" => {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
            "identifier" | "type_identifier" => {
                if let Some(name) = canonical_ts_base_name(node_text(&current, src)) {
                    if !collected_bases.iter().any(|b| b == &name) {
                        collected_bases.push(name);
                    }
                }
            }
            "generic_type" => {
                // `Foo<T>` — keep `Foo` and skip `type_arguments` entirely so we
                // don't accidentally collect `T` as a base.
                if let Some(name_child) = current.child_by_field_name("name") {
                    if let Some(name) = canonical_ts_base_name(node_text(&name_child, src)) {
                        if !collected_bases.iter().any(|b| b == &name) {
                            collected_bases.push(name);
                        }
                    }
                } else {
                    // Fallback for grammars without the `name` field: take the
                    // first identifier-like child and stop.
                    let mut cursor = current.walk();
                    for child in current.named_children(&mut cursor) {
                        if matches!(child.kind(), "identifier" | "type_identifier") {
                            if let Some(name) = canonical_ts_base_name(node_text(&child, src)) {
                                if !collected_bases.iter().any(|b| b == &name) {
                                    collected_bases.push(name);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            "nested_type_identifier" | "nested_identifier" | "member_expression" => {
                // Keep the complete owner-qualified type identity.
                if let Some(name) = canonical_ts_base_name(node_text(&current, src)) {
                    if !collected_bases.iter().any(|b| b == &name) {
                        collected_bases.push(name);
                    }
                }
            }
            // In particular, operands of `mixin(Base)` are not its returned
            // constructor. Only declared type syntax supplies a base here.
            _ => {}
        }
    }
}

/// Preserve the identity of a grammar-proven class/interface name while
/// omitting generic arguments. Namespace qualifiers are never discarded.
fn canonical_ts_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // `mod.Foo<T>` denotes the qualified base `mod.Foo`, not the type argument.
    let without_generics = trimmed.split('<').next().unwrap_or(trimmed).trim();
    if without_generics.is_empty() {
        return None;
    }
    Some(without_generics.to_string())
}
