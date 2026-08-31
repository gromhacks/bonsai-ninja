//! Lua language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler,
    kit::{
        collect_kinds, collect_receiver_field_writes, first_named_child_of_kind, import_index_from_tree,
        language_from_pack, node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, CallTargetExtraction, CharacterConstraintDomain,
    CharacterConstraintFact, CharacterConstraintOutput, CompilerGuardFact, ConditionEquality,
    ConditionExpressionFact, ConditionOperandFact, DeclIndex, FiniteLiteralSelectionFact, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    PredicateReturnFact, Ref, RefKind, StaticScalarValue, StaticStringMapEntry, StringCompositionFact,
    StringCompositionPart,
};
use tree_sitter::{Language, Node, Tree};

fn lua_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for_statement" {
        return None;
    }
    let clause = node.child_by_field_name("clause").or_else(|| {
        let mut cursor = node.walk();
        let clause = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "for_generic_clause");
        clause
    })?;
    Some((clause.named_child(0)?, clause.named_child(1)?))
}

/// Select the grammar's complete Lua call target. Method calls use a
/// `method_index_expression` (`resource:close`) in the `name` field rather
/// than the `dot_index_expression` used by ordinary table lookup. The
/// adapter preserves `:` until its post-lowering normalization can retain the
/// language-defined implicit receiver distinction.
fn lua_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() != "function_call" {
        return None;
    }
    let target = node.child_by_field_name("name").or_else(|| node.named_child(0))?;
    if !matches!(
        target.kind(),
        "identifier" | "dot_index_expression" | "bracket_index_expression" | "method_index_expression"
    ) {
        return None;
    }
    let full_text = node_text(&target, src)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

pub const LANG_ID: LanguageId = LanguageId::new("lua");
const PACK_NAME: &str = "lua";

fn lua_static_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    if node.kind() == "identifier" {
        return (!raw.is_empty()).then(|| raw.to_string());
    }
    if node.kind() != "string" {
        return None;
    }
    let quote = raw.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || raw.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let value = raw.get(1..raw.len().checked_sub(1)?)?;
    (!value.is_empty() && !value.contains('\\')).then(|| value.to_string())
}

// tree-sitter-lua (MunifTanjim) handler:
//   - `function_declaration` covers `function foo()` and `function M.foo()`
//   - `function_definition` covers anonymous `function() ... end`
//   - the `local_declaration` field marks `local function foo()` on its
//     ordinary `function_declaration` node
//   - Lua has no native exception construct; pcall/xpcall are the
//     idiomatic try-equivalent (function calls; we rely on the
//     do_block-descent + call-arg walking to surface their bodies).
const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &["nil", "number", "true", "false"],
    string_literal_kinds: &["string"],
    comment_kinds: &["comment", "hash_bang_line"],
    doc_comment_prefixes: &["---"],
    decorator_kinds: &[],
    parameter_container_kinds: &["parameters"],
    parameter_kinds: &["identifier", "vararg_expression"],
    parameter_annotation_name_extractor: None,
    variadic_parameter_kinds: &["vararg_expression"],
    binding_identifier_kinds: &["identifier"],
    identifier_kinds: &["identifier"],
    aggregate_pattern_kinds: &["variable_list"],
    named_aggregate_kinds: &["table_constructor"],
    positional_aggregate_kinds: &["table_constructor"],
    aggregate_pair_kinds: &["field"],
    aggregate_key_field_names: &["name"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["identifier"],
    static_subscript_key_extractor: Some(lua_static_key),
    lambda_value_container_kinds: &["table_constructor", "field"],
    transparent_call_wrapper_kinds: &["dot_index_expression", "bracket_index_expression"],
    // Lua wraps both sides of an assignment in list nodes. A list with one
    // parsed child is one expression/place; multi-child lists remain
    // aggregate bindings for the shared parallel-assignment lowering.
    single_expression_group_kinds: &["expression_list", "variable_list"],
    assignment_target_wrapper_kinds: &["variable_declaration"],
    binding_declaration_keyword_spellings: &["local"],
    nested_type_ownership: true,
    // `function_definition` is anonymous expression syntax. Keeping it in
    // `fn_kinds` makes Pass 1 skip it for lack of a declaration name while
    // Pass 2b also skips it as already handled, dropping callbacks stored in
    // tables entirely. Named/global and local functions have distinct CST
    // kinds; anonymous definitions belong exclusively to `lambda_kinds`.
    fn_kinds: &["function_declaration"],
    class_kinds: &[],
    class_decl_kinds: &[],
    method_kinds: &[],
    method_context_kinds: &[],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    if_kinds: &["if_statement", "elseif_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition"],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &[],
    condition_all_operators: &["and"],
    condition_any_operators: &["or"],
    condition_not_operators: &["not"],
    condition_not_operator_kinds: &[],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &[],
    loop_condition_field_names: &["condition"],
    loop_condition_extractor: None,
    branch_arm_kinds: &["block", "elseif_statement", "else_statement"],
    exclusive_branch_arm_kinds: &[],
    fallthrough_branch_arm_kinds: &[],
    exclusive_catch_arm_kinds: &[],
    additional_alternative_kinds: &[],
    for_kinds: &["for_statement"],
    foreach_kinds: &[],
    foreach_binding_extractor: Some(lua_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["repeat_statement"],
    loop_kinds: &[],
    call_kinds: &["function_call"],
    call_callee_field_names: &["name"],
    call_receiver_field_names: &["table"],
    call_member_field_names: &["method", "field"],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["arguments"],
    call_target_extractor: Some(lua_call_target),
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: None,
    call_ref_kinds: &["function_call"],
    member_expression_kinds: &["dot_index_expression"],
    subscript_expression_kinds: &["bracket_index_expression"],
    member_base_field_names: &["table"],
    member_name_field_names: &["field"],
    subscript_base_field_names: &["table"],
    // tree-sitter-lua names the parsed key of `table[key]` as `field`.
    // Keep `index` for grammar-pack compatibility, but derive both from CST
    // roles rather than re-reading bracket text.
    subscript_index_field_names: &["field"],
    assignment_kinds: &["assignment_statement", "variable_declaration"],
    return_kinds: &["return_statement"],
    throw_kinds: &[],
    lambda_kinds: &["function_definition"],
    try_kinds: &[],
    catch_kinds: &[],
    finally_kinds: &[],
    break_kinds: &["break_statement"],
    control_label_field_names: &[],
    control_target_extractor: None,
    loop_label_extractor: None,
    // Lua has no `continue` keyword. `goto label` is a general jump,
    // not a loop continue, so leaving this empty avoids mis-tagging
    // arbitrary gotos as `FlowEvent::Continue`.
    continue_kinds: &[],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &[],
    special_forms: &[],
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
    ..bonsai_lang_api::EMPTY_HANDLER
};

#[derive(Debug, Default, Copy, Clone)]
pub struct LuaAdapter;

impl LuaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for LuaAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Lua"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["lua"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            // `function T:method(...)` introduces the language-defined
            // receiver binding `self`; Lua has no super-dispatch token.
            implicit_receiver_tokens: &["self"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "assignment_statement"),
            ("custom lowering", "binary_expression"),
            ("custom lowering", "bracket_index_expression"),
            ("custom lowering", "dot_index_expression"),
            ("custom lowering", "expression_list"),
            ("custom lowering", "false"),
            ("custom lowering", "field"),
            ("custom lowering", "for_generic_clause"),
            ("custom lowering", "for_statement"),
            ("custom lowering", "function_call"),
            ("custom lowering", "function_declaration"),
            ("custom lowering", "identifier"),
            ("custom lowering", "method_index_expression"),
            ("custom lowering", "nil"),
            ("custom lowering", "number"),
            ("custom lowering", "parenthesized_expression"),
            ("custom lowering", "return_statement"),
            ("custom lowering", "string"),
            ("custom lowering", "string_content"),
            ("custom lowering", "table_constructor"),
            ("custom lowering", "true"),
            ("custom lowering", "variable_list"),
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
        let (local_fn_spans, table_member_names) = if let Some((snapshot, tree)) = parsed.as_ref() {
            let source = snapshot.text.as_bytes();
            idx.refs
                .extend(synthesize_lua_global_arg_refs(tree, source, file));
            // The current grammar parses `local function helper(...)`
            // as `function_declaration` in the chunk's exact
            // `local_declaration` field.
            let mut spans: Vec<bonsai_common::Span> = Vec::new();
            let root = tree.root_node();
            let mut chunk_cursor = root.walk();
            // Field-name walk handles the MunifTanjim shape where
            // `local function` rides as a `function_declaration`
            // tagged with the `local_declaration` field.
            if chunk_cursor.goto_first_child() {
                loop {
                    if chunk_cursor.field_name() == Some("local_declaration")
                        && chunk_cursor.node().kind() == "function_declaration"
                    {
                        spans.push(span_of(file, &chunk_cursor.node()));
                    }
                    if !chunk_cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            (spans, collect_lua_table_member_names(tree, source, file))
        } else {
            (Vec::new(), Vec::new())
        };
        // Lua has no language-level module boundary; file stem is the
        // closest semantic anchor for qualified_name and module_path.
        // See `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        apply_lua_table_member_semantic_identity(&mut idx, &table_member_names);
        // `local function` is chunk-private (file-scoped). Mark these
        // as Visibility::Private so the resolver refuses cross-file
        // calls to local Lua helpers.
        for decl in &mut idx.defs {
            if local_fn_spans.contains(&decl.span) {
                decl.visibility = bonsai_lang_api::Visibility::Private;
            }
        }
        // Lua module-table return idiom: `local M = {}; function M.foo(...
        // ); ... return M`. The trailing `return M` declares M as the
        // file's exported surface. Decls attached to the table (named
        // `M.foo`) keep `Public`; sibling top-level free functions
        // become `Visibility::Module` so the resolver narrows
        // cross-file candidate sets to the explicit exports.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            if let Some(table_name) = collect_lua_module_export_table(tree, src) {
                let table_dotted_prefix = format!("{table_name}.");
                let table_member_decls: std::collections::HashSet<bonsai_common::Span> =
                    collect_lua_table_member_decl_spans(tree, src, &table_name, file);
                for decl in &mut idx.defs {
                    if !matches!(decl.kind, bonsai_lang_api::DeclKind::Function) {
                        continue;
                    }
                    if decl.parent.is_some() {
                        continue;
                    }
                    if matches!(decl.visibility, bonsai_lang_api::Visibility::Private) {
                        continue;
                    }
                    let attached_to_table = table_member_decls.contains(&decl.span)
                        || decl.name.starts_with(&table_dotted_prefix);
                    if !attached_to_table {
                        decl.visibility = bonsai_lang_api::Visibility::Module;
                    }
                }
            }
            idx.character_constraints
                .extend(lua_provider_character_constraints(&idx.defs, tree, file, src));
            populate_lua_condition_expressions(&mut idx.branch_conditions, tree, file, src);
            idx.predicate_returns
                .extend(collect_lua_predicate_returns(&idx.defs, tree, file, src));
        }
        let table_field_assigns = parsed
            .as_ref()
            .map(|(snapshot, tree)| {
                collect_lua_table_literal_field_assigns(tree, snapshot.text.as_bytes(), file)
            })
            .unwrap_or_default();
        for decl in &mut idx.defs {
            insert_lua_table_field_assigns_in_events(&mut decl.flow_events, &table_field_assigns);
            normalize_lua_dot_calls(&mut decl.flow_events);
            enrich_lua_factory_receiver_field_writes(decl);
            mark_lua_receiver_factory(decl);
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                tree,
                file,
                src,
                &HANDLER,
                lua_static_scalar,
            );
            bonsai_lang_api::kit::populate_assignment_inline_callback_static_returns(
                &mut idx,
                tree,
                src,
                &HANDLER,
                lua_static_scalar,
            );
            idx.compiler_guards
                .extend(collect_lua_compound_static_allowlist_guards(
                    tree,
                    file,
                    src,
                    &idx.defs,
                    &idx.call_argument_values,
                ));
            idx.string_compositions
                .extend(collect_lua_string_compositions(tree, file, src));
            idx.string_compositions.sort_by_key(|fact| {
                (
                    fact.value_span.start,
                    fact.value_span.end,
                    fact.container_span.start,
                )
            });
            idx.string_compositions.dedup();
            idx.finite_literal_selections = collect_lua_finite_literal_selections(&idx, tree, file, src);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing follows adapter facts and
        // declarations; spelling alone is not constructor evidence.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
            return ImportIndex {
                file,
                ..ImportIndex::default()
            };
        };
        let src = snapshot.text.as_bytes();
        let mut idx = import_index_from_tree(&tree, src, file, parse_imports);
        if let (Some(table_name), Some(module)) = (
            collect_lua_module_export_table(&tree, src),
            lua_file_module_name(file, ctx),
        ) {
            idx.imports.push(ImportSpec {
                span: span_of(file, &tree.root_node()),
                module,
                alias: Some(table_name),
                is_wildcard: false,
                original_name: None,
                // Resolver-only self-module binding for the
                // `local M = {}; ...; return M` export idiom.
                // It is not an import statement and must not
                // appear in browse/export import inventories.
                scope: ImportScope::Local,
            });
        }
        idx
    }
}

/// Prove that a Lua table lookup with a literal fallback can produce only a
/// finite set of literal values. This is deliberately language syntax only:
/// downstream analysis decides which security boundary, if any, benefits
/// from the proof.
fn collect_lua_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    struct FiniteTableBinding {
        name: String,
        definition_target_id: usize,
        declaration_end: usize,
    }

    let assignments = collect_kinds(tree, &["assignment_statement"]);
    let mut bindings = Vec::new();
    for assignment in &assignments {
        let Some((target, value)) = lua_single_assignment(*assignment) else {
            continue;
        };
        if target.kind() != "identifier"
            || value.kind() != "table_constructor"
            || !lua_assignment_declares_local(*assignment)
            || !lua_table_contains_only_finite_literals(value, src)
        {
            continue;
        }
        let name = node_text(&target, src).trim();
        if name.is_empty()
            || !lua_finite_table_binding_is_stable(tree, target.id(), name, assignment.end_byte(), src)
        {
            continue;
        }
        bindings.push(FiniteTableBinding {
            name: name.to_string(),
            definition_target_id: target.id(),
            declaration_end: assignment.end_byte(),
        });
    }

    let mut facts = Vec::new();
    for selection in collect_kinds(tree, &["binary_expression"]) {
        let Some((lookup, fallback)) = lua_literal_fallback_selection(selection, src) else {
            continue;
        };
        let Some(table) = lookup.child_by_field_name("table") else {
            continue;
        };
        if table.kind() != "identifier" {
            continue;
        }
        let table_name = node_text(&table, src).trim();
        if !bindings.iter().any(|binding| {
            binding.name == table_name
                && binding.declaration_end <= selection.start_byte()
                && binding.definition_target_id != table.id()
        }) {
            continue;
        }
        debug_assert!(lua_finite_literal(fallback, src));
        let selection_span = span_of(file, &selection);
        if let Some(fact) =
            bonsai_lang_api::kit::finite_literal_selection_fact_for_span(index, tree, selection_span, |_| {
                true
            })
        {
            facts.push(fact);
        }
    }
    bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut facts);
    facts
}

fn lua_single_assignment(assignment: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let variables = first_named_child_of_kind(&assignment, "variable_list")?;
    let values = first_named_child_of_kind(&assignment, "expression_list")?;
    let mut variable_cursor = variables.walk();
    let targets = variables.named_children(&mut variable_cursor).collect::<Vec<_>>();
    let mut value_cursor = values.walk();
    let expressions = values.named_children(&mut value_cursor).collect::<Vec<_>>();
    match (targets.as_slice(), expressions.as_slice()) {
        ([target], [value]) => Some((*target, *value)),
        _ => None,
    }
}

fn lua_assignment_declares_local(assignment: Node<'_>) -> bool {
    let Some(declaration) = assignment
        .parent()
        .filter(|parent| parent.kind() == "variable_declaration")
    else {
        return false;
    };
    let Some(scope) = declaration.parent() else {
        return false;
    };
    let mut cursor = scope.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        if cursor.node().id() == declaration.id() {
            return cursor.field_name() == Some("local_declaration");
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

fn lua_table_contains_only_finite_literals(table: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = table.walk();
    let fields = table.named_children(&mut cursor).collect::<Vec<_>>();
    !fields.is_empty()
        && fields.into_iter().all(|field| {
            field.kind() == "field"
                && field
                    .child_by_field_name("value")
                    .is_some_and(|value| lua_finite_literal(value, src))
        })
}

fn lua_finite_literal(node: Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        "string" => lua_static_string(node, src).is_some(),
        "number" | "true" | "false" | "nil" => true,
        _ => false,
    }
}

fn lua_literal_fallback_selection<'tree>(
    expression: Node<'tree>,
    src: &[u8],
) -> Option<(Node<'tree>, Node<'tree>)> {
    let left = expression.child_by_field_name("left")?;
    let right = expression.child_by_field_name("right")?;
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    let lookup = lua_unwrap_parenthesized(left)?;
    let fallback = lua_unwrap_parenthesized(right)?;
    (operator == Some("or")
        && lookup.kind() == "bracket_index_expression"
        && lua_finite_literal(fallback, src))
    .then_some((lookup, fallback))
}

fn lua_finite_table_binding_is_stable(
    tree: &Tree,
    definition_target_id: usize,
    name: &str,
    declaration_end: usize,
    src: &[u8],
) -> bool {
    collect_kinds(tree, &["identifier"])
        .into_iter()
        .filter(|identifier| node_text(identifier, src).trim() == name)
        .all(|identifier| {
            if identifier.id() == definition_target_id {
                return true;
            }
            if identifier.start_byte() < declaration_end {
                return false;
            }
            let Some(lookup) = identifier
                .parent()
                .filter(|parent| parent.kind() == "bracket_index_expression")
            else {
                return false;
            };
            if lookup
                .child_by_field_name("table")
                .is_none_or(|table| table.id() != identifier.id())
            {
                return false;
            }
            !lua_node_is_assignment_target(lookup)
        })
}

fn lua_node_is_assignment_target(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "variable_list" => return true,
            "assignment_statement" | "expression_list" => return false,
            _ => node = parent,
        }
    }
    false
}

/// Record provider-bound character substitutions without assigning security
/// meaning to the operation name. Lua permits a method call to consume an
/// exact character-class pattern and an exact replacement table. The adapter
/// proves only that syntactic/runtime candidate and its complete mapping;
/// rule data selects which operation has substitution semantics.
fn lua_provider_character_constraints(
    defs: &[bonsai_lang_api::Decl],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterConstraintFact> {
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_declaration"]) {
        let function_span = span_of(file, &function);
        let Some(decl) = defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let mut body_cursor = body.walk();
        let statements = body.named_children(&mut body_cursor).collect::<Vec<_>>();
        let [return_statement] = statements.as_slice() else {
            continue;
        };
        if return_statement.kind() != "return_statement" {
            continue;
        }
        let Some(expression) = lua_single_expression(*return_statement) else {
            continue;
        };
        let Some(call) = lua_unwrap_parenthesized(expression).filter(|node| node.kind() == "function_call")
        else {
            continue;
        };
        let Some(target) = call.child_by_field_name("name").or_else(|| call.named_child(0)) else {
            continue;
        };
        if target.kind() != "method_index_expression" {
            continue;
        }
        let Some(receiver) = target.child_by_field_name("table") else {
            continue;
        };
        let receiver = node_text(&receiver, src).trim();
        let Some(input_param_index) = decl.params.iter().position(|param| param == receiver) else {
            continue;
        };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut argument_cursor = arguments.walk();
        let arguments = arguments.named_children(&mut argument_cursor).collect::<Vec<_>>();
        let [pattern, replacements] = arguments.as_slice() else {
            continue;
        };
        let Some(mut characters) = lua_exact_character_class(*pattern, src) else {
            continue;
        };
        let Some(mut mappings) = lua_exact_string_map(*replacements, src) else {
            continue;
        };
        characters.sort();
        characters.dedup();
        mappings.sort_by(|left, right| left.key.cmp(&right.key));
        mappings.dedup();
        if characters.len() != mappings.len()
            || !characters
                .iter()
                .zip(&mappings)
                .all(|(character, mapping)| character == &mapping.key)
        {
            continue;
        }
        let operation_call = node_text(&target, src)
            .chars()
            .filter(|character| !character.is_whitespace())
            .map(|character| if character == ':' { '.' } else { character })
            .collect::<String>();
        if operation_call.is_empty() {
            continue;
        }
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span: span_of(file, &call),
            input_place: receiver.to_string(),
            input_param_index: Some(input_param_index),
            proof: bonsai_lang_api::CharacterConstraintProof::ExactRuntimeSemantics,
            output: CharacterConstraintOutput::Return,
            domain: CharacterConstraintDomain::ProviderBound {
                factory_call: String::new(),
                operation_call,
                domain: Box::new(CharacterConstraintDomain::SubstitutesExact { mappings }),
            },
        });
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.transform_span.start));
    facts.dedup();
    facts
}

fn lua_single_expression(return_statement: Node<'_>) -> Option<Node<'_>> {
    let expression_list = return_statement
        .child_by_field_name("value")
        .or_else(|| first_named_child_of_kind(&return_statement, "expression_list"))?;
    let mut cursor = expression_list.walk();
    let expressions = expression_list.named_children(&mut cursor).collect::<Vec<_>>();
    let [expression] = expressions.as_slice() else {
        return None;
    };
    Some(*expression)
}

fn lua_unwrap_parenthesized(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "parenthesized_expression" {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        let [child] = children.as_slice() else {
            return None;
        };
        node = *child;
    }
    Some(node)
}

fn lua_exact_string_map(table: Node<'_>, src: &[u8]) -> Option<Vec<StaticStringMapEntry>> {
    if table.kind() != "table_constructor" {
        return None;
    }
    let mut entries = Vec::new();
    let mut cursor = table.walk();
    for field in table.named_children(&mut cursor) {
        if field.kind() != "field" {
            return None;
        }
        let key = lua_static_string(field.child_by_field_name("name")?, src)?;
        let value = lua_static_string(field.child_by_field_name("value")?, src)?;
        entries.push(StaticStringMapEntry { key, value });
    }
    (!entries.is_empty()).then_some(entries)
}

fn lua_exact_character_class(pattern: Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let pattern = lua_static_string(pattern, src)?;
    let inner = pattern.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty()
        || inner.starts_with('^')
        || inner
            .chars()
            .any(|character| matches!(character, '[' | ']' | '-' | '%' | '^'))
    {
        return None;
    }
    Some(inner.chars().map(|character| character.to_string()).collect())
}

fn lua_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = node_text(&node, src).trim();
    let quote = raw.chars().next()?;
    if !matches!(quote, '\'' | '"') || !raw.ends_with(quote) || raw.len() < 2 {
        return None;
    }
    let inner = raw.get(quote.len_utf8()..raw.len().checked_sub(quote.len_utf8())?)?;
    let mut decoded = String::new();
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let escaped = chars.next()?;
        decoded.push(match escaped {
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => return None,
        });
    }
    Some(decoded)
}

fn lua_exact_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    let node = lua_unwrap_parenthesized(node)?;
    match node.kind() {
        "identifier" => {
            let place = node_text(&node, src).trim();
            (!place.is_empty()).then(|| place.to_string())
        }
        "dot_index_expression" | "bracket_index_expression" => {
            let place = node_text(&node, src)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            (!place.is_empty()).then_some(place)
        }
        _ => None,
    }
}

fn lua_concat_operands<'tree>(node: Node<'tree>, src: &[u8]) -> Option<(Node<'tree>, Node<'tree>)> {
    let node = lua_unwrap_parenthesized(node)?;
    if node.kind() != "binary_expression" {
        return None;
    }
    let left = node.child_by_field_name("left").or_else(|| node.named_child(0))?;
    let right = node
        .child_by_field_name("right")
        .or_else(|| node.named_child(1))?;
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())?
        .trim();
    (operator == "..").then_some((left, right))
}

fn lower_lua_string_composition(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    parts: &mut Vec<(StringCompositionPart, Span)>,
) -> bool {
    let Some(node) = lua_unwrap_parenthesized(node) else {
        return false;
    };
    if let Some((left, right)) = lua_concat_operands(node, src) {
        return lower_lua_string_composition(left, file, src, parts)
            && lower_lua_string_composition(right, file, src, parts);
    }
    let span = span_of(file, &node);
    if let Some(value) = lua_static_string(node, src) {
        parts.push((StringCompositionPart::Literal { value }, span));
        return true;
    }
    if let Some(place) = lua_exact_place(node, src) {
        parts.push((StringCompositionPart::Place { place }, span));
        return true;
    }
    if node.kind() == "function_call" {
        let Some(target) = lua_call_target(node, src) else {
            return false;
        };
        parts.push((
            StringCompositionPart::Call {
                span: span_of(file, &target.node),
            },
            span,
        ));
        return true;
    }
    false
}

/// Lower only complete Lua `..` expressions. Unsupported operands reject the
/// entire fact, so downstream rule constraints never reason from a partial
/// reconstruction of the runtime string.
fn collect_lua_string_compositions(tree: &Tree, file: FileId, src: &[u8]) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for value in collect_kinds(tree, &["binary_expression"]) {
        if lua_concat_operands(value, src).is_none() {
            continue;
        }
        if value.parent().is_some_and(|parent| {
            lua_unwrap_parenthesized(parent).is_some_and(|parent| lua_concat_operands(parent, src).is_some())
        }) {
            continue;
        }
        let mut lowered = Vec::new();
        if !lower_lua_string_composition(value, file, src, &mut lowered) || lowered.len() < 2 {
            continue;
        }
        let dynamic = lowered
            .iter()
            .filter(|(part, _)| !matches!(part, StringCompositionPart::Literal { .. }))
            .map(|(_, span)| *span)
            .collect::<Vec<_>>();
        if dynamic.is_empty() {
            continue;
        }
        let value_span = span_of(file, &value);
        facts.push(StringCompositionFact {
            container_span: value_span,
            value_span,
            target: None,
            dynamic_anchor_span: (dynamic.len() == 1).then_some(dynamic[0]),
            parts: lowered.into_iter().map(|(part, _)| part).collect(),
        });
    }
    facts.sort_by_key(|fact| (fact.value_span.start, fact.value_span.end));
    facts.dedup();
    facts
}

/// Decode Lua-owned scalar syntax for exact compiler configuration facts.
fn lua_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "nil" => Some(StaticScalarValue::Null),
        "string" => Some(StaticScalarValue::String(lua_static_string(node, src)?)),
        _ => None,
    }
}

/// Attach exact Lua boolean syntax to the generic branch facts emitted by
/// the shared walker. Runtime/provider meaning remains outside the adapter.
fn populate_lua_condition_expressions(
    facts: &mut [bonsai_lang_api::BranchConditionFact],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    for branch in collect_kinds(tree, &["if_statement", "elseif_statement"]) {
        let branch_span = span_of(file, &branch);
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        let Some(fact) = facts.iter_mut().find(|fact| fact.branch_span == branch_span) else {
            continue;
        };
        fact.expression = Some(lower_lua_condition_expression(condition, file, src));
    }
}

/// Preserve the complete boolean return of single-expression predicate
/// helpers. This is syntax-only IR: calls remain spans until rule matching
/// assigns an operation its security meaning.
fn collect_lua_predicate_returns(
    defs: &[bonsai_lang_api::Decl],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<PredicateReturnFact> {
    let mut out = Vec::new();
    for function in collect_kinds(tree, &["function_declaration"]) {
        let function_span = span_of(file, &function);
        let Some(decl) = defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let mut cursor = body.walk();
        let statements = body
            .named_children(&mut cursor)
            .filter(|statement| statement.kind() != "comment")
            .collect::<Vec<_>>();
        let [return_statement] = statements.as_slice() else {
            continue;
        };
        if return_statement.kind() != "return_statement" {
            continue;
        }
        let Some(expression) = lua_single_expression(*return_statement) else {
            continue;
        };
        out.push(PredicateReturnFact {
            function_span: decl.span,
            return_span: span_of(file, return_statement),
            expression: lower_lua_condition_expression(expression, file, src),
        });
    }
    out.sort_by_key(|fact| (fact.function_span.start, fact.return_span.start));
    out.dedup();
    out
}

fn lua_nodes_below<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    out.sort_by_key(Node::start_byte);
    out
}

fn lua_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn lua_call_arguments(call: Node<'_>) -> Option<Vec<Node<'_>>> {
    let arguments = call.child_by_field_name("arguments")?;
    Some(lua_named_children(arguments))
}

fn lua_binary_parts<'tree, 'src>(
    expression: Node<'tree>,
    src: &'src [u8],
) -> Option<(Node<'tree>, &'src str, Node<'tree>)> {
    if expression.kind() != "binary_expression" {
        return None;
    }
    let left = expression.child_by_field_name("left")?;
    let right = expression.child_by_field_name("right")?;
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())?
        .trim();
    Some((left, operator, right))
}

fn lua_flatten_exact_conjunction<'tree>(
    expression: Node<'tree>,
    src: &[u8],
    out: &mut Vec<Node<'tree>>,
) -> bool {
    if let Some((left, "and", right)) = lua_binary_parts(expression, src) {
        lua_flatten_exact_conjunction(left, src, out) && lua_flatten_exact_conjunction(right, src, out)
    } else {
        out.push(expression);
        true
    }
}

fn lua_exact_true_table_bindings(tree: &Tree, src: &[u8]) -> std::collections::BTreeMap<String, usize> {
    let mut out = std::collections::BTreeMap::new();
    for assignment in collect_kinds(tree, &["assignment_statement"]) {
        let Some((target, value)) = lua_single_assignment(assignment) else {
            continue;
        };
        if target.kind() != "identifier"
            || value.kind() != "table_constructor"
            || !lua_assignment_declares_local(assignment)
        {
            continue;
        }
        let name = node_text(&target, src).trim();
        if name.is_empty()
            || !lua_finite_table_binding_is_stable(tree, target.id(), name, assignment.end_byte(), src)
        {
            continue;
        }
        let fields = lua_named_children(value);
        if fields.is_empty()
            || fields.iter().any(|field| {
                field.kind() != "field"
                    || field
                        .child_by_field_name("name")
                        .and_then(|key| lua_static_string(key, src))
                        .is_none()
                    || field
                        .child_by_field_name("value")
                        .is_none_or(|value| value.kind() != "true")
            })
        {
            continue;
        }
        out.insert(name.to_string(), fields.len());
    }
    out
}

#[derive(Clone)]
struct LuaCompoundPredicate {
    declaration_span: Span,
    name: String,
    input: String,
    extracted: String,
    extractor_call: String,
    extractor_literal: String,
    table: String,
    table_size: usize,
    proof_span: Span,
}

fn lua_compound_predicates(tree: &Tree, file: FileId, src: &[u8]) -> Vec<LuaCompoundPredicate> {
    let static_tables = lua_exact_true_table_bindings(tree, src);
    let mut predicates = Vec::new();
    for declaration in collect_kinds(tree, &["function_declaration"]) {
        let (Some(name), Some(parameters), Some(body)) = (
            declaration.child_by_field_name("name"),
            declaration.child_by_field_name("parameters"),
            declaration.child_by_field_name("body"),
        ) else {
            continue;
        };
        if name.kind() != "identifier" {
            continue;
        }
        let params = lua_named_children(parameters);
        let [param] = params.as_slice() else {
            continue;
        };
        if param.kind() != "identifier" {
            continue;
        }
        let statements = lua_named_children(body)
            .into_iter()
            .filter(|node| node.kind() != "comment")
            .collect::<Vec<_>>();
        let [assignment, returned] = statements.as_slice() else {
            continue;
        };
        let assignment = if assignment.kind() == "variable_declaration" {
            first_named_child_of_kind(assignment, "assignment_statement")
        } else {
            Some(*assignment)
        };
        let Some(assignment) = assignment else {
            continue;
        };
        let Some((extracted, extractor)) = lua_single_assignment(assignment) else {
            continue;
        };
        if extracted.kind() != "identifier" || extractor.kind() != "function_call" {
            continue;
        }
        let Some(target) = lua_call_target(extractor, src) else {
            continue;
        };
        let Some(receiver) = target.node.child_by_field_name("table") else {
            continue;
        };
        if node_text(&receiver, src).trim() != node_text(param, src).trim() {
            continue;
        }
        let Some(extractor_args) = lua_call_arguments(extractor) else {
            continue;
        };
        let [literal] = extractor_args.as_slice() else {
            continue;
        };
        let Some(extractor_literal) = lua_static_string(*literal, src) else {
            continue;
        };
        if returned.kind() != "return_statement" {
            continue;
        }
        let Some(return_expression) = lua_single_expression(*returned) else {
            continue;
        };
        let mut conjuncts = Vec::new();
        if !lua_flatten_exact_conjunction(return_expression, src, &mut conjuncts) || conjuncts.len() != 2 {
            continue;
        }
        let extracted_name = node_text(&extracted, src).trim();
        let has_presence_proof = conjuncts.iter().any(|conjunct| {
            let Some((left, operator, right)) = lua_binary_parts(*conjunct, src) else {
                return false;
            };
            operator == "~="
                && ((node_text(&left, src).trim() == extracted_name && right.kind() == "nil")
                    || (node_text(&right, src).trim() == extracted_name && left.kind() == "nil"))
        });
        let membership = conjuncts.iter().find_map(|conjunct| {
            let (left, operator, right) = lua_binary_parts(*conjunct, src)?;
            if operator != "==" {
                return None;
            }
            let lookup = if left.kind() == "bracket_index_expression" && right.kind() == "true" {
                left
            } else if right.kind() == "bracket_index_expression" && left.kind() == "true" {
                right
            } else {
                return None;
            };
            let table = lookup.child_by_field_name("table")?;
            let field = lookup.child_by_field_name("field")?;
            (node_text(&field, src).trim() == extracted_name)
                .then(|| node_text(&table, src).trim().to_string())
        });
        let Some(table) = membership.filter(|table| static_tables.contains_key(table)) else {
            continue;
        };
        predicates.push(LuaCompoundPredicate {
            declaration_span: span_of(file, &declaration),
            name: node_text(&name, src).trim().to_string(),
            input: node_text(param, src).trim().to_string(),
            extracted: extracted_name.to_string(),
            extractor_call: target.full_text,
            extractor_literal,
            table_size: static_tables[&table],
            table,
            proof_span: span_of(file, returned),
        });
        if !has_presence_proof {
            predicates.pop();
        }
    }
    predicates
}

fn lua_static_scalar_evidence(value: &StaticScalarValue) -> String {
    match value {
        StaticScalarValue::String(value) => format!("string:{value}"),
        StaticScalarValue::Boolean(value) => format!("boolean:{value}"),
        StaticScalarValue::Integer(value) => format!("integer:{value}"),
        StaticScalarValue::Null => "null".to_string(),
    }
}

fn lua_place_overwritten_between(body: Node<'_>, place: &str, start: usize, end: usize, src: &[u8]) -> bool {
    lua_nodes_below(body, "assignment_statement")
        .into_iter()
        .filter(|assignment| start < assignment.start_byte() && assignment.end_byte() < end)
        .filter_map(lua_single_assignment)
        .any(|(target, _)| node_text(&target, src).trim() == place)
}

/// Prove a local Lua helper whose complete return accepts only an extracted
/// token present in one immutable finite string table, plus the terminal
/// rejecting caller guard that dominates one exact call argument. This is
/// generic parsed evidence; rule data decides whether the extractor pattern,
/// sink call, and static call options form a security boundary.
fn collect_lua_compound_static_allowlist_guards(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    defs: &[bonsai_lang_api::Decl],
    argument_values: &[bonsai_lang_api::CallArgumentValueFact],
) -> Vec<CompilerGuardFact> {
    let predicates = lua_compound_predicates(tree, file, src);
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_declaration"]) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let function_span = span_of(file, &function);
        let Some(function_span) = defs
            .iter()
            .find(|decl| decl.span == function_span)
            .map(|decl| decl.span)
        else {
            continue;
        };
        for branch in lua_nodes_below(body, "if_statement") {
            let (Some(condition), Some(consequence)) = (
                branch.child_by_field_name("condition"),
                branch.child_by_field_name("consequence"),
            ) else {
                continue;
            };
            if condition.kind() != "unary_expression" {
                continue;
            }
            let Some(predicate_call) = condition.child_by_field_name("operand") else {
                continue;
            };
            if predicate_call.kind() != "function_call" {
                continue;
            }
            let operator = src
                .get(condition.start_byte()..predicate_call.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if operator != Some("not") {
                continue;
            }
            let Some(predicate_target) = lua_call_target(predicate_call, src) else {
                continue;
            };
            let Some(predicate) = predicates.iter().find(|predicate| {
                predicate.name == predicate_target.full_text
                    && predicate.declaration_span.end <= function.start_byte() as u64
            }) else {
                continue;
            };
            let Some(predicate_args) = lua_call_arguments(predicate_call) else {
                continue;
            };
            let [guarded_value] = predicate_args.as_slice() else {
                continue;
            };
            let guarded_place = node_text(guarded_value, src).trim();
            if guarded_place.is_empty() {
                continue;
            }
            let consequence_statements = lua_named_children(consequence)
                .into_iter()
                .filter(|node| node.kind() != "comment")
                .collect::<Vec<_>>();
            if consequence_statements.as_slice().len() != 1
                || consequence_statements[0].kind() != "return_statement"
            {
                continue;
            }
            for guarded_call in lua_nodes_below(body, "function_call")
                .into_iter()
                .filter(|call| call.start_byte() > branch.end_byte())
            {
                let Some(target) = lua_call_target(guarded_call, src) else {
                    continue;
                };
                let Some(arguments) = lua_call_arguments(guarded_call) else {
                    continue;
                };
                let Some((guarded_index, _)) = arguments
                    .iter()
                    .enumerate()
                    .find(|(_, argument)| node_text(argument, src).trim() == guarded_place)
                else {
                    continue;
                };
                if lua_place_overwritten_between(
                    body,
                    guarded_place,
                    branch.end_byte(),
                    guarded_call.start_byte(),
                    src,
                ) {
                    continue;
                }
                let guarded_call_span = span_of(file, &target.node);
                let extractor_tail = predicate
                    .extractor_call
                    .rsplit([':', '.'])
                    .next()
                    .unwrap_or(&predicate.extractor_call);
                let mut evidence = vec![
                    format!("guarded-call:{}", target.full_text),
                    format!("predicate-call:{}", predicate.name),
                    format!("predicate-input:{}", predicate.input),
                    format!("predicate-extracted:{}", predicate.extracted),
                    "predicate-complete:true".to_string(),
                    format!("extractor-call:{extractor_tail}"),
                    format!("extractor-target:{}", predicate.extractor_call),
                    format!("extractor-value:string:{}", predicate.extractor_literal),
                    format!("membership-table:{}", predicate.table),
                    format!("finite-string-membership-count:{}", predicate.table_size),
                    "finite-static-string-membership:true".to_string(),
                    format!("guarded-argument:{guarded_index}=predicate-argument:0"),
                ];
                for argument in argument_values
                    .iter()
                    .filter(|fact| fact.call_span == guarded_call_span)
                {
                    for field in &argument.exact_static_aggregate_fields {
                        evidence.push(format!(
                            "guarded-static-field:{}.{path}={value}",
                            argument.argument_index,
                            path = field.path.join("."),
                            value = lua_static_scalar_evidence(&field.value),
                        ));
                    }
                }
                evidence.sort();
                evidence.dedup();
                facts.push(CompilerGuardFact {
                    function_span,
                    guarded_call_span,
                    proof_span: predicate.proof_span,
                    capability: "terminal-predicate.compound-static-allowlist".to_string(),
                    evidence,
                });
            }
        }
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.guarded_call_span.start));
    facts.dedup();
    facts
}

fn lower_lua_condition_expression(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    let span = span_of(file, &node);
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return lower_lua_condition_expression(inner, file, src);
        }
    }
    if node.kind() == "unary_expression" {
        if let Some(operand) = node
            .child_by_field_name("operand")
            .or_else(|| node.named_child(0))
        {
            let operator = src
                .get(node.start_byte()..operand.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if operator == Some("not") {
                return ConditionExpressionFact::Not {
                    span,
                    operand: Box::new(lower_lua_condition_expression(operand, file, src)),
                };
            }
        }
    }
    if node.kind() == "binary_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left").or_else(|| node.named_child(0)),
            node.child_by_field_name("right").or_else(|| node.named_child(1)),
        ) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            match operator {
                Some("and") => {
                    return merge_lua_condition(span, left, right, file, src, true);
                }
                Some("or") => {
                    return merge_lua_condition(span, left, right, file, src, false);
                }
                Some("==" | "~=") => {
                    if let Some(call_truthiness) = lua_nil_call_truthiness_expression(
                        span,
                        left,
                        right,
                        operator == Some("~="),
                        file,
                        src,
                    ) {
                        return call_truthiness;
                    }
                    return ConditionExpressionFact::Equality {
                        span,
                        relation: if operator == Some("==") {
                            ConditionEquality::Equal
                        } else {
                            ConditionEquality::NotEqual
                        },
                        left: lua_condition_operand(left, file, src),
                        right: lua_condition_operand(right, file, src),
                    };
                }
                _ => {}
            }
        }
    }
    if node.kind() == "function_call" {
        return ConditionExpressionFact::Atom { span };
    }
    ConditionExpressionFact::Truthy {
        span,
        operand: lua_condition_operand(node, file, src),
    }
}

/// In Lua, exactly `nil` and `false` are falsey. A parsed call compared with
/// `nil` is therefore a direct truthiness predicate over that call result;
/// lowering this runtime rule here keeps the shared guard evaluator language
/// neutral and preserves the exact call span.
fn lua_nil_call_truthiness_expression(
    span: Span,
    left: Node<'_>,
    right: Node<'_>,
    not_equal: bool,
    file: FileId,
    src: &[u8],
) -> Option<ConditionExpressionFact> {
    let call = if left.kind() == "function_call" && right.kind() == "nil" {
        left
    } else if right.kind() == "function_call" && left.kind() == "nil" {
        right
    } else {
        return None;
    };
    let truthy = ConditionExpressionFact::Truthy {
        span: span_of(file, &call),
        operand: lua_condition_operand(call, file, src),
    };
    Some(if not_equal {
        truthy
    } else {
        ConditionExpressionFact::Not {
            span,
            operand: Box::new(truthy),
        }
    })
}

fn merge_lua_condition(
    span: Span,
    left: Node<'_>,
    right: Node<'_>,
    file: FileId,
    src: &[u8],
    all: bool,
) -> ConditionExpressionFact {
    let left = lower_lua_condition_expression(left, file, src);
    let right = lower_lua_condition_expression(right, file, src);
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

fn lua_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    ConditionOperandFact {
        span: span_of(file, &node),
        direct_call_span: (node.kind() == "function_call").then(|| span_of(file, &node)),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER),
        static_string: lua_static_string(node, src),
        static_value: lua_static_scalar(node, src),
    }
}

/// Preserve the table owner of Lua's declaration syntax
/// `function Table.member(...)`. The generic declaration walker correctly
/// extracts the callable's short name, while the adapter owns the table path
/// needed to resolve `Table.member(...)` as the same declaration.
fn collect_lua_table_member_names(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<(bonsai_common::Span, String)> {
    let mut out = Vec::new();
    for declaration in collect_kinds(tree, &["function_declaration"]) {
        let Some(name_node) = declaration.child_by_field_name("name") else {
            continue;
        };
        let rendered = node_text(&name_node, src).trim();
        if !rendered.contains(['.', ':']) {
            continue;
        }
        let canonical = rendered
            .chars()
            .filter(|character| !character.is_whitespace())
            .map(|character| if character == ':' { '.' } else { character })
            .collect::<String>();
        if canonical.split('.').any(str::is_empty) {
            continue;
        }
        out.push((span_of(file, &declaration), canonical));
    }
    out
}

fn apply_lua_table_member_semantic_identity(
    index: &mut DeclIndex,
    table_members: &[(bonsai_common::Span, String)],
) {
    for declaration in &mut index.defs {
        let Some((_, qualified_name)) = table_members.iter().find(|(span, _)| *span == declaration.span)
        else {
            continue;
        };
        declaration.qualified_name = Some(qualified_name.clone());
    }
}

#[derive(Clone, Debug)]
struct LuaTableFieldAssigns {
    assign_span: bonsai_common::Span,
    target: String,
    fields: Vec<FlowEvent>,
}

fn collect_lua_table_literal_field_assigns(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<LuaTableFieldAssigns> {
    let mut out = Vec::new();
    for assignment in collect_kinds(tree, &["assignment_statement", "variable_declaration"]) {
        let Some(variable_list) = first_named_child_of_kind(&assignment, "variable_list") else {
            continue;
        };
        let Some(expression_list) = first_named_child_of_kind(&assignment, "expression_list") else {
            continue;
        };
        let mut variable_cursor = variable_list.walk();
        let targets = variable_list
            .named_children(&mut variable_cursor)
            .collect::<Vec<_>>();
        let mut expression_cursor = expression_list.walk();
        let values = expression_list
            .named_children(&mut expression_cursor)
            .collect::<Vec<_>>();

        // Lua pairs assignment values by ordinal. Extra RHS values are
        // evaluated and discarded, missing RHS slots receive nil, and only a
        // final call/vararg may expand to multiple values. A table constructor
        // always contributes exactly one value, so zipping the explicit CST
        // children is the complete and conservative correspondence here.
        for (target_node, value_node) in targets.into_iter().zip(values) {
            if target_node.kind() != "identifier" || value_node.kind() != "table_constructor" {
                continue;
            }
            let target = node_text(&target_node, src).trim();
            if target.is_empty() || !target.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
                continue;
            }
            let mut fields = Vec::new();
            collect_lua_table_literal_fields(target, value_node, src, file, &mut fields);
            if !fields.is_empty() {
                out.push(LuaTableFieldAssigns {
                    assign_span: span_of(file, &assignment),
                    target: target.to_string(),
                    fields,
                });
            }
        }
    }
    out
}

fn collect_lua_table_literal_fields(
    target: &str,
    table: Node<'_>,
    src: &[u8],
    file: FileId,
    out: &mut Vec<FlowEvent>,
) {
    let mut cursor = table.walk();
    for field in table
        .named_children(&mut cursor)
        .filter(|node| node.kind() == "field")
    {
        let Some(name_node) = field.child_by_field_name("name") else {
            continue;
        };
        let Some(value_node) = field.child_by_field_name("value") else {
            continue;
        };
        let key = node_text(&name_node, src).trim();
        if key.is_empty() || !key.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
            continue;
        }
        let field_target = format!("{target}.{key}");
        let sources = lua_value_source_names(value_node, src);
        out.push(FlowEvent::Assign {
            span: span_of(file, &value_node),
            target: field_target.clone(),
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
        if value_node.kind() == "table_constructor" {
            collect_lua_table_literal_fields(&field_target, value_node, src, file, out);
        }
    }
}

fn lua_value_source_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        match node.kind() {
            "identifier" => {
                let name = node_text(&node, src).trim();
                if !name.is_empty() {
                    out.push(name.to_string());
                }
                return;
            }
            "dot_index_expression" | "bracket_index_expression" => {
                let name = node_text(&node, src)
                    .replace([' ', '\t', '\n', '\r'], "")
                    .replace('[', ".")
                    .replace(']', "")
                    .replace(['\"', '\''], "");
                if !name.is_empty() {
                    out.push(name);
                }
                return;
            }
            "string" | "number" | "nil" | "true" | "false" => return,
            _ => {}
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

fn insert_lua_table_field_assigns_in_events(
    events: &mut Vec<FlowEvent>,
    field_assigns: &[LuaTableFieldAssigns],
) {
    let mut index = 0usize;
    while index < events.len() {
        match &mut events[index] {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_lua_table_field_assigns_in_events(then_events, field_assigns);
                insert_lua_table_field_assigns_in_events(else_events, field_assigns);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_lua_table_field_assigns_in_events(body, field_assigns);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_lua_table_field_assigns_in_events(body, field_assigns);
                insert_lua_table_field_assigns_in_events(catch_events, field_assigns);
                insert_lua_table_field_assigns_in_events(finally_events, field_assigns);
            }
            _ => {}
        }

        let inserts = match &events[index] {
            FlowEvent::Assign { span, target, .. } => field_assigns
                .iter()
                .filter(|item| {
                    item.target == *target
                        && span.file == item.assign_span.file
                        && span.start <= item.assign_span.end
                        && item.assign_span.start <= span.end
                })
                .flat_map(|item| item.fields.clone())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        if inserts.is_empty() {
            index += 1;
            continue;
        }
        let inserted = inserts.len();
        events.splice((index + 1)..=index, inserts);
        index += inserted + 1;
    }
}

fn normalize_lua_dot_calls(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                call_kind,
                ..
            } if name.contains(':') => {
                // `table:method(args)` injects `table` as the implicit
                // receiver. Canonicalize the adapter fact to the shared
                // dotted name representation only after preserving that
                // execution semantic.
                let canonical = name.replace(':', ".");
                *receiver = canonical.rsplit_once('.').map(|(owner, _)| owner.to_string());
                *name = canonical;
                *call_kind = bonsai_lang_api::CallKind::Method;
            }
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                ..
            } if name.contains('.') => {
                // Lua's `table.member(args)` syntax does not inject an
                // implicit receiver. Only `table:member(args)` does, and
                // the grammar preserves that colon in the call name. The
                // table qualifier is a namespace expression here; retaining
                // it as a receiver would make the shared resolver treat the
                // explicit first argument as an implicit receiver and shift
                // every parameter mapping by one.
                *call_kind = bonsai_lang_api::CallKind::Function;
                *receiver = None;
                receiver_types.clear();
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_lua_dot_calls(then_events);
                normalize_lua_dot_calls(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_lua_dot_calls(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_lua_dot_calls(body);
                normalize_lua_dot_calls(catch_events);
                normalize_lua_dot_calls(finally_events);
            }
            _ => {}
        }
    }
}

fn enrich_lua_factory_receiver_field_writes(decl: &mut bonsai_lang_api::Decl) {
    // Run receiver-field collection whenever the method carries an
    // explicit `self` param (the dot-def form `function T.m(self, ...)`)
    // -- not only for factories that `return self`. A plain mutator
    // `self.field = <param>` must still record a receiver_field_write so
    // stored taint flows through instance state (audit L6).
    let has_self_param = decl.params.iter().any(|param| param == "self");
    if !has_self_param && !lua_returns_name(&decl.flow_events, "self") {
        return;
    }
    let writes = collect_receiver_field_writes(&decl.flow_events, &decl.params, None, &["self"], &[]);
    if writes.is_empty() {
        return;
    }
    decl.receiver_field_writes.extend(writes);
    if !decl.implicit_receiver_names.iter().any(|name| name == "self") {
        decl.implicit_receiver_names.push("self".to_string());
    }
    decl.receiver_field_writes
        .sort_by_key(|write| (write.span.start, write.target.clone()));
    decl.receiver_field_writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
}

/// Classify a Lua function as a constructor only when its compiler-lowered
/// body proves both halves of object construction: parameter-derived fields
/// are written through the language's receiver binding and that same receiver
/// value is returned. This covers metatable/table factories without relying
/// on a factory spelling such as `new`; a mutator that merely writes `self`
/// remains an ordinary function.
fn mark_lua_receiver_factory(decl: &mut bonsai_lang_api::Decl) {
    if !decl.receiver_field_writes.is_empty() && lua_returns_name(&decl.flow_events, "self") {
        decl.kind = bonsai_lang_api::DeclKind::Constructor;
    }
}

fn lua_returns_name(events: &[FlowEvent], name: &str) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return {
            value_name,
            value_flow,
            ..
        } => value_name.as_deref() == Some(name) || value_flow.place.as_deref() == Some(name),
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => lua_returns_name(then_events, name) || lua_returns_name(else_events, name),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            lua_returns_name(body, name)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            lua_returns_name(body, name)
                || lua_returns_name(catch_events, name)
                || lua_returns_name(finally_events, name)
        }
        _ => false,
    })
}

/// Surface every bare `arg` identifier as a Read ref. Lua exposes the
/// chunk's argv as a global named `arg`, and rules query it directly
/// — without these refs the matcher has nothing to bind to.
fn synthesize_lua_global_arg_refs(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    collect_kinds(tree, &["identifier"])
        .into_iter()
        .filter(|node| node_text(node, src) == "arg")
        .map(|node| Ref {
            span: span_of(file, &node),
            name: "arg".to_string(),
            kind: RefKind::Read,
            scope: None,
            resolved: None,
        })
        .collect()
}

/// Lift every `require(...)` call into an `ImportSpec`. Lua has no
/// native import keyword; `local X = require('pkg')` is the idiom and
/// the only signal we have to associate a local binding with a module.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Side-effect loads (`require('pkg')` with no binding) are still
    // indexed so rules can match on the module presence alone.
    for call_node in collect_kinds(tree, &["function_call"]) {
        let Some(name_node) = call_node.child_by_field_name("name") else {
            continue;
        };
        if node_text(&name_node, src) != "require" {
            continue;
        }
        let Some(arg_list) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        let module = first_named_child_of_kind(&arg_list, "string")
            .and_then(|string_node| first_named_child_of_kind(&string_node, "string_content"))
            .map(|content_node| node_text(&content_node, src).to_string())
            .unwrap_or_default();
        if module.is_empty() {
            continue;
        }
        let alias = call_node
            .parent()
            .filter(|parent| parent.kind() == "expression_list")
            .and_then(|expr_list| expr_list.parent())
            .filter(|parent| parent.kind() == "assignment_statement")
            .and_then(|assignment| first_named_child_of_kind(&assignment, "variable_list"))
            .and_then(|var_list| first_named_child_of_kind(&var_list, "identifier"))
            .map(|ident| node_text(&ident, src).to_string());
        let member = call_node
            .parent()
            .filter(|parent| parent.kind() == "dot_index_expression")
            .and_then(|dot| dot.child_by_field_name("field"))
            .map(|field| node_text(&field, src).to_string())
            .filter(|field| !field.trim().is_empty());
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module: module.clone(),
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if let Some(member) = member {
            if let Some(local) = local_lua_assignment_target_for_call(call_node, src) {
                imports.push(ImportSpec {
                    span: span_of(file, &call_node),
                    module,
                    alias: Some(local),
                    is_wildcard: false,
                    original_name: Some(member),
                    scope: ImportScope::Local,
                });
            }
        }
    }
    imports
}

fn local_lua_assignment_target_for_call(call_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut expression = call_node;
    let assignment = loop {
        let parent = expression.parent()?;
        match parent.kind() {
            "function_call"
            | "dot_index_expression"
            | "method_index_expression"
            | "parenthesized_expression" => {
                expression = parent;
            }
            "expression_list" => {
                break parent
                    .parent()
                    .filter(|candidate| candidate.kind() == "assignment_statement")?;
            }
            _ => return None,
        }
    };
    first_named_child_of_kind(&assignment, "variable_list")
        .and_then(|var_list| first_named_child_of_kind(&var_list, "identifier"))
        .map(|ident| node_text(&ident, src).to_string())
        .filter(|text| !text.trim().is_empty())
}

fn lua_file_module_name(file: FileId, ctx: &AdapterContext<'_>) -> Option<String> {
    let path = ctx
        .workspace_relative_path(file)
        .or_else(|| ctx.vfs.path(file).ok().map(|p| (*p).clone()))?;
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| !stem.is_empty())
}

/// Find the file's tail `return <ident>` and return `<ident>` if the
/// chunk's last statement is a bare-identifier return. This matches
/// the Lua module-export idiom (`return M`). Computed returns
/// (`return setmetatable(...)`) and absent returns yield `None`,
/// in which case the caller does not narrow visibility.
fn collect_lua_module_export_table(tree: &Tree, src: &[u8]) -> Option<String> {
    let root = tree.root_node();
    let mut last_return: Option<tree_sitter::Node<'_>> = None;
    let mut cursor = root.walk();
    // The export idiom places the return at the very end, but the
    // grammar permits multiple `return` statements in a chunk.
    for child in root.named_children(&mut cursor) {
        if child.kind() == "return_statement" {
            last_return = Some(child);
        }
    }
    let return_stmt = last_return?;
    let exprs = match return_stmt.child_by_field_name("expression_list") {
        Some(node) => node,
        None => {
            // Older grammar releases expose `expression_list` as an
            // unnamed child rather than a labelled field. Bind the
            // search result to a local so the cursor outlives the
            // `find` iterator's borrow.
            let mut return_cursor = return_stmt.walk();
            let found = return_stmt
                .named_children(&mut return_cursor)
                .find(|child| child.kind() == "expression_list");
            found?
        }
    };
    let mut expr_cursor = exprs.walk();
    let mut returned_exprs: Vec<tree_sitter::Node<'_>> = exprs.named_children(&mut expr_cursor).collect();
    // Multi-return (`return a, b`) is not the export idiom.
    if returned_exprs.len() != 1 {
        return None;
    }
    let only_expr = returned_exprs.pop()?;
    // Computed returns (`return setmetatable(...)`) are skipped — only
    // a bare identifier names the module-table.
    if only_expr.kind() != "identifier" {
        return None;
    }
    Some(node_text(&only_expr, src).to_string())
}

/// Walk every `function_declaration` and collect spans for those whose
/// `name` is a `dot_index_expression` rooted at `table_name` — i.e.
/// `function M.foo(...)`. The returned set is the export-set for the
/// module-table return idiom.
fn collect_lua_table_member_decl_spans(
    tree: &Tree,
    src: &[u8],
    table_name: &str,
    file: FileId,
) -> std::collections::HashSet<bonsai_common::Span> {
    let mut member_spans = std::collections::HashSet::new();
    for fn_node in collect_kinds(tree, &["function_declaration"]) {
        let Some(name_node) = fn_node.child_by_field_name("name") else {
            continue;
        };
        // Free functions (`function foo()`) have a plain identifier
        // here; only dotted forms attach to a table.
        if name_node.kind() != "dot_index_expression" {
            continue;
        }
        let Some(table_node) = name_node.child_by_field_name("table") else {
            continue;
        };
        if node_text(&table_node, src) != table_name {
            continue;
        }
        member_spans.insert(span_of(file, &fn_node));
    }
    member_spans
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
