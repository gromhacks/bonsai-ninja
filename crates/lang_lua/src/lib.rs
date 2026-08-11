//! Lua language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, collect_receiver_field_writes, first_named_child_of_kind, language_from_pack,
        node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, CallTargetExtraction, DeclIndex, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    Ref, RefKind,
};
use tree_sitter::{Language, Node, Tree};

fn lua_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if !matches!(node.kind(), "for_statement" | "for_in_statement") {
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
    if !matches!(node.kind(), "function_call" | "method_call") {
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
//   - `local_function` covers `local function foo()` scoped to the chunk
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
    fn_kinds: &["function_declaration", "function_definition", "local_function"],
    class_kinds: &[],
    class_decl_kinds: &[],
    method_kinds: &[],
    method_context_kinds: &[],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    if_kinds: &["if_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block"],
    branch_arm_kinds: &["block", "elseif_statement", "else_statement"],
    additional_alternative_kinds: &["elseif_statement", "else_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &["for_in_statement"],
    foreach_binding_extractor: Some(lua_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["repeat_statement"],
    loop_kinds: &[],
    call_kinds: &["function_call", "method_call"],
    call_callee_field_names: &["name"],
    call_receiver_field_names: &["table", "prefix"],
    call_member_field_names: &["method", "field"],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["arguments"],
    call_target_extractor: Some(lua_call_target),
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: None,
    call_ref_kinds: &["function_call", "method_call"],
    member_expression_kinds: &["dot_index_expression"],
    subscript_expression_kinds: &["bracket_index_expression"],
    member_base_field_names: &["table", "prefix"],
    member_name_field_names: &["field"],
    subscript_base_field_names: &["table", "prefix"],
    // tree-sitter-lua names the parsed key of `table[key]` as `field`.
    // Keep `index` for grammar-pack compatibility, but derive both from CST
    // roles rather than re-reading bracket text.
    subscript_index_field_names: &["field", "index"],
    assignment_kinds: &["assignment_statement", "variable_declaration"],
    return_kinds: &["return_statement"],
    throw_kinds: &[],
    lambda_kinds: &["function_definition"],
    try_kinds: &[],
    catch_kinds: &[],
    finally_kinds: &[],
    break_kinds: &["break_statement"],
    control_label_field_names: &[],
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
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        let (local_fn_spans, table_member_names) =
            if let Some((snapshot, tree)) = bonsai_lang_api::kit::parse_with(PACK_NAME, file, ctx) {
                let source = snapshot.text.as_bytes();
                idx.refs
                    .extend(synthesize_lua_global_arg_refs(&tree, source, file));
                // Two grammar variants for `local function foo() ... end`:
                //   - some tree-sitter-lua releases produce a dedicated
                //     `local_function` node kind;
                //   - the MunifTanjim/tree-sitter-lua grammar parses
                //     `local function helper(x) ... end` as a regular
                //     `function_declaration` whose role on the chunk
                //     is the `local_declaration` field. Detect the
                //     latter by walking the chunk's children and
                //     checking each child's field name.
                let mut spans: Vec<bonsai_common::Span> = collect_kinds(&tree, &["local_function"])
                    .into_iter()
                    .map(|local_fn_node| span_of(file, &local_fn_node))
                    .collect();
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
                (spans, collect_lua_table_member_names(&tree, source, file))
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
        if let Some((snapshot, tree)) = bonsai_lang_api::kit::parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            if let Some(table_name) = collect_lua_module_export_table(&tree, src) {
                let table_dotted_prefix = format!("{table_name}.");
                let table_member_decls: std::collections::HashSet<bonsai_common::Span> =
                    collect_lua_table_member_decl_spans(&tree, src, &table_name, file);
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
        }
        let table_field_assigns = parse_with(PACK_NAME, file, ctx)
            .map(|(snapshot, tree)| {
                collect_lua_table_literal_field_assigns(&tree, snapshot.text.as_bytes(), file)
            })
            .unwrap_or_default();
        for decl in &mut idx.defs {
            insert_lua_table_field_assigns_in_events(&mut decl.flow_events, &table_field_assigns);
            normalize_lua_dot_calls(&mut decl.flow_events);
            enrich_lua_factory_receiver_field_writes(decl);
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
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
        let mut idx = extract_imports_via(PACK_NAME, file, ctx, parse_imports);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            if let (Some(table_name), Some(module)) = (
                collect_lua_module_export_table(&tree, snapshot.text.as_bytes()),
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
        }
        idx
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
    for assignment in collect_kinds(tree, &["assignment_statement"]) {
        let Some(variable_list) = first_named_child_of_kind(&assignment, "variable_list") else {
            continue;
        };
        let Some(expression_list) = first_named_child_of_kind(&assignment, "expression_list") else {
            continue;
        };
        let Some(target_node) = variable_list
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&variable_list, "identifier"))
        else {
            continue;
        };
        let target = node_text(&target_node, src).trim();
        if target.is_empty() || !target.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
            continue;
        }
        let Some(table) = expression_list
            .child_by_field_name("value")
            .filter(|node| node.kind() == "table_constructor")
            .or_else(|| first_named_child_of_kind(&expression_list, "table_constructor"))
        else {
            continue;
        };
        let mut fields = Vec::new();
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
            let sources = lua_value_source_names(value_node, src);
            fields.push(FlowEvent::Assign {
                span: span_of(file, &value_node),
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
        if !fields.is_empty() {
            out.push(LuaTableFieldAssigns {
                assign_span: span_of(file, &assignment),
                target: target.to_string(),
                fields,
            });
        }
    }
    out
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
    let expr_node = call_node
        .parent()
        .filter(|parent| parent.kind() == "dot_index_expression")
        .unwrap_or(call_node);
    let assignment = expr_node
        .parent()
        .filter(|parent| parent.kind() == "expression_list")
        .and_then(|expr_list| expr_list.parent())
        .filter(|parent| parent.kind() == "assignment_statement")?;
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
