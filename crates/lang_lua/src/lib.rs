//! Lua language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, collect_receiver_field_writes, first_named_child_of_kind, language_from_pack,
        node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, DeclIndex, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, Ref, RefKind,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("lua");
const PACK_NAME: &str = "lua";

// tree-sitter-lua (MunifTanjim) handler:
//   - `function_declaration` covers `function foo()` and `function M.foo()`
//   - `function_definition` covers anonymous `function() ... end`
//   - `local_function` covers `local function foo()` scoped to the chunk
//   - Lua has no native exception construct; pcall/xpcall are the
//     idiomatic try-equivalent (function calls; we rely on the
//     do_block-descent + call-arg walking to surface their bodies).
const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &["function_declaration", "function_definition", "local_function"],
    class_kinds: &[],
    method_kinds: &[],
    method_context_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    if_kinds: &["if_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &["for_in_statement"],
    while_kinds: &["while_statement"],
    do_kinds: &["repeat_statement"],
    loop_kinds: &[],
    call_kinds: &["function_call", "method_call"],
    assignment_kinds: &["assignment_statement", "variable_declaration"],
    return_kinds: &["return_statement"],
    throw_kinds: &[],
    lambda_kinds: &["function_definition"],
    try_kinds: &[],
    catch_kinds: &[],
    finally_kinds: &[],
    break_kinds: &["break_statement"],
    // Lua has no `continue` keyword. `goto label` is a general jump,
    // not a loop continue, so leaving this empty avoids mis-tagging
    // arbitrary gotos as `FlowEvent::Continue`.
    continue_kinds: &[],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &[],
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
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
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: bonsai_lang_api::NO_SUPER_RECEIVER_TOKENS,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        let local_fn_spans =
            if let Some((snapshot, tree)) = bonsai_lang_api::kit::parse_with(PACK_NAME, file, ctx) {
                idx.refs.extend(synthesize_lua_global_arg_refs(
                    &tree,
                    snapshot.text.as_bytes(),
                    file,
                ));
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
                spans
            } else {
                Vec::new()
            };
        // Lua has no language-level module boundary; file stem is the
        // closest semantic anchor for qualified_name and module_path.
        // See `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
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
        // Recognised Lua lifecycle transitions. Lua method calls
        // (`f:close()`) land with bare method names per the kit, so
        // the call_match strings are the bare verbs.
        const LUA_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
        ];
        for decl in &mut idx.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, LUA_LIFECYCLE_TRANSITIONS);
            enrich_lua_factory_receiver_field_writes(decl);
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
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
                    scope: ImportScope::Module,
                });
            }
        }
        idx
    }
}

fn enrich_lua_factory_receiver_field_writes(decl: &mut bonsai_lang_api::Decl) {
    if decl.params.is_empty() || !lua_returns_name(&decl.flow_events, "self") {
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
            value_text,
            ..
        } => {
            value_name.as_deref() == Some(name)
                || value_text.as_deref().is_some_and(|text| text.trim() == name)
        }
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
    let only_expr = returned_exprs.pop().expect("single expression");
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
